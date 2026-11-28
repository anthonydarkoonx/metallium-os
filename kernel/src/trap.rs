//! Exception entry points called from boot.S.
use crate::sched;
use crate::smp;
use crate::task::{self, frame};
use crate::{compact, irq, mmu, swap, syscall, uart};
use core::arch::{asm, global_asm};

global_asm!(include_str!("boot.S"));

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
}

impl TrapFrame {
    pub const ZERO: TrapFrame = TrapFrame { x: [0; 31], sp: 0, elr: 0, spsr: 0 };
}

fn esr() -> u64 {
    let v: u64;
    // SAFETY: reads ESR_EL1, always readable at EL1; no memory is accessed.
    unsafe { asm!("mrs {}, esr_el1", out(reg) v) };
    v
}

fn far() -> u64 {
    let v: u64;
    // SAFETY: reads FAR_EL1, always readable at EL1; no memory is accessed.
    unsafe { asm!("mrs {}, far_el1", out(reg) v) };
    v
}

/// A translation fault on an address that is mapped now: a race with page migration, not a bug.
fn is_spurious(tid: usize, ec: u64, esr: u64) -> bool {
    let translation_fault = (esr & 0x3C) == 0x04; // FSC 0b0001xx
    translation_fault && matches!(ec, 0x20 | 0x24) && mmu::is_mapped(task::lock(task::aspace(tid)).l1, far() as usize)
}

fn ec_name(ec: u64) -> &'static str {
    match ec {
        0x20 | 0x21 => "instruction abort",
        0x22 => "PC alignment fault",
        0x24 | 0x25 => "data abort",
        0x26 => "SP alignment fault",
        0x00 => "undefined/unknown",
        0x07 => "floating-point or SIMD instruction in the kernel (the kernel is built soft-float)",
        0x0e => "illegal execution state",
        _ => "synchronous exception",
    }
}

/// Kernel entry from userspace: no lock is taken here. The task is owned by this core (see
/// sched.rs), so its register frame can be saved without synchronisation; each piece of
/// kernel work below takes just the locks it needs.
#[no_mangle]
extern "C" fn lower_sync(tf: &mut TrapFrame) {
    let cur = sched::current();
    *frame(cur) = *tf;
    let esr = esr();
    let ec = esr >> 26;
    let swap_fault = if ec == 0x15 { swap::Fault::Other } else { swap::handle_fault(cur, ec, esr, far() as usize) };
    let preempt = if ec == 0x15 {
        syscall::handle(cur)
    } else if ec == 0x07 {
        crate::fpu::first_use(cur); // the task's first FP/SIMD instruction: give it a clear register file and run it again
        false
    } else if let swap::Fault::Retry = swap_fault {
        false // a swapped-out page is back, or an aged one was marked used: run the instruction again
    } else if let swap::Fault::Sleep = swap_fault {
        // the page is on disk: sleep a tick, then the same instruction faults again until the pager has brought it back
        let wake_at = crate::timer::counter().saturating_add(crate::timer::interval());
        sched::set_state(cur, task::State::Sleep(wake_at));
        true
    } else if let swap::Fault::Kill(msg) = swap_fault {
        let why = alloc_free_fmt(ec, esr, far(), tf.elr, tf.x[30], tf.sp);
        task::die(cur, alloc_msg(msg, why.as_str()).as_str());
        true
    } else if is_spurious(cur, ec, esr) {
        // The page was momentarily unmapped while the compactor moved it, and is valid again:
        // re-execute the faulting instruction.
        compact::note_spurious_fault();
        false
    } else {
        let why = alloc_free_fmt(ec, esr, far(), tf.elr, tf.x[30], tf.sp);
        task::die(cur, why.as_str());
        true
    };
    sched::dispatch(tf, preempt);
    smp::kick_idle();
}

#[no_mangle]
extern "C" fn lower_irq(tf: &mut TrapFrame) {
    let core = smp::cpu_id();
    let cur = sched::current();
    *frame(cur) = *tf;
    if irq::handle() {
        task::TICKS_ON[cur][core].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    sched::dispatch(tf, true);
    smp::kick_idle();
}

/// IRQ taken while this core idles in `wfi` (no locks held).
#[no_mangle]
extern "C" fn kernel_irq(_tf: &mut TrapFrame) {
    irq::handle();
    smp::kick_idle();
}

#[no_mangle]
extern "C" fn kernel_sync_panic(tf: &mut TrapFrame) -> ! {
    let e = esr();
    if let Some(core) = mmu::kstack_guard_hit(far()) {
        uart::panic_print(format_args!("[kernel] PANIC: kernel stack overflow on core {core} (guard page hit at {:#x}, ELR={:#x})", far(), tf.elr));
        sched::semihost_exit(2)
    }
    uart::panic_print(format_args!(
        "[kernel] PANIC: synchronous exception in kernel: {} (ESR={:#x}) FAR={:#x} ELR={:#x}",
        ec_name(e >> 26),
        e,
        far(),
        tf.elr
    ));
    sched::semihost_exit(2)
}

#[no_mangle]
extern "C" fn bad_entry_panic(tf: &mut TrapFrame) -> ! {
    uart::panic_print(format_args!("[kernel] PANIC: unexpected exception vector (ELR={:#x})", tf.elr));
    sched::semihost_exit(2)
}

/// Fixed-capacity string so fault reports need no heap.
struct Msg {
    buf: [u8; 128],
    len: usize,
}

impl Msg {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("fault")
    }
}

impl core::fmt::Write for Msg {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

fn alloc_msg(prefix: &str, rest: &str) -> Msg {
    use core::fmt::Write;
    let mut m = Msg { buf: [0; 128], len: 0 };
    let _ = write!(m, "{prefix}: {rest}");
    m
}

fn alloc_free_fmt(ec: u64, esr: u64, far: u64, elr: u64, lr: u64, sp: u64) -> Msg {
    use core::fmt::Write;
    let mut m = Msg { buf: [0; 128], len: 0 };
    let _ = write!(m, "{} (ESR={:#x}) FAR={:#x} PC={:#x} LR={:#x} SP={:#x}", ec_name(ec), esr, far, elr, lr, sp);
    m
}
