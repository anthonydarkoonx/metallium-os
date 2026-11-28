//! Floating point and SIMD for user programs.
//!
//! The kernel itself is built soft-float and never touches the FP/SIMD registers, so it does not save them on entry. A user task starts
//! with the access to them *off* (`CPACR_EL1.FPEN = 0b01`: EL0 traps). The first instruction that uses them traps (`EC 0x07`); `first_use`
//! then gives the task a zeroed register file (so nothing of an earlier task is visible), turns the access on for it and lets the
//! instruction run again. From then on the scheduler saves and restores the task's registers (`q0`-`q31`, `FPCR`, `FPSR`) whenever it
//! is switched out and in, and sets `FPEN` on the way in: on for a task that has used FP, off for one that has not.
//!
//! This is *eager* switching for the tasks that use FP (and none for the others), not lazy: a lazily switched register file would stay
//! behind on the core the task last ran on, and a task that moves between cores would then need that core to be asked for it. Every
//! task is owned by one core from dispatch until that core's next dispatch decision (sched.rs), so saving at that point needs no lock.
//!
//! Threads are tasks, so each has its own register file. A restarted or new task slot starts with FP off and a clear file (`reset`).
//! Cost: 528 bytes of save area per task slot, a fixed 16 stores/loads of 32 bytes for a task that uses FP, nothing for one that does not.
use crate::table::Table;
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// One task's saved FP/SIMD state: the 32 128-bit vector registers, then `FPCR` and `FPSR` (the layout the assembly below uses).
#[repr(C, align(16))]
struct Area {
    q: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

const ZERO: Area = Area { q: [0; 32], fpcr: 0, fpsr: 0 };

struct Slot(UnsafeCell<Area>);

// SAFETY: a task's slot is touched only by the core that owns the task at that moment (sched.rs: from dispatch until that core's next
// dispatch decision, no other core can run or switch the task), and by `reset` while the slot is being recycled under the same rule.
unsafe impl Sync for Slot {}

static AREAS: Table<Slot> = Table::new();
/// Whether the task has used FP since it started: its registers are real and its `FPEN` is on while it runs.
static USED: Table<AtomicBool> = Table::new();

global_asm!(
    ".arch_extension fp",
    ".arch_extension simd",
    ".global metallium_fp_save",
    "metallium_fp_save:",
    "stp q0, q1, [x0]",
    "stp q2, q3, [x0, #32]",
    "stp q4, q5, [x0, #64]",
    "stp q6, q7, [x0, #96]",
    "stp q8, q9, [x0, #128]",
    "stp q10, q11, [x0, #160]",
    "stp q12, q13, [x0, #192]",
    "stp q14, q15, [x0, #224]",
    "stp q16, q17, [x0, #256]",
    "stp q18, q19, [x0, #288]",
    "stp q20, q21, [x0, #320]",
    "stp q22, q23, [x0, #352]",
    "stp q24, q25, [x0, #384]",
    "stp q26, q27, [x0, #416]",
    "stp q28, q29, [x0, #448]",
    "stp q30, q31, [x0, #480]",
    "mrs x1, fpcr",
    "mrs x2, fpsr",
    "add x0, x0, #512",
    "stp x1, x2, [x0]",
    "ret",
    ".global metallium_fp_load",
    "metallium_fp_load:",
    "ldp q0, q1, [x0]",
    "ldp q2, q3, [x0, #32]",
    "ldp q4, q5, [x0, #64]",
    "ldp q6, q7, [x0, #96]",
    "ldp q8, q9, [x0, #128]",
    "ldp q10, q11, [x0, #160]",
    "ldp q12, q13, [x0, #192]",
    "ldp q14, q15, [x0, #224]",
    "ldp q16, q17, [x0, #256]",
    "ldp q18, q19, [x0, #288]",
    "ldp q20, q21, [x0, #320]",
    "ldp q22, q23, [x0, #352]",
    "ldp q24, q25, [x0, #384]",
    "ldp q26, q27, [x0, #416]",
    "ldp q28, q29, [x0, #448]",
    "ldp q30, q31, [x0, #480]",
    "add x0, x0, #512",
    "ldp x1, x2, [x0]",
    "msr fpcr, x1",
    "msr fpsr, x2",
    "ret",
);

extern "C" {
    fn metallium_fp_save(area: *mut Area);
    fn metallium_fp_load(area: *const Area);
}

/// `CPACR_EL1.FPEN`: 0b11 = EL0 and EL1 may use FP/SIMD, 0b01 = only EL1 (EL0 traps).
fn set_access(on: bool) {
    let v: u64 = if on { 3 << 20 } else { 1 << 20 };
    // SAFETY: writes CPACR_EL1 on this core; the change takes effect no later than the exception return that follows, and only
    // widens or narrows EL0's access to FP/SIMD (the kernel never uses them).
    unsafe { asm!("msr cpacr_el1, {}", in(reg) v, options(nomem, nostack)) };
}

/// Carve the per-task tables (`n` tasks); called from `sched::init_tables`.
pub fn init_tables(n: usize) {
    AREAS.init(n, |_| Slot(UnsafeCell::new(ZERO)));
    USED.init(n, |_| const { AtomicBool::new(false) });
}

/// The task slot is new, or restarted: it has not used FP, and what it used before is gone.
pub fn reset(tid: usize) {
    USED[tid].store(false, Ordering::Relaxed);
}

/// The first FP/SIMD instruction of a task trapped. Called on the core that owns the task, before it runs again.
pub fn first_use(tid: usize) {
    // SAFETY: the task is owned by this core (see `Slot`), so nobody else touches its area.
    unsafe { *AREAS[tid].0.get() = ZERO };
    // SAFETY: the area is initialised, 16-byte aligned (`repr(align(16))`) and 528 bytes, the size the assembly reads.
    unsafe { metallium_fp_load(AREAS[tid].0.get()) }; // (this overwrites whatever an earlier task left in the registers)
    USED[tid].store(true, Ordering::Relaxed);
    set_access(true);
}

/// The task is being switched out on this core: keep its registers if it has any.
pub fn save(tid: usize) {
    if USED[tid].load(Ordering::Relaxed) {
        // SAFETY: the task is owned by this core; its registers are still in the hardware (nothing else has used them since it ran:
        // every other task that uses FP is saved here and loaded in `load`, and one that does not use FP traps instead of touching them).
        unsafe { metallium_fp_save(AREAS[tid].0.get()) };
    }
}

/// The task is about to run on this core: give it its registers, or turn FP off if it never used any.
pub fn load(tid: usize) {
    if USED[tid].load(Ordering::Relaxed) {
        // SAFETY: the task is owned by this core; the area holds what `save` (or `first_use`) put there.
        unsafe { metallium_fp_load(AREAS[tid].0.get()) };
        set_access(true);
    } else {
        set_access(false);
    }
}
