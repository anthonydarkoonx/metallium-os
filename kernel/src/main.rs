//! Metallium-OS microkernel entry point.
#![no_std]
#![no_main]

mod cache;
mod frame;
mod cap;
mod compact;
mod devices;
mod gic;
mod hal;
mod ipc;
mod irq;
mod kaslr;
mod mem;
mod mmu;
mod ring;
mod obj;
mod pager;
mod pci;
mod platform;
mod rand;
mod sched;
mod smmu;
mod smp;
mod spawn;
mod swap;
mod table;
mod sync;
mod syscall;
mod task;
mod thread;
mod timer;
mod trap;
mod uart;
mod virtio_rng;

use core::panic::PanicInfo;
use metallium_sched::Class;
use metallium_zram::{PageWorkspace, Slot, Zram, PAGE};
use sync::Global;

extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

/// Compressed-page pool (static arena, no heap).
static ZPOOL: Global<[u8; 256 * 1024]> = Global::new([0; 256 * 1024]);
static ZSLOTS: Global<[Slot; 64]> = Global::new([Slot::EMPTY; 64]);
/// Working memory of the Zstandard compressor (about 25 KiB).
static ZWS: Global<PageWorkspace> = Global::new(PageWorkspace::new());

/// Boot-time self-test of the ZRAM path using real physical frames:
/// compress cold pages, wipe the frames, bring the data back, verify.
fn zram_selftest() {
    zram_check("lz4", Zram::new(&mut *ZPOOL.get(), &mut *ZSLOTS.get()));
    zram_check("zstd", Zram::with_zstd(&mut *ZPOOL.get(), &mut *ZSLOTS.get(), &mut *ZWS.get()));
}

fn zram_check(codec: &str, mut z: Zram) {
    let frames: [usize; 3] = core::array::from_fn(|_| mem::alloc(mem::OWNER_KERNEL).expect("frame"));
    // SAFETY: every `pa` passed is a frame just taken from `mem::alloc` for the kernel: inside RAM, page-aligned, owned by this
    // function, and each returned reference is used for one statement or call before another is made.
    let page = |pa: usize| unsafe { &mut *(frame::phys::va(pa) as *mut [u8; PAGE]) };
    for i in 0..PAGE {
        page(frames[0])[i] = b"cold anonymous page "[i % 20];
        page(frames[1])[i] = 0;
        page(frames[2])[i] = (i as u32).wrapping_mul(2654435761).rotate_left(i as u32 % 31) as u8;
    }
    let want: [[u8; 16]; 3] = core::array::from_fn(|k| {
        let mut h = [0u8; 16];
        for (j, b) in h.iter_mut().enumerate() {
            *b = page(frames[k])[j * 251 % PAGE];
        }
        h
    });
    let handles: [_; 3] = core::array::from_fn(|k| z.store(page(frames[k])).expect("zram store"));
    let compressed = z.stored_bytes();
    for &f in &frames {
        page(f).fill(0xAA); // frame is "freed" and reused
    }
    let mut ok = true;
    for k in 0..3 {
        z.load(handles[k], page(frames[k])).expect("zram load");
        for j in 0..16 {
            ok &= page(frames[k])[j * 251 % PAGE] == want[k][j];
        }
    }
    kprintln!(
        "[zram] {codec}: {} KiB of cold pages held in {} B ({}%), swap-in verified: {}",
        3 * PAGE / 1024,
        compressed,
        compressed * 100 / (3 * PAGE),
        if ok { "PASS" } else { "FAIL" }
    );
    for f in frames {
        mem::free(f);
    }
}

/// Test aid (`opt/metallium/stack-overflow=1`): use up the kernel stack, which must end in the stack-guard panic.
/// (`opt/metallium/stack-overflow-core1=1`, or `opt/metallium/stack-overflow-core=N`: the same on core N, whose stack was made from RAM and has a guard of its own.)
pub static OVERFLOW_ON_CORE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);

#[inline(never)]
pub fn overflow_stack(depth: u64) -> u64 {
    let pad = [depth as u8; 1024];
    let p = core::hint::black_box(&pad);
    if depth == u64::MAX {
        return p[0] as u64;
    }
    overflow_stack(depth + 1) + p[(depth % 1024) as usize] as u64
}

/// Test aid (`opt/metallium/stack-overflow-bigframe=1`): one stack frame bigger than stack and guard together. The compiler
/// probes the stack a page at a time for frames like this, so the probe lands in the guard page instead of the frame
/// skipping over it.
#[inline(never)]
pub fn overflow_stack_bigframe(seed: u8) -> u8 {
    let mut big = [seed; 128 * 1024];
    let p = core::hint::black_box(&mut big);
    p[0] = p[0].wrapping_add(1);
    p[p.len() - 1]
}

#[no_mangle]
extern "C" fn kmain(dtb: usize) -> ! {
    // SAFETY: writes TPIDR_EL1 (the core number, 0 for the boot core); only `smp::cpu_id` reads it; no memory is accessed.
    unsafe { core::arch::asm!("msr tpidr_el1, xzr", options(nomem, nostack)) }; // core 0
    // Translation first: the locks behind the very first line printed are exclusive load/store pairs, which real
    // cores only support on cacheable memory (with the MMU off all memory is device memory and they fault).
    // RAM size from the harness (read with the MMU off: it is a device register); 128 MiB if it did not say. Beyond the first GiB the
    // direct map works in 2 MiB blocks, so the size is rounded down to a multiple of them there.
    platform::set_dtb(dtb);
    let ram = platform::ram_size().filter(|&s| (8 << 20..=frame::phys::MAX_RAM as u64).contains(&s)).map_or(128 << 20, |s| s as usize);
    let ram = mem::usable_ram(ram);
    mmu::init(ram);
    platform::init_machine(); // (device tree: interrupt controller, cores, firmware conduit)
    kprintln!("Metallium-OS 0.1 (aarch64, microkernel) booting{}", platform::BANNER_SUFFIX);
    match platform::cpu_count() {
        Some(n) => kprintln!("[machine] device tree at {:#x}: {n} cores, {}", platform::dtb_addr(), platform::intc_name()),
        None => kprintln!("[machine] no device tree (x0 = {dtb:#x}): cores found by asking the firmware, {}", platform::intc_name()),
    }
    platform::early_boot();
    // SAFETY: `__kernel_end` is a linker symbol; only its address is taken, it is never read.
    let kernel_end = unsafe { &__kernel_end as *const u8 as usize };
    platform::entropy_report();
    platform::init_flags();
    rand::init(platform::flag(b"opt/metallium/noaslr"));
    let overflow_core = if platform::flag(b"opt/metallium/stack-overflow-core1") { Some(1) } else { platform::number(b"opt/metallium/stack-overflow-core").map(|n| n as usize) };
    OVERFLOW_ON_CORE.store(overflow_core.unwrap_or(usize::MAX), core::sync::atomic::Ordering::SeqCst);
    if platform::flag(b"opt/metallium/stack-overflow") {
        kprintln!("[kernel] stack-overflow test: recursing");
        kprintln!("[kernel] ... {}", overflow_stack(0));
    }
    if platform::flag(b"opt/metallium/stack-overflow-bigframe") {
        kprintln!("[kernel] stack-overflow test: one frame of 128 KiB");
        kprintln!("[kernel] ... {}", overflow_stack_bigframe(1));
    }
    // SAFETY: `__kernel_start` is a linker symbol; only its address is taken, it is never read.
    let kernel_start = unsafe { &__kernel_start as *const u8 as usize };
    mem::init(ram, kernel_start..kernel_end);
    let k = kaslr::report();
    if let Some((old, len)) = k.old {
        // the image moved: what it left behind is free memory, and holds a copy of the kernel; clear it
        // SAFETY: `old..old+len` is the previous image's RAM; `kaslr` placed the copy disjoint from it, `mem::init` just listed it as free,
        // and the boot core is alone (no allocation or secondary core yet), so nothing else uses it.
        unsafe { core::ptr::write_bytes(frame::phys::va(old) as *mut u8, 0, len) };
    }
    kprintln!(
        "[mem] MMU on; {} MiB RAM, {} frames free, kernel at {:#x}..{:#x}",
        mem::total_frames() * mem::PAGE >> 20,
        mem::free_frames(),
        kernel_start,
        kernel_end
    );
    match k.outcome {
        kaslr::MOVED => kprintln!(
            "[kaslr] kernel image moved from {:#x} to {:#x}{}",
            kaslr::LINK_BASE,
            kernel_start,
            if k.weak { " (WARNING: neither RNDR nor the seed file: the address is guessable)" } else { "" }
        ),
        kaslr::NO_RAM_SIZE => kprintln!("[kaslr] WARNING: RAM size unknown: kernel image not moved"),
        kaslr::NO_ROOM => kprintln!("[kaslr] WARNING: no room in RAM to move the kernel image"),
        _ => kprintln!("[kaslr] WARNING: kernel address not randomised"),
    }
    let (wx, wxn, pan) = mmu::audit();
    let v = |b: bool| if b { "PASS" } else { "FAIL" };
    kprintln!(
        "[mmu] TEST kernel pages are write-xor-execute (code read-only, no other RAM executable): {}; WXN on: {}; PAN on (or not in this CPU): {}",
        v(wx),
        v(wxn),
        v(pan)
    );
    kprintln!("[mem] TEST every task's frames are on a per-owner list that is counted and freed without scanning RAM: {}", v(mem::owner_lists_selftest()));
    match mem::highmem_selftest() {
        Some(r) => kprintln!("[mem] TEST RAM above the first GiB is reached through the direct map: {}", v(r)),
        None => kprintln!("[mem] TEST RAM above the first GiB is reached through the direct map: SKIPPED (RAM ends inside the first GiB)"),
    }
    kprintln!("[mem] TEST the reverse map holds the addresses of the whole user space (up to 256 GiB): {}", v(mem::rmap_selftest()));
    let tasks = task::tasks_for(ram, platform::number(b"opt/metallium/max-tasks"));
    task::init_tables(tasks);
    obj::init_table(obj::objs_for(tasks));
    obj::init_sessions(tasks);
    kprintln!("[kernel] {tasks} task slots, {} endpoints, {} memory objects, {} file and {} network sessions", ipc::nep(), obj::objs_for(tasks), obj::sessions(), obj::sessions());
    timer::init();
    sched::init();
    sched::init_placement();
    platform::init_devices();
    kprintln!("[timer] {} + generic timer at {} Hz", platform::intc_name(), timer::HZ);
    zram_selftest();
    if platform::HAS_SMMU {
        smmu::init();
    }
    obj::init();

    // Policy: which services exist, and who may restart.
    task::spawn(0, "client", Class::Interactive, false);
    task::spawn(1, "service", Class::Interactive, true);
    task::spawn(2, "driver", Class::Background, true);
    task::spawn(3, "worker", Class::Heavy, false);
    devices::spawn_tasks(devices::Phase::Storage);
    devices::spawn_tasks(devices::Phase::Drivers);
    devices::spawn_tasks(devices::Phase::Console);
    if obj::gpu_present() {
        if platform::chaos_seed() != 0 {
            task::spawn(15, "monkey", Class::Background, false);
        } else if platform::fuzz_seed() != 0 {
            task::spawn(17, "fuzzer", Class::Background, false); // takes the monkey's task id (21)
        }
    }

    if obj::blk_present() {
        // CPU burners for the scheduler tests (idle until the conductor raises the flag)
        for _ in 0..3 {
            task::spawn(16, "spinner", Class::Heavy, false);
        }
    }

    // (after everything else: the tasks above keep the ids their clients know them by)
    devices::spawn_tasks(devices::Phase::Network);
    platform::spawn_extra_tasks();
    // the consoles of ttys 1..3 (the tty buffers exist only where sessions run): last, so every other task keeps the id its clients know it by
    if obj::gpu_present() && obj::blk_present() && (task::sessions_in_boot() || platform::only() == 15) {
        for _ in 1..obj::TTY_BUFFERS {
            task::spawn(22, "tty-console", Class::Interactive, false);
        }
    }

    kprintln!("[kernel] capability nodes in use: {} of {}", cap::nodes_in_use(), cap::NODES);
    kprintln!("[kernel] entering userspace");
    let others = smp::start_secondaries();
    kprintln!("[smp] {} cores online (boot core + {others} via PSCI)", others + 1);
    smp::boot_core_enter()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("[kernel] PANIC: {info}");
    sched::semihost_exit(3)
}
