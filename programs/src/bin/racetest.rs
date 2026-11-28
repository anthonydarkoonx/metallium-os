#![no_std]
#![no_main]
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::*};
use metallium_programs::thread;
use metallium_programs::*;

// Regression tests for the two races found by the kernel audit (SECURITY.md, H1 and H2). Each needs two cores and is a
// race, so a pass means "not seen in these runs"; the test is written so that the unfixed kernel fails it quickly.
//
//   1  H1: capability checks against revocation. A thread maps a shared-memory capability over and over while the main
//      thread revokes (and so frees) the object. If a map can complete after the revoke, a mapping of freed frames is left
//      behind; the main thread finds it because a fresh object cannot then be mapped at the same address (-5).
//      Exit 0 = no stale mapping in all rounds; 10 = one was left behind; other = setup failed.
//   2  H2: HEAP_RELEASE against the TLB. A thread keeps reading the first page of a heap range that the main thread gives
//      back. Another program (mode 3) is allocating and filling pages at the same time. If frames are freed before the TLB
//      is flushed, the thread's stale translation shows the other program's data. Prints "LEAK" when it does. The thread
//      ends up reading an unmapped page once the release is over, so this program is expected to fault: only the output
//      counts.
//   3  the allocating program for mode 2: waits for the main thread's signal (word 0 of the shared object in slot 0), then takes
//      and fills pages.

//   4, 5, 6  M1: run-time memory (MC_ALLOC) and a thread's copy of its capability. The thread ends the object, in three ways, through
//      its copy: 4 = CAP_REVOKE of itself, 5 = the thread simply ends, 6 = MC_FREE. The object must stay usable for the main
//      thread (whose capability it is): a second mapping works, and the first one still holds what was written. Exit 0 = it did.
//      (A MemCtl capability is in slot 1.)

//   7  M2: CAP_GRANT goes only where it is wanted. The argument's upper bits name another program (a sibling, mode 8). Grants of a
//      memory capability to a boot-time task (task 2), to the sibling (first free slot, and a named slot) must be refused (-1); a
//      grant to the parent must work. Exit code bits: 1 boot-time task not refused, 2 sibling not refused, 4 named slot in the
//      sibling not refused, 8 parent refused.
//   9  L1: SYSINFO pages 10, 11, 13 and 14 (what other tasks hold) need an Admin capability, which this program has not: each must
//      answer -1, while page 0 works. Exit code: one bit per page that was not refused (1, 2, 4, 8), 16 if page 0 failed.
//   10 M4: a floating-point / SIMD instruction in a user program runs (the first use traps into the kernel, which gives the task a clear
//      register file and switches it from then on: kernel/src/fpu.rs; `fptest` checks the isolation). Prints "survived" when it ran.
//   11 M4: TPIDR_EL0 belongs to the task: this one sets A, a thread sets B and gives up the CPU many times, and a new thread starts
//      with 0. Exit code bits: 1 the thread did not start with 0, 2 the thread lost its own value, 4 this task's value was changed.
//   12 M7: one program's run-time memory objects (SHM_CREATE) are limited, however many threads make them: seven threads and this one
//      create until refused. Exit code bits: 1 more than PROGRAM_OBJ_QUOTA (32) were made, 2 none were.
//   13 M7: one program's capability nodes are limited: this one holds 31 capabilities and starts seven threads that each copy all of
//      them. Exit code bits: 1 all seven threads were started (no limit), 2 none was.
//   14 M7: one program's run-time endpoints are limited, however many threads make them (a factory capability is in slot 1): seven
//      threads and this one create until refused. Exit code bits: 1 more than 4 were made, 2 none were.
//   15 M7: one program may not fill an endpoint's queue (a factory capability is in slot 1): it makes an endpoint, queues messages
//      to it until refused, and a thread of the same program then tries one more. Exit code bits: 1 not exactly 4 were queued
//      (half of the queue of 8), 2 the thread's message was accepted.
//   16 N1: a node number freed by a revoke is handed out again at once, so a copy of a capability that was read before the revoke must not
//      look alive after it. Thread A calls THREAD_CREATE with a copy of a shared-memory capability while the main thread revokes the
//      object (after a random delay) and creates a new one; the main thread arranged that the copy's node is the lowest free number, so
//      the console node that THREAD_CREATE makes for thread B takes it. B then maps the capability it was given: the new object must not
//      be mapped. Exit code: 0 = never, 10 = B mapped an object through a revoked capability, other = setup failed. (Needs 2 extra threads.)
//   17 N2: TASK_LOAD of an embryo that is killed while it loads. A thread loads 200 pages into an embryo; the main thread kills and collects
//      the embryo meanwhile (after a random delay). The load must stop with an error: if it comes back successful after the embryo has been
//      collected, it went on writing the page tables of a dead task. Exit code: 0 = never, 10 = it did. (A spawn capability is in slot 0.)
//   18, 19  N5: a file session page is wiped when it is handed to the next program. 18 (started with file access) maps its session page (slot 9),
//      fills it and ends; 19 (started with file access after 18 was collected, so it gets the same page) counts the non-zero bytes it finds
//      there before it has made a single request, and exits with that count. Expected 0.
//   20 N3: memory a thread made and gave to its own program outlives the thread, and the program pays for it. A thread makes 64 pages of shared
//      memory, grants it to the main thread and ends; 20 times. The program's limit is 400 pages: it must be refused after a few rounds. Exit 10
//      if 12 or more rounds were allowed (the memory was charged to nobody once its maker had ended).
//   21 N6: a program that ends while one of its threads is in SPAWN must not leave an embryo nobody owns. A thread keeps starting embryos and
//      killing them (a spawn capability is in slot 0); the main thread ends after a random delay. The conductor counts the live tasks before
//      and after many runs: a leaked embryo stays in the count for ever.
//   22 N11: only the pager's first task may use MC_PAGER_NEXT and MC_PAGER_DONE (a MemCtl capability with the pager right is in slot 1): this
//      program registers as the pager, a thread of it calls both; each must be refused (-1). Exit code bits: 1 NEXT was not refused, 2 DONE was not.
//   23 N10: two threads of one program that WAIT for the same dead child: exactly one may collect it. This one and a thread poll (WAIT without
//      blocking) for a killed child, 40 times (a spawn capability is in slot 0, the thread gets it too). Exit 10 if both collected one.
//   24 L3: the holding limit is checked and charged in one step. Seven threads and the main thread create 100 pages of shared memory at the same
//      moment, 1500 times (the limit is 400 pages, the seven thread stacks take 112, so two fit); after each round the program must not hold more
//      than its limit. Exit 10 if it did.
//   8  the sibling: sleeps for a while, then ends.

const BIG: usize = 0xA000_0000;
const MEMCTL: u64 = 18;
const MC_ALLOC: u64 = 2;
const MC_FREE: u64 = 3;
const PAGE: usize = 4096;
const E_BADCAP: i64 = -2;
const HEAP_RELEASE: u64 = 19;
const CAP_GRANT: u64 = 5;
/// The slot the thread receives the object in (the argument of CAP_GRANT is slot + 1).
const THEIR_SLOT: u64 = 20;

const ROUNDS: u32 = 3000;
const T_MAGIC: u64 = 0x7E57_7E57_7E57_7E57;
const U_MAGIC: u64 = 0xA110_CA7E_D0DE_C0DE;
const RELEASE_PAGES: usize = 2048;
const ALLOC_PAGES: usize = 4096;

static GEN: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static STOP: AtomicU32 = AtomicU32::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static LEAK: AtomicU32 = AtomicU32::new(0);
static WATCH: AtomicUsize = AtomicUsize::new(0);

fn rng(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

/// H1's mapper: for each round, once the main thread has handed it the object, map it until the capability is gone.
extern "C" fn mapper(_: u64) -> ! {
    let mut seen = 0;
    loop {
        let g = loop {
            if STOP.load(Acquire) != 0 {
                thread::exit(&DONE);
            }
            let g = GEN.load(Acquire);
            if g != seen {
                break g;
            }
            core::hint::spin_loop();
        };
        seen = g;
        for _ in 0..200_000 {
            if map(THEIR_SLOT, BIG, true) == E_BADCAP {
                break;
            }
        }
        DONE.store(g + 1000, Release); // (not the word the kernel stores into when the thread ends)
    }
}

fn h1() -> u64 {
    let id = thread::create_with_kernel_stack(mapper, 0, 0, 0);
    if id < 0 {
        return 2;
    }
    let mut r = 0x9E37_79B9_7F4A_7C15u64;
    for round in 1..=ROUNDS {
        let s = shm_create(1);
        if s < 0 {
            return 3;
        }
        let s = s as u64;
        if svc(CAP_GRANT, s, id as u64, 0xFFFF & !4, THEIR_SLOT + 1, 0)[0] as i64 != THEIR_SLOT as i64 {
            return 4;
        }
        GEN.store(round, Release);
        for _ in 0..(rng(&mut r) % 400) {
            core::hint::spin_loop(); // (a different point of the mapper's loop each time)
        }
        revoke_self(s);
        while DONE.load(Acquire) != round + 1000 {
            core::hint::spin_loop();
        }
        // The mapper is done and the object gone: nothing may be left mapped at BIG. A fresh object maps there only if so.
        let s2 = shm_create(1);
        if s2 < 0 {
            return 5;
        }
        let m = map(s2 as u64, BIG, true);
        revoke_self(s2 as u64); // (takes its mapping with it)
        if m != 0 {
            println!("racetest: STALE mapping left behind in round {round} (map of a fresh object returned {m})");
            return 10;
        }
    }
    STOP.store(1, Release);
    0
}

/// H2's reader: reads the first word of the range that is about to be released, as fast as it can.
extern "C" fn watcher(_: u64) -> ! {
    while GO.load(Acquire) == 0 {
        core::hint::spin_loop();
    }
    let p = WATCH.load(Relaxed) as *const u64;
    loop {
        // SAFETY: the main thread keeps this page mapped until it releases it; reading it afterwards faults, which ends the program, and this test expects that.
        let v = unsafe { core::ptr::read_volatile(p) };
        if v == U_MAGIC && LEAK.swap(1, Relaxed) == 0 {
            println!("racetest: LEAK, a released page shows another program's data ({v:#x})");
        }
    }
}

/// A word of the shared object both H2 programs hold in slot 0 (the conductor made it): the main thread sets it just before
/// the release, the allocator waits for it.
fn sync_word() -> &'static AtomicU32 {
    // SAFETY: slot 0 holds a 1-page shared object, mapped at BIG by `attach`; this program keeps it mapped to the end.
    unsafe { &*(BIG as *const AtomicU32) }
}

fn attach() -> bool {
    map(0, BIG, true) == 0
}

fn h2() -> u64 {
    if !attach() {
        return 1;
    }
    let base = heap_grow(RELEASE_PAGES as u64);
    if base < 0 {
        return 2;
    }
    let base = base as usize;
    for p in 0..RELEASE_PAGES {
        // SAFETY: `heap_grow` just mapped RELEASE_PAGES writable pages at `base`.
        unsafe { core::ptr::write_volatile((base + p * PAGE) as *mut u64, T_MAGIC) };
    }
    WATCH.store(base, Relaxed);
    if thread::create_with_kernel_stack(watcher, 0, 1 << 7, 0) < 0 /* (slot 7: where the console output goes) */ {
        return 3;
    }
    GO.store(1, Release);
    sleep(2); // let the watcher get its translation and run on its core
    sync_word().store(1, Release); // the allocator starts now
    let freed = svc(HEAP_RELEASE, 0, RELEASE_PAGES as u64, 0, 0, 0)[0] as i64;
    println!("racetest: released {freed} pages");
    0
}

/// The other program: waits for the release to start, then takes and fills as many pages as it can.
fn allocator() -> u64 {
    if !attach() {
        return 1;
    }
    while sync_word().load(Acquire) == 0 {
        core::hint::spin_loop();
    }
    let mut taken = 0;
    for _ in 0..ALLOC_PAGES {
        let b = heap_grow(1);
        if b < 0 {
            break;
        }
        // SAFETY: `heap_grow(1)` just mapped a writable page at `b`.
        unsafe { core::ptr::write_volatile(b as *mut u64, U_MAGIC) };
        taken += 1;
    }
    println!("racetest: allocator took {taken} pages");
    (taken != ALLOC_PAGES) as u64 // 0 = it got all it asked for while the release was running
}

static MODE: AtomicU32 = AtomicU32::new(0);
static TP_RESULT: AtomicU32 = AtomicU32::new(0);

fn tpidr_read() -> u64 {
    let v: u64;
    // SAFETY: reads TPIDR_EL0, which a program may use as it likes.
    unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) v, options(nomem, nostack)) };
    v
}

fn tpidr_write(v: u64) {
    // SAFETY: writes TPIDR_EL0, which a program may use as it likes.
    unsafe { core::arch::asm!("msr tpidr_el0, {}", in(reg) v, options(nomem, nostack)) };
}

extern "C" fn tp_thread(_: u64) -> ! {
    let mut bits = 0;
    if tpidr_read() != 0 {
        bits |= 1;
    }
    tpidr_write(0xB0B0_B0B0);
    for _ in 0..3000 {
        yield_now();
        if tpidr_read() != 0xB0B0_B0B0 {
            bits |= 2;
        }
    }
    TP_RESULT.store(bits, Release);
    thread::exit(&DONE)
}

fn tpidr() -> u64 {
    tpidr_write(0xA0A0_A0A0);
    if thread::create_with_kernel_stack(tp_thread, 0, 0, 0) < 0 {
        return 100;
    }
    let mut bits = 0;
    for _ in 0..3000 {
        yield_now();
        if tpidr_read() != 0xA0A0_A0A0 {
            bits |= 4;
        }
    }
    thread::join(&DONE);
    bits | TP_RESULT.load(Acquire) as u64
}

/// M1's thread: it holds copies of the MemCtl capability (slot 1) and of the object's (slot `s`).
extern "C" fn copier(s: u64) -> ! {
    match MODE.load(Acquire) {
        4 => {
            revoke_self(s);
        }
        6 => {
            svc(MEMCTL, 1, MC_FREE, s, 0, 0);
        }
        _ => {} // 5: it just ends
    }
    thread::exit(&DONE)
}

fn m1(mode: u64) -> u64 {
    let s = svc(MEMCTL, 1, MC_ALLOC, 1, 0, 0)[0] as i64;
    if s < 0 {
        return 2;
    }
    let s = s as u64;
    if map(s, BIG, true) != 0 {
        return 3;
    }
    // SAFETY: the 1-page object was just mapped writable at BIG.
    unsafe { core::ptr::write_volatile(BIG as *mut u64, T_MAGIC) };
    MODE.store(mode as u32, Release);
    if thread::create_with_kernel_stack(copier, s, (1 << 1) | (1 << s), 0) < 0 {
        return 4;
    }
    thread::join(&DONE);
    if map(s, BIG + 0x10000, true) != 0 {
        return 10; // the object is gone from under the capability that is still here
    }
    // SAFETY: BIG and BIG + 0x10000 are mappings of the same live object.
    if unsafe { core::ptr::read_volatile((BIG + 0x10000) as *const u64) } != T_MAGIC {
        return 11;
    }
    0
}

fn m2(sibling: u64, parent: u64) -> u64 {
    let s = shm_create(1);
    if s < 0 {
        return 100;
    }
    let s = s as u64;
    let mut bits = 0;
    let grant = |to: u64, dest: u64| svc(CAP_GRANT, s, to, 0xFFFF & !4, dest, 0)[0] as i64;
    if grant(2, 0) != -1 {
        bits |= 1;
    }
    if grant(sibling, 0) != -1 {
        bits |= 2;
    }
    if grant(sibling, 8) != -1 {
        bits |= 4;
    }
    if grant(parent, 0) < 0 {
        bits |= 8;
    }
    revoke_self(s); // (takes the copy in the parent with it)
    bits
}

const T_COUNT: usize = 28; // (task slots: a 64 MiB machine has 36 for programs and their threads)
static DONES: [AtomicU32; T_COUNT] = [const { AtomicU32::new(0) }; T_COUNT];
static MADE: AtomicU32 = AtomicU32::new(0);
/// How many threads have finished making things, and the signal for them to end (what a thread made goes with it when it ends).
static ARRIVED: AtomicU32 = AtomicU32::new(0);
static RELEASE: AtomicU32 = AtomicU32::new(0);

extern "C" fn maker(i: u64) -> ! {
    match MODE.load(Acquire) {
        12 => {
            while shm_create(1) >= 0 {
                MADE.fetch_add(1, SeqCst);
            }
        }
        14 => {
            while svc(27, 1, 0, 0, 0, 0)[0] as i64 >= 0 {
                MADE.fetch_add(1, SeqCst);
            }
        }
        _ => {} // 13: the copies are the test
    }
    ARRIVED.fetch_add(1, SeqCst);
    while RELEASE.load(Acquire) == 0 {
        thread::wait_word(&RELEASE, 0, 0);
    }
    thread::exit(&DONES[i as usize])
}

fn m7(mode: u64, limit: u32) -> u64 {
    MODE.store(mode as u32, Release);
    let mut held = 0;
    if mode == 13 {
        // (fill the table of capabilities: the slots the program was given are taken already)
        while shm_create(1) >= 0 {
            held += 1;
        }
        if held < 16 {
            return 90; // (the setup: capabilities to copy)
        }
    }
    let mut started = 0;
    for i in 0..T_COUNT {
        let mask = if mode == 13 { u32::MAX & !(1 << 31) } else { 1 << 1 };
        if thread::create_with_kernel_stack(maker, i as u64, mask, 0) >= 0 {
            started += 1;
        } else {
            DONES[i].store(1, Release);
        }
    }
    if mode != 13 {
        // this thread makes its share too
        loop {
            let ok = if mode == 12 { shm_create(1) >= 0 } else { svc(27, 1, 0, 0, 0, 0)[0] as i64 >= 0 };
            if !ok {
                break;
            }
            MADE.fetch_add(1, SeqCst);
        }
    }
    // (what a thread made is gone when it ends: count while they all still stand)
    while ARRIVED.load(Acquire) < started {
        sleep(1);
    }
    let made = MADE.load(SeqCst);
    RELEASE.store(1, Release);
    thread::wake_word(&RELEASE, T_COUNT);
    for d in DONES.iter() {
        thread::join(d);
    }
    let mut bits = 0;
    if mode == 13 {
        if started == T_COUNT as u32 {
            bits |= 1;
        }
        if started == 0 {
            bits |= 2;
        }
    } else {
        if made > limit {
            bits |= 1;
        }
        if made == 0 {
            bits |= 2;
        }
    }
    bits
}

fn queue_share() -> u64 {
    let ep = svc(27, 1, 0, 0, 0, 0)[0] as i64;
    if ep < 0 {
        return 90;
    }
    let mut n = 0;
    while svc(1, ep as u64, 0, 0, 0, 0)[0] as i64 == 0 && n < 16 {
        n += 1;
    }
    let mut bits = if n == 4 { 0 } else { 1 };
    MODE.store(15, Release);
    EPSLOT.store(ep as u32, Release);
    if thread::create_with_kernel_stack(sender, 0, 1 << ep, 0) < 0 {
        return 91;
    }
    thread::join(&DONES[0]);
    if THREAD_SENT.load(Acquire) != 0 {
        bits |= 2;
    }
    bits
}
static EPSLOT: AtomicU32 = AtomicU32::new(0);
static THREAD_SENT: AtomicU32 = AtomicU32::new(0);

extern "C" fn sender(_: u64) -> ! {
    if svc(1, EPSLOT.load(Acquire) as u64, 0, 0, 0, 0)[0] as i64 == 0 {
        THREAD_SENT.store(1, Release);
    }
    thread::exit(&DONES[0])
}

const ROUNDS16: usize = 60;
static GO16: AtomicU32 = AtomicU32::new(0);
static CHECK16: AtomicU32 = AtomicU32::new(0);
static SLOT16: AtomicU32 = AtomicU32::new(0);
static A_RES: AtomicU32 = AtomicU32::new(0);
static B_RES: AtomicU32 = AtomicU32::new(0);
static DONE16: [AtomicU32; 2 * ROUNDS16] = [const { AtomicU32::new(0) }; 2 * ROUNDS16];
static ROUND16: AtomicU32 = AtomicU32::new(0);

/// Thread B of N1: once the main thread says the object is replaced, map the capability it was given (slot of S).
extern "C" fn n1_b(_: u64) -> ! {
    let round = ROUND16.load(Acquire);
    while CHECK16.load(Acquire) != round {
        core::hint::spin_loop();
    }
    let r = map(SLOT16.load(Acquire) as u64, BIG + 0x20000, true);
    B_RES.store(if r == 0 { 1 } else { 2 }, Release);
    thread::exit(&DONE16[2 * round as usize + 1])
}

/// Thread A of N1: at the signal, start thread B with a copy of what it holds (slot of S).
extern "C" fn n1_a(_: u64) -> ! {
    let round = ROUND16.load(Acquire);
    while GO16.load(Acquire) != round {
        core::hint::spin_loop();
    }
    let slot = SLOT16.load(Acquire);
    let r = thread::create_with_kernel_stack(n1_b, 0, 1 << slot, 0);
    A_RES.store(if r >= 0 { 1 } else { 2 }, Release);
    thread::exit(&DONE16[2 * round as usize])
}

fn n1() -> u64 {
    let u = shm_create(1);
    if u < 0 {
        return 2;
    }
    let mut r = 0x9E37_79B9_7F4A_7C15u64;
    for round in 1..ROUNDS16 as u32 {
        // Two throw-away objects take the two lowest free node numbers, then the one under test; freeing the first two makes
        // those numbers the lowest free ones again, so thread A's console node and its copy of S (node of S's copy < S's own) take them.
        let (x1, x2, s) = (shm_create(1), shm_create(1), shm_create(1));
        if x1 < 0 || x2 < 0 || s < 0 {
            return 3;
        }
        revoke_self(x1 as u64);
        revoke_self(x2 as u64);
        ROUND16.store(round, Release);
        SLOT16.store(s as u32, Release);
        A_RES.store(0, Release);
        B_RES.store(0, Release);
        if thread::create_with_kernel_stack(n1_a, 0, 1 << s, 0) < 0 {
            return 4;
        }
        // (these two take the object-table entries the throw-aways left, so that the new object after the revoke gets S's entry)
        let (y1, y2) = (shm_create(1), shm_create(1));
        if y1 < 0 || y2 < 0 {
            return 5;
        }
        GO16.store(round, Release);
        for _ in 0..(rng(&mut r) % 3000) {
            core::hint::spin_loop();
        }
        revoke_self(s as u64);
        let s2 = shm_create(1);
        CHECK16.store(round, Release);
        thread::join(&DONE16[2 * round as usize]);
        if A_RES.load(Acquire) == 1 {
            thread::join(&DONE16[2 * round as usize + 1]);
        }
        let bug = B_RES.load(Acquire) == 1;
        for x in [y1, y2, s2] {
            if x >= 0 {
                revoke_self(x as u64);
            }
        }
        if bug {
            println!("racetest: a revoked capability mapped a new object in round {round}");
            return 10;
        }
    }
    revoke_self(u as u64);
    0
}

const N2_PAGES: usize = 200;
const ROUNDS17: usize = 40;
static START17: AtomicU32 = AtomicU32::new(0);
static ORDER17: AtomicU32 = AtomicU32::new(0);
static RES17: AtomicU32 = AtomicU32::new(0);
static LATE17: AtomicU32 = AtomicU32::new(0);
static SRC17: AtomicUsize = AtomicUsize::new(0);
static ROUND17: AtomicU32 = AtomicU32::new(0);
static DONE17: [AtomicU32; ROUNDS17 + 1] = [const { AtomicU32::new(0) }; ROUNDS17 + 1];

extern "C" fn loader(child: u64) -> ! {
    let mut lr = [0u8; 24];
    lr[0..8].copy_from_slice(&0x8000_0000u64.to_le_bytes());
    lr[8..16].copy_from_slice(&(SRC17.load(Acquire) as u64).to_le_bytes());
    lr[16..20].copy_from_slice(&(N2_PAGES as u32).to_le_bytes());
    lr[20..24].copy_from_slice(&1u32.to_le_bytes()); // read + write
    START17.store(1, Release);
    let r = svc(28, child, lr.as_ptr() as u64, 0, 0, 0)[0] as i64;
    // (a load that comes back successful after the embryo was killed and collected went on writing a dead task's tables)
    LATE17.store((r == 0 && ORDER17.load(Acquire) == 1) as u32, Release);
    RES17.store(if r == 0 { 1 } else { 2 }, Release);
    thread::exit(&DONE17[ROUND17.load(Acquire) as usize])
}

fn n2() -> u64 {
    let src = heap_grow(N2_PAGES as u64);
    if src < 0 {
        return 2;
    }
    SRC17.store(src as usize, Release);
    let mut r = 0x2545_F491_4F6C_DD1Du64;
    let mut late = 0;
    for round in 1..=ROUNDS17 as u32 {
        let mut req = [0u8; 96];
        req[0..4].copy_from_slice(&2u32.to_le_bytes());
        for i in 0..8 {
            req[64 + 4 * i] = NONE as u8; // (nothing is handed over)
        }
        let child = svc(SPAWN, 0, req.as_ptr() as u64, 0, 0, 0)[0] as i64;
        if child < 0 {
            println!("racetest: SPAWN failed ({child}) in round {round}");
            return 3;
        }
        START17.store(0, Release);
        ORDER17.store(0, Release);
        RES17.store(0, Release);
        LATE17.store(0, Release);
        ROUND17.store(round, Release);
        if thread::create_with_kernel_stack(loader, child as u64, 0, 0) < 0 {
            return 4;
        }
        while START17.load(Acquire) == 0 {
            core::hint::spin_loop();
        }
        for _ in 0..(rng(&mut r) % 40_000) {
            core::hint::spin_loop();
        }
        kill(child as u64);
        wait(child as u64, false);
        ORDER17.store(1, Release);
        thread::join(&DONE17[round as usize]);
        late += LATE17.load(Acquire);
    }
    if late > 0 {
        println!("racetest: TASK_LOAD went on loading into a collected embryo in {late} rounds");
        return 10;
    }
    0
}

const N3_ROUNDS: usize = 20;
static N3_OK: AtomicU32 = AtomicU32::new(0);
static N3_ME: AtomicU32 = AtomicU32::new(0);
static N3_ROUND: AtomicU32 = AtomicU32::new(0);
static DONE20: [AtomicU32; N3_ROUNDS + 1] = [const { AtomicU32::new(0) }; N3_ROUNDS + 1];

extern "C" fn orphaner(_: u64) -> ! {
    let s = shm_create(64);
    if s >= 0 && svc(CAP_GRANT, s as u64, N3_ME.load(Acquire) as u64, 0xFFFF & !4, 0, 0)[0] as i64 >= 0 {
        N3_OK.fetch_add(1, SeqCst);
    }
    thread::exit(&DONE20[N3_ROUND.load(Acquire) as usize])
}

fn n3() -> u64 {
    N3_ME.store(svc(21, 8, 0, 0, 0, 0)[1] as u32, Release);
    for round in 1..=N3_ROUNDS as u32 {
        N3_ROUND.store(round, Release);
        if thread::create_with_kernel_stack(orphaner, 0, 0, 0) < 0 {
            return 2;
        }
        thread::join(&DONE20[round as usize]);
    }
    let ok = N3_OK.load(Acquire);
    println!("racetest: {ok} of {N3_ROUNDS} threads were allowed to leave 64 pages behind");
    if ok >= 12 {
        10
    } else {
        0
    }
}

extern "C" fn spawn_loop(_: u64) -> ! {
    loop {
        // (eight embryos in a row, so that most of the time is spent inside SPAWN; then they are all ended and collected)
        let mut kids = [0i64; 8];
        for k in kids.iter_mut() {
            let mut req = [0u8; 96];
            req[0..4].copy_from_slice(&2u32.to_le_bytes());
            for i in 0..8 {
                req[64 + 4 * i] = NONE as u8;
            }
            *k = svc(SPAWN, 0, req.as_ptr() as u64, 0, 0, 0)[0] as i64;
        }
        for &k in kids.iter().filter(|&&k| k > 0) {
            kill(k as u64);
        }
        for &k in kids.iter().filter(|&&k| k > 0) {
            wait(k as u64, false);
        }
    }
}

fn n6() -> u64 {
    if thread::create_with_kernel_stack(spawn_loop, 0, 1 << 0, 0) < 0 {
        // (the thread gets the spawn capability: slot 0)
        return 2;
    }
    let mut r = svc(metallium_programs::random::GETRANDOM, 0, 0, 0, 0, 0)[1] | 1; // (a different delay every run)
    for _ in 0..(rng(&mut r) % 100_000) {
        core::hint::spin_loop();
    }
    0 // (the program ends here, with the thread most likely inside SPAWN)
}

#[repr(align(4096))]
struct PageBuf([u8; PAGE]);
static mut PBUF: PageBuf = PageBuf([0; PAGE]);
static PWORD: AtomicU32 = AtomicU32::new(0);
static P_NEXT: AtomicU32 = AtomicU32::new(0);
static P_DONE: AtomicU32 = AtomicU32::new(0);
static P_END: AtomicU32 = AtomicU32::new(0);

extern "C" fn pager_thread(_: u64) -> ! {
    // SAFETY: `addr_of_mut!` only makes a pointer to the page-aligned static; the kernel refuses the call, so nothing is written through it.
    let buf = unsafe { core::ptr::addr_of_mut!(PBUF) as u64 };
    P_NEXT.store(svc(MEMCTL, 1, 7, buf, 0, 0)[0] as u32, Release);
    P_DONE.store(svc(MEMCTL, 1, 8, 0, 0, 0)[0] as u32, Release);
    thread::exit(&P_END)
}

fn n11() -> u64 {
    if svc(MEMCTL, 1, 6, 1, &PWORD as *const AtomicU32 as u64, 0)[0] as i64 != 0 {
        return 2;
    }
    if thread::create_with_kernel_stack(pager_thread, 0, 1 << 1, 0) < 0 {
        return 3;
    }
    thread::join(&P_END);
    let mut bits = 0;
    if P_NEXT.load(Acquire) as i32 != -1 {
        bits |= 1;
    }
    if P_DONE.load(Acquire) as i32 != -1 {
        bits |= 2;
    }
    bits
}

const N10_ROUNDS: usize = 40;
static SLEEPER: &[u8] = include_bytes!("../../build/sleeper.bin");
static W_GO: AtomicU32 = AtomicU32::new(0);
static W_CHILD: AtomicU32 = AtomicU32::new(0);
static W_THREAD: AtomicU32 = AtomicU32::new(0); // 1: the thread collected the child, 2: it did not
static DONE23: [AtomicU32; N10_ROUNDS + 1] = [const { AtomicU32::new(0) }; N10_ROUNDS + 1];
static W_ROUND: AtomicU32 = AtomicU32::new(0);

/// Poll WAIT (without blocking) until the child is collected or is not ours: whether this caller collected it.
fn collect(child: u64) -> bool {
    loop {
        let r = wait(child, true);
        if r == -10 {
            core::hint::spin_loop(); // (E_AGAIN: not dead yet)
            continue;
        }
        return r != -5; // (E_INVAL: somebody else collected it)
    }
}

extern "C" fn waiter(_: u64) -> ! {
    let round = W_ROUND.load(Acquire);
    while W_GO.load(Acquire) != round {
        core::hint::spin_loop();
    }
    W_THREAD.store(if collect(W_CHILD.load(Acquire) as u64) { 1 } else { 2 }, Release);
    thread::exit(&DONE23[round as usize])
}

fn n10() -> u64 {
    let mut both = 0;
    for round in 1..=N10_ROUNDS as u32 {
        let child = spawn(0, &Spawn::new(SLEEPER));
        if child < 0 {
            println!("racetest: SPAWN failed ({child}) in round {round}");
            return 2;
        }
        W_CHILD.store(child as u32, Release);
        W_ROUND.store(round, Release);
        W_THREAD.store(0, Release);
        if thread::create_with_kernel_stack(waiter, 0, 0, 0) < 0 {
            return 3;
        }
        kill(child as u64);
        W_GO.store(round, Release);
        let mine = collect(child as u64);
        thread::join(&DONE23[round as usize]);
        if mine && W_THREAD.load(Acquire) == 1 {
            both += 1;
        }
    }
    if both > 0 {
        println!("racetest: both threads collected the same child in {both} rounds");
        return 10;
    }
    0
}

const L3_ROUNDS: u32 = 1500;
const L3_THREADS: u32 = 7;
static L3_GO: AtomicU32 = AtomicU32::new(0);
static L3_MADE: AtomicU32 = AtomicU32::new(0);
static L3_CLEAN_GO: AtomicU32 = AtomicU32::new(0);
static L3_CLEANED: AtomicU32 = AtomicU32::new(0);
static L3_DONE: [AtomicU32; L3_THREADS as usize] = [const { AtomicU32::new(0) }; L3_THREADS as usize];

extern "C" fn l3_thread(i: u64) -> ! {
    for round in 1..=L3_ROUNDS {
        while L3_GO.load(Acquire) < round {
            core::hint::spin_loop();
        }
        let s = shm_create(100);
        L3_MADE.fetch_add(1, SeqCst);
        while L3_CLEAN_GO.load(Acquire) < round {
            core::hint::spin_loop();
        }
        if s >= 0 {
            revoke_self(s as u64);
        }
        L3_CLEANED.fetch_add(1, SeqCst);
    }
    thread::exit(&L3_DONE[i as usize])
}

fn l3() -> u64 {
    for i in 0..L3_THREADS as u64 {
        if thread::create_with_kernel_stack(l3_thread, i, 0, 0) < 0 {
            return 2;
        }
    }
    let mut over = 0;
    for round in 1..=L3_ROUNDS {
        L3_MADE.store(0, Release);
        L3_CLEANED.store(0, Release);
        L3_GO.store(round, Release);
        let s = shm_create(100);
        L3_MADE.fetch_add(1, SeqCst);
        while L3_MADE.load(Acquire) < L3_THREADS + 1 {
            core::hint::spin_loop();
        }
        let q = quota();
        if q.held > q.limit {
            over += 1;
        }
        L3_CLEAN_GO.store(round, Release);
        if s >= 0 {
            revoke_self(s as u64);
        }
        while L3_CLEANED.load(Acquire) < L3_THREADS {
            core::hint::spin_loop();
        }
    }
    for d in L3_DONE.iter() {
        thread::join(d);
    }
    if over > 0 {
        println!("racetest: the program held more than its limit after {over} of {L3_ROUNDS} rounds");
        return 10;
    }
    0
}

const FS_PAGE_SLOT: u64 = 9;

fn session_page(fill: bool) -> u64 {
    if map(FS_PAGE_SLOT, BIG, true) != 0 {
        return 1000;
    }
    let p = BIG as *mut u8;
    let mut n = 0;
    for i in 0..PAGE {
        // SAFETY: the session page (one page) was just mapped writable at BIG.
        unsafe {
            if fill {
                core::ptr::write_volatile(p.add(i), 0xA5);
            } else if core::ptr::read_volatile(p.add(i)) != 0 {
                n += 1;
            }
        }
    }
    n
}

program!("racetest", |c| {
    match c.arg & 0xFF {
        8 => {
            sleep(100);
            0
        }
        9 => {
            let mut bits = 0;
            for (i, page) in [10u64, 11, 13, 14].iter().enumerate() {
                if svc(21, *page, 0, 0, 0, 0)[0] as i64 != -1 {
                    bits |= 1 << i;
                }
            }
            if svc(21, 0, 0, 0, 0, 0)[0] as i64 != 0 {
                bits |= 16;
            }
            bits
        }
        7 => m2(c.arg >> 8, c.parent),
        10 => {
            // SAFETY: `.inst` emits `movi v0.16b, #0`, which touches only a vector register that is this task's own.
            unsafe { core::arch::asm!(".inst 0x4f000400", out("v0") _) };
            println!("racetest: survived a SIMD instruction");
            0
        }
        11 => tpidr(),
        12 => m7(12, 256),
        13 => m7(13, 0),
        14 => m7(14, 16),
        15 => queue_share(),
        16 => n1(),
        20 => n3(),
        21 => n6(),
        22 => n11(),
        23 => n10(),
        24 => l3(),
        18 => session_page(true),
        19 => session_page(false),
        17 => n2(),
        4..=6 => m1(c.arg),
        1 => h1(),
        2 => h2(),
        3 => allocator(),
        _ => 99,
    }
});
