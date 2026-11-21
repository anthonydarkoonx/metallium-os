//! Tasks: address space, capability table, lifecycle (spawn / die / restart).
//!
//! Per-task state is split by who may touch it:
//!  * `Task` (below) sits behind the task's own lock: capabilities, mappings, page tables,
//!    reply links, the async-call table, heap size.
//!  * scheduling state (run state, running flag, dispatch stamps) lives in `sched.rs`
//!    behind the scheduler lock;
//!  * `Info` is written once at spawn and read-only afterwards, so it needs no lock;
//!  * the saved register frame is handed over by protocol, see `frame()`.
#![forbid(unsafe_code)]
use crate::cap::*;
use crate::ipc::{self};
use crate::mem::{self, PAGE};
use crate::sched;
use crate::sync::{Guard, SlotTable, SpinLock, R_TASK, R_TEARDOWN};
use crate::trap::TrapFrame;
use crate::{kprintln, mmu, obj};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use metallium_sched::Class;

/// Boot-time tasks first, then slots for tasks created at run time (programs and their threads). This is the most a boot can have
/// (the lock ranks in sync.rs and the scheduler's task masks are sized by it); `limit()` is how many it does have.
pub const MAX_TASKS: usize = 1024;
/// The smallest number of task slots a boot gets, and the most it gets from RAM alone: one slot per MiB of RAM, so that the tables
/// (about 4 KiB a slot) stay a small part of memory. The fw_cfg file `opt/metallium/max-tasks` overrides it (within these bounds' outer limits).
pub const MIN_TASKS: usize = 64;

/// How many task slots a machine with `ram` bytes gets.
pub fn tasks_for(ram: usize, requested: Option<u64>) -> usize {
    match requested {
        Some(n) => (n as usize).clamp(MIN_TASKS, MAX_TASKS),
        None => (ram >> 20).clamp(MIN_TASKS, MAX_TASKS),
    }
}

/// How many task slots this boot has (at most `MAX_TASKS`): set by `init_tables`.
static LIMIT: AtomicUsize = AtomicUsize::new(0);

pub fn limit() -> usize {
    LIMIT.load(Ordering::Relaxed)
}
/// First slot that may hold a task created at run time.
pub const FIRST_DYNAMIC_TASK: usize = 27;
pub const USER_BASE: usize = 0x8000_0000;
/// Code and data of a program lie between `USER_BASE` and here (the loader's limit; the old stack position is kept out).
pub const IMAGE_END: usize = 0x800F_0000;
/// The stack is `STACK_PAGES` pages whose top is chosen at random inside this region (`random_stack_top`); the page
/// below the stack and the page at its top stay unmapped (guard pages: nothing maps into this region but the stack).
pub const STACK_REGION_LO: usize = 0x8040_0000;
pub const STACK_REGION_HI: usize = 0x8100_0000;
pub const STACK_PAGES: usize = 16;
/// Anonymous per-task heap window, grown on demand with HEAP_GROW. It starts a random number of pages (below
/// `HEAP_SLIDE_PAGES`) after `HEAP_BASE` and ends at `HEAP_END`, which leaves the page after the last heap page unmapped.
pub const HEAP_BASE: usize = 0x8100_0000;
pub const HEAP_SLIDE_PAGES: usize = 4096;
pub const HEAP_END: usize = 0x8F00_0000;
pub const MAX_HEAP_PAGES: usize = 512;
/// The storage servers (roles 6 and 7: the log-structured store and the file layer) stage a whole write in memory before it is committed, so the
/// largest file that can be installed is about what their heap holds: 2048 pages (8 MiB) takes a 2.6 MB package (512 pages took 1.3 MB).
pub const STORAGE_HEAP_PAGES: usize = 2048;
/// The console (role 13): its own heap and the window surfaces of its clients (about 47 MiB in all: the wallpaper and its frosted copy, the shade snapshot, caches, and up to four 3 MiB fullscreen surfaces; a cap, not a reservation).
pub const CONSOLE_HEAP_PAGES: usize = crate::platform::CONSOLE_HEAP_PAGES;
/// Where this program's stack starts: a random page-aligned top with `STACK_PAGES` pages below it, an unmapped page
/// below those and an unmapped page at the top and above.
pub fn random_stack_top() -> usize {
    let lo = STACK_REGION_LO + (STACK_PAGES + 1) * PAGE;
    let hi = STACK_REGION_HI - PAGE;
    lo + crate::rand::below((hi - lo) / PAGE + 1) * PAGE
}

pub fn random_heap_base() -> usize {
    HEAP_BASE + crate::rand::below(HEAP_SLIDE_PAGES) * PAGE
}

/// Benchmark task layout (spawn order in main.rs).
pub const NOT_PINNED: u8 = u8::MAX;
pub const FIRST_BENCH_SERVER: usize = 10;
pub const FIRST_BENCH_CLIENT: usize = 14;
/// The test conductor may hold far more (it exercises memory pressure).
pub const CONDUCTOR_HEAP_PAGES: usize = 60_000;
/// What a boot-time task may hand down to the programs it starts: the conductor (which runs the test suites) a good deal
/// of the machine, the others (shell, the programs task, the fuzzer) 32 MiB.
pub const CONDUCTOR_BUDGET_PAGES: usize = 30_000;
pub const ROLE_BUDGET_PAGES: usize = 8_192;
/// Where a task's submission/completion ring page is mapped (see ring.rs).
/// (the page is put at a random page of the 16 MiB from here, `RING_SLIDE_PAGES`)
pub const RING_VA: usize = 0x8F00_0000;
pub const RING_SLIDE_PAGES: usize = 4096;
/// Where the image of a position-independent program is put (`spawn::FLAG_PIE`): a random page in here, which is most of
/// the 39-bit address space (L1 entries 8..256: below the ECAM window, above the 4 GiB the SoC's devices may use).
pub const PIE_LO: usize = 0x2_0000_0000;
pub const PIE_HI: usize = 0x40_0000_0000;
/// The largest position-independent image: 8 MiB (a fixed one has to fit below the first mappings: `IMAGE_END`).
pub const PIE_MAX_IMAGE: usize = 8 << 20;
pub const SHM_LO: usize = 0x8020_0000;
pub const SHM_HI: usize = 0x8040_0000;
/// A second, large window for shared memory (512 MiB): for programs that map many big buffers.
pub const BIG_SHM_LO: usize = 0xA000_0000;
pub const BIG_SHM_HI: usize = 0xC000_0000;
pub const MAX_MAPS: usize = 64;
/// A task that keeps crashing is left dead rather than restarted forever.
/// A service may be restarted this many times in a row ...
const MAX_RESTARTS: u32 = 5;
/// ... but the count starts over once an instance has run this long (a driver that crashes once in a
/// while must not use up its budget for good; one that crashes in a loop still gives up).
const STABLE_TICKS: u64 = 300;

static USER_IMG: &[u8] = include_bytes!("../../user/build/user.elf");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Free,
    Ready,
    RecvWait(u16),
    CallWait,
    Sleep(u64),
    IrqWait(u8),
    /// Sleeping in RING_ENTER until this many completions are available.
    RingWait(u32),
    /// Blocked in WAIT for this child program to exit (spawn.rs).
    ChildWait(u16),
    /// Blocked in WAIT_WORD (thread.rs) until woken, or until the counter reaches this value (0 = no deadline).
    WordWait(u64),
    /// A program created by SPAWN whose code is still being loaded by its parent (spawn.rs); never scheduled.
    Embryo,
    Dead,
}

#[derive(Clone, Copy)]
pub struct MapRec {
    pub used: bool,
    pub va: usize,
    pub pages: usize,
    pub node: crate::cap::NodeId,
}


/// Everything about a task that other cores may change: behind the task's lock.
pub struct Task {
    pub l1: usize,
    pub caps: [Cap; NCAPS],
    pub maps: [MapRec; MAX_MAPS],
    pub heap_pages: usize,
    /// Thread stacks the kernel made (`THREAD_CREATE` with no stack): (lowest mapped address, pages, thread); pages are
    /// counted against the heap limit.
    pub tstacks: [(usize, usize, u16); crate::spawn::MAX_THREADS],
    /// This address space's randomised layout (see `random_stack_top`, `random_heap_base`); set when the space is built.
    pub stack_top: usize,
    pub heap_base: usize,
    pub ring_pa: usize,
    pub pending: [crate::ring::Pending; crate::ring::MAX_PENDING],
    /// (caller, async tag or 0) we still owe a reply to.
    pub reply_to: Option<(u16, u8)>,
    /// Server currently handling our outstanding call.
    pub callee: Option<u16>,
}

impl Task {
    /// Pages held against the program's heap limit (contiguous allocations are counted separately).
    pub fn held_pages(&self) -> usize {
        self.heap_pages + self.tstacks.iter().map(|s| s.1).sum::<usize>()
    }

    const EMPTY: Task = Task {
        l1: 0,
        caps: [Cap::NONE; NCAPS],
        maps: [MapRec { used: false, va: 0, pages: 0, node: 0 }; MAX_MAPS],
        heap_pages: 0,
        tstacks: [(0, 0, 0); crate::spawn::MAX_THREADS],
        stack_top: 0,
        heap_base: 0,
        ring_pa: 0,
        pending: [crate::ring::Pending::FREE; crate::ring::MAX_PENDING],
        reply_to: None,
        callee: None,
    };
}

static TASKS: crate::table::Table<SpinLock<Task>> = crate::table::Table::new();
/// Lock task `tid` (rank `R_TASK + tid`: when taking several, take them in ascending order).
pub fn lock(tid: usize) -> Guard<'static, Task> {
    TASKS[tid].lock(R_TASK + tid as u16)
}

/// A task's name: up to 15 bytes of printable ASCII, kept inside the `Info` so a copy of it stays valid when the slot is reused.
#[derive(Clone, Copy)]
pub struct Name {
    buf: [u8; 15],
    len: u8,
}

impl Name {
    pub const EMPTY: Name = Name { buf: [0; 15], len: 0 };

    /// From a string (cut at 15 bytes; anything not printable ASCII becomes `?`).
    pub fn new(s: &[u8]) -> Name {
        let mut n = Name::EMPTY;
        for &b in s.iter().take(15) {
            n.buf[n.len as usize] = if (0x20..0x7F).contains(&b) { b } else { b'?' };
            n.len += 1;
        }
        n
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("?") // (`new` keeps it ASCII)
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Facts about a task: set when the slot is filled (at boot, or by SPAWN while the slot is free) and, for the two limits, by QUOTA.
/// Read by copy (`info`), so no reference outlives the slot's use.
#[derive(Clone, Copy)]
pub struct Info {
    pub role: u8,
    pub restartable: bool,
    pub name: Name,
    pub class: Class,
    /// Core this task is confined to (`NOT_PINNED` = any).
    pub pinned: u8,
    /// Most pages this task may hold itself: heap plus contiguous allocations (`MC_ALLOC`).
    pub heap_quota: usize,
    /// Most pages this task may hand down to the programs it starts (their quotas, budgets and images; see spawn.rs).
    pub budget: usize,
}

static INFO: SlotTable<Info> = SlotTable::new();

pub fn info(tid: usize) -> Info {
    *INFO.read(tid)
}

// The two facts the scheduler reads for every candidate on every decision, kept where they can be read without the checked borrow of
// `INFO` (a shared read-modify-write per task per scan, which many cores contend for): written when the slot's `Info` is.
static CLASS: crate::table::Table<core::sync::atomic::AtomicU8> = crate::table::Table::new();
static PINNED: crate::table::Table<core::sync::atomic::AtomicU8> = crate::table::Table::new();

fn publish_info(tid: usize, class: Class, pinned: u8) {
    CLASS[tid].store(class as u8, Ordering::Relaxed);
    PINNED[tid].store(pinned, Ordering::Relaxed);
}

pub fn class_of(tid: usize) -> Class {
    match CLASS[tid].load(Ordering::Relaxed) {
        x if x == Class::Interactive as u8 => Class::Interactive,
        x if x == Class::Heavy as u8 => Class::Heavy,
        _ => Class::Background,
    }
}

pub fn pinned_of(tid: usize) -> u8 {
    PINNED[tid].load(Ordering::Relaxed)
}

static FRAMES: SlotTable<TrapFrame> = SlotTable::new();

/// The task's saved registers. Not behind a lock: whoever currently *owns* the task writes it.
/// That is the core running it (from kernel entry until its dispatch), or, while it is blocked,
/// the one waker that completed what it waits for (the endpoint / interrupt / ring lock that
/// hands the task over guarantees there is exactly one). The scheduler lock, taken after the
/// last write and before the task becomes runnable, publishes the contents to the next core.
///
/// The access is checked: while the returned guard lives, a second `frame(tid)` (on this core or another) panics instead of
/// handing out a second `&mut`.
pub fn frame(tid: usize) -> crate::sync::RefMut<'static, TrapFrame> {
    FRAMES.write(tid)
}

/// Root of the task's page tables, readable by the dispatcher without taking the task lock.
static L1: crate::table::Table<AtomicUsize> = crate::table::Table::new();
pub fn l1_of(tid: usize) -> usize {
    L1[tid].load(Ordering::Acquire)
}

pub static RESTARTS: crate::table::Table<AtomicU32> = crate::table::Table::new();
/// Restarts since the last stable period (what `MAX_RESTARTS` limits); `RESTARTS` stays cumulative.
static STREAK: crate::table::Table<AtomicU32> = crate::table::Table::new();
static LAST_RESTART: crate::table::Table<core::sync::atomic::AtomicU64> = crate::table::Table::new();
/// Timer ticks each task has run on each core.
pub static TICKS_ON: crate::table::Table<[AtomicU32; crate::smp::MAX_CPUS]> = crate::table::Table::new();
pub fn owner(tid: usize) -> mem::Owner {
    mem::OWNER_TASK0 + tid as u16
}

/// The task whose address space `tid` runs in: itself, unless it is a thread (thread.rs). Everything about memory — the
/// page tables, the mappings, the heap, the frames and who owns them — is kept under that task's lock and name.
static SPACE: crate::table::Table<core::sync::atomic::AtomicU16> = crate::table::Table::new();
pub fn aspace(tid: usize) -> usize {
    match SPACE[tid].load(Ordering::Acquire) {
        u16::MAX => tid,
        leader => leader as usize,
    }
}

/// Make `tid` a thread of the program `leader` (a free slot), or (`None`) an ordinary task again.
pub fn set_aspace(tid: usize, leader: Option<usize>) {
    SPACE[tid].store(leader.map_or(u16::MAX, |l| l as u16), Ordering::Release);
}

/// The tasks (including `leader`) that run in `leader`'s address space and are not gone.
pub fn members(leader: usize) -> impl Iterator<Item = usize> {
    (0..limit()).filter(move |&m| aspace(m) == leader && !matches!(sched::state(m), State::Free | State::Dead))
}

fn install(t: &mut Task, tid: usize, slot: usize, kind: Kind, obj: u16, rights: Rights) {
    let node = mint_node(None).expect("capability nodes exhausted");
    t.caps[slot] = Cap::new(kind, obj, rights, node);
    if kind == Kind::Endpoint && rights & R_RECV != 0 {
        sched::note_recv_endpoint(tid, obj);
    }
}

/// The interactive boot (`make run-window`, no test mode) starts the session service: its endpoint is installed in the conductor and the screen task.
fn sessions_in_boot() -> bool {
    crate::platform::interactive() && crate::platform::only() == 0
}

/// Initial capabilities per role: the kernel's static "system policy".
fn boot_caps(t: &mut Task, tid: usize, role: u8) {
    install(t, tid, crate::syscall::CONSOLE_SLOT, Kind::Console, 0, 0);
    // the driver tasks (roles 4, 12, 14, 18): what their devices' entries in the registry list
    crate::devices::grant_to_driver(role, |slot, kind, obj, rights| install(t, tid, slot, kind, obj, rights));
    match role {
        0 => {
            install(t, tid, 0, Kind::Endpoint, ipc::EP_SERVICE, R_SEND);
            install(t, tid, 1, Kind::Memory, 0, R_MAP | R_WRITE | R_GRANT);
            install(t, tid, 2, Kind::Endpoint, ipc::EP_DRIVER, R_SEND);
            if obj::blk_present() {
                // clients talk to the block driver and share its buffer (no INFO right: no physical addresses)
                install(t, tid, 3, Kind::Endpoint, ipc::EP_BLK, R_SEND);
                install(t, tid, 4, Kind::Memory, obj::OBJ_BLK_BUF_CLIENT, R_MAP | R_WRITE);
                install(t, tid, 5, Kind::Endpoint, ipc::EP_ROFS, R_SEND);
                install(t, tid, 6, Kind::Memory, obj::OBJ_SHM_ROFS, R_MAP | R_WRITE);
                install(t, tid, 7, Kind::Endpoint, ipc::EP_LFS, R_SEND | R_GRANT); // (grant: the conductor hands the data store's endpoint to the session service in `make session-test`)
                install(t, tid, 8, Kind::Memory, obj::OBJ_SHM_LFS, R_MAP | R_WRITE);
                install(t, tid, 9, Kind::Endpoint, ipc::EP_VFS, R_SEND);
                install(t, tid, 10, Kind::Memory, obj::OBJ_SHM_VFS_CLIENT, R_MAP | R_WRITE);
                install(t, tid, 11, Kind::MemCtl, 0, R_MEM_STATS | R_MEM_ALLOC | R_MEM_SWAP | R_MEM_PAGER | R_GRANT); // (grant: the memory-limit tests hand it to a program)
                // conductor may start each benchmark client and read their results (not in the interactive boot, which runs no benchmarks: its slots stay free, for the session service to hand
                // the conductor a session's manager endpoint)
                if !crate::platform::interactive() {
                    for k in 0..ipc::BENCH_PAIRS {
                        install(t, tid, 16 + k, Kind::Endpoint, ipc::EP_BENCH_GO + k as u16, R_SEND);
                    }
                    install(t, tid, 20, Kind::Memory, obj::OBJ_SHM_BENCH, R_MAP);
                }
            }
            if obj::blk_present() {
                // scheduler tests: start and stop the CPU burners, and reserve real-time shares
                if !crate::platform::interactive() {
                    install(t, tid, 24, Kind::Memory, obj::OBJ_SHM_SPIN, R_MAP | R_WRITE);
                }
                if matches!(crate::platform::only(), 13 | 14) || sessions_in_boot() {
                    // (the conductor starts the session service and hands it this endpoint: `make session-test`, `make greeter-test`, and the interactive boot. Not in the other
                    // runs: the conductor's capability table has no free slot to spare there, and the test that grants into its first free one must keep finding one)
                    install(t, tid, 29, Kind::Endpoint, ipc::EP_SESSIONS, R_SEND | R_RECV | R_GRANT);
                }
                install(t, tid, 25, Kind::Sched, 0, R_RT);
                // programs: the right to create them (and to pass it on), and a demo endpoint they may be given
                install(t, tid, 26, Kind::Spawn, 0, R_SPAWN | R_SPAWN_FS | R_SPAWN_NET | R_GRANT);
                install(t, tid, 12, Kind::Factory, 0, R_EP_CREATE | R_GRANT);
                install(t, tid, 27, Kind::Endpoint, ipc::EP_DRIVER, R_SEND | R_GRANT);
                install(t, tid, 28, Kind::Admin, 0, R_REVOKE | R_GRANT | R_POWER); // (the console session hands a copy to the program manager for the task manager, and one with only `R_POWER` to the console)
            }
            if crate::platform::chaos_seed() != 0 {
                // chaos mode: the conductor drives a workload against every service and starts the monkey
                install(t, tid, 14, Kind::Endpoint, ipc::EP_KBD, R_SEND);
                install(t, tid, 22, Kind::Endpoint, ipc::EP_MONKEY, R_SEND);
            } else if crate::platform::only() == 10 {
                install(t, tid, 14, Kind::Endpoint, ipc::EP_KBD, R_SEND); // (the USB input test: the conductor waits for input the way a desktop does)
            }
            if obj::gpu_present() {
                // the conductor talks to the display driver and to the screen task; it never holds the framebuffer
                install(t, tid, 21, Kind::Endpoint, ipc::EP_GPU, R_SEND);
                install(t, tid, 23, Kind::Endpoint, ipc::EP_INFO, R_SEND);
            }
        }
        // the input driver serves its endpoint whichever devices it found (virtio-input, a USB controller, or both)
        14 => install(t, tid, 0, Kind::Endpoint, ipc::EP_KBD, R_RECV),
        1 => install(t, tid, 0, Kind::Endpoint, ipc::EP_SERVICE, R_RECV),
        2 => install(t, tid, 0, Kind::Endpoint, ipc::EP_DRIVER, R_RECV),
        9 => install(t, tid, 0, Kind::MemCtl, 0, R_MEM_STATS | R_MEM_COMPACT | R_MEM_SWAP), // compactd
        10 => {
            // benchmark server `k = tid - FIRST_BENCH_SERVER`: serves its own endpoint, nothing else
            install(t, tid, 0, Kind::Endpoint, ipc::EP_BENCH_SRV + (tid - FIRST_BENCH_SERVER) as u16, R_RECV);
        }
        11 => {
            // benchmark client: calls its server, waits for a start message, reports in a shared page
            let k = (tid - FIRST_BENCH_CLIENT) as u16;
            install(t, tid, 0, Kind::Endpoint, ipc::EP_BENCH_SRV + k, R_SEND);
            install(t, tid, 1, Kind::Endpoint, ipc::EP_BENCH_GO + k, R_RECV);
            install(t, tid, 2, Kind::Memory, obj::OBJ_SHM_BENCH, R_MAP | R_WRITE);
        }
        16 => {
            // CPU burner for the scheduler tests: reads the conductor's go/stop flag, nothing else
            install(t, tid, 0, Kind::Memory, obj::OBJ_SHM_SPIN, R_MAP);
        }
        17 => {
            // the syscall fuzzer (user/src/fuzz.rs): a deliberately mixed bag, one grantable capability
            install(t, tid, 0, Kind::Endpoint, ipc::EP_SERVICE, R_SEND | R_GRANT);
            // (slot 1 stays empty: the demo driver crashes on demand, which is not a finding)
            install(t, tid, 2, Kind::Endpoint, ipc::EP_VFS, R_SEND);
            install(t, tid, 3, Kind::Memory, obj::OBJ_SHM_VFS_PROGRAM, R_MAP | R_WRITE);
            install(t, tid, 4, Kind::Endpoint, ipc::EP_BLK, R_SEND);
            install(t, tid, 5, Kind::MemCtl, 0, R_MEM_STATS | R_MEM_ALLOC | R_MEM_SWAP | R_MEM_COMPACT);
            install(t, tid, 6, Kind::Sched, 0, R_RT);
            install(t, tid, 7, Kind::Memory, obj::OBJ_SHM_SPIN, R_MAP);
            install(t, tid, 8, Kind::Endpoint, ipc::EP_KBD, R_SEND);
            install(t, tid, 9, Kind::Endpoint, ipc::EP_GPU, R_SEND);
            install(t, tid, 10, Kind::Endpoint, ipc::EP_ROFS, R_SEND);
            install(t, tid, 11, Kind::Endpoint, ipc::EP_LFS, R_SEND);
            install(t, tid, 12, Kind::Spawn, 0, R_SPAWN | R_SPAWN_FS | R_GRANT); // children with random images; they must die with it
            install(t, tid, 13, Kind::Factory, 0, R_EP_CREATE | R_GRANT); // endpoints, which must go back to the pool
        }
        15 => {
            // the chaos monkey: may kill service tasks, can be started only through its endpoint
            install(t, tid, 0, Kind::Admin, 0, R_KILL);
            install(t, tid, 1, Kind::Endpoint, ipc::EP_MONKEY, R_RECV);
            install(t, tid, 2, Kind::MemCtl, 0, R_MEM_STATS | R_MEM_SWAP); // and push random pages out to the swap store
        }
        13 => {
            // system-information screen: draws into the framebuffer, asks the display driver to
            // present, and asks the block driver how big the disk is. Nothing else.
            install(t, tid, 0, Kind::Endpoint, ipc::EP_INFO, R_RECV);
            install(t, tid, 1, Kind::Endpoint, ipc::EP_GPU, R_SEND);
            install(t, tid, 2, Kind::Memory, obj::OBJ_GPU_FB, R_MAP | R_WRITE);
            install(t, tid, 3, Kind::Endpoint, ipc::EP_BLK, R_SEND);
            // and, as the shell: the keyboard driver and one VFS client page
            install(t, tid, 4, Kind::Endpoint, ipc::EP_KBD, R_SEND);
            install(t, tid, 5, Kind::Endpoint, ipc::EP_VFS, R_SEND);
            install(t, tid, 6, Kind::Memory, obj::OBJ_SHM_VFS_SHELL, R_MAP | R_WRITE);
            // the right to unlock the encrypted data volume (the greeter asks for the passphrase and sends it here; the store accepts only the lock's calls from a task that
            // has no file page of its own, so this is no access to the files)
            install(t, tid, 30, Kind::Endpoint, ipc::EP_LFS, R_SEND);
            if crate::platform::only() == 14 || sessions_in_boot() {
                install(t, tid, 29, Kind::Endpoint, ipc::EP_SESSIONS, R_SEND); // (the greeter logs users in through it; only where the conductor starts a session service)
            }
            // the shell starts programs, with file access and a standard-output endpoint it creates itself
            install(t, tid, 8, Kind::Spawn, 0, R_SPAWN | R_SPAWN_FS | R_SPAWN_NET | R_GRANT); // (grant: the console hands them on to the programs that start programs)
            install(t, tid, 9, Kind::Factory, 0, R_EP_CREATE | R_GRANT);
            if obj::net_present() {
                // the shell's own network session (`download`, `play URL`): endpoint in slot 12, session page in slot 13
                if let Some(k) = crate::spawn::boot_net_page(tid) {
                    install(t, tid, 12, Kind::Endpoint, ipc::EP_NET, R_SEND);
                    install(t, tid, 13, Kind::Memory, obj::OBJ_SHM_NET_PROG0 + k as u16, R_MAP | R_WRITE);
                }
            }
        }
        19 => {
            // the network service: its endpoint, the packet buffers and ring it shares with the driver (no physical
            // addresses), the right to wake the driver, and the session pages of programs
            install(t, tid, 0, Kind::Endpoint, ipc::EP_NET, R_RECV);
            install(t, tid, 1, Kind::Memory, obj::OBJ_NET_BUFS, R_MAP | R_WRITE);
            install(t, tid, 2, Kind::Memory, obj::OBJ_NET_RING, R_MAP | R_WRITE);
            install(t, tid, 3, Kind::Irq, obj::IRQ_NET, R_SEND);
            install(t, tid, 16, Kind::Memory, obj::OBJ_SHM_NET_REGION, R_MAP | R_WRITE);
        }
        5 => {
            // read-only system filesystem server (EROFS)
            install(t, tid, 0, Kind::Endpoint, ipc::EP_ROFS, R_RECV);
            install(t, tid, 1, Kind::Endpoint, ipc::EP_BLK, R_SEND);
            install(t, tid, 2, Kind::Memory, obj::OBJ_BLK_BUF_ROFS, R_MAP | R_WRITE);
            install(t, tid, 3, Kind::Memory, obj::OBJ_SHM_ROFS, R_MAP | R_WRITE);
            install(t, tid, 4, Kind::Memory, obj::OBJ_SHM_ROFS_VFS, R_MAP | R_WRITE);
        }
        6 => {
            // log-structured data store server
            install(t, tid, 0, Kind::Endpoint, ipc::EP_LFS, R_RECV);
            install(t, tid, 1, Kind::Endpoint, ipc::EP_BLK, R_SEND);
            install(t, tid, 2, Kind::Memory, obj::OBJ_BLK_BUF_LFS, R_MAP | R_WRITE);
            install(t, tid, 3, Kind::Memory, obj::OBJ_SHM_LFS, R_MAP | R_WRITE);
            install(t, tid, 4, Kind::Memory, obj::OBJ_SHM_LFS_VFS, R_MAP | R_WRITE);
        }
        7 => {
            // VFS server: the only task (besides the test conductor) that talks to both filesystems
            install(t, tid, 0, Kind::Endpoint, ipc::EP_VFS, R_RECV);
            install(t, tid, 1, Kind::Endpoint, ipc::EP_ROFS, R_SEND);
            install(t, tid, 2, Kind::Memory, obj::OBJ_SHM_ROFS_VFS, R_MAP | R_WRITE);
            install(t, tid, 3, Kind::Endpoint, ipc::EP_LFS, R_SEND);
            install(t, tid, 4, Kind::Memory, obj::OBJ_SHM_LFS_VFS, R_MAP | R_WRITE);
            install(t, tid, 5, Kind::Memory, obj::OBJ_SHM_VFS_CLIENT, R_MAP | R_WRITE);
            install(t, tid, 6, Kind::Memory, obj::OBJ_SHM_VFS_PROGRAM, R_MAP | R_WRITE);
            install(t, tid, 7, Kind::Memory, obj::OBJ_SHM_VFS_SHELL, R_MAP | R_WRITE);
            // the session pages of programs with file-system access (see spawn.rs)
            install(t, tid, 16, Kind::Memory, obj::OBJ_SHM_VFS_REGION, R_MAP | R_WRITE);
        }
        8 => {
            // an ordinary application: a VFS endpoint and its own page, nothing else
            install(t, tid, 0, Kind::Endpoint, ipc::EP_VFS, R_SEND);
            install(t, tid, 1, Kind::Memory, obj::OBJ_SHM_VFS_PROGRAM, R_MAP | R_WRITE);
            // (and the burners' flag page: in the scheduler tests the otherwise idle program is an Interactive CPU hog)
            install(t, tid, 2, Kind::Memory, obj::OBJ_SHM_SPIN, R_MAP);
        }
        _ => {}
    }
    // what only this machine has (its own devices' windows, the audio service): the platform adds them to the roles that use them
    crate::platform::boot_caps(role, &mut |slot, kind, obj, rights| install(t, tid, slot, kind, obj, rights));
}


/// A random base for a position-independent image (`spawn::FLAG_PIE` and the boot-time programs): a page in `PIE_LO..PIE_HI`
/// with room for `PIE_MAX_IMAGE` after it.
pub fn random_pie_base() -> usize {
    PIE_LO + crate::rand::below((PIE_HI - PIE_LO - PIE_MAX_IMAGE) / PAGE + 1) * PAGE
}

fn build(t: &mut Task, tid: usize) -> Result<(), &'static str> {
    let own = owner(tid);
    // The boot-time programs are one position-independent ELF file, read by the same loader that user programs go through
    // and put at a fresh random base each time a task is built (a restarted service moves).
    let mut plan = metallium_loader::plan(USER_IMG).map_err(|_| "bad user image")?;
    if !plan.is_pie() {
        return Err("user image not position-independent");
    }
    let base = random_pie_base();
    plan.rebase(base);
    let l1 = mmu::new_space(own).ok_or("out of memory")?;
    for (va, page, flags) in plan.pages(USER_IMG) {
        let pa = mem::alloc_movable(own, tid, va).ok_or("out of memory")?;
        crate::frame::phys::copy_to(pa, &page[..PAGE]);
        let perm = if flags & metallium_loader::X != 0 {
            mmu::Perm::Rx
        } else if flags & metallium_loader::W != 0 {
            mmu::Perm::Rw
        } else {
            mmu::Perm::Ro
        };
        mmu::map_user(l1, va, pa, perm, own).map_err(|_| "map failed")?;
        if flags & metallium_loader::X != 0 {
            mmu::sync_icache(pa, PAGE);
        }
    }
    let stack_top = random_stack_top();
    for i in 0..STACK_PAGES {
        let pa = mem::alloc_movable(own, tid, stack_top - (i + 1) * PAGE).ok_or("out of memory")?;
        mmu::map_user(l1, stack_top - (i + 1) * PAGE, pa, mmu::Perm::Rw, own).map_err(|_| "map failed")?;
    }
    t.stack_top = stack_top;
    t.heap_base = random_heap_base();
    t.l1 = l1;
    L1[tid].store(l1, Ordering::Release);
    let mut f = frame(tid);
    *f = TrapFrame::ZERO;
    f.x[0] = info(tid).role as u64;
    f.x[1] = tid as u64; // instance number for roles with several copies
    f.sp = stack_top as u64;
    f.elr = plan.entry_addr() as u64;
    f.spsr = 0; // EL0t, interrupts enabled
    t.caps = [Cap::NONE; NCAPS];
    t.maps = [MapRec { used: false, va: 0, pages: 0, node: 0 }; MAX_MAPS];
    t.heap_pages = 0;
    t.tstacks = [(0, 0, 0); crate::spawn::MAX_THREADS];
    t.ring_pa = 0;
    t.pending = [crate::ring::Pending::FREE; crate::ring::MAX_PENDING];
    t.reply_to = None;
    t.callee = None;
    sched::forget_recv_endpoints(tid);
    crate::spawn::restrict_boot_task(tid, info(tid).role);
    boot_caps(t, tid, info(tid).role);
    sched::set_state(tid, State::Ready);
    Ok(())
}

/// Describe a task about to be created at run time in slot `tid` (which is free, so nobody uses its entry).
pub fn set_dynamic_info(tid: usize, role: u8, name: &[u8; 8], class: Class, heap_pages: usize, budget: usize) {
    let n = name.iter().position(|&b| b == 0).unwrap_or(8);
    let name = if n == 0 { Name::new(b"prog") } else { Name::new(&name[..n]) };
    *INFO.write(tid) = Info { role, restartable: false, name, class, pinned: NOT_PINNED, heap_quota: heap_pages, budget };
    publish_info(tid, class, NOT_PINNED);
}

/// Change a program's limits (`QUOTA`): done under its task lock, which is what `heap_grow` reads them under.
pub fn set_limits(tid: usize, heap_quota: usize, budget: usize) {
    let mut i = INFO.write(tid);
    i.heap_quota = heap_quota;
    i.budget = budget;
}

/// Publish the page-table root of a task built at run time (see spawn.rs).
pub fn set_l1(tid: usize, l1: usize) {
    L1[tid].store(l1, Ordering::Release);
}

/// Boot-time only (single core): create a task and make it runnable.
pub fn spawn(role: u8, name: &'static str, class: Class, restartable: bool) -> usize {
    let tid = (0..limit()).find(|&i| sched::state(i) == State::Free).expect("no free task slot");
    let core = sched::assign_core(class);
    sched::init_task(tid, core);
    let mut i = Info {
        role,
        restartable,
        name: Name::new(name.as_bytes()),
        class,
        pinned: NOT_PINNED,
        heap_quota: match role {
            0 => CONDUCTOR_HEAP_PAGES,
            // the console holds its clients' window surfaces (shared memory it creates, charged to it) as well as its own heap
            13 => CONSOLE_HEAP_PAGES,
            6 | 7 => STORAGE_HEAP_PAGES,
            _ => MAX_HEAP_PAGES,
        },
        budget: if role == 0 { CONDUCTOR_BUDGET_PAGES } else { ROLE_BUDGET_PAGES },
    };
    // Benchmark pair k runs entirely on core k: no cross-core wakeups, no placement noise.
    if role == 10 {
        i.pinned = (tid - FIRST_BENCH_SERVER) as u8;
    } else if role == 11 {
        i.pinned = (tid - FIRST_BENCH_CLIENT) as u8;
    }
    publish_info(tid, i.class, i.pinned);
    *INFO.write(tid) = i;
    let mut t = lock(tid);
    build(&mut t, tid).expect("failed to build task");
    kprintln!("[kernel] spawned task {tid} '{name}' ({class:?}) on core {core} ({:?})", sched::core_kind(core));
    if crate::rand::deterministic() {
        kprintln!("[kernel] layout of task {tid}: stack top {:#x}, heap {:#x}", t.stack_top, t.heap_base);
    }
    tid
}

/// Serialises the lifecycle operations: a capability subtree revoked, a task dying, and the system calls that create, wait for, or put
/// capabilities into other tasks (`lifecycle`: SPAWN, WAIT, THREAD_CREATE, TASK_START, CAP_GRANT, RESTORE_OF). Those look at a task's state
/// under its lock and then act, which is only sound if the end of that task cannot slip in between, so they exclude each other. But
/// the teardown no longer freezes the whole machine: it takes the one endpoint or task lock it needs at the moment it needs it, and the
/// hot paths (IPC, memory syscalls, rings) go on in between. What makes that safe: a capability's node is killed atomically
/// *first* (`cap::kill_subtree`: nothing can be used or minted under it from then on), and only then are the tasks' tables swept; and a
/// dying task is cut off from the endpoints (no more waking it, no more calls linked to it) before anyone who relied on it is told.
/// (Rank `R_TEARDOWN`: outside every endpoint and task lock, inside SPAWN's.)
static TEARDOWN: SpinLock<()> = SpinLock::new(());

pub struct World {
    _only: Guard<'static, ()>,
}

/// Hold the lifecycle lock (see `TEARDOWN`): taken before any task lock, for the whole of a system call that creates, waits for or hands
/// capabilities to another task.
pub fn lifecycle() -> Guard<'static, ()> {
    TEARDOWN.lock(R_TEARDOWN)
}

impl World {
    pub fn lock() -> World {
        World { _only: lifecycle() }
    }

    /// Kill capabilities derived from `root` everywhere: clear table slots,
    /// unmap shared memory that was mapped through them, free the nodes.
    pub fn revoke_subtree(&mut self, root: crate::cap::NodeId, include_root: bool) -> usize {
        let mut marked = NodeSet::EMPTY;
        let n = crate::cap::kill_subtree(root, include_root, &mut marked);
        self.finish_revoke(&marked);
        n
    }

    /// The nodes in `marked` are dead (`cap::kill_subtree`): clear them out of every table, then free their numbers.
    fn finish_revoke(&mut self, marked: &NodeSet) {
        if !marked.any() {
            return;
        }
        // (the endpoints on which a receive capability is being revoked: a task asleep in receive on one must not sleep for ever)
        let mut hit = [0u64; ipc::MAX_EPS.div_ceil(64)];
        // (a free slot holds nothing, and a task made after the nodes were marked cannot get a capability under them: the sweep skips it)
        for tid in (0..limit()).filter(|&t| sched::state(t) != State::Free) {
            let mut t = lock(tid);
            for c in t.caps.iter_mut() {
                if c.kind != Kind::None && marked.has(c.node as usize) {
                    if c.kind == Kind::Endpoint && c.rights & R_RECV != 0 {
                        hit[c.obj as usize / 64] |= 1 << (c.obj % 64);
                    }
                    *c = Cap::NONE;
                }
            }
            for m in 0..MAX_MAPS {
                let rec = t.maps[m];
                if rec.used && marked.has(rec.node as usize) {
                    if t.l1 != 0 {
                        for p in 0..rec.pages {
                            mmu::unmap_user(t.l1, rec.va + p * PAGE);
                        }
                    }
                    t.maps[m].used = false;
                }
            }
        }
        // Whoever sleeps in receive on one of those endpoints and has no receive capability left for it is told. (The sweep is done, so
        // a task that held only revoked ones is found without any; one that holds another, still alive, goes on waiting.)
        for e in (0..ipc::nep()).filter(|&e| hit[e / 64] >> (e % 64) & 1 != 0) {
            let mut ep = ipc::lock_ep(e as u16);
            let Some(r) = ep.waiter else { continue };
            let r = r as usize;
            let still = lock(r).caps.iter().any(|c| c.kind == Kind::Endpoint && c.obj as usize == e && c.rights & R_RECV != 0 && c.alive());
            if !still {
                ep.waiter = None;
                frame(r).x[0] = crate::syscall::E_BADCAP as u64;
                sched::wake_if(r, State::RecvWait(e as u16));
            }
        }
        crate::ipc::destroy_marked(marked);
        crate::cap::free_marked(marked);
        mmu::flush_tlb();
        self.sweep_orphans();
    }

    /// Does any task still hold a live capability on shared-memory object `id`?
    fn memory_held(id: u16) -> bool {
        (0..limit()).filter(|&t| sched::state(t) != State::Free).any(|t| lock(t).caps.iter().any(|c| c.kind == Kind::Memory && c.obj == id && c.alive()))
    }

    /// Shared memory whose creator is gone is freed when nothing holds it any more.
    fn sweep_orphans(&mut self) {
        let mut from = 0;
        while let Some(id) = obj::next_orphan(from, None) {
            from = id as usize + 1;
            if !Self::memory_held(id) {
                obj::shm_destroy(id);
            }
        }
    }

    /// Program `leader` is ending: the shared memory it made that outlived its own capability (held by others) is charged to it still, and the
    /// charge is about to go. Give each such object to a program that holds it and can pay for it (it counts against that program's limit from
    /// now on); if no holder can, the object ends with its creator, and every holder's copy and mapping with it.
    fn hand_over_orphans(&mut self, leader: usize) {
        let mut from = 0;
        while let Some(id) = obj::next_orphan(from, Some(leader)) {
            from = id as usize + 1;
            let Some(o) = obj::get(id) else { continue };
            let mut taken = false;
            for h in 0..limit() {
                let q = aspace(h);
                if q == leader || matches!(sched::state(h), State::Free | State::Dead) {
                    continue;
                }
                if !lock(h).caps.iter().any(|c| c.kind == Kind::Memory && c.obj == id && c.alive()) {
                    continue;
                }
                let held = lock(q).held_pages();
                if crate::spawn::reserve_contig(q, held, o.pages) {
                    obj::shm_charge_to(id, q);
                    taken = true;
                    break;
                }
            }
            if !taken {
                let mut marked = NodeSet::EMPTY;
                for h in 0..limit() {
                    let t = lock(h);
                    let nodes: [Option<crate::cap::NodeId>; NCAPS] =
                        core::array::from_fn(|i| Some(t.caps[i]).filter(|c| c.kind == Kind::Memory && c.obj == id && c.alive()).map(|c| c.node));
                    drop(t);
                    for node in nodes.into_iter().flatten() {
                        crate::cap::kill_subtree(node, true, &mut marked);
                    }
                }
                self.finish_revoke(&marked);
                obj::shm_destroy(id);
            }
        }
    }

    /// Tear a task down: kill its capability subtrees and every link to it. (Its memory is `reclaim_space`, once
    /// nothing runs in the address space any more.)
    ///
    /// First the task is cut off from the endpoints (it is no longer woken by a sender, and the calls it had queued are dropped), so that no
    /// new link to it can form; then everyone still linked to it is told.
    fn reset(&mut self, tid: usize) {
        // (it can only be asleep in receive on an endpoint it holds a receive capability for; and only an endpoint with something queued can
        // hold calls of its to drop)
        let held = lock(tid).caps;
        for c in held.iter().filter(|c| c.kind == Kind::Endpoint && c.rights & R_RECV != 0) {
            let mut ep = ipc::lock_ep(c.obj);
            if ep.waiter == Some(tid as u16) {
                ep.waiter = None;
            }
        }
        for e in (0..ipc::nep()).filter(|&e| ipc::has_queued(e)) {
            ipc::lock_ep(e as u16).purge_calls_from(e as u16, tid as u16);
        }
        // Callers waiting for this task to reply (only a task in `CallWait` can be one) and async calls it was handling (only if any are
        // outstanding anywhere).
        for c in (0..limit()).filter(|&c| sched::state(c) == State::CallWait) {
            let mut t = lock(c);
            if t.callee == Some(tid as u16) && sched::state(c) == State::CallWait {
                t.callee = None;
                frame(c).x[0] = crate::syscall::E_DEAD as u64;
                sched::wake(c);
            }
        }
        if crate::ring::async_ops_outstanding() {
            for c in 0..limit() {
                crate::ring::fail_calls_to(&mut lock(c), c, tid);
            }
        }
        // The servers that still hold a reply link to it are the ones its own calls are linked to (a link is made on both sides at once).
        let (callee, pending): (Option<u16>, [Option<u16>; crate::ring::MAX_PENDING]) = {
            let t = lock(tid);
            (t.callee, core::array::from_fn(|i| t.pending[i].callee))
        };
        for s in callee.into_iter().chain(pending.into_iter().flatten()) {
            let mut t = lock(s as usize);
            if t.reply_to.map_or(false, |(who, _)| who == tid as u16) {
                t.reply_to = None;
            }
        }
        // Its capabilities, all revoked in one sweep of the tasks. Memory objects that need their own bookkeeping get it as their
        // capability comes up; what must wait for the sweep (freeing an object nobody holds) is done after it.
        let mut pending = NodeSet::EMPTY;
        let mut destroy = [None; NCAPS];
        for slot in 0..NCAPS {
            let c = lock(tid).caps[slot];
            if c.kind == Kind::None || !c.alive() {
                continue; // (or revoked already, with an ancestor, a moment ago in this very loop)
            }
            // memory from MC_ALLOC is private to its task (the capability has no GRANT right): its frames go
            // below with the rest, but the object-table entry would stay taken for ever (found by the fuzzer)
            if c.kind == Kind::Memory && obj::is_dynamic(c.obj) {
                match obj::get(c.obj) {
                    // The creator of shared memory is going. With no holders the memory goes too; with holders it
                    // lives on without a creator until the last of them lets go (a holder's own copy, or a thread's,
                    // just goes with the revocation below).
                    Some(o) if o.kind == obj::ObjKind::Shared => {
                        if o.root == c.node {
                            let mut holders = NodeSet::EMPTY;
                            if mark_subtree(c.node, false, &mut holders) > 0 {
                                obj::shm_orphan(c.obj);
                                crate::cap::detach_children(c.node);
                            } else {
                                destroy[slot] = Some(c.obj);
                            }
                        }
                    }
                    // (a copy of a run-time object's capability, a thread's, ends with the copy: the object stays with the creator's)
                    Some(o) if o.root != c.node => {}
                    _ => obj::release(c.obj),
                }
            }
            crate::cap::kill_subtree(c.node, true, &mut pending);
        }
        self.finish_revoke(&pending);
        for id in destroy.into_iter().flatten() {
            obj::shm_destroy(id);
        }
        {
            let mut t = lock(tid);
            t.caps = [Cap::NONE; NCAPS];
            t.reply_to = None;
            t.callee = None;
            crate::ring::reset_task(&mut t);
        }
        crate::irq::forget(tid as u16);
        crate::cap::forget_granter(tid);
        crate::cap::forget_revoked(tid);
    }

    /// Free an address space: its mappings, the pages in the swap store and every frame it owns. The last task that
    /// ran in it calls this.
    fn reclaim_space(&mut self, leader: usize) -> usize {
        self.hand_over_orphans(leader);
        let mut t = lock(leader);
        t.maps = [MapRec { used: false, va: 0, pages: 0, node: 0 }; MAX_MAPS];
        if t.l1 != 0 {
            crate::swap::release_task(t.l1); // pages in the swap store go with the frames
        }
        // The tables are freed with the frames below: nothing may walk them again. (Every user of `l1` already reads 0 as "no address space"; a
        // restarted service or a new program gets a root of its own from `build` or `spawn`.)
        t.l1 = 0;
        let n = mem::free_owned(owner(leader));
        crate::spawn::forget_usage(leader);
        mmu::flush_tlb();
        n
    }
}

/// Condemn every live task running `role` (see `sched::doom`).
pub fn condemn_role(role: u8, why: sched::Doom) -> usize {
    let mut n = 0;
    for tid in 0..limit() {
        // a dead task has nothing to kill (and a stale flag on it would hit its next instance)
        if !matches!(sched::state(tid), State::Free | State::Dead) && info(tid).role == role {
            sched::doom(tid, why);
            n += 1;
        }
    }
    n
}

/// A task faulted or exited: reclaim its resources, unblock anyone waiting
/// on it, and restart it if policy says so. A thread that dies this way takes the whole program with it.
pub fn die(tid: usize, why: &str) {
    die_as(tid, why, true, None)
}

/// A thread asked to end (THREAD_EXIT): only it goes. Once its slot is free, `exit_word` (address, value) is stored in
/// its program's memory and everyone waiting on it woken: a thread that has been joined is entirely gone.
pub fn die_thread(tid: usize, exit_word: (usize, u32)) {
    die_as(tid, "thread exit", false, Some(exit_word))
}

fn die_as(tid: usize, why: &str, program_dies: bool, exit_word: Option<(usize, u32)>) {
    // This core is still running on the dying task's page tables: leave them before they are freed.
    mmu::use_kernel_tables();
    let leader = aspace(tid);
    if !(crate::spawn::is_program(tid) && why == "exited") && !(leader != tid && !program_dies) {
        kprintln!("[kernel] task {tid} '{}' terminated: {why}", info(tid).name);
    }
    let mut w = World::lock();
    for sid in obj::sids_of_role(info(tid).role).into_iter().flatten() {
        crate::smmu::detach(sid); // the device is cut off until a new driver instance is given its pages
    }
    w.reset(tid);
    // Who else still runs in this address space? If the program is dying they are condemned, and the memory stays
    // until the last of them is gone (a thread on another core may be using it right now).
    let mut others = 0;
    for m in members(leader).filter(|&m| m != tid) {
        others += 1;
        if program_dies {
            sched::doom(m, sched::Doom::Parent);
        }
    }
    let last = others == 0;
    let freed = if last { w.reclaim_space(leader) } else { 0 };
    sched::clear_doom(tid);
    L1[tid].store(0, Ordering::Release);
    sched::clear_inherit(tid);
    sched::forget_task(tid);
    if leader != tid {
        // a thread leaves nothing behind for anyone to collect: its slot is free at once
        crate::spawn::thread_gone(tid, leader);
        if !last {
            crate::spawn::free_thread_stack(&mut lock(leader), tid);
        }
        if let (Some((va, value)), false) = (exit_word, last) {
            crate::thread::store_and_wake(&lock(leader), leader, va, value);
        }
    } else {
        sched::set_state(tid, State::Dead);
    }
    let now = crate::timer::ticks();
    if now.saturating_sub(LAST_RESTART[tid].load(Ordering::Relaxed)) >= STABLE_TICKS {
        STREAK[tid].store(0, Ordering::Relaxed);
    }
    // any task's children go with it; a program's own slot is freed or kept for its parent to collect once the
    // last of its threads is gone
    crate::spawn::on_death(&mut w, tid, if last { Some(leader) } else { None });
    if crate::spawn::is_program(tid) || leader != tid {
        // (no restarts: a program is its parent's business)
    } else if info(tid).restartable && STREAK[tid].load(Ordering::Relaxed) < MAX_RESTARTS {
        match build(&mut lock(tid), tid) {
            Ok(()) => {
                STREAK[tid].fetch_add(1, Ordering::Relaxed);
                LAST_RESTART[tid].store(now, Ordering::Relaxed);
                let n = RESTARTS[tid].fetch_add(1, Ordering::Relaxed) + 1;
                kprintln!("[kernel] reclaimed {freed} pages; restarted '{}' (restart #{n})", info(tid).name);
            }
            Err(e) => kprintln!("[kernel] restart of '{}' failed: {e}", info(tid).name),
        }
    } else {
        kprintln!("[kernel] reclaimed {freed} pages from '{}'", info(tid).name);
    }
}

/// Carve this module's per-task tables (`n` tasks); called once from `task::init_tables`.
pub fn init_tables(n: usize) {
    assert!((1..=MAX_TASKS).contains(&n) && limit() == 0, "task tables: bad size or initialised twice");
    LIMIT.store(n, Ordering::Relaxed);
    crate::sched::init_tables(n);
    crate::spawn::init_tables(n);
    crate::thread::init_tables(n);
    crate::ring::init_tables(n);
    crate::ipc::init_tables(crate::ipc::eps_for(n));
    TASKS.init(n, |_| const { SpinLock::new(Task::EMPTY) });
    L1.init(n, |_| const { AtomicUsize::new(0) });
    RESTARTS.init(n, |_| const { AtomicU32::new(0) });
    STREAK.init(n, |_| const { AtomicU32::new(0) });
    LAST_RESTART.init(n, |_| const { core::sync::atomic::AtomicU64::new(0) });
    TICKS_ON.init(n, |_| const { [const { AtomicU32::new(0) }; crate::smp::MAX_CPUS] });
    SPACE.init(n, |_| const { core::sync::atomic::AtomicU16::new(u16::MAX) });
    CLASS.init(n, |_| core::sync::atomic::AtomicU8::new(Class::Background as u8));
    PINNED.init(n, |_| core::sync::atomic::AtomicU8::new(NOT_PINNED));
    INFO.init(n, |_| Info { role: 0, restartable: false, name: Name::EMPTY, class: Class::Background, pinned: NOT_PINNED, heap_quota: MAX_HEAP_PAGES, budget: 0 });
    FRAMES.init(n, |_| TrapFrame::ZERO);
}
