//! Tasks created at run time: `SPAWN` makes an *embryo* (a task with stack, arguments and capabilities but no code),
//! `TASK_LOAD` and `TASK_START` fill and start it, `WAIT` collects a child's exit code, `KILL` ends it. The kernel reads
//! no executable format: the loader (`libs/metallium-loader`) runs in the parent and turns an image into page loads.
//!
//! A program runs in the first free slot from `FIRST_DYNAMIC_TASK` on, as a non-restartable task of role `ROLE_PROGRAM`.
//! What it may do is exactly what its parent delegated: up to eight capabilities, chosen by slot and only if the parent
//! holds them with the grant right (the grant right itself is not passed on), plus the console. The parent owns the child:
//!
//!  * `WAIT` blocks until the child is gone and returns its exit code (the `EXIT` argument; `EXIT_FAULTED` if it was
//!    killed by a fault, `EXIT_KILLED` if killed). A finished child stays a zombie (slot taken, memory returned)
//!    until its parent waits for it.
//!  * When a task with children dies, its children are killed and their slots freed as they die: nothing is left
//!    behind that nobody could wait for.
//!  * A child may be given the spawn capability itself (delegated like any other), so programs can start programs.
//!
//! Everything a child held — frames, page tables, capabilities, derived nodes — is reclaimed by the same code that
//! reclaims a crashed service, so slots can be reused indefinitely (the fuzzer and the tests count frames, capability
//! nodes and memory objects before and after).
#![forbid(unsafe_code)]
use crate::cap::*;
use crate::mem::{self, PAGE};
use crate::mmu;
use crate::sched;
use crate::sync::{SpinLock, R_SPAWNING};
use crate::task::{self, frame, lock, MapRec, State, World, FIRST_DYNAMIC_TASK, IMAGE_END, STACK_PAGES, USER_BASE};
use crate::trap::TrapFrame;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use metallium_sched::Class;

pub const ROLE_PROGRAM: u8 = 32;
/// A thread: a task that runs in another task's address space (see `thread_create`).
pub const ROLE_THREAD: u8 = 33;
pub const NO_PARENT: u16 = u16::MAX;
pub const EXIT_FAULTED: u64 = u64::MAX;
pub const EXIT_KILLED: u64 = u64::MAX - 1;
/// Delegation word: byte `i` is the parent's slot to give the child as its slot `i`; `NONE` skips.
pub const DELEG_NONE: u8 = 0xFF;
const MAX_DELEG: usize = 8;
/// Most heap a program may be given (pages), and what it gets by default.
const MAX_HEAP: usize = 16384;
const DEFAULT_HEAP: usize = 256;
/// Most programs one program may have at a time (zombies and embryos count), and the same for a boot-time task.
const MAX_CHILDREN_PROGRAM: usize = 8;
/// A boot-time task (the shell, the program manager) is trusted with as many programs at once as there are slots (at least this many).
const MAX_CHILDREN_ROLE: usize = 64;
/// What every program costs its parent's budget on top of its heap quota and its own budget: its stack and page tables.
const OVERHEAD: usize = STACK_PAGES + 8;
/// Largest budget a request may give.
const MAX_BUDGET: usize = 1 << 20;
/// Largest image (the address space below the stack).
const MAX_IMAGE: usize = IMAGE_END - USER_BASE;

pub const E_INVAL: i64 = crate::syscall::E_INVAL;
pub const E_FULL: i64 = crate::syscall::E_FULL;
pub const E_NOMEM: i64 = crate::syscall::E_NOMEM;
pub const E_PERM: i64 = crate::syscall::E_PERM;
pub const E_AGAIN: i64 = -10;

/// Counts up each time the slot is made into a new program (`spawn`, before it becomes an embryo). `task_load` runs for a long time and
/// lets go of the child's lock between pages; it remembers the epoch it started in, so that a child that was killed, collected and
/// replaced by another embryo of the same parent is not mistaken for the one it was loading.
static EPOCH: crate::table::Table<AtomicU32> = crate::table::Table::new();
static PARENT: crate::table::Table<AtomicU16> = crate::table::Table::new();
static EXIT_CODE: crate::table::Table<AtomicU64> = crate::table::Table::new();
static SPAWNING: SpinLock<()> = SpinLock::new(());
/// Per program: how many threads it may have, and how many it has now.
static THREAD_QUOTA: crate::table::Table<AtomicU8> = crate::table::Table::new();
static EXTRA: crate::table::Table<AtomicU8> = crate::table::Table::new();
// ---- memory budgets ----------------------------------------------------------------------------------------------------
//
// A task has two limits: `heap_quota` (pages it may hold itself: heap plus contiguous allocations) and `budget` (pages it
// may hand down). Starting a program costs its parent `heap + budget + OVERHEAD`, plus one page for every page of image
// loaded into it; the cost is returned when the program dies. So a tree of programs can never hold more than the root's
// budget, whatever any of them does: each can only give away what it was given. The conductor, the shell and the other
// boot-time tasks have fixed budgets (task.rs). All of this is bookkeeping with atomics: no new lock.

/// Per task: budget handed down to live children; what this program costs its parent (0 once refunded); contiguous
/// pages (`MC_ALLOC`) it holds.
static DELEGATED: crate::table::Table<AtomicUsize> = crate::table::Table::new();
static CHARGE: crate::table::Table<AtomicUsize> = crate::table::Table::new();
static CONTIG: crate::table::Table<AtomicUsize> = crate::table::Table::new();
fn try_charge(parent: usize, cost: usize) -> bool {
    let budget = task::info(parent).budget;
    let mut d = DELEGATED[parent].load(Ordering::SeqCst);
    loop {
        let Some(n) = d.checked_add(cost).filter(|&n| n <= budget) else { return false };
        match DELEGATED[parent].compare_exchange(d, n, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(now) => d = now,
        }
    }
}

fn uncharge(parent: usize, cost: usize) {
    let _ = DELEGATED[parent].try_update(Ordering::SeqCst, Ordering::SeqCst, |d| Some(d.saturating_sub(cost)));
}

/// Return a dead (or never started) program's cost to its parent, once.
fn refund(child: usize) {
    let c = CHARGE[child].swap(0, Ordering::SeqCst);
    let p = PARENT[child].load(Ordering::SeqCst);
    if c > 0 && p != NO_PARENT {
        uncharge(p as usize, c);
    }
}

/// Add `n` to a live program's cost (false if it has been refunded: it is gone).
fn add_charge(child: usize, n: usize) -> bool {
    let mut c = CHARGE[child].load(Ordering::SeqCst);
    loop {
        if c == 0 {
            return false;
        }
        match CHARGE[child].compare_exchange(c, c + n, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(now) => c = now,
        }
    }
}

fn children_of(p: usize) -> usize {
    (FIRST_DYNAMIC_TASK..task::limit()).filter(|&c| PARENT[c].load(Ordering::SeqCst) == p as u16).count()
}

/// The address space `a` has been emptied: what it held and what it handed down are gone.
pub fn forget_usage(a: usize) {
    CONTIG[a].store(0, Ordering::SeqCst);
    DELEGATED[a].store(0, Ordering::SeqCst);
}

/// Contiguous pages the program holds (`heap_grow` counts them against the same limit as its heap).
pub fn contig_pages(a: usize) -> usize {
    CONTIG[a].load(Ordering::SeqCst)
}

/// Claim `n` contiguous pages for program `a`, which holds `heap` heap pages (called under its task lock, like `heap_grow`).
pub fn reserve_contig(a: usize, heap: usize, n: usize) -> bool {
    // (look, check and add as one step: with a separate load and add, two threads could both see room for one more and both take it)
    let quota = task::info(a).heap_quota;
    CONTIG[a]
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |c| heap.saturating_add(c).checked_add(n).filter(|&t| t <= quota).map(|_| c + n))
        .is_ok()
}

pub fn release_contig(a: usize, n: usize) {
    let _ = CONTIG[a].try_update(Ordering::SeqCst, Ordering::SeqCst, |c| Some(c.saturating_sub(n)));
}

/// `QUOTA(op, ...)`. Op 0 asks about the caller's own program: returns its holding limit and sets x1 = pages it holds
/// (heap + contiguous), x2 = its budget, x3 = budget handed down so far, x4 = programs it has (zombies included).
/// Op 1 (`child`, `heap`, `budget`) changes a child's limits: the heap limit (1..=16384 pages) and the budget, charged
/// to (or refunded to) the caller's budget. The new limits may not be below what the child holds or has handed down.
pub fn quota(cur: usize, op: u64, child: u64, heap: u64, budget: u64) -> i64 {
    let pa = task::aspace(cur);
    match op {
        0 => {
            let held = lock(pa).held_pages() + contig_pages(pa);
            let mut f = frame(cur);
            f.x[1] = held as u64;
            f.x[2] = task::info(pa).budget as u64;
            f.x[3] = DELEGATED[pa].load(Ordering::SeqCst) as u64;
            f.x[4] = children_of(pa) as u64;
            task::info(pa).heap_quota as i64
        }
        1 => {
            let child = child as usize;
            if child >= task::limit() || !is_program(child) || PARENT[child].load(Ordering::SeqCst) != pa as u16 || matches!(sched::state(child), State::Free | State::Dead) {
                return E_INVAL;
            }
            if heap == 0 || heap > MAX_HEAP as u64 || budget > MAX_BUDGET as u64 {
                return E_INVAL;
            }
            let (nh, nb) = (heap as usize, budget as usize);
            // under the child's lock, which `heap_grow` and `MC_ALLOC` also take: its holdings cannot change meanwhile
            let t = lock(child);
            let (oh, ob) = (task::info(child).heap_quota, task::info(child).budget);
            if t.held_pages() + contig_pages(child) > nh || DELEGATED[child].load(Ordering::SeqCst) > nb {
                return E_INVAL;
            }
            // The new limits first (a spawn by the child now charges against them), then the parent's side.
            task::set_limits(child, nh, nb);
            if DELEGATED[child].load(Ordering::SeqCst) > nb {
                task::set_limits(child, oh, ob); // the child handed something down meanwhile
                return E_INVAL;
            }
            loop {
                let old = CHARGE[child].load(Ordering::SeqCst);
                if old == 0 {
                    task::set_limits(child, oh, ob);
                    return E_INVAL; // (it died)
                }
                let new = old - oh - ob + nh + nb;
                if new > old && !try_charge(pa, new - old) {
                    task::set_limits(child, oh, ob);
                    return E_NOMEM;
                }
                if CHARGE[child].compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    if new < old {
                        uncharge(pa, old - new);
                    }
                    break;
                }
                if new > old {
                    uncharge(pa, new - old); // somebody changed the charge meanwhile (TASK_LOAD): try again
                }
            }
            0
        }
        _ => E_INVAL,
    }
}

pub fn is_program(tid: usize) -> bool {
    tid >= FIRST_DYNAMIC_TASK && task::info(tid).role == ROLE_PROGRAM
}

/// Record the code a task exits with (called by `EXIT` just before the task dies). A thread that exits ends its
/// program, so the code is the program's.
pub fn set_exit_code(tid: usize, code: u64) {
    EXIT_CODE[task::aspace(tid)].store(code, Ordering::SeqCst);
}

/// Copy `dst.len()` bytes from the caller's address space; false if any of it is not mapped.
fn copy_from_user(tid: usize, mut va: usize, dst: &mut [u8]) -> bool {
    let tid = task::aspace(tid); // (a thread reads its program's memory)
    let mut done = 0;
    while done < dst.len() {
        let n = (dst.len() - done).min(PAGE - (va & (PAGE - 1)));
        {
            let t = lock(tid);
            let Some(pa) = crate::swap::translate(&t, tid, va) else { return false };
            if !crate::frame::phys::try_copy_from(pa, &mut dst[done..done + n]) {
                return false;
            }
        }
        done += n;
        va = match va.checked_add(n) {
            Some(v) => v,
            None => return done == dst.len(),
        };
    }
    true
}

// ---- the image area ----------------------------------------------------------------------------------------------------
//
// The kernel knows no executable format. `SPAWN` makes an *embryo*: a task with its stack, arguments and capabilities
// but no code, in `State::Embryo` (never scheduled). Its parent fills the image area with `TASK_LOAD`, one run of
// pages at a time, and starts it with `TASK_START`. The format readers live in `libs/metallium-loader`.

/// Pages a program may occupy: from the image base up to the stack.
const IMAGE_PAGES: usize = task::PIE_MAX_IMAGE / PAGE; // (the larger of the two kinds of image)
const BITMAP_WORDS: usize = (IMAGE_PAGES + 63) / 64;
/// Page permissions of `TASK_LOAD`.
const PERM_RX: u32 = 0;
const PERM_RW: u32 = 1;
const PERM_RO: u32 = 2;

/// Per embryo: which pages of the image area have been loaded, and which of those are executable. Written only by
/// the parent's system calls (and reset by `SPAWN`), so plain atomics suffice.
static LOADED: crate::table::Table<[AtomicU64; BITMAP_WORDS]> = crate::table::Table::new();
static EXEC: crate::table::Table<[AtomicU64; BITMAP_WORDS]> = crate::table::Table::new();
fn bit(map: &[AtomicU64; BITMAP_WORDS], page: usize) -> bool {
    map[page / 64].load(Ordering::SeqCst) & (1 << (page % 64)) != 0
}

fn set_bit(map: &[AtomicU64; BITMAP_WORDS], page: usize) {
    map[page / 64].fetch_or(1 << (page % 64), Ordering::SeqCst);
}

/// An embryo of `parent` (the only task that may load and start it).
fn embryo_of(parent: usize, tid: usize) -> bool {
    tid < task::limit() && is_program(tid) && PARENT[tid].load(Ordering::SeqCst) == task::aspace(parent) as u16 && sched::state(tid) == State::Embryo
}

/// The request block `SPAWN(slot, request va)` reads from the caller's memory (little endian, 96 bytes). It creates an
/// embryo (see above); the program's code comes with `TASK_LOAD` and `TASK_START`.
///
/// | offset | field |
/// |---|---|
/// | 0 | `version` u32 = 2 |
/// | 4 | `flags` u32: bit 0 = give the program file-system access (needs `R_SPAWN_FS` on the spawn capability) |
/// | 8 | `budget_pages` u32: pages the program may hand down to programs of its own (0 = none; at most 2^20) |
/// | 12, 16 | reserved, zero (version 1 had the image here) |
/// | 24 | `class` u32: 0 interactive, 1 background, 2 heavy |
/// | 28 | `heap_pages` u32 (0 = default 256, at most 16384) |
/// | 32 | `arg` u64: the program's x1 |
/// | 40, 48 | `args_va`, `args_len` u64: bytes (at most 1024) copied to the top of the program's stack; x3 = their address, x4 = length |
/// | 56 | `name` [u8; 8] (all zero: the name in the image header) |
/// | 64 | eight delegation entries `{ slot: u8 (0xFF = none), pad: u8, rights mask: u16 }`: the program's slot i gets the parent's capability `slot` with its rights ANDed with the mask |
///
/// Programs with file-system access hold the VFS endpoint in slot 8 and their session page in slot 9.
pub const REQ_SIZE: usize = 96;
pub const REQ_VERSION: u32 = 2;
pub const FLAG_FS: u32 = 1;
/// Flags bit 1: network access (needs `R_SPAWN_NET`): the network service's endpoint in child slot 10, the session page in 11.
pub const FLAG_NET: u32 = 2;
/// Flags bit 2: every `MEM_MAP` of the program must have address 0 (the kernel chooses; an address of its own is refused with
/// `E_PERM`), so that no mapping is at a place an attacker could know.
pub const FLAG_NO_FIXED_MAPS: u32 = 4;
/// Flags bit 3: a position-independent program. The kernel picks a random page-aligned image base in `task::PIE_LO..PIE_HI`
/// instead of `USER_BASE`; `TASK_BASE` tells the parent which, so that it can relocate the image before loading it.
pub const FLAG_PIE: u32 = 8;
/// Where each embryo's image area starts (`USER_BASE` unless it was spawned with `FLAG_PIE`).
static IMG_BASE: crate::table::Table<AtomicUsize> = crate::table::Table::new();
/// How many pages an image at `base` may have.
fn image_pages(base: usize) -> usize {
    if base == USER_BASE { MAX_IMAGE / PAGE } else { task::PIE_MAX_IMAGE / PAGE }
}

/// `TASK_BASE(child)`: the address the embryo's image area starts at.
pub fn task_base(parent: usize, child: usize) -> Result<usize, i64> {
    if !embryo_of(parent, child) {
        return Err(E_INVAL);
    }
    Ok(IMG_BASE[child].load(Ordering::SeqCst))
}
/// Programs started with `FLAG_NO_FIXED_MAPS`, by task slot.
static NO_FIXED_MAPS: crate::table::Table<core::sync::atomic::AtomicBool> = crate::table::Table::new();

/// The boot-time services (not the test programs) may not name addresses for `MEM_MAP` either.
pub fn restrict_boot_task(tid: usize, role: u8) {
    if matches!(role, 2 | 4 | 5 | 6 | 7 | 9 | 12 | 13 | 14 | 18 | 19 | 20 | 22) {
        NO_FIXED_MAPS[tid].store(true, Ordering::SeqCst);
    } else {
        NO_FIXED_MAPS[tid].store(false, Ordering::SeqCst);
    }
}

pub fn fixed_maps_allowed(program: usize) -> bool {
    !NO_FIXED_MAPS[program].load(Ordering::SeqCst)
}
pub const NET_EP_SLOT: usize = 10;
pub const NET_PAGE_SLOT: usize = 11;
/// Flags bits 8..11: how many threads (besides itself) the program may have at once.
const THREADS_SHIFT: u32 = 8;
pub const MAX_THREADS: usize = 8;
pub const MAX_ARGS: usize = 1024;
/// Child slots of the file-system capabilities.
pub const FS_EP_SLOT: usize = 8;
pub const FS_PAGE_SLOT: usize = 9;
/// File and network sessions one program may hold for the programs it starts, and the ones programs may never take.
const SESSION_SHARE: usize = 5;
const SESSION_RESERVE: usize = 2;
const NO_FS: u8 = u8::MAX;
static FS_PAGE: crate::table::Table<AtomicU8> = crate::table::Table::new();
static FS_GEN: crate::table::Table<AtomicU64> = crate::table::Table::new();
/// Which session pages are taken: one bit per page (`obj::MAX_SESSIONS` of them, `obj::sessions()` in use).
struct Pool([AtomicU64; crate::obj::MAX_SESSIONS / 64]);
impl Pool {
    const fn new() -> Pool {
        Pool([const { AtomicU64::new(0) }; crate::obj::MAX_SESSIONS / 64])
    }
    fn take(&self) -> Option<u8> {
        (0..crate::obj::sessions()).find(|&k| self.0[k / 64].fetch_or(1 << (k % 64), Ordering::SeqCst) & (1 << (k % 64)) == 0).map(|k| k as u8)
    }
    fn give(&self, k: u8) {
        self.0[k as usize / 64].fetch_and(!(1u64 << (k % 64)), Ordering::SeqCst);
    }
    fn used(&self) -> usize {
        self.0.iter().map(|w| w.load(Ordering::SeqCst).count_ones() as usize).sum()
    }
}
static FS_POOL: Pool = Pool::new();
static NET_PAGE: crate::table::Table<AtomicU8> = crate::table::Table::new();
static NET_GEN: crate::table::Table<AtomicU64> = crate::table::Table::new();
static NET_POOL: Pool = Pool::new();

/// (session page, generation) of a program's file-system session; page `NO_FS` if it has none. The generation changes
/// every time a slot gets a new program, so the VFS can tell a new program from its predecessor in the same slot.
/// The program that started program `p` (its parent), or `NO_PARENT` (65535) for one the kernel started itself.
pub fn parent_of(p: usize) -> u16 {
    PARENT[p].load(Ordering::SeqCst)
}

pub fn fs_session(tid: usize) -> (u8, u64, usize) {
    let p = task::aspace(tid); // (the threads of a program share its session)
    (FS_PAGE[p].load(Ordering::SeqCst), FS_GEN[p].load(Ordering::SeqCst), p)
}

/// Whether `(kind, obj, rights)` in `slot` of program `tid` is exactly what the kernel gives a program itself, with no parent: the console, and for
/// its file or network session the endpoint to the VFS or the network driver and the session's page and the session still exists: only then can it be given back after a revoke.
pub fn session_cap_ok(tid: usize, slot: usize, kind: Kind, obj: u16, rights: Rights) -> bool {
    let (fp, _, _) = fs_session(tid);
    let (np, _, _) = net_session(tid);
    match slot {
        crate::syscall::CONSOLE_SLOT => kind == Kind::Console && obj == 0 && rights == 0,
        FS_EP_SLOT => fp != NO_FS && kind == Kind::Endpoint && obj == crate::ipc::EP_VFS && rights == R_SEND,
        FS_PAGE_SLOT => fp != NO_FS && kind == Kind::Memory && obj == crate::obj::OBJ_SHM_VFS_PROG0 + fp as u16 && rights == R_MAP | R_WRITE,
        NET_EP_SLOT => np != NO_FS && kind == Kind::Endpoint && obj == crate::ipc::EP_NET && rights == R_SEND,
        NET_PAGE_SLOT => np != NO_FS && kind == Kind::Memory && obj == crate::obj::OBJ_SHM_NET_PROG0 + np as u16 && rights == R_MAP | R_WRITE,
        _ => false,
    }
}

/// (session page, generation, program) of a program's network session, as `fs_session`.
pub fn net_session(tid: usize) -> (u8, u64, usize) {
    let p = task::aspace(tid);
    (NET_PAGE[p].load(Ordering::SeqCst), NET_GEN[p].load(Ordering::SeqCst), p)
}

/// A boot-time task that talks to the network service itself (the shell, for `download`): its session page, claimed once
/// and kept across restarts of the task; the generation changes each time, so the service drops what a dead one held.
pub fn boot_net_page(tid: usize) -> Option<u8> {
    let p = task::aspace(tid);
    let mut k = NET_PAGE[p].load(Ordering::SeqCst);
    if k == NO_FS {
        k = claim_net_page()?;
        NET_PAGE[p].store(k, Ordering::SeqCst);
    }
    NET_GEN[p].fetch_add(1, Ordering::SeqCst);
    Some(k)
}

/// A boot-time task that is a client of the file system with a page of the session pool (the consoles of the ttys): claimed once, the generation changes each time it is built.
/// The VFS finds it by the page the kernel reports for the task (SYSINFO page 5), as for any program with file access.
pub fn boot_fs_page(tid: usize) -> Option<u8> {
    let p = task::aspace(tid);
    let mut k = FS_PAGE[p].load(Ordering::SeqCst);
    if k == NO_FS {
        k = claim_fs_page()?;
        FS_PAGE[p].store(k, Ordering::SeqCst);
    }
    FS_GEN[p].fetch_add(1, Ordering::SeqCst);
    Some(k)
}

/// Wipe a session page as it is given to a program: it still holds what the program before it (and the server) last put there, file contents and
/// paths or network data, and the new program maps it.
fn clear_session_page(obj: u16) {
    if let Some(o) = crate::obj::get(obj) {
        crate::frame::phys::zero_page(o.pa);
    }
}

fn claim_net_page() -> Option<u8> {
    let k = NET_POOL.take()?;
    clear_session_page(crate::obj::OBJ_SHM_NET_PROG0 + k as u16);
    Some(k)
}

fn drop_net_page(tid: usize) {
    let k = NET_PAGE[tid].swap(NO_FS, Ordering::SeqCst);
    if k != NO_FS {
        NET_POOL.give(k);
    }
}

fn claim_fs_page() -> Option<u8> {
    let k = FS_POOL.take()?;
    clear_session_page(crate::obj::OBJ_SHM_VFS_PROG0 + k as u16);
    Some(k)
}

fn drop_fs_page(tid: usize) {
    let k = FS_PAGE[tid].swap(NO_FS, Ordering::SeqCst);
    if k != NO_FS {
        FS_POOL.give(k);
    }
}

/// Create a program as `req_va` in `parent`'s address space describes (see `REQ_SIZE`); `spawn_rights` are the rights
/// of the spawn capability the parent used. Returns the child's task id.
pub fn spawn(parent: usize, spawn_rights: Rights, req_va: usize) -> Result<usize, i64> {
    let mut rq = [0u8; REQ_SIZE];
    if !copy_from_user(parent, req_va, &mut rq) {
        return Err(E_INVAL);
    }
    let u32_at = |o: usize| u32::from_le_bytes(rq[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(rq[o..o + 8].try_into().unwrap());
    if u32_at(0) != REQ_VERSION {
        return Err(E_INVAL);
    }
    let flags = u32_at(4);
    let budget = u32_at(8) as usize;
    if u32_at(12) != 0 || u64_at(16) != 0 || budget > MAX_BUDGET {
        return Err(E_INVAL);
    }
    let (arg, args_va, args_len) = (u64_at(32), u64_at(40) as usize, u64_at(48) as usize);
    let threads = ((flags >> THREADS_SHIFT) & 0xF) as usize;
    if flags & !(FLAG_FS | FLAG_NET | FLAG_NO_FIXED_MAPS | FLAG_PIE | 0xF << THREADS_SHIFT) != 0 || args_len > MAX_ARGS || threads > MAX_THREADS {
        return Err(E_INVAL);
    }
    if flags & FLAG_FS != 0 && spawn_rights & R_SPAWN_FS == 0 {
        return Err(E_PERM);
    }
    if flags & FLAG_NET != 0 && (spawn_rights & R_SPAWN_NET == 0 || !crate::obj::net_present()) {
        return Err(E_PERM);
    }
    let class = match u32_at(24) {
        0 => Class::Interactive,
        1 => Class::Background,
        2 => Class::Heavy,
        _ => return Err(E_INVAL),
    };
    let heap = match u32_at(28) as usize {
        0 => DEFAULT_HEAP,
        n if n <= MAX_HEAP => n,
        _ => return Err(E_INVAL),
    };
    let mut args = [0u8; MAX_ARGS];
    if args_len > 0 && !copy_from_user(parent, args_va, &mut args[..args_len]) {
        return Err(E_INVAL);
    }
    // What the parent hands over, read once (the table of capabilities may change under it afterwards).
    let mut give = [Cap::NONE; MAX_DELEG];
    {
        let t = lock(parent);
        for (i, g) in give.iter_mut().enumerate() {
            let slot = rq[64 + 4 * i];
            if slot == DELEG_NONE {
                continue;
            }
            let mask = u16::from_le_bytes([rq[66 + 4 * i], rq[67 + 4 * i]]);
            let c = *t.caps.get(slot as usize).ok_or(crate::syscall::E_BADCAP)?;
            if c.kind == Kind::None || !c.alive() || slot as usize == crate::syscall::CONSOLE_SLOT {
                return Err(crate::syscall::E_BADCAP);
            }
            if c.rights & R_GRANT == 0 {
                return Err(E_PERM);
            }
            *g = Cap { rights: c.rights & mask, ..c };
        }
    }

    let _one_at_a_time = SPAWNING.lock(R_SPAWNING);
    // (a program that starts programs may not use up the sessions: it gets `SESSION_SHARE` of its own, and the last `SESSION_RESERVE`
    // are for boot-time spawners; counted under the lock that serialises SPAWN)
    if is_program(task::aspace(parent)) {
        let pa = task::aspace(parent);
        let mine = |per: &crate::table::Table<AtomicU8>| (FIRST_DYNAMIC_TASK..task::limit()).filter(|&c| PARENT[c].load(Ordering::SeqCst) == pa as u16 && per[c].load(Ordering::SeqCst) != NO_FS).count();
        let full = |pool: &Pool| pool.used() + SESSION_RESERVE >= crate::obj::sessions();
        if (flags & FLAG_FS != 0 && (mine(&FS_PAGE) >= SESSION_SHARE || full(&FS_POOL)))
            || (flags & FLAG_NET != 0 && (mine(&NET_PAGE) >= SESSION_SHARE || full(&NET_POOL)))
        {
            return Err(E_FULL);
        }
    }
    let fs_page = if flags & FLAG_FS != 0 { Some(claim_fs_page().ok_or(E_FULL)?) } else { None };
    let net_page = if flags & FLAG_NET != 0 {
        match claim_net_page() {
            Some(k) => Some(k),
            None => {
                if let Some(k) = fs_page {
                    FS_POOL.give(k);
                }
                return Err(E_FULL);
            }
        }
    } else {
        None
    };
    let Some(tid) = (FIRST_DYNAMIC_TASK..task::limit()).find(|&i| sched::state(i) == State::Free) else {
        if let Some(k) = fs_page {
            FS_POOL.give(k);
        }
        if let Some(k) = net_page {
            NET_POOL.give(k);
        }
        return Err(E_FULL);
    };
    // The parent's limits: how many programs it may have, and what this one costs its budget.
    let pa = task::aspace(parent);
    let cost = heap + budget + OVERHEAD;
    let refused = if children_of(pa) >= if is_program(pa) { MAX_CHILDREN_PROGRAM } else { MAX_CHILDREN_ROLE.max(task::limit()) } {
        Some(E_FULL)
    } else if !try_charge(pa, cost) {
        Some(E_NOMEM)
    } else {
        None
    };
    if let Some(e) = refused {
        if let Some(k) = fs_page {
            FS_POOL.give(k);
        }
        if let Some(k) = net_page {
            NET_POOL.give(k);
        }
        return Err(e);
    }
    let own = task::owner(tid);
    let core = sched::assign_core(class);
    sched::init_task(tid, core);
    let mut name = [0u8; 8];
    name.copy_from_slice(if rq[56..64].iter().any(|&b| b != 0) { &rq[56..64] } else { b"program\0" });
    task::set_dynamic_info(tid, ROLE_PROGRAM, &name, class, heap, budget);
    EPOCH[tid].fetch_add(1, Ordering::SeqCst);
    PARENT[tid].store(pa as u16, Ordering::SeqCst);
    CHARGE[tid].store(cost, Ordering::SeqCst);
    DELEGATED[tid].store(0, Ordering::SeqCst);
    CONTIG[tid].store(0, Ordering::SeqCst);
    EXIT_CODE[tid].store(EXIT_FAULTED, Ordering::SeqCst);
    FS_GEN[tid].fetch_add(1, Ordering::SeqCst);
    THREAD_QUOTA[tid].store(threads as u8, Ordering::SeqCst);
    if flags & FLAG_NO_FIXED_MAPS != 0 {
        NO_FIXED_MAPS[tid].store(true, Ordering::SeqCst);
    } else {
        NO_FIXED_MAPS[tid].store(false, Ordering::SeqCst);
    }
    let base = if flags & FLAG_PIE != 0 {
        task::random_pie_base()
    } else {
        USER_BASE
    };
    IMG_BASE[tid].store(base, Ordering::SeqCst);
    EXTRA[tid].store(0, Ordering::SeqCst);
    FS_PAGE[tid].store(fs_page.unwrap_or(NO_FS), Ordering::SeqCst);
    NET_GEN[tid].fetch_add(1, Ordering::SeqCst);
    NET_PAGE[tid].store(net_page.unwrap_or(NO_FS), Ordering::SeqCst);
    for w in 0..BITMAP_WORDS {
        LOADED[tid][w].store(0, Ordering::SeqCst);
        EXEC[tid][w].store(0, Ordering::SeqCst);
    }

    let fail = |e: i64| -> Result<usize, i64> {
        // give back what was taken so far; the slot was never visible as live
        refund(tid);
        {
            let mut t = lock(tid);
            for c in t.caps.iter().filter(|c| c.kind != Kind::None) {
                free_node(c.node);
            }
            t.caps = [Cap::NONE; NCAPS];
            if t.l1 != 0 {
                crate::swap::release_task(t.l1);
            }
            t.l1 = 0;
        }
        mem::free_owned(own);
        mmu::flush_tlb();
        sched::release_core(core, class);
        drop_fs_page(tid);
        drop_net_page(tid);
        PARENT[tid].store(NO_PARENT, Ordering::SeqCst);
        Err(e)
    };

    let Some(l1) = mmu::new_space(own) else { return fail(E_NOMEM) };
    lock(tid).l1 = l1;
    let stack_top = task::random_stack_top();
    let heap_base = task::random_heap_base();
    let args_sp = stack_top - ((args_len + 15) & !15);
    // (a closure so that every guard is gone before `fail` takes the lock again)
    let built = (|| -> Result<(), i64> {
        for i in 0..STACK_PAGES {
            let _t = lock(tid);
            let va = stack_top - (i + 1) * PAGE;
            let pa = mem::alloc_movable(own, tid, va).ok_or(E_NOMEM)?;
            crate::frame::phys::zero_page(pa);
            if i == 0 && args_len > 0 {
                crate::frame::phys::copy_to(pa + (args_sp - va), &args[..args_len]);
            }
            mmu::map_user(l1, va, pa, mmu::Perm::Rw, own).map_err(|_| E_NOMEM)?;
        }
        let mut t = lock(tid);
        t.maps = [MapRec { used: false, va: 0, pages: 0, node: 0 }; task::MAX_MAPS];
        t.heap_pages = 0;
        t.tstacks = [(0, 0, 0); MAX_THREADS];
        t.stack_top = stack_top;
        t.heap_base = heap_base;
        t.ring_pa = 0;
        t.pending = [crate::ring::Pending::FREE; crate::ring::MAX_PENDING];
        t.reply_to = None;
        t.callee = None;
        t.caps = [Cap::NONE; NCAPS];
        sched::forget_recv_endpoints(tid);
        // What was handed over must still be what it was when it was read, before anything is made: a node number freed by a revoke is handed out again
        // at once (to the console node below, or to another program), so "is it alive" alone is not enough; `mint_for` checks the generation too.
        if give.iter().any(|g| g.kind != Kind::None && !g.alive()) {
            return Err(crate::syscall::E_BADCAP); // revoked since it was read (checked under a task lock: see `cap_grant`)
        }
        let node = crate::cap::mint_for(pa, None).ok_or(E_NOMEM)?;
        t.caps[crate::syscall::CONSOLE_SLOT] = Cap::new(Kind::Console, 0u16, 0, node);
        for (i, g) in give.iter().enumerate() {
            if g.kind == Kind::None {
                continue;
            }
            let node = crate::cap::mint_for(pa, Some(g.parent_ref())).ok_or(if g.alive() { E_NOMEM } else { crate::syscall::E_BADCAP })?;
            t.caps[i] = g.under(g.rights, node);
            if g.kind == Kind::Endpoint && g.rights & R_RECV != 0 {
                sched::note_recv_endpoint(tid, g.obj);
            }
        }
        if net_page.is_some() {
            let n1 = crate::cap::mint_for(pa, None).ok_or(E_NOMEM)?;
            t.caps[NET_EP_SLOT] = Cap::new(Kind::Endpoint, crate::ipc::EP_NET, R_SEND, n1);
        }
        if let Some(k) = net_page {
            let n2 = crate::cap::mint_for(pa, None).ok_or(E_NOMEM)?;
            t.caps[NET_PAGE_SLOT] = Cap::new(Kind::Memory, crate::obj::OBJ_SHM_NET_PROG0 + k as u16, R_MAP | R_WRITE, n2);
        }
        if let Some(k) = fs_page {
            let n1 = crate::cap::mint_for(pa, None).ok_or(E_NOMEM)?;
            t.caps[FS_EP_SLOT] = Cap::new(Kind::Endpoint, crate::ipc::EP_VFS, R_SEND, n1);
            let n2 = crate::cap::mint_for(pa, None).ok_or(E_NOMEM)?;
            t.caps[FS_PAGE_SLOT] = Cap::new(Kind::Memory, crate::obj::OBJ_SHM_VFS_PROG0 + k as u16, R_MAP | R_WRITE, n2);
        }
        Ok(())
    })();
    if let Err(e) = built {
        return fail(e);
    }
    task::set_l1(tid, l1);
    let mut f = frame(tid);
    *f = TrapFrame::ZERO;
    f.x[0] = ROLE_PROGRAM as u64;
    f.x[1] = arg;
    f.x[2] = task::aspace(parent) as u64;
    f.x[3] = args_sp as u64;
    f.x[4] = args_len as u64;
    f.sp = args_sp as u64;
    f.spsr = 0;
    // The slot becomes an embryo only if it still has its parent. The death of the parent's first task (while a thread of it is in this call)
    // (under the lifecycle lock, as SPAWN is) clears the `PARENT` of every slot it left to it, but does nothing for a slot that is not an embryo yet (a
    // `Free` one has nothing to end), so an embryo made after that would belong to nobody for ever. Looking and setting under a task lock
    // closes the gap: the death either ran before (the parent is gone: undo) or finds the embryo and ends it.
    let committed = {
        let _t = lock(tid);
        let still_mine = PARENT[tid].load(Ordering::SeqCst) == pa as u16;
        if still_mine {
            sched::set_state(tid, State::Embryo);
        }
        still_mine
    };
    if !committed {
        task::set_l1(tid, 0);
        return fail(E_INVAL);
    }
    Ok(tid)
}

/// `TASK_LOAD(child, request va)`: put `pages` fresh pages at `va` in the embryo `child`, filled from `src_va` in the
/// caller's memory, with permission `perm`. Request (24 bytes): `va` u64, `src_va` u64, `pages` u32, `perm` u32
/// (0 read+execute, 1 read+write, 2 read-only). A page can be loaded once, and never both writable and executable.
pub fn task_load(parent: usize, child: usize, req_va: usize) -> Result<(), i64> {
    // The embryo, its page-table root and its epoch, read together under its lock. A kill of the embryo takes this lock when it frees
    // the address space, and an embryo is only ever freed after it has been made runnable and killed (so it is not an embryo any more),
    // so while the lock is held and `embryo_of` is true, the tables are intact; see the loop below.
    let (epoch, l1) = {
        let t = lock(child.min(task::limit() - 1));
        if !embryo_of(parent, child) {
            return Err(E_INVAL);
        }
        (EPOCH[child].load(Ordering::SeqCst), t.l1)
    };
    let mut rq = [0u8; 24];
    if !copy_from_user(parent, req_va, &mut rq) {
        return Err(E_INVAL);
    }
    let (va, src_va) = (u64::from_le_bytes(rq[0..8].try_into().unwrap()) as usize, u64::from_le_bytes(rq[8..16].try_into().unwrap()) as usize);
    let (pages, perm) = (u32::from_le_bytes(rq[16..20].try_into().unwrap()) as usize, u32::from_le_bytes(rq[20..24].try_into().unwrap()));
    let perm_map = match perm {
        PERM_RX => mmu::Perm::Rx,
        PERM_RW => mmu::Perm::Rw,
        PERM_RO => mmu::Perm::Ro,
        _ => return Err(E_INVAL),
    };
    let base = IMG_BASE[child].load(Ordering::SeqCst);
    let max_pages = image_pages(base);
    if va % PAGE != 0 || va < base || pages == 0 || pages > max_pages || (va - base) / PAGE >= max_pages || (va - base) / PAGE + pages > max_pages {
        return Err(E_INVAL);
    }
    let first = (va - base) / PAGE;
    if (first..first + pages).any(|p| bit(&LOADED[child], p)) {
        return Err(E_INVAL);
    }
    // every page of image costs the parent's budget one page (returned when the child dies)
    let pa = task::aspace(parent);
    if !try_charge(pa, pages) {
        return Err(E_NOMEM);
    }
    if !add_charge(child, pages) {
        uncharge(pa, pages);
        return Err(E_INVAL);
    }
    let own = task::owner(child);
    let mut page = [0u8; PAGE];
    for i in 0..pages {
        if !copy_from_user(parent, src_va.checked_add(i * PAGE).ok_or(E_INVAL)?, &mut page) {
            return Err(E_INVAL);
        }
        let pva = va + i * PAGE;
        let t = lock(child); // the compactor must not see the frame between its allocation and its mapping
        // The child may have been killed (by a thread of the parent, or by the parent's death) since the last page: its tables are then freed, and
        // may be somebody else's. It may even have been collected and its slot made into a new embryo of this parent. Either way this load is over.
        if EPOCH[child].load(Ordering::SeqCst) != epoch || !embryo_of(parent, child) || t.l1 != l1 {
            return Err(E_INVAL);
        }
        let pa = mem::alloc_movable(own, child, pva).ok_or(E_NOMEM)?;
        crate::frame::phys::copy_to(pa, &page[..PAGE]);
        mmu::map_user(l1, pva, pa, perm_map, own).map_err(|_| E_NOMEM)?;
        if perm == PERM_RX {
            mmu::sync_icache(pa, PAGE);
            set_bit(&EXEC[child], first + i);
        }
        set_bit(&LOADED[child], first + i);
    }
    Ok(())
}

/// `TASK_START(child, entry)`: make the embryo runnable at `entry`, which must lie in a loaded executable page.
pub fn task_start(parent: usize, child: usize, entry: usize) -> Result<(), i64> {
    if child >= task::limit() || entry % 4 != 0 {
        return Err(E_INVAL);
    }
    // Everything under the child's lock, which the end of a task takes (and under the lifecycle lock): an embryo that was killed meanwhile has ended and
    // is not an embryo any more, and one that has not will be ended after it is made runnable. (Without it, a killed embryo could be made
    // `Ready` after it died, and a core would try to run a task with no address space.)
    let _t = lock(child);
    if !embryo_of(parent, child) {
        return Err(E_INVAL);
    }
    let base = IMG_BASE[child].load(Ordering::SeqCst);
    if entry < base || entry - base >= image_pages(base) * PAGE || !bit(&EXEC[child], (entry - base) / PAGE) {
        return Err(E_INVAL);
    }
    frame(child).elr = entry as u64;
    sched::set_state(child, State::Ready);
    Ok(())
}

/// What `WAIT` does.
pub enum Waited {
    /// The child is gone; its exit code (the slot is free again).
    Code(u64),
    /// The caller is now blocked; the code arrives in its x0 when the child dies.
    Blocked,
    Err(i64),
}

pub fn wait(cur: usize, child: usize, nohang: bool) -> Waited {
    if child >= task::limit() || !is_program(child) || PARENT[child].load(Ordering::SeqCst) != task::aspace(cur) as u16 || sched::state(child) == State::Embryo {
        return Waited::Err(E_INVAL); // (waiting for an embryo you have not started would never end)
    }
    // Under the lifecycle lock (the child's death holds it): the death either finished before we look
    // (the state is Dead) or finds us waiting.
    let _t = lock(cur);
    match sched::state(child) {
        // (a program that has died is not collectable until the last of its threads is gone)
        State::Dead if task::members(child).next().is_none() => {
            // The lock above is the caller's own task lock, and two threads of one program have different ones: both could get here for the
            // same zombie. Whoever takes the parent link away collects it; the other finds it gone. (Releasing twice would give back the
            // core's load twice, and, if a SPAWN took the slot in between, the new program's session.)
            if PARENT[child].compare_exchange(task::aspace(cur) as u16, NO_PARENT, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                return Waited::Err(E_INVAL);
            }
            let code = EXIT_CODE[child].load(Ordering::SeqCst);
            release(child);
            Waited::Code(code)
        }
        State::Free => Waited::Err(E_INVAL),
        _ if nohang => Waited::Err(E_AGAIN),
        _ => {
            sched::set_state(cur, State::ChildWait(child as u16));
            Waited::Blocked
        }
    }
}

/// Condemn a child (the next core to own it kills it). Killing a zombie is an error: it is already dead.
pub fn kill(cur: usize, child: usize) -> i64 {
    if child >= task::limit() || !is_program(child) || PARENT[child].load(Ordering::SeqCst) != task::aspace(cur) as u16 {
        return E_INVAL;
    }
    match sched::state(child) {
        State::Dead | State::Free => E_INVAL,
        _ => {
            EXIT_CODE[child].store(EXIT_KILLED, Ordering::SeqCst);
            sched::doom(child, sched::Doom::Parent);
            0
        }
    }
}

fn release(tid: usize) {
    PARENT[tid].store(NO_PARENT, Ordering::SeqCst);
    drop_fs_page(tid);
    drop_net_page(tid);
    sched::release_core(sched::home_core(tid), task::info(tid).class);
    sched::set_state(tid, State::Free);
}

/// A task has died and everything it held is reclaimed (called by `task::die` under the lifecycle lock): its children
/// are killed (whatever kind of task it was). `done` is the program whose address space is now empty, if `tid` was
/// the last task in it: that program's slot is freed or left as a zombie for its parent — handing the parent the code
/// at once if it is already waiting.
pub fn on_death(_w: &mut World, tid: usize, done: Option<usize>) {
    for c in FIRST_DYNAMIC_TASK..task::limit() {
        let par = PARENT[c].load(Ordering::SeqCst);
        // (children belong to a program, not to one of its threads)
        if par != NO_PARENT && (par == tid as u16 || done == Some(par as usize)) && c != tid {
            PARENT[c].store(NO_PARENT, Ordering::SeqCst);
            match sched::state(c) {
                State::Dead if task::members(c).next().is_none() => release(c),
                State::Free => {}
                _ => {
                    EXIT_CODE[c].store(EXIT_KILLED, Ordering::SeqCst);
                    sched::doom(c, sched::Doom::Parent);
                }
            }
        }
    }
    let Some(prog) = done.filter(|&p| is_program(p)) else { return };
    refund(prog); // its memory is back: so is its cost to the parent's budget
    drop_fs_page(prog); // the session ends with the program, not with its collection
    drop_net_page(prog);
    let p = PARENT[prog].load(Ordering::SeqCst);
    let code = EXIT_CODE[prog].load(Ordering::SeqCst);
    if p == NO_PARENT || matches!(sched::state(p as usize), State::Free | State::Dead) && task::members(p as usize).next().is_none() {
        release(prog);
        return;
    }
    // the parent (or one of its threads) may be waiting
    if let Some(waiter) = task::members(p as usize).find(|&m| sched::state(m) == State::ChildWait(prog as u16)) {
        frame(waiter).x[0] = code; // the result register, written before the parent can run
        sched::wake_if(waiter, State::ChildWait(prog as u16));
        release(prog);
    }
    // else: a zombie until the parent waits (or dies, which frees it above)
}

// ---- threads -----------------------------------------------------------------------------------------------------------

/// `THREAD_CREATE(entry, stack top, arg, capability mask)`: a new task in the caller's address space. It starts at
/// `entry` with `x0 = arg` and `sp = stack top` (the caller provides the stack; both are only addresses to the kernel:
/// a bad one makes the thread fault, which ends the program). It gets the capabilities of the caller's slots named by
/// the bits of `mask` (new nodes derived from the caller's, same rights) and the console. The program must have been
/// given threads when it was started (`THREADS_SHIFT`); at most `MAX_THREADS` at once.
///
/// A thread is scheduled on its own, with the program's class, and has its own capability table and IPC identity.
/// What belongs to the address space (mappings, heap, quota, file-system session) belongs to the program: the thread's
/// `MEM_MAP`, `HEAP_GROW` and file requests act on it. The thread ends with `THREAD_EXIT`; a fault, `EXIT`, or the end
/// of any other task of the program ends them all.
pub fn thread_create(cur: usize, entry: usize, sp: usize, arg: u64, mask: u32, stack_bytes: usize) -> Result<usize, i64> {
    let leader = task::aspace(cur);
    if !is_program(leader) {
        return Err(E_PERM); // only programs have threads
    }
    if sp == 0 && stack_bytes > THREAD_STACK_MAX {
        return Err(E_INVAL);
    }
    // A program that is being ended (its first task is gone, or this thread is condemned) gets no new threads.
    if matches!(sched::state(leader), State::Dead | State::Free) || sched::is_doomed(cur) {
        return Err(E_PERM);
    }
    let class = task::info(leader).class;
    // What the caller hands over, read once.
    let mut give = [Cap::NONE; NCAPS];
    {
        let t = lock(cur);
        for slot in 0..NCAPS {
            let c = t.caps[slot];
            // (an empty slot in the mask is skipped, so "everything I hold" is a valid mask)
            if slot != crate::syscall::CONSOLE_SLOT && mask & (1 << slot) != 0 && c.kind != Kind::None && c.alive() {
                give[slot] = c;
            }
        }
    }
    let _one_at_a_time = SPAWNING.lock(R_SPAWNING);
    // (the quota is claimed under the same lock as the slot, so no race can exceed it)
    if EXTRA[leader].load(Ordering::SeqCst) >= THREAD_QUOTA[leader].load(Ordering::SeqCst) {
        return Err(E_PERM);
    }
    let Some(tid) = (FIRST_DYNAMIC_TASK..task::limit()).find(|&i| sched::state(i) == State::Free) else { return Err(E_FULL) };
    let core = sched::assign_core(class);
    sched::init_task(tid, core);
    task::set_dynamic_info(tid, ROLE_THREAD, &name_of(leader), class, 0, 0);
    task::set_aspace(tid, Some(leader));
    PARENT[tid].store(NO_PARENT, Ordering::SeqCst);
    let fail = |e: i64| -> Result<usize, i64> {
        {
            let mut t = lock(tid);
            for c in t.caps.iter().filter(|c| c.kind != Kind::None) {
                free_node(c.node);
            }
            t.caps = [Cap::NONE; NCAPS];
        }
        task::set_aspace(tid, None);
        sched::release_core(core, class);
        Err(e)
    };
    {
        let mut t = lock(tid);
        t.caps = [Cap::NONE; NCAPS];
        t.reply_to = None;
        t.callee = None;
        sched::forget_recv_endpoints(tid);
        // (everything handed over is checked before the first node is made: see `spawn`)
        if give.iter().any(|g| g.kind != Kind::None && !g.alive()) {
            drop(t);
            return fail(crate::syscall::E_BADCAP); // revoked since it was read (checked under a task lock)
        }
        let Some(node) = crate::cap::mint_for(leader, None) else { drop(t); return fail(E_NOMEM) };
        t.caps[crate::syscall::CONSOLE_SLOT] = Cap::new(Kind::Console, 0u16, 0, node);
        for (i, g) in give.iter().enumerate() {
            if g.kind == Kind::None {
                continue;
            }
            let Some(node) = crate::cap::mint_for(leader, Some(g.parent_ref())) else {
                drop(t);
                return fail(if g.alive() { E_NOMEM } else { crate::syscall::E_BADCAP });
            };
            t.caps[i] = g.under(g.rights, node);
            if g.kind == Kind::Endpoint && g.rights & R_RECV != 0 {
                sched::note_recv_endpoint(tid, g.obj);
            }
        }
    }
    // The creator's own root, not the leader's: when the program's first task has died and its threads are only condemned, the leader's published
    // root is 0, and a thread made with it would stop the kernel the first time a core ran it. The creator is running in the space, so its root is good.
    let root = task::l1_of(cur);
    if root == 0 {
        return fail(E_PERM);
    }
    // no stack given: the kernel makes one, at a random place between unmapped pages, charged to the program
    let sp = if sp == 0 {
        match make_thread_stack(leader, tid, stack_bytes) {
            Ok(top) => top,
            Err(e) => return fail(e),
        }
    } else {
        sp
    };
    task::set_l1(tid, root);
    let mut f = frame(tid);
    *f = TrapFrame::ZERO;
    f.x[0] = arg;
    f.sp = sp as u64;
    f.elr = entry as u64;
    f.spsr = 0;
    EXTRA[leader].fetch_add(1, Ordering::SeqCst);
    sched::set_state(tid, State::Ready);
    Ok(tid)
}

/// Largest stack the kernel makes for a thread, and the size when none is asked for.
pub const THREAD_STACK_MAX: usize = 1 << 20;
pub const THREAD_STACK_DEFAULT: usize = 64 << 10;

/// A stack for thread `tid` of `leader`: `bytes` (0 = the default) rounded up to pages, at a random page-aligned place
/// in the stack region with an unmapped page below and above it, apart from the program's main stack and the other
/// thread stacks. Its pages count against the program's heap limit and belong to the program (a crash reclaims them).
/// Returns the stack top.
fn make_thread_stack(leader: usize, tid: usize, bytes: usize) -> Result<usize, i64> {
    let pages = (if bytes == 0 { THREAD_STACK_DEFAULT } else { bytes }).div_ceil(PAGE);
    let mut t = lock(leader);
    let Some(slot) = t.tstacks.iter().position(|s| s.1 == 0) else { return Err(E_FULL) };
    if t.held_pages().saturating_add(contig_pages(leader)).saturating_add(pages) > task::info(leader).heap_quota {
        return Err(E_NOMEM);
    }
    // where it may go: the stack and both guard pages inside the region
    let (lo, hi) = (task::STACK_REGION_LO + PAGE, task::STACK_REGION_HI - (pages + 1) * PAGE);
    let main = (t.stack_top - (STACK_PAGES + 1) * PAGE, t.stack_top + PAGE);
    let clash = |a: usize, b: usize, t: &task::Task| {
        let (a, b) = (a - PAGE, b + PAGE); // (guards included)
        (a < main.1 && main.0 < b) || t.tstacks.iter().any(|s| s.1 != 0 && a < s.0 + s.1 * PAGE + PAGE && s.0 - PAGE < b)
    };
    let mut base = None;
    for _ in 0..64 {
        let va = lo + crate::rand::below((hi - lo) / PAGE + 1) * PAGE;
        if !clash(va, va + pages * PAGE, &t) {
            base = Some(va);
            break;
        }
    }
    let Some(base) = base else { return Err(E_NOMEM) };
    let owner = mem::OWNER_TASK0 + leader as u16;
    for p in 0..pages {
        let va = base + p * PAGE;
        let ok = mem::alloc_movable(owner, leader, va).map_or(false, |pa| {
            let mapped = mmu::map_user(t.l1, va, pa, mmu::Perm::Rw, owner).is_ok();
            if !mapped {
                mem::free(pa);
            }
            mapped
        });
        if !ok {
            crate::swap::release_pages(t.l1, base, p);
            return Err(E_NOMEM);
        }
    }
    t.tstacks[slot] = (base, pages, tid as u16);
    Ok(base + pages * PAGE)
}

/// A thread that ends gives its stack back (under the lifecycle lock; the program lives on).
pub fn free_thread_stack(t: &mut task::Task, tid: usize) {
    for s in t.tstacks.iter_mut().filter(|s| s.1 != 0 && s.2 as usize == tid) {
        crate::swap::release_pages(t.l1, s.0, s.1);
        *s = (0, 0, 0);
    }
}

fn name_of(tid: usize) -> [u8; 8] {
    let mut n = [0u8; 8];
    let nm = task::info(tid).name;
    let src = nm.as_bytes();
    n[..src.len().min(8)].copy_from_slice(&src[..src.len().min(8)]);
    n
}

/// A thread's slot is free the moment it is gone (called by `task::die`, under the lifecycle lock).
pub fn thread_gone(tid: usize, leader: usize) {
    EXTRA[leader].fetch_sub(1, Ordering::SeqCst);
    task::set_aspace(tid, None);
    sched::release_core(sched::home_core(tid), task::info(tid).class);
    sched::set_state(tid, State::Free);
}

/// Carve this module's per-task tables (`n` tasks); called once from `task::init_tables`.
pub fn init_tables(n: usize) {
    NO_FIXED_MAPS.init(n, |_| core::sync::atomic::AtomicBool::new(false));
    EPOCH.init(n, |_| const { AtomicU32::new(0) });
    PARENT.init(n, |_| const { AtomicU16::new(NO_PARENT) });
    EXIT_CODE.init(n, |_| const { AtomicU64::new(EXIT_FAULTED) });
    THREAD_QUOTA.init(n, |_| const { AtomicU8::new(0) });
    EXTRA.init(n, |_| const { AtomicU8::new(0) });
    DELEGATED.init(n, |_| const { AtomicUsize::new(0) });
    CHARGE.init(n, |_| const { AtomicUsize::new(0) });
    CONTIG.init(n, |_| const { AtomicUsize::new(0) });
    LOADED.init(n, |_| const { [const { AtomicU64::new(0) }; BITMAP_WORDS] });
    EXEC.init(n, |_| const { [const { AtomicU64::new(0) }; BITMAP_WORDS] });
    IMG_BASE.init(n, |_| const { AtomicUsize::new(USER_BASE) });
    FS_PAGE.init(n, |_| const { AtomicU8::new(NO_FS) });
    FS_GEN.init(n, |_| const { AtomicU64::new(0) });
    NET_PAGE.init(n, |_| const { AtomicU8::new(NO_FS) });
    NET_GEN.init(n, |_| const { AtomicU64::new(0) });
}
