//! Swap: compress cold private pages into a RAM pool, and bring them back when touched.
//!
//! The *mechanism* is here; the *policy* (when memory is tight enough to evict) is the userspace memory
//! daemon, which reaches `evict` through a `MemCtl` capability with the swap right.
//!
//! * **Aging.** Pages are mapped with the access flag set. A pass of `evict` clears the flag of every page it
//!   meets that has it set (a *young* page) and moves on; a page found with the flag still clear since the
//!   previous pass has not been touched in between, so it is cold and is evicted. A touch of an aged page takes
//!   an access flag fault, which sets the flag again (`handle_fault`). This is the clock algorithm.
//! * **Eviction.** Under the owning task's lock: the descriptor is made invalid and every TLB flushed (so no
//!   core can still reach the frame), the page is compressed into the store, the descriptor becomes a *swapped*
//!   one carrying the store handle, and the frame is freed. Only pages with exactly one mapping that no kernel
//!   code addresses by physical address are eligible (the allocator's *movable* kind, minus the task's ring).
//! * **Bringing back.** A translation fault on a swapped descriptor allocates a frame, decompresses into it and
//!   re-installs the mapping with its old permissions, then the instruction is retried. The kernel does the
//!   same when a system call needs a user page that is swapped out (`translate`).
//! * **Teardown.** A dying task's store entries are released with its frames (`release_task`).
//!
//! Locking: all of it runs under one task's lock (rank `R_TASK + tid`); the store has its own lock above the
//! task locks and below the allocator's. Compression runs under the task lock only, never under the
//! allocator's.
#![forbid(unsafe_code)]
use crate::mem::{self, FKind, PAGE, RAM_BASE};
use crate::mmu::{self, Page};
use crate::sched;
use crate::task::State;
use crate::sync::{Global, SpinLock, R_SWAP};
use crate::task;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use metallium_zram::{Handle, PageWorkspace, Slot, Zram};

/// Check every page right after compressing it (costs a decompression per eviction).
const VERIFY_STORE: bool = false;
const POOL_BYTES: usize = crate::platform::SWAP_POOL_BYTES;
pub const NSLOTS: usize = crate::platform::SWAP_SLOTS;

static POOL: Global<[u8; POOL_BYTES]> = Global::new([0; POOL_BYTES]);
static SLOTS: Global<[Slot; NSLOTS]> = Global::new([Slot::EMPTY; NSLOTS]);
static WS: Global<PageWorkspace> = Global::new(PageWorkspace::new());
static STORE: SpinLock<Option<Zram<'static>>> = SpinLock::new(None);

static HAND: AtomicUsize = AtomicUsize::new(0);
static OUT: AtomicU64 = AtomicU64::new(0);
static IN: AtomicU64 = AtomicU64::new(0);
static DISCARDED: AtomicU64 = AtomicU64::new(0);
static FULL: AtomicU64 = AtomicU64::new(0);
static AGED: AtomicU64 = AtomicU64::new(0);
static TOUCHED: AtomicU64 = AtomicU64::new(0);

/// The size of the compressed store (a build-time capacity of the platform: the memory daemon scales its policy to it).
pub const fn pool_bytes() -> usize {
    POOL_BYTES
}

fn with_store<R>(f: impl FnOnce(&mut Zram<'static>) -> R) -> R {
    let mut g = STORE.lock(R_SWAP);
    let z = g.get_or_insert_with(|| {
        // (runs once, under the lock: the arenas belong to the store for good)
        Zram::with_zstd(
            POOL.take().expect("swap pool taken twice"),
            SLOTS.take().expect("swap slots taken twice"),
            WS.take().expect("swap workspace taken twice"),
        )
    });
    f(z)
}

fn discard(handle: u32) {
    let _ = with_store(|z| z.discard(Handle(handle)));
    DISCARDED.fetch_add(1, Ordering::Relaxed);
}

/// The entry left the store because the pager wrote the page to disk (pager.rs).
pub fn discard_handle(handle: u32) {
    discard(handle);
}

/// Decompress the store entry `handle` into `out` (it stays in the store).
pub fn load_to(handle: u32, out: &mut [u8; PAGE]) -> bool {
    with_store(|z| z.peek(Handle(handle), out)).is_ok()
}

/// A system call whose user memory was on disk: it has queued the page and must be run again once the page is back
/// (`syscall::handle` rewinds the `svc`). One flag per core: a system call runs to the end on the core it started on.
static RETRY: [core::sync::atomic::AtomicBool; crate::smp::MAX_CPUS] = [const { core::sync::atomic::AtomicBool::new(false) }; crate::smp::MAX_CPUS];

pub fn clear_retry() {
    RETRY[crate::smp::cpu_id()].store(false, Ordering::Relaxed);
}

pub fn take_retry() -> bool {
    RETRY[crate::smp::cpu_id()].swap(false, Ordering::Relaxed)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tried {
    Evicted,
    /// Not a candidate (not movable, task gone, ring page, ...).
    Skipped,
    /// Recently used: its access flag was cleared instead.
    Aged,
    /// The store has no room.
    Full,
}

/// Which pages `evict` may take.
#[derive(Clone, Copy)]
pub struct Filter {
    /// Evict without waiting for a page to prove cold.
    pub force: bool,
    /// Only pages of this task.
    pub only: Option<usize>,
    /// Only pages in the heap window.
    pub heap_only: bool,
}

fn try_evict(frame: usize, tid: usize, va: usize, f: Filter) -> Tried {
    if tid >= task::limit() || f.only.map_or(false, |o| o != tid) || matches!(sched::state(tid), State::Free | State::Dead) {
        return Tried::Skipped;
    }
    let t = task::lock(tid);
    if t.l1 == 0 || (f.heap_only && !(t.heap_base..task::HEAP_END).contains(&va)) {
        return Tried::Skipped;
    }
    let pa = RAM_BASE + frame * PAGE;
    {
        let m = mem::lock();
        if m.kind_at(frame) != FKind::Movable || m.rmap_at(frame) != (tid, va) {
            return Tried::Skipped; // the frame changed hands since the scan looked at it
        }
    }
    if t.ring_pa == pa {
        return Tried::Skipped; // the kernel addresses the ring page by physical address
    }
    if !f.force {
        match mmu::age(t.l1, va, pa) {
            None => return Tried::Skipped,
            Some(true) => {
                AGED.fetch_add(1, Ordering::Relaxed);
                return Tried::Aged;
            }
            Some(false) => {}
        }
    }
    let Some(old) = mmu::evict_begin(t.l1, va, pa) else { return Tried::Skipped };
    mmu::flush_tlb(); // no core can reach the frame any more
    match with_store(|z| {
        crate::frame::phys::with_page(pa, |page| {
            let h = z.store(page)?;
            if VERIFY_STORE {
                // diagnostic: decompress what was just stored and compare it with the page
                let mut back = [0u8; PAGE];
                let same = z.peek(h, &mut back).is_ok() && back == *page;
                if !same {
                    crate::kprintln!("[swap] VERIFY FAILED: page of task {tid} at {va:#x} does not survive compression");
                }
            }
            Ok::<_, metallium_zram::Error>(h)
        })
    }) {
        Ok(h) => {
            mmu::evict_commit(t.l1, va, old, h.0);
            mem::free(pa);
            OUT.fetch_add(1, Ordering::Relaxed);
            Tried::Evicted
        }
        Err(_) => {
            mmu::evict_abort(t.l1, va, old);
            FULL.fetch_add(1, Ordering::Relaxed);
            Tried::Full
        }
    }
}

/// One pass of the clock over the frames: evict up to `budget` pages. Returns (pages evicted, frames looked at).
pub fn evict(budget: usize, f: Filter) -> (usize, usize) {
    let n = mem::total_frames();
    let (mut done, mut looked, mut aged) = (0, 0, false);
    let mut hand = HAND.load(Ordering::Relaxed);
    while done < budget && looked < n {
        hand = (hand + 1) % n;
        looked += 1;
        let (kind, (tid, va)) = {
            let m = mem::lock();
            (m.kind_at(hand), m.rmap_at(hand))
        };
        if kind != FKind::Movable {
            continue;
        }
        match try_evict(hand, tid, va, f) {
            Tried::Evicted => done += 1,
            Tried::Aged => aged = true,
            Tried::Skipped => {}
            Tried::Full => break,
        }
    }
    HAND.store(hand, Ordering::Relaxed);
    if aged {
        mmu::flush_tlb(); // cached descriptors still say "accessed": drop them so the next touch faults
    }
    (done, looked)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Back {
    Ok,
    NoMemory,
    Corrupt,
}

/// Bring the page swapped out at `va` back (the task's lock is held by the caller).
fn bring_in(tid: usize, l1: usize, va: usize) -> Back {
    let Page::Swapped(handle) = mmu::inspect(l1, va) else { return Back::Corrupt };
    crate::pager::cancel_write(l1, Some(va)); // a write of this page to disk is out of date from now on
    let Some(pa) = mem::alloc_movable(mem::OWNER_TASK0 + tid as u16, tid, va) else { return Back::NoMemory };
    if with_store(|z| crate::frame::phys::with_page_mut(pa, |page| z.load(Handle(handle), page))).is_err() || !mmu::install_resident(l1, va, pa) {
        mem::free(pa);
        return Back::Corrupt;
    }
    IN.fetch_add(1, Ordering::Relaxed);
    Back::Ok
}

/// First touch of a page reserved by `MMAP` (the task's lock is held by the caller): allocate a zeroed frame, map it with the reserved
/// protection and count it against the program's memory limit. `write`/`exec` say what the access is; an access the reservation does not allow
/// is `Back::Corrupt` (the caller kills the program or fails the system call), as is going over the limit.
fn populate(tid: usize, t: &task::Task, va: usize, prot: u8, write: bool, exec: bool) -> Back {
    use mmu::{PROT_R, PROT_W, PROT_X};
    let allowed = if exec { prot & PROT_X != 0 } else if write { prot & PROT_W != 0 } else { prot & (PROT_R | PROT_W | PROT_X) != 0 };
    if !allowed {
        return Back::Corrupt;
    }
    let held = t.held_pages().saturating_add(crate::spawn::contig_pages(tid));
    if held >= task::info(tid).heap_quota {
        return Back::Corrupt; // (the program's limit: it dies of it, as a heap that cannot grow would be refused)
    }
    let Some(pa) = mem::alloc_movable(mem::OWNER_TASK0 + tid as u16, tid, va) else { return Back::NoMemory };
    if !mmu::populate_lazy(t.l1, va, pa) {
        mem::free(pa);
        return Back::Corrupt;
    }
    t.anon_pages.fetch_add(1, Ordering::Relaxed);
    Back::Ok
}

/// What a fault means to the swap system.
pub enum Fault {
    /// Not about swap or aging.
    Other,
    /// Handled: run the instruction again.
    Retry,
    /// The page cannot be brought back.
    Kill(&'static str),
    /// The page is on disk and the pager has been asked for it: sleep a tick, then run the instruction again.
    Sleep,
}

/// A user abort (`ec` 0x20 instruction, 0x24 data) of task `tid` at `far`.
///
/// Faults are decided by what the descriptor says *now*, under the task's lock, not by what it said when the
/// fault was taken: another core may have evicted, moved or aged the page in between.
pub fn handle_fault(tid: usize, ec: u64, esr: u64, far: usize) -> Fault {
    if !matches!(ec, 0x20 | 0x24) {
        return Fault::Other;
    }
    let tid = task::aspace(tid); // (a thread's pages are its program's)
    let va = far & !(PAGE - 1);
    let fsc = esr & 0x3F;
    let access_flag = (0x09..=0x0B).contains(&fsc);
    let translation = (0x04..=0x07).contains(&fsc);
    if !access_flag && !translation {
        return Fault::Other;
    }
    for attempt in 0..2 {
        let mut disk_wait = false;
        {
            let t = task::lock(tid);
            match mmu::inspect(t.l1, va) {
                Page::Resident { young, .. } => {
                    if !access_flag {
                        return Fault::Other; // a translation fault on a mapped page: it was being moved (see `trap`)
                    }
                    if !young && mmu::touch(t.l1, va) {
                        TOUCHED.fetch_add(1, Ordering::Relaxed);
                    }
                    return Fault::Retry;
                }
                Page::Absent => return Fault::Other,
                Page::Lazy(prot) => {
                    // data abort: the write bit says whether it was a store (ISS.WnR); instruction abort: a fetch
                    match populate(tid, &t, va, prot, ec == 0x24 && esr & (1 << 6) != 0, ec == 0x20) {
                        Back::Ok => return Fault::Retry,
                        Back::Corrupt => return Fault::Other, // not allowed by the reservation (or over the limit): the program dies as for any bad access
                        Back::NoMemory => {}
                    }
                }
                Page::Swapped(_) => match bring_in(tid, t.l1, va) {
                    Back::Ok => return Fault::Retry,
                    Back::Corrupt => return Fault::Kill("swapped-out page lost"),
                    Back::NoMemory => {}
                },
                Page::Disk(slot) => match crate::pager::request_in(tid, va, slot) {
                    crate::pager::Wait::Sleep => disk_wait = true,
                    crate::pager::Wait::Lost => return Fault::Kill("page on disk and the pager is gone"),
                },
            }
        }
        if disk_wait {
            crate::pager::kick_if_pending(); // (no lock held now)
            return Fault::Sleep;
        }
        if attempt == 0 {
            // out of frames: make room by evicting something (the lock is dropped: eviction takes others)
            evict(16, Filter { force: true, only: None, heap_only: false });
        }
    }
    Fault::Kill("out of memory bringing a swapped-out page back")
}

/// Physical address of user address `va` in a task whose lock the caller holds, bringing the page back from
/// the store first if it was swapped out.
pub fn translate(t: &task::Task, tid: usize, va: usize) -> Option<usize> {
    translate_for(t, tid, va, false)
}

/// `translate` for an address the kernel is about to write: refuses a page the program maps read-only (see `mmu::translate_writable`).
pub fn translate_writable(t: &task::Task, tid: usize, va: usize) -> Option<usize> {
    translate_for(t, tid, va, true)
}

fn translate_for(t: &task::Task, tid: usize, va: usize, write: bool) -> Option<usize> {
    let walk = |va| if write { mmu::translate_writable(t.l1, va) } else { mmu::translate(t.l1, va) };
    if let Some(pa) = walk(va) {
        return Some(pa);
    }
    if write && mmu::translate(t.l1, va).is_some() {
        return None; // mapped, but read-only for the program
    }
    let page = va & !(PAGE - 1);
    match mmu::inspect(t.l1, page) {
        Page::Lazy(prot) if populate(tid, t, page, prot, write, false) == Back::Ok => return walk(va), // (untouched `MMAP` memory the kernel is asked to read or fill)
        Page::Swapped(_) if bring_in(tid, t.l1, page) == Back::Ok => return walk(va),
        Page::Disk(slot) => {
            // the caller fails; a system call on the list in `syscall::handle` is run again when the page is back
            if let crate::pager::Wait::Sleep = crate::pager::request_in(tid, page, slot) {
                RETRY[crate::smp::cpu_id()].store(true, Ordering::Relaxed);
            }
        }
        _ => {}
    }
    None
}

/// Free `count` pages starting at `first` (page-aligned, stepping by one page), whether each is in a frame or in the
/// store (the task's lock is held). Returns how many had something mapped.
///
/// A frame goes back to the allocator only after the TLB flush that follows its unmapping: another core
/// running a thread of the same program may still hold a translation for it, and a frame freed too early can be handed to
/// another program while that thread can still read and write it. Frames are collected in batches.
pub fn release_pages(l1: usize, first: usize, count: usize) -> usize {
    release_range(l1, first, count, false).1
}

/// `release_pages` for any range, optionally only the pages of `MMAP` regions (`anon_only`; the others are left alone), and reserved pages that were
/// never touched are forgotten too. Returns (pages that were something: a frame, a store entry, a disk slot or a reservation, and how many of
/// those held a frame, a store entry or a disk slot).
pub fn release_range(l1: usize, first: usize, count: usize, anon_only: bool) -> (usize, usize) {
    const BATCH: usize = 64;
    let mut pending = [0usize; BATCH];
    let mut n = 0;
    let mut released = 0;
    let mut entries = 0;
    let drain = |pending: &[usize]| {
        if !pending.is_empty() {
            mmu::flush_tlb(); // no core can reach these frames any more
            for &pa in pending {
                mem::free(pa);
            }
        }
    };
    for p in 0..count {
        let va = first + p * PAGE;
        if anon_only && mmu::is_anon(l1, va) != Some(true) {
            continue;
        }
        match mmu::inspect(l1, va) {
            Page::Resident { pa, .. } => {
                mmu::unmap_user(l1, va);
                pending[n] = pa;
                n += 1;
                released += 1;
                entries += 1;
                if n == BATCH {
                    drain(&pending[..n]);
                    n = 0;
                }
            }
            Page::Swapped(_) | Page::Disk(_) => {
                crate::pager::cancel_write(l1, Some(va));
                if let Some((h, disk)) = mmu::clear_swapped(l1, va) {
                    if disk {
                        crate::pager::free_slot(h);
                    } else {
                        discard(h);
                    }
                }
                released += 1;
                entries += 1;
            }
            Page::Lazy(_) => {
                mmu::clear_lazy(l1, va);
                entries += 1;
            }
            Page::Absent => {}
        }
    }
    drain(&pending[..n]);
    mmu::flush_tlb(); // (also covers the entries that were swapped out)
    (entries, released)
}

/// A task is being torn down: its store entries go with its frames.
pub fn release_task(l1: usize) {
    if l1 != 0 {
        crate::pager::cancel_write(l1, None);
        mmu::for_each_swapped(l1, |h, disk| if disk { crate::pager::free_slot(h) } else { discard(h) });
    }
}

pub struct Stats {
    /// Pages in the store now.
    pub stored: u64,
    /// Compressed bytes they take.
    pub bytes: u64,
    pub out: u64,
    pub back: u64,
    pub full: u64,
    pub touched: u64,
}

pub fn stats() -> Stats {
    let (out, back, gone) = (OUT.load(Ordering::Relaxed), IN.load(Ordering::Relaxed), DISCARDED.load(Ordering::Relaxed));
    Stats {
        stored: out.saturating_sub(back + gone),
        bytes: with_store(|z| z.stored_bytes()) as u64,
        out,
        back,
        full: FULL.load(Ordering::Relaxed),
        touched: TOUCHED.load(Ordering::Relaxed),
    }
}
