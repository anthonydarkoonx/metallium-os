//! Asynchronous submission/completion rings (io_uring-style), one pair per task
//! in a single shared page.
//!
//!   page layout     offset  contents
//!                   0       sq_head  (u32, kernel advances)
//!                   4       sq_tail  (u32, user advances)
//!                   8       cq_head  (u32, user advances)
//!                   12      cq_tail  (u32, kernel advances)
//!                   64      SQ: 32 entries x 48 B  { op u32, slot u32, user_data u64, w[3] u64, pad }
//!                   1600    CQ: 32 entries x 48 B  { user_data u64, res i64, w[3] u64, pad }
//!
//! Each ring has exactly one producer and one consumer, so indices are plain
//! atomics with acquire/release ordering and no lock. Userspace posts entries
//! and polls completions without any syscall; `RING_ENTER` hands a batch to
//! the kernel and optionally sleeps until some completions have arrived.
//!
//! Every accepted submission yields exactly one completion. The kernel only
//! accepts a submission while (unfinished operations + unconsumed completions)
//! is below the CQ size, so the CQ can never overflow.
//!
//! Locking: the producer side of a ring (kernel posting completions) is serialised by the
//! task's *ring lock* (rank above every task lock, so completions can be posted while task
//! locks are held, e.g. when a reply arrives). The task lock itself protects the table of
//! operations still outstanding. `RING_ENTER` never holds the task lock while sending: a send
//! takes an endpoint lock, which ranks below it.
#![forbid(unsafe_code)]
use crate::cap::{Kind, R_SEND};
use crate::ipc::{self, Msg};
use crate::mem;
use crate::mmu::{self, Perm};
use crate::sched;
use crate::sync::{SpinLock, R_RING};
use crate::syscall::{E_FULL, E_INVAL, E_NOMEM};
use crate::task::{self, Task, RING_VA};
use crate::timer;
use crate::frame::phys;
use core::sync::atomic::{AtomicU32, Ordering};

pub const SQ_N: u32 = 32;
pub const CQ_N: u32 = 32;
pub const MAX_PENDING: usize = 16;
const OFF_SQ_HEAD: usize = 0;
const OFF_SQ_TAIL: usize = 4;
const OFF_CQ_HEAD: usize = 8;
const OFF_CQ_TAIL: usize = 12;
const SQ_OFF: usize = 64;
const CQ_OFF: usize = 1600;
const ENT: usize = 48;

pub const OP_NOP: u32 = 0;
pub const OP_SEND: u32 = 1;
pub const OP_CALL: u32 = 2;
pub const OP_TIMEOUT: u32 = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PKind {
    Free,
    Call,
    Timeout,
}

/// An operation whose completion is still outstanding.
#[derive(Clone, Copy)]
pub struct Pending {
    pub kind: PKind,
    pub user_data: u64,
    /// For calls: the server currently handling it.
    pub callee: Option<u16>,
    pub deadline: u64,
}

impl Pending {
    pub const FREE: Pending = Pending { kind: PKind::Free, user_data: 0, callee: None, deadline: 0 };
}

/// Operations outstanding across all tasks: lets the scheduler tell "idle" from "deadlocked"
/// without looking into any task.
static OUTSTANDING: AtomicU32 = AtomicU32::new(0);

pub fn async_ops_outstanding() -> bool {
    OUTSTANDING.load(Ordering::Relaxed) > 0
}

/// Serialises kernel-side producers of each task's completion ring.
static RING_LOCKS: crate::table::Table<SpinLock<()>> = crate::table::Table::new();
fn idx(pa: usize, off: usize) -> &'static AtomicU32 {
    crate::frame::phys::atomic_u32(pa + off)
}

/// Create the task's ring page. `t` is the (locked) caller.
pub fn setup(t: &mut Task, tid: usize) -> Result<usize, i64> {
    if t.ring_pa != 0 {
        return Err(E_INVAL);
    }
    let owner = mem::OWNER_TASK0 + tid as u16;
    // Unmovable: the kernel keeps raw pointers into this page while it is not holding the task lock, so
    // the compactor must never migrate it.
    let pa = mem::alloc(owner).ok_or(E_NOMEM)?;
    // a random page of the ring window (another mapping there, which is unlikely, makes it try again)
    let mut va = 0;
    for _ in 0..8 {
        let try_va = RING_VA + crate::rand::below(task::RING_SLIDE_PAGES) * mem::PAGE;
        if mmu::map_user(t.l1, try_va, pa, Perm::Rw, owner).is_ok() {
            va = try_va;
            break;
        }
    }
    if va == 0 {
        mem::free(pa);
        return Err(E_NOMEM);
    }
    t.ring_pa = pa;
    t.pending = [Pending::FREE; MAX_PENDING];
    Ok(va)
}

/// Drop ring state when a task dies (the page itself is reclaimed with its other frames).
pub fn reset_task(t: &mut Task) {
    let live = t.pending.iter().filter(|p| p.kind != PKind::Free).count() as u32;
    OUTSTANDING.fetch_sub(live, Ordering::Relaxed);
    t.ring_pa = 0;
    t.pending = [Pending::FREE; MAX_PENDING];
}

fn unconsumed(pa: usize) -> u32 {
    idx(pa, OFF_CQ_TAIL).load(Ordering::Acquire).wrapping_sub(idx(pa, OFF_CQ_HEAD).load(Ordering::Acquire))
}

fn outstanding(t: &Task) -> u32 {
    t.pending.iter().filter(|p| p.kind != PKind::Free).count() as u32 + unconsumed(t.ring_pa)
}

fn free_pending(t: &mut Task, i: usize) {
    if t.pending[i].kind != PKind::Free {
        t.pending[i] = Pending::FREE;
        OUTSTANDING.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Post one completion to the ring at `ring_pa` of task `tid`; wakes the task if it sleeps in
/// `RING_ENTER` for enough of them. (`ring_pa` is read from the locked task by the caller.)
pub fn post(tid: usize, ring_pa: usize, user_data: u64, res: i64, w: [u64; 3]) {
    if ring_pa == 0 {
        return;
    }
    {
        let _p = RING_LOCKS[tid].lock(R_RING + tid as u16);
        let tail = idx(ring_pa, OFF_CQ_TAIL).load(Ordering::Relaxed);
        if unconsumed(ring_pa) >= CQ_N {
            return; // unreachable by construction (see module docs)
        }
        let e = ring_pa + CQ_OFF + (tail % CQ_N) as usize * ENT;
        phys::write_u64(e, user_data);
        phys::write_i64(e + 8, res);
        for (i, v) in w.iter().enumerate() {
            phys::write_u64(e + 16 + 8 * i, *v);
        }
        idx(ring_pa, OFF_CQ_TAIL).store(tail.wrapping_add(1), Ordering::Release);
    }
    sched::ring_progress(tid, unconsumed(ring_pa));
}

/// A reply arrived for async call `tag` of `caller` (whose locked state is `tc`), served by `server`.
pub fn complete_call(tc: &mut Task, caller: usize, tag: u8, server: usize, w: [u64; 3]) -> bool {
    let Some(p) = tc.pending.get(tag as usize - 1).copied() else { return false };
    if p.kind != PKind::Call || p.callee != Some(server as u16) {
        return false;
    }
    free_pending(tc, tag as usize - 1);
    post(caller, tc.ring_pa, p.user_data, 0, w);
    true
}

pub fn set_callee(sender: &mut Task, tag: u8, server: usize) {
    if let Some(p) = sender.pending.get_mut(tag as usize - 1) {
        if p.kind == PKind::Call {
            p.callee = Some(server as u16);
        }
    }
}

/// An async call that was still queued on an endpoint that no longer exists fails.
pub fn fail_queued(t: &mut Task, tid: usize, tag: u8, res: i64) {
    if let Some(p) = t.pending.get(tag as usize - 1).copied() {
        if p.kind == PKind::Call && p.callee.is_none() {
            free_pending(t, tag as usize - 1);
            post(tid, t.ring_pa, p.user_data, res, [0; 3]);
        }
    }
}

/// `server` died: every async call from task `c` (whose locked state is `t`) that it was handling fails.
pub fn fail_calls_to(t: &mut Task, c: usize, server: usize) {
    for i in 0..MAX_PENDING {
        let p = t.pending[i];
        if p.kind == PKind::Call && p.callee == Some(server as u16) {
            free_pending(t, i);
            post(c, t.ring_pa, p.user_data, crate::syscall::E_DEAD, [0; 3]);
        }
    }
}

/// Called once per timer tick (on core 0): complete timeouts that have expired.
pub fn expire_timeouts() {
    if !async_ops_outstanding() {
        return;
    }
    let now = timer::ticks();
    for c in 0..task::limit() {
        let mut t = task::lock(c);
        if t.ring_pa == 0 {
            continue;
        }
        for i in 0..MAX_PENDING {
            let p = t.pending[i];
            if p.kind == PKind::Timeout && p.deadline <= now {
                free_pending(&mut t, i);
                post(c, t.ring_pa, p.user_data, 0, [0; 3]);
            }
        }
    }
}

fn alloc_pending(t: &mut Task, p: Pending) -> Option<usize> {
    let slot = t.pending.iter().position(|x| x.kind == PKind::Free)?;
    t.pending[slot] = p;
    OUTSTANDING.fetch_add(1, Ordering::Relaxed);
    Some(slot)
}

/// One submission, taken off the SQ under the task lock.
struct Sqe {
    op: u32,
    slot: u32,
    ud: u64,
    w: [u64; 3],
    /// Pending-table slot reserved for it (CALL / TIMEOUT).
    pend: Option<usize>,
    ring_pa: usize,
}

/// Take the next submission, if the CQ has room for its completion.
fn take_one(cur: usize, pa: usize) -> Option<Sqe> {
    let mut t = task::lock(cur);
    let tail = idx(pa, OFF_SQ_TAIL).load(Ordering::Acquire);
    let head = idx(pa, OFF_SQ_HEAD).load(Ordering::Relaxed);
    if head == tail || outstanding(&t) >= CQ_N {
        return None;
    }
    let e = pa + SQ_OFF + (head % SQ_N) as usize * ENT;
    let (op, slot, ud, w) = (
        phys::read_u32(e),
        phys::read_u32(e + 4),
        phys::read_u64(e + 8),
        [phys::read_u64(e + 16), phys::read_u64(e + 24), phys::read_u64(e + 32)],
    );
    idx(pa, OFF_SQ_HEAD).store(head.wrapping_add(1), Ordering::Release);
    let pend = match op {
        OP_CALL => alloc_pending(&mut t, Pending { kind: PKind::Call, user_data: ud, callee: None, deadline: 0 }),
        OP_TIMEOUT => alloc_pending(&mut t, Pending { kind: PKind::Timeout, user_data: ud, callee: None, deadline: timer::ticks() + w[0] }),
        _ => None,
    };
    Some(Sqe { op, slot, ud, w, pend, ring_pa: t.ring_pa })
}

fn exec(cur: usize, q: Sqe) {
    let fail = |res: i64| {
        let mut t = task::lock(cur);
        if let Some(i) = q.pend {
            free_pending(&mut t, i);
        }
        post(cur, t.ring_pa, q.ud, res, [0; 3]);
    };
    match q.op {
        OP_NOP => post(cur, q.ring_pa, q.ud, 0, [0; 3]),
        OP_SEND | OP_CALL => {
            let c = match crate::syscall::lookup(cur, q.slot as u64, Kind::Endpoint, R_SEND) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            let call = q.op == OP_CALL;
            let (tag, no_slot) = match (call, q.pend) {
                (true, Some(i)) => (i as u8 + 1, false),
                (true, None) => (0, true),
                _ => (0, false),
            };
            if no_slot {
                return fail(E_FULL);
            }
            match ipc::send(cur, c.obj, Msg { sender: cur as u16, call, tag, w: q.w, cap: None }) {
                Ok(()) if call => {} // completes when the server replies
                Ok(()) => post(cur, q.ring_pa, q.ud, 0, [0; 3]),
                Err(ipc::SendErr::Full) => fail(E_FULL),
            }
        }
        OP_TIMEOUT => {
            if q.pend.is_none() {
                fail(E_FULL);
            }
        }
        _ => fail(E_INVAL),
    }
}

/// Consume up to `to_submit` queued submissions. Returns how many were taken and
/// whether the caller was put to sleep because fewer than `min_complete` completions are ready.
pub fn enter(cur: usize, to_submit: u32, min_complete: u32) -> Result<(u32, bool), i64> {
    let pa = task::lock(cur).ring_pa;
    if pa == 0 {
        return Err(E_INVAL);
    }
    let mut n = 0;
    while n < to_submit {
        let Some(q) = take_one(cur, pa) else { break };
        exec(cur, q);
        n += 1;
    }
    // never wait for more completions than there can be: those queued plus the operations still in flight
    // (found by the syscall fuzzer: a task asking for 3 with nothing outstanding slept for ever)
    let can_complete = outstanding(&task::lock(cur));
    let min = min_complete.min(CQ_N).min(can_complete);
    // the result register must be written before the task can possibly be woken
    task::frame(cur).x[0] = n as u64;
    let sleep = sched::ring_wait_unless(cur, min, || unconsumed(pa) >= min);
    Ok((n, sleep))
}

/// Carve this module's per-task tables (`n` tasks); called once from `task::init_tables`.
pub fn init_tables(n: usize) {
    RING_LOCKS.init(n, |_| const { SpinLock::new(()) });
}
