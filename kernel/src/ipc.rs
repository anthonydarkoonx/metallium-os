//! Kernel endpoints: bounded message queues with at most one blocked receiver,
//! each behind its own lock (rank `R_EP + endpoint`).
//!
//! Ordering rules that make the lock-free-looking hand-offs safe:
//!  * a receiver registers as waiter and goes to sleep inside one critical
//!    section of the endpoint lock; a sender completes its delivery inside the
//!    same lock. So a wakeup can neither be lost nor arrive early.
//!  * a synchronous caller is marked blocked *before* its message becomes
//!    visible to the receiver (delivered or queued): the receiver may run on
//!    another core at once and reply, and the reply must find the caller blocked.
//!  * the sender's priority is recorded for priority inheritance at the moment
//!    of delivery/queueing, in atomics, so the scheduler never has to look here.
#![forbid(unsafe_code)]
use crate::sched::{self, NO_PRIO};
use crate::sync::{Guard, SpinLock, R_EP, R_EPCLAIM};
use crate::task::{self, frame, State};
use core::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use crate::cap::{Cap, Kind, NodeId, R_RECV};

/// Endpoints 0..24 are the boot-time services'; the rest are created at run time (`EP_CREATE`, see below).
pub const EP_FIRST_DYNAMIC: u16 = 25;
/// The most endpoints a boot can have (lock ranks are reserved for this many); `nep()` is how many it does have.
pub const MAX_EPS: usize = 16500;
static NEP: AtomicUsize = AtomicUsize::new(0);

pub fn nep() -> usize {
    NEP.load(Ordering::Relaxed)
}

/// How many endpoints a machine with `tasks` task slots gets: the boot-time ones and `MAX_OWNED_EPS` for every slot.
pub fn eps_for(tasks: usize) -> usize {
    (EP_FIRST_DYNAMIC as usize + MAX_OWNED_EPS * tasks).min(MAX_EPS)
}

/// Carve the endpoint tables for `n` endpoints; called once from `task::init_tables`.
pub fn init_tables(n: usize) {
    assert!(n > EP_FIRST_DYNAMIC as usize && n <= MAX_EPS && nep() == 0, "endpoint tables: bad size or initialised twice");
    NEP.store(n, Ordering::Relaxed);
    EP_NODE.init(n, |_| AtomicU16::new(NO_OWNER_NODE));
    EP_TASK.init(n, |_| AtomicU16::new(NO_OWNER));
    EPS.init(n, |_| SpinLock::new(Endpoint { q: [NO_MSG; QLEN], head: 0, len: 0, waiter: None, accepts: false }));
    BEST.init(n, |_| AtomicU8::new(NO_PRIO));
    QUEUED.init(n, |_| AtomicU8::new(0));
    BEST_DEADLINE.init(n, |_| AtomicU64::new(u64::MAX));
}
pub const EP_SERVICE: u16 = 0;
pub const EP_DRIVER: u16 = 1;
pub const EP_BLK: u16 = 2;
pub const EP_ROFS: u16 = 3;
pub const EP_LFS: u16 = 4;
pub const EP_VFS: u16 = 5;
/// The session service (`sessiond`): the greeter calls it to make accounts and log in; the boot flow (or a test conductor) hands the receive right to the service it starts.
pub const EP_SESSIONS: u16 = 14;
/// Benchmark pairs: server request endpoint and client start endpoint, per pair 0..4.
pub const EP_BENCH_SRV: u16 = 6;
pub const EP_BENCH_GO: u16 = 10;
/// The display driver.
pub const EP_GPU: u16 = 16;
/// The system-information screen: told to start once the display tests are done.
pub const EP_INFO: u16 = 17;
/// The keyboard driver, polled by the shell.
pub const EP_KBD: u16 = 18;
/// Chaos test: the conductor tells the monkey when to start.
pub const EP_MONKEY: u16 = 19;
/// The network service (`netd`): programs call it, the network driver tells it about frames and ticks.
pub const EP_NET: u16 = 20;
/// The audio service (a platform with an audio device runs it as role 20; others have none).
pub const EP_AUDIO: u16 = 21;
/// The consoles of ttys 1..3 (role 22), each told by the conductor when a session has its tty: 22, 23, 24.
pub const EP_TTY: u16 = 22;
pub const BENCH_PAIRS: usize = 4;
const QLEN: usize = 8;

#[derive(Clone, Copy)]
pub struct Msg {
    pub sender: u16,
    pub call: bool,
    /// 0 = synchronous caller blocked in IPC_CALL; otherwise 1 + index of the async call in the sender's ring.
    pub tag: u8,
    pub w: [u64; 3],
    /// A capability the sender offers with the message: a snapshot of its own capability (the node and generation it was made under, so that the copy
    /// that is made on delivery hangs under it and dies with it), rights already narrowed. Nothing is made until a receiver that asked for one takes
    /// the message (`install_cap`), so a message that is dropped or never received costs no node.
    pub cap: Option<Cap>,
}

const NO_MSG: Msg = Msg { sender: 0, call: false, tag: 0, w: [0; 3], cap: None };

/// What a receiver is told when a capability was offered and it could not be given: no free slot, over the node allowance, or the sender's capability
/// was revoked in the meantime. (A slot number plus one is 1..=32; this is outside that.)
pub const CAP_FAILED: u64 = 0xFF;

pub struct Endpoint {
    q: [Msg; QLEN],
    head: usize,
    len: usize,
    /// Receiver sleeping on this endpoint.
    pub waiter: Option<u16>,
    /// ... and whether it asked to be given a capability that comes with the message (`IPC_RECV` flag 2).
    pub accepts: bool,
}

impl Endpoint {
    /// Drop calls still queued from `tid`, a task that is dying. Nobody waits for their replies any
    /// more, and the task id is about to be reused by a fresh instance, which must not be confused
    /// with them (a server would link the stale call to the new instance and reply into its state).
    /// Plain notifications (`call == false`) stay: they were sent and are still deliverable.
    pub fn purge_calls_from(&mut self, e: u16, tid: u16) {
        let mut kept = [NO_MSG; QLEN];
        let mut n = 0;
        for k in 0..self.len {
            let m = self.q[(self.head + k) % QLEN];
            if !(m.call && m.sender == tid) {
                kept[n] = m;
                n += 1;
            }
        }
        self.q = kept;
        self.head = 0;
        self.len = n;
        self.refresh_best(e);
    }
}

/// Owner capability node of each run-time endpoint (`NO_OWNER`: free). The endpoint lives as long as that node.
const NO_OWNER: u16 = u16::MAX;
const NO_OWNER_NODE: NodeId = NodeId::MAX;
static EP_NODE: crate::table::Table<AtomicU16> = crate::table::Table::new();
/// ... and the task that created it (for its quota).
static EP_TASK: crate::table::Table<AtomicU16> = crate::table::Table::new();
/// Most run-time endpoints one program (all its threads together) may own at a time, and the ones programs may never take.
pub const MAX_OWNED_EPS: usize = 16;
const EP_RESERVE: usize = 16;
static CLAIM: SpinLock<()> = SpinLock::new(());

/// The capability node that is the root of endpoint `e` (the creator's own capability), if it is in use.
/// Can anything be queued on, or waiting at, endpoint `e`? (A boot endpoint always may; a run-time one only while it has an owner.)
pub fn in_use(e: usize) -> bool {
    e < EP_FIRST_DYNAMIC as usize || EP_NODE[e].load(Ordering::SeqCst) != NO_OWNER_NODE
}

pub fn root_node(e: u16) -> Option<NodeId> {
    let n = EP_NODE.iter().nth(e as usize)?.load(Ordering::SeqCst);
    (n != NO_OWNER_NODE).then_some(n)
}

/// The task that created run-time endpoint `e` (`None` for a boot endpoint or a free one).
pub fn dynamic_owner(e: u16) -> Option<u16> {
    if e < EP_FIRST_DYNAMIC || e as usize >= nep() {
        return None;
    }
    let t = EP_TASK[e as usize].load(Ordering::SeqCst);
    (EP_NODE[e as usize].load(Ordering::SeqCst) != NO_OWNER_NODE && t != NO_OWNER).then_some(t)
}

/// Claim a free run-time endpoint for `task`, owned by capability node `node`. None if the task is at its quota or
/// none is free.
pub fn claim_dynamic(task: usize, node: NodeId) -> Option<u16> {
    let _claiming = CLAIM.lock(R_EPCLAIM); // (threads of one program race: the count and the claim are one step)
    let prog = task::aspace(task);
    let in_use = |e: usize| EP_NODE[e].load(Ordering::SeqCst) != NO_OWNER_NODE;
    if crate::spawn::is_program(prog) {
        let owned = (EP_FIRST_DYNAMIC as usize..nep()).filter(|&e| in_use(e) && task::aspace(EP_TASK[e].load(Ordering::SeqCst) as usize) == prog).count();
        let free = (EP_FIRST_DYNAMIC as usize..nep()).filter(|&e| !in_use(e)).count();
        if owned >= MAX_OWNED_EPS || free <= EP_RESERVE {
            return None;
        }
    } else if (EP_FIRST_DYNAMIC as usize..nep()).filter(|&e| in_use(e) && EP_TASK[e].load(Ordering::SeqCst) == task as u16).count() >= MAX_OWNED_EPS {
        return None;
    }
    for e in EP_FIRST_DYNAMIC as usize..nep() {
        if EP_NODE[e].compare_exchange(NO_OWNER_NODE, node, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            EP_TASK[e].store(task as u16, Ordering::SeqCst);
            return Some(e as u16);
        }
    }
    None
}

/// The owner capabilities in `marked` are being revoked (their nodes are dead already): the run-time endpoints
/// they own cease to exist. Whoever waits on them or in their queues is told, so nobody sleeps for ever.
pub fn destroy_marked(marked: &crate::cap::NodeSet) {
    for e in EP_FIRST_DYNAMIC as usize..nep() {
        let n = EP_NODE[e].load(Ordering::SeqCst);
        if n == NO_OWNER_NODE || !marked.has(n as usize) {
            continue;
        }
        let dead = crate::syscall::E_DEAD;
        let mut ep = lock_ep(e as u16);
        if let Some(r) = ep.waiter.take() {
            frame(r as usize).x[0] = dead as u64;
            sched::wake_if(r as usize, State::RecvWait(e as u16));
        }
        let (head, len) = (ep.head, ep.len);
        let queued: [Msg; QLEN] = core::array::from_fn(|k| ep.q[(head + k) % QLEN]);
        ep.head = 0;
        ep.len = 0;
        ep.refresh_best(e as u16);
        for m in queued.iter().take(len) {
            let s = m.sender as usize;
            if !m.call {
                continue; // a plain notification nobody will read
            }
            if m.tag == 0 {
                frame(s).x[0] = dead as u64;
                sched::wake_if(s, State::CallWait);
            } else {
                crate::ring::fail_queued(&mut task::lock(s), s, m.tag, dead);
            }
        }
        EP_TASK[e].store(NO_OWNER, Ordering::SeqCst);
        EP_NODE[e].store(NO_OWNER_NODE, Ordering::SeqCst);
    }
}

static EPS: crate::table::Table<SpinLock<Endpoint>> = crate::table::Table::new();

/// Best (lowest) priority among the senders of requests queued on each endpoint.
static BEST: crate::table::Table<AtomicU8> = crate::table::Table::new();
/// How many messages are queued on each endpoint, readable without its lock (a hint: for deciding which endpoints are worth locking).
static QUEUED: crate::table::Table<AtomicU8> = crate::table::Table::new();

pub fn has_queued(e: usize) -> bool {
    QUEUED[e].load(Ordering::SeqCst) != 0
}
/// Earliest deadline among those senders that are real-time (or serving a real-time task).
static BEST_DEADLINE: crate::table::Table<AtomicU64> = crate::table::Table::new();

pub fn lock_ep(e: u16) -> Guard<'static, Endpoint> {
    EPS[e as usize].lock(R_EP + e)
}

pub fn best_queued(e: u16) -> u8 {
    BEST[e as usize].load(Ordering::Relaxed)
}

pub fn best_queued_deadline(e: u16) -> u64 {
    BEST_DEADLINE[e as usize].load(Ordering::Relaxed)
}

impl Endpoint {
    fn refresh_best(&self, e: u16) {
        let mut best = NO_PRIO;
        let mut deadline = u64::MAX;
        for k in 0..self.len {
            let sender = self.q[(self.head + k) % QLEN].sender as usize;
            best = best.min(sched::priority_to_pass_on(sender));
            deadline = deadline.min(sched::deadline_to_pass_on(sender));
        }
        BEST[e as usize].store(best, Ordering::Relaxed);
        QUEUED[e as usize].store(self.len as u8, Ordering::SeqCst);
        BEST_DEADLINE[e as usize].store(deadline, Ordering::Relaxed);
    }
}

/// Record who `rcv` now serves: reply link, the caller's "being served by" link, inherited priority.
/// The caller is blocked already (see module docs); its task lock is taken here together with ours.
fn link_call(rcv: usize, m: &Msg) {
    let sender = m.sender as usize;
    if rcv == sender {
        let mut t = task::lock(rcv);
        t.reply_to = Some((m.sender, m.tag));
        t.callee = Some(rcv as u16);
    } else {
        // both tasks, in ascending order
        let (lo, hi) = if rcv < sender { (rcv, sender) } else { (sender, rcv) };
        let mut glo = task::lock(lo);
        let mut ghi = task::lock(hi);
        let (r, s) = if rcv < sender { (&mut *glo, &mut *ghi) } else { (&mut *ghi, &mut *glo) };
        r.reply_to = Some((m.sender, m.tag));
        set_callee(s, m.tag, rcv);
    }
    sched::inherit_from(rcv, sender);
}

fn set_callee(sender: &mut task::Task, tag: u8, rcv: usize) {
    if tag == 0 {
        sender.callee = Some(rcv as u16);
    } else {
        crate::ring::set_callee(sender, tag, rcv);
    }
}

/// Give the capability `c`, offered with a message, to task `rcv` (whose table `t` the caller holds): a copy under the sender's node in the first free
/// slot, charged to the receiver's program. The slot plus one, or `CAP_FAILED`. The caller holds the lifecycle lock (as `CAP_GRANT` does), so no revoke and
/// no end of a task can run between the check that the sender's capability is alive (made under the node-table lock by `mint_for`) and the copy being in
/// the table.
fn install_cap(t: &mut task::Task, rcv: usize, c: &Cap) -> u64 {
    if c.kind == Kind::None || c.kind == Kind::Console || !c.alive() {
        return CAP_FAILED;
    }
    let Some(dst) = (0..crate::cap::NCAPS).find(|&i| i != crate::syscall::CONSOLE_SLOT && t.caps[i].kind == Kind::None) else { return CAP_FAILED };
    let Some(node) = crate::cap::mint_for(task::aspace(rcv), Some(c.parent_ref())) else { return CAP_FAILED };
    t.caps[dst] = c.under(c.rights, node);
    if c.kind == Kind::Endpoint && c.rights & R_RECV != 0 {
        sched::note_recv_endpoint(rcv, c.obj);
    }
    dst as u64 + 1
}

/// Write a message into a receiver's saved registers (its pending IPC_RECV result): `x1` the sender, `x2`..`x4` the words, `x5` bit 0 whether it is a call
/// and bits 8..15 the capability that came with it (slot plus one, or `CAP_FAILED`), which is only given to a receiver that `accept`s one.
fn deliver_regs(rcv: usize, m: &Msg, accept: bool) {
    let info = match (accept, m.cap) {
        (true, Some(c)) => install_cap(&mut task::lock(rcv), rcv, &c),
        _ => 0,
    };
    let mut f = frame(rcv);
    f.x[0] = 0;
    f.x[1] = m.sender as u64;
    f.x[2] = m.w[0];
    f.x[3] = m.w[1];
    f.x[4] = m.w[2];
    f.x[5] = m.call as u64 | info << 8;
}

pub enum SendErr {
    Full,
}

/// Send `m` (from task `cur`) to endpoint `e`. For a synchronous call the sender is left
/// blocked in `CallWait`; the caller of this function then reports `Block`.
pub fn send(cur: usize, e: u16, m: Msg) -> Result<(), SendErr> {
    let mut ep = lock_ep(e);
    let sync_call = m.call && m.tag == 0;
    if let Some(r) = ep.waiter.take() {
        let r = r as usize;
        deliver_regs(r, &m, ep.accepts);
        if m.call {
            link_call(r, &m);
        }
        // sender blocked first, receiver runnable second, in one scheduler critical section
        sched::block_and_wake(sync_call.then_some((cur, State::CallWait)), Some(r));
        return Ok(());
    }
    if ep.len == QLEN {
        return Err(SendErr::Full);
    }
    // (one program, with all its threads, may not fill a shared server's queue: it gets half)
    let prog = task::aspace(cur);
    if crate::spawn::is_program(prog) && (0..ep.len).filter(|&k| task::aspace(ep.q[(ep.head + k) % QLEN].sender as usize) == prog).count() >= QLEN / 2 {
        return Err(SendErr::Full);
    }
    let at = (ep.head + ep.len) % QLEN;
    ep.q[at] = m;
    ep.len += 1;
    ep.refresh_best(e);
    if sync_call {
        sched::set_state(cur, State::CallWait);
    }
    Ok(())
}

pub enum Recv {
    Got,
    Blocked,
    Busy,
    /// Nothing queued and the caller asked not to wait.
    Empty,
}

/// Receive on endpoint `e` for task `me`. On `Got` the message is already in `me`'s registers;
/// on `Blocked` the task is registered and asleep in `RecvWait`.
pub fn recv(me: usize, e: u16, block: bool, accept: bool) -> Recv {
    let mut ep = lock_ep(e);
    if ep.len > 0 {
        let m = ep.q[ep.head];
        ep.head = (ep.head + 1) % QLEN;
        ep.len -= 1;
        ep.refresh_best(e);
        deliver_regs(me, &m, accept);
        if m.call {
            link_call(me, &m);
        }
        return Recv::Got;
    }
    if !block {
        return Recv::Empty;
    }
    if ep.waiter.is_some() {
        return Recv::Busy;
    }
    ep.waiter = Some(me as u16);
    ep.accepts = accept;
    sched::set_state(me, State::RecvWait(e));
    Recv::Blocked
}

/// Park the call `server` is serving (a synchronous one): the caller stays blocked, the server is free to serve others, and gets back the caller's id as a token for `reply_to`. A server
/// that parks callers holds them in a table of its own; one that dies leaves them to the usual clean-up of callers of a dead server.
pub fn defer(server: usize) -> Option<u64> {
    let mut t = task::lock(server);
    match t.reply_to {
        Some((c, 0)) => {
            t.reply_to = None;
            drop(t);
            sched::clear_inherit(server);
            Some(c as u64)
        }
        _ => None,
    }
}

/// Answer a caller parked by `defer`: false if it is gone, was not parked by `server`, or has moved on.
pub fn reply_to(server: usize, token: u64, w: [u64; 3], cap: Option<Cap>) -> bool {
    if token >= task::limit() as u64 {
        return false;
    }
    let c = token as usize;
    let mut tc = task::lock(c);
    if tc.callee != Some(server as u16) || sched::state(c) != State::CallWait {
        return false;
    }
    tc.callee = None;
    let info = reply_cap(&mut tc, c, cap);
    let mut f = frame(c);
    f.x[0] = 0;
    f.x[1] = w[0];
    f.x[2] = w[1];
    f.x[3] = w[2];
    f.x[4] = info;
    sched::wake_if(c, State::CallWait)
}

/// The capability a reply carries, given to the caller `c` (whose table `tc` the caller of this holds) if the call said it would take one.
fn reply_cap(tc: &mut task::Task, c: usize, cap: Option<Cap>) -> u64 {
    match cap {
        Some(cp) if tc.reply_cap_ok => install_cap(tc, c, &cp),
        _ => 0,
    }
}

/// Reply from `server` to the caller it is currently serving.
pub fn reply(server: usize, w: [u64; 3], cap: Option<Cap>) -> bool {
    let link = task::lock(server).reply_to.take();
    let Some((c, tag)) = link else { return false };
    sched::clear_inherit(server);
    let c = c as usize;
    let mut tc = task::lock(c);
    if tag != 0 {
        return crate::ring::complete_call(&mut tc, c, tag, server, w);
    }
    if tc.callee != Some(server as u16) || sched::state(c) != State::CallWait {
        return false; // caller died or moved on
    }
    tc.callee = None;
    let info = reply_cap(&mut tc, c, cap);
    let mut f = frame(c);
    f.x[0] = 0;
    f.x[1] = w[0];
    f.x[2] = w[1];
    f.x[3] = w[2];
    f.x[4] = info;
    sched::wake_if(c, State::CallWait) // publishes the registers above
}
