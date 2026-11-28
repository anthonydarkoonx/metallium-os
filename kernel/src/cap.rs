//! Capabilities. Every capability sits in a derivation tree (`node`), so
//! revoking a capability atomically kills everything derived from it.
#![forbid(unsafe_code)]
use crate::sync::{SpinLock, R_NODES};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub const NCAPS: usize = 32;
/// A capability node's number; `NO_PARENT` (the largest value) means "no parent". (Widened from `u8` on the ROCK 3C, whose boot-time services and drivers
/// already use two thirds of 254 nodes, leaving too little for two windowed programs at once.)
pub type NodeId = u16;
/// Capability nodes in the whole system: enough for a thousand tasks with several capabilities each.
pub const NODES: usize = 16384;

/// A set of nodes (a bit each): what a revoke marks.
#[derive(Clone, Copy)]
pub struct NodeSet([u64; NODES / 64]);

impl NodeSet {
    pub const EMPTY: NodeSet = NodeSet([0; NODES / 64]);

    pub fn has(&self, n: usize) -> bool {
        self.0[n / 64] >> (n % 64) & 1 != 0
    }

    pub fn insert(&mut self, n: usize) {
        self.0[n / 64] |= 1 << (n % 64);
    }

    pub fn remove(&mut self, n: usize) {
        self.0[n / 64] &= !(1 << (n % 64));
    }

    pub fn any(&self) -> bool {
        self.0.iter().any(|&w| w != 0)
    }

    pub fn count(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }
}

pub type Rights = u16;

pub const R_SEND: Rights = 1;
pub const R_RECV: Rights = 2;
pub const R_GRANT: Rights = 4;
pub const R_MAP: Rights = 8;
pub const R_WRITE: Rights = 16;
/// May learn the physical address of DMA / MMIO objects (driver-only).
pub const R_INFO: Rights = 32;
/// Memory-control capability rights: read allocator statistics / run compaction / allocate contiguous memory.
pub const R_MEM_STATS: Rights = 1 << 6;
pub const R_MEM_COMPACT: Rights = 1 << 7;
pub const R_MEM_ALLOC: Rights = 1 << 8;
/// May evict pages to the compressed swap store (the policy of when to do so lives in userspace).
pub const R_MEM_SWAP: Rights = 1 << 10;
/// On a MemCtl capability: may act as the pager (see `pager.rs`): take the disk-writeback and page-in jobs.
pub const R_MEM_PAGER: Rights = 1 << 5;
/// Administrative right: may kill (and so restart) the system's restartable service tasks. Held only by the
/// chaos-test monkey.
pub const R_KILL: Rights = 1 << 9;
/// Administrative right: may revoke a capability held by a program that was started at run time (`REVOKE_OF`), never one that is the root
/// of its object. Held by the task manager only, through the program manager.
pub const R_REVOKE: Rights = 1 << 10; // (rights mean what the kind says: this one is for `Admin`, as `R_KILL` is)
/// May give itself a real-time reservation (see `sched.rs`): a guaranteed share of a core.
pub const R_RT: Rights = 1 << 11;
/// Switch the machine off or restart it (`POWER`). A right of the `Admin` kind (like `R_REVOKE` and `R_KILL`), sharing a bit with `R_RT` which belongs to `Sched`.
pub const R_POWER: Rights = 1 << 11;
/// May create programs (SPAWN). Delegated with the grant right so that programs can start programs.
pub const R_SPAWN: Rights = 1 << 12;
/// On a Spawn capability: programs it starts may be given file-system access.
pub const R_SPAWN_FS: Rights = 1 << 13;
/// On a Factory capability: may create endpoints (EP_CREATE).
pub const R_EP_CREATE: Rights = 1 << 14;
/// On a Spawn capability: programs it starts may be given network access.
pub const R_SPAWN_NET: Rights = 1 << 15;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    None,
    Endpoint,
    Memory,
    Console,
    Irq,
    /// Physical-memory management (statistics, compaction, contiguous allocation).
    MemCtl,
    /// Administrative authority over service tasks (see `R_KILL`).
    Admin,
    /// Scheduling authority (see `R_RT`).
    Sched,
    /// Authority to create programs (see spawn.rs, `R_SPAWN`).
    Spawn,
    /// Authority to create kernel objects at run time (endpoints: `R_EP_CREATE`).
    Factory,
}

#[derive(Clone, Copy)]
pub struct Cap {
    pub kind: Kind,
    /// Index of the kernel object (endpoint id / memory object id).
    pub obj: u16,
    pub rights: Rights,
    pub node: NodeId,
    /// The generation of `node` this capability was made under. A node number is reused as soon as it is freed, so a copy of a
    /// capability that was revoked (and whose number was handed out again) must not look alive: `alive` compares both.
    pub gen: u32,
}

impl Cap {
    pub const NONE: Cap = Cap { kind: Kind::None, obj: 0, rights: 0, node: 0, gen: 0 };

    /// This capability's node is still the one it was made under (not revoked, and not revoked and reused).
    pub fn alive(&self) -> bool {
        node_is(self.node, self.gen)
    }

    /// A capability of `kind` on object `obj`, hanging under the node `n` that was just made.
    pub fn new(kind: Kind, obj: impl Into<u16>, rights: Rights, n: Minted) -> Cap {
        Cap { kind, obj: obj.into(), rights, node: n.id, gen: n.gen }
    }

    /// The same capability under a new node (a copy), with `rights`.
    pub fn under(&self, rights: Rights, n: Minted) -> Cap {
        Cap { rights, node: n.id, gen: n.gen, ..*self }
    }

    /// The identity of this capability's node, to give as the parent of a new one.
    pub fn parent_ref(&self) -> (NodeId, u32) {
        (self.node, self.gen)
    }
}

/// A node that was just made: its number and generation.
#[derive(Clone, Copy)]
pub struct Minted {
    pub id: NodeId,
    pub gen: u32,
}

pub const NO_PARENT: NodeId = NodeId::MAX;
/// (task ids are `u8`: this is "granted by no task")
const NO_GRANTER: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Node {
    used: bool,
    /// Being revoked (`kill_subtree`): already dead to everyone, but its number is not free until the teardown that claimed it has swept every
    /// task's tables (`free_marked`). Nothing may be made under it meanwhile.
    dying: bool,
    parent: NodeId,
    /// The task that created this node with `CAP_GRANT` (`NO_PARENT` if it was not made by a grant, or the granter is gone).
    granter: u16,
    /// The program (address space) charged for this node when it was made for one (`mint_for`), else `NO_GRANTER`.
    owner: u16,
    /// Counts up each time this number is handed out (0 is never alive), and is kept while the number is free.
    gen: u32,
}

/// Most nodes one task may have outstanding through `CAP_GRANT`, and the nodes `CAP_GRANT` may never take: the rest are for
/// restarting a service and starting a program, which must not fail because a task with the grant right filled the table.
pub const GRANT_QUOTA: usize = 40;
pub const GRANT_RESERVE: usize = 48;

/// Mirror of `used`, readable without the lock: every IPC checks its capability is alive.
static ALIVE: [AtomicBool; NODES] = [const { AtomicBool::new(false) }; NODES];
/// Mirror of `Node::gen` for the same reason. Stored before `ALIVE` goes true, so a reader that sees a node alive sees at least the generation it was made with.
static GEN: [AtomicU32; NODES] = [const { AtomicU32::new(0) }; NODES];

static NODE_TABLE: SpinLock<[Node; NODES]> = SpinLock::new([Node { used: false, dying: false, parent: NO_PARENT, granter: NO_GRANTER, owner: NO_GRANTER, gen: 0 }; NODES]);

/// Take node `i` (free, found under the table lock `t`) as a new node and publish it.
fn take(t: &mut [Node; NODES], i: usize, parent: NodeId, granter: u16, owner: u16) -> Minted {
    let gen = t[i].gen.wrapping_add(1).max(1);
    t[i] = Node { used: true, dying: false, parent, granter, owner, gen };
    GEN[i].store(gen, Ordering::Release);
    ALIVE[i].store(true, Ordering::Release);
    Minted { id: i as NodeId, gen }
}

/// Is `p` (a node and the generation it was read under) still that node? Called under the table lock, with the minting that depends on it.
fn parent_ok(t: &[Node; NODES], p: (NodeId, u32)) -> bool {
    t.get(p.0 as usize).is_some_and(|n| n.used && !n.dying && n.gen == p.1)
}

pub fn mint_node(parent: Option<(NodeId, u32)>) -> Option<Minted> {
    let mut t = NODE_TABLE.lock(R_NODES);
    if parent.is_some_and(|p| !parent_ok(&t, p)) {
        return None;
    }
    let i = t.iter().position(|n| !n.used)?;
    Some(take(&mut t, i, parent.map_or(NO_PARENT, |p| p.0), NO_GRANTER, NO_GRANTER))
}

/// Most nodes one program (all its threads together) may hold that it made for itself: its own memory and endpoints, its threads'
/// copies of capabilities, what it gives the programs it starts. Programs may also never take the last `GRANT_RESERVE` nodes:
/// those are for restarting a boot service (which cannot fail) and for starting programs.
pub const PROGRAM_NODE_QUOTA: usize = 768;

/// A node for `owner`, a program's address space (charged to it, and refused over `PROGRAM_NODE_QUOTA` or into the reserve), or
/// for anything else (a boot-time task: unlimited, as `mint_node`).
pub fn mint_for(owner: usize, parent: Option<(NodeId, u32)>) -> Option<Minted> {
    let charged = crate::spawn::is_program(owner);
    let o = owner as u16;
    let mut t = NODE_TABLE.lock(R_NODES);
    // (the parent is checked here, under the table lock that makes the node: a parent that was revoked since the caller read it, and whose number
    // has been handed out again, is refused, whatever else happened in between)
    if parent.is_some_and(|p| !parent_ok(&t, p)) {
        return None;
    }
    if charged && (t.iter().filter(|n| n.used && n.owner == o).count() >= PROGRAM_NODE_QUOTA || t.iter().filter(|n| !n.used).count() <= GRANT_RESERVE) {
        return None;
    }
    let i = t.iter().position(|n| !n.used)?;
    Some(take(&mut t, i, parent.map_or(NO_PARENT, |p| p.0), NO_GRANTER, if charged { o } else { NO_GRANTER }))
}

/// A node made by `CAP_GRANT` from task `granter`: refused when the task already has `GRANT_QUOTA` outstanding, or when
/// fewer than `GRANT_RESERVE` nodes would be left for everyone else.
pub fn mint_granted(parent: (NodeId, u32), granter: usize) -> Option<Minted> {
    // (a program's grants also count against its node allowance for as long as the copies live: the `granter` is a task, and goes when a thread
    // ends, but the program that made the grant does not)
    let program = crate::task::aspace(granter);
    let charged = crate::spawn::is_program(program);
    let mut t = NODE_TABLE.lock(R_NODES);
    let g = granter as u16;
    if !parent_ok(&t, parent) {
        return None;
    }
    if t.iter().filter(|n| n.used && n.granter == g).count() >= GRANT_QUOTA
        || t.iter().filter(|n| !n.used).count() <= GRANT_RESERVE
        || (charged && t.iter().filter(|n| n.used && n.owner == program as u16).count() >= PROGRAM_NODE_QUOTA)
    {
        return None;
    }
    let i = t.iter().position(|n| !n.used)?;
    Some(take(&mut t, i, parent.0, g, if charged { program as u16 } else { NO_GRANTER }))
}

/// The node `n` hangs under and its generation, if `n` is in use and has one.
pub fn parent_of(n: NodeId) -> Option<(NodeId, u32)> {
    let t = NODE_TABLE.lock(R_NODES);
    let node = t.get(n as usize)?;
    if !node.used || node.parent == NO_PARENT {
        return None;
    }
    let p = t.get(node.parent as usize)?;
    p.used.then_some((node.parent, p.gen))
}

/// A capability that was revoked from a program by `REVOKE_OF`, kept so that the same one can be given back (`RESTORE_OF`): only what is in
/// this log can be restored, so restoring cannot make up authority. The parent is the node it hung under; it is given back as a new child of it.
#[derive(Clone, Copy)]
pub struct Revoked {
    pub id: u32,
    pub task: u16,
    pub slot: u8,
    pub kind: Kind,
    pub obj: u16,
    pub rights: Rights,
    /// The node it hung under, or `NO_PARENT` for a capability the kernel made itself (a file or network session of a program).
    pub parent: NodeId,
    /// The generation of that node when the capability was revoked: a node that was freed and made again under the same number is not it.
    pub parent_gen: u32,
    /// Where the program had it mapped (0 pages: not mapped), so that giving it back can map it again.
    pub map_va: usize,
    pub map_pages: usize,
}

const REVOKED_LOG: usize = 16;

struct Log {
    entries: [Option<Revoked>; REVOKED_LOG],
    next: usize,
    next_id: u32,
}

static REVOKED: SpinLock<Log> = SpinLock::new(Log { entries: [None; REVOKED_LOG], next: 0, next_id: 1 });

/// Remember a revoked capability of `task` (the oldest entry goes when the log is full); returns its id.
pub fn log_revoked(task: usize, slot: usize, c: Cap, parent: (NodeId, u32), map: (usize, usize)) -> u32 {
    let mut l = REVOKED.lock(R_NODES);
    let id = l.next_id;
    l.next_id = l.next_id.wrapping_add(1).max(1);
    let at = l.next;
    l.entries[at] = Some(Revoked { id, task: task as u16, slot: slot as u8, kind: c.kind, obj: c.obj, rights: c.rights, parent: parent.0, parent_gen: parent.1, map_va: map.0, map_pages: map.1 });
    l.next = (at + 1) % REVOKED_LOG;
    id
}

/// The `n`th revoked capability of `task`, oldest first, and how many there are.
pub fn revoked_nth(task: usize, n: usize) -> (Option<Revoked>, usize) {
    let l = REVOKED.lock(R_NODES);
    let mut mine: [Option<Revoked>; REVOKED_LOG] = [None; REVOKED_LOG];
    let mut count = 0;
    for k in 0..REVOKED_LOG {
        let e = l.entries[(l.next + k) % REVOKED_LOG];
        if let Some(r) = e.filter(|r| r.task as usize == task) {
            mine[count] = Some(r);
            count += 1;
        }
    }
    (mine.get(n).copied().flatten(), count)
}

/// The log entry with this id, if it is for `task`.
pub fn revoked_by_id(task: usize, id: u32) -> Option<Revoked> {
    REVOKED.lock(R_NODES).entries.iter().flatten().find(|r| r.id == id && r.task as usize == task).copied()
}

/// Drop an entry (it was given back).
pub fn forget_revoked_id(id: u32) {
    let mut l = REVOKED.lock(R_NODES);
    for e in l.entries.iter_mut() {
        if e.is_some_and(|r| r.id == id) {
            *e = None;
        }
    }
}

/// A task is gone: what was revoked from it can no longer be given back.
pub fn forget_revoked(tid: usize) {
    let mut l = REVOKED.lock(R_NODES);
    for e in l.entries.iter_mut() {
        if e.is_some_and(|r| r.task as usize == tid) {
            *e = None;
        }
    }
}

/// A node for a capability given back by `RESTORE_OF`: a child of `parent`, not counted against anyone's grant quota (the restorer is the trusted
/// administrator, and each give-back replaces a node a revoke freed), but never taking the nodes kept in reserve for restarting a service.
pub fn mint_restored(parent: (NodeId, u32)) -> Option<Minted> {
    let mut t = NODE_TABLE.lock(R_NODES);
    if !parent_ok(&t, parent) || t.iter().filter(|n| !n.used).count() <= GRANT_RESERVE {
        return None;
    }
    let i = t.iter().position(|n| !n.used)?;
    Some(take(&mut t, i, parent.0, NO_GRANTER, NO_GRANTER))
}

/// A task is gone: what it granted stays with the receivers, but no longer counts against the task id's next owner.
pub fn forget_granter(tid: usize) {
    let mut t = NODE_TABLE.lock(R_NODES);
    for n in t.iter_mut() {
        if n.used && n.granter == tid as u16 {
            n.granter = NO_GRANTER;
        }
    }
}

/// The children of `root` no longer depend on it: they become roots of their own trees (so revoking `root` leaves them).
pub fn detach_children(root: NodeId) {
    let mut t = NODE_TABLE.lock(R_NODES);
    for n in t.iter_mut() {
        if n.used && n.parent == root {
            n.parent = NO_PARENT;
        }
    }
}

pub fn node_alive(n: NodeId) -> bool {
    ALIVE[n as usize].load(Ordering::Acquire)
}

/// Is node `n` alive and still the generation `gen`? (A node revoked and made again under the same number is not.)
pub fn node_is(n: NodeId, gen: u32) -> bool {
    node_alive(n) && GEN[n as usize].load(Ordering::Acquire) == gen
}

pub fn free_node(n: NodeId) {
    let mut t = NODE_TABLE.lock(R_NODES);
    t[n as usize].used = false;
    t[n as usize].dying = false;
    ALIVE[n as usize].store(false, Ordering::Release);
}

/// Revoke `root`'s descendants (and `root` itself when `include_root`): every node of the subtree stops being alive at once, under the table
/// lock, so from here on no capability on one of them can be used or minted under. Adds them to `out` (which the caller may have used
/// for earlier calls) and returns how many. Their numbers stay taken until the caller has cleared them from the tasks' tables and calls
/// `free_marked`; teardowns are serialised (`task::World`), so no node is ever claimed twice. A root that is not alive marks nothing.
pub fn kill_subtree(root: NodeId, include_root: bool, out: &mut NodeSet) -> usize {
    let mut t = NODE_TABLE.lock(R_NODES);
    let r = root as usize;
    if r >= NODES || !t[r].used || t[r].dying {
        return 0;
    }
    let mut sub = NodeSet::EMPTY;
    sub.insert(r);
    loop {
        let mut changed = false;
        for i in 0..NODES {
            let p = t[i].parent;
            if t[i].used && !t[i].dying && !sub.has(i) && p != NO_PARENT && sub.has(p as usize) {
                sub.insert(i);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    if !include_root {
        sub.remove(r);
    }
    let mut n = 0;
    for i in 0..NODES {
        if sub.has(i) {
            t[i].dying = true;
            ALIVE[i].store(false, Ordering::Release);
            out.insert(i);
            n += 1;
        }
    }
    n
}

/// The nodes `kill_subtree` marked are cleared from every table: their numbers are free again.
pub fn free_marked(marked: &NodeSet) {
    let mut t = NODE_TABLE.lock(R_NODES);
    for i in 0..NODES {
        if marked.has(i) {
            t[i].used = false;
            t[i].dying = false;
            ALIVE[i].store(false, Ordering::Release);
        }
    }
}

/// Mark `root`'s descendants (and `root` itself when `include_root`) in `out`.
/// Returns how many nodes were marked.
pub fn mark_subtree(root: NodeId, include_root: bool, out: &mut NodeSet) -> usize {
    let t = NODE_TABLE.lock(R_NODES);
    *out = NodeSet::EMPTY;
    out.insert(root as usize);
    loop {
        let mut changed = false;
        for i in 0..NODES {
            let p = t[i].parent;
            if t[i].used && !t[i].dying && !out.has(i) && p != NO_PARENT && out.has(p as usize) {
                out.insert(i);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    if !include_root {
        out.remove(root as usize);
    }
    out.count()
}

/// Capability nodes in use (a margin check: `install` panics if they run out).
pub fn nodes_in_use() -> usize {
    ALIVE.iter().filter(|a| a.load(Ordering::Relaxed)).count()
}
