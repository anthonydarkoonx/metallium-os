//! Kernel memory objects that capabilities can name: plain shared RAM, DMA
//! buffers, and device MMIO windows. Includes the boot-time PCI probe for the virtio-blk device.
#![forbid(unsafe_code)]
use crate::sync::{SpinLock, R_OBJ};
use crate::mem;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjKind {
    Unused,
    Ram,
    Dma,
    Mmio,
    /// Created by a program (`SHM_CREATE`): single frames named by a list, shared by capability; see `shm_alloc`.
    Shared,
}

#[derive(Clone, Copy)]
pub struct MemObj {
    pub kind: ObjKind,
    pub pa: usize,
    pub pages: usize,
    /// MMIO: offset of the device inside its page. Shared memory: the program that created it (and is charged for it).
    pub aux: usize,
    /// Shared memory: the capability node of its creator's capability. The object lives exactly as long as that one.
    pub root: crate::cap::NodeId,
    /// Shared memory: where the list of its frames is (`ceil(pages / 1024)` kernel pages of `u32` frame numbers).
    pub list: usize,
    /// Run-time objects: the program (address space) charged a slot of the object table for it (`NO_OWNER` for the kernel's).
    pub owner: u16,
}

pub const OBJ_SHARED: u16 = 0;
pub const OBJ_BLK_MMIO: u16 = 1;
pub const OBJ_BLK_RING: u16 = 2;
/// One DMA buffer per block-driver client; the driver picks by kernel-provided sender id.
pub const OBJ_BLK_BUF_ROFS: u16 = 3;
pub const OBJ_BLK_BUF_LFS: u16 = 4;
pub const OBJ_BLK_BUF_CLIENT: u16 = 5;
/// Pages shared between the test client and each filesystem server.
pub const OBJ_SHM_ROFS: u16 = 6;
pub const OBJ_SHM_LFS: u16 = 7;
/// Pages the VFS server shares with the storage servers and with each of its clients.
pub const OBJ_SHM_ROFS_VFS: u16 = 8;
pub const OBJ_SHM_LFS_VFS: u16 = 9;
pub const OBJ_SHM_VFS_CLIENT: u16 = 10;
pub const OBJ_SHM_VFS_PROGRAM: u16 = 11;
/// Result page shared by the benchmark clients and the conductor.
pub const OBJ_SHM_BENCH: u16 = 12;
/// Read-only copy of the block device's PCI configuration space (the driver parses its capabilities).
pub const OBJ_BLK_PCICFG: u16 = 13;
/// The display device: registers, config copy, control-queue page, command page, framebuffer.
pub const OBJ_GPU_MMIO: u16 = 14;
pub const OBJ_GPU_PCICFG: u16 = 15;
pub const OBJ_GPU_QUEUE: u16 = 16;
pub const OBJ_GPU_CMD: u16 = 17;
pub const OBJ_GPU_FB: u16 = 18;
/// 1024 x 768 pixels of 4 bytes, physically contiguous.
pub const FB_PAGES: usize = 768;
/// The framebuffers of the other ttys (docs/MULTIUSER-PLAN.md, *TTYs*): 1024 x 768 each, like `OBJ_GPU_FB`, which is tty 0's. Made only where sessions run (the interactive boot, `only=15`):
/// three more are 9 MiB, which a test machine of 64 MiB does not spare.
pub const OBJ_GPU_FB1: u16 = 28;
pub const TTY_BUFFERS: usize = 4;
/// The keyboard: registers, config copy, and one page holding its event queue and buffers.
pub const OBJ_KBD_MMIO: u16 = 19;
pub const OBJ_KBD_PCICFG: u16 = 20;
pub const OBJ_KBD_QUEUE: u16 = 21;
/// Page the VFS server shares with the shell.
pub const OBJ_SHM_VFS_SHELL: u16 = 22;
/// Flag page the test conductor shares with the CPU-burner tasks (scheduler tests).
pub const OBJ_SHM_SPIN: u16 = 23;
/// The VFS server's view of the session pages of programs with file-system access: all of them as one object (`sessions()` pages),
/// which it maps once. Programs get one page each as objects of their own (`OBJ_SHM_VFS_PROG0 + k`) over the same frames.
pub const OBJ_SHM_VFS_REGION: u16 = 24;
/// The USB controller (the input driver's third device): its registers, its config-space copy, and the memory it and the driver share (rings, contexts, report buffers).
pub const OBJ_USB_MMIO: u16 = 25;
pub const OBJ_USB_PCICFG: u16 = 26;
pub const OBJ_USB_DMA: u16 = 27;
/// Pages of the USB DMA memory.
pub const USB_DMA_PAGES: usize = 80;
/// The network device: registers, config copy, the two virtqueue pages, the packet buffers (shared with `netd`), the
/// ring the driver and `netd` talk through, and the session pages of programs with network access (40..48).
pub const OBJ_NET_MMIO: u16 = 32;
pub const OBJ_NET_PCICFG: u16 = 33;
pub const OBJ_NET_QUEUES: u16 = 34;
pub const OBJ_NET_BUFS: u16 = 35;
pub const OBJ_NET_RING: u16 = 36;
pub const OBJ_SHM_NET_REGION: u16 = 40;
/// The pointer (a second virtio-input device, a tablet): registers, config copy, queue page.
pub const OBJ_PTR_MMIO: u16 = 48;
pub const OBJ_PTR_PCICFG: u16 = 49;
pub const OBJ_PTR_QUEUE: u16 = 50;
/// The entropy device (virtio-rng, driven by the entropy driver, role 21): registers, config copy, and the one page holding its queue and buffer.
pub const OBJ_RNG_MMIO: u16 = 37;
pub const OBJ_RNG_PCICFG: u16 = 38;
pub const OBJ_RNG_DMA: u16 = 51;
/// 64 receive and 32 transmit buffers of 2 KiB.
pub const NET_BUF_PAGES: usize = 48;
pub const IRQ_BLK: u16 = 0;
pub const IRQ_GPU: u16 = 1;
pub const IRQ_NET: u16 = 2;
pub const IRQ_USB: u16 = 3;

/// (ids are `u16`; the first 64 are the boot-time objects, the rest are created at run time: `PROGRAM_OBJ_QUOTA` of them for every
/// task slot, at least 192, sized at boot)
static OBJS: SpinLock<&'static mut [MemObj]> = SpinLock::new(&mut []);

/// How many object-table entries a machine with `tasks` task slots gets.
pub fn objs_for(tasks: usize) -> usize {
    (FIRST_DYNAMIC + (8 * tasks).max(192)).min(u16::MAX as usize)
}

/// Carve the object table for `n` entries; called once from `main`.
pub fn init_table(n: usize) {
    let mut t = OBJS.lock(R_OBJ);
    assert!(t.is_empty() && n > FIRST_DYNAMIC, "object table: bad size or initialised twice");
    *t = crate::table::carve_slice(n, |_| MemObj { kind: ObjKind::Unused, pa: 0, pages: 0, aux: 0, root: 0, list: 0, owner: NO_OWNER });
}

/// All streams a driver role's devices sit behind (the input driver has three: keyboard, pointer and USB controller).
pub fn sids_of_role(role: u8) -> [Option<u16>; 3] {
    crate::devices::sids_of_role(role)
}

pub fn get(i: u16) -> Option<MemObj> {
    OBJS.lock(R_OBJ).get(i as usize).copied().filter(|o| o.kind != ObjKind::Unused)
}

pub(crate) fn set(i: u16, kind: ObjKind, pa: usize, pages: usize, aux: usize) {
    // (a DMA buffer must lie where the device can address it: platforms whose devices use 32-bit addresses set `DMA_LIMIT`; the allocator hands unmovable frames out from the bottom of RAM)
    assert!(kind != ObjKind::Dma || pa.saturating_add(pages * mem::PAGE) <= crate::platform::DMA_LIMIT, "a DMA object lies above the platform's DMA limit");
    OBJS.lock(R_OBJ)[i as usize] = MemObj { kind, pa, pages, aux, root: 0, list: 0, owner: NO_OWNER };
}

pub fn init() {
    set(OBJ_SHARED, ObjKind::Ram, mem::alloc(mem::OWNER_KERNEL).expect("shared page"), 1, 0);
    crate::platform::probe_devices();
}

/// First object id handed out dynamically (below it: the fixed boot objects).
/// Object numbers 52..=63 belong to the platform (its own devices: `platform.rs` names them); the objects programs make start here.
pub const FIRST_PLATFORM_OBJ: u16 = 52;
/// The most session pages of either kind; the objects of the single pages follow the platform's (64.., then 64 + MAX_SESSIONS..).
pub const MAX_SESSIONS: usize = 256; // (one more than can be used: the pool bits are whole words)
pub const OBJ_SHM_VFS_PROG0: u16 = 64;
pub const OBJ_SHM_NET_PROG0: u16 = OBJ_SHM_VFS_PROG0 + MAX_SESSIONS as u16;
const FIRST_DYNAMIC: usize = 64 + 2 * MAX_SESSIONS;

static SESSIONS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// How many file sessions (and, separately, network sessions) a machine with `tasks` task slots has: a quarter of the slots, 8..255 (session numbers are
/// bytes, and 255 means "none" in `spawn.rs`).
pub fn sessions_for(tasks: usize) -> usize {
    (tasks / 4).clamp(8, MAX_SESSIONS - 1)
}

pub fn init_sessions(tasks: usize) {
    SESSIONS.store(sessions_for(tasks), core::sync::atomic::Ordering::SeqCst);
}

/// Session pages of each kind on this boot.
pub fn sessions() -> usize {
    SESSIONS.load(core::sync::atomic::Ordering::SeqCst)
}

/// Allocate the session pages of one kind: the region (one object over `sessions()` contiguous frames) and one single-page object per session.
pub fn make_sessions(region: u16, first: u16) {
    let n = sessions();
    let pa = mem::alloc_contig(n, mem::OWNER_KERNEL).expect("session pages");
    for k in 0..n {
        crate::frame::phys::zero_page(pa + k * mem::PAGE);
    }
    set(region, ObjKind::Ram, pa, n, 0);
    for k in 0..n {
        set(first + k as u16, ObjKind::Ram, pa + k * mem::PAGE, 1, 0);
    }
}

const NO_OWNER: u16 = u16::MAX;
/// Most run-time objects one program may have, and the object-table entries programs may never take (boot-time services make
/// objects too, and must not find the table full because programs filled it).
pub const PROGRAM_OBJ_QUOTA: usize = 32;
const OBJ_RESERVE: usize = 16;

fn owner_tag(owner: usize) -> u16 {
    if crate::spawn::is_program(owner) { owner as u16 } else { NO_OWNER }
}

fn over_quota(t: &[MemObj], owner: usize) -> bool {
    if !crate::spawn::is_program(owner) {
        return false;
    }
    let o = owner as u16;
    let dynamic = &t[FIRST_DYNAMIC..];
    dynamic.iter().filter(|x| x.kind != ObjKind::Unused && x.owner == o).count() >= PROGRAM_OBJ_QUOTA
        || dynamic.iter().filter(|x| x.kind == ObjKind::Unused).count() <= OBJ_RESERVE
}

/// Register a contiguous DMA-style object created at run time. `root` is the node of the creator's capability: the object
/// lives as long as that capability does (a copy of the capability, such as a thread's, never ends it).
pub fn alloc_dynamic(pa: usize, pages: usize, root: crate::cap::NodeId, owner: usize) -> Option<u16> {
    let mut t = OBJS.lock(R_OBJ);
    if over_quota(&t[..], owner) {
        return None;
    }
    let i = (FIRST_DYNAMIC..t.len()).find(|&i| t[i].kind == ObjKind::Unused)?;
    t[i] = MemObj { kind: ObjKind::Dma, pa, pages, aux: 0, root, list: 0, owner: owner_tag(owner) };
    Some(i as u16)
}

/// Dynamic objects in use (a leak check).
pub fn dynamic_in_use() -> usize {
    OBJS.lock(R_OBJ)[FIRST_DYNAMIC..].iter().filter(|o| o.kind != ObjKind::Unused).count()
}

pub fn is_dynamic(i: u16) -> bool {
    i as usize >= FIRST_DYNAMIC
}

pub fn release(i: u16) {
    set(i, ObjKind::Unused, 0, 0, 0);
}

/// A page the kernel allocates only so that an object exists where another machine has a device window.
pub(crate) fn dummy_page() -> usize {
    mem::alloc(mem::OWNER_KERNEL).expect("dummy page")
}

pub fn blk_present() -> bool {
    get(OBJ_BLK_MMIO).is_some()
}

pub fn gpu_present() -> bool {
    get(OBJ_GPU_MMIO).is_some()
}

pub fn net_present() -> bool {
    get(OBJ_NET_MMIO).is_some()
}

#[allow(dead_code)] // (the device table asks `devices::present` now; a platform may still call this)
pub fn kbd_present() -> bool {
    get(OBJ_KBD_MMIO).is_some()
}

// ---- memory that programs create and share (SHM_CREATE) ------------------------------------------------------------------
//
// A shared object is made of single frames (so it never needs a contiguous run), pinned (never moved or swapped, so that
// every holder sees the same physical page and `WAIT_WORD` can key words by address). The frames are owned by the creating
// program like its other memory. The creator's own capability is the object's kill switch: revoking it with `CAP_REVOKE`
// flag 1 frees the object and unmaps it everywhere. When the creator merely exits, holders keep what they have (an
// *orphan*, see `shm_orphan`): the memory goes when the last of them lets go.

/// Most pages one shared object may have (16 MiB).
pub const SHM_MAX_PAGES: usize = 4096;
const PER_LIST_PAGE: usize = mem::PAGE / 4;

/// Frames for a new shared object of `pages` pages owned by `owner`, and the list that names them (its address).
pub fn shm_alloc(pages: usize, owner: mem::Owner) -> Option<usize> {
    let lists = (pages + PER_LIST_PAGE - 1) / PER_LIST_PAGE;
    let list = mem::alloc_contig(lists, mem::OWNER_KERNEL)?;
    for i in 0..pages {
        match mem::alloc_kind(owner, mem::FKind::Pinned) {
            Some(pa) => crate::frame::phys::write_u32(list + 4 * i, (pa >> 12) as u32),
            None => {
                shm_release_frames(list, i, pages);
                return None;
            }
        }
    }
    Some(list)
}

/// Give back the first `have` frames named by `list` and the list itself (made for an object of `pages` pages).
pub fn shm_release_frames(list: usize, have: usize, pages: usize) {
    for j in 0..have {
        mem::free(crate::frame::phys::read_u32(list + 4 * j) as usize * mem::PAGE);
    }
    for l in 0..(pages + PER_LIST_PAGE - 1) / PER_LIST_PAGE {
        mem::free(list + l * mem::PAGE);
    }
}

/// The physical address of page `p` of a shared object.
pub fn shm_frame(o: &MemObj, p: usize) -> usize {
    debug_assert!(o.kind == ObjKind::Shared && p < o.pages);
    crate::frame::phys::read_u32(o.list + 4 * p) as usize * mem::PAGE
}

/// Register a shared object whose frames `shm_alloc` returned.
pub fn shm_register(pages: usize, creator: usize, root: crate::cap::NodeId, list: usize) -> Option<u16> {
    let mut t = OBJS.lock(R_OBJ);
    if over_quota(&t[..], creator) {
        return None;
    }
    let i = (FIRST_DYNAMIC..t.len()).find(|&i| t[i].kind == ObjKind::Unused)?;
    t[i] = MemObj { kind: ObjKind::Shared, pa: 0, pages, aux: creator, root, list, owner: owner_tag(creator) };
    Some(i as u16)
}

/// `MemObj::aux` of a shared object whose creator is gone and that is charged to nobody (the creator was a boot-time task).
pub const SHM_ORPHAN: usize = usize::MAX;
/// How many shared objects are orphans (the sweep after a revocation looks for them only when there are some).
static ORPHANS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Is this a shared object whose creator's capability is gone?
fn is_orphan(o: &MemObj) -> bool {
    o.kind == ObjKind::Shared && o.root == crate::cap::NO_PARENT
}

/// The creator's capability goes while others still hold the object: it lives on, its frames belonging to the kernel, until the last holder
/// lets go of it (`shm_destroy` then). Whoever maps it keeps what they see; nothing faults.
///
/// Who pays for it stays with the program that made it (`aux`, and the object-table entry in `owner`), so that ending a thread, or a program
/// that is not yet gone, does not hand out memory for free: `World::reclaim_space` moves the charge to a holder when that program ends (or
/// ends the object if no holder can take it). Only an object of a boot-time task (trusted, and restarted often) is charged to nobody.
pub fn shm_orphan(i: u16) {
    let mut t = OBJS.lock(R_OBJ);
    let o = &mut t[i as usize];
    if o.kind != ObjKind::Shared || is_orphan(o) {
        return;
    }
    for p in 0..o.pages {
        mem::set_owner(crate::frame::phys::read_u32(o.list + 4 * p) as usize * mem::PAGE, mem::OWNER_KERNEL);
    }
    if !crate::spawn::is_program(o.aux) {
        crate::spawn::release_contig(o.aux, o.pages);
        o.aux = SHM_ORPHAN;
        o.owner = NO_OWNER;
    }
    o.root = crate::cap::NO_PARENT;
    ORPHANS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// The first orphaned shared object at or after table entry `from` (for the sweep), if `charged_to` is `None`; with `Some(program)`, the first
/// one that is charged to that program.
pub fn next_orphan(from: usize, charged_to: Option<usize>) -> Option<u16> {
    if ORPHANS.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        return None;
    }
    let t = OBJS.lock(R_OBJ);
    (from.max(FIRST_DYNAMIC)..t.len()).find(|&i| is_orphan(&t[i]) && charged_to.is_none_or(|p| t[i].aux == p)).map(|i| i as u16)
}

/// Charge orphan `i` to program `q`, which has just reserved its pages: from now on `q` pays for it and it counts against `q`'s object limit.
pub fn shm_charge_to(i: u16, q: usize) {
    let mut t = OBJS.lock(R_OBJ);
    let o = &mut t[i as usize];
    if is_orphan(o) {
        o.aux = q;
        o.owner = owner_tag(q);
    }
}

/// Free a shared object: its frames, its list and its table entry, and the creator's charge for it. (The capabilities and
/// mappings must have been revoked first.)
pub fn shm_destroy(i: u16) {
    let Some(o) = get(i).filter(|o| o.kind == ObjKind::Shared) else { return };
    shm_release_frames(o.list, o.pages, o.pages);
    if is_orphan(&o) {
        ORPHANS.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
    if o.aux != SHM_ORPHAN {
        crate::spawn::release_contig(o.aux, o.pages);
    }
    release(i);
}
