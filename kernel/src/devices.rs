//! The device registry: which drivers this kernel knows, which device each one matches, and what the kernel prepares for it.
//!
//! Each entry of `DRIVERS` is one driver's description (name, class, the PCI id it matches, the role of the user-space task that drives it, and the
//! function that makes its kernel objects). Bus enumeration walks the bus once and binds each function to the first free matching entry; nothing
//! here names a particular device otherwise. Adding a device means adding a line to the table and a `setup` function, not editing the probe loop.
//!
//! The kernel still decides *which* devices are exposed (only those with an entry); the driver itself is a user-space task started from its role.
#![forbid(unsafe_code)]
use crate::cap::{Kind, Rights, R_INFO, R_MAP, R_RECV, R_SEND, R_WRITE};
use crate::ipc;
use crate::obj::*;
use crate::{irq, kprintln, mem, pci};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use metallium_sched::Class as SchedClass;

/// What a device is for. Several drivers can serve one class on different machines; clients ask for a class, not for a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DevClass {
    Block,
    Display,
    Keyboard,
    Pointer,
    Usb,
    Net,
    Entropy,
}

/// A PCI function exposed to a driver: its register BAR, a config-space copy, its interrupt.
pub struct Exposed {
    pub bar_pa: usize,
    pub bar_pages: usize,
    pub cfg_pa: usize,
    pub irq_id: u32,
    pub sid: u16,
}

/// How the kernel prepares a matched function.
pub enum Bind {
    /// Place the BARs and enable the function, then make the objects the driver needs. A function with no usable register BAR or interrupt is skipped.
    Expose { setup: fn(&pci::Func, &Exposed) },
}

/// When in the boot order a task starts. Task ids follow the order tasks are made in, and other tasks know their peers by id, so the order is part of the
/// system's layout: the phases keep it exactly what it was when `main.rs` spawned everything by hand.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The storage and file-system services, and the test servers that go with them.
    Storage,
    /// The device drivers.
    Drivers,
    /// The console (the screen task).
    Console,
    /// The network driver and `netd`, last, so that the tasks before keep their ids.
    Network,
    /// The entropy driver: after the network tasks, the board's extra tasks and the tty consoles (see `main.rs`).
    Entropy,
}

/// A task that exists because a device does: `count` copies of `role`, started in `phase` (and only if `requires`, a device it needs besides its own, is present too).
pub struct TaskSpec {
    pub role: u8,
    pub name: &'static str,
    pub class: SchedClass,
    pub restartable: bool,
    pub count: usize,
    pub phase: Phase,
    pub requires: Option<DevClass>,
}

const fn task(role: u8, name: &'static str, class: SchedClass, restartable: bool, count: usize, phase: Phase, requires: Option<DevClass>) -> TaskSpec {
    TaskSpec { role, name, class, restartable, count, phase, requires }
}

/// One capability a driver task starts with: the slot it lands in, what kind, which kernel object, and the rights. This is the driver's manifest: everything it
/// is allowed to touch, and nothing else.
#[derive(Clone, Copy)]
pub struct CapGrant {
    pub slot: u8,
    pub kind: Kind,
    pub obj: u16,
    pub rights: Rights,
}

const fn cap(slot: u8, kind: Kind, obj: u16, rights: Rights) -> CapGrant {
    CapGrant { slot, kind, obj, rights }
}

const DEV: Rights = R_MAP | R_WRITE | R_INFO; // a device window or DMA memory, with its physical address (drivers only)

pub struct Driver {
    pub name: &'static str,
    pub class: DevClass,
    /// PCI vendor and device id.
    pub pci: (u16, u16),
    /// The role of the task that drives it (`task.rs`); 0: none.
    pub role: u8,
    pub bind: Bind,
    /// What the driver task starts with (slots are the driver program's own numbering).
    pub grants: &'static [CapGrant],
    /// The memory the device itself may reach by DMA (the IOMMU confines its stream to exactly these objects).
    pub dma: &'static [u16],
    /// The tasks that run when this device is present, in the order they are made.
    pub tasks: &'static [TaskSpec],
    /// Logged at boot when no function matched.
    pub missing_note: Option<&'static str>,
}

/// The drivers, in matching order (two entries may share an id: the first function matched goes to the first, the next to the second).
pub static DRIVERS: [Driver; 7] = [
    Driver {
        name: "virtio-blk",
        class: DevClass::Block,
        pci: (pci::VIRTIO_VENDOR, pci::VIRTIO_BLK_MODERN),
        role: 4,
        bind: Bind::Expose { setup: setup_blk },
        grants: &[
        cap(0, Kind::Endpoint, ipc::EP_BLK, R_RECV),
        cap(1, Kind::Memory, OBJ_BLK_MMIO, DEV),
        cap(2, Kind::Memory, OBJ_BLK_RING, DEV),
        cap(3, Kind::Memory, OBJ_BLK_BUF_ROFS, DEV),
        cap(4, Kind::Memory, OBJ_BLK_BUF_LFS, DEV),
        cap(5, Kind::Memory, OBJ_BLK_BUF_CLIENT, DEV),
        cap(6, Kind::Irq, IRQ_BLK, R_RECV),
        cap(7, Kind::Memory, OBJ_BLK_PCICFG, R_MAP),
    ],
        dma: &[OBJ_BLK_RING, OBJ_BLK_BUF_ROFS, OBJ_BLK_BUF_LFS, OBJ_BLK_BUF_CLIENT],
        tasks: &[
        task(4, "blk-driver", SchedClass::Interactive, true, 1, Phase::Storage, None),
        task(5, "rofs-server", SchedClass::Interactive, true, 1, Phase::Storage, None),
        task(6, "lfs-server", SchedClass::Interactive, true, 1, Phase::Storage, None),
        task(7, "vfs-server", SchedClass::Interactive, true, 1, Phase::Storage, None),
        task(8, "program", SchedClass::Interactive, false, 1, Phase::Storage, None),
        task(9, "compactd", SchedClass::Background, true, 1, Phase::Storage, None),
        task(10, "bench-srv", SchedClass::Interactive, false, crate::ipc::BENCH_PAIRS, Phase::Storage, None),
        task(11, "bench-cli", SchedClass::Interactive, false, crate::ipc::BENCH_PAIRS, Phase::Storage, None),
    ],
        missing_note: Some("[dev] no virtio-blk device found"),
    },
    Driver {
        name: "virtio-gpu",
        class: DevClass::Display,
        pci: (pci::VIRTIO_VENDOR, pci::VIRTIO_GPU_MODERN),
        role: 12,
        bind: Bind::Expose { setup: setup_gpu },
        grants: &[
        cap(0, Kind::Endpoint, ipc::EP_GPU, R_RECV),
        cap(1, Kind::Memory, OBJ_GPU_MMIO, DEV),
        cap(2, Kind::Memory, OBJ_GPU_QUEUE, DEV),
        cap(3, Kind::Memory, OBJ_GPU_CMD, DEV),
        cap(4, Kind::Memory, OBJ_GPU_FB, DEV),
        cap(5, Kind::Irq, IRQ_GPU, R_RECV),
        cap(6, Kind::Memory, OBJ_GPU_PCICFG, R_MAP),
        // the other ttys' framebuffers (absent, and so not mapped by the driver, unless the machine runs sessions)
        cap(7, Kind::Memory, OBJ_GPU_FB1, DEV),
        cap(8, Kind::Memory, OBJ_GPU_FB1 + 1, DEV),
        cap(9, Kind::Memory, OBJ_GPU_FB1 + 2, DEV),
    ],
        dma: &[OBJ_GPU_QUEUE, OBJ_GPU_CMD, OBJ_GPU_FB, OBJ_GPU_FB1, OBJ_GPU_FB1 + 1, OBJ_GPU_FB1 + 2],
        tasks: &[
        task(12, "gpu-driver", SchedClass::Interactive, true, 1, Phase::Drivers, None),
        task(13, "console", SchedClass::Interactive, true, 1, Phase::Console, None), // (the VFS server finds it by its role)
    ],
        missing_note: Some("[dev] no virtio-gpu device found"),
    },
    Driver {
        name: "virtio-input keyboard",
        class: DevClass::Keyboard,
        pci: (pci::VIRTIO_VENDOR, pci::VIRTIO_INPUT_MODERN),
        role: 14,
        bind: Bind::Expose { setup: setup_kbd },
        grants: &[
        cap(1, Kind::Memory, OBJ_KBD_MMIO, DEV),
        cap(2, Kind::Memory, OBJ_KBD_QUEUE, DEV),
        cap(3, Kind::Memory, OBJ_KBD_PCICFG, R_MAP),
    ],
        dma: &[OBJ_KBD_QUEUE],
        tasks: &[task(14, "kbd-driver", SchedClass::Interactive, true, 1, Phase::Drivers, Some(DevClass::Display))],
        missing_note: None,
    },
    // the second input device: the driver checks that it is a pointer (it has absolute axes)
    Driver {
        name: "virtio-input pointer",
        class: DevClass::Pointer,
        pci: (pci::VIRTIO_VENDOR, pci::VIRTIO_INPUT_MODERN),
        role: 14,
        bind: Bind::Expose { setup: setup_ptr },
        grants: &[
        cap(4, Kind::Memory, OBJ_PTR_MMIO, DEV),
        cap(5, Kind::Memory, OBJ_PTR_QUEUE, DEV),
        cap(6, Kind::Memory, OBJ_PTR_PCICFG, R_MAP),
    ],
        dma: &[OBJ_PTR_QUEUE],
        tasks: &[],
        missing_note: None,
    },
    // USB: an xHCI controller with keyboards and pointers on its ports, driven by the same task as the virtio input devices (its events go the same way)
    Driver {
        name: "xhci",
        class: DevClass::Usb,
        pci: pci::XHCI,
        role: 14,
        bind: Bind::Expose { setup: setup_usb },
        grants: &[
        cap(7, Kind::Memory, OBJ_USB_MMIO, DEV),
        cap(8, Kind::Memory, OBJ_USB_DMA, DEV),
        cap(9, Kind::Memory, OBJ_USB_PCICFG, R_MAP),
        cap(10, Kind::Irq, IRQ_USB, R_RECV),
    ],
        dma: &[OBJ_USB_DMA],
        // (the input driver is started once, by whichever of its devices comes first in this table: `spawn_tasks` skips a role it has already made)
        tasks: &[task(14, "kbd-driver", SchedClass::Interactive, true, 1, Phase::Drivers, Some(DevClass::Display))],
        missing_note: None,
    },
    Driver {
        name: "virtio-net",
        class: DevClass::Net,
        pci: (pci::VIRTIO_VENDOR, pci::VIRTIO_NET_MODERN),
        role: 18,
        bind: Bind::Expose { setup: setup_net },
        grants: &[
        cap(0, Kind::Endpoint, ipc::EP_NET, R_SEND),
        cap(1, Kind::Memory, OBJ_NET_MMIO, DEV),
        cap(2, Kind::Memory, OBJ_NET_QUEUES, DEV),
        cap(3, Kind::Memory, OBJ_NET_PCICFG, R_MAP),
        cap(4, Kind::Memory, OBJ_NET_BUFS, DEV),
        cap(5, Kind::Memory, OBJ_NET_RING, R_MAP | R_WRITE),
        cap(6, Kind::Irq, IRQ_NET, R_RECV),
    ],
        dma: &[OBJ_NET_QUEUES, OBJ_NET_BUFS],
        tasks: &[
        task(18, "net-driver", SchedClass::Interactive, true, 1, Phase::Network, None),
        task(19, "netd", SchedClass::Interactive, true, 1, Phase::Network, None),
    ],
        missing_note: None,
    },
    Driver {
        name: "virtio-rng",
        class: DevClass::Entropy,
        pci: (pci::VIRTIO_VENDOR, pci::VIRTIO_RNG_MODERN),
        role: 21,
        bind: Bind::Expose { setup: setup_rng },
        grants: &[
        cap(1, Kind::Memory, OBJ_RNG_MMIO, DEV),
        cap(2, Kind::Memory, OBJ_RNG_DMA, DEV),
        cap(3, Kind::Memory, OBJ_RNG_PCICFG, R_MAP),
    ],
        dma: &[OBJ_RNG_DMA],
        // (spawned after everything else, the tty consoles included: it takes the last task id and every other task keeps its own)
        tasks: &[task(21, "rng-driver", SchedClass::Background, true, 1, Phase::Entropy, None)],
        missing_note: Some("[dev] no virtio-rng device found"),
    },
];

const N: usize = DRIVERS.len();
static CLAIMED: [AtomicBool; N] = [const { AtomicBool::new(false) }; N];
static SIDS: [AtomicU16; N] = [const { AtomicU16::new(0) }; N];

fn index_of(class: DevClass) -> Option<usize> {
    DRIVERS.iter().position(|d| d.class == class)
}

/// Is there a device of this class? True when its register window object exists, however it got there (the bus probe below, or a machine's own
/// `probe_devices`), so boards that make their objects themselves are served by the same table.
pub fn present(class: DevClass) -> bool {
    let mmio = match class {
        DevClass::Block => OBJ_BLK_MMIO,
        DevClass::Display => OBJ_GPU_MMIO,
        DevClass::Keyboard => OBJ_KBD_MMIO,
        DevClass::Pointer => OBJ_PTR_MMIO,
        DevClass::Usb => OBJ_USB_MMIO,
        DevClass::Net => OBJ_NET_MMIO,
        DevClass::Entropy => OBJ_RNG_MMIO,
    };
    crate::obj::get(mmio).is_some()
}

/// Give a driver task of `role` the capabilities its device entries list, and confine each device to its DMA memory.
/// (The role's other capabilities, from the platform, come after.)
pub fn grant_to_driver(role: u8, mut install: impl FnMut(usize, Kind, u16, Rights)) {
    if role == 0 {
        return;
    }
    for d in DRIVERS.iter().filter(|d| d.role == role && present(d.class)) {
        for g in d.grants {
            install(g.slot as usize, g.kind, g.obj, g.rights);
        }
        if !d.dma.is_empty() {
            crate::smmu::attach(sid_of(d.class), role, d.dma);
        }
    }
}

/// The table's own consistency, checked when the kernel is built: no two grants of one role share a slot.
const fn slots_distinct() -> bool {
    let mut i = 0;
    while i < N {
        let mut a = 0;
        while a < DRIVERS[i].grants.len() {
            let mut j = i;
            while j < N {
                if DRIVERS[j].role == DRIVERS[i].role {
                    let mut b = if j == i { a + 1 } else { 0 };
                    while b < DRIVERS[j].grants.len() {
                        if DRIVERS[j].grants[b].slot == DRIVERS[i].grants[a].slot {
                            return false;
                        }
                        b += 1;
                    }
                }
                j += 1;
            }
            a += 1;
        }
        i += 1;
    }
    true
}
const _: () = assert!(slots_distinct(), "two capabilities of one driver role share a slot (kernel/src/devices.rs)");

/// Boot time, single core: make the tasks of `phase` for every device that is present, in table order.
pub fn spawn_tasks(phase: Phase) {
    // (a role several devices share is started by the first of them only)
    let mut made = [false; 32];
    for d in DRIVERS.iter().filter(|d| present(d.class)) {
        for t in d.tasks.iter().filter(|t| t.phase == phase && t.requires.map_or(true, present)) {
            if t.count == 1 && core::mem::replace(&mut made[t.role as usize % 32], true) {
                continue;
            }
            for _ in 0..t.count {
                crate::task::spawn(t.role, t.name, t.class, t.restartable);
            }
        }
    }
}

/// Stream id of the device of `class` (its PCI requester id: bus 0, device, function 0); 0 when there is none.
pub fn sid_of(class: DevClass) -> u16 {
    index_of(class).map_or(0, |i| SIDS[i].load(Ordering::Relaxed))
}

/// All streams the devices driven by `role` sit behind (at most three: the input driver has a keyboard, a pointer and a USB controller).
pub fn sids_of_role(role: u8) -> [Option<u16>; 3] {
    let mut out = [None, None, None];
    let mut n = 0;
    for (i, d) in DRIVERS.iter().enumerate() {
        if d.role == role && role != 0 && CLAIMED[i].load(Ordering::Relaxed) && n < 3 {
            out[n] = Some(SIDS[i].load(Ordering::Relaxed));
            n += 1;
        }
    }
    out
}

/// Place the function's BARs, enable it, and describe what the driver gets. The driver is handed
/// only the BAR holding the virtio registers, never the bus.
fn expose(f: &pci::Func, cursor: &mut usize, what: &str, virtio: bool) -> Option<Exposed> {
    let mut bars = [(0usize, 0usize); 6];
    pci::assign_bars(f, cursor, &mut bars);
    // (a virtio device says which BAR holds its registers; an xHCI controller's are in BAR 0)
    let Some(bar) = (if virtio { pci::virtio_bar(f) } else { Some(0) }).map(|b| bars[b as usize % 6]).filter(|b| b.1 >= 4096) else {
        kprintln!("[dev] {what} at 00:{:02x}.0 has no usable register BAR", f.dev);
        return None;
    };
    let spi = f.intx_spi()?;
    pci::enable(f);
    let irq_id = 32 + spi;
    kprintln!("[dev] {what} (PCI 00:{:02x}.0), BAR at {:#x} ({} KiB), IRQ {}", f.dev, bar.0, bar.1 / 1024, irq_id);
    let cfg_pa = mem::alloc(mem::OWNER_KERNEL).expect("pci config page");
    pci::snapshot(f, cfg_pa);
    Some(Exposed { bar_pa: bar.0, bar_pages: bar.1 / mem::PAGE, cfg_pa, irq_id, sid: (f.dev as u16) << 3 })
}

/// Bus enumeration is kernel policy: only the devices this system has drivers for are exposed.
pub(crate) fn probe_pci() {
    let mut cursor = pci::window_start();
    for f in pci::scan() {
        let Some(i) = DRIVERS.iter().enumerate().position(|(i, d)| d.pci == (f.vendor(), f.device()) && !CLAIMED[i].load(Ordering::Relaxed)) else { continue };
        match &DRIVERS[i].bind {
            Bind::Expose { setup } => {
                let Some(d) = expose(&f, &mut cursor, DRIVERS[i].name, DRIVERS[i].pci.0 == pci::VIRTIO_VENDOR) else { continue };
                CLAIMED[i].store(true, Ordering::Relaxed);
                SIDS[i].store(d.sid, Ordering::Relaxed);
                setup(&f, &d);
            }
        }
    }
    for (i, d) in DRIVERS.iter().enumerate() {
        if let (false, Some(note)) = (CLAIMED[i].load(Ordering::Relaxed), d.missing_note) {
            kprintln!("{note}");
        }
    }
}

fn setup_blk(_f: &pci::Func, d: &Exposed) {
    set(OBJ_BLK_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_BLK_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_BLK_RING, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("dma ring"), 1, 0);
    for o in [OBJ_BLK_BUF_ROFS, OBJ_BLK_BUF_LFS, OBJ_BLK_BUF_CLIENT] {
        set(o, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("dma buf"), 1, 0);
    }
    for o in [OBJ_SHM_ROFS, OBJ_SHM_LFS, OBJ_SHM_ROFS_VFS, OBJ_SHM_LFS_VFS, OBJ_SHM_VFS_CLIENT, OBJ_SHM_VFS_PROGRAM, OBJ_SHM_BENCH, OBJ_SHM_VFS_SHELL, OBJ_SHM_SPIN]{
        set(o, ObjKind::Ram, mem::alloc(mem::OWNER_KERNEL).expect("shm page"), 1, 0);
    }
    crate::obj::make_sessions(OBJ_SHM_VFS_REGION, OBJ_SHM_VFS_PROG0);
    irq::register(IRQ_BLK as usize, d.irq_id);
}

fn setup_gpu(_f: &pci::Func, d: &Exposed) {
    set(OBJ_GPU_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_GPU_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_GPU_QUEUE, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("gpu queue"), 1, 0);
    set(OBJ_GPU_CMD, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("gpu command page"), 1, 0);
    let fb = mem::alloc_contig(FB_PAGES, mem::OWNER_KERNEL).expect("framebuffer");
    set(OBJ_GPU_FB, ObjKind::Dma, fb, FB_PAGES, 0);
    if crate::platform::interactive() || crate::platform::only() == 15 {
        for k in 0..TTY_BUFFERS - 1 {
            let fb = mem::alloc_contig(FB_PAGES, mem::OWNER_KERNEL).expect("tty framebuffer");
            set(OBJ_GPU_FB1 + k as u16, ObjKind::Dma, fb, FB_PAGES, 0);
        }
    }
    irq::register(IRQ_GPU as usize, d.irq_id);
}

fn setup_kbd(f: &pci::Func, d: &Exposed) {
    pci::disable_intx(f);
    set(OBJ_KBD_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_KBD_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_KBD_QUEUE, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("keyboard queue"), 1, 0);
    // no interrupt is registered: the driver polls its used ring when asked for keys
}

fn setup_ptr(f: &pci::Func, d: &Exposed) {
    pci::disable_intx(f);
    set(OBJ_PTR_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_PTR_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_PTR_QUEUE, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("pointer queue"), 1, 0);
}

fn setup_usb(f: &pci::Func, d: &Exposed) {
    set(OBJ_USB_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_USB_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_USB_DMA, ObjKind::Dma, mem::alloc_contig(USB_DMA_PAGES, mem::OWNER_KERNEL).expect("usb memory"), USB_DMA_PAGES, 0);
    irq::register(IRQ_USB as usize, d.irq_id); // (the controller's INTx line: the driver may wait for it; it is held off until it does)
}

fn setup_rng(f: &pci::Func, d: &Exposed) {
    pci::disable_intx(f);
    set(OBJ_RNG_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_RNG_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_RNG_DMA, ObjKind::Dma, mem::alloc(mem::OWNER_KERNEL).expect("rng page"), 1, 0);
    // no interrupt is registered: the driver polls its used ring
}

fn setup_net(_f: &pci::Func, d: &Exposed) {
    set(OBJ_NET_MMIO, ObjKind::Mmio, d.bar_pa, d.bar_pages, 0);
    set(OBJ_NET_PCICFG, ObjKind::Ram, d.cfg_pa, 1, 0);
    set(OBJ_NET_QUEUES, ObjKind::Dma, mem::alloc_contig(2, mem::OWNER_KERNEL).expect("net queues"), 2, 0);
    set(OBJ_NET_BUFS, ObjKind::Dma, mem::alloc_contig(NET_BUF_PAGES, mem::OWNER_KERNEL).expect("net buffers"), NET_BUF_PAGES, 0);
    set(OBJ_NET_RING, ObjKind::Ram, mem::alloc(mem::OWNER_KERNEL).expect("net ring"), 1, 0);
    crate::obj::make_sessions(OBJ_SHM_NET_REGION, OBJ_SHM_NET_PROG0);
    irq::register(IRQ_NET as usize, d.irq_id);
}
