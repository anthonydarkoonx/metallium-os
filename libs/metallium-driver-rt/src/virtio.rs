//! virtio 1.x over PCI, shared by the userspace device drivers. Written from the OASIS virtio
//! specification: vendor capabilities locate the common / notification / ISR / device structures
//! inside a BAR; a split virtqueue is a descriptor table, an available ring and a used ring.
//!
//! The kernel hands a driver the BAR that holds the registers and a read-only copy of the
//! device's PCI configuration space; everything else is parsed here.
use crate::dma;
use core::ptr::{read_volatile, write_volatile};

// common configuration structure
const C_DEVFEAT_SEL: usize = 0x00;
const C_DEVFEAT: usize = 0x04;
const C_DRVFEAT_SEL: usize = 0x08;
const C_DRVFEAT: usize = 0x0c;
const C_STATUS: usize = 0x14;
const C_QSEL: usize = 0x16;
const C_QSIZE: usize = 0x18;
const C_QENABLE: usize = 0x1c;
const C_QNOTIFY_OFF: usize = 0x1e;
const C_QDESC: usize = 0x20;
const C_QAVAIL: usize = 0x28;
const C_QUSED: usize = 0x30;

const ST_ACK: u8 = 1;
const ST_DRIVER: u8 = 2;
const ST_DRIVER_OK: u8 = 4;
const ST_FEATURES_OK: u8 = 8;

// split virtqueue layout inside one page: descriptors, available ring, used ring
pub const OFF_DESC: usize = 0x000;
pub const OFF_AVAIL: usize = 0x100;
pub const OFF_USED: usize = 0x200;

/// Where `queue_sized` puts the available and the used ring (offsets from the start of the queue's page), or None if the queue does not fit
/// in one page. The used ring starts on a 64-byte boundary, and the available ring ends in an earlier cache line.
pub fn packed_layout(size: u16) -> Option<(usize, usize)> {
    let avail = 16 * size as usize;
    let used = (avail + 6 + 2 * size as usize + 63) & !63;
    (used + 6 + 8 * size as usize <= 4096).then_some((avail, used))
}

/// # Safety
/// `a` must be a 4-aligned address of a mapped device register (or readable memory) of this task.
unsafe fn rd32(a: usize) -> u32 {
    // SAFETY: the caller's contract; volatile because it is device MMIO.
    unsafe { read_volatile(a as *const u32) }
}
/// # Safety
/// As `rd32`, writable.
unsafe fn wr32(a: usize, v: u32) {
    // SAFETY: the caller's contract; volatile device MMIO write.
    unsafe { write_volatile(a as *mut u32, v) }
}
/// # Safety
/// As `wr32` for `a` and `a + 4`.
unsafe fn wr64(a: usize, v: u64) {
    // SAFETY: the caller's contract covers both halves, `a` and `a + 4`.
    unsafe {
        wr32(a, v as u32);
        wr32(a + 4, (v >> 32) as u32);
    }
}
/// # Safety
/// `a` must be a 2-aligned address of a mapped device register of this task.
unsafe fn rd16(a: usize) -> u16 {
    // SAFETY: the caller's contract; volatile device MMIO read.
    unsafe { read_volatile(a as *const u16) }
}
/// # Safety
/// As `rd16`, writable.
unsafe fn wr16(a: usize, v: u16) {
    // SAFETY: the caller's contract; volatile device MMIO write.
    unsafe { write_volatile(a as *mut u16, v) }
}
pub fn fence() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// The structures of one virtio PCI device, as addresses in this task's mapping of its BAR.
pub struct Pci {
    common: usize,
    notify_base: usize,
    notify_mult: usize,
    notify_end: usize,
    isr: usize,
    devcfg: usize,
    devcfg_len: usize,
}

/// Size of virtio_pci_common_cfg up to and including queue_used (virtio 1.x, 4.1.4.3).
const COMMON_LEN: usize = 0x38;

impl Pci {
    // The common configuration structure: `open` checked that `common .. common + COMMON_LEN` lies inside the mapped BAR, and
    // every offset used below is one of the C_* register offsets (all inside COMMON_LEN, naturally aligned).
    fn cr32(&self, off: usize) -> u32 {
        assert!(off + 4 <= COMMON_LEN && off % 4 == 0);
        // SAFETY: inside the common structure `open` validated (see above).
        unsafe { rd32(self.common + off) }
    }
    fn cw32(&self, off: usize, v: u32) {
        assert!(off + 4 <= COMMON_LEN && off % 4 == 0);
        // SAFETY: as `cr32`.
        unsafe { wr32(self.common + off, v) }
    }
    fn cr16(&self, off: usize) -> u16 {
        assert!(off + 2 <= COMMON_LEN && off % 2 == 0);
        // SAFETY: as `cr32`.
        unsafe { rd16(self.common + off) }
    }
    fn cw16(&self, off: usize, v: u16) {
        assert!(off + 2 <= COMMON_LEN && off % 2 == 0);
        // SAFETY: as `cr32`.
        unsafe { wr16(self.common + off, v) }
    }
    fn cw64(&self, off: usize, v: u64) {
        assert!(off + 8 <= COMMON_LEN && off % 4 == 0);
        // SAFETY: as `cr32`.
        unsafe { wr64(self.common + off, v) }
    }

    /// Parse the vendor capabilities in the config-space copy at `cfg_va`. `bar_va` / `bar_bytes`
    /// describe the mapped BAR; `device` is the PCI device id the driver expects.
    ///
    /// # Safety
    /// `bar_va .. bar_va + bar_bytes` must be this task's mapping of the device's register BAR, and `cfg_va` the mapped,
    /// 4-aligned 256-byte copy of its configuration space. Every register address the returned `Pci` and its queues touch is
    /// derived from those two ranges, after the checks in this function.
    pub unsafe fn open(bar_va: usize, bar_bytes: usize, cfg_va: usize, device: u16) -> Result<Pci, &'static str> {
        // SAFETY: offset 0 is inside the 256-byte config copy the caller provides.
        if unsafe { rd32(cfg_va) } != (device as u32) << 16 | 0x1af4 {
            return Err("not the expected virtio device");
        }
        // SAFETY: `cfg_va` is the kernel-provided read-only config-space copy (256 bytes, page mapped); every `o` used is < 256 (ptr + 20 <= 256 is checked before capability reads).
        let b = |o: usize| unsafe { read_volatile((cfg_va + o) as *const u8) } as usize;
        // SAFETY: as for `b`: every `o` used is inside the 256-byte config copy (`ptr + 20 <= 256` is checked in the loop), 4-aligned by the caller's contract.
        let w = |o: usize| unsafe { rd32(cfg_va + o) } as usize;
        if b(0x06) & 0x10 == 0 {
            return Err("no capability list");
        }
        let (mut common, mut notify, mut mult, mut isr, mut dev) = (None, None, 0, None, None);
        let (mut notify_len, mut dev_len) = (0, 0);
        let mut ptr = b(0x34) & !3;
        for _ in 0..48 {
            if ptr < 0x40 || ptr + 20 > 256 {
                break;
            }
            if b(ptr) == 0x09 {
                let (ty, off, len) = (b(ptr + 3), w(ptr + 8), w(ptr + 12));
                if off.checked_add(len).map_or(true, |e| e > bar_bytes) {
                    return Err("capability outside the BAR");
                }
                // The device describes its own layout; a structure shorter than what the driver touches is refused.
                match ty {
                    1 if len >= COMMON_LEN => common = Some(off),
                    2 => (notify, mult, notify_len) = (Some(off), w(ptr + 16), len),
                    3 if len >= 1 => isr = Some(off),
                    4 => (dev, dev_len) = (Some(off), len),
                    _ => {}
                }
            }
            ptr = b(ptr + 1) & !3;
        }
        match (common, notify, isr, dev) {
            (Some(c), Some(n), Some(i), Some(d)) => {
                Ok(Pci {
                    common: bar_va + c,
                    notify_base: bar_va + n,
                    notify_mult: mult,
                    notify_end: bar_va + n + notify_len,
                    isr: bar_va + i,
                    devcfg: bar_va + d,
                    devcfg_len: dev_len,
                })
            }
            _ => Err("missing virtio capability"),
        }
    }

    fn status(&self) -> u8 {
        // SAFETY: `common` = bar_va + a capability offset checked in `open` to lie inside the mapped BAR with len >= COMMON_LEN (0x38), which covers C_STATUS; volatile device MMIO.
        unsafe { read_volatile((self.common + C_STATUS) as *const u8) }
    }
    fn set_status(&self, v: u8) {
        // SAFETY: as `status`: C_STATUS is inside the bounds-checked common structure; volatile device MMIO write.
        unsafe { write_volatile((self.common + C_STATUS) as *mut u8, v) }
    }

    /// Reset the device (discarding anything a crashed predecessor left behind) and negotiate:
    /// VERSION_1 (bit 32) and ACCESS_PLATFORM (bit 33, the device's DMA goes through the
    /// platform's IOMMU, which is how the kernel confines it), nothing else.
    pub fn start(&self) -> Result<(), &'static str> {
        self.start_with(0)
    }

    /// `start`, also accepting the device-specific feature bits `extra` (bits 0..31) the device offers.
    pub fn start_with(&self, extra: u32) -> Result<(), &'static str> {
        self.set_status(0);
        self.set_status(ST_ACK);
        self.set_status(ST_ACK | ST_DRIVER);
        self.cw32(C_DEVFEAT_SEL, 1);
        let feat = self.cr32(C_DEVFEAT);
        if feat & 1 == 0 {
            return Err("device lacks VIRTIO_F_VERSION_1");
        }
        if feat & 2 == 0 {
            return Err("device lacks VIRTIO_F_ACCESS_PLATFORM");
        }
        self.cw32(C_DEVFEAT_SEL, 0);
        let low = self.cr32(C_DEVFEAT);
        if low & extra != extra {
            return Err("device lacks a feature the driver needs");
        }
        self.cw32(C_DRVFEAT_SEL, 0);
        self.cw32(C_DRVFEAT, extra);
        self.cw32(C_DRVFEAT_SEL, 1);
        self.cw32(C_DRVFEAT, 0b11);
        self.set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK);
        if self.status() & ST_FEATURES_OK == 0 {
            return Err("device rejected features");
        }
        Ok(())
    }

    /// Set up virtqueue `index` of `size` entries in the page at `va` / `pa` (layout above).
    pub fn queue(&self, index: u16, size: u16, va: usize, pa: u64) -> Result<Queue, &'static str> {
        self.queue_at(index, size, va, pa, OFF_AVAIL, OFF_USED)
    }

    /// A queue of up to a few hundred entries: the three structures are packed one after the other from the start of
    /// the memory (descriptors, then the available ring, then the used ring), which must be zeroed and is one page. The used
    /// ring starts on a 64-byte boundary of its own: the driver cleans the available ring's cache lines and the device writes the used
    /// ring, so the two must never share a line (a clean would write the CPU's old copy of the used ring's header over the device's).
    pub fn queue_sized(&self, index: u16, size: u16, va: usize, pa: u64) -> Result<Queue, &'static str> {
        let (avail, used) = packed_layout(size).ok_or("queue does not fit")?;
        self.queue_at(index, size, va, pa, avail, used)
    }

    fn queue_at(&self, index: u16, size: u16, va: usize, pa: u64, off_avail: usize, off_used: usize) -> Result<Queue, &'static str> {
        self.cw16(C_QSEL, index);
        if self.cr16(C_QSIZE) < size {
            return Err("queue too small");
        }
        self.cw16(C_QSIZE, size);
        let off = self.cr16(C_QNOTIFY_OFF) as usize;
        // where this queue's doorbell is comes from the device too: it must be inside the notify structure
        let notify = off
            .checked_mul(self.notify_mult)
            .and_then(|o| self.notify_base.checked_add(o))
            .filter(|n| n.checked_add(2).map_or(false, |e| e <= self.notify_end))
            .ok_or("queue doorbell outside the notify structure")?;
        self.cw64(C_QDESC, pa + OFF_DESC as u64);
        self.cw64(C_QAVAIL, pa + off_avail as u64);
        self.cw64(C_QUSED, pa + off_used as u64);
        self.cw16(C_QENABLE, 1);
        Ok(Queue {
            va,
            pa,
            size,
            index,
            off_avail,
            off_used,
            avail_idx: 0,
            used_seen: 0,
            notify,
            inflight: [(0, 0); MAX_CHAIN],
            ninflight: 0,
            posted: [(0, 0); MAX_POSTED],
        })
    }

    pub fn driver_ok(&self) {
        self.set_status(ST_ACK | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK);
    }

    /// Reading the ISR status acknowledges the interrupt.
    pub fn ack_isr(&self) {
        // SAFETY: `isr` is inside the BAR (checked in `open`, len >= 1); the read has the side effect of acknowledging the interrupt, which is intended.
        unsafe { read_volatile(self.isr as *const u8) };
    }

    /// A byte of the device-specific configuration.
    pub fn config8(&self, off: usize) -> u8 {
        assert!(off < self.devcfg_len);
        // SAFETY: `off < devcfg_len` is asserted above and the device-config structure was checked to lie inside the BAR in `open`; volatile MMIO.
        unsafe { read_volatile((self.devcfg + off) as *const u8) }
    }

    pub fn set_config8(&self, off: usize, v: u8) {
        assert!(off < self.devcfg_len);
        // SAFETY: `off < devcfg_len` is asserted above and the device-config structure lies inside the BAR (checked in `open`); volatile MMIO.
        unsafe { write_volatile((self.devcfg + off) as *mut u8, v) }
    }

    /// A 32-bit word of the device-specific configuration.
    pub fn config32(&self, off: usize) -> u32 {
        assert!(off + 4 <= self.devcfg_len);
        // SAFETY: `off + 4 <= devcfg_len` (asserted); the device-config structure lies inside the BAR (checked in `open`).
        unsafe { rd32(self.devcfg + off) }
    }
}

/// One buffer of a descriptor chain: where the device finds it (`pa`), where this task sees it (`va`, for cache
/// maintenance; 0 = not mapped here, nothing to maintain), its length, and whether the device writes it.
#[derive(Clone, Copy)]
pub struct Buf {
    pub pa: u64,
    pub va: usize,
    pub len: u32,
    pub dev_writes: bool,
}

const MAX_CHAIN: usize = 4;
const MAX_POSTED: usize = 64;

/// One split virtqueue, driven synchronously: one chain of descriptors in flight at a time.
///
/// Every transfer is wrapped in the cache maintenance the module `dma` describes: the driver never has to
/// remember it, because buffers are handed to the queue with their addresses.
pub struct Queue {
    va: usize,
    pa: u64,
    size: u16,
    index: u16,
    off_avail: usize,
    off_used: usize,
    avail_idx: u16,
    used_seen: u16,
    notify: usize,
    /// device-written buffers of the chain in flight: invalidated again once it completes
    inflight: [(usize, u32); MAX_CHAIN],
    ninflight: usize,
    /// device-written buffer of each posted descriptor (queues the device fills on its own schedule)
    posted: [(usize, u32); MAX_POSTED],
}

impl Queue {
    /// Queue a chain of buffers and notify the device.
    pub fn submit(&mut self, chain: &[Buf]) {
        self.submit_quiet(chain);
        fence();
        // SAFETY: `notify` was checked in `queue_at` to lie, with its 2 bytes, inside the notify structure inside the BAR.
        unsafe { wr16(self.notify, self.index) };
    }

    /// Publish a chain without notifying the device: it will not look at it. (Tests use this to model
    /// a device that never answers.)
    pub fn submit_quiet(&mut self, chain: &[Buf]) {
        const NEXT: u16 = 1;
        const WRITE: u16 = 2;
        assert!(chain.len() <= self.size as usize, "descriptor chain longer than the queue");
        self.ninflight = 0;
        for b in chain {
            // what the device reads must be in memory; where it writes, no dirty line may survive to overwrite it
            if b.dev_writes {
                dma::flush(b.va, b.len as usize);
                if b.va != 0 && self.ninflight < MAX_CHAIN {
                    self.inflight[self.ninflight] = (b.va, b.len);
                    self.ninflight += 1;
                }
            } else {
                dma::clean(b.va, b.len as usize);
            }
        }
        for (i, b) in chain.iter().enumerate() {
            let last = i + 1 == chain.len();
            let d = (self.va + OFF_DESC + 16 * i) as *mut u8;
            // SAFETY: descriptors sit at `va + 16*i` inside the queue page the caller gave to `queue`/`queue_sized`; `chain.len() <= size` is asserted above, and the descriptor table (16 bytes per entry, `size` entries) lies inside the page.
            unsafe {
                write_volatile(d as *mut u64, b.pa);
                write_volatile(d.add(8) as *mut u32, b.len);
                write_volatile(d.add(12) as *mut u16, if last { 0 } else { NEXT } | if b.dev_writes { WRITE } else { 0 });
                write_volatile(d.add(14) as *mut u16, if last { 0 } else { i as u16 + 1 });
            }
        }
        dma::clean(self.va + OFF_DESC, 16 * chain.len());
        // SAFETY: the available ring is inside the queue page (layout fits one page: fixed offsets for small queues, `packed_layout` otherwise); the slot index is reduced modulo `size`; the device only reads this ring.
        unsafe {
            let avail = (self.va + self.off_avail) as *mut u16;
            write_volatile(avail.add(2 + (self.avail_idx % self.size) as usize), 0); // head = descriptor 0
            fence();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            write_volatile(avail.add(1), self.avail_idx);
        }
        dma::clean(self.va + self.off_avail, 4 + 2 * self.size as usize);
    }

    /// Has the device finished the chain submitted last? (Call after an interrupt.)
    pub fn done(&mut self) -> bool {
        fence();
        dma::flush(self.va + self.off_used, 4 + 8 * self.size as usize); // the device wrote the used ring
        // SAFETY: the used ring (idx at +2) is inside the queue page that `va` points at; the device wrote it, hence volatile after the `dma::flush` above.
        let used = unsafe { read_volatile((self.va + self.off_used + 2) as *const u16) };
        if used != self.used_seen {
            fence(); // the device's data is read only after its index is seen
            self.used_seen = used;
            for i in 0..self.ninflight {
                let (va, len) = self.inflight[i];
                dma::flush(va, len as usize); // the data the device wrote, not what the cache held
            }
            self.ninflight = 0;
            fence();
            return true;
        }
        false
    }

    pub fn pa(&self) -> u64 {
        self.pa
    }

    /// Hand the device one standalone buffer (descriptor `desc`), for queues the *device* fills
    /// on its own schedule, such as an input device's event queue. Call `kick` after a batch.
    pub fn post(&mut self, desc: u16, b: Buf) {
        assert!(desc < self.size, "descriptor id outside the queue");
        if b.dev_writes {
            dma::flush(b.va, b.len as usize);
            if let Some(p) = self.posted.get_mut(desc as usize) {
                *p = (b.va, b.len);
            }
        } else {
            dma::clean(b.va, b.len as usize);
        }
        let d = (self.va + OFF_DESC + 16 * desc as usize) as *mut u8;
        // SAFETY: `desc < size` is asserted above, so `va + 16*desc` is inside the descriptor table in the queue page.
        unsafe {
            write_volatile(d as *mut u64, b.pa);
            write_volatile(d.add(8) as *mut u32, b.len);
            write_volatile(d.add(12) as *mut u16, if b.dev_writes { 2 } else { 0 });
            write_volatile(d.add(14) as *mut u16, 0);
        }
        dma::clean(self.va + OFF_DESC + 16 * desc as usize, 16);
        // SAFETY: the available ring is inside the queue page (see `submit_quiet`); index reduced modulo `size`; device reads only.
        unsafe {
            let avail = (self.va + self.off_avail) as *mut u16;
            write_volatile(avail.add(2 + (self.avail_idx % self.size) as usize), desc);
            fence();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            write_volatile(avail.add(1), self.avail_idx);
        }
        dma::clean(self.va + self.off_avail, 4 + 2 * self.size as usize);
    }

    pub fn kick(&self) {
        fence();
        // SAFETY: `notify` was checked in `queue_at` to lie, with its 2 bytes, inside the notify structure inside the BAR.
        unsafe { wr16(self.notify, self.index) };
    }

    /// The next buffer the device has finished with: (descriptor id, bytes written).
    pub fn next_used(&mut self) -> Option<(u16, u32)> {
        fence();
        dma::flush(self.va + self.off_used, 4 + 8 * self.size as usize); // the device wrote the used ring
        // SAFETY: the used ring idx is inside the queue page; the device wrote it, volatile after the flush above.
        let idx = unsafe { read_volatile((self.va + self.off_used + 2) as *const u16) };
        if idx == self.used_seen {
            return None;
        }
        fence(); // the element is read only after its index is seen ...
        let e = (self.va + self.off_used + 4 + 8 * (self.used_seen % self.size) as usize) as *const u32;
        dma::flush(e as usize, 8); // ... and from memory, not from a line fetched before the device wrote it
        // SAFETY: `e` is the used-ring element for `used_seen % size`, inside the queue page (the layout reserves 8 bytes per entry), 4-aligned, and was just flushed so the device's data is read.
        let (id, len) = unsafe { (read_volatile(e), read_volatile(e.add(1))) };
        self.used_seen = self.used_seen.wrapping_add(1);
        if let Some(&(va, n)) = self.posted.get(id as usize) {
            dma::flush(va, n as usize); // the event the device wrote into the buffer, not a stale copy
        }
        fence();
        Some((id as u16, len))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A fake device: a 4 KiB BAR and a config-space copy with one virtio capability per `(type, offset, length, notify mult)`.
    fn fake(caps: &[(u8, u32, u32, u32)], qnotify: u16) -> (std::vec::Vec<u64>, std::vec::Vec<u64>) {
        let mut cfg = std::vec![0u64; 32]; // 256 bytes, aligned
        // SAFETY: test only: `cfg` is a live 256-byte (32 x u64) vector, 8-aligned, and no other reference exists.
        let c = unsafe { core::slice::from_raw_parts_mut(cfg.as_mut_ptr() as *mut u8, 256) };
        c[0..4].copy_from_slice(&(0x1042u32 << 16 | 0x1af4).to_le_bytes());
        c[6] = 0x10; // capability list
        c[0x34] = 0x40;
        for (i, &(ty, off, len, mult)) in caps.iter().enumerate() {
            let at = 0x40 + 20 * i;
            c[at] = 0x09;
            c[at + 1] = if i + 1 < caps.len() { (at + 20) as u8 } else { 0 };
            c[at + 3] = ty;
            c[at + 8..at + 12].copy_from_slice(&off.to_le_bytes());
            c[at + 12..at + 16].copy_from_slice(&len.to_le_bytes());
            c[at + 16..at + 20].copy_from_slice(&mult.to_le_bytes());
        }
        let mut bar = std::vec![0u64; 512];
        // SAFETY: test only: `bar` is a live 4096-byte (512 x u64) vector, 8-aligned, and no other reference exists.
        let b = unsafe { core::slice::from_raw_parts_mut(bar.as_mut_ptr() as *mut u8, 4096) };
        b[C_QSIZE..C_QSIZE + 2].copy_from_slice(&256u16.to_le_bytes());
        b[C_QNOTIFY_OFF..C_QNOTIFY_OFF + 2].copy_from_slice(&qnotify.to_le_bytes());
        (cfg, bar)
    }

    fn open(cfg: &mut [u64], bar: &mut [u64]) -> Result<Pci, &'static str> {
        // SAFETY: `bar` is a 4096-byte buffer and `cfg` a 256-byte, 8-aligned one, both alive for the call and the test.
        unsafe { Pci::open(bar.as_mut_ptr() as usize, 4096, cfg.as_mut_ptr() as usize, 0x1042) }
    }

    const GOOD: [(u8, u32, u32, u32); 4] = [(1, 0, 0x40, 0), (2, 0x100, 0x100, 4), (3, 0x200, 4, 0), (4, 0x300, 0x20, 0)];

    #[test]
    fn a_device_cannot_point_the_driver_outside_its_bar_or_structures() {
        let (mut cfg, mut bar) = fake(&GOOD, 3);
        let pci = open(&mut cfg, &mut bar).expect("a sane device opens");
        let page = std::vec![0u8; 8192];
        let va = (page.as_ptr() as usize + 4095) & !4095;
        assert!(pci.queue_sized(0, 8, va, 0x1000).is_ok(), "doorbell 3*4 inside the notify structure");
        // a structure past the end of the BAR
        for bad in [(1u8, 4090u32, 0x40u32), (2, 0xFFFF_FFF0, 0x100), (3, 4095, 4), (4, 0x300, u32::MAX)] {
            let mut caps = GOOD;
            caps[bad.0 as usize - 1] = (bad.0, bad.1, bad.2, if bad.0 == 2 { 4 } else { 0 });
            let (mut cfg, mut bar) = fake(&caps, 3);
            assert!(open(&mut cfg, &mut bar).is_err(), "cap {bad:?} must be refused");
        }
        // a common structure too short to hold the registers the driver uses
        let mut caps = GOOD;
        caps[0].2 = 0x10;
        let (mut cfg, mut bar) = fake(&caps, 3);
        assert!(open(&mut cfg, &mut bar).is_err());
        // a doorbell index that lands beyond the notify structure (and one whose multiplication overflows)
        for q in [0x40u16, 0xFFFF] {
            let (mut cfg, mut bar) = fake(&GOOD, q);
            let pci = open(&mut cfg, &mut bar).unwrap();
            assert!(pci.queue_sized(0, 8, va, 0x1000).is_err(), "doorbell index {q:#x}");
        }
        let mut caps = GOOD;
        caps[1].3 = u32::MAX; // multiplier so large the product wraps
        let (mut cfg, mut bar) = fake(&caps, 0xFFFF);
        let pci = open(&mut cfg, &mut bar).unwrap();
        assert!(pci.queue_sized(0, 8, va, 0x1000).is_err());
    }

    #[test]
    fn the_used_ring_never_shares_a_cache_line_with_the_available_ring() {
        for size in 1..=256u16 {
            let Some((avail, used)) = packed_layout(size) else { continue };
            let avail_last_byte = avail + 4 + 2 * size as usize + 2 - 1; // flags, idx, the entries, used_event
            assert_eq!(used % 64, 0, "size {size}: used ring not line-aligned");
            assert!(avail_last_byte / 64 < used / 64, "size {size}: the rings share a cache line");
            assert!(avail >= 16 * size as usize, "size {size}: overlaps the descriptors");
            assert!(used + 4 + 8 * size as usize + 2 <= 4096, "size {size}: past the page");
        }
    }

    #[test]
    fn the_network_queues_fit_one_page_each() {
        use metallium_net_ring::{NRX, NTX};
        assert!(packed_layout(NRX as u16).is_some());
        assert!(packed_layout(NTX as u16).is_some());
        // (the transmit queue starts one page after the receive queue)
        let (_, used) = packed_layout(NRX as u16).unwrap();
        assert!(used + 6 + 8 * NRX <= 4096);
    }

    #[test]
    fn a_queue_too_big_for_a_page_is_refused() {
        assert!(packed_layout(512).is_none());
    }
}
