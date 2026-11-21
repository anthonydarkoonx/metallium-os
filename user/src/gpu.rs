//! Display: the virtio-gpu driver (role 12) and the conductor's drawing test.
//!
//! The driver owns the device. Its DMA reach is limited by the kernel's IOMMU to its queue page,
//! its command page and the framebuffer. A client holds only the framebuffer (mapped for
//! drawing) and an endpoint: it draws pixels itself and asks the driver to present a rectangle.
//! Commands follow the virtio specification's GPU device (2D resources, one scanout).
use metallium_driver_rt::proto::gpu::*;
use metallium_driver_rt::virtio;
use metallium_driver_rt::*;

/// The screen size: a property of the machine's display, so it lives with its driver, not in the protocol (a board gives its own).
pub const W: usize = 1024;
pub const H: usize = 768;
const FB_BYTES: usize = W * H * 4;
const WATCHDOG_TICKS: u64 = 500;

// the driver's view
const MMIO_VA: usize = 0x8020_0000;
const QUEUE_VA: usize = 0x8021_0000;
const CMD_VA: usize = 0x8022_0000;
const CFG_VA: usize = 0x8023_0000;
/// (the framebuffer is 3 MiB: it goes in the large shared-memory window)
const FB_VA: usize = 0xBC00_0000;
const RESP: usize = 0x800; // responses go in the second half of the command page

// virtio_gpu_ctrl_type
const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
/// VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: a pixel is the 32-bit word 0x00RRGGBB.
const FORMAT_B8G8R8X8: u32 = 2;
/// Buffer `b` is virtio resource `b + 1`, mapped at handle `FB_VA + b * FB_STRIDE` (the driver's slot 4 for buffer 0, 7.. for the others).
const FB_STRIDE: usize = 0x40_0000;
const MAX_BUFFERS: usize = 4;

fn put32(off: usize, v: u32) {
    // SAFETY: CMD_VA is the command page mapped read-write (mem_map in gpu_init); callers use offsets < RESP + response size, well inside 4096 bytes.
    unsafe { write_volatile((va(CMD_VA) + off) as *mut u32, v) }
}
fn put64(off: usize, v: u64) {
    // SAFETY: same mapped command page; callers pass 8-aligned offsets inside it.
    unsafe { write_volatile((va(CMD_VA) + off) as *mut u64, v) }
}
fn get32(off: usize) -> u32 {
    // SAFETY: same mapped command page; the device wrote the response (volatile, after submit's cache maintenance).
    unsafe { read_volatile((va(CMD_VA) + off) as *const u32) }
}

struct Gpu {
    pci: virtio::Pci,
    q: virtio::Queue,
    cmd_pa: u64,
    fb_pa: u64,
    host_enabled: u32,
    /// How many buffers there are (1 unless the machine runs sessions) and which one is on the screen.
    buffers: usize,
    active: usize,
}

impl Gpu {
    /// Start a request: clear the 24-byte control header and set its type.
    fn begin(&self, ty: u32) {
        for o in (0..24).step_by(8) {
            put64(o, 0);
        }
        put32(0, ty);
    }

    /// Send the request in the command page (`req` bytes) and wait for the response (`resp` bytes).
    fn send(&mut self, req: usize, resp: usize) -> u32 {
        // SAFETY: CMD_VA is the mapped command page and `resp` (a response size of at most 24 + 16*24 bytes) fits after RESP; the device does not touch it before `submit`.
        unsafe { core::ptr::write_bytes((va(CMD_VA) + RESP) as *mut u8, 0, resp) };
        self.q.submit(&[
            virtio::Buf { pa: self.cmd_pa, va: va(CMD_VA), len: req as u32, dev_writes: false },
            virtio::Buf { pa: self.cmd_pa + RESP as u64, va: va(CMD_VA) + RESP, len: resp as u32, dev_writes: true },
        ]);
        self.wait_done(WATCHDOG_TICKS);
        get32(RESP)
    }

    /// Wait for the device to finish the command in flight; a device that stays silent for `limit` ticks
    /// is treated as dead (the driver exits, the kernel restarts it, starting up resets the device).
    fn wait_done(&mut self, limit: u64) {
        let deadline = ticks() + limit; // (absolute: the interrupt line may be shared, so wake-ups prove nothing)
        loop {
            let left = deadline.saturating_sub(ticks());
            if left == 0 || irq_wait_timeout(5, left) == E_TIMEDOUT {
                println!("[gpu] watchdog: the device did not answer within {} ms; restarting the driver", limit * 10);
                exit(1);
            }
            self.pci.ack_isr();
            if self.q.done() {
                return;
            }
        }
    }

    fn rect(&self, at: usize, x: usize, y: usize, w: usize, h: usize) {
        put32(at, x as u32);
        put32(at + 4, y as u32);
        put32(at + 8, w as u32);
        put32(at + 12, h as u32);
    }

    fn create(&mut self, id: u32, w: usize, h: usize) -> bool {
        self.begin(CMD_RESOURCE_CREATE_2D);
        put32(24, id);
        put32(28, FORMAT_B8G8R8X8);
        put32(32, w as u32);
        put32(36, h as u32);
        self.send(40, 24) == RESP_OK_NODATA
    }

    /// Back resource `id` with one contiguous guest range.
    fn attach(&mut self, id: u32, addr: u64, len: usize) -> bool {
        self.begin(CMD_RESOURCE_ATTACH_BACKING);
        put32(24, id);
        put32(28, 1); // one memory entry
        put64(32, addr);
        put32(40, len as u32);
        put32(44, 0);
        self.send(48, 24) == RESP_OK_NODATA
    }

    fn scanout(&mut self, id: u32, w: usize, h: usize) -> bool {
        self.begin(CMD_SET_SCANOUT);
        self.rect(24, 0, 0, w, h);
        put32(40, 0); // scanout 0
        put32(44, id);
        self.send(48, 24) == RESP_OK_NODATA
    }

    /// Copy a rectangle of the guest framebuffer to the host resource, then flush it to the screen.
    fn present(&mut self, id: u32, x: usize, y: usize, w: usize, h: usize) -> bool {
        self.transfer(id, x, y, w, h) && self.flush(id, x, y, w, h)
    }

    /// Copy a rectangle of the backing store to the host.
    fn transfer(&mut self, id: u32, x: usize, y: usize, w: usize, h: usize) -> bool {
        // the device reads the rectangle from memory: what the screen task drew must have left the CPU's caches
        // (every resource this driver backs is one of its mapped buffers: id = buffer + 1)
        metallium_driver_rt::dma::clean(va(FB_VA + (id as usize - 1) * FB_STRIDE) + (y * W + x) * 4, ((h - 1) * W + w) * 4);
        self.begin(CMD_TRANSFER_TO_HOST_2D);
        self.rect(24, x, y, w, h);
        put64(40, ((y * W + x) * 4) as u64); // where the rectangle's first pixel is in the backing store
        put32(48, id);
        put32(52, 0);
        self.send(56, 24) == RESP_OK_NODATA
    }

    /// Show a rectangle that was transferred.
    fn flush(&mut self, id: u32, x: usize, y: usize, w: usize, h: usize) -> bool {
        self.begin(CMD_RESOURCE_FLUSH);
        self.rect(24, x, y, w, h);
        put32(40, id);
        put32(44, 0);
        self.send(48, 24) == RESP_OK_NODATA
    }
}

fn gpu_init() -> Result<Gpu, &'static str> {
    if mem_map(1, MMIO_VA, true) != 0
        || mem_map(2, QUEUE_VA, true) != 0
        || mem_map(3, CMD_VA, true) != 0
        || mem_map(4, FB_VA, true) != 0
        || mem_map(6, CFG_VA, false) != 0
    {
        return Err("mapping failed");
    }
    let (s1, _, bar_pages, _) = cap_info(1);
    let (s2, queue_pa, _, _) = cap_info(2);
    let (s3, cmd_pa, _, _) = cap_info(3);
    let (s4, fb_pa, fb_pages, _) = cap_info(4);
    if s1 != 0 || s2 != 0 || s3 != 0 || s4 != 0 {
        return Err("cap_info failed");
    }
    if (fb_pages as usize) * 4096 < FB_BYTES {
        return Err("framebuffer too small");
    }
    // SAFETY: the BAR and config-space mappings the kernel gave this driver (`bar_pages` pages at MMIO_VA / CFG_VA, per its facts).
    let pci = unsafe { virtio::Pci::open(va(MMIO_VA), bar_pages as usize * 4096, va(CFG_VA), 0x1050) }?;
    pci.start()?;
    // the DMA pages outlive a crashed driver: forget stale queue and command state
    // SAFETY: QUEUE_VA and CMD_VA are the two pages mapped (checked) above; the device has not been given the queue yet.
    unsafe {
        core::ptr::write_bytes(va(QUEUE_VA) as *mut u8, 0, 4096);
        core::ptr::write_bytes(va(CMD_VA) as *mut u8, 0, 4096);
    }
    let q = pci.queue(0, 8, va(QUEUE_VA), queue_pa)?; // queue 0 is the control queue
    pci.driver_ok();
    let mut g = Gpu { pci, q, cmd_pa, fb_pa, host_enabled: 0, buffers: 1, active: 0 };

    g.begin(CMD_GET_DISPLAY_INFO);
    if g.send(24, 24 + 16 * 24) != RESP_OK_DISPLAY_INFO {
        return Err("display info failed");
    }
    let (host_w, host_h, enabled) = (get32(RESP + 32), get32(RESP + 36), get32(RESP + 40));
    g.host_enabled = enabled;
    if !g.create(1, W, H) || !g.attach(1, fb_pa, FB_BYTES) || !g.scanout(1, W, H) {
        return Err("could not set up the scanout");
    }
    // the other ttys' buffers, where the machine has them (the kernel makes them only where sessions run): each its own resource, none on the screen yet
    for b in 1..MAX_BUFFERS {
        if mem_map(7 + b as u64 - 1, FB_VA + b * FB_STRIDE, true) != 0 {
            break;
        }
        let (s, pa, pages, _) = cap_info(7 + b as u64 - 1);
        if s != 0 || (pages as usize) * 4096 < FB_BYTES || !g.create(b as u32 + 1, W, H) || !g.attach(b as u32 + 1, pa, FB_BYTES) {
            return Err("could not set up a tty's buffer");
        }
        g.buffers = b + 1;
    }
    println!("[gpu] scanout {W}x{H} ready (host reports {host_w}x{host_h}, enabled={enabled}), {} buffer(s)", g.buffers);
    Ok(g)
}

pub fn gpu_driver() -> ! {
    println!("[gpu] driver starting");
    let mut g = match gpu_init() {
        Ok(g) => g,
        Err(e) => {
            println!("[gpu] init failed: {e}");
            exit(1)
        }
    };
    loop {
        let m = recv(0);
        let (op, buffer) = (m.w[0] & 0xFF, (m.w[0] >> BUFFER_SHIFT) as usize & 0xFF);
        // a present names its tty's buffer (0 when it says nothing); one that is not on the screen is copied to the host, not shown
        let res = buffer as u32 + 1;
        let shown = buffer == g.active;
        match op {
            GPU_FLUSH | GPU_FLUSH2 if buffer >= g.buffers => {
                reply([1, 0, 0]);
            }
            GPU_FLUSH => {
                let (x, y, w, h) = (m.w[1] as usize & 0xffff, (m.w[1] >> 16) as usize & 0xffff, (m.w[1] >> 32) as usize & 0xffff, (m.w[1] >> 48) as usize);
                if w == 0 || h == 0 || x + w > W || y + h > H {
                    reply([1, 0, 0]);
                    continue;
                }
                let ok = if shown { g.present(res, x, y, w, h) } else { g.transfer(res, x, y, w, h) };
                reply([!ok as u64, 0, 0]);
            }
            GPU_FLUSH2 => {
                let unpack = |v: u64| (v as usize & 0xffff, (v >> 16) as usize & 0xffff, (v >> 32) as usize & 0xffff, (v >> 48) as usize);
                let rects = [unpack(m.w[1]), unpack(m.w[2])];
                let valid = |&(x, y, w, h): &(usize, usize, usize, usize)| w != 0 && h != 0 && x + w <= W && y + h <= H;
                // a rectangle that is all zero is "none"; anything else that is off the screen refuses the whole call
                if rects.iter().any(|r| (r.2 != 0 || r.3 != 0) && !valid(r)) {
                    reply([1, 0, 0]);
                    continue;
                }
                let mut ok = true;
                let (mut x0, mut y0, mut x1, mut y1, mut any) = (W, H, 0, 0, false);
                for r in rects.iter().filter(|r| valid(r)) {
                    ok &= g.transfer(res, r.0, r.1, r.2, r.3);
                    (x0, y0, x1, y1, any) = (x0.min(r.0), y0.min(r.1), x1.max(r.0 + r.2), y1.max(r.1 + r.3), true);
                }
                if ok && any && shown {
                    ok = g.flush(res, x0, y0, x1 - x0, y1 - y0);
                }
                reply([!ok as u64, 0, 0]);
            }
            GPU_INFO => {
                reply([W as u64 | (H as u64) << 32, g.host_enabled as u64, g.buffers as u64]);
            }
            GPU_SCANOUT => {
                // the tty switch is the input driver's (it sees Ctrl+Alt+F1..F12 first); the conductor (task 0) stands in for it in `make tty-test`
                let role = sysinfo_at(3, m.sender)[5];
                if m.sender != 0 && role != 14 {
                    reply([2, 0, 0]);
                    continue;
                }
                let b = m.w[1] as usize;
                if b >= g.buffers {
                    reply([1, 0, 0]);
                    continue;
                }
                // the buffer shown is whole: copy all of it, then point the scanout at it
                let ok = g.transfer(b as u32 + 1, 0, 0, W, H) && g.scanout(b as u32 + 1, W, H) && g.flush(b as u32 + 1, 0, 0, W, H);
                if ok {
                    g.active = b;
                    println!("[gpu] tty {b} is in front");
                }
                reply([!ok as u64, 0, 0]);
            }
            GPU_ACTIVE => {
                reply([g.active as u64, g.buffers as u64, 0]);
            }
            GPU_STALL => {
                if m.sender != 0 {
                    reply([1, 0, 0]);
                    continue;
                }
                println!("[gpu] test: sending a command without telling the device");
                g.begin(CMD_GET_DISPLAY_INFO);
                g.q.submit_quiet(&[
                    virtio::Buf { pa: g.cmd_pa, va: va(CMD_VA), len: 24, dev_writes: false },
                    virtio::Buf { pa: g.cmd_pa + RESP as u64, va: va(CMD_VA) + RESP, len: 24 + 16 * 24, dev_writes: true },
                ]);
                g.wait_done(100); // exits through the watchdog; never replies
            }
            GPU_EVIL if m.sender != 0 => {
                reply([1, 0, 0]); // fault injection is the test conductor's tool (the syscall fuzzer found it open to everyone)
            }
            GPU_EVIL => {
                // Make the device read a page beyond the framebuffer: back a second resource with it
                // and transfer. The IOMMU faults the access and the kernel restarts this driver, so
                // this never replies.
                let target = g.fb_pa + (FB_BYTES.div_ceil(4096) * 4096) as u64 + 0x1000;
                println!("[gpu] misbehaving: pointing the device at memory outside my grant ({target:#x})");
                let ok = g.create(9, 16, 16) && g.attach(9, target, 16 * 16 * 4) && g.present(9, 0, 0, 16, 16);
                reply([ok as u64, 0, 0]); // only reached if the DMA was NOT blocked
            }
            _ => {
                reply([1, 0, 0]);
            }
        }
    }
}

