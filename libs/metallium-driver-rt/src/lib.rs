//! The runtime every Metallium-OS user-space task is built on, and what the device drivers share: the system-call layer (`svc` and its wrappers), the console
//! (`println!`), the mapping layer (boot-time services name their mappings by handle and the kernel chooses the address), virtio, DMA cache maintenance
//! and the protocols between drivers and their clients (`proto`).
//!
//! Extracted from the user image's `main.rs` so that a driver depends on this crate and on nothing else of the image (see docs/DRIVER-PACKAGES.md).
#![no_std]

extern crate alloc;

pub mod dma;
pub mod proto;
pub mod virtio;

#[cfg(target_arch = "aarch64")]
pub use core::arch::asm;
pub use core::fmt::{self, Write};
pub use core::ptr::{read_volatile, write_volatile};

// (the protocol constants keep their short names for the code that has always used them)
pub use proto::blk::*;

// ---- syscall ABI (svc #0): x0 = id, x1..x5 = args; x0 = status on return ----
pub const IPC_SEND: u64 = 1;
pub const IPC_RECV: u64 = 2;
pub const IPC_CALL: u64 = 3;
pub const MEM_MAP: u64 = 4;
pub const CAP_GRANT: u64 = 5;
pub const CAP_REVOKE: u64 = 6;
pub const YIELD: u64 = 7;
pub const IPC_REPLY: u64 = 8;
pub const LOG: u64 = 9;
pub const SLEEP: u64 = 10;
pub const EXIT: u64 = 11;
pub const TICKS: u64 = 12;
pub const IRQ_WAIT: u64 = 13;
pub const CAP_INFO: u64 = 14;
pub const HEAP_GROW: u64 = 15;
pub const SYSINFO: u64 = 21;
pub const CLOCK: u64 = 34;
pub const GETRANDOM: u64 = 43;
/// The machine's own secret (only the data store server may ask): 32 bytes in x1..x4.
pub const DEVICE_SECRET: u64 = 46;
pub const IPC_DEFER: u64 = 47;
pub const IPC_REPLY_TO: u64 = 48;
pub const ADD_ENTROPY: u64 = 49;
/// Sleep for a number of microseconds, not rounded up to the scheduler tick.
pub const SLEEP_US: u64 = 44;
/// Set the wall clock to a Unix time in nanoseconds; only netd may.
pub const SETTIME: u64 = 45;

pub const E_BADCAP: i64 = -2;
pub const E_DEAD: i64 = -4;
pub const E_INVAL: i64 = -5;
pub const E_NOSYS: i64 = -7;
pub const E_NOMEM: i64 = -8;
pub const E_TIMEDOUT: i64 = -9;

pub const R_MAP: u64 = 8;
pub const CONSOLE: u64 = 15; // cap slot holding the console capability




#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn svc(id: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> [u64; 6] {
    let (mut r0, mut r1, mut r2, mut r3, mut r4, mut r5) = (id, a1, a2, a3, a4, a5);
    // SAFETY: SVC #0 traps to the kernel, which preserves every register except x0-x5 (the declared inout results); no stack is used; pointer args are validated by the kernel.
    unsafe {
        asm!("svc #0",
            inout("x0") r0, inout("x1") r1, inout("x2") r2,
            inout("x3") r3, inout("x4") r4, inout("x5") r5,
            options(nostack));
    }
    [r0, r1, r2, r3, r4, r5]
}

/// (Host builds only compile this crate; there is no kernel to call.)
#[cfg(not(target_arch = "aarch64"))]
pub fn svc(_id: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> [u64; 6] {
    unimplemented!("system calls exist only on the machine")
}


pub struct Con {
    buf: [u8; 192],
    len: usize,
}

impl Con {
    pub const fn new() -> Con {
        Con { buf: [0; 192], len: 0 }
    }

    pub fn flush(&mut self) {
        if self.len > 0 {
            svc(LOG, CONSOLE, self.buf.as_ptr() as u64, self.len as u64, 0, 0);
            self.len = 0;
        }
    }
}

impl Write for Con {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

/// Print a line on the console (one `LOG` call per 192 bytes).
#[macro_export]
macro_rules! println {
    ($($a:tt)*) => {{
        use ::core::fmt::Write as _;
        let mut c = $crate::Con::new();
        let _ = writeln!(c, $($a)*);
        c.flush();
    }};
}

/// The boot-time services keep their mappings at no address the kernel has not chosen: they name each one by a *handle*
/// (a constant in the old fixed window, `0x8020_0000..0x8040_0000`), `mem_map` has the kernel pick a random place for it
/// (`MEM_MAP` address 0) and remembers it, and `va(handle)` gives the address to use. Every handle owns 64 KiB, so
/// `handle + offset` works inside it. (The test programs, which exercise explicit addresses, do not call `auto_maps`.)
static AUTO_MAPS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub const HANDLE_LO: usize = 0x8020_0000;
pub const HANDLE_HI: usize = 0x8040_0000;
pub const HANDLE_SPAN: usize = 0x1_0000;
/// (the big window's handles, such as the framebuffer's, own the window up to its end)
pub const BIG_HANDLE_LO: usize = 0xA000_0000;
pub fn is_handle(h: usize) -> bool {
    (HANDLE_LO..HANDLE_HI).contains(&h) || (BIG_HANDLE_LO..0xC000_0000).contains(&h)
}
pub const MAX_HANDLES: usize = 24;
static HANDLES: [core::sync::atomic::AtomicUsize; MAX_HANDLES] = [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_HANDLES];
static REAL: [core::sync::atomic::AtomicUsize; MAX_HANDLES] = [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_HANDLES];

/// From now on this task's `mem_map` calls on handles let the kernel choose the address (and the kernel refuses any
/// other explicit address: the task was started with that restriction).
pub fn auto_maps() {
    AUTO_MAPS.store(true, core::sync::atomic::Ordering::SeqCst);
}

pub fn mem_map(slot: u64, handle: usize, writable: bool) -> i64 {
    use core::sync::atomic::Ordering::SeqCst;
    if !AUTO_MAPS.load(SeqCst) || !is_handle(handle) {
        return svc(MEM_MAP, slot, handle as u64, writable as u64, 0, 0)[0] as i64;
    }
    let r = svc(MEM_MAP, slot, 0, writable as u64, 0, 0)[0] as i64;
    if r < 0 {
        return r;
    }
    let i = (0..MAX_HANDLES).find(|&i| HANDLES[i].load(SeqCst) == handle).or_else(|| (0..MAX_HANDLES).find(|&i| HANDLES[i].load(SeqCst) == 0));
    let Some(i) = i else { return -3 };
    REAL[i].store(r as usize, SeqCst);
    HANDLES[i].store(handle, SeqCst);
    0
}

/// The address a handle (or an offset into one) really has; the argument itself if it is not a mapped handle.
pub fn va(handle: usize) -> usize {
    use core::sync::atomic::Ordering::SeqCst;
    let mut best: Option<(usize, usize)> = None;
    for i in 0..MAX_HANDLES {
        let h = HANDLES[i].load(SeqCst);
        if h != 0 && h <= handle && handle - h < if h >= BIG_HANDLE_LO { 0xC000_0000 - h } else { HANDLE_SPAN } && best.map_or(true, |(bh, _)| h > bh) {
            best = Some((h, REAL[i].load(SeqCst)));
        }
    }
    best.map_or(handle, |(h, real)| real + (handle - h))
}
pub fn cap_grant(slot: u64, target: u64, rights: u64) -> i64 {
    svc(CAP_GRANT, slot, target, rights, 0, 0)[0] as i64
}
pub fn cap_revoke(slot: u64) -> i64 {
    svc(CAP_REVOKE, slot, 0, 0, 0, 0)[0] as i64
}
pub fn send(slot: u64, w: [u64; 3]) -> i64 {
    svc(IPC_SEND, slot, w[0], w[1], w[2], 0)[0] as i64
}
/// Returns (status, reply words).
pub fn call(slot: u64, w: [u64; 3]) -> (i64, [u64; 3]) {
    let r = svc(IPC_CALL, slot, w[0], w[1], w[2], 0);
    (r[0] as i64, [r[1], r[2], r[3]])
}
pub struct Msg {
    pub sender: u64,
    pub w: [u64; 3],
    pub is_call: bool,
}
pub fn recv(slot: u64) -> Msg {
    let r = svc(IPC_RECV, slot, 0, 0, 0, 0);
    Msg { sender: r[1], w: [r[2], r[3], r[4]], is_call: r[5] != 0 }
}
/// Like `recv`, but returns `None` at once if nothing is queued (`IPC_RECV` with its second argument set).
pub fn try_recv(slot: u64) -> Option<Msg> {
    let r = svc(IPC_RECV, slot, 1, 0, 0, 0);
    (r[0] as i64 == 0).then(|| Msg { sender: r[1], w: [r[2], r[3], r[4]], is_call: r[5] != 0 })
}
pub fn reply(w: [u64; 3]) -> i64 {
    svc(IPC_REPLY, w[0], w[1], w[2], 0, 0)[0] as i64
}
/// Park the call being served (see `IPC_DEFER`): the caller waits, this task serves others; the token goes to `reply_to` later. `None` if there is no call to park.
pub fn defer() -> Option<u64> {
    let r = svc(IPC_DEFER, 0, 0, 0, 0, 0)[0] as i64;
    (r >= 0).then_some(r as u64)
}
/// Answer a parked caller; false if it is gone.
pub fn reply_to(token: u64, w: [u64; 3]) -> bool {
    svc(IPC_REPLY_TO, token, w[0], w[1], w[2], 0)[0] as i64 == 0
}
/// Hand the kernel 32 bytes from an entropy device (`ADD_ENTROPY`; only the entropy driver, role 21, may). 0 when they were folded in, `E_NOSYS` when the generator takes no
/// outside entropy (the layout debugging modes), `E_PERM` for any other caller.
pub fn add_entropy(bytes: &[u8; 32]) -> i64 {
    let w = |i: usize| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    svc(ADD_ENTROPY, w(0), w(1), w(2), w(3), 0)[0] as i64
}
/// Like `irq_wait`, but gives up after `ticks` (returns E_TIMEDOUT): the driver's watchdog on a silent device.
pub fn irq_wait_timeout(slot: u64, ticks: u64) -> i64 {
    svc(IRQ_WAIT, slot, ticks, 0, 0, 0)[0] as i64
}
/// (status, physical address, pages, offset-in-page)
pub fn cap_info(slot: u64) -> (i64, u64, u64, u64) {
    let r = svc(CAP_INFO, slot, 0, 0, 0, 0);
    (r[0] as i64, r[1], r[2], r[3])
}
/// System facts from the kernel (see the kernel's `sysinfo` for what each page returns).
pub fn sysinfo(page: u64) -> [u64; 6] {
    svc(SYSINFO, page, 0, 0, 0, 0)
}
/// One row of a kernel table: SYSINFO page 3 gives task `arg`'s (name, state, restarts, role).
pub fn sysinfo_at(page: u64, arg: u64) -> [u64; 6] {
    svc(SYSINFO, page, arg, 0, 0, 0)
}
/// Sleep for a number of microseconds, with the precision of the counter rather than the 10 ms tick (`SLEEP_US`).
pub fn sleep_us(us: u64) {
    svc(SLEEP_US, us, 0, 0, 0, 0);
}
pub fn sleep(ticks: u64) {
    svc(SLEEP, ticks, 0, 0, 0, 0);
}
pub fn ticks() -> u64 {
    svc(TICKS, 0, 0, 0, 0, 0)[0]
}
pub fn exit(code: u64) -> ! {
    svc(EXIT, code, 0, 0, 0, 0);
    loop {}
}

/// A private copy of bytes a client can change at any time (a session page). Parse the copy, never the page: a check made on
/// the page proves nothing about what is there when the bytes are used.
pub fn snapshot<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate().take(src.len()) {
        // SAFETY: `i < src.len()`; volatile so each byte is read exactly once.
        *o = unsafe { read_volatile(src.as_ptr().add(i)) };
    }
    out
}
