//! The smallest runtime a Metallium-OS program needs: system calls, console output, and the entry/exit glue.
//!
//! A program is a flat image whose 32-byte header the linker script writes (see ../link.ld); the kernel starts it at
//! the first instruction after the header with x0 = 32 (the "program" role), x1 = the argument its parent gave, x2 =
//! its parent's task id, x3/x4 = address and length of the argument block (NUL-separated strings, on its stack).
//! Capability slot 15 is the console; slots 0..7 hold what the parent delegated; with file-system access, slot 8 is
//! the VFS endpoint and slot 9 the session page (see `fs`).
#![no_std]

extern crate alloc;

use core::arch::asm;
use core::fmt::{self, Write};

pub const IPC_SEND: u64 = 1;
pub const IPC_CALL: u64 = 3;
pub const YIELD: u64 = 7;
pub const LOG: u64 = 9;
pub const SLEEP: u64 = 10;
pub const EXIT: u64 = 11;
pub const TICKS: u64 = 12;
pub const HEAP_GROW: u64 = 15;
pub const SPAWN: u64 = 24;
pub const WAIT: u64 = 25;
pub const KILL: u64 = 26;
pub const EP_CREATE: u64 = 27;
pub const IPC_RECV: u64 = 2;
pub const IPC_REPLY: u64 = 8;
pub const MEM_MAP: u64 = 4;
pub const CAP_REVOKE: u64 = 6;
pub const CAP_GRANT: u64 = 5;
pub const SYSINFO: u64 = 21;

pub mod ability;
pub mod env;
pub mod fs;
pub mod ctl;
pub mod heap;
pub mod io;
pub mod ipc;
// the network client API (sockets, name lookup, ping) lives in the networking repository, checked out next to this one
#[path = "../../../metallium-networking-userspace/client/net.rs"]
pub mod net;
pub mod process;
pub mod random;
pub mod rt;
pub mod sync;
pub mod thread;
pub mod time;

pub const CONSOLE: u64 = 15;
pub const NONE: u8 = 0xFF;
pub const EXIT_FAULTED: u64 = u64::MAX;
pub const EXIT_KILLED: u64 = u64::MAX - 1;

#[inline(always)]
pub fn svc(id: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> [u64; 6] {
    let (mut r0, mut r1, mut r2, mut r3, mut r4, mut r5) = (id, a1, a2, a3, a4, a5);
    unsafe {
        // SAFETY: `svc #0` enters the kernel, which per docs/ABI.md changes only x0-x5 (all declared `inout`) and nothing else; it uses no
        // stack (`nostack`), and the default asm options keep it a memory barrier, so pointers handed over as integers stay covered.
        asm!("svc #0", inout("x0") r0, inout("x1") r1, inout("x2") r2, inout("x3") r3, inout("x4") r4, inout("x5") r5, options(nostack));
    }
    [r0, r1, r2, r3, r4, r5]
}

pub fn exit(code: u64) -> ! {
    svc(EXIT, code, 0, 0, 0, 0);
    loop {}
}

pub fn yield_now() {
    svc(YIELD, 0, 0, 0, 0, 0);
}

pub fn sleep(ticks: u64) {
    svc(SLEEP, ticks, 0, 0, 0, 0);
}

pub fn ticks() -> u64 {
    svc(TICKS, 0, 0, 0, 0, 0)[0]
}

/// Call an endpoint capability; returns (status, reply words).
pub fn call(slot: u64, w: [u64; 3]) -> (i64, [u64; 3]) {
    let r = svc(IPC_CALL, slot, w[0], w[1], w[2], 0);
    (r[0] as i64, [r[1], r[2], r[3]])
}

pub const QUOTA: u64 = 36;

/// A program's memory limits (see `quota`).
#[derive(Clone, Copy, Debug)]
pub struct Quota {
    /// Pages it may hold itself (heap and contiguous allocations).
    pub limit: u64,
    /// Pages it holds.
    pub held: u64,
    /// Pages it may hand down to programs it starts.
    pub budget: u64,
    /// Pages it has handed down so far (to live programs).
    pub delegated: u64,
    /// Programs it has started and not yet collected.
    pub children: u64,
}

/// This program's memory limits and what it uses of them.
pub fn quota() -> Quota {
    let r = svc(QUOTA, 0, 0, 0, 0, 0);
    Quota { limit: r[0], held: r[1], budget: r[2], delegated: r[3], children: r[4] }
}

/// Change a child's limits: its own (`heap_pages`, 1..=1048576) and what it may hand down (`budget_pages`). Charged to this
/// program's budget; 0 or a negative error (not a child, below what it holds, over my budget).
pub fn set_child_quota(child: u64, heap_pages: u32, budget_pages: u32) -> i64 {
    svc(QUOTA, 1, child, heap_pages as u64, budget_pages as u64, 0)[0] as i64
}

/// Grow the heap by `pages`; the base address, or the error (negative).
pub fn heap_grow(pages: u64) -> i64 {
    svc(HEAP_GROW, pages, 0, 0, 0, 0)[0] as i64
}

pub const MMAP: u64 = 50;
pub const MUNMAP: u64 = 51;
pub const MPROTECT: u64 = 52;
/// Protections for `mmap` and `mprotect` (write and execute never together).
pub const PROT_NONE: u64 = 0;
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
/// `mmap` flag: use the address given (inside the arena) instead of choosing one.
pub const MAP_FIXED: u64 = 1 << 8;

/// `pages` pages of anonymous zeroed memory, allocated when first touched and counted against this program's memory limit then; the address, or the
/// error (negative). `prot` is `PROT_*`, optionally with `MAP_FIXED` (see the kernel's `MMAP`).
pub fn mmap(addr: u64, pages: u64, prot: u64) -> i64 {
    svc(MMAP, addr, pages, prot, 0, 0)[0] as i64
}

/// Free the `mmap` pages in a range (holes are fine); 0 or a negative error.
pub fn munmap(addr: u64, pages: u64) -> i64 {
    svc(MUNMAP, addr, pages, 0, 0, 0)[0] as i64
}

/// Change the protection of `mmap` pages (all of them must exist); 0 or a negative error. A page made executable is ready to run what was written to it.
pub fn mprotect(addr: u64, pages: u64, prot: u64) -> i64 {
    svc(MPROTECT, addr, pages, prot, 0, 0)[0] as i64
}

/// What a program tells `spawn` about the program it starts (see the kernel's spawn.rs for the request layout).
pub struct Spawn<'a> {
    pub image: &'a [u8],
    pub arg: u64,
    pub args: &'a [u8],
    pub heap_pages: u32,
    /// Pages the program may hand down to programs of its own (its children cost this program's budget too).
    pub budget_pages: u32,
    pub class: u32,
    pub fs: bool,
    /// How many threads besides itself the program may have at once (at most 64).
    pub threads: u8,
    /// (slot of mine, rights mask) for the child's slots 0, 1, ...; `None` leaves a slot empty.
    pub give: [Option<(u8, u16)>; 8],
}

impl<'a> Spawn<'a> {
    pub fn new(image: &'a [u8]) -> Spawn<'a> {
        Spawn { image, arg: 0, args: &[], heap_pages: 0, budget_pages: 0, class: 0, fs: false, threads: 0, give: [None; 8] }
    }
}

pub const ALL_BUT_GRANT: u16 = 0xFFFF & !4;

pub fn spawn(slot: u64, p: &Spawn) -> i64 {
    let mut b = [0u8; 96];
    b[4..8].copy_from_slice(&((p.fs as u32) | (p.threads as u32) << 8).to_le_bytes());
    b[8..12].copy_from_slice(&p.budget_pages.to_le_bytes());
    b[24..28].copy_from_slice(&p.class.to_le_bytes());
    b[28..32].copy_from_slice(&p.heap_pages.to_le_bytes());
    b[32..40].copy_from_slice(&p.arg.to_le_bytes());
    b[40..48].copy_from_slice(&(p.args.as_ptr() as u64).to_le_bytes());
    b[48..56].copy_from_slice(&(p.args.len() as u64).to_le_bytes());
    for i in 0..8 {
        let (from, mask) = p.give[i].unwrap_or((NONE, 0));
        b[64 + 4 * i] = from;
        b[66 + 4 * i..68 + 4 * i].copy_from_slice(&mask.to_le_bytes());
    }
    metallium_loader::spawn(|id, a1, a2, a3, a4| svc(id, a1, a2, a3, a4, 0)[0], slot, &mut b, p.image)
}

/// Create an endpoint with the factory capability in `slot`; the slot of the new (send+receive+grant) capability.
pub fn ep_create(slot: u64) -> i64 {
    svc(EP_CREATE, slot, 0, 0, 0, 0)[0] as i64
}

/// Revoke everything derived from the capability in `slot`.
pub fn revoke(slot: u64) -> i64 {
    svc(CAP_REVOKE, slot, 0, 0, 0, 0)[0] as i64
}

/// Revoke the capability in `slot` itself too (for an endpoint's creator: the endpoint ends).
pub fn revoke_self(slot: u64) -> i64 {
    svc(CAP_REVOKE, slot, 1, 0, 0, 0)[0] as i64
}

pub const SHM_CREATE: u64 = 37;

/// Fresh zeroed memory (1..=65536 pages) that can be shared: the slot of a memory capability (map, write, grant), or a
/// negative error (`-5` bad size, `-8` over the memory limit, `-3` no free slot). It lives as long as that capability:
/// grant it to other programs (or delegate it when starting them) to share it; `revoke_self` frees it for all of them.
pub fn shm_create(pages: u64) -> i64 {
    svc(SHM_CREATE, pages, 0, 0, 0, 0)[0] as i64
}

pub fn map(slot: u64, va: usize, writable: bool) -> i64 {
    svc(MEM_MAP, slot, va as u64, writable as u64, 0, 0)[0] as i64
}

/// Map the memory capability in `slot` where the kernel chooses (random, with an unmapped page on each side); the address, or
/// a negative error.
pub fn map_anywhere(slot: u64, writable: bool) -> i64 {
    svc(MEM_MAP, slot, 0, writable as u64, 0, 0)[0] as i64
}

pub struct Msg {
    pub sender: u64,
    pub w: [u64; 3],
    pub call: bool,
}

/// Receive on the endpoint in `slot`; `Err` is the kernel's error (the endpoint ended: -4).
pub fn recv(slot: u64) -> Result<Msg, i64> {
    let r = svc(IPC_RECV, slot, 0, 0, 0, 0);
    if r[0] as i64 != 0 {
        return Err(r[0] as i64);
    }
    Ok(Msg { sender: r[1], w: [r[2], r[3], r[4]], call: r[5] != 0 })
}

pub fn reply(w: [u64; 3]) -> i64 {
    svc(IPC_REPLY, w[0], w[1], w[2], 0, 0)[0] as i64
}

/// What a program is started with.
pub struct Ctx {
    pub arg: u64,
    pub parent: u64,
    args_ptr: u64,
    args_len: u64,
}

impl Ctx {
    /// # Safety
    /// `args_ptr..args_ptr + args_len` must be readable memory that stays mapped and unchanged for the life of the program
    /// (or `args_len` 0). Only the program entry code, which gets these from the kernel, builds one.
    #[doc(hidden)]
    pub unsafe fn new(arg: u64, parent: u64, args_ptr: u64, args_len: u64) -> Ctx {
        Ctx { arg, parent, args_ptr, args_len }
    }

    /// The argument block as bytes.
    pub fn args(&self) -> &'static [u8] {
        if self.args_len == 0 {
            &[]
        } else {
            // SAFETY: `Ctx::new`'s contract: `args_ptr..+args_len` is readable memory that stays mapped and unchanged for the whole run of the program;
            // u8 needs no alignment and `args_len > 0` here.
            unsafe { core::slice::from_raw_parts(self.args_ptr as *const u8, self.args_len as usize) }
        }
    }

    /// The strings of the argument block, in order (a string ends at its NUL; an empty one is returned as such).
    fn strings(&self) -> impl Iterator<Item = &'static [u8]> {
        let mut rest = self.args();
        core::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let n = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let s = &rest[..n];
            rest = &rest[(n + 1).min(rest.len())..];
            Some(s)
        })
    }

    /// The command line: the strings before the first empty one. By convention `argv(0)` is the program's name.
    pub fn argv(&self, i: usize) -> Option<&'static str> {
        self.strings().take_while(|s| !s.is_empty()).nth(i).and_then(|a| core::str::from_utf8(a).ok())
    }

    /// Number of command-line arguments, including the name.
    pub fn argc(&self) -> usize {
        self.strings().take_while(|s| !s.is_empty()).count()
    }

    /// The environment variables as (key, value) pairs.
    pub fn environment(&self) -> impl Iterator<Item = (&'static str, &'static str)> {
        self.strings().skip_while(|s| !s.is_empty()).skip(1).filter_map(|e| core::str::from_utf8(e).ok()).filter_map(|e| e.split_once('='))
    }

    /// The value of environment variable `key`: the strings after the empty one that ends the command line are
    /// `KEY=VALUE`.
    pub fn env(&self, key: &str) -> Option<&'static str> {
        self.strings()
            .skip_while(|s| !s.is_empty())
            .skip(1)
            .filter_map(|e| core::str::from_utf8(e).ok())
            .find_map(|e| e.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
    }
}

pub fn wait(child: u64, nohang: bool) -> i64 {
    svc(WAIT, child, nohang as u64, 0, 0, 0)[0] as i64
}

pub fn kill(child: u64) -> i64 {
    svc(KILL, child, 0, 0, 0, 0)[0] as i64
}

struct Out {
    buf: [u8; 200],
    len: usize,
}

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// The console endpoint: when the parent gave the program an endpoint in slot 7, standard output and input go through
/// it, one call at a time. WRITE: `w0` = 1 | n << 8 | first 6 bytes << 16, `w1`, `w2` = the next 16 (n <= 22); the
/// receiver replies. READ: `w0` = 2 | max << 8 (max <= 23); the reply holds `w0` = n | first 7 bytes << 8, `w1`, `w2` =
/// the next 16, n = 0 meaning end of input. Without such an endpoint (or if a call fails) output goes to the kernel's
/// console and input is empty.
pub const STDOUT_SLOT: u64 = 7;
static STDOUT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0); // 0 not tried, 1 works, 2 none

fn le(b: &[u8]) -> u64 {
    b.iter().enumerate().fold(0, |v, (i, &x)| v | (x as u64) << (8 * i))
}

fn unle(v: u64, out: &mut [u8]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = (v >> (8 * i)) as u8;
    }
}

/// Write bytes to standard output.
pub fn write_out(bytes: &[u8]) {
    console_write(1, bytes)
}

/// Write bytes to standard error (a different operation of the same console endpoint).
pub fn write_err(bytes: &[u8]) {
    console_write(3, bytes)
}

/// Is standard output an endpoint the parent gave (as opposed to the kernel console)?
pub fn console_is_endpoint() -> bool {
    STDOUT.load(core::sync::atomic::Ordering::Relaxed) != 2
}

fn console_write(op: u64, bytes: &[u8]) {
    use core::sync::atomic::Ordering::Relaxed;
    let mut rest = bytes;
    while STDOUT.load(Relaxed) != 2 && !rest.is_empty() {
        let n = rest.len().min(22);
        let c = &rest[..n];
        let w0 = op | (n as u64) << 8 | le(&c[..n.min(6)]) << 16;
        let w1 = if n > 6 { le(&c[6..n.min(14)]) } else { 0 };
        let w2 = if n > 14 { le(&c[14..n]) } else { 0 };
        let (st, _) = call(STDOUT_SLOT, [w0, w1, w2]);
        if st != 0 {
            STDOUT.store(2, Relaxed);
            break;
        }
        STDOUT.store(1, Relaxed);
        rest = &rest[n..];
    }
    if !rest.is_empty() {
        for chunk in rest.chunks(200) {
            svc(LOG, CONSOLE, chunk.as_ptr() as u64, chunk.len() as u64, 0, 0);
        }
    }
}

/// Read up to `buf.len()` bytes of standard input (blocks until some are there); 0 = end of input.
pub fn read_in(buf: &mut [u8]) -> usize {
    use core::sync::atomic::Ordering::Relaxed;
    if STDOUT.load(Relaxed) == 2 || buf.is_empty() {
        return 0;
    }
    let want = buf.len().min(23);
    let (st, r) = call(STDOUT_SLOT, [2 | (want as u64) << 8, 0, 0]);
    if st != 0 {
        STDOUT.store(2, Relaxed);
        return 0;
    }
    STDOUT.store(1, Relaxed);
    let n = ((r[0] & 0xFF) as usize).min(want);
    let mut tmp = [0u8; 23];
    unle(r[0] >> 8, &mut tmp[..7]);
    unle(r[1], &mut tmp[7..15]);
    unle(r[2], &mut tmp[15..23]);
    buf[..n].copy_from_slice(&tmp[..n]);
    n
}

/// Read a line (without its newline) into `buf`; None at the end of input with nothing read. Longer lines are cut.
pub fn read_line(buf: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    let mut any = false;
    loop {
        let mut b = [0u8; 1];
        if read_in(&mut b) == 0 {
            return if any { Some(n) } else { None };
        }
        any = true;
        if b[0] == b'\n' {
            return Some(n);
        }
        if n < buf.len() {
            buf[n] = b[0];
            n += 1;
        }
    }
}

#[doc(hidden)]
pub fn print(args: fmt::Arguments) {
    let mut o = Out { buf: [0; 200], len: 0 };
    let _ = o.write_fmt(args);
    write_out(&o.buf[..o.len]);
}

#[macro_export]
macro_rules! println {
    ($($t:tt)*) => {{ $crate::print(format_args!($($t)*)); $crate::print(format_args!("\n")) }};
}

/// Declare a program: `program!("name", |ctx| -> u64 { ... })`; the value is the exit code.
#[macro_export]
macro_rules! program {
    ($name:literal, $main:expr) => {
        #[link_section = ".programname"]
        #[used]
        static PROGRAM_NAME: [u8; 8] = $crate::name8($name);

        #[no_mangle]
        #[link_section = ".text._start"]
        pub extern "C" fn _start(_role: u64, arg: u64, parent: u64, args_ptr: u64, args_len: u64) -> ! {
            // SAFETY: the kernel starts every program with its own argument block; `_start` is only ever entered that way.
            unsafe { $crate::rt::start($main, arg, parent, args_ptr, args_len) }
        }
    };
}

pub const fn name8(s: &str) -> [u8; 8] {
    let b = s.as_bytes();
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < b.len() && i < 8 {
        out[i] = b[i];
        i += 1;
    }
    out
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    io::_eprint(format_args!("[program] panic: {info}\n"));
    exit(EXIT_FAULTED - 2)
}
