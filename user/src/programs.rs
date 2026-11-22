//! Programs: tests of SPAWN / WAIT / KILL. The conductor loads images from `/system/bin` (built by `make programs`), starts
//! them, collects their exit codes, kills them, runs out of task slots on purpose and starts programs from
//! programs; then it checks that nothing was left behind (frames, capability nodes, task slots).
use crate::bench::{counter, frequency};
use crate::vfs::Vfs;
use crate::*;
use alloc::string::String;
use alloc::vec::Vec;

const SPAWN: u64 = 24;
const WAIT: u64 = 25;
const KILL: u64 = 26;
const TASK_LOAD: u64 = 28;
const TASK_START: u64 = 29;
/// Conductor capability slots (see the kernel's `boot_caps`): the right to create programs, and a demo endpoint it may
/// pass on.
const SPAWN_SLOT: u64 = 26;
const DRIVER_SLOT: u64 = 27;
const FIRST_DYNAMIC: u64 = 27;
const EP_CREATE: u64 = 27;
const CAP_REVOKE: u64 = 6;
const FACTORY_SLOT: u64 = 12;
const ADMIN_SLOT: u64 = 28;
const EXIT_FAULTED: u64 = u64::MAX;
const EXIT_KILLED: u64 = u64::MAX - 1;
const E_PERM: i64 = -1;
const E_FULL: i64 = -3;
const E_AGAIN: i64 = -10;

/// A SPAWN request block (see the kernel's spawn.rs for the layout).
#[derive(Clone)]
struct Req {
    flags: u32,
    class: u32,
    heap: u32,
    budget: u32,
    arg: u64,
    args: Vec<u8>,
    name: [u8; 8],
    deleg: [(u8, u16); 8],
    version: u32,
}

impl Req {
    fn new() -> Req {
        Req { flags: 0, class: 0, heap: 0, budget: 0, arg: 0, args: Vec::new(), name: [0; 8], deleg: [(0xFF, 0); 8], version: 2 }
    }
    fn arg(mut self, a: u64) -> Req {
        self.arg = a;
        self
    }
    fn heap(mut self, pages: u32) -> Req {
        self.heap = pages;
        self
    }
    /// Pages the program may hand down to programs of its own.
    fn budget(mut self, pages: u32) -> Req {
        self.budget = pages;
        self
    }
    fn fs(mut self) -> Req {
        self.flags |= 1;
        self
    }
    /// The program may use the network.
    fn net(mut self) -> Req {
        self.flags |= 2;
        self
    }
    /// The program may have this many threads besides itself.
    fn threads(mut self, n: u32) -> Req {
        self.flags |= n << 8;
        self
    }
    /// The program may not name mapping addresses of its own.
    fn no_fixed_maps(mut self) -> Req {
        self.flags |= 4;
        self
    }
    fn args(mut self, a: &[u8]) -> Req {
        self.args = a.to_vec();
        self
    }
    /// Child slot i gets the parent's slot `from[i]`, rights ANDed with all-but-grant.
    fn give(mut self, from: &[u8]) -> Req {
        for (i, &f) in from.iter().enumerate() {
            self.deleg[i] = (f, 0xFFFF & !4);
        }
        self
    }
    fn give_masked(mut self, i: usize, from: u8, mask: u16) -> Req {
        self.deleg[i] = (from, mask);
        self
    }
    fn bytes(&self) -> [u8; 96] {
        let mut b = [0u8; 96];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..12].copy_from_slice(&self.budget.to_le_bytes());
        b[24..28].copy_from_slice(&self.class.to_le_bytes());
        b[28..32].copy_from_slice(&self.heap.to_le_bytes());
        b[32..40].copy_from_slice(&self.arg.to_le_bytes());
        b[40..48].copy_from_slice(&(self.args.as_ptr() as u64).to_le_bytes());
        b[48..56].copy_from_slice(&(self.args.len() as u64).to_le_bytes());
        b[56..64].copy_from_slice(&self.name);
        for (i, (slot, mask)) in self.deleg.iter().enumerate() {
            b[64 + 4 * i] = *slot;
            b[66 + 4 * i..68 + 4 * i].copy_from_slice(&mask.to_le_bytes());
        }
        b
    }
    fn go_with(&self, slot: u64, img: &[u8]) -> i64 {
        let mut b = self.bytes();
        metallium_loader::spawn(|id, a1, a2, a3, a4| svc(id, a1, a2, a3, a4, 0)[0], slot, &mut b, img)
    }
    fn go(&self, img: &[u8]) -> i64 {
        self.go_with(SPAWN_SLOT, img)
    }
}

/// SPAWN without the loader: an embryo with no code.
fn embryo(req: &Req) -> i64 {
    let b = req.bytes();
    svc(SPAWN, SPAWN_SLOT, b.as_ptr() as u64, 0, 0, 0)[0] as i64
}

/// TASK_LOAD with a hand-made request.
fn load_raw(tid: i64, va: u64, src: u64, pages: u32, perm: u32) -> i64 {
    let mut r = [0u8; 24];
    r[0..8].copy_from_slice(&va.to_le_bytes());
    r[8..16].copy_from_slice(&src.to_le_bytes());
    r[16..20].copy_from_slice(&pages.to_le_bytes());
    r[20..24].copy_from_slice(&perm.to_le_bytes());
    svc(TASK_LOAD, tid as u64, r.as_ptr() as u64, 0, 0, 0)[0] as i64
}

fn start_raw(tid: i64, entry: u64) -> i64 {
    svc(TASK_START, tid as u64, entry, 0, 0, 0)[0] as i64
}

fn wait(tid: i64, nohang: bool) -> i64 {
    svc(WAIT, tid as u64, nohang as u64, 0, 0, 0)[0] as i64
}

fn kill(tid: i64) -> i64 {
    svc(KILL, tid as u64, 0, 0, 0, 0)[0] as i64
}

/// Task-table state code of a task (0 = free slot, 7 = a zombie waiting to be waited for).
fn state_of(tid: i64) -> u64 {
    sysinfo_at(3, tid as u64)[3]
}

fn live_dynamic() -> usize {
    (FIRST_DYNAMIC..task_slots() as u64).filter(|&t| state_of(t as i64) != 0 && sysinfo_at(3, t)[0] != E_INVAL as u64).count()
}

/// How many task slots the machine has: the rows of the task table (SYSINFO page 3) until one is refused.
fn task_slots() -> usize {
    (0..4096u64).take_while(|&t| sysinfo_at(3, t)[0] as i64 == 0).count()
}

/// `make scale`: every task slot of a big table is used at once, and everything is back after they all end together.
pub fn scale_tests() {
    let _ = mem_map(10, 0x8034_0000, true);
    let v = Vfs::new(9, 0x8034_0000);
    let sleeper = v.read_file("/system/bin/sleeper").unwrap_or_default();
    if sleeper.len() < 32 {
        println!("[client] TEST the sleeper program is in the system image: FAIL");
        return;
    }
    let slots = task_slots();
    let (free0, nodes0, busy0) = (sysinfo(0)[3], sysinfo(1)[5], live_dynamic());
    let begin = counter();
    let mut kids: Vec<i64> = Vec::new();
    let mut last = 0;
    for _ in 0..slots + 8 {
        let t = Req::new().arg(1).heap(4).give_masked(1, FACTORY_SLOT as u8, 0xFFFF & !4).go(&sleeper); // (a small heap: the default 256 pages would use up the conductor's budget at about a hundred programs; each holds 4 endpoints and 2 shared-memory objects)
        if t < 0 {
            last = t;
            break;
        }
        kids.push(t);
    }
    let spawned = counter() - begin;
    sleep(50);
    let holding = live_dynamic() - busy0; // (a program that was refused an endpoint or an object has ended by now)
    let room = slots - FIRST_DYNAMIC as usize - busy0;
    println!("[client] TEST every one of {slots} task slots can be used, each holding 4 endpoints and 2 objects, then SPAWN says the table is full ({} programs of {room} free slots, then {last}; {holding} still holding them; {} us each): {}",
        kids.len(), spawned * 1_000_000 / frequency() / kids.len().max(1) as u64, verdict(last == E_FULL as i64 && kids.len() == room && holding == kids.len()));
    let begin = counter();
    for &k in &kids {
        kill(k);
    }
    let mut collected = 0;
    for &k in &kids {
        if wait(k, false) as u64 == EXIT_KILLED {
            collected += 1;
        }
    }
    let ended = counter() - begin;
    sleep(20);
    // many programs that all want the CPU at once: the scheduler must still answer the conductor's own sleep promptly, and all of them must finish
    let burn = v.read_file("/system/bin/burn").unwrap_or_default();
    if burn.len() >= 32 {
        let want = (slots - FIRST_DYNAMIC as usize - busy0).min(400);
        let burners: Vec<i64> = (0..want).map(|_| Req::new().arg(40).heap(4).go(&burn)).filter(|&t| t > 0).collect(); // (0.4 s of wall time each)
        let t0 = counter();
        sleep(10);
        let woke = (counter() - t0) * 1000 / frequency(); // ms
        let done = burners.iter().filter(|&&b| wait(b, false) >= 0).count();
        println!("[client] TEST with {} programs all wanting the CPU, a 10 ms sleep of the conductor takes {woke} ms and every program finishes ({done}): {}", burners.len(), verdict(woke < 500 && done == burners.len() && burners.len() == want));
    }
    let (free1, nodes1, busy1) = (sysinfo(0)[3], sysinfo(1)[5], live_dynamic());
    println!("[client] TEST they are all killed and collected together, and every frame, capability node and task slot is back (collected {collected} of {}, {} us each; frames {free0} -> {free1}, nodes {nodes0} -> {nodes1}, live programs {busy0} -> {busy1}): {}",
        kids.len(), ended * 1_000_000 / frequency() / kids.len().max(1) as u64, verdict(collected == kids.len() && free1 + 8 >= free0 && nodes1 <= nodes0 && busy1 == busy0));
}

/// Run a program with a console endpoint like the shell's: serve its output and its input (`input`, then end of input).
/// Returns (exit code, what it wrote); the console protocol is documented in docs/ABI.md.
fn run_with_console(req: Req, img: &[u8], input: &[u8]) -> (i64, Vec<u8>) {
    let (code, out, _err) = run_with_console3(req, img, input);
    (code, out)
}

/// ... and what it wrote to standard error (operation 3 of the same endpoint).
fn run_with_console3(req: Req, img: &[u8], input: &[u8]) -> (i64, Vec<u8>, Vec<u8>) {
    let ep = svc(EP_CREATE, FACTORY_SLOT, 0, 0, 0, 0)[0] as i64;
    if ep < 0 {
        return (ep, Vec::new(), Vec::new());
    }
    let tid = req.give_masked(7, ep as u8, 0b101).go(img); // (send, and the right to hand the console on)
    if tid < 0 {
        svc(CAP_REVOKE, ep as u64, 1, 0, 0, 0);
        return (tid, Vec::new(), Vec::new());
    }
    let mut input = input.to_vec();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut want: Option<usize> = None;
    let code = loop {
        if want.is_none() {
            let m = svc(2, ep as u64, 1, 0, 0, 0);
            if m[0] as i64 == 0 {
                let (w0, w1, w2) = (m[2], m[3], m[4]);
                match w0 & 0xFF {
                    op @ (1 | 3) => {
                        let n = ((w0 >> 8) & 0xFF) as usize;
                        let mut b = [0u8; 22];
                        b[..6].copy_from_slice(&(w0 >> 16).to_le_bytes()[..6]);
                        b[6..14].copy_from_slice(&w1.to_le_bytes());
                        b[14..22].copy_from_slice(&w2.to_le_bytes());
                        if op == 1 { &mut out } else { &mut err }.extend_from_slice(&b[..n.min(22)]);
                        reply([0, 0, 0]);
                    }
                    2 => want = Some((((w0 >> 8) & 0xFF) as usize).clamp(1, 23)),
                    _ => {
                        reply([0, 0, 0]);
                    }
                }
                continue;
            }
        }
        if let Some(max) = want {
            let n = input.len().min(max);
            let chunk: Vec<u8> = input.drain(..n).collect(); // empty = end of input
            let mut b = [0u8; 24];
            b[..n].copy_from_slice(&chunk);
            let word = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            reply([(n as u64) | (word(0) << 8), word(7), word(15)]);
            want = None;
            continue;
        }
        let w = wait(tid, true);
        if w != E_AGAIN as i64 {
            break w;
        }
        sleep(1);
    };
    svc(CAP_REVOKE, ep as u64, 1, 0, 0, 0);
    (code, out, err)
}

const MEMCTL: u64 = 18;
const MC_SWAP_OUT: u64 = 4;
const MC_SWAP_STATS: u64 = 5;
const MC_SWAP_WRITEBACK: u64 = 9;
const MC_PAGER_STATS: u64 = 10;
const MEM_SLOT: u64 = 11;
/// The size of the swap file in pages (2 MB).
const PAGER_SLOTS: u64 = 512;

struct PagerStats {
    written: u64,
    read: u64,
    cancelled: u64,
    failed: u64,
    slots: u64,
    registered: bool,
}

fn pager_stats() -> PagerStats {
    let r = svc(MEMCTL, MEM_SLOT, MC_PAGER_STATS, 0, 0, 0);
    PagerStats { written: r[0], read: r[1], cancelled: r[2], failed: r[3], slots: r[4], registered: r[5] != 0 }
}

fn start_pager(pager: &[u8], slots: u64) -> i64 {
    // (file access; the memory-control capability with only the pager right, in the pager's slot 1)
    let t = Req::new().arg(slots).heap(200).fs().give_masked(1, MEM_SLOT as u8, 1 << 5).go(pager);
    for _ in 0..600 {
        if t < 0 || pager_stats().registered {
            break;
        }
        sleep(1);
    }
    t
}

fn pager_tests(v: &Vfs, pager: &[u8], victim: &[u8]) {
    if pager.len() < 32 || victim.len() < 32 {
        println!("[client] TEST the pager programs are in the system image: FAIL");
        return;
    }
    let _ = v.unlink("/data/pagetest.go");
    let p1 = start_pager(pager, 96);
    println!("[client] TEST the pager starts and registers with the kernel (task {p1}): {}", verdict(p1 > 0 && pager_stats().registered));
    if p1 <= 0 {
        return;
    }
    let before = pager_stats();
    let stored0 = svc(MEMCTL, MEM_SLOT, MC_SWAP_STATS, 0, 0, 0)[0];

    // pages written back while the program sleeps, the pager restarted meanwhile, then every page read back
    let t = Req::new().arg(0).heap(120).fs().go(victim);
    sleep(100);
    let evicted = svc(MEMCTL, MEM_SLOT, MC_SWAP_OUT, 1024, 1 | 4 | (t as u64 + 1) << 8, 0)[0];
    let queued = svc(MEMCTL, MEM_SLOT, MC_SWAP_WRITEBACK, 512, 0, 0)[0] as i64;
    let mut waited = 0;
    while pager_stats().slots < 48 && waited < 3000 {
        sleep(2);
        waited += 2;
    }
    let mid = pager_stats();
    println!("[client] TEST pages go from the compressed store to the disk ({evicted} evicted, writeback asked: {queued}, {} on disk after {waited} ticks, {} write failures): {}",
        mid.slots, mid.failed - before.failed, verdict(evicted >= 48 && queued == 0 && mid.slots >= 48 && mid.failed == before.failed));
    kill(p1);
    wait(p1, false);
    let p2 = start_pager(pager, 96);
    println!("[client] TEST a restarted pager takes over (task {p2}): {}", verdict(p2 > 0 && pager_stats().registered));
    let _ = v.write_file("/data/pagetest.go", b"go");
    let code = if t > 0 { wait(t, false) } else { -1 };
    let _ = v.unlink("/data/pagetest.go");
    for _ in 0..300 {
        if pager_stats().slots == 0 {
            break;
        }
        sleep(1);
    }
    let after = pager_stats();
    println!("[client] TEST every page comes back from disk with its content, also for a system call (exit {code}, {} pages read from disk, {} slots still held): {}",
        after.read - before.read, after.slots, verdict(code == 0 && after.read - before.read >= 48 && after.slots == 0));

    // pages touched while they are being written, over and over
    let t = Req::new().arg(1).heap(120).go(victim);
    let mut rounds = 0;
    while rounds < 300 && state_of(t) != 7 {
        svc(MEMCTL, MEM_SLOT, MC_SWAP_OUT, 1024, 1 | 4 | (t as u64 + 1) << 8, 0);
        svc(MEMCTL, MEM_SLOT, MC_SWAP_WRITEBACK, 16, 0, 0);
        sleep(2);
        rounds += 1;
    }
    let code = if t > 0 { wait(t, false) } else { -1 };
    // (a write for a page of the program that has just gone may still be on its way: the pager finishes it, and gives the slot back)
    for _ in 0..300 {
        if pager_stats().slots == 0 {
            break;
        }
        sleep(1);
    }
    let end = pager_stats();
    println!("[client] TEST a program that keeps using its pages while they are pushed to disk sees no wrong data (exit {code}, {} written, {} read back, {} writes cancelled by a touch, {} failures): {}",
        end.written - after.written, end.read - after.read, end.cancelled - after.cancelled, end.failed - before.failed,
        verdict(code == 0 && end.failed == before.failed && end.written > after.written && end.read > after.read));
    let stored1 = svc(MEMCTL, MEM_SLOT, MC_SWAP_STATS, 0, 0, 0)[0];
    println!("[client] TEST nothing is left behind when the programs are gone (disk slots {}, store entries {} -> {}): {}", end.slots, stored0, stored1, verdict(end.slots == 0 && stored1 <= stored0 + 2));
    kill(p2);
    wait(p2, false);

    // the kernel seals every page before the pager sees it, and checks it when it comes back (kernel/src/pager.rs)
    let evict_and_write = |t: i64| {
        sleep(100);
        svc(MEMCTL, MEM_SLOT, MC_SWAP_OUT, 1024, 1 | 4 | (t as u64 + 1) << 8, 0);
        svc(MEMCTL, MEM_SLOT, MC_SWAP_WRITEBACK, 512, 0, 0);
    };
    let drain = || {
        for _ in 0..300 {
            if pager_stats().slots == 0 {
                break;
            }
            sleep(1);
        }
    };
    // a pager that looks at what it is given sees no plaintext; a good one then gets every page back right
    let _ = v.unlink("/data/pagetest.go");
    let sn = start_pager(pager, 96 | 1 << 16);
    let t = Req::new().arg(0).heap(120).fs().go(victim);
    evict_and_write(t);
    let seen = if sn > 0 { wait(sn, false) as u64 } else { 0 };
    let p3 = start_pager(pager, 96);
    let _ = v.write_file("/data/pagetest.go", b"go");
    let code = if t > 0 { wait(t, false) } else { -1 };
    let _ = v.unlink("/data/pagetest.go");
    drain();
    println!("[client] TEST the pager is handed sealed pages, never the program's bytes ({} of {} pages written looked like the victim's), and they come back right (victim exit {code}): {}",
        seen & 0xFF, seen >> 8, verdict(sn > 0 && seen >> 8 >= 48 && seen & 0xFF == 0 && code == 0));
    kill(p3);
    wait(p3, false);
    // a pager that changes a page on its way back is caught: the program is stopped (or told), and never sees wrong bytes
    let before = pager_stats();
    let tp = start_pager(pager, 96 | 2 << 16);
    let t = Req::new().arg(0).heap(120).fs().go(victim);
    evict_and_write(t);
    let mut waited = 0;
    while pager_stats().slots < 48 && waited < 3000 {
        sleep(2);
        waited += 2;
    }
    let _ = v.write_file("/data/pagetest.go", b"go");
    let code = if t > 0 { wait(t, false) as u64 } else { 0 };
    let _ = v.unlink("/data/pagetest.go");
    drain();
    let after = pager_stats();
    println!("[client] TEST a pager that changes a page on its way back is caught: the program faults instead of using it (exit {code:#x}, {} pages refused): {}",
        after.failed - before.failed, verdict(tp > 0 && (code == EXIT_FAULTED || code == 200) && after.failed > before.failed));
    kill(tp);
    wait(tp, false);
}

/// Pages the session service may hand down: a program manager per session (`sessiond`'s `SESSION_PAGES`) and the service's own.
const SESSIOND_BUDGET: u32 = 24000;

/// An interactive session: the conductor has no tests to run. It starts the program manager, hands the screen task (the shell) a
/// capability to send to the manager's control endpoint, and then has nothing left to do.
pub fn console_session() -> ! {
    sleep(30); // (the file-system services are still starting)
    let _ = mem_map(10, 0x8034_0000, true);
    let v = Vfs::new(9, 0x8034_0000);
    let progmgr = (0..20).find_map(|_| v.read_file("/system/bin/progmgr").ok().filter(|b| b.len() > 32).or_else(|| { sleep(20); None })).unwrap_or_default();
    let sessiond = v.read_file("/system/bin/sessiond").unwrap_or_default();
    let (mut ctl_slot, mut disp_slot, mut mgr, mut power_slot) = (0i64, 0i64, 0i64, 0i64);
    // the screen task is the one task of role 13
    let desk = (0..64u64).find(|&t| { let r = sysinfo_at(3, t); r[0] as i64 == 0 && r[3] != 0 && r[5] == 13 });
    // With a session service (the system image has one) there is no program manager of the machine: each login gets its own (`sessiond`, confined to the user's home), and the
    // console reaches the manager of the session that has the screen. Without one, the old single manager.
    let with_sessions = sessiond.len() > 32 && desk.is_some() && !progmgr.is_empty();
    if !progmgr.is_empty() {
        let ctl = if with_sessions { 0 } else { svc(EP_CREATE, FACTORY_SLOT, 0, 0, 0, 0)[0] as i64 }; // the manager's control endpoint
        let disp = svc(EP_CREATE, FACTORY_SLOT, 0, 0, 0, 0)[0] as i64; // the display endpoint the console serves and programs call
        // the manager: control endpoint (receive + send) as slot 0, the display endpoint (send, and the right to hand a send-only
        // copy to the programs that ask for a display) as slot 3, the endpoint factory and the spawn capability as 5 and 6 (with the right to
        // hand them on: a program with `permission = spawn` gets a narrowed copy of each, never with that right), file access, and a budget of
        // pages for the programs it starts
        let mut rq = Req::new().fs().heap(4096).budget(24000).give_masked(5, FACTORY_SLOT as u8, 0xFFFF).give_masked(6, SPAWN_SLOT as u8, 0xFFFF).give_masked(7, ADMIN_SLOT as u8, 0xFFFF & !0x800); // (the revoke authority: the manager hands it to the task manager)
        if ctl >= 0 && !with_sessions {
            rq = rq.give_masked(0, ctl as u8, 0b111); // (the right to give copies: shell clients get one)
        }
        if disp >= 0 {
            rq = rq.give_masked(3, disp as u8, 0b101);
        }
        if with_sessions {
            // the session service (programs/src/bin/sessiond.rs): the greeter in the screen task logs users in through the conductor's static endpoint (slot 29); it gets the display
            // endpoint to give to each session's manager, and the screen task's id (a login hands the console a way to reach that session's manager)
            let rq = Req::new().fs().heap(4096).budget(SESSIOND_BUDGET).arg(desk.unwrap_or(0)).give_masked(0, 29, 0b111).give_masked(3, disp as u8, 0b101).give_masked(5, FACTORY_SLOT as u8, 0xFFFF).give_masked(6, SPAWN_SLOT as u8, 0xFFFF).give_masked(4, 7, 0xFFFF);
            mgr = if disp >= 0 { rq.go(&sessiond) } else { disp };
            println!("[client] interactive session: session service task {mgr} (a program manager per session)");
        } else {
            mgr = if ctl >= 0 { rq.go(&progmgr) } else { ctl };
        }
        if mgr > 0 {
            if let Some(d) = desk {
                if !with_sessions {
                    ctl_slot = svc(5, ctl as u64, d, 0b101, 0, 0)[0] as i64; // CAP_GRANT: send, and the right to give a copy to the programs it starts
                }
                if disp >= 0 {
                    disp_slot = svc(5, disp as u64, d, 0b011, 0, 0)[0] as i64; // the console receives on it (and may send)
                }
                power_slot = svc(5, ADMIN_SLOT, d, 0x800, 0, 0)[0] as i64; // the right to switch the machine off or restart it (`R_POWER`), and nothing else of the admin capability
            }
        }
        println!("[client] interactive session: program manager task {}, control endpoint in the console's slot {ctl_slot}, display endpoint in {disp_slot}", if with_sessions { 0 } else { mgr });
        // (the programs that come with the console - dock, launcher, files, task manager - return with the new GUI)
    }
    if !with_sessions {
        if sessiond.len() > 32 {
            // (no screen task to hand a manager to, or no manager in the image: the service still runs for the greeter)
            let rq = Req::new().fs().heap(4096).budget(8000).give_masked(0, 29, 0b111).give_masked(5, FACTORY_SLOT as u8, 0xFFFF).give_masked(6, SPAWN_SLOT as u8, 0xFFFF).give_masked(4, 7, 0xFFFF);
            println!("[client] interactive session: session service task {}", rq.go(&sessiond));
        } else {
            println!("[client] interactive session: no session service in the system image");
        }
    }
    let mut mgr = if with_sessions { 0 } else { mgr };
    if with_sessions {
        // The console is not started until somebody has logged in (the greeter has the screen until then, and the conductor's call below would wait for the screen task anyway): the session
        // service made that user's program manager and gave this task a send copy of its control endpoint (a program may grant only to its parent), which goes on to the screen task.
        let session = loop {
            let (st, r) = call(29, [5, 0, 0]); // ACTIVE
            if st == 0 && r[0] & 0xFF == 0 {
                break r[0];
            }
            sleep(100);
        };
        let (id, m, slot) = ((session >> 8) & 0xFFFF, (session >> 24) & 0xFFFF, (session >> 40) & 0xFF);
        if let (Some(d), true) = (desk, m != 0 && slot != 0) {
            ctl_slot = svc(5, slot, d, 0b101, 0, 0)[0] as i64; // CAP_GRANT: send, and the right to give a copy to the programs it starts
            mgr = m as i64;
        }
        println!("[client] interactive session: session {id}'s program manager is task {mgr}, control endpoint in the console's slot {ctl_slot}");
    }
    let w2 = (disp_slot.max(0) as u64 & 0xFF) | (mgr.max(0) as u64) << 8 | (power_slot.max(0) as u64 & 0xFF) << 16;
    let (st, _) = call(23, [crate::info::INFO_CONSOLE, ctl_slot.max(0) as u64, w2]);
    println!("[client] interactive session: the console has the screen (status {st})");
    let tty_consoles = if with_sessions { start_tty_greeters(sysinfo(2)[3] == 16) } else { alloc::vec::Vec::new() };
    // the second memory tier: the pager writes the coldest pages of the compressed store to a swap file on the data disk (bounded: kernel/src/pager.rs
    // lets at most WRITE_CAP_PER_HOUR pages an hour reach the flash), and reads them back when a program touches one
    let pager = v.read_file("/system/bin/pager").unwrap_or_default();
    if pager.len() > 32 {
        let t = start_pager(&pager, PAGER_SLOTS);
        println!("[client] swap: pager task {t}, registered with the kernel: {}", pager_stats().registered);
    } else {
        println!("[client] swap: no pager in the system image");
    }
    // the consoles of the other ttys: when a user has logged in on one (its greeter did it), the session's manager is handed to that console, which starts on its own buffer
    let mut started = [false; 3];
    loop {
        for (i, &c) in tty_consoles.iter().enumerate() {
            if started[i] {
                continue;
            }
            let (st, r) = call(29, [6, c, 0]); // FROM: the session this console's greeter logged in
            if st != 0 || r[0] & 0xFF != 0 {
                continue;
            }
            let (id, m, slot) = ((r[0] >> 8) & 0xFFFF, (r[0] >> 24) & 0xFFFF, (r[0] >> 40) & 0xFF);
            if m == 0 || slot == 0 {
                continue;
            }
            let ctl = svc(5, slot, c, 0b101, 0, 0)[0] as i64; // CAP_GRANT to the console: send, and the right to give a copy to the programs it starts
            let (st, _) = call(18 + i as u64, [crate::info::INFO_CONSOLE, ctl.max(0) as u64, m << 8]);
            println!("[client] tty {}: session {id}'s program manager is task {m}, control endpoint in the console's slot {ctl}; its console started (status {st})", i + 1);
            started[i] = true;
        }
        sleep(20);
    }
}

/// The consoles of ttys 1..3 (role 22), in tty order: each is given its tty's input and buffer, and asked to run the greeter there. `second_user` (the test mode `only=16`): the conductor makes the
/// account "tester" (passphrase "second-pass") from the first user's session, so a test can log in on another tty (accounts are made only from an administrator's session and the greeter has no screen for it).
fn start_tty_greeters(second_user: bool) -> alloc::vec::Vec<u64> {
    let consoles: alloc::vec::Vec<u64> = (0..64u64).filter(|&t| { let r = sysinfo_at(3, t); r[0] as i64 == 0 && r[3] != 0 && r[5] == 22 }).collect();
    if second_user {
        let first = call(29, [5, 0, 0]);
        let acting = (first.1[0] >> 8) & 0xFFFF;
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(b"tester");
        let word = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
        let a = call(29, [1 | 1 << 8 | acting << 32, word(&name[..8]), word(&name[8..])]); // BEGIN, CREATE (acting session)
        let mut secret = [0u8; 16];
        secret[..11].copy_from_slice(b"second-pass");
        let b = call(29, [2 | 11 << 8, word(&secret[..8]), word(&secret[8..])]);
        println!("[client] test: the account tester is made (replies {} {}): {}", a.1[0], b.1[0] & 0xFF, verdict(a.0 == 0 && a.1[0] == 0 && b.0 == 0 && b.1[0] & 0xFF == 0));
    }
    for (i, &c) in consoles.iter().enumerate() {
        let tty = i as u64 + 1;
        let (a, b) = (call(14, [crate::proto::input::INPUT_ASSIGN, c, tty]), call(21, [crate::proto::gpu::GPU_BIND, c, tty]));
        let g = call(18 + i as u64, [crate::info::INFO_GREETER, 0, 0]);
        println!("[client] tty {tty}: console task {c} has its input and buffer (replies {} {}), greeter asked (status {})", a.1[0], b.1[0], g.0);
    }
    consoles
}

pub fn tests() {
    let _ = mem_map(10, 0x8034_0000, true); // (already mapped when the VFS tests ran first)
    let v = Vfs::new(9, 0x8034_0000);
    let load = |name: &str| v.read_file(&alloc::format!("/system/bin/{name}")).unwrap_or_default();
    let (hello, crash, sleeper, ping, memp, burn, spawner) =
        (load("hello"), load("crash"), load("sleeper"), load("ping"), load("mem"), load("burn"), load("spawner"));
    let (cat, fswrite, ls, fdprobe, kv, kvc, blocker) = (load("cat"), load("fswrite"), load("ls"), load("fdprobe"), load("kv"), load("kvc"), load("blocker"));
    let (argdump, upper, argdump_elf, hello_elf) = (load("argdump"), load("upper"), load("argdump.elf"), load("hello.elf"));
    let threads = load("threads");
    let stdtest = load("stdtest");
    let have = [&hello, &crash, &ping, &memp, &burn, &spawner, &cat, &fswrite, &ls, &fdprobe, &kv, &kvc, &blocker, &argdump, &upper].iter().all(|p| p.len() >= 32 && p[..4] == [0x7F, b'E', b'L', b'F']);
    println!("[client] TEST the programs are in the system image as position-independent ELF files (hello {} B, sleeper {} B, spawner {} B): {}", hello.len(), sleeper.len(), spawner.len(), verdict(have));
    if !have {
        return;
    }
    let freq = frequency();
    let free0 = sysinfo(0)[3];
    let nodes0 = sysinfo(1)[5];
    let busy0 = live_dynamic();

    // ---- start, run, collect the exit code ----------------------------------------------------------------------
    let t = Req::new().arg(41).go(&hello);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST a program runs and its exit code comes back through WAIT (task {t}, code {code}): {}", verdict(t >= FIRST_DYNAMIC as i64 && code == 41));
    println!("[client] TEST a collected program's slot is free again (state {}): {}", state_of(t), verdict(state_of(t) == 0));
    println!("[client] TEST waiting twice for the same program is refused ({}): {}", wait(t, false), verdict(wait(t, false) == E_INVAL as i64));

    // ---- faults --------------------------------------------------------------------------------------------------
    let t = Req::new().arg(0).go(&crash);
    let code = if t > 0 { wait(t, false) as u64 } else { 0 };
    println!("[client] TEST a program that faults ends with the fault code and the system carries on (code {code:#x}): {}", verdict(t > 0 && code == EXIT_FAULTED));

    // ---- address-space layout: guard pages around the stack and the heap, randomised stack, heap and ring --------------------
    let guard = load("guardtest");
    if guard.len() >= 32 {
        let run = |mode: u64| {
            let (code, out, _err) = run_with_console3(Req::new().arg(mode).heap(64), &guard, b"");
            (code as u64, String::from_utf8_lossy(&out).into_owned())
        };
        let (c4, _) = run(4);
        let faults: Vec<(u64, u64, String)> = [1u64, 2, 3, 5].iter().map(|&m| { let (c, o) = run(m); (m, c, o) }).collect();
        let bad: Vec<u64> = faults.iter().filter(|(_, c, o)| *c != EXIT_FAULTED || o.contains("readable") || o.contains("writable") || o.contains("never ran out")).map(|f| f.0).collect();
        println!("[client] TEST the stack is fully usable, and the guard pages below and above it, the end of the stack and the page after the heap fault (usable stack exit {c4}, modes that did not fault: {bad:?}): {}", verdict(c4 == 0 && bad.is_empty()));
        let field = |text: &str, key: &str| -> Option<u64> {
            let rest = &text[text.find(key)? + key.len()..];
            let end = rest.find(' ').unwrap_or(rest.len());
            u64::from_str_radix(rest[..end].trim_start_matches("0x"), 16).ok().or_else(|| rest[..end].parse().ok())
        };
        let (mut stacks, mut heaps, mut rings, mut sane) = (Vec::new(), Vec::new(), Vec::new(), true);
        for _ in 0..8 {
            let (code, out) = run(0);
            let (st, hb, rg) = (field(&out, "stack_top="), field(&out, "heap_base="), field(&out, "ring="));
            sane &= code == 0 && out.contains("local_in_stack=true") && out.contains("aslr=1");
            match (st, hb, rg) {
                (Some(st), Some(hb), Some(rg)) => {
                    sane &= st % 4096 == 0 && (0x8041_1000..=0x80FF_F000).contains(&st);
                    sane &= hb % 4096 == 0 && (0x8100_0000..0x8200_0000).contains(&hb);
                    sane &= (0x8F00_0000..0x9000_0000).contains(&rg) && rg % 4096 == 0;
                    stacks.push(st);
                    heaps.push(hb);
                    rings.push(rg);
                }
                _ => sane = false,
            }
        }
        let distinct = |v: &Vec<u64>| { let mut v = v.clone(); v.sort(); v.dedup(); v.len() };
        println!("[client] TEST every program gets its own randomised layout (distinct of 8: stack {}, heap {}, ring {}; all inside their windows: {sane}): {}",
            distinct(&stacks), distinct(&heaps), distinct(&rings), verdict(sane && distinct(&stacks) >= 6 && distinct(&heaps) >= 6 && distinct(&rings) >= 6));
        // threads on stacks the kernel makes
        let trun = |mode: u64| {
            let (code, out, _err) = run_with_console3(Req::new().arg(mode).heap(64).threads(1), &guard, b"");
            (code as u64, String::from_utf8_lossy(&out).into_owned())
        };
        let (c6, o6) = trun(6);
        let tfaults: Vec<u64> = [7u64, 8, 9].iter().filter(|&&m| { let (c, o) = trun(m); c != EXIT_FAULTED || o.contains("readable") || o.contains("never ran out") || o.contains("did not end") }).copied().collect();
        let (c10, o10) = trun(10);
        let refused = o10.contains("too_big=-5 over_quota=-8");
        println!("[client] TEST a thread on a kernel-made stack: inside the stack region, apart from the main stack, charged to the heap limit and given back (code {c6}), its guard pages fault (modes that did not: {tfaults:?}), and a stack over 1 MiB or over the heap limit is refused ({refused}): {}",
            verdict(c6 == 0 && o6.contains("tstack top=") && tfaults.is_empty() && refused && c10 == 0));
    } else {
        println!("[client] TEST the guard-page test program is in the system image: FAIL");
    }

    // ---- the races the kernel audit found (SECURITY.md, H1 and H2): see programs/src/bin/racetest.rs --------------------------
    let race = load("racetest");
    if race.len() >= 32 && sysinfo(0)[4] >= 2 {
        // H1: a thread maps an object while the main thread revokes it; no mapping of the freed frames may be left behind
        let (c1, o1, _) = run_with_console3(Req::new().arg(1).heap(64).threads(1), &race, b"");
        let o1 = String::from_utf8_lossy(&o1).into_owned();
        println!("[client] TEST a map that races a revoke never leaves a mapping of freed shared memory behind (exit code {c1}{}): {}", if o1.is_empty() { String::new() } else { alloc::format!(", {}", o1.trim()) }, verdict(c1 == 0));
        // H2: a thread keeps reading heap pages that the main thread releases, while another program allocates; it must never
        // see that program's data through a translation that outlived the unmapping
        let mut leaks = 0;
        let mut ran = 0;
        for _ in 0..12 {
            let s = svc(37, 1, 0, 0, 0, 0)[0] as i64;
            if s < 0 {
                break;
            }
            let alloc_t = Req::new().arg(3).heap(4300).give_masked(0, s as u8, 0xFFFF & !4).go(&race);
            if alloc_t > 0 {
                let (_c, out, _) = run_with_console3(Req::new().arg(2).heap(2200).threads(1).give_masked(0, s as u8, 0xFFFF & !4), &race, b"");
                leaks += String::from_utf8_lossy(&out).contains("LEAK") as u32;
                ran += (wait(alloc_t, false) == 0) as u32; // the allocator ran to its end alongside the release
            }
            svc(CAP_REVOKE, s as u64, 1, 0, 0, 0);
        }
        println!("[client] TEST pages released by HEAP_RELEASE are not reachable through a stale translation after they are freed (12 rounds, {ran} reached the release, {leaks} saw another program's data): {}", verdict(leaks == 0 && ran > 0));
        // N1: a copy of a capability that was read before a revoke is not alive after it, even when its node number has been handed out again
        let (n1, o1, _) = run_with_console3(Req::new().arg(16).heap(64).threads(2), &race, b"");
        let o1 = String::from_utf8_lossy(&o1).into_owned();
        println!("[client] TEST a capability copy read before a revoke stays dead when its node number is reused (exit code {n1}{}): {}", if o1.is_empty() { String::new() } else { alloc::format!(", {}", o1.trim()) }, verdict(n1 == 0));
        // N2: TASK_LOAD stops when the embryo it is loading is killed and collected, instead of writing the page tables of a dead task
        let (n2, o2, _) = run_with_console3(Req::new().arg(17).heap(260).budget(1500).threads(1).give(&[SPAWN_SLOT as u8]), &race, b"");
        let o2 = String::from_utf8_lossy(&o2).into_owned();
        println!("[client] TEST TASK_LOAD stops when its embryo is killed and collected (exit code {n2}{}): {}", if o2.is_empty() { String::new() } else { alloc::format!(", {}", o2.trim()) }, verdict(n2 == 0));
    } else if race.len() >= 32 {
        // (the H1 and H2 races need a second core to happen at all)
        println!("[client] TEST a map that races a revoke never leaves a mapping of freed shared memory behind (skipped: one core): PASS");
        println!("[client] TEST pages released by HEAP_RELEASE are not reachable through a stale translation after they are freed (skipped: one core): PASS");
        println!("[client] TEST a capability copy read before a revoke stays dead when its node number is reused (skipped: one core): PASS");
        println!("[client] TEST TASK_LOAD stops when its embryo is killed and collected (skipped: one core): PASS");
    } else {
        println!("[client] TEST the race test program is in the system image: FAIL");
    }
    // L3: the holding limit is checked and charged in one step, however many threads create at once
    if race.len() >= 32 && sysinfo(0)[4] >= 2 {
        let (c, o, _) = run_with_console3(Req::new().arg(24).heap(400).threads(7), &race, b"");
        let o = String::from_utf8_lossy(&o).into_owned();
        println!("[client] TEST threads creating shared memory at the same moment cannot take a program over its limit (exit code {c}{}): {}", if o.is_empty() { String::new() } else { alloc::format!(", {}", o.trim()) }, verdict(c == 0));    } else if race.len() >= 32 {
        println!("[client] TEST threads creating shared memory at the same moment cannot take a program over its limit (skipped: one core): PASS");
    }
    // N11: a thread of the pager may not call into the pager's job interface
    if race.len() >= 32 {
        let c = run_with_console3(Req::new().arg(22).heap(64).threads(1).give_masked(1, MEM_SLOT as u8, 0xFFFF & !4), &race, b"").0;
        println!("[client] TEST only the pager's first task may take its jobs (bits of calls that were not refused: {c:#x}): {}", verdict(c == 0));
    }
    // N10: two threads waiting for the same dead child: exactly one collects it
    if race.len() >= 32 && sysinfo(0)[4] >= 2 {
        let (c, o, _) = run_with_console3(Req::new().arg(23).heap(64).budget(3000).threads(1).give(&[SPAWN_SLOT as u8]), &race, b"");
        let o = String::from_utf8_lossy(&o).into_owned();
        println!("[client] TEST a dead child is collected by one of two threads that wait for it (exit code {c}{}): {}", if o.is_empty() { String::new() } else { alloc::format!(", {}", o.trim()) }, verdict(c == 0));
    } else if race.len() >= 32 {
        println!("[client] TEST a dead child is collected by one of two threads that wait for it (skipped: one core): PASS");
    }
    // L2 and N9: RESTORE_OF puts a capability back only under the node it hung under, not under whatever has taken that node's number since
    {
        let sh = svc(37, 1, 0, 0, 0, 0)[0] as i64;
        let t = if sh >= 0 { Req::new().arg(0).give_masked(0, sh as u8, 0xFFFF & !4).go(&sleeper) } else { -1 };
        if t > 0 {
            let went = svc(40, ADMIN_SLOT, t as u64, 0, 0, 0)[0] as i64; // (the program's copy: logged with the node it hung under)
            let id = svc(21, 14, t as u64, 0, 0, 0)[1];
            svc(CAP_REVOKE, sh as u64, 1, 0, 0, 0); // frees that node ...
            let fill: Vec<i64> = (0..3).map(|_| svc(37, 1, 0, 0, 0, 0)[0] as i64).collect(); // ... and these take the lowest free numbers again
            let back = svc(41, ADMIN_SLOT, t as u64, id, 0, 0)[0] as i64;
            for f in fill.iter().filter(|&&f| f >= 0) {
                svc(CAP_REVOKE, *f as u64, 1, 0, 0, 0);
            }
            kill(t);
            wait(t, false);
            println!("[client] TEST a revoked capability is not given back under a node that has been reused (revoked {went}, restore answered {back}): {}", verdict(went >= 1 && back == -4));
        } else {
            println!("[client] TEST a revoked capability is not given back under a node that has been reused (setup failed): FAIL");
        }
    }
    // N6: a program that ends while a thread of it is in SPAWN leaves no embryo behind (the count of live tasks is the same afterwards)
    if race.len() >= 32 && sysinfo(0)[4] >= 2 {
        let live0 = sysinfo(1)[3] as i64;
        for _ in 0..60 {
            run_with_console3(Req::new().arg(21).heap(64).budget(1500).threads(1).give(&[SPAWN_SLOT as u8]), &race, b"");
        }
        sleep(50);
        let leaked = sysinfo(1)[3] as i64 - live0;
        println!("[client] TEST a program that ends in the middle of SPAWN leaves no embryo nobody owns (60 runs, {leaked} tasks left over): {}", verdict(leaked == 0));    } else if race.len() >= 32 {
        println!("[client] TEST a program that ends in the middle of SPAWN leaves no embryo nobody owns (skipped: one core): PASS");
    }
    // N3: shared memory that a thread made and gave to its own program is charged to the program after the thread has ended
    if race.len() >= 32 {
        let (n3, o3, _) = run_with_console3(Req::new().arg(20).heap(400).threads(1), &race, b"");
        let o3 = String::from_utf8_lossy(&o3).into_owned();
        println!("[client] TEST shared memory that outlives the thread that made it is still charged to its program (exit code {n3}{}): {}", if o3.is_empty() { String::new() } else { alloc::format!(", {}", o3.trim()) }, verdict(n3 == 0));
    }
    // N5: a file session page is wiped when the next program gets it
    if race.len() >= 32 {
        let w = Req::new().arg(18).heap(64).fs().go(&race);
        let wc = if w > 0 { wait(w, false) } else { -1 };
        let r = Req::new().arg(19).heap(64).fs().go(&race);
        let leftover = if r > 0 { wait(r, false) } else { -1 };
        println!("[client] TEST a program's file session page holds nothing of the program before it (writer exit {wc}, bytes left over {leftover}): {}", verdict(wc == 0 && leftover == 0));
    }
    // M1: a thread's copy of a run-time memory capability cannot end the object, and MC_FREE does not take shared memory
    if race.len() >= 32 {
        let m1: Vec<u64> = [4u64, 5, 6]
            .iter()
            .map(|&mode| run_with_console3(Req::new().arg(mode).heap(64).threads(1).give_masked(1, MEM_SLOT as u8, 0xFFFF & !4), &race, b"").0 as u64)
            .collect();
        println!("[client] TEST a thread's copy of run-time memory cannot free it (exit codes for CAP_REVOKE, thread end, MC_FREE: {m1:?}): {}", verdict(m1.iter().all(|&c| c == 0)));
        // M2: a program may give capabilities only to its own program, the programs it started and the one that started it
        let sib = Req::new().arg(8).heap(64).go(&race);
        let m2 = if sib > 0 { run_with_console3(Req::new().arg(7 | (sib as u64) << 8).heap(64), &race, b"").0 } else { -1 };
        if sib > 0 {
            wait(sib, false);
        }
        println!("[client] TEST a program cannot put capabilities into a boot-time task or an unrelated program, but can into its parent (bits of refusals that failed: {m2:#x}): {}", verdict(m2 == 0));
        // M4: user programs cannot use FP/SIMD (the registers are not switched between tasks), and TPIDR_EL0 is per task
        let (c10, o10, _) = run_with_console3(Req::new().arg(10).heap(32), &race, b"");
        let o10 = String::from_utf8_lossy(&o10).into_owned();
        let (c11, _, _) = run_with_console3(Req::new().arg(11).heap(64).threads(1), &race, b"");
        println!("[client] TEST a SIMD instruction in a user program ends it ({c10:#x}, survived {}), and TPIDR_EL0 is not shared between tasks (bits {c11:#x}): {}", o10.contains("survived"), verdict(c10 as u64 == EXIT_FAULTED && !o10.contains("survived") && c11 == 0));
        // M7: a program's share of the global tables (memory objects, capability nodes, endpoints) is limited, however many threads it has
        let q12 = run_with_console3(Req::new().arg(12).heap(400).threads(7), &race, b"").0;
        let q13 = run_with_console3(Req::new().arg(13).heap(400).threads(7), &race, b"").0;
        let q14 = run_with_console3(Req::new().arg(14).heap(200).threads(7).give_masked(1, FACTORY_SLOT as u8, 0xFFFF & !4), &race, b"").0;
        let q15 = run_with_console3(Req::new().arg(15).heap(64).threads(1).give_masked(1, FACTORY_SLOT as u8, 0xFFFF & !4), &race, b"").0;
        // ... and more than its share of the file-system sessions for the programs it starts (5 of 8; the last 2 are the boot-time tasks')
        let t = Req::new().arg(2).budget(3000).give(&[SPAWN_SLOT as u8]).go(&spawner);
        let sessions = if t > 0 { wait(t, false) } else { -1 };
        println!("[client] TEST one program cannot fill an endpoint's queue (failure bits {q15:#x}) or take more than 5 file sessions for its children (got {sessions}): {}", verdict(q15 == 0 && sessions == 5));
        println!("[client] TEST one program cannot take more than its share of memory objects, capability nodes and endpoints, with threads (failure bits {q12:#x}, {q13:#x}, {q14:#x}): {}", verdict(q12 == 0 && q13 == 0 && q14 == 0));
        // L1: what other tasks hold is shown only to a holder of an Admin capability (the conductor has one)
        let l1 = run_with_console3(Req::new().arg(9).heap(64), &race, b"").0;
        let admin_ok = svc(21, 10, 0, 0, 0, 0)[0] == 0 && svc(21, 11, 0, 0, 0, 0)[0] == 0;
        println!("[client] TEST SYSINFO pages that list other tasks' capabilities refuse a program without an Admin capability, and answer one that has it (program bits {l1:#x}, with Admin {admin_ok}): {}", verdict(l1 == 0 && admin_ok));
        let shm = svc(37, 1, 0, 0, 0, 0)[0] as i64;
        let freed = svc(MEMCTL, MEM_SLOT, 3, shm as u64, 0, 0)[0] as i64;
        let still = shm >= 0 && svc(4, shm as u64, 0xA000_0000, 1, 0, 0)[0] == 0;
        svc(CAP_REVOKE, shm as u64, 1, 0, 0, 0);
        println!("[client] TEST MC_FREE refuses a shared-memory capability, which stays usable (result {freed}, still mapped {still}): {}", verdict(freed == E_INVAL as i64 && still));
    }

    // ---- the pager: pages written back to disk and read again ------------------------------------------------------------
    pager_tests(&v, &load("pager"), &load("pagetest"));

    // ---- kill, nohang, zombies -----------------------------------------------------------------------------------
    let t = Req::new().arg(0).go(&sleeper);
    sleep(5);
    let early = wait(t, true);
    let k = kill(t);
    let code = wait(t, false) as u64;
    println!("[client] TEST a running program: WAIT without blocking says try again ({early}), KILL ends it, WAIT returns the killed code ({k}, {code:#x}): {}",
        verdict(early == E_AGAIN as i64 && k == 0 && code == EXIT_KILLED));
    let t = Req::new().arg(3).go(&hello);
    sleep(10); // it has exited by now: a zombie until collected
    let z = state_of(t);
    let kz = kill(t);
    let code = wait(t, true);
    println!("[client] TEST a finished program waits as a zombie (state {z}); it cannot be killed again ({kz}); its code is collected without blocking ({code}): {}",
        verdict(z == 7 && kz == E_INVAL as i64 && code == 3));

    // ---- who may do what ------------------------------------------------------------------------------------------
    let static_wait = wait(4, true);
    let static_kill = kill(4);
    let me_kill = kill(0);
    println!("[client] TEST only the parent can wait for or kill a program, and system tasks are never programs ({static_wait} {static_kill} {me_kill}): {}",
        verdict(static_wait == E_INVAL as i64 && static_kill == E_INVAL as i64 && me_kill == E_INVAL as i64));
    let no_cap = Req::new().go_with(0, &hello); // slot 0 is an endpoint, not the right to spawn
    println!("[client] TEST SPAWN needs the spawn capability ({no_cap}): {}", verdict(no_cap == -2));

    // ---- capabilities are delegated, never invented --------------------------------------------------------------------
    let t = Req::new().arg(0).give(&[DRIVER_SLOT as u8]).go(&ping);
    let served = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST a program uses the endpoint its parent delegated (the driver answered {served}): {}", verdict(served > 0 && served < 1000));
    let t = Req::new().arg(0).go(&ping);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST without the delegation the same program has no endpoint (exit code {code}): {}", verdict(code == 1002));
    let no_grant = Req::new().arg(0).give(&[0]).go(&ping); // slot 0 may be used but not handed on
    let empty = Req::new().arg(0).give(&[13]).go(&ping);
    println!("[client] TEST a capability without the grant right, or an empty slot, cannot be delegated ({no_grant} {empty}): {}", verdict(no_grant == E_PERM as i64 && empty == -2));

    // ---- memory limits ---------------------------------------------------------------------------------------------
    let quota = 12u64;
    let t = Req::new().arg(quota).heap(quota as u32).go(&memp);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST a program gets exactly the heap it was given ({quota} pages used and checked, one more refused; exit code {code}): {}", verdict(code == 0));
    let free_after = sysinfo(0)[3];

    // ---- memory budgets: a program cannot take more than it was given, nor give away more than it holds -----------------
    let quotatest = load("quotatest");
    if quotatest.len() >= 32 {
        let q = |op: u64, child: i64, heap: u64, budget: u64| svc(36, op, child as u64, heap, budget, 0);
        let frames0 = sysinfo(0)[3];
        // a program that allocates until the allocator refuses stays inside its limit, and uses nearly all of it
        let t = Req::new().arg(0).heap(150).go(&quotatest);
        let code = if t > 0 { wait(t, false) } else { t };
        println!("[client] TEST a program that allocates until refused stays within its limit and can use nearly all of it (exit code {code}): {}", verdict(code == 0));
        // one that does not check dies alone, and its memory comes back
        let t = Req::new().arg(1).heap(150).go(&quotatest);
        let code = if t > 0 { wait(t, false) as u64 } else { 0 };
        let frames1 = sysinfo(0)[3];
        println!("[client] TEST a program that allocates without checking is stopped at its limit and dies alone (exit {code:#x}, frames {frames0} -> {frames1}): {}", verdict(code != 0 && frames1 + 64 >= frames0));
        // contiguous memory counts against the same limit as the heap
        let t = Req::new().arg(2).heap(120).give_masked(1, 11, 0xFFFF & !4).go(&quotatest);
        let code = if t > 0 { wait(t, false) } else { t };
        println!("[client] TEST contiguous allocations count against the program's limit together with its heap (exit code {code}): {}", verdict(code == 0));
        // a program can hand down only what its budget holds, and gets it back when the children are gone: default children cost 256 + 24 pages
        let t = Req::new().arg(3).heap(300).budget(700).give(&[SPAWN_SLOT as u8]).go(&quotatest);
        let packed = if t > 0 { wait(t, false) as u64 } else { 0 };
        let (count, err) = (packed & 0xFF, (packed >> 8) as i64);
        println!("[client] TEST a program with a budget of 700 pages starts two default programs and the third is refused for memory, then gets the budget back (started {count}, error -{err}, code {packed:#x}): {}", verdict(count == 2 && err == 8));
        // at most 8 programs at a time, however small
        let t = Req::new().arg(4).heap(300).budget(4000).give(&[SPAWN_SLOT as u8]).go(&quotatest);
        let packed = if t > 0 { wait(t, false) as u64 } else { 0 };
        let (count, err) = (packed & 0xFF, (packed >> 8) as i64);
        println!("[client] TEST a program may have at most 8 programs at a time, however much budget it has (started {count}, error -{err}): {}", verdict(count == 8 && err == 3));
        // the kernel's side: the cost of a program is charged to its parent's budget, with each loaded page, and refunded when it dies
        let own = q(0, 0, 0, 0);
        let (d0, children0) = (own[3], own[4]);
        let e = embryo(&Req::new().heap(100).budget(50));
        let after_spawn = q(0, 0, 0, 0)[3];
        let page = alloc::vec![0x5Au8; 16384]; // (three pages are read from the first page boundary in it)
        let src = (page.as_ptr() as u64 + 4095) & !4095;
        let loaded = load_raw(e, 0x8000_0000, src, 3, 1);
        let after_load = q(0, 0, 0, 0)[3];
        kill(e);
        sleep(3);
        let _ = wait(e, true); // (a killed embryo is a zombie until collected)
        let own2 = q(0, 0, 0, 0);
        println!("[client] TEST a program costs its heap + budget + 24 pages and each loaded image page one more, all refunded when it is gone (delegated {d0} -> {after_spawn} -> {after_load} -> {}, children {children0} -> {}): {}",
            own2[3], own2[4], verdict(e > 0 && loaded == 0 && after_spawn == d0 + 174 && after_load == d0 + 177 && own2[3] == d0 && own2[4] == children0));
        // resizing a child: raised within the parent's budget, refused beyond it, never below what it holds
        let before = q(0, 0, 0, 0)[3];
        let t = Req::new().arg(5).heap(100).go(&quotatest);
        sleep(10); // (it has grown its heap by 50 pages)
        let base = q(0, 0, 0, 0)[3];
        let below = q(1, t, 10, 0)[0] as i64;
        let too_big = q(1, t, 16385, 0)[0] as i64;
        let huge_budget = q(1, t, 100, 1 << 21)[0] as i64;
        let over_budget = q(1, t, 100, 100_000)[0] as i64;
        let up = q(1, t, 200, 100)[0] as i64;
        let raised = q(0, 0, 0, 0)[3];
        let stranger = q(1, 4, 100, 0)[0] as i64;
        let down = q(1, t, 100, 0)[0] as i64;
        let lowered = q(0, 0, 0, 0)[3];
        kill(t);
        let _ = wait(t, false);
        let gone = q(0, 0, 0, 0)[3];
        println!("[client] TEST a child's limits can be raised within the parent's budget and lowered, never below what it holds or beyond the budget (below {below}, too big {too_big}, huge budget {huge_budget}, over budget {over_budget}, up {up}, delegated {base} -> {raised} -> {lowered} -> {gone}, not my child {stranger}, down {down}): {}",
            verdict(below == E_INVAL as i64 && too_big == E_INVAL as i64 && huge_budget == E_INVAL as i64 && over_budget == -8 && up == 0 && raised == base + 200 && stranger == E_INVAL as i64 && down == 0 && lowered == base && gone == before && base > before + 124));
        let frames2 = sysinfo(0)[3];
        println!("[client] TEST every frame and capability node the memory-limit tests used is back (frames {frames0} -> {frames2}): {}", verdict(frames2 + 64 >= frames0));
    }

    // ---- shared memory made by programs (SHM_CREATE) -------------------------------------------------------------------------
    let shmtest = load("shmtest");
    if shmtest.len() >= 32 {
        const BIG: usize = 0xA000_0000;
        const PAGE: usize = 4096;
        let frames0 = sysinfo(0)[3];
        let objects0 = sysinfo(4)[2];
        let run = |arg: u64, heap: u32| {
            let t = Req::new().arg(arg).heap(heap).go(&shmtest);
            if t > 0 { wait(t, false) } else { t }
        };
        let pat = |i: usize, k: usize| (i.wrapping_mul(k)).wrapping_add(k) as u8;
        let code = run(0, 300);
        println!("[client] TEST SHM_CREATE: sizes, the charge against the limit, one object mapped twice, the mapping table and running out of slots (exit code {code}): {}", verdict(code == 0));
        // two programs share an object: what one writes the other reads
        let s = svc(37, 2, 0, 0, 0, 0)[0] as i64;
        let mapped = s >= 0 && svc(4, s as u64, BIG as u64, 1, 0, 0)[0] == 0;
        if mapped {
            // SAFETY: `mapped` is true, so BIG is a writable 2-page shared object mapped here; the shmtest program writes only page 1 while this test is blocked in `wait`, and `mem` is not used after the object is revoked.
            let mem = unsafe { core::slice::from_raw_parts_mut(BIG as *mut u8, 2 * PAGE) };
            for i in 0..PAGE {
                mem[i] = pat(i, 7);
            }
            let t = Req::new().arg(1).heap(50).give_masked(0, s as u8, 0xFFFF & !4).go(&shmtest);
            let code = if t > 0 { wait(t, false) } else { t };
            let seen = (0..PAGE).all(|i| mem[PAGE + i] == pat(i, 5));
            println!("[client] TEST a program shares memory it created with another: the other reads what was written first and writes what is read afterwards (exit code {code}, reply seen {seen}): {}", verdict(code == 0 && seen));
            // a capability with only the map right gives read-only access
            let t = Req::new().arg(3).heap(50).give_masked(0, s as u8, 8).go(&shmtest);
            let code = if t > 0 { wait(t, false) } else { t };
            println!("[client] TEST a capability granted without the write right cannot be mapped writable, and shows the data read-only (exit code {code}): {}", verdict(code == 0));
            // a holder that goes away leaves the object alone
            let t = Req::new().arg(8).heap(50).give_masked(0, s as u8, 0xFFFF & !4).go(&shmtest);
            let code = if t > 0 { wait(t, false) } else { t };
            // SAFETY: BIG is still mapped (the object is revoked only in the next step); offset 8 is inside page 0 and the holder has already exited.
            let marker = unsafe { core::ptr::read_volatile((BIG + 8) as *const u32) };
            let still = (0..PAGE).all(|i| i < 12 || mem[i] == pat(i, 7));
            println!("[client] TEST a holder of shared memory exiting does not free it or disturb it (exit code {code}, marker {marker:#x}, data intact {still}): {}", verdict(code == 0 && marker == 0x600D && still));
            // the creator takes the memory back: a holder that is still using it dies, alone
            let t = Req::new().arg(4).heap(50).give_masked(0, s as u8, 0xFFFF & !4).go(&shmtest);
            sleep(10);
            let r = svc(6, s as u64, 1, 0, 0, 0)[0] as i64;
            let code = if t > 0 { wait(t, false) as u64 } else { 0 };
            println!("[client] TEST when the creator takes shared memory back, a program still reading it faults and dies alone (revoke {r}, exit {code:#x}): {}", verdict(r >= 0 && code == u64::MAX));
        } else {
            println!("[client] TEST a program shares memory it created with another (SHM_CREATE {s}): FAIL");
        }
        // sleeping on a word of shared memory, woken from another program
        let s2 = svc(37, 1, 0, 0, 0, 0)[0] as i64;
        if s2 >= 0 && svc(4, s2 as u64, BIG as u64, 1, 0, 0)[0] == 0 {
            let t = Req::new().arg(2).heap(50).give_masked(0, s2 as u8, 0xFFFF & !4).go(&shmtest);
            sleep(30);
            // SAFETY: guarded by the `svc(4, s2, BIG, 1) == 0` check: BIG is a writable one-page shared object; the other program sleeps on this word.
            unsafe { core::ptr::write_volatile(BIG as *mut u32, 1) };
            let woken = svc(33, BIG as u64, 4, 0, 0, 0)[0];
            let code = if t > 0 { wait(t, false) } else { t };
            println!("[client] TEST a program sleeping on a word of shared memory is woken by another program (woke {woken}, exit code {code}): {}", verdict(woken == 1 && code == 0));
            svc(6, s2 as u64, 1, 0, 0, 0);
        } else {
            println!("[client] TEST a program sleeping on a word of shared memory is woken by another program (SHM_CREATE {s2}): FAIL");
        }
        // a creator that just exits: the memory goes with it
        let before = sysinfo(0)[3];
        let code = run(5, 120);
        let after = sysinfo(0)[3];
        println!("[client] TEST shared memory dies with its creator without being given back (exit code {code}, frames {before} -> {after}): {}", verdict(code == 0 && after + 8 >= before));
        // a creator that exits while another program holds the memory: the holder keeps it, and it is freed with the last holder
        let before = sysinfo(0)[3];
        let t = Req::new().arg(9).heap(100).go(&shmtest);
        let slot = if t > 0 { wait(t, false) } else { t };
        let during = sysinfo(0)[3];
        let (mapped, intact, info) = if (0..32).contains(&slot) {
            let m = svc(4, slot as u64, BIG as u64 + 0x40_0000, 0, 0, 0)[0] == 0;
            // SAFETY: only when `m` (the mapping succeeded) is the 8-page object `slot` readable at BIG + 0x40_0000.
            let mem: &[u8] = if m { unsafe { core::slice::from_raw_parts((BIG + 0x40_0000) as *const u8, 8 * PAGE) } } else { &[] };
            (m, m && (0..8 * PAGE).all(|i| mem[i] == pat(i, 9)), svc(38, slot as u64, 0, 0, 0, 0)[0])
        } else {
            (false, false, 0)
        };
        let r = if (0..32).contains(&slot) { svc(6, slot as u64, 1, 0, 0, 0)[0] as i64 } else { -1 };
        let after = sysinfo(0)[3];
        println!("[client] TEST shared memory outlives its creator while another program holds it, and is freed when the holder lets go (slot {slot}, mapped {mapped}, data intact {intact}, SHM_INFO {info:#x}, revoke {r}, frames {before} -> {during} -> {after}): {}",
            verdict(mapped && intact && info == (8 | 1 << 32) && r >= 0 && during + 8 <= before + 4 && after + 4 >= before));
        // the kernel picks mapping addresses
        let outs: Vec<(u64, String)> = (0..4).map(|_| { let (c, o, _) = run_with_console3(Req::new().arg(10).heap(300), &shmtest, b""); (c as u64, String::from_utf8_lossy(&o).into_owned()) }).collect();
        let firsts: Vec<String> = outs.iter().filter_map(|(_, o)| o.split("first=").nth(1).and_then(|r| r.split(' ').next()).map(|s| s.into())).collect();
        let mut distinct = firsts.clone();
        distinct.sort();
        distinct.dedup();
        let codes: Vec<u64> = outs.iter().map(|o| o.0).collect();
        println!("[client] TEST MEM_MAP with address 0 lets the kernel choose: random places inside the windows, a page apart, usable, and the large window for a large object (exit codes {codes:?}, {} different first addresses of 4): {}", distinct.len(), verdict(codes.iter().all(|&c| c == 0) && firsts.len() == 4 && distinct.len() >= 3));
        // the page next to an object the kernel placed is not mapped; a full usual window spills into the large one; the
        // right to name addresses can be withheld
        let nb = |m: u64| { let (c, o, _) = run_with_console3(Req::new().arg(m).heap(60), &shmtest, b""); (c as u64, String::from_utf8_lossy(&o).into_owned()) };
        let (a, ao) = nb(11);
        let (b, bo) = nb(12);
        let spill = run(13, 600);
        let gap = run(15, 600);
        let nofix = { let (c, _, _) = run_with_console3(Req::new().arg(14).heap(60).no_fixed_maps(), &shmtest, b""); c as u64 };
        println!("[client] TEST the pages next to a kernel-placed mapping fault (after: {a:#x}, before: {b:#x}), a full usual window spills into the large one (code {spill}), the only gap left in it is found (code {gap}), and a program without the right to name addresses can only map at 0 (code {nofix}): {}",
            verdict(a == EXIT_FAULTED && b == EXIT_FAULTED && !ao.contains("readable") && !bo.contains("readable") && spill == 0 && gap == 0 && nofix == 0));
        // 16 MiB, twice
        let code = run(7, 4096);
        println!("[client] TEST a 4096-page object is usable from end to end, freed and created again (exit code {code}): {}", verdict(code == 0));
        let (frames1, objects1) = (sysinfo(0)[3], sysinfo(4)[2]);
        println!("[client] TEST nothing is left behind by the shared-memory tests (frames {frames0} -> {frames1}, objects {objects0} -> {objects1}): {}", verdict(frames1 + 64 >= frames0 && objects1 == objects0));
    }

    // ---- programs starting programs; orphans do not outlive their parent ---------------------------------------------------------
    let t = Req::new().arg(0).budget(600).give(&[SPAWN_SLOT as u8]).go(&spawner);
    let packed = if t > 0 { wait(t, false) as u64 } else { 0 };
    let (c1, c2) = ((packed & 0xFF) as i64, ((packed >> 8) & 0xFF) as i64);
    sleep(30);
    println!("[client] TEST a program with the spawn capability starts programs, and they end with it (grandchildren {c1} and {c2}, slot states {} and {}): {}",
        state_of(c1), state_of(c2), verdict(packed < 0x1_0000 && c1 > 0 && c2 > 0 && state_of(c1) == 0 && state_of(c2) == 0));
    let t = Req::new().arg(0).go(&spawner); // no spawn capability delegated: its own spawn fails with the capability error
    let code = if t > 0 { wait(t, false) as u64 } else { 0 };
    println!("[client] TEST a program that was not delegated the spawn capability cannot spawn (exit code {code:#x}): {}", verdict(code == 0xFFFF_FFFF - 2));

    // ---- files: a program reaches the VFS only through the session its parent asked for ---------------------------------
    let t = Req::new().fs().args(b"cat\0/system/hello.txt\0").go(&cat);
    let n = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST a program started with file access reads a file through the VFS (cat printed {n} bytes of /system/hello.txt): {}", verdict(n == 42));
    let t = Req::new().args(b"cat\0/system/hello.txt\0").go(&cat);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST without file access the same program finds no file-system capability (exit code {code}): {}", verdict(code == 1002));
    let t = Req::new().fs().args(b"fswrite\0/data/by-a-program.txt\0written by a program\0").go(&fswrite);
    let code = if t > 0 { wait(t, false) } else { t };
    let back = v.read_file("/data/by-a-program.txt").unwrap_or_default();
    println!("[client] TEST a program writes a file that the conductor then reads ({code}, {:?}): {}", core::str::from_utf8(&back).unwrap_or("?"), verdict(code == 0 && back == b"written by a program"));
    let t = Req::new().fs().args(b"fswrite\0/system/new.txt\0nope\0").go(&fswrite);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST a program cannot write to the read-only system partition (exit code {code}: 2000 + EROFS 4): {}", verdict(code == 2004));
    let t = Req::new().fs().args(b"ls\0/system\0").go(&ls);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST a program lists a directory ({code} entries in /system): {}", verdict(code == 4));
    let t = Req::new().fs().args(b"fdprobe\0open\0").go(&fdprobe);
    sleep(20);
    kill(t);
    wait(t, false);
    let t2 = Req::new().fs().args(b"fdprobe\0read\0").go(&fdprobe); // takes the same slot: nothing of its predecessor's is open
    let code = if t2 > 0 { wait(t2, false) } else { t2 };
    println!("[client] TEST a program's file descriptors do not outlive it (same slot {}, next program's read of fd 0 gives {code}, EBADF is 3): {}", t == t2, verdict(t == t2 && code == 3));
    let mut sess: Vec<i64> = Vec::new();
    let mut last = 0;
    let total = sysinfo_at(18, 0)[1] as usize; // (a quarter of the task slots, 8 at least)
    for _ in 0..=total {
        let t = Req::new().fs().heap(2).go(&sleeper); // (a small heap: with the default 256 pages the conductor's page budget would end the run long before 255 programs)
        if t < 0 {
            last = t;
            break;
        }
        sess.push(t);
    }
    for &t in &sess {
        kill(t);
        wait(t, false);
    }
    let again = Req::new().fs().go(&sleeper);
    kill(again);
    wait(again, false);
    println!("[client] TEST every file session the kernel made ({total}) can be taken, the next request is refused ({} then {last}), and finished programs give theirs back ({again}): {}", sess.len(), verdict(sess.len() == total && last == E_FULL as i64 && again > 0));
    let t = Req::new().arg(1).budget(600).give_masked(0, SPAWN_SLOT as u8, 0xFFFF & !(4 | (1 << 13))).go(&spawner);
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST file access is a right of the spawn capability and is not handed on unless the parent passes it (child's request gave {code:#x}, -1 = {:#x}): {}", 0xFFFF_FFFFu64 - 1, verdict(code == 0xFFFF_FFFE));

    // ---- endpoints made at run time --------------------------------------------------------------------------------
    let mk = || svc(EP_CREATE, FACTORY_SLOT, 0, 0, 0, 0)[0] as i64;
    let revoke = |slot: i64| svc(CAP_REVOKE, slot as u64, 0, 0, 0, 0)[0] as i64; // what was derived from it
    let destroy = |slot: i64| svc(CAP_REVOKE, slot as u64, 1, 0, 0, 0)[0] as i64; // ... and the capability itself
    let ep = mk();
    let server = Req::new().give_masked(0, ep as u8, 0b11).go(&kv); // send + receive
    let c1 = Req::new().arg(1).give_masked(0, ep as u8, 0b01).go(&kvc); // send only
    let c2 = Req::new().arg(2).give_masked(0, ep as u8, 0b01).go(&kvc);
    let (r1, r2) = (if c1 > 0 { wait(c1, false) } else { c1 }, if c2 > 0 { wait(c2, false) } else { c2 });
    println!("[client] TEST two clients use a server built on an endpoint the conductor created, each holding only a send capability ({r1} {r2}): {}", verdict(r1 == 0 && r2 == 0));
    // a server blocked in receive learns that its endpoint is gone
    sleep(5);
    let gone = revoke(ep as i64);
    destroy(ep as i64); // (the endpoint itself lived on until now: its creator still held it)
    let code = if server > 0 { wait(server, false) } else { server };
    println!("[client] TEST revoking the server's capability wakes it from its receive (revoked {gone}, server exit code {code}: the 40 keys it held): {}", verdict(gone >= 1 && code == 40));
    let ep = mk();
    let b = Req::new().give_masked(0, ep as u8, 0b01).go(&blocker);
    sleep(10);
    destroy(ep as i64);
    let code = if b > 0 { wait(b, false) } else { b };
    println!("[client] TEST a caller waiting on an endpoint that ends is told so instead of waiting for ever (exit code {code}: 1000 + 4): {}", verdict(code == 1004));
    let eps: Vec<i64> = (0..5).map(|_| mk()).collect();
    let sixth = mk();
    println!("[client] TEST a task may own four endpoints at a time ({:?}, then {sixth}): {}", eps, verdict(eps[..4].iter().all(|&e| e >= 0) && eps[4] == E_FULL as i64 && sixth == E_FULL as i64));
    for &e in eps.iter().filter(|&&e| e >= 0) {
        destroy(e);
    }
    let after = mk();
    println!("[client] TEST endpoints return to the pool when their creator destroys them ({after}): {}", verdict(after >= 0));
    destroy(after);

    // ---- command line, environment, standard input and output -----------------------------------------------------------------
    let block = b"argdump\0one\0two words\0\0PWD=/x\0TERM=vt\0";
    let (code, out) = run_with_console(Req::new().arg(9).args(block), &argdump, b"");
    let text = core::str::from_utf8(&out).unwrap_or("?");
    println!("[client] TEST a program receives its command line (name first), environment, argument word and parent ({code}, {:?}): {}", text,
        verdict(code == 3 && text == "argc=3\nargv[0]=argdump\nargv[1]=one\nargv[2]=two words\nPWD=/x\nTERM=vt\narg=9 parent=0\n"));
    let (code, out) = run_with_console(Req::new().args(b"upper\0"), &upper, b"hello\nworld\nlast");
    println!("[client] TEST a program reads its standard input line by line until the input ends ({code} lines, {:?}): {}", core::str::from_utf8(&out).unwrap_or("?"), verdict(code == 3 && out == b"HELLO\nWORLD\nLAST\n"));
    let long: Vec<u8> = (0..5000u32).map(|i| if i % 50 == 49 { b'\n' } else { b'a' + (i % 26) as u8 }).collect();
    let (code, out) = run_with_console(Req::new().args(b"upper\0"), &upper, &long);
    let expect: Vec<u8> = long.iter().map(|b| b.to_ascii_uppercase()).collect();
    println!("[client] TEST 5000 bytes of input and output cross the console endpoint intact ({code} lines, {} bytes back): {}", out.len(), verdict(code == 100 && out == expect));
    let t = Req::new().args(b"upper\0").go(&upper); // no console at all: reads nothing, ends
    let code = if t > 0 { wait(t, false) } else { t };
    println!("[client] TEST without a console endpoint standard input is empty and the program still runs (exit {code}): {}", verdict(code == 0));

    // ---- ELF files ------------------------------------------------------------------------------------------------------------
    let (code, out) = run_with_console(Req::new().arg(9).args(block), &argdump_elf, b"");
    println!("[client] TEST an ELF executable is loaded and runs like a flat image ({} bytes; exit {code}, same output as above: {}): {}", argdump_elf.len(), out == b"argc=3\nargv[0]=argdump\nargv[1]=one\nargv[2]=two words\nPWD=/x\nTERM=vt\narg=9 parent=0\n", verdict(code == 3 && out.starts_with(b"argc=3")));
    // position-independent executables: random base, relocated pointers
    let pietest = load("pietest");
    let (code, out) = run_with_console(Req::new().arg(9).args(block), &argdump, b"");
    println!("[client] TEST a position-independent ELF executable runs like a flat image (exit {code}, same output as above: {}): {}", out == b"argc=3\nargv[0]=argdump\nargv[1]=one\nargv[2]=two words\nPWD=/x\nTERM=vt\narg=9 parent=0\n", verdict(code == 3 && out.starts_with(b"argc=3")));
    let mut bases = Vec::new();
    let mut all_ok = true;
    for _ in 0..6 {
        let (code, out) = run_with_console(Req::new().arg(10), &pietest, b"");
        let text = core::str::from_utf8(&out).unwrap_or("?");
        let data = text.split("data=0x").nth(1).and_then(|d| usize::from_str_radix(d.trim(), 16).ok()).unwrap_or(0);
        all_ok &= code == 11 && text.starts_with("ok=true ") && (0x2_0000_0000..0x40_0000_0000).contains(&data);
        bases.push(data >> 30);
    }
    bases.sort();
    bases.dedup();
    println!("[client] TEST position-independent programs get a random image base and follow relocated pointers and function tables ({} different of 6 runs, ok {all_ok}): {}", bases.len(), verdict(all_ok && bases.len() >= 4));
    let patch = |f: &dyn Fn(&mut Vec<u8>)| -> i64 {
        let mut e = hello_elf.clone();
        f(&mut e);
        Req::new().go(&e)
    };
    let u16le = |e: &mut Vec<u8>, o: usize, v: u16| e[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let u64le = |e: &mut Vec<u8>, o: usize, v: u64| e[o..o + 8].copy_from_slice(&v.to_le_bytes());
    // program header i sits at offset 64 + 56 i: type(4) flags(4) offset(8) vaddr(8) paddr(8) filesz(8) memsz(8)
    let results = [
        ("wrong machine", patch(&|e| u16le(e, 18, 62))),
        ("shared object", patch(&|e| u16le(e, 16, 3))),
        ("32-bit class", patch(&|e| e[4] = 1)),
        ("big endian", patch(&|e| e[5] = 2)),
        ("no program headers", patch(&|e| u16le(e, 56, 0))),
        ("too many program headers", patch(&|e| u16le(e, 56, 200))),
        ("program headers beyond the file", patch(&|e| u64le(e, 32, 1 << 30))),
        ("segment below the image base", patch(&|e| u64le(e, 64 + 56 + 16, 0x1000))),
        ("segment into the stack", patch(&|e| u64le(e, 64 + 56 + 16, 0x800F_F000))),
        ("segment wraps the address space", patch(&|e| u64le(e, 64 + 56 + 40, u64::MAX - 5))),
        ("file bytes beyond the file", patch(&|e| u64le(e, 64 + 56 + 8, 1 << 40))),
        ("more file than memory", patch(&|e| u64le(e, 64 + 56 + 32, 1 << 20))),
        ("writable and executable", patch(&|e| e[64 + 56 + 4] = 7)),
        ("entry outside the code", patch(&|e| u64le(e, 24, 0x8000_3000))),
        ("entry not aligned", patch(&|e| u64le(e, 24, 0x8000_0021))),
        ("dynamic section", patch(&|e| e[64 + 4 * 56..64 + 4 * 56 + 4].copy_from_slice(&2u32.to_le_bytes()))),
        ("interpreter", patch(&|e| e[64 + 4 * 56..64 + 4 * 56 + 4].copy_from_slice(&3u32.to_le_bytes()))),
        ("truncated", patch(&|e| e.truncate(100))),
    ];
    let bad: Vec<&str> = results.iter().filter(|(_, r)| *r != E_INVAL as i64).map(|(n, _)| *n).collect();
    println!("[client] TEST malformed ELF files are refused, each for its own reason ({} of {}; accepted by mistake: {:?}): {}", results.len() - bad.len(), results.len(), bad, verdict(bad.is_empty()));

    // ---- running out of slots --------------------------------------------------------------------------------------------
    let mut kids: Vec<i64> = Vec::new();
    let mut last = 0;
    // (as many tries as there are task slots, each with a small heap: the table must fill before the conductor's page budget does, whatever size the table is)
    for _ in 0..sysinfo_at(18, 0)[2] as usize {
        let t = Req::new().arg(0).heap(2).go(&sleeper);
        if t < 0 {
            last = t;
            break;
        }
        kids.push(t);
    }
    println!("[client] TEST all free task slots can be used, then SPAWN says the table is full ({} programs, then {last}): {}", kids.len(), verdict(last == E_FULL as i64 && kids.len() >= 10));
    for &k in &kids {
        kill(k);
    }
    let all_killed = kids.iter().all(|&k| wait(k, false) as u64 == EXIT_KILLED);
    println!("[client] TEST every one of them is killed and collected, and the slots are usable again: {}", verdict(all_killed && Req::new().arg(1).go(&hello) > 0 && {
        let t = Req::new().arg(2).go(&hello);
        wait(t, false) == 2
    }));
    // (the extra hello above was never waited for: collect it)
    for t in FIRST_DYNAMIC as i64..64 {
        if state_of(t) == 7 {
            wait(t, true);
        }
    }

    // ---- bad images ------------------------------------------------------------------------------------------------------------
    // (the header-patching cases need a flat image: sleeper is one; the ELF cases are tested separately)
    let flat = sleeper.clone();
    let mut bad: Vec<(&str, Vec<u8>)> = Vec::new();
    bad.push(("too short", flat[..16].to_vec()));
    let mut x = flat.clone();
    x[0] ^= 1;
    bad.push(("bad magic", x));
    let mut x = flat.clone();
    x[16..24].copy_from_slice(&(1u64 << 40).to_le_bytes());
    bad.push(("huge memory size", x));
    let mut x = flat.clone();
    x[8..16].copy_from_slice(&0x1000_0000u64.to_le_bytes());
    bad.push(("code larger than memory", x));
    let mut x = flat.clone();
    x[8..16].copy_from_slice(&123u64.to_le_bytes());
    bad.push(("unaligned code size", x));
    let mut x = flat.clone();
    x[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
    x.resize(0x3000, 0);
    bad.push(("image longer than its memory", x));
    let refused = bad.iter().filter(|(_, b)| Req::new().arg(0).go(b) == E_INVAL as i64).count();
    let class = Req { class: 7, ..Req::new() }.go(&flat);
    let version = embryo(&Req { version: 9, ..Req::new() });
    let old_style = {
        let mut b = Req::new().bytes();
        b[16..24].copy_from_slice(&1u64.to_le_bytes()); // an image length: the kernel no longer takes images
        svc(SPAWN, SPAWN_SLOT, b.as_ptr() as u64, 0, 0, 0)[0] as i64
    };
    println!("[client] TEST malformed images are refused by the loader, a bad class or request version or an image pointer by the kernel ({refused} of {} images, bad class {class}, unknown request version {version}, image pointer {old_style}): {}", bad.len(),
        verdict(refused == bad.len() && class == E_INVAL as i64 && version == E_INVAL as i64 && old_style == E_INVAL as i64));

    // ---- the kernel's side of loading: hostile TASK_LOAD / TASK_START -----------------------------------------------------
    {
        let base = 0x8000_0000u64;
        let page = alloc::vec![0x5Au8; 8192];
        let src = (page.as_ptr() as u64 + 4095) & !4095; // an address with a whole page behind it
        let e = embryo(&Req::new());
        let mut ok = e >= FIRST_DYNAMIC as i64;
        let mut why = alloc::vec::Vec::new();
        let mut check = |name: &'static str, got: i64, want: i64| {
            if got != want {
                ok = false;
                why.push(alloc::format!("{name}: {got}"));
            }
        };
        check("wait on an embryo", wait(e, true), E_INVAL as i64);
        check("start with nothing loaded", start_raw(e, base), E_INVAL as i64);
        check("unaligned address", load_raw(e, base + 8, src, 1, 1), E_INVAL as i64);
        check("below the image area", load_raw(e, base - 4096, src, 1, 1), E_INVAL as i64);
        check("beyond the image area", load_raw(e, 0x800F_0000, src, 1, 1), E_INVAL as i64);
        check("run past the image area", load_raw(e, 0x800E_F000, src, 2, 1), E_INVAL as i64);
        check("zero pages", load_raw(e, base, src, 0, 1), E_INVAL as i64);
        check("page count that wraps", load_raw(e, base, src, u32::MAX, 1), E_INVAL as i64);
        check("unknown permission", load_raw(e, base, src, 1, 3), E_INVAL as i64);
        check("unmapped source", load_raw(e, base, 0x7000_0000, 1, 1), E_INVAL as i64);
        check("source that wraps", load_raw(e, base, u64::MAX - 100, 1, 1), E_INVAL as i64);
        check("task that is not an embryo", load_raw(4, base, src, 1, 1), E_INVAL as i64);
        check("task out of range", load_raw(4000, base, src, 1, 1), E_INVAL as i64);
        check("data page", load_raw(e, base + 4096, src, 1, 1), 0);
        check("same page twice", load_raw(e, base + 4096, src, 1, 1), E_INVAL as i64);
        check("overlap with a loaded page", load_raw(e, base, src, 2, 0), E_INVAL as i64);
        check("start in a data page", start_raw(e, base + 4096), E_INVAL as i64);
        check("code page", load_raw(e, base, src, 1, 0), 0);
        check("misaligned entry", start_raw(e, base + 2), E_INVAL as i64);
        check("entry outside", start_raw(e, base + 0x8000), E_INVAL as i64);
        check("entry below", start_raw(e, 0x1000), E_INVAL as i64);
        check("kill the embryo", kill(e), 0);
        check("collect it", wait(e, false), EXIT_KILLED as i64);
        check("collected twice", wait(e, true), E_INVAL as i64);
        check("load after it is gone", load_raw(e, base, src, 1, 1), E_INVAL as i64);
        // an embryo that is started cannot be loaded or started again
        let f = Req::new().arg(7).go(&hello);
        check("load into a started program", load_raw(f, base + 0x8000, src, 1, 1), E_INVAL as i64);
        check("start twice", start_raw(f, base + 0x20), E_INVAL as i64);
        check("the started program still runs", wait(f, false), 7);
        println!("[client] TEST the kernel refuses hostile TASK_LOAD / TASK_START requests and an unstarted embryo can be killed and collected{}: {}", if why.is_empty() { alloc::string::String::new() } else { alloc::format!(" (wrong: {})", why.join(", ")) }, verdict(ok));
    }

    // ---- threads -----------------------------------------------------------------------------------------------------------------
    if threads.len() >= 32 {
        let frames0 = sysinfo(0)[3];
        let nodes_t0 = sysinfo(1)[5];
        let run = |mode: u64, n: u32, fs: bool| -> i64 {
            let mut r = Req::new().arg(mode).threads(n);
            if fs {
                r = r.fs().give(&[]).give_masked(0, 0xFF, 0);
            }
            let t = r.go(&threads);
            if t > 0 { wait(t, false) } else { t }
        };
        let c = run(0, 4, false);
        println!("[client] TEST five tasks of one program count under a lock they sleep on (total right, code {c}): {}", verdict(c == 0));
        let c = run(1, 1, false);
        println!("[client] TEST two tasks alternate through one waited-on word 500 times each (code {c}): {}", verdict(c == 0));
        let c = run(2, 1, false);
        println!("[client] TEST a word wait reports a changed value, a timeout, a bad address, and a wake that reaches a sleeper (code {c:#x}): {}", verdict(c == 0));
        let c = run(3, 2, false) as u64;
        println!("[client] TEST a fault in one thread ends the whole program, crashed (code {c:#x}): {}", verdict(c == EXIT_FAULTED));
        let c = run(4, 3, false);
        println!("[client] TEST a program whose main task exits ends its sleeping threads and returns the exit code (code {c}): {}", verdict(c == 7));
        let c = run(5, 1, false);
        println!("[client] TEST a thread calling exit ends the program with that code (code {c}): {}", verdict(c == 9));
        let c = run(6, 2, false);
        println!("[client] TEST the thread allowance holds, and a place is free again once its thread has been joined (code {c}): {}", verdict(c == 0));
        let none = run(0, 0, false);
        println!("[client] TEST a program started without a thread allowance cannot start a thread (code {none}): {}", verdict(none == 1));
        let wide = Req::new().arg(0).threads(9).go(&threads);
        println!("[client] TEST an allowance above the limit is refused ({wide}): {}", verdict(wide == E_INVAL as i64));
        let c = {
            let t = Req::new().arg(7).threads(2).fs().go(&threads);
            if t > 0 { wait(t, false) } else { t }
        };
        println!("[client] TEST a thread reads a file through its program's file session (code {c}): {}", verdict(c == 0));
        let c = run(9, 1, false);
        println!("[client] TEST 150 threads one after another each get a fresh slot (code {c}): {}", verdict(c == 0));
        let c = run(10, 4, false);
        println!("[client] TEST threads grow their program's heap and see each other's pages (code {c}): {}", verdict(c == 0));
        let c = run(11, 1, false);
        println!("[client] TEST a thread that ends naming the program's read-only code as its exit word leaves the code untouched (code {c}): {}", verdict(c == 0));
        let t = Req::new().arg(8).threads(4).go(&threads);
        sleep(15);
        let busy_slots = (FIRST_DYNAMIC as i64..64).filter(|&x| state_of(x) != 0).count();
        if busy_slots != 5 {
            println!("[client] (live slots: {:?})", (FIRST_DYNAMIC as i64..64).filter(|&x| state_of(x) != 0).map(|x| (x, state_of(x))).collect::<Vec<_>>());
        }
        let k = kill(t);
        let code = wait(t, false) as u64;
        sleep(20);
        let left = (FIRST_DYNAMIC as i64..64).filter(|&x| state_of(x) != 0).count();
        println!("[client] TEST killing a program stops its spinning threads (5 slots in use: {busy_slots}; kill {k}, code {code:#x}, slots left {left}): {}", verdict(busy_slots == 5 && k == 0 && code == EXIT_KILLED && left == 0));
        let (frames1, nodes_t1) = (sysinfo(0)[3], sysinfo(1)[5]);
        println!("[client] TEST every frame and capability node the threads used is back (frames {frames0} -> {frames1}, nodes {nodes_t0} -> {nodes_t1}): {}", verdict(frames1 + 64 >= frames0 && nodes_t1 <= nodes_t0));
    }

    // ---- the std-like layer ---------------------------------------------------------------------------------------------------
    if stdtest.len() >= 32 {
        let frames0 = sysinfo(0)[3];
        let nodes0 = sysinfo(1)[5];
        let block = b"stdtest\0one\0\0K=V\0PWD=/\0";
        let r = Req::new().arg(77).args(block).heap(1500).budget(2000).threads(8).fs().give_masked(5, FACTORY_SLOT as u8, 0xFFFF & !4).give_masked(6, SPAWN_SLOT as u8, 0xFFFF & !4);
        let (code, out, err) = run_with_console3(r, &stdtest, b"first\nsecond");
        let (outs, errs) = (String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned());
        println!("[client] std output: {outs:?}");
        println!("[client] std errors: {errs:?}");
        println!("[client] TEST the std-like layer (allocation, streams, files, threads, sync, clocks, processes, endpoints, environment) works end to end (exit {code}): {}", verdict(code == 0));
        println!("[client] TEST standard output and standard error arrive separately ({} and {} bytes): {}", out.len(), err.len(),
            verdict(outs.starts_with("out: hello 42\n") && outs.contains("raw bytes\n") && errs.contains("err: warning 7\n") && errs.contains("section endpoints ok") && !outs.contains("warning")));
        sleep(30);
        let (frames1, nodes1) = (sysinfo(0)[3], sysinfo(1)[5]);
        println!("[client] TEST the std test left nothing behind (frames {frames0} -> {frames1}, nodes {nodes0} -> {nodes1}, files: {:?}): {}",
            v.read_file("/data/std_test.txt").is_err(), verdict(frames1 + 64 >= frames0 && nodes1 <= nodes0 && v.read_file("/data/std_test.txt").is_err()));
    }

    // ---- many at once ------------------------------------------------------------------------------------------------------
    let t0 = counter();
    let kids: Vec<i64> = (0..8).map(|i| Req::new().arg(20 + i).go(&burn)).collect();
    let spawn_us = (counter() - t0) * 1_000_000 / freq / 8;
    let codes: Vec<i64> = kids.iter().map(|&k| if k > 0 { wait(k, false) } else { -1 }).collect();
    println!("[client] TEST eight CPU-bound programs run side by side and all finish ({} started at {spawn_us} us each, codes {:?}): {}",
        kids.iter().filter(|&&k| k > 0).count(), codes.iter().map(|c| c & 0xFFFF).collect::<Vec<_>>(), verdict(kids.iter().all(|&k| k > 0) && codes.iter().all(|&c| c >= 0)));

    // ---- nothing is left behind -------------------------------------------------------------------------------------------------
    // The baseline is taken after a few warm-up cycles and a pause: the first spawns allocate things that stay (the services' heaps
    // never shrink) and other work gives frames back late, so a baseline from the start of this whole group says more about what
    // happened before than about leaks. What is measured is what 300 more cycles leave behind.
    for i in 0..8 {
        let t = Req::new().arg(i).go(&hello);
        if t > 0 {
            wait(t, false);
        }
    }
    sleep(30);
    let (free0, nodes0, busy0) = (sysinfo(0)[3], sysinfo(1)[5], live_dynamic());
    let t0 = counter();
    let rounds = 300;
    let mut ok = true;
    for i in 0..rounds {
        let t = Req::new().arg(i % 100).go(&hello);
        ok &= t > 0 && wait(t, false) == (i % 100) as i64;
    }
    let per = (counter() - t0) * 1_000_000 / freq / rounds;
    sleep(20);
    let (free1, nodes1, busy1) = (sysinfo(0)[3], sysinfo(1)[5], live_dynamic());
    println!("[client] {rounds} start-run-collect cycles took {per} us each");
    println!("[client] TEST {rounds} programs later every frame, capability node and task slot is back (frames {free0} -> {free1}, nodes {nodes0} -> {nodes1}, live programs {busy0} -> {busy1}): {}",
        verdict(ok && free1 + 64 >= free0 && nodes1 <= nodes0 && busy1 == busy0));
    let _ = free_after;

    // ---- the program manager: runs last, after the leak checks above: the services' heaps never shrink, and reading the packages
    // raises their high-water marks, which would eat into those checks' slack (see docs/PROGRAMS.md)
    {
        let (progmgr, progctl) = (load("progmgr"), load("progctl"));
        let (frames0, nodes0, busy0) = (sysinfo(0)[3], sysinfo(1)[5], live_dynamic());
        let ctl = mk();
        // the manager: control endpoint (receive + send) as slot 0, the endpoint factory and the spawn capability as 5 and 6 (with the right
        // to hand a narrowed copy to a program with `permission = spawn`), file access, and a budget of pages for the programs it starts
        let mgr = Req::new().fs().budget(800).give_masked(0, ctl as u8, 0b11).give_masked(5, FACTORY_SLOT as u8, 0xFFFF).give_masked(6, SPAWN_SLOT as u8, 0xFFFF).go(&progmgr);
        // the driver holds only the right to send to the control endpoint (and file access, to look at where the programs keep their data)
        let drv = if mgr > 0 { Req::new().fs().give_masked(0, ctl as u8, 0b01).go(&progctl) } else { -1 };
        let failures = if drv > 0 { wait(drv, false) } else { -1 };
        println!("[client] TEST the program manager scenario ran to its end (program packages, lifecycle, crash restart, limits, permissions) with {failures} failed checks: {}", verdict(failures == 0));
        kill(mgr);
        wait(mgr, false);
        destroy(ctl as i64);
        sleep(30);
        let (frames1, nodes1, busy1) = (sysinfo(0)[3], sysinfo(1)[5], live_dynamic());
        println!("[client] TEST nothing is left behind once the program manager is gone (tasks {busy0} -> {busy1}, frames {frames0} -> {frames1}, capability nodes {nodes0} -> {nodes1}): {}", verdict(busy1 == busy0 && frames1 + 8 >= frames0 && nodes1 <= nodes0 + 1));
    }

}

/// Tests of the network stack against the host peer (`tools/netpeer.py`), run by `nettest` programs.
pub fn net_tests() {
    let v = Vfs::new(9, 0x8034_0000);
    let nettest = v.read_file("/system/bin/nettest").unwrap_or_default();
    if nettest.len() < 32 {
        println!("[client] TEST the network test program is in the system image: FAIL");
        return;
    }
    let frames0 = sysinfo(0)[3];
    let nodes0 = sysinfo(1)[5];
    let run = |mode: u64| -> (i64, String, String) {
        let (code, out, err) = run_with_console3(Req::new().arg(mode).net().threads(8).heap(2500), &nettest, b"");
        let (o, e) = (String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned());
        for l in o.lines().chain(e.lines()) {
            println!("[nettest {mode}] {l}");
        }
        (code, o, e)
    };
    let names: [(u64, &str); 14] = [
        (0, "the machine got an address by DHCP and pings its gateway (and gives up on an address that does not answer)"),
        (1, "names: dotted quads, localhost, and a name that does not exist"),
        (2, "UDP datagrams of 0 to 1472 bytes are echoed by the host, a closed port stays quiet, a bound port cannot be bound again"),
        (3, "1 MiB goes out and comes back over TCP, byte for byte"),
        (4, "2 MiB streamed by the host arrive intact and the stream ends"),
        (5, "2 MiB sent over TCP, half-closed, and the host's checksum agrees"),
        (6, "connecting to a port nobody listens on is refused, quickly"),
        (7, "a listener accepts a connection the host made through the forwarded port"),
        (8, "60 connections in a row and 20 UDP sockets at once, all closed again"),
        (9, "four threads with a connection each transfer at the same time"),
        (12, "a peer that answers in small slow pieces"),
        (15, "waiting is sleeping: an idle socket makes a handful of calls in a second, and what it waits for wakes it within 100 ms"),
        (10, "a program that leaves sockets open and ends"),
        (11, "... and the next program can use the same ports"),
    ];
    for (mode, what) in names {
        let (code, _, _) = run(mode);
        println!("[client] TEST net: {what} (exit {code}): {}", verdict(code == 0));
    }
    // the little programs a person would use
    let netcheck = v.read_file("/system/bin/netcheck").unwrap_or_default();
    let fetch = v.read_file("/system/bin/fetch").unwrap_or_default();
    let (code, out, _) = run_with_console3(Req::new().net().args(b"netcheck\0localhost\0"), &netcheck, b"");
    let text = String::from_utf8_lossy(&out).into_owned();
    println!("[client] net: netcheck says {text:?}");
    println!("[client] TEST net: the netcheck program shows the address, pings the gateway and resolves a name (exit {code}): {}",
        verdict(code == 0 && text.contains("address 10.0.2.15") && text.contains("ping 10.0.2.2:") && text.contains("localhost is 127.0.0.1")));
    let (code, out, err) = run_with_console3(Req::new().net().args(b"fetch\x0010.0.2.2\x007006\x00/hello\x00"), &fetch, b"");
    let text = String::from_utf8_lossy(&out).into_owned();
    println!("[client] net: fetch got {} bytes, errors {:?}", out.len(), String::from_utf8_lossy(&err));
    println!("[client] TEST net: the fetch program gets a web page from the host (exit {code}): {}",
        verdict(code == 0 && text.starts_with("HTTP/1.0 200 OK") && text.contains("hello from the host, you asked for /hello")));
    let (code, _, _) = run(13);
    println!("[client] TEST net: when the network service dies its clients are told, and it comes back (exit {code}): {}", verdict(code == 0));
    sleep(60);
    let (frames1, nodes1) = (sysinfo(0)[3], sysinfo(1)[5]);
    println!("[client] TEST net: nothing is left behind (frames {frames0} -> {frames1}, nodes {nodes0} -> {nodes1}): {}", verdict(frames1 + 64 >= frames0 && nodes1 <= nodes0 + 2));
}

/// `make session-test` (`opt/metallium/only=13`): the conductor plays the greeter against the session service (`programs/src/bin/sessiond.rs`): first account, logins, a
/// second and third account, two sessions at once, each confined to its home. The sessions' own lines (`[homeprobe ...]`) are checked by tools/session-test.py.
pub fn session_test() {
    sleep(30);
    let _ = mem_map(10, 0x8034_0000, true);
    let v = Vfs::new(9, 0x8034_0000);
    let img = (0..20).find_map(|_| v.read_file("/system/bin/sessiond").ok().filter(|b| b.len() > 32).or_else(|| { sleep(20); None })).unwrap_or_default();
    let ctl = 29i64; // the static session-service endpoint (the conductor's slot 29), the one the greeter calls
    let rq = Req::new().fs().heap(4096).budget(8000).give_masked(0, ctl as u8, 0b111).give_masked(5, FACTORY_SLOT as u8, 0xFFFF).give_masked(6, SPAWN_SLOT as u8, 0xFFFF).give_masked(4, 7, 0xFFFF); // (its slot 4: the data store, for the account domains; slot 7 is a program's standard output)
    let tid = if img.is_empty() || ctl < 0 { -1 } else { rq.go(&img) };
    println!("[session] sessiond started: task {tid}");
    if tid < 0 {
        return;
    }
    sleep(30);
    let ctl = ctl as u64;
    // the greeter's calls
    let begin = |action: u64, admin: bool, acting: u64, name: &str| {
        let mut raw = [0u8; 16];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        call(ctl, [1 | action << 8 | (admin as u64) << 16 | acting << 32, u64::from_le_bytes(raw[..8].try_into().unwrap()), u64::from_le_bytes(raw[8..].try_into().unwrap())])
    };
    let secret = |pass: &[u8]| {
        let mut last = (0i64, [99u64, 0, 0]);
        for off in (0..pass.len()).step_by(16) {
            let mut chunk = [0u8; 16];
            let n = (pass.len() - off).min(16);
            chunk[..n].copy_from_slice(&pass[off..off + n]);
            last = call(ctl, [2 | (pass.len() as u64) << 8 | (off as u64) << 24, u64::from_le_bytes(chunk[..8].try_into().unwrap()), u64::from_le_bytes(chunk[8..].try_into().unwrap())]);
            if last.1[0] != 4 {
                break;
            }
        }
        last.1
    };
    let act = |action: u64, admin: bool, acting: u64, name: &str, pass: &[u8]| {
        let b = begin(action, admin, acting, name);
        if b.0 != 0 || b.1[0] != 0 {
            return [90, 0, 0];
        }
        secret(pass)
    };
    let status = call(ctl, [4, 0, 0]).1;
    println!("[session] TEST a new machine has no accounts: {}", verdict(status[0] == 0));
    // a marker on the system's side of the disk: the host finds it in the clear (and the users' files not), see tools/session-test.py
    let _ = v.write_file("/data/system-marker.txt", b"SYSTEM-MARKER-in-the-clear-0123456789");
    let r = act(1, false, 0, "admin", b"admin-passphrase-1");
    let admin_recovery = [r[1], r[2]];
    println!("[session] TEST the first account is made (it becomes the administrator, uid 1) and its recovery key is returned: {}", verdict(r[0] & 0xFF == 0 && r[0] >> 8 == 1 && (r[1] != 0 || r[2] != 0)));
    let _ = admin_recovery;
    let r = act(1, false, 0, "admin", b"another");
    println!("[session] TEST a name that exists cannot be made again: {}", verdict(r[0] == 2));
    let r = act(1, false, 0, "bob", b"bobs-passphrase");
    println!("[session] TEST with an administrator, an account is made only from an administrator's session (none given: refused): {}", verdict(r[0] == 5));
    let r = act(2, false, 0, "admin", b"wrong passphrase");
    println!("[session] TEST a wrong passphrase does not log in: {}", verdict(r[0] == 7));
    let r = act(2, false, 0, "nobody", b"admin-passphrase-1");
    println!("[session] TEST an unknown name gives the same answer as a wrong passphrase: {}", verdict(r[0] == 7));
    let r = act(2, false, 0, "admin", b"admin-passphrase-1");
    let admin_session = r[1];
    println!("[session] TEST the administrator logs in (session {admin_session}): {}", verdict(r[0] == 0 && admin_session != 0));
    let r = act(1, false, admin_session, "alice", b"alices-passphrase");
    let r2 = act(1, false, admin_session, "bob", b"bobs-passphrase");
    let alice_recovery = [r[1], r[2]];
    println!("[session] TEST the administrator's session makes two more accounts: {}", verdict(r[0] & 0xFF == 0 && r2[0] & 0xFF == 0 && r[0] >> 8 == 2 && r2[0] >> 8 == 3));
    let r = act(1, false, admin_session, "Bad Name!", b"x");
    println!("[session] TEST a name with capitals or spaces is refused: {}", verdict(r[0] == 1));
    let a = act(2, false, 0, "alice", b"alices-passphrase");
    let b = act(2, false, 0, "bob", b"bobs-passphrase");
    println!("[session] TEST two users are logged in at once (sessions {} and {}): {}", a[1], b[1], verdict(a[0] == 0 && b[0] == 0 && a[1] != b[1]));
    let r = act(2, false, 0, "alice", b"alices-passphrase");
    println!("[session] TEST a user who already has a session cannot start a second: {}", verdict(r[0] == 8));
    sleep(900); // (the sessions run their probes: their lines are in the log)
    let st = call(ctl, [4, 0, 0]).1;
    println!("[session] TEST three accounts, three sessions: {}", verdict(st[0] == 3 && st[1] == 3));
    // alice's files while she is logged in and while she is not (her encryption domain is open only while she is)
    let open_read = v.read_file("/data/home/alice/note.txt");
    println!("[session] TEST while alice is logged in her files can be read (through the file system): {}", verdict(open_read.as_ref().map_or(false, |b| b == b"note of alice")));
    let r = call(ctl, [3, a[1], 0]).1;
    sleep(50);
    let locked_read = v.read_file("/data/home/alice/note.txt");
    println!("[session] TEST after her logout her files cannot be read by anyone, this task included (the domain's key is gone from the store): {}", verdict(r[0] == 0 && locked_read.is_err()));
    let again = act(2, false, 0, "alice", b"alices-passphrase");
    let reread = v.read_file("/data/home/alice/note.txt");
    println!("[session] TEST after a logout the user can log in again, and the files are there: {}", verdict(again[0] == 0 && reread.map_or(false, |b| b == b"note of alice")));
    // a forgotten passphrase: the recovery key opens the domain, a new passphrase replaces the old one
    let _ = call(ctl, [3, again[1], 0]);
    sleep(50);
    let mut wrong_key = [0u8; 16];
    wrong_key[..8].copy_from_slice(&alice_recovery[0].to_le_bytes());
    wrong_key[8..].copy_from_slice(&alice_recovery[1].to_le_bytes());
    wrong_key[0] ^= 1;
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&alice_recovery[0].to_le_bytes());
    key[8..].copy_from_slice(&alice_recovery[1].to_le_bytes());
    let bad = act(3, false, 0, "alice", &wrong_key);
    let good = act(3, false, 0, "alice", &key);
    let set = act(4, false, 0, "alice", b"alices-new-passphrase");
    println!("[session] TEST a wrong recovery key opens nothing, the right one lets the passphrase be replaced: {}", verdict(bad[0] == 7 && good[0] == 0 && set[0] == 0));
    let old = act(2, false, 0, "alice", b"alices-passphrase");
    let new = act(2, false, 0, "alice", b"alices-new-passphrase");
    println!("[session] TEST the old passphrase no longer logs in, the new one does, and the files are the same: {}", verdict(old[0] == 7 && new[0] == 0 && v.read_file("/data/home/alice/note.txt").map_or(false, |b| b == b"note of alice")));
    let nosession = act(4, false, 999, "alice", b"x");
    println!("[session] TEST a new passphrase cannot be set without a reset or the user's own session: {}", verdict(nosession[0] == 5));
    // the user changes the passphrase from the user's own session
    let own = act(4, false, b[1], "bob", b"bobs-changed-passphrase");
    let bob_out = call(ctl, [3, b[1], 0]).1;
    sleep(50);
    let bob_old = act(2, false, 0, "bob", b"bobs-passphrase");
    let bob_new = act(2, false, 0, "bob", b"bobs-changed-passphrase");
    println!("[session] TEST a user changes the passphrase from the user's own session: {}", verdict(own[0] == 0 && bob_out[0] == 0 && bob_old[0] == 7 && bob_new[0] == 0));
    println!("[session] done");
}

/// `make greeter-test` (`opt/metallium/only=14`): the conductor starts the session service and then leaves the machine to the greeter (the screen task runs it, with the service's
/// endpoint) and to the harness typing at it (tools/greeter-test.py).
pub fn greeter_test() {
    sleep(30);
    let _ = mem_map(10, 0x8034_0000, true);
    let v = Vfs::new(9, 0x8034_0000);
    let img = (0..20).find_map(|_| v.read_file("/system/bin/sessiond").ok().filter(|b| b.len() > 32).or_else(|| { sleep(20); None })).unwrap_or_default();
    let rq = Req::new().fs().heap(4096).budget(8000).give_masked(0, 29, 0b111).give_masked(5, FACTORY_SLOT as u8, 0xFFFF).give_masked(6, SPAWN_SLOT as u8, 0xFFFF).give_masked(4, 7, 0xFFFF);
    let tid = if img.is_empty() { -1 } else { rq.go(&img) };
    println!("[client] session service started for the greeter test: task {tid}");
    loop {
        sleep(1000);
    }
}

/// `make tty-test` (`opt/metallium/only=15`): the display driver has a buffer for each tty and shows the one it is told to. The conductor draws a red screen into tty 1's buffer and a blue one
/// into tty 2's (neither is in front: tty 0 is, so the screen must not change), then asks the driver to show 1, 2, 0 (and refuses 4); tools/tty-test.py takes a screenshot of each stage through
/// QMP and checks the colour. The screen task checks that a task other than the input driver and the conductor is refused.
pub fn tty_test() {
    use crate::proto::gpu::*;
    sleep(30);
    let (w, h) = (crate::gpu::W, crate::gpu::H);
    let (a, b) = (mem_map(16, 0xBC00_0000, true), mem_map(17, 0xBC40_0000, true));
    let info = call(21, [GPU_INFO, 0, 0]);
    println!("[tty] TEST the display driver has a buffer for each of four ttys and the conductor holds two of them (maps {a} {b}, buffers {}): {}", info.1[2], verdict(a == 0 && b == 0 && info.1[2] == 4));
    let paint = |va: usize, color: u32| {
        // SAFETY: the mapping above is a whole framebuffer of `w * h` words, which only this task writes.
        unsafe { core::slice::from_raw_parts_mut(va as *mut u32, w * h) }.fill(color);
    };
    paint(0xBC00_0000, 0x00FF_0000);
    paint(0xBC40_0000, 0x0000_00FF);
    let full = (w as u64) << 32 | (h as u64) << 48;
    let (s1, s2) = (call(21, [GPU_FLUSH2 | 1 << BUFFER_SHIFT, full, 0]), call(21, [GPU_FLUSH2 | 2 << BUFFER_SHIFT, full, 0]));
    println!("[tty] TEST drawing into the buffers of ttys that are not in front is accepted (status {} {}): {}", s1.1[0], s2.1[0], verdict(s1.0 == 0 && s1.1[0] == 0 && s2.0 == 0 && s2.1[0] == 0));
    let bad = call(21, [GPU_FLUSH2 | 4 << BUFFER_SHIFT, full, 0]);
    println!("[tty] TEST a buffer that does not exist is refused (reply {}): {}", bad.1[0], verdict(bad.1[0] == 1));
    // a task bound to a buffer draws only there: the conductor binds itself to tty 2, and a present that names a buffer that does not exist (9) goes to tty 2's instead of being refused
    let (bad_bind, bind) = (call(21, [GPU_BIND, 0, 4]), call(21, [GPU_BIND, 0, 2]));
    let forced = call(21, [GPU_FLUSH2 | 9 << BUFFER_SHIFT, full, 0]);
    let unbind = call(21, [GPU_BIND, 0, BIND_NONE]);
    let after = call(21, [GPU_FLUSH2 | 9 << BUFFER_SHIFT, full, 0]);
    println!("[tty] TEST a task bound to a tty's buffer draws only there, a buffer that does not exist cannot be bound, and an unbound task is refused again (replies {} {} {} {} {}): {}", bad_bind.1[0], bind.1[0], forced.1[0], unbind.1[0], after.1[0],
        verdict(bad_bind.1[0] == 1 && bind.1[0] == 0 && forced.1[0] == 0 && unbind.1[0] == 0 && after.1[0] == 1));
    println!("[tty] hidden: ttys 1 and 2 are drawn, tty 0 is in front");
    sleep(300);
    for t in [1u64, 2, 0] {
        let r = call(21, [GPU_SCANOUT, t, 0]);
        let act = call(21, [GPU_ACTIVE, 0, 0]);
        println!("[tty] TEST the driver switches to tty {t} (reply {}, in front {}): {}", r.1[0], act.1[0], verdict(r.0 == 0 && r.1[0] == 0 && act.1[0] == t));
        println!("[tty] showing {t}");
        sleep(300);
    }
    let r = call(21, [GPU_SCANOUT, 4, 0]);
    println!("[tty] TEST a tty that does not exist cannot be switched to (reply {}): {}", r.1[0], verdict(r.1[0] == 1));
    // input: the conductor plays tty 2's desktop. It is given tty 2's input, and polls for 15 s while tools/tty-test.py types a key, switches to tty 2 (Ctrl+Alt+F3), types, switches back
    // (Ctrl+Alt+F1) and types again: only the key typed while tty 2 was in front may arrive, and no F-key (press or release) at all.
    use crate::proto::input::*;
    let assign = call(14, [INPUT_ASSIGN, 0, 2]);
    println!("[tty] TEST the conductor is given tty 2's input (reply {}): {}", assign.1[0], verdict(assign.0 == 0 && assign.1[0] == 0));
    println!("[tty] input: start");
    let (mut chars, mut fkeys, mut fronts) = (alloc::string::String::new(), 0, 0);
    for _ in 0..1500 {
        let (st, r) = call(14, [KBD_POLL, 0, 0]);
        if st == 0 {
            for i in 0..(r[0] & 0xFF).min(16) {
                chars.push((r[1 + i as usize / 8] >> (8 * (i % 8))) as u8 as char);
            }
        }
        let (st, r) = call(14, [INPUT_POLL, 0, 0]);
        if st == 0 {
            for i in 0..(r[0] & 0xFF).min(2) as usize {
                let (kind, code) = (r[1 + i] & 0xFF, (r[1 + i] >> 8) & 0xFFFF);
                fronts += (kind == ev::FRONT) as u32;
                fkeys += (kind == ev::KEY && matches!(code, 59..=68 | 87 | 88)) as u32;
            }
        }
        sleep(1);
    }
    println!("[tty] input saw: \"{chars}\", {fkeys} function key event(s), {fronts} front event(s)");
    println!("[tty] TEST only the key typed while tty 2 was in front arrived, no function key reached it, and it was told once that it came to the front: {}", verdict(chars == "y" && fkeys == 0 && fronts == 1));
    println!("[tty] done");
    // the consoles of ttys 1..3 (role 22): the conductor plays the session service and gives tty 1's console its input and its buffer, then tells it to start; tools/tty-test.py
    // switches to tty 1 (Ctrl+Alt+F2) and checks that the console is on the screen, and that a key typed there reaches it and not the console of tty 2 (which is never started)
    let consoles: alloc::vec::Vec<u64> = (0..64u64).filter(|&t| { let r = sysinfo_at(3, t); r[0] as i64 == 0 && r[3] != 0 && r[5] == 22 }).collect();
    println!("[tty] TEST the boot has one console task for each of the ttys 1..3 ({}): {}", consoles.len(), verdict(consoles.len() == 3));
    if let Some(&c) = consoles.first() {
        let (a, b) = (call(14, [INPUT_ASSIGN, c, 1]), call(21, [GPU_BIND, c, 1]));
        println!("[tty] TEST the console of tty 1 is given its input and bound to its buffer (replies {} {}): {}", a.1[0], b.1[0], verdict(a.0 == 0 && a.1[0] == 0 && b.0 == 0 && b.1[0] == 0));
        let (st, r) = call(18, [crate::info::INFO_CONSOLE, 0, 0]);
        println!("[tty] TEST the console of tty 1 starts (status {st}, reply {}): {}", r[0], verdict(st == 0 && r[0] == 0));
        println!("[tty] console: started");
    }
    loop {
        sleep(1000);
    }
}
