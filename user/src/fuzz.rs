//! Syscall fuzzer (`fw_cfg opt/metallium/fuzz=<seed>`, `make fuzz`): role 17 calls every system call with
//! random and hostile arguments, holding a deliberately mixed set of capabilities (send rights to
//! most services, a MemCtl, a Sched, shared memory, one grantable capability). The conductor
//! (development mode 6) waits for it to finish and then checks what no single call could show:
//! the kernel is still up, no service was left dead, and the fuzzer's death returned every page it
//! ever held (the leak audit).
use crate::*;

const FUZZER_TID: u64 = 21;
const FUZZ_TICKS: u64 = 1500;
const MEMCTL: u64 = 18;
const SPAWN: u64 = 24;
const TASK_LOAD: u64 = 28;
const TASK_START: u64 = 29;
const WAIT_ID: u64 = 25;
const KILL: u64 = 26;
const CAP_REVOKE_ID: u64 = 6;
const IPC_RECV_ID: u64 = 2;
const EP_CREATE_ID: u64 = 27;
const SCHED: u64 = 23;
const RING_SETUP: u64 = 16;
const RING_ENTER: u64 = 17;
/// Slots the fuzzer holds (see the kernel's `boot_caps`, role 17).
const GRANTABLE: u64 = 0;
const SHM_SLOT: u64 = 3;
const SHM_VA: usize = 0x8034_0000;
const LEAK_SLACK_PAGES: u64 = 96;
const SPAWN_SLOT: u64 = 12;

/// Machine code that does something definite, for the images the fuzzer starts: exit(5); spin; sleep in a loop;
/// call SPAWN on itself with garbage; and plain random words.
const CODE: [&[u32]; 5] = [
    &[0xD280_0160, 0xD280_00A1, 0xD400_0001],                          // mov x0,#11; mov x1,#5; svc #0 (EXIT 5)
    &[0x1400_0000],                                                    // b .
    &[0xD280_0140, 0xD280_0061, 0xD400_0001, 0x17FF_FFFD],             // mov x0,#10; mov x1,#3; svc #0; b -3 words (SLEEP 3, for ever)
    &[0xD280_0300, 0xD280_0001, 0xD280_0002, 0xD400_0001, 0x17FF_FFFC], // mov x0,#24; ...; svc #0; b -4 words (SPAWN with junk)
    // THREAD_CREATE(entry = this loop, sp = own sp) over and over: every thread does the same, up to its allowance
    // (and sleeps a tick in between, so a program of nine such tasks does not starve everything else)
    &[0x1000_0001, 0xD280_03C0, 0x9100_03E2, 0xD280_0003, 0xD280_0004, 0xD400_0001, 0xD280_0140, 0xD280_0021, 0xD400_0001, 0x17FF_FFF7],
];

fn fuzz_spawn(rng: &mut u64, kids: &mut [i64; 8]) -> bool {
    // an image: header with sizes that are mostly sane, then code
    let mut img = [0u8; 8192];
    let code_end = [4096u64, 4096, 4096, 8192, 4096, 5000][(next(rng) % 6) as usize];
    let mem_size = [4096u64, 8192, 8192, 16384, 65536, 1 << 20][(next(rng) % 6) as usize];
    img[0..8].copy_from_slice(&0x4D4F_5355u64.to_le_bytes());
    img[8..16].copy_from_slice(&code_end.to_le_bytes());
    img[16..24].copy_from_slice(&mem_size.to_le_bytes());
    img[24..32].copy_from_slice(&next(rng).to_le_bytes());
    let pick = (next(rng) % 6) as usize;
    if pick < CODE.len() {
        for (i, w) in CODE[pick].iter().enumerate() {
            img[32 + 4 * i..36 + 4 * i].copy_from_slice(&w.to_le_bytes());
        }
    } else {
        for b in img[32..].iter_mut() {
            *b = next(rng) as u8;
        }
    }
    if next(rng) % 3 == 0 {
        // an ELF file instead: a header and up to three program headers, mostly sane values with hostile ones mixed in
        img.fill(0);
        img[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        img[4] = if next(rng) % 16 == 0 { 1 } else { 2 };
        img[5] = 1;
        img[6] = 1;
        img[16..18].copy_from_slice(&2u16.to_le_bytes());
        img[18..20].copy_from_slice(&(if next(rng) % 16 == 0 { 62u16 } else { 183 }).to_le_bytes());
        let entry = [0x8000_0100u64, 0x8000_0100, 0x8000_1000, 0x8000_0000, 0, 0x8010_0000][(next(rng) % 6) as usize];
        img[24..32].copy_from_slice(&entry.to_le_bytes());
        img[32..40].copy_from_slice(&64u64.to_le_bytes());
        img[54..56].copy_from_slice(&56u16.to_le_bytes());
        let n = 1 + (next(rng) % 3) as usize;
        img[56..58].copy_from_slice(&(if next(rng) % 16 == 0 { next(rng) as u16 } else { n as u16 }).to_le_bytes());
        for i in 0..n {
            let o = 64 + 56 * i;
            let ty = [1u32, 1, 1, 1, 3, 2, 0x6474_e551][(next(rng) % 7) as usize];
            let fl = [5u32, 4, 6, 6, 5, 7][(next(rng) % 6) as usize];
            let base = [0x8000_0000u64, 0x8000_1000, 0x8000_2000, 0x8000_0100, 0x8000_0000 + (next(rng) % 0xF0) * 0x1000, 0x7FFF_F000, u64::MAX - 0x100][(next(rng) % 7) as usize];
            let memsz = [0x1000u64, 0x2000, 0x10, 0x30000, 0, 1 << 40][(next(rng) % 6) as usize];
            let filesz = [0u64, 0x100, 0x1000, 0x2000, memsz][(next(rng) % 5) as usize];
            let off = [0u64, 0x100, 0x1000, 0x2000, 1 << 40][(next(rng) % 5) as usize];
            img[o..o + 4].copy_from_slice(&ty.to_le_bytes());
            img[o + 4..o + 8].copy_from_slice(&fl.to_le_bytes());
            img[o + 8..o + 16].copy_from_slice(&off.to_le_bytes());
            img[o + 16..o + 24].copy_from_slice(&base.to_le_bytes());
            img[o + 32..o + 40].copy_from_slice(&filesz.to_le_bytes());
            img[o + 40..o + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        // some code at the usual entry point
        for (i, w) in CODE[(next(rng) % 4) as usize].iter().enumerate() {
            img[0x100 + 4 * i..0x104 + 4 * i].copy_from_slice(&w.to_le_bytes());
        }
    }
    let len = [32u64, 36, 64, 4096, 4128, 8192][(next(rng) % 6) as usize];
    // the request block: mostly valid fields (class, heap pages, argument, delegation), some random
    let mut rq = [0u8; 96];
    rq[0..4].copy_from_slice(&(if next(rng) % 16 == 0 { next(rng) as u32 } else { 2 }).to_le_bytes());
    let allowance = if next(rng) % 2 == 0 { (1 + (next(rng) % 8) as u32) << 8 } else { 0 };
    rq[4..8].copy_from_slice(&(if next(rng) % 8 == 0 { next(rng) as u32 } else { allowance }).to_le_bytes());
    if next(rng) % 16 == 0 {
        rq[8..24].copy_from_slice(&[next(rng) as u8; 16]); // stale image fields: refused
    }
    rq[24..28].copy_from_slice(&((next(rng) % 4) as u32).to_le_bytes());
    rq[28..32].copy_from_slice(&((if next(rng) % 8 == 0 { next(rng) as u32 } else { 1 + (next(rng) % 64) as u32 })).to_le_bytes());
    rq[32..40].copy_from_slice(&next(rng).to_le_bytes());
    let args = [0u8; 64];
    rq[40..48].copy_from_slice(&(args.as_ptr() as u64).to_le_bytes());
    rq[48..56].copy_from_slice(&((if next(rng) % 8 == 0 { next(rng) % 2000 } else { next(rng) % 65 })).to_le_bytes());
    for i in 0..8 {
        rq[64 + 4 * i] = if next(rng) % 2 == 0 { 0xFF } else { (next(rng) % 32) as u8 };
        rq[66 + 4 * i..68 + 4 * i].copy_from_slice(&(next(rng) as u16).to_le_bytes());
    }
    // (through the loader, which sets the version and clears the image fields; the raw path is exercised below)
    let raw = rq[8] != 0 || rq[0] != 2 || next(rng) % 8 == 0;
    let t = if raw {
        svc(SPAWN, SPAWN_SLOT, rq.as_ptr() as u64, 0, 0, 0)[0] as i64
    } else {
        metallium_loader::spawn(|id, a1, a2, a3, a4| svc(id, a1, a2, a3, a4, 0)[0], SPAWN_SLOT, &mut rq, &img[..(len as usize).min(img.len())])
    };
    if t > 0 && raw {
        // an embryo made by hand: throw hostile loads and starts at it, then maybe let it start
        for _ in 0..4 {
            let mut r = [0u8; 24];
            let va = [0x8000_0000u64, 0x8000_1000, 0x8000_0008, 0x800F_F000, 0x7FFF_F000, u64::MAX - 4095, next(rng)][(next(rng) % 7) as usize];
            r[0..8].copy_from_slice(&va.to_le_bytes());
            r[8..16].copy_from_slice(&([img.as_ptr() as u64, img.as_ptr() as u64 + 3, next(rng), 0][(next(rng) % 4) as usize]).to_le_bytes());
            r[16..20].copy_from_slice(&([1u32, 1, 2, 300, 0, u32::MAX][(next(rng) % 6) as usize]).to_le_bytes());
            r[20..24].copy_from_slice(&((next(rng) % 4) as u32).to_le_bytes());
            let _ = svc(TASK_LOAD, t as u64, r.as_ptr() as u64, 0, 0, 0);
        }
        let _ = svc(TASK_START, t as u64, [0x8000_0000u64, 0x8000_1000, 0x8000_0002, next(rng)][(next(rng) % 4) as usize], 0, 0, 0);
    }
    let started = t > 0;
    if t > 0 {
        let at = (next(rng) % 8) as usize;
        if kids[at] > 0 {
            let _ = svc(KILL, kids[at] as u64, 0, 0, 0, 0);
            let _ = svc(WAIT_ID, kids[at] as u64, 1, 0, 0, 0);
        }
        kids[at] = t;
    }
    // poke at the children: wait without blocking, kill
    let k = kids[(next(rng) % 8) as usize];
    if k > 0 {
        if next(rng) % 2 == 0 {
            let _ = svc(WAIT_ID, k as u64, 1, 0, 0, 0);
        } else {
            let _ = svc(KILL, k as u64, 0, 0, 0, 0);
        }
    }
    started
}

fn next(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

/// An argument that is often meaningful (a slot, a small count, a plausible address) and sometimes hostile.
fn arg(rng: &mut u64, heap: u64) -> u64 {
    let r = next(rng);
    match r % 16 {
        0..=4 => (r >> 8) % 32,                                     // slots, task ids, small counts
        5 => 1 << ((r >> 8) % 64),                                  // powers of two
        6 => u64::MAX - (r >> 8) % 8192,                            // just below the wrap
        7 => (r >> 8) % 8,
        8 => [0x8000_0000, 0x8020_0000, 0x803F_F000, 0x8040_0000, 0x8100_0000, 0x8F00_0000][((r >> 8) % 6) as usize],
        9 => [0x4008_0000, 0x0900_0000, 0x0800_0000, 0xFFFF_0000_0000_0000, 0x4000_0000][((r >> 8) % 5) as usize], // kernel, devices, kernel half
        10 => SHM_VA as u64 + ((r >> 8) % 4) * 4096,
        11 => heap + ((r >> 8) % 8) * 4096 + (r >> 20) % 4096,
        12 => sysinfo(9)[2] as u64 - ((r >> 8) % 20) * 4096,           // the stack (and the guard page below it)
        13 => (r >> 8) & 0xFFF,
        _ => next(rng),
    }
}

pub fn fuzzer() -> ! {
    let seed = sysinfo(4)[1];
    println!("[fuzz] seed {seed}, {FUZZ_TICKS} ticks");
    let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    // something plausible to point the arguments at
    let _ = mem_map(SHM_SLOT, SHM_VA, true);
    let heap = svc(HEAP_GROW, 4, 0, 0, 0, 0)[0];
    let ring = svc(RING_SETUP, 0, 0, 0, 0, 0)[0];
    let start = ticks();
    let (mut calls, mut ok) = (0u64, 0u64);
    let mut kids = [0i64; 8];
    let mut started = 0u64;
    while ticks() - start < FUZZ_TICKS {
        for _ in 0..64 {
            let mut id = next(&mut rng) % 34;
            if id == EXIT || id == 0 {
                id = YIELD;
            }
            let mut a = [arg(&mut rng, heap), arg(&mut rng, heap), arg(&mut rng, heap), arg(&mut rng, heap), arg(&mut rng, heap)];
            match id {
                SLEEP => a[0] %= 3, // sleeping for ever is not interesting
                IPC_SEND => a[0] %= 12, // mostly the slots that hold endpoints
                IPC_CALL => {
                    // only the real servers must answer anything they are sent; the demo service and driver
                    // treat some operations as one-way, and a call to those never returns by design
                    a[0] = [2, 4, 10, 11, 5][(next(&mut rng) % 5) as usize];
                }
                // (grants go to program slots only: the program task's own tests would otherwise see capabilities it never had)
                CAP_GRANT => {
                    if next(&mut rng) % 4 != 0 {
                        a[0] = GRANTABLE;
                    }
                    a[1] = 27 + a[1] % 37;
                }
                RING_ENTER => {
                    // scribble in the ring page, then enter with small counts
                    if ring > 0 && ring < (1 << 48) {
                        let p = ring as *mut u32;
                        for _ in 0..(next(&mut rng) % 6) {
                            // SAFETY: `ring` is the page returned by RING_SETUP (checked > 0 and < 1<<48, so not an error code); the index is < 1024 words = 4096 bytes, one page. The kernel is the other party, so the deliberate scribbling is the test.
                            unsafe { write_volatile(p.add((next(&mut rng) % 1024) as usize), next(&mut rng) as u32) };
                        }
                    }
                    a[0] %= 4;
                    a[1] %= 4;
                }
                LOG => a[2] %= 300,
                MEMCTL => {
                    a[1] %= 7; // the real operations
                    if a[1] == 2 {
                        a[2] %= 40; // allocations of up to 40 pages
                    }
                }
                SCHED => a[0] %= 6,
                32 => a[2] = 1 + a[2] % 2, // WAIT_WORD: a wait that nobody wakes must end by itself
                WAIT_ID => a[1] = 1, // never block: a child that never ends would stop the fuzzer
                // (a receive on an endpoint the fuzzer itself made would wait for ever)
                IPC_RECV_ID => a[0] = 99,
                // (only the high slots: giving up one of the fuzzer's own service endpoints and then creating a fresh
                // endpoint in its place would make its "call the VFS" a call to itself, which waits for ever)
                CAP_REVOKE_ID => a[0] = 14 + a[0] % 17,
                SPAWN => a[0] = SPAWN_SLOT,
                EP_CREATE_ID => a[0] = 13,
                _ => {}
            }
            let r = svc(id, a[0], a[1], a[2], a[3], a[4]);
            calls += 1;
            ok += ((r[0] as i64) >= 0) as u64;
        }
        for _ in 0..3 {
            started += fuzz_spawn(&mut rng, &mut kids) as u64;
        }
        if next(&mut rng) % 8 == 0 {
            sleep(1); // let the other cores' services run
        }
    }
    println!("[fuzz] {calls} calls, {ok} succeeded, {started} programs started, done");
    exit(0)
}

/// The conductor's side (development mode 6).
pub fn conduct() {
    println!("[client] fuzz run: the conductor waits for the fuzzer");
    let t0 = ticks();
    let free0 = sysinfo(0)[3];
    let restarts0 = sysinfo(1)[4];
    let (nodes0, dyn0) = (sysinfo(1)[5], sysinfo(4)[2]);
    let mut done = false;
    while ticks() - t0 < FUZZ_TICKS + 3000 {
        sleep(20);
        if sysinfo_at(3, FUZZER_TID)[3] == 7 {
            done = true;
            break;
        }
    }
    println!("[client] TEST the fuzzer ran to its end (the kernel is still up): {}", verdict(done));
    sleep(200); // restarts and frees settle
    let dead: alloc::vec::Vec<u64> = [4u64, 5, 6, 7, 9, 12, 14, 20]
        .iter()
        .copied()
        .filter(|&t| sysinfo_at(3, t)[3] == 7)
        .collect();
    println!("[client] TEST no service was left dead (dead: {dead:?}): {}", verdict(dead.is_empty()));
    let (free1, restarts1) = (sysinfo(0)[3], sysinfo(1)[4]);
    println!("[client] fuzz: {} service restart(s) caused", restarts1 - restarts0);
    println!(
        "[client] TEST the fuzzer's death returned all its memory (free frames {free0} -> {free1}, slack {LEAK_SLACK_PAGES}): {}",
        verdict(free1 + LEAK_SLACK_PAGES >= free0)
    );
    let (nodes1, dyn1) = (sysinfo(1)[5], sysinfo(4)[2]);
    println!("[client] TEST capability nodes and dynamic memory objects are all back (nodes {nodes0} -> {nodes1}, objects {dyn0} -> {dyn1}): {}", verdict(nodes1 <= nodes0 && dyn1 <= dyn0));
    let programs = (28..64u64).filter(|&t| sysinfo_at(3, t)[3] != 0).count();
    println!("[client] TEST every program the fuzzer started is gone with it (live program slots: {programs}): {}", verdict(programs == 0));
    let alive = sysinfo_at(3, 0)[3] != 7;
    println!("[client] TEST the conductor itself survived: {}", verdict(alive));
}
