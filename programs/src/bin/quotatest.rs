#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use metallium_programs::*;

static SLEEPER: &[u8] = include_bytes!("../../build/sleeper.bin");

const MEMCTL: u64 = 18;
const MC_ALLOC: u64 = 2;
const MC_FREE: u64 = 3;

// Memory-limit tests, one per argument (the parent chooses the limits). Exit 0 = the limits held; otherwise a number
// saying which check failed. Modes 3 and 4 return their findings in the exit code instead.
//   0  runaway allocation: Vec after Vec until the allocator says no; stays inside the limit
//   1  the same without checking: allocates until the program is stopped (it must die alone)
//   2  contiguous allocations (memctl capability in slot 1) count against the same limit as the heap
//   3  starts programs (spawn capability in slot 0) until refused: count | error << 8, then proves the budget comes back
//   4  starts tiny programs until refused: the most a program may have at a time
//   5  grows its heap by 50 pages and sleeps (a child for the parent to resize)
program!("quotatest", |c| {
    match c.arg {
        0 => {
            let q = quota();
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let mut bytes = 0usize;
            loop {
                if chunks.try_reserve(1).is_err() {
                    break;
                }
                let mut b: Vec<u8> = Vec::new();
                if b.try_reserve_exact(16 * 1024).is_err() {
                    break;
                }
                b.resize(16 * 1024, 0xAB);
                bytes += b.len();
                chunks.push(b);
                if bytes > 64 << 20 {
                    return 1; // the limit did not stop it
                }
            }
            let q2 = quota();
            if q2.held > q2.limit || q2.limit != q.limit {
                return 2;
            }
            // nearly all of the limit was usable, none of it exceeded
            if (bytes / 4096) as u64 + 16 < q2.limit.saturating_sub(q.held) {
                return 3;
            }
            if chunks.iter().any(|b| b.iter().any(|&x| x != 0xAB)) {
                return 4;
            }
            0
        }
        1 => {
            let mut keep: Vec<Vec<u8>> = Vec::new();
            loop {
                let mut b: Vec<u8> = Vec::with_capacity(64 * 1024); // aborts when refused
                b.resize(64 * 1024, 1);
                keep.push(b);
            }
        }
        2 => {
            let mut got: Vec<i64> = Vec::with_capacity(128); // (so that pushing does not touch the heap)
            let q0 = quota();
            loop {
                let r = svc(MEMCTL, 1, MC_ALLOC, 16, 0, 0)[0] as i64;
                if r < 0 {
                    break;
                }
                got.push(r);
                if got.len() > 100 {
                    return 1;
                }
            }
            if got.is_empty() {
                return 2;
            }
            let q = quota();
            if q.held != q0.held + 16 * got.len() as u64 || q.limit - q.held >= 16 && got.len() < 12 {
                return 3; // counted wrongly, or refused while room was left (12 = capability slots free for it)
            }
            if heap_grow(q.limit - q.held + 1) >= 0 {
                return 4; // the heap must not get what the contiguous memory took
            }
            if svc(MEMCTL, 1, MC_FREE, got[0] as u64, 0, 0)[0] as i64 != 0 || quota().held != q.held - 16 {
                return 5;
            }
            if (svc(MEMCTL, 1, MC_ALLOC, 16, 0, 0)[0] as i64) < 0 || quota().held != q.held {
                return 6;
            }
            0
        }
        3 => {
            let mut kids: Vec<i64> = Vec::with_capacity(16);
            let q0 = quota();
            let mut err = 0i64;
            for _ in 0..8 {
                let t = spawn(0, &Spawn::new(SLEEPER));
                if t < 0 {
                    err = -t;
                    break;
                }
                kids.push(t);
            }
            let q = quota();
            let count = kids.len() as u64;
            // every child costs its heap (256 by default) plus its stack and tables
            if q.delegated - q0.delegated < count * 256 {
                return 0xFFFF_0001;
            }
            for &k in &kids {
                svc(KILL, k as u64, 0, 0, 0, 0);
            }
            for &k in &kids {
                svc(WAIT, k as u64, 0, 0, 0, 0);
            }
            if quota().delegated != q0.delegated || quota().children != 0 {
                return 0xFFFF_0002; // the budget did not come back
            }
            let again = spawn(0, &Spawn::new(SLEEPER));
            if again < 0 {
                return 0xFFFF_0003 | ((-again) as u64) << 32;
            }
            svc(KILL, again as u64, 0, 0, 0, 0);
            svc(WAIT, again as u64, 0, 0, 0, 0);
            count | (err as u64) << 8
        }
        4 => {
            let mut kids: Vec<i64> = Vec::new();
            let mut err = 0i64;
            for _ in 0..40 {
                let mut p = Spawn::new(SLEEPER);
                p.heap_pages = 1;
                let t = spawn(0, &p);
                if t < 0 {
                    err = -t;
                    break;
                }
                kids.push(t);
            }
            let count = kids.len() as u64;
            for &k in &kids {
                svc(KILL, k as u64, 0, 0, 0, 0);
            }
            for &k in &kids {
                svc(WAIT, k as u64, 0, 0, 0, 0);
            }
            count | (err as u64) << 8
        }
        _ => {
            heap_grow(50);
            loop {
                sleep(100);
            }
        }
    }
});
