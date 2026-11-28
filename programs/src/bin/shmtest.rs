#![no_std]
#![no_main]
extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use metallium_programs::*;

const MEMCTL: u64 = 18;
const MC_STATS: u64 = 0;
/// The large mapping window (0xA000_0000 .. 0xC000_0000).
const BIG: usize = 0xA000_0000;
const PAGE: usize = 4096;

/// # Safety
/// `va` must be a 4-aligned address inside an object this program has mapped and still has mapped. (Scenario 4 revokes an object
/// while it is in use on purpose, to see what the kernel does: that test accepts the fault.)
unsafe fn word(va: usize) -> &'static AtomicU32 {
    // SAFETY: the caller's contract.
    unsafe { &*(va as *const AtomicU32) }
}

fn pattern(i: usize, k: usize) -> u8 {
    (i.wrapping_mul(k)).wrapping_add(k) as u8
}

// Shared-memory tests, one per argument; the shared object, when there is one, is in slot 0. Exit 0 = ok, otherwise a
// number saying which check failed.
//   0  on its own: sizes, quota accounting, aliasing, slots running out, the limit on mappings
//   1  maps slot 0, checks page 0 holds pattern 7, writes pattern 5 into page 1
//   2  maps slot 0 and sleeps on its first word until the parent changes it and wakes it
//   3  slot 0 is read-only: a writable mapping is refused, a read-only one shows pattern 7
//   4  maps slot 0 and reads it for ever (it must die when the creator takes the memory back)
//   5  creates 64 pages, writes them, and exits without giving them back
//   6  creates an object bigger than the largest free run (a MemCtl capability is in slot 1)
//   7  a 16 MiB object: all of it usable, freed and created again
//   8  maps slot 0, writes a marker at offset 8 and exits (a holder going away must not free anything)
//   10 maps objects where the kernel chooses (address 0): inside the windows, apart, usable, random (prints the first address)
//   11 the page after an object mapped where the kernel chose is unmapped (must fault)
//   12 ... and the page before it (must fault)
//   13 the usual window is full: an object the kernel places goes to the large window
//   15 the usual window has exactly one gap that fits (5 pages for a 3-page object): the kernel finds it
//   14 started without the right to name addresses: a mapping at an address of its own is refused (-1), one at 0 works
//   9  makes an 8-page object, fills it, gives it to the parent (exit code = its slot there) and exits
program!("shmtest", |c| {
    match c.arg {
        0 => {
            if shm_create(0) != -5 || shm_create(65537) != -5 {
                return 1;
            }
            let held0 = quota().held;
            let s = shm_create(3);
            if s < 0 || quota().held != held0 + 3 {
                return 2;
            }
            let s = s as u64;
            // zero filled, readable and writable, 4 KiB aligned windows only
            if map(s, BIG + 1, true) != -5 || map(s, 0x8200_0000, true) != -5 || map(s, 0xC000_0000 - PAGE, true) != -5 {
                return 3;
            }
            if map(s, BIG, true) != 0 {
                return 4;
            }
            // SAFETY: the 3-page object was just mapped writable at BIG (`map` returned 0), so BIG..BIG + 3 pages is mapped, writable and exclusively ours here.
            let mem = unsafe { core::slice::from_raw_parts_mut(BIG as *mut u8, 3 * PAGE) };
            if mem.iter().any(|&b| b != 0) {
                return 5;
            }
            for (i, b) in mem.iter_mut().enumerate() {
                *b = pattern(i, 7);
            }
            // the same memory mapped twice at once is the same memory
            if map(s, BIG + 0x10_0000, true) != 0 {
                return 6;
            }
            // SAFETY: both mappings of the same object (BIG and BIG + 0x10_0000) succeeded above (`map` returned 0), so the address is 4-aligned and inside a live mapping.
            unsafe { word(BIG + 0x10_0000 + 4) }.store(0xCAFE_F00D, Ordering::SeqCst);
            // SAFETY: BIG was mapped above (`map` returned 0) and the address is 4-aligned and inside it.
            if unsafe { word(BIG + 4) }.load(Ordering::SeqCst) != 0xCAFE_F00D {
                return 7;
            }
            // an address already mapped cannot be mapped over
            if map(s, BIG + PAGE, true) != -5 {
                return 8;
            }
            // more mappings than the table has entries is refused politely (the object is one page here)
            let one = shm_create(1);
            if one < 0 {
                return 9;
            }
            let mut ok = 0;
            let mut last = 0;
            for i in 0..300 {
                last = map(one as u64, BIG + 0x40_0000 + i * PAGE, true);
                if last == 0 {
                    ok += 1;
                } else {
                    break;
                }
            }
            if ok < 200 || last != -8 {
                return 10;
            }
            // too little memory left under the limit is refused without side effects
            let limit = quota().limit;
            let held = quota().held;
            if shm_create(limit - held + 1) != -8 || quota().held != held {
                return 11;
            }
            // giving the memory back returns the charge; the mapping is gone with it
            if revoke_self(one as u64) < 0 || revoke_self(s) < 0 || quota().held != held0 {
                return 12;
            }
            // capability slots run out cleanly
            let mut made = 0;
            let mut err = 0;
            let mut slots = [0i64; 32];
            for _ in 0..32 {
                let r = shm_create(1);
                if r < 0 {
                    err = r;
                    break;
                }
                slots[made] = r;
                made += 1;
            }
            if made == 0 || err != -3 {
                return 13;
            }
            for &r in &slots[..made] {
                revoke_self(r as u64);
            }
            if quota().held != held0 || shm_create(1) < 0 {
                return 14;
            }
            0
        }
        10 => {
            let mut at = [0usize; 12];
            for (i, a) in at.iter_mut().enumerate() {
                let s = shm_create(3);
                let va = if s >= 0 { map_anywhere(s as u64, true) } else { s };
                let small = (0x8020_0000..0x8040_0000).contains(&(va as usize)) && va as usize + 3 * PAGE <= 0x8040_0000;
                let big = (0xA000_0000..0xC000_0000).contains(&(va as usize)) && va as usize + 3 * PAGE <= 0xC000_0000;
                if va < 0 || va as usize % PAGE != 0 || !(small || big) {
                    return 1;
                }
                *a = va as usize;
                // usable, and each object is its own memory
                // SAFETY: `*a` was just returned by `map_anywhere` for a 3-page writable object and checked page-aligned and inside a window.
                unsafe { core::ptr::write_volatile(*a as *mut u32, 0xA0 + i as u32) };
            }
            // SAFETY: every `a` is a mapped, page-aligned object start from the loop above (nothing was unmapped in between).
            if at.iter().enumerate().any(|(i, &a)| unsafe { core::ptr::read_volatile(a as *const u32) } != 0xA0 + i as u32) {
                return 2;
            }
            let mut sorted = at;
            sorted.sort();
            if sorted.windows(2).any(|w| w[1] < w[0] + 4 * PAGE) {
                return 3; // an object is 3 pages and a gap of at least one page lies between two
            }
            // a large object goes to the large window
            let s = shm_create(200);
            let va = if s >= 0 { map_anywhere(s as u64, true) } else { s };
            if va < 0 || !(0xA000_0000..0xC000_0000).contains(&(va as usize)) || va as usize % PAGE != 0 {
                return 4;
            }
            // SAFETY: `va` maps a 200-page writable object (checked page-aligned, in the large window); page 199 is its last page.
            unsafe { core::ptr::write_volatile((va as usize + 199 * PAGE) as *mut u8, 1) };
            println!("automap first={:#x} large={:#x}", at[0], va);
            0
        }
        11 | 12 => {
            let s = shm_create(3);
            let va = if s >= 0 { map_anywhere(s as u64, true) } else { s };
            if va < 0 {
                return 1;
            }
            // (the object is usable, so a fault below is the neighbour's)
            // SAFETY: `va` is the start of a freshly mapped writable 3-page object (`va >= 0` checked).
            unsafe { core::ptr::write_volatile(va as *mut u8, 1) };
            let at = if c.arg == 11 { va as usize + 3 * PAGE } else { va as usize - PAGE };
            // SAFETY: deliberately not sound: `at` is the unmapped guard page just after (scenario 11) or before (12) the object, so this read must fault and kill the program; that is the test.
            let v = unsafe { core::ptr::read_volatile(at as *const u8) };
            println!("shmtest {}: the neighbouring page is readable ({v})", c.arg);
            0
        }
        13 => {
            // fill the usual window but for a page or two with an object of the program's own choosing of address
            let big = shm_create(510);
            if big < 0 || map(big as u64, 0x8020_0000, true) != 0 {
                return 1;
            }
            for _ in 0..2 {
                let s = shm_create(3);
                let va = if s >= 0 { map_anywhere(s as u64, true) } else { s };
                if va < 0 || !(0xA000_0000..0xC000_0000).contains(&(va as usize)) {
                    return 2;
                }
                // SAFETY: `va` maps a 3-page writable object (checked in the window); page 2 is its last page.
                unsafe { core::ptr::write_volatile((va as usize + 2 * PAGE) as *mut u8, 1) };
            }
            0
        }
        15 => {
            let (a, b) = (shm_create(250), shm_create(257)); // (the second reaches the end of the window)
            if a < 0 || b < 0 || map(a as u64, 0x8020_0000, true) != 0 || map(b as u64, 0x8020_0000 + 255 * PAGE, true) != 0 {
                return 1;
            }
            let s = shm_create(3);
            let va = if s >= 0 { map_anywhere(s as u64, true) } else { s };
            if va != (0x8020_0000 + 251 * PAGE) as i64 {
                return 2;
            }
            0
        }
        14 => {
            let s = shm_create(1);
            if s < 0 || map(s as u64, BIG, true) != -1 {
                return 1;
            }
            let va = map_anywhere(s as u64, true);
            if va < 0 {
                return 2;
            }
            // SAFETY: `va` is the start of the 1-page writable object just mapped (`va >= 0` checked).
            unsafe { core::ptr::write_volatile(va as *mut u8, 1) };
            0
        }
        1 => {
            if map(0, BIG, true) != 0 {
                return 1;
            }
            // SAFETY: slot 0 is the parent's 2-page object (user/src/programs.rs) and `map` returned 0, so BIG..+2 pages is mapped and writable.
            let mem = unsafe { core::slice::from_raw_parts_mut(BIG as *mut u8, 2 * PAGE) };
            if (0..PAGE).any(|i| mem[i] != pattern(i, 7)) {
                return 2;
            }
            for i in 0..PAGE {
                mem[PAGE + i] = pattern(i, 5);
            }
            0
        }
        2 => {
            if map(0, BIG, true) != 0 {
                return 1;
            }
            // SAFETY: slot 0 was just mapped at BIG (`map` returned 0), so BIG is 4-aligned and inside a live mapping.
            let w = unsafe { word(BIG) };
            let t0 = ticks();
            let r = metallium_programs::thread::wait_word(w, 0, 300);
            let dt = ticks() - t0;
            if r != 0 || w.load(Ordering::SeqCst) != 1 {
                return 2;
            }
            if !(20..100).contains(&dt) {
                return 3; // not asleep for the 30 ticks before the wake-up, or not woken by it
            }
            0
        }
        3 => {
            if map(0, BIG, true) != -1 {
                return 1;
            }
            if map(0, BIG, false) != 0 {
                return 2;
            }
            // SAFETY: the read-only mapping of slot 0 (at least one page) succeeded (`map` returned 0), so BIG..+PAGE is mapped and readable.
            let mem = unsafe { core::slice::from_raw_parts(BIG as *const u8, PAGE) };
            if (0..PAGE).any(|i| mem[i] != pattern(i, 7)) {
                return 3;
            }
            0
        }
        4 => {
            if map(0, BIG, true) != 0 {
                return 1;
            }
            loop {
                // SAFETY: the `pages`-page object was mapped at BIG (`map` returned 0 above), and `p < pages`, so the 4-aligned address is inside the mapping.
                let _ = unsafe { word(BIG) }.load(Ordering::SeqCst);
                sleep(1);
            }
        }
        5 => {
            let s = shm_create(64);
            if s < 0 || map(s as u64, BIG, true) != 0 {
                return 1;
            }
            // SAFETY: the 64-page object was just mapped writable at BIG (`map` returned 0), so the whole range is ours to write.
            unsafe { core::ptr::write_bytes(BIG as *mut u8, 0x5A, 64 * PAGE) };
            0
        }
        6 => {
            let largest = svc(MEMCTL, 1, MC_STATS, 0, 0, 0)[2] as usize;
            let pages = largest + 1;
            if !(2..=4096).contains(&pages) {
                return 1; // (the machine is not fragmented, or the run is larger than an object may be: nothing to show)
            }
            let s = shm_create(pages as u64);
            if s < 0 {
                return 2;
            }
            if map(s as u64, BIG, true) != 0 {
                return 3;
            }
            for p in 0..pages {
                // SAFETY: the `pages`-page object is mapped at BIG and `p < pages`, so the 4-aligned address is inside the mapping.
                unsafe { word(BIG + p * PAGE) }.store(p as u32 ^ 0x5555, Ordering::SeqCst);
            }
            // SAFETY: as above: `p < pages`, inside the mapping at BIG.
            if (0..pages).any(|p| unsafe { word(BIG + p * PAGE) }.load(Ordering::SeqCst) != p as u32 ^ 0x5555) {
                return 4;
            }
            0
        }
        7 => {
            for round in 0..2u32 {
                let s = shm_create(4096);
                if s < 0 || map(s as u64, BIG, true) != 0 {
                    return 1;
                }
                // SAFETY: the 4096-page object was mapped at BIG (`map` returned 0), so BIG is 4-aligned and inside it.
                unsafe { word(BIG) }.store(round + 1, Ordering::SeqCst);
                // SAFETY: the last word, BIG + 4096 * PAGE - 4, is 4-aligned and inside the 4096-page mapping.
                unsafe { word(BIG + 4096 * PAGE - 4) }.store(!round, Ordering::SeqCst);
                // SAFETY: both addresses (first and last word) are 4-aligned and inside the live 4096-page mapping; `revoke_self` runs only afterwards.
                if unsafe { word(BIG) }.load(Ordering::SeqCst) != round + 1 || unsafe { word(BIG + 4096 * PAGE - 4) }.load(Ordering::SeqCst) != !round {
                    return 2;
                }
                if revoke_self(s as u64) < 0 {
                    return 3;
                }
            }
            0
        }
        8 => {
            if map(0, BIG, true) != 0 {
                return 1;
            }
            // SAFETY: slot 0 was mapped at BIG (`map` returned 0), so BIG + 8 is 4-aligned and inside the mapping.
            unsafe { word(BIG + 8) }.store(0x600D, Ordering::SeqCst);
            0
        }
        9 => {
            // make an object, fill it, give it to the parent and exit: the creator goes, the parent keeps the memory
            let s = shm_create(8);
            if s < 0 || map(s as u64, BIG, true) != 0 {
                return 100;
            }
            // SAFETY: the 8-page object was just mapped writable at BIG (`map` returned 0).
            let mem = unsafe { core::slice::from_raw_parts_mut(BIG as *mut u8, 8 * PAGE) };
            for (i, b) in mem.iter_mut().enumerate() {
                *b = pattern(i, 9);
            }
            match ipc::grant(s as u64, c.parent, 8 | 16) {
                Ok(slot) => slot, // the slot in the parent's table is the exit code
                Err(_) => 101,
            }
        }
        _ => 99,
    }
});
