//! The page-compaction daemon (role 9) and the conductor's memory-pressure test.
//!
//! Division of labour: the kernel provides the *mechanism* (relocating a movable
//! page without losing a concurrent access, contiguous allocation, statistics);
//! this task is the *policy*. It does nothing until the kernel has recorded failed
//! contiguous-allocation requests, then compacts in small bounded batches with a
//! pause between them, so the kernel lock is never held long and CPU use stays low.
use crate::*;

const MEMCTL: u64 = 18;
const HEAP_RELEASE: u64 = 19;
const MC_STATS: u64 = 0;
const MC_COMPACT: u64 = 1;
const MC_ALLOC: u64 = 2;
const MC_FREE: u64 = 3;
const MCF_DIRECT: u64 = 1;
const MC_SWAP_OUT: u64 = 4;
const MC_SWAP_STATS: u64 = 5;
const MC_SWAP_WRITEBACK: u64 = 9;
const MCS_FORCE: u64 = 1;
const MCS_SELF: u64 = 2;
const MCS_HEAP: u64 = 4;
/// Memory policy (`metallium_compact::policy`, host-tested): below the low mark of free frames, push cold pages into the compressed swap store until the
/// high mark is free. With a pager registered (swap to disk is set up: an interactive system) the marks scale with the machine's memory; without one only
/// the emergency reserve applies (well under the 96 frames the compaction test leaves free, so that test is unaffected).
use metallium_compact::policy::{self, Marks};

fn current_marks() -> Marks {
    let pager_running = sysinfo(16)[2] >> 16 & 1 != 0;
    if pager_running { policy::marks(sysinfo(0)[2]) } else { policy::EMERGENCY }
}

/// The size of the kernel's compressed store (SYSINFO page 17).
fn pool_bytes() -> u64 {
    sysinfo(17)[0]
}
/// Where this program's heap window starts (randomised per program: SYSINFO page 9).
fn heap_base() -> u64 {
    sysinfo(9)[1]
}
const PAGE: usize = 4096;

#[derive(Clone, Copy)]
struct MemStats {
    free: u64,
    largest: u64,
    failures: u64,
    migrated: u64,
    runs: u64,
}

/// Number of faults the kernel retried because they raced with a page migration.
fn retried_faults(slot: u64) -> u64 {
    svc(MEMCTL, slot, MC_STATS, 0, 0, 0)[0]
}

fn stats(slot: u64) -> MemStats {
    let r = svc(MEMCTL, slot, MC_STATS, 0, 0, 0);
    MemStats { free: r[1], largest: r[2], failures: r[3], migrated: r[4], runs: r[5] }
}

#[derive(Clone, Copy)]
struct SwapStats {
    stored: u64,
    bytes: u64,
    out: u64,
    back: u64,
    full: u64,
    touched: u64,
}

fn swap_stats(slot: u64) -> SwapStats {
    let r = svc(MEMCTL, slot, MC_SWAP_STATS, 0, 0, 0);
    SwapStats { stored: r[0], bytes: r[1], out: r[2], back: r[3], full: r[4], touched: r[5] }
}

/// Evict up to `budget` pages; returns the number evicted.
fn swap_out(slot: u64, budget: u64, flags: u64) -> u64 {
    svc(MEMCTL, slot, MC_SWAP_OUT, budget, flags, 0)[0]
}

/// The memory-pressure policy: a few clock passes (the first ages pages, the next evict the ones that stayed
/// cold), forcing eviction only when memory is nearly gone.
fn relieve_pressure(free: u64, high: u64) {
    let before = swap_stats(0);
    let mut evicted = 0;
    for round in 0..40 {
        let f = stats(0).free;
        if f >= high {
            break;
        }
        let force = if f < 8 || round >= 20 { MCS_FORCE } else { 0 };
        let n = swap_out(0, 64, force);
        evicted += n;
        if n == 0 && force != 0 {
            break; // nothing left to evict, or the store is full
        }
        if n == 0 {
            sleep(1); // give pages a moment to be touched (or not) between passes
        }
    }
    let after = swap_stats(0);
    println!("[compactd] memory pressure ({free} frames free): swapped out {evicted} cold pages, store holds {} pages in {} bytes, {} frames free",
        after.stored, after.bytes, stats(0).free);
    let _ = before;
}

/// Returns (pages moved, pass finished).
fn compact(slot: u64, budget: u64) -> (u64, bool) {
    let r = svc(MEMCTL, slot, MC_COMPACT, budget, 0, 0);
    (r[0], r[1] != 0)
}

// ---------------------------------------------------------------------------
// role 9: compactd
// ---------------------------------------------------------------------------
pub fn compactd() -> ! {
    println!("[compactd] up: demand-driven, compacts only after contiguous allocations fail");
    let mut seen = stats(0).failures;
    loop {
        let s = stats(0);
        if s.failures != seen {
            println!("[compactd] {} failed contiguous allocation(s): {} free frames in {} runs, largest run {}; compacting",
                s.failures - seen, s.free, s.runs, s.largest);
            seen = s.failures; // failures that arrive while we work trigger another pass
            let (mut moved, mut batches) = (0u64, 0u32);
            loop {
                let (m, done) = compact(0, 64);
                moved += m;
                batches += 1;
                if done {
                    break;
                }
                sleep(1); // yield the CPU (and the kernel lock) between batches
            }
            let a = stats(0);
            println!("[compactd] pass complete: {moved} pages migrated in {batches} batches; largest free run {} -> {}", s.largest, a.largest);
        }
        let marks = current_marks();
        if s.free < marks.low {
            relieve_pressure(s.free, marks.high);
        }
        // the compressed store is the first tier; when it is three quarters full, ask for its coldest pages to be written to
        // disk by the pager (nothing happens if there is none)
        let store = swap_stats(0);
        let pool = pool_bytes();
        if policy::store_needs_writeback(store.bytes, pool) && svc(MEMCTL, 0, MC_SWAP_WRITEBACK, 16, 0, 0)[0] as i64 == 0 {
            println!("[compactd] swap store {}% full: asked the pager to write 16 pages to disk", store.bytes * 100 / pool);
        }
        sleep(10);
    }
}

// ---------------------------------------------------------------------------
// conductor-side test
// ---------------------------------------------------------------------------

/// Distinct, position-dependent contents so a mis-copied or mis-mapped page is detected.
fn stamp(page: usize, id: u64) {
    let p = (heap_base() as usize + page * PAGE) as *mut u64;
    for j in 0..PAGE / 8 {
        // SAFETY: `p` is page `page` of this task's heap window (pages obtained from HEAP_GROW by the callers); j < PAGE/8 keeps the u64 write inside it.
        unsafe { write_volatile(p.add(j), (id.wrapping_mul(0x9E37_79B9_7F4A_7C15)) ^ (j as u64).wrapping_mul(0x0100_0000_01B3)) };
    }
}

fn check(page: usize, id: u64) -> bool {
    let p = (heap_base() as usize + page * PAGE) as *const u64;
    // SAFETY: same heap page as `stamp`, 8-aligned, j < PAGE/8; volatile so the compactor's migration is really observed.
    (0..PAGE / 8).all(|j| unsafe { read_volatile(p.add(j)) } == (id.wrapping_mul(0x9E37_79B9_7F4A_7C15)) ^ (j as u64).wrapping_mul(0x0100_0000_01B3))
}

const RESERVE: u64 = 96; // frames left free: less than the 128 we will ask for
const WANT: u64 = 128;
const MAP_VA: usize = 0x8038_0000;

/// Grow the heap until only `RESERVE` frames are free. Returns the first new page index and count.
/// (No allocation here: the heap allocator must not need memory while memory is exhausted.)
fn fill() -> Option<(usize, usize)> {
    let mut first = None;
    let mut count = 0usize;
    loop {
        let s = stats(11);
        if s.free <= RESERVE {
            return first.map(|f| (f, count));
        }
        let chunk = (s.free - RESERVE).min(256);
        let base = svc(HEAP_GROW, chunk, 0, 0, 0, 0)[0] as i64;
        if base < 0 {
            return None; // quota exhausted before memory was: RAM too large to fragment this way
        }
        let idx = (base as u64 - heap_base()) as usize / PAGE;
        let f = *first.get_or_insert(idx);
        if idx != f + count {
            return None; // not contiguous with our earlier pages (something else grew the heap)
        }
        count += chunk as usize;
    }
}

fn release(page: usize) {
    svc(HEAP_RELEASE, page as u64, 1, 0, 0, 0);
}

/// `ids[p]` of page `first + p` is `p as u64 + salt`; live pages are those with `live(p)`.
fn verify(first: usize, count: usize, salt: u64, live: impl Fn(usize) -> bool) -> (usize, bool) {
    let mut n = 0;
    for p in 0..count {
        if live(p) {
            if !check(first + p, p as u64 + salt) {
                return (n, false);
            }
            n += 1;
        }
    }
    (n, true)
}

/// Verify pages `lo..hi` of a block of `count` pages starting at heap page `first`.
fn verify_range(first: usize, _count: usize, lo: usize, hi: usize, salt: u64, live: impl Fn(usize) -> bool) -> bool {
    (lo..hi).all(|p| !live(p) || check(first + p, p as u64 + salt))
}

/// Can this task use up the machine's free memory with its own heap? The tests of what happens at the end of memory mean nothing if not, and trying would use up
/// the task's whole quota (the heap that was grown and released still counts against it) and leave every later allocation of the conductor to fail: on a larger
/// machine (2 GiB, say, against a quota of 60 000 pages) they are skipped.
fn can_exhaust() -> bool {
    let q = svc(36, 0, 0, 0, 0, 0); // QUOTA: limit, held
    stats(11).free < q[0].saturating_sub(q[1])
}

pub fn compaction_tests() {
    if !can_exhaust() {
        println!("[client] TEST memory compaction: SKIPPED (RAM too large to exhaust with this task's quota; run with -m 64M)");
        return;
    }
    let Some((first, count)) = fill() else {
        println!("[client] TEST memory compaction: SKIPPED (RAM too large to exhaust with this task's quota; run with -m 64M)");
        return;
    };
    for p in 0..count {
        stamp(first + p, p as u64 + 1);
    }
    let s = stats(11);
    println!("[client] TEST memory pressure: {} pages ({} MiB) held, {} frames left free: {}", count, count * PAGE >> 20, s.free,
        verdict(count > 1000 && s.free <= RESERVE));

    // Fragment: free every other page. Free memory is now plentiful but in isolated single frames.
    for p in (1..count).step_by(2) {
        release(first + p);
    }
    let s1 = stats(11);
    println!("[client] TEST fragmentation: {} free frames in {} runs, largest run {} (< {WANT}): {}", s1.free, s1.runs, s1.largest,
        verdict(s1.free >= WANT && s1.largest < WANT));

    let fail0 = s1.failures;
    let r = svc(MEMCTL, 11, MC_ALLOC, WANT, 0, 0)[0] as i64;
    let s2 = stats(11);
    println!("[client] TEST contiguous {} KiB allocation fails on fragmented memory (result {r}, failures {} -> {}): {}", WANT as usize * PAGE / 1024,
        fail0, s2.failures, verdict(r == E_NOMEM && s2.failures == fail0 + 1));

    // Shared memory is made of single frames: an object larger than the largest free run can still be created, mapped and used
    let want = s2.largest as u64 + 1;
    let sh = svc(37, want, 0, 0, 0, 0)[0] as i64;
    let base = 0xA000_0000usize;
    let mapped = sh >= 0 && svc(4, sh as u64, base as u64, 1, 0, 0)[0] == 0;
    let intact = mapped && {
        for p in 0..want as usize {
            // SAFETY: `base` is the object mapped (checked via `mapped`) at 0xA000_0000 with `want` pages; p < want, so the u32 lies in the object.
            unsafe { core::ptr::write_volatile((base + p * PAGE) as *mut u32, p as u32 ^ 0x5A5A) };
        }
        // SAFETY: same mapped `want`-page object as the writes above.
        (0..want as usize).all(|p| unsafe { core::ptr::read_volatile((base + p * PAGE) as *const u32) } == p as u32 ^ 0x5A5A)
    };
    println!("[client] TEST shared memory needs no contiguous run: {want} pages made while the largest free run is {} ({} created, mapped {mapped}): {}", s2.largest,
        if sh >= 0 { "was" } else { "not" }, verdict(sh >= 0 && intact));
    if sh >= 0 {
        svc(6, sh as u64, 1, 0, 0, 0);
    }

    // compactd notices the failure and compacts. Wait for contiguity to appear.
    let (t0, mig0) = (ticks(), s2.migrated);
    // While it works, keep reading every surviving page: some of those reads race with a page
    // being moved (on another core), and must still see the right data.
    // The compactor takes pages from the lowest physical addresses first, which are the
    // highest heap indices (movable pages are allocated downwards): hammer those in a tight
    // loop, and sweep the rest occasionally.
    let hot = count.saturating_sub(256);
    let mut s3 = s2;
    let (mut sweeps, mut sweeps_ok) = (0u32, true);
    let one_cpu = svc(20, 0, 0, 0, 0, 0)[0] == 1;
    while s3.largest < WANT && ticks() - t0 < 1000 {
        if one_cpu {
            // compactd is Background work and this loop never blocks: with no other core to run it on, it
            // would get the CPU only through the aging rule (a turn every 250 ms)
            sleep(1);
        }
        for _ in 0..200 {
            sweeps_ok &= verify_range(first, count, hot, count, 1, |p| p % 2 == 0);
        }
        sweeps_ok &= verify(first, count, 1, |p| p % 2 == 0).1;
        sweeps += 1;
        s3 = stats(11);
    }
    println!("[client] TEST compactd restores contiguity (largest free run {} -> {}, {} pages migrated, {} ticks): {}", s2.largest, s3.largest,
        s3.migrated - mig0, ticks() - t0, verdict(s3.largest >= WANT && s3.migrated > mig0));

    println!("[client] TEST every page read during migration held its data ({sweeps} full sweeps plus {} tight loops over the pages moving first, {} faults raced with a move and were retried): {}",
        sweeps * 200, retried_faults(11), verdict(sweeps_ok && sweeps > 0));

    // Let compactd finish its pass, then every surviving page must still hold exactly its data.
    sleep(30);
    let (n, ok) = verify(first, count, 1, |p| p % 2 == 0);
    println!("[client] TEST pages relocated by the compactor keep their contents ({n} pages verified): {}", verdict(ok && n > 500));

    // Use the contiguous memory.
    let slot = svc(MEMCTL, 11, MC_ALLOC, WANT, 0, 0)[0] as i64;
    let mut good = slot >= 0;
    let mut pa = 0u64;
    if good {
        let info = svc(14, slot as u64, 0, 0, 0, 0); // CAP_INFO: status, physical address, pages
        pa = info[1];
        good &= info[0] == 0 && info[2] == WANT && mem_map(slot as u64, MAP_VA, true) == 0;
        if good {
            let p = va(MAP_VA) as *mut u64;
            for i in 0..(WANT as usize * PAGE / 8) {
                // SAFETY: `p` is MAP_VA, mapped (checked) over a WANT-page capability (info[2] == WANT); i < WANT*PAGE/8 keeps the u64 in it.
                unsafe { write_volatile(p.add(i), i as u64 ^ 0xA5A5) };
            }
            // SAFETY: same mapped WANT-page region as the writes just above.
            good &= (0..(WANT as usize * PAGE / 8)).all(|i| unsafe { read_volatile(p.add(i)) } == i as u64 ^ 0xA5A5);
        }
        svc(MEMCTL, 11, MC_FREE, slot as u64, 0, 0);
    }
    println!("[client] TEST contiguous {} KiB block allocated after compaction, mapped and used (slot {slot}, pa {pa:#x}): {}", WANT as usize * PAGE / 1024, verdict(good));

    // Direct compaction: fragment again, then let the allocator compact synchronously.
    let (first2, count2) = match fill() {
        Some(x) => x,
        None => {
            println!("[client] TEST direct compaction: refill failed: FAIL");
            return;
        }
    };
    for p in 0..count2 {
        stamp(first2 + p, p as u64 + 1_000_000);
    }
    for p in (1..count2).step_by(2) {
        release(first2 + p);
    }
    let s4 = stats(11);
    let mig4 = s4.migrated;
    let slot = svc(MEMCTL, 11, MC_ALLOC, WANT, MCF_DIRECT, 0)[0] as i64;
    let s5 = stats(11);
    let (n1, ok1) = verify(first, count, 1, |p| p % 2 == 0);
    let (n2, ok2) = verify(first2, count2, 1_000_000, |p| p % 2 == 0);
    println!("[client] TEST direct compaction inside the allocator (largest run was {}, result {slot}, {} pages migrated, no failure recorded, {} pages verified): {}",
        s4.largest, s5.migrated - mig4, n1 + n2,
        verdict(s4.largest < WANT && slot >= 0 && s5.migrated > mig4 && s5.failures == s4.failures && ok1 && ok2));
    if slot >= 0 {
        svc(MEMCTL, 11, MC_FREE, slot as u64, 0, 0);
    }

    // Give everything back so later work has memory.
    svc(HEAP_RELEASE, first as u64, (first2 + count2 - first) as u64, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// conductor-side test: swap
// ---------------------------------------------------------------------------

/// A page's worth of one of four kinds of content (compresses to very different sizes), keyed by `id`.
fn fill_page(page: usize, id: u64) {
    let p = (heap_base() as usize + page * PAGE) as *mut u8;
    let mut x = id.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for i in 0..PAGE {
        let b = match id % 4 {
            0 => b"swap me out, cold anonymous page "[i % 33], // text
            1 => 0,                                           // zero page
            2 => {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8 // noise: incompressible
            }
            _ => ((i / 8) as u8).wrapping_add(id as u8), // slowly changing bytes
        };
        // SAFETY: `p` is heap page `page` (from HEAP_GROW in `swap_tests` / the pressure test), i < PAGE. The pressure test asserts its first HEAP_GROW succeeded.
        unsafe { write_volatile(p.add(i), b) };
    }
    // a unique mark at a position that differs per page, so a page restored in the wrong place is noticed
    // SAFETY: same heap page; id % 4000 < PAGE.
    unsafe { write_volatile(p.add(id as usize % 4000), 0xEE ^ id as u8) };
}

fn page_ok(page: usize, id: u64) -> bool {
    let p = (heap_base() as usize + page * PAGE) as *const u8;
    let mut x = id.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for i in 0..PAGE {
        let want = match id % 4 {
            0 => b"swap me out, cold anonymous page "[i % 33],
            1 => 0,
            2 => {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            }
            _ => ((i / 8) as u8).wrapping_add(id as u8),
        };
        let want = if i == id as usize % 4000 { 0xEE ^ id as u8 } else { want };
        // SAFETY: same heap page as `fill_page`; i < PAGE; the kernel swaps the page back in on a fault, so the read sees the stored data.
        if unsafe { read_volatile(p.add(i)) } != want {
            return false;
        }
    }
    true
}

pub fn swap_tests() {
    const N: usize = 96;
    let base = svc(HEAP_GROW, N as u64, 0, 0, 0, 0)[0] as i64;
    if base < 0 {
        println!("[client] TEST swap: SKIPPED (no heap)");
        return;
    }
    let first = (base as u64 - heap_base()) as usize / PAGE;
    for p in 0..N {
        fill_page(first + p, p as u64);
    }
    let (s0, f0) = (swap_stats(11), stats(11).free);
    // evict every heap page of this task (the budget exceeds what it has): the test pages, plus whatever the
    // allocator itself keeps in the heap window, which fault back in when used
    let evicted = swap_out(11, 1024, MCS_FORCE | MCS_SELF | MCS_HEAP) as usize;
    let (s1, f1) = (swap_stats(11), stats(11).free);
    println!("[client] TEST swap out: {evicted} heap pages evicted ({N} of them test pages), {} KiB held in {} bytes in the store ({}%), {} -> {} frames free: {}",
        evicted * PAGE / 1024, s1.bytes - s0.bytes, (s1.bytes - s0.bytes) * 100 / (evicted as u64 * PAGE as u64).max(1), f0, f1,
        verdict(evicted >= N && s1.stored - s0.stored == evicted as u64 && s1.bytes - s0.bytes < (evicted * PAGE) as u64 * 7 / 10 && f1 + 8 >= f0 + evicted as u64));

    // touching every page faults it back in, with exactly its old content
    let bad = (0..N).filter(|&p| !page_ok(first + p, p as u64)).count();
    let s2 = swap_stats(11);
    println!("[client] TEST swap in on access: {} page faults brought pages back, {bad} wrong: {}",
        s2.back - s1.back, verdict(bad == 0 && s2.back - s1.back >= N as u64 && s2.back - s1.back <= evicted as u64));

    // a system call that needs a swapped-out page gets it back too (the kernel reads the log text from user memory)
    let msg = b"[client] (this line was read from a page that had been swapped out)\n";
    let pg = (heap_base() as usize + first * PAGE) as *mut u8;
    for (i, &b) in msg.iter().enumerate() {
        // SAFETY: `pg` is the first heap page of this test's HEAP_GROW block; 3000 + i < 3068 < PAGE.
        unsafe { write_volatile(pg.add(3000 + i), b) };
    }
    let n = swap_out(11, 1024, MCS_FORCE | MCS_SELF | MCS_HEAP);
    let s3 = swap_stats(11);
    let r = svc(LOG, CONSOLE, pg as u64 + 3000, msg.len() as u64, 0, 0)[0] as i64;
    let s4 = swap_stats(11);
    println!("[client] TEST the kernel swaps a page in for a system call ({n} pages out, log call returned {r}, {} swapped in by it): {}",
        s4.back - s3.back, verdict(n as usize >= N && r == msg.len() as i64 && s4.back - s3.back >= 1 && s4.back - s3.back <= 3));

    // freeing swapped-out pages releases their store entries without bringing them back
    swap_out(11, 1024, MCS_FORCE | MCS_SELF | MCS_HEAP);
    let s5b = swap_stats(11);
    let freed = svc(HEAP_RELEASE, first as u64, N as u64, 0, 0, 0)[0];
    let s6 = swap_stats(11);
    println!("[client] TEST releasing swapped-out pages frees their store entries ({freed} released, store {} -> {} pages, {} swapped in): {}",
        s5b.stored, s6.stored, s6.back - s5b.back, verdict(freed as usize == N && s5b.stored - s6.stored == N as u64 && s6.back == s5b.back));

    // real pressure: use up memory; compactd's policy must push cold pages out, and everything must survive
    if !can_exhaust() {
        println!("[client] TEST memory pressure: SKIPPED (RAM too large to exhaust with this task's quota; run with -m 64M)");
        return;
    }
    let mut held = 0usize;
    let first2;
    {
        let b = svc(HEAP_GROW, 1, 0, 0, 0, 0)[0] as i64;
        assert!(b >= 0, "first heap grow failed: {b}");
        first2 = (b as u64 - heap_base()) as usize / PAGE;
        fill_page(first2, 1000);
        held += 1;
    }
    let mut stopped = 0i64;
    while stats(11).free > 12 {
        let b = svc(HEAP_GROW, 1, 0, 0, 0, 0)[0] as i64;
        if b < 0 {
            stopped = b;
            break;
        }
        let idx = (b as u64 - heap_base()) as usize / PAGE;
        if idx != first2 + held {
            stopped = 1;
            break;
        }
        fill_page(idx, 1000 + held as u64);
        held += 1;
    }
    let low = stats(11).free;
    let s7 = swap_stats(11);
    // compactd looks every 10 ticks and works in small steps: give it a few seconds
    let t0 = ticks();
    while swap_stats(11).out == s7.out && ticks() - t0 < 600 {
        sleep(5);
    }
    sleep(40);
    let s8 = swap_stats(11);
    let high = stats(11).free;
    println!("[client] TEST memory pressure makes compactd swap cold pages out ({held} pages held{}, free {low} -> {high}, {} pages swapped out, {} B in the store, store full {} times): {}",
        if stopped != 0 { alloc::format!(", growing stopped with {stopped}") } else { alloc::string::String::new() }, s8.out - s7.out, s8.bytes, s8.full, verdict(held > 500 && s8.out > s7.out && high > low && s8.full == 0));
    let bad = (0..held).filter(|&p| !page_ok(first2 + p, 1000 + p as u64)).count();
    let s9 = swap_stats(11);
    println!("[client] TEST every page survives the pressure ({held} verified, {bad} wrong, {} swapped back in, {} aged pages touched again): {}",
        s9.back - s8.back, s9.touched - s8.touched, verdict(bad == 0));
    svc(HEAP_RELEASE, first2 as u64, held as u64, 0, 0, 0);
    let end = swap_stats(11);
    // what remains is other tasks' (and the conductor's own allocator's) cold pages, which are meant to stay out
    println!("[client] TEST releasing the memory empties the store of the test's pages ({} pages, {} bytes left; {} were already there when the test pages were released): {}",
        end.stored, end.bytes, s6.stored, verdict(end.stored <= s6.stored + s8.out - s7.out + 8));
}

/// Pages that are written, evicted, written again and read back in random order against a model: a write
/// lost across an eviction, a page restored in the wrong place or stale content shows up as a mismatch.
pub fn swap_stress() {
    const N: usize = 256;
    const ROUNDS: usize = 150;
    let base = svc(HEAP_GROW, N as u64, 0, 0, 0, 0)[0] as i64;
    if base < 0 {
        println!("[client] TEST swap stress: SKIPPED (no heap)");
        return;
    }
    let first = (base as u64 - heap_base()) as usize / PAGE;
    // model: the last (round, word index) pattern written to each page; every page starts as zeros
    let mut gen = [0u64; N];
    let word = |page: usize, idx: usize| (heap_base() as usize + (first + page) * PAGE + idx * 8) as *mut u64;
    let pat = |page: usize, g: u64, idx: usize| g.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (page as u64) << 32 ^ idx as u64;
    let mut rng = 0xC0FFEEu64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let (s0, mut bad, mut first_bad) = (swap_stats(11), 0usize, None);
    for round in 1..=ROUNDS as u64 {
        // write a random subset (full page or a few words), some of them to pages that are swapped out right now
        for _ in 0..N / 3 {
            let p = (next() % N as u64) as usize;
            if next() % 3 == 0 {
                gen[p] = round;
                for i in 0..PAGE / 8 {
                    // SAFETY: `word(p, i)` is inside page p of this test's HEAP_GROW block of N pages (p < N, i < PAGE/8).
                    unsafe { write_volatile(word(p, i), pat(p, round, i)) };
                }
            } else {
                // a partial update: the model only tracks full-page patterns, so rewrite the rest too
                gen[p] = round;
                for i in 0..PAGE / 8 {
                    // SAFETY: same page and bounds as the full-page write above.
                    unsafe { write_volatile(word(p, i), pat(p, round, i)) };
                }
            }
        }
        // evict a random number of pages
        swap_out(11, 1 + next() % 200, MCS_FORCE | MCS_SELF | MCS_HEAP);
        // read back a random sample; every word must match the model
        for _ in 0..N / 4 {
            let p = (next() % N as u64) as usize;
            for i in 0..PAGE / 8 {
                let want = if gen[p] == 0 { 0 } else { pat(p, gen[p], i) };
                // SAFETY: in bounds as for the writes (p < N, i < PAGE/8); a swapped-out page is faulted back in by the kernel.
                let got = unsafe { read_volatile(word(p, i)) };
                if got != want {
                    bad += 1;
                    if first_bad.is_none() {
                        first_bad = Some((round, p, i, gen[p], got, want));
                    }
                    break;
                }
            }
        }
    }
    // final full check
    for p in 0..N {
        for i in 0..PAGE / 8 {
            let want = if gen[p] == 0 { 0 } else { pat(p, gen[p], i) };
            // SAFETY: in bounds as for the writes (p < N, i < PAGE/8).
            if unsafe { read_volatile(word(p, i)) } != want {
                bad += 1;
                if first_bad.is_none() {
                    // SAFETY: in bounds as for the writes (p < N, i < PAGE/8).
                    first_bad = Some((0, p, i, gen[p], unsafe { read_volatile(word(p, i)) }, want));
                }
                break;
            }
        }
    }
    let s1 = swap_stats(11);
    println!("[client] TEST swap stress ({ROUNDS} rounds, {} pages evicted, {} faulted back, first mismatch {first_bad:x?}): {}",
        s1.out - s0.out, s1.back - s0.back, verdict(bad == 0 && s1.out - s0.out > 1000));
    svc(HEAP_RELEASE, first as u64, N as u64, 0, 0, 0);
}
