//! Metallium-OS userspace image. One binary, four roles selected by the role id
//! the kernel passes in x0. Every task gets its own private copy of the image.
#![no_std]
#![no_main]

extern crate alloc;
#[macro_use]
extern crate metallium_driver_rt;
// the desktop, when the image is built with one (`make run-window DESKTOP=<path>`; docs/DESKTOP-INTERFACE.md): linked in with --extern
#[cfg(desktop)]
extern crate metallium_desktop_boot;
pub use metallium_driver_rt::*;

use core::arch::asm;
use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};

// ---- service protocol ----
const OP_SUM: u64 = 1;
const OP_NOTIFY: u64 = 3;
const OP_PING: u64 = 10;
const OP_CRASH: u64 = 11;

const SERVER_TID: u64 = 1;
const CLIENT_SHM: usize = 0x8020_0000;
const SERVER_SHM: usize = 0x8030_0000;

mod audio;
mod audiod;
mod bench;
mod chaos;
mod console;
mod screen;
mod font;
mod blk;
mod gpu;
mod gputest;
mod fuzz;
mod programs;
mod info;
mod kbd;
mod xhci;
mod greeter;
mod logo;
mod shell;
mod termedit;
mod compaction;
pub use metallium_driver_rt::{dma, proto, virtio};
// the network service, its driver and the HTTP client live in the networking repository (see its README.md)
pub use metallium_net_services::{httpc, netd, netdrv, netring};
mod heap;
mod ring;
mod sched;
mod storage;
mod vfs;

fn verdict(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn sum_bytes(p: *const u8, len: usize) -> u64 {
    let mut s = 0u64;
    for i in 0..len {
        // SAFETY: callers pass a mapped range: CLIENT_SHM (one page, `mem_map` checked by the test) or SERVER_SHM, which is read only after a successful mapping (`shm_mapped`) and clamped to 4096 bytes.
        s = s.wrapping_add(unsafe { read_volatile(p.add(i)) } as u64);
    }
    s
}

// ---------------------------------------------------------------------------
// role 0: client / test conductor
// ---------------------------------------------------------------------------
fn client() -> ! {
    println!("[client] online");
    if sysinfo(2)[2] != 0 {
        chaos::run(); // chaos-test mode (make chaos): a different job for the conductor
    }
    // an interactive session (make run-window): no tests, straight to the console
    if sysinfo(2)[1] != 0 && matches!(sysinfo(2)[3], 0 | 16) {
        programs::console_session();
    }
    // development shortcuts (make quick-bench / quick-sched): just one group of tests
    match sysinfo(2)[3] {
        1 => {
            bench::bench_tests();
            exit(0)
        }
        2 => {
            sched::sched_tests();
            exit(0)
        }
        6 => {
            fuzz::conduct();
            exit(0)
        }
        7 => {
            vfs::vfs_tests();
            programs::tests();
            exit(0)
        }
        8 => {
            vfs::vfs_tests();
            programs::net_tests();
            exit(0)
        }
        9 => {
            programs::scale_tests(); // make scale: every slot of a table of 1024 tasks
            exit(0)
        }
        15 => {
            programs::tty_test(); // make tty-test: two ttys' buffers and the display driver's switch between them
            exit(0)
        }
        14 => {
            programs::greeter_test(); // make greeter-test: the greeter's screens, driven by the harness
            exit(0)
        }
        13 => {
            programs::session_test(); // make session-test: the session service
            exit(0)
        }
        12 => {
            vfs::table_test(); // make table-test: the directory table of /data
            exit(0)
        }
        11 => {
            vfs::volume_test(); // make volume-test: the data volume's lock
            exit(0)
        }
        10 => {
            // make usb-test: the input driver logs what arrives while the harness types (the machine is stopped from outside); this task waits for input
            // the way a desktop does (`INPUT_WAIT`, up to a second at a time) and says how long each wait took
            let mut timeouts = 0;
            for _ in 0..600 {
                let t0 = ticks();
                let (st, r) = call(14, [proto::input::INPUT_WAIT, 1000, 0]);
                if st != 0 {
                    println!("[wait] call failed: {st}");
                    break;
                }
                let (n, ms) = (r[0] & 0xFF, (ticks() - t0) * 10);
                if n > 0 {
                    println!("[wait] {n} event(s) after {ms} ms");
                } else if timeouts < 2 {
                    timeouts += 1;
                    println!("[wait] nothing after {ms} ms");
                }
            }
            exit(0)
        }
        _ => {}
    }

    // 1. zero-copy shared memory: client fills a page, server sums it in place.
    let r = mem_map(1, CLIENT_SHM, true);
    if r != 0 {
        println!("[client] TEST zero-copy shared memory (map={r}): FAIL");
        exit(1);
    }
    let p = CLIENT_SHM as *mut u8;
    for i in 0..4096 {
        // SAFETY: CLIENT_SHM is the one-page mapping made above (checked: the run exits if it failed); i < 4096.
        unsafe { write_volatile(p.add(i), (i * 7 + 3) as u8) };
    }
    let expect = sum_bytes(p, 4096);
    let slot = cap_grant(1, SERVER_TID, R_MAP);
    let (st, rep) = call(0, [OP_SUM, slot as u64, 4096]);
    println!("[client] TEST zero-copy shared memory (map={r} grant_slot={slot} sum={} expect={expect}): {}",
        rep[1], verdict(r == 0 && st == 0 && rep[0] == 0 && rep[1] == expect));

    // 2. asynchronous send: no reply, returns immediately.
    let st = send(0, [OP_NOTIFY, 42, 0]);
    println!("[client] TEST async IPC_SEND (status={st}): {}", verdict(st == 0));

    // 3. revocation: server's capability + mapping must die with the revoke.
    let n = cap_revoke(1);
    let (st, rep) = call(0, [OP_SUM, slot as u64, 4096]);
    println!("[client] TEST capability revoke (revoked={n} call_status={st} server_err={}): {}",
        rep[1] as i64, verdict(n >= 1 && st == 0 && rep[0] != 0 && rep[1] as i64 == E_BADCAP));

    // 3b. a task with the grant right cannot use up the capability nodes: one task may have 40 grants outstanding, and 48
    // nodes stay free for restarts and new programs whatever it does
    let mut granted = 0;
    for _ in 0..8 {
        for target in 1..48u64 {
            if cap_grant(1, target, R_MAP) >= 0 {
                granted += 1;
            }
        }
    }
    let in_use = sysinfo(1)[5];
    cap_revoke(1);
    println!("[client] TEST capability grants are bounded (granted={granted} nodes_in_use={in_use}): {}",
        verdict(granted > 0 && granted <= 40 && in_use <= 254 - 48));

    // 4. driver fault isolation and restart.
    let (_, a) = call(2, [OP_PING, 0, 0]);
    let (_, b) = call(2, [OP_PING, 0, 0]);
    println!("[client] driver served {} then {}", a[0], b[0]);
    let (st, _) = call(2, [OP_CRASH, 0, 0]);
    println!("[client] TEST driver crash surfaces as error (status={st}): {}", verdict(st == E_DEAD));
    let (st, c) = call(2, [OP_PING, 0, 0]);
    println!("[client] TEST driver restarted with fresh state (status={st} served={}): {}",
        c[0], verdict(st == 0 && c[0] == 1));

    // 4b. a huge page count must not wrap around the heap-quota check and eat all of RAM
    // (The sum heap_pages + request only wraps to something small if the task already owns a few pages.)
    let warm = alloc::vec![1u8; 64 * 1024];
    let before = sysinfo(0)[3];
    let r = svc(HEAP_GROW, u64::MAX - 3, 0, 0, 0, 0)[0] as i64;
    let after = sysinfo(0)[3];
    drop(warm);
    println!("[client] TEST HEAP_GROW with a wrapping page count is refused (result {r}, free frames {before} -> {after}): {}",
        verdict(r == E_NOMEM && before.saturating_sub(after) < 64));

    // 5. storage through the userspace virtio-blk driver (shared DMA buffer, zero-copy)
    blk_tests();

    // 6. filesystem servers on top of the block driver (after the program task is done with the shared store)
    vfs::wait_for_program();
    storage::storage_tests();

    // 7. the VFS on top of everything, plus the concurrent program task
    vfs::vfs_tests();
    gputest::gpu_tests();
    info::conductor_start();

    // 8. asynchronous submission/completion rings
    ring::ring_tests();

    // 9. memory pressure, fragmentation and the compaction daemon (leaves memory free again)
    compaction::compaction_tests();
    compaction::swap_tests();
    compaction::swap_stress();
    let (line, ok) = dma::selftest();
    println!("[client] TEST cache maintenance for DMA runs at EL0 (data cache line {line} bytes, clean and flush leave the data intact): {}", verdict(ok));

    // 10. kernel lock scaling: independent IPC pairs
    bench::bench_tests();

    // 10b. the scheduler: slices, real-time reservations, balance across cores, placement by energy
    sched::sched_tests();

    // 10c. programs: SPAWN / WAIT / KILL
    programs::tests();

    // 10d. the network stack, against the host peer
    programs::net_tests();

    // 11. let the CPU-bound worker run (preemption) and the system idle.
    let t0 = ticks();
    sleep(30);
    let t1 = ticks();
    println!("[client] TEST sleep/timer (slept {} ticks): {}", t1 - t0, verdict(t1 - t0 >= 30));

    println!("[client] done");
    exit(0)
}

const BLK_BUF_VA: usize = 0x8030_0000;
const BLK_SECRET_VA: usize = 0x8031_0000;

fn blk_call(op: u64, sector: u64, nsec: u64) -> (i64, u64) {
    let (st, r) = call(3, [op, sector, nsec]);
    (st, r[0])
}

fn pattern_ok(buf: *const u8, first_sector: u64, nsec: u64) -> bool {
    for s in 0..nsec {
        for i in 0..512u64 {
            let want = ((first_sector + s) * 31 + i) as u8;
            // SAFETY: `buf` is the 4096-byte block-driver buffer mapped (checked) in `blk_tests`; callers read at most 8 sectors, so s*512 + i < 4096.
            if unsafe { read_volatile(buf.add((s * 512 + i) as usize)) } != want {
                return false;
            }
        }
    }
    true
}

fn blk_tests() {
    let m = mem_map(4, BLK_BUF_VA, true);
    if m != 0 {
        println!("[client] TEST virtio-blk: no block device (map={m}): FAIL");
        return;
    }
    let buf = va(BLK_BUF_VA) as *mut u8;

    // read sector 0 of the disk image
    let (st, dev_status) = blk_call(BLK_READ, 0, 1);
    let magic = b"METAL-OS-DISK v1";
    // SAFETY: `buf` is the mapped 4096-byte buffer (checked in `blk_tests`); i < 16.
    let ok = (0..magic.len()).all(|i| unsafe { read_volatile(buf.add(i)) } == magic[i]);
    println!("[client] TEST virtio-blk read sector 0 (status={st}/{dev_status}): {}", verdict(st == 0 && dev_status == 0 && ok));

    // write 8 sectors, clobber the buffer, read them back
    for s in 0..8u64 {
        for i in 0..512u64 {
            // SAFETY: `buf` is the mapped 4096-byte buffer; s < 8 and i < 512, so the offset is < 4096.
            unsafe { write_volatile(buf.add((s * 512 + i) as usize), ((100 + s) * 31 + i) as u8) };
        }
    }
    let (st1, d1) = blk_call(BLK_WRITE, 100, 8);
    for i in 0..4096 {
        // SAFETY: `buf` is the mapped 4096-byte buffer; i < 4096.
        unsafe { write_volatile(buf.add(i), 0) };
    }
    let (st2, d2) = blk_call(BLK_READ, 100, 8);
    let ok = pattern_ok(buf, 100, 8);
    println!("[client] TEST virtio-blk write+readback 4 KiB (status={st1}/{d1} {st2}/{d2}): {}",
        verdict(st1 == 0 && d1 == 0 && st2 == 0 && d2 == 0 && ok));

    // crash the driver mid-service; data must survive on the device
    let (st, _) = blk_call(BLK_CRASH, 0, 0);
    println!("[client] TEST blk driver crash surfaces as error (status={st}): {}", verdict(st == E_DEAD));
    for i in 0..4096 {
        // SAFETY: `buf` is the mapped 4096-byte buffer; i < 4096.
        unsafe { write_volatile(buf.add(i), 0) };
    }
    let (st, d) = blk_call(BLK_READ, 100, 8);
    let ok = pattern_ok(buf, 100, 8);
    println!("[client] TEST data survives blk driver restart (status={st}/{d}): {}", verdict(st == 0 && d == 0 && ok));

    // a device that never answers: the driver's watchdog notices, the driver is restarted
    let (st, _) = blk_call(BLK_STALL, 0, 0);
    println!("[client] TEST a block device that never answers is caught by the driver's watchdog, driver restarted (status={st}): {}", verdict(st == E_DEAD));
    let (st, d) = blk_call(BLK_READ, 100, 8);
    println!("[client] TEST the block driver serves requests again after the watchdog restart (status={st}/{d}): {}", verdict(st == 0 && d == 0));

    // a driver that makes its device DMA outside its grant: the IOMMU must stop it
    // The conductor fills a page the driver was never granted with a marker. If the device could
    // read it, the marker would land on disk sector 200.
    const MARKER: &[u8] = b"SECRET-NOT-FOR-IO";
    let secret = va(BLK_SECRET_VA) as *mut u8;
    let mapped = mem_map(6, BLK_SECRET_VA, true) == 0;
    if mapped {
        for i in 0..4096 {
            // SAFETY: `secret` is BLK_SECRET_VA, mapped (`mapped` checked) from capability slot 6, which is one 4096-byte page; i < 4096.
            unsafe { write_volatile(secret.add(i), MARKER[i % MARKER.len()]) };
        }
    }
    let (st, _) = blk_call(BLK_EVIL, 200, 1);
    println!("[client] TEST IOMMU stops a driver whose device DMAs outside its granted pages, driver restarted (status={st}): {}", verdict(mapped && st == E_DEAD));
    for i in 0..4096 {
        // SAFETY: `buf` is the mapped 4096-byte buffer; i < 4096.
        unsafe { write_volatile(buf.add(i), 0) };
    }
    let (st, d) = blk_call(BLK_READ, 200, 1);
    // SAFETY: `buf` is the mapped 4096-byte buffer; o + i < 512.
    let leaked = (0..512 - MARKER.len()).any(|o| (0..MARKER.len()).all(|i| unsafe { read_volatile(buf.add(o + i)) } == MARKER[i]));
    println!("[client] TEST the marker page never reached the disk (read back status={st}/{d}): {}", verdict(st == 0 && d == 0 && !leaked));
    for i in 0..4096 {
        // SAFETY: `buf` is the mapped 4096-byte buffer; i < 4096.
        unsafe { write_volatile(buf.add(i), 0) };
    }
    let (st, d) = blk_call(BLK_READ, 100, 8);
    let ok = pattern_ok(buf, 100, 8);
    println!("[client] TEST restarted block driver serves requests again (status={st}/{d}): {}", verdict(st == 0 && d == 0 && ok));
}

// ---------------------------------------------------------------------------
// role 4: virtio-blk driver (virtio 1.x over PCI, one request in flight, IRQ driven)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// role 1: service task (shared-memory checksum + notifications)
// ---------------------------------------------------------------------------
fn server() -> ! {
    println!("[server] listening");
    let mut shm_mapped = false;
    loop {
        let m = recv(0);
        match m.w[0] {
            OP_SUM => {
                let r = mem_map(m.w[1], SERVER_SHM, false);
                if r != 0 && (r != E_INVAL || !shm_mapped) {
                    // E_INVAL after a successful mapping just means "already mapped by an earlier call"
                    reply([1, r as u64, 0]);
                    continue;
                }
                shm_mapped = true;
                let s = sum_bytes(SERVER_SHM as *const u8, (m.w[2] as usize).min(4096)) /* one page is mapped */;
                reply([0, s, 0]);
            }
            OP_NOTIFY => println!("[server] async notify {} from task {} (call={})", m.w[1], m.sender, m.is_call),
            _ => {
                reply([1, E_INVAL as u64, 0]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// role 2: "hardware driver" realm: crashes on demand, kernel restarts it
// ---------------------------------------------------------------------------
fn driver() -> ! {
    println!("[driver] up");
    let mut served = 0u64;
    loop {
        let m = recv(0);
        match m.w[0] {
            OP_PING => {
                served += 1;
                reply([served, 0, 0]);
            }
            OP_CRASH => {
                println!("[driver] simulated fault: writing to unmapped MMIO");
                // SAFETY: deliberate fault injection: 0x1000 is below every mapping (images load at 0x8000_0000 or higher), so the store traps and the kernel restarts this driver; that is the test.
                unsafe { write_volatile(0x1000 as *mut u64, 0xDEAD) };
            }
            _ => {
                reply([0, 0, 0]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// role 3: CPU hog, never yields -> proves timer preemption
// ---------------------------------------------------------------------------
fn worker() -> ! {
    // (a console session has no tests to prove preemption for: the hog would keep one core at 100% for minutes)
    if sysinfo(2)[1] != 0 {
        loop {
            sleep(60000);
        }
    }
    let mut x = 1u64;
    let mut beats = 0;
    loop {
        for i in 0..40_000_000u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
        }
        beats += 1;
        // (only the first few and the last: a heartbeat that comes in the middle of a long test message splits that message)
        if beats <= 5 || beats == 3000 {
            println!("[worker] heartbeat {beats} (tick {}, x={:x})", ticks(), (x >> 40) & 0xff);
        }
        // (long enough to outlive the tests that run before the scheduler tests, which look for it: the suite takes minutes)
        if beats == 3000 {
            exit(0);
        }
    }
}

#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(role: u64, arg1: u64) -> ! {
    // The services take their memory where the kernel puts it, and the kernel agrees to nothing else (see `mem_map`).
    // The test programs (conductor, the test server, fuzzer, benchmarks, the monkey, the application) keep explicit addresses.
    if matches!(role, 2 | 4 | 5 | 6 | 7 | 9 | 12 | 13 | 14 | 18 | 19 | 20 | 22) {
        auto_maps();
    }
    match role {
        0 => client(),
        1 => server(),
        2 => driver(),
        4 => blk::blk_driver(),
        12 => gpu::gpu_driver(),
        13 => info::info_task(),
        22 => info::tty_console_task(),
        14 => kbd::kbd_driver(),
        18 => netdrv::net_driver(),
        20 => audiod::audiod(),
        19 => netd::netd(),
        15 => chaos::monkey(),
        5 => storage::rofs_server(),
        6 => storage::lfs_server(),
        7 => vfs::vfs_server(),
        9 => compaction::compactd(),
        16 => sched::spinner(arg1),
        17 => fuzz::fuzzer(),
        10 => bench::bench_server(),
        11 => bench::bench_client(arg1),
        8 => vfs::program(),
        _ => worker(),
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("[user] panic: {info}");
    exit(101)
}

#[allow(dead_code)]
fn _unused() {
    let _ = (YIELD, E_DEAD, R_MAP, HEAP_GROW);
}
