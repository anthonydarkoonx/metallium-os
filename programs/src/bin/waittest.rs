#![no_std]
#![no_main]
//! Timed receive and receive on several endpoints (`IPC_RECV` with a timeout, `IPC_WAIT_ANY`). The program makes its own endpoints (a factory capability is
//! in slot 1) and uses threads as the other side. Mode 0 runs the checks and exits with a bit set for each that failed (bit n for the nth); mode 1 waits for ever
//! on two endpoints with a thread in a timed receive, so that the conductor can kill it in the middle.
extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use metallium_programs::*;

const FACTORY: u64 = 1;

fn ep() -> u64 {
    svc(27, FACTORY, 0, 0, 0, 0)[0]
}

fn now_us() -> u64 {
    svc(34, 0, 0, 0, 0, 0)[0] / 1000
}

fn send(slot: u64, w: [u64; 3]) -> i64 {
    svc(IPC_SEND, slot, w[0], w[1], w[2], 0)[0] as i64
}

fn pause_ms(ms: u64) {
    sleep((ms + 9) / 10);
}

fn mode1() -> u64 {
    let (a, b) = (ep(), ep());
    let _t = thread::spawn(move || {
        let _ = recv_timeout(b, 3_000_000);
    });
    let r = wait_any(1 << a | 1 << b, false, false, 0);
    if r.is_ok() { 1 } else { 0 }
}

program!("waittest", |c| {
    if c.arg == 1 {
        return mode1();
    }
    let (mut bad, mut n) = (0u64, 0u32);
    let mut check = |name: &str, ok: bool| {
        n += 1;
        if !ok {
            println!("waittest: FAILED: {name}");
            bad |= 1 << n;
        }
    };
    let (a, b, cc) = (ep(), ep(), ep());
    let all = 1u32 << a | 1 << b | 1 << cc;

    // a timed receive on an empty endpoint gives up when the time is up
    let t0 = now_us();
    let r = recv_timeout(a, 30_000);
    let dt = now_us() - t0;
    check("a timed receive on an empty endpoint times out (-9) after about the time asked", matches!(r, Err(E_TIMEDOUT)) && dt >= 25_000 && dt < 1_000_000);

    // ... and returns the message when one arrives first
    let h = thread::spawn(move || {
        pause_ms(30);
        send(a, [7, 1, 2])
    });
    let t0 = now_us();
    let r = recv_timeout(a, 2_000_000);
    let dt = now_us() - t0;
    check("a timed receive returns a message that arrives before the time is up", matches!(&r, Ok(m) if m.w == [7, 1, 2]) && dt < 1_500_000);
    h.join();

    // wait on several: the one that gets the message is named
    let h = thread::spawn(move || {
        pause_ms(30);
        send(b, [8, 0, 0])
    });
    let r = wait_any(all, false, false, 2_000_000);
    check("a wait on three endpoints returns the message from the one it came to, and says which", matches!(&r, Ok(x) if x.slot == b && x.msg.w[0] == 8));
    h.join();

    // queued messages: each endpoint once, then nothing
    for (k, e) in [a, b, cc].into_iter().enumerate() {
        send(e, [20 + k as u64, 0, 0]);
    }
    let mut got: Vec<(u64, u64)> = Vec::new();
    for _ in 0..3 {
        if let Ok(x) = wait_any(all, false, true, 0) {
            got.push((x.slot, x.msg.w[0]));
        }
    }
    got.sort();
    let none = wait_any(all, false, true, 0);
    check("three queued messages come out once each, and then a non-blocking wait says nothing is queued (-10)", got == [(a, 20), (b, 21), (cc, 22)] && matches!(none, Err(-10)));

    // a wait that timed out leaves nothing behind that eats a later message or blocks a later receiver
    let r = wait_any(all, false, false, 20_000);
    send(a, [30, 0, 0]);
    let r2 = recv_timeout(a, 200_000);
    check("after a timed-out wait on several, a message to one of them is not lost and a plain receive there is not refused", matches!(r, Err(E_TIMEDOUT)) && matches!(&r2, Ok(m) if m.w[0] == 30));

    // a wait served by one endpoint leaves stale registrations on the others
    let h = thread::spawn(move || {
        pause_ms(20);
        send(b, [31, 0, 0])
    });
    let r = wait_any(all, false, false, 2_000_000);
    h.join();
    send(a, [32, 0, 0]);
    send(cc, [33, 0, 0]);
    let (ra, rc) = (recv_timeout(a, 200_000), recv_timeout(cc, 200_000));
    check("registrations left on the other endpoints by a served wait do not take or refuse anything", matches!(&r, Ok(x) if x.slot == b) && matches!(&ra, Ok(m) if m.w[0] == 32) && matches!(&rc, Ok(m) if m.w[0] == 33));

    // two senders on two endpoints at once: every message once, in order per endpoint
    const N: u64 = 150;
    static DONE: AtomicU32 = AtomicU32::new(0);
    let sender = move |e: u64| {
        for i in 0..N {
            while send(e, [1, i, 0]) == -3 {
                yield_now();
            }
        }
        DONE.fetch_add(1, Ordering::SeqCst);
    };
    let (h1, h2) = (thread::spawn(move || sender(a)), thread::spawn(move || sender(b)));
    let (mut next_a, mut next_b, mut ok) = (0u64, 0u64, true);
    for _ in 0..2 * N {
        match wait_any(1 << a | 1 << b, false, false, 5_000_000) {
            Ok(x) if x.slot == a && x.msg.w[1] == next_a => next_a += 1,
            Ok(x) if x.slot == b && x.msg.w[1] == next_b => next_b += 1,
            _ => {
                ok = false;
                break;
            }
        }
    }
    h1.join();
    h2.join();
    check("two threads sending on two endpoints while one waits on both: every message arrives exactly once, in order", ok && next_a == N && next_b == N);

    // a call that arrives through a wait on several is answered
    let h = thread::spawn(move || call(a, [5, 0, 0]));
    let r = wait_any(all, false, false, 2_000_000);
    let replied = matches!(&r, Ok(x) if x.msg.call && x.msg.w[0] == 5) && reply([0, 42, 0]) == 0;
    let (st, rw) = h.join();
    check("a synchronous call that arrives through a wait on several is answered, and the caller gets the reply", replied && st == 0 && rw[1] == 42);

    // one waiter per endpoint: a wait on an endpoint somebody else waits on is refused
    let h = thread::spawn(move || recv_timeout(cc, 1_000_000).map(|m| m.w[0]));
    pause_ms(30);
    let r = wait_any(all, false, false, 100_000);
    send(cc, [40, 0, 0]);
    let got = h.join();
    check("a wait that includes an endpoint another task is waiting on is refused (-3)", matches!(r, Err(-3)) && matches!(got, Ok(40)));

    // an endpoint that ends wakes the waiter with an error (only the creator's capability can end it: main destroys it while a thread waits)
    let victim = ep();
    let h = thread::spawn(move || wait_any(1 << victim | 1 << a, false, false, 2_000_000).err());
    pause_ms(30);
    revoke_self(victim);
    let r = h.join();
    check("a wait on an endpoint that is destroyed meanwhile ends with an error", matches!(r, Some(-4) | Some(-2)));

    // bad masks and slots
    check("an empty mask, a slot beyond the table and a slot that holds no endpoint are refused", matches!(wait_any(0, false, true, 0), Err(-5)) && matches!(svc(IPC_WAIT_ANY, 1 << 31, 1, 0, 0, 0)[0] as i64, -2) && matches!(wait_any(1 << 20, false, true, 0), Err(-2)));
    bad
});
