#![no_std]
#![no_main]
//! Capabilities in messages. Two programs that are *siblings* (neither started the other, so `CAP_GRANT` between them is refused) share memory by
//! sending capabilities through an endpoint their parent gave them (slot 0): `arg` 0 is the server (send+receive), 1 the client (send only).
//! The client exits with a bit set for each check that failed (bit n for the nth); the server with its own count (the client's last call, op 99, ends it).
use metallium_programs::*;

fn rd(a: i64, off: usize) -> u64 {
    // SAFETY: only used on addresses `map_anywhere` returned for a mapped, one-page object.
    unsafe { core::ptr::read_volatile((a as usize + off) as *const u64) }
}
fn wr(a: i64, off: usize, v: u64) {
    // SAFETY: as `rd`, on a mapping made writable.
    unsafe { core::ptr::write_volatile((a as usize + off) as *mut u64, v) }
}

fn server() -> u64 {
    let (mut plain_next, mut last_info, mut kept, mut bad) = (false, 0u64, None::<u64>, 0u64);
    let mut held = [0u64; 32];
    let mut nheld = 0usize;
    loop {
        let accept = !plain_next;
        plain_next = false;
        let Ok((m, got)) = recv_cap(0, accept) else { return bad };
        let info = match got {
            Received::None => 0,
            Received::Failed => CAP_FAILED,
            Received::Slot(n) => n + 1,
        };
        match m.w[0] {
            // a memory capability with the write right: read what the client wrote, write an answer
            1 => {
                let Received::Slot(s) = got else { reply([1, 0, 0]); continue };
                let a = map_anywhere(s, true);
                if a < 0 {
                    reply([2, 0, 0]);
                } else {
                    let v = rd(a, 0);
                    wr(a, 8, 0x2222);
                    reply([0, v, 0]);
                }
                revoke_self(s);
            }
            // the same with the write right taken away by the sender: a writable mapping is refused, a read-only one works
            2 => {
                let Received::Slot(s) = got else { reply([1, 0, 0]); continue };
                let writable = map_anywhere(s, true);
                let a = map_anywhere(s, false);
                reply([0, if a >= 0 { rd(a, 0) } else { 0 }, (writable == -1) as u64]);
                revoke_self(s);
            }
            // answer with a capability of our own (memory with the pattern 0xBEEF; the map right only)
            3 => {
                let s = shm_create(1);
                if s < 0 {
                    reply([1, 0, 0]);
                    continue;
                }
                let a = map_anywhere(s as u64, true);
                wr(a, 0, 0xBEEF);
                reply_cap([0, 0, 0], Some(Give { slot: s as u64, rights: 8 }));
                // (kept: the object lives as long as this capability does)
                if nheld < held.len() {
                    held[nheld] = s as u64;
                    nheld += 1;
                }
            }
            // report what the kernel said about the capability that came with this message, and keep it
            4 => {
                if let Received::Slot(s) = got {
                    kept = Some(s);
                }
                reply([0, info, 0]);
            }
            6 => {
                plain_next = true; // (the next message is received without asking for a capability)
                reply([0, 0, 0]);
            }
            7 => last_info = info, // a notification: nobody waits for an answer
            8 => {
                reply([0, 0, 0]);
                sleep(8); // (messages sent now are queued, and delivered when this receive comes)
            }
            9 => {
                reply([0, last_info, 0]);
            }
            // is the capability that was kept still any good? (the sender revokes what it sent, and the copy goes with it)
            13 => {
                let r = match kept {
                    Some(s) => map_anywhere(s, false),
                    None => -99,
                };
                reply([0, r as u64, 0]);
            }
            // fill this program's table of capabilities, so that the next one cannot be given
            10 => {
                let mut n = 0u64;
                while nheld < held.len() {
                    let s = shm_create(1);
                    if s < 0 {
                        break;
                    }
                    held[nheld] = s as u64;
                    nheld += 1;
                    n += 1;
                }
                reply([0, n, 0]);
            }
            12 => {
                for &s in &held[..nheld] {
                    revoke_self(s);
                }
                nheld = 0;
                reply([0, 0, 0]);
            }
            99 => {
                reply([0, 0, 0]);
                return bad;
            }
            _ => {
                bad += 1;
                reply([6, 0, 0]);
            }
        }
    }
}

fn client() -> u64 {
    // (the exit code has a bit for every check that failed, counting from 1: the checks run in the order they are written)
    let (mut bad, mut n) = (0u64, 0u32);
    let mut check = |name: &str, ok: bool| {
        n += 1;
        if !ok {
            println!("captest: FAILED: {name}");
            bad |= 1 << n;
        }
    };
    let all = 0xFFFFu16;

    // memory with the write right goes to an unrelated program, which reads and writes it
    let s = shm_create(1);
    let a = map_anywhere(s as u64, true);
    wr(a, 0, 0x1111);
    let (st, w, got) = call_cap(0, [1, 0, 0], Some(Give { slot: s as u64, rights: all }), false);
    check("a memory capability reaches an unrelated program, which reads what was written and answers through it", st == 0 && w[0] == 0 && w[1] == 0x1111 && rd(a, 8) == 0x2222 && got == Received::None);

    // rights only shrink: the write right taken away on the way
    let (st, w, _) = call_cap(0, [2, 0, 0], Some(Give { slot: s as u64, rights: 8 }), false);
    check("the sender narrows the rights: the receiver can map it read-only and not writable", st == 0 && w[1] == 0x1111 && w[2] == 1);

    // a reply carries a capability to a caller that said it would take one, and only to one that did
    let (st, w, got) = call_cap(0, [3, 0, 0], None, true);
    let ok = match got {
        Received::Slot(k) => {
            let b = map_anywhere(k, false);
            let writable = map_anywhere(k, true);
            b >= 0 && rd(b, 0) == 0xBEEF && writable == -1
        }
        _ => false,
    };
    check("a reply carries a capability to a caller that accepts one, with the rights the server gave", st == 0 && w[0] == 0 && ok);
    let (st, _, got) = call_cap(0, [3, 0, 0], None, false);
    check("a reply's capability is not given to a caller that did not ask", st == 0 && got == Received::None);

    // a receiver that does not ask is not given one (the message still arrives)
    let (st, _, _) = call_cap(0, [6, 0, 0], None, false);
    let (st2, w, _) = call_cap(0, [4, 0, 0], Some(Give { slot: s as u64, rights: all }), false);
    check("a receive that did not ask for a capability gets none (and its table is untouched)", st == 0 && st2 == 0 && w[1] == 0);
    let (st, w, _) = call_cap(0, [4, 0, 0], Some(Give { slot: s as u64, rights: all }), false);
    check("a receive that asked is given one: a slot", st == 0 && (1..=32).contains(&w[1]));

    // the copy hangs under the sender's capability: revoking that takes it away from the receiver
    let (_, w, _) = call_cap(0, [13, 0, 0], None, false);
    check("the copy works while the sender's capability does", (w[1] as i64) >= 0);
    revoke(s as u64); // (everything derived from it, not the capability itself)
    let (_, w, _) = call_cap(0, [13, 0, 0], None, false);
    check("... and is gone when the sender revokes what it derived", (w[1] as i64) < 0);

    // a capability sent and revoked before the receiver gets to it is not delivered
    let s2 = shm_create(1);
    call_cap(0, [8, 0, 0], None, false); // (the server answers, then sleeps)
    let st = send_cap(0, [7, 0, 0], Give { slot: s2 as u64, rights: all });
    revoke_self(s2 as u64);
    sleep(15);
    let (_, w, _) = call_cap(0, [9, 0, 0], None, false);
    check("a capability revoked while its message waits in the queue is reported as failed, not given", st == 0 && w[1] == CAP_FAILED);

    // a receiver with no free slot is told
    let s3 = shm_create(1);
    let (_, w, _) = call_cap(0, [10, 0, 0], None, false);
    let filled = w[1];
    let (st, w, _) = call_cap(0, [4, 0, 0], Some(Give { slot: s3 as u64, rights: all }), false);
    check("a receiver whose table is full is told the capability could not be given", filled > 0 && st == 0 && w[1] == CAP_FAILED);
    call_cap(0, [12, 0, 0], None, false);

    // what may not be sent
    let (st1, _, _) = call_cap(0, [4, 0, 0], Some(Give { slot: 0, rights: 1 }), false); // the endpoint capability: this program holds it without the grant right
    let (st2, _, _) = call_cap(0, [4, 0, 0], Some(Give { slot: 15, rights: all }), false); // the console
    let (st3, _, _) = call_cap(0, [4, 0, 0], Some(Give { slot: 29, rights: all }), false); // an empty slot
    check("a capability without the grant right, the console and an empty slot cannot be sent", st1 == -1 && st2 == -1 && st3 == -2);

    call_cap(0, [99, 0, 0], None, false);
    revoke_self(s3 as u64);
    bad
}

program!("captest", |c| if c.arg == 0 { server() } else { client() });
