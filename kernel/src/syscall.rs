//! System calls. ABI: `svc #0`, x0 = id, x1..x5 = arguments, x0 = result
//! (negative = error). Extra results come back in x1..x5.
//!
//! Each handler takes only the locks it needs, in rank order (see `sync.rs`); none runs
//! under a global lock. Handlers for the calling task `cur` may rely on `cur` being owned by
//! this core for the whole call (see sched.rs), so its register frame can be written freely.
#![forbid(unsafe_code)]
use crate::cap::*;
use crate::ipc::{self, Msg};
use crate::mmu::{self, Perm};
use crate::obj::{self, ObjKind};
use crate::sched;
use crate::task::{self, frame, info, State, World, SHM_HI, SHM_LO};
use crate::{compact, irq, mem, ring, timer, uart};

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
pub const RING_SETUP: u64 = 16;
pub const RING_ENTER: u64 = 17;
pub const MEMCTL: u64 = 18;
pub const HEAP_RELEASE: u64 = 19;
pub const NCPUS: u64 = 20;
pub const SYSINFO: u64 = 21;
pub const KILL_ROLE: u64 = 22;
/// Scheduler control and statistics; see `sched_call`.
pub const SCHED: u64 = 23;
/// Programs (spawn.rs): SPAWN(slot, image va, image length, params, delegation) -> task id; WAIT(task, nohang) -> exit
/// code; KILL(task).
pub const SPAWN: u64 = 24;
pub const WAIT: u64 = 25;
pub const KILL: u64 = 26;
/// EP_CREATE(factory slot) -> slot of a new endpoint capability (send+receive+grant); it exists as long as that
/// capability (or until it is revoked).
pub const EP_CREATE: u64 = 27;
/// TASK_LOAD(child, request va) puts pages into an embryo made by SPAWN; TASK_START(child, entry) starts it.
pub const TASK_LOAD: u64 = 28;
pub const TASK_START: u64 = 29;
/// Threads (spawn.rs, thread.rs): THREAD_CREATE(entry, stack top, arg, capability mask) -> thread id; THREAD_EXIT(word, value);
/// WAIT_WORD(address, expected, timeout ticks); WAKE_WORD(address, count) -> woken.
pub const THREAD_CREATE: u64 = 30;
pub const THREAD_EXIT: u64 = 31;
pub const WAIT_WORD: u64 = 32;
pub const WAKE_WORD: u64 = 33;
/// CLOCK(op): 0 = monotonic nanoseconds since the machine started; 1 = wall-clock nanoseconds since 1970 (`E_NOSYS` if
/// the platform has no real-time clock).
pub const CLOCK: u64 = 34;
/// IRQ_RAISE(slot): wake whoever waits on the interrupt line (needs the send right on its capability).
pub const IRQ_RAISE: u64 = 35;
/// QUOTA(op, child, heap, budget): memory limits of the caller's program (op 0) or of one of its children (op 1); see
/// `spawn::quota`.
pub const QUOTA: u64 = 36;
/// SHM_CREATE(pages) -> slot of a new memory capability (map, write, grant) for fresh zeroed memory that can be shared
/// with other programs; see `shm_create`.
pub const SHM_CREATE: u64 = 37;
/// SHM_INFO(slot) -> size in pages of the shared memory object the capability in `slot` names (it needs the map right),
/// plus 1 << 32 if the object's creator has gone (it lives on while someone holds it) and 1 << 33 if `slot` is the creator's
/// capability and no copy of it is held any more (the creator can tell that its partners are gone).
pub const SHM_INFO: u64 = 38;
/// TASK_BASE(child) -> the address an embryo's image area starts at (random if it was spawned with `FLAG_PIE`).
pub const TASK_BASE: u64 = 39;
/// REVOKE_OF(admin slot, task, slot) -> how many capabilities went: revokes the capability in `slot` of `task` (and what was derived from it).
/// Needs an `Admin` capability with `R_REVOKE`; only programs started at run time can be named, never the caller, and never the root capability
/// of an endpoint or of shared memory (that would end the object for everyone).
pub const REVOKE_OF: u64 = 40;
/// RESTORE_OF(admin slot, task, log id) -> the slot: gives back a capability that `REVOKE_OF` took from `task` (`SYSINFO` page 14 lists them), in the
/// slot it had, as a new child of the node it hung under. Needs the same `Admin` capability with `R_REVOKE`. Only what the log holds can come
/// back; a mapping that the revoke removed is not remapped, and copies that were derived from it are gone for good.
pub const RESTORE_OF: u64 = 41;
/// POWER(admin, op): 0 switches the machine off, 1 restarts it. Needs an `Admin` capability with `R_POWER`; does not return when it works.
pub const POWER: u64 = 42;
/// GETRANDOM() -> 0 and 40 random bytes in x1..x5 (little endian), drawn from the kernel's generator, for cryptography. `E_NOSYS` when that generator has no
/// real entropy behind it: no RNDR (FEAT_RNG), no full `opt/metallium/seed`, no virtio-rng device, or one of the layout debugging modes. A caller must treat that
/// as "no secure random numbers" and refuse to do cryptography rather than fall back to something weaker.
pub const GETRANDOM: u64 = 43;
/// Sleep for `a1` microseconds (not rounded up to the 10 ms scheduler tick): the wake-up is an exact counter deadline.
pub const SLEEP_US: u64 = 44;
/// SETTIME(unix_ns): set the wall clock (a machine without a battery-backed clock: the network service sets it from NTP). Only the network service
/// (role 19) may; the value must lie between 2024 and 2100.
pub const SETTIME: u64 = 45;
/// DEVICE_SECRET() -> 0 and 32 bytes in x1..x4: a secret that belongs to this machine (a chip's unique value; QEMU: the fw_cfg file `opt/metallium/device-secret`), the
/// one thing that opens an encrypted data volume without anyone typing a passphrase. Only the data store server (role 6) may ask (`E_PERM`); `E_NOSYS` if the machine has none.
pub const DEVICE_SECRET: u64 = 46;
/// IPC_DEFER() -> a token (the caller's id): park the synchronous call being served, so the server can serve others; `E_NOREPLY` if there is none (or it came through a ring).
pub const IPC_DEFER: u64 = 47;
/// IPC_REPLY_TO(token, w0, w1, w2): answer a caller parked by `IPC_DEFER`; `E_NOREPLY` if it is gone or was not parked by this task.
pub const IPC_REPLY_TO: u64 = 48;
/// ADD_ENTROPY(w0, w1, w2, w3): fold 32 bytes (four little-endian words) from an entropy device into the kernel's generator (`rand.rs`). Only the entropy driver
/// (role 21, the virtio-rng driver) may (`E_PERM`); `E_NOSYS` when the generator takes no outside entropy (the layout debugging modes: every layout is meant to follow from
/// the seed alone). Bytes that arrive make the generator strong enough for `GETRANDOM` even on a CPU without RNDR and with no seed file. A driver may call it again to reseed.
pub const ADD_ENTROPY: u64 = 49;
/// MMAP(addr, pages, prot | flags) -> address: `pages` pages of anonymous zeroed memory, private to the program, in the arena `task::MMAP_LO..MMAP_HI`.
/// Nothing is allocated until a page is first touched (it then counts against the program's memory limit), so a large reservation costs only
/// address space (at most `task::MAX_ANON_VIRT_PAGES` at a time) and page-table entries. `prot` (low byte): `PROT_R` 1, `PROT_W` 2, `PROT_X` 4, or 0 for a
/// reservation nothing may touch; write and execute together are refused (`E_PERM`): code is made by writing a region and then `MPROTECT`ing it
/// to read+execute. Without `MAP_FIXED` the kernel chooses the place (`addr` is ignored): the first at random, the next ones after it, each followed by an
/// unmapped guard page. With `MAP_FIXED` (flags bit 8) the pages at `addr` (inside the arena) are replaced if they are an earlier `MMAP`'s, and made if nothing is
/// there and the program may name addresses (`spawn::fixed_maps_allowed`), so a program that was started with `FLAG_NO_FIXED_MAPS` can re-map only
/// inside what the kernel gave it (a dynamic linker laying its segments out in the space it reserved).
pub const MMAP: u64 = 50;
/// MUNMAP(addr, pages): free the `MMAP` pages in the range (frames, swapped pages and untouched reservations alike; holes are fine); anything in the
/// range that is not an `MMAP` page is `E_INVAL`, and nothing is changed.
pub const MUNMAP: u64 = 51;
/// MPROTECT(addr, pages, prot): change the protection of `MMAP` pages, which must all exist (`E_INVAL`). Write+execute is `E_PERM`; a page that becomes
/// executable has its instruction cache made coherent first, so code written before the call runs.
pub const MPROTECT: u64 = 52;
pub const MAP_FIXED: u64 = 1 << 8;
pub const SC_RT_SET: u64 = 1;
pub const SC_RT_WAIT: u64 = 2;
pub const SC_RT_CLEAR: u64 = 3;
pub const SC_STATS: u64 = 4;

pub const E_PERM: i64 = -1;
pub const E_BADCAP: i64 = -2;
pub const E_FULL: i64 = -3;
pub const E_DEAD: i64 = -4;
pub const E_INVAL: i64 = -5;
pub const E_NOREPLY: i64 = -6;
pub const E_NOSYS: i64 = -7;
pub const E_NOMEM: i64 = -8;
/// A timed wait (IRQ_WAIT with a timeout) expired.
pub const E_TIMEDOUT: i64 = -9;

pub const CONSOLE_SLOT: usize = 15;
/// Free slots in a table that a program's `CAP_GRANT` into another program may not use up (see `cap_grant`).
const GRANT_RESERVE_SLOTS: usize = 4;
const MAX_LOG: usize = 256;

pub enum Out {
    Ret(i64),
    /// Task blocked; its result is written into its frame when it wakes.
    Block,
}

/// Look up a capability of the given kind with at least the rights `need`.
/// (The task lock is released before the node table is consulted; a concurrent revoke can
/// still win the race, like any revoke that lands just after a successful check.)
pub fn lookup(tid: usize, slot: u64, kind: Kind, need: Rights) -> Result<Cap, i64> {
    let c = *task::lock(tid).caps.get(slot as usize).ok_or(E_BADCAP)?;
    if c.kind != kind || !c.alive() {
        return Err(E_BADCAP);
    }
    if c.rights & need != need {
        return Err(E_PERM);
    }
    Ok(c)
}

/// Bit `t` of the task masks the task-manager pages answer with: only the first 64 task slots have one.
/// Bit `t % 64` if task `t` lies in window `w` (tasks `64 * w..64 * w + 64`), else 0: the task-holder masks of SYSINFO pages 11 and 13 cover one window at a time.
fn task_bit(t: usize, w: usize) -> u64 {
    if t / 64 == w { 1 << (t % 64) } else { 0 }
}

fn lookup_any(tid: usize, slot: u64) -> Result<Cap, i64> {
    let c = *task::lock(tid).caps.get(slot as usize).ok_or(E_BADCAP)?;
    if c.kind == Kind::None || !c.alive() {
        return Err(E_BADCAP);
    }
    Ok(c)
}

fn run(cur: usize) -> (u64, Out) {
    let f = *frame(cur);
    let (id, a1, a2, a3, a4) = (f.x[0], f.x[1], f.x[2], f.x[3], f.x[4]);
    // These look at another task's state under its lock and then act on it: the end of that task must not slip in between (task.rs `TEARDOWN`).
    // A message that carries a capability, or a receive that takes one, puts a copy into another task's table: the same exclusion as `CAP_GRANT`.
    let moves_cap = match id {
        IPC_SEND | IPC_CALL | IPC_REPLY_TO => f.x[5] & CAP_XFER != 0,
        IPC_REPLY => a4 & CAP_XFER != 0,
        IPC_RECV => a2 & RECV_ACCEPT != 0,
        _ => false,
    };
    let _life = (moves_cap || matches!(id, CAP_GRANT | RESTORE_OF | SPAWN | WAIT | TASK_START | THREAD_CREATE)).then(task::lifecycle);
    let out = match id {
        YIELD => Out::Ret(0),
        IPC_SEND | IPC_CALL => ipc_send(cur, a1, [a2, a3, a4], id == IPC_CALL, f.x[5]),
        IPC_RECV => ipc_recv(cur, a1, a2 & 1 != 0, a2 & RECV_ACCEPT != 0), // a2 bit 0: do not wait (E_AGAIN, -10, if nothing is queued); bit 1: take a capability that comes with the message
        IPC_REPLY => match cap_spec(cur, a4) {
            Ok(cap) => Out::Ret(if ipc::reply(cur, [a1, a2, a3], cap) { 0 } else { E_NOREPLY }),
            Err(e) => Out::Ret(e),
        },
        IPC_DEFER => Out::Ret(ipc::defer(cur).map_or(E_NOREPLY, |t| t as i64)),
        IPC_REPLY_TO => match cap_spec(cur, f.x[5]) {
            Ok(cap) => Out::Ret(if ipc::reply_to(cur, a1, [a2, a3, a4], cap) { 0 } else { E_NOREPLY }),
            Err(e) => Out::Ret(e),
        },
        MEM_MAP => mem_map(cur, a1, a2 as usize, a3 != 0),
        CAP_GRANT => cap_grant(cur, a1, a2, a3 as Rights, a4),
        CAP_REVOKE => cap_revoke(cur, a1, a2 & 1 != 0),
        LOG => log(cur, a1, a2 as usize, a3 as usize),
        SLEEP => {
            frame(cur).x[0] = 0; // the result, written before the task can be woken
            let wake_at = timer::counter().saturating_add(a1.saturating_mul(timer::interval())).min(1 << 55);
            sched::set_state(cur, State::Sleep(wake_at));
            Out::Block
        }
        TICKS => Out::Ret(timer::ticks() as i64),
        NCPUS => Out::Ret(crate::smp::online_mask().count_ones() as i64),
        SYSINFO => sysinfo(cur, a1, a2),
        KILL_ROLE => kill_role(cur, a1, a2),
        REVOKE_OF => revoke_of(cur, a1, a2, a3),
        RESTORE_OF => restore_of(cur, a1, a2, a3),
        POWER => power(cur, a1, a2),
        SCHED => sched_call(cur, [a1, a2, a3, a4, f.x[5]]),
        SPAWN => match lookup(cur, a1, Kind::Spawn, R_SPAWN) {
            Err(e) => Out::Ret(e),
            Ok(c) => Out::Ret(crate::spawn::spawn(cur, c.rights, a2 as usize).map_or_else(|e| e, |tid| tid as i64)),
        },
        WAIT => match crate::spawn::wait(cur, a1 as usize, a2 != 0) {
            crate::spawn::Waited::Code(c) => Out::Ret(c as i64),
            crate::spawn::Waited::Err(e) => Out::Ret(e),
            crate::spawn::Waited::Blocked => Out::Block,
        },
        KILL => Out::Ret(crate::spawn::kill(cur, a1 as usize)),
        TASK_LOAD => Out::Ret(crate::spawn::task_load(cur, a1 as usize, a2 as usize).map_or_else(|e| e, |()| 0)),
        TASK_START => Out::Ret(crate::spawn::task_start(cur, a1 as usize, a2 as usize).map_or_else(|e| e, |()| 0)),
        THREAD_CREATE => Out::Ret(crate::spawn::thread_create(cur, a1 as usize, a2 as usize, a3, a4 as u32, f.x[5] as usize).map_or_else(|e| e, |tid| tid as i64)),
        THREAD_EXIT if task::aspace(cur) == cur => Out::Ret(E_PERM), // (the program's first task ends with EXIT)
        THREAD_EXIT => {
            task::die_thread(cur, (a1 as usize, a2 as u32));
            Out::Block
        }
        WAIT_WORD => match crate::thread::wait(cur, a1 as usize, a2 as u32, a3) {
            crate::thread::Wait::Ret(r) => Out::Ret(r),
            crate::thread::Wait::Blocked => Out::Block,
        },
        WAKE_WORD => Out::Ret(crate::thread::wake(cur, a1 as usize, a2 as usize)),
        CLOCK => match a1 {
            0 => Out::Ret(timer::now_ns() as i64),
            1 => timer::wall_ns().map_or(Out::Ret(E_NOSYS), |ns| Out::Ret(ns as i64)),
            _ => Out::Ret(E_INVAL),
        },
        SLEEP_US => {
            frame(cur).x[0] = 0;
            let wake_at = timer::counter().saturating_add(timer::us_to_counter(a1.min(1_000_000))).min(1 << 55);
            sched::set_state(cur, State::Sleep(wake_at));
            Out::Block
        }
        ADD_ENTROPY => {
            const ENTROPY_ROLE: u8 = 21;
            if task::info(cur).role != ENTROPY_ROLE {
                Out::Ret(E_PERM)
            } else {
                let mut b = [0u8; 32];
                for (i, w) in [a1, a2, a3, a4].iter().enumerate() {
                    b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
                }
                let taken = crate::rand::add_entropy(&b);
                b.fill(0);
                Out::Ret(if taken { 0 } else { E_NOSYS })
            }
        }
        SETTIME => {
            const NETD_ROLE: u8 = 19;
            const Y2024: u64 = 1_704_067_200;
            const Y2100: u64 = 4_102_444_800;
            if task::info(cur).role != NETD_ROLE {
                Out::Ret(E_PERM)
            } else if !(Y2024 * 1_000_000_000..Y2100 * 1_000_000_000).contains(&a1) {
                Out::Ret(E_INVAL)
            } else {
                timer::set_wall(a1);
                Out::Ret(0)
            }
        }
        DEVICE_SECRET => {
            const STORE_ROLE: u8 = 6;
            if task::info(cur).role != STORE_ROLE {
                Out::Ret(E_PERM)
            } else if let Some(mut s) = crate::platform::device_secret() {
                let mut f = frame(cur);
                for i in 0..4 {
                    f.x[i + 1] = u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
                }
                s.fill(0);
                Out::Ret(0)
            } else {
                Out::Ret(E_NOSYS)
            }
        }
        GETRANDOM => {
            let mut b = [0u8; 40];
            if crate::rand::secure_fill(&mut b) {
                let mut f = frame(cur);
                for i in 0..5 {
                    f.x[i + 1] = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
                }
                b.fill(0);
                Out::Ret(0)
            } else {
                Out::Ret(E_NOSYS)
            }
        }
        IRQ_RAISE => match lookup(cur, a1, Kind::Irq, R_SEND) {
            Ok(c) => {
                irq::raise(c.obj);
                Out::Ret(0)
            }
            Err(e) => Out::Ret(e),
        },
        EP_CREATE => ep_create(cur, a1),
        IRQ_WAIT => irq_wait(cur, a1, a2),
        CAP_INFO => cap_info(cur, a1),
        QUOTA => Out::Ret(crate::spawn::quota(cur, a1, a2, a3, a4)),
        SHM_CREATE => shm_create(cur, a1 as usize),
        SHM_INFO => shm_info(cur, a1),
        TASK_BASE => Out::Ret(crate::spawn::task_base(cur, a1 as usize).map_or_else(|e| e, |b| b as i64)),
        HEAP_GROW => heap_grow(cur, a1 as usize),
        MMAP => mmap(cur, a1 as usize, a2 as usize, a3),
        MUNMAP => munmap(cur, a1 as usize, a2 as usize),
        MPROTECT => mprotect(cur, a1 as usize, a2 as usize, a3),
        HEAP_RELEASE => heap_release(cur, a1 as usize, a2 as usize),
        MEMCTL => memctl(cur, a1, a2, a3, a4),
        RING_SETUP => Out::Ret(ring_setup(cur)),
        RING_ENTER => match ring::enter(cur, a1 as u32, a2 as u32) {
            Err(e) => Out::Ret(e),
            Ok((n, false)) => Out::Ret(n as i64),
            Ok((_, true)) => Out::Block, // result register already written by `enter`
        },
        EXIT => {
            crate::spawn::set_exit_code(cur, a1);
            if cur == 0 {
                if cfg!(feature = "park-on-exit") {
                    // window mode: the system stays up so the information screen keeps updating;
                    // only the CPU-hog demo is stopped
                    task::condemn_role(3, sched::Doom::Killed);
                } else {
                    sched::finish(a1 as u32);
                }
            }
            task::die(cur, "exited");
            Out::Block
        }
        _ => Out::Ret(E_NOSYS),
    };
    (id, out)
}

/// Handle a syscall for `cur`; returns whether the scheduler should preempt.
pub fn handle(cur: usize) -> bool {
    crate::swap::clear_retry();
    let (id, out) = run(cur);
    crate::pager::kick_if_pending();
    if matches!(id, LOG | WAIT_WORD | WAKE_WORD) && matches!(out, Out::Ret(_)) && crate::swap::take_retry() {
        // the memory it reads is on disk and the pager has been asked for it: sleep a tick and run the call again
        frame(cur).elr -= 4;
        sched::set_state(cur, State::Sleep(timer::counter().saturating_add(timer::interval())));
        return false;
    }
    if let Out::Ret(r) = out {
        frame(cur).x[0] = r as u64;
    }
    if id == YIELD {
        sched::expire_slice(cur); // give the core to an equal competitor, if there is one
    }
    id == YIELD || id == SCHED
}

/// Switch off or restart the machine on behalf of a task that holds the right to.
fn power(cur: usize, slot: u64, op: u64) -> Out {
    if let Err(e) = lookup(cur, slot, Kind::Admin, R_POWER) {
        return Out::Ret(e);
    }
    if op > 1 {
        return Out::Ret(E_INVAL);
    }
    crate::kprintln!("[kernel] {} requested by task {cur}", if op == 1 { "restart" } else { "power off" });
    crate::frame::cpu::psci_power(op == 1);
    // the firmware did not do it: a switch-off can still end the emulator
    if op == 0 {
        sched::semihost_exit(0);
    }
    Out::Ret(E_NOSYS)
}

fn ep_create(cur: usize, slot: u64) -> Out {
    if let Err(e) = lookup(cur, slot, Kind::Factory, R_EP_CREATE) {
        return Out::Ret(e);
    }
    let mut t = task::lock(cur);
    let Some(free) = (0..NCAPS).find(|&i| i != CONSOLE_SLOT && t.caps[i].kind == Kind::None) else { return Out::Ret(E_NOMEM) };
    let Some(minted) = mint_for(task::aspace(cur), None) else { return Out::Ret(E_NOMEM) };
    let node = minted.id;
    match ipc::claim_dynamic(cur, node) {
        Some(e) => {
            t.caps[free] = Cap::new(Kind::Endpoint, e, R_SEND | R_RECV | R_GRANT, minted);
            sched::note_recv_endpoint(cur, e);
            Out::Ret(free as i64)
        }
        None => {
            free_node(node);
            Out::Ret(E_FULL)
        }
    }
}

fn ring_setup(cur: usize) -> i64 {
    if task::aspace(cur) != cur {
        return E_PERM; // one ring per address space: the program's first task has it
    }
    let mut t = task::lock(cur);
    ring::setup(&mut t, cur).map_or_else(|e| e, |va| va as i64)
}

/// A capability travels with a message when the register that follows the words holds a transfer spec: `CAP_XFER` (bit 62) set, the sender's slot plus one in
/// bits 0..7 (so 0 names no slot), the rights the copy gets in bits 8..23 (ANDed with the sender's own: rights only shrink). The sender needs the grant right on
/// it, as for `CAP_GRANT`, and the console cannot be sent. On `IPC_CALL`, `CAP_ACCEPT` (bit 61) says the caller will take a capability with the reply. No
/// spec (the marker bit clear: every caller that predates this, whatever else is in the register) sends none.
const CAP_XFER: u64 = 1 << 62;
const CAP_ACCEPT: u64 = 1 << 61;
/// `IPC_RECV` argument bit 1: give the capability that comes with the message (if any) to this task; the receiver's table is not touched otherwise.
const RECV_ACCEPT: u64 = 2;

fn cap_spec(cur: usize, spec: u64) -> Result<Option<Cap>, i64> {
    if spec & CAP_XFER == 0 {
        return Ok(None);
    }
    let slot = spec & 0xFF;
    if slot == 0 {
        return Ok(None); // (flags only: an `IPC_CALL` that sends nothing but will take a capability with the reply)
    }
    if slot as usize > NCAPS {
        return Err(E_BADCAP);
    }
    if slot as usize - 1 == CONSOLE_SLOT {
        return Err(E_PERM);
    }
    let c = lookup_any(cur, slot - 1)?;
    if c.rights & R_GRANT == 0 {
        return Err(E_PERM);
    }
    Ok(Some(Cap { rights: c.rights & ((spec >> 8) & 0xFFFF) as Rights, ..c }))
}

fn ipc_send(cur: usize, slot: u64, w: [u64; 3], call: bool, spec: u64) -> Out {
    let c = match lookup(cur, slot, Kind::Endpoint, R_SEND) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    let cap = match cap_spec(cur, spec) {
        Ok(cap) => cap,
        Err(e) => return Out::Ret(e),
    };
    if call {
        task::lock(cur).reply_cap_ok = spec & CAP_ACCEPT != 0 && spec & CAP_XFER != 0;
    }
    match ipc::send(cur, c.obj, Msg { sender: cur as u16, call, tag: 0, w, cap }) {
        Err(ipc::SendErr::Full) => Out::Ret(E_FULL),
        Ok(()) if call => Out::Block, // `send` left the caller blocked in CallWait
        Ok(()) => Out::Ret(0),
    }
}

fn ipc_recv(cur: usize, slot: u64, nonblock: bool, accept: bool) -> Out {
    let c = match lookup(cur, slot, Kind::Endpoint, R_RECV) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    match ipc::recv(cur, c.obj, !nonblock, accept) {
        ipc::Recv::Got => Out::Ret(0), // payload already in x1..x5
        ipc::Recv::Blocked => Out::Block,
        ipc::Recv::Busy => Out::Ret(E_FULL),
        ipc::Recv::Empty => Out::Ret(crate::spawn::E_AGAIN),
    }
}

/// Where `pages` pages can go in the mapping windows when the program does not say: a random page-aligned place with
/// one unmapped page between it and every other mapping (and the window's edge). The usual window is tried first for
/// objects up to `AUTO_SMALL_MAX` pages, then the large one, then the arena of `MMAP`.
const AUTO_SMALL_MAX: usize = 128;

fn pick_map_address(t: &task::Task, pages: usize) -> Option<usize> {
    let windows: &[(usize, usize)] = if pages <= AUTO_SMALL_MAX { &[(SHM_LO, SHM_HI), (task::BIG_SHM_LO, task::BIG_SHM_HI)] } else { &[(task::BIG_SHM_LO, task::BIG_SHM_HI)] };
    for &(lo, hi) in windows {
        // the object and a guard page after it must fit (the page before the window is unmapped anyway)
        let Some(room) = ((hi - lo) / mem::PAGE).checked_sub(pages + 1) else { continue };
        for _ in 0..32 {
            let va = lo + crate::rand::below(room + 1) * mem::PAGE;
            let (a, b) = (va - mem::PAGE, va + (pages + 1) * mem::PAGE); // guards included
            if t.maps.iter().all(|m| !m.used || b <= m.va || m.va + m.pages * mem::PAGE <= a) {
                return Some(va);
            }
        }
        // Chance found nothing (the window is nearly full): the first gap that fits, scanning the mappings in address order.
        let mut at = lo; // lowest address the object may start at
        loop {
            let end = at + (pages + 1) * mem::PAGE;
            if end > hi + mem::PAGE {
                break;
            }
            // the lowest mapping that gets in the way (a mapping within a page of either end counts)
            let clash = t.maps.iter().filter(|m| m.used && at < m.va + m.pages * mem::PAGE + mem::PAGE && m.va < end).map(|m| m.va + m.pages * mem::PAGE + mem::PAGE).max();
            match clash {
                None if at + pages * mem::PAGE <= hi => return Some(at),
                None => break,
                Some(next) => at = next,
            }
        }
    }
    // The two windows are full (or the object is too big for them): the arena of `MMAP`, which is 128 GiB, with a free page on both sides.
    let (lo, hi) = (task::MMAP_LO, task::MMAP_HI);
    let need = (pages + 2) * mem::PAGE;
    if need <= hi - lo {
        for _ in 0..64 {
            let va = lo + crate::rand::below((hi - lo - need) / mem::PAGE + 1) * mem::PAGE + mem::PAGE;
            if mmu::range_free(t.l1, va - mem::PAGE, pages + 2) {
                return Some(va);
            }
        }
    }
    None
}

/// `MEM_MAP(slot, va, writable)`. With `va` = 0 the kernel chooses the address (see `pick_map_address`) and returns it.
fn mem_map(cur: usize, slot: u64, va: usize, writable: bool) -> Out {
    let c = match lookup(cur, slot, Kind::Memory, R_MAP) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    if writable && c.rights & R_WRITE == 0 {
        return Out::Ret(E_PERM);
    }
    let Some(o) = obj::get(c.obj) else { return Out::Ret(E_BADCAP) };
    if o.kind == ObjKind::Mmio && c.rights & R_WRITE == 0 {
        return Out::Ret(E_PERM); // a device window is always mapped writable (below): without the write right it is not mapped at all
    }
    // (`va` comes from userspace: a sum that wraps must not pass the window check)
    let auto = va == 0;
    if !auto && !crate::spawn::fixed_maps_allowed(task::aspace(cur)) {
        return Out::Ret(E_PERM); // this program asked to have its mappings placed by the kernel
    }
    let end = va.checked_add(o.pages * mem::PAGE);
    let in_window = |lo: usize, hi: usize| va >= lo && end.map_or(false, |e| e <= hi);
    if !auto && (!(in_window(SHM_LO, SHM_HI) || in_window(task::BIG_SHM_LO, task::BIG_SHM_HI)) || va % mem::PAGE != 0) {
        return Out::Ret(E_INVAL);
    }
    let space = task::aspace(cur); // (a thread maps into its program's address space)
    let mut t = task::lock(space);
    // A revoke kills the nodes first and clears the tasks' tables afterwards, one lock at a time, so a node that is alive here is
    // swept out of this table only after this lock is released: the mapping below is recorded under it and the sweep will find and
    // remove it. Without this check a revoke landing after `lookup` would leave a mapping of freed memory behind.
    if !c.alive() {
        return Out::Ret(E_BADCAP);
    }
    let va = if auto {
        match pick_map_address(&t, o.pages) {
            Some(v) => v,
            None => return Out::Ret(E_NOMEM),
        }
    } else {
        va
    };
    if (0..o.pages).any(|p| mmu::is_present(t.l1, va + p * mem::PAGE)) {
        return Out::Ret(E_INVAL);
    }
    let Some(rec) = t.maps.iter().position(|m| !m.used) else { return Out::Ret(E_NOMEM) };
    let perm = match (o.kind, writable) {
        (ObjKind::Mmio, _) => Perm::Device, // MMIO is never read-only: reads have side effects too
        (_, true) => Perm::Rw,
        (_, false) => Perm::Ro,
    };
    for p in 0..o.pages {
        let pa = if o.kind == ObjKind::Shared { obj::shm_frame(&o, p) } else { o.pa + p * mem::PAGE };
        let r = mmu::map_user(t.l1, va + p * mem::PAGE, pa, perm, mem::OWNER_TASK0 + space as u16);
        if r.is_err() {
            for q in 0..p {
                mmu::unmap_user(t.l1, va + q * mem::PAGE);
            }
            return Out::Ret(E_NOMEM);
        }
    }
    t.maps[rec] = task::MapRec { used: true, va, pages: o.pages, node: c.node };
    drop(t);
    if auto && crate::platform::map_log() {
        crate::kprintln!("[map] task {space} role {} object {} ({} pages) at {va:#x}", task::info(space).role, c.obj, o.pages);
    }
    Out::Ret(if auto { va as i64 } else { 0 })
}

/// System facts for the information screen. Unprivileged: it reveals nothing a task could not
/// observe anyway. Page 0: (CPU id register, RAM frames, free frames, online CPUs, timer Hz).
/// Page 1: (IOMMU enabled, devices it confines, live tasks, driver restarts so far).
/// Page 2: (the harness asked for an interactive run, chaos-test seed or 0).
/// Page 9: the caller's layout (heap start, stack top, ASLR on, FEAT_RNG present).
/// Page 3, `arg` = task id: that task's (name 0..8, name 8..16, state code, restarts, role).
/// A boot endpoint's name, at most 16 bytes (the task manager shows it).
fn ep_name(e: u16) -> &'static str {
    match e {
        ipc::EP_SERVICE => "service",
        ipc::EP_DRIVER => "driver",
        ipc::EP_BLK => "block driver",
        ipc::EP_ROFS => "system files",
        ipc::EP_LFS => "data files",
        ipc::EP_VFS => "file system",
        6..=9 => "benchmark",
        ipc::EP_SESSIONS => "session service",
        ipc::EP_BENCH_GO..=15 => "benchmark go",
        ipc::EP_AUDIO => "audio service",
        ipc::EP_GPU => "display driver",
        ipc::EP_INFO => "info",
        ipc::EP_KBD => "input driver",
        ipc::EP_MONKEY => "fault injector",
        ipc::EP_NET => "network driver",
        ipc::EP_TTY..=24 => "tty console",
        _ => "endpoint",
    }
}

/// A memory object's name, at most 16 bytes.
fn obj_name(o: u16) -> &'static str {
    match o {
        obj::OBJ_SHARED => "shared",
        obj::OBJ_BLK_MMIO => "blk registers",
        obj::OBJ_BLK_RING => "blk ring",
        obj::OBJ_BLK_BUF_ROFS => "blk buf rofs",
        obj::OBJ_BLK_BUF_LFS => "blk buf lfs",
        obj::OBJ_BLK_BUF_CLIENT => "blk buf client",
        obj::OBJ_SHM_ROFS => "rofs shm",
        obj::OBJ_SHM_LFS => "lfs shm",
        obj::OBJ_SHM_ROFS_VFS => "rofs-vfs shm",
        obj::OBJ_SHM_LFS_VFS => "lfs-vfs shm",
        obj::OBJ_SHM_VFS_CLIENT => "vfs client shm",
        obj::OBJ_SHM_VFS_PROGRAM => "vfs program shm",
        obj::OBJ_SHM_BENCH => "bench results",
        obj::OBJ_BLK_PCICFG => "blk pci config",
        obj::OBJ_GPU_MMIO => "gpu registers",
        obj::OBJ_GPU_PCICFG => "gpu pci config",
        obj::OBJ_GPU_QUEUE => "gpu queue",
        obj::OBJ_GPU_CMD => "gpu commands",
        obj::OBJ_GPU_FB => "framebuffer",
        obj::OBJ_KBD_MMIO => "input registers",
        obj::OBJ_KBD_PCICFG => "input pci conf",
        obj::OBJ_KBD_QUEUE => "input queue",
        obj::OBJ_SHM_VFS_SHELL => "vfs shell shm",
        obj::OBJ_SHM_SPIN => "spin flag",
        obj::OBJ_SHM_VFS_REGION => "vfs sessions",
        obj::OBJ_USB_MMIO => "usb registers",
        obj::OBJ_USB_PCICFG => "usb pci config",
        obj::OBJ_USB_DMA => "usb memory",
        obj::OBJ_NET_MMIO => "net registers",
        obj::OBJ_NET_PCICFG => "net pci config",
        obj::OBJ_NET_QUEUES => "net queues",
        obj::OBJ_NET_BUFS => "net buffers",
        obj::OBJ_NET_RING => "net ring",
        obj::OBJ_SHM_NET_REGION => "net sessions",
        _ if (obj::OBJ_SHM_VFS_PROG0..obj::OBJ_SHM_VFS_PROG0 + obj::MAX_SESSIONS as u16).contains(&o) => "vfs program shm",
        _ if (obj::OBJ_SHM_NET_PROG0..obj::OBJ_SHM_NET_PROG0 + obj::MAX_SESSIONS as u16).contains(&o) => "net program shm",
        obj::OBJ_PTR_MMIO => "pointer regs",
        obj::OBJ_PTR_PCICFG => "pointer pci cfg",
        obj::OBJ_PTR_QUEUE => "pointer queue",
        obj::OBJ_RNG_DMA => "rng buffer",
        _ if obj::is_dynamic(o) => "shared memory",
        _ => "memory",
    }
}

/// Pages 10, 11, 13 and 14 show what other tasks hold and what was taken from them (slots, object numbers, rights, node numbers,
/// the log of revoked capabilities). That is the task manager's business, so they need an `Admin` capability; without one a
/// program could read, among other things, which slots of another program are free (SECURITY.md, L1).
fn sysinfo_needs_admin(cur: usize, page: u64) -> bool {
    matches!(page, 10 | 11 | 13 | 14) && !task::lock(cur).caps.iter().any(|c| c.kind == Kind::Admin && c.alive())
}

fn sysinfo(cur: usize, page: u64, arg: u64) -> Out {
    if sysinfo_needs_admin(cur, page) {
        return Out::Ret(E_PERM);
    }
    let mut f = frame(cur);
    match page {
        0 => {
            f.x[1] = crate::frame::cpu::midr();
            f.x[2] = mem::total_frames() as u64;
            f.x[3] = mem::free_frames() as u64;
            f.x[4] = crate::smp::online_mask().count_ones() as u64;
            f.x[5] = timer::HZ;
            Out::Ret(0)
        }
        1 => {
            let (enabled, devices) = crate::smmu::summary();
            f.x[1] = enabled as u64;
            f.x[2] = devices as u64;
            f.x[3] = (0..task::limit()).filter(|&t| !matches!(sched::state(t), State::Free | State::Dead)).count() as u64;
            f.x[4] = (0..task::limit()).map(|t| task::RESTARTS[t].load(core::sync::atomic::Ordering::Relaxed) as u64).sum();
            f.x[5] = crate::cap::nodes_in_use() as u64;
            Out::Ret(0)
        }
        3 => {
            // one row of the task table: (name bytes 0..8, name bytes 8..16, state code, restarts, role)
            let t = arg as usize;
            if t >= task::limit() {
                return Out::Ret(E_INVAL);
            }
            let code = match sched::state(t) {
                State::Free => 0,
                State::Ready => 1,
                State::RecvWait(_) => 2,
                State::CallWait => 3,
                State::Sleep(_) => 4,
                State::IrqWait(_) => 5,
                State::RingWait(_) => 6,
                State::Dead => 7,
                State::ChildWait(_) => 8,
                State::Embryo => 9,
                State::WordWait(_) => 10,
            };
            let nm = info(t).name;
            let name = nm.as_bytes();
            let pack = |off: usize| (0..8).fold(0u64, |v, i| v | (name.get(off + i).copied().unwrap_or(0) as u64) << (8 * i));
            f.x[1] = pack(0);
            f.x[2] = pack(8);
            f.x[3] = code;
            f.x[4] = task::RESTARTS[t].load(core::sync::atomic::Ordering::Relaxed) as u64;
            f.x[5] = info(t).role as u64;
            Out::Ret(0)
        }
        7 => {
            // pages task `arg` holds (a program's heap, stack, code, page tables, buffers; a thread counts for its program)
            let t = arg as usize;
            if t >= task::limit() {
                return Out::Ret(E_INVAL);
            }
            f.x[1] = mem::count_owned(mem::OWNER_TASK0 + task::aspace(t) as u16) as u64;
            Out::Ret(0)
        }
        8 => {
            // the caller's own task id (a thread's program: the id other programs know it by)
            f.x[1] = task::aspace(cur) as u64;
            Out::Ret(0)
        }
        2 => {
            f.x[1] = crate::platform::interactive() as u64;
            f.x[2] = crate::platform::chaos_seed();
            f.x[3] = crate::platform::only();
            Out::Ret(0)
        }
        5 => {
            // a program's file-system session: (page index or 255, generation, program, parent program or 255); see spawn.rs
            let t = arg as usize;
            if t >= task::limit() {
                return Out::Ret(E_INVAL);
            }
            let (page, gen, owner) = crate::spawn::fs_session(t);
            f.x[1] = page as u64;
            f.x[2] = gen;
            f.x[3] = owner as u64; // (the program a thread belongs to)
            f.x[4] = crate::spawn::parent_of(owner) as u64; // (the program that started it, 255 if none)
            Out::Ret(0)
        }
        6 => {
            // a program's network session: (page index or 255, generation, program); see spawn.rs
            let t = arg as usize;
            if t >= task::limit() {
                return Out::Ret(E_INVAL);
            }
            let (page, gen, owner) = crate::spawn::net_session(t);
            f.x[1] = page as u64;
            f.x[2] = gen;
            f.x[3] = owner as u64;
            Out::Ret(0)
        }
        9 => {
            // the layout of the caller's program: (heap window start, stack top, randomisation on, hardware random numbers)
            let t = task::lock(task::aspace(cur));
            f.x[1] = t.heap_base as u64;
            f.x[2] = t.stack_top as u64;
            f.x[3] = crate::rand::enabled() as u64;
            f.x[4] = crate::rand::has_hardware() as u64;
            Out::Ret(0)
        }
        18 => {
            // how many file sessions and network sessions there are (x1), and task slots (x2): the servers size their tables to them
            f.x[1] = crate::obj::sessions() as u64;
            f.x[2] = task::limit() as u64;
            Out::Ret(0)
        }
        19 => {
            // what the machine's display and storage are called (16 bytes each, NUL padded, in x1,x2 and x3,x4): `fetch` shows them
            let pack = |s: &str| {
                let mut w = [0u64; 2];
                for (i, b) in s.bytes().take(16).enumerate() {
                    w[i / 8] |= (b as u64) << (8 * (i % 8));
                }
                w
            };
            let (g, s) = (pack(crate::platform::gpu_name()), pack(crate::platform::storage_name()));
            f.x[1] = g[0];
            f.x[2] = g[1];
            f.x[3] = s[0];
            f.x[4] = s[1];
            Out::Ret(0)
        }
        20 => {
            // why the machine has no IOMMU, in at most 32 bytes (x1..x4, NUL padded): `fetch` shows it when SYSINFO page 1 says no device is confined
            let s = crate::platform::iommu_note();
            let mut w = [0u64; 4];
            for (i, b) in s.bytes().take(32).enumerate() {
                w[i / 8] |= (b as u64) << (8 * (i % 8));
            }
            f.x[1..5].copy_from_slice(&w);
            Out::Ret(0)
        }
        15 => {
            // how many capability nodes there are (the Capabilities program draws its meter against it)
            f.x[1] = crate::cap::NODES as u64;
            Out::Ret(0)
        }
        17 => {
            // the capacity of the second memory tier (read-only): bytes of the compressed store (the result), its slots (x1), the pages the pager may
            // write to disk in an hour (x2). The memory daemon scales its policy to them.
            f.x[1] = crate::swap::NSLOTS as u64;
            f.x[2] = crate::pager::WRITE_CAP_PER_HOUR;
            Out::Ret(crate::swap::pool_bytes() as i64)
        }
        16 => {
            // the second memory tier, for the task manager (read-only): pages written back so far (the result), pages read back (x1), pages now on disk
            // | pager running << 16 (x2), bytes in the compressed store (x3), pages written this hour | the hourly cap << 32 (x4), writes held back (x5)
            let (s, z) = (crate::pager::stats(), crate::swap::stats());
            f.x[1] = s.read;
            f.x[2] = s.slots_used | (s.registered as u64) << 16;
            f.x[3] = z.bytes;
            f.x[4] = s.hour_writes | crate::pager::WRITE_CAP_PER_HOUR << 32;
            f.x[5] = s.deferred;
            Out::Ret(s.written as i64)
        }
        10 => {
            // one capability slot of a task, for the task manager: `arg` = task | slot << 16; answers (kind, object, rights, node), kind 0 for an
            // empty slot (Endpoint 1, Memory 2, Console 3, Irq 4, MemCtl 5, Admin 6, Sched 7, Spawn 8, Factory 9). Read-only, like the other pages.
            let (t, slot) = ((arg & 0xFFFF) as usize, (arg >> 16) as usize);
            if t >= task::limit() || slot >= NCAPS {
                return Out::Ret(E_INVAL);
            }
            let mut c = task::lock(t).caps[slot];
            if !c.alive() {
                c = Cap::NONE; // (revoked: as good as empty)
            }
            f.x[1] = c.kind as u8 as u64;
            f.x[2] = c.obj as u64;
            f.x[3] = c.rights as u64;
            f.x[4] = c.node as u64;
            Out::Ret(0)
        }
        14 => {
            // what has been revoked from a task and can be given back, for the capabilities manager: `arg` = task | n << 16, the nth (oldest first).
            // Answers (id, slot, kind, object, rights | 1 << 16 if what it hung under is still there); `x0` is E_INVAL past the end. Read-only.
            let (t, n) = ((arg & 0xFFFF) as usize, (arg >> 16) as usize);
            if t >= task::limit() {
                return Out::Ret(E_INVAL);
            }
            match crate::cap::revoked_nth(t, n) {
                (Some(r), _) => {
                    (f.x[1], f.x[2], f.x[3], f.x[4], f.x[5]) = (r.id as u64, r.slot as u64, r.kind as u8 as u64, r.obj as u64, r.rights as u64 | ((if r.parent == crate::cap::NO_PARENT { crate::spawn::session_cap_ok(t, r.slot as usize, r.kind, r.obj, r.rights) } else { crate::cap::node_is(r.parent, r.parent_gen) }) as u64) << 16);
                    Out::Ret(0)
                }
                _ => Out::Ret(E_INVAL),
            }
        }
        13 => {
            // what revoking a capability would take with it, for the task manager: `arg` = task | slot << 16 | window << 24. Answers (how many other
            // capabilities are derived from it, a bit mask of the tasks of that window (64 tasks: `window * 64 ..`) holding them, how many capability nodes hang under it (it included), 1 if it is the root capability
            // of its object, which `REVOKE_OF` refuses). Read-only.
            let (t, slot, w) = ((arg & 0xFFFF) as usize, (arg >> 16 & 0xFF) as usize, (arg >> 24) as usize);
            if t >= task::limit() || slot >= NCAPS {
                return Out::Ret(E_INVAL);
            }
            let c = task::lock(t).caps[slot];
            if c.kind == Kind::None || !c.alive() {
                return Out::Ret(E_BADCAP);
            }
            let mut marked = crate::cap::NodeSet::EMPTY;
            let nodes = crate::cap::mark_subtree(c.node, true, &mut marked);
            let (mut copies, mut holders) = (0u64, 0u64);
            for tt in 0..task::limit() {
                let caps = task::lock(tt).caps;
                for (i, cc) in caps.iter().enumerate() {
                    if cc.kind != Kind::None && marked.has(cc.node as usize) && !(tt == t && i == slot) {
                        copies += 1;
                        holders |= task_bit(tt, w);
                    }
                }
            }
            let root = is_creator_root(t, slot, &c);
            (f.x[1], f.x[2], f.x[3], f.x[4]) = (copies, holders, nodes as u64, root as u64);
            Out::Ret(0)
        }
        11 => {
            // who holds a capability to an object, for the task manager: `arg` = kind | object << 8 | window << 24 (kinds as in page 10). Answers
            // bit masks of the tasks of that window (bit t is task `window * 64 + t`): (all holders, holders that may send / write, holders that may
            // receive / map, the creator or 0xFFFF, how many capabilities name it, in all windows). Read-only.
            let (kind, obj, w) = ((arg & 0xFF) as u8, ((arg >> 8) & 0xFFFF) as u16, (arg >> 24) as usize);
            let (mut any, mut user, mut serve, mut total) = (0u64, 0u64, 0u64, 0u64);
            for t in 0..task::limit() {
                let caps = task::lock(t).caps;
                for c in caps.iter() {
                    if c.kind as u8 != kind || c.kind == Kind::None || (c.obj != obj && matches!(c.kind, Kind::Endpoint | Kind::Memory | Kind::Irq)) {
                        continue;
                    }
                    any |= task_bit(t, w);
                    total += 1;
                    match c.kind {
                        Kind::Endpoint => {
                            if c.rights & R_SEND != 0 {
                                user |= task_bit(t, w);
                            }
                            if c.rights & R_RECV != 0 {
                                serve |= task_bit(t, w);
                            }
                        }
                        Kind::Memory => {
                            if c.rights & R_WRITE != 0 {
                                user |= task_bit(t, w);
                            }
                            if c.rights & R_MAP != 0 {
                                serve |= task_bit(t, w);
                            }
                        }
                        _ => {
                            user |= task_bit(t, w);
                            serve |= task_bit(t, w);
                        }
                    }
                }
            }
            let owner = match kind {
                k if k == Kind::Endpoint as u8 => ipc::dynamic_owner(obj).map_or(0xFFFF, |t| t as u64),
                k if k == Kind::Memory as u8 => obj::get(obj).filter(|o| o.kind == ObjKind::Shared).map_or(0xFFFF, |o| o.aux as u64),
                _ => 0xFFFF,
            };
            f.x[1] = any;
            f.x[2] = user;
            f.x[3] = serve;
            f.x[4] = owner;
            f.x[5] = total;
            Out::Ret(0)
        }
        12 => {
            // what a capability's object is, for the task manager: `arg` = kind | object << 8. Answers (name bytes 0..8, name bytes 8..16, size in pages
            // or the interrupt number, class, creator or 0xFFFF). Classes: 1 boot endpoint, 2 run-time endpoint, 3 RAM, 4 DMA buffer, 5 device registers,
            // 6 shared memory made by a program, 7 interrupt, 8 other.
            let (kind, obj) = ((arg & 0xFF) as u8, ((arg >> 8) & 0xFFFF) as u16);
            let (name, size, class, owner): (&str, u64, u64, u64) = match kind {
                k if k == Kind::Endpoint as u8 => match ipc::dynamic_owner(obj) {
                    Some(t) => ("dynamic endpoint", 0, 2, t as u64),
                    None => (ep_name(obj), 0, if obj >= ipc::EP_FIRST_DYNAMIC { 2 } else { 1 }, 0xFFFF),
                },
                k if k == Kind::Memory as u8 => match obj::get(obj) {
                    Some(o) => (
                        obj_name(obj),
                        o.pages as u64,
                        match o.kind {
                            ObjKind::Ram => 3,
                            ObjKind::Dma => 4,
                            ObjKind::Mmio => 5,
                            ObjKind::Shared => 6,
                            ObjKind::Unused => 8,
                        },
                        if o.kind == ObjKind::Shared { o.aux as u64 } else { 0xFFFF },
                    ),
                    None => ("(gone)", 0, 8, 0xFFFF),
                },
                k if k == Kind::Irq as u8 => (match obj { obj::IRQ_BLK => "block irq", obj::IRQ_GPU => "display irq", obj::IRQ_NET => "network irq", _ => "interrupt" }, obj as u64, 7, 0xFFFF),
                k if k == Kind::Console as u8 => ("console", 0, 8, 0xFFFF),
                k if k == Kind::MemCtl as u8 => ("memory control", 0, 8, 0xFFFF),
                k if k == Kind::Admin as u8 => ("admin", 0, 8, 0xFFFF),
                k if k == Kind::Sched as u8 => ("scheduler", 0, 8, 0xFFFF),
                k if k == Kind::Spawn as u8 => ("spawn", 0, 8, 0xFFFF),
                k if k == Kind::Factory as u8 => ("endpoint factory", 0, 8, 0xFFFF),
                _ => ("?", 0, 8, 0xFFFF),
            };
            let b = name.as_bytes();
            let pack = |off: usize| (0..8).fold(0u64, |v, i| v | (b.get(off + i).copied().unwrap_or(0) as u64) << (8 * i));
            f.x[1] = pack(0);
            f.x[2] = pack(8);
            f.x[3] = size;
            f.x[4] = class;
            f.x[5] = owner;
            Out::Ret(0)
        }
        4 => {
            f.x[1] = crate::platform::fuzz_seed();
            f.x[2] = obj::dynamic_in_use() as u64;
            Out::Ret(0)
        }
        _ => Out::Ret(E_INVAL),
    }
}

/// `SCHED(op, slot, p1, p2, p3)`.
///  * `SC_RT_SET`: reserve `p1` microseconds of CPU in every `p2` microseconds, on core `p3` (`u64::MAX`:
///    the cheapest core with room). Needs a `Sched` capability with `R_RT` in `slot`. The task is confined to
///    that core and runs ahead of everything else, earliest deadline first, until it has used its
///    budget for the period. Returns the core.
///  * `SC_RT_WAIT`: the job is done; sleep until the next period. Returns the instant (raw counter value,
///    what `cntvct_el0` reads) at which that period starts.
///  * `SC_RT_CLEAR`: give the reservation back.
///  * `SC_STATS`: read-only measurements, selected by `p1` (see the match below).
fn sched_call(cur: usize, a: [u64; 5]) -> Out {
    let mut f = frame(cur);
    match a[0] {
        SC_RT_SET => {
            if let Err(e) = lookup(cur, a[1], Kind::Sched, R_RT) {
                return Out::Ret(e);
            }
            let hint = (a[4] != u64::MAX).then_some(a[4] as usize);
            match sched::rt_set(cur, a[2], a[3], hint) {
                Ok(core) => Out::Ret(core as i64),
                Err(sched::RtError::Invalid) => Out::Ret(E_INVAL),
                Err(sched::RtError::NoCapacity) => Out::Ret(E_FULL),
            }
        }
        SC_RT_WAIT => match sched::rt_wait(cur) {
            None => Out::Ret(E_INVAL),
            Some((release, true)) => {
                f.x[0] = release as u64; // written before the task can be woken
                Out::Block
            }
            Some((release, false)) => Out::Ret(release as i64),
        },
        SC_RT_CLEAR => {
            sched::rt_clear(cur);
            Out::Ret(0)
        }
        SC_STATS => {
            match a[1] {
                // (switches, slice preemptions, wakeup preemptions, migrations, steals)
                0 => {
                    let k = sched::totals();
                    (f.x[1], f.x[2], f.x[3], f.x[4], f.x[5]) = (k.switches, k.slice_preempts, k.prio_preempts, k.migrations, k.steals);
                }
                // task `p2`: (counter ticks on efficiency cores, on performance cores, utilisation 0..1024, priority level, home core)
                1 => {
                    if a[2] as usize >= task::limit() {
                        return Out::Ret(E_INVAL);
                    }
                    let (l, b, u, p, h) = sched::task_stats(a[2] as usize);
                    (f.x[1], f.x[2], f.x[3], f.x[4], f.x[5]) = (l, b, u as u64, p as u64, h as u64);
                }
                // latency of priority level `p2` (0 real-time ... 3 heavy): (max, sum, count) in counter ticks
                2 => {
                    if a[2] >= 4 {
                        return Out::Ret(E_INVAL);
                    }
                    let (m, s, n) = sched::latency(a[2] as usize);
                    (f.x[1], f.x[2], f.x[3]) = (m, s, n);
                }
                // core `p2`: (utilisation 0..1024, busy counter ticks, kind 0 efficiency / 1 performance, requested frequency level)
                3 => {
                    if a[2] as usize >= crate::smp::MAX_CPUS {
                        return Out::Ret(E_INVAL);
                    }
                    let (u, busy) = sched::core_stats(a[2] as usize);
                    (f.x[1], f.x[2], f.x[3], f.x[4]) = (u as u64, busy, sched::core_kind(a[2] as usize) as u64, metallium_sched::energy::target_util(u) as u64);
                }
                // the calling task's real-time reservation: (jobs, missed deadlines, budget left, runtime, period) in counter ticks
                4 => match sched::rt_stats(cur) {
                    Some((j, m, b, r, p)) => (f.x[1], f.x[2], f.x[3], f.x[4], f.x[5]) = (j as u64, m as u64, b, r, p),
                    None => return Out::Ret(E_INVAL),
                },
                // clock: (counter frequency, counter now, jiffy length in counter ticks)
                5 => (f.x[1], f.x[2], f.x[3]) = (timer::freq(), timer::counter(), timer::interval()),
                6 => sched::reset_latency(),
                // timer interrupts taken by cores 0..3 so far
                7 => {
                    let t = sched::timer_irqs();
                    (f.x[1], f.x[2], f.x[3], f.x[4]) = (t[0], t[1], t[2], t[3]);
                }
                _ => return Out::Ret(E_INVAL),
            }
            Out::Ret(0)
        }
        _ => Out::Ret(E_INVAL),
    }
}

/// Kill every task running `role` (they are restarted if policy allows). Needs an `Admin`
/// capability with `R_KILL`, and only the restartable service roles can be named: the block
/// driver, the filesystem servers, the VFS, the display and keyboard drivers.
fn kill_role(cur: usize, slot: u64, role: u64) -> Out {
    if let Err(e) = lookup(cur, slot, Kind::Admin, R_KILL) {
        return Out::Ret(e);
    }
    if !matches!(role, 4 | 5 | 6 | 7 | 12 | 14 | 18 | 19) {
        return Out::Ret(E_INVAL);
    }
    Out::Ret(task::condemn_role(role as u8, sched::Doom::Killed) as i64)
}

/// Whether the capability `c` in `slot` of program `t` is one that revoking would destroy something with: the creator's capability of an endpoint or of
/// shared memory, or of any other object a program made itself (a memory allocation): a capability with no parent that is not one the kernel
/// gives every program (its console, its file and network session). Those are refused.
fn is_creator_root(t: usize, slot: usize, c: &Cap) -> bool {
    let object_root = match c.kind {
        Kind::Endpoint => ipc::root_node(c.obj) == Some(c.node),
        Kind::Memory => obj::get(c.obj).is_some_and(|o| o.kind == ObjKind::Shared && o.root == c.node),
        _ => false,
    };
    object_root || (crate::cap::parent_of(c.node).is_none() && !crate::spawn::session_cap_ok(t, slot, c.kind, c.obj, c.rights))
}

/// Revoke one capability of another program (see `REVOKE_OF`).
fn revoke_of(cur: usize, admin: u64, target: u64, slot: u64) -> Out {
    if let Err(e) = lookup(cur, admin, Kind::Admin, R_REVOKE) {
        return Out::Ret(e);
    }
    let t = target as usize;
    if t >= task::limit() || t < task::FIRST_DYNAMIC_TASK || task::aspace(t) == task::aspace(cur) || slot as usize >= NCAPS {
        return Out::Ret(E_INVAL);
    }
    let c = task::lock(t).caps[slot as usize];
    if c.kind == Kind::None || !c.alive() {
        return Out::Ret(E_BADCAP);
    }
    let root = is_creator_root(t, slot as usize, &c);
    if root {
        return Out::Ret(E_PERM);
    }
    // (kept in a log first, so that it can be given back: what it hung under, or, for the session capabilities the kernel made itself, that it is
    // exactly what the session has; and where it was mapped, so that the mapping can come back too)
    let parent = crate::cap::parent_of(c.node).or_else(|| crate::spawn::session_cap_ok(t, slot as usize, c.kind, c.obj, c.rights).then_some((crate::cap::NO_PARENT, 0)));
    if let Some(parent) = parent {
        let map = task::lock(task::aspace(t)).maps.iter().find(|m| m.used && m.node == c.node).map_or((0, 0), |m| (m.va, m.pages));
        crate::cap::log_revoked(t, slot as usize, c, parent, map);
    }
    Out::Ret(World::lock().revoke_subtree(c.node, true) as i64)
}

/// Map a memory capability's object into program `space` at `va` again, after a revoke removed the mapping (writable if the capability may write).
fn remap(space: usize, c: Cap, va: usize) -> bool {
    let Some(o) = obj::get(c.obj) else { return false };
    if o.kind == ObjKind::Mmio && c.rights & R_WRITE == 0 {
        return false; // (as in `MEM_MAP`)
    }
    let mut t = task::lock(space);
    // (as in `MEM_MAP`: a revoke kills nodes before it sweeps this table under this lock, so a capability that is alive under the lock is
    // swept after it is let go; one that was revoked since it was made must not leave a mapping behind)
    if !c.alive() {
        return false;
    }
    if (0..o.pages).any(|p| mmu::is_present(t.l1, va + p * mem::PAGE)) {
        return false;
    }
    let Some(rec) = t.maps.iter().position(|m| !m.used) else { return false };
    let perm = match (o.kind, c.rights & R_WRITE != 0) {
        (ObjKind::Mmio, _) => Perm::Device,
        (_, true) => Perm::Rw,
        (_, false) => Perm::Ro,
    };
    for p in 0..o.pages {
        let pa = if o.kind == ObjKind::Shared { obj::shm_frame(&o, p) } else { o.pa + p * mem::PAGE };
        if mmu::map_user(t.l1, va + p * mem::PAGE, pa, perm, mem::OWNER_TASK0 + space as u16).is_err() {
            for q in 0..p {
                mmu::unmap_user(t.l1, va + q * mem::PAGE);
            }
            return false;
        }
    }
    t.maps[rec] = task::MapRec { used: true, va, pages: o.pages, node: c.node };
    true
}

/// Give back a capability that `REVOKE_OF` took from a program (see `RESTORE_OF`).
fn restore_of(cur: usize, admin: u64, target: u64, id: u64) -> Out {
    if let Err(e) = lookup(cur, admin, Kind::Admin, R_REVOKE) {
        return Out::Ret(e);
    }
    let t = target as usize;
    if t >= task::limit() || t < task::FIRST_DYNAMIC_TASK || task::aspace(t) == task::aspace(cur) || matches!(sched::state(t), State::Free | State::Dead) {
        return Out::Ret(E_INVAL);
    }
    let Some(r) = crate::cap::revoked_by_id(t, id as u32) else { return Out::Ret(E_BADCAP) };
    // what it hung under must still be there (a session capability the kernel made itself: the session must still be exactly this), and so must the object
    let root = r.parent == crate::cap::NO_PARENT;
    let gone = if root { !crate::spawn::session_cap_ok(t, r.slot as usize, r.kind, r.obj, r.rights) } else { !crate::cap::node_is(r.parent, r.parent_gen) };
    if gone {
        return Out::Ret(E_DEAD);
    }
    let object_there = match r.kind {
        Kind::Endpoint => r.obj < ipc::EP_FIRST_DYNAMIC || ipc::dynamic_owner(r.obj).is_some(),
        Kind::Memory => obj::get(r.obj).is_some_and(|o| o.kind != ObjKind::Unused),
        _ => true,
    };
    if !object_there {
        return Out::Ret(E_DEAD);
    }
    let mut tl = task::lock(t);
    // (the program may have ended since the checks above: the end of a task, which runs under the lifecycle lock as this does, forgets its log entries, so one that
    // is still there under this lock means the task is the same one)
    if crate::cap::revoked_by_id(t, id as u32).is_none() {
        return Out::Ret(E_DEAD);
    }
    let slot = r.slot as usize;
    if slot >= NCAPS || (slot == CONSOLE_SLOT && r.kind != Kind::Console) || tl.caps[slot].kind != Kind::None {
        return Out::Ret(E_FULL); // (the program may have put something else there)
    }
    let node = if root { crate::cap::mint_node(None) } else { crate::cap::mint_restored((r.parent, r.parent_gen)) };
    // (a parent that was revoked since the check above, and its number given out again, is refused here: checked under the node-table lock)
    let Some(node) = node else { return Out::Ret(if !root && !crate::cap::node_is(r.parent, r.parent_gen) { E_DEAD } else { E_NOMEM }) };
    let cap = Cap::new(r.kind, r.obj, r.rights, node);
    tl.caps[slot] = cap;
    drop(tl);
    // a memory capability that was mapped is mapped again where it was
    if r.kind == Kind::Memory && r.map_pages > 0 {
        remap(task::aspace(t), cap, r.map_va);
    }
    if r.kind == Kind::Endpoint && r.rights & R_RECV != 0 {
        sched::note_recv_endpoint(t, r.obj);
    }
    crate::cap::forget_revoked_id(r.id);
    Out::Ret(slot as i64)
}

/// Physical address / size of a DMA or MMIO object, for drivers holding `R_INFO`.
fn cap_info(cur: usize, slot: u64) -> Out {
    let c = match lookup(cur, slot, Kind::Memory, R_INFO) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    match obj::get(c.obj) {
        Some(o) if o.kind != ObjKind::Ram && o.kind != ObjKind::Shared => {
            let mut f = frame(cur);
            f.x[1] = o.pa as u64;
            f.x[2] = o.pages as u64;
            f.x[3] = o.aux as u64;
            Out::Ret(0)
        }
        _ => Out::Ret(E_PERM),
    }
}

/// Map `pages` fresh anonymous pages at the end of the task's heap window; returns their base VA.
/// The frames are *movable* (the compactor may relocate them) and belong to the task, so a
/// crash reclaims them like any other memory.
fn heap_grow(cur: usize, pages: usize) -> Out {
    let cur = task::aspace(cur); // (the heap, its quota and its frames belong to the program, not to a thread)
    let mut t = task::lock(cur);
    // `pages` comes from userspace: a wrapping sum would slip past the quota check
    let held = t.held_pages().saturating_add(crate::spawn::contig_pages(cur)); // (contiguous allocations count against the same limit)
    if pages == 0 || held.checked_add(pages).map_or(true, |total| total > info(cur).heap_quota) {
        return Out::Ret(E_NOMEM);
    }
    let base = t.heap_base + t.heap_pages * mem::PAGE;
    if base + pages * mem::PAGE > task::HEAP_END {
        return Out::Ret(E_NOMEM); // (the page after the heap stays unmapped)
    }
    let owner = mem::OWNER_TASK0 + cur as u16;
    for p in 0..pages {
        let va = base + p * mem::PAGE;
        let ok = mem::alloc_movable(owner, cur, va).map_or(false, |pa| {
            let mapped = mmu::map_user(t.l1, va, pa, Perm::Rw, owner).is_ok();
            if !mapped {
                mem::free(pa);
            }
            mapped
        });
        if !ok {
            return Out::Ret(E_NOMEM); // pages mapped so far stay owned; reclaimed when the task dies
        }
        t.heap_pages += 1;
    }
    Out::Ret(base as i64)
}

/// Give back `count` pages of the heap window starting at page `first` (like madvise(DONTNEED)):
/// they are unmapped and their frames freed; the window keeps its size, with a hole.
fn heap_release(cur: usize, first: usize, count: usize) -> Out {
    let t = task::lock(task::aspace(cur));
    if first.checked_add(count).map_or(true, |e| e > t.heap_pages) {
        return Out::Ret(E_INVAL);
    }
    let freed = crate::swap::release_pages(t.l1, t.heap_base + first * mem::PAGE, count);
    Out::Ret(freed as i64)
}

/// The range `addr..addr + pages * PAGE`, inside the `MMAP` arena and no bigger than a program may reserve; `None` if it is not.
fn anon_range(addr: usize, pages: usize) -> Option<usize> {
    if pages == 0 || pages > task::MAX_ANON_VIRT_PAGES || addr % mem::PAGE != 0 {
        return None;
    }
    let end = addr.checked_add(pages * mem::PAGE)?;
    (addr >= task::MMAP_LO && end <= task::MMAP_HI).then_some(end)
}

/// Where `pages` pages (and an unmapped guard page after them) go in the arena when the program does not say: after the last place handed out, or at
/// random if that is taken or past the end.
fn pick_anon_address(t: &mut task::Task, pages: usize) -> Option<usize> {
    let (lo, hi) = (task::MMAP_LO, task::MMAP_HI);
    let need = pages.checked_add(1)? * mem::PAGE;
    if need > hi - lo {
        return None;
    }
    if t.mmap_next == 0 {
        t.mmap_next = lo + crate::rand::below((hi - lo) / 2 / mem::PAGE) * mem::PAGE; // (the first place is random: the arena's layout is not guessable)
    }
    let next = t.mmap_next;
    if next >= lo && next + need <= hi && mmu::range_free(t.l1, next, pages + 1) {
        t.mmap_next = next + need;
        return Some(next);
    }
    for _ in 0..64 {
        let va = lo + crate::rand::below((hi - lo - need) / mem::PAGE + 1) * mem::PAGE;
        let before = if va > lo { va - mem::PAGE } else { va }; // (a free page before it too, so two regions never touch)
        if mmu::range_free(t.l1, before, pages + 1 + (va - before) / mem::PAGE) {
            t.mmap_next = va + need;
            return Some(va);
        }
    }
    None
}

fn mmap(cur: usize, addr: usize, pages: usize, a3: u64) -> Out {
    let prot = (a3 & 0xFF) as u8;
    let fixed = a3 & MAP_FIXED != 0;
    if a3 & !(0xFF | MAP_FIXED) != 0 || prot & !7 != 0 || pages == 0 || pages > task::MAX_ANON_VIRT_PAGES {
        return Out::Ret(E_INVAL);
    }
    if prot & mmu::PROT_W != 0 && prot & mmu::PROT_X != 0 {
        return Out::Ret(E_PERM); // write xor execute
    }
    let space = task::aspace(cur); // (a thread maps into its program's address space)
    let mut t = task::lock(space);
    if t.l1 == 0 {
        return Out::Ret(E_PERM);
    }
    let mut existing = 0usize; // reserved pages of an earlier MMAP that this one replaces
    let va = if fixed {
        if anon_range(addr, pages).is_none() {
            return Out::Ret(E_INVAL);
        }
        if !mmu::range_free(t.l1, addr, pages) {
            for p in 0..pages {
                match mmu::is_anon(t.l1, addr + p * mem::PAGE) {
                    Some(true) => existing += 1,
                    Some(false) => return Out::Ret(E_INVAL), // (something else is mapped there: never replaced)
                    None => {}
                }
            }
        }
        if existing < pages && !crate::spawn::fixed_maps_allowed(space) {
            return Out::Ret(E_PERM); // this program asked to have its mappings placed by the kernel: it may only re-map what it was given
        }
        addr
    } else {
        match pick_anon_address(&mut t, pages) {
            Some(v) => v,
            None => return Out::Ret(E_NOMEM),
        }
    };
    if t.anon_virt.load(core::sync::atomic::Ordering::Relaxed) - existing + pages > task::MAX_ANON_VIRT_PAGES {
        return Out::Ret(E_NOMEM);
    }
    if existing > 0 {
        let (entries, populated) = crate::swap::release_range(t.l1, va, pages, true);
        t.anon_virt.fetch_sub(entries, core::sync::atomic::Ordering::Relaxed);
        t.anon_pages.fetch_sub(populated, core::sync::atomic::Ordering::Relaxed);
    }
    let owner = mem::OWNER_TASK0 + space as u16;
    for p in 0..pages {
        if mmu::reserve_anon(t.l1, va + p * mem::PAGE, prot, owner).is_err() {
            for q in 0..p {
                mmu::clear_lazy(t.l1, va + q * mem::PAGE);
            }
            return Out::Ret(E_NOMEM); // (page tables for the range could not be made)
        }
    }
    t.anon_virt.fetch_add(pages, core::sync::atomic::Ordering::Relaxed);
    Out::Ret(va as i64)
}

fn munmap(cur: usize, addr: usize, pages: usize) -> Out {
    if anon_range(addr, pages).is_none() {
        return Out::Ret(E_INVAL);
    }
    let space = task::aspace(cur);
    let t = task::lock(space);
    if t.l1 == 0 {
        return Out::Ret(E_PERM);
    }
    if !mmu::range_free(t.l1, addr, pages) {
        if (0..pages).any(|p| mmu::is_anon(t.l1, addr + p * mem::PAGE) == Some(false)) {
            return Out::Ret(E_INVAL);
        }
        let (entries, populated) = crate::swap::release_range(t.l1, addr, pages, true);
        t.anon_virt.fetch_sub(entries, core::sync::atomic::Ordering::Relaxed);
        t.anon_pages.fetch_sub(populated, core::sync::atomic::Ordering::Relaxed);
    }
    Out::Ret(0)
}

fn mprotect(cur: usize, addr: usize, pages: usize, a3: u64) -> Out {
    let prot = a3 as u8;
    if a3 > 0xFF || prot & !7 != 0 || anon_range(addr, pages).is_none() {
        return Out::Ret(E_INVAL);
    }
    if prot & mmu::PROT_W != 0 && prot & mmu::PROT_X != 0 {
        return Out::Ret(E_PERM); // write xor execute
    }
    let space = task::aspace(cur);
    let t = task::lock(space);
    if t.l1 == 0 {
        return Out::Ret(E_PERM);
    }
    if (0..pages).any(|p| mmu::is_anon(t.l1, addr + p * mem::PAGE) != Some(true)) {
        return Out::Ret(E_INVAL); // (a hole, or something that is not MMAP memory: nothing is changed)
    }
    let mut made_code = false;
    for p in 0..pages {
        let va = addr + p * mem::PAGE;
        if prot & mmu::PROT_X != 0 && matches!(mmu::inspect(t.l1, va), mmu::Page::Swapped(_) | mmu::Page::Disk(_)) {
            crate::pager::cancel_write(t.l1, Some(va)); // (executable pages never go to the pager)
        }
        if let Some(Some(pa)) = mmu::set_prot(t.l1, va, prot) {
            mmu::clean_dcache_pou(pa, mem::PAGE); // (code written through the data cache must reach the point where fetches look)
            made_code = true;
        }
    }
    mmu::flush_tlb(); // the new permissions apply on every core from here
    if made_code {
        mmu::flush_icache();
    }
    Out::Ret(0)
}

const MC_STATS: u64 = 0;
const MC_COMPACT: u64 = 1;
const MC_ALLOC: u64 = 2;
const MC_FREE: u64 = 3;
const MC_SWAP_OUT: u64 = 4;
const MC_SWAP_STATS: u64 = 5;
const MC_PAGER_REGISTER: u64 = 6;
const MC_PAGER_NEXT: u64 = 7;
const MC_PAGER_DONE: u64 = 8;
const MC_SWAP_WRITEBACK: u64 = 9;
const MC_PAGER_STATS: u64 = 10;
/// MC_SWAP_OUT flags: evict without waiting for pages to age; only the caller's own pages.
const MCS_FORCE: u64 = 1;
const MCS_SELF: u64 = 2;
/// Flags bits 8.. : only pages of task (value - 1), 0 = any task.
/// ... only pages of the heap window.
const MCS_HEAP: u64 = 4;
/// MC_ALLOC flag: compact synchronously if no contiguous run exists.
const MCF_DIRECT: u64 = 1;

/// Memory management through a `MemCtl` capability. `a2` = operation.
fn memctl(cur: usize, slot: u64, op: u64, a3: u64, a4: u64) -> Out {
    let need = match op {
        MC_STATS | MC_SWAP_STATS => R_MEM_STATS,
        MC_SWAP_OUT | MC_SWAP_WRITEBACK => R_MEM_SWAP,
        MC_PAGER_STATS => R_MEM_STATS,
        MC_PAGER_REGISTER | MC_PAGER_NEXT | MC_PAGER_DONE => R_MEM_PAGER,
        MC_COMPACT => R_MEM_COMPACT,
        MC_ALLOC | MC_FREE => R_MEM_ALLOC,
        _ => return Out::Ret(E_INVAL),
    };
    if let Err(e) = lookup(cur, slot, Kind::MemCtl, need) {
        return Out::Ret(e);
    }
    let mut f = frame(cur);
    match op {
        MC_STATS => {
            let s = compact::stats();
            f.x[1] = mem::free_frames() as u64;
            f.x[2] = mem::largest_free_run() as u64;
            f.x[3] = s.failures;
            f.x[4] = s.migrated;
            f.x[5] = mem::free_runs() as u64;
            Out::Ret(s.spurious as i64) // faults that raced with a migration and were retried
        }
        MC_SWAP_OUT => {
            let filter = crate::swap::Filter { force: a4 & MCS_FORCE != 0, only: if a4 & MCS_SELF != 0 { Some(task::aspace(cur)) } else { ((a4 >> 8) as usize).checked_sub(1) }, heap_only: a4 & MCS_HEAP != 0 };
            let (evicted, looked) = crate::swap::evict((a3 as usize).clamp(1, 1024), filter);
            f.x[1] = looked as u64;
            Out::Ret(evicted as i64)
        }
        MC_PAGER_REGISTER => Out::Ret(crate::pager::register(cur, a3 as usize, a4 as usize)),
        MC_PAGER_NEXT => match crate::pager::next(cur, a3 as usize) {
            Ok((kind, slot)) => {
                f.x[1] = slot;
                Out::Ret(kind as i64)
            }
            Err(e) => Out::Ret(e),
        },
        MC_PAGER_DONE => Out::Ret(crate::pager::done(cur, a3, a4 as usize)),
        MC_SWAP_WRITEBACK => Out::Ret(crate::pager::want((a3 as usize).clamp(1, 1024))),
        MC_PAGER_STATS => {
            let s = crate::pager::stats();
            f.x[1] = s.read;
            f.x[2] = s.cancelled;
            f.x[3] = s.failed;
            f.x[4] = s.slots_used;
            f.x[5] = s.registered as u64;
            Out::Ret(s.written as i64)
        }
        MC_SWAP_STATS => {
            let s = crate::swap::stats();
            f.x[1] = s.bytes;
            f.x[2] = s.out;
            f.x[3] = s.back;
            f.x[4] = s.full;
            f.x[5] = s.touched;
            Out::Ret(s.stored as i64)
        }
        MC_COMPACT => {
            let (moved, done) = compact::compact((a3 as usize).clamp(1, 1024));
            f.x[1] = done as u64;
            Out::Ret(moved as i64)
        }
        MC_ALLOC => {
            let pages = a3 as usize;
            if pages == 0 || pages > 1024 {
                return Out::Ret(E_INVAL);
            }
            let asp = task::aspace(cur);
            let owner = mem::OWNER_TASK0 + asp as u16; // (freed with the address space, not with the thread)
            // counted against the program's limit before anything is taken, under the lock `heap_grow` uses
            if !crate::spawn::reserve_contig(asp, task::lock(asp).held_pages(), pages) {
                return Out::Ret(E_NOMEM);
            }
            let Some(pa) = compact::alloc_contig(pages, owner, a4 & MCF_DIRECT != 0) else {
                crate::spawn::release_contig(asp, pages);
                return Out::Ret(E_NOMEM);
            };
            let mut t = task::lock(cur);
            let free_slot = (0..NCAPS).find(|&i| i != CONSOLE_SLOT && t.caps[i].kind == Kind::None);
            let node = crate::cap::mint_for(asp, None);
            let obj = node.and_then(|n| obj::alloc_dynamic(pa, pages, n.id, asp));
            match (free_slot, node, obj) {
                (Some(s), Some(n), Some(o)) => {
                    t.caps[s] = Cap::new(Kind::Memory, o, R_MAP | R_WRITE | R_INFO, n);
                    Out::Ret(s as i64)
                }
                (_, n, o) => {
                    // out of capability slots / nodes / objects: undo
                    crate::spawn::release_contig(asp, pages);
                    for i in 0..pages {
                        mem::free(pa + i * mem::PAGE);
                    }
                    if let Some(n) = n {
                        free_node(n.id);
                    }
                    if let Some(o) = o {
                        obj::release(o);
                    }
                    Out::Ret(E_NOMEM)
                }
            }
        }
        _ => {
            // MC_FREE: a3 = slot of a Memory capability previously returned by MC_ALLOC
            let c = match lookup_any(cur, a3) {
                Ok(c) if c.kind == Kind::Memory => c,
                _ => return Out::Ret(E_BADCAP),
            };
            let Some(o) = obj::get(c.obj) else { return Out::Ret(E_BADCAP) };
            if !obj::is_dynamic(c.obj) {
                return Out::Ret(E_PERM);
            }
            if o.kind != ObjKind::Dma {
                return Out::Ret(E_INVAL); // shared memory is ended with CAP_REVOKE (flag 1) on the creator's capability
            }
            let mut w = World::lock();
            w.revoke_subtree(c.node, true); // clears the capability and unmaps it everywhere
            if o.root != c.node {
                return Out::Ret(0); // a copy (a thread's, say): only the copy goes, the object stays with its creator's capability
            }
            drop(w);
            let holder = mem::owner_of(o.pa);
            if holder >= mem::OWNER_TASK0 {
                crate::spawn::release_contig((holder - mem::OWNER_TASK0) as usize, o.pages);
            }
            for i in 0..o.pages {
                mem::free(o.pa + i * mem::PAGE);
            }
            obj::release(c.obj);
            Out::Ret(0)
        }
    }
}

/// `SHM_CREATE(pages)`: fresh zeroed memory (1..=4096 pages) that can be mapped here and shared with other programs by
/// granting the capability. Counted against the creator program's holding limit (like `MC_ALLOC`). The memory lives as
/// long as the returned capability: when the creator exits or revokes it (`CAP_REVOKE` flag 1), every holder's copy and
/// mapping goes and the frames are freed. `E_NOMEM`: over the limit or out of memory; `E_FULL`: no free slot, capability
/// node or object-table entry.
fn shm_create(cur: usize, pages: usize) -> Out {
    if pages == 0 || pages > obj::SHM_MAX_PAGES {
        return Out::Ret(E_INVAL);
    }
    let asp = task::aspace(cur);
    // (the task lock is held across the reservation, as `heap_grow` holds it across its own: the heap cannot grow between reading it and claiming)
    if !crate::spawn::reserve_contig(asp, task::lock(asp).held_pages(), pages) {
        return Out::Ret(E_NOMEM);
    }
    let Some(list) = obj::shm_alloc(pages, mem::OWNER_TASK0 + asp as u16) else {
        crate::spawn::release_contig(asp, pages);
        return Out::Ret(E_NOMEM);
    };
    let mut t = task::lock(cur);
    let free_slot = (0..NCAPS).find(|&i| i != CONSOLE_SLOT && t.caps[i].kind == Kind::None);
    let node = crate::cap::mint_for(asp, None);
    let object = node.and_then(|n| obj::shm_register(pages, asp, n.id, list));
    match (free_slot, node, object) {
        (Some(s), Some(n), Some(o)) => {
            t.caps[s] = Cap::new(Kind::Memory, o, R_MAP | R_WRITE | R_GRANT, n);
            Out::Ret(s as i64)
        }
        (_, n, o) => {
            // (no free slot, no capability node or no object-table entry: undo whatever did succeed)
            crate::spawn::release_contig(asp, pages);
            obj::shm_release_frames(list, pages, pages);
            if let Some(n) = n {
                free_node(n.id);
            }
            if let Some(o) = o {
                obj::release(o);
            }
            Out::Ret(E_FULL)
        }
    }
}

/// `SHM_INFO(slot)`: how many pages the shared object has (so that a program that was given one can map and check it
/// without trusting what the giver says about its size). Memory from other sources is not described here.
fn shm_info(cur: usize, slot: u64) -> Out {
    match lookup(cur, slot, Kind::Memory, R_MAP) {
        Ok(c) => match obj::get(c.obj) {
            // bit 32: the creator is gone (the memory stays as long as someone holds it); bit 33: this is the creator's
            // capability and nobody holds a copy any more
            Some(o) if o.kind == ObjKind::Shared => {
                let alone = o.root == c.node && crate::cap::mark_subtree(c.node, false, &mut crate::cap::NodeSet::EMPTY) == 0;
                Out::Ret(o.pages as i64 | ((o.root == crate::cap::NO_PARENT) as i64) << 32 | (alone as i64) << 33)
            }
            _ => Out::Ret(E_INVAL),
        },
        Err(e) => Out::Ret(e),
    }
}

/// Block until the device interrupts. `timeout` > 0 bounds the wait in ticks: a device that never answers
/// makes the call return `E_TIMEDOUT` instead of blocking the driver for ever.
fn irq_wait(cur: usize, slot: u64, timeout: u64) -> Out {
    let c = match lookup(cur, slot, Kind::Irq, R_RECV) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    match irq::wait(c.obj, cur, timeout) {
        irq::Wait::Ready => Out::Ret(0),
        irq::Wait::Blocked => Out::Block,
        irq::Wait::Busy => Out::Ret(E_FULL),
    }
}

/// `CAP_GRANT(slot, task, rights mask, dest)`: `dest` 0 puts the capability in the target's first free slot, `dest` = n + 1 in slot n exactly (refused
/// if that slot is not free), which is how a program manager gives back the capability a program expects in a fixed slot.
fn cap_grant(cur: usize, slot: u64, target: u64, mask: Rights, dest: u64) -> Out {
    let c = match lookup_any(cur, slot) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    if c.rights & R_GRANT == 0 {
        return Out::Ret(E_PERM);
    }
    let target = target as usize;
    if target >= task::limit() || matches!(sched::state(target), State::Free | State::Dead) {
        return Out::Ret(E_INVAL);
    }
    let target_space = task::aspace(target); // (what the checks below were made for: looked at again under the target's lock)
    // A program (as opposed to a boot-time service) may put capabilities only where it has a reason to: into its own program (its
    // threads), into the programs it started, and into the program that started it. Anyone else did not ask for it: a grant fills
    // the receiver's table and can take the slot a program expects to find something in (SECURITY.md, M2). A named slot is the
    // parent's way of giving a child what it expects in a fixed place; a child's grant to its parent never takes the parent's
    // last `GRANT_RESERVE_SLOTS` free slots.
    let mut reserve = 0;
    if crate::spawn::is_program(task::aspace(cur)) {
        let (me, them) = (task::aspace(cur), task::aspace(target));
        let to_child = crate::spawn::parent_of(them) as usize == me;
        let to_parent = crate::spawn::parent_of(me) as usize == them;
        if them != me && !to_child && !to_parent {
            return Out::Ret(E_PERM);
        }
        if dest != 0 && them != me && !to_child {
            return Out::Ret(E_PERM);
        }
        if them != me {
            reserve = GRANT_RESERVE_SLOTS;
        }
    }
    let mut t = task::lock(target); // only the target's table changes (the source is just read above)
    if !c.alive() {
        return Out::Ret(E_BADCAP); // revoked since the lookup (a revoke kills nodes before it sweeps, and a grant runs under the lifecycle lock): no copy may outlive it
    }
    // The end of a task wipes its table under the lifecycle lock, which a grant holds, so a target that is gone (or whose slot is somebody else's now) must be
    // noticed here, under its lock: a capability put into a table that is wiped afterwards, or into a stranger's, would never be freed.
    if matches!(sched::state(target), State::Free | State::Dead) || task::aspace(target) != target_space {
        return Out::Ret(E_INVAL);
    }
    let dst = if dest == 0 {
        let free = |t: &task::Task| (0..NCAPS).filter(|&i| i != CONSOLE_SLOT && t.caps[i].kind == Kind::None).count();
        if free(&t) <= reserve {
            return Out::Ret(E_NOMEM);
        }
        let Some(d) = (0..NCAPS).find(|&i| i != CONSOLE_SLOT && t.caps[i].kind == Kind::None) else {
            return Out::Ret(E_NOMEM);
        };
        d
    } else {
        let want = (dest - 1) as usize;
        if want >= NCAPS || want == CONSOLE_SLOT {
            return Out::Ret(E_INVAL);
        }
        if t.caps[want].kind != Kind::None {
            return Out::Ret(E_FULL);
        }
        want
    };
    // (the source is checked again inside `mint_granted`, under the node-table lock that makes the copy: node and generation)
    let Some(node) = crate::cap::mint_granted(c.parent_ref(), cur) else { return Out::Ret(if c.alive() { E_NOMEM } else { E_BADCAP }) };
    // rights can only shrink; GRANT is not passed on unless explicitly masked in
    let rights = c.rights & mask;
    t.caps[dst] = c.under(rights, node);
    if c.kind == Kind::Endpoint && rights & R_RECV != 0 {
        sched::note_recv_endpoint(target, c.obj);
    }
    Out::Ret(dst as i64)
}

/// `CAP_REVOKE(slot, flags)`: everything derived from the capability in `slot`; with flag 1 the capability itself too
/// (for the creator of a run-time endpoint, that ends the endpoint).
fn cap_revoke(cur: usize, slot: u64, itself: bool) -> Out {
    let c = match lookup_any(cur, slot) {
        Ok(c) => c,
        Err(e) => return Out::Ret(e),
    };
    if itself && c.kind == Kind::Memory && obj::is_dynamic(c.obj) {
        // giving up one's own run-time memory is freeing it (as MC_FREE): the object and the frames go back
        if let Some(o) = obj::get(c.obj) {
            if o.kind == ObjKind::Shared {
                // the creator's capability: the object ends, for every holder. A holder's copy just goes.
                if o.root == c.node {
                    // (the object is freed under the same lock as the revoke, so no one can map it in between)
                    let mut w = World::lock();
                    let n = w.revoke_subtree(c.node, true);
                    obj::shm_destroy(c.obj);
                    return Out::Ret(n as i64);
                }
                return Out::Ret(World::lock().revoke_subtree(c.node, true) as i64);
            }
            let mut w = World::lock();
            let n = w.revoke_subtree(c.node, true);
            if o.root != c.node {
                return Out::Ret(n as i64); // a copy: only the copy goes
            }
            for i in 0..o.pages {
                mem::free(o.pa + i * mem::PAGE);
            }
            obj::release(c.obj);
            return Out::Ret(n as i64);
        }
    }
    Out::Ret(World::lock().revoke_subtree(c.node, itself) as i64)
}

fn log(cur: usize, slot: u64, ptr: usize, len: usize) -> Out {
    if let Err(e) = lookup(cur, slot, Kind::Console, 0) {
        return Out::Ret(e);
    }
    if len > MAX_LOG {
        return Out::Ret(E_INVAL);
    }
    // copy the user bytes out under the task lock (the compactor may be moving its pages),
    // then print without it
    let mut buf = [0u8; MAX_LOG];
    {
        let space = task::aspace(cur);
        let t = task::lock(space);
        for (i, b) in buf.iter_mut().take(len).enumerate() {
            let Some(pa) = ptr.checked_add(i).and_then(|va| crate::swap::translate(&t, space, va)) else { return Out::Ret(E_INVAL) };
            let Some(v) = crate::frame::phys::try_read_u8(pa) else { return Out::Ret(E_INVAL) };
            *b = v;
        }
    }
    uart::write_bytes(&buf[..len]);
    Out::Ret(len as i64)
}
