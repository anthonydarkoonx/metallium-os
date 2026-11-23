//! Random numbers for address-space layout randomisation (`random_stack_top` etc. in task.rs). Not for cryptography.
//!
//! The generator is `metallium-rand`'s ChaCha20 with fast key erasure: each draw is unrelated to the others, and nothing a
//! program can see (its own stack top, say) says anything about the next program's layout.
//!
//! Seeding, in order of preference (all of it is folded into one key, so any one good source is enough):
//!  * the CPU's RNDR register, where FEAT_RNG exists (QEMU's `-cpu max` has it);
//!  * `-fw_cfg name=opt/metallium/seed,file=/dev/urandom` (the first 32 bytes; the test harness can pass this);
//!  * the system counter and the machine ID (weak: that is all there is without the other two).
//! After boot, the time of every interrupt is folded in as well.
//!
//! Later, the entropy driver (a user-space task, role 21, for a virtio-rng device if there is one) hands the kernel 32 bytes with
//! `ADD_ENTROPY` and folds them in again from time to time (not in the debugging modes below, which promise a layout that depends
//! on nothing else). Tasks made before its first delivery are laid out from the sources above only.
//!
//! For debugging there are three modes that give up unpredictability on purpose:
//!  * `opt/metallium/noaslr=1`: every layout is the lowest value of its range;
//!  * `opt/metallium/aslr-log=1`: draws a boot seed, prints it, and runs from it with no later input;
//!  * `opt/metallium/aslr-seed=<n>`: runs from the seed `n` (a number an `aslr-log` run printed). Layouts of the programs started
//!    at boot are then the same as in that run; programs started later depend on the order in which they are started.
#![forbid(unsafe_code)]
use crate::sync::{SpinLock, R_RAND};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use metallium_rand::Rng;

static RNG: SpinLock<Option<Rng>> = SpinLock::new(None);
static HAS_RNDR: AtomicBool = AtomicBool::new(false);
static DISABLED: AtomicBool = AtomicBool::new(false);
/// Has the generator taken real entropy (RNDR, a full seed file, or a virtio-rng device) and is it in its unpredictable mode? Only then `GETRANDOM` answers.
static STRONG: AtomicBool = AtomicBool::new(false);
/// Interrupt timestamps are folded in only in the unpredictable mode (a replay must not depend on them).
static JITTER_ON: AtomicBool = AtomicBool::new(false);
static JITTER: AtomicU64 = AtomicU64::new(0);

/// Is every layout a function of the seed alone (replay and log modes)? Then the boot log lists them.
pub fn deterministic() -> bool {
    enabled() && !JITTER_ON.load(Ordering::Relaxed)
}

fn counter() -> u64 {
    crate::frame::cpu::counter()
}

fn midr() -> u64 {
    crate::frame::cpu::midr()
}

/// One word from RNDR, if the CPU has it and it answers.
fn rndr() -> Option<u64> {
    if !HAS_RNDR.load(Ordering::Relaxed) {
        return None;
    }
    for _ in 0..4 {
        if let Some(v) = crate::frame::cpu::rndr() {
            return Some(v);
        }
    }
    None
}

/// The whole generator state from a 64-bit seed (so that a printed seed reproduces a run).
fn from_seed(n: u64) -> Rng {
    let mut seed = [0u8; 32];
    for (i, c) in seed.chunks_mut(8).enumerate() {
        c.copy_from_slice(&(n ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes());
    }
    let mut r = Rng::from_seed(seed);
    r.mix(b"metallium-os aslr seed");
    r
}

/// Seed from the hardware and the harness. `disable` fixes every layout.
pub fn init(disable: bool) {
    HAS_RNDR.store(crate::frame::cpu::has_rndr(), Ordering::Relaxed);
    DISABLED.store(disable, Ordering::Relaxed);
    let replay = crate::platform::number(b"opt/metallium/aslr-seed");
    let log = crate::platform::flag(b"opt/metallium/aslr-log");
    let mut rng;
    if disable {
        crate::kprintln!("[rand] WARNING: layout randomisation is off (opt/metallium/noaslr): every layout is the lowest value of its range");
    }
    if let Some(n) = replay {
        rng = from_seed(n);
        crate::kprintln!("[rand] layouts replay seed {n}");
        crate::kprintln!("[rand] WARNING: layouts follow from a seed that was given (opt/metallium/aslr-seed): anyone who knows it can predict them");
    } else {
        let mut seed = [0u8; 32];
        let from_file = crate::platform::bytes(b"opt/metallium/seed", &mut seed);
        let mut hw = [0u8; 32];
        let mut from_rndr = 0;
        for c in hw.chunks_mut(8) {
            if let Some(v) = rndr() {
                c.copy_from_slice(&v.to_le_bytes());
                from_rndr += 1;
            }
        }
        rng = Rng::from_seed(seed);
        rng.mix(&hw);
        let mut misc = [0u8; 16];
        misc[..8].copy_from_slice(&counter().to_le_bytes());
        misc[8..].copy_from_slice(&midr().to_le_bytes());
        rng.mix(&misc);
        if log {
            let n = rng.next_u64();
            rng = from_seed(n);
            crate::kprintln!("[rand] layouts from seed {n} (replay with -fw_cfg name=opt/metallium/aslr-seed,string={n})");
            crate::kprintln!("[rand] WARNING: the seed is printed (opt/metallium/aslr-log): layouts are predictable from this log");
        } else {
            JITTER_ON.store(true, Ordering::Relaxed);
            let strong = from_file == 32 || from_rndr == 4;
            STRONG.store(strong && !disable, Ordering::Relaxed);
            crate::kprintln!("[rand] layouts seeded from: {}{}counter", if from_rndr == 4 { "RNDR " } else { "" }, if from_file > 0 { crate::platform::SEED_SOURCE } else { "" });
            if !strong {
                crate::kprintln!("[rand] WARNING: neither RNDR nor a full opt/metallium/seed: layouts are seeded from the counter alone and can be guessed");
            }
        }
    }
    *RNG.lock(R_RAND) = Some(rng);
}

/// Does the generator take outside entropy (not in the replay, log and noaslr modes)?
pub fn wants_entropy() -> bool {
    JITTER_ON.load(Ordering::Relaxed) && enabled()
}

/// Fold outside entropy (the entropy driver's bytes, `ADD_ENTROPY`) into the generator. Returns false, and does nothing, in the
/// modes where every layout is meant to follow from the seed alone.
pub fn add_entropy(data: &[u8]) -> bool {
    if !wants_entropy() {
        return false;
    }
    if let Some(r) = RNG.lock(R_RAND).as_mut() {
        r.mix(data);
    }
    // (a device that gave at least 16 bytes of its own makes the generator strong, even on a CPU without RNDR)
    if data.len() >= 16 && enabled() {
        STRONG.store(true, Ordering::Relaxed);
    }
    true
}

/// Does the generator have real entropy behind it (so that its output may be used for cryptography)?
pub fn secure_available() -> bool {
    STRONG.load(Ordering::Relaxed)
}

/// Fill `out` with random bytes for cryptographic use; false, and nothing written, if the generator has no real entropy (the layout-randomisation
/// debugging modes, or a machine with no RNDR, no seed and no virtio-rng). The generator is the same ChaCha20 with fast key erasure that draws the
/// layouts: what a program sees of its own layout says nothing about other draws.
pub fn secure_fill(out: &mut [u8]) -> bool {
    if !secure_available() {
        return false;
    }
    with(|r| r.fill(out));
    true
}

/// An interrupt happened: remember when (the next draw folds it in). Cheap and lock-free.
pub fn note_event() {
    if JITTER_ON.load(Ordering::Relaxed) {
        let j = JITTER.load(Ordering::Relaxed);
        JITTER.store(j.rotate_left(7) ^ counter(), Ordering::Relaxed);
    }
}

pub fn enabled() -> bool {
    !DISABLED.load(Ordering::Relaxed)
}

pub fn has_hardware() -> bool {
    HAS_RNDR.load(Ordering::Relaxed)
}

fn with<R>(f: impl FnOnce(&mut Rng) -> R) -> R {
    let mut g = RNG.lock(R_RAND);
    let r = g.as_mut().expect("rand::init not called");
    if JITTER_ON.load(Ordering::Relaxed) {
        r.mix(&JITTER.load(Ordering::Relaxed).to_le_bytes());
    }
    f(r)
}

pub fn next() -> u64 {
    with(|r| r.next_u64())
}

/// A value in `0..n` (`0` when randomisation is off, so layouts are the same every run).
pub fn below(n: usize) -> usize {
    if n <= 1 || !enabled() {
        return 0;
    }
    with(|r| r.below(n as u64)) as usize
}
