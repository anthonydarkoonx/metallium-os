//! The unlock screen: while the data volume is encrypted and locked the screen task shows this before anything else (and before the file system serves a byte
//! of `/data`), reads the passphrase from the keyboard and sends it to the data store (`proto::volume`). A greeter of its own (a separate repository linked in
//! with `GREETER=<path>`, docs/GREETER-INTERFACE.md) takes the place of this one; this is what a machine without one shows.
use crate::font::{draw_text, fill_rect};
use crate::gpu::{H, W};
use crate::proto::gpu::GPU_FLUSH2;
use crate::proto::input::{K_BACKSPACE, KBD_POLL};
use crate::proto::volume::{state, LFS_STATUS, LFS_UNLOCK, MORE};
use crate::*;

/// The screen task's capability slots (`kernel/src/task.rs`): the display driver, the keyboard driver, the data store's endpoint.
const SL_GPU: u64 = 1;
const SL_KBD: u64 = 4;
const SL_STORE: u64 = 30;
/// The session service's endpoint (the screen task has a send right to it; nothing receives until a session service runs: one is started in the interactive boot and in `opt/metallium/only=14` (`make greeter-test`),
/// so only there is the slot passed on: a call on an endpoint nobody receives on would wait for ever; 0 tells a greeter there is no service).
const SL_SESSIONS: u64 = 29;

/// Whose session has the screen: the session service's `ACTIVE` answer (id, the name in two words), set when the greeter returns after a login. The id is 0 with no session service.
static ACTIVE_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static ACTIVE_NAME: [core::sync::atomic::AtomicU64; 2] = [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)];

/// The user whose session has the screen (id, name), if a session service ran and somebody logged in.
pub fn active_session() -> Option<(u64, alloc::string::String)> {
    use core::sync::atomic::Ordering::Relaxed;
    let id = ACTIVE_ID.load(Relaxed);
    if id == 0 {
        return None;
    }
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&ACTIVE_NAME[0].load(Relaxed).to_le_bytes());
    raw[8..].copy_from_slice(&ACTIVE_NAME[1].load(Relaxed).to_le_bytes());
    let n = raw.iter().position(|&c| c == 0).unwrap_or(16);
    Some((id, alloc::string::String::from_utf8_lossy(&raw[..n]).into_owned()))
}

/// Ask the session service whose session is the newest (`ACTIVE`, programs/src/bin/sessiond.rs): `(id, name words)`, or `None` if nobody is logged in.
fn ask_active() -> Option<(u64, [u64; 2])> {
    let (st, r) = call(SL_SESSIONS, [5, 0, 0]);
    (st == 0 && r[0] & 0xFF == 0).then_some(((r[0] >> 8) & 0xFFFF, [r[1], r[2]]))
}

/// How the volume is (`state`, flags), or `None` if the store cannot be asked.
pub fn volume_status() -> Option<(u64, u64)> {
    let (st, r) = call(SL_STORE, [LFS_STATUS, 0, 0]);
    (st == 0).then_some((r[0], r[1]))
}

/// Send a passphrase in chunks of 16 bytes; the store's answer (0 unlocked, 1 wrong, ...).
pub fn send_passphrase(word: &[u8]) -> u64 {
    let mut last = 5;
    for off in (0..word.len()).step_by(16) {
        let mut chunk = [0u8; 16];
        let n = (word.len() - off).min(16);
        chunk[..n].copy_from_slice(&word[off..off + n]);
        let w1 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
        let w2 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
        let (st, r) = call(SL_STORE, [LFS_UNLOCK | (word.len() as u64) << 8 | (off as u64) << 24, w1, w2]);
        last = if st == 0 { r[0] } else { 100 };
        if last != MORE {
            break;
        }
    }
    last
}

/// Draw the prompt: centred lines on a plain background.
fn draw(fb: &mut [u32], typed: usize, message: &str) {
    fill_rect(fb, W, 0, 0, W, H, 0x101820);
    let scale = 3;
    let line = |fb: &mut [u32], y: usize, color: u32, text: &str| {
        let w = text.len() * 6 * scale;
        draw_text(fb, W, W.saturating_sub(w) / 2, y, scale, color, text);
    };
    line(fb, H / 2 - 120, 0xE6EDF3, "Metallium-OS");
    line(fb, H / 2 - 60, 0x8FA3B5, "The data volume is encrypted.");
    let dots: alloc::string::String = core::iter::repeat('*').take(typed.min(40)).collect();
    line(fb, H / 2, 0xE6EDF3, &alloc::format!("Passphrase: {dots}_"));
    if !message.is_empty() {
        line(fb, H / 2 + 70, 0xFF7B72, message);
    }
}

fn present() {
    let _ = call(SL_GPU, [GPU_FLUSH2, (W as u64) << 32 | (H as u64) << 48, 0]);
}

/// Runs the greeter if there is something to ask: the volume is locked (until it opens), or a session service is running (accounts: setup, login). With no greeter linked in, the
/// built-in prompt only unlocks a locked volume. `fb` is the W x H scanout buffer.
pub fn unlock_screen(fb: *mut u32) {
    let locked = volume_status().map_or(false, |(s, _)| s == state::LOCKED);
    // (a session service is started in the interactive boot and in the test mode `only=14`: a call on an endpoint nobody receives on would wait for ever, so the slot is passed on only there)
    let sessions = if sysinfo(2)[3] == 14 || (sysinfo(2)[1] != 0 && matches!(sysinfo(2)[3], 0 | 16)) { SL_SESSIONS } else { 0 };
    #[cfg(greeter)]
    if locked || sessions != 0 {
        println!("[greeter] handing the screen to the greeter");
        loop {
            metallium_greeter_boot::metallium_greeter_run(SL_GPU, SL_KBD, SL_STORE, sessions, 2, fb as usize);
            if volume_status().map_or(false, |(s, _)| s == state::LOCKED) {
                break; // (the built-in prompt follows)
            }
            if sessions == 0 {
                return;
            }
            // with a session service the screen is not handed on until somebody is logged in: the console must not be reachable without a session
            if let Some((id, name)) = ask_active() {
                use core::sync::atomic::Ordering::Relaxed;
                ACTIVE_NAME[0].store(name[0], Relaxed);
                ACTIVE_NAME[1].store(name[1], Relaxed);
                ACTIVE_ID.store(id, Relaxed);
                println!("[greeter] session {id} has the screen");
                return;
            }
            println!("[greeter] the greeter returned and nobody is logged in: it runs again");
            sleep(100);
        }
        println!("[greeter] the greeter returned with the volume still locked: the built-in prompt follows");
    }
    #[cfg(not(greeter))]
    let _ = sessions;
    if !locked {
        return;
    }
    // SAFETY: `fb` is the `W * H` scanout buffer the screen task mapped.
    let fb = unsafe { core::slice::from_raw_parts_mut(fb, W * H) };
    println!("[greeter] the data volume is locked: asking for the passphrase");
    let mut word = alloc::vec::Vec::<u8>::new();
    let mut message = "";
    let mut shown = (usize::MAX, "x");
    loop {
        match volume_status() {
            Some((s, _)) if s == state::LOCKED => {}
            _ => break, // (opened, by someone else or by us)
        }
        if shown != (word.len(), message) {
            draw(fb, word.len(), message);
            present();
            shown = (word.len(), message);
        }
        let (st, r) = call(SL_KBD, [KBD_POLL, 0, 0]);
        let n = if st == 0 { r[0].min(16) } else { 0 };
        if n == 0 {
            sleep(1);
            continue;
        }
        for i in 0..n {
            let k = (r[1 + i as usize / 8] >> (8 * (i % 8))) as u8;
            match k {
                b'\r' | b'\n' => {
                    let result = send_passphrase(&word);
                    word.iter_mut().for_each(|b| *b = 0);
                    word.clear();
                    message = if result == 0 { "" } else { "Wrong passphrase" };
                }
                K_BACKSPACE | 0x7f => {
                    word.pop();
                    message = "";
                }
                c if (0x20..0x7f).contains(&c) && word.len() < 120 => {
                    word.push(c);
                    message = "";
                }
                _ => {}
            }
        }
    }
    fill_rect(fb, W, 0, 0, W, H, 0x101820);
    present();
    println!("[greeter] unlocked");
}
