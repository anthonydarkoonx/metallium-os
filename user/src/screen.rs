//! The screen task's session: the terminal, centred on the screen, with the keyboard. There is no windowing system (the old GUI was removed on
//! 2026-11-16; a new one is designed in `docs/`). The command shell draws into a buffer this task owns; this file copies the changed rows to the
//! scanout buffer and asks the display driver to flush them.
use crate::gpu::{H, W};
use crate::proto::gpu::GPU_FLUSH2;
use crate::proto::input::KBD_POLL;
use crate::shell::{Host, Shell as Terminal};
use crate::*;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

const FB_VA: usize = 0xBC00_0000;
/// The backdrop behind the terminal.
const BACKDROP: u32 = 0x101820;

static mut KEYS: Vec<u8> = Vec::new();

fn take_keys() -> Vec<u8> {
    poll_keys();
    // SAFETY: the screen task is single-threaded; the shell and this file never run at the same time.
    unsafe { core::mem::take(&mut *core::ptr::addr_of_mut!(KEYS)) }
}

fn poll_keys() {
    let (st, r) = call(4, [KBD_POLL, 0, 0]);
    if st == 0 {
        for i in 0..r[0].min(16) {
            let k = (r[1 + i as usize / 8] >> (8 * (i % 8))) as u8;
            if k != crate::proto::input::K_ATTENTION {
                // SAFETY: as above.
                unsafe { (*core::ptr::addr_of_mut!(KEYS)).push(k) };
            }
        }
    }
}

/// Copy the terminal's changed rows to the screen and flush them.
fn present(fb: *mut u32, term: &[u32], ox: usize, oy: usize) -> bool {
    let Some((y0, y1)) = crate::console::take_dirty() else { return false };
    let (tw, th) = (crate::console::WIDTH, crate::console::HEIGHT);
    let y1 = y1.min(th);
    for y in y0..y1 {
        // SAFETY: the row lies inside the `W` x `H` scanout buffer (the terminal is centred and smaller than the screen).
        unsafe { core::ptr::copy_nonoverlapping(term.as_ptr().add(y * tw), fb.add((oy + y) * W + ox), tw) };
    }
    let r = (ox as u64) | ((oy + y0) as u64) << 16 | (tw as u64) << 32 | ((y1 - y0) as u64) << 48;
    let _ = call(1, [GPU_FLUSH2, r, 0]);
    true
}

/// Hand the screen to a desktop, if the image was built with one (`make run-window DESKTOP=<path>`, docs/DESKTOP-INTERFACE.md).
/// `w2` is what `console_session` sends: the display endpoint's slot (bits 0..8), the program manager's task (8..16) and the power
/// right's slot (16..24). Returns only when there is no desktop in the image or no display endpoint to serve it on.
#[cfg(desktop)]
fn desktop(w2: u64) {
    let display = w2 & 0xFF;
    if display != 0 {
        println!("[console] handing the screen to the desktop");
        metallium_desktop_boot::metallium_desktop_run(display, 1, 4, 2, FB_VA, ((w2 >> 8) & 0xFF) as u32, (w2 >> 16) & 0xFF)
    }
}
#[cfg(not(desktop))]
fn desktop(_w2: u64) {}

/// The terminal's pixels, made once: a console that goes back to the greeter and starts again must not leave a buffer behind each time.
static mut TERM: Option<&'static mut [u32]> = None;

/// Run the console until the user logs out (which returns); without a session service it does not return.
pub fn run(facts: crate::info::Facts, ctl: u64, w2: u64) {
    desktop(w2);
    if mem_map(2, FB_VA, true) != 0 {
        println!("[console] cannot map the framebuffer");
        exit(1)
    }
    let fb = va(FB_VA) as *mut u32;
    let (tw, th) = (crate::console::WIDTH, crate::console::HEIGHT);
    // SAFETY: the screen task is single-threaded; nothing else touches `TERM`, and the buffer it holds is used only by the shell started below, which is gone when this returns.
    let term_buf: &'static mut [u32] = unsafe { (*core::ptr::addr_of_mut!(TERM)).take() }.unwrap_or_else(|| Box::leak(vec![0u32; tw * th].into_boxed_slice()));
    term_buf.fill(crate::console::themed(crate::console::BG));
    let (ox, oy) = (W.saturating_sub(tw) / 2, H.saturating_sub(th) / 2);
    // SAFETY: the scanout buffer is `W * H` words.
    unsafe { core::slice::from_raw_parts_mut(fb, W * H) }.fill(BACKDROP);
    let _ = call(1, [GPU_FLUSH2, (W as u64) << 32 | (H as u64) << 48, 0]);
    // SAFETY: `term_buf` is leaked, so it lives for ever; it holds `tw * th` (WIDTH * HEIGHT) words and nothing else uses it.
    let mut shell = unsafe { Terminal::new(term_buf.as_mut_ptr(), facts, Host { keys: take_keys, idle: || sleep(1) }) };
    shell.progmgr = (ctl != 0).then_some(ctl);
    shell.start();
    println!("[console] up: terminal only, no windowing system");
    let mut last_active = 0u64;
    loop {
        if shell.logout {
            println!("[console] logged out");
            // SAFETY: as above.
            unsafe { *core::ptr::addr_of_mut!(TERM) = Some(core::slice::from_raw_parts_mut(term_buf.as_mut_ptr(), tw * th)) };
            return;
        }
        let shown = present(fb, term_buf, ox, oy);
        let keys = take_keys();
        let typed = !keys.is_empty();
        for k in keys {
            shell.typed(k);
        }
        if shown || typed {
            last_active = ticks();
        }
        if !shown && !typed {
            if ticks().wrapping_sub(last_active) < 25 {
                sleep_us(500);
            } else {
                sleep(1);
            }
        }
    }
}
