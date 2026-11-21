//! The screen task (role 13). It owns the framebuffer mapping and the display driver's client
//! endpoint. First it can draw the colour-bar test card for the display tests (`INFO_CARD`); when
//! the conductor says `INFO_START` it has nothing more to draw; an interactive session says `INFO_CONSOLE` and the screen becomes the console (`console.rs`).
use crate::gpu::{H, W};
use crate::proto::gpu::{GPU_FLUSH, GPU_INFO};
use crate::*;
use alloc::format;
use alloc::string::String;

/// The test conductor is done with the display tests: the screen task has nothing more to draw. (It only answers: the console is
/// not started, so the rest of the test suite runs on a quiet system.)
pub const INFO_START: u64 = 40;
/// An interactive session (`make run-window`): the screen task becomes the console. w1: my slot for the program manager's control
/// endpoint (0: none), w2: my slot for the display endpoint | the manager's task id << 8.
pub const INFO_CONSOLE: u64 = 42;
/// Draw the colour-bar test card and present it.
pub const INFO_CARD: u64 = 41;

/// (the framebuffer is 3 MiB: it goes in the large shared-memory window)
const FB_VA: usize = 0xBC00_0000;

/// What the machine looks like. The fixed parts are gathered once; RAM, tasks and uptime are asked again.
pub struct Facts {
    pub midr: u64,
    pub ncpus: u64,
    pub hz: u64,
    pub ram_pages: u64,
    pub sectors: u64,
    pub gpu_w: u64,
    pub gpu_h: u64,
}

pub fn cpu_name(midr: u64) -> String {
    let (implementer, part) = (midr >> 24 & 0xff, midr >> 4 & 0xfff);
    let name = match (implementer, part) {
        (0x41, 0xd03) => "Cortex-A53",
        (0x41, 0xd04) => "Cortex-A35",
        (0x41, 0xd05) => "Cortex-A55",
        (0x41, 0xd07) => "Cortex-A57",
        (0x41, 0xd08) => "Cortex-A72",
        (0x41, 0xd09) => "Cortex-A73",
        (0x41, 0xd0a) => "Cortex-A75",
        (0x41, 0xd0b) => "Cortex-A76",
        (0x41, 0xd0c) => "Neoverse-N1",
        (0x41, 0xd0d) => "Cortex-A77",
        (0x00, _) | (0x51, _) => "QEMU virtual CPU",
        (0x41, _) => return format!("ARM part {part:#x}"),
        _ => return format!("implementer {implementer:#x} part {part:#x}"),
    };
    String::from(name)
}

pub fn gather() -> Facts {
    let s = sysinfo(0);
    // a service that is restarting answers with an error and echoes our request: use fallbacks
    let (bst, blk) = call(3, [BLK_INFO, 0, 0]);
    let (gst, gpu) = call(1, [GPU_INFO, 0, 0]);
    let (gpu_w, gpu_h) = if gst == 0 { (gpu[0] & 0xffff_ffff, gpu[0] >> 32) } else { (W as u64, H as u64) };
    Facts { midr: s[1], ncpus: s[4], hz: s[5].max(1), ram_pages: s[2], sectors: if bst == 0 { blk[0] } else { 0 }, gpu_w, gpu_h }
}

pub fn uptime(f: &Facts) -> String {
    let secs = ticks() / f.hz;
    format!("{}h {}m {:02}s", secs / 3600, secs / 60 % 60, secs % 60)
}

/// "used / total" in MiB.
pub fn ram(f: &Facts) -> String {
    let free = sysinfo(0)[3];
    format!("{} MiB / {} MiB", (f.ram_pages - free) * 4096 >> 20, f.ram_pages * 4096 >> 20)
}

pub fn info_task() -> ! {
    if mem_map(2, FB_VA, true) != 0 {
        println!("[shell] cannot map the framebuffer");
        exit(1)
    }
    let fb = va(FB_VA) as *mut u32;
    crate::greeter::unlock_screen(fb); // (an encrypted, locked data volume: ask for the passphrase before anything else)
    if sysinfo(2)[3] == 15 {
        // (`make tty-test`: a task that is neither the input driver nor the conductor may not switch the screen)
        let r = call(1, [crate::proto::gpu::GPU_SCANOUT, 1, 0]);
        println!("[tty] TEST the screen task may not switch ttys (reply {}): {}", r.1[0], verdict(r.1[0] == 2));
    }
    println!("[shell] waiting for the display tests to finish");
    loop {
        let m = recv(0);
        match m.w[0] {
            INFO_CARD => {
                // SAFETY: `fb` is the W x H scanout buffer mapped at FB_VA above.
                unsafe { crate::gputest::draw_test_card(fb) };
                let ok = call(1, [GPU_FLUSH, (W as u64) << 32 | (H as u64) << 48, 0]);
                reply([(ok.0 != 0 || ok.1[0] != 0) as u64, 0, 0]);
            }
            INFO_START => {
                reply([0, 0, 0]);
            }
            INFO_CONSOLE => {
                reply([0, 0, 0]);
                crate::screen::run(gather(), m.w[1], m.w[2])
            }
            _ => {
                reply([1, 0, 0]);
            }
        }
    }
}

/// The conductor tells the screen task to take over the display once the tests are done.
pub fn conductor_start() {
    let (st, r) = call(23, [INFO_START, 0, 0]);
    println!("[client] TEST system information screen is drawn and presented (status={st}): {}", verdict(st == 0 && r[0] == 0));
    println!("[fetch] screen presented");
    // Hold still for the screenshot harness. When the harness is going to type into the guest
    // (fw_cfg opt/metallium/interactive) hold much longer: it ends the run itself.
    sleep(if sysinfo(2)[1] != 0 { 60000 } else { 250 });
}
