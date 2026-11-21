//! Input driver (role 14): virtio-input over PCI (keyboard and pointer), polled.
//!
//! The device writes 8-byte events (`type`, `code`, `value`, little endian) into buffers the
//! driver keeps on its event queue. Nothing here waits for an interrupt: the shell asks for keys
//! (`KBD_POLL`) and the driver drains the queue, turns key presses into characters with a US
//! layout, and returns up to 16 at a time. Key numbers are the PC/AT scan-code-set-1 numbering of
//! the main keyboard block, which is what the virtio specification's evdev codes use for these keys.
use metallium_driver_rt::proto::input::*;
use metallium_driver_rt::virtio;
use crate::xhci;
use metallium_driver_rt::*;


// where the two devices' memory goes in this task: (registers, queue page, config copy)
const VAS: [(usize, usize, usize); 2] = [(0x8020_0000, 0x8021_0000, 0x8022_0000), (0x8024_0000, 0x8025_0000, 0x8026_0000)];
const NBUF: u16 = 16;
const BUF_OFF: usize = 0x400; // 16 event buffers of 8 bytes, after the rings

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
const REL_WHEEL: u16 = 8;
const BTN_LEFT: u16 = 0x110;
const CFG_EV_BITS: u8 = 0x11;
const KEY_LCTRL: u16 = 29;
const KEY_LSHIFT: u16 = 42;
const KEY_RSHIFT: u16 = 54;
const KEY_RCTRL: u16 = 97;
const KEY_CAPSLOCK: u16 = 58;
const KEY_LALT: u16 = 56;
const KEY_RALT: u16 = 100;
const KEY_DELETE: u16 = 111;
const KEY_ESC: u16 = 1;
/// The display driver's endpoint (the input driver's slot 11): the driver tells it which tty's buffer to show.
const GPU_SLOT: u64 = 11;
/// F1..F12 as tty numbers 0..11 (the PC/AT numbers: F1..F10 are 59..68, F11 and F12 are 87 and 88).
fn fkey(code: u16) -> Option<usize> {
    match code {
        59..=68 => Some((code - 59) as usize),
        87 => Some(10),
        88 => Some(11),
        _ => None,
    }
}

/// (unshifted, shifted) character for a key number; 0 for keys we do not map.
pub fn map(code: u16) -> (u8, u8) {
    const DIGITS: &[u8; 10] = b"1234567890";
    const SHIFTED: &[u8; 10] = b"!@#$%^&*()";
    match code {
        1 => (0x1b, 0x1b),
        2..=11 => (DIGITS[code as usize - 2], SHIFTED[code as usize - 2]),
        12 => (b'-', b'_'),
        13 => (b'=', b'+'),
        14 => (K_BACKSPACE, K_BACKSPACE),
        15 => (b'\t', b'\t'),
        16..=25 => (b"qwertyuiop"[code as usize - 16], b"QWERTYUIOP"[code as usize - 16]),
        26 => (b'[', b'{'),
        27 => (b']', b'}'),
        28 => (b'\n', b'\n'),
        30..=38 => (b"asdfghjkl"[code as usize - 30], b"ASDFGHJKL"[code as usize - 30]),
        39 => (b';', b':'),
        40 => (b'\'', b'"'),
        41 => (b'`', b'~'),
        43 => (b'\\', b'|'),
        44..=50 => (b"zxcvbnm"[code as usize - 44], b"ZXCVBNM"[code as usize - 44]),
        51 => (b',', b'<'),
        52 => (b'.', b'>'),
        53 => (b'/', b'?'),
        57 => (b' ', b' '),
        102 => (K_HOME, K_HOME),
        103 => (K_UP, K_UP),
        104 => (K_PGUP, K_PGUP),
        105 => (K_LEFT, K_LEFT),
        106 => (K_RIGHT, K_RIGHT),
        107 => (K_END, K_END),
        108 => (K_DOWN, K_DOWN),
        109 => (K_PGDN, K_PGDN),
        111 => (K_DELETE, K_DELETE),
        _ => (0, 0),
    }
}

struct Dev {
    pci: virtio::Pci,
    q: virtio::Queue,
    queue_va: usize,
    queue_pa: u64,
    pointer: bool,
}

struct Kbd {
    dev: [Option<Dev>; 2],
    /// The USB controller, if the machine has one: keyboards and pointers on its ports feed the same queues.
    usb: Option<xhci::Usb>,
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps: bool,
    out: [u8; 64],
    head: usize,
    tail: usize,
    /// Input events not yet taken (a ring; a full ring drops the oldest event).
    evs: [u64; 64],
    ev_head: usize,
    ev_len: usize,
    /// The pointer's position so far, and whether it moved since the last report.
    px: i32,
    py: i32,
    moved: bool,
    /// The tty in front (its tasks get the input), the switch Ctrl+Alt+F<n> asked for that the main loop has not done yet, and the F-keys whose release is to be swallowed too.
    active: usize,
    switch: Option<usize>,
    swallow: u16,
    /// Which tty each task's input belongs to (`INPUT_ASSIGN`); a task that is not here is on tty 0.
    assigned: [(u16, u8); 8],
}

impl Kbd {
    fn tty_of(&self, task: u64) -> usize {
        self.assigned.iter().find(|a| a.0 as u64 == task && a.0 != u16::MAX).map_or(0, |a| a.1 as usize)
    }

    /// Whatever is pending belongs to the tty that was in front: drop it, and tell the one coming to the front (so a desktop repaints).
    fn switched(&mut self, tty: usize) {
        self.active = tty;
        (self.head, self.tail, self.ev_head, self.ev_len) = (0, 0, 0, 0);
        self.push_event(ev::pack(ev::FRONT, 0, tty as i32));
    }

    fn push(&mut self, c: u8) {
        let next = (self.tail + 1) % self.out.len();
        if next != self.head {
            self.out[self.tail] = c;
            self.tail = next;
        } // a full buffer drops the key
    }

    fn push_event(&mut self, e: u64) {
        if self.ev_len == self.evs.len() {
            self.ev_head = (self.ev_head + 1) % self.evs.len();
            self.ev_len -= 1;
        }
        let at = (self.ev_head + self.ev_len) % self.evs.len();
        self.evs[at] = e;
        self.ev_len += 1;
    }

    /// The pointer's position changed: report it, replacing a position report nobody has taken yet.
    fn push_move(&mut self) {
        let e = ev::pack(ev::MOVE, 0, self.px | self.py << 16);
        if self.ev_len > 0 {
            let last = (self.ev_head + self.ev_len - 1) % self.evs.len();
            if self.evs[last] & 0xff == ev::MOVE {
                self.evs[last] = e;
                return;
            }
        }
        self.push_event(e);
    }

    fn key(&mut self, code: u16, value: u32) {
        // Ctrl+Alt+F1..F12 is the tty switch: the driver sees the keys first, does the switch itself and the keys reach no desktop (nor their release)
        if let Some(n) = fkey(code) {
            if value != 0 && self.ctrl && self.alt {
                if value == 1 {
                    self.switch = Some(n);
                }
                self.swallow |= 1 << n;
                return;
            }
            if self.swallow & 1 << n != 0 {
                if value == 0 {
                    self.swallow &= !(1 << n);
                }
                return;
            }
        }
        self.push_event(ev::pack(ev::KEY, code, value as i32));
        match code {
            KEY_LSHIFT | KEY_RSHIFT => self.shift = value != 0,
            KEY_LCTRL | KEY_RCTRL => self.ctrl = value != 0,
            KEY_LALT | KEY_RALT => self.alt = value != 0,
            // the attention key: Ctrl+Alt+Delete, or Ctrl+Shift+Escape
            KEY_DELETE if value == 1 && self.ctrl && self.alt => self.push(K_ATTENTION),
            KEY_ESC if value == 1 && self.ctrl && self.shift => self.push(K_ATTENTION),
            KEY_CAPSLOCK if value == 1 => self.caps = !self.caps,
            _ if value == 0 => {}
            _ => {
                let (plain, shifted) = map(code);
                let letter = plain.is_ascii_lowercase();
                let c = if self.shift != (self.caps && letter) { shifted } else { plain };
                if c == 0 {
                    return;
                }
                self.push(if self.ctrl && letter { c & 0x1f } else { c });
            }
        }
    }

    fn pointer_event(&mut self, ty: u16, code: u16, value: u32) {
        match (ty, code) {
            (EV_ABS, ABS_X) => {
                self.px = value.min(32767) as i32;
                self.moved = true;
            }
            (EV_ABS, ABS_Y) => {
                self.py = value.min(32767) as i32;
                self.moved = true;
            }
            (EV_KEY, BTN_LEFT..=0x117) => self.push_event(ev::pack(ev::BUTTON, code - BTN_LEFT + 1, (value != 0) as i32)),
            (EV_REL, REL_WHEEL) => self.push_event(ev::pack(ev::WHEEL, 0, value as i32)),
            (EV_SYN, _) if self.moved => {
                self.moved = false;
                self.push_move();
            }
            _ => {}
        }
    }

    /// Drain finished event buffers, give each back to the device, and decode the events.
    fn pump(&mut self) {
        if let Some(mut u) = self.usb.take() {
            u.poll(self);
            self.usb = Some(u);
        }
        for i in 0..2 {
            let mut posted = false;
            if let Some(d) = &self.dev[i] {
                d.pci.ack_isr(); // (polled: the kernel keeps the device from interrupting, and this clears whatever it holds)
            }
            // The device writes the used ring: bound the work and the ids it hands back.
            for _ in 0..2 * NBUF {
                let Some(d) = self.dev[i].as_mut() else { break };
                let Some((id, _)) = d.q.next_used() else { break };
                if id >= NBUF {
                    continue;
                }
                let e = (d.queue_va + BUF_OFF + 8 * id as usize) as *const u8;
                // SAFETY: `e` points at event buffer `id` (id < NBUF checked above) at BUF_OFF + 8*id, inside the queue page (0x400 + 16*8 <= 4096); 8-aligned; the device wrote it and `next_used` flushed it.
                let (ty, code, value) = unsafe { (read_volatile(e as *const u16), read_volatile(e.add(2) as *const u16), read_volatile(e.add(4) as *const u32)) };
                let (pa, va, pointer) = (d.queue_pa + (BUF_OFF + 8 * id as usize) as u64, d.queue_va + BUF_OFF + 8 * id as usize, d.pointer);
                d.q.post(id, virtio::Buf { pa, va, len: 8, dev_writes: true });
                posted = true;
                if pointer {
                    self.pointer_event(ty, code, value);
                } else if ty == EV_KEY {
                    self.key(code, value);
                }
            }
            if posted {
                if let Some(d) = &self.dev[i] {
                    d.q.kick();
                }
            }
        }
    }

    /// Up to 16 pending characters, packed for the reply.
    fn take(&mut self) -> [u64; 3] {
        let (mut n, mut w) = (0u64, [0u64; 2]);
        while self.head != self.tail && n < 16 {
            w[n as usize / 8] |= (self.out[self.head] as u64) << (8 * (n % 8));
            self.head = (self.head + 1) % self.out.len();
            n += 1;
        }
        [n, w[0], w[1]]
    }

    /// Collect input until an event is pending or `ms` run out (`INPUT_WAIT`). Virtio input devices are polled, so while there are any this looks again every
    /// millisecond; with only a USB controller it sleeps on the controller's interrupt.
    fn wait_events(&mut self, ms: u64) {
        let end = ticks() + ms.div_ceil(10);
        loop {
            self.pump();
            let now = ticks();
            if self.ev_len > 0 || now >= end {
                return;
            }
            match &mut self.usb {
                Some(u) if self.dev.iter().all(|d| d.is_none()) => u.wait(end - now),
                _ => sleep_us(1000),
            }
        }
    }

    /// Up to two pending input events.
    fn take_events(&mut self) -> [u64; 3] {
        let mut r = [0u64; 3];
        let mut n = 0;
        while self.ev_len > 0 && n < 2 {
            r[1 + n] = self.evs[self.ev_head];
            self.ev_head = (self.ev_head + 1) % self.evs.len();
            self.ev_len -= 1;
            n += 1;
        }
        r[0] = n as u64 | (self.dev.iter().flatten().any(|d| d.pointer) as u64 | self.usb.as_ref().is_some_and(|u| u.pointers > 0) as u64) << 8;
        r
    }
}

impl xhci::Sink for Kbd {
    fn key(&mut self, code: u16, value: u32) {
        Kbd::key(self, code, value);
    }
    fn pointer(&mut self, ty: u16, code: u16, value: u32) {
        self.pointer_event(ty, code, value);
    }
}

/// Bring one device up from the capabilities in slots `base`, `base + 1`, `base + 2` (registers, queue page, config copy).
fn dev_init(which: usize, base: u64) -> Result<Dev, &'static str> {
    let (mmio_va, queue_va, cfg_va) = VAS[which];
    if mem_map(base, mmio_va, true) != 0 || mem_map(base + 1, queue_va, true) != 0 || mem_map(base + 2, cfg_va, false) != 0 {
        return Err("mapping failed");
    }
    let (mmio_va, queue_va, cfg_va) = (va(mmio_va), va(queue_va), va(cfg_va)); // (where the kernel put them)
    let (s1, _, bar_pages, _) = cap_info(base);
    let (s2, queue_pa, _, _) = cap_info(base + 1);
    if s1 != 0 || s2 != 0 {
        return Err("cap_info failed");
    }
    // SAFETY: the BAR and config-space mappings the kernel gave this driver (`bar_pages` pages at MMIO_VA / CFG_VA, per its facts).
    let pci = unsafe { virtio::Pci::open(mmio_va, bar_pages as usize * 4096, cfg_va, 0x1052) }?;
    // a pointer has absolute axes: ask the device which kinds of events it produces (virtio-input's EV_BITS query)
    pci.set_config8(0, CFG_EV_BITS);
    pci.set_config8(1, EV_ABS as u8);
    let pointer = pci.config8(2) != 0;
    pci.start()?;
    // SAFETY: `queue_va` is the queue page just mapped (checked) read-write; the device has not been given a queue yet.
    unsafe { core::ptr::write_bytes(queue_va as *mut u8, 0, 4096) }; // forget a crashed predecessor's ring state
    let q = pci.queue(0, NBUF, queue_va, queue_pa)?; // queue 0 is the event queue
    pci.driver_ok();
    let mut d = Dev { pci, q, queue_va, queue_pa, pointer };
    for id in 0..NBUF {
        d.q.post(id, virtio::Buf { pa: queue_pa + (BUF_OFF + 8 * id as usize) as u64, va: queue_va + BUF_OFF + 8 * id as usize, len: 8, dev_writes: true });
    }
    d.q.kick();
    Ok(d)
}

fn kbd_init() -> Result<Kbd, &'static str> {
    let first = dev_init(0, 1).ok();
    let second = dev_init(1, 4).ok(); // (no second device: no pointer)
    // the USB controller's registers are in slot 7 when the machine has one
    let usb = if cap_info(7).0 == 0 {
        match xhci::Usb::init() {
            Ok(u) => Some(u),
            Err(e) => {
                println!("[usb] controller: {e}");
                None
            }
        }
    } else {
        None
    };
    if first.is_none() && second.is_none() && usb.is_none() {
        return Err("no input device");
    }
    Ok(Kbd {
        dev: [first, second],
        usb,
        shift: false,
        ctrl: false,
        alt: false,
        caps: false,
        out: [0; 64],
        head: 0,
        tail: 0,
        evs: [0; 64],
        ev_head: 0,
        ev_len: 0,
        px: 0,
        py: 0,
        moved: false,
        active: 0,
        switch: None,
        swallow: 0,
        assigned: [(u16::MAX, 0); 8],
    })
}

pub fn kbd_driver() -> ! {
    println!("[kbd] driver starting");
    let mut k = match kbd_init() {
        Ok(k) => k,
        Err(e) => {
            println!("[kbd] init failed: {e}");
            exit(1)
        }
    };
    let kinds: alloc::vec::Vec<&str> = k.dev.iter().flatten().map(|d| if d.pointer { "pointer" } else { "keyboard" }).collect();
    if !kinds.is_empty() {
        println!("[kbd] virtio-input ready: {} ({NBUF} event buffers each, polled)", kinds.join(" + "));
    }
    if let Some(u) = &k.usb {
        println!("[kbd] usb ready: {} keyboard(s), {} pointer(s), polled", u.keyboards, u.pointers);
    }
    loop {
        let m = recv(0);
        k.pump();
        if let Some(t) = k.switch.take() {
            // the display driver does the switch (it answers 1 for a tty it has no buffer for: nothing changes then)
            let (st, r) = call(GPU_SLOT, [crate::proto::gpu::GPU_SCANOUT, t as u64, 0]);
            if st == 0 && r[0] == 0 && t != k.active {
                k.switched(t);
                println!("[kbd] tty {t} is in front");
            }
        }
        // a task gets input only while its tty is in front; the others see nothing (and go on asking: a desktop of a tty behind has nothing to do anyway)
        let mine = k.tty_of(m.sender) == k.active;
        match m.w[0] {
            KBD_POLL if mine => reply(k.take()),
            INPUT_POLL if mine => reply(k.take_events()),
            INPUT_WAIT if mine => {
                k.wait_events(m.w[1].min(1000));
                // (a switch during the wait: whatever arrived is for the tty that is in front now)
                if k.tty_of(m.sender) == k.active { reply(k.take_events()) } else { reply([0, 0, 0]) }
            }
            KBD_POLL | INPUT_POLL | INPUT_WAIT => reply([0, 0, 0]),
            INPUT_ASSIGN => {
                let (task, tty) = (m.w[1], m.w[2]);
                let slot = k.assigned.iter().position(|a| a.0 as u64 == task || a.0 == u16::MAX);
                match slot {
                    Some(i) if m.sender == 0 && task < u16::MAX as u64 && tty < 12 => {
                        k.assigned[i] = (task as u16, tty as u8);
                        reply([0, 0, 0])
                    }
                    _ => reply([1, 0, 0]),
                }
            }
            INPUT_ACTIVE => reply([k.active as u64, 0, 0]),
            _ => reply([0, 0, 0]),
        };
    }
}
