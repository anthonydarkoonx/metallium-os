//! The protocols between drivers and their clients: request numbers, reply layouts and the constants a client needs to talk to a driver. A driver and its
//! clients (the console, the shell, `netd`) both depend on this, so neither has to include the other. (Test-only requests are marked as such.)

/// The block driver (role 4).
pub mod blk {
    pub const BLK_READ: u64 = 20;
    pub const BLK_WRITE: u64 = 21;
    pub const BLK_CRASH: u64 = 22;
    /// Ask the block driver for the disk size in sectors.
    pub const BLK_INFO: u64 = 24;
    /// Test only: submit a request without notifying the device, so it never answers.
    pub const BLK_STALL: u64 = 25;
    /// The block driver gives a command this long before declaring the device dead (5 s).
    pub const BLK_WATCHDOG_TICKS: u64 = 500;
    /// Test only: a driver that points its device's DMA at memory it was never granted.
    pub const BLK_EVIL: u64 = 23;
}

/// The display driver (role 12).
pub mod gpu {

    /// Present a rectangle: w1 = x | y << 16 | w << 32 | h << 48.
    pub const GPU_FLUSH: u64 = 30;
    /// Test only: a driver whose device is made to read memory outside its grant.
    pub const GPU_EVIL: u64 = 31;
    /// Ask for (scanout width | height << 32, whether the host reports the display enabled).
    pub const GPU_INFO: u64 = 32;
    /// Test only: send a command without notifying the device, so it never answers.
    pub const GPU_STALL: u64 = 33;
    /// Present up to two rectangles in one call: w1 and w2 are each `x | y << 16 | w << 32 | h << 48`; a zero rectangle is skipped.
    /// Both are copied to the host, then one flush covers the pair. Replies 0, or 1 if a rectangle is outside the screen.
    pub const GPU_FLUSH2: u64 = 34;
    /// Which tty's buffer a present (`GPU_FLUSH`, `GPU_FLUSH2`) is for: put `buffer << 8` in w0 next to the op (0 is the first framebuffer, the one the machine boots with; a driver with
    /// fewer buffers refuses a number it does not have). A buffer that is not on the screen is copied to the host but not shown: it is whole when its tty comes to the front.
    pub const BUFFER_SHIFT: u64 = 8;
    /// Show buffer w1 (the tty in front): `GPU_SCANOUT`. Only the input driver (which sees Ctrl+Alt+F1..F12 first) and the test conductor may ask; anyone else gets 2.
    /// Replies 0, 1 for a buffer that does not exist, 2 for a refused caller.
    pub const GPU_SCANOUT: u64 = 35;
    /// Which buffer is on the screen: reply [buffer, number of buffers, 0]. `GPU_INFO`'s third word is the number of buffers too.
    pub const GPU_ACTIVE: u64 = 36;
}

/// The data volume's lock (the data store server, role 6; the greeter and the other system tasks that hold its endpoint send these). Nothing else about the
/// volume can be asked while it is locked: every file call is answered with `LOCKED`.
pub mod volume {
    /// Ask how the volume is: reply = [state, flags, 0]. `state`: see `state`. `flags`: bit 0 a passphrase opens it, bit 1 the machine's own secret opens it.
    pub const LFS_STATUS: u64 = 120;
    /// Unlock with a passphrase, sent in chunks of 16 bytes: `w[0]` = `LFS_UNLOCK | total length << 8 | offset << 24`, `w[1]`, `w[2]` = the 16 bytes at `offset`
    /// (zero padded). Reply `[result, 0, 0]`: 0 unlocked, `MORE` send the next chunk, 1 wrong passphrase, 2 not locked, 5 malformed. At most 128 bytes.
    pub const LFS_UNLOCK: u64 = 121;
    /// Set (or change) the passphrase of an unlocked encrypted volume, in the same chunks. Reply 0 done, `MORE`, 2 the volume is not encrypted and unlocked, 5 malformed.
    pub const LFS_SET_PASSPHRASE: u64 = 122;
    /// Per-user encryption domains (`docs/ENCRYPTION.md`): domain `d` (1..=63) holds the blocks of the files whose inode numbers carry `d` in bits 24..29. Every call is
    /// `w[0] = op | d << 8 | total length << 16 | offset << 32 | kind << 48`, with a secret in chunks of 16 bytes in `w[1]`, `w[2]` as for `LFS_UNLOCK`.
    /// CREATE a domain (secret: its passphrase): the reply of the last chunk is `[0, recovery key (16 bytes in w1 and w2)]`: shown to the user once, never stored.
    pub const LFS_DOMAIN_CREATE: u64 = 123;
    /// UNLOCK with `kind` 1 (the passphrase) or 3 (the 16 recovery-key bytes): `[0]` open, `[1]` wrong, `[3]` there is no such domain.
    pub const LFS_DOMAIN_UNLOCK: u64 = 124;
    /// LOCK: the store forgets the domain's key at once (its blocks cannot be read or written until it is unlocked again). Reply `[0]`.
    pub const LFS_DOMAIN_LOCK: u64 = 125;
    /// STATUS -> `[state, flags, 0]`: 0 no such domain, 1 locked, 2 open; flags: bit 0 a passphrase slot, bit 1 a recovery slot.
    pub const LFS_DOMAIN_STATUS: u64 = 126;
    /// SET the passphrase of an open domain (the secret: the new passphrase): replaces the passphrase slot, keeps the recovery slot.
    pub const LFS_DOMAIN_SET_PASSPHRASE: u64 = 127;
    /// Reply of a file call while the volume is locked or damaged.
    pub const LOCKED: u64 = 10;
    pub const MORE: u64 = 4;
    pub mod state {
        /// Not encrypted (a volume made before encryption existed, or by a machine that has no secret).
        pub const PLAIN: u64 = 0;
        pub const LOCKED: u64 = 1;
        pub const UNLOCKED: u64 = 2;
        /// Encrypted, but the store could not be read (a damaged volume is never formatted over).
        pub const DAMAGED: u64 = 3;
    }
}

/// The input driver (role 14): keyboard and pointer.
pub mod input {
    /// Ask for pending characters: reply = [count, bytes 0..8 packed little-endian, bytes 8..16].
    pub const KBD_POLL: u64 = 70;
    /// Ask for pending input events (keys as the device numbers them, pointer position, buttons, wheel):
    /// reply = [count | 1 << 8 if the machine has a pointer, event, event], at most two events of eight bytes (see `Event`).
    pub const INPUT_POLL: u64 = 71;
    /// Like `INPUT_POLL`, but if there is no event yet the call waits for one: `w[1]` = the longest wait in milliseconds (at most 1000; 0 = do not wait).
    /// The reply is the same; no events means the time ran out. The driver does nothing else while it waits (so one client should use it, and a
    /// `KBD_POLL` from another waits its turn).
    pub const INPUT_WAIT: u64 = 72;
    /// Say which tty a task's input belongs to: `w[1]` = the task, `w[2]` = the tty (0..11). Only the conductor (task 0) may; the session service's registration is to come. A task
    /// nobody assigned is on tty 0. Replies 0, or 1 for a refused caller or a bad number.
    pub const INPUT_ASSIGN: u64 = 73;
    /// Which tty is in front (the driver switches on Ctrl+Alt+F1..F12 and tells the display driver): reply [tty, 0, 0].
    pub const INPUT_ACTIVE: u64 = 74;

    /// An input event, packed in a word: `kind` (low byte), `code` (next 16 bits), `value` (high 32 bits).
    pub mod ev {
        /// `code` = key number (the device's numbering: the PC/AT set-1 numbers of the main block, 0x110.. for mouse buttons),
        /// `value` = 1 pressed, 0 released, 2 auto-repeat.
        pub const KEY: u64 = 1;
        /// The pointer's absolute position, `value` = x | y << 16, each 0..=32767 of the device's range.
        pub const MOVE: u64 = 2;
        /// A pointer button, `code` = 1 left, 2 right, 3 middle, 4.. others; `value` = 1 pressed, 0 released.
        pub const BUTTON: u64 = 3;
        /// The wheel, `value` = signed clicks (positive = away from the user).
        pub const WHEEL: u64 = 4;
        /// Your tty has come to the front (`value` = the tty): repaint and present again. Sent to the tty's queue when it is switched to.
        pub const FRONT: u64 = 5;
        pub fn pack(kind: u64, code: u16, value: i32) -> u64 {
            kind | (code as u64) << 8 | (value as u32 as u64) << 32
        }
    }

    // special characters the driver reports
    pub const K_BACKSPACE: u8 = 0x08;
    pub const K_UP: u8 = 0x80;
    pub const K_DOWN: u8 = 0x81;
    pub const K_LEFT: u8 = 0x82;
    pub const K_RIGHT: u8 = 0x83;
    pub const K_HOME: u8 = 0x84;
    pub const K_END: u8 = 0x85;
    pub const K_PGUP: u8 = 0x86;
    pub const K_PGDN: u8 = 0x87;
    pub const K_DELETE: u8 = 0x88;
    /// Ctrl+Alt+Delete or Ctrl+Shift+Escape: the "attention" key; the console shows the task manager instead of passing it to a window.
    pub const K_ATTENTION: u8 = 0x90;
}

/// The network driver (role 18); the rings it shares with `netd` are in `netring`.
pub mod net {
    pub const NET_EVENT: u64 = 0x100;
}
