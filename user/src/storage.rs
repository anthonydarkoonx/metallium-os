//! Storage servers (each runs as its own restartable task) and the client-side
//! tests for them.
//!
//!   client --IPC--> rofs-server --IPC--> blk-driver --virtio--> disk
//!   client --IPC--> lfs-server  --IPC--> blk-driver
//!
//! Bulk data moves through shared pages (no copies through the kernel); the
//! block driver picks each caller's DMA buffer from the kernel-provided sender id.
use crate::*;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

// disk layout (must match tools/mkdisk.py). The system partition starts at sector 1024; its size is in the disk header (layout 5: `SYSTEM_MIB` of mkdisk.py), and the
// data partition follows it. These are the sizes of the default disk, which is what an older disk (layout 4) has: see `layout`.
const ROFS_BASE: u64 = 1024;
const ROFS_SECTORS: u64 = 12288;
const LFS_BASE: u64 = 13312;
const LFS_SECTORS: u64 = 11264; // (what the data store gets when the block driver cannot say how big the disk is: the small test disk)

// protocols
const ROFS_READ: u64 = 30; // path in shm[0..256) -> data in shm[256..)
const ROFS_STAT: u64 = 32; // -> reply [0, size, kind(1 file / 2 dir)]
const ROFS_LIST: u64 = 31; // path in shm[0..256) -> '\n'-separated names in shm[256..)
const ROFS_READLINK: u64 = 33; // path (its last component not followed) -> the target of the symbolic link in shm[256..) -> [0, bytes]; 6 if it is not a link
const ROFS_LSTAT: u64 = 34; // like ROFS_STAT, but a symbolic link is reported as itself: kind 3, its size the length of its target
const LFS_PUT: u64 = 40; // w1 = key, 4 KiB block in shm
const LFS_GET: u64 = 41;
const LFS_SYNC: u64 = 42; // reply: device_writes, logical_writes
const LFS_CRASH: u64 = 43;
const LFS_DEL: u64 = 44;
const LFS_STAT: u64 = 45; // reply: gc_runs, gc_moved, free_blocks
const LFS_FAIL_GET: u64 = 46; // test hook: the next LFS_GET reports an I/O error
/// Reply: this instance's epoch. Every store instance has its own; a restarted one has a larger one, and has lost
/// every block that was staged but not yet synced. `LFS_SYNC` takes an expected epoch in w[2] and refuses (status 3,
/// nothing synced) if this is not that instance: a client that staged blocks with a predecessor must not be told
/// they are durable because the successor had nothing to sync.
const LFS_EPOCH: u64 = 47;
use metallium_driver_rt::proto::volume::{state, LFS_DOMAIN_CREATE, LFS_DOMAIN_LOCK, LFS_DOMAIN_SET_PASSPHRASE, LFS_DOMAIN_STATUS, LFS_DOMAIN_UNLOCK, LFS_SET_PASSPHRASE, LFS_STATUS, LFS_UNLOCK, LOCKED, MORE};
const DATA_OFF: usize = 256;

const SERVER_BUF_VA: usize = 0x8022_0000;
const SERVER_SHM_VA: usize = 0x8023_0000;

// ---------------------------------------------------------------------------
// block device access over IPC
// ---------------------------------------------------------------------------
#[derive(Clone, Copy)]
struct BlkDev {
    ep: u64,
    buf: usize,
    base: u64,
    blocks: u64,
}

impl BlkDev {
    /// Retries when the driver dies mid-request: it is restarted by the kernel
    /// and block I/O is idempotent, so replaying is safe.
    fn xfer(&self, op: u64, blk: u64) -> Result<(), ()> {
        if blk >= self.blocks {
            return Err(());
        }
        self.xfer_at(op, blk * 8, 8)
    }
    /// `count` sectors from sector `sector` of this partition, through the driver's buffer (at its start).
    fn xfer_at(&self, op: u64, sector: u64, count: u64) -> Result<(), ()> {
        if sector + count > self.blocks * 8 {
            return Err(());
        }
        for _ in 0..8 {
            let (st, r) = call(self.ep, [op, self.base + sector, count]);
            if st == E_DEAD {
                sleep(2);
                continue;
            }
            return if st == 0 && r[0] == 0 { Ok(()) } else { Err(()) };
        }
        Err(())
    }
    /// 4096 bytes at sector `sector` (not a multiple of 8: the encrypted volume's blocks are 9 sectors apart).
    fn read_block_at(&self, sector: u64, out: &mut [u8; 4096]) -> Result<(), ()> {
        self.xfer_at(BLK_READ, sector, 8)?;
        // SAFETY: as in `read_block`.
        unsafe { core::ptr::copy_nonoverlapping(self.buf as *const u8, out.as_mut_ptr(), 4096) };
        Ok(())
    }
    fn write_block_at(&self, sector: u64, data: &[u8; 4096]) -> Result<(), ()> {
        // SAFETY: as in `write_block`.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.buf as *mut u8, 4096) };
        self.xfer_at(BLK_WRITE, sector, 8)
    }
    fn read_block(&self, blk: u64, out: &mut [u8; 4096]) -> Result<(), ()> {
        self.xfer(BLK_READ, blk)?;
        // SAFETY: `self.buf` is this server's 4096-byte block-driver buffer (SERVER_BUF_VA, mapped by `map_server_memory` before any `BlkDev` exists); `out` is a separate 4096-byte array; the transfer finished in `xfer`.
        unsafe { core::ptr::copy_nonoverlapping(self.buf as *const u8, out.as_mut_ptr(), 4096) };
        Ok(())
    }
    fn write_block(&self, blk: u64, data: &[u8; 4096]) -> Result<(), ()> {
        // SAFETY: as in `read_block`: `self.buf` is the mapped 4096-byte driver buffer and `data` a separate array; the driver reads it only after `xfer`.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.buf as *mut u8, 4096) };
        self.xfer(BLK_WRITE, blk)
    }
}

impl metallium_lfs::BlockDev for BlkDev {
    fn blocks(&self) -> u64 {
        self.blocks
    }
    fn read(&self, blk: u64, buf: &mut [u8; 4096]) -> Result<(), metallium_lfs::Error> {
        self.read_block(blk, buf).map_err(|_| metallium_lfs::Error::Io)
    }
    fn write(&mut self, blk: u64, buf: &[u8; 4096]) -> Result<(), metallium_lfs::Error> {
        self.write_block(blk, buf).map_err(|_| metallium_lfs::Error::Io)
    }
}

// ---------------------------------------------------------------------------
// the encrypted data volume
// ---------------------------------------------------------------------------
// Layout of an encrypted volume (sectors of the data partition): the volume header (`metallium-crypt`, one 4 KiB block: key slots) at 0..8; then every block of
// the store takes 9 sectors: its 4096 bytes of ciphertext and, in a sector of its own, the nonce and tag. The store above sees plain 4 KiB blocks.
const HEADER_SECTORS: u64 = 8;
const PBKDF2_ITERATIONS: u32 = 100_000;

fn random_bytes(out: &mut [u8]) -> bool {
    let mut at = 0;
    while at < out.len() {
        let r = svc(GETRANDOM, 0, 0, 0, 0, 0);
        if r[0] as i64 != 0 {
            return false;
        }
        for w in &r[1..6] {
            for b in w.to_le_bytes() {
                if at < out.len() {
                    out[at] = b;
                    at += 1;
                }
            }
        }
    }
    true
}

/// The machine's own secret, if it has one and this task may ask.
fn device_secret() -> Option<[u8; 32]> {
    let r = svc(DEVICE_SECRET, 0, 0, 0, 0, 0);
    if r[0] as i64 != 0 {
        return None;
    }
    let mut s = [0u8; 32];
    for i in 0..4 {
        s[i * 8..i * 8 + 8].copy_from_slice(&r[i + 1].to_le_bytes());
    }
    Some(s)
}

#[derive(Clone, Copy)]
struct EncDev {
    raw: BlkDev,
    key: [u8; 32],
    id: [u8; 16],
}

impl EncDev {
    fn first(&self, blk: u64) -> u64 {
        HEADER_SECTORS + 9 * blk
    }
}

impl metallium_lfs::BlockDev for EncDev {
    fn blocks(&self) -> u64 {
        (self.raw.blocks * 8).saturating_sub(HEADER_SECTORS) / 9
    }
    fn read(&self, blk: u64, out: &mut [u8; 4096]) -> Result<(), metallium_lfs::Error> {
        use metallium_lfs::Error;
        if blk >= self.blocks() {
            return Err(Error::Io);
        }
        let at = self.first(blk);
        let mut meta = [0u8; metallium_crypt::META_LEN];
        self.raw.xfer_at(BLK_READ, at + 8, 1).map_err(|_| Error::Io)?;
        // SAFETY: `raw.buf` is this server's mapped 4096-byte driver buffer; the one-sector transfer has finished and wrote the first 512 bytes.
        unsafe { core::ptr::copy_nonoverlapping(self.raw.buf as *const u8, meta.as_mut_ptr(), meta.len()) };
        self.raw.read_block_at(at, out).map_err(|_| Error::Io)?;
        // (a block that was never written, or was torn, or was changed, does not open: the store above treats that as a block that is not valid)
        if metallium_crypt::open_block(&self.key, &self.id, blk, &meta, out) {
            Ok(())
        } else {
            out.fill(0);
            Err(Error::Corrupt)
        }
    }
    fn write(&mut self, blk: u64, buf: &[u8; 4096]) -> Result<(), metallium_lfs::Error> {
        use metallium_lfs::Error;
        if blk >= self.blocks() {
            return Err(Error::Io);
        }
        let mut nonce = [0u8; 12];
        if !random_bytes(&mut nonce) {
            return Err(Error::Io); // (no secure random numbers: nothing is written that could repeat a nonce)
        }
        let mut data = *buf;
        let meta = metallium_crypt::seal_block(&self.key, &self.id, blk, nonce, &mut data);
        let at = self.first(blk);
        self.raw.write_block_at(at, &data).map_err(|_| Error::Io)?;
        // SAFETY: as above: the driver's buffer; the sector is written with the metadata first and zeros after it.
        unsafe {
            core::ptr::write_bytes(self.raw.buf as *mut u8, 0, 512);
            core::ptr::copy_nonoverlapping(meta.as_ptr(), self.raw.buf as *mut u8, meta.len());
        }
        self.raw.xfer_at(BLK_WRITE, at + 8, 1).map_err(|_| Error::Io)
    }
}

/// The store's device: the partition as it is, or the encrypted view of it.
#[derive(Clone, Copy)]
enum VolDev {
    Plain(BlkDev),
    Enc(EncDev),
}

impl metallium_lfs::BlockDev for VolDev {
    fn blocks(&self) -> u64 {
        match self {
            VolDev::Plain(d) => d.blocks(),
            VolDev::Enc(d) => d.blocks(),
        }
    }
    fn read(&self, blk: u64, buf: &mut [u8; 4096]) -> Result<(), metallium_lfs::Error> {
        match self {
            VolDev::Plain(d) => d.read(blk, buf),
            VolDev::Enc(d) => d.read(blk, buf),
        }
    }
    fn write(&mut self, blk: u64, buf: &[u8; 4096]) -> Result<(), metallium_lfs::Error> {
        match self {
            VolDev::Plain(d) => d.write(blk, buf),
            VolDev::Enc(d) => d.write(blk, buf),
        }
    }
}

type Store = metallium_lfs::Lfs<VolDev>;

/// What the data volume is right now.
enum Vol {
    /// Not encrypted.
    Plain(Store),
    /// Encrypted and locked: the header, and what has been typed so far.
    Locked { header: Box<[u8; metallium_crypt::HEADER_LEN]> },
    /// Encrypted and open.
    Open { fs: Store, header: Box<[u8; metallium_crypt::HEADER_LEN]>, key: [u8; 32] },
    /// Encrypted, but the store does not read: it is never formatted over.
    Damaged,
}

impl Vol {
    fn store(&mut self) -> Option<&mut Store> {
        match self {
            Vol::Plain(fs) | Vol::Open { fs, .. } => Some(fs),
            _ => None,
        }
    }
}

/// Make an encrypted volume on a blank partition: a fresh key, the header with one slot for the machine's secret, and an empty store.
fn create_encrypted(raw: BlkDev, secret: &[u8; 32]) -> Option<Vol> {
    let (mut id, mut key, mut salt, mut nonce) = ([0u8; 16], [0u8; 32], [0u8; 32], [0u8; 12]);
    if !(random_bytes(&mut id) && random_bytes(&mut key) && random_bytes(&mut salt) && random_bytes(&mut nonce)) {
        return None;
    }
    let mut header = Box::new(metallium_crypt::new_header(id));
    metallium_crypt::set_slot(&mut header, 0, metallium_crypt::Kind::Device, secret, 1, salt, nonce, &key);
    // the store first, then the header that makes the volume exist: a crash in between leaves a blank partition, not half a volume
    let dev = VolDev::Enc(EncDev { raw, key, id });
    let fs = metallium_lfs::Lfs::format(dev).ok()?;
    raw.write_block(0, &header).ok()?;
    Some(Vol::Open { fs, header, key })
}

/// Mount an encrypted volume whose key is known.
fn open_encrypted(raw: BlkDev, header: Box<[u8; metallium_crypt::HEADER_LEN]>, key: [u8; 32]) -> Vol {
    let dev = VolDev::Enc(EncDev { raw, key, id: metallium_crypt::volume_id(&header) });
    match metallium_lfs::Lfs::mount(dev) {
        Ok(fs) => Vol::Open { fs, header, key },
        Err(_) => Vol::Damaged,
    }
}

fn flags_of(header: &[u8; metallium_crypt::HEADER_LEN]) -> u64 {
    let mut f = 0;
    for i in 0..metallium_crypt::SLOTS {
        match metallium_crypt::slot_kind(header, i) {
            Some(metallium_crypt::Kind::Passphrase) => f |= 1,
            Some(metallium_crypt::Kind::Device) => f |= 2,
            Some(metallium_crypt::Kind::Recovery) | None => {}
        }
    }
    f
}

/// EROFS byte source with a one-block cache.
struct BlkSource {
    dev: BlkDev,
    cache: RefCell<(u64, Box<[u8; 4096]>)>,
}

impl metallium_erofs::Source for BlkSource {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), metallium_erofs::Error> {
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let (idx, inb) = (pos / 4096, (pos % 4096) as usize);
            let mut c = self.cache.borrow_mut();
            if c.0 != idx {
                self.dev.read_block(idx, &mut c.1).map_err(|_| metallium_erofs::Error::Io)?;
                c.0 = idx;
            }
            let n = (buf.len() - done).min(4096 - inb);
            buf[done..done + n].copy_from_slice(&c.1[inb..inb + n]);
            done += n;
        }
        Ok(())
    }
}

/// Each client of a storage server has its own shared page, chosen by the
/// kernel-provided sender id: 0 = test conductor, 7 = VFS server.
fn shm_for(sender: u64) -> Option<&'static mut [u8; 4096]> {
    let i = match sender {
        0 => 0,
        7 => 1,
        _ => return None,
    };
    // SAFETY: i is 0 or 1; SERVER_SHM_VA and the page after it were mapped read-write by `map_server_memory` before the server loop; the client may write the page concurrently, so its contents are untrusted bytes.
    Some(unsafe { &mut *((va(SERVER_SHM_VA + i * 0x1000)) as *mut [u8; 4096]) })
}

fn map_server_memory(buf_slot: u64) {
    if mem_map(buf_slot, SERVER_BUF_VA, true) != 0
        || mem_map(3, SERVER_SHM_VA, true) != 0
        || mem_map(4, SERVER_SHM_VA + 0x1000, true) != 0
    {
        println!("[storage] mapping failed");
        exit(1);
    }
}

// ---------------------------------------------------------------------------
// role 5: EROFS system-partition server (read-only)
// ---------------------------------------------------------------------------
/// The disk's layout from sector 0: (sectors of the system partition, first sector of the data partition). Layout 5 has the size in bytes 48..56 of the
/// header; a disk made before that (layout 4), or a header that does not make sense, has the sizes of the default disk.
fn layout() -> (u64, u64) {
    let hdr = BlkDev { ep: 1, buf: va(SERVER_BUF_VA), base: 0, blocks: 1 };
    let mut b = Box::new([0u8; 4096]);
    if hdr.read_block(0, &mut b).is_ok() && &b[40..48] == b"layout=5" {
        let rofs = u64::from_le_bytes(b[48..56].try_into().unwrap());
        if (2048..1 << 32).contains(&rofs) && rofs % 8 == 0 {
            return (rofs, ROFS_BASE + rofs);
        }
    }
    (ROFS_SECTORS, LFS_BASE)
}

pub fn rofs_server() -> ! {
    map_server_memory(2);
    let (rofs_sectors, _) = layout();
    let dev = BlkDev { ep: 1, buf: va(SERVER_BUF_VA), base: ROFS_BASE, blocks: rofs_sectors / 8 };
    let src = BlkSource { dev, cache: RefCell::new((u64::MAX, Box::new([0; 4096]))) };
    let fs = match metallium_erofs::Erofs::new(src) {
        Ok(fs) => fs,
        Err(e) => {
            println!("[rofs] mount failed: {e:?}");
            exit(1)
        }
    };
    println!("[rofs] EROFS system partition mounted (read-only)");
    loop {
        let m = recv(0);
        let Some(page) = shm_for(m.sender) else {
            reply([9, 0, 0]);
            continue;
        };
        let own: [u8; DATA_OFF] = snapshot(&page[..DATA_OFF]); // (the client may rewrite the page while we parse it)
        let plen = own.iter().position(|&c| c == 0).unwrap_or(DATA_OFF);
        let path = core::str::from_utf8(&own[..plen]).unwrap_or("");
        // symbolic links are followed in every component, and in the last one except for `lstat` and `readlink`; a loop or a long chain is status 11
        let follow = !matches!(m.w[0], ROFS_LSTAT | ROFS_READLINK);
        let ino = match fs.resolve(path, follow) {
            Ok(i) => i,
            Err(metallium_erofs::Error::TooManyLinks) => {
                reply([11, 0, 0]);
                continue;
            }
            Err(_) => {
                reply([1, 0, 0]);
                continue;
            }
        };
        match m.w[0] {
            ROFS_STAT => {
                reply([0, ino.size, if ino.is_dir() { 2 } else { 1 }]);
            }
            ROFS_LSTAT => {
                reply([0, ino.size, if ino.is_symlink() { 3 } else if ino.is_dir() { 2 } else { 1 }]);
            }
            ROFS_READLINK => {
                match fs.readlink(&ino, &mut page[DATA_OFF..]) {
                    Ok(n) => reply([0, n as u64, 0]),
                    Err(metallium_erofs::Error::NotLink) => reply([6, 0, 0]),
                    Err(_) => reply([7, 0, 0]),
                };
            }
            ROFS_READ if ino.is_file() => {
                let len = (m.w[2] as usize).min(4096 - DATA_OFF);
                match fs.read(&ino, m.w[1], &mut page[DATA_OFF..DATA_OFF + len]) {
                    Ok(n) => reply([0, n as u64, ino.size]),
                    Err(_) => reply([2, 0, 0]),
                };
            }
            ROFS_LIST if ino.is_dir() => {
                // `w[1]` entries are skipped (a directory too big for one page is read in pieces: the caller asks again from where the last piece ended); only whole
                // names are put in the page, and the third reply word says whether more are left
                let cursor = m.w[1] as usize;
                let cap = 4096 - DATA_OFF;
                let (mut out, mut seen, mut more) = (Vec::new(), 0usize, false);
                let _ = fs.read_dir(&ino, |n, _, ftype| {
                    if n == b"." || n == b".." {
                        return true;
                    }
                    if seen >= cursor {
                        if out.len() + n.len() + 2 > cap {
                            more = true;
                            return false;
                        }
                        out.extend_from_slice(n);
                        if ftype == 2 {
                            out.push(b'/'); // directories carry a trailing slash
                        }
                        out.push(b'\n');
                    }
                    seen += 1;
                    true
                });
                page[DATA_OFF..DATA_OFF + out.len()].copy_from_slice(&out);
                reply([0, out.len() as u64, more as u64]);
            }
            _ => {
                reply([3, 0, 0]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// role 6: log-structured data store server
// ---------------------------------------------------------------------------
pub fn lfs_server() -> ! {
    map_server_memory(2);
    // the data partition is the rest of the disk, whatever its size (tools/mkdisk.py leaves it to us); where it starts depends on the size of the system partition
    let (_, lfs_base) = layout();
    let sectors = match call(1, [BLK_INFO, 0, 0]) {
        (0, r) if r[0] >= lfs_base + 4096 => r[0] - lfs_base,
        _ => LFS_SECTORS,
    };
    let raw = BlkDev { ep: 1, buf: va(SERVER_BUF_VA), base: lfs_base, blocks: sectors / 8 };
    println!("[lfs] data partition: {} KiB", sectors / 2);
    let secret = device_secret();
    let mut header0 = Box::new([0u8; metallium_crypt::HEADER_LEN]);
    let encrypted = raw.read_block(0, &mut header0).is_ok() && metallium_crypt::is_header(&header0[..]);
    let mut vol = if encrypted {
        // an encrypted volume: the machine's own secret opens it if it can; otherwise it waits for a passphrase (`LFS_UNLOCK`)
        match secret.and_then(|s| metallium_crypt::unlock(&header0, metallium_crypt::Kind::Device, &s)) {
            Some(key) => {
                println!("[lfs] encrypted volume opened with the machine's secret");
                open_encrypted(raw, header0, key)
            }
            None => {
                println!("[lfs] encrypted volume: locked, waiting for a passphrase");
                Vol::Locked { header: header0 }
            }
        }
    } else {
        match metallium_lfs::Lfs::mount(VolDev::Plain(raw)) {
            Ok(fs) => {
                println!("[lfs] mounted existing store: {} blocks live (not encrypted)", fs.len());
                Vol::Plain(fs)
            }
            Err(_) => {
                // a blank partition: a machine with a secret of its own gets an encrypted volume (by default), any other a plain one as before
                match secret.and_then(|s| create_encrypted(raw, &s)) {
                    Some(v) => {
                        println!("[lfs] no valid store: made an encrypted volume (machine secret)");
                        v
                    }
                    None => match metallium_lfs::Lfs::format(VolDev::Plain(raw)) {
                        Ok(fs) => {
                            println!("[lfs] no valid checkpoint: formatted fresh store");
                            Vol::Plain(fs)
                        }
                        Err(e) => {
                            println!("[lfs] format failed: {e:?}");
                            exit(1)
                        }
                    },
                }
            }
        }
    };
    if let Vol::Open { fs, .. } = &vol {
        println!("[lfs] encrypted store: {} blocks live", fs.len());
    }
    let mut pass = [0u8; 128];
    let mut pass_len = 0usize;
    let mut domains = Domains { keys: [None; MAX_DOMAINS] };
    let mut tmp = Box::new([0u8; 4096]);
    let mut fail_get = false;
    let epoch = ticks() + 1;
    loop {
        let m = recv(0);
        // the lock's own calls (any holder of the endpoint; nothing here touches the files)
        let op = m.w[0] & 0xFF;
        if matches!(op, LFS_STATUS | LFS_UNLOCK | LFS_SET_PASSPHRASE) {
            reply(volume_call(&mut vol, raw, op, &m, &mut pass, &mut pass_len));
            continue;
        }
        if (LFS_DOMAIN_CREATE..=LFS_DOMAIN_SET_PASSPHRASE).contains(&op) {
            reply(domain_call(&mut vol, &mut domains, op, &m, &mut pass, &mut pass_len));
            continue;
        }
        let Some(fs) = vol.store() else {
            reply([LOCKED, 0, 0]);
            continue;
        };
        let key = m.w[1];
        let Some(sh) = shm_for(m.sender) else {
            reply([9, 0, 0]);
            continue;
        };
        match m.w[0] {
            LFS_PUT | LFS_GET | LFS_DEL if reserved_key(key) => {
                reply([9, 0, 0]); // (twins and domain headers are the store's own)
            }
            LFS_PUT => {
                tmp.copy_from_slice(&sh[..]);
                let d = domain_of(key);
                if d == 0 {
                    fs.write_block(key, &tmp);
                    reply([0, epoch, 0]);
                } else if let Some(dk) = domains.keys[d] {
                    // a block of a user's domain: sealed under the domain's key before it reaches the log
                    reply([if put_sealed(fs, &dk, d, key, &mut tmp) { 0 } else { 2 }, epoch, 0]);
                } else {
                    reply([LOCKED, epoch, 0]);
                }
            }
            // status 0 = found, 1 = there is no such block (a hole), 2 = the store could not tell (I/O error):
            // a client must never take an error for a hole, or a failed read turns into zeros
            LFS_GET => match if core::mem::take(&mut fail_get) { Err(metallium_lfs::Error::Io) } else { fs.read_block(key, &mut tmp) } {
                Ok(()) => {
                    let d = domain_of(key);
                    if d != 0 {
                        match domains.keys[d] {
                            None => {
                                reply([LOCKED, epoch, 0]);
                                continue;
                            }
                            Some(dk) => {
                                if !open_sealed(fs, &dk, d, key, &mut tmp) {
                                    reply([2, epoch, 0]); // (changed on the disk, or not this block: an error, never a hole)
                                    continue;
                                }
                            }
                        }
                    }
                    sh.copy_from_slice(&tmp[..]);
                    reply([0, epoch, 0]);
                }
                Err(metallium_lfs::Error::NotFound) => {
                    reply([1, epoch, 0]);
                }
                Err(_) => {
                    reply([2, epoch, 0]);
                }
            },
            LFS_EPOCH => {
                reply([0, epoch, 0]);
            }
            LFS_FAIL_GET => {
                fail_get = true;
                reply([0, 0, 0]);
            }
            LFS_STAT => {
                reply([fs.stats.gc_runs, fs.stats.gc_moved, fs.free_blocks()]);
            }
            LFS_DEL => {
                fs.delete_block(key);
                reply([0, epoch, 0]);
            }
            LFS_SYNC => {
                if m.w[2] != 0 && m.w[2] != epoch {
                    reply([3, 0, 0]); // the caller staged its blocks with an earlier instance: they are gone
                    continue;
                }
                let st = fs.sync().is_ok();
                reply([!st as u64, fs.stats.device_writes, fs.stats.logical_writes]);
            }
            LFS_CRASH => {
                println!("[lfs] simulated fault with unsynced data in RAM");
                // SAFETY: deliberate fault injection: 0x3000 is below every mapping (images are at 0x8000_0000 or higher), so the store traps and the kernel restarts lfs; that is the test.
                unsafe { write_volatile(0x3000 as *mut u64, 1) };
            }
            _ => {
                reply([9, 0, 0]);
            }
        }
    }
}


// ---------------------------------------------------------------------------
// per-user encryption domains
// ---------------------------------------------------------------------------
// An inode number carries a domain in bits 24..29 (0: the system's, which has no layer of its own beyond the volume's). Blocks of a domain d > 0 are sealed under that
// domain's key before they reach the store's log: the store reads the domain out of the block's key (`domain_of`). A block is exactly 4096 bytes, so its nonce and tag
// (28 bytes) are kept in a *twin* block that holds those of 16 consecutive blocks of one inode (`twin_key`; bit 62 of the key marks a twin). The domain's own key is in a header
// block (key `DOMAIN_HDR + d`, the volume header's format) sealed by the user's passphrase and by a recovery key; it is held in memory only while the domain is unlocked.
const DOMAIN_HDR: u64 = 0x4000;
const TWIN_BIT: u64 = 1 << 62;
const MAX_DOMAINS: usize = 64;

fn domain_of(key: u64) -> usize {
    ((key >> 56) & 0x3F) as usize
}
fn twin_key(key: u64) -> u64 {
    (key & 0xFFFF_FFFF_0000_0000) | TWIN_BIT | ((key & 0xFFFF_FFFF) >> 4)
}
/// Keys that belong to the store itself: twins and domain headers. A client may not read, write or delete them.
fn reserved_key(key: u64) -> bool {
    key & TWIN_BIT != 0 || (DOMAIN_HDR..DOMAIN_HDR + MAX_DOMAINS as u64).contains(&key)
}
fn domain_id(d: usize) -> [u8; 16] {
    let mut id = [0xD0u8; 16];
    id[15] = d as u8;
    id
}

struct Domains {
    keys: [Option<[u8; 32]>; MAX_DOMAINS],
}

/// Seal `data` (in place) as the block `key` of domain `d` and write it and its tag to the store.
fn put_sealed(fs: &mut Store, dk: &[u8; 32], d: usize, key: u64, data: &mut [u8; 4096]) -> bool {
    let mut nonce = [0u8; 12];
    if !random_bytes(&mut nonce) {
        return false; // (no secure random numbers: nothing is written under a nonce that might repeat)
    }
    let meta = metallium_crypt::seal_block(dk, &domain_id(d), key, nonce, &mut data[..]);
    let tk = twin_key(key);
    let mut tb = [0u8; 4096];
    match fs.read_block(tk, &mut tb) {
        Ok(()) | Err(metallium_lfs::Error::NotFound) => {}
        Err(_) => return false,
    }
    let at = (key & 0xF) as usize * 32;
    tb[at..at + metallium_crypt::META_LEN].copy_from_slice(&meta);
    fs.write_block(key, data);
    fs.write_block(tk, &tb);
    true
}

/// Open a block of domain `d` that was just read (still sealed) into `data`: false if it does not authenticate.
fn open_sealed(fs: &Store, dk: &[u8; 32], d: usize, key: u64, data: &mut [u8; 4096]) -> bool {
    let mut tb = [0u8; 4096];
    if fs.read_block(twin_key(key), &mut tb).is_err() {
        return false;
    }
    let at = (key & 0xF) as usize * 32;
    let mut meta = [0u8; metallium_crypt::META_LEN];
    meta.copy_from_slice(&tb[at..at + metallium_crypt::META_LEN]);
    metallium_crypt::open_block(dk, &domain_id(d), key, &meta, &mut data[..])
}

/// The domain calls (`proto::volume`): create, unlock, lock, status, set the passphrase.
fn domain_call(vol: &mut Vol, domains: &mut Domains, op: u64, m: &Msg, pass: &mut [u8; 128], pass_len: &mut usize) -> [u64; 3] {
    use metallium_crypt::{unlock, Kind};
    let d = ((m.w[0] >> 8) & 0xFF) as usize;
    let Some(fs) = vol.store() else { return [LOCKED, 0, 0] };
    if d == 0 || d >= MAX_DOMAINS {
        return [5, 0, 0];
    }
    let hdr_key = DOMAIN_HDR + d as u64;
    let mut hdr = Box::new([0u8; 4096]);
    let have = match fs.read_block(hdr_key, &mut hdr) {
        Ok(()) => metallium_crypt::is_header(&hdr[..]),
        Err(metallium_lfs::Error::NotFound) => false,
        Err(_) => return [2 + 3, 0, 0],
    };
    if op == LFS_DOMAIN_STATUS {
        if !have {
            return [0, 0, 0];
        }
        let mut flags = 0;
        for i in 0..metallium_crypt::SLOTS {
            match metallium_crypt::slot_kind(&hdr, i) {
                Some(Kind::Passphrase) => flags |= 1,
                Some(Kind::Recovery) => flags |= 2,
                _ => {}
            }
        }
        return [if domains.keys[d].is_some() { 2 } else { 1 }, flags, 0];
    }
    if op == LFS_DOMAIN_LOCK {
        if let Some(k) = domains.keys[d].as_mut() {
            k.fill(0);
        }
        domains.keys[d] = None;
        return [0, 0, 0];
    }
    // the secret, in chunks
    let (total, offset, kind) = (((m.w[0] >> 16) & 0xFFFF) as usize, ((m.w[0] >> 32) & 0xFFFF) as usize, ((m.w[0] >> 48) & 0xF) as u8);
    if offset == 0 {
        *pass_len = 0;
    }
    if total == 0 || total > pass.len() || offset % 16 != 0 || offset >= total || offset != *pass_len {
        *pass_len = 0;
        pass.fill(0);
        return [5, 0, 0];
    }
    let mut chunk = [0u8; 16];
    chunk[..8].copy_from_slice(&m.w[1].to_le_bytes());
    chunk[8..].copy_from_slice(&m.w[2].to_le_bytes());
    let n = (total - offset).min(16);
    pass[offset..offset + n].copy_from_slice(&chunk[..n]);
    *pass_len = offset + n;
    if *pass_len < total {
        return [MORE, 0, 0];
    }
    let word: alloc::vec::Vec<u8> = pass[..total].to_vec();
    pass.fill(0);
    *pass_len = 0;
    match op {
        LFS_DOMAIN_CREATE => {
            if have {
                return [2, 0, 0];
            }
            let (mut id, mut key, mut rec) = ([0u8; 16], [0u8; 32], [0u8; 16]);
            let (mut s1, mut s2, mut n1, mut n2) = ([0u8; 32], [0u8; 32], [0u8; 12], [0u8; 12]);
            if !(random_bytes(&mut id) && random_bytes(&mut key) && random_bytes(&mut rec) && random_bytes(&mut s1) && random_bytes(&mut s2) && random_bytes(&mut n1) && random_bytes(&mut n2)) {
                return [5, 0, 0];
            }
            let mut h = metallium_crypt::new_header(id);
            metallium_crypt::set_slot(&mut h, 0, Kind::Passphrase, &word, PBKDF2_ITERATIONS, s1, n1, &key);
            metallium_crypt::set_slot(&mut h, 1, Kind::Recovery, &rec, 1, s2, n2, &key);
            fs.write_block(hdr_key, &h);
            if fs.sync().is_err() {
                return [5, 0, 0];
            }
            domains.keys[d] = Some(key);
            [0, u64::from_le_bytes(rec[..8].try_into().unwrap()), u64::from_le_bytes(rec[8..].try_into().unwrap())]
        }
        LFS_DOMAIN_UNLOCK => {
            if !have {
                return [3, 0, 0];
            }
            let k = if kind == 3 { unlock(&hdr, Kind::Recovery, &word) } else { unlock(&hdr, Kind::Passphrase, &word) };
            match k {
                Some(key) => {
                    domains.keys[d] = Some(key);
                    [0, 0, 0]
                }
                None => [1, 0, 0],
            }
        }
        LFS_DOMAIN_SET_PASSPHRASE => {
            let Some(key) = domains.keys[d] else { return [LOCKED, 0, 0] };
            if !have {
                return [3, 0, 0];
            }
            let (mut s, mut n) = ([0u8; 32], [0u8; 12]);
            if !(random_bytes(&mut s) && random_bytes(&mut n)) {
                return [5, 0, 0];
            }
            let slot = (0..metallium_crypt::SLOTS).find(|&i| metallium_crypt::slot_kind(&hdr, i) == Some(Kind::Passphrase)).or_else(|| (0..metallium_crypt::SLOTS).find(|&i| metallium_crypt::slot_kind(&hdr, i).is_none()));
            let Some(slot) = slot else { return [5, 0, 0] };
            metallium_crypt::set_slot(&mut hdr, slot, Kind::Passphrase, &word, PBKDF2_ITERATIONS, s, n, &key);
            fs.write_block(hdr_key, &hdr);
            if fs.sync().is_ok() { [0, 0, 0] } else { [5, 0, 0] }
        }
        _ => [5, 0, 0],
    }
}

/// The lock's calls: status, unlock with a passphrase, set a passphrase. The passphrase comes in 16-byte chunks (`proto::volume`).
fn volume_call(vol: &mut Vol, raw: BlkDev, op: u64, m: &Msg, pass: &mut [u8; 128], pass_len: &mut usize) -> [u64; 3] {
    if op == LFS_STATUS {
        return match vol {
            Vol::Plain(_) => [state::PLAIN, 0, 0],
            Vol::Locked { header } => [state::LOCKED, flags_of(header), 0],
            Vol::Open { header, .. } => [state::UNLOCKED, flags_of(header), 0],
            Vol::Damaged => [state::DAMAGED, 0, 0],
        };
    }
    // chunks of a passphrase
    let (total, offset) = (((m.w[0] >> 8) & 0xFFFF) as usize, ((m.w[0] >> 24) & 0xFFFF) as usize);
    let usable = match (op, &*vol) {
        (LFS_UNLOCK, Vol::Locked { .. }) => true,
        (LFS_SET_PASSPHRASE, Vol::Open { .. }) => true,
        _ => false,
    };
    if !usable {
        *pass_len = 0;
        pass.fill(0);
        return [2, 0, 0];
    }
    if offset == 0 {
        *pass_len = 0; // (a new passphrase starts: whatever an earlier, unfinished one left is dropped)
    }
    if total == 0 || total > pass.len() || offset % 16 != 0 || offset >= total || offset != *pass_len {
        *pass_len = 0;
        pass.fill(0);
        return [5, 0, 0];
    }
    let mut chunk = [0u8; 16];
    chunk[..8].copy_from_slice(&m.w[1].to_le_bytes());
    chunk[8..].copy_from_slice(&m.w[2].to_le_bytes());
    let n = (total - offset).min(16);
    pass[offset..offset + n].copy_from_slice(&chunk[..n]);
    *pass_len = offset + n;
    if *pass_len < total {
        return [MORE, 0, 0];
    }
    let word: alloc::vec::Vec<u8> = pass[..total].to_vec();
    pass.fill(0);
    *pass_len = 0;
    let result = if op == LFS_UNLOCK {
        let Vol::Locked { header } = vol else { return [2, 0, 0] };
        match metallium_crypt::unlock(header, metallium_crypt::Kind::Passphrase, &word) {
            Some(key) => {
                let header = core::mem::replace(header, Box::new([0u8; metallium_crypt::HEADER_LEN]));
                *vol = open_encrypted(raw, header, key);
                println!("[lfs] volume unlocked");
                0
            }
            None => 1,
        }
    } else {
        let Vol::Open { header, key, .. } = vol else { return [2, 0, 0] };
        let (mut salt, mut nonce) = ([0u8; 32], [0u8; 12]);
        if !(random_bytes(&mut salt) && random_bytes(&mut nonce)) {
            return [5, 0, 0];
        }
        // the slot that already holds a passphrase, else the first empty one
        let slot = (0..metallium_crypt::SLOTS)
            .find(|&i| metallium_crypt::slot_kind(header, i) == Some(metallium_crypt::Kind::Passphrase))
            .or_else(|| (0..metallium_crypt::SLOTS).find(|&i| metallium_crypt::slot_kind(header, i).is_none()));
        match slot {
            Some(i) => {
                metallium_crypt::set_slot(header, i, metallium_crypt::Kind::Passphrase, &word, PBKDF2_ITERATIONS, salt, nonce, key);
                if raw.write_block(0, header).is_ok() { 0 } else { 5 }
            }
            None => 5,
        }
    };
    [result, 0, 0]
}

// ---------------------------------------------------------------------------
// client-side tests
// ---------------------------------------------------------------------------
const C_ROFS_SHM: usize = 0x8032_0000;
const C_LFS_SHM: usize = 0x8033_0000;

fn cshm(base: usize) -> &'static mut [u8; 4096] {
    // SAFETY: `base` is C_ROFS_SHM or C_LFS_SHM, mapped (checked) at the top of `storage_tests` before any `cshm` call; the server writes the page only while we are blocked in `call`.
    unsafe { &mut *(base as *mut [u8; 4096]) }
}

fn set_path(p: &str) {
    let s = cshm(C_ROFS_SHM);
    s[..p.len()].copy_from_slice(p.as_bytes());
    s[p.len()] = 0;
}

fn rofs_read(path: &str, off: u64, len: u64) -> (i64, u64, u64) {
    set_path(path);
    let (st, r) = call(5, [ROFS_READ, off, len]);
    (if st != 0 { st } else { r[0] as i64 }, r[1], r[2])
}

fn block_pattern(key: u64, out: &mut [u8; 4096]) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = (key * 17 + i as u64) as u8;
    }
}

fn lfs_put(key: u64) -> bool {
    block_pattern(key, cshm(C_LFS_SHM));
    let (st, r) = call(7, [LFS_PUT, key, 0]);
    st == 0 && r[0] == 0
}

fn lfs_get_ok(key: u64) -> bool {
    cshm(C_LFS_SHM).fill(0);
    let (st, r) = call(7, [LFS_GET, key, 0]);
    if st != 0 || r[0] != 0 {
        return false;
    }
    let mut want = [0u8; 4096];
    block_pattern(key, &mut want);
    cshm(C_LFS_SHM)[..] == want[..]
}

pub fn storage_tests() {
    if mem_map(6, C_ROFS_SHM, true) != 0 || mem_map(8, C_LFS_SHM, true) != 0 {
        println!("[client] TEST storage: cannot map server pages: FAIL");
        return;
    }

    // --- EROFS: read-only system image ---
    let (st, n, size) = rofs_read("/hello.txt", 0, 100);
    let want = b"Hello from the Metallium-OS system image!\n";
    let ok = st == 0 && n as usize == want.len() && size == n && &cshm(C_ROFS_SHM)[DATA_OFF..DATA_OFF + want.len()] == want;
    println!("[client] TEST EROFS read /hello.txt ({n} bytes): {}", verdict(ok));

    let mut all_ok = true;
    let mut off = 0u64;
    while off < 9000 {
        let (st, n, size) = rofs_read("/bin/blob.bin", off, 3840);
        let page = cshm(C_ROFS_SHM);
        all_ok &= st == 0 && size == 9000 && n > 0;
        for i in 0..n as usize {
            all_ok &= page[DATA_OFF + i] == (((off as usize + i) * 7) % 251) as u8;
        }
        off += n.max(1);
    }
    println!("[client] TEST EROFS read 9000-byte file across blocks: {}", verdict(all_ok));

    set_path("/");
    let (st, r) = call(5, [ROFS_LIST, 0, 0]);
    let n = r[1] as usize;
    let names = String::from_utf8_lossy(&cshm(C_ROFS_SHM)[DATA_OFF..DATA_OFF + n]).into_owned();
    println!("[client] TEST EROFS list / ({:?}): {}", names.replace('\n', " ").trim_end(),
        verdict(st == 0 && names == "bin/\netc/\nhello.txt\nusr/\n"));
    let (st, _, _) = rofs_read("/no/such/file", 0, 10);
    println!("[client] TEST EROFS missing path rejected (status={st}): {}", verdict(st != 0));

    // --- LFS: random-ish overwrites coalesce into sequential log writes ---
    // The store is shared with the VFS and program, so measure this batch as a delta of the
    // server's cumulative counters.
    let (_, base) = call(7, [LFS_SYNC, 0, 0]);
    let mut ok = true;
    for k in 1..=5 {
        ok &= lfs_put(k);
    }
    for _ in 0..50 {
        ok &= lfs_put(3); // hot block rewritten 50 times before the sync
    }
    let (st, r) = call(7, [LFS_SYNC, 0, 0]);
    let (dev_w, log_w) = (r[1] - base[1], r[2] - base[2]);
    println!("[client] TEST LFS write coalescing ({log_w} logical writes -> {dev_w} device blocks): {}",
        verdict(ok && st == 0 && r[0] == 0 && log_w >= 55 && dev_w * 2 < log_w));

    // --- LFS crash consistency: synced data survives a server crash, unsynced does not ---
    let ok = lfs_put(99); // never synced
    let (st, _) = call(7, [LFS_CRASH, 0, 0]);
    println!("[client] TEST LFS server crash surfaces as error (status={st}, staged={ok}): {}", verdict(ok && st == E_DEAD));
    let synced_ok = (1..=5).all(lfs_get_ok);
    let (st99, r99) = call(7, [LFS_GET, 99, 0]);
    println!("[client] TEST LFS synced blocks survive restart, unsynced block lost: {}",
        verdict(synced_ok && st99 == 0 && r99[0] != 0));

    // --- whole-stack fault: the block driver dies under the LFS server's feet ---
    let mut ok = lfs_put(7);
    let (st, _) = call(3, [BLK_CRASH, 0, 0]); // driver restarts; servers retry transparently
    ok &= st == E_DEAD;
    let (st, r) = call(7, [LFS_SYNC, 0, 0]);
    ok &= st == 0 && r[0] == 0;
    println!("[client] TEST LFS sync across a block-driver crash: {}", verdict(ok && lfs_get_ok(7) && (1..=5).all(lfs_get_ok)));
}
