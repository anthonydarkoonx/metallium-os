//! Virtual file system: one namespace over two userspace filesystems.
//!
//!   /system  -> rofs-server (EROFS, read-only)
//!   /data    -> a small file layer stored on lfs-server blocks (read/write)
//!
//! Applications only hold a capability to this server: they never see the
//! block driver or either filesystem. Requests/data travel through a shared
//! page per client; the kernel-supplied sender id selects the page and the
//! file-descriptor table, so clients cannot touch each other's state.
//!
//! /data layout on the log-structured store: key 0 is the directory table
//! (a flat table of full paths, so directories nest), file data lives at
//! key (inode << 32 | block). Closing a written file commits data *and*
//! directory table in a single LFS checkpoint, so a crash leaves either the
//! old or the new version, never a mix.
use crate::*;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// ---- client <-> VFS protocol ----
const V_OPEN: u64 = 50; // path in page, w1 = flags            -> [0, fd]
const V_READ: u64 = 51; // w1 = fd, w2 = len; data -> page[256..] -> [0, n]
const V_WRITE: u64 = 52; // w1 = fd, w2 = len; data <- page[256..] -> [0, n]
const V_SEEK: u64 = 53; // w1 = fd, w2 = offset
const V_CLOSE: u64 = 54; // w1 = fd (commits written data)
const V_STAT: u64 = 55; // path in page -> [0, size, kind]
const V_LIST: u64 = 56; // path in page -> names '\n'-separated at page[256..] -> [0, bytes]
const V_LOCK: u64 = 69; // w1 = fd, w2 = 1 shared / 2 exclusive / 3 unlock: an advisory lock on the open file; EAGAIN if another open file holds a conflicting one (it never waits)
const V_STAT_TIME: u64 = 68; // path in page, w1 = 1: do not follow a symbolic link in the last component -> [0, size, kind | modification time (seconds since 1970, 0 if not known) << 8]
const V_LSTAT: u64 = 66; // like V_STAT, but a symbolic link is reported as itself: [0, length of its target, 3]
const V_READLINK: u64 = 67; // path in page (the last component not followed) -> the target at page[256..] -> [0, bytes]; EINVAL if it is not a symbolic link
const V_LIST_AT: u64 = 65; // path in page, w1 = entries already received -> the next whole names at page[256..] -> [0, bytes, 1 if more are left]
const V_UNLINK: u64 = 57;
const V_MKDIR: u64 = 58;
const V_SYNC: u64 = 59;
const V_CRASH: u64 = 60; // fault injection for tests
const V_FAIL_SYNC: u64 = 61; // fault injection: the next checkpoint request fails (conductor only)
const V_RENAME: u64 = 63; // "from\0to\0" in page: move a file, or a directory with everything in it, inside /data (one commit)
const V_MKDIR_DOMAIN: u64 = 64; // path in page, w1 = a domain 1..=63: make a directory whose files are sealed under that encryption domain (unconfined callers only)
const V_SCOPE: u64 = 62; // path in page, w1 = a program's task id: confine that program (started by the caller, not yet running) to the directory

// status codes (reply[0])
pub const ENOENT: u64 = 1;
pub const EISDIR: u64 = 2; // wrong kind of object for the operation
pub const EBADF: u64 = 3;
pub const EROFS: u64 = 4;
pub const ENOSPC: u64 = 5;
pub const EINVAL: u64 = 6;
pub const EIO: u64 = 7;
pub const EEXIST: u64 = 8;
pub const ENOTEMPTY: u64 = 9;
pub const EPERM: u64 = 10; // (V_SCOPE: not the program's parent)
pub const ELOOP: u64 = 11; // too many symbolic links (a loop, or a chain longer than 16)
pub const EAGAIN: u64 = 12; // V_LOCK: the file is locked by someone else

/// A scoped program (see `V_SCOPE`) may have at most this many entries (files and directories) under its directory: the data
/// store has few, and one program must not be able to use them all up.
const SCOPE_MAX_ENTRIES: usize = 12;

/// A confined program's scope: the generation of its session, the directory it is confined to, and the quotas that bind it (that directory's, and those of every directory
/// above it that has one: a home's quota covers everything the programs under it make).
type Scope = (u64, String, Vec<(String, usize)>);

/// Would one more entry exceed a quota of the chain?
fn over_quota(ds: &Datafs, quotas: &[(String, usize)]) -> bool {
    quotas.iter().any(|(dir, limit)| scope_entries(ds, dir) >= *limit)
}

pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;

/// Largest file the data store accepts. (An offset near 2^40 would alias another inode's block keys,
/// and truncating such a file would loop for ever.) The store itself is only a few MiB.
const MAX_FILE: u64 = 16 << 20;
const DATA: usize = 256;
const MAXIO: usize = 4096 - DATA;
const BS: usize = 4096;

// ---- backend protocols (see storage.rs) ----
const ROFS_READ: u64 = 30;
const ROFS_LIST: u64 = 31;
const ROFS_READLINK: u64 = 33;
const ROFS_LSTAT: u64 = 34;
const ROFS_STAT: u64 = 32;
const LFS_PUT: u64 = 40;
const LFS_GET: u64 = 41;
const LFS_SYNC: u64 = 42;
const LFS_DEL: u64 = 44;
const LFS_EPOCH: u64 = 47;

// ---- server memory map & capability slots (kernel policy, see task.rs) ----
const SL_ROFS_EP: u64 = 1;
const SL_ROFS_SHM: u64 = 2;
const SL_LFS_EP: u64 = 3;
const SL_LFS_SHM: u64 = 4;
const VA_ROFS: usize = 0x8024_0000;
const VA_LFS: usize = 0x8025_0000;
const VA_CLIENT0: usize = 0x8026_0000; // sender 0: test conductor
const VA_CLIENT8: usize = 0x8027_0000; // sender 8: application
const VA_SHELL: usize = 0x8028_0000; // sender SHELL_SENDER: the shell
/// Pages for programs with file-system access: session k of the kernel's pool is VFS capability slot 16 + k.
const VA_PROG0: usize = 0x8029_0000;
static PROG_SESSIONS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static SHELL_TASK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(20);

/// The console's task id (the one task of role 13; 20 on the QEMU machine, earlier where there is no display or keyboard
/// driver before it): looked up when the server starts.
fn find_shell() {
    for t in 0..64u64 {
        let r = sysinfo_at(3, t);
        if r[0] as i64 == 0 && r[3] != 0 && r[5] == 13 {
            SHELL_TASK.store(t, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// A session page shared with another task (a client, or a backend). The peer writes it at any time it runs, so the page is never
/// turned into a Rust reference: everything goes through copies in and out (`put`, `get`, `vec`, `snap`), each a bounded raw copy.
#[derive(Clone, Copy)]
struct Pg(usize);

fn page(va: usize) -> Pg {
    Pg(va)
}

impl Pg {
    /// Copy `src` into the page at `off`.
    fn put(self, off: usize, src: &[u8]) {
        assert!(off <= BS && src.len() <= BS - off);
        // SAFETY: callers pass the address of a page `vfs_server` mapped (VA_ROFS, VA_LFS, the client sessions) or a client's own
        // mapped session page of `BS` bytes; the range is inside it (asserted); `src` is a local slice, never inside the page.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (self.0 as *mut u8).add(off), src.len()) }
    }

    /// Copy page bytes at `off` into `dst`.
    fn get(self, off: usize, dst: &mut [u8]) {
        assert!(off <= BS && dst.len() <= BS - off);
        // SAFETY: as `put`; `dst` is a local slice.
        unsafe { core::ptr::copy_nonoverlapping((self.0 as *const u8).add(off), dst.as_mut_ptr(), dst.len()) }
    }

    fn vec(self, off: usize, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.get(off, &mut v);
        v
    }

    /// Set the bytes from `from` to the end of the page to `byte`.
    fn fill_from(self, from: usize, byte: u8) {
        assert!(from <= BS);
        // SAFETY: as `put`: `from..BS` is inside the page.
        unsafe { core::ptr::write_bytes((self.0 as *mut u8).add(from), byte, BS - from) }
    }

    fn snap<const N: usize>(self, off: usize) -> [u8; N] {
        let mut a = [0u8; N];
        self.get(off, &mut a);
        a
    }
}

/// Backends restart on crash and every request is idempotent, so retry on E_DEAD.
fn backend(ep: u64, w: [u64; 3]) -> Option<[u64; 3]> {
    for _ in 0..6 {
        let (st, r) = call(ep, w);
        if st == E_DEAD {
            sleep(2);
            continue;
        }
        return if st == 0 { Some(r) } else { None };
    }
    None
}

// ---------------------------------------------------------------------------
// path handling
// ---------------------------------------------------------------------------
fn norm(p: &str) -> Option<String> {
    if !p.starts_with('/') {
        return None;
    }
    let mut out = String::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => return None,
            _ => {
                out.push('/');
                out.push_str(c);
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    (out.len() < PATH_MAX).then_some(out)
}

enum Route {
    Root,
    Rofs(String),
    Data(String),
}

fn route(p: &str) -> Option<Route> {
    if p == "/" {
        return Some(Route::Root);
    }
    for (prefix, mk) in [("/system", true), ("/data", false)] {
        if p == prefix || p.strip_prefix(prefix).map_or(false, |r| r.starts_with('/')) {
            let rest = &p[prefix.len()..];
            let rest = if rest.is_empty() { String::from("/") } else { String::from(rest) };
            return Some(if mk { Route::Rofs(rest) } else { Route::Data(rest) });
        }
    }
    None
}

/// The route of a path as a program confined to `scope` sees it: `/data/...` is `scope/...` (the program cannot name anything outside:
/// `..` is refused by `norm`, and the rewrite happens after it), `/system` and `/` are as for everyone. None if the result would
/// not fit a directory entry.
fn route_scoped(p: &str, scope: Option<&str>) -> Option<Route> {
    match (route(p)?, scope) {
        (Route::Data(rest), Some(sc)) => {
            let full = if rest == "/" { String::from(sc) } else { alloc::format!("{sc}{rest}") };
            (full.len() < PATH_MAX).then_some(Route::Data(full))
        }
        (r, _) => Some(r),
    }
}

/// Entries under a scope (what the quota counts).
fn scope_entries(ds: &Datafs, sc: &str) -> usize {
    let prefix = alloc::format!("{sc}/");
    ds.ents.iter().filter(|e| e.ino != 0 && e.path().starts_with(prefix.as_str())).count()
}

// ---------------------------------------------------------------------------
// /system backend calls
// ---------------------------------------------------------------------------
fn rofs_path(p: &str) {
    let pg = page(va(VA_ROFS));
    pg.put(0, p.as_bytes());
    pg.put(p.len(), &[0]);
}

/// The VFS status for the status the system-partition server answered with.
fn rofs_status(code: u64) -> u64 {
    match code {
        1 => ENOENT,
        2 | 3 => EISDIR,
        6 => EINVAL,
        11 => ELOOP,
        _ => EIO,
    }
}

fn rofs_stat(p: &str) -> Result<(u64, u64), u64> {
    rofs_path(p);
    let r = backend(SL_ROFS_EP, [ROFS_STAT, 0, 0]).ok_or(EIO)?;
    if r[0] == 0 { Ok((r[2], r[1])) } else { Err(rofs_status(r[0])) }
}

fn rofs_lstat(p: &str) -> Result<(u64, u64), u64> {
    rofs_path(p);
    let r = backend(SL_ROFS_EP, [ROFS_LSTAT, 0, 0]).ok_or(EIO)?;
    if r[0] == 0 { Ok((r[2], r[1])) } else { Err(rofs_status(r[0])) }
}

fn rofs_readlink(p: &str) -> Result<Vec<u8>, u64> {
    rofs_path(p);
    let r = backend(SL_ROFS_EP, [ROFS_READLINK, 0, 0]).ok_or(EIO)?;
    if r[0] == 0 { Ok(page(va(VA_ROFS)).vec(DATA, r[1] as usize)) } else { Err(rofs_status(r[0])) }
}

fn rofs_read(p: &str, off: u64, out: &mut [u8]) -> Result<usize, u64> {
    rofs_path(p);
    let r = backend(SL_ROFS_EP, [ROFS_READ, off, out.len() as u64]).ok_or(EIO)?;
    match r[0] {
        0 => {
            let n = r[1] as usize;
            page(va(VA_ROFS)).get(DATA, &mut out[..n]);
            Ok(n)
        }
        1 => Err(ENOENT),
        3 => Err(EISDIR),
        11 => Err(ELOOP),
        _ => Err(EIO),
    }
}

fn rofs_list(p: &str) -> Result<Vec<u8>, u64> {
    rofs_list_at(p, 0).map(|(v, _)| v)
}

/// The names of `/system` directory `p` after the first `cursor`, as many whole ones as fit a page, and whether there are more.
fn rofs_list_at(p: &str, cursor: u64) -> Result<(Vec<u8>, bool), u64> {
    rofs_path(p);
    let r = backend(SL_ROFS_EP, [ROFS_LIST, cursor, 0]).ok_or(EIO)?;
    match r[0] {
        0 => Ok((page(va(VA_ROFS)).vec(DATA, r[1] as usize), r[2] != 0)),
        1 => Err(ENOENT),
        11 => Err(ELOOP),
        _ => Err(EISDIR),
    }
}

/// The lines of the '\n'-separated listing `v` after the first `cursor`, as many whole ones as fit a page, and whether there are more.
fn lines_from(v: &[u8], cursor: usize) -> (Vec<u8>, bool) {
    let mut at = 0;
    for _ in 0..cursor {
        match v[at..].iter().position(|&c| c == b'\n') {
            Some(i) => at += i + 1,
            None => return (Vec::new(), false),
        }
    }
    let mut end = at;
    while end < v.len() {
        let line = v[end..].iter().position(|&c| c == b'\n').map_or(v.len() - end, |i| i + 1);
        if end + line - at > MAXIO {
            return (v[at..end].to_vec(), true);
        }
        end += line;
    }
    (v[at..end].to_vec(), false)
}

// ---------------------------------------------------------------------------
// /data file layer over LFS blocks
// ---------------------------------------------------------------------------
const META_KEY: u64 = 0;
/// The block listing the in-place update sessions that have not committed yet (see `Session`).
const JOURNAL_KEY: u64 = 1;
const JOURNAL_MAGIC: u32 = 0x4C4E_4A56; // "VJNL"
/// "VFS3": the directory table spans several blocks (up to `NENT` entries, paths of up to `PATH_MAX` bytes). "VFS2" (inode numbers in pairs, see `Shadow`;
/// one block, `OLD_NENT` entries of `OLD_ENT_SZ` bytes with 64-byte paths) is still read, and the next commit writes the new layout; a table older than that is not read.
const MAGIC: u32 = 0x3353_4656;
const MAGIC_V2: u32 = 0x3253_4656;
const OLD_NENT: usize = 51;
const OLD_ENT_SZ: usize = 80;
/// An inode number: bit 31 marks an undo block's key, bit 30 is the store's (twin blocks), bits 24..29 are the file's encryption domain (0: the system's), bits 0..23 count.
const DOMAIN_SHIFT: u32 = 24;
const INO_COUNTER_MAX: u32 = (1 << 24) - 16;
fn domain_of_ino(ino: u32) -> u32 {
    (ino >> DOMAIN_SHIFT) & 0x3F
}
/// Entries (files and directories) in `/data`, for the whole machine. A table written with fewer reads as it was (the blocks it never wrote are free entries), so raising this
/// changes nothing on a disk that is already in use. The entries are searched one after the other, so a lookup costs time in proportion.
const NENT: usize = 4096;
const PATH_MAX: usize = 128;
const ENT_SZ: usize = 144;
/// Entries per metadata block (the first 16 bytes of each block are its header) and the blocks the table takes. Block 0 is `META_KEY`, block b is `META_MORE + b`.
const EPB: usize = (BS - 16) / ENT_SZ;
const META_BLOCKS: usize = NENT.div_ceil(EPB);
const META_MORE: u64 = 0x1000;
/// The modification times: one block, a `u32` (seconds since 1970; 0 = not known) for each table slot, written in the same checkpoint as the table so that the two are
/// never out of step. A table from before there was one has none: every time reads 0 until the file is next written.
const META_TIMES: u64 = 0x3000;
/// Times in a block (a `u32` each) and the blocks they take: block `b` is key `META_TIMES + b` and holds the times of entries `b * TPB ..`.
const TPB: usize = BS / 4;
const TIME_BLOCKS: usize = NENT.div_ceil(TPB);

/// The wall clock in seconds since 1970, 0 if the machine has none (`CLOCK` answers `E_NOSYS`).
fn now_secs() -> u32 {
    let r = svc(34, 1, 0, 0, 0, 0)[0] as i64;
    if r < 0 { 0 } else { (r as u64 / 1_000_000_000) as u32 }
}
/// The journal is spread the same way: 16 bytes per entry, block b at `JOURNAL_MORE + b` (block 0 is `JOURNAL_KEY`).
const JEPB: usize = (BS - 16) / 16;
const JOURNAL_BLOCKS: usize = NENT.div_ceil(JEPB);
const JOURNAL_MORE: u64 = 0x2000;
const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;

#[derive(Clone, Copy)]
struct Ent {
    path: [u8; PATH_MAX],
    ino: u32, // 0 = free slot
    kind: u8,
    size: u64,
}

impl Ent {
    const FREE: Ent = Ent { path: [0; PATH_MAX], ino: 0, kind: 0, size: 0 };
    fn path(&self) -> &str {
        let n = self.path.iter().position(|&c| c == 0).unwrap_or(PATH_MAX);
        core::str::from_utf8(&self.path[..n]).unwrap_or("")
    }
}

/// The epoch of the store instance that answered last (see `LFS_EPOCH` in storage.rs). 0 = none yet.
static LAST_EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn note_epoch(r: [u64; 3]) -> [u64; 3] {
    LAST_EPOCH.store(r[1], core::sync::atomic::Ordering::Relaxed);
    r
}

fn last_epoch() -> u64 {
    LAST_EPOCH.load(core::sync::atomic::Ordering::Relaxed)
}

/// Ask the store which instance it is. A different answer than before means it restarted since, and lost every
/// block that had been staged but not synced.
fn lfs_epoch() -> Result<u64, u64> {
    backend(SL_LFS_EP, [LFS_EPOCH, 0, 0]).map(note_epoch).map(|r| r[1]).ok_or(EIO)
}

/// Ok(true): the block is in the page; Ok(false): the store has no such block (a hole). Any other answer is an
/// error: taking a failed read for a hole would hand zeros to the reader.
fn lfs_get(key: u64) -> Result<bool, u64> {
    match note_epoch(backend(SL_LFS_EP, [LFS_GET, key, 0]).ok_or(EIO)?)[0] {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(EIO),
    }
}
fn lfs_put(key: u64) -> Result<(), u64> {
    match backend(SL_LFS_EP, [LFS_PUT, key, 0]).map(note_epoch) {
        Some(r) if r[0] == 0 => Ok(()),
        _ => Err(EIO),
    }
}
fn lfs_del(key: u64) -> Result<(), u64> {
    backend(SL_LFS_EP, [LFS_DEL, key, 0]).map(note_epoch).map(|_| ()).ok_or(EIO)
}
/// Test hook: make the next `lfs_sync` report an I/O error without asking the store.
static FAIL_NEXT_SYNC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Make everything staged so far durable, provided it was all staged with the store instance that answered last
/// (the one that took the puts just before this call): if that instance has gone, the sync is refused.
fn lfs_sync() -> Result<(), u64> {
    if FAIL_NEXT_SYNC.swap(false, core::sync::atomic::Ordering::Relaxed) {
        return Err(EIO);
    }
    match backend(SL_LFS_EP, [LFS_SYNC, 0, last_epoch()]) {
        Some(r) if r[0] == 0 => Ok(()),
        _ => Err(EIO),
    }
}

/// The uncommitted new version of a file that a writer is *replacing* (opened with O_TRUNC). Every file
/// owns a *pair* of inode numbers
/// (`ino` and `ino ^ 1`): the directory table points at one, and a writer builds the next version in the
/// other. Readers keep seeing the committed version; the close that flips the table (one checkpoint)
/// is the commit. A writer that dies midway leaves blocks nothing refers to, never a half-written file.
#[derive(Clone, Copy)]
struct Shadow {
    ino: u32,
    size: u64,
    /// The store instance this writer's blocks were staged with: if the store has restarted by the time the
    /// writer closes, the blocks are gone and the commit must fail (see `LFS_EPOCH`).
    epoch: u64,
}

/// An in-place update in progress (a writer opened *without* O_TRUNC). The new bytes go straight into the
/// file's own blocks, so before a block is first overwritten its old content is copied to an *undo* block.
/// The session's record (inode, generation, size before) is kept in the journal block, and every checkpoint
/// writes the journal together with the data it covers, so whichever checkpoint a crash finds, it also finds
/// what is needed to take the file back to its size and content before the session. Closing the writer ends
/// the session in one checkpoint (journal entry removed, new size committed). A session that never closes is
/// rolled back: at restart, or when the next writer opens the file. The result is that an in-place update
/// either happens completely or not at all, at a cost of one extra copy per block touched.
struct Session {
    /// Distinguishes this session's undo blocks from leftovers of earlier ones (see `undo_key`).
    gen: u32,
    old_size: u64,
    /// The store instance holding the journal entry and the undo blocks (see `Shadow::epoch`).
    epoch: u64,
    /// Blocks of the old file already copied to undo blocks, one bit each.
    logged: Vec<u64>,
}

fn key(ino: u32, blk: u64) -> u64 {
    (ino as u64) << 32 | blk
}

/// Undo blocks live in a key space of their own: inode numbers have their top bit set (real ones never do:
/// `create` stops before) and the session generation sits above the block number.
fn undo_key(ino: u32, gen: u32, blk: u64) -> u64 {
    key(ino | 0x8000_0000, (gen as u64 & 0xFFFF) << 16 | blk)
}

struct Datafs {
    next_ino: u32,
    ents: Vec<Ent>,
    dirty: bool,
    /// The uncommitted next version of each entry, if a writer has one (memory only: lost with the VFS).
    shadow: Vec<Option<Shadow>>,
    /// Bumped whenever a writer opens: an older writer's descriptor stops working, so a client that
    /// died holding a file open can never wedge it.
    wgen: Vec<u32>,
    /// The in-place update in progress for each entry, if any (also recorded in the journal block).
    session: Vec<Option<Session>>,
    next_gen: u32,
    /// The journal block has to be rewritten at the next flush.
    jdirty: bool,
    /// What each metadata block held when it was last read or written (a hash of its bytes; 0: never written): a commit writes only the blocks that changed.
    meta_hash: Vec<u64>,
    /// The same for the journal blocks after the first (0: empty and never written).
    jhash: Vec<u64>,
    /// Modification time of each entry (see `META_TIMES`), and a hash of each block of them as last read or written (0: never written).
    times: Vec<u32>,
    times_hash: Vec<u64>,
}

fn fnv(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h = (h ^ x as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h | 1 // (never 0: 0 means "not written")
}

impl Datafs {
    fn load() -> Datafs {
        let mut d = Datafs {
            next_ino: 2,
            ents: vec![Ent::FREE; NENT],
            dirty: false,
            shadow: vec![None; NENT],
            wgen: vec![0; NENT],
            session: (0..NENT).map(|_| None).collect(),
            next_gen: 1,
            jdirty: false,
            meta_hash: vec![0; META_BLOCKS],
            jhash: vec![0; JOURNAL_BLOCKS],
            times: vec![0; NENT],
            times_hash: vec![0; TIME_BLOCKS],
        };
        match lfs_get(META_KEY) {
            Ok(true) => {
                let copy = page(va(VA_LFS)).vec(0, BS); // (parse a private copy)
                let pg = &copy[..];
                let magic = u32::from_le_bytes(pg[0..4].try_into().unwrap());
                if magic == MAGIC_V2 {
                    // the older table: one block, 51 entries with 64-byte paths; the next commit writes the new layout
                    d.next_ino = u32::from_le_bytes(pg[4..8].try_into().unwrap());
                    d.next_gen = u32::from_le_bytes(pg[8..12].try_into().unwrap()).max(1);
                    for (i, e) in d.ents.iter_mut().enumerate().take(OLD_NENT) {
                        let b = &pg[16 + i * OLD_ENT_SZ..16 + (i + 1) * OLD_ENT_SZ];
                        e.path[..64].copy_from_slice(&b[..64]);
                        e.ino = u32::from_le_bytes(b[64..68].try_into().unwrap());
                        e.kind = b[68];
                        e.size = u64::from_le_bytes(b[72..80].try_into().unwrap());
                    }
                } else if magic == MAGIC {
                    d.next_ino = u32::from_le_bytes(pg[4..8].try_into().unwrap());
                    d.next_gen = u32::from_le_bytes(pg[8..12].try_into().unwrap()).max(1);
                    d.parse_meta(0, pg);
                    for b in 1..META_BLOCKS {
                        match lfs_get(META_MORE + b as u64) {
                            Ok(true) => {
                                let more = page(va(VA_LFS)).vec(0, BS);
                                d.parse_meta(b, &more[..]);
                            }
                            Ok(false) => {} // (never written: all of its entries are free)
                            Err(_) => {
                                println!("[vfs] cannot read /data metadata; refusing to start");
                                exit(1)
                            }
                        }
                    }
                    // what is on the disk now, so that a commit rewrites only what changes
                    for b in 0..META_BLOCKS {
                        if b == 0 || d.meta_present(b) {
                            d.meta_hash[b] = fnv(&d.meta_block(b));
                        }
                    }
                    for b in 0..TIME_BLOCKS {
                        match lfs_get(META_TIMES + b as u64) {
                            Ok(true) => {
                                let blk = page(va(VA_LFS)).vec(0, BS);
                                for k in 0..TPB.min(NENT - b * TPB) {
                                    d.times[b * TPB + k] = u32::from_le_bytes(blk[k * 4..k * 4 + 4].try_into().unwrap());
                                }
                                d.times_hash[b] = fnv(&blk);
                            }
                            Ok(false) => {} // (never written: all unknown)
                            Err(_) => {
                                println!("[vfs] cannot read /data metadata; refusing to start");
                                exit(1)
                            }
                        }
                    }
                }
            }
            Ok(false) => {}
            Err(_) => {
                // Starting "empty" here would overwrite real data at the next flush.
                println!("[vfs] cannot read /data metadata; refusing to start");
                exit(1)
            }
        }
        d.recover();
        d
    }

    /// Entries `b * EPB ..` from the bytes of metadata block `b`.
    fn parse_meta(&mut self, b: usize, pg: &[u8]) {
        for k in 0..EPB {
            let i = b * EPB + k;
            if i >= NENT {
                break;
            }
            let r = &pg[16 + k * ENT_SZ..16 + (k + 1) * ENT_SZ];
            let e = &mut self.ents[i];
            e.path.copy_from_slice(&r[..PATH_MAX]);
            e.ino = u32::from_le_bytes(r[PATH_MAX..PATH_MAX + 4].try_into().unwrap());
            e.kind = r[PATH_MAX + 4];
            e.size = u64::from_le_bytes(r[PATH_MAX + 8..PATH_MAX + 16].try_into().unwrap());
        }
    }

    /// Does metadata block `b` hold any entry in use?
    fn meta_present(&self, b: usize) -> bool {
        self.ents[b * EPB..((b + 1) * EPB).min(NENT)].iter().any(|e| e.ino != 0)
    }

    /// The bytes of metadata block `b` (block 0 also carries the counters).
    fn meta_block(&self, b: usize) -> Vec<u8> {
        let mut pg = vec![0u8; BS];
        if b == 0 {
            pg[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            pg[4..8].copy_from_slice(&self.next_ino.to_le_bytes());
            pg[8..12].copy_from_slice(&self.next_gen.to_le_bytes());
        } else {
            pg[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        }
        for k in 0..EPB {
            let i = b * EPB + k;
            if i >= NENT {
                break;
            }
            let e = &self.ents[i];
            let r = &mut pg[16 + k * ENT_SZ..16 + (k + 1) * ENT_SZ];
            r[..PATH_MAX].copy_from_slice(&e.path);
            r[PATH_MAX..PATH_MAX + 4].copy_from_slice(&e.ino.to_le_bytes());
            r[PATH_MAX + 4] = e.kind;
            r[PATH_MAX + 8..PATH_MAX + 16].copy_from_slice(&e.size.to_le_bytes());
        }
        pg
    }

    /// The bytes of journal block `b`: the in-place update sessions of entries `b * JEPB ..`.
    fn journal_block(&self, b: usize) -> Vec<u8> {
        let mut pg = vec![0u8; BS];
        pg[0..4].copy_from_slice(&JOURNAL_MAGIC.to_le_bytes());
        for k in 0..JEPB {
            let i = b * JEPB + k;
            if i >= NENT {
                break;
            }
            if let Some(s) = &self.session[i] {
                let r = &mut pg[16 + k * 16..32 + k * 16];
                r[0..4].copy_from_slice(&self.ents[i].ino.to_le_bytes());
                r[4..8].copy_from_slice(&s.gen.to_le_bytes());
                r[8..16].copy_from_slice(&s.old_size.to_le_bytes());
            }
        }
        pg
    }

    /// Roll back every in-place update that was in progress when the previous VFS died or the power failed.
    fn recover(&mut self) {
        match lfs_get(JOURNAL_KEY) {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => {
                println!("[vfs] cannot read the /data journal; refusing to start");
                exit(1)
            }
        }
        let copy = page(va(VA_LFS)).vec(0, BS); // (parse a private copy)
        if u32::from_le_bytes(copy[0..4].try_into().unwrap()) != JOURNAL_MAGIC {
            return;
        }
        let mut found = vec![(0u32, 0u32, 0u64); NENT];
        let mut fill = |blk: &[u8], b: usize, found: &mut Vec<(u32, u32, u64)>| {
            for k in 0..JEPB {
                let i = b * JEPB + k;
                if i >= NENT {
                    break;
                }
                let r = &blk[16 + k * 16..32 + k * 16];
                found[i] = (u32::from_le_bytes(r[0..4].try_into().unwrap()), u32::from_le_bytes(r[4..8].try_into().unwrap()), u64::from_le_bytes(r[8..16].try_into().unwrap()));
            }
        };
        fill(&copy[..], 0, &mut found);
        for b in 1..JOURNAL_BLOCKS {
            match lfs_get(JOURNAL_MORE + b as u64) {
                Ok(true) => {
                    let more = page(va(VA_LFS)).vec(0, BS);
                    if u32::from_le_bytes(more[0..4].try_into().unwrap()) == JOURNAL_MAGIC {
                        fill(&more[..], b, &mut found);
                        self.jhash[b] = 1; // (written once: the next commit rewrites it, empty if the rollback cleared it)
                    }
                }
                Ok(false) => {}
                Err(_) => {
                    println!("[vfs] cannot read the /data journal; refusing to start");
                    exit(1)
                }
            }
        }
        let mut rolled = 0;
        let mut garbage = Vec::new();
        for (i, &(ino, gen, old_size)) in found.iter().enumerate() {
            if ino == 0 {
                continue;
            }
            if self.ents[i].ino == ino {
                let cur = self.ents[i].size;
                if Self::restore(ino, gen, old_size, cur).is_err() {
                    println!("[vfs] cannot roll back an unfinished update; refusing to start");
                    exit(1)
                }
                self.ents[i].size = old_size;
                rolled += 1;
            }
            garbage.push((undo_key(ino, gen, 0), Self::blocks(old_size)));
        }
        self.jdirty = true;
        self.dirty = true;
        if self.flush().is_err() {
            println!("[vfs] cannot commit the rollback; refusing to start");
            exit(1)
        }
        Self::reap(&garbage);
        println!("[vfs] rolled back {rolled} unfinished in-place update(s)");
    }

    /// Put the file `ino` back as it was before the session `gen`: restore the blocks that were logged, and drop
    /// the blocks the session added past the old end. (Staged only: the caller commits.)
    fn restore(ino: u32, gen: u32, old_size: u64, cur_size: u64) -> Result<(), u64> {
        for b in 0..Self::blocks(old_size) {
            if lfs_get(undo_key(ino, gen, b))? {
                lfs_put(key(ino, b))?; // the page now holds the old content
            }
        }
        for b in Self::blocks(old_size)..Self::blocks(cur_size.max(old_size)) {
            lfs_del(key(ino, b))?;
        }
        Ok(())
    }

    /// Persist directory table and make everything written so far durable.
    fn flush(&mut self) -> Result<(), u64> {
        // the metadata blocks that changed since they were last read or written (block 0 always: it has the counters); one that was never written and holds nothing is skipped
        let mut hashes = self.meta_hash.clone();
        for b in 0..META_BLOCKS {
            let blk = self.meta_block(b);
            let h = fnv(&blk);
            if h == self.meta_hash[b] || (b != 0 && self.meta_hash[b] == 0 && !self.meta_present(b)) {
                continue;
            }
            page(va(VA_LFS)).put(0, &blk);
            lfs_put(if b == 0 { META_KEY } else { META_MORE + b as u64 })?;
            hashes[b] = h;
        }
        // the times, in the same checkpoint: the blocks that changed (one that was never written and holds no time is skipped)
        let mut times_hash = self.times_hash.clone();
        for b in 0..TIME_BLOCKS {
            let tblk = self.times_block(b);
            let th = fnv(&tblk);
            if th != self.times_hash[b] && (self.times_hash[b] != 0 || self.times[b * TPB..((b + 1) * TPB).min(NENT)].iter().any(|&t| t != 0)) {
                page(va(VA_LFS)).put(0, &tblk);
                lfs_put(META_TIMES + b as u64)?;
                times_hash[b] = th;
            }
        }
        let mut jhashes = self.jhash.clone();
        if self.jdirty {
            for b in 0..JOURNAL_BLOCKS {
                let blk = self.journal_block(b);
                let used = self.session[b * JEPB..((b + 1) * JEPB).min(NENT)].iter().any(|s| s.is_some());
                if b != 0 && !used && self.jhash[b] == 0 {
                    continue; // never written and nothing to write
                }
                page(va(VA_LFS)).put(0, &blk);
                lfs_put(if b == 0 { JOURNAL_KEY } else { JOURNAL_MORE + b as u64 })?;
                jhashes[b] = if used { fnv(&blk) } else { 0 };
            }
        }
        lfs_sync()?;
        self.meta_hash = hashes;
        self.jhash = jhashes;
        self.times_hash = times_hash;
        self.dirty = false;
        self.jdirty = false;
        Ok(())
    }

    fn find(&self, p: &str) -> Option<usize> {
        self.ents.iter().position(|e| e.ino != 0 && e.path() == p)
    }

    /// Block `b` of modification times (see `META_TIMES`).
    fn times_block(&self, b: usize) -> [u8; BS] {
        let mut blk = [0u8; BS];
        for (k, t) in self.times[b * TPB..((b + 1) * TPB).min(NENT)].iter().enumerate() {
            blk[k * 4..k * 4 + 4].copy_from_slice(&t.to_le_bytes());
        }
        blk
    }

    /// Entry `slot` was changed now; the table is committed with the next flush.
    fn touch(&mut self, slot: usize) {
        self.times[slot] = now_secs();
        self.dirty = true;
    }

    /// The directory that contains `p` had an entry made or removed (the top directory has no entry of its own).
    fn touch_parent(&mut self, p: &str) {
        if let Some(i) = p.rfind('/').filter(|&i| i > 0) {
            if let Some(s) = self.find(&p[..i]) {
                self.touch(s);
            }
        }
    }

    fn parent_is_dir(&self, p: &str) -> bool {
        match p.rfind('/') {
            Some(0) => true,
            Some(i) => self.find(&p[..i]).map_or(false, |x| self.ents[x].kind == KIND_DIR),
            None => false,
        }
    }

    /// The encryption domain of the directory `p` is in (0 for the top level).
    fn parent_domain(&self, p: &str) -> u32 {
        match p.rfind('/') {
            Some(i) if i > 0 => self.find(&p[..i]).map_or(0, |x| domain_of_ino(self.ents[x].ino)),
            _ => 0,
        }
    }

    fn create(&mut self, p: &str, kind: u8) -> Result<usize, u64> {
        let dom = self.parent_domain(p);
        self.create_in(p, kind, dom)
    }

    /// Make an entry whose inode carries encryption domain `dom` (a file takes its directory's; `V_MKDIR_DOMAIN` starts a new one).
    fn create_in(&mut self, p: &str, kind: u8, dom: u32) -> Result<usize, u64> {
        if self.find(p).is_some() {
            return Err(EEXIST);
        }
        if !self.parent_is_dir(p) {
            return Err(ENOENT);
        }
        let slot = self.ents.iter().position(|e| e.ino == 0).ok_or(ENOSPC)?;
        if self.next_ino >= INO_COUNTER_MAX || dom > 0x3F {
            return Err(ENOSPC); // inode numbers must stay below the undo and twin key space (see `undo_key`)
        }
        let mut e = Ent::FREE;
        e.path[..p.len()].copy_from_slice(p.as_bytes());
        e.ino = dom << DOMAIN_SHIFT | self.next_ino;
        e.kind = kind;
        self.next_ino += 2; // a pair: the file's current and its shadow inode
        self.ents[slot] = e;
        self.touch(slot);
        self.touch_parent(p);
        Ok(slot)
    }

    fn blocks(size: u64) -> u64 {
        size.div_ceil(BS as u64)
    }

    /// A writer opens `slot`. It supersedes any earlier writer, and an in-place update the earlier writer left
    /// unfinished is rolled back first. A *replacing* writer (`truncate`) builds its version in the shadow
    /// inode and commits it atomically at close; any other writer updates the file in place under an undo
    /// session (see `Session`), which is started by its first write.
    fn open_writer(&mut self, slot: usize, truncate: bool) -> Result<u32, u64> {
        self.abandon_session(slot)?;
        let epoch = if truncate { lfs_epoch()? } else { 0 };
        self.wgen[slot] = self.wgen[slot].wrapping_add(1);
        self.shadow[slot] = truncate.then(|| Shadow { ino: self.ents[slot].ino ^ 1, size: 0, epoch });
        Ok(self.wgen[slot])
    }

    /// Undo and end the in-place update in progress on `slot`, if any.
    fn abandon_session(&mut self, slot: usize) -> Result<(), u64> {
        let Some(s) = self.session[slot].take() else { return Ok(()) };
        let (ino, cur) = (self.ents[slot].ino, self.ents[slot].size);
        if let Err(e) = Self::restore(ino, s.gen, s.old_size, cur) {
            self.session[slot] = Some(s);
            return Err(e);
        }
        self.ents[slot].size = s.old_size;
        self.jdirty = true;
        self.dirty = true;
        if let Err(e) = self.flush() {
            self.ents[slot].size = cur;
            self.session[slot] = Some(s);
            return Err(e);
        }
        Self::reap(&[(undo_key(ino, s.gen, 0), Self::blocks(s.old_size))]);
        Ok(())
    }

    /// Start an in-place update session on `slot` and make its journal entry durable before any block of the
    /// file is touched.
    fn begin_session(&mut self, slot: usize) -> Result<(), u64> {
        let old_size = self.ents[slot].size;
        self.session[slot] = Some(Session { gen: self.next_gen, old_size, epoch: 0, logged: vec![0; Self::blocks(old_size).div_ceil(64) as usize] });
        self.next_gen = self.next_gen.wrapping_add(1).max(1);
        self.jdirty = true;
        self.dirty = true;
        if let Err(e) = self.flush() {
            self.session[slot] = None;
            return Err(e);
        }
        if let Some(s) = self.session[slot].as_mut() {
            s.epoch = last_epoch(); // the instance that just made the journal entry durable
        }
        Ok(())
    }

    /// Before block `blk` of the file is overwritten in place, keep its old content (once per session).
    fn log_block(&mut self, slot: usize, blk: u64) -> Result<(), u64> {
        let ino = self.ents[slot].ino;
        let Some(s) = self.session[slot].as_mut() else { return Ok(()) };
        if blk >= Self::blocks(s.old_size) || s.logged[(blk / 64) as usize] >> (blk % 64) & 1 == 1 {
            return Ok(()); // beyond the old end (rollback drops it), or saved already
        }
        if !lfs_get(key(ino, blk))? {
            page(va(VA_LFS)).fill_from(0, 0); // a hole reads as zeros
        }
        lfs_put(undo_key(ino, s.gen, blk))?;
        s.logged[(blk / 64) as usize] |= 1 << (blk % 64);
        Ok(())
    }

    /// Where the next write goes: (inode, current size). The shadow if there is one, else the file itself.
    fn target(&self, slot: usize) -> (u32, u64) {
        match self.shadow[slot] {
            Some(sh) => (sh.ino, sh.size),
            None => (self.ents[slot].ino, self.ents[slot].size),
        }
    }

    fn read_blocks(ino: u32, size: u64, off: u64, out: &mut [u8]) -> Result<usize, u64> {
        if off >= size {
            return Ok(0);
        }
        let total = out.len().min((size - off) as usize);
        let mut done = 0;
        while done < total {
            let pos = off + done as u64;
            let (blk, inb) = (pos / BS as u64, (pos % BS as u64) as usize);
            let n = (total - done).min(BS - inb);
            if lfs_get(key(ino, blk))? {
                page(va(VA_LFS)).get(inb, &mut out[done..done + n]);
            } else {
                out[done..done + n].fill(0); // hole
            }
            done += n;
        }
        Ok(total)
    }

    /// Read from the committed version, or (`writer`) from the writer's own version if it has one.
    fn read(&self, slot: usize, off: u64, out: &mut [u8], writer: bool) -> Result<usize, u64> {
        match self.shadow[slot].filter(|_| writer) {
            Some(sh) => Self::read_blocks(sh.ino, sh.size, off, out),
            None => Self::read_blocks(self.ents[slot].ino, self.ents[slot].size, off, out),
        }
    }

    /// Make bytes `from..to` of the shadow read as zeros, block by block. Files are kept *dense*: a block
    /// left behind by an interrupted earlier write must never show through as content.
    fn zero_range(ino: u32, from: u64, to: u64) -> Result<(), u64> {
        let (bs, mut b) = (BS as u64, from / BS as u64);
        if from % bs != 0 {
            // the end of the block holding `from`: keep what is below it, zero the rest
            if lfs_get(key(ino, b))? {
                page(va(VA_LFS)).fill_from((from % bs) as usize, 0);
                lfs_put(key(ino, b))?;
            }
            b += 1;
        }
        while b < to / bs {
            page(va(VA_LFS)).fill_from(0, 0);
            lfs_put(key(ino, b))?;
            b += 1;
        }
        Ok(())
    }

    fn write(&mut self, slot: usize, off: u64, data: &[u8]) -> Result<usize, u64> {
        if off.checked_add(data.len() as u64).map_or(true, |end| end > MAX_FILE) {
            return Err(ENOSPC); // file too large
        }
        let in_place = self.shadow[slot].is_none();
        if in_place && self.session[slot].is_none() {
            self.begin_session(slot)?;
        }
        let (ino, size) = self.target(slot);
        if off > size {
            if in_place && size % BS as u64 != 0 {
                self.log_block(slot, size / BS as u64)?; // zeroing the end of the last block changes it
            }
            Self::zero_range(ino, size, off)?;
        }
        let mut done = 0;
        while done < data.len() {
            let pos = off + done as u64;
            let (blk, inb) = (pos / BS as u64, (pos % BS as u64) as usize);
            let n = (data.len() - done).min(BS - inb);
            if in_place {
                self.log_block(slot, blk)?;
            }
            let k = key(ino, blk);
            if n < BS {
                // partial block: read-modify-write. Only the part below the old end of file is content.
                let valid = size.saturating_sub(blk * BS as u64).min(BS as u64) as usize;
                if valid > 0 && lfs_get(k)? {
                    page(va(VA_LFS)).fill_from(valid, 0);
                } else {
                    page(va(VA_LFS)).fill_from(0, 0);
                }
            }
            page(va(VA_LFS)).put(inb, &data[done..done + n]);
            lfs_put(k)?;
            done += n;
        }
        let new_size = size.max(off + data.len() as u64);
        match &mut self.shadow[slot] {
            Some(sh) => sh.size = new_size,
            None => self.ents[slot].size = new_size,
        }
        self.dirty = true;
        Ok(done)
    }

    /// The writer closes: flip the file to its new version in one checkpoint, then free the old blocks.
    fn commit(&mut self, slot: usize) -> Result<(), u64> {
        if self.shadow[slot].is_some() || self.session[slot].is_some() {
            self.touch(slot); // (a writer closes: the file was changed now; the flush below commits the time with the data)
        }
        if let Some(sh) = self.shadow[slot].take() {
            // Blocks staged with a store instance that has since restarted are gone; flipping the table to them
            // would publish a file whose data reads back as zeros or as an older version.
            if lfs_epoch()? != sh.epoch {
                return Err(EIO);
            }
            let (old_ino, old_size) = (self.ents[slot].ino, self.ents[slot].size);
            self.ents[slot].ino = sh.ino;
            self.ents[slot].size = sh.size;
            self.dirty = true;
            if let Err(e) = self.flush() {
                // The checkpoint did not complete. The store may even have lost the blocks of the new version
                // (it restarts from its last checkpoint), so the table must not point at them: keep serving the
                // old version, which is still intact, and let the next flush rewrite the table.
                self.ents[slot].ino = old_ino;
                self.ents[slot].size = old_size;
                return Err(e);
            }
            Self::reap(&[(key(old_ino, 0), Self::blocks(old_size))]);
        } else if self.session[slot].as_ref().is_some_and(|s| s.epoch != lfs_epoch().unwrap_or(0)) {
            // the store restarted during the update and lost what it had staged; what survives is a consistent
            // checkpoint of the file as the journal describes it, so take the update back
            self.abandon_session(slot)?;
            return Err(EIO);
        } else if let Some(s) = self.session[slot].take() {
            // the update is complete: the new size and the end of the session commit together
            self.jdirty = true;
            self.dirty = true;
            if let Err(e) = self.flush() {
                self.session[slot] = Some(s);
                return Err(e);
            }
            Self::reap(&[(undo_key(self.ents[slot].ino, s.gen, 0), Self::blocks(s.old_size))]);
        } else if self.dirty {
            self.flush()?;
        }
        Ok(())
    }

    /// Delete blocks nothing refers to any more: for each `(first key, count)`, that many consecutive keys.
    /// Errors are ignored: this is only garbage collection.
    fn reap(garbage: &[(u64, u64)]) {
        for &(first, count) in garbage {
            for b in 0..count {
                let _ = lfs_del(first + b);
            }
        }
    }

    /// Remove entry `i`. Returns the blocks to free *after* the table has been committed: deleting them
    /// first would leave, after a crash, a committed file whose blocks are gone.
    fn unlink(&mut self, i: usize) -> Result<Vec<(u64, u64)>, u64> {
        let mut garbage = Vec::new();
        if self.ents[i].kind == KIND_DIR {
            let prefix = alloc::format!("{}/", self.ents[i].path());
            if self.ents.iter().any(|e| e.ino != 0 && e.path().starts_with(prefix.as_str())) {
                return Err(ENOTEMPTY);
            }
        } else {
            garbage.push((key(self.ents[i].ino, 0), Self::blocks(self.ents[i].size)));
            if let Some(sh) = self.shadow[i].take() {
                garbage.push((key(sh.ino, 0), Self::blocks(sh.size)));
            }
            if let Some(s) = self.session[i].take() {
                // the file goes, and with it the update; the undo blocks go after the commit like the rest
                garbage.push((undo_key(self.ents[i].ino, s.gen, 0), Self::blocks(s.old_size)));
                self.jdirty = true;
            }
        }
        self.wgen[i] = self.wgen[i].wrapping_add(1); // any writer still holding the file loses it
        let gone = String::from(self.ents[i].path());
        self.ents[i] = Ent::FREE;
        self.times[i] = 0;
        self.dirty = true;
        self.touch_parent(&gone);
        Ok(garbage)
    }

    /// Move `from` (a file, or a directory and everything under it) to `to`, which must not exist and whose parent must be a directory.
    /// Only the paths change (the contents are keyed by inode): the next flush commits the whole move at once.
    fn rename(&mut self, from: &str, to: &str) -> Result<(), u64> {
        let i = self.find(from).ok_or(ENOENT)?;
        if from == to {
            return Ok(());
        }
        if self.find(to).is_some() {
            return Err(EEXIST);
        }
        let is_dir = self.ents[i].kind == KIND_DIR;
        let prefix = alloc::format!("{from}/");
        if is_dir && to.starts_with(prefix.as_str()) {
            return Err(EINVAL); // (a directory into itself)
        }
        if !self.parent_is_dir(to) {
            return Err(ENOENT);
        }
        if domain_of_ino(self.ents[i].ino) != self.parent_domain(to) {
            return Err(EINVAL); // (a file or directory stays in its encryption domain: moving it into another would leave its blocks under the wrong key)
        }
        let moves: Vec<(usize, String)> = self
            .ents
            .iter()
            .enumerate()
            .filter(|(_, e)| e.ino != 0 && (e.path() == from || (is_dir && e.path().starts_with(prefix.as_str()))))
            .map(|(k, e)| (k, alloc::format!("{to}{}", &e.path()[from.len()..])))
            .collect();
        if moves.iter().any(|(_, p)| p.len() >= PATH_MAX) {
            return Err(EINVAL); // a new path would not fit an entry: nothing moves
        }
        for (k, p) in moves {
            let e = &mut self.ents[k];
            e.path = [0; PATH_MAX];
            e.path[..p.len()].copy_from_slice(p.as_bytes());
        }
        self.touch(i);
        self.touch_parent(from);
        self.touch_parent(to);
        Ok(())
    }

    fn list(&self, dir: &str) -> Vec<u8> {
        let prefix = if dir == "/" { String::from("/") } else { alloc::format!("{dir}/") };
        let mut out = Vec::new();
        for e in self.ents.iter().filter(|e| e.ino != 0) {
            if let Some(rest) = e.path().strip_prefix(prefix.as_str()) {
                if !rest.is_empty() && !rest.contains('/') {
                    out.extend_from_slice(rest.as_bytes());
                    if e.kind == KIND_DIR {
                        out.push(b'/');
                    }
                    out.push(b'\n');
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// the server
// ---------------------------------------------------------------------------
#[derive(Clone)]
enum Fd {
    Free,
    Rofs { path: String, off: u64 },
    Data { slot: usize, ino: u32, off: u64, flags: u64, gen: u32 },
}

const FDS: usize = 16;

/// The page of `sender`'s session, whether this is a new program in that task slot (its descriptor table must
/// start empty), and whose descriptor table it is (the program's, for a thread). Programs started with file-system access are known to the kernel, which says which page is theirs.
fn client_page(sender: u64, gens: &mut [u64]) -> Option<(usize, bool, usize)> {
    match sender {
        0 => Some((va(VA_CLIENT0), false, 0)),
        8 => Some((va(VA_CLIENT8), false, 8)),
        s if s == SHELL_TASK.load(core::sync::atomic::Ordering::Relaxed) => Some((va(VA_SHELL), false, s as usize)),
        // (a boot task below 27 that has a session page, the consoles of ttys 1..3, is served like a program: the kernel says which page is its own)
        s if s != 0 && (s as usize) < gens.len() => {
            let r = sysinfo_at(5, s);
            // (the threads of a program share its session, and so its descriptors: `r[3]` is the program)
            let (page, gen, owner) = (r[1] as usize, r[2], r[3] as usize);
            if page >= PROG_SESSIONS.load(core::sync::atomic::Ordering::Relaxed) || owner >= gens.len() {
                return None;
            }
            let fresh = gens[owner] != gen;
            gens[owner] = gen;
            Some((va(VA_PROG0 + page * 0x1000), fresh, owner))
        }
        _ => None,
    }
}

fn get_path(pg: Pg) -> Option<String> {
    let own: [u8; DATA] = pg.snap(0); // (the client may rewrite the page while we parse it)
    let n = own.iter().position(|&c| c == 0)?;
    norm(core::str::from_utf8(&own[..n]).ok()?)
}

pub fn vfs_server() -> ! {
    find_shell();
    let maps = [(SL_ROFS_SHM, VA_ROFS), (SL_LFS_SHM, VA_LFS), (5, VA_CLIENT0), (6, VA_CLIENT8), (7, VA_SHELL)];
    let info = sysinfo_at(18, 0);
    let (sessions, slots) = (info[1] as usize, info[2] as usize);
    PROG_SESSIONS.store(sessions, core::sync::atomic::Ordering::Relaxed);
    // (all the session pages are one object, in slot 16: page k is at VA_PROG0 + k * 4096)
    for (slot, va) in maps.into_iter().chain([(16, VA_PROG0)]) {
        if mem_map(slot, va, true) != 0 {
            println!("[vfs] mapping failed");
            exit(1);
        }
    }
    // an encrypted data volume waits for its key (the greeter asks the user for the passphrase): nothing is read from it, and so nothing is served, until it is open
    let mut told = false;
    loop {
        let (st, r) = call(SL_LFS_EP, [proto::volume::LFS_STATUS, 0, 0]);
        if st != 0 || r[0] != proto::volume::state::LOCKED {
            break;
        }
        if !told {
            println!("[vfs] /data is locked: waiting for the volume to be unlocked");
            told = true;
        }
        sleep(10);
    }
    let mut ds = Datafs::load();
    println!("[vfs] up: /system (EROFS, read-only), /data (log-structured, {} entries)", ds.ents.iter().filter(|e| e.ino != 0).count());
    let mut fds: Vec<Vec<Fd>> = (0..slots).map(|_| vec![Fd::Free; FDS]).collect();
    let mut gens = vec![0u64; slots];
    // per program: (the generation of its session, the directory it is confined to); valid only while the generation matches
    let mut scopes: Vec<Option<Scope>> = (0..slots).map(|_| None).collect();
    let mut locks: Vec<FileLock> = Vec::new();
    loop {
        let m = recv(0);
        let Some((va, fresh, who)) = client_page(m.sender, &mut gens) else {
            reply([EINVAL, 0, 0]);
            continue;
        };
        if fresh {
            fds[who] = vec![Fd::Free; FDS]; // a new program in that task slot: nothing of its predecessor's is open
            locks.retain(|l| l.who != who); // ... and nothing of its predecessor's is locked
        }
        if m.w[0] == V_LOCK {
            reply(lock_request(&fds, &gens, &mut locks, who, m.w[1], m.w[2]));
            continue;
        }
        if m.w[0] == V_CLOSE {
            if let Some(idx) = fd_slot(&fds[who], m.w[1]) {
                locks.retain(|l| !(l.who == who && l.idx == idx)); // (the descriptor is free after this: its lock goes with it)
            }
        }
        if (m.w[0] == V_CRASH || m.w[0] == V_FAIL_SYNC) && m.sender != 0 {
            reply([EINVAL, 0, 0]); // fault injection is the test conductor's tool, not every client's
            continue;
        }
        let pg = page(va);
        if m.w[0] == V_SCOPE {
            reply(scope_request(&ds, &mut scopes, &gens, who, pg, m.w[1], m.w[2]));
            continue;
        }
        let table = &mut fds[who];
        let scope = scopes[who].as_ref().filter(|(g, _, _)| *g == gens[who]).map(|(_, d, q)| (d.clone(), q.clone()));
        let r = handle(&mut ds, table, pg, m.w, scope.as_ref().map(|(d, _)| d.as_str()), scope.as_ref().map_or(&[][..], |(_, q)| q.as_slice()));
        reply(r);
    }
}

/// An advisory lock on an open file (`V_LOCK`, like `flock`): held by one open file description (client `who`, descriptor table entry `idx`), on one file.
/// Any number of shared locks, or one exclusive; asking again on the same descriptor converts it. It goes with the descriptor: `close`, and a new program in
/// the client's task slot (see the main loop), release it. Locks are advisory: nothing but a program that asks for one is kept out, and a lock is held on a
/// `/data` file only (the system partition is read-only: a lock there is always granted and holds nothing).
#[derive(Clone, Copy)]
struct FileLock {
    who: usize,
    idx: usize,
    ino: u32,
    exclusive: bool,
}

/// Does client `who` still have the session it had (a program that ended, or was replaced, left its locks behind: the server is told nothing, but the kernel knows)?
fn client_alive(who: usize, gens: &[u64]) -> bool {
    if who == 0 || who == 8 || who as u64 == SHELL_TASK.load(core::sync::atomic::Ordering::Relaxed) {
        return true; // (the conductor, the console and the shell have sessions of their own for good)
    }
    let r = sysinfo_at(5, who as u64);
    (r[1] as usize) < PROG_SESSIONS.load(core::sync::atomic::Ordering::Relaxed) && r[2] == gens[who]
}

fn lock_request(fds: &[Vec<Fd>], gens: &[u64], locks: &mut Vec<FileLock>, who: usize, fd: u64, op: u64) -> [u64; 3] {
    let Some(idx) = fd_slot(&fds[who], fd) else { return [EBADF, 0, 0] };
    locks.retain(|l| l.who == who || client_alive(l.who, gens)); // (locks of programs that have ended are gone)
    let ino = match fds[who][idx] {
        Fd::Data { ino, .. } => ino,
        Fd::Rofs { .. } => return if (1..=3).contains(&op) { [0, 0, 0] } else { [EINVAL, 0, 0] },
        Fd::Free => return [EBADF, 0, 0],
    };
    match op {
        3 => {
            locks.retain(|l| !(l.who == who && l.idx == idx));
            [0, 0, 0]
        }
        1 | 2 => {
            let exclusive = op == 2;
            if locks.iter().any(|l| l.ino == ino && !(l.who == who && l.idx == idx) && (l.exclusive || exclusive)) {
                return [EAGAIN, 0, 0];
            }
            locks.retain(|l| !(l.who == who && l.idx == idx));
            locks.push(FileLock { who, idx, ino, exclusive });
            [0, 0, 0]
        }
        _ => [EINVAL, 0, 0],
    }
}

/// `V_SCOPE`: the caller (program `who`) confines its child `w1` to the directory in the page. Only the program's parent may
/// (the kernel says who that is), only while the child has a file session, and the directory is named as the *caller* sees it, so
/// a caller that is itself confined can only narrow, never widen. The child is confined from its first request: it is
/// normally still an embryo when this arrives (see `metallium_loader::spawn_with`).
fn scope_request(ds: &Datafs, scopes: &mut [Option<Scope>], gens: &[u64], who: usize, pg: Pg, child: u64, quota: u64) -> [u64; 3] {
    let err = |e: u64| [e, 0, 0];
    let child = child as usize;
    if child >= scopes.len() || child == who {
        return err(EINVAL);
    }
    let r = sysinfo_at(5, child as u64);
    let (page, gen, owner, parent) = (r[1] as usize, r[2], r[3] as usize, r[4] as usize);
    if page >= PROG_SESSIONS.load(core::sync::atomic::Ordering::Relaxed) || owner != child {
        return err(EINVAL);
    }
    if parent != who {
        return err(EPERM);
    }
    let Some(p) = get_path(pg) else { return err(EINVAL) };
    let mine = scopes[who].as_ref().filter(|(g, _, _)| *g == gens[who]).map(|(_, d, q)| (d.clone(), q.clone()));
    let Some(Route::Data(full)) = route_scoped(&p, mine.as_ref().map(|(d, _)| d.as_str())) else { return err(EINVAL) };
    match &mine {
        // "the same as mine": `/data` as the caller sees it. A confined caller hands its own confinement on (so a confined program that starts programs does not hand them
        // an unconfined file session: `Command` asks for this by default); an unconfined caller has nothing to hand on, and the child stays unconfined too
        Some((dir, q)) if full == *dir => {
            scopes[child] = Some((gen, dir.clone(), q.clone()));
            return [0, 0, 0];
        }
        None if full == "/" => {
            scopes[child] = None;
            return [0, 0, 0];
        }
        _ => {}
    }
    if full == "/" || ds.find(&full).map_or(true, |s| ds.ents[s].kind != KIND_DIR) {
        return err(ENOENT);
    }
    // the child's entry quota: the default unless asked for, never more than the caller's own, never more than the table holds
    let mut limit = if quota == 0 { SCOPE_MAX_ENTRIES } else { (quota as usize).min(NENT) };
    let mut chain = mine.map(|(_, q)| q).unwrap_or_default();
    if let Some((_, own)) = chain.last() {
        limit = limit.min(*own);
    }
    chain.push((full.clone(), limit));
    scopes[child] = Some((gen, full, chain));
    [0, 0, 0]
}

fn fd_slot(table: &[Fd], fd: u64) -> Option<usize> {
    let i = fd as usize;
    (i < FDS && !matches!(table[i], Fd::Free)).then_some(i)
}

fn handle(ds: &mut Datafs, table: &mut [Fd], pg: Pg, w: [u64; 3], scope: Option<&str>, quotas: &[(String, usize)]) -> [u64; 3] {
    let err = |e: u64| [e, 0, 0];
    match w[0] {
        V_OPEN => {
            let Some(p) = get_path(pg) else { return err(EINVAL) };
            let flags = w[1];
            let Some(fi) = table.iter().position(|f| matches!(f, Fd::Free)) else { return err(ENOSPC) };
            match route_scoped(&p, scope) {
                None => err(ENOENT),
                Some(Route::Root) => err(EISDIR),
                Some(Route::Rofs(rest)) => {
                    if flags & (O_WRITE | O_CREATE | O_TRUNC) != 0 {
                        return err(EROFS);
                    }
                    match rofs_stat(&rest) {
                        Ok((1, _)) => {
                            table[fi] = Fd::Rofs { path: rest, off: 0 };
                            [0, fi as u64, 0]
                        }
                        Ok(_) => err(EISDIR),
                        Err(e) => err(e),
                    }
                }
                Some(Route::Data(rest)) => {
                    if rest == "/" {
                        return err(EISDIR);
                    }
                    let slot = match ds.find(&rest) {
                        Some(s) => s,
                        None if flags & O_CREATE != 0 && over_quota(ds, quotas) => return err(ENOSPC),
                        None if flags & O_CREATE != 0 => match ds.create(&rest, KIND_FILE) {
                            Ok(s) => s,
                            Err(e) => return err(e),
                        },
                        None => return err(ENOENT),
                    };
                    if ds.ents[slot].kind == KIND_DIR {
                        return err(EISDIR);
                    }
                    let gen = if flags & O_WRITE != 0 {
                        match ds.open_writer(slot, flags & O_TRUNC != 0) {
                            Ok(g) => g,
                            Err(e) => return err(e),
                        }
                    } else {
                        0
                    };
                    table[fi] = Fd::Data { slot, ino: ds.ents[slot].ino, off: 0, flags, gen };
                    [0, fi as u64, 0]
                }
            }
        }
        V_READ => {
            let Some(i) = fd_slot(table, w[1]) else { return err(EBADF) };
            let len = (w[2] as usize).min(MAXIO);
            let mut buf = vec![0u8; len];
            let res = match &mut table[i] {
                Fd::Rofs { path, off } => rofs_read(path, *off, &mut buf).map(|n| {
                    *off += n as u64;
                    n
                }),
                Fd::Data { slot, ino, off, flags, gen } => {
                    let writer = *flags & O_WRITE != 0;
                    if *flags & O_READ == 0 {
                        Err(EBADF)
                    } else if ds.ents[*slot].ino != *ino || (writer && ds.wgen[*slot] != *gen) {
                        Err(EBADF) // the file was unlinked or replaced underneath us
                    } else {
                        ds.read(*slot, *off, &mut buf, writer).map(|n| {
                            *off += n as u64;
                            n
                        })
                    }
                }
                Fd::Free => Err(EBADF),
            };
            match res {
                Ok(n) => {
                    pg.put(DATA, &buf[..n]);
                    [0, n as u64, 0]
                }
                Err(e) => err(e),
            }
        }
        V_WRITE => {
            let Some(i) = fd_slot(table, w[1]) else { return err(EBADF) };
            let len = (w[2] as usize).min(MAXIO);
            match &mut table[i] {
                Fd::Data { slot, ino, off, flags, gen } if *flags & O_WRITE != 0 && ds.ents[*slot].ino == *ino && ds.wgen[*slot] == *gen => {
                    match ds.write(*slot, *off, &pg.vec(DATA, len)) {
                        Ok(n) => {
                            *off += n as u64;
                            [0, n as u64, 0]
                        }
                        Err(e) => err(e),
                    }
                }
                Fd::Rofs { .. } => err(EROFS),
                _ => err(EBADF),
            }
        }
        V_SEEK => {
            let Some(i) = fd_slot(table, w[1]) else { return err(EBADF) };
            match &mut table[i] {
                Fd::Rofs { off, .. } | Fd::Data { off, .. } => {
                    if w[2] > MAX_FILE {
                        return err(EINVAL);
                    }
                    *off = w[2];
                }
                Fd::Free => {}
            }
            [0, 0, 0]
        }
        V_CLOSE => {
            let Some(i) = fd_slot(table, w[1]) else { return err(EBADF) };
            let closing = core::mem::replace(&mut table[i], Fd::Free);
            if let Fd::Data { slot, ino, flags, gen, .. } = closing {
                if flags & O_WRITE != 0 {
                    // only the current writer commits; one that was superseded (or whose file was removed) is told
                    if ds.ents[slot].ino != ino || ds.wgen[slot] != gen {
                        return err(EBADF);
                    }
                    if let Err(e) = ds.commit(slot) {
                        return err(e);
                    }
                }
            }
            [0, 0, 0]
        }
        V_STAT | V_STAT_TIME | V_LSTAT | V_READLINK | V_LIST | V_LIST_AT | V_UNLINK | V_MKDIR => {
            let Some(p) = get_path(pg) else { return err(EINVAL) };
            let Some(rt) = route_scoped(&p, scope) else { return err(ENOENT) };
            match (w[0], rt) {
                (V_STAT_TIME, Route::Root) => [0, 0, 2],
                (V_STAT_TIME, Route::Rofs(r)) => (if w[1] == 1 { rofs_lstat(&r) } else { rofs_stat(&r) }).map_or_else(err, |(k, s)| [0, s, k]), // (the system image has no times: 0)
                (V_STAT_TIME, Route::Data(r)) if r == "/" => [0, 0, 2],
                (V_STAT_TIME, Route::Data(r)) => match ds.find(&r) {
                    Some(s) => [0, ds.ents[s].size, ds.ents[s].kind as u64 | (ds.times[s] as u64) << 8],
                    None => err(ENOENT),
                },
                (V_LSTAT, Route::Rofs(r)) => rofs_lstat(&r).map_or_else(err, |(k, s)| [0, s, k]),
                (V_LSTAT, Route::Root) => [0, 0, 2],
                (V_LSTAT, Route::Data(r)) if r == "/" => [0, 0, 2],
                (V_LSTAT, Route::Data(r)) => match ds.find(&r) {
                    Some(s) => [0, ds.ents[s].size, ds.ents[s].kind as u64], // (/data has no symbolic links: lstat is stat)
                    None => err(ENOENT),
                },
                (V_READLINK, Route::Rofs(r)) => match rofs_readlink(&r) {
                    Ok(t) => {
                        pg.put(DATA, &t);
                        [0, t.len() as u64, 0]
                    }
                    Err(e) => err(e),
                },
                (V_READLINK, Route::Data(r)) if ds.find(&r).is_none() => err(ENOENT),
                (V_READLINK, _) => err(EINVAL), // (not a symbolic link)
                (V_LIST_AT, rt) => {
                    let cursor = w[1];
                    let listing = match rt {
                        Route::Root => Ok(if cursor == 0 { (b"system/\ndata/\n".to_vec(), false) } else { (Vec::new(), false) }),
                        Route::Rofs(r) => rofs_list_at(&r, cursor),
                        Route::Data(r) => match (r == "/", ds.find(&r)) {
                            (true, _) => Ok(lines_from(&ds.list("/"), cursor as usize)),
                            (_, Some(s)) if ds.ents[s].kind == KIND_DIR => Ok(lines_from(&ds.list(&r), cursor as usize)),
                            (_, Some(_)) => Err(EISDIR),
                            _ => Err(ENOENT),
                        },
                    };
                    match listing {
                        Ok((v, more)) => {
                            pg.put(DATA, &v);
                            [0, v.len() as u64, more as u64]
                        }
                        Err(e) => err(e),
                    }
                }
                (V_STAT, Route::Root) => [0, 0, 2],
                (V_STAT, Route::Rofs(r)) => rofs_stat(&r).map_or_else(err, |(k, s)| [0, s, k]),
                (V_STAT, Route::Data(r)) if r == "/" => [0, 0, 2],
                (V_STAT, Route::Data(r)) => match ds.find(&r) {
                    Some(s) => [0, ds.ents[s].size, ds.ents[s].kind as u64],
                    None => err(ENOENT),
                },
                (V_LIST, rt) => {
                    let names = match rt {
                        Route::Root => Ok(b"system/\ndata/\n".to_vec()),
                        Route::Rofs(r) => rofs_list(&r),
                        Route::Data(r) => match (r == "/", ds.find(&r)) {
                            (true, _) => Ok(ds.list("/")),
                            (_, Some(s)) if ds.ents[s].kind == KIND_DIR => Ok(ds.list(&r)),
                            (_, Some(_)) => Err(EISDIR),
                            _ => Err(ENOENT),
                        },
                    };
                    match names {
                        Ok(v) => {
                            let n = v.len().min(MAXIO);
                            pg.put(DATA, &v[..n]);
                            [0, n as u64, 0]
                        }
                        Err(e) => err(e),
                    }
                }
                (_, Route::Data(r)) if r != "/" => {
                    let res = if w[0] == V_MKDIR {
                        if over_quota(ds, quotas) {
                            return err(ENOSPC);
                        }
                        ds.create(&r, KIND_DIR).map(|_| Vec::new())
                    } else {
                        ds.find(&r).ok_or(ENOENT).and_then(|s| ds.unlink(s))
                    };
                    match res.and_then(|garbage| ds.flush().map(|_| garbage)) {
                        Ok(garbage) => {
                            Datafs::reap(&garbage); // after the commit, never before
                            [0, 0, 0]
                        }
                        Err(e) => err(e),
                    }
                }
                (_, Route::Rofs(_)) => err(EROFS),
                _ => err(EINVAL),
            }
        }
        V_MKDIR_DOMAIN => {
            let Some(p) = get_path(pg) else { return err(EINVAL) };
            if scope.is_some() {
                return err(EPERM); // only an unconfined caller (the session service) starts a domain
            }
            let dom = w[1] as u32;
            if dom == 0 || dom > 0x3F {
                return err(EINVAL);
            }
            let Some(Route::Data(rest)) = route_scoped(&p, scope) else { return err(EINVAL) };
            if rest == "/" || ds.parent_domain(&rest) != 0 {
                return err(EINVAL); // (a domain's directory is made in the top-level domain)
            }
            match ds.create_in(&rest, KIND_DIR, dom).and_then(|_| ds.flush()) {
                Ok(()) => [0, 0, 0],
                Err(e) => err(e),
            }
        }
        V_RENAME => {
            let Some(from) = get_path(pg) else { return err(EINVAL) };
            let own: [u8; DATA] = pg.snap(0); // (a private copy: the client may rewrite the page meanwhile)
            let n = own.iter().position(|&c| c == 0).unwrap_or(DATA);
            let rest = &own[(n + 1).min(DATA)..DATA];
            let Some(m) = rest.iter().position(|&c| c == 0) else { return err(EINVAL) };
            let Some(to) = core::str::from_utf8(&rest[..m]).ok().and_then(norm) else { return err(EINVAL) };
            match (route_scoped(&from, scope), route_scoped(&to, scope)) {
                (Some(Route::Data(a)), Some(Route::Data(b))) => {
                    // (the root of /data, or of a confined program's directory, stays where it is)
                    let root = scope.unwrap_or("/");
                    if a == "/" || b == "/" || a == root || b == root {
                        return err(EINVAL);
                    }
                    match ds.rename(&a, &b).and_then(|_| ds.flush()) {
                        Ok(()) => [0, 0, 0],
                        Err(e) => err(e),
                    }
                }
                (Some(Route::Rofs(_)), _) | (_, Some(Route::Rofs(_))) => err(EROFS),
                (None, _) | (_, None) => err(ENOENT),
                _ => err(EINVAL),
            }
        }
        V_SYNC => ds.flush().map_or_else(err, |_| [0, 0, 0]),
        V_FAIL_SYNC => {
            FAIL_NEXT_SYNC.store(true, core::sync::atomic::Ordering::Relaxed);
            [0, 0, 0]
        }
        V_CRASH => {
            println!("[vfs] simulated fault: fd tables and unflushed metadata are lost");
            // SAFETY: deliberate fault injection: 0x4000 is below every mapping (images are at 0x8000_0000 or higher), so the store traps and the kernel restarts the VFS; that is the test.
            unsafe { write_volatile(0x4000 as *mut u64, 1) };
            err(EIO)
        }
        _ => err(EINVAL),
    }
}

// ---------------------------------------------------------------------------
// client library (what an application links against)
// ---------------------------------------------------------------------------
/// Err(code): positive = VFS status, negative = IPC error (e.g. E_DEAD if the VFS crashed).
pub type VResult<T> = Result<T, i64>;

#[derive(Clone, Copy)]
pub struct Vfs {
    ep: u64,
    shm: usize,
}

impl Vfs {
    pub fn new(ep: u64, shm: usize) -> Vfs {
        Vfs { ep, shm }
    }

    fn pg(&self) -> Pg {
        page(self.shm)
    }

    fn rpc(&self, op: u64, a: u64, b: u64) -> VResult<(u64, u64)> {
        let (st, r) = call(self.ep, [op, a, b]);
        if st != 0 {
            return Err(st);
        }
        if r[0] != 0 {
            return Err(r[0] as i64);
        }
        Ok((r[1], r[2]))
    }

    fn with_path(&self, p: &str, op: u64, a: u64) -> VResult<(u64, u64)> {
        if p.len() >= DATA {
            return Err(EINVAL as i64);
        }
        let pg = self.pg();
        pg.put(0, p.as_bytes());
        pg.put(p.len(), &[0]);
        self.rpc(op, a, 0)
    }

    pub fn open(&self, path: &str, flags: u64) -> VResult<u64> {
        self.with_path(path, V_OPEN, flags).map(|r| r.0)
    }
    pub fn close(&self, fd: u64) -> VResult<()> {
        self.rpc(V_CLOSE, fd, 0).map(|_| ())
    }
    pub fn seek(&self, fd: u64, off: u64) -> VResult<()> {
        self.rpc(V_SEEK, fd, off).map(|_| ())
    }
    pub fn read(&self, fd: u64, buf: &mut [u8]) -> VResult<usize> {
        let mut done = 0;
        while done < buf.len() {
            let want = (buf.len() - done).min(MAXIO);
            let (n, _) = self.rpc(V_READ, fd, want as u64)?;
            if n == 0 {
                break;
            }
            self.pg().get(DATA, &mut buf[done..done + n as usize]);
            done += n as usize;
        }
        Ok(done)
    }
    pub fn write(&self, fd: u64, data: &[u8]) -> VResult<usize> {
        let mut done = 0;
        while done < data.len() {
            let n = (data.len() - done).min(MAXIO);
            self.pg().put(DATA, &data[done..done + n]);
            let (wrote, _) = self.rpc(V_WRITE, fd, n as u64)?;
            done += wrote as usize;
        }
        Ok(done)
    }
    pub fn stat(&self, path: &str) -> VResult<(u64, u64)> {
        self.with_path(path, V_STAT, 0).map(|(size, kind)| (kind, size))
    }
    /// An advisory lock on an open file: `op` 1 shared, 2 exclusive, 3 unlock. `Err(EAGAIN)` if another open file holds a conflicting lock: it does not wait.
    pub fn flock(&self, fd: u64, op: u64) -> VResult<()> {
        self.rpc(V_LOCK, fd, op).map(|_| ())
    }
    /// (kind, size, modification time in seconds since 1970 (0: not known)) of a path; `nofollow` for a symbolic link itself.
    pub fn stat_time(&self, path: &str, nofollow: bool) -> VResult<(u64, u64, u64)> {
        self.with_path(path, V_STAT_TIME, nofollow as u64).map(|(size, kt)| (kt & 0xFF, size, kt >> 8))
    }
    /// (kind, size) of a path without following a symbolic link in its last component: kind 3 is a link, its size the length of its target.
    pub fn lstat(&self, path: &str) -> VResult<(u64, u64)> {
        self.with_path(path, V_LSTAT, 0).map(|(size, kind)| (kind, size))
    }
    /// The target of a symbolic link.
    pub fn readlink(&self, path: &str) -> VResult<String> {
        let (n, _) = self.with_path(path, V_READLINK, 0)?;
        Ok(String::from_utf8_lossy(&self.pg().vec(DATA, n as usize)).into_owned())
    }
    pub fn list(&self, path: &str) -> VResult<String> {
        let (n, _) = self.with_path(path, V_LIST, 0)?;
        Ok(String::from_utf8_lossy(&self.pg().vec(DATA, n as usize)).into_owned())
    }
    /// All the names of a directory, however many: asks for the pieces until there are no more.
    pub fn list_all(&self, path: &str) -> VResult<String> {
        let (mut out, mut cursor) = (String::new(), 0u64);
        loop {
            let (n, more) = self.with_path(path, V_LIST_AT, cursor)?;
            let piece = String::from_utf8_lossy(&self.pg().vec(DATA, n as usize)).into_owned();
            cursor += piece.bytes().filter(|&c| c == b'\n').count() as u64;
            out.push_str(&piece);
            if more == 0 || n == 0 {
                return Ok(out);
            }
        }
    }
    /// Move a file, or a directory with everything in it, inside `/data` (one commit).
    pub fn rename(&self, from: &str, to: &str) -> VResult<()> {
        if from.len() + to.len() + 2 > DATA {
            return Err(EINVAL as i64);
        }
        let pg = self.pg();
        pg.put(0, from.as_bytes());
        pg.put(from.len(), &[0]);
        pg.put(from.len() + 1, to.as_bytes());
        pg.put(from.len() + 1 + to.len(), &[0]);
        self.rpc(V_RENAME, 0, 0).map(|_| ())
    }
    pub fn unlink(&self, path: &str) -> VResult<()> {
        self.with_path(path, V_UNLINK, 0).map(|_| ())
    }
    pub fn mkdir(&self, path: &str) -> VResult<()> {
        self.with_path(path, V_MKDIR, 0).map(|_| ())
    }
    pub fn crash(&self) -> i64 {
        call(self.ep, [V_CRASH, 0, 0]).0
    }
    /// Test hook (conductor only): the next checkpoint the VFS asks the store for fails.
    pub fn fail_next_sync(&self) -> i64 {
        call(self.ep, [V_FAIL_SYNC, 0, 0]).0
    }

    /// Whole-file convenience helpers.
    pub fn read_file(&self, path: &str) -> VResult<Vec<u8>> {
        let (_, size) = self.stat(path)?;
        let fd = self.open(path, O_READ)?;
        let mut v = vec![0u8; size as usize];
        let n = self.read(fd, &mut v);
        self.close(fd)?;
        v.truncate(n?);
        Ok(v)
    }
    pub fn write_file(&self, path: &str, data: &[u8]) -> VResult<()> {
        let fd = self.open(path, O_WRITE | O_CREATE | O_TRUNC)?;
        let r = self.write(fd, data);
        self.close(fd)?; // close commits
        r.map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// role 8: an ordinary application. Holds exactly one VFS capability.
// ---------------------------------------------------------------------------
const PROGRAM_SHM: usize = 0x8034_0000;

pub fn program() -> ! {
    if sysinfo(2)[3] == 2 {
        crate::sched::interactive_hog(); // scheduler tests: the program is a CPU hog of the Interactive class
    }
    if mem_map(1, PROGRAM_SHM, true) != 0 {
        println!("[program] cannot map its VFS page");
        exit(1);
    }
    let v = Vfs::new(0, PROGRAM_SHM);
    println!("[program] online (capabilities: one VFS endpoint)");

    let os = v.read_file("/system/etc/os-release");
    println!("[program] TEST read /system/etc/os-release ({}): {}",
        os.as_ref().map_or(0, |b| b.len()), verdict(os.map_or(false, |b| b.starts_with(b"NAME=Metallium-OS"))));

    let mut log = Vec::new();
    for i in 0..3 {
        log.extend_from_slice(alloc::format!("line {i}\n").as_bytes());
    }
    let ok = v.write_file("/data/program.log", &log).is_ok();
    // append through seek-to-end
    let (_, size) = v.stat("/data/program.log").unwrap_or((0, 0));
    let fd = v.open("/data/program.log", O_WRITE);
    let ok2 = fd.and_then(|fd| {
        v.seek(fd, size)?;
        v.write(fd, b"line 3\n")?;
        v.close(fd)
    });
    let back = v.read_file("/data/program.log");
    println!("[program] TEST write + append + read back /data/program.log: {}",
        verdict(ok && ok2.is_ok() && back.map_or(false, |b| b == b"line 0\nline 1\nline 2\nline 3\n")));

    let names = v.list("/data").unwrap_or_default();
    println!("[program] TEST list /data ({:?}): {}", names.replace('\n', " ").trim_end(), verdict(names.contains("program.log")));

    // offsets are bounded: a huge seek must not alias another file's blocks or make truncate loop for ever
    let big = v.open("/data/program.log", O_WRITE).and_then(|fd| {
        let seek = v.seek(fd, 1 << 40);
        let _ = v.close(fd);
        seek
    });
    let fd = v.open("/data/program.log", O_WRITE);
    let wr = fd.and_then(|fd| {
        v.seek(fd, MAX_FILE - 2)?;
        let r = v.write(fd, b"toolong");
        let _ = v.close(fd);
        r
    });
    println!("[program] TEST file size is bounded (seek past the limit {big:?}, write past it {wr:?}): {}", verdict(big == Err(EINVAL as i64) && wr == Err(ENOSPC as i64)));

    let r = v.write_file("/system/hack.txt", b"x");
    println!("[program] TEST /system rejects writes ({r:?}): {}", verdict(r == Err(EROFS as i64)));

    // least privilege: no block driver, no filesystem servers, no device memory
    let (st, _) = call(3, [BLK_READ, 0, 1]);
    let (st2, _) = call(5, [30, 0, 0]);
    println!("[program] TEST no direct device or filesystem access (status {st}, {st2}): {}",
        verdict(st == E_BADCAP && st2 == E_BADCAP));

    // the test-only crash hook belongs to the conductor: an ordinary client cannot kill the VFS with it
    let (st, r) = call(0, [V_CRASH, 0, 0]);
    println!("[program] TEST an ordinary client cannot use the VFS fault-injection hook (status {st}, reply {}): {}", r[0], verdict(st == 0 && r[0] == EINVAL));

    let _ = v.write_file("/data/program.done", b"done");
    exit(0)
}

// ---------------------------------------------------------------------------
// conductor-side VFS tests (role 0)
// ---------------------------------------------------------------------------
const C_VFS_SHM: usize = 0x8034_0000;

fn pat(i: usize) -> u8 {
    (i * 13 + 5) as u8
}

/// The program task shares the data store with the conductor's direct LFS tests, and a sync by
/// either commits everything staged by both. Let the program finish first so those tests are isolated.
/// (It is done when its task has exited. Not when `/data/program.done` exists: on a disk that has been
/// booted before, that file is left over from the last boot.)
pub fn wait_for_program() {
    for _ in 0..400 {
        let mut alive = false;
        for t in 0..32u64 {
            let r = sysinfo_at(3, t);
            if r[0] as i64 == E_INVAL {
                break;
            }
            // role 8 is the program; state code 0 = free, 7 = dead
            alive |= r[5] == 8 && r[3] != 0 && r[3] != 7;
        }
        if !alive {
            return;
        }
        sleep(5);
    }
}

pub fn vfs_tests() {
    let m = mem_map(10, C_VFS_SHM, true);
    if m != 0 && m != E_INVAL {
        println!("[client] TEST VFS: cannot map page: FAIL");
        return;
    }
    let v = Vfs::new(9, C_VFS_SHM);

    let h = v.read_file("/system/hello.txt");
    println!("[client] TEST VFS read /system/hello.txt: {}",
        verdict(h.map_or(false, |b| b == b"Hello from the Metallium-OS system image!\n")));

    // a directory with more names than a page holds is listed in pieces, each from where the last ended
    let one_page = v.list("/system/usr/share/dirtest").map(|s| s.lines().count()).unwrap_or(0);
    let all = v.list_all("/system/usr/share/dirtest").unwrap_or_default();
    let mut names: Vec<&str> = all.lines().collect();
    let total = names.len();
    names.sort();
    names.dedup();
    println!("[client] TEST a /system directory of 420 entries is listed whole in pieces (one page holds {one_page}, all pieces {total}, {} different, first {:?}): {}", names.len(),
        names.first(), verdict(one_page < 420 && total == 420 && names.len() == 420 && names[0] == "entry-0000-with-a-longish-name" && names[419] == "entry-0419-with-a-longish-name"));

    // modification times of /data entries: set when a file is made and when a writer closes, on the directory when an entry is added, removed or moved
    {
        let secs = |p: &str| v.stat_time(p, false).map(|(_, _, t)| t).unwrap_or(u64::MAX);
        let wall = svc(34, 1, 0, 0, 0, 0)[0] as i64;
        let clock = wall > 0;
        let wall_s = if clock { wall as u64 / 1_000_000_000 } else { 0 };
        let _ = v.mkdir("/data/times");
        let made = v.write_file("/data/times/a.txt", b"one").is_ok();
        let (a1, d1) = (secs("/data/times/a.txt"), secs("/data/times"));
        if clock {
            sleep(120); // (the times are whole seconds)
        }
        let rewrote = v.write_file("/data/times/a.txt", b"two!").is_ok();
        let a2 = secs("/data/times/a.txt");
        let b_made = v.write_file("/data/times/b.txt", b"x").is_ok();
        let d2 = secs("/data/times");
        let moved = v.rename("/data/times/a.txt", "/data/times/c.txt").is_ok();
        let c = secs("/data/times/c.txt");
        let gone = v.unlink("/data/times/b.txt").is_ok();
        let d3 = secs("/data/times");
        let root_and_system = v.stat_time("/data", false) == Ok((2, 0, 0)) && v.stat_time("/system/hello.txt", false).map(|(k, _, t)| (k, t)) == Ok((1, 0));
        let nothing_there = v.stat_time("/data/times/nope", false) == Err(ENOENT as i64);
        let ok = if clock {
            a1 + 5 >= wall_s && a1 <= wall_s + 5 && d1 >= a1 && a2 > a1 && d2 > d1 && c >= a2 && d3 >= d2
        } else {
            [a1, d1, a2, d2, c, d3].iter().all(|&t| t == 0)
        };
        println!("[client] TEST /data entries have modification times: a file's when it was made and when a writer closed it, its directory's when an entry is added, moved or removed (clock {clock}: made {made} {a1} -> {a2} after a rewrite {rewrote}, directory {d1} -> {d2} -> {d3} {b_made} {moved} {gone}, system image and root {root_and_system}, missing {nothing_there}): {}",
            verdict(made && rewrote && b_made && moved && gone && root_and_system && nothing_there && ok));
        for n in ["c.txt", "a.txt", "b.txt"] {
            let _ = v.unlink(&alloc::format!("/data/times/{n}"));
        }
        let _ = v.unlink("/data/times");
    }

    // symbolic links on /system: followed by open, stat and list (in every component of a path), not by lstat and readlink; loops and long chains are ELOOP
    {
        let l = "/system/usr/share/links";
        let want = b"link target\n".to_vec();
        let reads: Vec<bool> = ["rel", "abs", "up", "hop19", "hop5"].iter().map(|n| v.read_file(&alloc::format!("{l}/{n}")).map_or(false, |b| b == want)).collect();
        let through_dir = v.read_file(&alloc::format!("{l}/dirlink/inner.txt")).map_or(false, |b| b == b"inner\n") && v.read_file(&alloc::format!("{l}/dirabs/inner.txt")).map_or(false, |b| b == b"inner\n");
        let stat_file = v.stat(&alloc::format!("{l}/rel")).map_or(false, |(k, s)| k == 1 && s == 12);
        let stat_dir = v.stat(&alloc::format!("{l}/dirlink")).map_or(false, |(k, _)| k == 2);
        let listed = v.list(&alloc::format!("{l}/dirlink")).map_or(false, |s| s.trim_end() == "inner.txt");
        let lstat = v.lstat(&alloc::format!("{l}/rel")) == Ok((3, 10)) && v.lstat(&alloc::format!("{l}/dirlink")).map(|(k, _)| k) == Ok(3) && v.lstat(&alloc::format!("{l}/target.txt")) == Ok((1, 12)) && v.lstat(&alloc::format!("{l}/sub")).map(|(k, _)| k) == Ok(2);
        let readlink = v.readlink(&alloc::format!("{l}/rel")).as_deref() == Ok("target.txt") && v.readlink(&alloc::format!("{l}/abs")).as_deref() == Ok("/usr/share/links/target.txt") && v.readlink(&alloc::format!("{l}/target.txt")) == Err(EINVAL as i64) && v.readlink(&alloc::format!("{l}/nope")) == Err(ENOENT as i64);
        let errors = v.stat(&alloc::format!("{l}/loop1")) == Err(ELOOP as i64) && v.stat(&alloc::format!("{l}/dangling")) == Err(ENOENT as i64) && v.stat(&alloc::format!("{l}/hop0")) == Err(ELOOP as i64) && v.open(&alloc::format!("{l}/loop2"), O_READ) == Err(ELOOP as i64) && v.lstat(&alloc::format!("{l}/loop1")).map(|(k, _)| k) == Ok(3);
        println!("[client] TEST symbolic links on /system are followed in paths (reads {reads:?}, through directory links {through_dir}, stat of a link: file {stat_file}, directory {stat_dir}, list {listed}), lstat and readlink see the link itself ({lstat} {readlink}), and a loop, a chain of 20 and a dangling link fail with ELOOP and ENOENT ({errors}): {}",
            verdict(reads.iter().all(|&b| b) && through_dir && stat_file && stat_dir && listed && lstat && readlink && errors));
    }

    let blob = v.read_file("/system/bin/blob.bin");
    println!("[client] TEST VFS read 9000-byte file via fd: {}",
        verdict(blob.map_or(false, |b| b.len() == 9000 && b.iter().enumerate().all(|(i, &x)| x == ((i * 7) % 251) as u8))));

    // a 224 KB text file: stored LZ4-compressed on the system partition
    let lorem: Vec<u8> = (0..4000).flat_map(|i| alloc::format!("Metallium-OS system image, line {i:05}: the quick brown fox\n").into_bytes()).collect();
    let got = v.read_file("/system/usr/share/lorem.txt");
    println!("[client] TEST VFS read {} KB file from the compressed system image ({} bytes read): {}", lorem.len() / 1000,
        got.as_ref().map_or(0, |b| b.len()), verdict(got.map_or(false, |b| b == lorem)));

    let (root, sys) = (v.list("/").unwrap_or_default(), v.list("/system").unwrap_or_default());
    println!("[client] TEST VFS list / and /system ({:?} | {:?}): {}", root.replace('\n', " ").trim_end(),
        sys.replace('\n', " ").trim_end(), verdict(root == "system/\ndata/\n" && sys == "bin/\netc/\nhello.txt\nusr/\n"));

    let r1 = v.write_file("/system/x", b"1");
    let r2 = v.mkdir("/system/d");
    let r3 = v.unlink("/system/hello.txt");
    println!("[client] TEST VFS /system is read-only ({r1:?} {r2:?} {r3:?}): {}",
        verdict(r1 == Err(EROFS as i64) && r2 == Err(EROFS as i64) && r3 == Err(EROFS as i64)));

    // /data: nested directory, multi-block file
    let big: Vec<u8> = (0..10000).map(pat).collect();
    // a /data directory with more names than one page of a listing holds (60 names of 100 characters), listed in pieces
    let mut made = 0;
    let _ = v.mkdir("/data/wide");
    for i in 0..60 {
        if v.write_file(&alloc::format!("/data/wide/{i:0>100}"), b"x").is_ok() {
            made += 1;
        }
    }
    let first = v.list("/data/wide").map(|s| s.lines().count()).unwrap_or(0);
    let all = v.list_all("/data/wide").unwrap_or_default();
    let mut names: Vec<&str> = all.lines().collect();
    names.sort();
    names.dedup();
    println!("[client] TEST a /data directory of 60 long names is listed whole in pieces (made {made}, one page holds {first}, all pieces {}): {}", names.len(),
        verdict(made == 60 && first < 60 && names.len() == 60 && names[0].len() == 100));
    for i in 0..60 {
        let _ = v.unlink(&alloc::format!("/data/wide/{i:0>100}"));
    }
    let _ = v.unlink("/data/wide");

    let ok = v.mkdir("/data/docs").is_ok() && v.write_file("/data/docs/note.txt", &big).is_ok();
    let st = v.stat("/data/docs/note.txt");
    let back = v.read_file("/data/docs/note.txt");
    println!("[client] TEST VFS create+write+read /data/docs/note.txt (10000 bytes): {}",
        verdict(ok && st == Ok((1, 10000)) && back.map_or(false, |b| b == big)));

    // overwrite 100 bytes straddling a block boundary
    let fd = v.open("/data/docs/note.txt", O_READ | O_WRITE).unwrap_or(99);
    let ow = v.seek(fd, 4050).and_then(|_| v.write(fd, &[0xEE; 100])).and_then(|_| v.close(fd));
    let mut expect = big.clone();
    expect[4050..4150].fill(0xEE);
    let back = v.read_file("/data/docs/note.txt");
    println!("[client] TEST VFS overwrite across a block boundary: {}",
        verdict(ow.is_ok() && back.map_or(false, |b| b == expect)));

    let names = v.list("/data/docs").unwrap_or_default();
    let nonempty = v.unlink("/data/docs");
    let gone = v.unlink("/data/docs/note.txt").is_ok() && v.stat("/data/docs/note.txt") == Err(ENOENT as i64);
    let rmdir = v.unlink("/data/docs").is_ok();
    println!("[client] TEST VFS list, rmdir-nonempty refused, unlink, rmdir ({:?}): {}", names.trim_end(),
        verdict(names == "note.txt\n" && nonempty == Err(ENOTEMPTY as i64) && gone && rmdir));

    // --- crash consistency across the whole stack ---
    let keep = b"persist me across crashes";
    let wrote = v.write_file("/data/keep.txt", keep).is_ok();
    let stale = v.open("/data/keep.txt", O_READ).unwrap_or(99);
    let time_before = v.stat_time("/data/keep.txt", false).map(|(_, _, t)| t);
    let st = v.crash();
    let after = v.read_file("/data/keep.txt");
    let time_after = v.stat_time("/data/keep.txt", false).map(|(_, _, t)| t);
    println!("[client] TEST a file's modification time is in the table that survives a restart of the VFS ({time_before:?} before, {time_after:?} after): {}", verdict(time_before.is_ok() && time_before == time_after));
    let mut probe = [0u8; 4];
    let stale_read = v.read(stale, &mut probe);
    println!("[client] TEST VFS data survives vfs-server crash; old fd rejected (status={st}, stale={stale_read:?}): {}",
        verdict(wrote && st == E_DEAD && after.map_or(false, |b| b == keep) && stale_read == Err(EBADF as i64)));

    let _ = call(7, [43, 0, 0]); // crash lfs-server
    let _ = call(3, [BLK_CRASH, 0, 0]); // and the block driver under it
    let after = v.read_file("/data/keep.txt");
    let grown = v.write_file("/data/after.txt", b"written after the crashes").is_ok();
    println!("[client] TEST VFS data survives lfs-server + blk-driver crashes, writes still work: {}",
        verdict(after.map_or(false, |b| b == keep) && grown && v.read_file("/data/after.txt").map_or(false, |b| b == b"written after the crashes")));

    // --- replacing a file is atomic: a writer killed midway leaves the previous version, never a mixture ---
    let ver_a: Vec<u8> = (0..9000).map(|i| (i * 7 + 1) as u8).collect();
    let ver_b: Vec<u8> = (0..9000).map(|i| (i * 13 + 5) as u8).collect();
    let wrote_a = v.write_file("/data/cow.bin", &ver_a).is_ok();
    let began = v.open("/data/cow.bin", O_WRITE | O_TRUNC).and_then(|fd| v.write(fd, &ver_b[..5000]));
    let st = v.crash(); // the VFS dies with the rewrite half done; the LFS keeps what was staged
    let read_back = |path: &str| -> VResult<Vec<u8>> {
        let mut r = v.read_file(path);
        for _ in 0..100 {
            if !matches!(r, Err(e) if e == E_DEAD) {
                break; // anything but "the service is restarting" is an answer
            }
            sleep(3);
            r = v.read_file(path);
        }
        r
    };
    let after = read_back("/data/cow.bin");
    println!("[client] TEST an interrupted rewrite leaves the previous version of the file intact (crash status={st}, began={began:?}, {} bytes back): {}",
        after.as_ref().map_or(0, |b| b.len()), verdict(wrote_a && began.is_ok() && st == E_DEAD && after.map_or(false, |b| b == ver_a)));
    let redo = v.write_file("/data/cow.bin", &ver_b).is_ok();
    println!("[client] TEST a completed rewrite replaces the file, whatever the dead attempt left behind: {}",
        verdict(redo && read_back("/data/cow.bin").map_or(false, |b| b == ver_b)));

    // --- files are dense: blocks left by a dead writer never show through a sparse write ---
    let first = v.write_file("/data/sparse.bin", &[0xAA; 12288]).is_ok();
    let _ = v.open("/data/sparse.bin", O_WRITE | O_TRUNC).and_then(|fd| v.write(fd, &[0xBB; 12288]));
    let _ = v.crash(); // leaves 12 KiB of 0xBB staged in the shadow inode
    let sparse = (|| -> VResult<()> {
        let fd = {
            let mut r = v.open("/data/sparse.bin", O_WRITE | O_TRUNC);
            for _ in 0..100 {
                if !matches!(r, Err(e) if e == E_DEAD) {
                    break;
                }
                sleep(3);
                r = v.open("/data/sparse.bin", O_WRITE | O_TRUNC);
            }
            r?
        };
        v.write(fd, &[0x11])?;
        v.seek(fd, 10000)?;
        v.write(fd, &[0x22])?;
        v.close(fd)
    })();
    let mut want = vec![0u8; 10001];
    want[0] = 0x11;
    want[10000] = 0x22;
    println!("[client] TEST a sparse write reads back zeros in the gap, never data a dead writer left behind ({sparse:?}): {}",
        verdict(first && sparse.is_ok() && read_back("/data/sparse.bin").map_or(false, |b| b == want)));

    // --- a checkpoint that fails must not leave the table pointing at blocks the disk does not have ---
    // (found by the chaos test once swapping slowed the services down: a close whose checkpoint failed while the
    // store was being killed left the VFS serving the new size with the old version's blocks)
    let ck1: Vec<u8> = (0..3000).map(|i| (i * 3 + 1) as u8).collect();
    let ck2: Vec<u8> = (0..3300).map(|i| (i * 5 + 2) as u8).collect();
    let c1 = v.write_file("/data/ckpt.bin", &ck1).is_ok();
    let armed = v.fail_next_sync();
    let c2 = v.write_file("/data/ckpt.bin", &ck2); // the checkpoint at close fails
    let _ = call(7, [43, 0, 0]); // the store dies and restarts from its last checkpoint: the new blocks are gone
    let mut got = v.read_file("/data/ckpt.bin");
    for _ in 0..100 {
        if got.is_ok() {
            break;
        }
        sleep(3);
        got = v.read_file("/data/ckpt.bin");
    }
    println!("[client] TEST a failed checkpoint at close leaves the file at its old version, even after the store loses the new blocks (armed={armed}, write {c2:?}): {}",
        verdict(c1 && armed == 0 && c2.is_err() && got.map_or(false, |b| b == ck1)));
    let again = v.write_file("/data/ckpt.bin", &ck2).is_ok() && v.read_file("/data/ckpt.bin").map_or(false, |b| b == ck2);
    println!("[client] TEST the file takes a new version normally afterwards: {}", verdict(again));

    // --- the store restarting between a writer's writes and its close must fail the close ---
    // (found by the chaos test: the VFS retried the checkpoint against the restarted store, which had nothing staged
    // and so reported success, and the table then pointed at blocks that no longer existed)
    let ep1: Vec<u8> = (0..9000).map(|i| (i * 7 + 3) as u8).collect();
    let ep2: Vec<u8> = (0..9000).map(|i| (i * 11 + 5) as u8).collect();
    let e_ok = v.write_file("/data/epoch.bin", &ep1).is_ok();
    let staged = v.open("/data/epoch.bin", O_WRITE | O_TRUNC).and_then(|fd| v.write(fd, &ep2).map(|_| fd));
    let _ = call(7, [43, 0, 0]); // the store dies; its replacement has none of the staged blocks
    sleep(30);
    let closed = staged.and_then(|fd| v.close(fd));
    let mut got = v.read_file("/data/epoch.bin");
    for _ in 0..100 {
        if got.is_ok() {
            break;
        }
        sleep(3);
        got = v.read_file("/data/epoch.bin");
    }
    println!("[client] TEST a close after the store restarted fails and the file keeps its old version (close {closed:?}): {}",
        verdict(e_ok && closed.is_err() && got.map_or(false, |b| b == ep1)));
    sleep(320); // (the store restarts count against the same budget as the VFS crashes below)

    // --- a read the store cannot serve is an error, never a block of zeros ---
    // (found by the chaos test: a read that raced with the block driver being killed came back as zeros)
    let hole_file: Vec<u8> = (0..9000).map(|i| (i * 13 + 7) as u8).collect();
    let hw = v.write_file("/data/hole.bin", &hole_file).is_ok();
    let _ = call(7, [46, 0, 0]); // the store's next read fails with an I/O error
    let failed = v.read_file("/data/hole.bin");
    let fine = v.read_file("/data/hole.bin");
    println!("[client] TEST a read that fails inside the store is reported as an error, not returned as zeros (first {:?}, then {} bytes): {}",
        failed.as_ref().map(|b| b.len()), fine.as_ref().map_or(0, |b| b.len()),
        verdict(hw && failed.is_err() && fine.map_or(false, |b| b == hole_file)));

    // --- updating a file in place is atomic too: it happens completely, or not at all ---
    let open_retry = |path: &str, flags: u64| -> VResult<u64> {
        let mut r = v.open(path, flags);
        for _ in 0..100 {
            if !matches!(r, Err(e) if e == E_DEAD) {
                break;
            }
            sleep(3);
            r = v.open(path, flags);
        }
        r
    };
    // a service that crashes more than five times within 300 ticks is given up on: let this one run long enough
    // for its crash count to start over before the next burst of fault injection
    sleep(320);
    let old: Vec<u8> = (0..9000).map(|i| (i * 5 + 3) as u8).collect();
    let new: Vec<u8> = (0..9000).map(|i| (i * 11 + 9) as u8).collect();
    let wrote_old = v.write_file("/data/inplace.bin", &old).is_ok();
    // a writer overwrites all three blocks, then *another* client's checkpoint commits the half-done state
    // (every checkpoint covers every file), then the VFS dies before the writer closes
    let began = v.open("/data/inplace.bin", O_WRITE).and_then(|fd| v.write(fd, &new));
    let foreign = v.write_file("/data/other.bin", b"someone else's file, committed meanwhile").is_ok();
    let st = v.crash();
    let after = read_back("/data/inplace.bin");
    println!("[client] TEST an in-place update killed midway, even across another file's checkpoint, rolls back to the old content (crash status={st}, began={began:?}): {}",
        verdict(wrote_old && began.is_ok() && foreign && st == E_DEAD && after.map_or(false, |b| b == old)));
    println!("[client] TEST the other file's own commit survived the rollback: {}",
        verdict(read_back("/data/other.bin").map_or(false, |b| b == b"someone else's file, committed meanwhile")));

    // the same update, run to the end and closed, is durable
    let done = open_retry("/data/inplace.bin", O_WRITE).and_then(|fd| {
        v.write(fd, &new)?;
        v.close(fd)
    });
    let _ = v.crash();
    println!("[client] TEST a completed in-place update survives a VFS crash ({done:?}): {}",
        verdict(done.is_ok() && read_back("/data/inplace.bin").map_or(false, |b| b == new)));

    // growing a file in place and dying leaves it at its old size with its old last block
    let grown_ok = open_retry("/data/inplace.bin", O_WRITE).and_then(|fd| {
        v.seek(fd, 8990)?;
        v.write(fd, &[0xCD; 6000])?; // overwrites the end of the last block and adds two blocks
        Ok(fd)
    });
    let _ = v.write_file("/data/other.bin", b"another checkpoint");
    let _ = v.crash();
    let after = read_back("/data/inplace.bin");
    println!("[client] TEST growing a file in place and dying leaves its old size and content ({} bytes back): {}",
        after.as_ref().map_or(0, |b| b.len()), verdict(grown_ok.is_ok() && after.map_or(false, |b| b == new)));

    sleep(320);
    // a writer that never closes is rolled back by the next writer; the next writer's own update commits
    let a = v.open("/data/inplace.bin", O_WRITE).and_then(|fd| {
        v.write(fd, &[0x77; 5000])?;
        Ok(fd)
    });
    let b = v.open("/data/inplace.bin", O_WRITE).and_then(|fd| {
        v.write(fd, b"patched")?;
        v.close(fd)
    });
    let late = a.and_then(|fd| v.write(fd, b"zombie")); // the superseded writer is told off
    let mut want = new.clone();
    want[..7].copy_from_slice(b"patched");
    println!("[client] TEST the next writer rolls back an abandoned update and commits only its own ({b:?}, late write {late:?}): {}",
        verdict(b.is_ok() && late.is_err() && v.read_file("/data/inplace.bin").map_or(false, |x| x == want)));

    // an old session's leftovers never leak into a new one: die, recover, update one block, die again
    let first = v.open("/data/inplace.bin", O_WRITE).and_then(|fd| v.write(fd, &[0x11; 9000]));
    let _ = v.write_file("/data/other.bin", b"checkpoint 3");
    let _ = v.crash();
    let second = open_retry("/data/inplace.bin", O_WRITE).and_then(|fd| {
        v.seek(fd, 4096)?;
        v.write(fd, &[0x22; 4096])
    });
    let _ = v.write_file("/data/other.bin", b"checkpoint 4");
    let _ = v.crash();
    println!("[client] TEST sessions after a recovery start clean (first={first:?}, second={second:?}): {}",
        verdict(first.is_ok() && second.is_ok() && read_back("/data/inplace.bin").map_or(false, |x| x == want)));

    // unlinking a file with an update in progress leaves no trace and no confusion for a new file of that name
    let u = v.open("/data/inplace.bin", O_WRITE).and_then(|fd| v.write(fd, &[0x33; 100]));
    let gone = v.unlink("/data/inplace.bin").is_ok();
    let fresh = v.write_file("/data/inplace.bin", b"fresh").is_ok();
    let _ = v.crash();
    println!("[client] TEST unlink during an update, then a new file of the same name, then a crash: {}",
        verdict(u.is_ok() && gone && fresh && read_back("/data/inplace.bin").map_or(false, |x| x == b"fresh")));

    // --- sustained writing far beyond the partition's capacity needs the cleaner ---
    // A database-style workload: a 100-block file gets random single-block overwrites while a
    // second file is rewritten wholesale. Live blocks end up scattered across the log, so
    // free segments run out and the cleaner has to move data.
    let blockpat = |blk: usize, gen: u32| -> Vec<u8> { (0..4096).map(|i| (blk as u32 * 7 + gen * 13 + i as u32) as u8).collect() };
    let mut gens = vec![0u32; 100];
    let mut db = Vec::new();
    for b in 0..100 {
        db.extend_from_slice(&blockpat(b, 0));
    }
    let mut ok = v.write_file("/data/db.bin", &db).is_ok();
    let (_, s0) = call(7, [45, 0, 0]);
    let mut total = db.len();
    let mut rng = 12345u32;
    for round in 0..130u32 {
        let content: Vec<u8> = (0..49152).map(|i| (i as u32).wrapping_mul(31).wrapping_add(round) as u8).collect();
        ok &= v.write_file("/data/hot.bin", &content).is_ok();
        total += content.len();
        for _ in 0..2 {
            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            let b = (rng >> 16) as usize % 100;
            gens[b] += 1;
            let r = v.open("/data/db.bin", O_WRITE).and_then(|fd| {
                v.seek(fd, b as u64 * 4096)?;
                v.write(fd, &blockpat(b, gens[b]))?;
                v.close(fd)
            });
            ok &= r.is_ok();
            total += 4096;
        }
    }
    let (_, s1) = call(7, [45, 0, 0]);
    let hot_ok = v.read_file("/data/hot.bin").map_or(false, |b| {
        b.len() == 49152 && b.iter().enumerate().all(|(i, &x)| x == (i as u32).wrapping_mul(31).wrapping_add(129) as u8)
    });
    let db_ok = v.read_file("/data/db.bin").map_or(false, |b| {
        b.len() == 100 * 4096 && (0..100).all(|k| b[k * 4096..(k + 1) * 4096] == blockpat(k, gens[k])[..])
    });
    println!("[client] TEST VFS sustained writes ({} KiB into a 6 MiB partition): all ok={ok}, hot file intact={hot_ok}, db file intact={db_ok}, cleaner passes={}, blocks moved={}: {}",
        total / 1024, s1[0] - s0[0], s1[1] - s0[1], verdict(ok && hot_ok && db_ok && s1[0] > s0[0] && s1[1] > s0[1]));

    // --- the program task ran concurrently through the same VFS ---
    let mut seen = false;
    for _ in 0..200 {
        if v.stat("/data/program.done").is_ok() {
            seen = true;
            break;
        }
        sleep(5);
    }
    let log = v.read_file("/data/program.log").unwrap_or_default();
    println!("[client] TEST VFS program task's files are visible to other tasks ({} bytes): {}", log.len(),
        verdict(seen && log == b"line 0\nline 1\nline 2\nline 3\n"));
}

/// `make volume-test` (`opt/metallium/only=11`): the conductor drives the data volume's lock the way a greeter does and keeps a marker file on it, so that a host script
/// can boot one disk several times (with and without the machine's secret) and check what is on the disk and what can be read back. Prints `[vol] ...` lines.
pub fn volume_test() {
    use proto::volume::*;
    const PHRASE: &[u8] = b"hunter2-correct horse";
    const MARKER: &[u8] = b"TOP-SECRET-PAYLOAD-0123456789-metallium";
    fn send(op: u64, word: &[u8]) -> u64 {
        let mut last = 5;
        for off in (0..word.len()).step_by(16) {
            let mut chunk = [0u8; 16];
            let n = (word.len() - off).min(16);
            chunk[..n].copy_from_slice(&word[off..off + n]);
            let w1 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            let w2 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
            let (st, r) = call(7, [op | (word.len() as u64) << 8 | (off as u64) << 24, w1, w2]);
            last = if st == 0 { r[0] } else { 100 };
            if last != MORE {
                break;
            }
        }
        last
    }
    let (_, r) = call(7, [LFS_STATUS, 0, 0]);
    println!("[vol] state {} flags {}", r[0], r[1]);
    if r[0] == state::LOCKED {
        println!("[vol] wrong passphrase: {}", send(LFS_UNLOCK, b"not the passphrase"));
        println!("[vol] wrong long passphrase: {}", send(LFS_UNLOCK, &[b'x'; 100]));
        println!("[vol] unlock: {}", send(LFS_UNLOCK, PHRASE));
        let (_, r) = call(7, [LFS_STATUS, 0, 0]);
        println!("[vol] state after unlock {} flags {}", r[0], r[1]);
    }
    let (_, r) = call(7, [LFS_STATUS, 0, 0]);
    if r[0] != state::UNLOCKED && r[0] != state::PLAIN {
        println!("[vol] volume stays shut (state {})", r[0]);
        return;
    }
    let flags = r[1];
    let m = mem_map(10, C_VFS_SHM, true);
    if m != 0 && m != E_INVAL {
        println!("[vol] cannot map the VFS page");
        return;
    }
    let v = Vfs::new(9, C_VFS_SHM);
    match v.read_file("/data/secret.txt") {
        Ok(b) if b == MARKER => println!("[vol] marker read back: OK"),
        Ok(_) => println!("[vol] marker read back: WRONG CONTENT"),
        Err(_) => {
            let w = v.write_file("/data/secret.txt", MARKER);
            let (_, _) = call(9, [59, 0, 0]); // V_SYNC
            println!("[vol] marker written: {}", if w.is_ok() { "OK" } else { "FAILED" });
        }
    }
    if r[0] == state::UNLOCKED && flags & 1 == 0 {
        println!("[vol] set passphrase: {}", send(LFS_SET_PASSPHRASE, PHRASE));
    }
    // a file call while open must still work after all this
    println!("[vol] done");
}

const C_LFS_SHM2: usize = 0x8035_0000;

/// `make table-test` (`opt/metallium/only=12`): the directory table of `/data`. A table in the older layout (one block, 51 entries) is still read and the next commit
/// writes the new one; the new one holds hundreds of entries across a restart, and more than the 1024 it once held; long paths work up to the limit.
pub fn table_test() {
    fn verdict_line(what: &str, ok: bool) {
        println!("[table] TEST {what}: {}", if ok { "PASS" } else { "FAIL" });
    }
    let m = mem_map(10, C_VFS_SHM, true);
    let l = mem_map(8, C_LFS_SHM2, true);
    if (m != 0 && m != E_INVAL) || (l != 0 && l != E_INVAL) {
        println!("[table] cannot map the pages");
        return;
    }
    let v = Vfs::new(9, C_VFS_SHM);
    let sync = || {
        let _ = call(9, [V_SYNC, 0, 0]);
    };
    // ---- an older-layout table: written to the store behind the VFS's back, then the VFS restarts and reads it
    // SAFETY: C_LFS_SHM2 is the conductor's page of the data store (mapped above); the store reads it only while this task is blocked in `call`.
    let pg = unsafe { &mut *(va(C_LFS_SHM2) as *mut [u8; 4096]) };
    pg.fill(0);
    pg[0..4].copy_from_slice(&MAGIC_V2.to_le_bytes());
    pg[4..8].copy_from_slice(&0x5002u32.to_le_bytes()); // next inode
    pg[8..12].copy_from_slice(&1u32.to_le_bytes()); // next generation
    let name = b"/old.txt";
    pg[16..16 + name.len()].copy_from_slice(name);
    pg[16 + 64..16 + 68].copy_from_slice(&0x5000u32.to_le_bytes()); // inode
    pg[16 + 68] = KIND_FILE;
    pg[16 + 72..16 + 80].copy_from_slice(&5u64.to_le_bytes()); // size
    let (st1, _) = call(7, [LFS_PUT, META_KEY, 0]);
    pg.fill(0);
    pg[..5].copy_from_slice(b"hello");
    let (st2, _) = call(7, [LFS_PUT, key(0x5000, 0), 0]);
    let (st3, _) = call(7, [LFS_SYNC, 0, 0]);
    let _ = v.crash(); // (the VFS restarts and loads what the store holds now)
    let old = v.read_file("/data/old.txt");
    verdict_line("a table in the older layout (51 entries, 64-byte paths) is read", st1 == 0 && st2 == 0 && st3 == 0 && old.as_ref().map_or(false, |b| b == b"hello"));
    let w = v.write_file("/data/new.txt", b"second");
    sync();
    let _ = v.crash();
    let (a, b) = (v.read_file("/data/old.txt"), v.read_file("/data/new.txt"));
    verdict_line(
        "the next commit writes the new layout, and the old file and the new one survive a restart",
        w.is_ok() && a.map_or(false, |x| x == b"hello") && b.map_or(false, |x| x == b"second"),
    );
    // ---- hundreds of entries
    let made = v.mkdir("/data/many").is_ok();
    let mut ok = made;
    for i in 0..300 {
        ok &= v.write_file(&alloc::format!("/data/many/f{i:03}"), alloc::format!("file {i}").as_bytes()).is_ok();
    }
    sync();
    let count = |v: &Vfs| v.list("/data/many").map_or(0, |l| l.lines().count());
    verdict_line("300 files in one directory (the table used to hold 51 entries in all)", ok && count(&v) == 300);
    let _ = v.crash();
    let again = count(&v) == 300 && v.read_file("/data/many/f299").map_or(false, |b| b == b"file 299");
    verdict_line("... and they are all there after a restart (the table spans several blocks)", again);
    let mut gone = true;
    for i in 0..150 {
        gone &= v.unlink(&alloc::format!("/data/many/f{i:03}")).is_ok();
    }
    sync();
    let _ = v.crash();
    verdict_line("removing half of them is kept across a restart", gone && count(&v) == 150 && v.read_file("/data/many/f000").is_err() && v.read_file("/data/many/f200").is_ok());
    // ---- more than the table used to hold (1024 entries for the whole machine)
    let mut ok = v.mkdir("/data/big").is_ok();
    for i in 0..1500 {
        ok &= v.write_file(&alloc::format!("/data/big/g{i:04}"), alloc::format!("g{i}").as_bytes()).is_ok();
    }
    sync();
    let big_count = |v: &Vfs| v.list_all("/data/big").map_or(0, |l| l.lines().count());
    verdict_line("1500 more files, more entries in all than the 1024 the table used to hold", ok && big_count(&v) == 1500);
    let _ = v.crash();
    verdict_line("... all there after a restart, in the blocks that table never had", big_count(&v) == 1500 && v.read_file("/data/big/g1499").map_or(false, |b| b == b"g1499") && v.read_file("/data/many/f299").map_or(false, |b| b == b"file 299"));
    // ---- long paths
    let mut dir = String::from("/data");
    let mut deep = true;
    while dir.len() + 12 < 92 {
        dir.push_str("/dddddddddd"); // 11 bytes a level
        deep &= v.mkdir(&dir).is_ok();
    }
    let long = alloc::format!("{dir}/file-with-a-longer-name.txt");
    let w = v.write_file(&long, b"deep");
    let too_long = alloc::format!("{dir}/{}", "x".repeat(60));
    verdict_line(
        &alloc::format!("a path of {} bytes works and one past the limit is refused", long.len()),
        deep && long.len() > 100 && long.len() < PATH_MAX && w.is_ok() && v.read_file(&long).map_or(false, |b| b == b"deep") && v.write_file(&too_long, b"x").is_err(),
    );
    println!("[table] done");
}
