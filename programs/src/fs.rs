//! File access for programs started with file-system access: the VFS endpoint is slot 8, the session page slot 9.
//! The protocol is the VFS's (one request at a time; paths and data travel through the session page).
use crate::call;

const EP: u64 = 8;
const PAGE_SLOT: u64 = 9;
/// Where the session page is mapped (the kernel chooses; 0 until it is).
static VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn va() -> usize {
    VA.load(core::sync::atomic::Ordering::Relaxed)
}
const DATA: usize = 256;
const MAXIO: usize = 4096 - DATA;

const V_OPEN: u64 = 50;
const V_READ: u64 = 51;
const V_WRITE: u64 = 52;
const V_CLOSE: u64 = 54;
const V_STAT: u64 = 55;
const V_LIST: u64 = 56;
const V_LIST_AT: u64 = 65;
const V_STAT_TIME: u64 = 68;
const V_LOCK: u64 = 69;
const V_LSTAT: u64 = 66;
const V_READLINK: u64 = 67;
const V_UNLINK: u64 = 57;
const V_MKDIR: u64 = 58;
const V_SYNC: u64 = 59;
const V_SCOPE: u64 = 62;
const V_MKDIR_DOMAIN: u64 = 64;
const V_RENAME: u64 = 63;

pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;

/// An error: a kernel status (negative: the IPC itself failed) or a VFS status (ENOENT 1, EISDIR 2, EBADF 3, EROFS 4,
/// ENOSPC 5, EINVAL 6, EIO 7, EEXIST 8, ENOTEMPTY 9).
pub type Error = i64;

/// Map the session page if it is not yet (the file lock is held).
fn map_session() -> Result<(), i64> {
    if va() == 0 {
        let r = crate::map_anywhere(PAGE_SLOT, true);
        if r < 0 {
            return Err(r);
        }
        VA.store(r as usize, core::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// A handle to the program's file session. One session page serves the whole program, so every call takes the program's
/// file lock: handles may be used from any thread, one request at a time.
pub struct Fs(());

impl Fs {
    /// Map the session page. Fails (with the kernel's error) if the program was started without file-system access.
    pub fn open() -> Result<Fs, i64> {
        LOCK.lock();
        let r = map_session();
        LOCK.unlock();
        r.map(|_| Fs(()))
    }

    fn with<T>(&self, f: impl FnOnce(&Sess) -> T) -> T {
        LOCK.lock();
        let r = f(&Sess(()));
        LOCK.unlock();
        r
    }

    pub fn open_file(&self, path: &str, flags: u64) -> Result<u64, Error> {
        self.with(|s| s.open_file(path, flags))
    }

    pub fn close(&self, fd: u64) -> Result<(), Error> {
        self.with(|s| s.close(fd))
    }

    /// Read up to `buf.len()` bytes; the number read (0 at the end of the file).
    pub fn read(&self, fd: u64, buf: &mut [u8]) -> Result<usize, Error> {
        self.with(|s| s.read(fd, buf))
    }

    pub fn write(&self, fd: u64, data: &[u8]) -> Result<usize, Error> {
        self.with(|s| s.write(fd, data))
    }

    /// (size, kind) of a path: kind 1 = file, 2 = directory.
    pub fn stat(&self, path: &str) -> Result<(u64, u64), Error> {
        self.with(|s| s.stat(path))
    }

    /// See `Session::flock`.
    pub fn flock(&self, fd: u64, op: u64) -> Result<(), Error> {
        self.with(|s| s.flock(fd, op))
    }

    /// See `Session::lstat`.
    pub fn lstat(&self, path: &str) -> Result<(u64, u64), Error> {
        self.with(|s| s.lstat(path))
    }

    /// See `Session::stat_time`.
    pub fn stat_time(&self, path: &str, nofollow: bool) -> Result<(u64, u64, u64), Error> {
        self.with(|s| s.stat_time(path, nofollow))
    }

    /// See `Session::readlink`.
    pub fn readlink(&self, path: &str, buf: &mut [u8]) -> Result<usize, Error> {
        self.with(|s| s.readlink(path, buf))
    }

    /// The names in a directory, '\n'-separated, into `buf`; the number of bytes.
    pub fn list(&self, path: &str, buf: &mut [u8]) -> Result<usize, Error> {
        self.with(|s| s.list(path, buf))
    }

    /// See `Session::list_at`.
    pub fn list_at(&self, path: &str, cursor: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.with(|s| s.list_at(path, cursor, buf))
    }

    pub fn unlink(&self, path: &str) -> Result<(), Error> {
        self.with(|s| s.unlink(path))
    }

    pub fn mkdir(&self, path: &str) -> Result<(), Error> {
        self.with(|s| s.mkdir(path))
    }

    /// Move a file, or a directory with everything in it, to a new path on the same disk (one commit: all or nothing).
    pub fn rename(&self, from: &str, to: &str) -> Result<(), Error> {
        self.with(|s| s.rename(from, to))
    }

    /// Have everything written so far put on the disk (a checkpoint of the whole data partition).
    pub fn sync(&self) -> Result<(), Error> {
        self.with(|s| s.sync())
    }

    /// Confine the program `child` (one this program started, not yet running) to the directory `dir`: its `/data` becomes `dir`.
    pub fn scope(&self, child: u64, dir: &str) -> Result<(), Error> {
        self.with(|s| s.scope(child, dir, 0))
    }

    /// Whole-file write (created or truncated; the close commits it).
    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), Error> {
        self.with(|s| s.write_file(path, data))
    }
}

struct Sess(());

impl Sess {
    /// Copy `src` into the session page at `off`. The page is shared with the VFS server, so it is only touched through raw
    /// pointers and only while the program's file lock is held (one request at a time).
    fn put(&self, off: usize, src: &[u8]) {
        assert!(off + src.len() <= 4096);
        // SAFETY: `va()` is the mapped 4096-byte session page (Sess exists only after a successful map); the range is checked
        // above; `src` is a caller slice that cannot overlap the foreign page.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (va() as *mut u8).add(off), src.len()) }
    }

    fn put_byte(&self, off: usize, b: u8) {
        self.put(off, &[b]);
    }

    /// Copy from the session page at `off` into `dst`.
    fn get(&self, off: usize, dst: &mut [u8]) {
        assert!(off + dst.len() <= 4096);
        // SAFETY: as in `put`.
        unsafe { core::ptr::copy_nonoverlapping((va() as *const u8).add(off), dst.as_mut_ptr(), dst.len()) }
    }

    fn rpc(&self, op: u64, a: u64, b: u64) -> Result<(u64, u64), Error> {
        let (st, r) = call(EP, [op, a, b]);
        if st != 0 {
            return Err(st);
        }
        if r[0] != 0 {
            return Err(r[0] as i64);
        }
        Ok((r[1], r[2]))
    }

    fn with_path(&self, path: &str, op: u64, a: u64) -> Result<(u64, u64), Error> {
        if path.len() >= DATA {
            return Err(6);
        }
        self.put(0, path.as_bytes());
        self.put_byte(path.len(), 0);
        self.rpc(op, a, 0)
    }

    fn open_file(&self, path: &str, flags: u64) -> Result<u64, Error> {
        self.with_path(path, V_OPEN, flags).map(|r| r.0)
    }

    fn close(&self, fd: u64) -> Result<(), Error> {
        self.rpc(V_CLOSE, fd, 0).map(|_| ())
    }

    /// Read up to `buf.len()` bytes; the number read (0 at the end of the file).
    fn read(&self, fd: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let mut done = 0;
        while done < buf.len() {
            let want = (buf.len() - done).min(MAXIO);
            let (n, _) = self.rpc(V_READ, fd, want as u64)?;
            if n == 0 {
                break;
            }
            self.get(DATA, &mut buf[done..done + n as usize]);
            done += n as usize;
        }
        Ok(done)
    }

    fn write(&self, fd: u64, data: &[u8]) -> Result<usize, Error> {
        let mut done = 0;
        while done < data.len() {
            let n = (data.len() - done).min(MAXIO);
            self.put(DATA, &data[done..done + n]);
            let (wrote, _) = self.rpc(V_WRITE, fd, n as u64)?;
            done += wrote as usize;
        }
        Ok(done)
    }

    /// (size, kind) of a path: kind 1 = file, 2 = directory.
    fn stat(&self, path: &str) -> Result<(u64, u64), Error> {
        self.with_path(path, V_STAT, 0)
    }

    /// An advisory lock on the open file `fd`: `op` 1 shared, 2 exclusive, 3 unlock; status 12 when someone else holds a conflicting one.
    fn flock(&self, fd: u64, op: u64) -> Result<(), Error> {
        self.rpc(V_LOCK, fd, op).map(|_| ())
    }

    /// `stat` without following a symbolic link in the last component: kind 3 = a link, its size the length of its target.
    fn lstat(&self, path: &str) -> Result<(u64, u64), Error> {
        self.with_path(path, V_LSTAT, 0)
    }

    /// (size, kind, modification time in seconds since 1970 or 0) of a path, optionally not following a symbolic link in its last component.
    fn stat_time(&self, path: &str, nofollow: bool) -> Result<(u64, u64, u64), Error> {
        let (size, kt) = self.with_path(path, V_STAT_TIME, nofollow as u64)?;
        Ok((size, kt & 0xFF, kt >> 8))
    }

    /// The target of a symbolic link, into `buf`: the number of bytes.
    fn readlink(&self, path: &str, buf: &mut [u8]) -> Result<usize, Error> {
        let (n, _) = self.with_path(path, V_READLINK, 0)?;
        let n = (n as usize).min(buf.len()).min(MAXIO);
        self.get(DATA, &mut buf[..n]);
        Ok(n)
    }

    /// The names in a directory, '\n'-separated, into `buf`; the number of bytes.
    fn list(&self, path: &str, buf: &mut [u8]) -> Result<usize, Error> {
        let (n, _) = self.with_path(path, V_LIST, 0)?;
        let n = (n as usize).min(buf.len()).min(MAXIO);
        self.get(DATA, &mut buf[..n]);
        Ok(n)
    }

    /// The next piece of a directory's names after the first `cursor` (whole names, '\n'-separated), into `buf`: the number of bytes and whether there are more.
    fn list_at(&self, path: &str, cursor: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        let (n, more) = self.with_path(path, V_LIST_AT, cursor)?;
        let n = (n as usize).min(buf.len()).min(MAXIO);
        self.get(DATA, &mut buf[..n]);
        Ok((n, more != 0))
    }

    fn unlink(&self, path: &str) -> Result<(), Error> {
        self.with_path(path, V_UNLINK, 0).map(|_| ())
    }

    fn mkdir(&self, path: &str) -> Result<(), Error> {
        self.with_path(path, V_MKDIR, 0).map(|_| ())
    }

    /// Move a file, or a directory with everything in it, to a new path on the same disk (one commit: all or nothing).
    fn rename(&self, from: &str, to: &str) -> Result<(), Error> {
        if from.len() + to.len() + 2 > DATA {
            return Err(6);
        }
        self.put(0, from.as_bytes());
        self.put_byte(from.len(), 0);
        self.put(from.len() + 1, to.as_bytes());
        self.put_byte(from.len() + 1 + to.len(), 0);
        self.rpc(V_RENAME, 0, 0).map(|_| ())
    }

    /// Have everything written so far put on the disk (a checkpoint of the whole data partition).
    fn sync(&self) -> Result<(), Error> {
        self.rpc(V_SYNC, 0, 0).map(|_| ())
    }

    /// Confine the program `child` (one this program started, not yet running) to the directory `dir`: its `/data` becomes `dir`. `quota`: the entries (files and
    /// directories) it may have there, 0 for the default.
    fn scope(&self, child: u64, dir: &str, quota: u64) -> Result<(), Error> {
        if dir.len() >= DATA {
            return Err(6);
        }
        self.put(0, dir.as_bytes());
        self.put_byte(dir.len(), 0);
        self.rpc(V_SCOPE, child, quota).map(|_| ())
    }

    /// Whole-file write (created or truncated; the close commits it).
    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), Error> {
        let fd = self.open_file(path, O_WRITE | O_CREATE | O_TRUNC)?;
        let r = self.write(fd, data);
        self.close(fd)?;
        r.map(|_| ())
    }
}

// ---- the std-like layer ---------------------------------------------------------------------------------------------------
//
// One session page serves the whole program, so every operation takes the program's file lock: threads may use files
// freely, one request at a time.
use crate::io::{self, ErrorKind};
use crate::thread::Mutex as RawMutex;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

static LOCK: RawMutex = RawMutex::new();
static OPENED: AtomicU8 = AtomicU8::new(0); // 0 not yet, 1 mapped, 2 no file access

fn to_io(e: Error) -> io::Error {
    if e < 0 {
        io::Error::from_kernel(e)
    } else {
        io::Error::from_vfs(e)
    }
}

/// Run `f` on the program's session, mapping it first if need be.
fn session<T>(f: impl FnOnce(&Sess) -> Result<T, Error>) -> io::Result<T> {
    LOCK.lock();
    if OPENED.load(Ordering::Relaxed) == 0 {
        OPENED.store(if map_session().is_ok() { 1 } else { 2 }, Ordering::Relaxed);
    }
    let r = if OPENED.load(Ordering::Relaxed) == 1 { f(&Sess(())).map_err(to_io) } else { Err(io::Error::new(ErrorKind::PermissionDenied)) };
    LOCK.unlock();
    r
}

#[derive(Clone, Copy, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions { read: false, write: false, create: false, truncate: false }
    }
    pub fn read(&mut self, v: bool) -> &mut OpenOptions {
        self.read = v;
        self
    }
    pub fn write(&mut self, v: bool) -> &mut OpenOptions {
        self.write = v;
        self
    }
    pub fn create(&mut self, v: bool) -> &mut OpenOptions {
        self.create = v;
        self
    }
    pub fn truncate(&mut self, v: bool) -> &mut OpenOptions {
        self.truncate = v;
        self
    }

    pub fn open(&self, path: &str) -> io::Result<File> {
        let flags = (if self.read { O_READ } else { 0 }) | (if self.write { O_WRITE } else { 0 }) | (if self.create { O_CREATE } else { 0 }) | (if self.truncate { O_TRUNC } else { 0 });
        let fd = session(|fs| fs.open_file(path, flags))?;
        Ok(File { fd, pos: 0, path: String::from(path) })
    }
}

/// An open file. Closing (on drop, or `close`) is what commits a written file.
pub struct File {
    fd: u64,
    pos: u64,
    path: String,
}

#[derive(Clone, Copy, Debug)]
pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

/// The state of an advisory lock request that did not wait: someone else holds a conflicting lock on the file.
pub const EAGAIN: i64 = 12;

impl File {
    /// An advisory lock on this file (like `flock` with `LOCK_NB`): shared, or exclusive. It never waits: `ErrorKind::WouldBlock` if another open file holds a
    /// conflicting lock (retry later, as a blocking lock does by polling). Asking again converts the lock. It is released by `unlock`, when the file is closed or
    /// when the program ends.
    pub fn try_lock(&self, exclusive: bool) -> io::Result<()> {
        match session(|fs| fs.flock(self.fd, if exclusive { 2 } else { 1 })) {
            Err(e) if e.code == EAGAIN => Err(io::Error { kind: ErrorKind::WouldBlock, code: EAGAIN }),
            r => r,
        }
    }

    pub fn unlock(&self) -> io::Result<()> {
        session(|fs| fs.flock(self.fd, 3))
    }

    pub fn open(path: &str) -> io::Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    /// Create (or empty) a file for writing.
    pub fn create(path: &str) -> io::Result<File> {
        OpenOptions::new().write(true).create(true).truncate(true).open(path)
    }

    pub fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => metadata(&self.path)?.len.checked_add_signed(d),
        }
        .ok_or(io::Error::new(ErrorKind::InvalidInput))?;
        session(|fs| fs.rpc(V_SEEK, self.fd, target))?;
        self.pos = target;
        Ok(target)
    }

    /// Close the file, reporting whether the commit succeeded (dropping it ignores the answer).
    pub fn close(mut self) -> io::Result<()> {
        let fd = core::mem::replace(&mut self.fd, u64::MAX);
        session(|fs| fs.close(fd))
    }
}

const V_SEEK: u64 = 53;

impl Drop for File {
    fn drop(&mut self) {
        if self.fd != u64::MAX {
            let fd = self.fd;
            let _ = session(|fs| fs.close(fd));
        }
    }
}

impl io::Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.fd;
        let n = session(|fs| fs.read(fd, buf))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl io::Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let fd = self.fd;
        let n = session(|fs| fs.write(fd, buf))?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Metadata {
    pub len: u64,
    pub is_dir: bool,
    /// A symbolic link (only from `symlink_metadata`: `metadata` follows links); `len` is then the length of its target.
    pub is_symlink: bool,
    /// When it was last changed, in seconds since 1970; 0 if not known (files of the system image have none, and neither has a machine without a clock).
    pub modified: u64,
}

impl Metadata {
    pub fn is_file(&self) -> bool {
        !self.is_dir && !self.is_symlink
    }
    pub fn is_symlink(&self) -> bool {
        self.is_symlink
    }
}

/// Information about a path, following symbolic links.
pub fn metadata(path: &str) -> io::Result<Metadata> {
    let (len, kind, modified) = session(|fs| fs.stat_time(path, false))?;
    Ok(Metadata { len, is_dir: kind == 2, is_symlink: false, modified })
}

/// Information about a path itself: a symbolic link in its last component is not followed.
pub fn symlink_metadata(path: &str) -> io::Result<Metadata> {
    let (len, kind, modified) = session(|fs| fs.stat_time(path, true))?;
    Ok(Metadata { len, is_dir: kind == 2, is_symlink: kind == 3, modified })
}

/// The target of a symbolic link (`InvalidInput` if the path is not one).
pub fn read_link(path: &str) -> io::Result<String> {
    let mut buf = alloc::vec![0u8; MAXIO];
    let n = session(|fs| fs.readlink(path, &mut buf))?;
    String::from_utf8(buf[..n].to_vec()).map_err(|_| io::Error::new(ErrorKind::InvalidData))
}

pub fn exists(path: &str) -> bool {
    metadata(path).is_ok()
}

/// The whole file.
pub fn read(path: &str) -> io::Result<Vec<u8>> {
    use io::Read;
    let len = metadata(path)?.len as usize;
    let mut f = File::open(path)?;
    let mut v = Vec::with_capacity(len);
    f.read_to_end(&mut v)?;
    Ok(v)
}

pub fn read_to_string(path: &str) -> io::Result<String> {
    String::from_utf8(read(path)?).map_err(|_| io::Error::new(ErrorKind::InvalidData))
}

/// Replace (or create) a file with `data`; the answer says whether it was committed.
pub fn write(path: &str, data: &[u8]) -> io::Result<()> {
    use io::Write;
    let mut f = File::create(path)?;
    f.write_all(data)?;
    f.close()
}

pub fn remove_file(path: &str) -> io::Result<()> {
    session(|fs| fs.unlink(path))
}

/// Remove an empty directory.
pub fn remove_dir(path: &str) -> io::Result<()> {
    session(|fs| fs.unlink(path))
}

pub fn create_dir(path: &str) -> io::Result<()> {
    session(|fs| fs.mkdir(path))
}

/// Move or rename a file or a directory (with everything in it) on the data disk.
pub fn rename(from: &str, to: &str) -> io::Result<()> {
    session(|fs| fs.rename(from, to))
}

/// Have every file written so far reach the disk (before the machine is switched off or restarted).
pub fn sync() -> io::Result<()> {
    session(|fs| fs.sync())
}

/// Make a directory whose files are sealed under the encryption domain `domain` (1..=63): only an unconfined program may (the session service, for a new account's home).
pub fn create_dir_in_domain(path: &str, domain: u64) -> io::Result<()> {
    session(|fs| fs.with_path(path, V_MKDIR_DOMAIN, domain).map(|_| ()))
}

/// Confine a program this one has just started (and that has not run yet) to `dir`: for it, `/data` is `dir`. See `Command::scope`.
pub fn scope(child: u64, dir: &str) -> io::Result<()> {
    session(|fs| fs.scope(child, dir, 0))
}

/// The same with an entry quota (0: the default). `dir` may be `/data`: "the same as mine" (a confined program hands its own confinement on; an unconfined one leaves the child unconfined).
pub fn scope_with_quota(child: u64, dir: &str, quota: u64) -> io::Result<()> {
    session(|fs| fs.scope(child, dir, quota))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

/// The entries of a directory (directories are listed with a trailing '/' by the VFS).
pub fn read_dir(path: &str) -> io::Result<Vec<DirEntry>> {
    // (a directory is read in pieces of a page, each from where the last ended, so a directory of any size comes out whole)
    let mut buf = alloc::vec![0u8; MAXIO];
    let (mut out, mut cursor) = (Vec::new(), 0u64);
    loop {
        let (n, more) = session(|fs| fs.list_at(path, cursor, &mut buf))?;
        let text = core::str::from_utf8(&buf[..n]).map_err(|_| io::Error::new(ErrorKind::InvalidData))?;
        for s in text.split('\n').filter(|s| !s.is_empty()) {
            cursor += 1;
            out.push(match s.strip_suffix('/') {
                Some(d) => DirEntry { name: String::from(d), is_dir: true },
                None => DirEntry { name: String::from(s), is_dir: false },
            });
        }
        if !more || n == 0 {
            return Ok(out);
        }
    }
}
