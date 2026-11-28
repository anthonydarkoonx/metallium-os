//! Read-only EROFS reader (subset). Provenance: see `PROVENANCE.md` and the
//! header of `zmap.rs`. Checked against images produced by the reference
//! `mkfs.erofs`, used only as a black-box test oracle (`tests/real_images.rs`).
//!
//! Supported: compact + extended inodes; flat-plain and flat-inline data;
//! LZ4- and ZSTD-compressed files (per extent, so images mixing both work) in
//! both the compact and the legacy "full" index layouts, including big
//! physical clusters; directories and path lookup. Rejected with
//! `Error::Unsupported`: chunk-based layout, tail-packing / fragments /
//! interlaced clusters, other algorithms (MicroLZMA, DEFLATE), and single
//! compressed extents larger than 1 MiB.
//!
//! The uncompressed path needs no heap. Reading compressed files allocates
//! one buffer per decompressed extent (cached, last extent only).
#![forbid(unsafe_code)]
#![no_std]
extern crate alloc;

mod zmap;

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

pub const MAGIC: u32 = 0xE0F5_E1E2;
const SB_OFF: u64 = 1024;
const DIRENT_SZ: usize = 12;
const MAX_BLK: usize = 4096;
const INCOMPAT_LZ4_0PADDING: u32 = 1;

const LAYOUT_PLAIN: u8 = 0;
const LAYOUT_COMPRESSED_FULL: u8 = 1;
const LAYOUT_INLINE: u8 = 2;
const LAYOUT_COMPRESSED_COMPACT: u8 = 3;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFLNK: u16 = 0o120000;
/// Most symbolic links `Erofs::resolve` follows in one path (a longer chain, or a loop, is `Error::TooManyLinks`).
pub const MAX_LINKS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    BadMagic,
    Unsupported,
    Corrupt,
    NotFound,
    NotDir,
    /// More than `MAX_LINKS` symbolic links met while resolving a path (a loop, or a very long chain).
    TooManyLinks,
    /// `readlink` of something that is not a symbolic link.
    NotLink,
}

/// Backing storage (flash partition, RAM image, ...).
pub trait Source {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), Error>;
}

impl Source for &[u8] {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), Error> {
        let start = usize::try_from(off).map_err(|_| Error::Io)?;
        let end = start.checked_add(buf.len()).ok_or(Error::Io)?;
        buf.copy_from_slice(self.get(start..end).ok_or(Error::Io)?);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Inode {
    pub nid: u64,
    pub mode: u16,
    pub size: u64,
    layout: u8,
    raw_blkaddr: u32,
    /// Byte offset just past the inode and its xattr area (inline data / z-map header start here).
    inline_off: u64,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

pub struct Erofs<S> {
    src: S,
    blksz: u64,
    meta_blkaddr: u64,
    root_nid: u64,
    lz4_0padding: bool,
    /// Compressed-file caches (see zmap.rs).
    z: RefCell<zmap::Cache>,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl<S: Source> Erofs<S> {
    pub fn new(src: S) -> Result<Self, Error> {
        let mut sb = [0u8; 128];
        src.read_at(SB_OFF, &mut sb)?;
        if le32(&sb, 0) != MAGIC {
            return Err(Error::BadMagic);
        }
        let bits = sb[12];
        if !(9..=12).contains(&bits) {
            return Err(Error::Unsupported);
        }
        Ok(Erofs {
            src,
            blksz: 1 << bits,
            meta_blkaddr: le32(&sb, 40) as u64,
            root_nid: le16(&sb, 14) as u64,
            lz4_0padding: le32(&sb, 80) & INCOMPAT_LZ4_0PADDING != 0,
            z: RefCell::new(zmap::Cache::default()),
        })
    }

    pub fn root(&self) -> Result<Inode, Error> {
        self.inode(self.root_nid)
    }

    pub fn inode(&self, nid: u64) -> Result<Inode, Error> {
        let addr = self.meta_blkaddr * self.blksz + nid * 32;
        let mut raw = [0u8; 64];
        self.src.read_at(addr, &mut raw[..32])?;
        let format = le16(&raw, 0);
        let extended = format & 1 == 1;
        let layout = ((format >> 1) & 7) as u8;
        let xattr_icount = le16(&raw, 2) as u64;
        let (isize, size) = if extended {
            self.src.read_at(addr + 32, &mut raw[32..64])?;
            (64u64, le64(&raw, 8))
        } else {
            (32u64, le32(&raw, 8) as u64)
        };
        if !matches!(layout, LAYOUT_PLAIN | LAYOUT_INLINE | LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT) {
            return Err(Error::Unsupported);
        }
        let xsize = if xattr_icount > 0 { 12 + 4 * (xattr_icount - 1) } else { 0 };
        Ok(Inode {
            nid,
            mode: le16(&raw, 4),
            size,
            layout,
            raw_blkaddr: le32(&raw, 16),
            inline_off: addr + isize + xsize,
        })
    }

    /// Read file/dir data at `off`; returns bytes read (short at EOF).
    pub fn read(&self, ino: &Inode, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if matches!(ino.layout, LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT) {
            return self.read_compressed(ino, off, buf);
        }
        let mut pos = off;
        let mut done = 0usize;
        while done < buf.len() && pos < ino.size {
            let bi = pos / self.blksz;
            let in_blk = pos % self.blksz;
            let n = (buf.len() - done)
                .min((self.blksz - in_blk) as usize)
                .min((ino.size - pos) as usize);
            let tail = ino.layout == LAYOUT_INLINE && bi >= ino.size / self.blksz;
            let phys = if tail {
                ino.inline_off + in_blk
            } else {
                (ino.raw_blkaddr as u64 + bi) * self.blksz + in_blk
            };
            self.src.read_at(phys, &mut buf[done..done + n])?;
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }


    /// Visit directory entries as `(name, nid, file_type)`; return `false` to stop.
    pub fn read_dir<F>(&self, dir: &Inode, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&[u8], u64, u8) -> bool,
    {
        if !dir.is_dir() {
            return Err(Error::NotDir);
        }
        if self.blksz as usize > MAX_BLK {
            return Err(Error::Unsupported);
        }
        let mut blk = [0u8; MAX_BLK];
        let mut base = 0u64;
        while base < dir.size {
            let valid = (dir.size - base).min(self.blksz) as usize;
            self.read(dir, base, &mut blk[..valid])?;
            let first = le16(&blk, 8) as usize;
            if first < DIRENT_SZ || first % DIRENT_SZ != 0 || first > valid {
                return Err(Error::Corrupt);
            }
            let count = first / DIRENT_SZ;
            for i in 0..count {
                let d = i * DIRENT_SZ;
                let nid = le64(&blk, d);
                let start = le16(&blk, d + 8) as usize;
                let ftype = blk[d + 10];
                let end = if i + 1 < count { le16(&blk, d + DIRENT_SZ + 8) as usize } else { valid };
                if start > end || end > valid {
                    return Err(Error::Corrupt);
                }
                let mut name = &blk[start..end];
                if i + 1 == count {
                    // last name has no successor to delimit it: NUL-terminated if short
                    if let Some(z) = name.iter().position(|&c| c == 0) {
                        name = &name[..z];
                    }
                }
                if !f(name, nid, ftype) {
                    return Ok(());
                }
            }
            base += self.blksz;
        }
        Ok(())
    }

    pub fn lookup_in(&self, dir: &Inode, name: &[u8]) -> Result<Inode, Error> {
        let mut found = None;
        self.read_dir(dir, |n, nid, _| {
            if n == name {
                found = Some(nid);
                false
            } else {
                true
            }
        })?;
        self.inode(found.ok_or(Error::NotFound)?)
    }

    /// Resolve an absolute or relative `/`-separated path (symlinks not followed).
    pub fn lookup(&self, path: &str) -> Result<Inode, Error> {
        let mut cur = self.root()?;
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            cur = self.lookup_in(&cur, part.as_bytes())?;
        }
        Ok(cur)
    }

    /// The target of the symbolic link `ino`, into `buf` (a longer one is cut): the number of bytes.
    pub fn readlink(&self, ino: &Inode, buf: &mut [u8]) -> Result<usize, Error> {
        if !ino.is_symlink() {
            return Err(Error::NotLink);
        }
        let n = (ino.size as usize).min(buf.len());
        self.read(ino, 0, &mut buf[..n])
    }

    /// Resolve a path, following symbolic links in every component and, with `follow_last`, in the last one too (`false`: the link itself is the answer, as
    /// for `lstat`). A target is relative to the directory the link is in; an absolute one starts at the root of this image. `..` of the root is the root. At
    /// most `MAX_LINKS` links are followed in all, so a loop ends in `Error::TooManyLinks`.
    pub fn resolve(&self, path: &str, follow_last: bool) -> Result<Inode, Error> {
        extern crate alloc;
        use alloc::vec::Vec;
        let split = |p: &[u8], todo: &mut Vec<Vec<u8>>| {
            // (pushed last to first, so the first component is on top)
            for part in p.split(|&c| c == b'/').rev().filter(|c| !c.is_empty() && *c != b".") {
                todo.push(part.to_vec());
            }
        };
        let mut dirs: Vec<Inode> = Vec::new();
        dirs.push(self.root()?);
        let mut todo: Vec<Vec<u8>> = Vec::new();
        split(path.as_bytes(), &mut todo);
        let mut links = 0;
        while let Some(part) = todo.pop() {
            if part == b".." {
                if dirs.len() > 1 {
                    dirs.pop();
                }
                continue;
            }
            let cur = *dirs.last().ok_or(Error::Corrupt)?;
            let ino = self.lookup_in(&cur, &part)?;
            let last = todo.is_empty();
            if ino.is_symlink() && (!last || follow_last) {
                links += 1;
                if links > MAX_LINKS {
                    return Err(Error::TooManyLinks);
                }
                let mut target = alloc::vec![0u8; (ino.size as usize).min(4096)];
                let n = self.readlink(&ino, &mut target)?;
                if target.first() == Some(&b'/') {
                    dirs.truncate(1);
                }
                split(&target[..n], &mut todo);
                continue;
            }
            if last {
                return Ok(ino);
            }
            if !ino.is_dir() {
                return Err(Error::NotDir);
            }
            dirs.push(ino);
        }
        dirs.last().copied().ok_or(Error::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const BS: usize = 4096;

    fn dir_block(entries: &[(&str, u64, u8)]) -> Vec<u8> {
        let hdr = entries.len() * DIRENT_SZ;
        let mut names = Vec::new();
        let mut out = vec![0u8; hdr];
        for (i, (n, nid, t)) in entries.iter().enumerate() {
            let off = (hdr + names.len()) as u16;
            out[i * 12..i * 12 + 8].copy_from_slice(&nid.to_le_bytes());
            out[i * 12 + 8..i * 12 + 10].copy_from_slice(&off.to_le_bytes());
            out[i * 12 + 10] = *t;
            names.extend_from_slice(n.as_bytes());
        }
        out.extend(names);
        out
    }

    fn compact(layout: u16, mode: u16, size: u32, raw: u32) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0..2].copy_from_slice(&(layout << 1).to_le_bytes());
        v[4..6].copy_from_slice(&mode.to_le_bytes());
        v[8..12].copy_from_slice(&size.to_le_bytes());
        v[16..20].copy_from_slice(&raw.to_le_bytes());
        v
    }

    fn extended(layout: u16, mode: u16, size: u64, raw: u32) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[0..2].copy_from_slice(&((layout << 1) | 1).to_le_bytes());
        v[4..6].copy_from_slice(&mode.to_le_bytes());
        v[8..16].copy_from_slice(&size.to_le_bytes());
        v[16..20].copy_from_slice(&raw.to_le_bytes());
        v
    }

    fn put(img: &mut [u8], at: usize, data: &[u8]) {
        img[at..at + data.len()].copy_from_slice(data);
    }

    fn build() -> (Vec<u8>, Vec<u8>) {
        let mut img = vec![0u8; 5 * BS];
        let mut sb = vec![0u8; 128];
        sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        sb[12] = 12;
        sb[14..16].copy_from_slice(&40u16.to_le_bytes()); // root nid
        put(&mut img, 1024, &sb); // meta_blkaddr = 0

        let big: Vec<u8> = (0..9000u32).map(|i| (i * 7 % 251) as u8).collect();

        // root dir (nid 40 @1280), inline directory data
        let root = dir_block(&[(".", 40, 2), ("..", 40, 2), ("hello.txt", 64, 1), ("big.bin", 128, 1), ("sub", 80, 2)]);
        put(&mut img, 1280, &compact(2, S_IFDIR | 0o755, root.len() as u32, 0));
        put(&mut img, 1280 + 32, &root);
        // hello.txt (nid 64 @2048), inline
        let hello = b"Hello from Metallium-OS EROFS!";
        put(&mut img, 2048, &compact(2, S_IFREG | 0o644, hello.len() as u32, 0));
        put(&mut img, 2048 + 32, hello);
        // sub (nid 80 @2560)
        let sub = dir_block(&[(".", 80, 2), ("..", 40, 2), ("inner.txt", 96, 1)]);
        put(&mut img, 2560, &compact(2, S_IFDIR | 0o755, sub.len() as u32, 0));
        put(&mut img, 2560 + 32, &sub);
        // sub/inner.txt (nid 96 @3072), plain layout in block 2
        put(&mut img, 3072, &compact(0, S_IFREG | 0o600, 5, 2));
        put(&mut img, 2 * BS, b"inner");
        // big.bin (nid 128 @4096), extended inode, 2 full blocks (3,4) + inline tail
        put(&mut img, 4096, &extended(2, S_IFREG | 0o644, 9000, 3));
        put(&mut img, 3 * BS, &big[..BS]);
        put(&mut img, 4 * BS, &big[BS..2 * BS]);
        put(&mut img, 4096 + 64, &big[2 * BS..]);
        (img, big)
    }

    #[test]
    fn lookup_and_read() {
        let (img, big) = build();
        let fs = Erofs::new(img.as_slice()).unwrap();
        let h = fs.lookup("/hello.txt").unwrap();
        let mut b = [0u8; 64];
        let n = fs.read(&h, 0, &mut b).unwrap();
        assert_eq!(&b[..n], b"Hello from Metallium-OS EROFS!");

        let i = fs.lookup("sub/inner.txt").unwrap();
        let n = fs.read(&i, 0, &mut b).unwrap();
        assert_eq!(&b[..n], b"inner");

        let g = fs.lookup("/big.bin").unwrap();
        assert_eq!(g.size, 9000);
        let mut all = vec![0u8; 9000];
        assert_eq!(fs.read(&g, 0, &mut all).unwrap(), 9000);
        assert_eq!(all, big);
        // unaligned read across the plain/inline boundary
        let mut part = [0u8; 300];
        assert_eq!(fs.read(&g, 8100, &mut part).unwrap(), 300);
        assert_eq!(&part[..], &big[8100..8400]);
        // short read at EOF
        assert_eq!(fs.read(&g, 8990, &mut part).unwrap(), 10);
    }

    #[test]
    fn errors() {
        let (img, _) = build();
        let fs = Erofs::new(img.as_slice()).unwrap();
        assert_eq!(fs.lookup("/nope").unwrap_err(), Error::NotFound);
        assert_eq!(fs.lookup("/hello.txt/x").unwrap_err(), Error::NotDir);
        let mut names = Vec::new();
        fs.read_dir(&fs.root().unwrap(), |n, _, _| {
            names.push(std::string::String::from_utf8_lossy(n).into_owned());
            true
        })
        .unwrap();
        assert_eq!(names, [".", "..", "hello.txt", "big.bin", "sub"]);
        let zeros = vec![0u8; 8192];
        assert_eq!(Erofs::new(zeros.as_slice()).err(), Some(Error::BadMagic));
    }
}
