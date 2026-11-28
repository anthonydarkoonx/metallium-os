//! Symbolic links: `Erofs::resolve` and `readlink` against an image made by the reference `mkfs.erofs` (skipped, with a note, when it is not installed).
use metallium_erofs::{Erofs, Error, MAX_LINKS};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn links() {
    if Command::new("mkfs.erofs").arg("--version").output().is_err() {
        eprintln!("mkfs.erofs not installed: skipping");
        return;
    }
    let base: PathBuf = std::env::temp_dir().join(format!("metallium-erofs-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let t = base.join("tree");
    fs::create_dir_all(t.join("a/b")).unwrap();
    fs::create_dir_all(t.join("other")).unwrap();
    fs::write(t.join("a/target.txt"), b"hello").unwrap();
    fs::write(t.join("a/b/deep.txt"), b"deep").unwrap();
    symlink("target.txt", t.join("a/rel")).unwrap(); // relative to its own directory
    symlink("/a/target.txt", t.join("a/abs")).unwrap(); // absolute: from the root of the image
    symlink("../target.txt", t.join("a/b/up")).unwrap(); // upwards
    symlink("b", t.join("a/dirlink")).unwrap(); // a link to a directory
    symlink("/a", t.join("other/toa")).unwrap(); // ... in another directory, absolute
    symlink("loop2", t.join("loop1")).unwrap();
    symlink("loop1", t.join("loop2")).unwrap();
    symlink("nowhere", t.join("dangling")).unwrap();
    symlink("../../../../a/target.txt", t.join("a/b/toofar")).unwrap(); // `..` above the root stays at the root
    for i in 0..MAX_LINKS + 4 {
        symlink(format!("hop{}", i + 1), t.join(format!("hop{i}"))).unwrap();
    }
    symlink("a/target.txt", t.join(format!("hop{}", MAX_LINKS + 4))).unwrap();
    let img = base.join("img.erofs");
    let out = Command::new("mkfs.erofs").arg(&img).arg(&t).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let data = fs::read(&img).unwrap();
    let efs = Erofs::new(data.as_slice()).unwrap();
    let read = |p: &str| -> Result<Vec<u8>, Error> {
        let ino = efs.resolve(p, true)?;
        let mut b = vec![0u8; ino.size as usize];
        let n = efs.read(&ino, 0, &mut b)?;
        b.truncate(n);
        Ok(b)
    };
    assert_eq!(read("/a/target.txt").unwrap(), b"hello");
    assert_eq!(read("/a/rel").unwrap(), b"hello");
    assert_eq!(read("/a/abs").unwrap(), b"hello");
    assert_eq!(read("/a/b/up").unwrap(), b"hello");
    assert_eq!(read("/a/dirlink/deep.txt").unwrap(), b"deep", "a link to a directory in the middle of a path");
    assert_eq!(read("/other/toa/dirlink/up").unwrap(), b"hello", "links through links");
    assert_eq!(read("/a/b/toofar").unwrap(), b"hello", ".. above the root is the root");
    assert_eq!(read("a/rel").unwrap(), b"hello", "a path without the leading slash");
    assert!(efs.resolve("/a/dirlink", true).unwrap().is_dir(), "a link to a directory resolves to the directory");
    assert!(efs.resolve("/a/dirlink", false).unwrap().is_symlink(), "without following the last link it is the link");
    assert!(efs.resolve("/a/rel", false).unwrap().is_symlink());
    let mut buf = [0u8; 64];
    let n = efs.readlink(&efs.resolve("/a/abs", false).unwrap(), &mut buf).unwrap();
    assert_eq!(&buf[..n], b"/a/target.txt");
    let n = efs.readlink(&efs.resolve("/a/b/up", false).unwrap(), &mut buf).unwrap();
    assert_eq!(&buf[..n], b"../target.txt");
    assert_eq!(efs.readlink(&efs.resolve("/a/target.txt", true).unwrap(), &mut buf), Err(Error::NotLink));
    assert_eq!(efs.resolve("/loop1", true).err(), Some(Error::TooManyLinks));
    assert_eq!(efs.resolve("/dangling", true).err(), Some(Error::NotFound));
    assert!(efs.resolve("/dangling", false).unwrap().is_symlink(), "a dangling link is still a link");
    assert_eq!(efs.resolve("/a/target.txt/x", true).err(), Some(Error::NotDir));
    assert_eq!(efs.resolve("/hop5", true).map(|i| i.size).ok(), Some(5), "a chain of exactly MAX_LINKS links");
    assert_eq!(efs.resolve("/hop4", true).err(), Some(Error::TooManyLinks), "one link more than the limit");
    assert_eq!(efs.resolve("/hop0", true).err(), Some(Error::TooManyLinks), "a chain longer than the limit");
    let _ = fs::remove_dir_all(&base);
}
