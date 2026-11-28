//! Input and output: the `Read` and `Write` traits and the three standard streams. Standard output and input go
//! through the console endpoint the parent gave (slot 7), standard error through the same endpoint with its own
//! operation; without one they use the kernel console and an empty input.
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    IsADirectory,
    InvalidInput,
    ReadOnly,
    StorageFull,
    AlreadyExists,
    NotEmpty,
    Io,
    BrokenPipe,
    Unsupported,
    PermissionDenied,
    OutOfMemory,
    WouldBlock,
    TimedOut,
    UnexpectedEof,
    InvalidData,
    AddrInUse,
    AddrNotAvailable,
    ConnectionRefused,
    ConnectionReset,
    NotConnected,
    Other,
}

/// An error: what kind, and the raw status behind it (a VFS status 1.., or a kernel status, negative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub code: i64,
}

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub const fn new(kind: ErrorKind) -> Error {
        Error { kind, code: 0 }
    }

    /// From a kernel status (negative).
    pub fn from_kernel(code: i64) -> Error {
        let kind = match code {
            -1 => ErrorKind::PermissionDenied,
            -2 => ErrorKind::PermissionDenied,
            -3 => ErrorKind::WouldBlock,
            -4 => ErrorKind::BrokenPipe,
            -5 => ErrorKind::InvalidInput,
            -7 => ErrorKind::Unsupported,
            -8 => ErrorKind::OutOfMemory,
            -9 => ErrorKind::TimedOut,
            -10 => ErrorKind::WouldBlock,
            _ => ErrorKind::Other,
        };
        Error { kind, code }
    }

    /// From a VFS status.
    pub fn from_vfs(code: i64) -> Error {
        let kind = match code {
            1 => ErrorKind::NotFound,
            2 => ErrorKind::IsADirectory,
            3 => ErrorKind::InvalidInput,
            4 => ErrorKind::ReadOnly,
            5 => ErrorKind::StorageFull,
            6 => ErrorKind::InvalidInput,
            7 => ErrorKind::Io,
            8 => ErrorKind::AlreadyExists,
            9 => ErrorKind::NotEmpty,
            12 => ErrorKind::WouldBlock,
            _ => ErrorKind::Other,
        };
        Error { kind, code }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (status {})", self.kind, self.code)
    }
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf)? {
                0 => return Err(Error::new(ErrorKind::Io)),
                n => buf = &buf[n..],
            }
        }
        Ok(())
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<()> {
        struct Adapter<'a, W: ?Sized> {
            inner: &'a mut W,
            error: Option<Error>,
        }
        impl<W: Write + ?Sized> fmt::Write for Adapter<'_, W> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                match self.inner.write_all(s.as_bytes()) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.error = Some(e);
                        Err(fmt::Error)
                    }
                }
            }
        }
        let mut a = Adapter { inner: self, error: None };
        match fmt::write(&mut a, args) {
            Ok(()) => Ok(()),
            Err(_) => Err(a.error.unwrap_or(Error::new(ErrorKind::Io))),
        }
    }
}

pub trait Read {
    /// Read some bytes; 0 means the end.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    fn read_to_end(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        let start = out.len();
        let mut chunk = [0u8; 512];
        loop {
            match self.read(&mut chunk)? {
                0 => return Ok(out.len() - start),
                n => out.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn read_to_string(&mut self, out: &mut String) -> Result<usize> {
        let mut bytes = Vec::new();
        let n = self.read_to_end(&mut bytes)?;
        out.push_str(core::str::from_utf8(&bytes).map_err(|_| Error::new(ErrorKind::InvalidData))?);
        Ok(n)
    }

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf)? {
                0 => return Err(Error::new(ErrorKind::UnexpectedEof)),
                n => buf = &mut buf[n..],
            }
        }
        Ok(())
    }
}

pub struct Stdout;
pub struct Stderr;
pub struct Stdin;

pub fn stdout() -> Stdout {
    Stdout
}
pub fn stderr() -> Stderr {
    Stderr
}
pub fn stdin() -> Stdin {
    Stdin
}

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        crate::write_out(buf);
        Ok(buf.len())
    }
}

impl Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        crate::write_err(buf);
        Ok(buf.len())
    }
}

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(crate::read_in(buf))
    }
}

impl Stdin {
    /// Read up to and including the next newline into `line`; the number of bytes (0 at the end of the input).
    pub fn read_line(&self, line: &mut String) -> Result<usize> {
        let mut bytes = Vec::new();
        loop {
            let mut b = [0u8; 1];
            if crate::read_in(&mut b) == 0 {
                break;
            }
            bytes.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
        line.push_str(core::str::from_utf8(&bytes).map_err(|_| Error::new(ErrorKind::InvalidData))?);
        Ok(bytes.len())
    }
}

impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }
}

impl Read for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = buf.len().min(self.len());
        buf[..n].copy_from_slice(&self[..n]);
        *self = &self[n..];
        Ok(n)
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    let _ = stdout().write_fmt(args);
}

#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments) {
    let _ = stderr().write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($t:tt)*) => { $crate::io::_print(format_args!($($t)*)) };
}

#[macro_export]
macro_rules! eprint {
    ($($t:tt)*) => { $crate::io::_eprint(format_args!($($t)*)) };
}

#[macro_export]
macro_rules! eprintln {
    ($($t:tt)*) => {{ $crate::io::_eprint(format_args!($($t)*)); $crate::io::_eprint(format_args!("\n")) }};
}
