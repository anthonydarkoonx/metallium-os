//! The Metal Program Package (`.map`): one file holding a program's manifest and its files.
//!
//! ```text
//! offset  size
//!  0      8   magic "METALMAP"
//!  8      4   version = 1
//! 12      4   manifest length M
//! 16      4   number of files N
//! 20      4   table length T
//! 24      4   CRC-32 (IEEE) of everything after the header up to the signature (manifest, table, data)
//! 28      4   signature length S: 0 (unsigned) or 72
//! 32      M   manifest (UTF-8 text, see below)
//! 32+M    T   file table: N entries of  u16 path length, u32 offset into the data, u32 length, path bytes
//! 32+M+T  .   data (the files, back to back)
//! end-S   S   signature block: key id (8 bytes: the first 8 of SHA-512 of the public key), Ed25519 signature (64 bytes)
//!             of every byte before it
//! ```
//! Integers are little-endian. The manifest is `key = value` lines (`#` starts a comment):
//!
//! ```text
//! id         = counter            # 1..=16 of a-z 0-9 _ - .
//! name       = Counter            # shown to the user
//! version    = 1.0.0
//! unsigned   = true               # phase 1: no signature check yet, the flag says so out loud
//! heap_pages = 128                # memory limit, 1..=1048576 (default 128)
//! threads    = 0                  # extra threads, 0..=64
//! quota      = 12                 # files and directories the program may have in its own directory, 1..=1024 (default 12)
//! class      = interactive        # interactive | background | heavy
//! role = desktop                  # the desktop (taskbar, Start menu): the manager gives the compositor its role; implies shell
//! permission = files              # files | network | display | shell | allfiles | admin | spawn (repeatable)
//! spawn_pages = 4096               # with `spawn`: pages the program may hand down to the programs it starts (default 4096, max 1048576)
//! ability    = main ui bin/counter.pie     # name, kind (ui | service), entry file in the package
//! ```
//! A signed package is accepted if its key is in the system's trust store (`/system/etc/program-keys`, lines `name = <64 hex digits of
//! the public key>`) and the signature verifies; a package without one only if the policy (`/system/etc/program-policy`,
//! `allow_unsigned = true`) allows unsigned programs *and* the manifest says `unsigned = true`. See [`check`].
//!
//! Everything is checked before a program is installed: sizes, the checksum, the manifest, that every path is a plain
//! relative path inside the package, and that every ability's entry is an ELF file. The parser never panics.
#![forbid(unsafe_code)]
#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const MAGIC: &[u8; 8] = b"METALMAP";
pub const VERSION: u32 = 1;
pub const HEADER: usize = 32;
pub const SIG_LEN: usize = 72;
/// The largest package the parser will open at all. A signed package may be this big (it is the browser, with a JavaScript engine in it).
pub const MAX_PACKAGE: usize = 12 << 20;
/// The largest package without a trusted signature: [`check`] refuses a bigger one. What can fill the program manager's memory is bounded by who
/// vouches for it, so the size a program may have grows with trust, not with what the file says about itself.
pub const MAX_PACKAGE_UNSIGNED: usize = 4 << 20;
pub const MAX_MANIFEST: usize = 4096;
pub const MAX_FILES: usize = 64;
pub const MAX_ABILITIES: usize = 8;
pub const MAX_ID: usize = 16;
pub const MAX_HEAP_PAGES: u32 = 1 << 20;
pub const MAX_THREADS: u8 = 64;
pub const MAX_QUOTA: u16 = 1024;
pub const DEFAULT_HEAP_PAGES: u32 = 128;
/// What a program with `permission = spawn` may hand down to the programs it starts, unless `spawn_pages` says otherwise.
pub const DEFAULT_SPAWN_PAGES: u32 = 4096;
pub const MAX_SPAWN_PAGES: u32 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooShort,
    TooLarge,
    BadMagic,
    BadVersion,
    BadChecksum,
    BadTable,
    BadPath,
    BadManifest(&'static str),
    MissingEntry,
    NotElf,
    BadSignatureBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Reads and writes the program's own private directory (every program has that) *and* the shared file system.
    Files,
    Network,
    /// May create windows on the console (gets a send capability to the display endpoint).
    Display,
    /// A shell client: may take the panel and console roles, list and raise other programs' windows, and talk to the program manager
    /// (the taskbar and the Start menu). Implies `display`.
    Shell,
    /// May see the whole file system, not just its own directory (a file manager). The widest file permission: the program is trusted like the terminal.
    AllFiles,
    /// May revoke capabilities of other programs (the task manager): gets the program manager's copy of the revoke authority.
    Admin,
    /// May start programs of its own (a terminal running command-line programs): gets a spawn capability and an endpoint factory.
    /// The programs it starts never get more than it has: file access only if it has `allfiles`, network only if it has `network`,
    /// and they cannot start programs themselves.
    Spawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Interactive,
    Background,
    Heavy,
}

impl Class {
    /// The scheduling class number of the spawn request.
    pub fn number(self) -> u32 {
        match self {
            Class::Interactive => 0,
            Class::Background => 1,
            Class::Heavy => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Has a lifecycle (create, foreground, background, destroy).
    Ui,
    /// Runs without a screen; the lifecycle is create and destroy only.
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ability {
    pub name: String,
    pub kind: Kind,
    pub entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub unsigned: bool,
    pub heap_pages: u32,
    pub threads: u8,
    /// How many files and directories its own directory may hold (0: the default, 12).
    pub quota: u16,
    pub class: Class,
    pub files: bool,
    pub network: bool,
    pub display: bool,
    pub shell: bool,
    pub allfiles: bool,
    pub admin: bool,
    pub spawn: bool,
    /// With `spawn`: the pages it may hand down to the programs it starts (0 without `spawn`).
    pub spawn_pages: u32,
    /// `role = desktop`: the program is the desktop (taskbar, Start menu); the manager tells the compositor so after it starts it.
    pub desktop: bool,
    pub abilities: Vec<Ability>,
}

impl Manifest {
    pub fn ability(&self, name: &str) -> Option<&Ability> {
        self.abilities.iter().find(|a| a.name == name)
    }
    pub fn has(&self, p: Permission) -> bool {
        match p {
            Permission::Files => self.files,
            Permission::Network => self.network,
            Permission::Display => self.display,
            Permission::Shell => self.shell,
            Permission::AllFiles => self.allfiles,
            Permission::Admin => self.admin,
            Permission::Spawn => self.spawn,
        }
    }
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'))
        && !s.starts_with('.')
}

/// A plain relative path: no empty, `.` or `..` parts, no backslash or control byte, no leading or trailing `/`.
pub fn path_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 200
        && !p.bytes().any(|b| b < 0x20 || b == 0x7F || b == b'\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

pub fn parse_manifest(text: &str) -> Result<Manifest, Error> {
    let bad = |m: &'static str| Error::BadManifest(m);
    let mut m = Manifest {
        id: String::new(),
        name: String::new(),
        version: String::new(),
        unsigned: false,
        heap_pages: DEFAULT_HEAP_PAGES,
        threads: 0,
        quota: 0,
        class: Class::Interactive,
        files: false,
        network: false,
        display: false,
        shell: false,
        allfiles: false,
        admin: false,
        spawn: false,
        spawn_pages: 0,
        desktop: false,
        abilities: Vec::new(),
    };
    let mut spawn_pages: Option<u32> = None;
    let mut seen: Vec<&str> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or(bad("line without ="))?;
        let (k, v) = (k.trim(), v.trim());
        if v.is_empty() {
            return Err(bad("empty value"));
        }
        if !matches!(k, "permission" | "ability") {
            if seen.contains(&k) {
                return Err(bad("duplicate key"));
            }
            seen.push(k);
        }
        match k {
            "id" => {
                if !ident_ok(v) {
                    return Err(bad("bad id"));
                }
                m.id = v.into();
            }
            "name" => {
                if v.len() > 40 || v.bytes().any(|b| b < 0x20) {
                    return Err(bad("bad name"));
                }
                m.name = v.into();
            }
            "version" => {
                if v.len() > 16 || !v.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                    return Err(bad("bad version"));
                }
                m.version = v.into();
            }
            "unsigned" => {
                m.unsigned = match v {
                    "true" => true,
                    "false" => false,
                    _ => return Err(bad("unsigned must be true or false")),
                }
            }
            "heap_pages" => {
                m.heap_pages = v.parse().map_err(|_| bad("bad heap_pages"))?;
                if m.heap_pages == 0 || m.heap_pages > MAX_HEAP_PAGES {
                    return Err(bad("heap_pages out of range"));
                }
            }
            "spawn_pages" => {
                let n: u32 = v.parse().map_err(|_| bad("bad spawn_pages"))?;
                if n == 0 || n > MAX_SPAWN_PAGES {
                    return Err(bad("spawn_pages out of range"));
                }
                spawn_pages = Some(n);
            }
            "threads" => {
                m.threads = v.parse().map_err(|_| bad("bad threads"))?;
                if m.threads > MAX_THREADS {
                    return Err(bad("threads out of range"));
                }
            }
            "quota" => {
                m.quota = v.parse().map_err(|_| bad("bad quota"))?;
                if m.quota == 0 || m.quota > MAX_QUOTA {
                    return Err(bad("quota out of range"));
                }
            }
            "class" => {
                m.class = match v {
                    "interactive" => Class::Interactive,
                    "background" => Class::Background,
                    "heavy" => Class::Heavy,
                    _ => return Err(bad("unknown class")),
                }
            }
            "permission" => match v {
                "files" => m.files = true,
                "network" => m.network = true,
                "display" => m.display = true,
                "allfiles" => m.allfiles = true,
                "admin" => m.admin = true,
                "spawn" => m.spawn = true,
                "shell" => {
                    m.shell = true;
                    m.display = true;
                }
                _ => return Err(bad("unknown permission")),
            },
            // (a desktop is a shell client: it needs the display and the control endpoint)
            "role" => match v {
                "desktop" => {
                    m.desktop = true;
                    m.shell = true;
                    m.display = true;
                }
                _ => return Err(bad("unknown role")),
            },
            "ability" => {
                let mut it = v.split_whitespace();
                let (Some(name), Some(kind), Some(entry), None) = (it.next(), it.next(), it.next(), it.next()) else {
                    return Err(bad("ability needs: name kind entry"));
                };
                if !ident_ok(name) || m.abilities.iter().any(|a| a.name == name) {
                    return Err(bad("bad or duplicate ability name"));
                }
                let kind = match kind {
                    "ui" => Kind::Ui,
                    "service" => Kind::Service,
                    _ => return Err(bad("ability kind must be ui or service")),
                };
                if !path_ok(entry) {
                    return Err(bad("bad ability entry path"));
                }
                if m.abilities.len() == MAX_ABILITIES {
                    return Err(bad("too many abilities"));
                }
                m.abilities.push(Ability { name: name.into(), kind, entry: entry.into() });
            }
            _ => return Err(bad("unknown key")),
        }
    }
    if m.id.is_empty() {
        return Err(bad("no id"));
    }
    if m.name.is_empty() {
        m.name = m.id.clone();
    }
    if m.version.is_empty() {
        return Err(bad("no version"));
    }
    if m.abilities.is_empty() {
        return Err(bad("no ability"));
    }
    m.spawn_pages = match (m.spawn, spawn_pages) {
        (true, n) => n.unwrap_or(DEFAULT_SPAWN_PAGES),
        (false, None) => 0,
        (false, Some(_)) => return Err(bad("spawn_pages needs permission = spawn")),
    };
    Ok(m)
}

/// CRC-32 (IEEE 802.3, reflected), bitwise: packages are small and this runs once per install.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ (0xEDB8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

#[derive(Debug, Clone)]
pub struct File<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
}

/// The signature block of a package and what it covers.
#[derive(Debug, Clone, Copy)]
pub struct Signature<'a> {
    pub key_id: [u8; 8],
    pub sig: [u8; 64],
    /// Every byte of the package before the signature block.
    pub signed: &'a [u8],
}

#[derive(Debug)]
pub struct Package<'a> {
    /// The size of the whole file.
    pub size: usize,
    pub manifest: Manifest,
    pub signature: Option<Signature<'a>>,
    files: Vec<File<'a>>,
}

impl<'a> Package<'a> {
    /// Check and open a package.
    pub fn parse(b: &'a [u8]) -> Result<Package<'a>, Error> {
        let size = b.len();
        if size > MAX_PACKAGE {
            return Err(Error::TooLarge);
        }
        if b.len() < HEADER {
            return Err(Error::TooShort);
        }
        if &b[..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        if u32_at(b, 8) != Some(VERSION) {
            return Err(Error::BadVersion);
        }
        let (mlen, n, tlen, crc) = (u32_at(b, 12).unwrap() as usize, u32_at(b, 16).unwrap() as usize, u32_at(b, 20).unwrap() as usize, u32_at(b, 24).unwrap());
        if mlen > MAX_MANIFEST || n > MAX_FILES {
            return Err(Error::TooLarge);
        }
        let sig_len = u32_at(b, 28).unwrap() as usize;
        if sig_len != 0 && sig_len != SIG_LEN {
            return Err(Error::BadSignatureBlock);
        }
        if b.len() < HEADER + sig_len {
            return Err(Error::TooShort);
        }
        let (b, sigblock) = b.split_at(b.len() - sig_len);
        if crc32(&b[HEADER..]) != crc {
            return Err(Error::BadChecksum);
        }
        let signature = (sig_len != 0).then(|| Signature { key_id: sigblock[..8].try_into().unwrap(), sig: sigblock[8..].try_into().unwrap(), signed: b });
        let tstart = HEADER.checked_add(mlen).ok_or(Error::TooShort)?;
        let dstart = tstart.checked_add(tlen).ok_or(Error::TooShort)?;
        if dstart > b.len() {
            return Err(Error::TooShort);
        }
        let manifest = parse_manifest(core::str::from_utf8(&b[HEADER..tstart]).map_err(|_| Error::BadManifest("not UTF-8"))?)?;
        let (table, data) = (&b[tstart..dstart], &b[dstart..]);
        let mut files: Vec<File<'a>> = Vec::new();
        let mut at = 0usize;
        for _ in 0..n {
            let plen = u16::from_le_bytes(table.get(at..at + 2).ok_or(Error::BadTable)?.try_into().unwrap()) as usize;
            let off = u32_at(table, at + 2).ok_or(Error::BadTable)? as usize;
            let len = u32_at(table, at + 6).ok_or(Error::BadTable)? as usize;
            let p = table.get(at + 10..at + 10 + plen).ok_or(Error::BadTable)?;
            at += 10 + plen;
            let path = core::str::from_utf8(p).map_err(|_| Error::BadPath)?;
            if !path_ok(path) || files.iter().any(|f| f.path == path) {
                return Err(Error::BadPath);
            }
            let end = off.checked_add(len).ok_or(Error::BadTable)?;
            files.push(File { path, data: data.get(off..end).ok_or(Error::BadTable)? });
        }
        if at != table.len() {
            return Err(Error::BadTable);
        }
        for a in &manifest.abilities {
            let f = files.iter().find(|f| f.path == a.entry).ok_or(Error::MissingEntry)?;
            if f.data.len() < 64 || f.data[..4] != *b"\x7fELF" {
                return Err(Error::NotElf);
            }
        }
        Ok(Package { size, manifest, signature, files })
    }

    pub fn files(&self) -> &[File<'a>] {
        &self.files
    }

    pub fn file(&self, path: &str) -> Option<&'a [u8]> {
        self.files.iter().find(|f| f.path == path).map(|f| f.data)
    }
}

/// Build an unsigned package (the host tools and the tests; `tools/mkmap.py` writes the same format).
pub fn build(manifest: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut table, mut data) = (Vec::new(), Vec::new());
    for (p, d) in files {
        table.extend_from_slice(&(p.len() as u16).to_le_bytes());
        table.extend_from_slice(&(data.len() as u32).to_le_bytes());
        table.extend_from_slice(&(d.len() as u32).to_le_bytes());
        table.extend_from_slice(p.as_bytes());
        data.extend_from_slice(d);
    }
    let mut body = Vec::new();
    body.extend_from_slice(manifest.as_bytes());
    body.extend_from_slice(&table);
    body.extend_from_slice(&data);
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    for v in [VERSION, manifest.len() as u32, files.len() as u32, table.len() as u32, crc32(&body), 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------------------------------------------------
// trust: who may sign, and whether unsigned programs may run
// ---------------------------------------------------------------------------------------------------------------

/// A key the system trusts to sign programs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub name: String,
    pub key: [u8; 32],
    /// The first 8 bytes of SHA-512 of the key: what a package's signature block names.
    pub id: [u8; 8],
}

pub fn key_id(key: &[u8; 32]) -> [u8; 8] {
    metallium_ed25519::sha512(key)[..8].try_into().unwrap()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The trust store: `name = <64 hex digits>` lines, `#` comments. A bad line is an error (a store that silently drops a key
/// would be a surprise), and so is a name used twice.
pub fn parse_keys(text: &str) -> Result<Vec<TrustedKey>, Error> {
    let mut out: Vec<TrustedKey> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (name, hex) = line.split_once('=').ok_or(Error::BadManifest("trust store: line without ="))?;
        let (name, hex) = (name.trim(), hex.trim());
        let key = unhex32(hex).ok_or(Error::BadManifest("trust store: not 64 hex digits"))?;
        if !ident_ok(name) || out.iter().any(|k| k.name == name) {
            return Err(Error::BadManifest("trust store: bad or repeated key name"));
        }
        out.push(TrustedKey { name: name.into(), id: key_id(&key), key });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Developer mode: packages without a signature may be installed if their manifest says `unsigned = true`.
    pub allow_unsigned: bool,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy { allow_unsigned: false }
    }
}

/// `allow_unsigned = true|false`. Anything else (including a typo) is an error and the caller keeps the strict default.
pub fn parse_policy(text: &str) -> Result<Policy, Error> {
    let mut p = Policy::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
            Some(("allow_unsigned", "true")) => p.allow_unsigned = true,
            Some(("allow_unsigned", "false")) => p.allow_unsigned = false,
            _ => return Err(Error::BadManifest("policy: unknown line")),
        }
    }
    Ok(p)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    /// No signature, and the policy and manifest do not allow an unsigned program.
    Unsigned,
    /// Signed with a key the system does not know.
    UnknownKey,
    /// The signature does not match the package.
    BadSignature,
    /// No signature, and the package is bigger than [`MAX_PACKAGE_UNSIGNED`].
    UnsignedTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Signed by the trusted key of this name.
    Signed(String),
    /// Unsigned, allowed in developer mode.
    Unsigned,
}

/// Decide whether a (structurally valid) package may be installed.
pub fn check(pkg: &Package, keys: &[TrustedKey], policy: &Policy) -> Result<Trust, TrustError> {
    match &pkg.signature {
        Some(s) => {
            let k = keys.iter().find(|k| k.id == s.key_id).ok_or(TrustError::UnknownKey)?;
            if metallium_ed25519::verify(&k.key, s.signed, &s.sig) {
                Ok(Trust::Signed(k.name.clone()))
            } else {
                Err(TrustError::BadSignature)
            }
        }
        None if policy.allow_unsigned && pkg.manifest.unsigned && pkg.size > MAX_PACKAGE_UNSIGNED => Err(TrustError::UnsignedTooLarge),
        None if policy.allow_unsigned && pkg.manifest.unsigned => Ok(Trust::Unsigned),
        None => Err(TrustError::Unsigned),
    }
}

#[cfg(test)]
mod tests;
