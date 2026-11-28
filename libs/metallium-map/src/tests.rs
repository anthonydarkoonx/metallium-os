extern crate std;
use super::*;
use std::vec;
use std::vec::Vec;

const MANIFEST: &str = "id = counter\nname = Counter\nversion = 1.0.0\nunsigned = true\nheap_pages = 64\nclass = background\npermission = files\nability = main ui bin/counter\nability = sync service bin/sync\n";

fn elf() -> Vec<u8> {
    let mut v = vec![0u8; 100];
    v[..4].copy_from_slice(b"\x7fELF");
    v
}

fn pkg() -> Vec<u8> {
    let e = elf();
    build(MANIFEST, &[("bin/counter", &e), ("bin/sync", &e), ("res/icon.txt", b"icon")])
}

#[test]
fn round_trip() {
    let b = pkg();
    let p = Package::parse(&b).unwrap();
    let m = &p.manifest;
    assert_eq!((m.id.as_str(), m.name.as_str(), m.version.as_str()), ("counter", "Counter", "1.0.0"));
    assert!(m.unsigned && m.files && !m.network);
    assert_eq!((m.heap_pages, m.threads, m.class), (64, 0, Class::Background));
    assert_eq!(m.abilities.len(), 2);
    assert_eq!(m.ability("sync").unwrap().kind, Kind::Service);
    assert_eq!(p.file("res/icon.txt"), Some(&b"icon"[..]));
    assert_eq!(p.file("nope"), None);
    assert_eq!(p.files().len(), 3);
}

/// Under Miri (about 100x slower) the exhaustive byte sweeps look at every 37th byte instead of every byte.
const MIRI_STRIDE: usize = if cfg!(miri) { 37 } else { 1 };

#[test]
fn every_corruption_is_refused() {
    let b = pkg();
    // flipping any single byte of the body is caught by the checksum, of the header by the header checks
    for i in (0..b.len()).step_by(MIRI_STRIDE) {
        let mut c = b.clone();
        c[i] ^= 0x01;
        assert!(Package::parse(&c).is_err(), "byte {i} flipped went unnoticed");
    }
    // every truncation is refused
    for n in (0..b.len()).step_by(MIRI_STRIDE) {
        assert!(Package::parse(&b[..n]).is_err(), "truncated to {n}");
    }
}

#[test]
fn parser_never_panics_on_noise() {
    let mut s = 0x1234_5678u32;
    for _ in 0..if cfg!(miri) { 100 } else { 3000 } {
        let n = (s % 300) as usize;
        let mut v: Vec<u8> = (0..n).map(|_| { s = s.wrapping_mul(1664525).wrapping_add(1013904223); (s >> 24) as u8 }).collect();
        if n > 8 && s & 1 == 0 {
            v[..8].copy_from_slice(MAGIC);
        }
        let _ = Package::parse(&v);
        let _ = parse_manifest(&std::string::String::from_utf8_lossy(&v));
    }
}

#[test]
fn manifest_rules() {
    let ok = |t: &str| parse_manifest(t).is_ok();
    let base = "id = a\nversion = 1\nability = m ui bin/a\n";
    assert!(ok(base));
    assert!(!ok("version = 1\nability = m ui bin/a\n"), "no id");
    assert!(!ok("id = a\nability = m ui bin/a\n"), "no version");
    assert!(!ok("id = a\nversion = 1\n"), "no ability");
    assert!(!ok(&std::format!("{base}extra = 1\n")), "unknown key");
    assert!(!ok(&std::format!("{base}id = b\n")), "duplicate key");
    assert!(!ok(&std::format!("{base}permission = root\n")), "unknown permission");
    assert!(!ok(&std::format!("{base}heap_pages = 0\n")) && !ok(&std::format!("{base}heap_pages = 1048577\n")));
    assert!(ok(&std::format!("{base}heap_pages = 1048576\n")) && ok(&std::format!("{base}threads = 64\n")));
    assert!(!ok(&std::format!("{base}threads = 65\n")));
    assert!(ok(&std::format!("{base}quota = 100\n")) && ok(&std::format!("{base}quota = 1024\n")));
    assert!(!ok(&std::format!("{base}quota = 0\n")) && !ok(&std::format!("{base}quota = 1025\n")) && !ok(&std::format!("{base}quota = many\n")), "quota range");
    assert_eq!(parse_manifest(&std::format!("{base}quota = 100\n")).unwrap().quota, 100);
    assert_eq!(parse_manifest(base).unwrap().quota, 0, "no quota: the default");
    assert!(!ok(&std::format!("{base}ability = m ui bin/b\n")), "duplicate ability");
    assert!(!ok("id = A\nversion = 1\nability = m ui bin/a\n"), "upper case id");
    assert!(!ok("id = abcdefghijklmnopq\nversion = 1\nability = m ui bin/a\n"), "id too long");
    assert!(!ok("id = ..\nversion = 1\nability = m ui bin/a\n"), "dotted id");
    assert!(!ok("id = a\nversion = 1\nability = m ui ../a\n"), "escaping path");
    assert!(!ok("id = a\nversion = 1\nability = m ui /a\n"), "absolute path");
    assert!(!ok("id = a\nversion = 1\nability = m gui bin/a\n"), "unknown kind");
    assert!(ok("# comment\nid = a # trailing\n\nversion = 1\nability = m ui bin/a\n"));
}

#[test]
fn paths() {
    for p in ["a", "a/b", "bin/x.y"] {
        assert!(path_ok(p), "{p}");
    }
    for p in ["", "/a", "a/", "a//b", "a/./b", "a/../b", "..", "a\\b", "a\nb"] {
        assert!(!path_ok(p), "{p:?}");
    }
}

#[test]
fn package_rules() {
    let e = elf();
    // an ability whose entry is missing, or not an ELF file
    assert_eq!(Package::parse(&build(MANIFEST, &[("bin/counter", &e)])).unwrap_err(), Error::MissingEntry);
    assert_eq!(Package::parse(&build(MANIFEST, &[("bin/counter", &e), ("bin/sync", b"not an elf file at all, but long enough to pass the length check ..........")])).unwrap_err(), Error::NotElf);
    // duplicate and unsafe paths in the table
    assert_eq!(Package::parse(&build(MANIFEST, &[("bin/counter", &e), ("bin/sync", &e), ("bin/sync", &e)])).unwrap_err(), Error::BadPath);
    assert_eq!(Package::parse(&build(MANIFEST, &[("bin/counter", &e), ("bin/sync", &e), ("../x", b"x")])).unwrap_err(), Error::BadPath);
    // a table entry that points outside the data
    let mut b = pkg();
    let tstart = HEADER + MANIFEST.len();
    b[tstart + 6..tstart + 10].copy_from_slice(&u32::MAX.to_le_bytes());
    let crc = crc32(&b[HEADER..]);
    b[24..28].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(Package::parse(&b).unwrap_err(), Error::BadTable);
    // wrong magic and version
    let mut b = pkg();
    b[0] = b'X';
    assert_eq!(Package::parse(&b).unwrap_err(), Error::BadMagic);
    let mut b = pkg();
    b[8] = 2;
    assert_eq!(Package::parse(&b).unwrap_err(), Error::BadVersion);
    // too many files
    let many: Vec<(std::string::String, Vec<u8>)> = (0..=MAX_FILES).map(|i| (std::format!("f{i}"), vec![1u8])).collect();
    let refs: Vec<(&str, &[u8])> = many.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
    assert_eq!(Package::parse(&build(MANIFEST, &refs)).unwrap_err(), Error::TooLarge);
}

#[test]
fn package_size_grows_with_trust() {
    let e = elf();
    let big = |n: usize| build(MANIFEST, &[("bin/counter", &e), ("bin/sync", &e), ("res/data", &vec![7u8; n])]);
    // an unsigned package (developer mode, and it asks for it) may be 4 MiB, not more
    let under = big(MAX_PACKAGE_UNSIGNED - 4096);
    let p = Package::parse(&under).unwrap();
    assert!(p.size <= MAX_PACKAGE_UNSIGNED);
    assert_eq!(check(&p, &[], &Policy { allow_unsigned: true }), Ok(Trust::Unsigned));
    let over = big(MAX_PACKAGE_UNSIGNED + 1);
    let p = Package::parse(&over).unwrap(); // (structurally fine: the size is the trust check's business)
    assert_eq!(check(&p, &[], &Policy { allow_unsigned: true }), Err(TrustError::UnsignedTooLarge));
    // without developer mode it is simply unsigned, whatever its size
    assert_eq!(check(&p, &[], &Policy::default()), Err(TrustError::Unsigned));
    // the parser's own ceiling covers a signed browser and nothing near memory exhaustion
    assert!(Package::parse(&big(MAX_PACKAGE - 4096)).is_ok());
    assert_eq!(Package::parse(&big(MAX_PACKAGE)).unwrap_err(), Error::TooLarge);
}

#[test]
fn crc_known_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

// ---- signatures and trust (the fixtures were made by tools/mkmap.py, i.e. by Python's `cryptography` package) ----
const FIXTURE_UNSIGNED: &str = "4d4554414c4d415001000000b0000000030000003d00000016c06f80000000006964203d20636f756e7465720a6e616d65203d20436f756e7465720a76657273696f6e203d20312e302e300a756e7369676e6564203d20747275650a686561705f7061676573203d2036340a636c617373203d206261636b67726f756e640a7065726d697373696f6e203d2066696c65730a6162696c697479203d206d61696e2075692062696e2f636f756e7465720a6162696c697479203d2073796e6320736572766963652062696e2f73796e630a0b00000000006400000062696e2f636f756e7465720800640000006400000062696e2f73796e630c00c8000000040000007265732f69636f6e2e7478747f454c460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f454c4600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069636f6e";
const FIXTURE_SIGNED: &str = "4d4554414c4d415001000000b0000000030000003d00000016c06f80480000006964203d20636f756e7465720a6e616d65203d20436f756e7465720a76657273696f6e203d20312e302e300a756e7369676e6564203d20747275650a686561705f7061676573203d2036340a636c617373203d206261636b67726f756e640a7065726d697373696f6e203d2066696c65730a6162696c697479203d206d61696e2075692062696e2f636f756e7465720a6162696c697479203d2073796e6320736572766963652062696e2f73796e630a0b00000000006400000062696e2f636f756e7465720800640000006400000062696e2f73796e630c00c8000000040000007265732f69636f6e2e7478747f454c460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f454c4600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069636f6ebb39261bf84b32c92a0a11c16a1c12aa565ee75f6e0b3fe29931706e96f024e1e84e2cbfc265ae1ae969a6390e3bb4f9ccbf3b3be6d7b4001f87a6d40980bd9c15dbcb1af4970407";
const KEY: &str = "f91a1d1445f5041ced24082f877ace74bd612467f137add9739fefb746cb3236";
const OTHER_KEY: &str = "d3809747ef2a266a272f28a247bc8e5f33fb98534032cc0a4926bc8a705e2269";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn trusted(name: &str, hex: &str) -> TrustedKey {
    let key: [u8; 32] = unhex(hex).try_into().unwrap();
    TrustedKey { name: name.into(), id: key_id(&key), key }
}

#[test]
fn the_rust_builder_writes_what_the_python_tool_writes() {
    let e = elf();
    assert_eq!(build(MANIFEST, &[("bin/counter", &e), ("bin/sync", &e), ("res/icon.txt", b"icon")]), unhex(FIXTURE_UNSIGNED));
}

#[test]
fn signed_packages() {
    let signed = unhex(FIXTURE_SIGNED);
    let p = Package::parse(&signed).unwrap();
    assert!(p.signature.is_some());
    let strict = Policy::default();
    let keys = [trusted("test", KEY)];
    assert_eq!(check(&p, &keys, &strict), Ok(Trust::Signed("test".into())));
    // a key the system does not know, and a key list that has the right id but the wrong key
    assert_eq!(check(&p, &[trusted("other", OTHER_KEY)], &strict), Err(TrustError::UnknownKey));
    assert_eq!(check(&p, &[], &strict), Err(TrustError::UnknownKey));
    let mut liar = trusted("liar", OTHER_KEY);
    liar.id = keys[0].id;
    assert_eq!(check(&p, &[liar], &strict), Err(TrustError::BadSignature));
    // developer mode does not make a signed package less checked
    assert_eq!(check(&p, &[trusted("other", OTHER_KEY)], &Policy { allow_unsigned: true }), Err(TrustError::UnknownKey));
}

#[test]
fn every_change_to_a_signed_package_is_caught() {
    let signed = unhex(FIXTURE_SIGNED);
    let keys = [trusted("test", KEY)];
    let strict = Policy::default();
    // change one byte anywhere before the signature and repair the checksum: only the signature can notice
    let sig_at = signed.len() - SIG_LEN;
    let mut caught = 0;
    let mut tried = 0;
    for i in (0..sig_at).step_by(MIRI_STRIDE) {
        tried += 1;
        let mut b = signed.clone();
        b[i] ^= 0x01;
        if i >= HEADER {
            let crc = crc32(&b[HEADER..sig_at]);
            b[24..28].copy_from_slice(&crc.to_le_bytes());
        }
        match Package::parse(&b) {
            Err(_) => caught += 1,
            Ok(p) => {
                assert!(check(&p, &keys, &strict).is_err(), "byte {i} changed and the package was accepted");
                caught += 1;
            }
        }
    }
    assert_eq!(caught, tried);
    // and every byte of the signature block itself
    for i in (sig_at..signed.len()).step_by(MIRI_STRIDE) {
        let mut b = signed.clone();
        b[i] ^= 0x80;
        let p = Package::parse(&b).unwrap();
        assert!(check(&p, &keys, &strict).is_err(), "signature byte {i}");
    }
}

#[test]
fn unsigned_packages_and_the_policy() {
    let b = unhex(FIXTURE_UNSIGNED);
    let p = Package::parse(&b).unwrap(); // (its manifest says unsigned = true)
    assert!(p.signature.is_none() && p.manifest.unsigned);
    assert_eq!(check(&p, &[], &Policy::default()), Err(TrustError::Unsigned));
    assert_eq!(check(&p, &[], &Policy { allow_unsigned: true }), Ok(Trust::Unsigned));
    // developer mode alone is not enough: the manifest has to ask for it
    let e = elf();
    let quiet = build(&MANIFEST.replace("unsigned = true\n", ""), &[("bin/counter", &e), ("bin/sync", &e)]);
    let p = Package::parse(&quiet).unwrap();
    assert_eq!(check(&p, &[], &Policy { allow_unsigned: true }), Err(TrustError::Unsigned));
}

#[test]
fn signature_block_sizes() {
    let mut b = unhex(FIXTURE_SIGNED);
    b[28] = 71; // a signature length that is not 0 or 72
    assert_eq!(Package::parse(&b).unwrap_err(), Error::BadSignatureBlock);
    let mut b = unhex(FIXTURE_UNSIGNED);
    b[28] = 72; // claims a signature that is not there
    assert!(Package::parse(&b).is_err());
}

#[test]
fn trust_store_and_policy_files() {
    let ok = std::format!("# keys\ndev = {KEY}\nother = {OTHER_KEY} # second\n");
    let keys = parse_keys(&ok).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].name, "dev");
    assert_eq!(keys[0].id, key_id(&keys[0].key));
    assert!(parse_keys("").unwrap().is_empty());
    for bad in ["dev", "dev = 12", "dev = zz", &std::format!("dev = {KEY}\ndev = {OTHER_KEY}"), &std::format!("Dev = {KEY}"), &std::format!("dev = {KEY}00")] {
        assert!(parse_keys(bad).is_err(), "{bad:?}");
    }
    assert_eq!(parse_policy("").unwrap(), Policy { allow_unsigned: false });
    assert_eq!(parse_policy("allow_unsigned = true\n").unwrap(), Policy { allow_unsigned: true });
    assert_eq!(parse_policy("# c\nallow_unsigned = false").unwrap(), Policy { allow_unsigned: false });
    for bad in ["allow_unsigned = yes", "allow_unsigned", "other = 1"] {
        assert!(parse_policy(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_allfiles_permission_is_its_own() {
    let m = parse_manifest("id = fm\nname = Files\nversion = 1.0.0\nclass = interactive\npermission = display\npermission = allfiles\nability = main ui bin/fm\n").unwrap();
    assert!(m.allfiles && m.display && !m.files && !m.shell);
    assert!(m.has(Permission::AllFiles) && !m.has(Permission::Files));
    let plain = parse_manifest("id = fm\nname = Files\nversion = 1.0.0\nclass = interactive\nability = main ui bin/fm\n").unwrap();
    assert!(!plain.allfiles, "not given unless asked for");
}

#[test]
fn role_desktop_makes_a_shell_client_and_only_that_role_exists() {
    let base = "id = desktop\nname = Desktop\nversion = 1.0.0\nclass = interactive\nability = main ui bin/desktop\n";
    let m = parse_manifest(&std::format!("{base}role = desktop\n")).unwrap();
    assert!(m.desktop && m.shell && m.display, "a desktop is a shell client with the display");
    assert!(!parse_manifest(base).unwrap().desktop, "no role, no desktop");
    assert!(parse_manifest(&std::format!("{base}role = panel\n")).is_err(), "unknown role");
    assert!(parse_manifest(&std::format!("{base}role = desktop\nrole = desktop\n")).is_err(), "role twice");
}

#[test]
fn the_spawn_permission_and_its_budget() {
    let base = "id = term\nname = Terminal\nversion = 1.0.0\nability = main ui bin/term\n";
    let m = parse_manifest(&std::format!("{base}permission = spawn\n")).unwrap();
    assert!(m.spawn && m.has(Permission::Spawn));
    assert_eq!(m.spawn_pages, DEFAULT_SPAWN_PAGES, "spawn without spawn_pages hands down the default");
    assert!(!m.files && !m.allfiles && !m.network, "spawn implies no other permission");
    let m = parse_manifest(&std::format!("{base}permission = spawn\nspawn_pages = 8192\n")).unwrap();
    assert_eq!(m.spawn_pages, 8192);
    let plain = parse_manifest(base).unwrap();
    assert!(!plain.spawn && !plain.has(Permission::Spawn));
    assert_eq!(plain.spawn_pages, 0, "nothing to hand down without spawn");
    assert_eq!(parse_manifest(&std::format!("{base}spawn_pages = 64\n")), Err(Error::BadManifest("spawn_pages needs permission = spawn")));
    for bad in ["0", "1048577", "lots", "-1"] {
        assert!(parse_manifest(&std::format!("{base}permission = spawn\nspawn_pages = {bad}\n")).is_err(), "{bad}");
    }
    assert!(parse_manifest(&std::format!("{base}permission = spawn\nspawn_pages = 1048576\n")).is_ok());
    assert!(parse_manifest(&std::format!("{base}permission = spawn\nspawn_pages = 1\nspawn_pages = 2\n")).is_err(), "duplicate key");
}
