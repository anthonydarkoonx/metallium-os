#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use alloc::string::String;
use metallium_programs::ability::*;
use metallium_programs::*;

// Sample program that checks what its storage really is. Started by the program manager with `permission = files`; argv[1] is its id
// (`fsa` or `fsb`: two packages of this one program). For it `/data` is a private directory. It saves its answer (word 0) and
// 0xFEED (word 1) and ends cleanly. Bits of the answer:
//   0 wrote /data/note.txt and read it back          1 cannot reach the other program's directory by its real path
//   2 cannot read the manager's packages (/data/programs) 3 `..` is refused
//   4 listing /data shows only its own file           5 at most 12 files can be made, not 40
//   6 /system is readable                             7 /system is not writable
//   8 it cannot confine other programs (scope on any task but its own children is refused)
struct Probe {
    id: String,
}

impl Ability for Probe {
    fn on_create(&mut self, _r: Option<(u64, u64)>) {
        let mut code = 0u64;
        let note = format!("secret-of-{}", self.id);
        if fs::write("/data/note.txt", note.as_bytes()).is_ok() && fs::read("/data/note.txt").map_or(false, |b| b == note.as_bytes()) {
            code |= 1;
        }
        let other = if self.id == "fsa" { "fsb" } else { "fsa" };
        if fs::read(&format!("/data/programdata/{other}/note.txt")).is_err() && fs::read(&format!("/data/programdata/{other}")).is_err() {
            code |= 2;
        }
        if fs::read("/data/programs/counter.map").is_err() && fs::read_dir("/data/programs").is_err() {
            code |= 4;
        }
        if fs::read("/data/../system/hello.txt").is_err() {
            code |= 8;
        }
        if fs::read_dir("/data").map_or(false, |l| l.len() == 1 && l[0].name == "note.txt") {
            code |= 16;
        }
        let mut made = 0;
        for i in 0..40 {
            if fs::write(&format!("/data/f{i}"), b"x").is_ok() {
                made += 1;
            }
        }
        // (the default quota is 12 entries, with the note and the file already made; `fsq` has `quota = 100` in its manifest: all 40 fit)
        if (self.id == "fsq" && made == 40) || (self.id != "fsq" && (8..=12).contains(&made)) {
            code |= 32;
        }
        if fs::read("/system/hello.txt").is_ok() {
            code |= 64;
        }
        if fs::write("/system/x", b"x").is_err() {
            code |= 128;
        }
        // confining programs is the parent's right: not mine, whoever the target is (none of these is a program I started)
        if [0u64, 1, 8, 27, 28, 29, 30, 31, 32, 33].iter().all(|&t| fs::scope(t, "/data").is_err()) {
            code |= 256;
        }
        save(code, 0xFEED);
        exit(0);
    }
}

ability!("fsprog", |c: &Ctx| Probe { id: String::from(c.argv(1).unwrap_or("?")) });
