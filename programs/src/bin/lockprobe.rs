#![no_std]
#![no_main]
use metallium_programs::fs::*;
use metallium_programs::io::ErrorKind;
use metallium_programs::*;

// lockprobe <mode> <path>: opens the file and asks for an advisory lock; exit code 0 when it went as the mode says, else a number saying how it did not.
//   1: an exclusive lock must be refused (someone holds a lock)     2: a shared lock must be refused (someone holds an exclusive one)
//   3: take an exclusive lock and exit without releasing it         4: an exclusive lock must be granted, then released
program!("lockprobe", |c| {
    let (mode, path) = (c.argv(1).unwrap_or("0"), c.argv(2).unwrap_or("/data/lock.txt"));
    let Ok(f) = File::open(path) else { return 10 };
    match mode {
        "1" => match f.try_lock(true) {
            Err(e) if e.kind == ErrorKind::WouldBlock => 0,
            Ok(()) => 1,
            Err(_) => 2,
        },
        "2" => match f.try_lock(false) {
            Err(e) if e.kind == ErrorKind::WouldBlock => 0,
            Ok(()) => 1,
            Err(_) => 2,
        },
        "3" => {
            if f.try_lock(true).is_ok() {
                core::mem::forget(f); // (no unlock, no close: the program just ends)
                0
            } else {
                1
            }
        }
        "4" => {
            if f.try_lock(true).is_err() {
                return 1;
            }
            if f.unlock().is_err() { 2 } else { 0 }
        }
        _ => 9,
    }
});
