#![no_std]
#![no_main]
//! MMAP / MUNMAP / MPROTECT test. `arg` selects what to do (mode 0 runs the checks that must all pass and exits with the number of failures;
//! the others do one thing that ends the program, and the conductor looks at how: 1 touch a `PROT_NONE` page, 2 store to a read-only page, 3 run code in
//! a page that is not executable, 4 touch a page after `munmap`, 5 touch more of a mapping than the memory limit allows).
use metallium_programs::*;

const PAGE: u64 = 4096;
const ARENA_LO: u64 = 0x20_0000_0000;
const ARENA_HI: u64 = 0x40_0000_0000;

fn rd(a: u64) -> u8 {
    // SAFETY: only used on addresses this program mapped with `mmap` and has not unmapped.
    unsafe { core::ptr::read_volatile(a as *const u8) }
}
fn wr(a: u64, v: u8) {
    // SAFETY: only used on addresses this program mapped writable with `mmap` and has not unmapped.
    unsafe { core::ptr::write_volatile(a as *mut u8, v) }
}
fn held() -> u64 {
    quota().held
}

fn modes(mode: u64) -> u64 {
    match mode {
        1 => {
            let a = mmap(0, 1, PROT_NONE) as u64;
            rd(a);
            0
        }
        2 => {
            let a = mmap(0, 1, PROT_READ) as u64;
            rd(a);
            wr(a, 1); // (a lazy page, written: the first touch is a store, which the reservation forbids)
            0
        }
        3 => {
            let a = mmap(0, 1, PROT_READ | PROT_WRITE) as u64;
            wr(a, 0);
            // SAFETY: deliberately jumps to a page that is not executable: the kernel must end the program.
            unsafe { core::arch::asm!("blr {a}", a = in(reg) a, clobber_abi("C")) };
            0
        }
        4 => {
            let a = mmap(0, 4, PROT_READ | PROT_WRITE) as u64;
            wr(a + PAGE, 1);
            wr(a + 2 * PAGE, 1);
            if munmap(a + PAGE, 2) != 0 {
                return 99;
            }
            wr(a, 1); // still mapped
            wr(a + 3 * PAGE, 1);
            wr(a + PAGE, 2); // gone: faults
            0
        }
        5 => {
            let q = quota();
            let n = q.limit + 64;
            let a = mmap(0, n, PROT_READ | PROT_WRITE);
            if a < 0 {
                return 98;
            }
            for p in 0..n {
                wr(a as u64 + p * PAGE, 1); // faults once the limit is reached
            }
            0
        }
        _ => 97,
    }
}

program!("mmaptest", |c| {
    if c.arg != 0 {
        return modes(c.arg);
    }
    let mut bad = 0u64;
    let mut check = |name: &str, ok: bool| {
        if !ok {
            println!("mmaptest: FAILED: {name}");
            bad += 1;
        }
    };

    // a mapping is in the arena, zeroed, and costs memory only when touched
    let h0 = held();
    let a = mmap(0, 256, PROT_READ | PROT_WRITE);
    check("mmap returns an address in the arena", a > 0 && (a as u64) >= ARENA_LO && (a as u64) + 256 * PAGE <= ARENA_HI && a as u64 % PAGE == 0);
    let a = a as u64;
    check("an untouched mapping holds no memory", held() == h0);
    check("it reads as zero", (0..256).all(|p| rd(a + p * PAGE) == 0));
    check("reading touches it (256 pages now count)", held() == h0 + 256);
    for p in 0..256 {
        wr(a + p * PAGE + 7, (p * 3 + 1) as u8);
    }
    check("it can be written and read back", (0..256).all(|p| rd(a + p * PAGE + 7) == (p * 3 + 1) as u8));

    // a second mapping is elsewhere, with an unmapped page between
    let b = mmap(0, 4, PROT_READ | PROT_WRITE) as u64;
    check("two mappings do not overlap and are a page apart", b >= ARENA_LO && (b >= a + 257 * PAGE || b + 5 * PAGE <= a));

    // unmapping the middle leaves the ends
    check("munmap of a middle range works", munmap(a + 100 * PAGE, 50) == 0);
    check("the frames of the 50 pages come back", held() == h0 + 256 - 50);
    check("the ends are intact", rd(a + 99 * PAGE + 7) == (99 * 3 + 1) as u8 && rd(a + 150 * PAGE + 7) == (150 * 3 + 1) as u8);
    check("munmap of a range with holes works", munmap(a + 90 * PAGE, 100) == 0);
    check("munmap of nothing works", munmap(a + 100 * PAGE, 10) == 0);
    check("munmap of the heap or the stack is refused", munmap(0x8100_0000, 1) == -5 && munmap(0x8000_0000, 1) == -5);
    check("munmap outside the arena is refused", munmap(ARENA_HI, 1) == -5 && munmap(ARENA_LO - PAGE, 1) == -5 && munmap(a + 1, 1) == -5 && munmap(a, 0) == -5);
    check("munmap of the rest", munmap(a, 256) == 0);
    check("everything is back (the second mapping was never touched)", held() == h0);
    check("a mapping can be freed and the address range used again (fixed)", mmap(a, 8, PROT_READ | PROT_WRITE | MAP_FIXED) == a as i64);
    wr(a, 9);
    check("MAP_FIXED over an earlier mapping gives zeroes", mmap(a, 8, PROT_READ | PROT_WRITE | MAP_FIXED) == a as i64 && rd(a) == 0);
    check("MAP_FIXED outside the arena is refused", mmap(0x8100_0000, 1, PROT_READ | MAP_FIXED) == -5 && mmap(ARENA_HI - PAGE, 2, PROT_READ | MAP_FIXED) == -5 && mmap(a + 1, 1, PROT_READ | MAP_FIXED) == -5);
    check("MAP_FIXED over a mapping and free space together", mmap(a, 16, PROT_READ | PROT_WRITE | MAP_FIXED) == a as i64);

    // write xor execute
    check("write+execute is refused", mmap(0, 1, PROT_WRITE | PROT_EXEC) == -1);
    check("mprotect to write+execute is refused", mprotect(a, 1, PROT_WRITE | PROT_EXEC) == -1);
    check("mprotect of a hole is refused", mprotect(a + 16 * PAGE, 1, PROT_READ) == -5);
    check("mprotect of the heap is refused", mprotect(0x8100_0000, 1, PROT_READ) == -5);
    check("unknown flag bits are refused", mmap(0, 1, 0x1000) == -5 && mprotect(a, 1, 8) == -5);

    // code: write it into a writable page, make it executable, run it, change it, run it again
    let code = mmap(0, 2, PROT_READ | PROT_WRITE) as u64;
    let emit = |value: u32| {
        // SAFETY: `code` is a page this program mapped writable: `mov x0, #value; ret`.
        unsafe {
            core::ptr::write_volatile(code as *mut u32, 0xD280_0000 | (value << 5)); // mov x0, #value
            core::ptr::write_volatile((code + 4) as *mut u32, 0xD65F_03C0); // ret
        }
    };
    emit(42);
    check("mprotect to read+execute", mprotect(code, 2, PROT_READ | PROT_EXEC) == 0);
    let call = |at: u64| -> u64 {
        // SAFETY: `at` holds `mov x0, #n; ret`, made executable by mprotect.
        let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(at as usize) };
        f()
    };
    check("code written before mprotect runs", call(code) == 42);
    check("mprotect back to read+write", mprotect(code, 2, PROT_READ | PROT_WRITE) == 0);
    emit(43);
    check("mprotect to execute again", mprotect(code, 2, PROT_READ | PROT_EXEC) == 0);
    check("the new code runs, not the old", call(code) == 43);
    // an executable page that was never touched (lazy) becomes code on its first fetch
    let z = mmap(0, 1, PROT_READ | PROT_EXEC) as u64;
    check("an untouched read+execute page reads as zero", rd(z) == 0 && rd(z + 4095) == 0);

    // the kernel reads untouched memory on the program's behalf (WAIT_WORD looks at the word: not equal to 1, so it does not sleep)
    let w = mmap(0, 1, PROT_READ | PROT_WRITE) as u64;
    let before = held();
    let r = svc(32, w, 1, 0, 0, 0)[0] as i64;
    check("the kernel faults in an untouched page it is asked to read", held() == before + 1 && r != -5);

    // limits on reservations
    check("a reservation over 4 GiB is refused", mmap(0, (1 << 20) + 1, PROT_READ) == -5);
    let big = mmap(0, 1 << 19, PROT_READ | PROT_WRITE); // 2 GiB, untouched: costs nothing
    let big2 = mmap(0, (1 << 19) + 1, PROT_READ | PROT_WRITE);
    check("2 GiB can be reserved, and the total is capped", big > 0 && big2 == -8);
    check("a reserved region that is touched in one place holds one page", {
        let h = held();
        wr(big as u64 + 12345 * PAGE, 1);
        held() == h + 1
    });
    check("freeing the 2 GiB", munmap(big as u64, 1 << 19) == 0);
    bad
});
