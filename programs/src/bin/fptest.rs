#![no_std]
#![no_main]
//! FP/SIMD test: fills all 32 vector registers and FPCR with a pattern that depends on the seed, then keeps checking them while it
//! yields, sleeps and is preempted (other copies run with other seeds, on other cores or the same one). The registers are touched with
//! NEON instructions in assembly because this crate is built soft-float, so the compiler never uses them by itself.
//! `arg` = seed in the low 32 bits; bit 32 set: first check that the registers read as zero before this program wrote any (the
//! first use of FP/SIMD must show nothing of an earlier task). Exit code 0: all good; otherwise the number of mismatches.
use core::arch::asm;
use metallium_programs::*;

#[repr(C, align(16))]
struct Buf([u128; 32]);

fn pattern(seed: u64) -> Buf {
    let mut b = Buf([0; 32]);
    for i in 0..32u64 {
        let lo = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i + 1).wrapping_mul(0xD6E8_FEB8_6659_FD93);
        let hi = lo.rotate_left(17) ^ seed.wrapping_add(i);
        b.0[i as usize] = ((hi as u128) << 64) | lo as u128;
    }
    b
}

fn load_all(b: &Buf) {
    // SAFETY: reads the 512 bytes of `b` into q0-q31 (the compiler never uses those registers: the crate is soft-float).
    unsafe {
        asm!(
            ".arch_extension simd",
            "ldp q0, q1, [{p}, #0]",
            "ldp q2, q3, [{p}, #32]",
            "ldp q4, q5, [{p}, #64]",
            "ldp q6, q7, [{p}, #96]",
            "ldp q8, q9, [{p}, #128]",
            "ldp q10, q11, [{p}, #160]",
            "ldp q12, q13, [{p}, #192]",
            "ldp q14, q15, [{p}, #224]",
            "ldp q16, q17, [{p}, #256]",
            "ldp q18, q19, [{p}, #288]",
            "ldp q20, q21, [{p}, #320]",
            "ldp q22, q23, [{p}, #352]",
            "ldp q24, q25, [{p}, #384]",
            "ldp q26, q27, [{p}, #416]",
            "ldp q28, q29, [{p}, #448]",
            "ldp q30, q31, [{p}, #480]",
            p = in(reg) b.0.as_ptr(),
            options(nostack, readonly)
        )
    }
}

fn store_all(b: &mut Buf) {
    // SAFETY: writes q0-q31 into the 512 bytes of `b`.
    unsafe {
        asm!(
            ".arch_extension simd",
            "stp q0, q1, [{p}, #0]",
            "stp q2, q3, [{p}, #32]",
            "stp q4, q5, [{p}, #64]",
            "stp q6, q7, [{p}, #96]",
            "stp q8, q9, [{p}, #128]",
            "stp q10, q11, [{p}, #160]",
            "stp q12, q13, [{p}, #192]",
            "stp q14, q15, [{p}, #224]",
            "stp q16, q17, [{p}, #256]",
            "stp q18, q19, [{p}, #288]",
            "stp q20, q21, [{p}, #320]",
            "stp q22, q23, [{p}, #352]",
            "stp q24, q25, [{p}, #384]",
            "stp q26, q27, [{p}, #416]",
            "stp q28, q29, [{p}, #448]",
            "stp q30, q31, [{p}, #480]",
            p = in(reg) b.0.as_mut_ptr(),
            options(nostack)
        )
    }
}

fn set_fpcr(v: u64) {
    // SAFETY: FPCR is this program's own floating-point control register.
    unsafe { asm!(".arch_extension fp", "msr fpcr, {v}", v = in(reg) v, options(nomem, nostack)) }
}

fn get_fpcr() -> u64 {
    let v: u64;
    // SAFETY: reads this program's FPCR.
    unsafe { asm!(".arch_extension fp", "mrs {v}, fpcr", v = out(reg) v, options(nomem, nostack)) }
    v
}

program!("fptest", |c| {
    let seed = c.arg & 0xFFFF_FFFF;
    let mut bad = 0u64;
    if c.arg >> 32 & 1 == 1 {
        let mut z = Buf([0; 32]);
        z.0[0] = 1; // (so a store that did not happen would show)
        store_all(&mut z);
        if z.0.iter().any(|&q| q != 0) || get_fpcr() != 0 {
            bad += 1000;
        }
    }
    let want = pattern(seed);
    let fpcr = (seed & 3) << 22; // the rounding mode bits: another thing that must not leak between tasks
    load_all(&want);
    set_fpcr(fpcr);
    let mut spin = 1u64;
    for round in 0..300u64 {
        match round % 4 {
            0 => yield_now(),
            1 => sleep(1),
            _ => {
                for i in 0..20_000u64 {
                    spin = spin.wrapping_mul(6364136223846793005).wrapping_add(i); // (long enough for a timer preemption now and then)
                }
            }
        }
        let mut got = Buf([0; 32]);
        store_all(&mut got);
        if got.0 != want.0 || get_fpcr() != fpcr {
            bad += 1;
            load_all(&want); // (carry on, so one failure does not hide the rest)
            set_fpcr(fpcr);
        }
    }
    bad + (spin & 0) // (keeps the loop)
});
