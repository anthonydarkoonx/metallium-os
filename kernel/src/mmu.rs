//! Stage-1 translation: 4 KiB granule, 39-bit VA, TTBR0 only.
//!
//! * L1[0] 0x0000_0000..1G   device, EL1-only (UART, GIC, PCI BARs)
//! * L1[256] 0x40_0000_0000..+1G device, EL1-only (PCIe ECAM)
//! * L1[1] 0x4000_0000..2G   RAM identity map, EL1-only: 2 MiB blocks, never executable; and 4 KiB pages where the kernel image
//!   is: code read + execute, read-only data, and the data, .bss and stacks read + write (the stacks' guard pages are
//!   left unmapped, so an overflow faults instead of overwriting what lies below). No page is both writable and executable
//!   (SCTLR_EL1.WXN makes that a rule rather than a habit), and where the CPU has PAN the kernel cannot touch a page
//!   that EL0 can reach by accident.
//! * TTBR1 0xFFFF_FF80_0000_0000 + pa: the direct map of the RAM above the first GiB of it (`frame::phys::va`), read + write, never executable.
//! * L1[2] 0x8000_0000..3G   per-task user window (4 KiB pages, EL0 access)
//! * L1[8..256] 8G..256G     per-task window for the images of position-independent programs (same, tables made on demand)
use crate::mem;
use crate::sync::Global;
use core::arch::asm;

const VALID_BLOCK: u64 = 0b01;
const VALID_TABLE: u64 = 0b11;
const AF: u64 = 1 << 10;
const SH_INNER: u64 = 3 << 8;
const ATTR_NORMAL: u64 = 0 << 2;
const ATTR_DEVICE: u64 = 1 << 2;
const AP_EL0: u64 = 1 << 6; // AP[1]: EL0 may access
const AP_RO: u64 = 1 << 7; // AP[2]: read-only
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
/// A 1 GiB block of device memory at the physical address in its low bits: EL1 only, never executable (for the platform's `map_devices`).
pub const DEVICE_BLOCK: u64 = VALID_BLOCK | ATTR_DEVICE | AF | PXN | UXN;
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// Software bits of a user descriptor (the hardware ignores bits 58:55). `ANON`: the page belongs to an `MMAP` region (valid or not, in a
/// frame, swapped out, or not yet touched). `LAZY` (with bit 0 clear): reserved by `MMAP` and not touched yet; the permission bits are
/// those the page will get when the first access to it allocates a zeroed frame (`populate_lazy`).
const LAZY: u64 = 1 << 57;
const ANON: u64 = 1 << 58;
const PERM_MASK: u64 = AP_EL0 | AP_RO | UXN;

/// Protection bits of `MMAP`/`MPROTECT`. Write and execute never go together (checked by the system calls); write or execute implies read.
pub const PROT_R: u8 = 1;
pub const PROT_W: u8 = 2;
pub const PROT_X: u8 = 4;

/// The permission bits of a descriptor for `prot`: none is read-only with no EL0 access at all (a guard).
fn prot_bits(prot: u8) -> u64 {
    if prot & PROT_X != 0 {
        AP_EL0 | AP_RO
    } else if prot & PROT_W != 0 {
        AP_EL0 | UXN
    } else if prot & PROT_R != 0 {
        AP_EL0 | AP_RO | UXN
    } else {
        AP_RO | UXN
    }
}

fn prot_of(pte: u64) -> u8 {
    if pte & AP_EL0 == 0 {
        return 0;
    }
    PROT_R | if pte & AP_RO == 0 { PROT_W } else { 0 } | if pte & UXN == 0 { PROT_X } else { 0 }
}

pub const USER_LO: usize = 0x8000_0000;
pub const USER_HI: usize = 0xC000_0000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// read + execute
    Rx,
    /// read + write, never executable
    Rw,
    /// read only, never executable
    Ro,
    /// read + write device memory (nGnRnE), never executable
    Device,
}

#[repr(C, align(4096))]
struct Table([u64; 512]);

static KERNEL_L1: Global<Table> = Global::new(Table([0; 512]));
static KERNEL_L2: Global<Table> = Global::new(Table([0; 512]));
/// TTBR1: the direct map of the RAM above the identity window (`frame::phys::va`): 1 GiB blocks, and for the last, partial GiB the
/// 2 MiB blocks of `KERNEL_L2_HI`. The same for every task; the user windows live in TTBR0.
static KERNEL_L1_HI: Global<Table> = Global::new(Table([0; 512]));
static KERNEL_L2_HI: Global<Table> = Global::new(Table([0; 512]));
/// 4 KiB tables for the 2 MiB blocks the kernel image lies in (about 4.5 MiB with the boot core's stack, at any page: at most three blocks, 6 here for headroom; `init` checks).
const KERNEL_L3_N: usize = 6;
static KERNEL_L3: Global<[Table; KERNEL_L3_N]> = Global::new([const { Table([0; 512]) }; KERNEL_L3_N]);

/// Per core: 64 KiB of kernel stack and an unmapped guard below it, and 16 KiB for the emergency stack (a stack overflow is reported on it). The boot core's
/// stack and guard are at the end of the image (linker.ld, boot.S use the same numbers); the other cores' are made from RAM in `smp.rs`.
pub const KSTACK_SIZE: usize = 0x10000;
pub const KSTACK_GUARD: usize = 0x4000;
pub const KSTACK_EMERGENCY: usize = 0x4000;
pub const KSTACK_STRIDE: usize = KSTACK_SIZE + KSTACK_GUARD;

extern "C" {
    static __stack_top: u8;
    static __kernel_start: u8;
    static __text_end: u8;
    static __ro_end: u8;
}

/// If `addr` is in the guard of a core's kernel stack: which core.
pub fn kstack_guard_hit(addr: u64) -> Option<usize> {
    // SAFETY: `__stack_top` is a linker symbol; only its address is taken, it is never read.
    let top = unsafe { &__stack_top as *const u8 as usize };
    let a = addr as usize;
    if (top - KSTACK_STRIDE..top - KSTACK_SIZE).contains(&a) {
        return Some(0);
    }
    (1..crate::smp::MAX_CPUS).find(|&n| {
        let g = crate::smp::GUARD_START[n].load(core::sync::atomic::Ordering::Relaxed);
        g != 0 && (g..g + KSTACK_GUARD).contains(&a)
    })
}

/// Take pages out of the kernel's identity map (a stack guard made from RAM): a 2 MiB block that holds them is first made a table of 4 KiB pages with the same
/// mapping. Boot core, before the other cores run (so that nobody uses a block while it is being replaced). `false` if the pages are not identity-mapped RAM.
pub fn unmap_kernel_pages(start: usize, bytes: usize) -> bool {
    let gib = crate::platform::RAM_BASE & !0x3FFF_FFFF;
    if start < crate::platform::RAM_BASE || start + bytes > crate::frame::phys::ID_END || start % mem::PAGE != 0 || bytes % mem::PAGE != 0 {
        return false;
    }
    let mut l2g = KERNEL_L2.get();
    let l2 = &mut l2g.0;
    // First every 2 MiB block the pages lie in becomes a table (nothing is unmapped yet, so a failure here leaves the map as it was), then the pages go.
    for page in (start..start + bytes).step_by(mem::PAGE) {
        let bi = (page - gib) >> 21;
        if bi >= 512 || l2[bi] & 0b11 == 0 {
            return false; // (not mapped at all)
        }
        if l2[bi] & 0b11 == 0b01 {
            // a block: the same mapping in 4 KiB pages (break before make: empty the entry and flush before the table goes in)
            let Some(f) = mem::alloc_kind(mem::OWNER_KERNEL, mem::FKind::Pinned) else { return false };
            let attrs = l2[bi] & !ADDR_MASK & !0b11;
            let base = gib + (bi << 21);
            for (i, e) in table(f).iter_mut().enumerate() {
                *e = (base + i * mem::PAGE) as u64 | 0b11 | attrs;
            }
            l2[bi] = 0;
            flush_tlb();
            l2[bi] = f as u64 | VALID_TABLE;
        }
    }
    for page in (start..start + bytes).step_by(mem::PAGE) {
        let bi = (page - gib) >> 21;
        table((l2[bi] & ADDR_MASK) as usize)[(page >> 12) & 511] = 0;
    }
    flush_tlb();
    true
}

/// `ram` is the size of RAM in bytes (a multiple of 2 MiB where it reaches past the identity window).
pub fn init(ram: usize) {
    // The MMU is off until the end of this function, so no atomic operations (the checked `Global::get` uses them: on the board
    // they fault on Device memory); only the boot core runs and nothing else touches these tables yet.
    // SAFETY: boot core only, before secondaries start; each table is borrowed once, here.
    let (l1_guard, l2_guard, l3s) = unsafe { (KERNEL_L1.boot_get(), KERNEL_L2.boot_get(), KERNEL_L3.boot_get()) };
    // SAFETY: as above, for the two direct-map tables.
    let (hi1_guard, hi2_guard) = unsafe { (KERNEL_L1_HI.boot_get(), KERNEL_L2_HI.boot_get()) };
    build_direct_map(&mut hi1_guard.0, &mut hi2_guard.0, ram);
    let l1 = &mut l1_guard.0;
    crate::platform::map_devices(l1);
    // RAM: 2 MiB blocks, except where the kernel stacks are (4 KiB pages, the guards unmapped)
    let normal = ATTR_NORMAL | SH_INNER | AF | UXN | PXN;
    let l2 = &mut l2_guard.0;
    // (the 1 GiB of address space that holds the RAM: its first-level slot, and the physical address of its start)
    let gib = crate::platform::RAM_BASE & !0x3FFF_FFFF;
    for (i, e) in l2.iter_mut().enumerate() {
        let pa = gib + i * (2 << 20);
        #[allow(clippy::absurd_extreme_comparisons)] // the bound is 0 on some platforms (QEMU), non-zero on others
        let unmapped = pa < crate::platform::RAM_UNMAPPED_BELOW;
        *e = if unmapped { 0 } else { pa as u64 | VALID_BLOCK | normal };
    }
    // SAFETY: the four are linker symbols; only their addresses are taken, they are never read.
    let (start, text_end, ro_end, top) = unsafe {
        (&__kernel_start as *const u8 as usize, &__text_end as *const u8 as usize, &__ro_end as *const u8 as usize, &__stack_top as *const u8 as usize)
    };
    let mut used = 0;
    assert!(((top - 1 - gib) >> 21) - ((start - gib) >> 21) < KERNEL_L3_N, "the kernel image (with its stacks) spans more 2 MiB blocks than KERNEL_L3_N");
    for block in (start - gib) >> 21..=(top - 1 - gib) >> 21 {
        let l3 = &mut l3s[used].0;
        used += 1;
        let base = gib + (block << 21);
        for (p, e) in l3.iter_mut().enumerate() {
            let pa = base + p * mem::PAGE;
            let guard = (top - KSTACK_STRIDE..top - KSTACK_SIZE).contains(&pa); // (the boot core's; the others' are made later, in `unmap_kernel_pages`)
            // (pages of the block outside the image are ordinary RAM: read + write, never executable)
            let perm = if (start..text_end).contains(&pa) {
                AP_RO | UXN // code
            } else if (text_end..ro_end).contains(&pa) {
                AP_RO | UXN | PXN
            } else {
                UXN | PXN
            };
            *e = if guard { 0 } else { pa as u64 | VALID_TABLE | ATTR_NORMAL | SH_INNER | AF | perm };
        }
        l2[block] = l3.as_ptr() as u64 | VALID_TABLE;
    }
    l1[gib >> 30] = l2.as_ptr() as u64 | VALID_TABLE;
    enable_this_cpu();
}

/// The direct map: RAM from the end of the identity window to the end of RAM, read + write, never executable, global. Ranges that are not RAM (`platform::ram_hole`) are not mapped
/// (a device window must not be mapped as cacheable memory: a speculative read of a register can have side effects). One 1 GiB block per GiB of RAM; a GiB that holds a hole is
/// mapped in 2 MiB blocks (only one GiB may be mapped that way: one second-level table).
fn build_direct_map(l1: &mut [u64; 512], l2: &mut [u64; 512], ram: usize) {
    use crate::frame::phys::{GIB, ID_END};
    // (the MMU is off here: ask the platform directly, no cached state)
    let overlaps_hole = |start: usize, end: usize| (0..).map_while(crate::platform::ram_hole).any(|(h0, h1)| start < h1 && end > h0);
    let normal = ATTR_NORMAL | SH_INNER | AF | UXN | PXN;
    let end = crate::platform::RAM_BASE + ram;
    let mut gib = ID_END;
    let mut split = false;
    while gib < end {
        let last = gib + GIB;
        if !overlaps_hole(gib, last.min(end)) && last <= end {
            l1[gib >> 30] = gib as u64 | VALID_BLOCK | normal;
        } else if overlaps_hole(gib, last.min(end)) && (0..).map_while(crate::platform::ram_hole).any(|(h0, h1)| h0 <= gib && h1 >= last.min(end)) {
            // (wholly a hole: nothing is mapped)
        } else {
            assert!(!split, "the direct map: more than one GiB of RAM that is split by a hole or ends short of a whole GiB");
            split = true;
            for (i, e) in l2.iter_mut().enumerate() {
                let pa = gib + i * (2 << 20);
                *e = if pa + (2 << 20) <= end && !overlaps_hole(pa, pa + (2 << 20)) { pa as u64 | VALID_BLOCK | normal } else { 0 };
            }
            l1[gib >> 30] = l2.as_ptr() as u64 | VALID_TABLE;
        }
        gib += GIB;
    }
}

/// Turn the MMU on for the calling core with the shared kernel tables.
pub fn enable_this_cpu() {
    let mair: u64 = 0x00FF; // attr0 = normal write-back, attr1 = device-nGnRnE
    let parange: u64;
    // SAFETY: reads ID_AA64MMFR0_EL1, a read-only feature register; no memory is accessed.
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) parange) };
    let tcr: u64 = 25            // T0SZ: 39-bit VA
        | (1 << 8) | (1 << 10)   // IRGN0/ORGN0 write-back
        | (3 << 12)              // SH0 inner shareable
        | (25 << 16)             // T1SZ: 39-bit VA (the direct map, 512 GiB at `frame::phys::DIRECT_BASE`)
        | (1 << 24) | (1 << 26)  // IRGN1/ORGN1 write-back
        | (3 << 28)              // SH1 inner shareable
        | (2 << 30)              // TG1: 4 KiB granule
        | ((parange & 7) << 32); // IPS
    let ttbr0 = KERNEL_L1.addr() as u64;
    let ttbr1 = KERNEL_L1_HI.addr() as u64;
    // SAFETY: KERNEL_L1 (device block + RAM identity map, built by `init`) maps this very code and stack, so execution continues
    // after the M bit is set; the cache/TLB maintenance first makes the tables visible. Run once per core, interrupts masked.
    unsafe {
        asm!(
            // the tables were written by the boot core (or with the MMU off): finish those writes before this core's walker
            // can look at them, and start from an empty instruction cache
            "dsb ish",
            "ic iallu",
            "dsb nsh",
            "isb",
            "msr mair_el1, {mair}",
            "msr tcr_el1, {tcr}",
            "msr ttbr0_el1, {ttbr}",
            "msr ttbr1_el1, {ttbr1}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            "mrs {t}, sctlr_el1",
            "orr {t}, {t}, #(1 << 0)",   // M
            "orr {t}, {t}, #(1 << 2)",   // C
            "orr {t}, {t}, #(1 << 12)",  // I
            "orr {t}, {t}, #(1 << 19)",  // WXN: a page that can be written cannot be executed, whatever its table entry says
            "orr {t}, {t}, #(1 << 15)",  // UCT: userspace may read CTR_EL0 (cache line sizes)
            "orr {t}, {t}, #(1 << 26)",  // UCI: userspace may clean / flush its DMA buffers (DC CVAC, DC CIVAC)
            "msr sctlr_el1, {t}",
            "isb",
            mair = in(reg) mair, tcr = in(reg) tcr, ttbr = in(reg) ttbr0, ttbr1 = in(reg) ttbr1,
            t = out(reg) _,
        );
    }
    enable_pan();
}

/// Where the CPU has PAN (ARMv8.1), keep EL1 from reading or writing memory that EL0 can reach: clear SCTLR_EL1.SPAN so that
/// every exception from EL0 enters the kernel with PAN set, and set it now for the code that runs before the first one. The
/// kernel reaches a program's frames through the identity map (EL1-only), never through the program's own addresses, so a
/// kernel access that PAN stops is a bug (a pointer a program chose, followed).
fn enable_pan() {
    if !has_pan() {
        return;
    }
    // SAFETY: clears SCTLR_EL1.SPAN (bit 23) and sets PSTATE.PAN (`msr pan, #1`, written as its encoding so that the assembler's
    // target need not name the feature); no memory is accessed.
    unsafe {
        asm!(
            "mrs {t}, sctlr_el1",
            "bic {t}, {t}, #(1 << 23)",
            "msr sctlr_el1, {t}",
            "isb",
            ".inst 0xd500419f",
            "isb",
            t = out(reg) _,
        );
    }
}

fn has_pan() -> bool {
    let mmfr1: u64;
    // SAFETY: reads ID_AA64MMFR1_EL1, a read-only feature register; no memory is accessed.
    unsafe { asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nomem, nostack)) };
    mmfr1 >> 20 & 0xF != 0
}

/// Boot-time check of the rules above, from the live tables and registers of the calling core: (text is read-only and the only
/// executable RAM, nothing writable is executable, WXN is on, PAN is on where the CPU has it).
pub fn audit() -> (bool, bool, bool) {
    // SAFETY: linker symbols; only addresses are taken.
    let (start, text_end) = unsafe { (&__kernel_start as *const u8 as usize, &__text_end as *const u8 as usize) };
    let l1g = KERNEL_L1.get();
    let l1 = &l1g.0;
    let (mut text_ro, mut only_text_x) = (true, true);
    let ram_gib = crate::platform::RAM_BASE >> 30;
    let l2 = table((l1[ram_gib] & ADDR_MASK) as usize);
    let mut leaf_check = |pa: usize, e: u64| {
        if e & 1 == 0 {
            return;
        }
        let exec = e & PXN == 0;
        let writable = e & AP_RO == 0;
        if (start..text_end).contains(&pa) {
            text_ro &= !writable && exec;
        } else if exec {
            only_text_x = false;
        }
        if exec && writable {
            only_text_x = false;
        }
    };
    for (i, &e) in l2.iter().enumerate() {
        let base = (ram_gib << 30) + i * (2 << 20);
        if e & 0b11 == 0b11 {
            let l3 = table((e & ADDR_MASK) as usize);
            for (p, &pe) in l3.iter().enumerate() {
                leaf_check(base + p * mem::PAGE, pe);
            }
        } else {
            leaf_check(base, e);
        }
    }
    let sctlr: u64;
    // SAFETY: reads SCTLR_EL1; no memory is accessed.
    unsafe { asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack)) };
    let wxn = sctlr >> 19 & 1 != 0;
    let pan_ok = !has_pan() || {
        let pan: u64;
        // SAFETY: reads PSTATE.PAN (`mrs`, s3_0_c4_c2_3), which exists only where ID_AA64MMFR1_EL1 says so: checked just above.
        unsafe { asm!("mrs {}, s3_0_c4_c2_3", out(reg) pan, options(nomem, nostack)) };
        pan >> 22 & 1 != 0 && sctlr >> 23 & 1 == 0
    };
    (text_ro && only_text_x, wxn, pan_ok)
}

fn table(pa: usize) -> &'static mut [u64; 512] {
    assert!(crate::frame::phys::is_ram_page(pa), "mmu::table: {pa:#x} is not a RAM frame");
    // SAFETY: `pa` is a whole RAM frame (checked). A table is only reached while the owning task's lock (or boot, single core)
    // is held, which is what keeps two live `&mut` to one table from existing; callers use the reference within one operation.
    unsafe { &mut *(crate::frame::phys::va(pa) as *mut [u64; 512]) }
}

/// New user address space: kernel mappings copied in, empty user window.
pub fn new_space(owner: mem::Owner) -> Option<usize> {
    let l1_pa = mem::alloc_kind(owner, mem::FKind::PageTable)?;
    let l2_pa = mem::alloc_kind(owner, mem::FKind::PageTable)?;
    let l1 = table(l1_pa);
    let kernel = KERNEL_L1.get();
    l1[0] = kernel.0[0];
    l1[1] = kernel.0[1];
    l1[3] = kernel.0[3]; // (empty unless the SoC's peripherals live there: see `init`)
    l1[2] = l2_pa as u64 | VALID_TABLE;
    Some(l1_pa)
}

fn in_user_range(va: usize) -> bool {
    (USER_LO..USER_HI).contains(&va) || (crate::task::PIE_LO..crate::task::PIE_HI).contains(&va)
}

fn in_user(va: usize) -> bool {
    in_user_range(va) && va % mem::PAGE == 0
}

/// The L1 entries that hold user tables: the fixed window and the position-independent range.
fn user_l1_entries() -> impl Iterator<Item = usize> {
    core::iter::once(2).chain(crate::task::PIE_LO >> 30..crate::task::PIE_HI >> 30)
}

/// The L2 table for the 1 GiB around `va` (made if `create` names an owner).
fn l2_for(l1: usize, va: usize, create: Option<mem::Owner>) -> Option<&'static mut [u64; 512]> {
    if !in_user_range(va) {
        return None; // (L1 entries outside the user ranges hold the kernel's own tables)
    }
    let e = &mut table(l1)[(va >> 30) & 511];
    if *e & 1 == 0 {
        *e = mem::alloc_kind(create?, mem::FKind::PageTable)? as u64 | VALID_TABLE;
    }
    Some(table((*e & ADDR_MASK) as usize))
}

fn leaf(l1: usize, va: usize, create: Option<mem::Owner>) -> Option<&'static mut u64> {
    let l2 = l2_for(l1, va, create)?;
    let i2 = (va >> 21) & 511;
    if l2[i2] & 1 == 0 {
        let owner = create?;
        l2[i2] = mem::alloc_kind(owner, mem::FKind::PageTable)? as u64 | VALID_TABLE;
    }
    let l3 = table((l2[i2] & ADDR_MASK) as usize);
    Some(&mut l3[(va >> 12) & 511])
}

pub fn map_user(l1: usize, va: usize, pa: usize, perm: Perm, owner: mem::Owner) -> Result<(), ()> {
    if !in_user(va) {
        return Err(());
    }
    let mut pte = pa as u64 | VALID_TABLE | AF | NG | PXN;
    pte |= if perm == Perm::Device { ATTR_DEVICE | (2 << 8) } else { ATTR_NORMAL | SH_INNER };
    pte |= match perm {
        Perm::Rx => AP_EL0 | AP_RO,
        Perm::Rw => AP_EL0 | UXN,
        Perm::Ro => AP_EL0 | AP_RO | UXN,
        Perm::Device => AP_EL0 | UXN,
    };
    let slot = leaf(l1, va, Some(owner)).ok_or(())?;
    if *slot != 0 {
        return Err(()); // mapped, or swapped out: either way the address is taken
    }
    *slot = pte;
    Ok(())
}

pub fn unmap_user(l1: usize, va: usize) {
    if in_user(va) {
        if let Some(slot) = leaf(l1, va, None) {
            *slot = 0;
        }
    }
}

/// What a user page's descriptor says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    /// Nothing mapped.
    Absent,
    /// In a frame. `young`: the access flag is set (the page was touched since it was last aged). `anon`: a page of an `MMAP` region.
    Resident { pa: usize, young: bool, exec: bool, anon: bool },
    /// Reserved by `MMAP` and not touched yet: the protection (`PROT_*`) it will have. The first access allocates a zeroed frame.
    Lazy(u8),
    /// In the swap store: the handle to load it back with.
    Swapped(u32),
    /// Written to the disk by the pager (pager.rs): the disk slot to read it back from.
    Disk(u32),
}

/// Descriptor of a page that has been swapped out: *invalid* (bit 0 clear, so every access faults), with a
/// software-use bit set and the swap handle where the frame address was. The permission bits are kept, so
/// bringing the page back restores exactly the mapping it had.
const SWAPPED: u64 = 1 << 56;
/// With `SWAPPED`: the page is not in the store but on disk, and the number in the address field is a disk slot.
const ON_DISK: u64 = 1 << 55;

pub fn inspect(l1: usize, va: usize) -> Page {
    let va = va & !(mem::PAGE - 1);
    if !in_user(va) {
        return Page::Absent;
    }
    match leaf(l1, va, None) {
        Some(&mut pte) if pte & 1 != 0 => Page::Resident { pa: (pte & ADDR_MASK) as usize, young: pte & AF != 0, exec: pte & UXN == 0, anon: pte & ANON != 0 },
        Some(&mut pte) if pte & LAZY != 0 => Page::Lazy(prot_of(pte)),
        Some(&mut pte) if pte & SWAPPED != 0 && pte & ON_DISK != 0 => Page::Disk(((pte & ADDR_MASK) >> 12) as u32),
        Some(&mut pte) if pte & SWAPPED != 0 => Page::Swapped(((pte & ADDR_MASK) >> 12) as u32),
        _ => Page::Absent,
    }
}

/// Reserve the page at `va` for `MMAP`: nothing is allocated (but the page-table pages, owned by `owner`) until it is first touched.
pub fn reserve_anon(l1: usize, va: usize, prot: u8, owner: mem::Owner) -> Result<(), ()> {
    if !in_user(va) {
        return Err(());
    }
    let slot = leaf(l1, va, Some(owner)).ok_or(())?;
    if *slot != 0 {
        return Err(());
    }
    *slot = LAZY | ANON | prot_bits(prot);
    Ok(())
}

/// Forget a reserved page that was never touched; false if the descriptor is not one.
pub fn clear_lazy(l1: usize, va: usize) -> bool {
    match leaf(l1, va & !(mem::PAGE - 1), None) {
        Some(slot) if *slot & 1 == 0 && *slot & LAZY != 0 => {
            *slot = 0;
            true
        }
        _ => false,
    }
}

/// First touch of a reserved page: map the (zeroed) frame `pa` with the permissions reserved for it. False if the descriptor is not a reserved page.
pub fn populate_lazy(l1: usize, va: usize, pa: usize) -> bool {
    let Some(slot) = leaf(l1, va & !(mem::PAGE - 1), None) else { return false };
    if *slot & 1 != 0 || *slot & LAZY == 0 {
        return false;
    }
    let exec = *slot & UXN == 0 && *slot & AP_EL0 != 0;
    if exec {
        sync_icache(pa, mem::PAGE);
    }
    *slot = pa as u64 | VALID_TABLE | AF | NG | PXN | ATTR_NORMAL | SH_INNER | ANON | (*slot & PERM_MASK);
    // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
    unsafe { asm!("dsb ishst", "isb") };
    true
}

/// Is the page at `va` part of an `MMAP` region (in any state)? `None`: nothing is there.
pub fn is_anon(l1: usize, va: usize) -> Option<bool> {
    let slot = leaf(l1, va & !(mem::PAGE - 1), None)?;
    (*slot != 0).then_some(*slot & ANON != 0)
}

/// Change the protection of an `MMAP` page, whatever its state (a swapped-out or reserved page keeps it in its descriptor). `None`: not an
/// `MMAP` page. `Some(Some(pa))`: it is in frame `pa` and has become executable, so the caller makes the code visible to instruction fetch
/// (`clean_dcache_pou`, `flush_icache`); in any case the caller flushes the TLBs after the last page, which makes the new permissions apply.
pub fn set_prot(l1: usize, va: usize, prot: u8) -> Option<Option<usize>> {
    let slot = leaf(l1, va & !(mem::PAGE - 1), None)?;
    if *slot == 0 || *slot & ANON == 0 {
        return None;
    }
    let was_exec = *slot & UXN == 0 && *slot & AP_EL0 != 0;
    *slot = (*slot & !PERM_MASK) | prot_bits(prot);
    let now_exec = prot & PROT_X != 0;
    if *slot & 1 != 0 {
        // SAFETY: barrier only; publishes the descriptor store above to the table walkers.
        unsafe { asm!("dsb ishst") };
        if now_exec && !was_exec {
            return Some(Some((*slot & ADDR_MASK) as usize));
        }
    }
    Some(None)
}

/// Is every page of `va..va + pages * PAGE` unmapped (no frame, no swapped page, no reservation)? Skips whole empty tables, so a large
/// empty range is cheap to check.
pub fn range_free(l1: usize, va: usize, pages: usize) -> bool {
    let Some(end) = pages.checked_mul(mem::PAGE).and_then(|n| va.checked_add(n)) else { return false };
    let mut a = va;
    while a < end {
        if !in_user_range(a) {
            return false;
        }
        let e1 = table(l1)[(a >> 30) & 511];
        if e1 & 1 == 0 {
            a = (a | ((1 << 30) - 1)) + 1;
            continue;
        }
        let e2 = table((e1 & ADDR_MASK) as usize)[(a >> 21) & 511];
        if e2 & 1 == 0 {
            a = (a | ((1 << 21) - 1)) + 1;
            continue;
        }
        if table((e2 & ADDR_MASK) as usize)[(a >> 12) & 511] != 0 {
            return false;
        }
        a += mem::PAGE;
    }
    true
}

/// Mapped now, or swapped out (the address is taken either way).
pub fn is_present(l1: usize, va: usize) -> bool {
    inspect(l1, va) != Page::Absent
}

/// Clock aging: if the page at `va` is still in frame `pa`, clear its access flag and report whether it was set.
/// The caller flushes the TLB afterwards, so the next access reloads the descriptor and faults. `None`: the
/// mapping is not what the caller expects.
pub fn age(l1: usize, va: usize, pa: usize) -> Option<bool> {
    let slot = leaf(l1, va, None)?;
    if *slot & 1 == 0 || (*slot & ADDR_MASK) as usize != pa {
        return None;
    }
    let young = *slot & AF != 0;
    *slot &= !AF;
    Some(young)
}

/// An access flag fault: the page was touched after being aged. Set the flag; false if the descriptor does
/// not describe such a page.
pub fn touch(l1: usize, va: usize) -> bool {
    match leaf(l1, va & !(mem::PAGE - 1), None) {
        Some(slot) if *slot & 1 != 0 && *slot & AF == 0 => {
            *slot |= AF;
            // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
            unsafe { asm!("dsb ishst", "isb") };
            true
        }
        _ => false,
    }
}

/// First step of swapping a page out: make the mapping invalid (break), returning the old descriptor. The
/// caller flushes all TLBs, then copies the page away, then calls `evict_commit` (or `evict_abort`).
pub fn evict_begin(l1: usize, va: usize, pa: usize) -> Option<u64> {
    let slot = leaf(l1, va, None)?;
    let old = *slot;
    if old & 1 == 0 || (old & ADDR_MASK) as usize != pa {
        return None;
    }
    *slot = 0;
    Some(old)
}

pub fn evict_abort(l1: usize, va: usize, old: u64) {
    if let Some(slot) = leaf(l1, va, None) {
        *slot = old;
        // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
        unsafe { asm!("dsb ishst", "isb") };
    }
}

pub fn evict_commit(l1: usize, va: usize, old: u64, handle: u32) {
    if let Some(slot) = leaf(l1, va, None) {
        *slot = (old & !ADDR_MASK & !1) | SWAPPED | (handle as u64) << 12;
        // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
        unsafe { asm!("dsb ishst", "isb") };
    }
}

/// Map a swapped-out page back at `va` in frame `pa`, whose content is already in place.
pub fn install_resident(l1: usize, va: usize, pa: usize) -> bool {
    let Some(slot) = leaf(l1, va, None) else { return false };
    if *slot & 1 != 0 || *slot & SWAPPED == 0 {
        return false;
    }
    let exec = *slot & UXN == 0;
    if exec {
        sync_icache(pa, mem::PAGE); // freshly written bytes must be visible to instruction fetch
    }
    *slot = (*slot & !ADDR_MASK & !SWAPPED & !ON_DISK) | pa as u64 | VALID_TABLE | AF;
    // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
    unsafe { asm!("dsb ishst", "isb") };
    true
}

/// Forget a swapped-out page without bringing it back; returns its handle (and whether it was a disk slot).
pub fn clear_swapped(l1: usize, va: usize) -> Option<(u32, bool)> {
    let slot = leaf(l1, va & !(mem::PAGE - 1), None)?;
    if *slot & 1 != 0 || *slot & SWAPPED == 0 {
        return None;
    }
    let h = ((*slot & ADDR_MASK) >> 12) as u32;
    let disk = *slot & ON_DISK != 0;
    *slot = 0;
    Some((h, disk))
}

/// The page at `va` goes from the swap store (handle `handle`) to disk slot `slot`; false if the descriptor is not
/// exactly that store entry any more.
pub fn swapped_to_disk(l1: usize, va: usize, handle: u32, slot_no: u32) -> bool {
    let Some(slot) = leaf(l1, va & !(mem::PAGE - 1), None) else { return false };
    if *slot & 1 != 0 || *slot & SWAPPED == 0 || *slot & ON_DISK != 0 || ((*slot & ADDR_MASK) >> 12) as u32 != handle {
        return false;
    }
    *slot = (*slot & !ADDR_MASK) | ON_DISK | (slot_no as u64) << 12;
    // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
    unsafe { asm!("dsb ishst", "isb") };
    true
}

/// The first page at or after `from` (a page-aligned user address) that is in the swap store (not on disk) and is not code: its
/// address and handle. Executable pages never go to the pager (it would be handing it the program's instructions to change).
pub fn find_swapped(l1: usize, from: usize) -> Option<(usize, u32)> {
    for i1 in user_l1_entries() {
        let e1 = table(l1)[i1];
        if e1 & 1 == 0 || (i1 + 1) << 30 <= from {
            continue;
        }
        let l2 = table((e1 & ADDR_MASK) as usize);
        for i2 in 0..512 {
            if l2[i2] & 1 == 0 {
                continue;
            }
            let l3 = table((l2[i2] & ADDR_MASK) as usize);
            for i3 in 0..512 {
                let va = (i1 << 30) + (i2 << 21) + (i3 << 12);
                let pte = l3[i3];
                if va >= from && pte & 1 == 0 && pte & SWAPPED != 0 && pte & ON_DISK == 0 && pte & UXN != 0 {
                    return Some((va, ((pte & ADDR_MASK) >> 12) as u32));
                }
            }
        }
    }
    None
}

/// Call `f` with the handle of every swapped-out page of the address space `l1`, and whether it is a disk slot.
pub fn for_each_swapped(l1: usize, mut f: impl FnMut(u32, bool)) {
    for i1 in user_l1_entries() {
        let e1 = table(l1)[i1];
        if e1 & 1 == 0 {
            continue;
        }
        for &e2 in table((e1 & ADDR_MASK) as usize).iter() {
            if e2 & 1 == 0 {
                continue;
            }
            for &pte in table((e2 & ADDR_MASK) as usize).iter() {
                if pte & 1 == 0 && pte & SWAPPED != 0 {
                    f(((pte & ADDR_MASK) >> 12) as u32, pte & ON_DISK != 0);
                }
            }
        }
    }
}

pub fn is_mapped(l1: usize, va: usize) -> bool {
    in_user(va & !(mem::PAGE - 1)) && leaf(l1, va & !(mem::PAGE - 1), None).map_or(false, |p| *p & 1 != 0)
}

/// Software page-table walk (used to validate user pointers).
pub fn translate(l1: usize, va: usize) -> Option<usize> {
    translate_for(l1, va, false)
}

/// Like `translate`, for an address the *kernel is about to write* on the program's behalf: None if the program's own mapping is read-only
/// (code, `Perm::Ro` shared pages). The kernel reaches RAM through its own read-write mapping, so without this check a program could get the
/// kernel to write into a page it is not allowed to write.
pub fn translate_writable(l1: usize, va: usize) -> Option<usize> {
    translate_for(l1, va, true)
}

fn translate_for(l1: usize, va: usize, write: bool) -> Option<usize> {
    let page = va & !(mem::PAGE - 1);
    if !in_user(page) {
        return None;
    }
    let pte = *leaf(l1, page, None)?;
    if pte & 1 == 0 || pte & AP_EL0 == 0 || (write && pte & AP_RO != 0) {
        return None; // (a page the program may not touch at all, `PROT_NONE`, is not read or written for it either)
    }
    Some((pte & ADDR_MASK) as usize | (va & (mem::PAGE - 1)))
}

/// Move one private user page to another frame while its owner may be running on another core.
///
/// Break-before-make: the mapping is first made invalid and the TLBs of *all* cores are
/// flushed, so nobody can still be using the old frame; only then is the page copied and the
/// mapping re-established. A core touching the page in the window takes a translation fault;
/// its handler waits for the kernel lock, which is held for this whole operation, finds the
/// mapping valid again, and simply retries (see `trap::lower_sync`).
/// Returns false (touching nothing) if the mapping is not what the caller expects.
pub fn migrate_user_page(l1: usize, va: usize, old_pa: usize, new_pa: usize) -> bool {
    let Some(slot) = leaf(l1, va, None) else { return false };
    let old = *slot;
    if old & 1 == 0 || (old & ADDR_MASK) as usize != old_pa {
        return false;
    }
    *slot = 0;
    flush_tlb();
    // SAFETY: sole caller (`compact::migrate`) passes a Movable frame and a Free frame re-validated under the mem lock, so both are
    // distinct whole RAM frames; the mapping was just broken and TLBs flushed, so no core is using `old_pa`. Not itself range-checked.
    unsafe { core::ptr::copy(crate::frame::phys::va(old_pa) as *const u8, crate::frame::phys::va(new_pa) as *mut u8, mem::PAGE) };
    if old & UXN == 0 {
        sync_icache(new_pa, mem::PAGE); // executable page: fresh bytes must be visible to fetch
    }
    *slot = (old & !ADDR_MASK) | new_pa as u64;
    // SAFETY: barrier only; publishes the descriptor store above to the table walkers and synchronises the context.
    unsafe { asm!("dsb ishst", "isb") };
    true
}

/// Run on the kernel's own tables (no user mappings). Needed before a task's page tables are
/// freed: the dying task's address space is still this core's active TTBR0 until then, and a
/// freed table frame can be handed straight back out (and zeroed) by the allocator.
pub fn use_kernel_tables() {
    switch_to(KERNEL_L1.addr() as usize, 0);
}

/// Install `l1` with address-space id `asid` (tasks use tid + 1; the kernel's own table is 0).
/// User pages are non-global, so their TLB entries are tagged with the ASID and survive a switch
/// away and back: no TLB flush on the hot path. (Reusing an ASID for a new address space is made
/// safe by the broadcast flush in `task::die`.)
pub fn switch_to(l1: usize, asid: u16) {
    // A task with no address space has l1 == 0; running on it would unmap the kernel (it runs from TTBR0 too), so refuse.
    assert!(l1 != 0 && l1 % mem::PAGE == 0, "switch_to: bad page-table root {l1:#x}");
    // SAFETY: `l1` is a page-aligned root that is the kernel table or a task table (copy of the kernel mappings); only the
    // ASID/base register is written, followed by an isb.
    unsafe { asm!("msr ttbr0_el1, {}", "isb", in(reg) l1 as u64 | (asid as u64) << 48) };
}

pub fn flush_tlb() {
    // SAFETY: TLB invalidate (inner-shareable) bracketed by barriers; it only drops cached translations, so nothing stale remains.
    unsafe { asm!("dsb ishst", "tlbi vmalle1is", "dsb ish", "isb") };
}

/// Make freshly written code visible to instruction fetch.
pub fn sync_icache(pa: usize, len: usize) {
    clean_dcache_pou(pa, len);
    flush_icache();
}

/// Clean the data cache of `pa..pa+len` to the point of unification (the first half of `sync_icache`: do it for every page, then `flush_icache` once).
pub fn clean_dcache_pou(pa: usize, len: usize) {
    let step = crate::cache::line();
    let pa = crate::frame::phys::cache_va(pa); // (a page above the identity window is reached through the direct map: the instruction takes a virtual address)
    let mut a = pa & !(step - 1);
    while a < pa + len {
        // SAFETY: `dc cvau` cleans one line inside `pa..pa+len` (RAM the caller just wrote); it only writes back, never alters data.
        unsafe { asm!("dc cvau, {}", in(reg) a) };
        a += step;
    }
}

/// Invalidate the instruction caches of every core, after the data caches were cleaned (`clean_dcache_pou`).
pub fn flush_icache() {
    // SAFETY: barriers plus an instruction-cache invalidate to the point of unification; drops cached instructions only, so fetch
    // sees the cleaned bytes.
    unsafe { asm!("dsb ish", "ic ialluis", "dsb ish", "isb") };
}
