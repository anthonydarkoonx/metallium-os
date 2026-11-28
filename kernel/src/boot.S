// Metallium-OS boot code and exception vectors (AArch64, QEMU virt).

// Stack, zeroed .bss, FP enabled, exception vectors: for the image at the address it now runs at.
.macro EARLY_SETUP
    adrp    x9, __stack_top
    add     x9, x9, :lo12:__stack_top
    mov     sp, x9
    adrp    x9, __bss_start
    add     x9, x9, :lo12:__bss_start
    adrp    x10, __bss_end
    add     x10, x10, :lo12:__bss_end
1:  cmp     x9, x10
    b.hs    2f
    str     xzr, [x9], #8
    b       1b
2:
    mov     x9, #(1 << 20)          // CPACR_EL1.FPEN = 0b01: EL0 traps on FP/SIMD until a task first uses it (fpu.rs then switches its registers), EL1 may
    msr     cpacr_el1, x9
    adrp    x9, vectors
    add     x9, x9, :lo12:vectors
    msr     vbar_el1, x9
    isb
.endm

// Where the image was before it moved itself (0: it did not); written by the code below into the moved copy.
.section .data.kaslr, "aw"
.global kaslr_old_base
.balign 8
kaslr_old_base:
    .quad   0

// The Linux arm64 "Image" header (Documentation/arch/arm64/booting): the first 64 bytes of the flat image (`make kernel` makes it with objcopy). QEMU, U-Boot
// (`booti`) and most boot loaders recognise it by the magic number and then pass the device tree's address in x0 and place it clear of the image; a
// loader that reads the ELF file instead jumps to `_start` and passes nothing, and the kernel carries on without a tree where it can (see platform.rs).
.section .text.boot0, "ax"
.global _image_header
_image_header:
    b       _start                  // code0: executable code, the entry
    .long   0                       // code1
    .quad   0x80000                 // text_offset: the image's place in RAM (the link address minus the RAM base)
    .quad   __image_size            // image_size: including .bss and the stacks, so the tree is placed after all of it
    .quad   0x2                     // flags: little endian, 4 KiB pages, text_offset is honoured
    .quad   0                       // res2
    .quad   0                       // res3
    .quad   0                       // res4
    .long   0x644d5241              // magic "ARM\x64"
    .long   0                       // res5

.section .text.boot, "ax"
// (The ELF file has the same entry point and load address in its headers; the Image header above is for loaders that look for it.)
.global _start
_start:
    mov     x28, x0                 // the device tree's address (firmware's x0), kept in a callee-saved register for `kaslr_place` and `kmain`
    mrs     x9, mpidr_el1
    and     x9, x9, #0xff
    cbnz    x9, park                // only core 0 boots

    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.ne    2f
    // entered at EL2: drop to EL1 (AArch64)
    mov     x9, #(1 << 31)
    msr     hcr_el2, x9
    mov     x9, #0x33ff
    msr     cptr_el2, x9            // no trapping of FP/SIMD or system registers to EL2
    mov     x9, #0x0800
    movk    x9, #0x30d0, lsl #16
    msr     sctlr_el1, x9           // EL1 with MMU and caches off (the reset value; unknown otherwise)
    mov     x9, #0x3c5              // EL1h, DAIF masked
    msr     spsr_el2, x9
    mov     x9, #3
    msr     cnthctl_el2, x9         // allow EL1 timer access
    msr     cntvoff_el2, xzr
    mov     x9, #0xf
    msr     S3_4_C12_C9_5, x9       // ICC_SRE_EL2: let EL1 use the GICv3 system registers (hardware with a GICv3 only)
    adr     x9, 2f
    msr     elr_el2, x9
    eret
2:
    // The image is position-independent, linked at LINK_BASE (QEMU loads it there). Apply the relocations in place first:
    // everything below reaches its data through pointers the relocations fix.
    adrp    x9, __kernel_start
    add     x9, x9, :lo12:__kernel_start   // where we run
    movz    x10, #0x4008, lsl #16          // LINK_BASE: where we were linked
    sub     x11, x9, x10                   // slide (0 when loaded at the link address)
    adrp    x12, __rela_start
    add     x12, x12, :lo12:__rela_start
    adrp    x13, __rela_end
    add     x13, x13, :lo12:__rela_end
5:  cmp     x12, x13
    b.hs    6f
    ldp     x14, x15, [x12], #16           // r_offset, r_info
    ldr     x16, [x12], #8                 // r_addend
    cmp     w15, #1027                     // R_AARCH64_RELATIVE
    b.ne    5b
    add     x16, x16, x11
    sub     x14, x14, x10
    str     x16, [x9, x14]
    b       5b
6:
    EARLY_SETUP
    // Kernel address randomisation (kaslr.rs): where should the image live? x0 = the new address, 0 = stay.
    mov     x0, x28
    bl      kaslr_place
    cbz     x0, 20f
    // Move there. Copy the image up to .bss, make the copy's relocated slots point into itself, enter the copy.
    adrp    x9, __kernel_start
    add     x9, x9, :lo12:__kernel_start   // from
    mov     x10, x0                        // to
    sub     x15, x10, x9                   // slide (two's complement: the copy may lie below or above)
    adrp    x11, __bss_start
    add     x11, x11, :lo12:__bss_start
    sub     x11, x11, x9                   // bytes (a multiple of 4096)
    add     x11, x9, x11                   // end of the part to copy
    mov     x12, x9
    mov     x13, x10
10: cmp     x12, x11
    b.hs    11f
    ldp     x14, x16, [x12], #16
    stp     x14, x16, [x13], #16
    b       10b
11: movz    x9, #0x4008, lsl #16           // LINK_BASE
    adrp    x12, __rela_start
    add     x12, x12, :lo12:__rela_start
    adrp    x13, __rela_end
    add     x13, x13, :lo12:__rela_end
12: cmp     x12, x13
    b.hs    13f
    ldp     x14, x16, [x12], #16           // r_offset, r_info
    ldr     x17, [x12], #8                 // r_addend (unused: the slot already holds it)
    cmp     w16, #1027
    b.ne    12b
    sub     x14, x14, x9                   // offset of the slot in the image
    ldr     x16, [x10, x14]                // the copy's slot: an address in the old image ...
    add     x16, x16, x15                  // ... made an address in the copy
    str     x16, [x10, x14]
    b       12b
13: // tell the copy where the old image was, so it can give that memory back
    adrp    x14, kaslr_old_base
    add     x14, x14, :lo12:kaslr_old_base
    adrp    x16, __kernel_start
    add     x16, x16, :lo12:__kernel_start
    str     x16, [x14, x15]
    dsb     sy
    ic      iallu
    dsb     sy
    isb
    adrp    x14, 20f
    add     x14, x14, :lo12:20f
    add     x14, x14, x15                  // the same place in the copy
    br      x14
20:
    EARLY_SETUP
    mov     x0, x28
    bl      kmain
park:
    wfe
    b       park

// Secondary core entry (PSCI CPU_ON): x0 = the context id: the core's stack top (made from RAM by smp.rs) | the core's number, MMU off.
.global _secondary_start
_secondary_start:
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.ne    2f
    mov     x9, #(1 << 31)
    msr     hcr_el2, x9
    mov     x9, #0x33ff
    msr     cptr_el2, x9
    mov     x9, #0x0800
    movk    x9, #0x30d0, lsl #16
    msr     sctlr_el1, x9
    mov     x9, #0x3c5
    msr     spsr_el2, x9
    mov     x9, #3
    msr     cnthctl_el2, x9
    msr     cntvoff_el2, xzr
    mov     x9, #0xf
    msr     S3_4_C12_C9_5, x9
    adr     x9, 2f
    msr     elr_el2, x9
    eret
2:
    // x0 = the context id `smp.rs` gave PSCI: the core's stack top (page aligned, in RAM it was made from) with the core number in the low 12 bits
    and     x10, x0, #0xfff
    bic     x9, x0, #0xfff
    mov     sp, x9
    mov     x0, x10
    mov     x9, #(1 << 20)          // (as on the boot core)
    msr     cpacr_el1, x9
    adrp    x9, vectors
    add     x9, x9, :lo12:vectors
    msr     vbar_el1, x9
    isb
    bl      secondary_main          // x0 = core id, untouched above
    b       park

// TrapFrame layout: x0..x30 @0..247, sp_el0 @248, elr @256, spsr @264 (272 total)
.macro SAVE, sp0=1
    sub     sp, sp, #272
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    .if \sp0
    mrs     x0, sp_el0
    .else
    mov     x0, xzr                 // (SP_EL0 cannot be read while it is the stack pointer)
    .endif
    mrs     x1, elr_el1
    mrs     x2, spsr_el1
    str     x0, [sp, #248]
    stp     x1, x2, [sp, #256]
.endm

.macro RESTORE
    ldr     x0, [sp, #248]
    msr     sp_el0, x0
    ldp     x1, x2, [sp, #256]
    msr     elr_el1, x1
    msr     spsr_el1, x2
    ldp     x0, x1, [sp, #0]
    ldp     x2, x3, [sp, #16]
    ldp     x4, x5, [sp, #32]
    ldp     x6, x7, [sp, #48]
    ldp     x8, x9, [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30, [sp, #240]
    add     sp, sp, #272
    eret
.endm

.section .text.vectors, "ax"
.balign 2048
.global vectors
vectors:
    // Current EL with SP0
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    // Current EL with SPx
    .balign 128
    b       cur_sync
    .balign 128
    b       cur_irq
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    // Lower EL, AArch64
    .balign 128
    b       low_sync
    .balign 128
    b       low_irq
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    // Lower EL, AArch32 (unsupported)
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry
    .balign 128
    b       bad_entry

.balign 128
cur_sync:
    // A fault in the kernel is fatal, and may be a stack overflow (the stack pointer then points into the guard):
    // report it from a stack of its own (SP_EL0, which is not needed any more: nothing returns from here).
    msr     spsel, #0
    mrs     x17, tpidr_el1
    adrp    x16, emergency_stacks   // the boot core's is in the image (16 KiB) ...
    add     x16, x16, :lo12:emergency_stacks
    add     x16, x16, #16384
    cbz     x17, 4f
    adrp    x16, CORE_EMERG_TOP     // ... the others' were made from RAM with their stacks (smp.rs)
    add     x16, x16, :lo12:CORE_EMERG_TOP
    ldr     x16, [x16, x17, lsl #3]
4:  mov     sp, x16
    SAVE    0
    mov     x0, sp
    bl      kernel_sync_panic
cur_irq:
    SAVE
    mov     x0, sp
    bl      kernel_irq
    RESTORE
low_sync:
    SAVE
    mov     x0, sp
    bl      lower_sync
    RESTORE
low_irq:
    SAVE
    mov     x0, sp
    bl      lower_irq
    RESTORE
bad_entry:
    SAVE
    mov     x0, sp
    bl      bad_entry_panic

// void enter_user(const TrapFrame *tf): first dispatch, never returns.
.section .text
.global enter_user
enter_user:
    mrs     x9, tpidr_el1           // this core's number (set at bring-up)
    adrp    x10, __stack_top        // the boot core's stack is in the image ...
    add     x10, x10, :lo12:__stack_top
    cbz     x9, 3f
    adrp    x10, CORE_STACK_TOP     // ... the others' were made from RAM (smp.rs)
    add     x10, x10, :lo12:CORE_STACK_TOP
    ldr     x10, [x10, x9, lsl #3]
3:  mov     sp, x10
    sub     sp, sp, #272
    mov     x10, sp
    mov     x11, #17
1:  ldp     x12, x13, [x0], #16
    stp     x12, x13, [x10], #16
    subs    x11, x11, #1
    b.ne    1b
    RESTORE

.section .bss.emergency, "aw", @nobits
.balign 16
.global emergency_stacks
emergency_stacks:
    .space  16384
