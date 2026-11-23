# Porting Metallium-OS to single-board computers: what is QEMU-specific

An audit of 2026-11-13 (read-only: nothing was changed or run on a board). Everything here comes from reading the sources; facts about real boards are
from memory and **must be checked against each board's documentation** before relying on them.

## What is portable as it is
* The architecture-neutral core: scheduler (`kernel/src/sched.rs`, `libs/metallium-sched`), capabilities, IPC and rings, memory manager policy
  (compaction, zram swap, pager), spawn and the loader, the program manager, and every crate in `libs/` (file systems, network stack, programs). They are `no_std`, safe Rust, and host-tested.
* The Rust target (`aarch64-unknown-none-softfloat`: no floating point in the kernel) runs on any ARMv8-A core.
* `boot.S` already drops from EL2 to EL1 and enables the GICv3 system-register interface "on hardware with a GICv3", so it expects to be entered the way
  U-Boot or board firmware enters a kernel. The kernel is position independent (KASLR moves it), so the link address is not a hard problem.
* DMA cache maintenance (`user/src/dma.rs`, `kernel/src/cache.rs`) and a non-coherent mode (`opt/metallium/dma-noncoherent`, tested by
  `make qemu-test-noncoherent`) already exist, which most SBCs need.

## What is specific to QEMU's `virt` machine

| Area | Where | What it assumes | What a board needs |
|---|---|---|---|
| RAM map | `mem.rs` (`RAM_BASE` 0x4000_0000; the frame tables are carved from the top of RAM at boot, 10 bytes per frame), `main.rs` (RAM size from fw_cfg, else 128 MiB, accepted range 8 MiB..255 GiB), `mmu.rs` (identity map of the first GiB of RAM from 0x4000_0000 in 2 MiB blocks; the rest through a TTBR1 direct map; device blocks, ECAM at 0x40_0000_0000) | one contiguous RAM region at a fixed base, up to 255 GiB | a memory map per board (often several regions with holes, RAM base elsewhere), a frame table that skips the holes, MMIO windows from a board table |
| Load address | `linker.ld`, `kaslr.rs` (`LINK_BASE` 0x4008_0000), `boot.S` | QEMU loads the image at 0x40080000 | the board's load address (a per-board constant) |
| Boot hand-off | `boot.S`, `main.rs` | no use of the firmware's device tree pointer or memory map | at least the memory ranges; ideally a small device-tree reader for bases and interrupts |
| Console | `uart.rs` | PL011 at 0x0900_0000, polled, no setup | the board's UART (PL011 or a 16550-style one with a different register layout), clock and pin setup if firmware did not leave it ready |
| Interrupts | `gic.rs` (GICv2: GICD 0x0800_0000, GICC 0x0801_0000) | GICv2 at fixed addresses | the board's GIC (`platform/qemu_virt/gicv3.rs` is a GICv3 driver: distributor, redistributors, system-register interface; the platform picks v2 or v3 from the device tree); many SoCs have a GICv3 (distributor, redistributors, system registers): `gic.rs` has no GICv3 driver |
| Cores, power | `smp.rs` (`MAX_CPUS` 32, each core's stacks made from RAM at boot, the machine's own count and MPIDRs from `platform::cpu_count` / `cpu_mpidr`, PSCI CPU_ON through `hvc #0`), `frame::cpu::psci_power` (SYSTEM_OFF / SYSTEM_RESET, same conduit, used to shut down and restart) | PSCI over HVC, core id = index | PSCI over **SMC** (after the EL2 to EL1 drop nothing handles HVC), the board's core ids, 4 or 8 cores; some older firmware uses spin tables instead of PSCI |
| Clock | `platform.rs` (PL031 RTC at 0x0901_0000) | an RTC at a fixed address | the board's RTC, or none (`SystemTime::now()` is `None`) |
| Test hooks | `platform.rs` (fw_cfg: RAM size, `opt/metallium/*` flags), semihosting exit in `sched.rs` | QEMU's fw_cfg and semihosting | nothing: both are already optional (no fw_cfg means every flag is off and RAM is 128 MiB; keep an explicit RAM size) |
| PCIe | `pci.rs` (ECAM 0x40_1000_0000, window 0x1000_0000..0x3eff_0000, only virtio vendor 0x1af4 matched) | firmware-free, ready-made host bridge | a host-controller driver and window set-up per SoC (if the board's devices hang off PCIe at all) |
| IOMMU | `smmu.rs` (SMMUv3 at 0x0905_0000) | an Arm SMMUv3 confines every user-space driver's DMA | most SBC SoCs do not have one (some have a vendor IOMMU, a few an SMMU). Without it a user-space driver with a DMA-capable device can reach any memory, which weakens the "drivers are ordinary confined programs" story (see below) |
| Entropy | `rand.rs`; the virtio-rng driver is user space ([metallium-entropy-userspace](https://github.com/anthonydarkoonx/metallium-entropy-userspace)) | a virtio-rng device; `RNDR` if the CPU has it (ARMv8.5, so not on A53/A55/A72) | the SoC's hardware random generator driver, for ASLR/KASLR quality |
| Drivers | `user/src/virtio.rs`, `storage.rs`, `gpu.rs`, `kbd.rs`, `netdrv.rs` (now in the networking repository, `services/src/`; about 1.6k lines together): virtio block, GPU, input and net over PCI | virtio devices | one replacement per board and device, below |

### The drivers a board needs (the real work)
1. **Storage:** an SD/eMMC controller (SDHCI, Arasan, DesignWare MMC or a Broadcom/Rockchip variant) plus clocks.
2. **Display:** start with the framebuffer the firmware leaves (a "simple framebuffer": address, size, stride from the device tree or firmware); a real HDMI/DSI driver is far larger. The terminal session (`user/src/desktop.rs`) already draws into a framebuffer and flushes rectangles, so it needs only a driver that shows a rectangle (the `GPU_FLUSH` / `GPU_FLUSH2` protocol; on a plain framebuffer a flush is a cache clean).
3. **Input:** USB keyboard and mouse need a USB host controller stack (xHCI or DWC2) and HID: the largest single item. A serial-only shell is the first milestone.
4. **Network:** the SoC's Ethernet MAC (or a PCIe NIC) plus PHY set-up; the stack (`metallium-net`, in the networking repository) is independent of it.
5. **Platform plumbing** (clocks, resets, pin mux, regulators) that firmware may or may not have done.

## Suggested order
1. **A platform layer. (Started 2026-11-16: `kernel/src/hal.rs` has the traits for console, interrupt controller, power/cores and clock; QEMU `virt` is `kernel/src/platform/qemu_virt.rs`; still to do: memory map and entropy behind the same layer, and the board's own files in the new shape, see BOARD-SYNC.md.)** Move every constant and little driver in the table above behind one module per target (`platform/qemu_virt.rs`, `platform/<board>.rs`) chosen by a cargo feature: memory map, UART, interrupt controller, PSCI conduit, RTC, entropy, load address. This is exactly the code that belongs in the framework side of the framekernel layering (`kernel/src/frame.rs` and its siblings), so the port is "implement the frame for a new board", and the safe modules (`cap`, `ipc`, `sched`, `spawn`, ...) stay as they are.
2. **Milestone 1:** boot to the serial console on one board: memory map, UART, interrupt controller, timer, PSCI over SMC, and a larger frame table. QEMU can help before hardware arrives if it has a model of the board (check the installed QEMU's machine list); the interrupt controller and PSCI parts can be tried on QEMU `virt` with `gic-version=3`.
3. **Milestone 2:** the firmware framebuffer plus the serial shell: the terminal appears on the screen, driven by a UART keyboard if need be.
4. **Milestone 3:** storage (the file systems and the program manager's data partition need it), then USB input, then network.

## Design points to decide before the first board
* **No IOMMU.** Options: (a) accept weaker confinement on boards without one and say so; (b) keep DMA-capable drivers inside the kernel's trusted base on such boards; (c) make the kernel own the descriptor rings and bounce buffers (copy data between a driver's private memory and a DMA window the kernel controls), which costs copies but keeps drivers confined. (c) fits the capability model best.
* **Core count and kinds:** `MAX_CPUS` is 32 (the count comes from the device tree) and the scheduler knows performance and efficiency cores; 8-core big.LITTLE boards would exercise it. (Task slots are no longer fixed: up to 1024, sized at boot.)
* **RAM above the first GiB (done in the general tree, 2026-11-19):** the kernel identity-maps only the 1 GiB window around `RAM_BASE` (the image lives there; `frame::phys::ID_BASE..ID_END`); the rest of RAM is reached at `DIRECT_BASE + pa` through TTBR1 (`frame::phys::va`, built by `mmu::build_direct_map`). Every access to a frame by physical address goes through `frame::phys`, `mmu::table` or `va`; code that must use a physical address as a pointer (SMMU tables, a probe's DMA page) takes its frame from `mem::alloc_identity`. The frame tables are sized from the RAM found and live in the last frames of RAM. Still one contiguous region from `RAM_BASE`: a board whose RAM has holes or sits below its devices needs a region table.
* **Timing:** QEMU's emulated numbers (IPC about 28 us per round trip, repaints of 1 to 3 ms) say little about a real SBC. Re-measure there (`make quick-bench`, `make ui-perf`) before deciding on the IPC fast path.

## Leftovers
`kernel/target-rock3c/` is an old build directory from 24 to 25 October (a Rock 3C build was apparently tried then). Nothing in the sources, Makefile or docs refers to it, and its contents were not inspected; it can probably be deleted.


## Device registry (2026-11-16)
`kernel/src/devices.rs` holds the table of drivers the kernel knows (class, PCI id, driver role, object set-up). A machine with PCI devices adds entries; a machine without PCI (a board) still makes its objects in its own `probe_devices`, and moving those into the same table (matching on a device-tree compatible string instead of a PCI id) is the next step. The driver tasks themselves are still roles of the single user image (`user/src/main.rs`, `task::spawn` in `kernel/src/main.rs`); the table now also says which tasks start for each device (stage 2b); making the driver programs separate packages is stage 3.
