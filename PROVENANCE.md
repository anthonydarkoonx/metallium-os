# Provenance and licensing

Metallium-OS is licensed **Apache-2.0 OR MIT**. The rule for this repository: no code copied from, or
directly derived from, GPL (or other copyleft) sources. Everything is written from public
specifications, hardware documentation, or measurements of file formats.

## Where each component comes from

| component | basis |
|---|---|
| kernel (boot, MMU, scheduler, capabilities, IPC, rings, SMP, drivers' kernel side) | original design; hardware behaviour from the Arm Architecture Reference Manual, GICv2 and generic-timer specifications, PSCI specification, PL011 TRM, QEMU `virt` documented memory map, semihosting specification |
| userspace servers, VFS, daemons | original design |
| `user/src/audio.rs` (the audio ring protocol, WAV parsing, sample-rate conversion), `httpc.rs` (plain HTTP client) and the network-time client in `netd.rs` (both now in the networking repository, `services/src/`), the shell's `play` and `download` | Original. Written from the specifications: the RIFF/WAVE format description, HTTP/1.0 (RFC 1945) and SNTP (RFC 4330). They were first written for the ROCK 3C test port and moved into this tree on 2026-11-15; none of it came from Linux or U-Boot source. The board's own hardware drivers stay in `rock 3c test/` (see `docs/BOARD-SYNC.md`). |
| `user/src/dma.rs`, `kernel/src/cache.rs`, the cache maintenance in `user/src/virtio.rs` and `kernel/src/smmu.rs` | Original. The maintenance operations, `CTR_EL0`, `SCTLR_EL1.UCI/UCT` and the clean/invalidate rules follow the Arm Architecture Reference Manual; which buffers a virtio device reads or writes follows the OASIS virtio specification; the SMMU's `IDR0.COHACC` and non-coherent attribute rules follow the Arm SMMUv3 specification (IHI 0070). |
| `kernel/src/swap.rs` (clock aging, eviction to the compressed pool, swap-in on fault) and the VFS undo journal (`user/src/vfs.rs`) | Original design. The access flag, access-flag and translation faults, break-before-make and TLB maintenance follow the Arm Architecture Reference Manual (VMSAv8-64); the clock algorithm and undo logging are textbook techniques written here. Nothing from Linux or any Linux-derived source. |
| `libs/metallium-zstd` encoder (`encode.rs`), small decoder (`lite.rs`), FSE tables and descriptions (`fse.rs`), Huffman literals (`huff.rs`), bit readers/writers (`bits.rs`) | RFC 8878 only: frame and block headers (§3.1.1.1-3.1.1.2), literals section (§3.1.1.3.1), sequences section and codes (§3.1.1.3.2), the FSE state machine (§4.1). The encoder is the inverse of the decoder's state walk, derived from that description; it was validated against the real `zstd` tool (run as a black-box decoder, never read or copied) and against the full decoder in this repository The Huffman-coded literals (§3.1.1.3.1, §4.2: weights, canonical code assignment, the one- and four-stream layouts, the FSE-coded weight stream with its two interleaved states) and the transmitted FSE table descriptions (§4.1.1, written by inverting the spec's reader) are likewise from RFC 8878 only; the code-length limiting and count normalisation are generic textbook methods written here. Checked against the real `zstd` tool as a black-box decoder and against the independent full decoder in the same crate. |
| `libs/metallium-lz4` | public LZ4 block-format description; interoperability checked against the `lz4` command-line tool |
| `libs/metallium-zstd` | RFC 8878. The constant tables are verified against the RFC text by `tools/check_zstd_tables.py` (`make provenance-check`). The `zstd` tool is a test oracle only. *Disclosure:* the tables were first transcribed from the (BSD-3-Clause option of the) zstd C sources and then proven identical to the RFC's; the decoder logic is original |
| `libs/metallium-lfs` | original design (segmented log, delta-chained index, double-buffered checkpoints) |
| `libs/metallium-erofs` | on-disk structure layouts (superblock, inode, directory entry, compression header fields). The compressed-index decoder (`zmap.rs`) is a fresh implementation written from *measurements*: hexdumps of images produced by `mkfs.erofs`, compared against the extent maps `dump.erofs -e` prints. An earlier version of that decoder was deleted and replaced because its structure followed recalled kernel code |
| `libs/metallium-zram`, `libs/metallium-sched` | original |
| `libs/metallium-compact` and the kernel's page migration | original; the two-finger compaction idea is textbook operating-systems material (a migrate scan from one end, a free scan from the other), implemented here from that description |
| RAM-size discovery | QEMU's documented `fw_cfg` interface (the harness passes `opt/metallium/ram-bytes`); no Linux boot protocol or device-tree code |
| virtio-blk driver | OASIS virtio 1.x specification: PCI transport (vendor capabilities, common/notify/ISR/device structures), split virtqueue, feature bits `VERSION_1` and `ACCESS_PLATFORM` |
| `user/src/gpu.rs` (display driver) and the framebuffer objects | OASIS virtio 1.2 specification, section 5.7 (GPU device): control header, `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D`, `RESOURCE_ATTACH_BACKING`, `SET_SCANOUT`, `TRANSFER_TO_HOST_2D`, `RESOURCE_FLUSH`, format enum; every value read from the specification text. The 5x9 font (`user/src/font.rs`, all printable ASCII including lower case) was drawn by hand for this project, not taken from any existing console font; CPU model names come from Arm's published part numbers |
| `user/src/kbd.rs` (keyboard driver) | OASIS virtio 1.2 specification, section 5.8 (input device): device id, eventq, the 8-byte event layout, buffer rules. Key numbers are the PC/AT scan-code-set-1 numbering of the main keyboard block (the specification says codes follow evdev, which reuses it); the US-layout character table and modifier handling were written for this project, and the Linux input header was not consulted |
| `user/src/console.rs`, `user/src/shell.rs`, `user/src/chaos.rs` (fault-injection test) | original |
| `user/src/virtio.rs` | OASIS virtio 1.x specification (PCI transport, split virtqueue) |
| `kernel/src/pci.rs` (PCIe enumeration, BAR assignment) | PCI Express Base Specification (configuration header, capability list, BAR sizing protocol); the virtio vendor-capability layout from the virtio specification; ECAM address and the 32-bit memory window from QEMU `virt`'s documented memory map and the device tree QEMU generates |
| `kernel/src/smmu.rs` (IOMMU) | Arm System MMU architecture specification, SMMUv3 (IHI 0070): register map, stream table entry, command and event queue formats, stage-2 translation tables. Written without consulting any other implementation. *Disclosure:* the encodings were first written from knowledge of the public specification, then checked line by line against the text of IHI 0070 D.a (stream table entry stage-2 fields and `Config`, command opcodes and argument layouts, event record layout and ids, the `CR0`/`CR1`/`IRQ_CTRL` bit assignments, queue register offsets). That check found and fixed two errors that QEMU's behaviour had hidden: the event queue's PROD/CONS registers are architecturally in register page 1 (page 0 is only an optional alias), and overflow is signalled through `PROD.OVFLG`/`CONS.OVACKFLG`. QEMU was used only as a black-box test target |
| `kernel/src/sched.rs`, `kernel/src/timer.rs`, `libs/metallium-sched/src/{rt,util,energy}.rs` (time slices, real-time reservations, load balancing, energy-aware placement) | Textbook algorithms written for this project: earliest-deadline-first scheduling and its utilisation bound (Liu & Layland, 1973); periodic reservations with budget enforcement (the constant-bandwidth-server idea of throttling a task that overruns its budget until its period ends); round robin with a per-class quantum; a decaying average of busy time for utilisation; a convex power model for choosing the cheapest core. The Linux scheduler (and its deadline and energy-aware code) was not consulted, and no code, constants or names were taken from it. The power figures are nominal, rounded numbers chosen for this project, not from any datasheet or kernel table |
| `tools/` | original |

## GPL tools used as black-box test oracles

`mkfs.erofs`, `dump.erofs` and `fsck.erofs` (erofs-utils) and the `zstd`/`lz4` command-line tools are
run by tests and by `tools/mkdisk.py` to produce and judge images. `qemu-system-aarch64` (GPL-2.0) is the
platform the tests run on: it is executed, and its source (including its SMMUv3 and virtio models) was
not read or used. They are not linked, copied,
vendored or shipped, and no source from them is in this repository.

## Honest limits

* The on-disk format of EROFS is whatever the existing implementations write; any correct reader
  must agree with them on every field, so equal *behaviour* is unavoidable. What this record
  covers is where the *code* comes from.

## Typeface
`libs/metallium-gfx/src/font_data.rs` holds glyph bitmaps of **IBM Plex Sans** and **IBM Plex Mono**, rasterised from the font files of the original build machine (`/usr/share/fonts/truetype/ibm-plex`; the generator script was removed with the GUI on 2026-11-16, the data file stays). The terminal draws with the monospaced face (`typeface::MONO`). IBM Plex is published under the SIL Open Font License 1.1, which permits embedding and distribution; the bitmaps are not a font program and are not named as one. The 5x9 bitmap font in `libs/metallium-gfx/src/font.rs` was drawn for this project.

## ROCK 3C board port (separate repository)
The board port to the Radxa ROCK 3C lives in its own repository, [metallium-os-rock3c](https://github.com/anthonydarkoonx/metallium-os-rock3c),
licensed GPL-2.0-only as a whole: its drivers are ported from Linux and U-Boot. Nothing from it comes into this tree; a driver for
this tree is written from the hardware manuals.
