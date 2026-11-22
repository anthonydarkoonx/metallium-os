OBJCOPY ?= aarch64-linux-gnu-objcopy
TARGET  := aarch64-unknown-none-softfloat
USER_ELF := user/target/$(TARGET)/release/metallium-user
KERNEL   := kernel/target/$(TARGET)/release/metallium-kernel
# QEMU loads the kernel as an ELF file (entry point and load address come from the ELF headers).
KERNEL_BIN := $(KERNEL).img
DISK     ?= disk.img
# the interactive console runs with more memory: every fullscreen program has a 3 MiB surface
UI_RAM_MIB ?= 128
SMP ?= 4
# the interrupt controller QEMU emulates (2 or 3); the kernel reads which from the device tree
GIC ?= 2
RAM_MIB ?= 64
# System-image compression (see tools/mkdisk.py); the 1-CPU test run uses LZ4 so both decoders run in QEMU.
EROFS_OPTS ?= -zzstd,level=19 -C16384
export EROFS_OPTS

# With performance cores online (3+ CPUs) the Heavy task must have stayed on them.
ifeq ($(shell test $(SMP) -ge 3 && echo y),y)
SCHED_PAT := 'TEST Heavy work stays on performance cores when they are not oversubscribed.*PASS'
else
SCHED_PAT := '(Heavy): no performance cores online'
endif
# Host port forwarded to the guest's TCP port 7777 (the inbound connection of the network tests); tools/netpeer.py uses it.
NET_FWD_PORT ?= 18077
# the input devices: virtio keyboard and tablet (the USB test swaps them for an xHCI controller with a USB keyboard and tablet)
QEMU_INPUT := -device virtio-keyboard-pci,disable-legacy=on,iommu_platform=on -device virtio-tablet-pci,disable-legacy=on,iommu_platform=on
QEMU_USB_INPUT := -device qemu-xhci,id=xhci -device usb-kbd,id=kbd0,bus=xhci.0 -device usb-tablet,id=tab0,bus=xhci.0
# ... or with a hub on the first port and both devices behind it
# a hub with seven keyboards, a keyboard and a tablet beside it: ten devices (the driver used to take six)
QEMU_USB_MANY_INPUT := -device qemu-xhci,id=xhci -device usb-hub,id=hub1,bus=xhci.0,port=1 -device usb-kbd,id=kbd1,bus=xhci.0,port=1.1 -device usb-kbd,id=kbd2,bus=xhci.0,port=1.2 -device usb-kbd,id=kbd3,bus=xhci.0,port=1.3 -device usb-kbd,id=kbd4,bus=xhci.0,port=1.4 -device usb-kbd,id=kbd5,bus=xhci.0,port=1.5 -device usb-kbd,id=kbd6,bus=xhci.0,port=1.6 -device usb-kbd,id=kbd7,bus=xhci.0,port=1.7 -device usb-kbd,id=kbd0,bus=xhci.0,port=2 -device usb-tablet,id=tab0,bus=xhci.0,port=3
QEMU_USB_HUB_INPUT := -device qemu-xhci,id=xhci -device usb-hub,id=hub1,bus=xhci.0,port=1 -device usb-kbd,id=kbd0,bus=xhci.0,port=1.1 -device usb-tablet,id=tab0,bus=xhci.0,port=1.2
QEMU_DEV := -drive if=none,id=d0,file=$(DISK),format=raw -device virtio-blk-pci,drive=d0,disable-legacy=on,iommu_platform=on \
            -device virtio-gpu-pci,disable-legacy=on,iommu_platform=on,xres=1024,yres=768 \
            $(QEMU_INPUT) \
            -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$(NET_FWD_PORT)-:7777 -device virtio-net-pci,netdev=n0,disable-legacy=on,iommu_platform=on \
            -device virtio-rng-pci,disable-legacy=on,iommu_platform=on
# (a fresh 32 random bytes for every make run: the kernel mixes them into its layout generator, see kernel/src/rand.rs)
SEED_FILE := $(shell head -c 32 /dev/urandom > build-seed.bin && echo build-seed.bin)
# (more QEMU options for a run, e.g. `make qemu-test QEMU_EXTRA='-fw_cfg name=opt/metallium/device-secret,file=build-device-secret.bin'`)
QEMU_EXTRA ?=
QEMU     := qemu-system-aarch64 -fw_cfg name=opt/metallium/seed,file=$(SEED_FILE) -machine virt,gic-version=$(GIC),iommu=smmuv3 -cpu max -smp $(SMP) -m $(RAM_MIB)M -fw_cfg name=opt/metallium/ram-bytes,string=$(shell echo $$(( $(RAM_MIB) * 1048576 ))) \
            -nographic -semihosting $(QEMU_DEV) $(QEMU_EXTRA) -kernel $(KERNEL_BIN)

# The command line the tests use (for the scripts in tools/ that start the guest themselves)
print-qemu:
	@echo '$(QEMU)'

# The network tests need the host peer (tools/netpeer.py) running while the guest boots.
WITH_PEER := tools/with-peer.sh $(NET_FWD_PORT)

# Chaos test: a monkey kills services at random while a workload uses them; see user/src/chaos.rs.
CHAOS_SEED ?= 1
chaos: kernel disk
	@$(WITH_PEER) sh -c 'timeout 200 $(QEMU) -fw_cfg name=opt/metallium/chaos,string=$(CHAOS_SEED) > build-chaos.log 2>&1'; rc=$$?; \
	 grep -E "^\[(chaos|monkey)\].*(TEST|done|CORRUPT|LOST|workload|free frames)" build-chaos.log; \
	 [ $$(grep -c "^\[chaos\] TEST.*PASS" build-chaos.log) -ge 7 ] && \
	 ! grep -qE "^\[chaos\].*(FAIL|CORRUPT|LOST)" build-chaos.log && \
	 grep -q "^\[chaos\] done" build-chaos.log && \
	 echo "== CHAOS (seed $(CHAOS_SEED)): ALL PASS ==" || { echo "== CHAOS (seed $(CHAOS_SEED)): FAILED (qemu rc=$$rc), see build-chaos.log =="; exit 1; }


.PHONY: greeter-test-tty tty-test bigram-test greeter-test greeter-test-manager session-test-encrypted session-test table-test greeter-lib qemu-test-encrypted volume-test elf-boot-test usb-test usb-test-many usb-test-hub usb-test-noncoherent scale scale-run desktop-programs desktop-lib clippy stack-guard aslr-replay print-qemu quick-programs programs fuzz quick-bench quick-sched qemu-test-noncoherent chaos all user kernel disk erofs-check map-check qemu-test-up inherit-ab provenance-check run run-window test host-test qemu-test clean

all: kernel

# A desktop environment can take over the screen task: `make run-window DESKTOP=../metallium-os-desktop` builds that repository's
# `metallium-desktop-boot` crate (the contract is docs/DESKTOP-INTERFACE.md) and links it into the user image. Without DESKTOP
# the image has the built-in terminal console and nothing of any desktop.
DESKTOP ?=
ifneq ($(DESKTOP),)
DESKTOP_DIR := $(abspath $(DESKTOP))
DESKTOP_OUT := $(DESKTOP_DIR)/target-metallium-os/$(TARGET)/release
DESKTOP_REPO := "https://github.com/anthonydarkoonx/metallium-os"
# (the desktop's dependencies sit in `deps/` or, with newer cargo, in `build/<crate>/<hash>/out/`: every such directory is searched)
DESKTOP_FLAGS := --cfg desktop --extern metallium_desktop_boot=$(DESKTOP_OUT)/libmetallium_desktop_boot.rlib $$(for d in $(DESKTOP_OUT)/deps $(DESKTOP_OUT)/build/*/*/out; do test -d $$d && printf -- '-L dependency=%s ' $$d; done)
# The desktop's programs: its `os/` workspace builds them as position-independent programs; they are signed and put in the system image by
# tools/mkmap.py (METALLIUM_EXTRA_PACKAGES) and installed by default through `/etc/program-defaults`.
DESKTOP_PKG := $(DESKTOP_DIR)/target-metallium-os/pkg
export METALLIUM_EXTRA_PACKAGES := $(DESKTOP_PKG)
DESKTOP_PIE := -C relocation-model=pic -C link-arg=-pie -C link-arg=--no-dynamic-linker -C link-arg=-znorelro
desktop-programs:
	cp $(DESKTOP_DIR)/os/Cargo.lock $(DESKTOP_DIR)/os/Cargo.lock.metallium-os-bak 2>/dev/null || true
	cd $(DESKTOP_DIR)/os && METALLIUM_OS_DIR=$(CURDIR) RUSTFLAGS='$(DESKTOP_PIE) -Zembed-metadata=yes' cargo build --release --target $(TARGET) --target-dir ../target-metallium-os-programs \
	  --config 'patch.$(DESKTOP_REPO).metallium-driver-rt.path="$(CURDIR)/libs/metallium-driver-rt"' \
	  --config 'patch.$(DESKTOP_REPO).metallium-gfx.path="$(CURDIR)/libs/metallium-gfx"' \
	  --config 'patch.$(DESKTOP_REPO).metallium-programs.path="$(CURDIR)/programs"'; rc=$$?; \
	  if [ -f $(DESKTOP_DIR)/os/Cargo.lock.metallium-os-bak ]; then mv $(DESKTOP_DIR)/os/Cargo.lock.metallium-os-bak $(DESKTOP_DIR)/os/Cargo.lock; fi; test $$rc = 0
	rm -rf $(DESKTOP_PKG); mkdir -p $(DESKTOP_PKG)/bin $(DESKTOP_PKG)/packages
	for f in $(DESKTOP_DIR)/os/src/bin/*.rs; do n=$$(basename $$f .rs); cp $(DESKTOP_DIR)/target-metallium-os-programs/$(TARGET)/release/$$n $(DESKTOP_PKG)/bin/$$n.pie; done
	cp $(DESKTOP_DIR)/os/packages/*.manifest $(DESKTOP_PKG)/packages/
	cp $(DESKTOP_DIR)/os/defaults $(DESKTOP_PKG)/defaults
disk: desktop-programs

desktop-lib:
	cp $(DESKTOP_DIR)/Cargo.lock $(DESKTOP_DIR)/Cargo.lock.metallium-os-bak
	cd $(DESKTOP_DIR) && RUSTFLAGS='-C relocation-model=pic -Zembed-metadata=yes' cargo build --release --target $(TARGET) -p metallium-desktop-boot --target-dir target-metallium-os --config 'profile.release.lto="fat"' \
	  --config 'patch.$(DESKTOP_REPO).metallium-driver-rt.path="$(CURDIR)/libs/metallium-driver-rt"' \
	  --config 'patch.$(DESKTOP_REPO).metallium-gfx.path="$(CURDIR)/libs/metallium-gfx"'; rc=$$?; \
	  mv $(DESKTOP_DIR)/Cargo.lock.metallium-os-bak $(DESKTOP_DIR)/Cargo.lock; exit $$rc
user: desktop-lib
endif

# A greeter can take over the screen while the encrypted data volume is locked (docs/GREETER-INTERFACE.md): `make run-window GREETER=../greeter` builds that
# repository's `metallium-greeter-boot` crate and links it into the screen task. Without GREETER the built-in text prompt asks for the passphrase.
GREETER ?=
# (cargo features of the greeter crate, e.g. `log-key` for `make greeter-test`)
GREETER_FEATURES ?=
ifneq ($(GREETER),)
GREETER_DIR := $(abspath $(GREETER))
GREETER_OUT := $(GREETER_DIR)/target-metallium-os/$(TARGET)/release
GREETER_REPO := "https://github.com/anthonydarkoonx/metallium-os"
GREETER_FLAGS := --cfg greeter --extern metallium_greeter_boot=$(GREETER_OUT)/libmetallium_greeter_boot.rlib $$(for d in $(GREETER_OUT)/deps $(GREETER_OUT)/build/*/*/out; do test -d $$d && printf -- '-L dependency=%s ' $$d; done)
greeter-lib:
	cp -f $(GREETER_DIR)/Cargo.lock $(GREETER_DIR)/Cargo.lock.metallium-os-bak 2>/dev/null || true
	cd $(GREETER_DIR) && RUSTFLAGS='-C relocation-model=pic -Zembed-metadata=yes' cargo build --release --target $(TARGET) -p metallium-greeter-boot $(if $(GREETER_FEATURES),--features $(GREETER_FEATURES)) --target-dir target-metallium-os --config 'profile.release.lto="fat"' \
	  --config 'patch.$(GREETER_REPO).metallium-driver-rt.path="$(CURDIR)/libs/metallium-driver-rt"' \
	  --config 'patch.$(GREETER_REPO).metallium-gfx.path="$(CURDIR)/libs/metallium-gfx"'; rc=$$?; \
	  if [ -f $(GREETER_DIR)/Cargo.lock.metallium-os-bak ]; then mv $(GREETER_DIR)/Cargo.lock.metallium-os-bak $(GREETER_DIR)/Cargo.lock; fi; exit $$rc
user: greeter-lib
endif
ifneq ($(DESKTOP)$(GREETER),)
USER_RUSTFLAGS := RUSTFLAGS="-C relocation-model=pic $(DESKTOP_FLAGS) $(GREETER_FLAGS)"
endif

user:
	cd user && $(USER_RUSTFLAGS) cargo build --release
	mkdir -p user/build
	cp $(USER_ELF) user/build/user.elf

# The kernel as a flat Linux-style "Image" (see boot.S): what QEMU and boot loaders take when they should hand over the device tree.
OBJCOPY ?= $(shell command -v aarch64-linux-gnu-objcopy || command -v rust-objcopy || echo objcopy)
KERNEL_IMG = $(OBJCOPY) -O binary $(1) $(1).img

kernel: user
	cd kernel && cargo build --release
	$(call KERNEL_IMG,$(KERNEL))

# Programs started with SPAWN (programs/): position-independent ELF files in programs/build (random image base each run; the
# loader relocates them), packed into the system image under /bin. `sleeper` stays a flat image (the user crate embeds
# it); the static `.elf` copies of argdump and hello exist to test the loader's fixed-address path.
PROGRAM_BINS := racetest guardtest pager pagetest hello crash ping mem burn spawner cat fswrite ls fdprobe kv kvc blocker argdump upper threads stdtest nettest netcheck fetch quotatest shmtest pietest progmgr progctl counter crasher hog probe fsprog sessiond homeprobe
PIE_FLAGS := -C relocation-model=pic -C link-arg=-pie -C link-arg=--no-dynamic-linker -C link-arg=-znorelro --cfg getrandom_backend=\"custom\"
programs:
	rm -rf programs/build; mkdir -p programs/build
	cd programs && cargo build --release --bin sleeper
	$(OBJCOPY) -O binary programs/target/$(TARGET)/release/sleeper programs/build/sleeper.bin
	cd programs && cargo build --release
	for a in argdump hello; do cp programs/target/$(TARGET)/release/$$a programs/build/$$a.elf; done
	cd programs && METALLIUM_PIE=1 RUSTFLAGS="$(PIE_FLAGS)" cargo build --release --target-dir target-pie
	for a in $(PROGRAM_BINS); do cp programs/target-pie/$(TARGET)/release/$$a programs/build/$$a.pie; done

disk: programs
	python3 tools/mkdisk.py $(DISK)

run: kernel disk
	$(QEMU)

host-test:
	cargo test --workspace

# Independent check: the Rust EROFS reader must parse the Python-built image.
erofs-check:
	python3 tools/mkdisk.py $(DISK) build-sys.erofs
	cargo run -q --release -p metallium-erofs --example erofscat -- build-sys.erofs /hello.txt
	@rm -f build-sys.erofs

# Independent check: the Rust package parser must accept what tools/mkmap.py builds (and refuse the flawed fixtures).
map-check: programs
	python3 tools/mkmap.py
	@for f in counter crasher hog probefs probenofs probespawn probespawnall fsa fsb fsq nosign mismatch rogue tampered; do cargo run -q --release -p metallium-map --example mapinfo -- programs/build/maps/$$f.map | grep -q '^ok ' || { echo "map-check: $$f.map not accepted"; exit 1; }; done
	@cargo run -q --release -p metallium-map --example mapinfo -- programs/build/maps/corrupt.map | grep -q 'refused BadChecksum' || { echo "map-check: corrupt.map not refused"; exit 1; }
	@echo "== MAP CHECK: ALL PASS =="

# Boot in QEMU and assert on the console transcript.
qemu-test: kernel disk
	@$(WITH_PEER) sh -c 'timeout 260 $(QEMU) > build.log 2>&1'; rc=$$?; cat build.log; \
	 grep -q "TEST zero-copy shared memory.*PASS" build.log && \
	 grep -q "TEST async IPC_SEND.*PASS" build.log && \
	 grep -q "TEST the reverse map holds the addresses of the whole user space.*PASS" build.log && \
	 grep -q "TEST kernel pages are write-xor-execute.*: PASS; WXN on: PASS; PAN on.*: PASS" build.log && \
	 grep -q "TEST one program cannot take more than its share.*PASS" build.log && \
	 grep -q "TEST one program cannot fill an endpoint.s queue.*PASS" build.log && \
	 grep -q "TEST capability revoke.*PASS" build.log && \
	 grep -q "TEST capability grants are bounded.*PASS" build.log && \
	 grep -q "TEST the stack is fully usable.*PASS" build.log && \
	 grep -q "TEST every program gets its own randomised layout.*PASS" build.log && \
	 grep -q "TEST a thread on a kernel-made stack.*PASS" build.log && \
	 grep -q "TEST MEM_MAP with address 0 lets the kernel choose.*PASS" build.log && \
	 grep -q "TEST the pages next to a kernel-placed mapping fault.*PASS" build.log && \
	 grep -q "TEST pages go from the compressed store to the disk.*PASS" build.log && \
	 grep -q "TEST a restarted pager takes over.*PASS" build.log && \
	 grep -q "TEST every page comes back from disk.*PASS" build.log && \
	 grep -q "TEST a program that keeps using its pages while they are pushed to disk.*PASS" build.log && \
	 grep -q "TEST nothing is left behind when the programs are gone.*PASS" build.log && \
	 grep -q "TEST the pager is handed sealed pages.*PASS" build.log && \
	 grep -q "TEST a pager that changes a page on its way back is caught.*PASS" build.log && \
	 grep -q "TEST driver crash surfaces as error.*PASS" build.log && \
	 grep -q "TEST driver restarted with fresh state.*PASS" build.log && \
	 grep -q "TEST sleep/timer.*PASS" build.log && \
	 grep -q "TEST virtio-blk read sector 0.*PASS" build.log && \
	 grep -q "TEST virtio-blk write+readback.*PASS" build.log && \
	 grep -q "TEST IOMMU stops a driver.*PASS" build.log && \
	 grep -q "TEST a block device that never answers.*PASS" build.log && \
	 grep -q "TEST the block driver serves requests again after the watchdog.*PASS" build.log && \
	 grep -q "TEST a display device that never answers.*PASS" build.log && \
	 grep -q "TEST the display driver presents again after the watchdog.*PASS" build.log && \
	 grep -q "TEST an interrupted rewrite leaves the previous version.*PASS" build.log && \
	 grep -q "TEST a completed rewrite replaces the file.*PASS" build.log && \
	 grep -q "TEST a sparse write reads back zeros.*PASS" build.log && \
	 grep -q "TEST HEAP_GROW with a wrapping page count is refused.*PASS" build.log && \
	 grep -q "TEST an ordinary client cannot use the VFS fault-injection hook.*PASS" build.log && \
	 grep -q "TEST file size is bounded.*PASS" build.log && \
	 grep -q "TEST display: a test card is drawn.*PASS" build.log && \
	 grep -q "TEST system information screen is drawn.*PASS" build.log && \
	 grep -q "TEST IOMMU stops the display driver.*PASS" build.log && \
	 grep -q "TEST restarted display driver presents.*PASS" build.log && \
	 grep -q "TEST the marker page never reached the disk.*PASS" build.log && \
	 grep -q "TEST restarted block driver serves requests again.*PASS" build.log && \
	 grep -q "\[smmu\] blocked DMA: F_TRANSLATION" build.log && \
	 grep -q "TEST blk driver crash surfaces as error.*PASS" build.log && \
	 grep -q "TEST data survives blk driver restart.*PASS" build.log && \
	 grep -q "TEST EROFS read /hello.txt.*PASS" build.log && \
	 grep -q "TEST EROFS read 9000-byte file across blocks: PASS" build.log && \
	 grep -q "TEST EROFS list /.*PASS" build.log && \
	 grep -q "TEST EROFS missing path rejected.*PASS" build.log && \
	 grep -q "TEST LFS write coalescing.*PASS" build.log && \
	 grep -q "TEST LFS server crash surfaces as error.*PASS" build.log && \
	 grep -q "TEST LFS synced blocks survive restart, unsynced block lost: PASS" build.log && \
	 grep -q "TEST LFS sync across a block-driver crash: PASS" build.log && \
	 grep -q "TEST VFS read /system/hello.txt: PASS" build.log && \
	 grep -q "TEST VFS read 9000-byte file via fd: PASS" build.log && \
	 grep -q "TEST VFS read 236 KB file from the compressed system image.*PASS" build.log && \
	 grep -q "TEST VFS list / and /system.*PASS" build.log && \
	 grep -q "TEST VFS /system is read-only.*PASS" build.log && \
	 grep -q "TEST VFS create+write+read /data/docs/note.txt.*PASS" build.log && \
	 grep -q "TEST VFS overwrite across a block boundary: PASS" build.log && \
	 grep -q "TEST VFS list, rmdir-nonempty refused.*PASS" build.log && \
	 grep -q "TEST VFS data survives vfs-server crash; old fd rejected.*PASS" build.log && \
	 grep -q "TEST VFS data survives lfs-server + blk-driver crashes.*PASS" build.log && \
	 grep -q "TEST VFS sustained writes.*PASS" build.log && \
	 grep -q "TEST VFS program task's files are visible.*PASS" build.log && \
	 grep -q "\[program\] TEST read /system/etc/os-release.*PASS" build.log && \
	 grep -q "\[program\] TEST write + append + read back.*PASS" build.log && \
	 grep -q "\[program\] TEST list /data.*PASS" build.log && \
	 grep -q "\[program\] TEST /system rejects writes.*PASS" build.log && \
	 grep -q "\[program\] TEST no direct device or filesystem access.*PASS" build.log && \
	 grep -q "TEST async ring setup.*PASS" build.log && \
	 grep -q "TEST ring batch: 3 NOPs, 1 syscall.*PASS" build.log && \
	 grep -q "TEST ring: 4 concurrent async calls + timeout, 1 syscall.*PASS" build.log && \
	 grep -q "TEST ring: completions reaped by polling.*PASS" build.log && \
	 grep -q "TEST priority inheritance.*PASS" build.log && \
	 grep -q "TEST ring: async call to a crashing driver.*PASS" build.log && \
	 grep -q "TEST ring backpressure.*PASS" build.log && \
	 grep -q "TEST memory pressure.*PASS" build.log && \
	 grep -q "TEST fragmentation.*PASS" build.log && \
	 grep -q "TEST contiguous 512 KiB allocation fails on fragmented memory.*PASS" build.log && \
	 grep -q "TEST compactd restores contiguity.*PASS" build.log && \
	 grep -q "TEST every page read during migration held its data.*PASS" build.log && \
	 grep -q "TEST pages relocated by the compactor keep their contents.*PASS" build.log && \
	 grep -q "TEST contiguous 512 KiB block allocated after compaction.*PASS" build.log && \
	 grep -q "TEST direct compaction inside the allocator.*PASS" build.log && \
	 grep -q $(SCHED_PAT) build.log && \
	 { [ $(SMP) -lt 3 ] || grep -q "TEST a CPU hog that was pushed onto an efficiency core goes back to a performance core once one is idle.*PASS" build.log; } && \
	 grep -q "TEST scheduler shares the cores fairly.*PASS" build.log && \
	 grep -q "TEST scheduler keeps the cores busy.*PASS" build.log && \
	 grep -q "TEST real-time task meets its deadlines.*PASS" build.log && \
	 grep -q "TEST real-time task is dispatched within 1 ms.*PASS" build.log && \
	 grep -q "TEST an overrunning real-time task gets its reserved.*PASS" build.log && \
	 grep -q "TEST real-time admission refuses.*PASS" build.log && \
	 grep -q "TEST a reservation needs the scheduling capability.*PASS" build.log && \
	 grep -q "TEST waiting for the next period without a reservation is refused.*PASS" build.log && \
	 { grep -q "TEST sleeping cores take no periodic tick.*PASS" build.log || [ $(SMP) -lt 3 ]; } && \
	 { grep -q "TEST a real-time caller's urgency reaches the server it calls.*PASS" build.log || [ $(SMP) -gt 1 ]; } && \
	 ! grep -q "TEST \(scheduler\|real-time\|a light task\|hogs take turns\|sustained\|sleeping cores\|a CPU hog that was pushed\).*FAIL" build.log && \
	 grep -q "TEST a program runs and its exit code comes back through WAIT.*PASS" build.log && \
	 grep -q "TEST a program that faults ends with the fault code.*PASS" build.log && \
	 grep -q "TEST a running program: WAIT without blocking.*PASS" build.log && \
	 grep -q "TEST a program uses the endpoint its parent delegated.*PASS" build.log && \
	 grep -q "TEST a program gets exactly the heap it was given.*PASS" build.log && \
	 grep -q "TEST a program with the spawn capability starts programs, and they end with it.*PASS" build.log && \
	 grep -q "TEST a program started with file access reads a file through the VFS.*PASS" build.log && \
	 grep -q "TEST a program writes a file that the conductor then reads.*PASS" build.log && \
	 grep -q "TEST a program's file descriptors do not outlive it.*PASS" build.log && \
	 grep -q "TEST every file session the kernel made.*PASS" build.log && \
	 grep -q "TEST two clients use a server built on an endpoint.*PASS" build.log && \
	 grep -q "TEST revoking the server's capability wakes it.*PASS" build.log && \
	 grep -q "TEST a caller waiting on an endpoint that ends is told so.*PASS" build.log && \
	 grep -q "TEST a task may own four endpoints at a time.*PASS" build.log && \
	 grep -q "TEST program packages in the system image install.*PASS" build.log && \
	 grep -q "TEST a corrupt package, one whose id differs.*PASS" build.log && \
	 grep -q "TEST signatures: an unsigned package, one signed by a key.*PASS" build.log && \
	 grep -q "TEST the manifest's limits and permissions, and that it was signed.*PASS" build.log && \
	 grep -q "TEST a program starts and its UI ability comes to the foreground.*PASS" build.log && \
	 grep -q "TEST on_create and on_foreground ran.*PASS" build.log && \
	 grep -q "TEST starting it again is refused.*PASS" build.log && \
	 grep -q "TEST the manager moves it to the background.*PASS" build.log && \
	 grep -q "TEST \.\.\. and back to the foreground.*PASS" build.log && \
	 grep -q "TEST the ability's own work (on_tick) runs.*PASS" build.log && \
	 grep -q "TEST a crashing program is restarted by the manager.*PASS" build.log && \
	 grep -q "TEST the restarted instance got what the crashed one had saved.*PASS" build.log && \
	 grep -q "TEST the other program did not notice.*PASS" build.log && \
	 grep -q "TEST a crash does not stop the crasher for good.*PASS" build.log && \
	 grep -q "TEST a program that runs into its memory limit dies alone.*PASS" build.log && \
	 grep -q "TEST \.\.\. while the others keep running.*PASS" build.log && \
	 grep -q "TEST a program sees files only with the files permission.*PASS" build.log && \
	 grep -q "TEST a program starts programs only with the spawn permission.*PASS" build.log && \
	 grep -q "TEST WAIT_WORD and WAKE_WORD on a device mapping are refused.*PASS" build.log && \
	 grep -q "TEST threads creating shared memory at the same moment.*PASS" build.log && \
	 grep -q "TEST only the pager.s first task may take its jobs.*PASS" build.log && \
	 grep -q "TEST a dead child is collected by one of two threads.*PASS" build.log && \
	 grep -q "TEST a revoked capability is not given back under a node that has been reused.*PASS" build.log && \
	 grep -q "TEST a program that ends in the middle of SPAWN leaves no embryo.*PASS" build.log && \
	 grep -q "TEST shared memory that outlives the thread that made it is still charged.*PASS" build.log && \
	 grep -q "TEST a program.s file session page holds nothing of the program before it.*PASS" build.log && \
	 grep -q "TEST a thread.s copy of run-time memory cannot free it.*PASS" build.log && \
	 grep -q "TEST MC_FREE refuses a shared-memory capability.*PASS" build.log && \
	 grep -q "TEST a program cannot put capabilities into a boot-time task.*PASS" build.log && \
	 grep -q "TEST a SIMD instruction in a user program ends it.*PASS" build.log && \
	 grep -q "TEST SYSINFO pages that list other tasks. capabilities refuse.*PASS" build.log && \
	 grep -q "TEST a map that races a revoke never leaves.*PASS" build.log && \
	 grep -q "TEST pages released by HEAP_RELEASE are not reachable.*PASS" build.log && \
	 grep -q "TEST a capability copy read before a revoke stays dead.*PASS" build.log && \
	 grep -q "TEST TASK_LOAD stops when its embryo is killed.*PASS" build.log && \
	 grep -q "TEST stopping asks the ability to leave.*PASS" build.log && \
	 grep -q "TEST stopping what is not running is refused.*PASS" build.log && \
	 grep -q "TEST a program's storage is private.*PASS" build.log && \
	 grep -q "TEST each program's files are where the manager put them.*PASS" build.log && \
	 grep -q "TEST \.\.\. and a program that makes files until it is stopped.*PASS" build.log && \
	 grep -q "TEST uninstalling a program removes its data.*PASS" build.log && \
	 grep -q "TEST a program that is not running can be uninstalled.*PASS" build.log && \
	 grep -q "TEST a program can be installed again after being uninstalled.*PASS" build.log && \
	 grep -q "TEST the program manager scenario ran to its end.*PASS" build.log && \
	 grep -q "TEST nothing is left behind once the program manager is gone.*PASS" build.log && \
	 grep -q "TEST a program receives its command line (name first), environment.*PASS" build.log && \
	 grep -q "TEST a program reads its standard input line by line.*PASS" build.log && \
	 grep -q "TEST 5000 bytes of input and output cross the console endpoint intact.*PASS" build.log && \
	 grep -q "TEST an ELF executable is loaded and runs like a flat image.*PASS" build.log && \
	 grep -q "TEST malformed ELF files are refused.*PASS" build.log && \
	 grep -q "TEST a position-independent ELF executable runs like a flat image.*PASS" build.log && \
	 grep -q "TEST position-independent programs get a random image base.*PASS" build.log && \
	 grep -q "TEST all free task slots can be used.*PASS" build.log && \
	 grep -q "TEST malformed images are refused by the loader.*PASS" build.log && \
	 grep -q "TEST the kernel refuses hostile TASK_LOAD.*PASS" build.log && \
	 grep -q "TEST the std-like layer.*PASS" build.log && \
	 grep -q "TEST standard output and standard error arrive separately.*PASS" build.log && \
	 grep -q "TEST the std test left nothing behind.*PASS" build.log && \
	 grep -q "TEST net: the machine got an address by DHCP.*PASS" build.log && \
	 grep -q "TEST net: names: dotted quads.*PASS" build.log && \
	 grep -q "TEST net: UDP datagrams of 0 to 1472.*PASS" build.log && \
	 grep -q "TEST net: 1 MiB goes out and comes back.*PASS" build.log && \
	 grep -q "TEST net: 2 MiB streamed by the host.*PASS" build.log && \
	 grep -q "TEST net: 2 MiB sent over TCP, half-closed.*PASS" build.log && \
	 grep -q "TEST net: connecting to a port nobody listens on.*PASS" build.log && \
	 grep -q "TEST net: a listener accepts a connection.*PASS" build.log && \
	 grep -q "TEST net: 60 connections in a row.*PASS" build.log && \
	 grep -q "TEST memory pressure makes compactd swap cold pages out.*PASS" build.log && \
	 grep -q "TEST net: four threads with a connection.*PASS" build.log && \
	 grep -q "TEST net: waiting is sleeping.*PASS" build.log && \
	 grep -q "TEST net: a peer that answers in small slow pieces.*PASS" build.log && \
	 grep -q "TEST net: a program that leaves sockets open.*PASS" build.log && \
	 grep -q "TEST net: \.\.\. and the next program can use the same ports.*PASS" build.log && \
	 grep -q "TEST net: when the network service dies.*PASS" build.log && \
	 grep -q "TEST net: nothing is left behind (frames.*PASS" build.log && \
	 grep -q "TEST five tasks of one program count under a lock.*PASS" build.log && \
	 grep -q "TEST two tasks alternate through one waited-on word.*PASS" build.log && \
	 grep -q "TEST a word wait reports a changed value.*PASS" build.log && \
	 grep -q "TEST a fault in one thread ends the whole program.*PASS" build.log && \
	 grep -q "TEST a program whose main task exits ends its sleeping threads.*PASS" build.log && \
	 grep -q "TEST a thread calling exit ends the program.*PASS" build.log && \
	 grep -q "TEST the thread allowance holds.*PASS" build.log && \
	 grep -q "TEST a program started without a thread allowance.*PASS" build.log && \
	 grep -q "TEST an allowance above the limit is refused.*PASS" build.log && \
	 grep -q "TEST a thread reads a file through its program.*PASS" build.log && \
	 grep -q "TEST 150 threads one after another.*PASS" build.log && \
	 grep -q "TEST threads grow their program's heap.*PASS" build.log && \
	 grep -q "TEST killing a program stops its spinning threads.*PASS" build.log && \
	 grep -q "TEST every frame and capability node the threads used is back.*PASS" build.log && \
	 grep -q "TEST 300 programs later every frame, capability node and task slot is back.*PASS" build.log && \
	 grep -q "TEST a program that allocates until refused stays within its limit.*PASS" build.log && \
	 grep -q "TEST a program that allocates without checking is stopped at its limit.*PASS" build.log && \
	 grep -q "TEST contiguous allocations count against the program's limit.*PASS" build.log && \
	 grep -q "TEST a program with a budget of 700 pages starts two default programs.*PASS" build.log && \
	 grep -q "TEST a program may have at most 8 programs at a time.*PASS" build.log && \
	 grep -q "TEST a program costs its heap + budget + 24 pages.*PASS" build.log && \
	 grep -q "TEST a child's limits can be raised within the parent's budget.*PASS" build.log && \
	 grep -q "TEST every frame and capability node the memory-limit tests used is back.*PASS" build.log && \
	 grep -q "TEST SHM_CREATE: sizes, the charge against the limit.*PASS" build.log && \
	 grep -q "TEST shared memory outlives its creator while another program holds it.*PASS" build.log && \
	 grep -q "TEST a program shares memory it created with another.*PASS" build.log && \
	 grep -q "TEST a capability granted without the write right.*PASS" build.log && \
	 grep -q "TEST a holder of shared memory exiting does not free it.*PASS" build.log && \
	 grep -q "TEST when the creator takes shared memory back.*PASS" build.log && \
	 grep -q "TEST a program sleeping on a word of shared memory is woken.*PASS" build.log && \
	 grep -q "TEST shared memory dies with its creator.*PASS" build.log && \
	 grep -q "TEST a 4096-page object is usable.*PASS" build.log && \
	 grep -q "TEST nothing is left behind by the shared-memory tests.*PASS" build.log && \
	 grep -q "TEST shared memory needs no contiguous run.*PASS" build.log && \
	 ! grep -aq "TEST.*program.*FAIL" build.log && \
	 python3 tools/checkdisk.py $(DISK) && \
	 grep -q "zram\] lz4: .*swap-in verified: PASS" build.log && \
	 grep -q "zram\] zstd: .*swap-in verified: PASS" build.log && \
	 grep -q "worker\] heartbeat" build.log && \
	 echo "== QEMU INTEGRATION: ALL PASS ==" || { echo "== QEMU INTEGRATION: FAILED (qemu rc=$$rc) =="; exit 1; }

# Development shortcuts: boot, run one group of the conductor's tests and stop (see platform.rs `only`).
quick-bench: kernel disk
	@timeout 60 $(QEMU) -fw_cfg name=opt/metallium/only,string=1 2>&1 | grep -E "BENCH|PANIC|panic|^\[sched\] [0-9]"

# Syscall fuzzer (user/src/fuzz.rs): hostile calls from a task with a mixed set of capabilities, then a leak audit.
fuzz: kernel disk
	@timeout 120 $(QEMU) -fw_cfg name=opt/metallium/fuzz,string=$(or $(SEED),1) > build-fuzz.log 2>&1; rc=$$?; \
	 grep -aE "fuzz|\[client\] TEST|PANIC|panic" build-fuzz.log; \
	 [ $$(grep -ac "^\[client\] TEST.*PASS" build-fuzz.log) -ge 5 ] && \
	 ! grep -aqE "TEST.*FAIL|PANIC|panic" build-fuzz.log && \
	 echo "== FUZZ (seed $(or $(SEED),1)): ALL PASS ==" || { echo "== FUZZ (seed $(or $(SEED),1)): FAILED (qemu rc=$$rc), see build-fuzz.log =="; exit 1; }

quick-programs: kernel disk
	@timeout 90 $(QEMU) -fw_cfg name=opt/metallium/only,string=7 2>&1 | grep -aE "TEST|\[client\]|PANIC|panic|\[hello|\[crash"

quick-net: kernel disk
	@$(WITH_PEER) sh -c 'timeout 200 $(QEMU) -fw_cfg name=opt/metallium/only,string=8 2>&1 | grep -aE "TEST|\[client\]|\[nettest|\[netd|PANIC|panic"'

# Every task slot of a big table at once (1024 slots, 512 MiB): programs are started until SPAWN says the table is full, then all end together.
scale:
	@$(MAKE) -s scale-run RAM_MIB=512

scale-run: kernel disk
	@timeout 280 $(QEMU) -fw_cfg name=opt/metallium/only,string=9 -fw_cfg name=opt/metallium/max-tasks,string=1024 > build-scale.log 2>&1; \
	 grep -a "task slots\|TEST\|PANIC\|panic" build-scale.log | cut -c1-300; \
	 if grep -aq "TEST every one of 1024 task slots.*PASS" build-scale.log && grep -aq "TEST they are all killed.*PASS" build-scale.log && ! grep -aq "PANIC" build-scale.log; then echo "== SCALE: ALL PASS =="; else echo "== SCALE: FAILED =="; exit 1; fi

quick-sched: kernel disk
	@timeout 90 $(QEMU) -fw_cfg name=opt/metallium/only,string=2 2>&1 | grep -E "SCHED|TEST|^\[sched\]|PANIC|panic|DEBUG"

# uniprocessor configuration too: no PSCI cores, no performance cores
qemu-test-up:
	@$(MAKE) -s qemu-test SMP=1 EROFS_OPTS='-zlz4hc'

# The same boot with the SMMU declared non-coherent: tables and queues are then programmed non-cacheable and every
# CPU write the SMMU must see is cleaned first (what a device that does not snoop the CPU caches needs). QEMU's
# models ignore the attributes, so this checks that the maintenance path runs and breaks nothing.
qemu-test-noncoherent: kernel disk
	@$(WITH_PEER) sh -c 'timeout 260 $(QEMU) -fw_cfg name=opt/metallium/dma-noncoherent,string=1 > build-noncoherent.log 2>&1'; rc=$$?; \
	 grep -E "SMMUv3 enabled|TEST virtio-blk write|TEST IOMMU stops|TEST the display driver|FAIL" build-noncoherent.log | cut -c1-200; \
	 grep -q "not coherent" build-noncoherent.log && ! grep -q "FAIL" build-noncoherent.log && \
	 grep -q "TEST virtio-blk write+readback.*PASS" build-noncoherent.log && \
	 grep -q "TEST IOMMU stops a driver.*PASS" build-noncoherent.log && \
	 grep -q "TEST the display driver presents again after the watchdog.*PASS" build-noncoherent.log && \
	 echo "== NON-COHERENT DMA: ALL PASS ==" || { echo "== NON-COHERENT DMA: FAILED (qemu rc=$$rc), see build-noncoherent.log =="; exit 1; }

# Layout randomisation is reproducible: the same seed gives the boot tasks the same stacks and heaps, another seed does not,
# and the seeds from the harness (no seed given) give different layouts every boot.
aslr-replay: kernel disk
	@run() { timeout 120 $(QEMU) -fw_cfg name=opt/metallium/only,string=2 $$1 2>&1 | grep -a "layout of task" ; } ; \
	 a=$$(run "-fw_cfg name=opt/metallium/aslr-seed,string=12345"); b=$$(run "-fw_cfg name=opt/metallium/aslr-seed,string=12345"); c=$$(run "-fw_cfg name=opt/metallium/aslr-seed,string=12346"); \
	 n=$$(echo "$$a" | grep -c .); \
	 [ "$$n" -ge 10 ] && [ "$$a" = "$$b" ] && [ "$$a" != "$$c" ] && echo "== ASLR REPLAY: ALL PASS ($$n boot tasks, same seed same layouts, other seed other layouts) ==" || { echo "== ASLR REPLAY: FAILED ($$n lines) =="; exit 1; }

# Entropy: a normal boot folds in the virtio-rng device's bytes and warns about nothing; the modes that give up
# unpredictability (noaslr, aslr-seed, aslr-log) say so in the boot log and leave the device alone.
entropy: kernel disk
	@run() { timeout 120 $(QEMU) -fw_cfg name=opt/metallium/only,string=2 $$1 2>&1 | grep -a "\[rand\]" ; } ; \
	 n=$$(run ""); a=$$(run "-fw_cfg name=opt/metallium/noaslr,string=1"); b=$$(run "-fw_cfg name=opt/metallium/aslr-seed,string=7"); c=$$(run "-fw_cfg name=opt/metallium/aslr-log,string=1"); \
	 echo "$$n" | grep -q "virtio-rng: 32 bytes folded" && ! echo "$$n" | grep -q WARNING \
	 && echo "$$a" | grep -q "WARNING.*randomisation is off" && echo "$$b" | grep -q "WARNING.*seed that was given" && echo "$$c" | grep -q "WARNING.*seed is printed" \
	 && ! echo "$$a$$b$$c" | grep -q "bytes folded" \
	 && w=$$(timeout 120 $(subst -cpu max,-cpu cortex-a72,$(subst file=$(SEED_FILE),string=short,$(QEMU))) -fw_cfg name=opt/metallium/only,string=2 2>&1 | grep -a "\[rand\]\|\[kaslr\]") \
	 && echo "$$w" | grep -q "WARNING: neither RNDR nor a full opt/metallium/seed" && echo "$$w" | grep -q "kaslr\] kernel image moved.*WARNING: neither RNDR" && ! echo "$$n" | grep -q "neither RNDR" \
	 && echo "== ENTROPY: ALL PASS (virtio-rng folded in on a normal boot; noaslr, aslr-seed and aslr-log warn and skip it; a boot with no RNDR and no seed file warns twice) ==" || { echo "== ENTROPY: FAILED: $$n / $$a / $$b / $$c / $$w =="; exit 1; }

# The boot-time services map their devices and shared pages where the kernel chooses: three boots, the same mappings made
# each time, at different addresses.
service-maps: kernel disk
	@for i in 1 2 3; do timeout 120 $(QEMU) -fw_cfg name=opt/metallium/only,string=2 -fw_cfg name=opt/metallium/map-log,string=1 > build-map$$i.log 2>&1; done; \
	 r=$$(python3 tools/check_service_maps.py build-map1.log build-map2.log build-map3.log) && echo "== SERVICE MAPS: $$r ==" || { echo "== SERVICE MAPS: $$r =="; exit 1; }

# Kernel address randomisation: the kernel image sits at a different place in RAM on every boot, inside RAM, clear of the
# first 512 KiB, and the system comes up from there (the boot test programs run). Also with the smallest RAM it supports.
KASLR_BOOTS ?= 8
kaslr: kernel disk
	@addrs=""; for i in $$(seq $(KASLR_BOOTS)); do \
	   out=$$(timeout 120 $(QEMU) -fw_cfg name=opt/metallium/only,string=2 2>&1); \
	   a=$$(echo "$$out" | grep -a "kernel image moved" | sed 's/.* to \(0x[0-9a-f]*\).*/\1/'); \
	   echo "$$out" | grep -aq "PANIC" && { echo "== KASLR: FAILED: panic at $$a =="; exit 1; }; \
	   echo "$$out" | grep -aq "\[client\] TEST" || { echo "== KASLR: FAILED: no tests ran at $$a =="; exit 1; }; \
	   addrs="$$addrs $$a"; done; \
	 n=$$(echo $$addrs | tr ' ' '\n' | sort -u | grep -c .); \
	 bad=$$(echo $$addrs | tr ' ' '\n' | while read a; do [ -n "$$a" ] && [ $$((a)) -ge $$((0x40080000)) ] && [ $$((a)) -lt $$((0x40000000 + $(RAM_MIB) * 1048576)) ] || echo bad; done | grep -c bad); \
	 small=$$(timeout 120 $(subst -m $(RAM_MIB)M,-m 16M,$(subst $(shell echo $$(( $(RAM_MIB) * 1048576 ))),16777216,$(QEMU))) -fw_cfg name=opt/metallium/only,string=2 2>&1 | grep -a "kernel image moved\|no room" | head -1); \
	 [ "$$n" -ge $$(( $(KASLR_BOOTS) - 1 )) ] && [ "$$bad" = 0 ] && echo "$$small" | grep -q . \
	 && echo "== KASLR: ALL PASS ($(KASLR_BOOTS) boots, $$n different kernel addresses, all inside RAM; 16 MiB RAM: $$small) ==" || { echo "== KASLR: FAILED: $$n different addresses in $(KASLR_BOOTS) boots, $$bad out of range:$$addrs; 16 MiB: $$small =="; exit 1; }

# The kernel's stacks have unmapped guard pages: running one out ends in a clear panic (not in silent corruption of
# whatever lay below it), on the boot core and on another core.
stack-guard: kernel disk
	@out=$$(timeout 60 $(QEMU) -fw_cfg name=opt/metallium/stack-overflow,string=1 2>&1 | grep -a "stack overflow\|PANIC"); \
	 out1=$$(timeout 60 $(QEMU) -fw_cfg name=opt/metallium/stack-overflow-core1,string=1 2>&1 | grep -a "stack overflow\|PANIC"); \
	 outb=$$(timeout 60 $(QEMU) -fw_cfg name=opt/metallium/stack-overflow-bigframe,string=1 2>&1 | grep -a "stack overflow\|PANIC"); \
	 out31=$$(timeout 90 $(QEMU) -machine virt,gic-version=3,iommu=smmuv3 -smp 32 -fw_cfg name=opt/metallium/stack-overflow-core,string=31 2>&1 | grep -a "stack overflow\|PANIC"); \
	 echo "$$out" | grep -q "kernel stack overflow on core 0 (guard page hit" && echo "$$out1" | grep -q "kernel stack overflow on core 1 (guard page hit" && echo "$$out31" | grep -q "kernel stack overflow on core 31 (guard page hit" && echo "$$outb" | grep -q "kernel stack overflow on core 0 (guard page hit" && echo "== STACK GUARD: ALL PASS (core 0, core 1 and core 31 report the overflow, a frame bigger than the guard too) ==" || { echo "== STACK GUARD: FAILED: $$out / $$out1 / $$out31 / $$outb =="; exit 1; }

test: host-test erofs-check map-check qemu-test qemu-test-encrypted volume-test table-test session-test session-test-encrypted qemu-test-up qemu-test-noncoherent aslr-replay entropy kaslr service-maps stack-guard elf-boot-test fuzz usb-test usb-test-hub usb-test-many usb-test-noncoherent

# Licensing hygiene: the ZSTD constants must equal RFC 8878's tables (needs network once).
provenance-check:
	@test -f build-rfc8878.txt || curl -sL https://www.rfc-editor.org/rfc/rfc8878.txt -o build-rfc8878.txt
	python3 tools/check_zstd_tables.py build-rfc8878.txt

# Throw away what runs leave in the project folder: the disk images of `make run-window DISK=runN.img` and of the UI tests, logs and test
# summaries, screenshots and previews. (Close any QEMU window first: its disk image goes too. Build caches stay: `make clean` removes those.)
tidy:
	rm -f run[0-9]*.img ui-*.img gui-*.img disk.img *.log full.sum up.sum build-window.sock build-gui.sock
	rm -rf build-probe

clean:
	cargo clean
	cd kernel && cargo clean
	cd user && cargo clean

# Same boot, but in a QEMU window (serial console shown in the GTK window);
# -no-shutdown keeps the window open after the kernel powers off.
# an interactive run keeps the data partition of the last one (saved colours and settings, installed programs)
run-window: export KEEP_DATA = 1
# (the interactive console gets a roomy data partition: a sparse file, the guest uses all of it; the test suites keep the small default)
run-window: export DATA_MIB ?= 1024
run-window: user disk
	cd kernel && cargo build --release --features park-on-exit --target-dir target-window
	$(call KERNEL_IMG,kernel/target-window/$(TARGET)/release/metallium-kernel)
	qemu-system-aarch64 -machine virt,gic-version=$(GIC),iommu=smmuv3 -cpu max -smp $(SMP) -m $(UI_RAM_MIB)M -fw_cfg name=opt/metallium/ram-bytes,string=$(shell echo $$(( $(UI_RAM_MIB) * 1048576 ))) \
	  -fw_cfg name=opt/metallium/interactive,string=1 -display gtk,zoom-to-fit=on -serial vc:900x600 -monitor none -qmp unix:build-window.sock,server,nowait -semihosting $(QEMU_DEV) \
	  -name "Metallium-OS" -kernel kernel/target-window/$(TARGET)/release/metallium-kernel.img

# A/B evidence for priority inheritance: on one CPU the polling test must pass with it and fail without.
inherit-ab: user disk
	cd kernel && cargo build --release --features no-inherit --target-dir target-noinherit
	$(call KERNEL_IMG,kernel/target-noinherit/$(TARGET)/release/metallium-kernel)
	@echo "--- without inheritance (1 CPU):"
	@timeout 60 qemu-system-aarch64 -machine virt,gic-version=$(GIC),iommu=smmuv3 -cpu max -smp 1 -m $(RAM_MIB)M -fw_cfg name=opt/metallium/ram-bytes,string=$(shell echo $$(( $(RAM_MIB) * 1048576 ))) -nographic -semihosting $(QEMU_DEV) \
	  -kernel kernel/target-noinherit/$(TARGET)/release/metallium-kernel.img 2>&1 | grep "priority inheritance" || true
	@$(MAKE) -s kernel
	@echo "--- with inheritance (1 CPU):"
	@timeout 60 qemu-system-aarch64 -machine virt,gic-version=$(GIC),iommu=smmuv3 -cpu max -smp 1 -m $(RAM_MIB)M -fw_cfg name=opt/metallium/ram-bytes,string=$(shell echo $$(( $(RAM_MIB) * 1048576 ))) -nographic -semihosting $(QEMU_DEV) \
	  -kernel $(KERNEL_BIN) 2>&1 | grep "priority inheritance" || true

# Hardening lints (fast, no QEMU): deny-level clippy plus the unsafe_op_in_unsafe_fn / undocumented_unsafe_blocks rules from each Cargo.toml.
clippy:
	cargo clippy --workspace --all-targets
	cd kernel && cargo clippy --release
	cd user && cargo clippy --release
	cd programs && cargo clippy --release

# USB input: an xHCI controller with a USB keyboard and tablet instead of the virtio ones; the script types and clicks through QEMU's QMP socket and
# checks that the driver saw each key and button (the driver logs them only in this mode, `opt/metallium/only=10`).
usb-test: kernel disk
	@python3 tools/usb-test.py '$(subst $(QEMU_INPUT),$(QEMU_USB_INPUT),$(QEMU)) -fw_cfg name=opt/metallium/only,string=10' flat

# ... and again with the machine's DMA treated as not cache-coherent (the driver must clean and flush its rings and buffers itself)
usb-test-noncoherent: kernel disk
	@python3 tools/usb-test.py '$(subst $(QEMU_INPUT),$(QEMU_USB_INPUT),$(QEMU)) -fw_cfg name=opt/metallium/only,string=10 -fw_cfg name=opt/metallium/dma-noncoherent,string=1' flat

# ... with the keyboard and tablet behind a hub (and the noncoherent variant)
usb-test-hub: kernel disk
	@python3 tools/usb-test.py '$(subst $(QEMU_INPUT),$(QEMU_USB_HUB_INPUT),$(QEMU)) -fw_cfg name=opt/metallium/only,string=10' hub
	@python3 tools/usb-test.py '$(subst $(QEMU_INPUT),$(QEMU_USB_HUB_INPUT),$(QEMU)) -fw_cfg name=opt/metallium/only,string=10 -fw_cfg name=opt/metallium/dma-noncoherent,string=1' hub

# ... and with ten devices (hub with seven keyboards)
usb-test-many: kernel disk
	@python3 tools/usb-test.py '$(subst $(QEMU_INPUT),$(QEMU_USB_MANY_INPUT),$(QEMU)) -fw_cfg name=opt/metallium/only,string=10' many

# The whole integration suite with the data volume encrypted (a machine secret makes the blank disk an encrypted volume): file system, crash recovery, cleaning, everything
qemu-test-encrypted: kernel disk
	@head -c 32 /dev/urandom > build-device-secret.bin
	@$(MAKE) --no-print-directory qemu-test QEMU_EXTRA='-fw_cfg name=opt/metallium/device-secret,file=build-device-secret.bin' 2>&1 | tee build-encrypted.log | grep -E "encrypted|INTEGRATION" ; grep -q "ALL PASS" build-encrypted.log && grep -q "made an encrypted volume" build-encrypted.log; rc=$$?; rm -f build-device-secret.bin; exit $$rc

# The directory table of /data: an older-layout table is read, hundreds of entries, long paths (see tools/table-test.py)
table-test: kernel disk
	@python3 tools/table-test.py '$(QEMU)'

# Sessions: accounts, logins, homes confined per user (tools/session-test.py)
session-test: kernel disk
	@python3 tools/session-test.py '$(QEMU)'

# The same with the machine volume encrypted too (the users' domains on top of the volume's own layer)
session-test-encrypted: kernel disk
	@head -c 32 /dev/urandom > build-device-secret.bin
	@python3 tools/session-test.py '$(QEMU) -fw_cfg name=opt/metallium/device-secret,file=build-device-secret.bin' encrypted; rc=$$?; rm -f build-device-secret.bin; exit $$rc

# The greeter end to end: `make greeter-test GREETER=../greeter` builds that repository's crate with its `log-key` feature (the test types the recovery key back, which it reads from
# the console: a real image never prints it) and types at the screens through QMP (tools/greeter-test.py)
greeter-test:
	@test -n "$(GREETER)" || { echo "greeter-test needs GREETER=<the greeter repository>"; exit 1; }
	@$(MAKE) --no-print-directory user kernel disk GREETER=$(GREETER) GREETER_FEATURES=log-key
	@python3 tools/greeter-test.py '$(QEMU)'

# ... and the interactive boot itself: a login starts the user's own program manager, and the console is given its control endpoint (no test mode; the conductor starts the service)
# The same on two ttys (the conductor makes a second account; the test logs in on tty 1 with Ctrl+Alt+F2 and checks that session's console and program manager)
greeter-test-tty:
	@test -n "$(GREETER)" || { echo "greeter-test-tty needs GREETER=<the greeter repository>"; exit 1; }
	@$(MAKE) --no-print-directory user kernel disk GREETER=$(GREETER) GREETER_FEATURES=log-key
	@GREETER_MANAGER=1 GREETER_TTY=1 python3 tools/greeter-test.py '$(QEMU)'

greeter-test-manager:
	@test -n "$(GREETER)" || { echo "greeter-test-manager needs GREETER=<the greeter repository>"; exit 1; }
	@$(MAKE) --no-print-directory user kernel disk GREETER=$(GREETER) GREETER_FEATURES=log-key
	@GREETER_MANAGER=1 python3 tools/greeter-test.py '$(QEMU)'

# The display driver's ttys: a buffer for each, and the driver shows the one it is told to (the conductor plays the input driver; tools/tty-test.py takes screenshots through QMP)
tty-test: kernel disk
	@python3 tools/tty-test.py '$(QEMU)'

# Big RAM with a hole (a stand-in for a board with two banks): 6 GiB with the 1 GiB from 3 GiB to 4 GiB not RAM. The kernel must count only real RAM, never map or hand out the hole, and run
# programs whose pages lie above the first GiB and above 4 GiB; the swap and compaction tests of `make qemu-test` need memory pressure and so are not run here.
BIGRAM_HOLE := -fw_cfg name=opt/metallium/ram-hole-start,string=3221225472 -fw_cfg name=opt/metallium/ram-hole-size,string=1073741824
bigram-test: kernel disk
	@$(MAKE) --no-print-directory table-test session-test RAM_MIB=6144 QEMU_EXTRA='$(BIGRAM_HOLE)'
	@python3 -c "import re,sys; t=open('build-table.log',errors='replace').read(); m=re.search(r'MMU on; 6144 MiB RAM, (\\d+) frames free', t); n=int(m.group(1)) if m else 0; ok=1_200_000<n<=1_310_720 and 'PANIC' not in t; print('[bigram] 6144 MiB with a 1 GiB hole: %d frames free (a hole-free 6 GiB would have about 1.57 million): %s' % (n, 'PASS' if ok else 'FAIL')); print('== BIG RAM: ALL PASS ==' if ok else '== BIG RAM: FAILED =='); sys.exit(0 if ok else 1)"

# The data volume's encryption end to end: one disk booted five times (see tools/volume-test.py)
volume-test: kernel disk
	@python3 tools/volume-test.py '$(QEMU)'

# The ELF file instead of the flat Image: QEMU passes no device tree, so the kernel asks the firmware how many cores there are and the controller which GIC it is (GICv2 with 8 cores, GICv3 with 32).
elf-boot-test: kernel disk
	@python3 tools/elf-boot-test.py '$(QEMU)' 2
	@python3 tools/elf-boot-test.py '$(QEMU)' 3
