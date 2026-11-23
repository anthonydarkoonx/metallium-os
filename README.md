# Metallium-OS (prototype)

A Rust `no_std` AArch64 microkernel that boots on QEMU `virt` (1-4 cores), with userspace tasks, a
capability/IPC syscall ABI with async rings, fault-isolated restartable driver and filesystem
servers, a VFS, and host-tested storage / memory libraries. Licensed Apache-2.0 OR MIT.

    make run          # boot in QEMU (needs qemu-system-aarch64, rustup target
                      #   aarch64-unknown-none-softfloat, aarch64-linux-gnu-objcopy)
    make run SMP=2    # choose the core count (1-4)
    make run-window   # same boot in a QEMU window (the display shows the virtio-gpu test card)
    make test         # host unit tests, real-mkfs.erofs cross-checks, QEMU integration test on 4 CPUs and on 1
    make chaos        # kill services at random while a workload runs (CHAOS_SEED=n picks the sequence)
    make fuzz         # hostile syscalls from a task with mixed capabilities, then a leak audit (SEED=n)
    make inherit-ab   # priority-inheritance A/B demo on one CPU
    make provenance-check   # verify the ZSTD tables against RFC 8878 (needs network once)
    make run RAM_MIB=32     # choose the RAM size (passed to the kernel via QEMU fw_cfg)

See `PROVENANCE.md` for where every component comes from (no GPL-derived code). The Radxa ROCK 3C board port, whose drivers are
ported from Linux and U-Boot, is a separate GPL-2.0-only repository: [metallium-os-rock3c](https://github.com/anthonydarkoonx/metallium-os-rock3c).

## Layout
| path | what |
|---|---|
| `kernel/` | boot, MMU, frame allocator, device-tree reader, GICv2/GICv3 + timer, SMP (up to 32 cores), scheduler, capabilities, IPC, async rings, syscalls, PCIe enumeration, SMMUv3 IOMMU |
| `user/` | one userspace image, role chosen at start: test conductor, IPC service, crashy demo driver, CPU-hog worker, virtio-blk driver, virtio-gpu display driver, virtio-input keyboard driver, screen task + shell, EROFS server, LFS server, VFS server, `prog`; per-task heap, ring library |
| `tools/` | host tools: EROFS image builder (fallback), disk assembler (uses `mkfs.erofs` when present), post-run disk checker |
| `libs/metallium-lz4` | LZ4 block compress/decompress (interop-checked against the `lz4` CLI) |
| `libs/metallium-zram` | compressed page store with compaction; LZ4 or Zstandard pages; used by the kernel at boot |
| `libs/metallium-zstd` | Zstandard (RFC 8878), from the spec: a frame decoder (bounds-checked, verifies the XXH64 checksum), an allocation-free *compressor*, and an allocation-free decoder for the compressor's output (the kernel has no heap) |
| `libs/metallium-erofs` | read-only EROFS reader incl. LZ4- and ZSTD-compressed files and big physical clusters; runs in the `rofs-server` task |
| `libs/metallium-lfs` | log-structured CoW block store with segment cleaning; runs in the `lfs-server` task |
| `libs/metallium-map` | the `.map` program package format: parser, validator, builder, trust store and signature policy (see `docs/PROGRAMS.md`) |
| `libs/metallium-gfx` | 2D drawing primitives and the bitmap/outline typefaces; the terminal draws its text with it. The OS ships no window system: it is meant to run one (a window manager or desktop environment) as ordinary user programs; see `docs/DESKTOP-INTERFACE.md` |
| `libs/metallium-input` | device-neutral input events: pointer (mouse/touch/pen) and key events in 24.8 fixed point, the translator for the drivers' packed words, the gesture recogniser (tap, context menu, pan, fling, pinch). Host-tested, for a window system to use |
| `libs/metallium-fdt` | flattened device tree reader (RAM, cores and their speeds, GIC, PSCI conduit); host-tested on real QEMU trees and damaged copies |
| *entropy driver (separate repository)* | [metallium-entropy-userspace](https://github.com/anthonydarkoonx/metallium-entropy-userspace): the virtio-rng driver (role 21), which feeds the kernel's generator with `ADD_ENTROPY` |
| *networking (separate repository)* | [metallium-networking-userspace](https://github.com/anthonydarkoonx/metallium-networking-userspace): the IP stack (`metallium-net`), the network service `netd`, the virtio-net driver `netdrv`, the HTTP client, the client API and test programs, and the host peer; see its `README.md` |
| `libs/metallium-usb` | USB input without hardware: HID descriptor and report parsing, key tables; host-tested |
| `libs/metallium-ed25519` | SHA-512 and Ed25519 signature verification (RFC 8032), no heap |
| `libs/metallium-sched` | big.LITTLE placement policy; the kernel feeds it a mock topology |
| `libs/metallium-driver-rt` | what the user-space tasks and the device drivers share: the system-call layer and `println!`, the mapping layer, virtio, DMA cache maintenance, the driver/client protocols (`proto`) and the network ring layout (see `docs/DRIVER-PACKAGES.md`) |
| `libs/metallium-compact` | physical-memory compaction planner (two-finger scan) and fragmentation metrics; property-tested on the host |

## Syscall ABI (`svc #0`)
x0 = id, x1..x5 = args; x0 = result (negative = error); extra results in x1..x5.
`IPC_SEND=1 IPC_RECV=2 IPC_CALL=3 MEM_MAP=4 CAP_GRANT=5 CAP_REVOKE=6 YIELD=7`, plus additions:
`IPC_REPLY=8 LOG=9 SLEEP=10 EXIT=11 TICKS=12 IRQ_WAIT=13 CAP_INFO=14 HEAP_GROW=15 RING_SETUP=16 RING_ENTER=17`,
`MEMCTL=18 HEAP_RELEASE=19 NCPUS=20 SYSINFO=21` (CPU id, RAM, IOMMU and task counts, harness flags).

## Async rings
`RING_SETUP` maps one page per task holding a submission ring and a completion ring (32 entries
each, single-producer/single-consumer, acquire/release indices, no locks). Userspace queues `NOP`,
`SEND`, `CALL` (async IPC; the reply is a completion tagged with the caller's `user_data`) and
`TIMEOUT` entries and polls completions without any syscall; `RING_ENTER(n, min)` submits a batch and
can sleep until `min` completions are ready. The kernel only accepts a submission while outstanding
operations + unconsumed completions stay below the CQ size, so the CQ cannot overflow. A server that
dies with calls in flight completes them with `E_DEAD`.

## Memory management and the compaction daemon
RAM is sized at boot (8 MiB to 255 GiB). The allocator's per-frame tables (19 bytes a frame, including a list of each owner's frames, so a dying task's memory is found without scanning RAM) are carved out of the last frames of RAM. The kernel identity-maps the first GiB of RAM (its image lives there) and reaches the rest through a direct map in TTBR1 (`0xFFFF_FF80_0000_0000 + pa`), so the user windows in TTBR0 never collide with RAM.
Every physical frame has a kind: unmovable (kernel, page tables, DMA/shared objects) or movable (a
private user page with exactly one mapping, recorded in a reverse map). Unmovable frames are taken from
the bottom of RAM and movable ones from the top, so they do not interleave. The kernel provides the
*mechanism*: it can migrate a movable page (invalidate the mapping, broadcast a TLB flush, copy, remap;
a core that touches the page in that window faults, waits for the kernel lock, finds the mapping valid
and retries), allocate physically contiguous memory, and report fragmentation statistics. The *policy*
is the userspace `compactd` task: demand-driven, it does nothing until contiguous allocations have
failed, then compacts in bounded batches of 64 pages with a pause between them. A contiguous allocation
can also compact synchronously (`MC_ALLOC` with the direct flag). The planner is `libs/metallium-compact`.

Tested in QEMU with 64 MiB: the conductor fills memory with pages holding known data, frees every other
one (thousands of single-frame holes), shows a 512 KiB contiguous request fail, lets `compactd` fix it,
hammers the pages being moved from another core (faults that raced with a move are counted and
retried), verifies every page afterwards, then repeats with synchronous compaction.

## Task slots
The number of task slots is chosen at boot (`task::tasks_for`): one per MiB of RAM, between 64 and 1024, or what the fw_cfg file `opt/metallium/max-tasks` says. All per-task state (task records, saved registers, scheduler slots, spawn bookkeeping) is carved out of RAM at that size (`kernel/src/table.rs`), and so are the endpoint table (the 22 boot-time endpoints and `MAX_OWNED_EPS` = 4 for every task slot: 4118 at 1024 slots) and the memory-object table (64 boot-time entries and 8 for every slot, at least 192). The capability node pool holds 8192 nodes. Endpoint and object ids are 16 bits. `make scale` starts programs until all 997 free slots of a 1024-slot table are used (each holding 4 endpoints and 2 shared-memory objects), ends them together and checks that every frame, node and slot comes back.

## Scheduling, SMP and locking
Cores come up through PSCI `CPU_ON` (up to 32; how many, and their MPIDRs, come from the device tree), each with its own stack (made from RAM, with an unmapped guard below it), MMU setup and timer. There is
**no global kernel lock**: kernel code on different cores runs in parallel.

*Locks.* A small set of spinlocks, each with a *rank*; a core may only acquire a lock whose rank exceeds
every lock it already holds, so no cycle of waiting cores can form. The check runs on every acquisition
and panics immediately on a violation instead of deadlocking once in a million runs.
`lifecycle < spawn < compaction < endpoint(e) < task(t) < ring(t) < capability nodes < irq < objects < smmu < memory < console`.
Common paths (an IPC round trip between two tasks, a syscall on the caller's own state) take only their
own endpoint and task locks. The operations that must see many tasks (a task dying, a capability revoke)
exclude each other and the calls that create, wait for or give capabilities to other tasks (SPAWN, WAIT, THREAD_CREATE,
TASK_START, CAP_GRANT, RESTORE_OF) with the *lifecycle* lock, but they no longer stop the machine: a revoke first
kills its capability nodes atomically (nothing can be used or made under a dead node), then clears the tasks' tables one task lock at a
time and only then frees the node numbers; a dying task is first cut off from the endpoints (no sender wakes it, its queued calls are
dropped), then everyone linked to it is told. Memory is claimed under its lock and zeroed outside it; the console
lock keeps lines from interleaving.

*Scheduler.* Lock-free (its ready, timed and real-time task sets are multi-word bit masks, one bit per task slot): each task's run state is one atomic word and a core *claims* a task with a
compare-and-swap. A task is owned by a core from dispatch until that core's next dispatch decision, so
no other core can pick it while its own core is still handling its syscall. Wakeups write the task's
frame first and publish with a release store; a core that claims the task sees it. Blocking is ordered so
a caller is marked blocked *before* the task that will reply can run; idle cores announce themselves,
re-check for work, and are woken by a targeted IPI (one core per runnable task, claimed by the sender).

Policy (`kernel/src/sched.rs`; the arithmetic lives in `libs/metallium-sched` and is unit-tested on the host):

* **Real-time reservations.** A task holding a `Sched` capability with `R_RT` can reserve `runtime` microseconds of CPU in
  every `period` (`SCHED(SC_RT_SET, ...)`). It is admitted if the reserved shares on one core stay under 80% (earliest
  deadline first with implicit deadlines meets every deadline up to 100%; the rest is for the kernel and everyone else),
  is confined to that core, and runs ahead of every other class, earliest deadline first. It says its job is done with
  `SC_RT_WAIT` and sleeps to the next period; one that overruns its budget is parked until the period ends (so a runaway
  real-time task can take no more than it reserved), and every period that ends with a job unfinished is counted as a
  missed deadline. The core's timer is armed for the exact instant a real-time task is due, not for the next tick. A
  server that is serving a real-time caller inherits its deadline (through IPC, like the class priority).
* **Classes.** Below real time, strict class priority (Interactive > Background > Heavy), *priority inheritance* (kept in
  atomics: the caller being served and the senders queued on the endpoints a task receives on), an aging rule (a runnable
  task that has not run for 250 ms goes first), per-task core pinning.
* **Time slices.** Round robin within a priority with a slice per class (2 ms interactive, 5 ms background, 15 ms heavy:
  short for work that rarely uses its slice, long for compute, so it is switched less and keeps its caches). A task keeps
  its core until the slice is used up *and* an equal competitor is waiting, or until something that outranks it becomes
  runnable. The slice end is a one-shot timer event programmed only while somebody is waiting for the core.
* **Wakeup preemption.** When a task becomes runnable that outranks what a busy core is running, that core is interrupted at once
  (one IPI per runnable task, to the core running the least important thing it outranks) instead of at the next tick.
* **Load balance and stealing.** Work-conserving: any idle core takes any runnable task it may run. A task prefers the core
  it last ran on (warm caches); another core takes it only when that core is busy (an idle home core is woken for it).
  Counters (`SCHED(SC_STATS, 0)`) show migrations and how many were taken from a busy core.
* **Tickless idle.** A core with nothing to run and nothing it must watch does not take the 100 Hz tick: its timer is set for
  its own next real-time event only, and the lowest-numbered sleeping core also watches for the earliest time any task
  waits for (a sleep, or a timed wait for an interrupt). It keeps ticking while a runnable task is waiting for a core
  (the class rules depend on how long it has waited) or asynchronous calls with timeouts are outstanding. In the test, one
  second of mostly idle time on 4 cores takes about 140 timer interrupts instead of 400 (the busy core still ticks).
* **Energy-aware placement.** Each task and each core has a measured utilisation (a decaying average over 8 ms windows,
  rising quickly and falling slowly). Light work stays on efficiency cores, sustained compute on performance cores; the other
  kind helps only when a task does not fit (it needs more than 80% of an efficiency core) or has waited too long (5 ms for
  Heavy work, 4 ms for light work), and a task goes back as soon as its slice ends. Among the idle cores that may run a
  woken task, the one where it adds the least power wins (a convex power model, with a cost for waking a cluster).
  **The power figures are nominal and relative, not measurements, and there is no actuator: the kernel computes the
  frequency each core would ask for (`target_util`, shown at shutdown) but QEMU has no operating points and no platform
  driver sets them.** The mock 2+2 big.LITTLE split is still a mock: QEMU's cores are identical.

Address spaces are ASID-tagged, so a task switch needs no TLB flush.

*What this scheduler does not do, and what was and was not tested.* Real-time tasks are partitioned: each is confined to
the one core it was admitted on, with implicit deadlines (deadline = period) and a hard budget (it cannot use idle time
beyond its reservation); there is no global EDF, no migration of real-time tasks and no sporadic or mixed-criticality
model. A server that serves a real-time caller inherits its deadline, but that path has only host unit tests of the
ordering (`Rank::inherit`), no QEMU test. The kernel
computes the frequency each core would ask for but nothing actuates it (QEMU has no operating points, and a platform
needs a governor driver), and the power model is nominal. The real-time numbers below were measured on an emulator
whose host threads are occasionally descheduled for milliseconds, which no guest scheduler can prevent, so the tests
tolerate a few outliers and say so; on real hardware the interrupt-to-dispatch latency would have to be measured again.
To keep four emulated cores from queueing on the emulator's global lock (every counter read takes it), the scheduler
reads the clock sparingly: a context switch caused by a task blocking in a system call may reuse the previous reading
(at most 8 in a row; any timer interrupt, and any core with a real-time task, reads it afresh), so run time of ordinary
tasks is accounted slightly short; a real-time task's budget is enforced by a timer event at the exact instant it runs out.

*Measured* (`make test` prints it; QEMU on a 16-thread host, 4 CPUs): N independent client/server pairs,
each pair pinned to its own core, 6000 IPC round trips each. Throughput varies by about +-6% from run
to run with host load (and drops further if other jobs share the machine), so ranges are given:

| | big kernel lock (before) | fine-grained (now) |
|---|---|---|
| 1 pair | ~48,000 round trips/s | 45,000-48,000 |
| 2 pairs | ~66,700 (1.4x) | 80,000-86,000 (1.7-1.9x) |
| 4 pairs | ~67,000 (1.4x) | 141,000-150,000 (3.1-3.3x) |
| lock acquisitions that had to wait | ~50% | ~0.0% (endpoint, task) |

*Scheduler rewrite, same benchmark, same session, alternating runs* (the host was noisier than when the table above was taken, so
compare only within these lines): previous scheduler 41,000 / 71,000-75,000 / 100,000-106,000 round trips/s for 1 / 2 / 4
pairs; this one 28,000-38,000 / 69,000-75,000 / 103,000-113,000. Two and four pairs are equal within the noise; one pair is
about 10% slower (the extra bookkeeping on each context switch: utilisation, slices, wake stamps). Getting there took
work: the first version of the new scheduler was 40% slower at four pairs, because on an emulator every read of the system
counter and every write of the timer takes the emulator's global lock; the hot paths now read the clock lazily, program the
timer only when an earlier interrupt is needed, and keep per-task and per-core data on their own cache lines.

The before column is a single measurement taken when the big lock was still in the kernel, so a
1-pair difference of a few percent is inside the noise: no slowdown is demonstrated. The point is that
unrelated work no longer serialises. The remaining gap to linear scaling at 4 pairs is not lock
contention (the locks barely wait); it is likely QEMU's own multi-core emulation, which I have not
separated from the kernel.

## Programs: SPAWN, WAIT, KILL
The task table is no longer fixed at boot. Slots 0-24 hold the boot-time services; slots 25-63 are for *programs* and their threads,
created at run time with a `Spawn` capability (right `R_SPAWN`; the conductor holds it, and may pass it on with the
grant right, so programs can start programs). **The kernel knows no executable format.** `SPAWN` makes an *embryo* — a
task with a 64 KiB stack, its arguments and its capabilities but no code — `TASK_LOAD` puts fresh pages with chosen
contents and permissions into it (never writable and executable at once), and `TASK_START` begins execution. Reading
the image is the job of the loader (`libs/metallium-loader`, ordinary code in the parent, unit-tested and fuzzed on the
host): the flat format of `programs/link.ld` (a 32-byte header with magic, size of the read-execute part, total memory and
an 8-byte name, then code) and static ELF files. The program starts at EL0 with `x1` = a 64-bit argument and `x2` = its
parent. A program
holds the console and exactly the capabilities its parent chose to delegate (up to eight, by slot, only those the
parent holds with the grant right; the grant right itself is not passed on) and a heap quota the parent sets (at most
4096 pages). Memory limits are hierarchical: a program also gets a *budget* of pages it may hand down, a spawn costs the
parent `heap + budget + 24` pages (plus one per loaded image page) until the child is gone, a program may have at most 8
programs at a time, contiguous allocations count against the same limit as the heap, and a parent can resize a child
(`QUOTA`). So a tree of programs cannot hold more than its root's budget, whatever it does (see `docs/ABI.md`).

`WAIT(task, nohang)` blocks until the child is gone and returns its exit code (the `EXIT` argument; `u64::MAX` if it
faulted, `u64::MAX-1` if it was killed); a finished child is a zombie holding only its slot until collected.
`KILL(task)` condemns a child. Only the parent may wait for or kill a child. When *any* task dies its children are killed
and their slots freed as they die, so nothing is left that nobody could collect; everything a program held is reclaimed
by the same code that reclaims a crashed service. `programs/` holds a few programs (`hello`, `crash`, `sleeper`, `ping`,
`mem`, `burn`, `spawner`), built by `make programs` and packed into the system image under `/bin`; `make quick-programs`
runs just their tests (a program's exit code, a fault, kill and zombies, delegation and its refusal, the heap limit,
programs starting programs, running out of slots, malformed images, eight programs at once, and 300 start-run-collect
cycles after which every frame, capability node and slot is back: about 0.5 ms each under QEMU). The run-state bitmasks
of the scheduler are 64 bits wide now (it was 32 tasks).

Programs can also **serve**: `EP_CREATE` (with a `Factory` capability) makes an endpoint at run time, owned by the
capability it returns; the creator delegates a receive copy to a server program and send-only copies to clients, and
revoking or destroying it wakes whoever waits on it (sixteen exist at most, four per task). With `file access` in the
spawn request a program gets a VFS session (one page per program slot, a quarter as many as task slots, 8 to 255; the VFS server asks the kernel which page belongs to a
sender, and starts a new program in a reused slot with no open files). The request block (`SPAWN` takes the address of a
96-byte structure) also carries the argument block (NUL-separated strings copied onto the child's stack) and
per-capability rights masks. The shell runs `/system/bin/<name>` (or `/data/bin`, or a path) with a command line and environment (the argument block), and is
the program's console: output comes back as the command's output (so programs pipe and redirect like builtins), input is
the previous pipeline stage or the keyboard (Ctrl-D ends it), and Ctrl-C ends the program. **ELF executables** (static
AArch64 `ET_EXEC`, or position-independent `ET_DYN` with a random kernel-chosen base in a 248 GiB range; every program in `/bin` and the boot-time services are built that way) load as well as the flat images; a malformed one is refused for the right reason (segments outside
the image window, writable-and-executable pages, dynamic linking, truncated files, ...). `docs/ABI.md` is the complete interface.

## Threads
A program may be given an allowance of up to eight *threads* (`THREAD_CREATE`): extra tasks that run in its address
space, each with its own registers, stack, capability table (copies of chosen capabilities of the creator) and
scheduling state, so they run on different cores at once. The memory side — page tables, mappings, heap and its quota,
the owner of every frame — stays with the program's first task, which is also the name the file system and the parent
know; a thread's `HEAP_GROW`, `MEM_MAP` and page faults act on it. The memory of a program is returned when the last
of its tasks is gone (a fault anywhere, `EXIT`, or `KILL` ends them all, and the kernel waits for every one before it
frees a frame). The one blocking primitive is `WAIT_WORD(address, expected, timeout)` / `WAKE_WORD(address, count)`:
check-and-sleep is atomic with respect to the wake, so "store, then wake" never loses a sleeper; `THREAD_EXIT` stores a
value in a word and wakes its waiters only after the thread's slot is free, which makes a joined thread entirely gone.
`programs/src/thread.rs` builds `join` and a `Mutex` from them; the tests count under a lock with five tasks, alternate two
tasks 500 times through one word, time out waits, crash and kill programs whose threads sleep or spin, read files
through the shared session, start 150 threads in a row and check that every frame and capability node comes back.

## The std-like layer
`programs/src/` (the library `metallium_programs`) is what a Metallium-OS program links: a native API shaped like Rust's `std` where that
fits, with no POSIX in it. `heap` is the allocator (a coalescing free list over `HEAP_GROW`), so `Vec`, `String`, `Box`,
`BTreeMap` and `Arc` work; `io` has `Read`/`Write`, `stdin`/`stdout`/`stderr` (standard error is its own operation on the
console endpoint) and `print!`/`println!`/`eprintln!`; `fs` has `File`, `OpenOptions`, `read`/`write`, `metadata`,
`read_dir`, `create_dir`, `remove_*` over the VFS session (one lock, so threads share it safely); `thread` has `spawn`,
`JoinHandle`, `scope`, `Builder`; `sync` has `Mutex`, `Condvar`, `RwLock`, `Once`, `OnceLock`, `mpsc` channels, all built from
`WAIT_WORD`/`WAKE_WORD`; `time` has `Instant`, `SystemTime`, `sleep` (a new `CLOCK` call: monotonic nanoseconds, and the
wall clock from QEMU's PL031); `process` has `Command` (arguments, environment, capabilities, heap and thread allowance,
inherited or captured standard streams, `output_with_input`) and `Child`; `ipc` has typed `Endpoint`s; `env` has
`args`/`var`/`vars`. A program is `program!("name", |c| -> u64 { ... })`, whose value (a `u64`, `()` or a `Result`) is the
exit code. `stdtest` (an 8-section program, ~80 checks) runs all of it under QEMU, including threads that serve an
endpoint, children whose output is captured, and a check that no frame or capability node is left behind.

## Networking
The networking code lives in its own repository, [metallium-networking-userspace](https://github.com/anthonydarkoonx/metallium-networking-userspace), which has to be checked out next to this one (the Cargo manifests and the Makefile refer to `../metallium-networking-userspace`). The stack is written from the RFCs (`crates/metallium-net` there, `no_std`, driven by its caller: frames in, time in, frames out):
Ethernet and ARP, IPv4 with fragment reassembly, ICMP echo and errors, UDP, **TCP** (RFC 9293 state machine with
RFC 5961 blind-reset protection, window scaling, Nagle, delayed ACKs, RFC 6298 retransmission timer, RFC 5681/6582 slow
start, congestion avoidance, fast retransmit and NewReno recovery, zero-window probes; no SACK or timestamps yet), a
DHCP client with renewal, and a DNS resolver. It was tested before it ever saw a NIC: 30 host tests (RFC test vectors,
a simulated link with loss, duplication, reordering, delay and a bandwidth limit, 200 000 mutated frames, 12 000 random
segments at established connections, and a soak of random links - 40 000 rounds were run once - that moves hundreds of
kilobytes both ways and closes from a random side). The soak found two real bugs: after a timeout the sender
rewound `snd_nxt` and then rejected the acknowledgements for what it had already sent, and its pure ACKs carried the
rewound sequence number, which the peer threw away as old.

Two userspace services run it. `net-driver` (role 18) is the virtio-net driver: 64 receive and 32 transmit buffers in
DMA memory it shares with the service, a ring page between them, the device confined by the IOMMU to exactly those
pages; it parses nothing. `netd` (role 19) owns the stack, speaks the session protocol of `docs/ABI.md`, and gives every
program that was started with the network flag its own handles, which it closes when the program ends. A new
`IRQ_RAISE` call lets the service wake the driver as if the device had interrupted. Under QEMU's user-mode network the
guest gets 10.0.2.15 by DHCP, pings the gateway, resolves names, and runs TCP at 14-19 MB/s against a Python peer
(`tools/netpeer.py` in that repository) on the host: 1 MiB echoed byte for byte, 2 MiB down and up with a checksum, 60 connections in a
row, four threads with a connection each, a listener the host reaches through a port forward, sockets abandoned by a
program that exits, and `netd` killed while a connection is open. `make quick-net` runs just those.

## Syscall fuzzer
`make fuzz` (`fw_cfg opt/metallium/fuzz=<seed>`, part of `make test`) starts a task (role 17, `user/src/fuzz.rs`) that holds
a deliberately mixed set of capabilities (send rights to the VFS, block driver, filesystems, display and keyboard
drivers, a `MemCtl` with every right, a `Sched`, shared memory, one grantable endpoint) and calls every system call
for 15 s with random and hostile arguments (wrapping addresses, kernel and device addresses, stale slots, a ring page
scribbled with random indices). The conductor then checks that the kernel is up, that no service was left dead, that
the free frames, capability nodes and dynamic memory objects are back where they were, and that it survived itself.
What it found so far: the block and display drivers' fault-injection operations were open to every holder of their
endpoint; `RING_ENTER` slept for ever when asked to wait for more completions than could arrive; the object-table
entries of `MC_ALLOC` memory were not released when their task died (six deaths would have exhausted `MC_ALLOC`);
`MEM_MAP` and `LOG` summed user addresses without overflow checks.

## Fault injection: the chaos test
Services are meant to be killable at any instant, so `make chaos` kills them at random instead of at
hand-picked points. A *monkey* task (role 15, started only when the harness passes `fw_cfg
opt/metallium/chaos=<seed>`) holds the only `Admin` capability; it sleeps 0.2-2 s, then kills one of the block
driver, the EROFS server, the LFS server, the VFS, the display driver or the keyboard driver (a `KILL_ROLE`
syscall that needs that capability and can name only those roles). The kernel then restarts it the usual way:
reclaims its pages, cuts its device off in the SMMU, rebuilds it. Meanwhile the conductor runs a workload
against every service for 30 s and checks, exactly:

* a `/data` write that returned success reads back byte for byte; a write that failed because a service
  died under it may or may not have landed, but is atomic (the old version or the new one, never a mix);
  a confirmed file never goes missing;
* EROFS reads on `/system` stay correct; display flushes, keyboard polls and block queries recover;
* afterwards every service answers again, every file is a legal version, and free memory has not shrunk
  across all the restarts (a leak per restart would show immediately).

A sample run: 31 kills (blk 7, rofs 6, lfs 4, vfs 7, gpu 3, kbd 4), 1,305 writes, 953 verified reads, zero
corruption, free frames 13,850 -> 13,921.

What it found: in one of the first 16 campaign runs (seed 56, 4 CPUs) a read of a file returned 3,511 bytes
matching neither the old nor the new version, because the VFS died while rewriting a file in place and
the LFS kept the half-written blocks. That is now a deterministic regression test (kill the VFS in the
middle of a rewrite; the previous version must come back intact), and the file layer rewrites by copy-on-write
(see the storage stack below).

*Restart policy.* A service is restarted up to 5 times *in a row*; the count starts over once an instance
has run for 3 s. (It used to be 5 for the whole run, so a driver that crashed once an hour would die for good
on its sixth crash. The chaos test kills services more than five times, so it relies on the budget recovering.) A service that crashes in a tight loop still gives up.

## ZRAM with two codecs
`libs/metallium-zram` is a compressed page store (static arenas, no heap). It compresses with LZ4 or with
**Zstandard**: `libs/metallium-zstd`'s compressor is allocation-free (a 4 KiB-page workspace is about 50 KiB). Per
block it finds matches with short hash chains and one step of lazy matching; Huffman-codes the literals
(one stream below 1 KiB of literals, four above; the code description is 4-bit weights or an FSE stream),
falling back to raw or RLE literals when those are smaller; and gives each of the three sequence streams
the cheapest of the predefined FSE table, a one-symbol RLE table, or a table fitted to the block and
transmitted (the choice is made by computing each option's exact bit cost). Its frames are ordinary
Zstandard frames: the real `zstd` tool decodes every one of them (checked over all shapes and sizes, 400
random pages, and pages whose byte distributions force each description format). The kernel reads them
back with a small allocation-free decoder for exactly that subset (Huffman codes up to 10 bits, tables up
to 2^8 states; it says `Unsupported` for anything else, such as repeat-offset codes or a table reused from
an earlier block, never misreads; 30,000 random corruptions of entropy-coded frames must not panic).
Measured page sizes (`cargo test -p metallium-zram -- --nocapture compare`): zero page 26 B (LZ4) vs 11 B,
numbered text 431 vs 276 B, source code 967 vs 544 B, small-integer array 826 vs 346 B, noise 4096 vs 4096 B
(kept raw). On real files, one frame per 4 KiB page (`ratio_report` in `libs/metallium-zstd/tests/encoder.rs`),
the output is the same size as the real `zstd -3` or a little smaller (Rust source 43% of the input vs 44%,
a Python binary 59% vs 60%, libc 55% vs 57%), because a page is too small for what the higher levels do
(repeat offsets, optimal parsing) to pay. Missing: repeat-offset codes, a Huffman table or sequence
tables reused across blocks (no cross-block state: each page is its own frame), dictionaries.

### Swap: compressed RAM, in the kernel (`kernel/src/swap.rs`)
The ZRAM store is the kernel's swap device. Cold private user pages are compressed (Zstandard, a 2 MiB pool)
and their frames freed; the next touch decompresses them back. Mechanism in the kernel, policy in userspace:
* **Which pages.** A clock algorithm on the MMU's access flag: pages are mapped young; a pass clears the flag
  of every young page it meets (and flushes the TLBs, so the next touch faults), and evicts a page whose flag
  is still clear from the previous pass. A touch of an aged page takes an *access flag fault*, which just
  sets the flag. Only the allocator's *movable* pages are eligible (exactly one mapping, found through the
  reverse map), minus the task's ring page, which the kernel addresses physically. Page tables, DMA buffers
  and shared objects never move or swap.
* **Evicting.** Under the owning task's lock: break the mapping (invalid descriptor, all TLBs flushed, so no
  core can still reach the frame), compress, store the handle in the now-invalid descriptor (a software bit
  marks it swapped, the permission bits stay), free the frame. If the store is full the mapping is restored.
* **Bringing back.** A translation fault on a swapped descriptor allocates a frame, decompresses into it and
  re-installs the mapping (with an instruction-cache sync for code); the instruction runs again. System calls
  that read user memory (`log`) bring pages back the same way. If no frame is free, the handler first evicts
  16 other pages. Faults are decided by what the descriptor says *under the lock*, because another core may
  have evicted, moved or aged the page between the fault and the handler.
* **Teardown.** A dying task's store entries are released with its frames; releasing heap pages frees swapped
  ones from the store without decompressing them.
* **Policy.** `compactd` watches free frames: below 24 it runs clock passes until 128 are free (forcing
  eviction only when fewer than 8 remain). The chaos monkey also forces random evictions of any task's pages
  while it kills services (every seed: pages pushed out, brought back, and discarded with their task).
Measured in the QEMU test: 580 heap pages (2.3 MiB) evicted into 225 KB (9%, the test mixes text, zero,
slowly-changing and random pages), every page read back intact, a system call that needed a swapped-out
page got it back, and with memory exhausted (12 frames left of 64 MiB) the daemon swapped cold pages out and
all 12,850 pages the test held were verified afterwards (12,750 of them also took access-flag faults).
* **Writeback to disk (the pager).** When the pool is three quarters full `compactd` asks for 16 pages to be written back
  (`MC_SWAP_WRITEBACK`). The kernel never waits for a disk: a userspace **pager** (`programs/src/bin/pager.rs`, an ordinary program
  with file access and a `MemCtl` capability holding `R_MEM_PAGER`) asks for jobs (`MC_PAGER_NEXT`): a *write* job carries a
  page decompressed from the store and **sealed** (ChaCha20-Poly1305, a boot-time key only the kernel has; checked again when the page comes back, a changed page is lost and the program faults; code pages are never written back), which the pager writes to a slot of `/data/swap` and reports (`MC_PAGER_DONE`); only then
  does the descriptor change to "on disk (slot)" and the store entry go. A task that touches such a page takes a translation
  fault, the kernel queues a *read* job and puts the task to sleep for a tick; it faults again until the pager has read the
  slot and the kernel has mapped a frame filled from it. `LOG`, `WAIT_WORD` and `WAKE_WORD` on a page that is on disk are
  restarted the same way (the `svc` is rewound). Rules that keep it safe (kernel/src/pager.rs): only pages of programs with
  no threads are written back (never boot services, so the VFS server and block driver cannot end up waiting for the disk,
  and never the pager); a touch, a release or the program's end while a write is in flight cancels the write (the commit is
  made under the program's lock and checks the descriptor still holds that exact store entry); a failed read unmaps the page
  rather than serving wrong data; if the pager is gone for 5 s the programs waiting for it are killed; a restarted pager takes
  over the outstanding job. QEMU tests: 48 pages written, the pager killed and restarted, every page read back with its
  content, a `LOG` call on a page on disk, and a program rewriting its pages while they are pushed out (about 240 written,
  190 read back, 15 writes cancelled by a touch, no wrong data, no slot left behind).
**Not implemented**: swapping shared or pinned pages, a per-task limit, readahead, compressed writes (the disk gets whole
pages), writeback for programs with threads (a thread-exit wake-up through a word on a page on disk would be lost), and
disk-backed pages for the boot services. Someone has to start the pager (the test conductor does); without one the pool
simply fills and eviction stops (pages stay resident) rather than failing.

## Storage stack (all userspace, all restartable)
    program / client -> vfs-server -> rofs-server -> blk-driver -> virtio-blk -> disk.img  (/system: EROFS, read-only)
                              \-> lfs-server  -> blk-driver                           (/data: log-structured)
The VFS (`user/src/vfs.rs`) gives applications open/read/write/seek/close/stat/list/mkdir/unlink with
per-client file descriptors. `/data` is a small file layer on the log-structured store: a directory
table (up to 1024 entries over several blocks, full paths of up to 127 bytes so directories nest) plus data blocks keyed by inode.
**Replacing a file is atomic.** Every file owns a *pair* of inode numbers, and the directory table points at
one. A writer that opens with `O_TRUNC` builds the new version in the other, readers keep seeing the
committed version, and the close that rewrites the table (one LFS checkpoint) flips the file over; only then
are the old blocks freed. A writer killed halfway leaves blocks nothing refers to, never a half-written file
(the chaos test found the earlier in-place scheme tearing exactly this way). Removing a file likewise commits
the table first and frees its blocks afterwards. **The store's restarts are visible to the VFS.** The store (LFS server) keeps staged blocks in RAM until a
checkpoint, so a restarted instance has silently lost them, and a retried checkpoint against it would report
success with nothing to commit. Every store instance therefore has an *epoch*; every reply carries it, a
checkpoint request names the epoch it expects (the store refuses otherwise), and a writer remembers the epoch it
staged under: a close after a restart fails (and an in-place update is rolled back) instead of publishing a file
whose blocks are gone. A read the store cannot serve is an error, never a hole, and a failed checkpoint leaves the
table on the old version. (These three were found by the chaos test once swapping slowed the services down: before
that, no seed happened to put a store restart between a writer's puts and its close.)
Files are kept dense, so a block left behind by a dead
writer can never show through a gap in a later sparse write. A newer writer supersedes an older one, so a
client that died holding a file open cannot wedge it.
**In-place updates are atomic too**, without copying the file: a writer opened without `O_TRUNC` runs an
*undo session*. Its first write records the session (file, generation, size before) in a journal block and
makes that durable; then, before any block of the file is first overwritten, the old content is copied to an
undo block (blocks past the old end need none, a rollback just drops them). Every checkpoint writes the
journal together with the data it covers, so whichever checkpoint a crash finds (even one that another
client's commit made while this update was half done) also finds what is needed to undo it. Closing the
writer commits the new size and ends the session in one checkpoint, then frees the undo blocks. A session
that never closes is rolled back at the next VFS start, or when the next writer opens the file. The cost is
one extra block copy per block touched, so the database-style workload stays far cheaper than copying the
file. While a session is open, other readers see the in-place bytes (it is atomic across crashes, not
isolated from concurrent readers). Seven tests kill the VFS mid-update, across another file's checkpoint,
while growing a file, with abandoned and superseded writers, and after an unlink (each fails if undo
logging is switched off).
The data layer's directory table is format `VFS3` (several blocks, 1024 entries, 127-byte paths); a `VFS2` table (one block, 51 entries) is still read and the next commit
writes the new layout (`make table-test`); a table older than `VFS2` is not read, so such a `/data` partition starts out empty. The `prog` task holds only a VFS capability.

Disk layout (`tools/mkdisk.py`; `EROFS_OPTS` picks the compression, default ZSTD + 16 KiB clusters): sector 0 magic, 1024..3071 EROFS image, 4096..16383 LFS store.
Servers pass bulk data through shared pages; each block-driver client has its own DMA buffer, chosen by
the kernel-supplied sender id. Servers retry block I/O when the driver restarts.

The log-structured store divides the log into segments, writes sequentially into free ones, and runs a
cleaner (copy live blocks forward, snapshot the index, commit) when free space runs low. Space freed by
a commit is only reused by a later commit, so a crash at any point finds the last checkpoint intact.

## Userspace drivers
A driver task is given capabilities, not privileges: a `Memory` cap for its device's registers (mapped
as device memory), `Memory` caps for DMA buffers, an `Irq` cap it blocks on with `IRQ_WAIT`, and
`R_INFO` to learn physical addresses via `CAP_INFO` (clients don't get that right). `user/` contains a
virtio 1.x block driver built this way. The device is a **PCIe** function (`virtio-blk-pci`): the
kernel scans the ECAM region, sizes and places the BARs (nothing ran before it to do so), and hands
the driver only the BAR that holds the virtio registers plus a read-only copy of the device's config
space, from which the driver parses the virtio capabilities itself.

### The device watchdog
A device that stops answering must not hang its driver (and everything waiting on it) for ever. `IRQ_WAIT`
takes an optional timeout in ticks; the block and display drivers give each command 5 s, and when the
device stays silent they log it and exit, the kernel restarts them, and starting up resets the device.
The expiry is settled under the IRQ lock against a real interrupt, so a late answer cannot be lost or
delivered twice. Tested by making each driver submit a command *without notifying the device* (a request
only the conductor may make): the driver notices within 1 s, restarts, and serves again.

### Display, keyboard and the shell
Three PCIe devices sit behind the SMMU, each with its own driver task and its own stream: the block
device, a **virtio-gpu** (2D) and a **virtio-input keyboard**. The shared virtio-PCI transport is
`user/src/virtio.rs`.

*Display.* The kernel allocates a 640x480 framebuffer (300 contiguous pages). The display driver
(`user/src/gpu.rs`) holds it plus its queue and command pages; the SMMU limits the device to exactly those
pages. The *screen task* (`user/src/info.rs`) also maps the framebuffer and draws into it; the driver
only turns "present this rectangle" requests into `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH`.
The test conductor holds neither the framebuffer nor the device.

*Keyboard.* `user/src/kbd.rs` keeps 16 receive buffers on the device's event queue. It is a *polled*
driver: no interrupt, the shell asks for keys (`KBD_POLL`) and the driver drains the queue, decodes key
presses with a US layout (Shift, Caps Lock, Ctrl, arrows) and returns up to 16 characters. A desktop asks for raw
events instead (`INPUT_POLL`: keys, pointer position, buttons, wheel), or sleeps until there is one (`INPUT_WAIT`, up to a second at a time).

*Encrypted data volume.* `/data` can be encrypted (`docs/ENCRYPTION.md`): a random volume key sealed under key slots (a passphrase, PBKDF2-HMAC-SHA512; and the machine's
own secret, so nobody has to type anything), every 4 KiB block sealed with ChaCha20-Poly1305 under a fresh nonce with its position authenticated. A blank data partition on a
machine that has a device secret becomes an encrypted volume by default; a locked volume holds the file server back and the screen task shows a greeter (the built-in prompt,
or a separate repository's: `docs/GREETER-INTERFACE.md`). `make volume-test` and `make qemu-test-encrypted`.

*USB input.* The same task also drives a USB controller (`user/src/xhci.rs`, xHCI; the parsing is in `libs/metallium-usb`): keyboards
and pointers on root ports or behind hubs (up to three tiers, 16 devices at once), plugged and unplugged while the system runs,
with key repeat (the device does not do it). The controller's interrupt wakes a waiting client when the machine has no virtio
input device; `make usb-test`, `usb-test-hub`, `usb-test-many` and `usb-test-noncoherent` drive it through QEMU's monitor. Not done: SuperSpeed hubs and hubs
with one transaction translator per port.

*Console and shell.* The screen task draws a scrolling text console (`user/src/console.rs`: 52x20
cells of a hand-drawn 5x9 font, a banner, a status bar with live uptime and RAM) and runs a shell on it
(`user/src/shell.rs`). The shell is an ordinary VFS client (task id 20 has its own shared page in the
VFS server); beyond its screen it holds three capabilities: the keyboard driver, one VFS endpoint and
that page. What you see after boot:

    METALLIUM-OS
    KERNEL   Metallium-OS 0.1 aarch64 microkernel
    UPTIME   0h 0m 4s
    CPU      4x Cortex-A72           <- MIDR_EL1, through the SYSINFO syscall
    GPU      virtio-gpu 640x480 (2D)
    RAM      11 MiB / 64 MiB
    STORAGE  10 MiB virtio-blk (EROFS + LFS)
    IOMMU    Arm SMMUv3, 3 devices confined
    TASKS    20 running, 9 driver restarts
    metallium /> ls /system
    bin/  etc/  hello.txt  usr/
    metallium /> echo hi > /data/note.txt
    metallium /> cat /data/note.txt
    hi
    metallium /> _
    up 0h 0m 50s   RAM 9 MiB / 64 MiB   18 tasks

Commands: `help fetch uptime free clear pwd cd ls cat stat mkdir rm echo ps grep wc head tail sort`.
A line is `cmd args | cmd args ... [> file | >> file]`, words may be quoted, and `ls /system | grep etc`,
`ps | grep vfs` or `cat f | sort` work: each program reads a file argument or the pipe (`grep` matches plain
text, not regular expressions). `>` / `>>` write files on `/data` (`/system` is read-only and says so).
`ps` lists the kernel's task table (state, restarts). Keys: **Tab** completes command names, files and
directories (and lists the choices when there are several), Up/Down history, Backspace, Ctrl-L clears,
Ctrl-C cancels. `make run-window` opens a QEMU window with the terminal centred on a plain backdrop (`user/src/screen.rs`); click into the window to give it the keyboard
(Ctrl-Alt-G releases it). That session skips the tests and starts the program manager. Output is upper/lower case as typed; there is no mouse support.

*How it is tested.* The display driver's test card, and its restart after the IOMMU kills it, are checked from the guest's log by `make qemu-test` and `make qemu-test-noncoherent`. The screen itself is not read back from outside.

### The IOMMU: a driver cannot make its device reach memory it was not given
Holding MMIO and DMA capabilities used to be enough to make the device read or write *any* physical
page. Now the kernel programs an **Arm SMMUv3** (`kernel/src/smmu.rs`): when the block driver's
capabilities are installed, the device's stream gets a stage-2 translation whose tables map exactly the
DMA pages the driver holds (4 pages) and nothing else; an unattached stream is aborted. The device
must negotiate `VIRTIO_F_ACCESS_PLATFORM` (otherwise the virtio device bypasses the IOMMU, which
was the first thing the test caught). The addresses are identity-mapped, so the SMMU restricts *where* a
device can reach, not what address it uses.

On a fault the SMMU's event interrupt logs it, cuts the stream off at once, and condemns the owning
driver; the scheduler kills it the next time any core would run it (never while it runs elsewhere) and
the normal restart path gives the new instance fresh pages and a fresh translation.

Tested with a deliberately misbehaving driver (`BLK_EVIL`): it points the device's data descriptor at
a page it was never granted, which the conductor has filled with a marker. The device's read faults
(`F_TRANSLATION`), the driver is restarted, the request fails with `E_DEAD`, the marker never reaches
the disk, and the restarted driver serves requests. As a control, granting that page to the stream makes
both checks fail.

## Status: what is real, what is not
Working and tested (host tests, plus a QEMU test asserting on console output and the final disk):
boot to EL0, per-task page tables, timer preemption, SMP on 1-4 cores with fine-grained locking and a lock-free scheduler (priority and deadline inheritance, real-time reservations with admission control and budget enforcement, per-class time slices, wakeup preemption, work stealing with core affinity, energy-aware placement, tickless idle),
capability grant/revoke (subtree revocation also unmaps shared pages), zero-copy shared memory, async
rings, driver crash -> page reclaim -> restart, PCIe enumeration, an SMMUv3 IOMMU that confines the block device
to its driver's pages (tested against a misbehaving driver), an IRQ-driven userspace virtio-blk driver whose data
survives mid-service crashes, a VFS with a least-privilege program task, a log-structured store with
segment cleaning (power-cut tested at every write point), LZ4-compressed EROFS reading verified against
real `mkfs.erofs` output (plain, LZ4, LZ4HC, ZSTD, legacy-index, 1 KiB blocks, big 16/64 KiB physical
clusters: 172 files byte-for-byte in each), a ZSTD decoder checked against the reference `zstd` encoder
(192 frames, levels 1-19, plus 30,000 corrupted frames that must not panic), LZ4, ZRAM.

Not implemented (despite the original spec): a window system, compositor or GUI (the kernel is meant to be paired with a separate window manager or desktop environment), a mouse, a GPU beyond one 2D
scanout (no 3D, cursor, resize or multiple outputs), shell features beyond line editing (no pipes,
scripts, job control or tab completion); real SoC/mobile drivers; ARM CCA/RME realms (driver
isolation here is plain EL0 + MMU); an IOMMU for devices other than the block device (only virtio-blk, virtio-gpu and the keyboard are
behind the SMMU; the SMMU is driven with polling command completion, wired interrupts and stage 2
only, with no ATS/PRI/MSI);
POSIX semantics beyond the basics
(no permissions, timestamps, hard links, mmap; `/data` holds at most 1024 files and directories, paths
under 128 bytes, 4 KiB per IPC round trip); EROFS tail-packing, fragments/packed inodes, MicroLZMA and
DEFLATE and ZSTD dictionaries -- such images are rejected, never
misread; a
secure/verified boot.

**DMA cache maintenance** is implemented (`user/src/dma.rs`, `kernel/src/cache.rs`) but can only be *run*, not proven, under
QEMU, whose devices are coherent. Every transfer of a userspace driver goes through the virtqueue wrapper, which
cleans (`DC CVAC`) what the device reads (descriptors, available ring, request headers, data to write, the
framebuffer rectangle before a transfer) before telling it, and flushes (`DC CIVAC`) what the device writes (data read,
status bytes, the used ring, input events) both before the transfer and again once it completes, so no dirty line can
overwrite the device's data and no stale line is read in its place. Only clean and clean-and-invalidate are used
because those are the operations EL0 may execute (the kernel sets `SCTLR_EL1.UCI`/`UCT`); they never lose a
neighbour's data in a shared line. The kernel does the same for the SMMU's stream table, translation tables and
queues, and when `IDR0.COHACC` says the SMMU does not snoop the caches (or the harness pretends so:
`make qemu-test-noncoherent`, part of `make test`) programs them non-cacheable and non-shareable as the architecture
requires. Not covered: buffers a driver does not map (the deliberately misbehaving test drivers), devices other than
the three virtio ones and the SMMU, cache-line-sharing hazards between a device-written buffer and unrelated CPU data
(buffers here are whole pages or line-aligned structures), and a real non-coherent device has never run it.

**Address-space layout** is randomised per program (stack, heap, ring page, and the stacks the kernel makes for threads) from a ChaCha20 generator seeded from several sources, with replayable seeds for debugging; the stack, thread-stack and heap ends have unmapped guard pages (docs/ABI.md, last section); shared-memory mappings are randomised when the program asks the kernel to choose (`MEM_MAP` address 0); program images are randomised too (position-independent ELF files), and the kernel image sits at a random place in RAM on every boot (`make kaslr`, docs/ABI.md); the kernel's own stacks have 16 KiB unmapped guards (`make stack-guard`).

**Other security limits that are by design absent**: and **no side-channel mitigations at all**: nothing against Spectre-style speculation (no speculation
barriers on kernel entry, no branch-predictor or cache flushing on a task switch, no retpoline-equivalents), cache
or TLB timing channels between tasks (caches and TLBs are shared and only ASID-tagged), rowhammer, or timing leaks in
the compressors (compressed size and time depend on the data, which matters for swap: an observer who can measure
swap activity learns about page contents). Isolation here is page tables plus capabilities plus the SMMU, not more.

`cap_grant` is bounded: a task may have 40 grant-made capability nodes outstanding, and 48 nodes are never given out by it, so a hostile
holder of `R_GRANT` cannot make a restart fail by exhausting the node table (test "capability grants are bounded").

The kernel uses `unsafe` (MMIO, asm, lock-protected globals). The code written in the latest sessions
(PCIe, SMMU, display, keyboard, shell, fault injection) had one independent read-only review; every
finding that could be confirmed by reading the code was fixed, and the ones reachable from userspace got
regression tests, each checked to fail when its bug is put back. The kernel is still unaudited. The log-structured store
reformats a data partition that has no valid checkpoint, without asking; an IO error in the middle of a
commit leaves its in-memory accounting stale until remount.
