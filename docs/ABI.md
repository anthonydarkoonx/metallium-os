# Metallium-OS userspace ABI (version 1)

What a program can rely on. Everything here is tested (`make test`); the kernel is the reference.

## Calling convention
`svc #0` from EL0. `x0` = call number, `x1`..`x5` = arguments. On return `x0` = result (negative = error) and `x1`..`x5`
carry extra results. Nothing else is clobbered. All pointers are virtual addresses in the caller's space; the kernel
translates them page by page (swapped-out pages are brought back) and rejects anything unmapped or outside user space.

Errors: `-1` no permission, `-2` bad capability (empty slot, wrong kind, revoked), `-3` full, `-4` the other side died
or the endpoint ended, `-5` invalid argument, `-6` no reply owed, `-7` no such call, `-8` out of memory, `-9` timed out,
`-10` try again (non-blocking call would block).

## Floating point
User programs must not use floating-point or SIMD registers: `CPACR_EL1` traps them at EL0 and the program is ended (the registers are not saved between tasks). Build programs for a soft-float target (`aarch64-unknown-none-softfloat`). `TPIDR_EL0` is per task and starts at 0.

## Capabilities
Every right to do anything is a capability in one of 32 slots of the task's table (slot 15 is the console). A capability
has a kind and rights bits: send 1, receive 2, grant 4, map 8, write 16, info 32, memory-stats/compact/alloc/swap, kill,
real-time, spawn `1<<12`, spawn-with-files `1<<13`, create-endpoints `1<<14`. Capabilities form a derivation tree:
revoking one revokes everything derived from it. A holder with the grant right can give a copy with fewer rights to a
task (`CAP_GRANT`) or to a program it starts (the spawn request).

## Calls
| # | name | arguments → results |
|---|---|---|
| 1 | IPC_SEND | slot, w0, w1, w2: queue a message, don't wait (`-3` if the queue is full) |
| 2 | IPC_RECV | slot, nonblock: wait for a message → x1 sender task id, x2..x4 words, x5 = 1 if the sender is waiting for a reply. With `nonblock != 0` and nothing queued: `-10`. `-4`/`-2` if the endpoint ends or the capability is revoked while waiting |
| 3 | IPC_CALL | slot, w0..w2: send and wait for the reply → x1..x3 reply words. `-4` if the server dies or the endpoint ends |
| 8 | IPC_REPLY | w0..w2: answer the caller being served |
| 4 | MEM_MAP | slot, va, writable: map a memory capability at `va` (4 KiB aligned, wholly inside 0x8020_0000..0x8040_0000 or inside the large window 0xA000_0000..0xC000_0000); at most 64 mappings per program. `va` = 0: the kernel chooses a random place (usual window for up to 128 pages, else the large one) with an unmapped page after the object and before the next mapping, and returns the address (explicit mappings return 0). If the window it tries first has no room it uses the other one; a program started with `FLAG_NO_FIXED_MAPS` (spawn flags bit 2) gets `-1` for any `va` but 0 |
| 5 | CAP_GRANT | slot, task id, rights mask, dest: give a copy to a running task; `dest` 0 = its first free slot, `dest` = n + 1 = slot n exactly (refused if that slot is in use). A *program* (anything started with `SPAWN`, as opposed to a boot-time service) may give only into its own program (its threads), into programs it started, and into the program that started it; any other target answers `-1`. A named slot (`dest` ≠ 0) is allowed only into a child, and a grant into another program never takes its last 4 free slots (`-8`). Boot-time services are not restricted. To share memory with an unrelated program, delegate it at `SPAWN` or route it through a common parent |
| 6 | CAP_REVOKE | slot, flags: revoke what was derived from the capability; flag 1 also the capability itself (for an endpoint's creator: the endpoint ends; for run-time memory: it is freed, but only through the creator's capability: on a copy, such as a thread's, only the copy goes) |
| 7 | YIELD | |
| 9 | LOG | console slot, va, len (≤ 256): write bytes to the console |
| 10 | SLEEP | ticks (100 per second) |
| 11 | EXIT | code: end the task; a parent collects `code` with WAIT |
| 12 | TICKS | → ticks since boot |
| 15 | HEAP_GROW | pages → base of the new pages (the heap window starts at a random page within 16 MiB of 0x8100_0000 and ends at 0x8F00_0000; the page after the last heap page is unmapped; limited by the task's quota; `SYSINFO` page 9 gives the start) |
| 19 | HEAP_RELEASE | first page, count |
| 14 | CAP_INFO | slot → physical address, pages, offset (drivers only) |
| 16, 17 | RING_SETUP, RING_ENTER | asynchronous submission/completion rings (`kernel/src/ring.rs`); RING_SETUP returns the ring page's address, a random page within 16 MiB of 0x8F00_0000 |
| 18 | MEMCTL | memory capability slot, op…: statistics, compaction, contiguous allocation, swap; ops 6–10: the pager (below) |
| 20 | NCPUS | → online cores |
| 41 | RESTORE_OF | admin slot, task, log id → the slot: gives back a capability that `REVOKE_OF` took from `task` (listed by `SYSINFO` page 14), in the slot it had (refused if that slot is in use now), as a new child of the node it hung under (refused if that node or the object is gone). Every capability a program has without a parent is one of three kinds. The ones the kernel gives it at spawn (its console, and its file and network session capabilities in slots 8 to 11) are logged too and come back as roots, but only while they are still exactly what the kernel would give (the session must exist). The ones the program made itself (the creator's capability of an endpoint, of shared memory, of a memory allocation) are refused by `REVOKE_OF`: revoking them would destroy the object. Everything else hangs under a node and comes back under it. A restored capability takes a node that is not counted against any grant quota (it replaces one the revoke freed); a memory capability that was mapped is mapped again at the same address. Needs the same `Admin` capability with `R_REVOKE`. Only what the kernel's log of the last 16 revokes holds can come back, so nothing can be made up; copies derived from it stay gone. The log forgets a task's entries when it ends |
| 43 | GETRANDOM | no arguments → 0 and 40 random bytes in `x1`..`x5` (little endian), drawn from the kernel's generator for cryptographic use; `E_NOSYS` (-7) when that generator has no real entropy behind it (no RNDR, no full `opt/metallium/seed`, no virtio-rng device, or one of the layout debugging modes): the caller must then refuse to do cryptography, not fall back to something weaker (`programs/src/random.rs`) |
| 40 | REVOKE_OF | admin slot, task, slot → how many capabilities went: revokes the capability in `slot` of another program (and what was derived from it). Needs an `Admin` capability with `R_REVOKE` (1 << 10); only programs started at run time can be named, never the caller, never the root capability of an endpoint or of shared memory (that would end the object for everyone). The conductor holds it (slot 28), the program manager gets a copy, and a program with `permission = admin` (the task manager) gets one in slot 4 |
| 46 | DEVICE_SECRET | → 0 and 32 bytes in `x1`..`x4`: the machine's own secret (only the data store server, role 6; `E_PERM` for anyone else, `E_NOSYS` if the machine has none): what opens an encrypted data volume without a passphrase (`docs/ENCRYPTION.md`) |
| 47 | IPC_DEFER | → token (the caller's id): park the synchronous call being served; the caller stays blocked and this task can `recv` again. `E_NOREPLY` if there is no such call |
| 48 | IPC_REPLY_TO | token, w0..w2: answer a caller parked by `IPC_DEFER` (`E_NOREPLY` if it is gone or was not parked by this task) |
| 21 | SYSINFO | page, arg → facts (pages 10, 11, 13 and 14, which show what other tasks hold, answer `-1` unless the caller holds an `Admin` capability; pages 0..20 (20: why the machine has no IOMMU, up to 32 bytes in `x1`..`x4`; 18: the number of file and network sessions, and of task slots; 19: the display's and the storage's names, 16 bytes each, NUL padded, in `x1`,`x2` and `x3`,`x4`): 0 memory, 1 tasks, 2 harness flags, 3 task table rows (`arg` = slot; `-5` past the last of the machine's task slots, 64 to 1024: one per MiB of RAM, or the fw_cfg file `opt/metallium/max-tasks`), 4 fuzz seed, 5 file sessions (page, generation, program, parent program or 0xFFFF), 6 network sessions, 7 pages held by a task's program, 8 the caller's own task id, 9 the caller's layout: heap start, stack top, whether randomisation is on, whether the CPU has hardware random numbers, 10 one capability slot of a task (`arg` = task \| slot << 16; any task): kind, object, rights, node; 11 who holds a capability to an object (`arg` = kind \| object << 8 \| window << 24, the object in 16 bits): bit masks of the tasks of one window (bit t is task `window * 64 + t`; all holders, may send / write, may receive / map), the creator or 0xFFFF, how many capabilities name it in all windows; 12 what the object is (`arg` as in 11): 16-byte name in `x1`,`x2`, size in pages or interrupt number, class, creator or 0xFFFF; 13 what revoking a capability would take with it (`arg` = task \| slot << 16 \| window << 24): how many other capabilities derive from it, the tasks of that window holding them (bit mask), how many capability nodes hang under it, 1 if it is the root capability of its object (`REVOKE_OF` refuses those); 14 what has been revoked from a task and can be given back (`arg` = task \| n << 16, oldest first): id, slot, kind, object, rights \| 1 << 16 if what it hung under is still there) |
| 23 | SCHED | op…: real-time reservations (`R_RT`), statistics |
| 24 | SPAWN | spawn capability slot, request va → task id of a new *embryo* (a task with stack, arguments and capabilities but no code; never scheduled) |
| 25 | WAIT | task id, nohang → the child's exit code (blocks until it ends unless nohang: `-10`) |
| 26 | KILL | task id: end a child you started |
| 28 | TASK_LOAD | embryo's task id, request va (24 bytes: `u64` address, `u64` source address in the caller, `u32` pages, `u32` permission 0 = read+execute, 1 = read+write, 2 = read-only): fresh pages at the address, filled from the caller's memory. A page can be loaded once; the kernel never makes a page writable and executable |
| 29 | TASK_START | embryo's task id, entry address (4-aligned, in a loaded executable page): the embryo becomes runnable |
| 30 | THREAD_CREATE | entry, stack top (0 = the kernel makes the stack), `x0` argument, capability mask, stack size in bytes → thread id: a new task in the caller's address space (see Threads) |
| 31 | THREAD_EXIT | address of a word, value: end the calling thread; once it is entirely gone the kernel stores the value in the word and wakes its waiters |
| 32 | WAIT_WORD | address, expected, timeout in ticks (0 = none): sleep while the 32-bit word equals `expected` → 0 woken, `-10` word differed, `-9` timed out, `-5` the address is not in RAM (a device mapping) |
| 33 | WAKE_WORD | address, count → how many sleepers were woken (longest waiting first); `-5` if the address is not in RAM (a device mapping) |
| 34 | CLOCK | op 0: monotonic nanoseconds since the machine started; op 1: wall-clock nanoseconds since 1970 (`-7` where the platform has no real-time clock: QEMU's PL031 has one) |
| 35 | IRQ_RAISE | slot of an interrupt-line capability with the send right: wake whoever waits on it with `IRQ_WAIT` (or make its next wait return at once) |
| 36 | QUOTA | op 0: the caller's program's memory limits → limit (pages it may hold: heap + contiguous), `x1` held, `x2` budget, `x3` budget handed down so far, `x4` programs it has (zombies included). Op 1, child, heap pages (1..=4096), budget pages: change a child's limits (see Memory limits) |
| 38 | SHM_INFO | memory capability slot (map right) → pages of the shared object it names, plus `1 << 32` if its creator has gone and `1 << 33` if the slot holds the creator's capability and no copy is held any more |
| 39 | TASK_BASE | embryo's task id → the address its image area starts at: `0x8000_0000`, or a random page in `0x2_0000_0000..0x40_0000_0000` (about 26 bits of choice) if it was spawned with flags bit 3 (position-independent; the loader relocates the image to that base before `TASK_LOAD`) |
| 37 | SHM_CREATE | pages (1..=4096) → slot of a new memory capability (map, write, grant) for fresh zeroed memory that can be shared with other programs (see Shared memory) |
| 27 | EP_CREATE | factory capability slot → slot of a new endpoint capability (send+receive+grant); at most 4 per program, 16 in the system |

## Programs
The kernel knows no executable format. `SPAWN` makes an embryo, the parent fills the image area (0x8000_0000 up to the
stack) with `TASK_LOAD` and starts it with `TASK_START`; only the parent may do so, and `WAIT` on an unstarted embryo is
refused (`KILL` collects it). The loader (`libs/metallium-loader`, linked into every program that starts programs: `spawn()`
in `programs/src/lib.rs`) reads two image formats, recognised by their first bytes. It is ordinary user code, unit-tested and
fuzzed on the host, and refuses what it cannot load with `-5`.

**ELF** (`\x7fELF`): a statically linked 64-bit little-endian AArch64 executable (`ET_EXEC`, machine 183), at most
4 MiB, at most 16 program headers. Every `PT_LOAD` segment must lie between 0x8000_0000 and 0x800F_0000. Segments may share a page (their permissions are united) but no page may be writable and
executable; `memsz > filesz` is zero-filled. `PT_INTERP` and `PT_DYNAMIC` of a fixed executable are refused. A position-independent executable (`ET_DYN` linked at 0, `-pie`) is also accepted: the loader spawns it with flags bit 3, reads the base from `TASK_BASE` and applies its `R_AARCH64_RELATIVE` relocations (any other relocation, `DT_NEEDED` or a PLT is refused);
other header types are ignored. The entry point must be 4-byte aligned in executable memory. Anything a normal bare-metal
toolchain produces with `-Ttext=0x80000000 -z max-page-size=4096` (or a linker script like `programs/link.ld`) qualifies.

**Flat image**: 32-byte header (`u64` magic `0x4D4F5355`, size of the read-execute part, total memory size — both
multiples of 4096 — and 8 bytes of name), code from the first byte after it (the entry point), data and bss behind
(see `programs/link.ld`).

`SPAWN` reads a 96-byte request in the caller's memory:

| offset | field |
|---|---|
| 0 | `u32` version = 2 (the loader fills it in) |
| 4 | `u32` flags: 1 = file access (needs the spawn-with-files right) |
| 8 | `u32` budget pages: what the program may hand down to programs of its own (0 = nothing, max 2^20) |
| 12, 16 | reserved, zero (version 1 had the image here; non-zero is refused) |
| 24 | `u32` class: 0 interactive, 1 background, 2 heavy |
| 28 | `u32` heap pages (0 = 256, max 4096) |
| 32 | `u64` argument → the program's `x1` |
| 40, 48 | `u64` argument block address, length (≤ 1024) |
| 56 | 8 bytes name (zero: the loader uses the image's; "elf" for ELF files) |
| 64 | 8 × `{u8 slot (0xFF = none), u8 pad, u16 rights mask}`: the program's slot i gets the caller's capability (needs grant), rights ANDed with the mask |

**Start state.** EL0, `x0` = 32, `x1` = argument, `x2` = parent's task id, `x3`/`x4` = address/length of the argument block
(copied to the top of the stack; `sp` is just below it), 64 KiB of stack at a random page of 0x8040_0000..0x8100_0000 (the page below it and the page at its top are unmapped guard pages; `SYSINFO` page 9 gives the top), the console capability in slot
15, delegated capabilities in slots 0–7. With file access: the VFS endpoint in slot 8, the session page (a memory
capability) in slot 9. Heap: `HEAP_GROW`, window as above, limited by the heap quota in the request.

**Argument block.** NUL-terminated strings: the command line (`argv[0]` is the program's name by convention), then an
empty string, then environment variables `KEY=VALUE`. (So an empty argument cannot be passed.) The shell supplies `PWD`,
`PATH`, `TERM`, `HOME`. `programs/src/lib.rs` has `Ctx::argc/argv/env`.

**Console.** By convention the shell (and any parent that wants to capture a program's I/O) gives a send-only endpoint
in slot 7 (send, and the grant right so that it can be handed to the programs it starts). One call at a time:
* WRITE: `w0` = 1 | n << 8 | first 6 bytes << 16, `w1` = bytes 6..14, `w2` = bytes 14..22 (n ≤ 22). The receiver replies.
* WRITE to standard error: the same layout with operation 3 (the shell prints it at once, never into a pipe).
* READ: `w0` = 2 | max << 8 (max ≤ 23). The receiver replies when it has input: `w0` = n | first 7 bytes << 8, `w1` =
  bytes 7..15, `w2` = bytes 15..23; n = 0 is end of input (and stays so).
Without a console endpoint (or if a call fails), output goes to the kernel console (LOG) and input is empty. The shell
feeds READ from the previous pipeline stage or, at the end of a pipeline, from the keyboard line by line (Ctrl-D ends the
input, Ctrl-C kills the program).

Lifecycle: the parent owns the child (`WAIT`, `KILL`). When a task dies its children are killed. A finished child holds
only its slot until collected. Exit code `u64::MAX` = crashed, `u64::MAX-1` = killed.

## Memory limits
Every task has two limits: a **holding limit** (the heap quota: pages it may hold itself, `HEAP_GROW` and contiguous
`MC_ALLOC` allocations together) and a **budget** (pages it may hand down). Starting a program costs its parent
`heap + budget + 24` pages of budget (24 = stack and page tables), and every page loaded into it with `TASK_LOAD` one more;
the cost is returned when the program dies, once. The kernel refuses a spawn that does not fit (`-8`, no memory), so a tree
of programs can never hold more than the budget of its root, whatever any of them does. The boot-time tasks have fixed
budgets (the conductor 30 000 pages, the others 8 192); a program starts with the budget its parent gave it, which is 0 by
default. A program may have at most 8 programs at a time (64 for the boot-time tasks); zombies and unstarted embryos
count, `-3` when it is reached. A parent changes a child's limits with `QUOTA` op 1: the change is charged to or
refunded to its own budget, and refused (`-5`) below what the child holds or has handed down, or (`-8`) beyond the
parent's budget. Allocation past a limit returns `-8` to the program that asked; nothing else is affected.

## Shared memory
`SHM_CREATE(pages)` makes memory that programs share. It is not a privilege: the pages count against the creator's holding
limit (like `MC_ALLOC`; `-8` over it) and the capability needs a free slot (`-3` when there is none, or no capability node or
object-table entry; at most 192 such objects exist in the system, 32 per program). The memory is zeroed and made of single frames, so it never
needs a contiguous run, and it is pinned: it never moves or swaps, so every holder sees the same physical pages and
`WAIT_WORD`/`WAKE_WORD` on its words wake across programs.

The creator's capability has map, write and grant rights. Giving it away (`CAP_GRANT`, or the delegation list of a `SPAWN`
request) hands over a copy with the rights ANDed with the mask: a copy without the write right can only be mapped read-only
(`MEM_MAP` writable gives `-1`). Mapping goes in the usual window or in the large one (512 MiB, for big buffers). `MEM_MAP` with address 0 lets the kernel choose (`programs::map_anywhere`). The file-system and network session pages of `programs` are mapped this way, and `programs::process::Command` starts children with `FLAG_NO_FIXED_MAPS`, so a program started through it has no mapping at an address that could be known beforehand.

**Lifetime.** The creator's capability is the object's kill switch: when the creator revokes it with `CAP_REVOKE` flag 1,
every copy and every mapping of it, in every program, is removed and the frames are freed (a program still touching it
faults and dies alone), and the same happens when the creator exits and nobody else holds a copy. If the creator exits
while others hold copies, the object lives on as an *orphan*: it belongs to the kernel, is charged to nobody (the
creator's charge is returned at once), the holders keep what they have, and it is freed when the last holder lets go
(`CAP_REVOKE` or exit). A holder that exits or revokes its own copy changes nothing for the others. Revoking what the
creator granted (`CAP_REVOKE` without flag 1) takes the copies away from the holders: a program that relies on memory a
partner made must expect that, which is why a server that reads a client's memory (a compositor, say) should create that memory itself.

`SHM_INFO(slot)` gives the size in pages of a shared object (needing only the map right, so a program that was given one can
check what it maps) with bit 32 set when its creator is gone and bit 33 when `slot` is the creator's capability and no copy of
it is held any more: the creator can tell that its partners are gone.

**Capability slots.** A new capability (`SHM_CREATE`, `CAP_GRANT`, `EP_CREATE`) goes to the first free slot of the table,
except slot 15, which holds the console. There are 1024 capability nodes in the system (a node is one capability and the
copies derived from it).

**Per-program limits on shared tables.** A program (its threads together) may hold at most 32 run-time memory objects
(`SHM_CREATE`, `MC_ALLOC`), at most 192 capability nodes it made for itself (its own memory and endpoints, its threads' copies, what it
gives the programs it starts), and at most 4 run-time endpoints; with all its threads it may have at most 4 of the 8 messages queued at one endpoint (`IPC_SEND` answers `-3` beyond that) and may hold 5 of the file-system and 5 of the network sessions (a quarter of the task slots each, 8 to 255; SYSINFO 18 gives the number) for the programs it starts (`SPAWN` answers `E_FULL`). Programs also never take the last 16 object-table entries, the last 48
capability nodes or the last 4 endpoints: those stay for boot-time services. Over a limit the call fails as if the table were full
(`-3`, `E_FULL` or `E_NOMEM` as before). What a thread creates is its own: it goes when the thread ends, so a program that wants memory or
endpoints to outlive its threads makes them in the first thread.

## Threads
A *thread* is a task that runs in another task's address space. `SPAWN` request `flags` bits 8..11 give a program an
allowance of 0..8 threads at once (default 0; the parent decides). `THREAD_CREATE(entry, stack top, arg, mask)` starts a
thread at `entry` with `x0 = arg`, `sp = stack top` (16-byte aligned; the program provides the stack, for example from
its heap) and, for every bit `i` of `mask`, a copy of the creator's capability in slot `i` (same rights, a new node
derived from the original, so revoking the original takes it back) plus the console.

**Kernel-made stacks.** With stack top 0 the kernel makes the stack: the sixth argument is its size in bytes (0 = 64 KiB,
at most 1 MiB, rounded up to pages; more gives `-5`). It sits at a random page in the stack region, apart from the
main stack and the other thread stacks, with an unmapped guard page below and above it, so an overflow faults instead of
running into other memory. Its pages count against the program's heap limit (`-8` when they do not fit) and are freed
when the thread ends (`THREAD_EXIT`, fault or kill); `QUOTA` shows them in the pages held. `programs::thread::Builder` uses
this for every thread. A stack the program provides itself (stack top not 0) works as before, without guard pages.

Errors: `-1` = no allowance left, `-3` = no free task slot.

What belongs to the **program** and is shared by its threads: the address space and everything about it (mappings, heap
and its quota — `MEM_MAP`, `HEAP_GROW`, `HEAP_RELEASE` and `MC_ALLOC` act on it — the ring, which only the first task may
set up), the file-system session (one page: threads must not use it at the same time, so take a lock around a file
operation; the file descriptors are the program's), the exit code, and its place in the parent's task table. What belongs
to the **thread**: its registers and stack, its capability table, its scheduling state, its IPC identity (servers see
the thread's task id; `SYSINFO` page 5 tells them which program it belongs to), and the endpoints it created.

Ending: `THREAD_EXIT` ends only the calling thread and frees its slot at once. A fault in any task of the program, `EXIT`
from any of them, or `KILL` of the program by its parent ends *all* of them (the exit code is the program's); the memory
is returned when the last one is gone, and the parent's `WAIT` returns then. A parent may `WAIT`/`KILL` through any of its
threads.

`WAIT_WORD`/`WAKE_WORD` are the only blocking primitive threads need: check-and-sleep is atomic with respect to
`WAKE_WORD`, so "change the word, then wake" never loses a sleeper. A word in a program's own memory is per program. A word
in memory that never moves — a shared memory object, a DMA buffer — is identified by its physical address, so programs that
both have the page mapped can wake each other (the network service wakes sleeping programs this way). Joining a thread: pass a
word to `THREAD_EXIT` and wait on it (`programs/src/thread.rs`: `join`, and a `Mutex` built from the two calls).

## Network
Programs started with the network flag (`SPAWN` flags bit 1; the parent's spawn capability needs the network right)
hold a send capability to the network service `netd` in slot 10 and a session page in slot 11, and use it like the file
system: map the page, `IPC_CALL` the endpoint with `w0` = operation, names and data in the page from offset 256 (at most
3840 bytes). The service answers every call at once: `w0` of the reply is a status (0 ok, 1 would block, 2 end of stream, 3 no
address yet, 4 out of sockets, 5 address in use, 6 bad handle, 7 invalid, 8 failed with the reason in `w1`: 1 refused/not
found, 2 reset/failed, 3 timed out). Handles belong to the program that made them and are closed when it ends.

**Waiting.** The first 32-bit word of the session page is an event counter. A call that answers "would block" leaves a
watch in the service (what the program is waiting for); when it is satisfied the service adds one to the counter and calls
`WAKE_WORD` on it. A program that wants to block reads the counter *before* the call and, on "would block", does
`WAIT_WORD(counter, value read, timeout)` (`programs/src/net.rs` does, with a half-second cap in case a wake-up is lost, e.g.
because the service was restarted: it wakes every session when it starts). An idle socket costs about three calls a second.

| op | meaning |
|---|---|
| 100 STATUS | → `w1` = address \| mask << 32, `w2` = gateway \| DNS server << 32 (status 3 until DHCP has finished) |
| 101 PING, 102 PING_REPLY | send an echo request (`w1` address, `w2` = identifier \| sequence << 16 \| length << 32, payload in the page); wait for the answer |
| 110 UDP_BIND, 111 UDP_SEND, 112 UDP_RECV, 113 UDP_CLOSE | datagrams: `w1` = port (0 = any) → handle; send `w1` = handle \| length << 32, `w2` = address \| port << 32; receive → length \| port << 32, address |
| 120 TCP_CONNECT, 121 TCP_STATE, 122 TCP_WRITE, 123 TCP_READ, 124 TCP_CLOSE, 125 TCP_ABORT, 129 TCP_NODELAY, 133 TCP_SHUTDOWN | streams: connect `w1` = address, `w2` = port → handle (the connection forms in the background: ask for the state until it is no longer 0); state → `w1` = state (0 connecting, 1 up, 2 peer finished, 3 closing, 4 closed) \| error << 8, `w2` = readable \| space << 32 |
| 126 TCP_LISTEN, 127 TCP_ACCEPT, 128 TCP_UNLISTEN | `w1` = port, `w2` = backlog → handle; accept → connection handle, peer address \| port << 32 |
| 130 DNS_START, 131 DNS_RESULT, 132 DNS_RELEASE | the name in the page (`w1` = length) → query; the result is a count and 4-byte addresses in the page |

`programs/src/net.rs` wraps this as `UdpSocket`, `TcpStream`, `TcpListener`, `lookup_host`, `ping` and `config`. The network
driver (`netdrv`) and `netd` share a page of rings and the packet buffers (`metallium-net-ring`, in the networking repository); `netd` wakes the driver
with `IRQ_RAISE`, the driver wakes `netd` with a message to its endpoint.

## Files
The VFS is a service: send `IPC_CALL` to its endpoint with the session page mapped; paths and data travel in the page
(`programs/src/fs.rs` is a client). Operations: open 50, read 51, write 52, seek 53, close 54 (a close commits written
data), stat 55, list 56, unlink 57, mkdir 58, sync 59. `/system` (EROFS, read-only) and `/data` (log-structured, crash
safe). Status in reply word 0: 0 ok, ENOENT 1, EISDIR 2, EBADF 3, EROFS 4, ENOSPC 5, EINVAL 6, EIO 7, EEXIST 8,
ENOTEMPTY 9, EPERM 10. A program's descriptors belong to it and vanish with it (a new program in the same slot starts clean).

**Confined programs (`SCOPE` 62).** A parent can confine a program it started to one directory of `/data`: path in the page, `w1` = the
child's task id. Afterwards the child's `/data` *is* that directory (a path is rewritten after `..` has been refused, so nothing
outside can be named), `/system` stays readable, and the child may have at most 12 entries (files and directories) under it, so one
program cannot use up the store's few. Only the child's parent may do it (the kernel reports the parent in `SYSINFO` page 5), and a
confined parent names the directory as it sees it, so confinement can only narrow. `metallium_loader::spawn_with` calls a hook after the
program is loaded and before its first instruction, which is where the program manager does it: there is no moment at which the program
runs unconfined. A confinement belongs to one session (generation): the next program in that slot starts unconfined.

## Endpoints
`EP_CREATE` makes an endpoint that lives as long as its creator's capability. The creator hands out send-only copies
(`CAP_GRANT` or a spawn delegation with mask 1) and a receive copy to its server. Revoking the server's capability wakes
it from a blocked receive; destroying the endpoint (`CAP_REVOKE` flag 1) fails every call still waiting on it with `-4`.

## Address-space layout randomisation and guard pages
Each program (and each restart of a boot-time service) gets a fresh layout, drawn by `kernel/src/rand.rs` (ChaCha20 with fast key erasure, `libs/metallium-rand`, written from RFC 8439 and checked against its test vectors; every draw is independent
of the others, so one program's layout says nothing about the next one's; not a vetted cryptographic RNG):

| what | where | choices |
|---|---|---|
| stack top | page-aligned, 64 KiB below it, inside 0x8040_0000..0x8100_0000 | ~3000 pages |
| heap start | 0x8100_0000 + a random number of pages | 4096 pages |
| ring page | 0x8F00_0000 + a random page | 4096 pages |

Unmapped guard pages: one below the stack, one at (and above) its top, one after the last heap page (`HEAP_GROW` refuses to
pass 0x8F00_0000); nothing a program can map (the shared-memory windows are elsewhere) lands next to the stack, so a stack
overflow (of the main stack or of a kernel-made thread stack) or an overrun of the heap's end faults the program instead of corrupting a neighbour.
Seeding folds together the CPU's RNDR register (FEAT_RNG), the first 32 bytes of `-fw_cfg name=opt/metallium/seed,file=<file>` (the Makefile
passes 32 fresh bytes from `/dev/urandom` on every run), the counter and machine ID, 32 bytes read once from a virtio-rng device when the bus is probed (`kernel/src/virtio_rng.rs`; the device sits behind its own SMMU stream, reaches one page, and is shut down again), and, after boot, the time of every interrupt. Without
RNDR and without the seed file only the counter is unpredictable and the boot log says "(weak ...)". Debugging modes, all of which give up
unpredictability on purpose: `opt/metallium/noaslr=1` fixes every layout (the lowest value of each range); `opt/metallium/aslr-log=1` prints a boot
seed and runs from it; `opt/metallium/aslr-seed=<n>` replays that seed (the boot tasks then get the same layouts as in the logged run; the boot
log lists them; programs started later depend on the order they are started in). `make aslr-replay` checks that. Each of the three modes prints a `[rand] WARNING` line at boot and leaves the virtio-rng device unread; `make entropy` checks the warnings and that a normal boot folds the device's bytes in.
Program images: position-independent `ET_DYN` programs (everything under `/bin` and the boot-time services) get a random base in
`0x2_0000_0000..0x40_0000_0000` and may be 8 MiB; flat images and static `ET_EXEC` programs stay at 0x8000_0000 (960 KiB).
Not randomised: those fixed images, shared-memory
windows when the program names an address (with `MEM_MAP` address 0 the kernel picks a random one, a page apart from other
mappings; a program started with `FLAG_NO_FIXED_MAPS` cannot name one; the boot-time services, which are trusted and map
device windows, still do). Thread stacks the kernel makes (`THREAD_CREATE` with stack top 0, see Threads) are randomised and have
guard pages; one the program provides itself does not.

**Kernel address (`kernel/src/kaslr.rs`, `boot.S`).** The kernel is a position-independent executable linked at 0x4008_0000, where QEMU
loads it. At boot it applies its relocations, picks a random page-aligned address in RAM where the whole image (code, data, `.bss`, stacks)
fits clear of the first 512 KiB and of the old image, copies itself there with the copy's pointers corrected, and continues in the copy; `kmain`
clears the old image and the allocator treats it as free memory. RAM is identity-mapped, so this changes the physical and the virtual address
together. With 64 MiB of RAM that is about 14 bits. The generator takes RNDR, the harness's seed file and the counter; with neither RNDR nor the
seed file the boot log says the address is guessable. `opt/metallium/noaslr` and the seed modes do not fix it. It does not hide the kernel from
anything that learns one kernel address (the boot log prints them; no system call does). If the RAM size is unknown the image stays put, with a
warning. `make kaslr` boots eight times and checks the addresses differ and lie in RAM.

**Kernel stacks.** Each core has 64 KiB of stack with a 16 KiB unmapped guard below it and a 16 KiB emergency stack (the boot core's are in the kernel
image, the others' are made from RAM when the core starts; RAM is mapped with 2 MiB blocks, and 4 KiB pages where the stacks are). A kernel stack overflow faults; the exception vector switches to a per-core emergency stack and the
kernel stops with "kernel stack overflow on core N" instead of overwriting memory below. A single stack frame larger than the
guard cannot jump over it: for large frames the compiler emits an inline probe that touches one 4 KiB page at a time
(`stack-probes` in the target spec), so the probe lands in the guard. `make stack-guard` provokes an overflow on cores 0, 1 and 31 (32 cores, GICv3)
and with one 128 KiB frame (`opt/metallium/stack-overflow=1`, `opt/metallium/stack-overflow-core1=1`, `opt/metallium/stack-overflow-core=N`, `opt/metallium/stack-overflow-bigframe=1`).

## The pager (`kernel/src/pager.rs`)
`MEMCTL` ops on a `MemCtl` capability. `MC_SWAP_WRITEBACK`(9, `n`) needs `R_MEM_SWAP`; 6, 7, 8 need `R_MEM_PAGER` (rights bit 5 of a
MemCtl capability); `MC_PAGER_STATS`(10) needs `R_MEM_STATS`.

| op | arguments | result |
|---|---|---|
| 6 `MC_PAGER_REGISTER` | `slots` (size of the swap file in pages, at most 1024), `word` (address of a 32-bit word the kernel changes and wakes when there is a job) | 0; the caller is the pager (one at a time; a dead pager is replaced) |
| 7 `MC_PAGER_NEXT` | `buffer` (page-aligned address in the pager's memory) | job kind in `x0` (0 none, 1 write, 2 read), disk slot in `x1`. A write job's page is already in `buffer`, **sealed**: 4096 bytes of ciphertext (ChaCha20-Poly1305 under a key only the kernel has; the tag is kept by the kernel, not written to disk). The pager stores them as they are. Asking again returns the same job |
| 8 `MC_PAGER_DONE` | `status` (0 = done), `buffer` | 0. For a read the kernel checks `buffer` against the seal and, if it is what was written, decrypts it into a new frame and maps it; if not (changed, or from another slot) the page is lost, the program faults when it touches it, `E_INVAL` goes to the pager, and the failure count rises; for a write it commits |
| 9 `MC_SWAP_WRITEBACK` | `n` | 0: `n` more pages (cold ones in the compressed store) are to be written back |
| 10 `MC_PAGER_STATS` | | written in `x0`; `x1` read, `x2` cancelled writes, `x3` failures (including pages that came back changed), `x4` disk slots in use, `x5` a pager is registered |

Executable pages are never written back. Without real entropy for the key (`rand::secure_fill` refuses: the debugging modes, or no RNDR, seed file or virtio-rng) nothing is written back at all. Pages on disk are page-table descriptors with the software bits `SWAPPED` and `ON_DISK` and the slot number where the frame
address was. See the README ("Swap") for the rules about what may be written back and what a fault on such a page does.
