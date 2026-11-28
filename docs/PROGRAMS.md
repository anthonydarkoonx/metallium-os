# Programs: the `.map` package, the program manager and the ability model (phases 1 and 2)

An *program* is a Metal Program Package (`.map`): one file with a manifest and the programs it runs. The *program manager*
(`progmgr`, `programs/src/bin/progmgr.rs`) installs packages, starts their *abilities* with exactly the rights the manifest
asks for, tells them when they move between foreground and background, and restarts one that crashes. Nothing here is in
the kernel: `progmgr` is an ordinary program that holds the spawn capability, and a program is an ordinary PIE ELF program
built with the `programs` crate.

## The package (`libs/metallium-map`, `tools/mkmap.py`)
Header (32 bytes: magic `METALMAP`, version 1, manifest length, file count, table length, CRC-32 of the rest), manifest,
file table, data. `Package::parse` checks sizes, the checksum, the manifest, that every path is a plain relative path
inside the package, and that every ability's entry is an ELF file; it never panics (unit-tested, including every
single-byte corruption and every truncation of a package). `tools/mkmap.py` builds the packages in
`programs/packages/<id>.manifest`; `make map-check` has the Rust parser check what the Python tool built.

Manifest (`key = value`, `#` comments): `id` (1-16 of `a-z 0-9 _ - .`), `name`, `version`, `unsigned`, `heap_pages`
(1-1048576, default 128), `threads` (0-64), `quota` (1-1024: the files and directories the program's own directory may hold, default 12), `class` (interactive/background/heavy), `permission` (`files`, `network`,
repeatable; `display` gives the program the display endpoint (slot 2; for a window system to use); `allfiles` gives the whole file system instead of the program's own directory (for programs that browse the whole disk); `shell` makes the program a shell client: the program manager gives it its control endpoint as slot 3; `spawn` lets the program start programs of its own, see *Starting programs* below), `spawn_pages` (with `spawn`: pages it may hand down to the programs it starts, 1-16384, default 4096), `ability = NAME ui|service bin/PROGRAM` (repeatable, up to 8).

## Signing and trust (`libs/metallium-ed25519`)
A package may carry a signature block (72 bytes at the end: a key id and an Ed25519 signature of every byte before it). The system
decides whom to trust with two files of the read-only system image: `/system/etc/program-keys` (`name = <64 hex digits>`, one line per
trusted public key) and `/system/etc/program-policy` (`allow_unsigned = false`). `metallium_map::check` accepts a package only if it is
signed by a trusted key and the signature verifies, or, in developer mode (`allow_unsigned = true`), if it is unsigned *and* its
manifest says `unsigned = true`. A missing trust store trusts nobody and an unreadable policy is the strict one. The manager
checks at install *and again at every start* (the copy in `/data/programs` is on a writable partition).

`libs/metallium-ed25519` is SHA-512 and Ed25519 verification, written from FIPS 180-4 and RFC 8032 with no heap and no `unsafe`. Its
constants are generated from their definitions; it is tested against RFC 8032 vectors 1 and 2, signatures made by Python's
`cryptography` package, a check that `[L]B` is the identity, and that every changed byte of a signature, key or message is
refused (it is not constant time: verification handles only public data). `tools/mkmap.py` signs with `tools/keys/dev.seed`;
`rogue.seed` is a key the image does not trust. Both are public test keys.

## Installing
Packages of the system image are in `/system/usr/programs/<id>.map`. `INSTALL` checks one (structure, then trust) and copies it to
`/data/programs/<id>.map` (the data partition holds few files, so a package is one file, not a directory tree); the manager
re-reads `/data/programs` when it starts. The package's id must equal its file name. `UNINSTALL` refuses while an ability runs.

## What an ability gets
Started from the package's bytes with `Command::image`, with: the heap limit, scheduling class and thread count of the
manifest; file-system access only with `permission = files`, and then confined to the program's own directory (below); network only with `permission = network`; slot 0, a
read-only *board* page; slot 1, a send capability to the manager's *program endpoint*. No control endpoint, and no spawn
capability unless the manifest says `permission = spawn` (below). The control endpoint (install/start/stop) is a different endpoint: only its holders can use it, and the program
endpoint refuses everything except `save`. The `probe` sample checks all of this from inside a program.

## Starting programs (`permission = spawn`)
A program that runs other programs (a terminal running command-line programs) declares `permission = spawn`. The manager then gives it:

| Slot | Capability | Rights |
|---|---|---|
| 5 | endpoint factory | create endpoints (for its children's consoles); not the right to pass it on |
| 6 | spawn | start programs; **with file access only if the program has `allfiles`**, with network only if it has `network`; not the right to pass it on |

and a budget of `spawn_pages` (default 4096) to hand down, taken from the manager's own. These are the slots `metallium-programs`' `Command`
uses, so `Command::new("ls").spawn()` works in such a program as it is. The rules:
* **Children never get more than their parent.** File access for a child needs `allfiles`, not `files`: a child started with file access
  gets a new file session that is *not* confined to the parent's directory (confinement belongs to one session, see `docs/ABI.md`
  `SCOPE`), so a confined program handing one out would escape its directory. A `files`-only program with `spawn` starts programs without
  file access. Network for a child needs `network`.
* **No grandchildren.** Neither capability carries the grant right, so the programs it starts cannot start programs of their own.
* **They are its children.** It may `WAIT` for and `KILL` them, and they end when it ends (stopped, crashed or uninstalled).
* A program may have at most 32 programs at a time (`docs/ABI.md`, *Memory limits*).

The OS console (role 13) is not a program and keeps its own spawn capability (slot 8). A desktop's shells should declare `spawn`
rather than rely on that (`docs/DESKTOP-INTERFACE.md`).

## Private storage
A program with `permission = files` has its own directory, `/data/programdata/<id>`, and for the program **that directory is `/data`**: the VFS
rewrites its paths after refusing `..`, so it cannot name another program's data, the manager's packages or anything else on the data
partition; `/system` stays readable and read-only. The directory is made when the program first starts and removed when it is
uninstalled. A program may have at most 12 files and directories in it (the data store holds few entries in all). The manager asks
the VFS to confine the program *after the program is loaded and before it runs its first instruction* (`Command::scope`,
`metallium_loader::spawn_with`, VFS `SCOPE`, see `docs/ABI.md`), and the VFS accepts that request only from the program's parent. The `fsprog`
sample checks all of it from inside two programs with the same code.

## Lifecycle (`programs/src/ability.rs`)
`impl Ability` with `on_create(restored)`, `on_foreground`, `on_background`, `on_destroy`, `on_tick`; declare with
`ability!("name", |ctx| value)`. The manager writes the state into the program's board entry and wakes it with `WAKE_WORD`;
the ability sleeps on the entry's sequence word (`WAIT_WORD` with the tick interval as timeout), so nothing polls between
changes. A UI ability starts in the foreground; a service ability has no foreground or background. `STOP` sets the
state to *destroying*; the ability runs `on_destroy` and returns; one that has not left after 50 ticks is killed.

## Supervision
The manager polls its children once per tick. An ability that ends with a non-zero code (a fault, a panic, killed by its
limit) is restarted a tick later; `on_create` gets the two words the previous instance passed to `ability::save` (kept
in the manager's memory, so they survive a crash of the ability, not of the manager). More than 3 crashes within 10 s and
the manager gives up (`ST_FAILED`). An ability that ends with 0, or after `STOP`, is stopped and not restarted.

## Control protocol
`IPC_CALL` on the control endpoint: `w0 = op | ability << 8`, `w1`,`w2` = the id (16 bytes). Ops: INSTALL 1, UNINSTALL 2,
START 3, STOP 4, STATE 5 (reply `state | restarts << 8 | running << 24`, last exit code), FOREGROUND 6, BACKGROUND 7,
LIST 8 (`w1` = index), INFO 10, SAVED 11, NAME 12, POLICY_GET 13, POLICY_SET 14, GRANT 15 (see *Permission policy* below). START carries the permissions this start gives up in bits 16..22 of `w0` (bit 0 files, 1 network, 2 display, 3 shell, 4 allfiles, 5 admin, 6 spawn), STATE reports them in bits 25..31. INFO reports `spawn` in bit 32 of `w1` and `spawn_pages` from bit 33. Status in the reply's `w0`: 0 ok, 1 no such program (INSTALL: not found), 2 no such
ability (INSTALL: invalid package), 3 wrong state (INSTALL: id differs from the file name), 4 refused (INSTALL: the program
runs), 5 failed, 6 not marked unsigned, 7 all 16 board entries in use. `progctl` is the command-line client
(`progctl install ID`, `start`, `stop`, `state`, `list`) and, started with no arguments, the test scenario.

## Tests
`make qemu-test` starts `progmgr` and runs `progctl`'s scenario: install five packages and refuse four flawed ones,
lifecycle callbacks, a crash and restart with saved state while another program keeps running, a memory hog that is stopped
by its limit and given up on, rights (files, control endpoint, spawn), stop, uninstall, reinstall, and a leak check
(tasks, frames, capability nodes). `make map-check` and `cargo test -p metallium-map` cover the format.

## Boot and the shell
`make run-window` no longer runs the test suite first: the conductor starts the program manager, gives the screen task a send
capability to its control endpoint, and the screen task shows the terminal (`user/src/screen.rs`: terminal only, no windows). In the shell, `prog` runs `progctl` with that capability: `prog available` (the
packages of the system image), `prog install ID`, `prog start ID`, `prog list`, `prog state ID` (state, restarts, the two saved words:
the counter program's first word is its tick count), `program fg ID`, `program bg ID`, `prog stop ID`, `prog info ID`, `prog uninstall ID`.
`make qemu-test` still runs the whole suite and does not start the manager outside its own test.

## Not done yet
No service registry. The manager is not restarted if it crashes, and what abilities `save` lives in its memory. Signature
checking trusts the system image's key list: nothing yet measures that the image itself is the one that was built.


## Permission policy

What a program may do is the **manifest** (the ceiling, fixed at install), less what the user has taken away. Three layers, each only able to narrow the one above:

1. **Manifest**: `permission = ...` (signed with the package).
2. **Stored policy**: `/data/programs/<id>.pol`, one byte of permission bits the user took away (same bit order as above, plus bit 6 spawn). It applies to every start, restarts after a crash included, and goes when the program is uninstalled. Set with `POLICY_SET` (the new bits in bits 16..22 of `w0`; reply: old, new), read with `POLICY_GET` (reply `stored | declared << 8`, and the running task or MAX).
3. **This start**: the bits in `START` (the New Task box's tick boxes). Not stored.

The program gets `manifest & !stored & !start`. Nothing can add a permission the manifest does not declare.

**Taking away and giving back, live.** The permissions that stand for a capability take effect in a running program at once: *window* is the display endpoint (slot 2), *shell* the control endpoint (slot 3), *revoke* the revoke authority (slot 4), *spawn* the spawn capability and endpoint factory (slots 6 and 5). Taking one away is the kernel's `REVOKE_OF` (a privileged program does it); giving it back is `GRANT` (the program manager hands its own copy over with `CAP_GRANT` and a destination slot, so the program finds it where it looks; it refuses unless the manifest declares the permission, the stored policy allows it and the program runs). *Files*, *network* and *all files* are sessions the kernel sets up at spawn: a change is stored and applies at the next start.

There is no graphical front end in the tree. A revoke of one of the three capabilities above can be **kept off**, which stores the policy bit after the kernel has accepted the revoke. In a running program only the bits that change at once (window, shell, revoke, spawn) follow in the program manager's record of what it runs without; the others show *on until restart* / *off until restart* until the next start.
