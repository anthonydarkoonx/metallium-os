# Multiple users: a plan (2026-11-20; phase 1 partly built, see *Status*)

## What the OS already gives
* **Processes are isolated by capabilities**, not by user ids: a task can touch another task, a file or a device only through a capability it was given. So *process*
  separation between users is free: two sessions that share no capabilities cannot see each other.
* **Files are the weak point**: the VFS is one namespace; separation today is per *program* (`V_SCOPE`: a program is confined to `/data/programdata/<id>`, set by its parent
  before it runs; `allfiles` and `admin` are permissions in the manifest and the stored policy).
* The **program manager** (`progmgr`) holds spawn/revoke/power authority and keeps per-program policy in `/data/programs`.
* The **screen task** owns the display and keyboard, and (since the encrypted volume) runs a greeter before anything else.
* **Encryption**: one volume key, four key slots (`docs/ENCRYPTION.md`).

## Model
A **user** is a name, a numeric id (16 bits, an index, never reused while the account exists), a role (**admin** or **standard**), a home directory and a **credential**
(a passphrase). There is no uid in the kernel. A **session** is the set of tasks one login started; it is the unit of isolation and the unit of cleanup.
* **Isolation of processes**: free (capabilities). A session's tasks get only capabilities derived from that session's own manager.
* **Isolation of files**: the VFS confines a session to its home with the mechanism programs already use (`V_SCOPE`), extended from "a directory" to "a user": `/home/<name>`
  is `/` for the user's desktop and programs; `/data/shared` is the only common place, and `/system` stays read-only for everyone.
* **Authority**: only an admin session's manager holds the privileged capabilities (power, revoke authority, install-for-everyone, creating users). A standard user's manager
  gets a narrowed copy (no `admin`, no `allfiles`).

## Parts
1. **Account store** (`/data/accounts`, owned by the session service, readable by nobody else): per user id, name, role, home key slot (below), created/last login. No password
   hashes: a credential is a key slot, so there is nothing to crack offline other than the slot itself.
2. **Session service** (a new small boot task, between the greeter and the program manager): `LOGIN(name, passphrase) -> session`, `LOGOUT`, `CREATE_USER`, `SET_CREDENTIAL`,
   `LIST`. On login it starts **one program manager per session** (own control endpoint, own `/home/<name>/.programs` policy, own spawn budget) and the user's desktop; on
   logout it kills the session's tasks (the manager's revoke authority covers them) and revokes its capabilities.
3. **VFS**: a session id with every client (the kernel already tells the VFS which task is calling; the session service tells it which tasks form a session); homes are
   scoped at the root, not per program; per-user quotas (entries and bytes) replace the single global small limit.
4. **Greeter**: asks for a user name and a passphrase (and, first boot, creates the first admin); the contract grows from `LFS_UNLOCK` to `LOGIN`.
5. **Encryption per user** (the part that makes it real): see below.

## Encryption per user (recommended)
One machine-wide volume key (device secret) protects the system data and the accounts; **each home is its own encryption domain** with its own random key, sealed in a
slot opened by that user's passphrase. The store tags every block with its domain id (authenticated, like the volume id today); the VFS says which domain a file belongs to; the
store keeps only the keys of unlocked domains. A locked home is unreadable *by other users, by an admin, and by a copied disk* until its owner logs in. Costs: the store needs a
domain id in `LFS_PUT/GET` (the on-disk block format already carries room in the authenticated data, so a format bump is small); the directory structure of a home must live in
that home's blocks; an admin who forgets a user's passphrase cannot recover the data (an optional escrow slot, off by default).

## Decisions (2026-11-20)
1. **Several sessions at once, switched with Ctrl+Alt+F1..F12.** F1 is the default session's tty (the first login at boot lands there). F2..F12 each show a login prompt until
   someone logs in on them; a logged-in tty keeps its session alive while another is in front. One live session per user: logging in as a user who already has a session
   says so and offers to switch to its tty.
2. **Encryption per user** (each home its own key, opened by that user's passphrase).
3. **One admin, created at first boot** (the first-boot greeter is a setup screen: name, passphrase, recovery key). More users are created by the admin afterwards.
4. **Program configuration is per user** (GlieseWM's config and every program's data live under the user's home; `GLIESE_CONF` becomes `~/.config/gliese/gliese.conf`).

## TTYs: switching is switching userspaces
Each session is a **complete userspace**: its own desktop task, program manager and programs, drawing into **its own scanout buffer**. Ctrl+Alt+F1..F12 only changes which
session is *in front*; nothing is emulated and nothing is copied:
* **Display**: the display driver gets one new operation, "scan out buffer N" (virtio-gpu: set the scanout resource; the board's VOP2: write another buffer address to the
  window and flip). The session in front is simply the one whose buffer is scanned out. A session behind keeps running and drawing into its own buffer, which is not shown.
* **Input**: the input driver learns which session is active and delivers events only to that session's input endpoint. It sees the keys first, so it **intercepts
  Ctrl+Alt+F1..F12 itself** (it already does this for the attention key), switches the active session and tells the display driver, and the key never reaches any desktop.
  A desktop that wants to repaint on being brought to the front gets one event ("you are in front") and presents again.
* **Who may switch**: the right to register a session (its buffer and input endpoint) and to switch is a capability only the session service holds; sessions cannot take
  the screen or the keyboard from each other.
* **F1** is the default session's tty. **F2..F12** with no session run the greeter (one per tty, drawing into that tty's buffer); logging in turns the tty into that user's session.
What remains non-trivial, honestly: (1) the **desktop must be its own task per session**, so the desktop seam grows a second form (a program entry point given its display
and input capabilities, instead of a function linked into the one screen task), and GlieseWM needs the matching change; (2) a **buffer per tty** in use (1920x1080 is 8 MiB;
allocate it lazily when a session starts); (3) a per-session `GPU_FLUSH2` must go to that session's buffer, so the display driver needs a buffer id per client
(a capability per session, not a protocol rewrite).

## Recovery
A forgotten passphrase must not mean a brick, and must not mean the admin can read everyone's files. Options, and what I would do:
* **No recovery**: strongest, and a forgotten passphrase loses that home for good. Right for a user who opts out.
* **Admin escrow**: every home key also sealed for the admin. Easy support, but the admin can read all homes and the admin's passphrase becomes the one secret that matters.
  Rejected as a default.
* **Recovery key (recommended default)**: at account creation a random recovery key (say 24 words, shown once on screen, to be written down) is sealed into one more
  slot of that home. It opens that home only. Nobody else holds it, nothing is escrowed, and the user (or the admin acting for them, with the key in hand) can reset the
  passphrase. A user may decline it at creation (then: no recovery).
* **Reset without the data**: the admin can always **wipe and recreate** a home (new key, empty files), so a locked-out user gets an account back, never the old data.
* **The machine volume**: the device secret binds the system data to one chip (a replaced board, a copied card). At first boot the admin also gets a recovery key for the machine
  volume. Without it a dead board means the system data is gone (the homes are separate, and open with their own passphrases/recovery keys on a rebuilt system).
First boot therefore shows two things to write down: the admin's home recovery key and the machine recovery key.

## Phases and tests (revised order)
| Phase | What | Test |
|---|---|---|
| 1 | Accounts, session service, one desktop and program manager per session, VFS homes (session-scoped), first-boot setup greeter, one tty | two users (one at a time): A cannot list, open or create in B's home (no `..`, no absolute paths); A's programs cannot reach B's tasks; logout leaves no task of the session |
| 2 | Per-user encryption domains and recovery keys | per user, the marker test of `make volume-test`: B's marker unreadable without B's key even with the machine unlocked; recovery key opens only its home; wrong key opens nothing |
| 3 | Per-session buffers, \"scan out buffer N\" and \"active session\" in the display and input drivers, Ctrl+Alt+F1..F12, the desktop as a task, concurrent sessions | two live sessions: the display and input follow the active tty; the other keeps running; switching back restores its screen; F-keys never reach a desktop |
| 4 | Admin model: create/remove users, system-wide installs, power, wipe-and-recreate | a standard user cannot do any of those; revoke authority is absent from a standard session |
| 5 | Board: the chip secret (OTP) for the machine volume, then the same tests on the ROCK 3C | volume and session tests on hardware |

## Known dependencies and risks
* The data store is **small and its directory is one in-memory table** (`Datafs`, scoped programs get 12 entries): homes need a real directory structure, per-user quotas and a
  bigger store before more than a couple of users is practical.
* The VFS must learn session identity without trusting clients: the kernel's sender id plus the session service's table (the same trust the VFS already puts in a program's
  parent for `V_SCOPE`).
* Nothing here changes the kernel's isolation guarantees; the risk is in the services (session service, VFS, greeter), which are all in the trusted base of a login.

## Status (2026-11-20)
Built and tested (phase 1, without the desktop and the encryption domains):
* **`/data` table**: 1024 entries, 127-byte paths (`VFS3`), so homes fit (`make table-test`).
* **Per-scope quotas and inherited confinement** (VFS `V_SCOPE`): a scope carries an entry quota (a manifest's `quota = N`, default 12, never more than the parent's); the quotas of every
  directory above also bind (a home's quota covers what its programs make). `/data` as the scope path means "the same as mine": a confined program hands its own confinement to its
  children, and `Command` asks for it by default, so a session cannot launder its confinement by starting programs; an unconfined parent leaves children unconfined as before.
* **`sessiond`** (`programs/src/bin/sessiond.rs`): accounts in `/data/accounts` (only it, unconfined, can see the file; PBKDF2-HMAC-SHA512 hashes until phase 2 makes the credential a key
  slot), the first account is the administrator, further accounts only from an administrator's live session, login/logout, one session per user, several sessions at once, each a
  program confined to `/data/home/<name>` with a quota. One answer for an unknown name and a wrong passphrase.
* **`make session-test`**: the conductor plays the greeter; three accounts, two users logged in at once, each session cannot see the account store, the other home, `..` or `/home`, has its own
  files and its quota, its child programs are confined to the same home; no passphrase is on the disk in the clear. (A control without confinement fails eight of those checks.)
**Phase 2 (2026-11-21):** per-user encryption domains and recovery keys are built (`docs/ENCRYPTION.md`, *Per-user encryption domains*): login unlocks the account's domain, logout locks it, the
recovery key replaces a forgotten passphrase, and `make session-test` checks from the host that no user's file is on the disk in the clear.
**Greeter (2026-11-21):** the greeter exists as its own repository (`metallium-greeter`) with the first-boot setup, login, recovery screens and `make greeter-test`; `sessiond` is not in the boot flow yet.
**Phase 3, first part (2026-11-21):** in the interactive boot `sessiond` and the greeter are in the normal boot (`make run-window GREETER=<greeter>`); the conductor waits for the first login, and a login starts that user's own *program manager* confined to the home (no machine-wide manager); the console is given its control endpoint (a program may grant only to its parent, so `sessiond` grants to the conductor, which passes it to the screen task) and says who is signed in. `make greeter-test-manager GREETER=...` checks it. **Phase 3, second part (2026-11-21): the ttys' lower layer.** The display driver has a framebuffer per tty (four; tty 0 is the boot one, the other three exist only where sessions run) and `GPU_SCANOUT` shows one; the input driver intercepts Ctrl+Alt+F1..F12, tells the display driver, and hands input only to the tasks of the tty in front (`INPUT_ASSIGN`: only the conductor may assign for now; an `ev::FRONT` event tells a desktop it is in front). `make tty-test` checks it with screenshots and key presses through QMP. **Phase 3, third part (2026-11-22, started):** `GPU_BIND` (conductor only) binds a task to one tty's buffer, so a session's console can draw only on its own tty (`make tty-test` checks it). **Console per tty (2026-11-22, built):** the boot makes three console tasks (role 22, `info::tty_console_task`) in the interactive boot and in `make tty-test`: each has its own tty buffer, its own start endpoint (`EP_TTY` 22..24; `EP_FIRST_DYNAMIC` is now 25), the input and display drivers, and a file page of the session pool (`spawn::boot_fs_page`; the VFS serves any task whose kernel-reported page is valid, not only ids from 27). The conductor starts one with `INFO_CONSOLE` after `INPUT_ASSIGN` and `GPU_BIND`; `make tty-test` checks that tty 1's console draws on its own buffer and shows on Ctrl+Alt+F2. **Greeter and login hand-off (2026-11-22, built):** once the first user is logged in the conductor gives each console its tty's input and buffer (`INPUT_ASSIGN`, `GPU_BIND`) and asks it to run the greeter there (`INFO_GREETER`). `sessiond` records which task completed each login (`FROM`, op 6) and keeps one half-finished request per sender; the conductor polls `FROM` for each console, and when a session appears hands that console the session's program manager (CAP_GRANT) and starts it (`INFO_CONSOLE`). `make greeter-test-tty GREETER=../greeter` (`only=16`: the conductor makes a second account, `tester`) logs in on tty 1 through Ctrl+Alt+F2 and checks two sessions with a program manager each. **Logout (2026-11-22, built):** the terminal command `logout` asks the session service to end the console's session (`LOGOUT`: its tasks are killed, the home's domain is locked); `screen::run` returns, the console runs the greeter again on its own buffer, and the conductor (which polls `FROM` for tty 0's screen task as well) sees the session gone and hands the next login's manager to the console. `make greeter-test-tty` logs out and in again on tty 1 and on tty 0. Each login leaves one dead capability slot in the conductor's table (the manager's control endpoint). **Key isolation (checked):** `make greeter-test-tty` types on tty 0 and on tty 1 in turn and compares screenshots pixel by pixel: the text shows on the tty in front (about 1000 pixels change) and nothing changes on the hidden console (0 pixels). **Per-tty wait (2026-11-22, built):** two new system calls, `IPC_DEFER` and `IPC_REPLY_TO` (docs/ABI.md 47, 48), let a server park a synchronous caller and answer it later. The input driver parks the polls of a task whose tty is behind (a poll for 250 ms, an `INPUT_WAIT` for as long as it asked) and answers them when that tty comes to the front or the time is up; while anything is parked it looks for messages every tick, so a silent tty in front cannot freeze the others. A hidden console now wakes four times a second instead of a hundred, and a hidden desktop does not spin. A pending tty switch also ends the driver's own `INPUT_WAIT` at once (it could take a second before). `make tty-test` checks the held wait; `make qemu-test` still passes. **Still to do:** more than three extra ttys, a check that keys typed on one tty never reach the other's console. **Original plan:** one boot-role console task per tty 1..3, started by the conductor on login (own buffer, display endpoint, input, VFS page; the VFS server's client pages are fixed per sender, so it needs matching pages), registered with `INPUT_ASSIGN` and `GPU_BIND`. **Not done:** a desktop/console per session drawing into its own buffer (today every session's console is the one screen task on tty 0, so Ctrl+Alt+F2 shows a black screen until something draws there; F1 returns), `sessiond` registering its sessions' tasks with `INPUT_ASSIGN`, the greeter on F2..F12, several live sessions at once, logout from the console, a per-tty wait for hidden desktops (they now spin on empty replies).
Not built yet: the real session payload (a desktop and a program manager per session: phase 3), the greeter's login screen and the first-boot setup (recovery keys), per-user encryption
(phase 2), the tty switch, roles beyond the administrator, per-user byte quotas, removing an account.
