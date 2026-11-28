//! Scheduler over trap frames.
//!
//! * Real-time tasks (periodic reservations, earliest deadline first) outrank everything; they
//!   are admitted against a per-core share limit and throttled when they overrun their budget.
//! * Below them, strict class priority (interactive, background, heavy) with priority and
//!   deadline inheritance through IPC, and an aging rule against starvation.
//! * Within a priority, round robin with a time slice per class: a task keeps its core until the
//!   slice is used up or something that outranks it becomes runnable (which interrupts the core at
//!   once). Slices are one-shot timer events, not ticks.
//! * Work-conserving across cores: any idle core may take any runnable task it is eligible for.
//!   A task prefers the core it last ran on (warm caches) and is taken from there only when that
//!   core is busy. Energy-aware: light work stays on efficiency cores and sustained compute on
//!   performance cores unless it has waited too long or does not fit; the choice among eligible
//!   idle cores is the cheapest in added power, from measured utilisation.
//! * Per-core pinning (benchmarks, real-time tasks).
//! * Tickless idle: a core with nothing to run and nothing to watch takes no periodic tick.
//!
//! There is no scheduler lock: run states are atomics and a core claims a task
//! with a compare-and-swap (see "run state" below). (The one lock, the real-time admission table,
//! is taken only when a reservation is made or given back.) Nothing here reads task or
//! endpoint data either: priority inheritance works from atomics that the IPC
//! code keeps up to date.
//!
//! Ownership rule: a task is `running` from the moment a core dispatches it
//! until that same core's *next* dispatch decision, which includes the whole
//! time the core spends in the kernel on the task's behalf. A task that is
//! `running` is never picked by another core, so no two cores ever run (or
//! handle a syscall for) the same task at once.
#![forbid(unsafe_code)]
use crate::ipc;
use crate::smp::{self, MAX_CPUS};
use crate::sync::{SlotTable, Slots, SpinLock, R_RT};
use crate::task::{self, frame, info, State, NOT_PINNED};
use crate::trap::TrapFrame;
use crate::{kprintln, mem, mmu, timer};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use metallium_sched::energy::{self, CoreState, Spill};
use metallium_sched::rt::{Admission, Job, Params};
use metallium_sched::util::Util;
use metallium_sched::{place, quantum_us, Class, Core, CoreKind, Rank};

// ---- run state ------------------------------------------------------------------------------
//
// Lock-free: each task's run state is one atomic word, and "this core owns this task" is one
// atomic flag claimed by compare-and-swap. The rules that make that sufficient:
//  * only the core that owns a task (it is `running`) ever blocks it, and only a waker that has
//    just completed what a task waits for ever makes it runnable, so a state never changes
//    under a decision that matters;
//  * whoever makes a task runnable writes its register frame first and publishes with a
//    release store; a core that picks the task reads the state with acquire and claims it with
//    an acq-rel CAS, so it sees the frame;
//  * a core gives a task back (`running = false`) only after its registers are saved and its
//    state is final.
// There is therefore no scheduler lock, and the hot IPC paths touch no shared lock at all.

fn encode(s: State) -> u64 {
    match s {
        State::Free => 0,
        State::Ready => 1,
        State::RecvWait(e) => 2 | (e as u64) << 8,
        State::CallWait => 3,
        State::Sleep(d) => 4 | d << 8,
        State::IrqWait(i) => 5 | (i as u64) << 8,
        State::RingWait(m) => 6 | (m as u64) << 8,
        State::Dead => 7,
        State::ChildWait(c) => 8 | (c as u64) << 8,
        State::Embryo => 9,
        State::WordWait(d) => 10 | d << 8,
        State::MultiWait(t) => 11 | (t as u64) << 8,
        State::MultiClaimed => 12,
    }
}

fn decode(v: u64) -> State {
    match v & 0xFF {
        0 => State::Free,
        1 => State::Ready,
        2 => State::RecvWait((v >> 8) as u16),
        3 => State::CallWait,
        4 => State::Sleep(v >> 8),
        5 => State::IrqWait((v >> 8) as u8),
        6 => State::RingWait((v >> 8) as u32),
        8 => State::ChildWait((v >> 8) as u16),
        9 => State::Embryo,
        10 => State::WordWait(v >> 8),
        11 => State::MultiWait((v >> 8) as u32),
        12 => State::MultiClaimed,
        _ => State::Dead,
    }
}

/// Pads a value to its own cache lines, so that cores working on different tasks (or being different
/// cores) never write the same line.
#[repr(align(128))]
struct Padded<T>(T);

impl<T> core::ops::Deref for Padded<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Padded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Everything the scheduler keeps per task and writes on the hot path, in one place of its own.
#[repr(align(128))]
struct Slot {
    /// The run state (see `encode`).
    state: AtomicU64,
    /// Owned by some core (running in userspace, or handling a kernel entry for the task).
    running: AtomicBool,
    /// Start of the task's last slice (smaller = has waited longer).
    stamp: AtomicU64,
    /// ... the same, for the anti-starvation rule.
    last_run: AtomicU64,
    /// When the task last became runnable (or was last put back in the queue): how long it has waited.
    ready_at: AtomicU64,
    /// When the task was due to run: its wakeup instant, so timer slack counts as latency.
    due_at: AtomicU64,
    /// When the task's current stretch on a core began.
    run_start: AtomicU64,
    /// When the task's time slice ends (`u64::MAX`: never).
    slice_end: AtomicU64,
    /// The core the task last ran on (its cache is warm there).
    home: AtomicU8,
    /// The kind of core it last ran on (0 efficiency, 1 performance).
    kind_last: AtomicU8,
    /// Utilisation of that core's time it used, when last published, and when.
    util: AtomicU32,
    util_at: AtomicU64,
    /// Counter ticks the task has run on efficiency / performance cores.
    run_cnt: [AtomicU64; 2],
    /// Level (and, for real-time, deadline) the task inherited from the caller it is serving
    /// (transitive: it is the caller's *effective* priority at the time the call was delivered).
    /// `NO_PRIO` / `u64::MAX` when serving nobody.
    inherit: AtomicU8,
    inherit_dl: AtomicU64,
}

impl Slot {
    const NEW: Slot = Slot {
        state: AtomicU64::new(0),
        running: AtomicBool::new(false),
        stamp: AtomicU64::new(0),
        last_run: AtomicU64::new(0),
        ready_at: AtomicU64::new(0),
        due_at: AtomicU64::new(0),
        run_start: AtomicU64::new(0),
        slice_end: AtomicU64::new(u64::MAX),
        home: AtomicU8::new(0),
        kind_last: AtomicU8::new(0),
        util: AtomicU32::new(0),
        util_at: AtomicU64::new(0),
        run_cnt: [AtomicU64::new(0), AtomicU64::new(0)],
        inherit: AtomicU8::new(NO_PRIO),
        inherit_dl: AtomicU64::new(u64::MAX),
    };
}

static SLOT: crate::table::Table<Slot> = crate::table::Table::new();
/// Condemned tasks: their device broke the rules (see smmu.rs). Whichever core next owns the
/// task kills it, so the kill never races with the task running on another core.
static DOOMED: crate::table::Table<AtomicBool> = crate::table::Table::new();
/// Why: see `Doom`.
static DOOM_WHY: crate::table::Table<AtomicU8> = crate::table::Table::new();
#[derive(Clone, Copy)]
pub enum Doom {
    /// The task's device faulted in the IOMMU.
    Iommu = 1,
    /// Killed through an `Admin` capability (or window-mode shutdown of the demo tasks).
    Killed = 2,
    /// Killed by the program that created it (KILL), or because that program ended.
    Parent = 3,
}

fn doom_reason(tid: usize) -> &'static str {
    match DOOM_WHY[tid].load(Ordering::SeqCst) {
        1 => "its device tried to DMA outside the pages it was granted (IOMMU fault)",
        3 => "killed by its parent",
        _ => "killed by an administrator (kill_role)",
    }
}
/// Counter value at which a timed `IRQ_WAIT` expires (0 = no deadline).
static IRQ_DEADLINE: crate::table::Table<AtomicU64> = crate::table::Table::new();
/// Condemn `tid`: it is killed (and restarted, if policy allows) the next time a core would
/// run it. A blocked task is made runnable so that happens promptly.
pub fn doom(tid: usize, why: Doom) {
    DOOM_WHY[tid].store(why as u8, Ordering::SeqCst);
    DOOMED[tid].store(true, Ordering::SeqCst);
    let s = state(tid);
    if matches!(s, State::RecvWait(_) | State::MultiWait(_) | State::CallWait | State::Sleep(_) | State::IrqWait(_) | State::RingWait(_) | State::ChildWait(_) | State::Embryo | State::WordWait(_)) {
        let _ = wake_if(tid, s);
    }
}

/// The deadline of a timed receive (`IPC_RECV`, `IPC_WAIT_ANY`; 0 = none), kept in the same per-task cell as `IRQ_WAIT`'s: a task waits for one
/// thing at a time. Set before the task's state says it is waiting. Untimed waits (almost all of them) do not write the cell if it is clear already.
pub fn set_wait_deadline(tid: usize, deadline: u64) {
    if deadline != 0 || IRQ_DEADLINE[tid].load(Ordering::Relaxed) != 0 {
        set_irq_deadline(tid, deadline);
    }
}

/// `tid` is in `MultiWait(tok)`: take it, so that nobody else can deliver to it or time it out; true for the one caller that gets it. The claimant
/// writes the task's result registers and then makes it `Ready` with `wake_if(tid, State::MultiClaimed)`.
pub fn claim_multi(tid: usize, tok: u32) -> bool {
    let ok = SLOT[tid].state.compare_exchange(encode(State::MultiWait(tok)), encode(State::MultiClaimed), Ordering::SeqCst, Ordering::Relaxed).is_ok();
    if ok {
        publish(tid);
    }
    ok
}

pub fn set_irq_deadline(tid: usize, deadline: u64) {
    IRQ_DEADLINE[tid].store(deadline, Ordering::SeqCst);
    if deadline != 0 {
        NEXT_TIMED.fetch_min(deadline, Ordering::SeqCst);
    }
}

/// Has `tid` been condemned and not yet killed?
pub fn is_doomed(tid: usize) -> bool {
    DOOMED[tid].load(Ordering::SeqCst)
}

pub fn clear_doom(tid: usize) {
    DOOMED[tid].store(false, Ordering::SeqCst);
}

pub fn state(tid: usize) -> State {
    decode(SLOT[tid].state.load(Ordering::Acquire))
}

/// Which tasks are worth looking at, so the scheduler need not look at all of them: bit `i` of the
/// low half is set while task `i` is runnable, bit `32 + i` while it waits for a time to pass (a
/// sleep or a timed wait for an interrupt). A hint, kept in step with the state words: whoever changes
/// a state updates the bits afterwards (`publish`), so for a moment they may lag, and everybody
/// confirms against the state before acting. (A waker's `kick_idle` always comes after its publish, so a
/// core that missed the lagging bit while going to sleep is woken by the interrupt.)
static READY: TaskMask = TaskMask::new();
static TIMED: TaskMask = TaskMask::new();
/// Tasks the machine is not finished with: runnable, sleeping, waiting for an interrupt, or waiting on a ring (`alive`).
static LIVE: TaskMask = TaskMask::new();
/// A time no timed task is due before (`u64::MAX`: none waits for a time): `wake_sleepers` looks at no task until the clock gets there. Lowered by whoever starts
/// a timed wait, recomputed by the scan.
static NEXT_TIMED: AtomicU64 = AtomicU64::new(u64::MAX);

/// One bit per task slot, in as many words as `MAX_TASKS` needs (the scheduler's hints and the real-time set live in these).
const TASK_WORDS: usize = task::MAX_TASKS.div_ceil(64);

/// A snapshot of a `TaskMask`, or a set built locally (the tasks `choose` has already tried).
#[derive(Clone, Copy)]
struct TaskSet([u64; TASK_WORDS]);

impl TaskSet {
    const EMPTY: TaskSet = TaskSet([0; TASK_WORDS]);

    fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }

    /// Everything in `self` that is not in `other`.
    fn without(mut self, other: &TaskSet) -> TaskSet {
        for (w, o) in self.0.iter_mut().zip(other.0.iter()) {
            *w &= !o;
        }
        self
    }

    fn any(&self) -> bool {
        self.0.iter().any(|&w| w != 0)
    }

    /// The tasks in the set, lowest first.
    fn iter(self) -> impl Iterator<Item = usize> {
        (0..TASK_WORDS).flat_map(move |k| each(self.0[k]).map(move |b| k * 64 + b))
    }
}

/// Task bits that cores read and change without a lock.
struct TaskMask([AtomicU64; TASK_WORDS]);

impl TaskMask {
    const fn new() -> Self {
        TaskMask([const { AtomicU64::new(0) }; TASK_WORDS])
    }

    fn load(&self, order: Ordering) -> TaskSet {
        TaskSet(core::array::from_fn(|k| self.0[k].load(order)))
    }

    fn has(&self, i: usize) -> bool {
        self.0[i / 64].load(Ordering::SeqCst) & 1 << (i % 64) != 0
    }

    fn set(&self, i: usize, on: bool) {
        let bit = 1u64 << (i % 64);
        let _ = self.0[i / 64].try_update(Ordering::SeqCst, Ordering::SeqCst, |m| Some(if on { m | bit } else { m & !bit }));
    }
}

/// Bring the task's bits in line with its state. Reads the state itself, and repeats if it changed
/// meanwhile: two cores that change a task's state (a waker, and the task's own core going to sleep)
/// each publish after their own store, and whichever publishes last must describe the state that is
/// current then, not the one its own store wrote.
fn publish(tid: usize) {
    loop {
        let s = state(tid);
        let (ready, timed) = match s {
            State::Ready => (true, false),
            State::Sleep(_) | State::IrqWait(_) => (false, true),
            State::WordWait(d) if d != 0 => (false, true),
            State::RecvWait(_) | State::MultiWait(_) if IRQ_DEADLINE[tid].load(Ordering::SeqCst) != 0 => (false, true),
            _ => (false, false),
        };
        let live = ready || timed || matches!(s, State::RingWait(_));
        // (one word each now: add before removing, so that a task changing from one kind of wait to the other is
        // never in neither mask, which a core deciding how long to sleep could take for "nothing to wake for")
        for add in [true, false] {
            for (mask, want) in [(&READY, ready), (&TIMED, timed), (&LIVE, live)] {
                if want == add && mask.has(tid) != want {
                    mask.set(tid, want);
                }
            }
        }
        // (the time goes in after the task's bit: a scan that has just reset the hint and read the mask either sees the bit, or the hint is lowered after it)
        match s {
            State::Sleep(d) => {
                NEXT_TIMED.fetch_min(d, Ordering::SeqCst);
            }
            State::WordWait(d) if d != 0 => {
                NEXT_TIMED.fetch_min(d, Ordering::SeqCst);
            }
            State::IrqWait(_) | State::RecvWait(_) | State::MultiWait(_) => {
                let d = IRQ_DEADLINE[tid].load(Ordering::SeqCst);
                if d != 0 {
                    NEXT_TIMED.fetch_min(d, Ordering::SeqCst);
                }
            }
            _ => {}
        }
        if state(tid) == s {
            return;
        }
    }
}

/// Tasks that may be runnable.
fn ready_mask() -> TaskSet {
    READY.load(Ordering::SeqCst)
}

/// Tasks that wait for a time to pass.
fn timed_mask() -> TaskSet {
    TIMED.load(Ordering::SeqCst)
}

/// The tasks in a mask, lowest first.
fn each(m: impl Into<u64>) -> impl Iterator<Item = usize> {
    let mut m: u64 = m.into();
    core::iter::from_fn(move || {
        if m == 0 {
            return None;
        }
        let i = m.trailing_zeros() as usize;
        m &= m - 1;
        Some(i)
    })
}

pub fn set_state(tid: usize, s: State) {
    if s == State::Ready {
        unstamp(tid);
    }
    // SeqCst: pairs with the idle protocol (a core checks for work after announcing itself idle)
    SLOT[tid].state.store(encode(s), Ordering::SeqCst);
    publish(tid);
}

/// Make a blocked task runnable. (Whoever calls this has just completed what the task waits for.)
pub fn wake(tid: usize) {
    set_state(tid, State::Ready);
}

/// Make `tid` runnable only if it is in state `expected`. Returns whether it was.
pub fn wake_if(tid: usize, expected: State) -> bool {
    let ok = SLOT[tid].state.compare_exchange(encode(expected), encode(State::Ready), Ordering::SeqCst, Ordering::Relaxed).is_ok();
    if ok {
        unstamp(tid);
        publish(tid);
    }
    ok
}

/// A task became runnable. Reading the clock here would cost on every wakeup (and on an emulator
/// a lot), so the time is filled in by the first scheduler pass that looks at the task (`waited`):
/// microseconds later, and by a core that has the time at hand anyway.
fn unstamp(tid: usize) {
    SLOT[tid].ready_at.store(0, Ordering::Relaxed);
    SLOT[tid].due_at.store(0, Ordering::Relaxed);
    set_flag(&STATS[smp::cpu_id()].dirty, true);
}

/// Did this core make a task runnable (or put one back in the queue, or take a timer tick) since the
/// last call? Only then is it worth looking for another core to run it: a core that has nothing new
/// to place does not scan the queue and the other cores on every system call.
pub fn take_dirty() -> bool {
    let d = &STATS[smp::cpu_id()].dirty;
    if d.load(Ordering::Relaxed) {
        d.store(false, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// A timer tick: the queue is looked at again whether or not anything was woken (a task that waited
/// for another kind of core may have waited long enough).
pub fn tick() {
    set_flag(&STATS[smp::cpu_id()].dirty, true);
}

pub fn count_timer_irq() {
    bump(&mine().timer_irqs);
}

/// Timer interrupts taken by each core so far.
pub fn timer_irqs() -> [u64; MAX_CPUS] {
    core::array::from_fn(|c| STATS[c].timer_irqs.load(Ordering::Relaxed))
}

/// How long the runnable task `tid` has waited (its first look stamps it).
fn waited(tid: usize, now: u64) -> u64 {
    let r = SLOT[tid].ready_at.load(Ordering::Relaxed);
    if r == 0 {
        SLOT[tid].ready_at.store(now, Ordering::Relaxed);
        if SLOT[tid].due_at.load(Ordering::Relaxed) == 0 {
            SLOT[tid].due_at.store(now, Ordering::Relaxed);
        }
        0
    } else {
        now.saturating_sub(r)
    }
}

/// Block `blocker` in `state` and then wake `waker`.
/// The blocker must be set blocked *before* the waker can run: the waker may be the very
/// task that will complete what the blocker waits for.
pub fn block_and_wake(blocker: Option<(usize, State)>, waker: Option<usize>) {
    if let Some((t, st)) = blocker {
        set_state(t, st);
    }
    if let Some(w) = waker {
        set_state(w, State::Ready);
    }
}

/// A completion arrived for `tid`: wake it if it sleeps in RING_ENTER for this many.
pub fn ring_progress(tid: usize, available: u32) {
    if let State::RingWait(min) = state(tid) {
        if available >= min {
            let _ = wake_if(tid, State::RingWait(min));
        }
    }
}

/// Block in RING_ENTER unless `ready()` already holds. Registers first, then looks: a poster
/// publishes its completion and then looks for sleepers, so one of the two always sees the other.
pub fn ring_wait_unless(tid: usize, min: u32, ready: impl FnOnce() -> bool) -> bool {
    set_state(tid, State::RingWait(min));
    if ready() {
        // enough completions already: undo, unless a poster has woken us in the meantime
        let _ = wake_if(tid, State::RingWait(min));
        return false;
    }
    true
}

// ---- which core is running what ------------------------------------------------------------

/// Each task's `TPIDR_EL0` (the thread-pointer register, which EL0 may read and write), kept while the task is not running so that
/// one task's value is never seen by another (SECURITY.md, M4).
static TPIDR: crate::table::Table<AtomicU64> = crate::table::Table::new();
fn tpidr_save(tid: usize) {
    TPIDR[tid].store(crate::frame::cpu::tpidr_el0(), Ordering::Relaxed);
}

fn tpidr_load(tid: usize) {
    crate::frame::cpu::set_tpidr_el0(TPIDR[tid].load(Ordering::Relaxed));
}

static CURRENT: [Padded<AtomicUsize>; MAX_CPUS] = [const { Padded(AtomicUsize::new(usize::MAX)) }; MAX_CPUS];

pub fn current() -> usize {
    CURRENT[smp::cpu_id()].load(Ordering::Relaxed)
}

pub fn set_current(core: usize, tid: usize) {
    CURRENT[core].store(tid, Ordering::Relaxed);
}

// ---- time and measurements ------------------------------------------------------------------
//
// All times below are system-counter ticks (see timer.rs). Every field is written by one core at a
// time: the core that owns the task (see the ownership rule above), or the one dispatching.

static TASK_UTIL: SlotTable<Padded<Util>> = SlotTable::new();

static CORE_TRACK: Slots<Padded<Util>, MAX_CPUS> = Slots::new([const { Padded(Util::new(1)) }; MAX_CPUS]);

/// Derived once the timer is running: everything the policy compares times against.
static WINDOW: AtomicU64 = AtomicU64::new(1);
static STARVATION: AtomicU64 = AtomicU64::new(u64::MAX);
static SPILL_HEAVY: AtomicU64 = AtomicU64::new(u64::MAX);
static SPILL_LIGHT: AtomicU64 = AtomicU64::new(u64::MAX);
/// A task that became runnable this recently is not yet worth interrupting a core for (see `resched_targets`).
static SETTLE: AtomicU64 = AtomicU64::new(0);
/// Slice per priority level (index = level; the real-time level has none).
static QUANTUM: [AtomicU64; 4] = [const { AtomicU64::new(u64::MAX) }; 4];

/// A task that has not run for this long is served first, whatever its priority (strict priority
/// alone lets a busy Interactive task starve every daemon). Real-time tasks are exempt: their
/// share is bounded by admission, so they cannot starve anyone for good.
const STARVATION_US: u64 = 250_000;
/// How long Heavy work waits for a performance core before an efficiency core helps (and the
/// other way round for light work).
const SPILL_HEAVY_US: u64 = 5_000;
const SPILL_LIGHT_US: u64 = 4_000;
/// How long a runnable task waits before an equal competitor's core is told to start its slice timer.
const SETTLE_US: u64 = 200;
/// Window of the utilisation averages.
const UTIL_WINDOW_US: u64 = 8_192;

pub fn init() {
    let c = timer::us_to_counter;
    WINDOW.store(c(UTIL_WINDOW_US), Ordering::Relaxed);
    STARVATION.store(c(STARVATION_US), Ordering::Relaxed);
    SPILL_HEAVY.store(c(SPILL_HEAVY_US), Ordering::Relaxed);
    SPILL_LIGHT.store(c(SPILL_LIGHT_US), Ordering::Relaxed);
    SETTLE.store(c(SETTLE_US), Ordering::Relaxed);
    for (level, class) in [(1, Class::Interactive), (2, Class::Background), (3, Class::Heavy)] {
        QUANTUM[level].store(c(quantum_us(class)), Ordering::Relaxed);
    }
    TASK_UTIL.for_each_mut(|_, u| {
        **u = Util::new(c(UTIL_WINDOW_US));
    });
    for u in CORE_TRACK.all_mut().iter_mut() {
        **u = Util::new(c(UTIL_WINDOW_US));
    }
}

fn spill() -> Spill {
    Spill { heavy: SPILL_HEAVY.load(Ordering::Relaxed), light: SPILL_LIGHT.load(Ordering::Relaxed) }
}

/// An average that nobody has refreshed for a while has decayed: about 30% per window.
fn decayed(util: u32, at: u64, now: u64) -> u32 {
    let windows = now.saturating_sub(at) / WINDOW.load(Ordering::Relaxed).max(1);
    util >> (windows / 2).min(31)
}

fn task_util(tid: usize, now: u64) -> u32 {
    decayed(SLOT[tid].util.load(Ordering::Relaxed), SLOT[tid].util_at.load(Ordering::Relaxed), now)
}

/// The task's recent demand as speed-independent work (see `energy`).
fn task_work(tid: usize, now: u64) -> u32 {
    let kind = if SLOT[tid].kind_last.load(Ordering::Relaxed) == 0 { CoreKind::Little } else { CoreKind::Big };
    energy::to_work(task_util(tid, now), kind)
}

pub fn core_util(core: usize, now: u64) -> u32 {
    decayed(STATS[core].util.load(Ordering::Relaxed), STATS[core].util_at.load(Ordering::Relaxed), now)
}

fn core_states(now: u64) -> [CoreState; MAX_CPUS] {
    core::array::from_fn(|c| CoreState {
        kind: core_kind(c),
        util: core_util(c, now),
        active: CURRENT[c].load(Ordering::Relaxed) != usize::MAX,
    })
}

// ---- statistics -----------------------------------------------------------------------------

/// Per-core counters, one cache line group each, written only by their own core (a shared counter
/// would bounce between the cores on every context switch).
#[repr(align(128))]
pub struct CoreStats {
    pub switches: AtomicU64,
    /// Switches because a time slice ran out with an equal competitor waiting.
    pub slice_preempts: AtomicU64,
    /// Switches because something that outranks the running task became runnable.
    pub prio_preempts: AtomicU64,
    /// Interrupts sent by this core to busy cores (preemption, or to start a slice timer).
    pub preempt_ipis: AtomicU64,
    /// A task started here that last ran on a different core.
    pub migrations: AtomicU64,
    /// ... and the core it left was busy: it was taken from a busy queue.
    pub steals: AtomicU64,
    /// Heavy tasks run on efficiency cores (or light ones on performance cores) after waiting.
    pub spills: AtomicU64,
    /// Candidate searches (`best_candidate`), and the ready tasks they looked at in all.
    pub picks: AtomicU64,
    pub scanned: AtomicU64,
    /// Timer interrupts this core has taken (ticks, slice ends, real-time events).
    timer_irqs: AtomicU64,
    /// Wake-to-run latency per level: maximum, sum, count (counter ticks).
    lat_max: [AtomicU64; 4],
    lat_sum: [AtomicU64; 4],
    lat_n: [AtomicU64; 4],
    /// Counter ticks this core has spent running tasks, and its utilisation as last published (and when).
    busy: AtomicU64,
    util: AtomicU32,
    util_at: AtomicU64,
    /// The last time read on this core and how many context switches ago (see `sample_clock`).
    clock: AtomicU64,
    clock_age: AtomicU32,
    /// This core made something runnable since it last looked for a core to run it (see `take_dirty`).
    dirty: AtomicBool,
    /// An interrupt for this core's preemption is on its way.
    preempt_pending: AtomicBool,
    /// This core's timer is set for the end of the running task's slice. Programming a timer costs,
    /// so that is done only while someone is waiting for the core; the first waiter to arrive on a
    /// core without one interrupts it to start the timer (see `resched_targets`).
    slice_timer: AtomicBool,
}

impl CoreStats {
    const NEW: CoreStats = CoreStats {
        switches: AtomicU64::new(0),
        slice_preempts: AtomicU64::new(0),
        prio_preempts: AtomicU64::new(0),
        preempt_ipis: AtomicU64::new(0),
        migrations: AtomicU64::new(0),
        steals: AtomicU64::new(0),
        spills: AtomicU64::new(0),
        picks: AtomicU64::new(0),
        scanned: AtomicU64::new(0),
        timer_irqs: AtomicU64::new(0),
        lat_max: [const { AtomicU64::new(0) }; 4],
        lat_sum: [const { AtomicU64::new(0) }; 4],
        lat_n: [const { AtomicU64::new(0) }; 4],
        busy: AtomicU64::new(0),
        util: AtomicU32::new(0),
        util_at: AtomicU64::new(0),
        clock: AtomicU64::new(0),
        clock_age: AtomicU32::new(0),
        dirty: AtomicBool::new(false),
        preempt_pending: AtomicBool::new(false),
        slice_timer: AtomicBool::new(false),
    };
}

static STATS: [CoreStats; MAX_CPUS] = [CoreStats::NEW; MAX_CPUS];

/// Only the owning core writes a counter, so a plain load + store is enough (no read-modify-write).
fn bump(c: &AtomicU64) {
    c.store(c.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

fn mine() -> &'static CoreStats {
    &STATS[smp::cpu_id()]
}

#[derive(Default)]
pub struct Totals {
    pub switches: u64,
    pub slice_preempts: u64,
    pub prio_preempts: u64,
    pub preempt_ipis: u64,
    pub migrations: u64,
    pub steals: u64,
    pub spills: u64,
    pub picks: u64,
    pub scanned: u64,
}

pub fn totals() -> Totals {
    let sum = |f: fn(&CoreStats) -> &AtomicU64| STATS.iter().map(|s| f(s).load(Ordering::Relaxed)).sum::<u64>();
    Totals {
        switches: sum(|s| &s.switches),
        slice_preempts: sum(|s| &s.slice_preempts),
        prio_preempts: sum(|s| &s.prio_preempts),
        preempt_ipis: sum(|s| &s.preempt_ipis),
        migrations: sum(|s| &s.migrations),
        steals: sum(|s| &s.steals),
        spills: sum(|s| &s.spills),
        picks: sum(|s| &s.picks),
        scanned: sum(|s| &s.scanned),
    }
}

/// Wake-to-run latency at a priority level over all cores: (maximum, sum, count), counter ticks.
pub fn latency(level: usize) -> (u64, u64, u64) {
    let max = STATS.iter().map(|s| s.lat_max[level].load(Ordering::Relaxed)).max().unwrap_or(0);
    let sum = STATS.iter().map(|s| s.lat_sum[level].load(Ordering::Relaxed)).sum();
    let n = STATS.iter().map(|s| s.lat_n[level].load(Ordering::Relaxed)).sum();
    (max, sum, n)
}

pub fn reset_latency() {
    for s in STATS.iter() {
        for l in 0..4 {
            s.lat_max[l].store(0, Ordering::Relaxed);
            s.lat_sum[l].store(0, Ordering::Relaxed);
            s.lat_n[l].store(0, Ordering::Relaxed);
        }
    }
}

/// (counter ticks run on efficiency cores, on performance cores, utilisation, priority level, home core)
pub fn task_stats(tid: usize) -> (u64, u64, u32, u8, usize) {
    let now = timer::counter();
    (
        SLOT[tid].run_cnt[0].load(Ordering::Relaxed),
        SLOT[tid].run_cnt[1].load(Ordering::Relaxed),
        task_util(tid, now),
        eff_prio(tid),
        SLOT[tid].home.load(Ordering::Relaxed) as usize,
    )
}

pub fn core_stats(core: usize) -> (u32, u64) {
    (core_util(core, timer::counter()), STATS[core].busy.load(Ordering::Relaxed))
}

// ---- placement ------------------------------------------------------------------------------

/// The placement table: each core's kind (`core_kind`: a mock DynamIQ-style topology, QEMU gives us identical cores) and the weight of the tasks placed on it.
///
/// The loads change when tasks are created on one core and die on another, so the table is behind a lock (it was a
/// lock-free global that two cores could write at once).
static CORES: SpinLock<[Core; MAX_CPUS]> = SpinLock::new([const { Core { kind: CoreKind::Big, load: 0, throttled: false } }; MAX_CPUS]);

/// The cores a task may be placed on: all the machine has (4 if its device tree did not say).
fn placeable() -> usize {
    crate::platform::cpu_count().unwrap_or(4).min(MAX_CPUS)
}

/// Give the placement table its kinds; once at boot.
pub fn init_placement() {
    work_out_kinds();
    let mut cores = CORES.lock(R_RT);
    for (c, core) in cores.iter_mut().enumerate() {
        core.kind = core_kind(c);
    }
}

pub fn assign_core(class: Class) -> usize {
    let mut cores = CORES.lock(R_RT);
    let c = place(&cores[..placeable()], class).unwrap_or(0);
    cores[c].load += match class {
        Class::Background => 10,
        Class::Interactive => 25,
        Class::Heavy => 60,
    };
    c
}

/// A task placed by `assign_core` is gone: its weight no longer counts against the core.
pub fn release_core(core: usize, class: Class) {
    let mut cores = CORES.lock(R_RT);
    let w = match class {
        Class::Background => 10,
        Class::Interactive => 25,
        Class::Heavy => 60,
    };
    cores[core].load = cores[core].load.saturating_sub(w);
}

/// The core the task last ran on (or was placed on).
pub fn home_core(tid: usize) -> usize {
    SLOT[tid].home.load(Ordering::Relaxed) as usize
}

/// Which cores are efficiency cores (bit per core), worked out once at boot (`init_placement`): `core_kind` is asked for every candidate of every search.
static LITTLE: AtomicU32 = AtomicU32::new(0b11);

pub fn core_kind(core: usize) -> CoreKind {
    if LITTLE.load(Ordering::Relaxed) >> core & 1 != 0 { CoreKind::Little } else { CoreKind::Big }
}

/// The device tree's core speeds (`capacity-dmips-mhz`) say which are the efficiency cores when the machine has two kinds; otherwise the model is
/// fixed: cores 0 and 1 are the little ones, all the others the big ones (QEMU's cores are alike).
fn work_out_kinds() {
    let mask = (0..MAX_CPUS).fold(0u32, |m, c| {
        let little = crate::platform::core_is_little(c).unwrap_or(c < 2);
        m | (little as u32) << c
    });
    LITTLE.store(mask, Ordering::Relaxed);
}

fn big_online() -> bool {
    (0..MAX_CPUS).any(|c| smp::online_mask() & (1 << c) != 0 && core_kind(c) == CoreKind::Big)
}

/// A new task (or a new instance of one): where it starts, with no history.
pub fn init_task(tid: usize, core: usize) {
    SLOT[tid].home.store(core as u8, Ordering::Relaxed);
    forget_task(tid);
}

/// The task is gone (or restarted): drop what the scheduler learned about it.
pub fn forget_task(tid: usize) {
    rt_clear(tid);
    SLOT[tid].util.store(0, Ordering::Relaxed);
    **TASK_UTIL.write(tid) = Util::new(WINDOW.load(Ordering::Relaxed));
    SLOT[tid].slice_end.store(u64::MAX, Ordering::Relaxed);
    SLOT[tid].run_start.store(0, Ordering::Relaxed);
    crate::fpu::reset(tid); // (and starts with floating point off)
    TPIDR[tid].store(0, Ordering::Relaxed); // (a new task, or a restarted one, starts with a clear thread pointer)
}

// ---- priorities and inheritance ------------------------------------------------------------
//
// Levels: 0 real-time (ordered by deadline), then 1 interactive, 2 background, 3 heavy.

fn class_level(c: Class) -> u8 {
    match c {
        Class::Interactive => 1,
        Class::Background => 2,
        Class::Heavy => 3,
    }
}

pub const NO_PRIO: u8 = 4;
const NO_EP: u16 = u16::MAX;

/// The (at most two) endpoints a task receives on; their queued senders' priority counts too.
static RECV_EPS: crate::table::Table<[AtomicU16; 2]> = crate::table::Table::new();
pub fn note_recv_endpoint(tid: usize, e: u16) {
    for slot in &RECV_EPS[tid] {
        if slot.load(Ordering::Relaxed) == e {
            return;
        }
    }
    for slot in &RECV_EPS[tid] {
        if slot.compare_exchange(NO_EP, e, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            return;
        }
    }
}

pub fn forget_recv_endpoints(tid: usize) {
    for slot in &RECV_EPS[tid] {
        slot.store(NO_EP, Ordering::Relaxed);
    }
}

pub fn clear_inherit(tid: usize) {
    SLOT[tid].inherit.store(NO_PRIO, Ordering::Relaxed);
    SLOT[tid].inherit_dl.store(u64::MAX, Ordering::Relaxed);
}

fn own_level(tid: usize) -> u8 {
    if is_rt(tid) {
        0
    } else {
        class_level(task::class_of(tid))
    }
}

/// What a task passes on to whoever serves its request: its own level or what it inherited.
pub fn priority_to_pass_on(tid: usize) -> u8 {
    own_level(tid).min(SLOT[tid].inherit.load(Ordering::Relaxed))
}

/// ... and its deadline, if that level is real-time.
pub fn deadline_to_pass_on(tid: usize) -> u64 {
    RT_DEADLINE[tid].load(Ordering::Relaxed).min(SLOT[tid].inherit_dl.load(Ordering::Relaxed))
}

pub fn inherit_from(server: usize, caller: usize) {
    if !cfg!(feature = "no-inherit") {
        SLOT[server].inherit.store(priority_to_pass_on(caller), Ordering::Relaxed);
        SLOT[server].inherit_dl.store(deadline_to_pass_on(caller), Ordering::Relaxed);
    }
}

fn eff_prio(tid: usize) -> u8 {
    let mut p = own_level(tid);
    if p == 0 || cfg!(feature = "no-inherit") {
        return p;
    }
    p = p.min(SLOT[tid].inherit.load(Ordering::Relaxed));
    for slot in &RECV_EPS[tid] {
        let e = slot.load(Ordering::Relaxed);
        if e != NO_EP {
            p = p.min(ipc::best_queued(e));
        }
    }
    p
}

/// Deadline that orders tasks at the real-time level: its own, or that of the real-time work it serves.
fn eff_deadline(tid: usize) -> u64 {
    let mut d = deadline_to_pass_on(tid);
    for slot in &RECV_EPS[tid] {
        let e = slot.load(Ordering::Relaxed);
        if e != NO_EP {
            d = d.min(ipc::best_queued_deadline(e));
        }
    }
    d
}

/// Does `a` have to run before `b`?  (Strictly: a higher level, or at the real-time level an
/// earlier deadline.)
fn outranks(a: usize, b: usize) -> bool {
    rank(a).outranks(rank(b))
}

fn rank(tid: usize) -> Rank {
    Rank { level: eff_prio(tid), deadline: eff_deadline(tid) }
}

// ---- real-time reservations ------------------------------------------------------------------

const NO_CORE: u8 = u8::MAX;
/// Core a real-time task is admitted on and confined to (`NO_CORE`: not real-time).
static RT_CORE: crate::table::Table<AtomicU8> = crate::table::Table::new();
/// Deadline of its current job, readable from any core.
static RT_DEADLINE: crate::table::Table<AtomicU64> = crate::table::Table::new();
/// The reserved share it was admitted with.
static RT_SHARE: crate::table::Table<AtomicU64> = crate::table::Table::new();
/// The job state. Only the task's own core touches it after admission (the core the task is confined to).
static RT_JOB: SlotTable<Option<Job>> = SlotTable::new();
/// Tasks that hold a reservation.
static RT_TASKS: TaskMask = TaskMask::new();
static ADMISSION: SpinLock<Admission<MAX_CPUS>> = SpinLock::new(Admission::new());

fn is_rt(tid: usize) -> bool {
    RT_CORE[tid].load(Ordering::Relaxed) != NO_CORE
}

fn rt_publish(tid: usize, job: &Job) {
    RT_DEADLINE[tid].store(job.deadline(), Ordering::Relaxed);
}

pub enum RtError {
    Invalid,
    NoCapacity,
}

/// Give `tid` a reservation of `runtime_us` every `period_us` on `hint` (or on the cheapest core
/// that has room) and confine it to that core. Returns the core.
pub fn rt_set(tid: usize, runtime_us: u64, period_us: u64, hint: Option<usize>) -> Result<usize, RtError> {
    rt_clear(tid);
    let params = Params { runtime: timer::us_to_counter(runtime_us), period: timer::us_to_counter(period_us) };
    if !params.valid() || runtime_us == 0 || period_us > 10_000_000 {
        return Err(RtError::Invalid);
    }
    let online = smp::online_mask();
    // efficiency cores first, then performance cores
    let mut order = [0usize; MAX_CPUS];
    let mut n = 0;
    match hint {
        Some(c) if c < MAX_CPUS && online & (1 << c) != 0 => {
            order[0] = c;
            n = 1;
        }
        Some(_) => return Err(RtError::Invalid),
        None => {
            for kind in [CoreKind::Little, CoreKind::Big] {
                for c in (0..MAX_CPUS).filter(|&c| online & (1 << c) != 0 && core_kind(c) == kind) {
                    order[n] = c;
                    n += 1;
                }
            }
        }
    }
    let (core, share) = ADMISSION.lock(R_RT).admit(&order[..n], params).map_err(|_| RtError::NoCapacity)?;
    let job = Job::start(params, timer::counter());
    *RT_JOB.write(tid) = Some(job);
    rt_publish(tid, &job);
    RT_SHARE[tid].store(share, Ordering::Relaxed);
    SLOT[tid].slice_end.store(u64::MAX, Ordering::Relaxed); // no slice: its budget limits it
    SLOT[tid].home.store(core as u8, Ordering::Relaxed);
    RT_CORE[tid].store(core as u8, Ordering::SeqCst); // last: from here on only `core` touches the job
    RT_TASKS.set(tid, true);
    Ok(core)
}

/// Give the reservation back; the task is an ordinary one again.
pub fn rt_clear(tid: usize) {
    let core = RT_CORE[tid].swap(NO_CORE, Ordering::SeqCst);
    if core != NO_CORE {
        RT_TASKS.set(tid, false);
        ADMISSION.lock(R_RT).release(core as usize, RT_SHARE[tid].swap(0, Ordering::Relaxed));
        *RT_JOB.write(tid) = None;
        RT_DEADLINE[tid].store(u64::MAX, Ordering::Relaxed);
        SLOT[tid].slice_end.store(0, Ordering::Relaxed); // an ordinary task again: its next dispatch starts a slice
    }
}

/// The running real-time task says its job is done. Returns the start of its next period and
/// whether it has to wait for it.
pub fn rt_wait(tid: usize) -> Option<(u64, bool)> {
    let mut slot = RT_JOB.write(tid);
    let job = slot.as_mut()?;
    let now = timer::counter();
    let wake_at = job.finish(now);
    rt_publish(tid, job);
    if wake_at > now {
        set_state(tid, State::Sleep(wake_at));
        Some((wake_at, true))
    } else {
        Some((job.release, false))
    }
}

/// (jobs, missed deadlines, budget left, runtime, period) in counter ticks.
pub fn rt_stats(tid: usize) -> Option<(u32, u32, u64, u64, u64)> {
    let slot = RT_JOB.read(tid);
    let j = slot.as_ref()?;
    Some((j.jobs, j.missed, j.budget, j.params.runtime, j.params.period))
}

/// Put a runnable real-time task to sleep until `until` (it resumes exactly where it was).
fn park(tid: usize, until: u64) {
    if SLOT[tid].state.compare_exchange(encode(State::Ready), encode(State::Sleep(until)), Ordering::SeqCst, Ordering::Relaxed).is_ok() {
        publish(tid);
    }
}

/// Called on the task's core before it is considered: starts a new period when one has begun, and
/// parks a task that has used up its budget until the period ends (it sleeps; nothing else about
/// it changes, it resumes exactly where it was).
fn rt_gate(tid: usize, now: u64) -> bool {
    let mut slot = RT_JOB.write(tid);
    let Some(job) = slot.as_mut() else { return true };
    job.advance(now);
    rt_publish(tid, job);
    if job.throttled(now) {
        let until = job.deadline();
        park(tid, until);
        return false;
    }
    true
}

/// The next instant anything real-time happens on `core`: a real-time task due to wake, and the end
/// of `running`'s budget if it is real-time.
fn rt_event(core: usize, running: usize, now: u64) -> u64 {
    let mut ev = u64::MAX;
    for i in RT_TASKS.load(Ordering::Relaxed).iter() {
        if RT_CORE[i].load(Ordering::Relaxed) as usize != core {
            continue;
        }
        if let State::Sleep(d) = state(i) {
            ev = ev.min(d);
        }
        if i == running {
            if let Some(j) = &*RT_JOB.read(i) {
                ev = ev.min(now + j.budget);
            }
        }
    }
    ev
}

// ---- picking --------------------------------------------------------------------------------

fn pin_of(tid: usize) -> u8 {
    let r = RT_CORE[tid].load(Ordering::Relaxed);
    if r != NO_CORE {
        r
    } else {
        task::pinned_of(tid)
    }
}

fn pin_ok(tid: usize, core: usize) -> bool {
    let p = pin_of(tid);
    p == NOT_PINNED || p as usize == core
}

/// May `tid` run on `core`, after waiting `waited`? (Class rules: see `energy::may_run`.)
fn class_ok(tid: usize, core: usize, now: u64, waited: u64) -> bool {
    energy::may_run(task::class_of(tid), task_work(tid, now), core_kind(core), waited, big_online(), spill())
}

fn eligible(tid: usize, core: usize, now: u64) -> bool {
    pin_ok(tid, core) && (pin_of(tid) != NOT_PINNED || class_ok(tid, core, now, waited(tid, now)))
}

/// Is `tid` fair game for `core`? Its home core gets first call on it: another core takes it only
/// if the home core is busy (or cannot run it); an idle home core will be woken for it.
fn stealable(tid: usize, core: usize, now: u64) -> bool {
    let h = SLOT[tid].home.load(Ordering::Relaxed) as usize;
    h == core || smp::online_mask() & (1 << h) == 0 || CURRENT[h].load(Ordering::Relaxed) != usize::MAX || !eligible(tid, h, now)
}

/// Runnable on `core` now? A task another core is running is not, except for the one this
/// core itself is currently running (`cur`), which may be chosen again.
fn can_run(i: usize, core: usize, cur: usize, now: u64) -> bool {
    state(i) == State::Ready
        && (i == cur || !SLOT[i].running.load(Ordering::Acquire))
        && eligible(i, core, now)
        && stealable(i, core, now)
        && rt_gate(i, now)
}

fn starved(i: usize, now: u64) -> bool {
    now.saturating_sub(SLOT[i].last_run.load(Ordering::Relaxed)) >= STARVATION.load(Ordering::Relaxed)
}

fn wake_sleepers(now: u64) {
    if now < NEXT_TIMED.load(Ordering::SeqCst) {
        return; // nobody is due yet: no need to look at the sleepers at all
    }
    // (starting over: a wait begun while this scan runs lowers the time itself; the ones the scan sees and leaves lower it to theirs)
    NEXT_TIMED.store(u64::MAX, Ordering::SeqCst);
    let mut next = u64::MAX;
    for i in timed_mask().iter() {
        match state(i) {
            State::Sleep(deadline) => {
                if deadline <= now {
                    if wake_if(i, State::Sleep(deadline)) {
                        SLOT[i].due_at.store(deadline, Ordering::Relaxed); // it was due then, not when we noticed
                    }
                } else {
                    next = next.min(deadline);
                }
            }
            State::IrqWait(idx) => {
                let d = IRQ_DEADLINE[i].load(Ordering::SeqCst);
                if d != 0 && d <= now {
                    crate::irq::expire(i, idx);
                } else if d != 0 {
                    next = next.min(d);
                }
            }
            State::WordWait(d) if d != 0 => {
                if d <= now {
                    crate::thread::expire(i, d);
                } else {
                    next = next.min(d);
                }
            }
            State::RecvWait(e) => {
                let d = IRQ_DEADLINE[i].load(Ordering::SeqCst);
                if d != 0 && d <= now {
                    crate::ipc::expire(i, e);
                } else if d != 0 {
                    next = next.min(d);
                }
            }
            State::MultiWait(tok) => {
                let d = IRQ_DEADLINE[i].load(Ordering::SeqCst);
                if d != 0 && d <= now {
                    crate::ipc::expire_multi(i, tok);
                } else if d != 0 {
                    next = next.min(d);
                }
            }
            _ => {}
        }
    }
    NEXT_TIMED.fetch_min(next, Ordering::SeqCst);
}

/// Best candidate (not in `skip`) for `core`: real-time work first (earliest deadline), then tasks
/// that starve (longest waiting), then the highest effective priority, then the task that has waited
/// longest, with the home core breaking ties. Reads are racy by design; the choice is confirmed by
/// claiming the task.
fn best_candidate(core: usize, cur: usize, now: u64, skip: &TaskSet) -> Option<usize> {
    let mut rt: Option<(u64, u64, usize)> = None;
    let mut starving: Option<(u64, usize)> = None;
    let mut by_level: [Option<(u64, bool, usize)>; 4] = [None; 4];
    let looked = &mine().scanned;
    bump(&mine().picks);
    for i in ready_mask().without(skip).iter() {
        looked.fetch_add(1, Ordering::Relaxed);
        if !can_run(i, core, cur, now) {
            continue;
        }
        let level = eff_prio(i);
        let stamp = SLOT[i].stamp.load(Ordering::Relaxed);
        if level == 0 {
            let key = (eff_deadline(i), stamp, i);
            if rt.map_or(true, |b| key < b) {
                rt = Some(key);
            }
            continue;
        }
        if starved(i, now) {
            let key = (SLOT[i].last_run.load(Ordering::Relaxed), i);
            if starving.map_or(true, |b| key < b) {
                starving = Some(key);
            }
        }
        let key = (stamp, SLOT[i].home.load(Ordering::Relaxed) as usize != core, i);
        let slot = &mut by_level[(level as usize).min(3)];
        if slot.map_or(true, |b| key < b) {
            *slot = Some(key);
        }
    }
    if let Some(r) = rt {
        return Some(r.2);
    }
    if let Some(s) = starving {
        return Some(s.1);
    }
    by_level.iter().flatten().next().map(|k| k.2)
}

fn alive() -> bool {
    // (the mask is a hint that may lag a state change, but never leaves a task in none of its masks while it changes between kinds of wait)
    LIVE.load(Ordering::SeqCst).any() || crate::ring::async_ops_outstanding()
}

/// May `core` take (or be interrupted for) the ready task `i`?
fn can_take(i: usize, core: usize, now: u64) -> bool {
    eligible(i, core, now) && stealable(i, core, now)
}

/// Of the idle cores in `able`, the one where running `i` costs the least power (its home core if
/// that is as good a kind of core: the caches are warm there).
fn pick_core(i: usize, able: u32, now: u64) -> u32 {
    if able.count_ones() == 1 {
        return able;
    }
    let cores = core_states(now);
    let best = energy::place(&cores, task_work(i, now), |c| able & (1 << c) != 0);
    let home = SLOT[i].home.load(Ordering::Relaxed) as usize;
    match best {
        Some(b) if able & (1 << home) != 0 && cores[home].kind == cores[b].kind => 1 << home,
        Some(b) => 1 << b,
        None => able & able.wrapping_neg(),
    }
}

/// Context switches that may share one reading of the clock (see `sample_clock`).
const CLOCK_SHARE: u32 = 8;

/// The time for a scheduling decision. Reading the system counter is cheap on real hardware but not
/// on an emulator (there every read takes the machine-wide lock, and four busy cores queue up on
/// it), and a switch caused by a task blocking in a system call, which can follow the last one by
/// microseconds, hardly needs a fresh reading. So those reuse the previous one, up to `CLOCK_SHARE`
/// switches in a row. A timer interrupt always reads the clock (so at most a jiffy goes by), and so
/// does any core that has a real-time task, whose budget must be exact. The price: a stale
/// reading makes a slice start slightly early, and run time slightly short.
fn sample_clock(core: usize, interrupt: bool) -> u64 {
    let st = &STATS[core];
    let age = st.clock_age.load(Ordering::Relaxed);
    if interrupt || age >= CLOCK_SHARE || RT_TASKS.load(Ordering::Relaxed).any() {
        let now = timer::counter();
        st.clock.store(now, Ordering::Relaxed);
        st.clock_age.store(0, Ordering::Relaxed);
        now
    } else {
        st.clock_age.store(age + 1, Ordering::Relaxed);
        st.clock.load(Ordering::Relaxed)
    }
}

/// Store only when the value changes: a line that other cores read must not be dirtied for nothing.
fn set_flag(f: &AtomicBool, v: bool) {
    if f.load(Ordering::Relaxed) != v {
        f.store(v, Ordering::Relaxed);
    }
}

/// Cores with a preemption interrupt on its way, and cores whose timer is set for a slice end.
fn flagged(f: fn(&CoreStats) -> &AtomicBool) -> u32 {
    (0..MAX_CPUS).fold(0, |m, c| m | (f(&STATS[c]).load(Ordering::Relaxed) as u32) << c)
}

/// Is someone waiting who could take `core` from `running` when its slice ends?
fn contended(core: usize, running: usize, now: u64) -> bool {
    let level = eff_prio(running);
    ready_mask().iter().any(|i| {
        i != running && state(i) == State::Ready && !SLOT[i].running.load(Ordering::Acquire) && eff_prio(i) <= level && can_take(i, core, now)
    })
}

/// After kernel work that may have made tasks runnable: which sleeping cores to wake (`idle` is
/// the mask of sleepers), and which busy cores to interrupt because a task that outranks what they
/// run is waiting. At most one core per runnable, not-yet-running task: the task's best idle core,
/// else the busy core running the least important work it outranks. (Waking every capable core would
/// send each wakeup to all of them; all but one would find nothing and go back to sleep: an
/// interrupt storm that starves real work.)
pub fn resched_targets(idle: u32) -> (u32, u32) {
    let me = smp::cpu_id();
    let mut now = 0;
    let online = smp::online_mask();
    let (mut wake, mut preempt) = (0u32, 0u32);
    let mut flags: Option<(u32, u32)> = None; // (preemption interrupts on their way, slice timers set)
    for i in ready_mask().iter() {
        if state(i) != State::Ready || SLOT[i].running.load(Ordering::Acquire) {
            continue;
        }
        let pinned = pin_of(i);
        if pinned as usize == me {
            continue; // waits for this very core, which dispatches it as soon as the running task gives way
        }
        // the cores that could run it
        let cores = if pinned == NOT_PINNED { online } else { online & (1 << pinned) };
        if cores == 0 {
            continue;
        }
        if pinned == NOT_PINNED && now == 0 {
            now = sample_clock(me, false); // the class rules depend on how long it has waited
        }
        let mut able = 0u32;
        for core in each(cores & idle & !wake) {
            if can_take(i, core, now) {
                able |= 1 << core;
            }
        }
        if able != 0 {
            wake |= pick_core(i, able, now);
            continue;
        }
        let (pending, timers) = *flags.get_or_insert_with(|| (flagged(|s| &s.preempt_pending), flagged(|s| &s.slice_timer)));
        // No idle core can take it: interrupt the core running the least important thing it outranks.
        let mut worst: Option<(u8, u64, usize)> = None;
        for core in each(cores & !idle & !(preempt | pending)) {
            let c = CURRENT[core].load(Ordering::Relaxed);
            if c == usize::MAX || c == i || !outranks(i, c) || !can_take(i, core, now) {
                continue;
            }
            let key = (eff_prio(c), eff_deadline(c), core);
            if worst.map_or(true, |w| key > w) {
                worst = Some(key);
            }
        }
        if let Some((_, _, core)) = worst {
            preempt |= 1 << core;
            continue;
        }
        // Nobody to preempt, but an equal competitor must get its turn at the end of the running
        // task's slice: make sure that core has a timer set for it. (Not for a task that has only
        // just become runnable: the core it was made runnable on is usually about to dispatch it. And
        // not for one pinned to a busy core: that core arms its own slice timer at its next decision.)
        if pinned != NOT_PINNED || waited(i, now) < SETTLE.load(Ordering::Relaxed) {
            continue;
        }
        for core in each(cores & !idle & !(preempt | pending | timers)) {
            let c = CURRENT[core].load(Ordering::Relaxed);
            if c != usize::MAX && c != i && eff_prio(c) != 0 && eff_prio(i) == eff_prio(c) && can_take(i, core, now) {
                if core == me {
                    // our own core: just set its timer
                    timer::arm(core, SLOT[c].slice_end.load(Ordering::Relaxed));
                    set_flag(&STATS[core].slice_timer, true);
                } else {
                    preempt |= 1 << core;
                }
                break;
            }
        }
    }
    // Heavy work that spilled onto an efficiency core (its own kind was busy for a while) goes back
    // when a performance core is idle: nothing else would move it, as it is not contended and so its
    // slice never ends. Interrupt that core with the slice given up; its dispatch then lets go of the
    // task (the class rules forbid it there), and the idle performance core is woken for it.
    if big_online() {
        let mut free_big = each(online & idle & !wake).filter(|&c| core_kind(c) == CoreKind::Big).count();
        for core in each(online & !idle & !(preempt | flagged(|s| &s.preempt_pending))) {
            if free_big == 0 {
                break;
            }
            let c = CURRENT[core].load(Ordering::Relaxed);
            if core_kind(core) != CoreKind::Little || c == usize::MAX || task::class_of(c) != Class::Heavy || pin_of(c) != NOT_PINNED || is_rt(c) {
                continue;
            }
            if now == 0 {
                now = sample_clock(me, false);
            }
            if waited(c, now) < SPILL_HEAVY.load(Ordering::Relaxed) {
                continue; // (it has only just started here)
            }
            expire_slice(c);
            preempt |= 1 << core;
            free_big -= 1;
        }
    }
    if preempt != 0 {
        for c in each(preempt) {
            STATS[c].preempt_pending.store(true, Ordering::SeqCst);
        }
        mine().preempt_ipis.store(mine().preempt_ipis.load(Ordering::Relaxed) + preempt.count_ones() as u64, Ordering::Relaxed);
    }
    (wake, preempt)
}

/// The earliest instant a task waits for (a sleep, or a timed wait for an interrupt), if the system can do
/// without a tick until then. `None` when it cannot: asynchronous calls with timeouts are outstanding
/// (core 0's tick expires them), or a runnable task waits for a core and the class rules that
/// decide which one (they depend on how long it has waited) must be looked at again and again.
fn quiet_until(online: u32) -> Option<u64> {
    if crate::ring::async_ops_outstanding() {
        return None;
    }
    let ready_waiting = ready_mask().iter().any(|i| {
        state(i) == State::Ready && !SLOT[i].running.load(Ordering::Acquire) && {
            let p = pin_of(i);
            p == NOT_PINNED || online & (1 << p) != 0 // (a task pinned to a core that does not exist waits forever, ticks or not)
        }
    });
    if ready_waiting {
        return None;
    }
    let mut at = u64::MAX;
    for i in timed_mask().iter() {
        match state(i) {
            State::Sleep(d) => at = at.min(d),
            State::WordWait(d) if d != 0 => at = at.min(d),
            State::IrqWait(_) | State::RecvWait(_) | State::MultiWait(_) => {
                let d = IRQ_DEADLINE[i].load(Ordering::SeqCst);
                if d != 0 {
                    at = at.min(d);
                }
            }
            _ => {}
        }
    }
    Some(at)
}

/// The sleeping core that is watching the clock for the earliest time any task waits for, and the
/// time it set (see `idle_timer`).
static WATCHER: AtomicUsize = AtomicUsize::new(usize::MAX);
static WATCH_AT: AtomicU64 = AtomicU64::new(0);

/// Program an idle core's timer. With nothing to wait for it sleeps until it is woken; otherwise
/// until this core's next real-time event, and, unless another sleeping core is already watching for
/// the earliest time any task waits for (a time at least as early), until that time too. (The other
/// sleepers need not all wake for it. If the watcher gets busy it ticks and finds the deadline then,
/// and the next core to go to sleep takes over.)
fn idle_timer(core: usize, now: u64) {
    let rt = rt_event(core, usize::MAX, now);
    match quiet_until(smp::online_mask()) {
        None => timer::arm(core, if rt == u64::MAX { 0 } else { rt }),
        Some(deadline) => {
            let w = WATCHER.load(Ordering::SeqCst);
            let covered = w != usize::MAX && w != core && smp::is_idle(w) && WATCH_AT.load(Ordering::SeqCst) <= deadline;
            let at = if covered || deadline == u64::MAX {
                rt
            } else {
                WATCH_AT.store(deadline, Ordering::SeqCst);
                WATCHER.store(core, Ordering::SeqCst);
                rt.min(deadline)
            };
            timer::arm_idle(core, if at == u64::MAX { 0 } else { at });
        }
    }
}

/// Is there anything `core` could run right now? (Used to close the race between deciding to
/// sleep and a wakeup that arrives just before the core is marked idle.)
pub fn has_work_for(core: usize) -> bool {
    let now = timer::counter();
    ready_mask().iter().any(|i| can_run(i, core, usize::MAX, now))
}

/// Give up the rest of the running task's slice.
pub fn expire_slice(tid: usize) {
    SLOT[tid].slice_end.store(0, Ordering::Relaxed);
}

fn quantum_of(tid: usize) -> u64 {
    if is_rt(tid) {
        u64::MAX
    } else {
        QUANTUM[class_level(task::class_of(tid)) as usize].load(Ordering::Relaxed)
    }
}

fn start_slice(tid: usize, now: u64) {
    SLOT[tid].slice_end.store(now.saturating_add(quantum_of(tid)), Ordering::Relaxed);
    SLOT[tid].stamp.store(now, Ordering::Relaxed); // time of the slice start: earlier = has waited longer
    SLOT[tid].last_run.store(now, Ordering::Relaxed);
    SLOT[tid].ready_at.store(now, Ordering::Relaxed);
}

/// Should the waiting task `cand` take the core from `cur` now?
fn should_switch(cand: usize, cur: usize, expired: bool, now: u64) -> bool {
    if outranks(cand, cur) {
        return true;
    }
    // A slice that has run out hands the core to an equal or better competitor, or to one that
    // starves; real-time tasks have no slice (they leave when their job is done or the budget is).
    expired && eff_prio(cur) != 0 && (eff_prio(cand) <= eff_prio(cur) || starved(cand, now))
}

fn claim(cand: usize) -> bool {
    if SLOT[cand].running.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        if state(cand) == State::Ready {
            return true;
        }
        SLOT[cand].running.store(false, Ordering::Release); // changed under us: look again
    }
    false
}

/// Pick what `core` runs next and take ownership of it (`RUNNING`), unless it is `cur` already.
fn choose(core: usize, cur: usize, preempt: bool, now: u64) -> Option<usize> {
    let mut skip = TaskSet::EMPTY;
    if cur != usize::MAX && state(cur) == State::Ready && pin_ok(cur, core) {
        if !preempt {
            return Some(cur);
        }
        let expired = now >= SLOT[cur].slice_end.load(Ordering::Relaxed);
        // an unexpired slice was granted by an earlier decision; a new one needs a fresh look at the class rules
        if !expired || class_ok(cur, core, now, 0) {
            skip.insert(cur);
            for _ in 0..=task::limit() {
                let Some(cand) = best_candidate(core, cur, now, &skip) else { break };
                if !should_switch(cand, cur, expired, now) {
                    break;
                }
                if claim(cand) {
                    if outranks(cand, cur) {
                        bump(&mine().prio_preempts);
                    } else {
                        bump(&mine().slice_preempts);
                    }
                    return Some(cand);
                }
                skip.insert(cand);
            }
            if expired {
                start_slice(cur, now); // nobody to hand the core to: another slice
            }
            return Some(cur);
        }
    }
    if cur != usize::MAX {
        skip.insert(cur);
    }
    for _ in 0..=task::limit() {
        let cand = best_candidate(core, cur, now, &skip)?;
        if claim(cand) {
            return Some(cand);
        }
        skip.insert(cand);
    }
    None
}

/// Charge the time `cur` has just run on `core` to everything that keeps score.
fn account(cur: usize, core: usize, now: u64) {
    let start = SLOT[cur].run_start.load(Ordering::Relaxed);
    if start == 0 || now <= start {
        return;
    }
    SLOT[cur].run_start.store(now, Ordering::Relaxed);
    let ran = now - start;
    let kind = core_kind(core);
    // (single writer each: the core that owns the task, and the core itself)
    let rc = &SLOT[cur].run_cnt[kind as usize];
    rc.store(rc.load(Ordering::Relaxed) + ran, Ordering::Relaxed);
    STATS[core].busy.store(STATS[core].busy.load(Ordering::Relaxed) + ran, Ordering::Relaxed);
    // The averages are exact in the trackers; publishing them costs divisions, so not on every switch.
    let refresh = WINDOW.load(Ordering::Relaxed) / 4;
    let mut u = TASK_UTIL.write(cur);
    u.run(start, now);
    if now.saturating_sub(SLOT[cur].util_at.load(Ordering::Relaxed)) >= refresh {
        SLOT[cur].util.store(u.value(now), Ordering::Relaxed);
        SLOT[cur].util_at.store(now, Ordering::Relaxed);
    }
    SLOT[cur].kind_last.store(kind as u8, Ordering::Relaxed);
    let mut c = CORE_TRACK.write(core);
    c.run(start, now);
    if now.saturating_sub(STATS[core].util_at.load(Ordering::Relaxed)) >= refresh {
        STATS[core].util.store(c.value(now), Ordering::Relaxed);
        STATS[core].util_at.store(now, Ordering::Relaxed);
    }
    if RT_CORE[cur].load(Ordering::Relaxed) as usize == core {
        if let Some(job) = RT_JOB.write(cur).as_mut() {
            job.charge(ran);
            rt_publish(cur, job);
            if job.throttled(now) {
                // budget gone: park it until the period ends (the budget timer fired for exactly this)
                park(cur, job.deadline());
            }
        }
    }
}

/// `next` starts running on `core`.
fn start_running(next: usize, cur: usize, core: usize, now: u64) {
    if next != cur {
        let st = &STATS[core];
        bump(&st.switches);
        let ready = SLOT[next].due_at.load(Ordering::Relaxed);
        if ready != 0 {
            let l = (eff_prio(next) as usize).min(3);
            let lat = now.saturating_sub(ready);
            if lat > st.lat_max[l].load(Ordering::Relaxed) {
                st.lat_max[l].store(lat, Ordering::Relaxed);
            }
            st.lat_sum[l].store(st.lat_sum[l].load(Ordering::Relaxed) + lat, Ordering::Relaxed);
            bump(&st.lat_n[l]);
        }
        let home = SLOT[next].home.load(Ordering::Relaxed) as usize;
        if home != core {
            bump(&st.migrations);
            if CURRENT[home].load(Ordering::Relaxed) != usize::MAX {
                bump(&st.steals);
            }
            SLOT[next].home.store(core as u8, Ordering::Relaxed);
        }
        if pin_of(next) == NOT_PINNED && !class_ok(next, core, now, 0) {
            bump(&st.spills);
        }
        start_slice(next, now);
    }
    SLOT[next].run_start.store(now, Ordering::Relaxed);
}

/// Choose the next task for this core and load its saved state into `tf`.
/// `tf` holds the interrupted task's registers, already saved by the caller.
pub fn dispatch(tf: &mut TrapFrame, preempt: bool) {
    let core = smp::cpu_id();
    let mut cur = CURRENT[core].load(Ordering::Relaxed);
    // Fast path: a system call after which the same task simply goes on. Nothing to decide, no
    // clock to read; the time it takes is accounted at the next real decision.
    if !preempt && cur != usize::MAX && state(cur) == State::Ready && pin_ok(cur, core) && !DOOMED[cur].load(Ordering::SeqCst) {
        let age = &STATS[core].clock_age;
        age.store(age.load(Ordering::Relaxed) + 1, Ordering::Relaxed); // the next reading that is shared is older
        mmu::switch_to(task::l1_of(cur), cur as u16 + 1);
        *tf = *frame(cur);
        return;
    }
    set_flag(&STATS[core].preempt_pending, false);
    if cur != usize::MAX {
        tpidr_save(cur); // (the register still holds the interrupted task's value)
        crate::fpu::save(cur); // (so do the FP/SIMD registers, if it used them)
    }
    let mut now = sample_clock(core, preempt);
    if cur != usize::MAX {
        account(cur, core, now);
    }
    let mut first_pass = true;
    loop {
        if !first_pass {
            now = timer::counter();
            STATS[core].clock.store(now, Ordering::Relaxed);
            STATS[core].clock_age.store(0, Ordering::Relaxed);
            timer::resync(core, now); // this core may have slept through several ticks
        }
        // Sleepers wake at timer interrupts (every jiffy; sooner for real-time tasks, which arm their own
        // event). A switch caused by a system call does not have to look: the first pass after one
        // would only find what the next tick finds.
        if preempt || !first_pass {
            wake_sleepers(now);
        }
        first_pass = false;
        // A task condemned while it was running may block in the very syscall that brought us here
        // (doom() saw it running, so it did not wake it): make it runnable so it is killed now rather
        // than never.
        if cur != usize::MAX && DOOMED[cur].load(Ordering::SeqCst) {
            let s = state(cur);
            if matches!(s, State::RecvWait(_) | State::MultiWait(_) | State::CallWait | State::Sleep(_) | State::IrqWait(_) | State::RingWait(_)) {
                let _ = wake_if(cur, s);
            }
        }
        match choose(core, cur, preempt, now) {
            Some(next) if DOOMED[next].swap(false, Ordering::SeqCst) => {
                // This core owns `next` now: no other core can be running it.
                task::die(next, doom_reason(next));
                if next != cur {
                    SLOT[next].running.store(false, Ordering::Release);
                }
            }
            Some(next) => {
                if cur != usize::MAX && cur != next {
                    if state(cur) == State::Ready {
                        // back in the queue
                        SLOT[cur].ready_at.store(now, Ordering::Relaxed);
                        SLOT[cur].due_at.store(now, Ordering::Relaxed);
                        set_flag(&STATS[core].dirty, true);
                    }
                    SLOT[cur].running.store(false, Ordering::Release); // hand the outgoing task back
                }
                start_running(next, cur, core, now);
                CURRENT[core].store(next, Ordering::Relaxed);
                mmu::switch_to(task::l1_of(next), next as u16 + 1);
                tpidr_load(next);
                crate::fpu::load(next);
                *tf = *frame(next);
                let slice = SLOT[next].slice_end.load(Ordering::Relaxed);
                let mut ev = rt_event(core, next, now);
                if slice != u64::MAX && contended(core, next, now) {
                    ev = ev.min(slice);
                    set_flag(&STATS[core].slice_timer, true);
                } else {
                    set_flag(&STATS[core].slice_timer, false);
                }
                timer::arm(core, if ev == u64::MAX { 0 } else { ev });
                return;
            }
            None => {
                if cur != usize::MAX {
                    if state(cur) == State::Ready {
                        // let go of it (it may not stay here): another core is to be woken for it
                        SLOT[cur].ready_at.store(now, Ordering::Relaxed);
                        SLOT[cur].due_at.store(now, Ordering::Relaxed);
                        set_flag(&STATS[core].dirty, true);
                    }
                    SLOT[cur].running.store(false, Ordering::Release);
                    CURRENT[core].store(usize::MAX, Ordering::Relaxed);
                    cur = usize::MAX;
                }
                if !alive() {
                    kprintln!("[kernel] no runnable or sleeping tasks left");
                    finish(1);
                }
                // A sleeper we just woke may belong on another (sleeping) core: say so before dozing off.
                smp::kick_idle();
                set_flag(&STATS[core].slice_timer, false);
                idle_timer(core, now);
                smp::idle();
            }
        }
    }
}

pub fn finish(code: u32) -> ! {
    kprintln!(
        "[kernel] shutdown: exit code {code}, uptime {} ticks, {}/{} frames free",
        timer::ticks(),
        mem::free_frames(),
        mem::total_frames()
    );
    for class in 0..crate::sync::CLASS_NAMES.len() {
        let (acq, wait) = crate::sync::stats(class);
        if acq > 0 {
            kprintln!(
                "[locks] {:<10} {:>9} acquisitions, {:>8} had to wait ({}.{}%)",
                crate::sync::CLASS_NAMES[class],
                acq,
                wait,
                wait * 100 / acq,
                wait * 1000 / acq % 10
            );
        }
    }
    let c = crate::compact::stats();
    kprintln!(
        "[mem] largest free run {} of {} free frames in {} runs; compaction: {} pages migrated in {} passes, {} refused, {} contiguous-allocation failures, {} racing faults retried",
        mem::largest_free_run(), mem::free_frames(), mem::free_runs(), c.migrated, c.passes, c.rejected, c.failures, c.spurious
    );
    for i in 0..task::limit() {
        let st = state(i);
        if st != State::Free {
            let ticks: [u32; MAX_CPUS] = core::array::from_fn(|c| task::TICKS_ON[i][c].load(Ordering::Relaxed));
            kprintln!("[kernel]   task {i} '{}' state={:?} restarts={} ticks per core {:?}", info(i).name, st, task::RESTARTS[i].load(Ordering::Relaxed), ticks);
        }
    }
    // Placement check: Heavy work must have stayed on performance cores when they exist.
    let big = big_online();
    for i in (0..task::limit()).filter(|&i| task::class_of(i) == Class::Heavy && state(i) != State::Free) {
        let t: [u32; MAX_CPUS] = core::array::from_fn(|c| task::TICKS_ON[i][c].load(Ordering::Relaxed));
        let (little, bigt) = (t[..2].iter().sum::<u32>(), t[2..].iter().sum::<u32>());
        if big {
            kprintln!("[sched] '{}' (Heavy) ran {} ticks on performance cores, {} on efficiency cores: {}", info(i).name, bigt, little, if little == 0 && bigt > 0 { "PASS" } else { "spilled" });
        } else {
            kprintln!("[sched] '{}' (Heavy): no performance cores online ({} cores), ran {} ticks", info(i).name, smp::online_mask().count_ones(), little + bigt);
        }
    }
    let k = totals();
    kprintln!(
        "[sched] {} switches ({} by slice expiry, {} by a higher-priority wakeup, {} interrupts sent for preemption and slice timers); {} migrations, {} taken from a busy core, {} onto the other kind of core",
        k.switches, k.slice_preempts, k.prio_preempts, k.preempt_ipis, k.migrations, k.steals, k.spills
    );
    kprintln!("[sched] {} candidate searches looked at {} ready tasks ({} each)", k.picks, k.scanned, k.scanned / k.picks.max(1));
    let now = timer::counter();
    let wall = now.max(1);
    let mut est_mj = 0u64;
    for core in 0..MAX_CPUS {
        if smp::online_mask() & (1 << core) == 0 {
            continue;
        }
        let kind = core_kind(core);
        let busy = STATS[core].busy.load(Ordering::Relaxed);
        let pct = busy * 1000 / wall;
        kprintln!("[sched] core {core} ({kind:?}): busy {}.{}%, utilisation now {}/1024, would request {}/1024", pct / 10, pct % 10, core_util(core, now), energy::target_util(core_util(core, now)));
        // model estimate: full power while busy, idle power the rest of the time
        let m = energy::model(kind);
        let (busy_us, wall_us) = (timer::counter_to_us(busy), timer::counter_to_us(wall));
        est_mj += (busy_us * m.active_mw as u64 + wall_us.saturating_sub(busy_us) * m.idle_mw as u64) / 1_000_000;
    }
    kprintln!("[sched] estimated CPU energy over the run: {est_mj} mJ (nominal power model, not a measurement)");
    for (l, name) in ["real-time", "interactive", "background", "heavy"].iter().enumerate() {
        let (max, sum, n) = latency(l);
        if n > 0 {
            kprintln!("[sched] wake-to-run latency {name}: max {} us, mean {} us over {n} dispatches", timer::counter_to_us(max), timer::counter_to_us(sum / n));
        }
    }
    semihost_exit(code)
}

pub fn semihost_exit(code: u32) -> ! {
    if cfg!(feature = "park-on-exit") {
        kprintln!("[kernel] halted (window mode): close the window to quit");
        loop {
            crate::frame::cpu::wait_for_event();
        }
    }
    crate::frame::cpu::semihost_exit(code);
    loop {
        crate::frame::cpu::wait_for_event();
    }
}

/// Carve this module's per-task tables (`n` tasks); called once from `task::init_tables`.
pub fn init_tables(n: usize) {
    SLOT.init(n, |_| Slot::NEW);
    DOOMED.init(n, |_| const { AtomicBool::new(false) });
    DOOM_WHY.init(n, |_| const { AtomicU8::new(0) });
    IRQ_DEADLINE.init(n, |_| const { AtomicU64::new(0) });
    TPIDR.init(n, |_| const { AtomicU64::new(0) });
    crate::fpu::init_tables(n);
    RECV_EPS.init(n, |_| const { [const { AtomicU16::new(NO_EP) }; 2] });
    RT_CORE.init(n, |_| const { AtomicU8::new(NO_CORE) });
    RT_DEADLINE.init(n, |_| const { AtomicU64::new(u64::MAX) });
    RT_SHARE.init(n, |_| const { AtomicU64::new(0) });
    TASK_UTIL.init(n, |_| Padded(Util::new(1)));
    RT_JOB.init(n, |_| None);
}
