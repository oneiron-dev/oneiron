//! One installed organ: its process, its crash history, its condition.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oneiron_organ_protocol::OrganIdentity;

use crate::error::{HostError, Unavailable};
use crate::process::OrganProcess;
use crate::spec::{HostConfig, OrganSpec, OrganTier};

const CRASH_WINDOW: Duration = Duration::from_secs(600);
const QUARANTINE_AFTER: usize = 5;
const BACKOFF_BASE: Duration = Duration::from_millis(250);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Where an installed organ stands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OrganState {
    /// A process is up and has passed the handshake.
    Warm,
    /// No process; the next call starts one.
    Cold,
    /// No process; the next start waits for the backoff to pass.
    Backoff,
    Unavailable(Unavailable),
}

/// What the host can say about one organ.
#[derive(Debug, Clone)]
pub struct OrganStatus {
    pub state: OrganState,
    pub pid: Option<u32>,
    pub organ: Option<OrganIdentity>,
    pub spawns: u64,
    pub recent_crashes: usize,
    pub net_isolated: bool,
    /// Spawn to `hello_ack`, for the last start.
    pub last_spawn: Option<Duration>,
}

#[derive(Debug, Default)]
struct SlotState {
    process: Option<Arc<OrganProcess>>,
    /// Every process this slot started that may still run: the current
    /// one, and older ones a call in flight may still hold. Held strongly
    /// until each has been killed and reaped, so none can end in some other
    /// thread's drop, out of a revocation's sight. Each process's reader
    /// thread forgets it once it has been reaped.
    generations: Vec<Arc<OrganProcess>>,
    /// Processes started for one call each ([`Slot::fresh_process`]): never
    /// `process`, and stopped when that call ends.
    one_call: Vec<Arc<OrganProcess>>,
    crashes: VecDeque<Instant>,
    not_before: Option<Instant>,
    unavailable: Option<Unavailable>,
    spawns: u64,
    last_spawn: Option<Duration>,
}

#[derive(Debug)]
pub(crate) struct Slot {
    pub(crate) spec: OrganSpec,
    state: Mutex<SlotState>,
}

impl Slot {
    pub(crate) fn new(spec: OrganSpec) -> Self {
        Self {
            spec,
            state: Mutex::new(SlotState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn unavailable(&self, reason: Unavailable) -> HostError {
        HostError::Unavailable {
            organ: self.spec.name.clone(),
            reason,
        }
    }

    /// The live process, started if needed. Concurrent first calls wait for
    /// one start, which is bounded by the handshake timeout or `deadline`.
    pub(crate) fn process(
        self: &Arc<Self>,
        config: &HostConfig,
        deadline: Option<Instant>,
    ) -> Result<Arc<OrganProcess>, HostError> {
        let mut state = self.lock();
        if let Some(reason) = &state.unavailable {
            return Err(self.unavailable(reason.clone()));
        }
        if let Some(process) = &state.process {
            if process.is_alive() {
                return Ok(Arc::clone(process));
            }
            let counted = !process.stopped_by_host();
            state.process = None;
            if counted {
                record_crash(&mut state);
            }
            if let Some(reason) = &state.unavailable {
                return Err(self.unavailable(reason.clone()));
            }
        }
        let process = self.start(&mut state, &self.spec, config, deadline)?;
        state.process = Some(Arc::clone(&process));
        Ok(process)
    }

    /// A new process for one call, beside the live one, under the same
    /// condition, backoff and crash history. The caller stops it when the
    /// call ends ([`Slot::stopped`]); until then a revocation finds it.
    pub(crate) fn fresh_process(
        self: &Arc<Self>,
        config: &HostConfig,
        deadline: Option<Instant>,
        memory_bytes: Option<u64>,
    ) -> Result<Arc<OrganProcess>, HostError> {
        let mut state = self.lock();
        if let Some(reason) = &state.unavailable {
            return Err(self.unavailable(reason.clone()));
        }
        // A call sized by its caller starts under its own memory grant;
        // the install grant's other terms, its pin and its verbs hold.
        let sized = memory_bytes.map(|memory_bytes| OrganSpec {
            memory_bytes,
            ..self.spec.clone()
        });
        let spec = sized.as_ref().unwrap_or(&self.spec);
        let process = self.start(&mut state, spec, config, deadline)?;
        state.one_call.push(Arc::clone(&process));
        Ok(process)
    }

    /// Starts a process under `spec`, once the backoff has passed, and
    /// tracks it.
    fn start(
        self: &Arc<Self>,
        state: &mut SlotState,
        spec: &OrganSpec,
        config: &HostConfig,
        deadline: Option<Instant>,
    ) -> Result<Arc<OrganProcess>, HostError> {
        if let Some(not_before) = state.not_before {
            let now = Instant::now();
            if now < not_before {
                return Err(HostError::Backoff {
                    organ: self.spec.name.clone(),
                    retry_after: not_before - now,
                });
            }
        }
        if self.spec.tier == OrganTier::ThirdParty {
            return Err(self.unavailable(Unavailable::ThirdPartyUnconfined));
        }
        let slot = Arc::downgrade(self);
        let forget = move || {
            if let Some(slot) = slot.upgrade() {
                slot.prune();
            }
        };
        match OrganProcess::spawn(spec, config, deadline, forget) {
            Ok(process) => {
                state.generations.retain(|old| !old.has_ended());
                state.generations.push(Arc::clone(&process));
                state.spawns += 1;
                state.last_spawn = Some(process.spawn_time);
                state.not_before = None;
                Ok(process)
            }
            Err(HostError::Handshake(reason)) => {
                state.unavailable = Some(Unavailable::Incompatible(reason.clone()));
                Err(HostError::Handshake(reason))
            }
            // The caller ran out of time; the organ is not at fault.
            Err(HostError::DeadlineExceeded) => Err(HostError::DeadlineExceeded),
            Err(err) => {
                record_crash(state);
                Err(err)
            }
        }
    }

    /// Forgets `process` as the live one or a one-call one. Whether it was.
    fn forget(state: &mut SlotState, process: &Arc<OrganProcess>) -> bool {
        if state
            .process
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, process))
        {
            state.process = None;
            return true;
        }
        let before = state.one_call.len();
        state.one_call.retain(|one| !Arc::ptr_eq(one, process));
        state.one_call.len() < before
    }

    /// The process died under a call: forget it, and count the crash unless
    /// the host itself stopped it.
    pub(crate) fn crashed(&self, process: &Arc<OrganProcess>) {
        let mut state = self.lock();
        if Self::forget(&mut state, process) && !process.stopped_by_host() {
            record_crash(&mut state);
        }
    }

    /// The host stopped the process on purpose (deadline, unload, revoke,
    /// the end of its one call): forget it without counting a crash.
    pub(crate) fn stopped(&self, process: &Arc<OrganProcess>) {
        let mut state = self.lock();
        Self::forget(&mut state, process);
        state.generations.retain(|old| !old.has_ended());
    }

    pub(crate) fn current(&self) -> Option<Arc<OrganProcess>> {
        self.lock().process.clone()
    }

    /// Every process of this slot that may still run, current or not. A
    /// process whose socket closed counts until it is killed and reaped: it
    /// may still hold what it mapped.
    pub(crate) fn live(&self) -> Vec<Arc<OrganProcess>> {
        let mut state = self.lock();
        state.generations.retain(|old| old.is_running());
        state.generations.clone()
    }

    /// Forgets every process that has been killed and reaped. Until then a
    /// stopped process is held here; after, it holds only its sockets. It
    /// never waits for an end in progress.
    pub(crate) fn prune(&self) {
        self.lock().generations.retain(|old| !old.has_ended());
    }

    /// Whether this slot was retired and every process it started has
    /// ended, so a revocation has nothing left to find in it. A slot not
    /// retired yet can still start one, however empty it is now.
    pub(crate) fn finished(&self) -> bool {
        let mut state = self.lock();
        state.generations.retain(|old| !old.has_ended());
        state.unavailable.is_some() && state.generations.is_empty()
    }

    /// Refuses every later call and hands back every live process to stop.
    pub(crate) fn revoke(&self) -> Vec<Arc<OrganProcess>> {
        self.retire(Unavailable::Revoked)
    }

    /// As [`Slot::revoke`], for an install a reinstall replaced. A call that
    /// picked this slot before the swap can start no process in it after,
    /// so a later revocation, which sees only installed slots, misses none.
    pub(crate) fn retire(&self, reason: Unavailable) -> Vec<Arc<OrganProcess>> {
        let mut state = self.lock();
        state.unavailable = Some(reason);
        state.process = None;
        state.one_call.clear();
        state.generations.retain(|old| old.is_running());
        state.generations.clone()
    }

    pub(crate) fn take_if_idle(&self, idle: Duration) -> Option<Arc<OrganProcess>> {
        let mut state = self.lock();
        let unload = state
            .process
            .as_ref()
            .and_then(|process| process.idle_for())
            .is_some_and(|for_how_long| for_how_long >= idle);
        if unload { state.process.take() } else { None }
    }

    pub(crate) fn status(&self) -> OrganStatus {
        let state = self.lock();
        let live = state.process.as_ref().filter(|process| process.is_alive());
        let organ_state = if let Some(reason) = &state.unavailable {
            OrganState::Unavailable(reason.clone())
        } else if live.is_some() {
            OrganState::Warm
        } else if state.not_before.is_some_and(|at| Instant::now() < at) {
            OrganState::Backoff
        } else {
            OrganState::Cold
        };
        OrganStatus {
            state: organ_state,
            pid: live.map(|process| process.pid),
            organ: live.map(|process| process.hello.organ.clone()),
            spawns: state.spawns,
            recent_crashes: state.crashes.len(),
            net_isolated: live.is_some_and(|process| process.net_isolated),
            last_spawn: state.last_spawn,
        }
    }
}

fn record_crash(state: &mut SlotState) {
    let now = Instant::now();
    state.crashes.push_back(now);
    while state
        .crashes
        .front()
        .is_some_and(|at| now.duration_since(*at) > CRASH_WINDOW)
    {
        state.crashes.pop_front();
    }
    let recent = state.crashes.len();
    if recent >= QUARANTINE_AFTER {
        state.unavailable = Some(Unavailable::Quarantined);
        return;
    }
    let shift = u32::try_from(recent.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(16);
    let backoff = BACKOFF_BASE.saturating_mul(1 << shift).min(BACKOFF_CAP);
    state.not_before = Some(now + backoff);
}
