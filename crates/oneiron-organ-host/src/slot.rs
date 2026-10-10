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
    /// one start.
    pub(crate) fn process(&self, config: &HostConfig) -> Result<Arc<OrganProcess>, HostError> {
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
        match OrganProcess::spawn(&self.spec, config) {
            Ok(process) => {
                state.spawns += 1;
                state.last_spawn = Some(process.spawn_time);
                state.not_before = None;
                state.process = Some(Arc::clone(&process));
                Ok(process)
            }
            Err(HostError::Handshake(reason)) => {
                state.unavailable = Some(Unavailable::Incompatible(reason.clone()));
                Err(HostError::Handshake(reason))
            }
            Err(err) => {
                record_crash(&mut state);
                Err(err)
            }
        }
    }

    /// The process died under a call: forget it, and count the crash unless
    /// the host itself stopped it.
    pub(crate) fn crashed(&self, process: &Arc<OrganProcess>) {
        let mut state = self.lock();
        if state
            .process
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, process))
        {
            state.process = None;
            if !process.stopped_by_host() {
                record_crash(&mut state);
            }
        }
    }

    /// The host stopped the process on purpose (deadline, unload, revoke):
    /// forget it without counting a crash.
    pub(crate) fn stopped(&self, process: &Arc<OrganProcess>) {
        let mut state = self.lock();
        if state
            .process
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, process))
        {
            state.process = None;
        }
    }

    pub(crate) fn current(&self) -> Option<Arc<OrganProcess>> {
        self.lock().process.clone()
    }

    pub(crate) fn revoke(&self) -> Option<Arc<OrganProcess>> {
        let mut state = self.lock();
        state.unavailable = Some(Unavailable::Revoked);
        state.process.take()
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
    let shift = u32::try_from(recent.saturating_sub(1)).unwrap_or(u32::MAX).min(16);
    let backoff = BACKOFF_BASE.saturating_mul(1 << shift).min(BACKOFF_CAP);
    state.not_before = Some(now + backoff);
}
