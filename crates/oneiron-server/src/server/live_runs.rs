//! The live agent runs a harness may act for over HTTP (OF-181).
//!
//! The resident pump registers each leased AGENT_DEF run it enters, with the
//! run's lease proof, and takes the run's guard for each whole executor
//! entry. A harness holding a credential paired to that exact agent attaches
//! to the run (`POST /v1/core/live-runs/{run}/attach`) and gets an opaque
//! handle back, to that caller only; its actions name the handle, and run
//! under the run's proof while they hold the same guard. The attachment is
//! kept on the run's replay row, so a restarted runner that re-registers the
//! same lease honours the handle again.
//!
//! A handle is valid while its runner holds the same lease: no wall-clock
//! TTL. One credential attaches per lease generation and none rebinds it. A
//! run leaves at settlement, unless it parks on a durable wait, which keeps
//! its lease. An unattached run has no handle, and a handle never falls back
//! to an actor's latest run or to plain dispatch.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::http::StatusCode;
use oneiron::attempt_queue::AttemptRecord;
use oneiron::code_run::live_run::{
    self, CodeRunLiveRunBinding, LIVE_RUN_ISSUED_LEN, LiveRunCredential,
};
use oneiron::task_verb::HostBinding;
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};
use tokio::sync::OwnedMutexGuard;

use crate::config::models::PlannerSettings;

/// An action on a live-run row named no handle.
pub(crate) const LIVE_RUN_REQUIRED: &str = "live_run_required";
/// The handle is not one this host issues.
pub(crate) const LIVE_RUN_INVALID: &str = "live_run_invalid";
/// No live run this credential may act for: an unknown run, another
/// credential or actor, or a run with no attachment. One answer for all.
pub(crate) const LIVE_RUN_UNAVAILABLE: &str = "live_run_unavailable";
/// The run's lease moved on.
pub(crate) const LIVE_RUN_STALE: &str = "live_run_stale";
/// The run is mid-entry or mid-action.
pub(crate) const CODE_RUN_BUSY: &str = "code_run_busy";
/// Another credential is attached to this lease generation.
pub(crate) const LIVE_RUN_ATTACHED: &str = "live_run_attached";

/// The version tag every handle opens with.
const HANDLE_TAG: &str = "lr1";

/// Why a live-run attach or action was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveRunRefusal {
    Required,
    Invalid,
    Unavailable,
    Stale,
    Busy,
    Attached,
}

impl LiveRunRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Required => LIVE_RUN_REQUIRED,
            Self::Invalid => LIVE_RUN_INVALID,
            Self::Unavailable => LIVE_RUN_UNAVAILABLE,
            Self::Stale => LIVE_RUN_STALE,
            Self::Busy => CODE_RUN_BUSY,
            Self::Attached => LIVE_RUN_ATTACHED,
        }
    }

    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::Required | Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unavailable => StatusCode::FORBIDDEN,
            Self::Stale | Self::Busy | Self::Attached => StatusCode::CONFLICT,
        }
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Required => "this action acts on a live run and names none",
            Self::Invalid => "the live-run handle is malformed",
            Self::Unavailable => "no live run this credential may act for",
            Self::Stale => "the live run's lease moved on",
            Self::Busy => "the live run is busy",
            Self::Attached => "another credential is attached to this live run",
        }
    }

    pub(crate) const fn suggestion(self) -> &'static str {
        match self {
            Self::Required | Self::Invalid | Self::Unavailable => {
                "Attach at POST /v1/core/live-runs/{run}/attach and send its liveRun."
            }
            Self::Stale => "Attach again once the run holds its next lease.",
            Self::Busy => "Retry once the run's current entry or action ends.",
            Self::Attached => "Act with the credential attached to this lease.",
        }
    }
}

/// Who attaches or acts: the credential's actor, and its identity.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveRunCaller {
    pub(crate) actor: WriteActor,
    pub(crate) credential: LiveRunCredential,
}

/// The host's live runs, by executor run id.
#[derive(Default)]
pub(crate) struct LiveRuns {
    runs: Mutex<HashMap<EntityId, Arc<LiveRunEntry>>>,
}

/// One registered run: its executor run, the agent it runs as, the leased
/// try its runner holds and that lease's proof, its attachment, and its
/// guard.
pub(crate) struct LiveRunEntry {
    run: EntityId,
    actor: WriteActor,
    leased: AttemptRecord,
    proof: HostBinding,
    /// The host's `[models.planner]` its runner plans under, and the model
    /// the run executes on: an action's leader rows are planned as its
    /// entries' are.
    planner: Option<PlannerSettings>,
    executor: String,
    attached: Mutex<Option<CodeRunLiveRunBinding>>,
    serial: Arc<tokio::sync::Mutex<()>>,
}

impl LiveRunEntry {
    /// The run's guard for one whole executor entry or settlement: waits
    /// while an action holds it. Blocking; never call it on the runtime.
    pub(crate) fn enter(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.serial).blocking_lock_owned()
    }

    fn is_lease(&self, actor: WriteActor, leased: &AttemptRecord) -> bool {
        is_actor(self.actor, actor)
            && self.leased.id == leased.id
            && self.leased.lease_owner == leased.lease_owner
            && self.leased.attempt_count == leased.attempt_count
    }

    /// The run's guard if no entry or action holds it.
    fn try_serial(&self) -> Result<OwnedMutexGuard<()>, LiveRunRefusal> {
        Arc::clone(&self.serial)
            .try_lock_owned()
            .map_err(|_| LiveRunRefusal::Busy)
    }
}

impl LiveRuns {
    /// Registers run `run`, which its runner enters as `actor` under the
    /// lease of `leased`, proven by `proof`, planning under `planner` on the
    /// model `executor`. The same lease keeps its entry, attachment and
    /// guard; another replaces them, keeping the attachment the run's replay
    /// row holds only when it names this exact lease.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one fact of the registered run"
    )]
    pub(crate) fn register(
        &self,
        vault: &Vault,
        run: EntityId,
        actor: WriteActor,
        leased: &AttemptRecord,
        proof: HostBinding,
        planner: Option<PlannerSettings>,
        executor: String,
    ) -> oneiron::Result<Arc<LiveRunEntry>> {
        if let Some(entry) = self.get(run)
            && entry.is_lease(actor, leased)
        {
            return Ok(entry);
        }
        let attached = live_run::live_run_binding(vault, &run)?
            .filter(|binding| binding.is_for_lease(actor, leased));
        let entry = Arc::new(LiveRunEntry {
            run,
            actor,
            leased: leased.clone(),
            proof,
            planner,
            executor,
            attached: Mutex::new(attached),
            serial: Arc::default(),
        });
        self.map().insert(run, Arc::clone(&entry));
        Ok(entry)
    }

    /// Settles run `run` with `settlement` under its guard, so no action runs
    /// across the settlement, then drops the run unless it `waits` on a
    /// durable wait that settled: a parked run keeps its lease, and so its
    /// handle. Blocking.
    pub(crate) fn settle<T, E>(
        &self,
        run: Option<EntityId>,
        waits: bool,
        settlement: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let Some(run) = run else {
            return settlement();
        };
        let serial = self.get(run).map(|entry| entry.enter());
        let settled = settlement();
        if !(waits && settled.is_ok()) {
            self.map().remove(&run);
        }
        drop(serial);
        settled
    }

    /// Attaches `caller` to run `run` and answers its handle. The caller
    /// must be the run's own agent; under the run's guard its lease must
    /// still hold. The credential attached already gets the same handle
    /// again; another is refused. Blocking.
    pub(crate) fn attach(
        &self,
        vault: &Vault,
        run: EntityId,
        caller: LiveRunCaller,
    ) -> oneiron::Result<Result<String, LiveRunRefusal>> {
        let Some(entry) = self
            .get(run)
            .filter(|entry| is_agent(entry.actor, caller.actor))
        else {
            return Ok(Err(LiveRunRefusal::Unavailable));
        };
        let _serial = match entry.try_serial() {
            Ok(serial) => serial,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !self.holds(vault, &entry)? {
            return Ok(Err(LiveRunRefusal::Stale));
        }
        let mut attached = lock(&entry.attached);
        match &*attached {
            Some(binding) if binding.is_for_credential(&caller.credential) => {
                return Ok(Ok(handle_text(run, binding)));
            }
            Some(_) => return Ok(Err(LiveRunRefusal::Attached)),
            None => {}
        }
        // A run whose first entry has not saved its record yet is mid-start.
        let Some(binding) =
            live_run::attach_live_run(vault, &run, entry.actor, &entry.leased, caller.credential)?
        else {
            return Ok(Err(LiveRunRefusal::Busy));
        };
        let handle = handle_text(run, &binding);
        *attached = Some(binding);
        Ok(Ok(handle))
    }

    /// The live run `text` names, for `caller` only: the run's own agent,
    /// with the credential attached to it.
    pub(crate) fn resolve(
        &self,
        text: &str,
        caller: LiveRunCaller,
    ) -> Result<ResolvedLiveRun, LiveRunRefusal> {
        let (run, issued) = parse_handle(text).ok_or(LiveRunRefusal::Invalid)?;
        let entry = self
            .get(run)
            .filter(|entry| is_agent(entry.actor, caller.actor))
            .ok_or(LiveRunRefusal::Unavailable)?;
        let binding = lock(&entry.attached)
            .clone()
            .filter(|binding| {
                binding.issued() == issued && binding.is_for_credential(&caller.credential)
            })
            .ok_or(LiveRunRefusal::Unavailable)?;
        Ok(ResolvedLiveRun { entry, binding })
    }

    fn get(&self, run: EntityId) -> Option<Arc<LiveRunEntry>> {
        self.map().get(&run).cloned()
    }

    /// Whether `entry` is still its run's registered entry and its lease
    /// still holds, read live. A run whose lease moved on leaves.
    fn holds(&self, vault: &Vault, entry: &Arc<LiveRunEntry>) -> oneiron::Result<bool> {
        if !is_current(&self.map(), entry) {
            return Ok(false);
        }
        if live_run::live_run_lease_holds(vault, &entry.proof)? {
            return Ok(true);
        }
        let mut runs = self.map();
        if is_current(&runs, entry) {
            runs.remove(&entry.run);
        }
        Ok(false)
    }

    fn map(&self) -> MutexGuard<'_, HashMap<EntityId, Arc<LiveRunEntry>>> {
        lock(&self.runs)
    }
}

/// A handle resolved to its registered run, not yet held.
pub(crate) struct ResolvedLiveRun {
    entry: Arc<LiveRunEntry>,
    binding: CodeRunLiveRunBinding,
}

impl ResolvedLiveRun {
    /// The `[models.planner]` the run's runner plans under, and the model it
    /// executes on, for the planner its action's leader rows run on.
    pub(crate) fn planner(&self) -> (Option<&PlannerSettings>, &str) {
        (self.entry.planner.as_ref(), &self.entry.executor)
    }

    /// The idempotency key an action through this handle runs under.
    pub(crate) fn action_key(&self, key: &str) -> oneiron::Result<String> {
        self.binding.action_key(key)
    }

    /// Takes the run's guard for one whole action, then rechecks that the
    /// run is still registered under its lease, which still holds, with
    /// this attachment. A held guard answers busy at once, never waits.
    pub(crate) fn hold(
        &self,
        runs: &LiveRuns,
        vault: &Vault,
    ) -> oneiron::Result<Result<HeldLiveRun, LiveRunRefusal>> {
        let serial = match self.entry.try_serial() {
            Ok(serial) => serial,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !runs.holds(vault, &self.entry)? {
            return Ok(Err(LiveRunRefusal::Stale));
        }
        if lock(&self.entry.attached).as_ref() != Some(&self.binding) {
            return Ok(Err(LiveRunRefusal::Unavailable));
        }
        Ok(Ok(HeldLiveRun {
            proof: self.entry.proof.clone(),
            _serial: serial,
        }))
    }
}

/// A live run held for one action: its lease proof, under its guard.
pub(crate) struct HeldLiveRun {
    proof: HostBinding,
    _serial: OwnedMutexGuard<()>,
}

impl HeldLiveRun {
    /// The run's lease proof, for the action's host binding.
    pub(crate) fn proof(&self) -> HostBinding {
        self.proof.clone()
    }
}

/// Whether `entry` is still its run's registered entry in `runs`.
fn is_current(runs: &HashMap<EntityId, Arc<LiveRunEntry>>, entry: &Arc<LiveRunEntry>) -> bool {
    runs.get(&entry.run)
        .is_some_and(|held| Arc::ptr_eq(held, entry))
}

/// Whether `caller` is `actor`.
fn is_actor(actor: WriteActor, caller: WriteActor) -> bool {
    actor.entity_ref() == caller.entity_ref() && actor.actor_class() == caller.actor_class()
}

/// Whether `caller` is the agent `actor` a run runs as.
fn is_agent(actor: WriteActor, caller: WriteActor) -> bool {
    caller.actor_class() == EdgeActorClass::Agent && is_actor(actor, caller)
}

/// `lr1.<run hex>.<issued hex>`: the run is only a lookup hint, and the
/// issued id names the attachment.
fn handle_text(run: EntityId, binding: &CodeRunLiveRunBinding) -> String {
    format!(
        "{HANDLE_TAG}.{}.{:032x}",
        run.to_hex(),
        u128::from_be_bytes(binding.issued())
    )
}

fn parse_handle(text: &str) -> Option<(EntityId, [u8; LIVE_RUN_ISSUED_LEN])> {
    let mut parts = text.split('.');
    let (Some(HANDLE_TAG), Some(run), Some(issued), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if issued.len() != 32 || !issued.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let issued = u128::from_str_radix(issued, 16).ok()?.to_be_bytes();
    Some((EntityId::from_hex(run).ok()?, issued))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
