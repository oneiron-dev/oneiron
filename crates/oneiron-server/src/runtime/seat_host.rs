//! The served seat host (FIX 4552, DOOR-124): the run host that runs the
//! official signed-in CLIs (`claude`, `codex`, `opencode`) for the BYOA
//! CLI attempts dispatched on this vault, on the person's own runtime.
//!
//! The Dreamer's seat executors dispatch an attempt and park awaiting its
//! foreign exhaust; that path is unchanged. This host is a pump beside the
//! resident pump: on the vault's attempt signal, and on a slow timer, it
//! reads the queued CLI attempts it can run and claims each by id through
//! the queue's existing lease ([`ByoaDispatcher::claim_host_cli_attempt`]),
//! so an attempt another runner leased keeps its lease and nothing runs
//! twice. For each claim it:
//!
//! 1. registers the run's T1 destinations on the server's
//!    [`SecretDestinations`], keyed by the leased attempt, from the
//!    operator's own bindings (`[runtime.host_destinations]`), before any
//!    process starts;
//! 2. builds [`OfficialCliSeatExecutor`] in the run's checkout worktree,
//!    over the host's disk floor and those destinations;
//! 3. runs [`ByoaDispatcher::execute_cli`] and captures the terminal
//!    exhaust ([`ByoaDispatcher::capture_terminal_exhaust`]).
//!
//! The destinations are retired on every way out (an answer, a failure, a
//! failed spawn, a lost or replaced lease, a stop) by the guard the leased
//! run holds, and only its own registration: a successor's stays. The host
//! starts only where the own-runtime executor may serve: never on a hosted
//! vault, whose logins run behind the microVM executor. No secret byte
//! reaches an argv, a log, a reply or a receipt; T0, T1 and T2 custody,
//! taint and capture are as they were.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::checkout::{
    CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId, CheckoutLeaseAct,
    CheckoutLeaseService, CheckoutLiveness, CheckoutLivenessPulse, CheckoutRepoOps,
    CheckoutResult,
};
use oneiron::code_sandbox::SandboxBoundaryContract;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::dispatch_byoa::{
    ByoEndpointBackendFactory, ByoEndpointSpec, ByoaCliExecutor, ByoaDispatcher, ByoaEgressLease,
    ByoaEgressPort, ByoaError, ByoaExhaust, ByoaInputStager, ByoaResult, ByoaTerminalDisposition,
    CLAUDE_CODE_PROGRAM, CODEX_PROGRAM, CaptureByoaExhaust, CliSandboxSpec, OPENCODE_PROGRAM,
};
use oneiron::git_wire::GitWire;
use oneiron::origin::smart_http::SpillFloor;
use oneiron::{HostingPrivacyPosture, LlmBackend, Vault};
use oneiron_vault_contract::now_ts;
use tokio::sync::broadcast;

use super::seat_login::OfficialCliSeatExecutor;
use super::secret_destinations::{
    RunSecretDestinations, SecretDestination, SecretDestinations, is_env_name,
};
use super::staged_input::WorkdirStager;
use crate::server::SyncServer;

/// The seat host's lease owner.
const LEASE_OWNER: &str = "oneiron-server-seat-host";
/// How often the host looks again with no signal: an attempt's backoff or
/// schedule ends without one.
const RECHECK: Duration = Duration::from_secs(30);
/// The shortest wait between two passes, so a burst of commits costs one.
const PASS_SPACING: Duration = Duration::from_secs(1);
/// What one seat run may take: the most the CLI door admits, since an
/// official CLI's work is the person's own (CALLS: seat run budget).
const SEAT_RUN_BUDGET: ExecutionBudget = ExecutionBudget::new(3600, 4096, 128);

impl SyncServer {
    /// Starts the seat host, or `None` on a vault whose posture keeps the
    /// own-runtime executor off it (a hosted or relay vault), or when the
    /// owner's `[runtime] seat_host` leaves the attempts to another runner.
    pub(crate) fn spawn_seat_host(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        if !self.config.runtime.seat_host
            || self.vault().privacy_posture() != HostingPrivacyPosture::SelfHostLocal
        {
            return None;
        }
        let server = Arc::clone(self);
        Some(tokio::spawn(async move { server.host_seats_forever().await }))
    }

    async fn host_seats_forever(self: Arc<Self>) {
        // Subscribed before the first pass, so a commit between that pass
        // and the first wait still wakes the loop.
        let mut wake = AttemptQueue::new(self.vault()).subscribe();
        // Attempts this host runs now, from their claim to their capture.
        let running: Arc<Mutex<HashSet<AttemptId>>> = Arc::default();
        loop {
            let server = Arc::clone(&self);
            let ready = tokio::task::spawn_blocking(move || server.ready_seat_runs())
                .await
                .unwrap_or_default();
            for id in ready {
                if !lock(&running).insert(id) {
                    continue;
                }
                let (server, running) = (Arc::clone(&self), Arc::clone(&running));
                tokio::task::spawn_blocking(move || {
                    server.host_seat_run(id);
                    lock(&running).remove(&id);
                });
            }
            let woke = tokio::select! {
                signal = wake.recv() => !matches!(signal, Err(broadcast::error::RecvError::Closed)),
                () = tokio::time::sleep(RECHECK) => true,
            };
            if !woke {
                return;
            }
            tokio::time::sleep(PASS_SPACING).await;
            // One pass serves the burst of commits that woke it.
            while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = wake.try_recv() {}
        }
    }

    /// The CLI attempts this host can run now. Blocking.
    fn ready_seat_runs(&self) -> Vec<AttemptId> {
        ByoaDispatcher::new(self.vault(), NoEndpoints, NoEgress)
            .ready_host_cli_attempts(now_ts(), runs_here)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "the seat host cannot read its attempts; it retries");
                Vec::new()
            })
    }

    /// Claims attempt `id`, runs it and captures its exhaust, its
    /// destinations held for the run alone. Blocking.
    fn host_seat_run(&self, id: AttemptId) {
        let vault: &Vault = self.vault();
        let mut dispatcher = ByoaDispatcher::new(vault, NoEndpoints, NoEgress)
            .with_input_stager(CheckoutStager { vault });
        let fence = match dispatcher.claim_host_cli_attempt(id, LEASE_OWNER, now_ts(), runs_here) {
            Ok(Some(fence)) => fence,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "a seat attempt could not be claimed; it stays queued");
                return;
            }
        };
        let held = HeldDestinations::register(
            &self.secret_destinations,
            fence.attempt_id,
            &self.config.runtime.host_destinations,
        );
        let mut executor = CheckoutSeat {
            vault,
            floor: Arc::new(self.transfers.disk.clone()),
            destinations: held.as_ref().map(|held| held.handle.clone()),
        };
        let checkouts = CheckoutLeaseService::new(vault, ReadOnly, ReadOnly);
        let ran = dispatcher.execute_cli(
            &fence,
            SEAT_RUN_BUDGET,
            &checkouts,
            &mut executor,
            now_ts(),
        );
        // The run's processes are done: what was delivered for them goes.
        drop(held);
        let (disposition, exhaust, reason) = match ran {
            Ok(exhaust) => (ByoaTerminalDisposition::Completed, exhaust, None),
            Err(error) => {
                tracing::warn!(%error, "a seat run failed; its failure is captured");
                let reason = Some(error.to_string());
                (ByoaTerminalDisposition::Failed, ByoaExhaust::default(), reason)
            }
        };
        let captured = dispatcher.capture_terminal_exhaust(CaptureByoaExhaust {
            attempt_id: fence.attempt_id,
            lease_owner: fence.lease_owner,
            attempt_count: fence.attempt_count,
            disposition,
            exhaust,
            reason,
            now: now_ts(),
        });
        if let Err(error) = captured {
            tracing::warn!(%error, "a seat run's exhaust was not captured");
        }
    }
}

/// Whether this host runs `spec`: one of the official CLIs, with no custody
/// handle to inject (a login seat's credential stays inside the CLI).
fn runs_here(spec: &CliSandboxSpec) -> bool {
    [CLAUDE_CODE_PROGRAM, CODEX_PROGRAM, OPENCODE_PROGRAM].contains(&spec.program.as_str())
        && spec.credential_handles.is_empty()
}

/// The destinations one leased run registered: retired, its own
/// registration only, when the run lets them go, on every way out.
struct HeldDestinations<'a> {
    registry: &'a SecretDestinations,
    run: AttemptId,
    handle: RunSecretDestinations,
}

impl<'a> HeldDestinations<'a> {
    /// Registers `bindings`, variable to effector, for `run`. A binding
    /// whose variable is no environment variable name or whose effector is
    /// blank is passed over, with a warning; with none left, nothing is
    /// registered and a T1 grant refuses by name, as before.
    fn register(
        registry: &'a SecretDestinations,
        run: AttemptId,
        bindings: &BTreeMap<String, String>,
    ) -> Option<Self> {
        let mut destinations = Vec::new();
        for (variable, effector) in bindings {
            if !is_env_name(variable) || effector.trim().is_empty() {
                tracing::warn!(
                    %variable,
                    "a runtime.host_destinations binding names no variable or no effector; passed over"
                );
                continue;
            }
            destinations.push(SecretDestination::env(variable.clone(), effector.trim()));
        }
        if destinations.is_empty() {
            return None;
        }
        match registry.register(run, destinations) {
            Ok(handle) => Some(Self {
                registry,
                run,
                handle,
            }),
            Err(error) => {
                tracing::warn!(%error, "a seat run's destinations were not registered");
                None
            }
        }
    }
}

impl Drop for HeldDestinations<'_> {
    fn drop(&mut self) {
        self.registry.retire_own(self.run, &self.handle);
    }
}

/// The official CLI executor in the worktree of the checkout the run is
/// bound to, over the host's disk floor and the run's destinations.
struct CheckoutSeat<'a> {
    vault: &'a Vault,
    floor: Arc<dyn SpillFloor>,
    destinations: Option<RunSecretDestinations>,
}

impl ByoaCliExecutor for CheckoutSeat<'_> {
    fn run(
        &mut self,
        spec: &CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
        boundary: SandboxBoundaryContract,
        budget: ExecutionBudget,
        authorize: &mut dyn FnMut(&str, u64) -> ByoaResult<ByoaEgressLease>,
    ) -> ByoaResult<ByoaExhaust> {
        let mut seat = OfficialCliSeatExecutor {
            workdir: worktree(self.vault, checkout)?,
            secret_destinations: self.destinations.clone(),
            floor: Some(Arc::clone(&self.floor)),
        };
        seat.run(spec, checkout, boundary, budget, authorize)
    }
}

/// Stages a run's pinned job in the worktree of its checkout.
struct CheckoutStager<'a> {
    vault: &'a Vault,
}

impl ByoaInputStager for CheckoutStager<'_> {
    fn stage(&mut self, checkout: &CheckoutLeaseAct, name: &str, bytes: &[u8]) -> ByoaResult<()> {
        let mut stager = WorkdirStager {
            workdir: worktree(self.vault, checkout)?,
        };
        stager.stage(checkout, name, bytes)
    }
}

/// The worktree `checkout` is materialized into, made when it is not yet.
fn worktree(vault: &Vault, checkout: &CheckoutLeaseAct) -> ByoaResult<PathBuf> {
    let refused = |what: &str| ByoaError::Backend(format!("the seat host could not {what}"));
    let wire = GitWire::new(vault).map_err(|_| refused("open the vault's git wire"))?;
    wire.materialize(checkout)
        .map_err(|_| refused("materialize the run's checkout"))?;
    wire.checkout_worktree_path(checkout)
        .map_err(|_| refused("find the run's checkout worktree"))
}

/// A seat run reaches no endpoint: the official CLI talks to its vendor.
struct NoEndpoints;

impl ByoEndpointBackendFactory for NoEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        Err(ByoaError::Backend(
            "the seat host serves no endpoint connector".to_owned(),
        ))
    }
}

/// A seat run takes no egress lease: the own-runtime executor runs on the
/// person's own network, which no lease mediates.
struct NoEgress;

impl ByoaEgressPort for NoEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "the seat host leases no egress".to_owned(),
        })
    }
}

/// The checkout service's sides for the run's one read of an unbound
/// checkout's lease: the host writes no checkout fact and no liveness.
struct ReadOnly;

impl CheckoutFactSink for ReadOnly {
    fn apply_checkout_fact(&mut self, _mutation: CheckoutFactMutation) -> CheckoutResult<()> {
        Err(CheckoutError::Invalid("the seat host only reads checkouts"))
    }
}

impl CheckoutLiveness for ReadOnly {
    fn publish(&mut self, _pulse: CheckoutLivenessPulse) -> CheckoutResult<()> {
        Err(CheckoutError::Invalid("the seat host only reads checkouts"))
    }

    fn current(&self, _id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(None)
    }

    fn clear(&mut self, _id: CheckoutId, _epoch: u64) -> CheckoutResult<()> {
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
