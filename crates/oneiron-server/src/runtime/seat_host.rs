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
//! twice. It claims only attempts whose seat names no machine or names one
//! of this host's machine labels: this install's machine id (the vault's own
//! `host`) and any alias its operator declared (`[runtime]
//! seat_host_aliases`, FIX 9420), so an attempt aimed at another machine's
//! runner stays for that runner. For each claim it:
//!
//! 1. registers the run's T1 destinations on the server's
//!    [`super::SecretDestinations`], keyed by the leased attempt, from the
//!    operator's own bindings (`[runtime.host_destinations]`), before any
//!    process starts, and watches the claim while the run goes on
//!    (`child_run`, `lease`);
//! 2. builds [`OfficialCliSeatExecutor`] in the run's checkout worktree,
//!    over the host's disk floor and those destinations;
//! 3. runs [`ByoaDispatcher::execute_cli`] and settles its end: a bound
//!    runner work's through the owner's runner-seat route at its own seat,
//!    anything else captured as before (`terminal`, FIX 9320).
//!
//! The destinations are retired on every way out (an answer, a failure, a
//! failed spawn, a lost or replaced lease, a stop) by the guard the leased
//! run holds, and only its own registration: a successor's stays. A claim
//! lost while the run goes on retires them at once. The host
//! starts only where the own-runtime executor may serve: never on a hosted
//! vault, whose logins run behind the microVM executor. No secret byte
//! reaches an argv, a log, a reply or a receipt; T0, T1 and T2 custody,
//! taint and capture are as they were.

mod child_run;
mod lease;
mod terminal;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::checkout::{
    CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId, CheckoutLeaseAct,
    CheckoutLeaseService, CheckoutLiveness, CheckoutLivenessPulse, CheckoutRepoOps, CheckoutResult,
};
use oneiron::code_sandbox::SandboxBoundaryContract;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::dispatch_byoa::{
    ByoEndpointBackendFactory, ByoEndpointSpec, ByoaCliExecutor, ByoaDispatcher, ByoaEgressLease,
    ByoaEgressPort, ByoaError, ByoaExhaust, ByoaInputStager, ByoaResult, CLAUDE_CODE_PROGRAM,
    CODEX_PROGRAM, CliSandboxSpec, OPENCODE_PROGRAM,
};
use oneiron::git_wire::GitWire;
use oneiron::origin::smart_http::SpillFloor;
use oneiron::{HostingPrivacyPosture, LlmBackend, Vault};
use oneiron_vault_contract::now_ts;
use tokio::sync::broadcast;

use self::child_run::{NoSeatChildRuns, SeatChildRun};
use super::seat_login::{OfficialCliSeatExecutor, RunnerSeatPolicySettings};
use super::secret_destinations::RunSecretDestinations;
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
        Some(tokio::spawn(
            async move { server.host_seats_forever().await },
        ))
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
        let machines = self.seat_host_machines();
        ByoaDispatcher::new(self.vault(), NoEndpoints, NoEgress)
            .ready_host_cli_attempts(now_ts(), &machines, runs_here)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "the seat host cannot read its attempts; it retries");
                Vec::new()
            })
    }

    /// Claims attempt `id`, runs it and settles its end, everything it
    /// holds held under its claim for the run alone. Blocking.
    fn host_seat_run(self: &Arc<Self>, id: AttemptId) {
        let vault: &Vault = self.vault();
        let mut dispatcher = ByoaDispatcher::new(vault, NoEndpoints, NoEgress)
            .with_input_stager(CheckoutStager { vault });
        let machines = self.seat_host_machines();
        let claimed =
            dispatcher.claim_host_cli_attempt(id, LEASE_OWNER, now_ts(), &machines, runs_here);
        let fence = match claimed {
            Ok(Some(fence)) => fence,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "a seat attempt could not be claimed; it stays queued");
                return;
            }
        };
        let child = SeatChildRun::begin(self, &fence, &NoSeatChildRuns);
        let mut executor = CheckoutSeat {
            vault,
            floor: Arc::new(self.transfers.disk.clone()),
            destinations: child.destinations(),
            stop: child.stop_flag(),
        };
        let checkouts = CheckoutLeaseService::new(vault, ReadOnly, ReadOnly);
        let ran =
            dispatcher.execute_cli(&fence, SEAT_RUN_BUDGET, &checkouts, &mut executor, now_ts());
        // The run's processes are done: what was delivered for them goes,
        // and its claim is no longer watched.
        if child.end() {
            tracing::warn!(
                "a seat run's claim ended while it ran; its end is captured if it still may be"
            );
        }
        let runner_seats = self.seat_runner_policy();
        terminal::settle_host_seat(&mut dispatcher, runner_seats.as_ref(), &fence, ran);
    }
}

impl SyncServer {
    /// This host's machine labels for a seat's `machine_ref` (FIX 4552, FIX
    /// 9420): this install's machine id, as the vault reports its `host`,
    /// then each alias its operator declared in `[runtime]
    /// seat_host_aliases`. With no id minted yet, only the aliases name it,
    /// and with neither the host claims only attempts naming no machine.
    fn seat_host_machines(&self) -> Vec<String> {
        let mut machines: Vec<String> = match self.vault().local_machine() {
            Ok(machine) => machine
                .map(|machine| machine.id.to_hex())
                .into_iter()
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "the seat host cannot read its machine id");
                Vec::new()
            }
        };
        machines.extend(
            self.config
                .runtime
                .seat_host_aliases
                .iter()
                .map(|alias| alias.trim())
                .filter(|alias| !alias.is_empty())
                .map(str::to_owned),
        );
        machines
    }

    /// The owner's runner-seat policy (`[models.dreamer] runner_seats`) a
    /// bound runner work's end is routed under (FIX 9320). The server keeps
    /// no models config yet: until the AI host hands it on, none is named and
    /// every run is captured plain, as before.
    fn seat_runner_policy(&self) -> Option<RunnerSeatPolicySettings> {
        None
    }
}

/// Whether this host runs `spec`: one of the official CLIs, with no custody
/// handle to inject (a login seat's credential stays inside the CLI).
fn runs_here(spec: &CliSandboxSpec) -> bool {
    [CLAUDE_CODE_PROGRAM, CODEX_PROGRAM, OPENCODE_PROGRAM].contains(&spec.program.as_str())
        && spec.credential_handles.is_empty()
}

/// The official CLI executor in the worktree of the checkout the run is
/// bound to, over the host's disk floor and the run's destinations.
struct CheckoutSeat<'a> {
    vault: &'a Vault,
    floor: Arc<dyn SpillFloor>,
    destinations: Option<RunSecretDestinations>,
    /// Raised when the run's claim is lost: its process stops.
    stop: Option<Arc<AtomicBool>>,
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
            stop: self.stop.clone(),
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
