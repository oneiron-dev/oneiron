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
//! 3. materializes the T1 secrets the run declares into those destinations
//!    before its process starts (FIX 10624; ARCH-0069, T1 "injected at
//!    materialization, revoked at teardown"): each entry of the secret
//!    manifest at the checkout's pinned commit that names an environment
//!    variable this host offers as a destination gets one grant, minted for
//!    the run's attempt through the vault's grant door, whose receipt is taken
//!    at materialization. A declared secret the vault refuses fails the run
//!    before any spawn. The grants are torn down once the process is done,
//!    and the run's exhaust carries their taint;
//! 4. runs [`ByoaDispatcher::execute_cli`] and settles its end: a bound
//!    runner work's through the owner's runner-seat route at its own seat,
//!    anything else captured as before (`terminal`, FIX 9320).
//!
//! The destinations are retired on every way out (an answer, a failure, a
//! failed spawn, a lost or replaced lease, a stop) by the guard the leased
//! run holds, and only its own registration: a successor's stays. A claim
//! lost while the run goes on retires them at once. The host
//! starts only where the own-runtime executor may serve: never on a hosted
//! vault, whose logins run behind the microVM executor. No secret byte
//! reaches an argv, a log, a reply or a receipt. A running process's
//! environment never changes: a value it needs later is a T1 helper's or a
//! T0 door's, never this host's.

mod child_run;
mod helper_run;
mod lease;
mod terminal;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::checkout::{CheckoutLeaseAct, CheckoutRepoOps};
use oneiron::code_sandbox::ProposalSpoolFloor;
use oneiron::code_sandbox::SandboxBoundaryContract;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::dispatch_byoa::{
    ByoEndpointBackendFactory, ByoEndpointSpec, ByoaCliExecutor, ByoaDispatcher, ByoaEgressLease,
    ByoaEgressPort, ByoaError, ByoaExecutionFence, ByoaExhaust, ByoaInputStager, ByoaResult,
    CLAUDE_CODE_PROGRAM, CODEX_PROGRAM, CliSandboxSpec, OPENCODE_PROGRAM, declared_host_secrets,
    seat_secret_caller,
};
use oneiron::entity_id::EntityId;
use oneiron::git_wire::GitWire;
use oneiron::secret_lease::{
    SECRET_GRANT_MAX_TTL_SECS, SecretGrantCaller, SecretGrantTarget, SecretTaintRef,
};
use oneiron::{HostingPrivacyPosture, LlmBackend, Vault};
use oneiron_vault_contract::now_ts;
use tokio::sync::broadcast;

use self::child_run::{NoSeatChildRuns, SeatChildRun};
use self::helper_run::SeatHelper;
use super::seat_login::{OfficialCliSeatExecutor, RunnerSeatPolicySettings, SEAT_ENV_REMOVED};
use super::secret_destinations::{RunSecretDestinations, SECRET_DESTINATION_ENV_PREFIX};
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
            server: self,
            fence: &fence,
            run: fence.attempt_id,
            floor: Arc::new(self.transfers.disk.clone()),
            destinations: child.destinations(),
            stop: child.stop_flag(),
        };
        let ran = dispatcher.execute_cli(&fence, SEAT_RUN_BUDGET, &mut executor, now_ts());
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
    /// bound runner work's end is routed under (FIX 9320), as the AI host
    /// keeps it from the models config (FIX 10625); with none named, every
    /// run is captured plain.
    fn seat_runner_policy(&self) -> Option<RunnerSeatPolicySettings> {
        self.ai.runner_seats().cloned()
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
    /// The server whose helper registrations and issuer the run's
    /// credential helper uses (FIX 10624 step 2).
    server: &'a SyncServer,
    /// The run's claim.
    fence: &'a ByoaExecutionFence,
    /// The leased attempt: the run its T1 grants are held for.
    run: AttemptId,
    floor: Arc<dyn ProposalSpoolFloor>,
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
            helper_env: None,
            model_env: None,
        };
        let ttl_secs = budget.wall_clock_secs.clamp(1, SECRET_GRANT_MAX_TTL_SECS);
        let grants = match &self.destinations {
            Some(destinations) => {
                SeatGrants::materialize(self.vault, self.run, destinations, checkout, ttl_secs)?
            }
            None => None,
        };
        let helper = match SeatHelper::begin(self.server, self.fence, checkout, ttl_secs) {
            Ok(helper) => helper,
            Err(error) => {
                if let (Some(grants), Some(destinations)) = (grants, &self.destinations) {
                    grants.revoke(self.vault, self.run, destinations);
                }
                return Err(error);
            }
        };
        seat.helper_env = helper.as_ref().and_then(SeatHelper::env);
        seat.model_env = helper.as_ref().and_then(SeatHelper::model_env);
        let ran = seat.run(spec, checkout, boundary, budget, authorize);
        let mut taints = match (grants, &self.destinations) {
            (Some(grants), Some(destinations)) => grants.revoke(self.vault, self.run, destinations),
            _ => Vec::new(),
        };
        if let Some(helper) = helper {
            taints.extend(helper.end(self.server));
        }
        ran.map(|mut exhaust| {
            for taint in taints {
                if !exhaust.secret_taint_refs.contains(&taint) {
                    exhaust.secret_taint_refs.push(taint);
                }
            }
            exhaust
        })
    }
}

/// The T1 grants a seat run's host minted for it before its process started
/// (FIX 10624): one per declared secret this host offers a destination for,
/// each held for the run's attempt alone.
struct SeatGrants {
    caller: SecretGrantCaller,
    minted: Vec<(EntityId, SecretTaintRef)>,
}

impl SeatGrants {
    /// Mints the grants for what `checkout`'s run declares into
    /// `destinations`, the receipt of each taken as its value lands, or
    /// `None` when the run declares none this host offers. A declared secret
    /// the vault refuses tears down the grants already minted and fails the
    /// run: its process never starts without a value it declared.
    fn materialize(
        vault: &Vault,
        run: AttemptId,
        destinations: &RunSecretDestinations,
        checkout: &CheckoutLeaseAct,
        ttl_secs: u64,
    ) -> ByoaResult<Option<Self>> {
        let mut wanted = Vec::new();
        for secret in declared_host_secrets(vault, checkout)? {
            if SEAT_ENV_REMOVED.contains(&secret.variable.as_str()) {
                // The seat runs on the person's own login: a vendor credential
                // variable never reaches its process, so none is minted for it.
                tracing::warn!(
                    variable = %secret.variable,
                    "a seat run declares a vendor credential variable; it is not materialized"
                );
                continue;
            }
            let destination = format!("{SECRET_DESTINATION_ENV_PREFIX}{}", secret.variable);
            if destinations.names(&destination) {
                wanted.push((secret.name, destination));
            }
        }
        if wanted.is_empty() {
            return Ok(None);
        }
        let mut grants = Self {
            caller: seat_secret_caller(vault, run)?,
            minted: Vec::with_capacity(wanted.len()),
        };
        for (name, destination) in wanted {
            let minted = vault.mint_secret_grant_for_name(
                &grants.caller,
                &name,
                SecretGrantTarget::HostDestination { name: destination },
                Some(ttl_secs),
                None,
                &mut destinations.own_delivery(run),
            );
            match minted {
                Ok(minted) => grants.minted.push((
                    minted.grant.grant_id,
                    SecretTaintRef {
                        secret_ref: name,
                        generation: minted.grant.generation,
                    },
                )),
                Err(error) => {
                    grants.revoke(vault, run, destinations);
                    return Err(error.into());
                }
            }
        }
        Ok(Some(grants))
    }

    /// Tears every grant down, its value withdrawn from `destinations`, and
    /// hands back the taint the run's output carries for them. A grant that
    /// cannot be torn down now ends at its expiry.
    fn revoke(
        self,
        vault: &Vault,
        run: AttemptId,
        destinations: &RunSecretDestinations,
    ) -> Vec<SecretTaintRef> {
        let Self { caller, minted } = self;
        minted
            .into_iter()
            .map(|(grant, taint)| {
                let torn = vault.teardown_secret_grant(
                    &caller,
                    &grant,
                    &mut destinations.own_delivery(run),
                );
                if let Err(error) = torn {
                    tracing::warn!(
                        %error,
                        "a seat run's secret grant could not be torn down; it ends at its expiry"
                    );
                }
                taint
            })
            .collect()
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
