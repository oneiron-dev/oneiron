//! The automatic re-entry of a served MCP `execute_code` run parked on a
//! durable wait (FIX 4606).
//!
//! An MCP caller holds no parked attempt, so no trap wakes its run when the
//! wait's reply is delivered: a code consent answer settled and delivered,
//! and the run still waited for its caller's next call. Now each entry that
//! parks its run registers an owned continuation here, keyed by the run: the
//! run's handle, task and wait key, its replay generation, and the admitted
//! request's whole caller context, which carries its credential, scope,
//! locality, destination, off-record session and stream connection, beside
//! the instrument that credential was admitted on and its connector
//! registration's ceiling.
//!
//! A committed delivery is readiness. The connector settler's pass drains
//! the registry: a run no entry holds, whose record has not moved since it
//! parked and whose wait has its reply, is entered again on a task of its
//! own. A caller's own call that registers checks the same at once, so a
//! reply delivered before the registration waits for no pass. Readiness is
//! not authority: the caller's kept instrument, its registration and
//! `execute_code`'s own gate are checked again first, and nothing stands in
//! for the caller. The run then goes through the same admitted execution
//! helper as the caller's own call, under the host's single flight, run
//! admission, model seat and spend line, each verb call under its own gate.
//!
//! Readiness is checked before the run is the re-entry's own, so it is only
//! a hint. A caller's own call can reach the host's single flight first,
//! consume the reply and move the record on. The re-entry therefore carries
//! the wait and the generation it was readied for, and the host reads the
//! record again once the single flight and the run permit are the
//! re-entry's own. A record that moved runs no batch for it, and the
//! re-entry ends as one that started nothing.
//!
//! An entry's outcome replaces the registration: another wait registers that
//! wait, and any other end removes it. The caller's own call stays a valid
//! re-entry and takes its turn in the same single flight.
//!
//! The registry is memory, so a restart forgets it. A run parked on a code
//! consent wait is entered again after a restart from its wait alone
//! (`recovery`): the wait keeps the admitted caller's origin and slip
//! witness, and the run keeps its caller's own task. Each settler pass
//! builds such a run's continuation again for the same caller, verified
//! again now, and enters it through the same path. This covers live paired
//! slips and the attested owner. A custom registration a restart lost is
//! not made again from its saved ceiling: its run stays parked, its caller
//! unavailable, until the caller's own next call. Any other parked run
//! waits for its caller's next call, as before.

mod origin;
mod recovery;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

use oneiron::EntityId;
use oneiron::authority::InvocationSlipBinding;
use oneiron::code_run::{CodeRunReplayGeneration, CodeRunReplayRecord, WaitDeliveries, WaitKey};
use oneiron::engine_executor::EngineExecutorOutcome;
use oneiron::runtime_hooks::verb::{VerbAskInstrument, VerbAskRefusal};

pub(super) use self::origin::mcp_code_consent_origin;
use super::McpCallContext;
use crate::mcp::{McpCodeExecutionError, McpCodeRunResumeCondition};
use crate::server::{HousekeepingAdmission, SyncServer};

/// The host's background write gate, held weak (FIX 4606): the strong gate
/// is the connector settler's own.
type WeakAdmission = Weak<dyn Fn() -> Option<Box<dyn Send>> + Send + Sync>;

/// The served MCP runs parked on a durable wait, each with the owned
/// continuation that enters it again once the wait's reply is delivered
/// (FIX 4606). In memory; a run parked on a code consent wait is built
/// again from its wait after a restart (`recovery`).
#[derive(Default)]
pub(crate) struct McpCodeRunContinuations {
    runs: Mutex<HashMap<EntityId, McpCodeRunSlot>>,
    /// The waits whose automatic re-entry ran and failed in this process
    /// (FIX 4606). A run recovered from its wait is not entered again for
    /// one, so a failing run is not run and spent again on every pass.
    failed: Mutex<HashSet<WaitKey>>,
    /// The host's write gate for background work, the one its connector
    /// settler passes through. Each re-entry holds one admission of it from
    /// before it is spawned until it returns, so a managed vault frozen for
    /// reap sees it in flight, and admits none while frozen. Unset until
    /// the settler starts: no run is entered again before then. Held weak:
    /// the settler's own task holds the gate, so the server never owns a
    /// gate that owns the server, and no run is entered again once the
    /// settler has stopped.
    admission: OnceLock<WeakAdmission>,
}

/// One run's place in the registry.
#[derive(Default)]
struct McpCodeRunSlot {
    /// The run's entries that began and have not ended: its caller's own
    /// calls, and at most one re-entry.
    entries: usize,
    /// How many outcomes this slot applied. An entry that ends with no
    /// outcome clears only a registration no newer outcome replaced.
    applied: u64,
    /// The replay generation of the newest outcome applied. An older
    /// entry's outcome that ends after it is stale and changes nothing.
    generation: Option<CodeRunReplayGeneration>,
    continuation: Option<McpCodeRunContinuation>,
}

impl McpCodeRunSlot {
    /// Whether this slot still registers `continuation`'s wait at its
    /// generation.
    fn holds(&self, continuation: &McpCodeRunContinuation) -> bool {
        self.continuation.as_ref().is_some_and(|held| {
            held.wait == continuation.wait && held.generation == continuation.generation
        })
    }
}

impl McpCodeRunContinuations {
    /// Binds re-entries to `admit`, the host's write gate for its connector
    /// settler's passes. The first binding stands.
    pub(crate) fn admit_with(&self, admit: &HousekeepingAdmission) {
        let _ = self.admission.set(Arc::downgrade(admit));
    }

    /// One admission for a re-entry, held until it returns; `None` while
    /// the host admits no background write, or before the settler starts.
    fn admit(&self) -> Option<Box<dyn Send>> {
        let admit = self.admission.get().and_then(Weak::upgrade)?;
        admit()
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<EntityId, McpCodeRunSlot>> {
        self.runs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The continuations of the runs no entry holds now.
    fn idle(&self) -> Vec<McpCodeRunContinuation> {
        self.slots()
            .values()
            .filter(|slot| slot.entries == 0)
            .filter_map(|slot| slot.continuation.clone())
            .collect()
    }

    /// Removes `continuation`'s registration while it stands and no entry
    /// holds its run.
    fn discard(&self, continuation: &McpCodeRunContinuation) {
        let mut slots = self.slots();
        if slots
            .get(&continuation.wait.run)
            .is_some_and(|slot| slot.entries == 0 && slot.holds(continuation))
        {
            slots.remove(&continuation.wait.run);
        }
    }
}

/// Whether `earlier` is an older state of the same run's record than
/// `later`: a record only grows, so no count of an older entry's generation
/// is ahead of a newer one's.
fn precedes(earlier: &CodeRunReplayGeneration, later: &CodeRunReplayGeneration) -> bool {
    earlier != later
        && earlier.output_count <= later.output_count
        && earlier.step_checkpoint_count <= later.step_checkpoint_count
        && earlier.bridge_call_count <= later.bridge_call_count
}

/// One parked run's owned continuation: what its next entry needs, kept
/// from the admitted entry that parked it.
#[derive(Clone)]
struct McpCodeRunContinuation {
    /// The caller's handle onto the run; the run's id derives from it.
    run_ref: String,
    /// The REPL task the run carries out.
    task: String,
    /// The wait the run parked on, keyed as its reply is delivered: the
    /// run's id, the wait's id and how often the run resumed from it.
    wait: WaitKey,
    /// The run's replay generation when it parked. A record that moved
    /// since parks on no wait this continuation names.
    generation: CodeRunReplayGeneration,
    /// The admitted request's caller context, whole: its credential, scope,
    /// locality and destination, off-record session and stream connection.
    caller: McpCallContext,
    /// The instrument the caller's credential was admitted on, when it kept
    /// one, and the binding that witnesses it.
    instrument: Option<VerbAskInstrument>,
    witness: Option<InvocationSlipBinding>,
    /// The ceiling of the connector registration the call came in by;
    /// `None` for a managed vault's attested owner, who has none.
    registration: Option<oneiron::runtime_hooks::verb::VerbAskMcpCeiling>,
}

impl McpCodeRunContinuation {
    fn new(
        server: &SyncServer,
        caller: &McpCallContext,
        run_ref: &str,
        task: &str,
        wait: WaitKey,
        generation: CodeRunReplayGeneration,
    ) -> Self {
        let auth = caller.auth.as_ref();
        let owner = auth.and_then(crate::api::scoped_auth::attested_owner_holder);
        Self {
            run_ref: run_ref.to_owned(),
            task: task.to_owned(),
            wait,
            generation,
            caller: caller.clone(),
            instrument: auth
                .and_then(|auth| crate::api::scoped_auth::verb_ask_instrument(&server.vault, auth)),
            witness: auth
                .and_then(crate::auth::CoreAuth::invocation_slip)
                .cloned(),
            registration: owner
                .is_none()
                .then(|| super::verb_hooks::mcp_adapter_ceiling(caller)),
        }
    }

    /// Where its run stands now, as the vault's committed rows say. A
    /// record that does not read, an erased one included, is not known to
    /// stand where it registered.
    fn readiness(&self, vault: &oneiron::Vault) -> McpCodeRunReadiness {
        let generation = vault
            .get_code_run_replay_record(&self.wait.run)
            .and_then(|record| {
                record
                    .as_ref()
                    .map(CodeRunReplayRecord::generation)
                    .transpose()
            });
        match generation {
            Ok(Some(generation)) if generation == self.generation => {}
            Ok(_) => return McpCodeRunReadiness::Moved,
            Err(error) => {
                tracing::warn!(
                    %error,
                    run = %self.wait.run.to_hex(),
                    "a parked MCP code run's record did not read; it is not entered again"
                );
                return McpCodeRunReadiness::Moved;
            }
        }
        match WaitDeliveries::canonical(vault).delivery(&self.wait) {
            Ok(None) => McpCodeRunReadiness::Parked,
            Ok(Some(_)) => McpCodeRunReadiness::Delivered,
            // A reply that does not read, one an erase took included (FIX
            // 5718), readies nothing: the caller's next call meets it.
            Err(error) => {
                tracing::debug!(
                    %error,
                    run = %self.wait.run.to_hex(),
                    "a parked MCP code run's reply did not read; it is not entered again"
                );
                McpCodeRunReadiness::Moved
            }
        }
    }
}

/// Where a registered run stands.
enum McpCodeRunReadiness {
    /// Parked where it registered, its reply not delivered yet.
    Parked,
    /// Parked where it registered, its reply delivered: it enters again.
    Delivered,
    /// Its record moved since it registered, is gone, or it or the reply
    /// did not read: the run is not known to stand ready where it
    /// registered.
    Moved,
}

/// What one entry's end tells of its run.
enum McpCodeRunEnd {
    /// The entry waited out its turn, or, as a re-entry, found its run moved
    /// past the wait it was readied for (FIX 4606), and started nothing.
    Untouched,
    /// The run's state after the entry is unknown: it failed, or its caller
    /// left before its outcome came back.
    Unknown,
    /// The run's record at `generation`, parked on `continuation`'s wait or
    /// on none.
    Recorded {
        generation: CodeRunReplayGeneration,
        continuation: Option<McpCodeRunContinuation>,
    },
}

impl McpCodeRunEnd {
    fn of(
        server: &SyncServer,
        caller: &McpCallContext,
        run_ref: &str,
        task: &str,
        outcome: &Result<EngineExecutorOutcome, McpCodeExecutionError>,
    ) -> Self {
        let outcome = match outcome {
            Err(McpCodeExecutionError::RunWaitedOut) => return Self::Untouched,
            Err(_) => return Self::Unknown,
            Ok(outcome) => outcome,
        };
        let Ok(generation) = outcome.replay_record.generation() else {
            return Self::Unknown;
        };
        Self::Recorded {
            generation,
            continuation: outcome.parked_wait().map(|parked| {
                McpCodeRunContinuation::new(server, caller, run_ref, task, parked.key, generation)
            }),
        }
    }
}

/// One entry of a run, counted from its start until its outcome settles the
/// run's registration. Dropped unsettled, as when its caller leaves while
/// the run's worker still runs, it clears the registration no newer outcome
/// replaced: the run's state is unknown, so only the caller's own next call
/// enters it.
pub(super) struct McpCodeRunEntry {
    server: Arc<SyncServer>,
    run_id: EntityId,
    /// Its slot's applied count when this entry began.
    applied: u64,
    /// The wait this entry, the registry's re-entry, was claimed for;
    /// `None` for a caller's own call.
    claimed: Option<WaitKey>,
    settled: bool,
}

impl McpCodeRunEntry {
    /// Counts one entry of `run_id`: its caller's own call.
    pub(super) fn begin(server: &Arc<SyncServer>, run_id: EntityId) -> Self {
        let applied = {
            let mut slots = server.mcp_code_run_continuations.slots();
            let slot = slots.entry(run_id).or_default();
            slot.entries += 1;
            slot.applied
        };
        Self {
            server: Arc::clone(server),
            run_id,
            applied,
            claimed: None,
            settled: false,
        }
    }

    /// Takes `continuation` for its run's re-entry: only while its slot
    /// still registers it and no other entry holds the run.
    fn claim(server: &Arc<SyncServer>, continuation: &McpCodeRunContinuation) -> Option<Self> {
        let run_id = continuation.wait.run;
        let applied = {
            let mut slots = server.mcp_code_run_continuations.slots();
            let slot = slots
                .get_mut(&run_id)
                .filter(|slot| slot.entries == 0 && slot.holds(continuation))?;
            slot.continuation = None;
            slot.entries = 1;
            slot.applied
        };
        Some(Self {
            server: Arc::clone(server),
            run_id,
            applied,
            claimed: Some(continuation.wait),
            settled: false,
        })
    }

    pub(super) const fn run_id(&self) -> EntityId {
        self.run_id
    }

    /// Whether this is the only entry of its run under way. This is a
    /// readiness hint only (FIX 4606): a caller's own call can begin right
    /// after it answers. The host's read of the run's record under its
    /// single flight is the fence.
    fn sole(&self) -> bool {
        self.server
            .mcp_code_run_continuations
            .slots()
            .get(&self.run_id)
            .is_some_and(|slot| slot.entries == 1)
    }

    /// Settles the run's registration with this entry's outcome: a run
    /// parked on a wait registers its continuation, and any other end
    /// removes it. After a caller's own call the registration is checked at
    /// once, so a reply delivered before it is not left for the next pass;
    /// after a re-entry the settler's next pass checks it, so no re-entry
    /// follows another without a pass between them.
    pub(super) fn settle(
        mut self,
        caller: &McpCallContext,
        run_ref: &str,
        task: &str,
        outcome: &Result<EngineExecutorOutcome, McpCodeExecutionError>,
    ) {
        // A re-entry that ran and failed is not made again for its wait in
        // this process (FIX 4606), marked before its slot frees. A permit
        // wait or a provider outage is tried again on a later pass.
        if let (Some(wait), Err(error)) = (self.claimed, outcome)
            && !matches!(
                error,
                McpCodeExecutionError::RunWaitedOut
                    | McpCodeExecutionError::ProviderUnavailable { .. }
            )
        {
            self.server.mcp_code_run_continuations.fail(wait);
        }
        let end = McpCodeRunEnd::of(&self.server, caller, run_ref, task, outcome);
        if let Some(continuation) = self.end(end)
            && self.claimed.is_none()
        {
            reenter_if_ready(&self.server, continuation);
        }
    }

    /// Ends this re-entry as one that started nothing (FIX 4606): its run
    /// had left the wait or the generation it was readied for once the
    /// host's single flight was its own. Its claim already took the
    /// registration it was readied from. A registration a newer entry made
    /// stands for the settler's next pass.
    pub(super) fn supersede(mut self) {
        self.end(McpCodeRunEnd::Untouched);
    }

    /// Ends this entry with `end`; answers the continuation it registered.
    fn end(&mut self, end: McpCodeRunEnd) -> Option<McpCodeRunContinuation> {
        self.settled = true;
        let mut slots = self.server.mcp_code_run_continuations.slots();
        let slot = slots.get_mut(&self.run_id)?;
        slot.entries = slot.entries.saturating_sub(1);
        let registered = match end {
            McpCodeRunEnd::Untouched => None,
            McpCodeRunEnd::Unknown => {
                if slot.applied == self.applied {
                    slot.continuation = None;
                }
                None
            }
            McpCodeRunEnd::Recorded {
                generation,
                continuation,
            } => {
                if slot
                    .generation
                    .is_some_and(|newest| precedes(&generation, &newest))
                {
                    None
                } else {
                    slot.applied += 1;
                    slot.generation = Some(generation);
                    slot.continuation.clone_from(&continuation);
                    continuation
                }
            }
        };
        if slot.entries == 0 && slot.continuation.is_none() {
            slots.remove(&self.run_id);
        }
        registered
    }
}

impl Drop for McpCodeRunEntry {
    fn drop(&mut self) {
        if !self.settled {
            self.end(McpCodeRunEnd::Unknown);
        }
    }
}

/// The connector settler's drain of the parked MCP runs (FIX 4606): each
/// registered run that is ready enters again on a task of its own; a run
/// whose record moved since it registered loses its registration. Then each
/// run a restart left parked on a code consent wait is built again from its
/// wait and enters the same way. Called on the settler's blocking worker,
/// inside its admitted pass.
pub(crate) fn reenter_ready_mcp_code_runs(server: &Arc<SyncServer>) {
    for continuation in server.mcp_code_run_continuations.idle() {
        reenter_if_ready(server, continuation);
    }
    recovery::reenter_recovered_mcp_code_runs(server);
}

fn reenter_if_ready(server: &Arc<SyncServer>, continuation: McpCodeRunContinuation) {
    match continuation.readiness(&server.vault) {
        McpCodeRunReadiness::Parked => {}
        McpCodeRunReadiness::Moved => server.mcp_code_run_continuations.discard(&continuation),
        McpCodeRunReadiness::Delivered => {
            // A re-entry writes as the host's own background work: it takes
            // the host's write admission before it is spawned and holds it
            // through its last write. While none is admitted (a managed
            // vault frozen for reap), its run waits for a later pass.
            let Some(admission) = server.mcp_code_run_continuations.admit() else {
                return;
            };
            if let Some(entry) = McpCodeRunEntry::claim(server, &continuation) {
                tokio::spawn(reenter(Arc::clone(server), entry, continuation, admission));
            }
        }
    }
}

/// Enters a ready run again for its original caller, or not at all: the
/// caller must stand now, and a call of its own that began meanwhile takes
/// the run where it stands instead. The entry carries the wait and the
/// generation its registration was readied for, and the host enters the run
/// only while its record still stands there (FIX 4606). The outcome goes to
/// no one; the run's record keeps it for the caller's next call.
async fn reenter(
    server: Arc<SyncServer>,
    entry: McpCodeRunEntry,
    continuation: McpCodeRunContinuation,
    admission: Box<dyn Send>,
) {
    // Held until the entry returns, past its host worker's last write.
    let _admission = admission;
    if !caller_stands(&server, &continuation).await || !entry.sole() {
        return;
    }
    let run = continuation.wait.run.to_hex();
    let entered = super::exec_board_verbs::resume_mcp_code_run(
        &server,
        &continuation.caller,
        &continuation.run_ref,
        &continuation.task,
        entry,
        McpCodeRunResumeCondition::new(continuation.wait, continuation.generation),
    )
    .await;
    match entered.map(|entered| entered.map(|entered| entered.outcome)) {
        Ok(None) => {
            tracing::debug!(
                %run,
                "a parked MCP code run was not entered again: another entry took it past the wait its re-entry was readied for"
            );
        }
        Ok(Some(Ok(outcome))) => {
            tracing::debug!(
                %run,
                status = ?outcome.status,
                "a parked MCP code run entered again once its wait's reply was delivered"
            );
        }
        Ok(Some(Err(error))) => {
            tracing::info!(
                %run,
                %error,
                "a parked MCP code run entered again and failed; its caller's next call meets it"
            );
        }
        Err(error) => {
            tracing::info!(%run, kind = error.kind, "a parked MCP code run was not entered again");
        }
    }
}

/// Readiness is not authority: the original caller as it stands now. Its
/// kept instrument verifies again as the same slip at the same ceiling, or
/// as the same live owner; a connector's registration resolves again at
/// the ceiling the call was admitted at and still admits its proof; and
/// `execute_code`'s own gate admits it. Nothing stands in: never the owner,
/// a wider scope or another actor.
async fn caller_stands(server: &Arc<SyncServer>, continuation: &McpCodeRunContinuation) -> bool {
    let caller = &continuation.caller;
    let Some(auth) = caller.auth.as_ref() else {
        return not_entered(continuation, &VerbAskRefusal::CredentialMissing);
    };
    // A caller with neither a kept instrument nor a connector registration
    // has nothing to verify again here, so its run waits for its own next
    // call, as a hook's ask on such a call does (FIX 11063).
    if continuation.instrument.is_none() && continuation.registration.is_none() {
        return not_entered(continuation, &VerbAskRefusal::CredentialUnavailable);
    }
    if let Some(instrument) = &continuation.instrument
        && let Err(refusal) = crate::code_consent_host::kept_instrument_auth(
            server,
            instrument,
            continuation.witness.as_ref(),
            None,
        )
    {
        return not_entered(continuation, &refusal);
    }
    if let Some(ceiling) = &continuation.registration {
        let Ok(now) = server.vault.capability_slip_now() else {
            return not_entered(continuation, &VerbAskRefusal::CredentialUnavailable);
        };
        let resolved = server.mcp_registry.lock().await.resolve_connection(
            &caller.stream_connection.0,
            now,
            |class, actor| {
                server
                    .vault
                    .gate_actor_ceiling_exists(class, actor)
                    .unwrap_or(false)
            },
        );
        let resolved = match resolved {
            Ok(resolved) => resolved,
            Err(error) => return not_entered(continuation, &error),
        };
        if ceiling != &super::verb_hooks::mcp_adapter_ceiling(&resolved) {
            return not_entered(continuation, &VerbAskRefusal::ScopeRefused);
        }
        if let Err(error) = super::actor_dispatch::mcp_proof_admits(server, &resolved, auth) {
            return not_entered(continuation, &error.kind);
        }
    }
    if let Err(error) = super::actor_dispatch::mcp_execute_code_gate(server, caller) {
        return not_entered(continuation, &error.kind);
    }
    true
}

/// Logs why a ready run is not entered again; its registration goes with
/// the entry that claimed it.
fn not_entered(continuation: &McpCodeRunContinuation, refusal: &dyn std::fmt::Debug) -> bool {
    tracing::info!(
        run = %continuation.wait.run.to_hex(),
        ?refusal,
        "a parked MCP code run is not entered again: its original caller does not stand now"
    );
    false
}
