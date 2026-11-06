//! The served `execute_code` host: the run limits one server works under,
//! and the engine-native adapter that enters each durable run on the
//! injected provider.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::code_run::SpawnHostSeat;
use oneiron::engine_executor::{EngineExecutorOutcome, EngineExecutorStatus};

use super::active_run::{ActiveRun, ActiveRuns};
use super::compaction_home::caller_compaction_seat;
use super::native_run::run_engine_native_code_mode;
use super::{
    McpCodeExecutionError, McpCodeExecutionHost, McpCodeExecutionRequest, McpCodeModeProvider,
    McpCodeRunResumeCondition, McpCodeRunResumed, mcp_code_run_id, run_read_worlds,
};
use crate::admission::{Admission, Permit};
use crate::mcp::run_seats::RunSeats;
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// How many `execute_code` runs one server works on at once.
///
/// Each run is an OS thread with its own reactor and sandbox runtime, so the
/// bound is on runs, not calls: a run holds its place until its worker ends,
/// whether or not its caller is still waiting. Past the bound a run waits its
/// turn, round-robin across credentials; it is never refused for count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeRunLimits {
    /// Runs at once, across every credential.
    pub total: usize,
    /// How long a run waits for its turn.
    pub wait: Duration,
}

/// What one run may come to in memory: its sandbox store's ceiling eight
/// times over, for the interpreter, the reactor and the run's own state.
const RUN_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

impl CodeRunLimits {
    /// The runs this machine has room for: four a core, as runs mostly wait
    /// on model calls, and no more than its memory holds.
    #[must_use]
    pub fn runs_for_this_machine() -> usize {
        let by_cores = crate::machine::cores().saturating_mul(4);
        let by_memory = crate::machine::memory_bytes().map_or(by_cores, |bytes| {
            usize::try_from(bytes / RUN_MEMORY_BYTES).unwrap_or(usize::MAX)
        });
        by_cores.min(by_memory).max(1)
    }
}

impl Default for CodeRunLimits {
    fn default() -> Self {
        Self {
            total: Self::runs_for_this_machine(),
            wait: crate::config::LimitsConfig::default().queue_wait(),
        }
    }
}

/// The PRODUCTION adapter: the injected provider, entered through the engine's
/// own durable executor.
pub struct McpEngineNativeCodeHost {
    pub(super) provider: Arc<dyn McpCodeModeProvider>,
    /// Each run's single flight: one entry at a time, the next in arrival
    /// order (FIX 9505).
    pub(super) active: ActiveRuns,
    seats: Arc<Mutex<RunSeats>>,
    /// Keyed by the credential's stream connection, its registered
    /// fingerprint.
    pub(super) runs: Admission<String>,
    /// Where each run's seat to spawn reader children comes from; none
    /// binds no seat, and `self.spawn` answers `reader_spawn_unbound`.
    pub(super) reader_seats: Option<Arc<crate::server::ReaderSeats>>,
    /// The operator's own Git door base each run's checkouts point at (FIX
    /// 7181); `None` keeps a run's own base.
    git_door_base: Option<String>,
}

impl fmt::Debug for McpEngineNativeCodeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpEngineNativeCodeHost").finish()
    }
}

impl McpEngineNativeCodeHost {
    /// A host running at most `limits.total` runs at once; past it a run
    /// waits, and the crossing asks in `questions`.
    #[must_use]
    pub fn new(
        provider: Arc<dyn McpCodeModeProvider>,
        limits: CodeRunLimits,
        questions: Arc<LimitQuestions>,
    ) -> Self {
        Self {
            provider,
            active: ActiveRuns::new(limits.wait),
            seats: Arc::default(),
            runs: Admission::new(LimitRow::CodeRuns, questions, limits.total, limits.wait),
            reader_seats: None,
            git_door_base: None,
        }
    }

    /// Lends each run a seat to spawn reader children under, from `seats`,
    /// which notes where the run's caller sits for its children's reads.
    #[must_use]
    pub(crate) fn with_reader_seats(mut self, seats: Arc<crate::server::ReaderSeats>) -> Self {
        self.reader_seats = Some(seats);
        self
    }

    /// The operator's own Git door base for each run's checkouts (FIX 7181).
    #[must_use]
    pub(crate) fn with_git_door_base(mut self, base: Option<String>) -> Self {
        self.git_door_base = base;
        self
    }

    /// The provider every run of this host executes on.
    pub(crate) fn provider(&self) -> &Arc<dyn McpCodeModeProvider> {
        &self.provider
    }

    /// The permits every run of this host waits its turn for, an
    /// `execute_code` run's and a host worker's alike.
    pub(crate) fn runs(&self) -> &Admission<String> {
        &self.runs
    }

    /// `request`'s turn in its run's single flight, once the request still
    /// names the run its scoped identity derives. A second entry of a run
    /// still running waits behind it, in arrival order, holding no permit
    /// while it waits (FIX 9505).
    async fn single_flight(
        &self,
        request: &McpCodeExecutionRequest<'_>,
    ) -> Result<ActiveRun, McpCodeExecutionError> {
        if request.run_id != mcp_code_run_id(request.run_ref, request.actor) {
            return Err(scoped_identity_changed());
        }
        self.active.acquire(request.run_id).await
    }

    /// The seat `request`'s run spawns reader children under, when this
    /// host lends seats. The run spends under no scope, so its children
    /// spend on the host's meter, as its own calls do, on a clock one window
    /// from its first spawn.
    fn reader_seat(&self, request: &McpCodeExecutionRequest<'_>) -> Option<SpawnHostSeat> {
        self.reader_seats.as_ref().map(|lent| {
            lent.seat(
                request.run_id,
                None,
                request.actor.destination(),
                self.provider.reader_window_tokens(),
            )
        })
    }

    /// `request`'s run permit. Past the bound the run waits its
    /// credential's turn. The permit moves into the run's worker, so a
    /// caller who hangs up frees nothing its run still holds.
    async fn permit(
        &self,
        request: &McpCodeExecutionRequest<'_>,
    ) -> Result<Permit, McpCodeExecutionError> {
        self.runs
            .admit(request.actor.stream_connection.0.clone())
            .await
            .map_err(|_| McpCodeExecutionError::RunWaitedOut)
    }

    /// One entry of `request`'s run, once its single flight (`guard`) and
    /// its run permit are the entry's own: the run's config, read under
    /// single flight, its model seat, and its worker. The worker releases
    /// the single flight and the permit before it wakes the entry.
    async fn run_admitted(
        &self,
        request: McpCodeExecutionRequest<'_>,
        guard: ActiveRun,
        permit: Permit,
        reader_seat: Option<SpawnHostSeat>,
    ) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
        let vault = Arc::clone(&request.vault);
        let provider = Arc::clone(&self.provider);
        let seats = Arc::clone(&self.seats);
        let write_actor = request.actor.write_actor();
        let model_call_context = request
            .actor
            .auth
            .as_ref()
            .map(|_| (request.actor.actor_ref, request.off_record_session.clone()));
        let placement = (request.actor.scope.world_ref, request.actor.scope.facet_ref);
        let verbs = Arc::clone(&request.verbs);
        // The admitted caller a code consent wait of the run keeps (FIX 4606).
        let consent_origin = request.consent_origin.clone();
        // The gated run source is HOST-derived: the caller's handle is a label
        // inside it, never the WHO.
        let run_ref = format!("mcp.execute_code:{}", request.run_ref);
        let git_door_base = self.git_door_base.clone();
        // Read under single-flight: what the provider derives from the
        // run's record is not raced by another attempt making it.
        let config = provider
            .executor_config(&vault, request.run_id, request.task)
            .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?;
        if config.run_id != request.run_id || config.task != request.task {
            return Err(scoped_identity_changed());
        }
        let run_id = request.run_id;
        // The slip the caller's credential proved at admission: it and
        // its parent are the run's own lineage (FIX 4705). Never a tool
        // argument.
        let opener = request
            .actor
            .auth
            .as_ref()
            .and_then(|auth| auth.verified_slip())
            .cloned();
        // The run's read scope (FIX 11768): its seat is born under it.
        // A scope the vault cannot read is not born.
        let worlds = run_read_worlds(&vault, opener.as_ref(), placement.0)
            .map_err(McpCodeExecutionError::RunBinding)?;
        let mut seat = seats
            .lock()
            .map_err(|_| McpCodeExecutionError::RunBinding("run seats poisoned".into()))?
            .take(run_id)
            .or_else(|| {
                caller_compaction_seat(
                    &vault,
                    provider.as_ref(),
                    request.actor,
                    write_actor,
                    opener.clone(),
                )
            });
        if let Some(seat) = seat.as_mut() {
            // Its summaries are born where the run's credential writes.
            seat.place(placement.0, placement.1);
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // The engine REPL driver holds `&mut dyn JsCodeModeRuntime` across
        // its own awaits, so its future is deliberately not `Send`. It runs
        // on its OWN thread with its OWN current-thread reactor; the
        // gateway task holds no lock and only awaits the answer, so a
        // durable wait never becomes a held connection.
        let worker = crate::engine_thread("mcp-execute-code".to_owned())
            .spawn(move || {
                let outcome = run_engine_native_code_mode(
                    &vault,
                    provider.as_ref(),
                    write_actor,
                    model_call_context,
                    &run_ref,
                    &config,
                    verbs,
                    opener.as_ref(),
                    worlds,
                    reader_seat,
                    seat.as_mut(),
                    git_door_base,
                    consent_origin,
                );
                if let (Some(seat), Ok(mut seats)) = (seat, seats.lock()) {
                    let ended = outcome.as_ref().is_ok_and(|outcome| {
                        matches!(outcome.status, EngineExecutorStatus::Complete)
                    });
                    seats.put(run_id, seat, ended);
                }
                // Completion must release single-flight and the run's
                // permit before waking an awaiter that may immediately
                // re-enter this persisted run or start another.
                drop(guard);
                drop(permit);
                let _ = sender.send(outcome);
            })
            .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
        // Detached on purpose: the caller awaits the answer instead of
        // blocking a runtime worker to join it.
        drop(worker);
        receiver.await.map_err(|_| {
            McpCodeExecutionError::Run("execute_code worker ended without a result".to_owned())
        })?
    }
}

/// The provider or the request named another run than its scoped identity
/// derives.
fn scoped_identity_changed() -> McpCodeExecutionError {
    McpCodeExecutionError::RunBinding("provider changed scoped run identity".into())
}

impl McpCodeExecutionHost for McpEngineNativeCodeHost {
    fn production_runtime_available(&self) -> bool {
        self.provider.production_runtime_available()
    }

    fn engine_native(&self) -> Option<&McpEngineNativeCodeHost> {
        Some(self)
    }

    fn execute<'a>(
        &'a self,
        request: McpCodeExecutionRequest<'a>,
    ) -> Pin<
        Box<dyn Future<Output = Result<EngineExecutorOutcome, McpCodeExecutionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let guard = self.single_flight(&request).await?;
            // A caller's own call is lent its reader seat before it waits
            // for its permit.
            let reader_seat = self.reader_seat(&request);
            let permit = self.permit(&request).await?;
            self.run_admitted(request, guard, permit, reader_seat).await
        })
    }

    /// FIX 4606: the fence of an automatic re-entry. A caller's own call
    /// can reach the run's single flight first, consume the reply and move
    /// the record on; this entry then waits behind it. So once the single
    /// flight and the permit are this entry's own, and before any config,
    /// seat or worker exists, the host reads the record again. A record that
    /// left the readied wait or generation runs no batch. The registry's
    /// readiness check is only a hint; this read is the fence.
    fn execute_resumed<'a>(
        &'a self,
        request: McpCodeExecutionRequest<'a>,
        condition: McpCodeRunResumeCondition,
    ) -> Pin<Box<dyn Future<Output = Result<McpCodeRunResumed, McpCodeExecutionError>> + Send + 'a>>
    {
        Box::pin(async move {
            let guard = self.single_flight(&request).await?;
            let permit = self.permit(&request).await?;
            if !condition.stands(&request.vault) {
                return Ok(McpCodeRunResumed::Superseded);
            }
            let reader_seat = self.reader_seat(&request);
            self.run_admitted(request, guard, permit, reader_seat)
                .await
                .map(|outcome| McpCodeRunResumed::Entered(Box::new(outcome)))
        })
    }
}
