//! The served `execute` host: the run limits one server works under,
//! and the engine-native adapter that enters each durable run on the
//! injected provider.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use oneiron::engine_executor::{EngineExecutorOutcome, EngineExecutorStatus, SelfBriefPort};

use super::active_run::{ActiveRun, ActiveRuns};
use super::native_run::{run_engine_native_caller_source, run_engine_native_code_mode};
use super::{
    McpCodeExecutionError, McpCodeExecutionHost, McpCodeExecutionRequest, McpCodeModeProvider,
    McpCodeRunInput, McpCodeRunResumeCondition, McpCodeRunResumed, mcp_code_run_id,
    run_read_worlds,
};
use crate::admission::{Admission, Permit};
use crate::wire_telemetry::{LimitQuestions, LimitRow};
use oneiron_contracts::fingerprint::ContentHash;

/// How many `execute` runs one server works on at once.
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
    /// Keyed by the credential's stream connection, its registered
    /// fingerprint.
    pub(super) runs: Admission<String>,
    /// Where the off-record facade run's seat to spawn reader children comes
    /// from (mcp/exec_host/off_record_run.rs, a direct facade door, not an
    /// MCP run); none binds no seat, and `self.spawn` answers
    /// `reader_spawn_unbound`. An MCP run is lent none: its children would
    /// spend on the host's meter, which no direct call reaches
    /// (CODE-MODE-LENDING-RUN-SPEND = A, FIX CODE-MODE-LENDING-W5).
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
            runs: Admission::new(LimitRow::CodeRuns, questions, limits.total, limits.wait),
            reader_seats: None,
            git_door_base: None,
        }
    }

    /// Lends the off-record facade run a seat to spawn reader children
    /// under, from `seats`, which notes where the run's caller sits for its
    /// children's reads. An MCP run is lent none: its children would spend
    /// on the host's meter, which no direct call reaches
    /// (CODE-MODE-LENDING-RUN-SPEND = A, FIX CODE-MODE-LENDING-W5).
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
    /// `execute` run's and a host worker's alike.
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
    /// single flight, and its worker. The worker cleans up terminal runs
    /// before releasing single flight and the permit, then wakes the entry.
    async fn run_admitted(
        &self,
        request: McpCodeExecutionRequest<'_>,
        guard: ActiveRun,
        permit: Permit,
    ) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
        let vault = Arc::clone(&request.vault);
        let provider = Arc::clone(&self.provider);
        let write_actor = request.actor.write_actor();
        // A caller-source run makes no model calls, so it binds no model-call caller (FIX
        // EXECUTE-CALLER-CODE).
        let model_call_context = match request.input {
            McpCodeRunInput::Task(_) => request
                .actor
                .auth
                .as_ref()
                .map(|_| (request.actor.actor_ref, request.off_record_session.clone())),
            McpCodeRunInput::CallerSource(_) => None,
        };
        let placement = (request.actor.scope.world_ref, request.actor.scope.facet_ref);
        let birth_position = request.actor.scope.birth_position();
        let verbs = Arc::clone(&request.verbs);
        // The admitted caller a code consent wait of the run keeps (FIX 4606).
        let consent_origin = request.consent_origin.clone();
        let brief = request.brief.clone();
        // The gated run source is HOST-derived: the caller's handle is a label
        // inside it, never the WHO.
        let run_ref = format!("mcp.execute_code:{}", request.run_ref);
        let git_door_base = self.git_door_base.clone();
        // Read under single-flight: what the provider derives from the
        // run's record is not raced by another attempt making it.
        let (config, code) = match request.input {
            McpCodeRunInput::Task(task) => {
                let config = provider
                    .executor_config(&vault, request.run_id, task)
                    .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?;
                if config.run_id != request.run_id || config.task != task {
                    return Err(scoped_identity_changed());
                }
                (config, None)
            }
            // A caller-source run binds its code's digest (FIX EXECUTE-CALLER-CODE).
            McpCodeRunInput::CallerSource(code) => {
                let config = provider
                    .source_executor_config(&vault, request.run_id, code)
                    .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?;
                if config.run_id != request.run_id
                    || config.caller_source_digest != Some(ContentHash::of(code.as_bytes()))
                {
                    return Err(scoped_identity_changed());
                }
                (config, Some(code.to_owned()))
            }
        };
        // The slip the caller's credential proved at admission: it and
        // its parent are the run's own lineage (FIX 4705). Never a tool
        // argument.
        let opener = request
            .actor
            .auth
            .as_ref()
            .and_then(|auth| auth.verified_slip())
            .cloned();
        // The run's read scope (FIX 11768): a task run's seat is born under it. A caller-source
        // run takes no seat, so it reads no worlds (FIX EXECUTE-CALLER-CODE).
        let worlds = match code.as_ref() {
            None => run_read_worlds(&vault, opener.as_ref(), placement.0)
                .map_err(McpCodeExecutionError::RunBinding)?,
            Some(_) => Vec::new(),
        };
        let run_end = request.run_end;
        // An MCP run takes no compaction seat, for either input: its window
        // stays raw (CODE-MODE-LENDING-RUN-SPEND = A, FIX CODE-MODE-LENDING-W6).
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // The engine REPL driver holds `&mut dyn JsCodeModeRuntime` across
        // its own awaits, so its future is deliberately not `Send`. It runs
        // on its OWN thread with its OWN current-thread reactor; the
        // gateway task holds no lock and only awaits the answer, so a
        // durable wait never becomes a held connection.
        let worker = crate::engine_thread("mcp-execute-code".to_owned())
            .spawn(move || {
                // FIX 17594 D5: under the run's single flight, past its
                // identity, admission and config checks, a task run's brief
                // is installed for this entry before it runs; one that
                // does not install leaves the entry without it. A caller-source run makes no
                // model calls, so it installs none (FIX EXECUTE-CALLER-CODE).
                let installed =
                    code.is_none() && brief.as_ref().is_some_and(|brief| brief.install());
                let port = brief
                    .as_deref()
                    .filter(|_| installed)
                    .map(|brief| brief as &dyn SelfBriefPort);
                let outcome = match code.as_ref() {
                    Some(code) => run_engine_native_caller_source(
                        &vault,
                        provider.as_ref(),
                        write_actor,
                        &run_ref,
                        &config,
                        code,
                        verbs,
                        opener.as_ref(),
                        birth_position,
                        git_door_base,
                        consent_origin,
                    ),
                    None => run_engine_native_code_mode(
                        &vault,
                        provider.as_ref(),
                        write_actor,
                        model_call_context,
                        &run_ref,
                        &config,
                        verbs,
                        opener.as_ref(),
                        worlds,
                        birth_position,
                        git_door_base,
                        consent_origin,
                        port,
                    ),
                };
                let ended = match &outcome {
                    Ok(outcome) => matches!(outcome.status, EngineExecutorStatus::Complete),
                    Err(error) => error.ends_run(),
                };
                // The run's brief closes as the run completes, here and
                // not with its waiter, so a caller who hung up cannot
                // keep it; a resumable outcome or a failure the same
                // `run_ref` re-enters keeps it. A window outgrown ends the
                // run as completion does: entering again meets it again
                // (FIX CODE-MODE-LENDING-W6). A caller-source run installed none.
                if ended
                    && code.is_none()
                    && let Some(brief) = &brief
                {
                    brief.close();
                }
                // End the run's resources under single flight even if the caller hung up.
                if ended && let Some(run_end) = run_end {
                    run_end.end();
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
            McpCodeExecutionError::Run("execute worker ended without a result".to_owned())
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

    fn task_runtime_available(&self) -> bool {
        self.provider.task_runtime_available()
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
            // A task entry on a host without task readiness refuses with the existing
            // model-unavailable kind, before single flight, and changes no record (FIX
            // EXECUTE-CALLER-CODE).
            if matches!(request.input, McpCodeRunInput::Task(_)) && !self.task_runtime_available() {
                return Err(McpCodeExecutionError::ProviderUnavailable { retry_after: 0 });
            }
            let guard = self.single_flight(&request).await?;
            // An MCP run is lent no reader seat, for either input: its
            // children would spend on the host's meter, which no direct call
            // reaches (CODE-MODE-LENDING-RUN-SPEND = A, FIX CODE-MODE-LENDING-W5).
            let permit = self.permit(&request).await?;
            self.run_admitted(request, guard, permit).await
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
            // As in [`Self::execute`]: a task re-entry without task readiness refuses with the
            // existing model-unavailable kind and changes no record (FIX EXECUTE-CALLER-CODE).
            if matches!(request.input, McpCodeRunInput::Task(_)) && !self.task_runtime_available() {
                return Err(McpCodeExecutionError::ProviderUnavailable { retry_after: 0 });
            }
            let guard = self.single_flight(&request).await?;
            let permit = self.permit(&request).await?;
            if !condition.stands(&request.vault) {
                return Ok(McpCodeRunResumed::Superseded);
            }
            // An MCP run is lent no reader seat, as in [`Self::execute`].
            self.run_admitted(request, guard, permit)
                .await
                .map(|outcome| McpCodeRunResumed::Entered(Box::new(outcome)))
        })
    }
}
