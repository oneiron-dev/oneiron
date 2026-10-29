//! The recording JS host, its state and its runtime adapter.
//! Entry type: `RecordingJsHost`.
//! Child modules implement behavior; sandbox and call types belong to code_sandbox and code_run.

mod boundary;
mod dispatch;
mod prompt;
mod readers;
mod receipts;
mod results;
mod type_feedback;

use super::cancel::StepCancellation;
use super::program_entry::{InjectedAnswer, PROGRAM_RESUME_HELD, ProgramInjection};
use super::stack_floor::below_stack_floor;
use super::store::{
    ByteCount, ObservationRef, RECOVERABLE_OUTPUT_CHUNK_BYTES, RESULT_READ_ROOT,
    RESULT_REPLY_INLINE_BYTES, StreamedOutputs, bridge_result_output_path, is_result_output_path,
    recoverable_output_path, result_handle_json, result_read_path, store_result_output_path,
    write_json,
};
use super::types::{
    CallableProgram, EngineExecutorResult, ExecutorLegibility, JsCodeModeHost, JsCodeModeRuntime,
    JsCodeModeStream, JsResultCall, JsResultRef, JsResultTarget, SelfDispatchResponse,
    StoreReceiptInput,
};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, DelegatedSource, ExecutorCallSite, ExecutorStorage, GatedActorWrite,
    ReaderFindingRef, ReaderJobKind, ReaderJobState, ResultFacet, ResultRead, ResultReply, RunCall,
    SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDurableWait, SelfEffect, SelfFailedResult,
    SelfReaderReportCall, SelfReaderSpawnCall, SelfSkillCall, SelfSkillCallResult,
    SelfSummarizeCall, SummarizeReply, agent_verb_rows_of, result_cannot, result_card,
    result_refusal, scoped_child_read_refusal, self_call_inputs,
};
use crate::code_run::{
    OccurrenceRef, ReaderFoldReceipt, ReaderSubstrateRef, ReceiptFinding, ReceiptPartial,
    ReceiptSource, ReceiptTree,
};
use crate::code_sandbox::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_WIT_WORLD_NAME, SandboxBoundaryContract,
    SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestTier,
};
use crate::compaction::output::OutputRef;
use crate::dreamer_wake::BudgetLegibilityEnvelope;
use crate::entity_id::EntityId;
use crate::error::{CodeError, GateError};
use crate::store::BodySink;
use crate::{Error, Result};
use serde_json::json;

pub(super) use self::boundary::executor_boundary_contract;
pub(super) use self::prompt::{executor_system_prompt, executor_turn_instruction};
use self::results::recorded_output;
pub(super) use self::type_feedback::{CallableChecks, PINNED_PROGRAM_STEP};

pub(super) struct RecordingJsHost<'a, 's> {
    gated_write: &'a GatedActorWrite<'a>,
    run_id: EntityId,
    step_start: u64,
    next_seq: u64,
    determinism: CodeRunDeterminism,
    legibility: Option<ExecutorLegibility<'a>>,
    storage: Option<&'s ExecutorStorage<'a>>,
    /// The run's share of the result-memory pool, which a callable skill's
    /// answer check holds its buffers on (FIX 10149).
    result_share: Option<&'s crate::result_memory::ResultShare>,
    recoverable: Vec<(u64, CodeRunRawOutput, OutputRef)>,
    /// The step's result as the guest streams it, written into the run's
    /// body store frame by frame.
    streamed: StreamedOutputs,
    /// The run's earlier results stored as bodies (bridge results and
    /// stored values), which the guest may read back.
    results: Vec<CodeRunRawOutput>,
    /// This step's results stored as bodies, for the record.
    pub(super) captured: Vec<CodeRunRawOutput>,
    /// The run's result names, as its record holds them.
    bindings: Vec<CodeRunResultBinding>,
    /// The names this step bound or rebound, in order, for the record.
    pub(super) bound: Vec<CodeRunResultBinding>,
    /// The fold receipts this step's stores computed, written with its
    /// bindings in its checkpoint's one transaction.
    pub(super) receipts: Vec<ReaderFoldReceipt>,
    /// The rows the run's recorded verb answers were served from, `None`
    /// when one kept no set (DEC-0005).
    recorded_rows: Option<Vec<EntityId>>,
    pub(super) bridge_calls: Vec<CodeRunBridgeCall>,
    pub(super) durable_wait: Option<SelfDurableWait>,
    /// First hard bridge failure (gate rejection or failed audited write).
    /// The guest received a typed `Denied`/`Failed` RESPONSE for it (budget
    /// attached); the executor fails the step with this error AFTER the
    /// step returns, and later calls and recorded-output reads in the step
    /// are refused fail-closed.
    pub(super) hard_failure: Option<Error>,
    /// Whether a call failed with no response the bridge could record. Its
    /// bridge position keeps no row, so no later row can checkpoint; later
    /// calls and recorded-output reads in the step are refused as after a
    /// hard failure.
    left_a_gap: bool,
    /// The TASK the agent's own refusal declined in this step (OF-533). The
    /// run does nothing more for it: later calls and recorded-output reads
    /// are refused, and the step closes the run.
    pub(super) declined: Option<EntityId>,
    /// The run's executor, `provider/name@revision`, as the callable skills
    /// its program calls are credited to (OF-353).
    skill_executor: Option<String>,
    /// Callable skills this host is running now, each nested in the one
    /// before: a callable that calls another runs its step inside its own.
    callable_depth: u32,
    /// The host projection already ran this outer call's verb hooks.
    admitted_skill_seq: Option<u64>,
    /// Each stored skill this host's callable calls read and loaded, and the
    /// rows of every result a read took from another run (`None` once one
    /// kept no set): what a callable's answer stands on, counted in
    /// [`Self::result_rows`].
    pub(super) callable_rows: (Vec<EntityId>, Option<Vec<EntityId>>),
    /// A turn program's pinned entry only (DOOR-141 PR3b): the calls an
    /// earlier entry settled, answered in their place instead of issued.
    pub(super) injection: Option<ProgramInjection>,
    /// The type checks of the callable skills this host's calls run (FIX
    /// 10389): none attached until the run lends its service.
    callable_checks: CallableChecks<'s>,
}

/// Whether the gate an act takes over the run's results (a store, a fold, a
/// summary, a spawn) counts the stored skills its callables loaded and the
/// other runs' results they read, as each read's gate does (FIX 5460). Off:
/// such an act runs as it did before those rows were counted.
const ACT_GATES_COUNT_CALLABLE_ROWS: bool = false;

/// A result a reference names for this run: one of its own, the source a
/// reader child reads in its parent's record, or a finding of one of the
/// run's children in that child's.
struct ResolvedResult {
    output: CodeRunRawOutput,
    name: Option<String>,
    /// The run whose occurrence of it a read's taint is read in.
    owner: EntityId,
    /// The rows a read of it is withheld by beside the run's own, when it is
    /// not the run's: `Some(None)` when they are not known.
    rows: Option<Option<Vec<EntityId>>>,
    /// The range of its body a read of it must stay inside, and reads by
    /// default, in the owner's offsets.
    within: Option<(u64, u64)>,
    /// Whether a read of it re-checks that the reader child's job is live.
    child_source: bool,
}

impl<'a, 's> RecordingJsHost<'a, 's> {
    pub(super) fn new(
        gated_write: &'a GatedActorWrite<'a>,
        run_id: EntityId,
        next_seq: u64,
        determinism: CodeRunDeterminism,
        legibility: Option<ExecutorLegibility<'a>>,
    ) -> Self {
        Self {
            gated_write,
            run_id,
            step_start: next_seq,
            next_seq,
            determinism,
            legibility,
            storage: None,
            result_share: None,
            recoverable: Vec::new(),
            streamed: StreamedOutputs::default(),
            results: Vec::new(),
            captured: Vec::new(),
            bindings: Vec::new(),
            bound: Vec::new(),
            receipts: Vec::new(),
            recorded_rows: Some(Vec::new()),
            bridge_calls: Vec::new(),
            durable_wait: None,
            hard_failure: None,
            left_a_gap: false,
            declined: None,
            skill_executor: None,
            callable_depth: 0,
            admitted_skill_seq: None,
            callable_rows: (Vec::new(), Some(Vec::new())),
            injection: None,
            callable_checks: CallableChecks::default(),
        }
    }

    /// Names the run's executor, as the callable skills its program calls
    /// are credited to (OF-353).
    pub(super) fn with_skill_executor(mut self, executor: &crate::ModelId) -> Self {
        self.skill_executor = Some(executor.as_str().to_owned());
        self
    }

    /// Lends the run's share of the result-memory pool to the callable
    /// skills its program calls (FIX 10149).
    pub(super) fn with_result_share(
        mut self,
        share: &'s crate::result_memory::ResultShare,
    ) -> Self {
        self.result_share = Some(share);
        self
    }

    /// Lends the run's type-feedback service to the callable skills its
    /// calls run, each checked once under its own identity (FIX 10389).
    pub(super) fn with_callable_checks(mut self, checks: CallableChecks<'s>) -> Self {
        self.callable_checks = checks;
        self
    }

    /// Only the credential-bound host projection sets this; nested calls
    /// still enter their own verb hooks.
    pub(super) fn with_admitted_skill_call(mut self, seq: u64) -> Self {
        self.admitted_skill_seq = Some(seq);
        self
    }

    /// Bind only committed observations from the current run to the linked
    /// file-read import. A guest cannot turn a hash into another run's output.
    /// Each reference is its body's manifest digest and length.
    pub(super) fn with_recoverable_outputs(
        mut self,
        storage: &'s ExecutorStorage<'a>,
        record: &CodeRunReplayRecord,
        observations: Vec<(u64, CodeRunRawOutput, ObservationRef)>,
    ) -> EngineExecutorResult<Self> {
        if record.run_id != self.run_id {
            return Err(Error::InvalidConfig("executor output run mismatch".into()).into());
        }
        self.recoverable = observations
            .into_iter()
            .map(|(seq, output, observation)| (seq, output, observation.source))
            .collect();
        self.results = record
            .outputs
            .iter()
            .filter(|output| is_result_output_path(&output.path))
            .cloned()
            .collect();
        // Its steps' type diagnostics kept whole, read as its results are
        // (FIX 8277).
        if let ExecutorStorage::Canonical(vault) = storage {
            self.results
                .extend(vault.type_diagnostics_bodies(record.run_id));
        }
        self.bindings = record.bindings.clone();
        self.recorded_rows = record.agent_verb_rows();
        self.storage = Some(storage);
        Ok(self)
    }

    /// The step's streamed result, for the executor to publish.
    pub(super) fn take_streamed(&mut self) -> StreamedOutputs {
        std::mem::take(&mut self.streamed)
    }

    fn budget(&self) -> Option<BudgetLegibilityEnvelope> {
        self.legibility.as_ref().map(ExecutorLegibility::envelope)
    }

    /// The ONE response chokepoint: every guest-visible bridge-call
    /// response — success, wait, or typed error outcome — leaves through
    /// here so the budget envelope can never be skipped. `view` is a verb
    /// hook's view of the outcome, which the guest reads in its place.
    fn respond(
        &self,
        outcome: SelfDispatchOutcome,
        view: Option<serde_json::Value>,
    ) -> SelfDispatchResponse {
        // The run's read-world capture sees every answer first (FIX 6130).
        self.gated_write
            .read_worlds_answered(self.run_id, &outcome, view.is_some());
        SelfDispatchResponse {
            outcome,
            budget: self.budget(),
            view,
        }
    }
}

impl JsCodeModeHost for RecordingJsHost<'_, '_> {
    fn start_callable_check(&mut self, seq: u64, program: CallableProgram<'_>) {
        self.start_callable_check_at(seq, program);
    }

    fn write_output(&mut self, stream: JsCodeModeStream<'_>, frame: &[u8]) -> Result<bool> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        self.streamed.write(storage, stream, frame)?;
        self.gated_write.activity_streamed(frame);
        Ok(true)
    }

    fn read_recoverable_output(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor recoverable output storage unavailable".into(),
        ))?;
        // The run's recorded outputs hold what its calls read.
        self.admit_result_read(storage)?;
        // Once an erase of the run's actor took its replies, none is read
        // back (FIX 5718).
        if storage.code_run_response_erased(self.run_id)? {
            return Err(crate::code_run::response_erased_error(
                "a recorded output read",
            ));
        }
        if path.starts_with(RESULT_READ_ROOT) {
            return self.read_stored_result(storage, path);
        }
        for (seq, output, source) in &self.recoverable {
            if !path.starts_with(&format!("/mnt/outputs/.oneiron-context-ref/{seq}/")) {
                continue;
            }
            let base = recoverable_output_path(*seq, *source);
            let offset = path
                .strip_prefix(&format!("{base}/chunk/"))
                .and_then(|value| {
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|offset| value == offset.to_string())
                })
                .ok_or(Error::InvalidConfig(
                    "invalid recoverable output reference".into(),
                ))?;
            if offset as u64 > source.byte_len {
                return Err(Error::InvalidConfig(
                    "recoverable output offset exceeds source".into(),
                ));
            }
            // Only the chunk leaves the store: an inline body is read in
            // place, a file body by range.
            if output.output_ref() != *source {
                return Err(Error::CorruptedIndex("recoverable output integrity"));
            }
            let chunk = storage
                .read_code_run_raw_output_range(
                    output,
                    offset as u64,
                    RECOVERABLE_OUTPUT_CHUNK_BYTES,
                )?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
            return Ok(Some(chunk));
        }
        Err(Error::InvalidConfig(
            "recoverable output is outside this run".into(),
        ))
    }

    fn store_reply(&mut self, reply: &serde_json::Value) -> Result<Option<serde_json::Value>> {
        let Some(storage) = self.storage else {
            return Ok(None);
        };
        let mut sink = storage.code_run_output_sink()?;
        write_json(&mut sink, reply)?;
        self.bind_stored(storage, sink, None).map(Some)
    }

    fn result_call(&mut self, call: JsResultCall) -> Result<serde_json::Value> {
        match call {
            JsResultCall::Store {
                name,
                sources,
                receipt,
            } => self.store_result(name, &sources, receipt.as_ref()),
            JsResultCall::Describe(target) => self.describe_result(&target),
            JsResultCall::CanRead { target, child } => self.can_read_result(&target, child),
            JsResultCall::Read {
                target,
                facet,
                input,
            } => self.read_result(&target, facet, input),
        }
    }

    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        self.dispatch_call(call, None)
    }

    fn dispatch_self_nested(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchResponse> {
        self.dispatch_call(call, Some((runtime, &StepCancellation::never())))
    }

    fn dispatch_self_nested_cancellable(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
        cancel: &StepCancellation,
    ) -> Result<SelfDispatchResponse> {
        self.dispatch_call(call, Some((runtime, cancel)))
    }
}

/// The declarations the system prompt teaches, in its order: the WIT host
/// verbs, the code-mode catalog fragment (every row at its SDK path, with its
/// typed input and reply), and the interpreter's own functions. A feedback
/// check reads these same texts.
pub(super) fn executor_declarations() -> [oneiron_code_check::Declaration<'static>; 3] {
    [
        ("code-run.d.ts", PLAIN_JS_HOST_VERB_DTS),
        (
            "code-mode.d.ts",
            crate::task_verb::sdk::code_mode_catalog_fragment().text,
        ),
        (
            "runtime.d.ts",
            include_str!("../../../../components/code-run-quickjs/runtime.d.ts"),
        ),
    ]
    .map(|(name, text)| oneiron_code_check::Declaration { name, text })
}
