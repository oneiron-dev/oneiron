//! JS host bridge: recording dispatcher, sandbox contract, and prompt sites.

use super::types::{
    EngineExecutorResult, ExecutorLegibility, JsCodeModeHost, SelfDispatchResponse,
};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, GatedActorWrite, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfDurableWait, SelfEffect, SelfFailedResult,
};
use crate::code_sandbox::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_WIT_WORLD_NAME, SandboxBoundaryContract,
    SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestTier,
};
use crate::dreamer_wake::BudgetLegibilityEnvelope;
use crate::entity_id::EntityId;
use crate::{Error, Result};

pub(super) struct RecordingJsHost<'a> {
    gated_write: &'a GatedActorWrite<'a>,
    run_id: EntityId,
    next_seq: u64,
    determinism: CodeRunDeterminism,
    legibility: Option<ExecutorLegibility<'a>>,
    pub(super) bridge_calls: Vec<CodeRunBridgeCall>,
    pub(super) durable_wait: Option<SelfDurableWait>,
    /// First hard bridge failure (gate rejection or failed audited write).
    /// The guest received a typed `Denied`/`Failed` RESPONSE for it (budget
    /// attached); the executor fails the step with this error AFTER the
    /// step returns, and later calls in the step are refused fail-closed.
    pub(super) hard_failure: Option<Error>,
}

impl<'a> RecordingJsHost<'a> {
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
            next_seq,
            determinism,
            legibility,
            bridge_calls: Vec::new(),
            durable_wait: None,
            hard_failure: None,
        }
    }

    fn budget(&self) -> Option<BudgetLegibilityEnvelope> {
        self.legibility.as_ref().map(ExecutorLegibility::envelope)
    }

    /// The ONE response chokepoint: every guest-visible bridge-call
    /// response — success, wait, or typed error outcome — leaves through
    /// here so the budget envelope can never be skipped.
    fn respond(&self, outcome: SelfDispatchOutcome) -> SelfDispatchResponse {
        SelfDispatchResponse {
            outcome,
            budget: self.budget(),
        }
    }
}

impl JsCodeModeHost for RecordingJsHost<'_> {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let started_at_ms = self.determinism.frozen_unix_ms.saturating_add(seq);
        // ONE-1686: the speech family's order and timestamp are the BRIDGE's,
        // stamped here — on the one ordering path every `self.*` call takes —
        // before the row is recorded or the effect dispatched. Guest code
        // cannot forge either, and the replay row, the dispatched call and the
        // emitted bubble all carry the same number.
        let call = call.with_bridge_stamp(seq, started_at_ms);
        if let Some(wait) = &self.durable_wait {
            let outcome = SelfDispatchOutcome::DurableWait(wait.clone());
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(outcome));
        }
        if self.hard_failure.is_some() {
            // Fail-closed after the first hard failure: no further gate
            // dispatches; the guest sees a typed Failed response (budget
            // attached) and the replay row records exactly that.
            let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: "host bridge halted after failed call".to_owned(),
            });
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(outcome));
        }
        // ONE-1314: the current step's own history, observed at the last
        // moment before this call dispatches. The durable half was observed
        // when the step opened; together they are every bridge call this run
        // has made, so a write can never be sealed against a narrower history
        // than the one already recorded.
        self.gated_write.observe_bridge_history(&self.bridge_calls);
        let outcome = match self
            .gated_write
            .dispatch_for_executor_run(self.run_id, call.clone())
        {
            Ok(outcome) => outcome,
            Err(err) => {
                let Some(error_outcome) = dispatch_error_outcome(&call, &err) else {
                    // Infrastructure failure: no guest-visible response
                    // exists for this call at all.
                    return Err(err);
                };
                let row = CodeRunBridgeCall::record(
                    seq,
                    &call,
                    &error_outcome,
                    started_at_ms,
                    started_at_ms,
                )?;
                self.bridge_calls.push(row);
                self.hard_failure = Some(err);
                return Ok(self.respond(error_outcome));
            }
        };
        let finished_at_ms = started_at_ms;
        let row = CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, finished_at_ms)?;
        if self.durable_wait.is_none()
            && let SelfDispatchOutcome::DurableWait(wait) = &outcome
        {
            self.durable_wait = Some(wait.clone());
        }
        self.bridge_calls.push(row);
        Ok(self.respond(outcome))
    }
}

fn dispatch_error_outcome(call: &SelfCall, err: &Error) -> Option<SelfDispatchOutcome> {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => Some(SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: call.effect(),
            outcome: (*outcome).to_owned(),
            reason_codes: reason_codes
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
        })),
        _ if records_failed_effect(call.effect()) => {
            Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: err.to_string(),
            }))
        }
        _ => None,
    }
}

/// Effects whose failure is REPLAY-VISIBLE rather than infrastructural.
///
/// These cross an audited durable boundary, so a refusal is part of the run's
/// history: the guest sees a typed `Failed` response, the row lands in the
/// replay log, and the fail-closed barrier refuses everything after it.
/// ONE-1686 adds the speech family — a refused bubble (a stale route after a
/// mid-run mode flip, a door rejection) is exactly that kind of failure.
fn records_failed_effect(effect: SelfEffect) -> bool {
    matches!(
        effect,
        SelfEffect::MemoryPutClaim | SelfEffect::MemorySupersedeClaim | SelfEffect::MemoryPutEdge
    ) || effect.is_speech()
}

pub(super) const EXECUTOR_REQUIRED_HOST_IMPORTS: &[&str] = &[
    "self.memory.search",
    "self.memory.put_claim",
    "self.memory.supersede_claim",
    "self.memory.put_edge",
    "self.ask_human",
    "self.askHuman",
    "self.speak",
    "self.think",
    "self.express",
];

pub(super) fn executor_boundary_contract() -> EngineExecutorResult<SandboxBoundaryContract> {
    let boundary = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    if boundary.guest_language() != SandboxGuestLanguage::PlainJavaScript {
        return Err(Error::InvariantViolation("executor sandbox is not plain JavaScript").into());
    }
    if boundary.component_boundary() != SandboxComponentBoundary::WasmtimeWit {
        return Err(Error::InvariantViolation("executor sandbox is not the WIT boundary").into());
    }
    if boundary.wit_world() != SANDBOX_WIT_WORLD_NAME {
        return Err(Error::InvariantViolation("executor sandbox WIT world drift").into());
    }
    for required in EXECUTOR_REQUIRED_HOST_IMPORTS {
        if !boundary
            .linked_imports()
            .iter()
            .any(|import| import.name() == *required)
        {
            return Err(Error::InvariantViolation(
                "executor sandbox missing advertised host import",
            )
            .into());
        }
    }
    Ok(boundary)
}

/// The system and per-turn sites render the SAME resolved prompt-package
/// block. The prose lives outside Rust so agent-facing instructions cannot
/// drift from prompt tooling or be hand-copied between call sites.
pub(super) fn executor_system_prompt(wire: &str) -> String {
    let wire = wire.trim_end();
    format!(
        "You are Oneiron's engine-native executor.\n{wire}\n\
         The guest runs inside the CODE-1 Wasmtime WIT component boundary.\n\
         Clock and random values are host-controlled imports for replay determinism.\n\
         Use the prompt-side host verb types below as documentation only; runtime effects arrive \
         as typed host imports:\n\n{PLAIN_JS_HOST_VERB_DTS}"
    )
}

/// The per-turn trailing instruction: the SAME canonical wire teaching, bound
/// to the durable step the model is being asked for.
pub(super) fn executor_turn_instruction(step_seq: u64, wire: &str) -> String {
    let wire = wire.trim_end();
    format!("Emit the source for durable step {step_seq}.\n{wire}")
}
