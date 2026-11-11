//! Native model-call evidence shared by the probe and decision rungs.
use oneiron::code_run::model_call::{
    MODEL_CALL_SCHEMA, ModelCallInputPart, ModelCallKind, ModelCallRecord, NativeReadDigests,
    NativeReadFailure, NativeReadOutcome, NativeReadRunSource, native_read_digests,
    record_model_call_in_txn,
};
use oneiron::code_run::{CapsuleRungBinding, ReadWorldUnknown};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{FatalLlmError, LabelReadRequest, LlmError, ModelId, RetryableLlmError};
use oneiron::{EntityId, ModelLocality, Vault};

/// A native read has no assistant message or generative request. Its evidence
/// fingerprints the admitted pack and keeps absent usage distinct from zero.
pub(crate) struct NativeReadCapture<'a> {
    vault: &'a Vault,
    actor: EntityId,
    session: Option<String>,
    no_record_at_arrival: bool,
    digests: NativeReadDigests,
    input: NativeCallInput,
}

#[derive(Clone, Copy)]
enum NativeCallInput {
    LabelRead(NativeReadRunSource),
    SeatDecision,
}

impl<'a> NativeReadCapture<'a> {
    pub(crate) fn new(
        vault: &'a Vault,
        request: &LabelReadRequest<'_>,
        actor: Option<EntityId>,
        session: Option<String>,
        no_record_at_arrival: bool,
        run_source: NativeReadRunSource,
    ) -> Option<Self> {
        let Some(actor) = actor else {
            tracing::debug!("decision-read evidence skipped: actor is unresolved");
            return None;
        };
        let digests = match native_read_digests(request.state, request.questions) {
            Ok(digests) => digests,
            Err(error) => {
                tracing::warn!(%error, "decision-read request digests failed");
                return None;
            }
        };
        Some(Self {
            vault,
            actor,
            session,
            no_record_at_arrival,
            digests,
            input: NativeCallInput::LabelRead(run_source),
        })
    }

    pub(crate) fn from_seat(
        vault: &'a Vault,
        digests: Option<NativeReadDigests>,
        actor: EntityId,
        session: Option<String>,
        no_record_at_arrival: bool,
    ) -> Option<Self> {
        let Some(digests) = digests else {
            tracing::warn!("native-seat evidence skipped: request fingerprint is unavailable");
            return None;
        };
        Some(Self {
            vault,
            actor,
            session,
            no_record_at_arrival,
            digests,
            input: NativeCallInput::SeatDecision,
        })
    }

    pub(crate) fn record(
        &self,
        run: &RunAdmission,
        call_index: impl FnOnce() -> u64,
        model: &str,
        revision: &str,
        locality: ModelLocality,
        outcome: NativeReadOutcome,
    ) {
        if self.no_record_at_arrival
            || self
                .vault
                .model_call_keeps_no_record_for(self.session.as_deref(), Some(self.actor))
        {
            return;
        }
        let model = match ModelId::new(model) {
            Ok(model) => model,
            Err(error) => {
                tracing::warn!(%error, "decision-read evidence skipped: invalid reader model id");
                return;
            }
        };
        // Attribution is evidence only, after the provider terminal. The live
        // admission, meter, permit and retry keep their original run.
        let evidence = run.initiated_by(Some(self.actor));
        let record = ModelCallRecord {
            schema: MODEL_CALL_SCHEMA,
            attempt: evidence.instance(),
            lease_generation: u64::from(evidence.revision()),
            call_index: call_index(),
            kind: match self.input {
                NativeCallInput::LabelRead(run_source) => ModelCallKind::LabelRead {
                    run_source,
                    digests: self.digests.clone(),
                    revision: revision.to_owned(),
                    outcome,
                },
                NativeCallInput::SeatDecision => ModelCallKind::SeatDecision {
                    run_source: NativeReadRunSource::Caller,
                    digests: self.digests.clone(),
                    revision: revision.to_owned(),
                    outcome,
                },
            },
            route: None,
            rung: CapsuleRungBinding {
                model,
                locality,
                prompt: None,
            },
            issuing_login: None,
            organization: None,
            project: None,
            credential_id: None,
            response_id: None,
            thread_id: None,
            previous_response_id: None,
            store: None,
            endpoint: None,
            captured_at: self.vault.now_recorded_at(),
            receipt_ref: None,
            actor: evidence.principal(),
            produced_pending: false,
            tool_rounds: false,
            rounds_truncated: false,
            replay_of: None,
            source_rows: Vec::new(),
            produced_rows: Vec::new(),
            input_parts: vec![ModelCallInputPart::Unknown {
                reason: "decision-read request sources were not captured".to_owned(),
            }],
            reasoning: Vec::new(),
            read_world_epoch: None,
            read_worlds: None,
            read_world_unknown: vec![ReadWorldUnknown::Uncaptured],
            tools_present: false,
            summary_requested: false,
            erased: false,
        };
        if let Err(error) = self
            .vault
            .with_write_txn_grouped(|txn| record_model_call_in_txn(self.vault, txn, &record))
        {
            tracing::warn!(%error, "decision-read model-call record failed");
        }
    }
}

pub(crate) fn native_read_failure(error: &LlmError) -> Option<NativeReadFailure> {
    match error {
        LlmError::Fatal(FatalLlmError::InvalidRequest) => Some(NativeReadFailure::InvalidRequest),
        LlmError::Fatal(FatalLlmError::Auth) => Some(NativeReadFailure::Auth),
        LlmError::Fatal(FatalLlmError::LabelRead(failure)) => {
            Some(NativeReadFailure::LabelRead(*failure))
        }
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => {
            Some(NativeReadFailure::RateLimited)
        }
        LlmError::Retryable(RetryableLlmError::Timeout) => Some(NativeReadFailure::Timeout),
        LlmError::Retryable(RetryableLlmError::ServerError) => Some(NativeReadFailure::ServerError),
        _ => None,
    }
}
