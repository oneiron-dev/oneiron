//! The Dreamer writes a declared scope summary's body (ARCH-0006a).
//!
//! A caller declares the scope through [`Vault::request_scope_summary`]; this
//! arm reads the covered records, asks the Dreamer's model with the host's
//! summary instruction, and lands the body under the Dreamer's byline. The
//! instruction is host configuration: the engine ships no summary prompt.

use super::resources::document_version;
use super::step_charge::StepChargeTally;
use super::support::{DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE, invalid_consolidation};
use super::turn_text::{collect_in, dreamer_read, snapshot};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, DreamerAttemptExecutor,
    WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelTierRef, ResponseFormat, ScopeResource, StepOutcome, TierPrecedence,
    call_as_step,
};
use crate::registry::ENTITY_TYPE_TURN;
use crate::scope_summary::{ComposedSummary, SummarySourceMessage};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// Wraps an executor with the declared-summary arm. Every other attempt is
/// delegated untouched.
pub struct ScopeSummaryExecutor<'a, E> {
    inner: E,
    backend: &'a dyn LlmBackend,
    guard: &'a BudgetGuard,
    actor: WriteActor,
    model: ModelId,
    inference: HostInferenceContext<'a>,
    /// The host's summary instruction; without one a declaration cannot run.
    instruction: Option<&'a str>,
}

impl<'a, E> ScopeSummaryExecutor<'a, E> {
    #[must_use]
    pub fn new(
        inner: E,
        backend: &'a dyn LlmBackend,
        guard: &'a BudgetGuard,
        actor: WriteActor,
        model: ModelId,
        inference: HostInferenceContext<'a>,
        instruction: Option<&'a str>,
    ) -> Self {
        Self {
            inner,
            backend,
            guard,
            actor,
            model,
            inference,
            instruction,
        }
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for ScopeSummaryExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type != DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE {
            return self.inner.execute(attempt, ctx).await;
        }
        self.compose(attempt, ctx).await
    }
}

impl<E> ScopeSummaryExecutor<'_, E> {
    async fn compose(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        if self.actor != ctx.vault.dreamer_actor_for_attempt(attempt_id)? {
            return Err(invalid_consolidation(
                "executor actor is not the queued Dreamer authority",
            ));
        }
        let Some(instruction) = self.instruction else {
            return Err(Error::InvalidConfig(
                "the host configured no Dreamer summary instruction".into(),
            ));
        };
        // A replay after the body landed completes without a second call: the
        // landed reply is part of the scope now, so it would compose anew.
        if ctx.vault.composed_scope_summary_landed(attempt_id)? {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        let plan = ctx
            .vault
            .plan_scope_summary(&attempt.status.payload.input)?;
        // Nothing is spent yet: a scope that cannot be read just refuses.
        let evidence =
            scope_evidence(ctx.vault, &plan.sources).map_err(EvidenceError::into_error)?;
        let Some(first) = evidence.covers.first().copied() else {
            return Err(invalid_consolidation("summary scope has no text"));
        };
        let memo = plan.composition_memo(
            &evidence
                .covers
                .iter()
                .copied()
                .zip(evidence.versions.iter().copied())
                .collect::<Vec<_>>(),
            &evidence.messages,
            &evidence.text,
            &[instruction, self.model.as_str()],
        )?;
        // The same composition already stands: no second call, no second
        // SUMMARY; only the landing this declaration asks for.
        if ctx
            .vault
            .reuse_composed_scope_summary(&plan, &first, &memo)?
        {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        let locality = self
            .inference
            .selected_locality()
            .ok_or_else(|| Error::InvalidConfig("summary host binding needs locality".into()))?;
        let request = LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                // The call reads exactly the versions the Dreamer was admitted
                // to read.
                scope: crate::llm::Scope {
                    readable: evidence.readable.clone(),
                    ..crate::llm::Scope::default()
                },
                // The scope's transcript leaves the vault exactly as an
                // extraction's does, so it passes the same egress gate.
                purpose: CallPurpose::Extraction,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Extraction,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Text,
                locality,
            }
            .with_purpose_defaults(),
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: instruction.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: evidence.text.clone(),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        let request = ctx
            .vault
            .authorize_model_role(
                crate::llm::manifest::ModelRole::ExtractionTeacher,
                request,
                &self.inference,
            )?
            .into_request();
        let step_hash = request
            .canonical_hash()
            .map_err(|_| invalid_consolidation("summary request did not hash"))?;
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: plan.scope.conversation,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let mut charges = StepChargeTally::default();
        let response = match call_as_step(&step_ctx, self.backend, self.guard, request).await {
            Ok(StepOutcome::Finished { response, .. }) => {
                charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)?;
                response
            }
            Ok(StepOutcome::Trapped { .. }) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: "durable step trapped for resume".to_owned(),
                });
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(charges.checkpoint());
            }
            Err(DurableStepError::DeadlineHardCut) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                });
            }
            Err(DurableStepError::FinalizeRefused) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: "wake pass finalize window".to_owned(),
                });
            }
            Err(DurableStepError::Engine(error)) => return Err(error),
            Err(other) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: other.to_string(),
                });
            }
        };
        if ctx.deadline.expired() {
            return Ok(charges.checkpoint());
        }
        let body: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let body = body.trim();
        if body.is_empty() {
            return Ok(charges.park("the model wrote an empty summary"));
        }
        // The body must summarize the text as it stands: an edit while the
        // model wrote sends the declaration round again, soon. The call is
        // paid either way, so every outcome here carries its spend.
        match scope_evidence(ctx.vault, &plan.sources) {
            Ok(now) if now == evidence => {}
            // The Dreamer may no longer read what the body was written from:
            // this declaration ends here.
            Err(EvidenceError::Withheld(error)) => {
                return Ok(charges.park(&format!("summary evidence withheld: {error}")));
            }
            Ok(_) | Err(EvidenceError::Failed(_)) => {
                return Ok(compose_again(&charges, ctx.now_ms));
            }
        }
        let composed = ComposedSummary {
            text: body,
            covers: evidence.covers,
            messages: evidence.messages,
            memo,
        };
        match ctx
            .vault
            .land_composed_scope_summary(attempt_id, &plan, &composed, self.actor)
        {
            Ok(_) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            Err(Error::ConcurrentWrite(_)) => Ok(compose_again(&charges, ctx.now_ms)),
            // A refusal at the landing door (the requester's gate, a landing
            // turn gone) is this declaration's end; the paid call still settles.
            Err(error) => Ok(charges.park(&format!("summary landing refused: {error}"))),
        }
    }
}

/// How long a declaration whose scope moved waits before it composes again.
const SCOPE_DRIFT_RETRY_SECS: u64 = 60;

/// A scope that moved under the model is ordinary progress, not a stop: the
/// attempt keeps its spend and composes again over the scope as it is then.
fn compose_again(charges: &StepChargeTally, now_ms: u64) -> DreamerAttemptExecution {
    DreamerAttemptExecution::Deferred {
        completed_units: charges.units,
        retry_at: now_ms
            .div_ceil(1_000)
            .saturating_add(SCOPE_DRIFT_RETRY_SECS),
    }
}

/// The scope as the Dreamer may read it, read in one snapshot.
#[derive(Debug, Default, PartialEq, Eq)]
struct ScopeEvidence {
    /// One line per covered record, as the model reads it.
    text: String,
    /// The records whose text the model reads: the summary's covers.
    covers: Vec<EntityId>,
    /// Content hash of each covered record's body, in `covers` order.
    versions: Vec<[u8; 32]>,
    /// The MESSAGEs that text came from, at the revisions read.
    messages: Vec<SummarySourceMessage>,
    /// Every record and MESSAGE version read: the model call's read scope.
    readable: BTreeSet<ScopeResource>,
}

/// Why the scope could not be read.
enum EvidenceError {
    /// The Dreamer's read authority withholds a MESSAGE a record's text needs.
    Withheld(Error),
    /// Anything else: the scope moved under the read, or storage failed.
    Failed(Error),
}

impl EvidenceError {
    fn into_error(self) -> Error {
        match self {
            Self::Withheld(error) | Self::Failed(error) => error,
        }
    }
}

/// The sources' text as the Dreamer reads it, one line per record. Every
/// record is read through the Dreamer's own scoped read, inline text
/// included: a record it may not read is neither in the prompt nor covered.
/// The plan's sources never hold an earlier summary's reply, so a summary
/// never feeds on summary prose.
fn scope_evidence(
    vault: &Vault,
    sources: &[EntityId],
) -> std::result::Result<ScopeEvidence, EvidenceError> {
    let read = dreamer_read(vault).map_err(EvidenceError::Failed)?;
    let txn = snapshot(vault).map_err(EvidenceError::Failed)?;
    let rows = read
        .get_entities_parts_in_txn(&txn, sources)
        .map_err(EvidenceError::Failed)?;
    let mut evidence = ScopeEvidence::default();
    for (record, row) in sources.iter().zip(rows) {
        let Some((ENTITY_TYPE_TURN, _, body)) = row else {
            continue;
        };
        let mut withheld = 0;
        let turn = collect_in(&read, &txn, record, &body, &mut withheld).map_err(|error| {
            if withheld == 0 {
                EvidenceError::Failed(error)
            } else {
                EvidenceError::Withheld(error)
            }
        })?;
        let Some(text) = turn.text() else {
            continue;
        };
        evidence
            .text
            .push_str(&format!("[{}] {text}\n", record.to_hex()));
        evidence.covers.push(*record);
        evidence
            .versions
            .push(super::swarm_evidence_content_hash(&body));
        evidence.readable.insert(document_version(*record, &body));
        for (message, revision, version) in turn.message_pins() {
            evidence.messages.push(SummarySourceMessage {
                id: message,
                revision,
            });
            evidence.readable.insert(version.clone());
        }
    }
    evidence.messages.sort_unstable();
    Ok(evidence)
}
