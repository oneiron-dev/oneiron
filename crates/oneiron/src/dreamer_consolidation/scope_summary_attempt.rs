//! The Dreamer writes a declared scope summary's body (ARCH-0006a).
//!
//! A caller declares the scope through [`Vault::request_scope_summary`]; this
//! arm reads the covered records, asks the Dreamer's model with the host's
//! summary instruction, and lands the body under the Dreamer's byline. The
//! instruction is host configuration: the engine ships no summary prompt.

use super::residency::{residency_deferral, waits_on_residency};
use super::resources::document_version;
use super::step_charge::StepChargeTally;
use super::support::{DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE, invalid_consolidation};
use super::turn_text::{TurnText, collect_in, dreamer_read};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, DreamerAttemptExecutor,
    WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelId, ModelTierRef, ResponseFormat, ScopeResource, StepOutcome, TierPrecedence,
    call_as_step_checked,
};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_NOTE, ENTITY_TYPE_TURN};
use crate::scope_summary::{
    ComposedSummary, ScopeSummaryPlan, SummarySourceMessage, SummarySourceVersion,
};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

mod chunks;
mod output;

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
    /// The tokens one call's input may fill on `model`, as the host counts
    /// them (FIX 7509 P7b); `None` reads the vault's own row for the model.
    window_tokens: Option<u64>,
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
            window_tokens: None,
        }
    }

    /// The tokens one call's input may fill on the model, lent by the host
    /// (FIX 7509 P7b): a sitting too big for one call pages its TURNs to it.
    #[must_use]
    pub fn with_window_tokens(mut self, window_tokens: Option<u64>) -> Self {
        self.window_tokens = window_tokens;
        self
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
        // A source TURN partly away from this replica (OF-534) is owed: the
        // declaration waits, queued, for the promotion (FIX 3861).
        let (plan, evidence) = match ctx.vault.plan_scope_summary(&attempt.status.payload.input) {
            Ok(planned) => planned,
            Err(error) if waits_on_residency(&error) => {
                return Ok(residency_deferral(ctx.now_ms, 0));
            }
            Err(error) => return Err(error),
        };
        // FIX 4465 B: an epoch keyframe is its writer's own words, an agent's
        // first person when it wrote as itself. A third-person summary is
        // composed beside it under the Dreamer's byline and never takes it
        // as the editor text it revises.
        if let Some(previous) = plan.previous
            && crate::compaction::is_epoch_summary(ctx.vault, &previous)?
        {
            return Err(invalid_consolidation(
                "an epoch summary is never a scope summary's editor text",
            ));
        }
        // A NOTE review's topic summary the topic's group outgrew completes
        // without composing (Engine 10-21, option A): the larger group's
        // own declaration composes it.
        if plan.scope.is_none()
            && super::note_topics::note_topic_summary_outgrown(
                ctx.vault,
                attempt,
                plan.requester,
                &plan.sources,
            )
        {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        let Some(first) = evidence.covers.first().copied() else {
            // A sitting that retained no text has no summary (FIX 7509): its
            // attempt completes with none, never with invented prose.
            if plan.session.is_some() {
                return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
            }
            return Err(invalid_consolidation("summary scope has no text"));
        };
        // A sitting's lines cite its TURNs by the labels its evidence showed
        // (FIX 7509).
        let labels = plan.session.map(|_| output::turn_labels(&evidence.covers));
        // The host supplies the instruction. The typed output contract makes
        // the Dreamer distill editor wants into `keep` alongside its prose.
        let schema = if labels.is_some() {
            output::session_schema()
        } else {
            serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["text", "keep"],
                "properties": {"text": {"type": "string"}, "keep": {"type": "string"}}
            })
        };
        // A sitting too big for one call on its model's known window pages
        // its TURNs (FIX 7509 P7b, Rule 5); one that fits, or whose window
        // is unknown, is the one call below, byte for byte.
        if labels.is_some()
            && let Some(window) = self.session_window(ctx.vault)
            && chunks::framed_tokens(instruction, &summary_input(&plan, &evidence.text)?, &schema)?
                > window
        {
            return self
                .compose_pages(attempt, ctx, &plan, &evidence, instruction, window)
                .await;
        }
        let params = serde_json::to_vec(&(instruction, self.model.as_str(), &schema))
            .map_err(|_| invalid_consolidation("summary policy did not encode"))?;
        let params_hash = *blake3::hash(&params).as_bytes();
        let memo = plan.composition_memo(&evidence, &params_hash)?;
        // The same composition already stands: no second call, no second
        // SUMMARY; only the landing this declaration asks for.
        match ctx.vault.reuse_composed_scope_summary(
            attempt_id,
            &plan,
            &evidence,
            &first,
            &memo,
            &params_hash,
        ) {
            Ok(true) => return Ok(DreamerAttemptExecution::Completed { completed_units: 0 }),
            Ok(false) => {}
            Err(error) if waits_on_residency(&error) => {
                return Ok(residency_deferral(ctx.now_ms, 0));
            }
            Err(error) => return Err(error),
        }
        let request = self.summary_request(
            ctx.vault,
            &evidence,
            schema,
            instruction,
            summary_input(&plan, &evidence.text)?,
        )?;
        let step_hash = request
            .canonical_hash()
            .map_err(|_| invalid_consolidation("summary request did not hash"))?;
        // A NOTE set's summary is in no conversation: its step is about the
        // first NOTE whose text it reads (FIX 5757).
        let subject = match &plan.scope {
            Some(scope) => scope.conversation,
            None => first,
        };
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let mut charges = StepChargeTally::default();
        // The reply answers to the summary contract inside the step (FIX
        // 7272): the schema's door first, then the parse the landing uses.
        let check_labels = labels.clone();
        let check = move |response: &LlmResponse| match &check_labels {
            Some(labels) => output::session_output(response, labels)
                .map(drop)
                .map_err(str::to_owned),
            None => check_summary_reply(response),
        };
        let response = match call_as_step_checked(
            &step_ctx,
            self.backend,
            self.guard,
            request,
            &check,
        )
        .await
        {
            Ok(StepOutcome::Finished { response, .. }) => {
                charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)?;
                response
            }
            Ok(StepOutcome::Trapped { .. }) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: "durable step trapped for resume".to_owned(),
                    cause: DreamerParkCause::Signal,
                });
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(charges.checkpoint());
            }
            Err(DurableStepError::DeadlineHardCut) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                    cause: DreamerParkCause::Checkpoint,
                });
            }
            Err(DurableStepError::FinalizeRefused) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: "wake pass finalize window".to_owned(),
                    cause: DreamerParkCause::Checkpoint,
                });
            }
            Err(DurableStepError::Engine(error)) => return Err(error),
            // A reply the schema door or the summary check refused was paid
            // and never memoized: it is asked again after its retry delay
            // (FIX 7272, Engine 10-21).
            Err(other @ DurableStepError::SpentSchemaValidation { .. }) => {
                if let DurableStepError::SpentSchemaValidation { usage, .. } = &other {
                    charges.record_usage(usage);
                }
                return Ok(charges.park_for(&other.to_string(), DreamerParkCause::Retry));
            }
            // Parks Retry unless only an owner act clears it (FIX 7369).
            Err(other) => {
                return Ok(DreamerAttemptExecution::Park {
                    reason: other.to_string(),
                    cause: DreamerParkCause::of_step(&other),
                });
            }
        };
        if ctx.deadline.expired() {
            return Ok(charges.checkpoint());
        }
        // The step's check already admitted this reply; a memo stored before
        // the check existed still answers to the same parse here.
        let (text, keep, line_sources) = match &labels {
            Some(labels) => match output::session_output(&response, labels) {
                Ok(lines) => (lines.text, lines.keep, Some(lines.line_sources)),
                Err(reason) => return Ok(charges.park_for(reason, DreamerParkCause::Retry)),
            },
            None => match summary_output(&response) {
                Ok(summary) => (summary.text.trim().to_owned(), summary.keep, None),
                Err(reason) => return Ok(charges.park_for(reason, DreamerParkCause::Retry)),
            },
        };
        let composed = ComposedSummary {
            text: &text,
            keep: &keep,
            params_hash,
            instruction,
            model: self.model.as_str(),
            covers: evidence.covers.clone(),
            messages: evidence.messages.clone(),
            memo,
            line_sources,
        };
        match ctx
            .vault
            .land_composed_scope_summary(attempt_id, &plan, &evidence, &composed, self.actor)
        {
            Ok(_) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            Err(Error::ConcurrentWrite(_)) => Ok(compose_again(&charges, ctx.now_ms)),
            // A source demoted while the model wrote waits for its promotion,
            // the paid call settled, as a moved scope composes again.
            Err(error) if waits_on_residency(&error) => {
                Ok(residency_deferral(ctx.now_ms, charges.units))
            }
            // A refusal at the landing door (the requester's gate, a landing
            // turn gone) is this declaration's end; the paid call still settles.
            Err(error) => Ok(charges.park(&format!("summary landing refused: {error}"))),
        }
    }

    /// The summary call reading `user` under the host's `instruction`, in
    /// the envelope every summary call goes out in: exactly the versions
    /// `evidence` pins readable, authorized for the narrative role, its
    /// reasoning bound.
    fn summary_request(
        &self,
        vault: &Vault,
        evidence: &ScopeSummaryEvidence,
        schema: serde_json::Value,
        instruction: &str,
        user: String,
    ) -> Result<LlmRequest> {
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
                response_format: ResponseFormat::Json { schema },
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
                    content: vec![ContentPart::Text { text: user }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        let mut request = vault
            .authorize_model_role(super::DREAMER_NARRATIVE_ROLE, request, &self.inference)?
            .into_request();
        super::roles::bind_reasoning(vault, self.backend, &mut request)?;
        Ok(request)
    }
}

/// The input one summary call reads: the declaration's purpose, the editor's
/// `keep`, the body it revises and the `records`, as one JSON object.
fn summary_input(plan: &ScopeSummaryPlan, records: &str) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "purpose": plan.purpose,
        "keep": plan.keep,
        "editor_text": plan.editor_text,
        "records": records,
    }))
    .map_err(|_| invalid_consolidation("summary input encoding"))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryOutput {
    text: String,
    keep: String,
}

/// The reply's summary, or the static reason it is none: its text parts
/// parse as [`SummaryOutput`] and the summary text is not blank. The step's
/// check and the landing both read the reply through this one parse.
fn summary_output(response: &LlmResponse) -> std::result::Result<SummaryOutput, &'static str> {
    let body = output::reply_text(response);
    let output: SummaryOutput = serde_json::from_str(body.trim())
        .map_err(|_| "the model wrote an invalid summary/keep result")?;
    if output.text.trim().is_empty() {
        return Err("the model wrote an empty summary");
    }
    Ok(output)
}

/// The summary step's reply check: a reply [`summary_output`] refuses is
/// refused inside the step, paid and never memoized.
fn check_summary_reply(response: &LlmResponse) -> std::result::Result<(), String> {
    summary_output(response).map(drop).map_err(str::to_owned)
}

/// All evidence and authority-dependent text pins, collected in one snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ScopeSummaryEvidence {
    pub(crate) text: String,
    pub(crate) covers: Vec<EntityId>,
    pub(crate) messages: Vec<SummarySourceMessage>,
    pub(crate) source_versions: Vec<SummarySourceVersion>,
    readable: BTreeSet<ScopeResource>,
    /// A sitting's TURNs as read, one beside each of `covers` (FIX 7509
    /// P7b): the text a sitting too big for one call pages. Empty for every
    /// other target.
    turns: Vec<(EntityId, TurnText)>,
}

impl ScopeSummaryEvidence {
    pub(crate) fn fingerprint(&self) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(&(&self.source_versions, &self.text))
            .map_err(|_| invalid_consolidation("summary evidence did not hash"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

fn source_pin(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    row: Option<&(u8, u64, Vec<u8>)>,
) -> Result<SummarySourceVersion> {
    Ok(SummarySourceVersion {
        id: id.to_hex(),
        entity_type: row.map(|row| row.0),
        learned_at: row.map(|row| row.1),
        revision: row.map(|row| super::swarm_evidence_content_hash(&row.2)),
        record_hash: if row.is_some() {
            vault
                .store
                .port_entity_raw(txn, &id)?
                .map(|raw| *blake3::hash(&raw).as_bytes())
        } else {
            None
        },
        frontier: if row.is_some() {
            crate::entity_doc::source_frontier_in_txn(&vault.store, txn, &id)?
        } else {
            None
        },
        projected_text: None,
    })
}

/// Reads through the Dreamer's own scoped read, including every child of a
/// witnessed turn. It is also the landing fence, under the landing writer.
/// A sitting's TURNs (`labelled`, FIX 7509) are shown under the labels the
/// engine mints for the call, in source order, which its lines cite; every
/// other TURN under its id.
pub(crate) fn scope_summary_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
    labelled: bool,
) -> Result<ScopeSummaryEvidence> {
    let read = dreamer_read(vault)?;
    let rows = read.get_entities_parts_in_txn(txn, sources)?;
    let mut evidence = ScopeSummaryEvidence::default();
    for (record, row) in sources.iter().zip(rows) {
        let mut pin = source_pin(vault, txn, *record, row.as_ref())?;
        // A NOTE reads as the Dreamer's one NOTE projection (FIX 907): its
        // admitted text, pinned by the projection's fingerprint beside the
        // row, its frontier and the policy the plan pins.
        if let Some((ENTITY_TYPE_NOTE, _, body)) = &row {
            if let Some(note) = super::note_text::note_text_in(vault, txn, record, body)? {
                pin.projected_text = Some(note.fingerprint);
                evidence
                    .text
                    .push_str(&format!("[{}] {}\n", record.to_hex(), note.text));
                evidence.covers.push(*record);
                evidence.readable.insert(note.version);
            }
            evidence.source_versions.push(pin);
            continue;
        }
        let Some((ENTITY_TYPE_TURN, _, body)) = row else {
            evidence.source_versions.push(pin);
            continue;
        };
        let turn = collect_in(&read, txn, record, &body, &mut 0)?;
        pin.projected_text = Some(turn.summary_fingerprint()?);
        evidence.source_versions.push(pin);
        let Some(text) = turn.text() else {
            continue;
        };
        let label = if labelled {
            output::turn_label(evidence.covers.len())
        } else {
            record.to_hex()
        };
        evidence.text.push_str(&format!("[{label}] {text}\n"));
        evidence.covers.push(*record);
        if labelled {
            evidence.turns.push((*record, turn.clone()));
        }
        evidence.readable.insert(document_version(*record, &body));
        for (message, revision, version) in turn.message_pins() {
            evidence.messages.push(SummarySourceMessage {
                id: message,
                revision,
            });
            evidence.readable.insert(version.clone());
            // The child pin includes its exact stored row and frontier as
            // well as the TURN's authorship/finality/child-set fingerprint.
            let message_row = read
                .get_entities_parts_in_txn(txn, &[message])?
                .pop()
                .flatten();
            evidence
                .source_versions
                .push(source_pin(vault, txn, message, message_row.as_ref())?);
        }
    }
    evidence.messages.sort_unstable();
    evidence.messages.dedup();
    Ok(evidence)
}
