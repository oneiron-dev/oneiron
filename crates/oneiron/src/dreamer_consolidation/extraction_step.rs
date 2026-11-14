//! One bound generative extraction step over served TURN spans.
//!
//! A bound job cites only served TURN locators. This module snapshots those
//! locators into a native transcript with native labels, then runs the
//! transcript as one durable extraction generation on the attempt's borrowed
//! role. The snapshot holds in the validation transaction; failure rules load
//! after it, in execution, so a retracted rule never shapes a prepared input.

use std::collections::{BTreeMap, BTreeSet};

use super::call_labels::{CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::failure_rules::{self, Stage};
use super::resources::BoundBranchRead;
use super::roles::{DREAMER_EXTRACTION_ROLE, bind_reasoning};
use super::support::invalid_consolidation;
use super::watermark::decode_turn_body;
use crate::claim::ScopedRead;
use crate::dreamer_runner::ExtractionStepLoan;
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(oneiron_test_support)]
use crate::memory::MemoryError;
use crate::memory::MemoryResult;
use oneiron_model::llm::Scope;

/// One bound extraction step's checked input, snapshotted in validation.
///
/// The transcript renders only served words, each TURN under its native body
/// speaker or unknown, with native conversation headers and turn labels. The
/// scope is the bound attenuated scope for the cited TURNs. The sources are
/// every row the transcript was read from. No person-mint namespace binds the
/// request; the job output decoding owns declared persons.
pub(crate) struct PreparedExtractionStep {
    /// Holds the native transcript over the served words, with labels rendered in.
    transcript: String,
    /// Holds the call labels the transcript assigned, binding the request identity.
    labels: CallLabelMap,
    /// Holds the attenuated scope the bound call asks under.
    scope: Scope,
    /// Holds every row the transcript was read from, for the sourced backend.
    sources: Vec<EntityId>,
}

/// Snapshots `words` into a native transcript with native labels and scope.
///
/// Each word's TURN must be a queued TURN of `bound`, with its declared part
/// conversation. Each TURN's speaker is its checked native body speaker, or
/// unknown when the body names none. The transcript lists each cited TURN in
/// input order under its conversation header, each named by its turn label.
/// The scope is the bound attenuated scope for the cited TURNs, with the
/// MESSAGE rows behind it. No queue or lineage reads run here; the request
/// binds labels with no person-mint namespace. Failure rules are not loaded
/// here; execution loads them after this snapshot closes.
///
/// # Errors
///
/// An unlisted TURN, an unreadable TURN body, a wrong TURN type, or the
/// attenuated scope projection's own failures.
pub(crate) fn prepare_bound_step(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    bound: &BoundBranchRead,
    words: &[(EntityId, String)],
) -> Result<PreparedExtractionStep> {
    let cited: Vec<EntityId> = words.iter().map(|(turn, _)| *turn).collect();
    let scoped = bound.extraction_scope(vault, txn, &cited)?;
    let distinct: BTreeSet<EntityId> = cited.iter().copied().collect();
    let ordered: Vec<EntityId> = distinct.iter().copied().collect();
    let rows = read.get_entities_parts_in_txn(txn, &ordered)?;
    let mut speakers = BTreeMap::new();
    for (turn, row) in ordered.iter().zip(rows) {
        bound
            .turn_conversation(*turn)
            .ok_or_else(|| invalid_consolidation("unlisted branch turn"))?;
        let Some((kind, _, body)) = row else {
            return Err(invalid_consolidation("branch source is not readable"));
        };
        if kind != crate::registry::ENTITY_TYPE_TURN {
            return Err(invalid_consolidation("invalid branch source type"));
        }
        speakers.insert(*turn, decode_turn_body(&body).speaker);
    }
    let mut labels = CallLabelMap::default();
    let mut transcript = String::new();
    let mut current = None;
    for (at, (turn, text)) in words.iter().enumerate() {
        let conversation = bound
            .turn_conversation(*turn)
            .ok_or_else(|| invalid_consolidation("unlisted branch turn"))?;
        if at == 0 || Some(conversation) != current {
            current = Some(conversation);
            let header = labels.assign(LabelKind::Conversation, conversation);
            transcript.push_str(&format!("conversation {header}\n"));
        }
        let turn_label = labels.assign(LabelKind::Turn, *turn);
        let speaker = speakers
            .get(turn)
            .and_then(|speaker| speaker.as_deref())
            .unwrap_or("unknown");
        transcript.push_str(&format!("[{turn_label} {speaker}] {text}\n"));
    }
    let mut sources: Vec<EntityId> = labels.rows().collect();
    sources.extend(scoped.message_sources);
    Ok(PreparedExtractionStep {
        transcript,
        labels,
        scope: scoped.scope,
        sources,
    })
}

/// Runs `prepared` as one durable extraction generation on the borrowed role.
///
/// Failure rules load here, after the input snapshot closed. The request is
/// the shipped `request_over` with no source rule over the prepared
/// transcript, then the labels bound with no person-mint namespace, then the
/// Extraction rules, then the final Extraction role authorization and
/// reasoning binding. The call sends on the sourced backend bound to the
/// prepared sources. The durable execution uses the standard three retries
/// with the original attempt context and guard. The outcome is accounted into
/// the shared tally through the borrowed native helper, with a test
/// observation for the spent generation, before the original outcome moves
/// into the shared request-hash receipt converter.
///
/// # Errors
///
/// The shipped prompt's unreadability, the role authorization or reasoning
/// binding refusals, the request hash's bad spelling, the tally lock or
/// charge failures, and the shared receipt converter's own failures.
pub(crate) async fn execute_bound_step(
    ctx: &crate::model_step_context::DurableStepContext<'_>,
    prepared: &PreparedExtractionStep,
    loan: &ExtractionStepLoan<'_>,
) -> MemoryResult<crate::llm::model_step::ModelStepReceipt> {
    let rules = failure_rules::load(ctx.vault)?;
    let mut request = ConsolidationExecutor::request_over(
        &loan.call,
        None,
        prepared.transcript.clone(),
        &prepared.scope,
    )?;
    prepared.labels.bind_request(&mut request, None);
    if let Some(rules) = rules.as_ref() {
        rules.bind(Stage::Extraction, &mut request);
    }
    let mut request = ctx
        .vault
        .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &loan.call.inference)?
        .into_request();
    bind_reasoning(ctx.vault, loan.call.backend, &mut request)?;
    let backend = loan.call.call_backend(Some(prepared.sources.clone()));
    #[cfg(oneiron_test_support)]
    let request_hash = request
        .canonical_hash()
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let execution_request = request.clone();
    let (outcome, unsaved_usage) = crate::llm::call_as_step_with_unsaved_usage(
        ctx,
        backend.get(),
        loan.guard,
        execution_request,
    )
    .await;
    {
        let mut charges = loan
            .charges
            .lock()
            .map_err(|_| crate::error::Error::InvariantViolation("extraction charge tally lock"))?;
        super::step_charge::charge_borrowed_slice_outcome(
            ctx.vault,
            &outcome,
            unsaved_usage.as_ref(),
            &mut charges,
        )?;
        #[cfg(oneiron_test_support)]
        {
            let observed = match &outcome {
                Ok(crate::model_step_context::StepOutcome::Finished {
                    binding,
                    response,
                    memoized,
                    ..
                }) => Some(super::step_charge::SpentObservation {
                    hash: request_hash,
                    usage: response.usage.clone(),
                    binding: Some(*binding),
                    memoized: *memoized,
                }),
                Ok(crate::model_step_context::StepOutcome::Trapped { .. }) => None,
                Err(error) => {
                    if let Some(usage) = error.spent_usage() {
                        Some(super::step_charge::SpentObservation {
                            hash: request_hash,
                            usage: usage.clone(),
                            binding: None,
                            memoized: false,
                        })
                    } else if let Some(usage) = unsaved_usage.as_ref() {
                        Some(super::step_charge::SpentObservation {
                            hash: request_hash,
                            usage: (*usage).clone(),
                            binding: None,
                            memoized: false,
                        })
                    } else {
                        None
                    }
                }
            };
            if let Some(observation) = observed {
                charges.spent_observations.push(observation);
            }
        }
    }
    crate::llm::request_hash_submit_receipt(ctx.vault, ctx.attempt_id, &request, outcome)
}
