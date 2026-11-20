//! One bound generative extraction step over served TURN spans.
//!
//! A bound job cites only served TURN locators. This module snapshots those
//! locators into a native transcript with native labels, then runs the
//! transcript as one durable extraction generation on the attempt's borrowed
//! role. The snapshot holds in the validation transaction; failure rules load
//! after it, in execution, so a retracted rule never shapes a prepared input.

mod reply;

use std::collections::{BTreeMap, BTreeSet};

use super::TurnText;
use super::call_labels::{CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::extraction_pack::{bound_branch_error, extraction_layout_refusal};
use super::failure_rules::{self, Stage};
use super::neighbourhood::Neighbourhood;
use super::resources::BoundBranchRead;
use super::roles::{DREAMER_EXTRACTION_ROLE, bind_reasoning};
use super::support::invalid_consolidation;
use super::watermark::decode_turn_body;
use crate::claim::ScopedRead;
use crate::dreamer_runner::ExtractionStepLoan;
use crate::entity_id::EntityId;
use crate::memory::{ExtractionLayout, ExtractionStepSlice, MemoryError, MemoryResult};
use crate::snapshot_read::SourceVersion;
use crate::store::model_step_submission::ModelStepResult;
use oneiron_model::llm::Scope;

/// One bound extraction step's checked input, snapshotted in validation.
///
/// The transcript renders exactly one native slice and page over the
/// served words, each TURN under its native body speaker or unknown,
/// with native conversation headers, listing lines and turn labels. The
/// transcript holds no host material; execution prepends the loan's
/// material through the shared helper before the request hashes. The
/// scope is the bound attenuated scope for the cited TURNs under the
/// slice's kept listing. The sources are every row the transcript was
/// read from. The correctable set freezes the listed and speaker Entity
/// ids whose step scope holds a correctable claim. The inputs name the
/// version of every row whose words the transcript shows, so a receipt
/// answers only while each still reads at it. The request also names the
/// label table, each piece's served range and the sources
/// ([`Self::call_inputs`]), and the step's record keeps them. No person-mint
/// namespace binds the request; the decoded reply retains declared persons
/// without minting them.
pub(crate) struct PreparedExtractionStep {
    /// Holds the native transcript over the served words, with labels rendered in.
    transcript: String,
    /// Holds the call labels the transcript assigned, binding the request identity.
    labels: CallLabelMap,
    /// Holds each TURN's served words, start and pinned version.
    pieces: Vec<ExtractionStepPiece>,
    /// Holds the attenuated scope the bound call asks under.
    scope: Scope,
    /// Holds every row the transcript was read from, for the sourced backend.
    sources: Vec<EntityId>,
    /// Holds the listed and speaker Entity ids whose step scope holds
    /// a correctable claim.
    correctable: BTreeSet<EntityId>,
    /// Holds the version of every row whose words the transcript shows,
    /// in id order, as the request names them.
    inputs: Vec<SourceVersion>,
}

impl PreparedExtractionStep {
    /// What this step's call shows beside its words, as its request names it
    /// and its record keeps it: the row behind each label, the served byte
    /// range of each piece in request order, and the sources in id order,
    /// each once.
    fn call_inputs(&self) -> crate::llm::StepCallInputs {
        let sources: BTreeSet<EntityId> = self.sources.iter().copied().collect();
        crate::llm::StepCallInputs {
            labels: self.labels.table(),
            ranges: self
                .pieces
                .iter()
                .map(|piece| crate::llm::StepInputRange {
                    turn: piece.turn,
                    start: piece.start,
                    end: piece.start + piece.text.len() as u64,
                })
                .collect(),
            sources: sources.into_iter().collect(),
        }
    }
}

/// Renders the wake's admitted host material as every extraction input
/// leads with it.
///
/// Each string becomes one `[host material]` line, in order. The
/// material is context for the call, never a turn, so no label names it
/// and nothing cites it. Native slices and the bound step share this
/// helper, so the bound transcript is byte-identical to native's slice
/// transcript including the material lines.
pub(crate) fn render_host_material(material: &[String]) -> String {
    let mut out = String::new();
    for text in material {
        out.push_str("[host material] ");
        out.push_str(text);
        out.push('\n');
    }
    out
}

/// Builds the native slice group key for one TURN: its part line with
/// the known entities it co-mentions.
///
/// Native slices and the bound step group by this key, so a bound cite
/// spans exactly one native slice.
pub(crate) fn slice_group_key(
    known: &Neighbourhood,
    line: u32,
    body: &[u8],
    text: Option<&str>,
) -> (u32, Vec<EntityId>) {
    (line, known.mentioned(body, text))
}

/// Holds the one served piece of a TURN at its checked version.
#[derive(Clone)]
pub(crate) struct ExtractionStepPiece {
    /// Names the TURN whose words were served.
    pub(crate) turn: EntityId,
    /// Holds the first served byte in TURN coordinates.
    pub(crate) start: u64,
    /// Holds exactly the words served for this entry.
    pub(crate) text: String,
    /// Holds the source version checked with the served words.
    pub(crate) version: SourceVersion,
}

/// Snapshots `pieces` into one native slice transcript with native
/// labels and scope.
///
/// Each piece's TURN must be a queued TURN of `bound`, with its declared
/// part conversation. The cited TURNs must form exactly one native
/// slice, grouped by part line and co-mentioned known entities over the
/// frozen TURN texts, and `page` must name one page of that slice's
/// listing when it pages. Each TURN's speaker is its checked native body
/// speaker, or unknown when the body names none, with the source speaker
/// PERSON label beside the role as native shows it. The transcript lists
/// each cited TURN in input order under its conversation header, each
/// named by its turn label, with the selected listing page after the
/// first header. The transcript holds no host material; execution
/// prepends it. The scope is the bound attenuated scope under the
/// slice's kept listing, with the MESSAGE rows behind it. No queue or
/// lineage reads run here; the request binds labels with no person-mint
/// namespace. The inputs name each cited TURN at its checked version and
/// each listed entity, listed claim and membership claim behind a listed
/// relationship as the caller reads it here, `reader_scope` being the
/// caller's grant scope. Failure rules are not loaded here; execution
/// loads them after this snapshot closes.
///
/// # Errors
///
/// A layout refusal with the typed native slices when the cited TURNs
/// span slices or name no valid page, an unlisted TURN, an unreadable
/// TURN body, a wrong TURN type, or the attenuated scope projection's
/// own failures.
pub(crate) fn prepare_bound_step(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    reader_scope: Option<&crate::federation::Scope>,
    bound: &BoundBranchRead,
    pieces: &[ExtractionStepPiece],
    page: Option<usize>,
) -> MemoryResult<PreparedExtractionStep> {
    let cited: Vec<EntityId> = pieces.iter().map(|piece| piece.turn).collect();
    let distinct: BTreeSet<EntityId> = cited.iter().copied().collect();
    let ordered: Vec<EntityId> = distinct.iter().copied().collect();
    let rows = read
        .get_entities_parts_in_txn(txn, &ordered)
        .map_err(bound_branch_error)?;
    let mut speakers: BTreeMap<EntityId, Option<String>> = BTreeMap::new();
    let mut bodies: BTreeMap<EntityId, Vec<u8>> = BTreeMap::new();
    for (turn, row) in ordered.iter().zip(rows) {
        bound
            .turn_conversation(*turn)
            .ok_or_else(|| bound_branch_error(invalid_consolidation("unlisted branch turn")))?;
        let Some((kind, _, body)) = row else {
            return Err(bound_branch_error(invalid_consolidation(
                "branch source is not readable",
            )));
        };
        if kind != crate::registry::ENTITY_TYPE_TURN {
            return Err(bound_branch_error(invalid_consolidation(
                "invalid branch source type",
            )));
        }
        speakers.insert(*turn, decode_turn_body(&body).speaker);
        bodies.insert(*turn, body);
    }
    let mut groups: BTreeMap<(u32, Vec<EntityId>), Vec<usize>> = BTreeMap::new();
    for (index, piece) in pieces.iter().enumerate() {
        let body = bodies
            .get(&piece.turn)
            .ok_or_else(|| bound_branch_error(invalid_consolidation("unlisted branch turn")))?;
        let frozen = bound.turn_text(piece.turn).and_then(TurnText::text);
        let line = bound.turn_line(piece.turn);
        let key = slice_group_key(bound.neighbourhood(), line, body, frozen);
        groups.entry(key).or_default().push(index);
    }
    if groups.len() != 1 {
        let slices = layout_slices(bound, &groups);
        return Err(extraction_layout_refusal(
            format!(
                "an extraction step cites one native slice; the cited TURNs span {} native slices",
                groups.len()
            ),
            ExtractionLayout::StepSlices { slices },
        ));
    }
    let ((_, entities), positions) = groups
        .into_iter()
        .next()
        .ok_or_else(|| bound_branch_error(invalid_consolidation("unlisted branch turn")))?;
    let known = bound.neighbourhood().slice(&entities);
    let pages = known.pages(|id| bound.priors().contains_key(id));
    let page_count = pages.len();
    let selected = match page {
        None if page_count == 1 => 0,
        Some(index) if index < page_count => index,
        _ => {
            let mut evidence = positions;
            evidence.sort_unstable();
            let message = if page.is_none() {
                format!(
                    "an extraction step names its listing page when its slice pages into {page_count} pages"
                )
            } else {
                format!(
                    "an extraction step page must be below its slice page count of {page_count}"
                )
            };
            return Err(extraction_layout_refusal(
                message,
                ExtractionLayout::StepSlices {
                    slices: vec![ExtractionStepSlice {
                        evidence,
                        pages: page_count,
                    }],
                },
            ));
        }
    };
    let scoped = bound
        .extraction_scope(vault, txn, &cited, &known)
        .map_err(bound_branch_error)?;
    let mut labels = CallLabelMap::default();
    let mut transcript = String::new();
    let mut current = None;
    let mut page_rels: Vec<EntityId> = scoped
        .scope
        .relationship
        .iter()
        .flatten()
        .copied()
        .collect();
    if scoped.scope.relationship.is_none() {
        page_rels.extend(pages[selected].member_relationships());
    }
    for (at, piece) in pieces.iter().enumerate() {
        let turn = piece.turn;
        let text = &piece.text;
        let conversation = bound
            .turn_conversation(turn)
            .ok_or_else(|| bound_branch_error(invalid_consolidation("unlisted branch turn")))?;
        if at == 0 || Some(conversation) != current {
            current = Some(conversation);
            let header = labels.assign(LabelKind::Conversation, conversation);
            transcript.push_str(&format!("conversation {header}\n"));
            if at == 0 {
                transcript
                    .push_str(&pages[selected].render(&mut labels, page_rels.iter().copied()));
            }
        }
        let turn_label = labels.assign(LabelKind::Turn, turn);
        let role = speakers
            .get(&turn)
            .and_then(|speaker| speaker.as_deref())
            .unwrap_or("unknown");
        let speaker = bound
            .turn_text(turn)
            .and_then(TurnText::source_speaker)
            .map(|person| format!(" {}", labels.assign(LabelKind::Entity, person)))
            .unwrap_or_default();
        transcript.push_str(&format!("[{turn_label} {role}{speaker}] {text}\n"));
    }
    let mut sources: Vec<EntityId> = labels.rows().collect();
    let mut listed: Vec<EntityId> = labels
        .labelled(LabelKind::Entity)
        .chain(labels.labelled(LabelKind::Claim))
        .map(|(_, id)| id)
        .collect();
    if scoped.scope.relationship.is_none() {
        sources.extend(pages[selected].membership_bindings());
        listed.extend(pages[selected].membership_bindings());
    }
    sources.extend(scoped.message_sources);
    let inputs = step_input_versions(txn, read, reader_scope, pieces, listed)?;
    let correctable: BTreeSet<EntityId> = labels
        .labelled(LabelKind::Entity)
        .map(|(_, id)| id)
        .filter(|id| !bound.correctable(*id, &scoped.scope).is_empty())
        .collect();
    Ok(PreparedExtractionStep {
        transcript,
        labels,
        pieces: pieces.to_vec(),
        scope: scoped.scope,
        sources,
        correctable,
        inputs,
    })
}

/// The version of every row whose words the transcript shows, in id
/// order: each cited TURN at the version its words were checked at, and
/// each `listed` row as the caller reads it now. A listed row that the
/// caller's grant does not reach, or `read` does not serve, showed the
/// caller nothing it may read, so it is not named.
///
/// # Errors
///
/// Storage errors, and a TURN whose text does not project.
fn step_input_versions(
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    reader_scope: Option<&crate::federation::Scope>,
    pieces: &[ExtractionStepPiece],
    listed: Vec<EntityId>,
) -> MemoryResult<Vec<SourceVersion>> {
    let mut versions: BTreeMap<EntityId, SourceVersion> = pieces
        .iter()
        .map(|piece| (piece.turn, piece.version.clone()))
        .collect();
    for id in listed {
        if versions.contains_key(&id)
            || !crate::snapshot_read::observed_claim_reads_in_txn(
                read.vault(),
                txn,
                read,
                reader_scope,
                id,
            )?
        {
            continue;
        }
        if let Some((version, _)) = crate::snapshot_read::source_version_in_txn(read, txn, &id)? {
            versions.insert(id, version);
        }
    }
    Ok(versions.into_values().collect())
}

/// Builds the typed layout rows for `groups` in native key order.
///
/// Each row names its request positions ascending with its slice page count.
fn layout_slices(
    bound: &BoundBranchRead,
    groups: &BTreeMap<(u32, Vec<EntityId>), Vec<usize>>,
) -> Vec<ExtractionStepSlice> {
    groups
        .iter()
        .map(|((_, entities), positions)| {
            let known = bound.neighbourhood().slice(entities);
            let pages = known.pages(|id| bound.priors().contains_key(id));
            let mut evidence = positions.clone();
            evidence.sort_unstable();
            ExtractionStepSlice {
                evidence,
                pages: pages.len(),
            }
        })
        .collect()
}

/// Runs `prepared` as one durable extraction generation on the borrowed role.
///
/// Failure rules load here, after the input snapshot closed. The
/// request is `request_over` in the loan's prompt, the host's words the
/// native pass asks in, with no source rule over the prepared transcript
/// led by the loan's host material through the shared helper, then the
/// labels bound with no person-mint namespace, then the prepared inputs'
/// versions and the call inputs in the host options, then the Extraction rules,
/// then the final Extraction role authorization and reasoning binding.
/// The bound path has no clean-slice loan, extraction-width, or
/// trust-flag equivalent for material; none is invented. The call sends
/// on the sourced backend bound to the
/// prepared sources. The durable execution keeps the standard three transport retries
/// with the original attempt context and guard. The outcome is accounted into
/// the shared tally through the borrowed native helper, with a test
/// observation for the spent generation, before the original outcome moves
/// into the shared request-hash receipt converter. Each submit generates once; a
/// refused reply is paid and not memoized. A finished submit, including a memo
/// resubmit, decodes against these same pieces into the receipt's JSON.
///
/// # Errors
///
/// The role call's missing locality, the role authorization or reasoning
/// binding refusals, the request hash's bad spelling, the tally lock or
/// charge failures, and the shared receipt converter's own failures.
pub(crate) async fn execute_bound_step(
    ctx: &crate::model_step_context::DurableStepContext<'_>,
    prepared: &PreparedExtractionStep,
    loan: &ExtractionStepLoan<'_>,
) -> MemoryResult<crate::llm::model_step::ModelStepReceipt> {
    let rules = failure_rules::load(ctx.vault)?;
    let material = render_host_material(loan.material);
    let transcript = format!("{material}{}", prepared.transcript);
    let mut request = ConsolidationExecutor::request_over(
        &loan.call,
        loan.prompt,
        None,
        transcript,
        &prepared.scope,
    )?;
    prepared.labels.bind_request(&mut request, None);
    crate::llm::bind_step_input_versions(&mut request, &prepared.inputs)?;
    crate::llm::bind_step_call_inputs(&mut request, &prepared.call_inputs())?;
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
    let check = reply::check_bound_reply(prepared);
    let (outcome, unsaved_usage) = crate::llm::call_as_step_checked_with_unsaved_usage(
        ctx,
        backend.get(),
        loan.guard,
        execution_request,
        &check,
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
    let mut receipt =
        crate::llm::request_hash_submit_receipt(ctx.vault, ctx.attempt_id, &request, outcome)?;
    if let Some(ModelStepResult::Finished { response, json, .. }) = receipt.result.as_mut() {
        *json = Some(reply::decode_bound_reply(response, prepared)?);
    }
    Ok(receipt)
}

/// Returns the native slice turns with transcripts for `turns` of
/// `attempt`, in native slice order, for bound-step parity tests.
///
/// The helper prepares the queued attempt the way native extraction
/// does, opens its branch, and slices the given TURNs natively with
/// `material` on the wake, so each transcript leads with the shared
/// material prefix. The wake's listings are read for `destination_bound`,
/// as a driven pass reads them. Tests compare the bound request text against the
/// matching slice transcript, mapping native order to request evidence
/// positions through the turns.
///
/// # Errors
///
/// A missing queue record, an unprepared branch, the branch opening
/// failures, or the native slicing failures.
#[cfg(oneiron_test_support)]
pub(crate) fn native_slice_transcripts_for_test(
    vault: &crate::Vault,
    attempt: crate::attempt_queue::AttemptId,
    turns: &[EntityId],
    material: &[String],
    destination_bound: Option<&crate::settings::ReadDestination>,
) -> MemoryResult<Vec<(Vec<EntityId>, String)>> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let attempt_entity = EntityId::from_bytes(*attempt.as_bytes()).map_err(crate::Error::from)?;
    let (scope, _) =
        crate::snapshot_read::queued_extraction_branch_in_txn(vault, &txn, attempt_entity)?;
    drop(txn);
    let wake = super::wake_plan::PreparedWake::prepare_one_for_bound(
        vault,
        scope,
        attempt,
        destination_bound,
    )
    .map_err(MemoryError::from)?;
    let plan = match wake.preparation(attempt) {
        Some(super::wake_plan::AttemptPreparation::Ready(plan)) => plan.clone(),
        _ => {
            return Err(MemoryError::bad_request(
                "the test attempt prepared no branch",
            ));
        }
    };
    let wake = wake.with_hook_material(material.to_vec());
    let actor = vault.dreamer_authority().map_err(MemoryError::from)?;
    let resources = super::resources::BranchResources::open_prepared(vault, actor, &plan, &wake)
        .map_err(MemoryError::from)?;
    let config = vault.consolidation_selection().map_err(MemoryError::from)?;
    let (slices, _) = resources
        .extraction_slices(turns, config.extraction_turns_per_child)
        .map_err(MemoryError::from)?;
    Ok(slices
        .into_iter()
        .map(|slice| (slice.turns, slice.transcript))
        .collect())
}
