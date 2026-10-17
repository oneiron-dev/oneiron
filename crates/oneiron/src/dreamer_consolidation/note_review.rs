//! ARCH-0032 stage 2 (OF-073): the Dreamer reviews NOTEs. A Nightly child
//! pages through the vault's NOTEs, reads each one the Dreamer may read
//! whose kind allows extraction, asks the extraction role which beliefs the
//! note grounds, and promotes them through the promotion gate. Every belief
//! cites byte ranges of the exact markdown read, so a model cannot ground a
//! belief in text the note does not hold. A NOTE whose markdown has not
//! changed since its last review is not read again.
//!
//! Each review records its verdict on the NOTE, the stage-2 classification
//! (Engine ruling C, 10-17): `promote` when the model rates the note's
//! importance at least [`PROMOTE_IMPORTANCE`], else `extract` when it
//! grounded a belief, else `skip`. A NOTE's kind, privacy and write policy
//! stay as born; the review never re-kinds one.
//!
//! A NOTE whose kind extracts after the seal is read once it is sealed (the
//! one NOTE seal, `note/lifecycle.rs`). A sealed scratchpad is read through
//! its marks (ARCH-0032 #scratchpad-marks): its `scratch` lines are blanked
//! before the model reads it, each `keep` line is asked for, and every other
//! line is the model's to decide.

use std::collections::BTreeSet;

use rmpv::Value;

use super::evidence::EvidenceLocator;
use super::executor::ConsolidationExecutor;
use super::executor::extraction::{
    check_extraction_reply, decode_model_locator, entity_id_from_hex, extraction_reply,
};
use super::provenance::PromotionCandidate;
use super::roles::DREAMER_EXTRACTION_ROLE;
use super::step_charge::StepChargeTally;
use super::support::{SCOPE_PROJECT_KEY, TURN_BODY_FACET_REF_KEY, invalid_consolidation};
use super::value_projection::json_to_rmpv;
use crate::claim::{ClaimSource, ClaimSubject, ScopedRead};
use crate::dreamer_promotion::{DreamerRunContext, promote_consolidated_claims};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{
    DurableStepContext, DurableStepError, ScopeResource, StepOutcome, call_as_step_checked,
};
use crate::note::ExtractionDefault;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, Result, Vault};

const CURSOR: SideTable<(), EntityId, Named> =
    SideTable::new(&side_table::DREAMER_NOTE_REVIEW_CURSOR);
const SEEN: SideTable<EntityId, NoteReviewRecord, Named> =
    SideTable::new(&side_table::DREAMER_NOTE_REVIEW_SEEN);
/// The importance at which a note's verdict is `promote` (ARCH-0032
/// `dr:P16`: a scratchpad item promotes at `importance >= 0.75`).
const PROMOTE_IMPORTANCE: f64 = 0.75;

/// The review's verdict on one NOTE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum NoteVerdict {
    /// The note grounded at least one belief.
    Extract,
    /// Nothing in it is worth keeping.
    Skip,
    /// The note itself matters to keep.
    Promote,
}

/// What the last review of one NOTE read and decided.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct NoteReviewRecord {
    /// BLAKE3 of the markdown read: an unchanged NOTE is not read again.
    fingerprint: [u8; 32],
    verdict: NoteVerdict,
    /// The model's importance for the note itself, 0 to 1, when it gave one.
    importance: Option<f64>,
}
/// NOTEs per page. The cursor moves a page at a time, so a review cut by
/// its deadline resumes where it stopped.
const PAGE: usize = 32;

/// One NOTE the review reads: its live markdown, the version the request
/// pins, and the scope stamps its beliefs inherit.
struct Note {
    id: EntityId,
    markdown: String,
    /// A sealed scratchpad's review: whether a line is marked `keep`.
    sealed_pad: Option<bool>,
    fingerprint: [u8; 32],
    facet: EntityId,
    project: EntityId,
    version: ScopeResource,
}

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_note_review(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.scope.is_some() {
            return Err(invalid_consolidation("the NOTE review has no branch scope"));
        }
        let attempt_id = attempt.status.attempt.id;
        let run = DreamerRunContext {
            run_id: attempt
                .status
                .attempt
                .run_id
                .clone()
                .unwrap_or_else(|| bytes_to_hex_lower(attempt_id.as_bytes())),
            attempt_id,
            agent_actor: self.actor,
            now_ms: ctx.now_ms,
        };
        // A kind whose extraction default is Allowed is read. An AfterSeal
        // kind is read once its NOTE is sealed. A diary stays private
        // strategy, and a Disabled kind is never read.
        let kinds = ctx.vault.note_kind_descriptors()?;
        let of = |default: ExtractionDefault| -> BTreeSet<String> {
            kinds
                .iter()
                .filter(|kind| kind.extraction == default)
                .map(|kind| kind.kind.clone())
                .collect()
        };
        let allowed = of(ExtractionDefault::Allowed);
        let after_seal = of(ExtractionDefault::AfterSeal);
        let read = super::turn_text::dreamer_read(ctx.vault)?;
        let mut charges = StepChargeTally::default();
        loop {
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            let after = {
                let txn = ctx.vault.store.env.read_txn()?;
                CURSOR.get(&ctx.vault.store, &txn, &())?
            };
            let page = ctx
                .vault
                .entities_by_type_page(ENTITY_TYPE_NOTE, after.as_ref(), PAGE)?;
            for note in readable_notes(ctx.vault, &read, &page, &allowed, &after_seal)? {
                if let Some(stop) = self
                    .review_note(attempt, ctx, &run, &note, &mut charges)
                    .await?
                {
                    return Ok(stop);
                }
            }
            let full = page.len() == PAGE;
            ctx.vault
                .with_write_txn_grouped(|txn| match page.last().filter(|_| full) {
                    Some(last) => CURSOR.put(&ctx.vault.store, txn, &(), last),
                    None => CURSOR.delete(&ctx.vault.store, txn, &()).map(|_| ()),
                })?;
            if !full {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: charges.units,
                });
            }
        }
    }

    /// Reviews one NOTE. `Some` is the attempt's stop (a park or a
    /// checkpoint); `None` means this NOTE is done and the review goes on.
    async fn review_note(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        run: &DreamerRunContext,
        note: &Note,
        charges: &mut StepChargeTally,
    ) -> Result<Option<DreamerAttemptExecution>> {
        let call = self.role(DREAMER_EXTRACTION_ROLE);
        let mut scope = crate::llm::Scope::default();
        scope.project = Some(note.project);
        scope.readable.insert(note.version.clone());
        let request =
            match Self::note_request(&call, note.id, &note.markdown, note.sealed_pad, &scope) {
                Ok(request) => request,
                Err(error) => return Ok(Some(charges.park(&error.to_string()))),
            };
        let mut request =
            match ctx
                .vault
                .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &call.inference)
            {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(Some(charges.park(&error.to_string()))),
            };
        if let Err(error) = super::roles::bind_reasoning(ctx.vault, call.backend, &mut request) {
            return Ok(Some(charges.park(&error.to_string())));
        }
        let Ok(hash) = request.canonical_hash() else {
            return Ok(Some(charges.park("note review request hash failed")));
        };
        let step = DurableStepContext {
            vault: ctx.vault,
            attempt_id: run.attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: note.id,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let response = match call_as_step_checked(
            &step,
            call.backend,
            self.guard,
            request,
            &check_extraction_reply,
        )
        .await
        {
            Ok(StepOutcome::Finished {
                response,
                failure_policy,
                ..
            }) => {
                charges.record_terminal(ctx.vault, run.attempt_id, hash, &response.usage)?;
                // A fallback reply is no review: the NOTE stays unseen, so
                // the next pass asks the model again.
                if failure_policy.is_some() {
                    return Ok(Some(charges.park("note review needs the extraction model")));
                }
                response
            }
            Ok(StepOutcome::Trapped { .. }) => {
                return Ok(Some(charges.park_for(
                    "durable step trapped for resume",
                    DreamerParkCause::Signal,
                )));
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(Some(charges.checkpoint()));
            }
            Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                charges.record_usage(&usage);
                return Ok(Some(charges.park(&format!(
                    "note review reply refused: {}",
                    errors.join("; ")
                ))));
            }
            Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
                return Ok(Some(charges.checkpoint()));
            }
            Err(error) => {
                return Ok(Some(
                    charges.park_for(&error.to_string(), DreamerParkCause::of_step(&error)),
                ));
            }
        };
        if ctx.deadline.expired() {
            return Ok(Some(charges.checkpoint()));
        }
        let reply = match extraction_reply(&response) {
            Ok(reply) => reply,
            Err(error) => return Ok(Some(charges.park(&error.to_string()))),
        };
        let importance = reply
            .importance
            .as_ref()
            .and_then(serde_json::Value::as_f64)
            .filter(|importance| (0.0..=1.0).contains(importance));
        let mut candidates = Vec::new();
        for item in &reply.candidates {
            match note_candidate(item, note, run) {
                Ok(candidate) => candidates.push(candidate),
                Err(reason) => tracing::warn!(
                    target: "oneiron::dreamer",
                    %reason,
                    note = %note.id.to_hex(),
                    "note review candidate not written"
                ),
            }
        }
        let verdict = if importance.is_some_and(|importance| importance >= PROMOTE_IMPORTANCE) {
            NoteVerdict::Promote
        } else if candidates.is_empty() {
            NoteVerdict::Skip
        } else {
            NoteVerdict::Extract
        };
        if !candidates.is_empty() {
            // A refusal is the gate's answer about one belief (a persona
            // belief, say, needs turns from two sessions), never a reason
            // to read the NOTE again.
            let outcome = promote_consolidated_claims(ctx.vault, run, candidates)?;
            for (claim, reason) in &outcome.rejected {
                tracing::info!(
                    target: "oneiron::dreamer",
                    claim = %claim.to_hex(),
                    %reason,
                    "note review belief not promoted"
                );
            }
        }
        ctx.vault.with_write_txn_grouped(|txn| {
            SEEN.put(
                &ctx.vault.store,
                txn,
                &note.id,
                &NoteReviewRecord {
                    fingerprint: note.fingerprint,
                    verdict,
                    importance,
                },
            )
        })?;
        Ok(None)
    }
}

/// The NOTEs on `page` the review reads: live and readable by the Dreamer,
/// of an Allowed kind or a sealed NOTE of an AfterSeal kind (a sealed pad
/// read through its line marks), changed since their last review, and with a
/// birth facet and one project for their beliefs. Anything else is skipped,
/// never widened.
fn readable_notes(
    vault: &Vault,
    read: &ScopedRead<'_>,
    page: &[EntityId],
    allowed: &BTreeSet<String>,
    after_seal: &BTreeSet<String>,
) -> Result<Vec<Note>> {
    let txn = super::turn_text::snapshot(vault)?;
    let mut notes = Vec::new();
    for id in page {
        let Ok(mut parts) = read.get_entities_parts_in_txn(&txn, std::slice::from_ref(id)) else {
            continue;
        };
        let Some((kind, _, body)) = parts.pop().flatten() else {
            continue;
        };
        if kind != ENTITY_TYPE_NOTE {
            continue;
        }
        let Ok(decoded) = crate::note::decode_note_body_in_txn(&vault.store, &txn, &body) else {
            continue;
        };
        let kind_name = decoded.kind.as_str();
        let (markdown, sealed_pad) = if allowed.contains(kind_name.as_ref()) {
            (decoded.markdown.clone(), None)
        } else if after_seal.contains(kind_name.as_ref())
            && crate::note::note_sealed_in_txn(&vault.store, &txn, *id)?
        {
            if vault.scratchpad_sealed_in_txn(&txn, *id)? {
                let (text, keep) = crate::context_board::sealed_pad_review_text(&decoded.markdown);
                (text, Some(keep))
            } else {
                (decoded.markdown.clone(), None)
            }
        } else {
            continue;
        };
        if markdown.trim().is_empty() {
            continue;
        }
        let fingerprint = *blake3::hash(decoded.markdown.as_bytes()).as_bytes();
        if SEEN
            .get(&vault.store, &txn, id)?
            .is_some_and(|seen| seen.fingerprint == fingerprint)
        {
            continue;
        }
        let Some(facet) = crate::federation::record_scope::birth_facet(&vault.store, &txn, *id)?
        else {
            continue;
        };
        let Some(project) = super::resources::stored_project(&vault.store, &txn, *id, kind, &body)?
        else {
            continue;
        };
        notes.push(Note {
            id: *id,
            version: super::resources::document_version(*id, &body),
            markdown,
            sealed_pad,
            fingerprint,
            facet,
            project,
        });
    }
    Ok(notes)
}

/// One reply candidate as a belief `note` grounds, or why it is not
/// written. Every evidence ref must be a byte range of the note's markdown
/// on character boundaries. A candidate citing anything else, or naming a
/// correction or a relationship, is skipped: the review holds no prior head
/// and a NOTE carries no relationship.
fn note_candidate(
    item: &serde_json::Value,
    note: &Note,
    run: &DreamerRunContext,
) -> Result<PromotionCandidate> {
    let named = |field: &str| item.get(field).is_some_and(|value| !value.is_null());
    if named("corrects") || named("rel") {
        return Err(invalid_consolidation(
            "a note review holds no prior head or relationship",
        ));
    }
    let subject = item
        .get("subject")
        .and_then(serde_json::Value::as_str)
        .and_then(entity_id_from_hex)
        .ok_or_else(|| invalid_consolidation("note candidate names no subject"))?;
    let predicate = item
        .get("predicate")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_consolidation("note candidate names no predicate"))?;
    crate::claim::validate_predicate(predicate, false).map_err(|_| {
        invalid_consolidation("note candidate's predicate breaks the claim grammar")
    })?;
    let value = match item.get("value") {
        Some(value) if !value.is_null() => json_to_rmpv(value),
        _ => return Err(invalid_consolidation("note candidate names no value")),
    };
    let confidence = item
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.5) as f32;
    let refs = item
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .filter(|refs| !refs.is_empty())
        .ok_or_else(|| invalid_consolidation("note candidate cites no evidence"))?;
    for cited in refs {
        let EvidenceLocator::TurnTextRange {
            source_id,
            start,
            end,
        } = decode_model_locator(cited)?
        else {
            return Err(invalid_consolidation(
                "note candidate cites something other than the note",
            ));
        };
        // A blank range grounds nothing: a sealed pad's scratch lines read
        // as blanks.
        if source_id != note.id
            || start >= end
            || end > note.markdown.len()
            || !note.markdown.is_char_boundary(start)
            || !note.markdown.is_char_boundary(end)
            || note.markdown[start..end].trim().is_empty()
        {
            return Err(invalid_consolidation(
                "note candidate's evidence is not a range of the note",
            ));
        }
    }
    let mut fields = vec![(
        Value::from(TURN_BODY_FACET_REF_KEY),
        Value::Binary(note.facet.as_bytes().to_vec()),
    )];
    if let Some(topic) = item.get("topic_key").filter(|topic| !topic.is_null()) {
        fields.push((Value::from("topic_key"), json_to_rmpv(topic)));
    }
    if note.project != crate::claim::default_project_id() {
        fields.push((
            Value::from(SCOPE_PROJECT_KEY),
            Value::Binary(note.project.as_bytes().to_vec()),
        ));
    }
    let candidate =
        ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence)
            .with_scope(Value::Map(fields));
    let facts = super::conflict::candidate_facts(&candidate)?;
    let claim_id = super::conflict::deterministic_claim_id(
        run.attempt_id,
        subject,
        predicate,
        &facts.value,
        facts.world,
        facts.facet,
        facts.rel,
        facts.project,
        facts.topic.as_deref(),
    )?;
    Ok(PromotionCandidate {
        claim_id,
        candidate,
        evidence_turn_refs: vec![note.id],
        provenance_chain: Vec::new(),
        supersedes: None,
        // The Dreamer's reading of a NOTE is its own inference, whoever
        // wrote the NOTE.
        evidence_meet: ClaimSource::Generated,
        occurred: TimeRange {
            start: run.now_ms,
            end: run.now_ms,
        },
        learned_at: run.now_ms,
    })
}
