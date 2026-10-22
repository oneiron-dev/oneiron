//! ARCH-0032 stage 2 (OF-073): the Dreamer reviews NOTEs. A Nightly child
//! pages through the vault's NOTEs, reads each one the Dreamer may read
//! whose kind allows extraction, asks the extraction role which beliefs the
//! note grounds, and promotes them through the promotion gate. Every belief
//! quotes the exact markdown read, and the review binds each quote to the one
//! byte range of it that it names (FIX 7506), so a model cannot ground a
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
//!
//! A `keep` line no belief cites is recorded on the review's record as
//! `keep_missed` (FIX 2240). The next Nightly review asks for those lines
//! once more, the rest of the pad blanked; a line missed again stays a
//! recorded miss and is not asked for a third time.
//!
//! The first review to finish in a calendar month also runs the NOTE
//! tombstone review (`note/tombstone_review.rs`, FIX 2419).
//!
//! A review whose reply names the note's topic keeps it on the record as
//! its topic membership, and that write also declares the topic group's
//! summary (`note_topics.rs`, FIX 907). A reply that names none, or names
//! one malformed, keeps none and declares nothing.

use std::ops::Range;

use super::executor::ConsolidationExecutor;
use super::executor::extraction::check_extraction_reply;
use super::extracted_people::{MintNamespace, NoteSource, bind_people, mint_note_people};
use super::neighbourhood::{Neighbourhood, Passage, discover_in};
use super::note_classification::{PadAsk, note_classification_reply};
use super::note_topics::{
    NoteTopicLineage, NoteTopicMembership, queue_note_topic_summaries_in_txn,
};
use super::roles::DREAMER_EXTRACTION_ROLE;
use super::step_charge::StepChargeTally;
use super::support::invalid_consolidation;
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedRead;
use crate::dreamer_promotion::{DreamerRunContext, promote_consolidated_claims};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{
    DurableStepContext, DurableStepError, ScopeResource, StepOutcome, call_as_step_checked,
};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

mod candidates;
use candidates::{NoteSources, cites, note_candidate};

const CURSOR: SideTable<(), EntityId, Named> =
    SideTable::new(&side_table::DREAMER_NOTE_REVIEW_CURSOR);
const SEEN: SideTable<EntityId, NoteReviewRecord, Named> =
    SideTable::new(&side_table::DREAMER_NOTE_REVIEW_SEEN);
/// The importance at which a note's verdict is `promote` (ARCH-0032
/// `dr:P16`: a scratchpad item promotes at `importance >= 0.75`).
const PROMOTE_IMPORTANCE: f64 = 0.75;
/// How many times an unchanged sealed pad's missed `keep` lines are asked
/// for again after the first review (FIX 2240).
const KEEP_REASKS: u8 = 1;

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
    /// A sealed pad's `keep` lines no belief cites: each line's text as a
    /// byte range of the markdown.
    keep_missed: Vec<Range<usize>>,
    /// Re-asks for `keep_missed` spent on this markdown, at most
    /// [`KEEP_REASKS`].
    keep_reasks: u8,
    /// The review attempt that wrote this record: an attempt resumed after a
    /// checkpoint never re-asks what it just asked.
    attempt: AttemptId,
    /// The note's topic, when its classification named one (FIX 907): the
    /// one record of its topic membership.
    topic: Option<NoteTopicMembership>,
}
/// NOTEs per page. The cursor moves a page at a time, so a review cut by
/// its deadline resumes where it stopped.
const PAGE: usize = 32;

/// One NOTE the review reads: its live markdown, the version the request
/// pins, and the scope stamps its beliefs inherit.
struct Note {
    id: EntityId,
    markdown: String,
    /// A sealed scratchpad's review: how it asks for the pad's `keep` lines.
    sealed_pad: Option<PadAsk>,
    /// The text ranges of the `keep` lines this read asks a belief of.
    keep: Vec<Range<usize>>,
    /// On a re-ask, the record of the review whose misses it asks for.
    reask_of: Option<NoteReviewRecord>,
    fingerprint: [u8; 32],
    facet: EntityId,
    project: EntityId,
    version: ScopeResource,
    /// The known entities the markdown names, read as an extraction
    /// transcript's listing is (FIX 7506): entities only, no claims.
    listed: Neighbourhood,
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
            for note in readable_notes(ctx.vault, &read, &page, attempt_id)? {
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
                // The month's first finished NOTE review also proposes the
                // month's NOTE tombstones (FIX 2419); it only asks the owner.
                crate::note::review_note_tombstones(ctx.vault)?;
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
        // The people a reply declares are minted under the review's queued
        // parent, else its lineage's first try (FIX 7579), from the NOTE's own
        // axes (FIX 7506).
        let namespace = MintNamespace::new(
            super::extracted_people::original_try(ctx.vault, run.attempt_id)?,
            attempt.status.payload.parent_attempt,
            None,
            Some(note.facet),
            None,
        );
        let (request, labels) = match Self::note_request(
            &call,
            note.id,
            &note.listed,
            &note.markdown,
            note.sealed_pad,
            &scope,
            &namespace,
        ) {
            Ok(request) => request,
            Err(error) => return Ok(Some(charges.park_on_error(&error))),
        };
        let mut request =
            match ctx
                .vault
                .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &call.inference)
            {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(Some(charges.park_on_error(&error))),
            };
        if let Err(error) = super::roles::bind_reasoning(ctx.vault, call.backend, &mut request) {
            return Ok(Some(charges.park_on_error(&error)));
        }
        let Ok(hash) = request.canonical_hash() else {
            // It waits on no owner act: it resumes after its retry delay
            // (OF-193a).
            return Ok(Some(charges.park_for(
                "note review request hash failed",
                DreamerParkCause::Retry,
            )));
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
            &check_note_review_reply,
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
                    return Ok(Some(charges.park_on_fallback(
                        ctx.vault,
                        run.attempt_id,
                        hash,
                        NOTE_FALLBACK,
                        &response,
                    )?));
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
            // A refused reply asks again after its retry delay (FIX 7218,
            // Engine 10-21): a private park would keep its row leased.
            Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                charges.record_usage(&usage);
                return Ok(Some(charges.park_for(
                    &format!("note review reply refused: {}", errors.join("; ")),
                    DreamerParkCause::Retry,
                )));
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
        let reply = match note_classification_reply(&response) {
            Ok(reply) => reply,
            Err(error) => return Ok(Some(charges.park_on_error(&error))),
        };
        let importance = reply.importance;
        // The reply's labels read through the request's own map; each
        // declared person binds once, before any candidate names it.
        let sources = NoteSources {
            labels: &labels,
            note,
        };
        let people = bind_people(&reply.persons, &sources, &namespace);
        let mut candidates = Vec::new();
        let mut cited = Vec::new();
        for item in &reply.candidates {
            match note_candidate(item, note, run, &sources, &people) {
                Ok((candidate, ranges)) => {
                    candidates.push(candidate);
                    cited.extend(ranges);
                }
                Err(reason) => tracing::warn!(
                    target: "oneiron::dreamer",
                    %reason,
                    note = %note.id.to_hex(),
                    "note review candidate not written"
                ),
            }
        }
        // A keep line counts as kept when a written candidate cites its
        // text, whatever the promotion gate then answers about that belief.
        let keep_missed: Vec<Range<usize>> = note
            .keep
            .iter()
            .filter(|line| !cited.iter().any(|range| cites(&note.markdown, range, line)))
            .cloned()
            .collect();
        let (verdict, importance) = match &note.reask_of {
            // A re-ask reads only the missed lines: the note's verdict and
            // importance stay the first review's, unless the re-ask grounds
            // a belief a skipped note did not.
            Some(prior) if prior.verdict == NoteVerdict::Skip && !candidates.is_empty() => {
                (NoteVerdict::Extract, prior.importance)
            }
            Some(prior) => (prior.verdict, prior.importance),
            None if importance.is_some_and(|importance| importance >= PROMOTE_IMPORTANCE) => {
                (NoteVerdict::Promote, importance)
            }
            None if candidates.is_empty() => (NoteVerdict::Skip, importance),
            None => (NoteVerdict::Extract, importance),
        };
        let keep_reasks = note
            .reask_of
            .as_ref()
            .map_or(0, |prior| prior.keep_reasks.saturating_add(1));
        // A re-ask's topic stays the first review's, as its verdict does.
        let topic = match &note.reask_of {
            Some(prior) => prior.topic,
            None => reply
                .topic_key
                .as_deref()
                .map(|key| NoteTopicMembership::new(key, note.facet, note.project)),
        };
        if !keep_missed.is_empty() {
            tracing::info!(
                target: "oneiron::dreamer",
                note = %note.id.to_hex(),
                missed = keep_missed.len(),
                asked_again = keep_reasks >= KEEP_REASKS,
                "note review: keep lines grounded no belief"
            );
        }
        // The NOTE's people land before the beliefs about them.
        mint_note_people(
            ctx.vault,
            &people,
            &NoteSource {
                id: note.id,
                version: &note.version,
                markdown: &note.markdown,
            },
            ctx.now_ms,
        )?;
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
        let lineage = NoteTopicLineage {
            requester: run.agent_actor,
            parent: run.attempt_id,
            run_id: attempt.status.attempt.run_id.as_deref(),
            now: ctx.now_ms / 1_000,
        };
        let declared = ctx.vault.with_write_txn_grouped(|txn| {
            // The topic the NOTE's last review kept, when this review moves
            // it to another or to none: that group is declared again
            // without it (FIX 7459).
            let left =
                topic_of_in_txn(ctx.vault, txn, &note.id).filter(|kept| topic != Some(*kept));
            SEEN.put(
                &ctx.vault.store,
                txn,
                &note.id,
                &NoteReviewRecord {
                    fingerprint: note.fingerprint,
                    verdict,
                    importance,
                    keep_missed,
                    keep_reasks,
                    attempt: run.attempt_id,
                    topic,
                },
            )?;
            // The membership and its topic's summary commit together (FIX
            // 907): a replay never finds this NOTE reviewed and the summary
            // unqueued.
            let mut declared = match &topic {
                Some(topic) => queue_note_topic_summaries_in_txn(ctx.vault, txn, topic, &lineage)?,
                None => false,
            };
            if let Some(left) = &left {
                declared |= queue_note_topic_summaries_in_txn(ctx.vault, txn, left, &lineage)?;
            }
            Ok(declared)
        })?;
        if declared {
            ctx.vault.store.notify_attempt_observers();
        }
        Ok(None)
    }
}

/// Every reviewed NOTE whose review record keeps `topic`, in id order: the
/// record is the one membership, kept in no other index (FIX 907).
pub(super) fn topic_members_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    topic: &NoteTopicMembership,
) -> Result<Vec<EntityId>> {
    let mut members = Vec::new();
    for row in SEEN.iter_from(&vault.store, txn, &[])? {
        let (note, record) = row?;
        if record.topic.as_ref() == Some(topic) {
            members.push(note);
        }
    }
    Ok(members)
}

/// The topic `note`'s review record keeps, read in `txn`; `None` when the
/// record keeps none, or is gone or does not read.
pub(super) fn topic_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: &EntityId,
) -> Option<NoteTopicMembership> {
    SEEN.get(&vault.store, txn, note)
        .ok()
        .flatten()
        .and_then(|record| record.topic)
}

/// Why a review parks on a deterministic fallback.
const NOTE_FALLBACK: &str = "note review needs the extraction model";

/// The review step's check (FIX 7431): a deterministic fallback whose park
/// would resume as a Retry is refused inside the step, never memoized, so
/// the Retry asks the model again; any other reply answers to the extraction
/// contract, as before.
fn check_note_review_reply(response: &crate::llm::LlmResponse) -> std::result::Result<(), String> {
    if super::step_charge::retry_fallback(response) {
        return Err(NOTE_FALLBACK.to_owned());
    }
    check_extraction_reply(response)
}

/// The NOTEs on `page` the review reads: live and readable by the Dreamer,
/// Allowed by its kind or its override, or sealed and AfterSeal (a sealed pad
/// read through its line marks), changed since their last review, and with a
/// birth facet and one project for their beliefs. Anything else is skipped,
/// never widened. An unchanged sealed pad is read again only for the
/// re-ask of the `keep` lines its last review missed (FIX 2240), and never
/// by the `attempt` that wrote that review.
fn readable_notes(
    vault: &Vault,
    read: &ScopedRead<'_>,
    page: &[EntityId],
    attempt: AttemptId,
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
        // The one NOTE projection (FIX 907): Allowed reads whole, AfterSeal
        // once sealed (a sealed pad through its marks); a diary, a Disabled
        // NOTE and an empty one are never read.
        let Some(projected) = super::note_text::note_text_in(vault, &txn, id, &body)? else {
            continue;
        };
        let super::note_text::NoteText {
            markdown: stored,
            text: markdown,
            sealed_pad,
            keep,
            version,
            ..
        } = projected;
        let sealed_pad = sealed_pad.then_some(PadAsk::First {
            keep: !keep.is_empty(),
        });
        let fingerprint = *blake3::hash(stored.as_bytes()).as_bytes();
        let seen = SEEN
            .get(&vault.store, &txn, id)?
            .filter(|seen| seen.fingerprint == fingerprint);
        let (markdown, sealed_pad, keep, reask_of) = match seen {
            None => (markdown, sealed_pad, keep, None),
            Some(seen)
                if sealed_pad.is_some()
                    && !seen.keep_missed.is_empty()
                    && seen.keep_reasks < KEEP_REASKS
                    && seen.attempt != attempt =>
            {
                let missed = seen.keep_missed.clone();
                let text = crate::context_board::sealed_pad_reask_text(&stored, &missed);
                (text, Some(PadAsk::Missed), missed, Some(seen))
            }
            Some(_) => continue,
        };
        let Some(facet) = crate::federation::record_scope::birth_facet(&vault.store, &txn, *id)?
        else {
            continue;
        };
        let Some(project) = super::resources::stored_project(&vault.store, &txn, *id, kind, &body)?
        else {
            continue;
        };
        // The entities the markdown names, by the transcript listing's own
        // probes, through the review's own scoped read: no claims, so the
        // review's scope holds no prior head. A NOTE carries no byline.
        let passage = Passage {
            turns: &[(&[][..], Some(markdown.as_str()))],
            axes: None,
            bound: None,
            thing: None,
        };
        let (listed, _) = discover_in(vault, &txn, read, attempt, &passage)?;
        notes.push(Note {
            id: *id,
            version,
            markdown,
            sealed_pad,
            keep,
            reask_of,
            fingerprint,
            facet,
            project,
            listed,
        });
    }
    Ok(notes)
}
