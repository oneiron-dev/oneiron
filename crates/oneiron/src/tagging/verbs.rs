//! Typed public reads of the tagging marker and the saved tag sets: the
//! `vault.tagging.*` doors over [`Vault::tagging_marker`],
//! [`Vault::turn_tags`], [`Vault::tagging_trace_history`] and
//! [`Vault::tagged_mentions`]. Every door acts through the caller's own
//! credential: the named turn must read on the bound actor's recorded lane,
//! exactly as the sibling scoped reads admit theirs, and a mention is
//! served only while its turn and its MESSAGE read, naming only the entities
//! the lane reads (OPUS-LEAKS). Every answer, and a point read's
//! NOT_FOUND, carries the lane's scope receipt, which names no hidden world
//! and counts no hidden row (FIX 10170). Saved tags read from text the turn
//! no longer shows stay readable, said to be stale and pending their retag
//! (FIX 10169). Nothing here authors a claim: the tagger's saved spans,
//! coreference, mood and labels stay derived tags.

use serde::{Deserialize, Serialize};

use super::freshness::{
    TaggingFreshness, TaggingMoodPartView, mood_freshness, mood_part_views,
    tagging_freshness_in_txn,
};
use super::history::TaggingTraceRecord;
use super::marker::MarkerPayload;
use super::tags::{
    DerivationEnvelope, MentionHit, MentionLink, MentionReference, TaggedMention, TurnTags,
};
use super::trace::{HandBackReason, SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace};
use super::{OutputRefusal, TaggingMode};
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::extraction::{EncoderExecution, SpeakerTarget};
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::{EntityId, Error};

#[doc(hidden)]
pub use oneiron_verb_wire::tagging::verbs::{
    DerivationEnvelopeView, MentionLinkView, MentionReferenceView, MergeEvidenceView,
    TaggedMentionView, TaggingFailureView, TaggingHistoryView, TaggingMarkerState,
    TaggingMarkerView, TaggingMentionHitView, TaggingMentionsRequest, TaggingMentionsView,
    TaggingOutcomeView, TaggingSpeakerTarget, TaggingStatusView, TaggingTagsView, TaggingTraceView,
    TaggingTurnRequest, TaggingVadView, TurnTagsView,
};

fn refusal_str(refusal: OutputRefusal) -> &'static str {
    match refusal {
        OutputRefusal::MoodOutOfRange => "mood_out_of_range",
        OutputRefusal::UnknownMessage => "unknown_message",
        OutputRefusal::BadOffsets => "bad_offsets",
        OutputRefusal::BadLabel => "bad_label",
        OutputRefusal::BadConfidence => "bad_confidence",
        OutputRefusal::BadLink => "bad_link",
        OutputRefusal::UnknownContext => "unknown_context",
        OutputRefusal::SpanOrder => "span_order",
        OutputRefusal::OtherStack => "other_stack",
    }
}

fn failure_view(failure: &TaggingFailure) -> TaggingFailureView {
    match failure {
        TaggingFailure::Call { code } => TaggingFailureView {
            class: "call".to_owned(),
            code: Some(code.clone()),
            refusal: None,
        },
        TaggingFailure::Refused { refusal } => TaggingFailureView {
            class: "refused".to_owned(),
            code: None,
            refusal: Some(refusal_str(*refusal).to_owned()),
        },
        TaggingFailure::Panicked => TaggingFailureView {
            class: "panicked".to_owned(),
            code: None,
            refusal: None,
        },
    }
}

fn outcome_view(outcome: &TaggingOutcome) -> TaggingOutcomeView {
    match outcome {
        TaggingOutcome::Saved {
            spans,
            links,
            mood,
            linked,
            minted,
            context_links,
            speaker_links,
            unresolved_context_links,
            unresolved_speaker_links,
            surprise,
        } => TaggingOutcomeView::Saved {
            spans: *spans,
            links: *links,
            mood: *mood,
            linked: *linked,
            minted: *minted,
            context_links: *context_links,
            speaker_links: *speaker_links,
            unresolved_context_links: *unresolved_context_links,
            unresolved_speaker_links: *unresolved_speaker_links,
            surprise: *surprise,
        },
        TaggingOutcome::Shadowed {
            spans,
            links,
            mood,
            mapped_spans,
            context_links,
            speaker_links,
        } => TaggingOutcomeView::Shadowed {
            spans: *spans,
            links: *links,
            mood: *mood,
            mapped_spans: *mapped_spans,
            context_links: *context_links,
            speaker_links: *speaker_links,
        },
        TaggingOutcome::Imported { spans, links, mood } => TaggingOutcomeView::Imported {
            spans: *spans,
            links: *links,
            mood: *mood,
        },
        TaggingOutcome::Skipped { reason } => TaggingOutcomeView::Skipped {
            reason: match reason {
                SkipReason::TurnGone => "turn_gone",
                SkipReason::NoText => "no_text",
            }
            .to_owned(),
        },
        TaggingOutcome::Superseded { retry_at } => TaggingOutcomeView::Superseded {
            retry_at: *retry_at,
        },
        TaggingOutcome::Deferred { retry_at } => TaggingOutcomeView::Deferred {
            retry_at: *retry_at,
        },
        TaggingOutcome::Failed { failure, retry_at } => TaggingOutcomeView::Failed {
            failure: failure_view(failure),
            retry_at: *retry_at,
        },
        TaggingOutcome::Rekeyed => TaggingOutcomeView::Rekeyed,
        TaggingOutcome::HandedBack { reason, retry_at } => TaggingOutcomeView::HandedBack {
            reason: match reason {
                HandBackReason::WorkerRestarted => "worker_restarted",
                HandBackReason::SettlementFailed => "settlement_failed",
            }
            .to_owned(),
            retry_at: *retry_at,
        },
        TaggingOutcome::Unreadable => TaggingOutcomeView::Unreadable,
    }
}

fn trace_view(record: &TaggingTraceRecord) -> TaggingTraceView {
    let trace: &TaggingTrace = &record.trace;
    TaggingTraceView {
        recorded_at: record.recorded_at,
        attempt: trace.attempt.clone(),
        turn_ref: trace.turn.map(|turn| turn.to_hex()),
        checkpoint: trace.checkpoint.clone(),
        stack: trace.stack.clone(),
        model: trace.model.clone(),
        input_hash: trace.input_hash.clone(),
        try_number: trace.try_number,
        call_micros: trace.call_micros,
        execution: trace.execution.clone(),
        outcome: outcome_view(&trace.outcome),
    }
}

fn marker_view(record: &AttemptRecord) -> TaggingMarkerView {
    let payload = MarkerPayload::decode(&record.payload);
    TaggingMarkerView {
        attempt_ref: bytes_to_hex_lower(record.id.as_bytes()),
        state: record.state.as_str().to_owned(),
        checkpoint: payload.as_ref().map(|payload| payload.checkpoint.clone()),
        stack: payload.and_then(|payload| payload.stack),
        attempt_count: record.attempt_count,
        retry_of: record.retry_of.map(|id| bytes_to_hex_lower(id.as_bytes())),
        scheduled_at: record.scheduled_at.or(record.backoff_until),
        last_error: record.last_error.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

pub(crate) fn mention_view(index: usize, mention: &TaggedMention) -> TaggedMentionView {
    TaggedMentionView {
        index,
        message_ref: mention.message.to_hex(),
        start: mention.start,
        end: mention.end,
        label: mention.label.clone(),
        confidence: mention.confidence,
        link: match &mention.link {
            MentionLink::Tag => MentionLinkView::Tag,
            MentionLink::Candidates { kind, entities } => MentionLinkView::Candidates {
                kind: *kind,
                entity_refs: entities.iter().map(EntityId::to_hex).collect(),
            },
            MentionLink::Minted { kind, entity } => MentionLinkView::Minted {
                kind: *kind,
                entity_ref: entity.to_hex(),
            },
        },
        antecedent: mention.antecedent,
        reference: mention.reference.map(|reference| match reference {
            MentionReference::Context => MentionReferenceView::Context,
            MentionReference::Speaker { target, resolved } => MentionReferenceView::Speaker {
                target: match target {
                    SpeakerTarget::Speaker => TaggingSpeakerTarget::Speaker,
                    SpeakerTarget::Addressee => TaggingSpeakerTarget::Addressee,
                },
                resolved,
            },
        }),
        link_confidence: mention.link_confidence,
    }
}

pub(crate) fn envelope_view(envelope: &DerivationEnvelope) -> DerivationEnvelopeView {
    DerivationEnvelopeView {
        content_hash: envelope.content_hash.clone(),
        model_id: envelope.model_id.clone(),
        stack: envelope.stack.clone(),
        version: envelope.version.clone(),
        params_hash: envelope.params_hash.clone(),
    }
}

fn tags_view(tags: &TurnTags, freshness: TaggingFreshness) -> TurnTagsView {
    TurnTagsView {
        turn_ref: tags.turn.to_hex(),
        envelope: envelope_view(&tags.envelope),
        message_refs: tags.messages.iter().map(EntityId::to_hex).collect(),
        mentions: tags
            .mentions
            .iter()
            .enumerate()
            .map(|(index, mention)| mention_view(index, mention))
            .collect(),
        merge_evidence: tags
            .merge_evidence
            .iter()
            .map(|evidence| MergeEvidenceView {
                span: evidence.span,
                antecedent: evidence.antecedent,
                confidence: evidence.confidence,
            })
            .collect(),
        mood: tags.mood.map(|mood| TaggingVadView {
            valence: mood.valence,
            arousal: mood.arousal,
            dominance: mood.dominance,
        }),
        mood_freshness: tags.mood.map(|_| mood_freshness(freshness, tags)),
        mood_parts: mood_part_views(tags),
        saved_at: tags.saved_at,
        surprise: tags.surprise,
        freshness,
    }
}

fn hit_view(hit: &MentionHit, freshness: TaggingFreshness) -> TaggingMentionHitView {
    TaggingMentionHitView {
        turn_ref: hit.turn.to_hex(),
        index: hit.index,
        mention: mention_view(hit.index, &hit.mention),
        freshness,
    }
}

/// The retry instant a trace outcome scheduled, when it scheduled one.
fn outcome_retry_at(outcome: &TaggingOutcome) -> Option<u64> {
    match outcome {
        TaggingOutcome::Superseded { retry_at }
        | TaggingOutcome::Deferred { retry_at }
        | TaggingOutcome::Failed { retry_at, .. }
        | TaggingOutcome::HandedBack { retry_at, .. } => Some(*retry_at),
        _ => None,
    }
}

/// A tag set as a lane reads it (OPUS-LEAKS), and which of its mentions
/// show.
struct LaneTags {
    tags: TurnTags,
    /// By stored index: whether the mention shows.
    kept: Vec<bool>,
}

impl LaneTags {
    fn kept(&self, index: usize) -> bool {
        self.kept.get(index).copied().unwrap_or(false)
    }
}

/// `tags` as the lane whose point read is `reads` sees them: a mention shows
/// only while the lane reads its MESSAGE, and its link names only the
/// entities the lane reads (a provisional entity, local to this vault,
/// shows with its mention). A coreference or merge evidence naming a
/// mention left out goes with it. The mood, its parts and the surprise are
/// measured over every MESSAGE of the set, so they show only while the lane
/// reads them all. Every mention keeps its stored index.
fn lane_tags(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    tags: &TurnTags,
    mut reads: impl FnMut(&EntityId) -> crate::Result<bool>,
) -> crate::Result<LaneTags> {
    let mut shown = tags.clone();
    let mut messages = std::collections::BTreeSet::new();
    for message in &tags.messages {
        if reads(message)? {
            messages.insert(*message);
        }
    }
    let kept: Vec<bool> = tags
        .mentions
        .iter()
        .map(|mention| messages.contains(&mention.message))
        .collect();
    let mut entities = std::collections::BTreeMap::new();
    for (mention, keep) in shown.mentions.iter_mut().zip(&kept) {
        if !keep {
            continue;
        }
        for entity in mention.link.entities().to_vec() {
            let readable = match entities.get(&entity) {
                Some(readable) => *readable,
                None => {
                    let readable =
                        super::provisional::exists_in_txn(store, txn, &entity)? || reads(&entity)?;
                    entities.insert(entity, readable);
                    readable
                }
            };
            if !readable {
                mention.link = mention.link.without(&entity);
            }
        }
        if let Some(antecedent) = mention.antecedent
            && !kept.get(antecedent).copied().unwrap_or(false)
        {
            mention.antecedent = None;
        }
    }
    let is_kept = |index: usize| kept.get(index).copied().unwrap_or(false);
    shown
        .merge_evidence
        .retain(|evidence| is_kept(evidence.span) && is_kept(evidence.antecedent));
    if messages.len() != tags.messages.len() {
        shown.mood = None;
        shown.mood_carried = false;
        shown.mood_parts.clear();
        shown.surprise = None;
    }
    shown.messages.retain(|message| messages.contains(message));
    Ok(LaneTags { tags: shown, kept })
}

impl Memory<'_> {
    /// Resolves a turn ref and admits it on the bound actor's recorded
    /// lane, listing it as the answer's producer, with the lane's receipt
    /// for the answer. An absent turn, and one the lane does not read, get
    /// one NOT_FOUND that carries the receipt (FIX 10170). A denial at the
    /// lane's own floor adds no omission count.
    fn tagging_turn(
        &self,
        reference: &str,
    ) -> MemoryResult<(EntityId, ScopedRead<'_>, ScopedReadReceipt)> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let turn = match resolve_entity_ref(self.vault(), reference) {
            Ok(turn) => turn,
            Err(error) if error.code == MEMORY_CODE_NOT_FOUND => {
                return Err(error.with_read_receipt(lane.read_receipt(None, 0)?));
            }
            Err(error) => return Err(error),
        };
        self.produced_from([turn]);
        if !lane.is_entity_readable(&turn)? {
            let receipt = lane.read_receipt(None, 0)?;
            return Err(MemoryError::from(Error::EntityNotFound).with_read_receipt(receipt));
        }
        let receipt = lane.read_receipt(None, 0)?;
        Ok((turn, lane, receipt))
    }

    /// `vault.tagging.status`: pending, retrying or settled, with the
    /// configured checkpoint, the serving model and the failure reason.
    pub fn tagging_status(
        &self,
        input: &TaggingTurnRequest,
    ) -> MemoryResult<ScopedReadResult<TaggingStatusView>> {
        let (turn, _, receipt) = self.tagging_turn(&input.turn_ref)?;
        let vault = self.vault();
        let tagging = vault.tagging_marker_config();
        let config = tagging.as_ref();
        let marker = vault.tagging_marker(&turn)?;
        let traces = vault.tagging_trace_history(Some(&turn))?;
        let tags = vault.turn_tags(&turn)?;
        let freshness = match &tags {
            Some(_) => vault.tagging_freshness(&turn)?,
            None => None,
        };
        let last = traces.last();
        let state = if config.is_none() {
            TaggingMarkerState::Unconfigured
        } else if let Some(record) = &marker {
            if record.state == AttemptState::Scheduled || record.retry_of.is_some() {
                TaggingMarkerState::Retrying
            } else {
                TaggingMarkerState::Pending
            }
        } else if tags.is_some() {
            TaggingMarkerState::Settled
        } else {
            match last.map(|record| &record.trace.outcome) {
                Some(
                    TaggingOutcome::Saved { .. }
                    | TaggingOutcome::Shadowed { .. }
                    | TaggingOutcome::Imported { .. }
                    | TaggingOutcome::Skipped { .. },
                ) => TaggingMarkerState::Settled,
                Some(TaggingOutcome::Failed { .. } | TaggingOutcome::Unreadable) => {
                    TaggingMarkerState::Failed
                }
                Some(_) | None => TaggingMarkerState::Absent,
            }
        };
        let failure = last.and_then(|record| match &record.trace.outcome {
            TaggingOutcome::Failed { failure, .. } => Some(failure_view(failure)),
            _ => None,
        });
        let retry_at = marker
            .as_ref()
            .and_then(|record| record.scheduled_at.or(record.backoff_until))
            .or_else(|| last.and_then(|record| outcome_retry_at(&record.trace.outcome)));
        let model = last
            .and_then(|record| record.trace.model.clone())
            .or_else(|| tags.as_ref().map(|tags| tags.envelope.model_id.clone()));
        let value = TaggingStatusView {
            turn_ref: turn.to_hex(),
            state,
            configured: config.is_some(),
            checkpoint: config.map(|config| config.checkpoint.clone()),
            stack: config.and_then(|config| config.stack.clone()),
            mode: config.map(|config| {
                match config.mode {
                    TaggingMode::Save => "save",
                    TaggingMode::Shadow => "shadow",
                }
                .to_owned()
            }),
            model,
            marker: marker.as_ref().map(marker_view),
            failure,
            retry_at,
            try_number: last.map(|record| record.trace.try_number),
            has_tags: tags.is_some(),
            freshness,
            saved_at: tags.as_ref().map(|tags| tags.saved_at),
            last_trace: last.map(trace_view),
        };
        Ok(ScopedReadResult { value, receipt })
    }

    /// `vault.tagging.tags`: the settled tag set — mention spans, targets,
    /// coreference, affect, PII and other labels, and their derivation.
    pub fn tagging_tags(
        &self,
        input: &TaggingTurnRequest,
    ) -> MemoryResult<ScopedReadResult<TaggingTagsView>> {
        let (turn, lane, receipt) = self.tagging_turn(&input.turn_ref)?;
        let vault = self.vault();
        // The set, how current it is and what of it the lane reads, in one
        // snapshot.
        let view = lane.with_grant_read_snapshot(|txn| -> MemoryResult<_> {
            let Some(tags) = super::tags::readable_view_in_txn(&vault.store, txn, &turn)? else {
                return Ok(None);
            };
            let freshness = tagging_freshness_in_txn(vault, txn, &turn, &tags)?;
            let policy = lane.live_policy_manifest_in(txn)?;
            let shown = lane_tags(&vault.store, txn, &tags, |id| {
                lane.is_entity_readable_with_policy_in(txn, &policy, id)
            })?;
            self.produced_from(shown.tags.messages.iter().copied());
            let mut view = tags_view(&shown.tags, freshness);
            view.mentions.retain(|mention| shown.kept(mention.index));
            Ok(Some(view))
        })?;
        let value = TaggingTagsView {
            turn_ref: turn.to_hex(),
            tags: view,
        };
        Ok(ScopedReadResult { value, receipt })
    }

    /// `vault.tagging.history`: the traces that stay once settled markers
    /// leave the job ledger, oldest first.
    pub fn tagging_history(
        &self,
        input: &TaggingTurnRequest,
    ) -> MemoryResult<ScopedReadResult<TaggingHistoryView>> {
        let (turn, _, receipt) = self.tagging_turn(&input.turn_ref)?;
        let traces = self.vault().tagging_trace_history(Some(&turn))?;
        let value = TaggingHistoryView {
            turn_ref: turn.to_hex(),
            traces: traces.iter().map(trace_view).collect(),
        };
        Ok(ScopedReadResult { value, receipt })
    }

    /// `vault.tagging.mentions`: the saved mentions naming one entity,
    /// each served only while its turn reads on the caller's lane; a hidden
    /// turn's mention is left out before the limit counts (FIX 10170).
    /// Denials at the lane's own floor add no omission count.
    pub fn tagging_mentions(
        &self,
        input: &TaggingMentionsRequest,
    ) -> MemoryResult<ScopedReadResult<TaggingMentionsView>> {
        if input.limit == 0 {
            return Err(MemoryError::bad_request(
                "tagging mentions limit must be at least 1",
            ));
        }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let entity = match resolve_entity_ref(self.vault(), &input.entity_ref) {
            Ok(entity) => entity,
            Err(error) if error.code == MEMORY_CODE_NOT_FOUND => {
                return Err(error.with_read_receipt(lane.read_receipt(None, 0)?));
            }
            Err(error) => return Err(error),
        };
        // An entity the lane does not read has no mentions it may see. A
        // provisional entity has no row: each of its hits is judged by its
        // own TURN and MESSAGE below, and one the lane reads no hit of
        // answers as an id that names nothing.
        let provisional = self.vault().provisional_entity(&entity)?.is_some();
        if !provisional && !lane.is_entity_readable(&entity)? {
            let receipt = lane.read_receipt(None, 0)?;
            return Err(MemoryError::from(Error::EntityNotFound).with_read_receipt(receipt));
        }
        let mut mentions = Vec::new();
        let mut current = std::collections::BTreeMap::new();
        let mut turn_tags = std::collections::BTreeMap::new();
        for mut hit in self.vault().tagged_mentions(&entity)? {
            if mentions.len() == input.limit {
                break;
            }
            if !lane.is_entity_readable(&hit.turn)?
                || !lane.is_entity_readable(&hit.mention.message)?
            {
                continue;
            }
            for linked in hit.mention.link.entities().to_vec() {
                if self.vault().provisional_entity(&linked)?.is_none()
                    && !lane.is_entity_readable(&linked)?
                {
                    hit.mention.link = hit.mention.link.without(&linked);
                }
            }
            // A coreference names its antecedent mention's place: it shows
            // only while the lane reads that mention's MESSAGE too.
            if let Some(antecedent) = hit.mention.antecedent {
                if let std::collections::btree_map::Entry::Vacant(slot) = turn_tags.entry(hit.turn)
                {
                    slot.insert(self.vault().turn_tags(&hit.turn)?);
                }
                let source = turn_tags
                    .get(&hit.turn)
                    .and_then(Option::as_ref)
                    .and_then(|tags| tags.mentions.get(antecedent))
                    .map(|mention| mention.message);
                let shown = match source {
                    Some(message) => lane.is_entity_readable(&message)?,
                    None => false,
                };
                if !shown {
                    hit.mention.antecedent = None;
                }
            }
            let freshness = match current.get(&hit.turn) {
                Some(freshness) => *freshness,
                None => {
                    let freshness = self.vault().tagging_freshness(&hit.turn)?;
                    let freshness = freshness.unwrap_or_default();
                    current.insert(hit.turn, freshness);
                    freshness
                }
            };
            self.produced_from([hit.turn, hit.mention.message]);
            mentions.push(hit_view(&hit, freshness));
        }
        // The loop stops early only at `limit` (at least 1) hits, so no hit
        // means none of the entity's hits reads: a provisional entity named
        // only where the lane does not read is not found, as an absent id
        // is (review round 2 of #6970).
        if provisional && mentions.is_empty() {
            let receipt = lane.read_receipt(None, 0)?;
            return Err(MemoryError::from(Error::EntityNotFound).with_read_receipt(receipt));
        }
        let value = TaggingMentionsView {
            entity_ref: entity.to_hex(),
            mentions,
        };
        let receipt = lane.read_receipt(None, 0)?;
        Ok(ScopedReadResult { value, receipt })
    }
}
