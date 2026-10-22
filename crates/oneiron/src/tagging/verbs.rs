//! Typed public reads of the tagging marker and the saved tag sets: the
//! `vault.tagging.*` doors over [`Vault::tagging_marker`],
//! [`Vault::turn_tags`], [`Vault::tagging_trace_history`] and
//! [`Vault::tagged_mentions`]. Every door acts through the caller's own
//! credential: the named turn must read on the bound actor's recorded lane,
//! exactly as the sibling scoped reads admit theirs, and a mention is
//! served only while its turn reads. Nothing here authors a claim: the
//! tagger's saved spans, coreference, mood and labels stay derived tags.

use serde::{Deserialize, Serialize};

use super::history::TaggingTraceRecord;
use super::marker::MarkerPayload;
use super::tags::{
    DerivationEnvelope, MentionHit, MentionLink, MentionReference, TaggedMention, TurnTags,
};
use super::trace::{HandBackReason, SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace};
use super::{OutputRefusal, TaggingMode};
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::claim::ClaimReadStatus;
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::extraction::{EncoderExecution, SpeakerTarget};
use crate::memory::{Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::{EntityId, Error};

/// One TURN ref: the turn whose marker, tags or trace history is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaggingTurnRequest {
    pub turn_ref: String,
}

/// One entity ref and a page bound: the saved mentions naming the entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaggingMentionsRequest {
    pub entity_ref: String,
    /// Maximum mentions (required; no unbounded scans).
    pub limit: usize,
}

/// Where a turn's tagging stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaggingMarkerState {
    /// No tagger is armed on this vault.
    Unconfigured,
    /// Armed, but no marker, tag set or trace names this turn.
    Absent,
    /// A marker is queued or leased: the pass has not settled yet.
    Pending,
    /// A marker is waiting for its scheduled retry after a failed try.
    Retrying,
    /// The marker settled: tags were saved, shadowed, imported or skipped.
    Settled,
    /// The last settled try failed for good and no marker is live.
    Failed,
}

/// The live marker row, while its pass is still owed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingMarkerView {
    /// The marker attempt, as 32 lowercase hex digits.
    pub attempt_ref: String,
    /// The job row's durable state: queued, leased, scheduled, paused or landing.
    pub state: String,
    /// The checkpoint the marker was committed for, when its payload reads.
    pub checkpoint: Option<String>,
    /// The stack pinned beside it, when committed with one.
    pub stack: Option<String>,
    /// Lease-generation fence within this try; it does not count retries.
    pub attempt_count: u32,
    /// The try this marker retries, when it is a retry.
    pub retry_of: Option<String>,
    /// Store-clock second a scheduled retry becomes claimable.
    pub scheduled_at: Option<u64>,
    /// The last error the row records, when one is stamped.
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Why an attempt failed, as its trace recorded it: no turn text, no answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingFailureView {
    /// `call`, `refused` or `panicked`.
    pub class: String,
    /// The host failure class or engine error kind, for a failed call.
    pub code: Option<String>,
    /// The contract rule a refused answer broke, for a refusal.
    pub refusal: Option<String>,
}

/// How one attempt settled, as its trace recorded it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TaggingOutcomeView {
    Saved {
        spans: usize,
        links: usize,
        mood: bool,
        linked: usize,
        minted: usize,
        context_links: usize,
        speaker_links: usize,
        unresolved_context_links: usize,
        unresolved_speaker_links: usize,
        surprise: Option<f32>,
    },
    Shadowed {
        spans: usize,
        links: usize,
        mood: bool,
        mapped_spans: usize,
        context_links: usize,
        speaker_links: usize,
    },
    Imported {
        spans: usize,
        links: usize,
        mood: bool,
    },
    Skipped {
        /// `turn_gone` or `no_text`.
        reason: String,
    },
    Superseded {
        retry_at: u64,
    },
    Deferred {
        retry_at: u64,
    },
    Failed {
        failure: TaggingFailureView,
        retry_at: u64,
    },
    Rekeyed,
    HandedBack {
        /// `worker_restarted` or `settlement_failed`.
        reason: String,
        retry_at: u64,
    },
    Unreadable,
}

/// One recorded tagging trace: which tagger, which try, what happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingTraceView {
    /// Store-clock second the trace was recorded at.
    pub recorded_at: u64,
    /// The marker attempt, as 32 lowercase hex digits.
    pub attempt: String,
    /// The marked turn, when the payload named one.
    pub turn_ref: Option<String>,
    /// The checkpoint the marker was committed for.
    pub checkpoint: String,
    /// The stack pinned beside it, when committed with one.
    pub stack: Option<String>,
    /// The serving model's id, when the tagger was called.
    pub model: Option<String>,
    /// The input digest, when the turn had text to read.
    pub input_hash: Option<String>,
    /// 1 for a marker's first attempt, n for its (n-1)th retry.
    pub try_number: u32,
    /// Wall time of the tagger call in microseconds, when one was made.
    pub call_micros: Option<u64>,
    /// What ran the call, when a worker was dispatched for it.
    pub execution: Option<EncoderExecution>,
    pub outcome: TaggingOutcomeView,
}

/// A turn's tagging marker and settlement at a glance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingStatusView {
    pub turn_ref: String,
    pub state: TaggingMarkerState,
    /// Whether a tagger is armed on this vault.
    pub configured: bool,
    /// The configured tagger checkpoint, when armed.
    pub checkpoint: Option<String>,
    /// The configured stack pinned beside it, when one is pinned.
    pub stack: Option<String>,
    /// `save` or `shadow`, when armed.
    pub mode: Option<String>,
    /// The model that last served this turn: its newest trace's, else the
    /// saved set's derivation (`model@checkpoint` or `held@checkpoint`).
    pub model: Option<String>,
    /// The live marker, while its pass is still owed.
    pub marker: Option<TaggingMarkerView>,
    /// The newest trace's failure, when that try failed.
    pub failure: Option<TaggingFailureView>,
    /// Store-clock second the next try becomes claimable, while retrying.
    pub retry_at: Option<u64>,
    /// The newest trace's try number, when a trace is kept.
    pub try_number: Option<u32>,
    /// Whether a saved tag set reads for this turn.
    pub has_tags: bool,
    /// Store-clock second the saved set was saved, when one reads.
    pub saved_at: Option<u64>,
    /// The newest recorded trace, when one is kept.
    pub last_trace: Option<TaggingTraceView>,
}

/// A turn's recorded tagging traces, oldest first, bounded by the vault's
/// configured trace history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingHistoryView {
    pub turn_ref: String,
    pub traces: Vec<TaggingTraceView>,
}

/// The derivation a saved tag set was read under: its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DerivationEnvelopeView {
    pub content_hash: String,
    /// `model@checkpoint` for the slot's tagger, `held@checkpoint` for an importer's tags.
    pub model_id: String,
    pub stack: Option<String>,
    pub version: String,
    pub params_hash: String,
}

/// Where a saved mention points. None of these is an edge or a belief.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "link", rename_all = "snake_case")]
pub enum MentionLinkView {
    /// The label maps to no entity kind: the span stays a tag. A PII or
    /// other model label (an EMAIL span, say) reads here by its label.
    Tag,
    /// Soft candidates the identity key named, real or provisional.
    Candidates { kind: u8, entity_refs: Vec<String> },
    /// The provisional entity the save minted for this span.
    Minted { kind: u8, entity_ref: String },
}

/// Who a speaker reference says a span is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaggingSpeakerTarget {
    Speaker,
    Addressee,
}

/// A coreference decision reaching outside the turn's own spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MentionReferenceView {
    Context,
    Speaker {
        target: TaggingSpeakerTarget,
        resolved: bool,
    },
}

/// One saved mention span, as the tagger suggested it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggedMentionView {
    /// The mention's place in its tag set; coreference names spans by it.
    pub index: usize,
    /// The MESSAGE the span is in.
    pub message_ref: String,
    /// Byte offsets into the message's text.
    pub start: usize,
    pub end: usize,
    /// The model label: a name class, a PII class, a pronoun class.
    pub label: String,
    pub confidence: f32,
    pub link: MentionLinkView,
    /// The span index this one corefers with, when the tagger linked them.
    pub antecedent: Option<usize>,
    pub reference: Option<MentionReferenceView>,
    pub link_confidence: Option<f32>,
}

/// Coreference evidence joining spans linked to different entities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MergeEvidenceView {
    pub span: usize,
    pub antecedent: usize,
    pub confidence: f32,
}

/// A turn mood the tagger returned: valence -1..=1, arousal/dominance 0..=1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingVadView {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

/// One turn's saved tags under one derivation envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnTagsView {
    pub turn_ref: String,
    pub envelope: DerivationEnvelopeView,
    /// The MESSAGE rows the tags were read from, in input order.
    pub message_refs: Vec<String>,
    pub mentions: Vec<TaggedMentionView>,
    pub merge_evidence: Vec<MergeEvidenceView>,
    /// The turn's mood, when the tagger returned one.
    pub mood: Option<TaggingVadView>,
    /// Store-clock second of the save.
    pub saved_at: u64,
    /// Surprise beside the set this one replaced, absent for the first set.
    pub surprise: Option<f32>,
}

/// The tags saved for a turn, or none while its marker still owes a pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingTagsView {
    pub turn_ref: String,
    pub tags: Option<TurnTagsView>,
}

/// One saved mention, found by the entity it names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingMentionHitView {
    pub turn_ref: String,
    pub index: usize,
    pub mention: TaggedMentionView,
}

/// Every saved mention naming one entity, by turn then span place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingMentionsView {
    pub entity_ref: String,
    pub mentions: Vec<TaggingMentionHitView>,
}

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

fn tags_view(tags: &TurnTags) -> TurnTagsView {
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
        saved_at: tags.saved_at,
        surprise: tags.surprise,
    }
}

fn hit_view(hit: &MentionHit) -> TaggingMentionHitView {
    TaggingMentionHitView {
        turn_ref: hit.turn.to_hex(),
        index: hit.index,
        mention: mention_view(hit.index, &hit.mention),
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

impl Memory<'_> {
    /// Resolves a turn ref and admits it on the bound actor's recorded
    /// lane, with the NOT_FOUND an absent turn gets, listing it as the
    /// answer's producer.
    fn tagging_turn(&self, reference: &str) -> MemoryResult<EntityId> {
        let turn = resolve_entity_ref(self.vault(), reference)?;
        self.produced_from([turn]);
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        if !lane.is_entity_readable(&turn)? {
            return Err(Error::EntityNotFound.into());
        }
        Ok(turn)
    }

    /// `vault.tagging.status`: pending, retrying or settled, with the
    /// configured checkpoint, the serving model and the failure reason.
    pub fn tagging_status(&self, input: &TaggingTurnRequest) -> MemoryResult<TaggingStatusView> {
        let turn = self.tagging_turn(&input.turn_ref)?;
        let vault = self.vault();
        let config = vault.config.tagging.as_ref();
        let marker = vault.tagging_marker(&turn)?;
        let traces = vault.tagging_trace_history(Some(&turn))?;
        let tags = vault.turn_tags(&turn)?;
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
        Ok(TaggingStatusView {
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
            saved_at: tags.as_ref().map(|tags| tags.saved_at),
            last_trace: last.map(trace_view),
        })
    }

    /// `vault.tagging.tags`: the settled tag set — mention spans, targets,
    /// coreference, affect, PII and other labels, and their derivation.
    pub fn tagging_tags(&self, input: &TaggingTurnRequest) -> MemoryResult<TaggingTagsView> {
        let turn = self.tagging_turn(&input.turn_ref)?;
        let tags = self.vault().turn_tags(&turn)?;
        if let Some(tags) = &tags {
            self.produced_from(tags.messages.iter().copied());
        }
        Ok(TaggingTagsView {
            turn_ref: turn.to_hex(),
            tags: tags.as_ref().map(tags_view),
        })
    }

    /// `vault.tagging.history`: the traces that stay once settled markers
    /// leave the job ledger, oldest first.
    pub fn tagging_history(&self, input: &TaggingTurnRequest) -> MemoryResult<TaggingHistoryView> {
        let turn = self.tagging_turn(&input.turn_ref)?;
        let traces = self.vault().tagging_trace_history(Some(&turn))?;
        Ok(TaggingHistoryView {
            turn_ref: turn.to_hex(),
            traces: traces.iter().map(trace_view).collect(),
        })
    }

    /// `vault.tagging.mentions`: the saved mentions naming one entity,
    /// each served only while its turn reads on the caller's lane.
    pub fn tagging_mentions(
        &self,
        input: &TaggingMentionsRequest,
    ) -> MemoryResult<TaggingMentionsView> {
        if input.limit == 0 {
            return Err(MemoryError::bad_request(
                "tagging mentions limit must be at least 1",
            ));
        }
        let entity = resolve_entity_ref(self.vault(), &input.entity_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let mut mentions = Vec::new();
        for hit in self.vault().tagged_mentions(&entity)? {
            if mentions.len() == input.limit {
                break;
            }
            if !lane.is_entity_readable(&hit.turn)? {
                continue;
            }
            self.produced_from([hit.turn, hit.mention.message]);
            mentions.push(hit_view(&hit));
        }
        Ok(TaggingMentionsView {
            entity_ref: entity.to_hex(),
            mentions,
        })
    }
}
