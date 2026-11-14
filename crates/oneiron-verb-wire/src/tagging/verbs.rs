//! Moved from `crates/oneiron/src/tagging/verbs.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::extraction::types::EncoderExecution;
use crate::tagging::freshness::TaggingFreshness;
use crate::tagging::freshness::TaggingMoodPartView;
use serde::Deserialize;
use serde::Serialize;

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
    /// How current the saved set is, when one reads.
    pub freshness: Option<TaggingFreshness>,
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
    /// How current the mood is, when there is one: stale too when it is an
    /// earlier set's, kept beside a turn last read in windows.
    pub mood_freshness: Option<TaggingFreshness>,
    /// The mood of each window of a turn read in several, never averaged.
    pub mood_parts: Vec<TaggingMoodPartView>,
    /// Store-clock second of the save.
    pub saved_at: u64,
    /// Surprise beside the set this one replaced, absent for the first set.
    pub surprise: Option<f32>,
    /// How current the set, its mentions and the provisional names it
    /// holds are beside the turn's text now.
    pub freshness: TaggingFreshness,
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
    /// How current its turn's saved set is.
    pub freshness: TaggingFreshness,
}

/// Every saved mention naming one entity, by turn then span place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaggingMentionsView {
    pub entity_ref: String,
    pub mentions: Vec<TaggingMentionHitView>,
}
