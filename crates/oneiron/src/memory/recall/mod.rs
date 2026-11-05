//! Recall and `MemoryPack` assembly (S6): recall/recall_in_session and the
//! scope-honesty + provenance plumbing.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::structural::*;
use super::*;
use crate::ports::EntityStoreRead;

mod admission;
mod call_mode;
mod conversation;
mod home;
mod hyde_host;
mod items;
mod paid;
mod presentation;
mod render_budget;
mod scope_honesty;
mod selection;
mod speculative;
mod stale;
pub use stale::MemoryStaleStamp;

pub use self::call_mode::{DEFAULT_CALL_MODE_DEADLINE, RecallEffort, resolve_recall_dial};
pub(crate) use self::conversation::{ConversationGate, conversation_candidate_admits};
pub use self::home::{
    HOME_RECALL_MERGE_ORDER, HomeRecallCaller, HomeRecallMergeOrder, RecallResidence,
    RecallResidenceHit, RecallResidenceSource,
};
#[cfg(feature = "sync")]
pub use self::home::{HomeRecallAsk, complete_with_home};
#[cfg(test)]
pub(super) use self::paid::PREPARED_SCORES_TAKEN;
pub use self::paid::{
    RecallRerank, RecallRerankHost, RerankDocument, RerankEgress, RerankReport, RerankScores,
    RerankSkip,
};
#[cfg(feature = "sync")]
pub(crate) use self::selection::RecallKinds;

use self::presentation::{hedge_bucket_for, hedge_bucket_for_band, value_text_of};
pub(super) use self::presentation::{parse_pack_format, truncate_text};
pub(super) use self::render_budget::execution_render_budget;
use self::selection::RecallPin;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, claim_surfaceable};
fn served_value_json(value: &rmpv::Value) -> serde_json::Value {
    crate::batch::export::served_messagepack_json(value.clone())
}
use crate::claim::retrieval_scope::FacetMode;
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, FieldProfile, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::memory::retrieval_defaults::DEFAULT_RECENCY_HALF_LIFE_DAYS;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::rerank::RerankOptions;
use crate::retrieval_depth::RecallExecution;
use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use crate::serialize::{SerializeConfig, serialize_pack};
use oneiron_model::llm::BudgetLease;

/// The S6 `MemoryPack` schema version.
pub const MEMORY_PACK_VERSION: u32 = 1;

const PPR_SEED_LIMIT: usize = 8;

/// Bounded claim scan behind scope-honesty world enumeration.
const SCOPE_HONESTY_SCAN_CAP: usize = 512;

/// The token budget a rendered pack is cut to when neither the caller nor
/// the reader profile it opted into names one: a default, never a ceiling
/// (FIX 9962, [`render_budget`]).
pub(super) const RECALL_TOKEN_BUDGET: usize = 4000;

/// Retrieval effort dial (S6). Deliberately distinct from `llm.rs`
/// `ReasoningEffort` (the LLM dial) and `context_pack.rs` `FieldProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Available vector, text, phonetic and temporal signals, then blend.
    Light,
    /// Light plus seed-specific search PPR.
    Medium,
    /// Medium plus two-hop expansion and top-30 reranking.
    High,
    /// Four-hop expansion and top-50 reranking.
    Xhigh,
    /// Ten-hop expansion, top-50 reranking and bitemporal search.
    Max,
}

impl Effort {
    /// Stable five-level wire vocabulary. Retired names are not aliases.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "light" => Some(Self::Light),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::Xhigh),
            "max" => Some(Self::Max),
            _ => None,
        }
    }
    /// Paid tiers require an explicit lease and reranker; never silent fallback.
    #[must_use]
    pub const fn requires_rerank(self) -> bool {
        matches!(self, Self::High | Self::Xhigh | Self::Max)
    }
    #[must_use]
    pub const fn graph_depth(self) -> u32 {
        match self {
            Self::Light => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Xhigh => 4,
            Self::Max => 10,
        }
    }
    #[must_use]
    pub const fn rerank_top_n(self) -> usize {
        match self {
            Self::Xhigh | Self::Max => 50,
            _ => 30,
        }
    }
}

/// Recall scoping (S5): world/facet narrowing and the kinds returned — unset
/// means the vault floor; the scope never widens beyond it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallScope {
    /// WORLD entity ref; scopes to that world plus base reality. Unset reads
    /// base plus the actor's active world (ARCH-0022), never every world.
    pub world_ref: Option<String>,
    /// Explicit All, Base or world/set selection; a non-base selection can decline base.
    #[serde(default)]
    pub worlds: Option<super::RecallWorlds>,
    /// Project audience ids. Empty requests add no narrowing to the credential.
    #[serde(default)]
    pub project_refs: Vec<String>,
    /// Conversation entity refs. Empty adds no narrowing; with `person_ref`,
    /// only conversations selected by both axes remain.
    #[serde(default)]
    pub conversation_refs: Vec<String>,
    /// PERSON entity ref; selects conversations where they authored at least
    /// one live MESSAGE, never conversations that merely mention them.
    pub person_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
    /// Registry kinds to return (`MESSAGE`, `CLAIM`, `PERSON`, ...). Unset
    /// returns every kind but the ones with no text of their own
    /// ([`CONTAINER_KINDS`]), so `limit` slots go to rows that say something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

/// Kinds that hold no text of their own: conversations and sessions, and the
/// worlds and facets that scope memories. Recall returns them only when
/// [`RecallScope::kinds`] names them.
///
/// A TURN is content, not a container: it is the embedding unit (ARCH-0004),
/// and recall returns a matched MESSAGE as its turn, quoting the message
/// ([`MemoryItem::cited_messages`]).
pub const CONTAINER_KINDS: [u8; 4] = [
    crate::registry::ENTITY_TYPE_CONVERSATION,
    crate::registry::ENTITY_TYPE_SESSION,
    crate::registry::ENTITY_TYPE_FACET,
    crate::registry::ENTITY_TYPE_WORLD,
];

/// What recall refuses from its request alone, before it reads the vault: a
/// zero limit, an `as_of` out of range, a paid effort without its lease and
/// reranker (unless its host serves no reranker), an unknown format or kind.
/// A door that pays for a query vector runs this first, so a request recall
/// would refuse costs no embedding.
pub(crate) fn check_recall_request(
    effort: Effort,
    scope: &RecallScope,
    limit: usize,
    format: Option<&str>,
    lease: Option<&BudgetLease>,
    execution: &RecallExecution<'_>,
) -> MemoryResult<()> {
    if limit == 0 {
        return Err(MemoryError::bad_request("recall limit must be at least 1"));
    }
    crate::memory::caps::check_as_of(execution.as_of)?;
    if effort.requires_rerank() && !execution.rerank_unavailable {
        if lease.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_LEASE_REQUIRED,
                "high, xhigh and max recall require a budget lease",
                &["Use light or medium, or present a lease."],
            ));
        }
        if execution.reranker.is_none() {
            return Err(MemoryError::bad_request(
                "paid recall requires a prepared reranker",
            ));
        }
    }
    format.map(parse_pack_format).transpose()?;
    recall_kinds(scope)?;
    Ok(())
}

/// The kinds a recall admits, resolved once from its scope. `None` is the
/// default: every kind but [`CONTAINER_KINDS`].
fn recall_kinds(scope: &RecallScope) -> MemoryResult<Option<Vec<u8>>> {
    let Some(kinds) = &scope.kinds else {
        return Ok(None);
    };
    if kinds.is_empty() {
        return Err(MemoryError::bad_request_with(
            "scope.kinds must name at least one registry kind",
            &["Name each kind once, or omit kinds for the default kinds."],
        ));
    }
    let mut types = kinds
        .iter()
        .map(|kind| type_byte_for_kind(kind))
        .collect::<MemoryResult<Vec<u8>>>()?;
    types.sort_unstable();
    types.dedup();
    Ok(Some(types))
}

/// Item provenance (S6, default-on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemoryProvenance {
    /// Claim source string, or `record` for structural source records.
    pub source: String,
    /// This revision plus superseded ancestors (32-hex ids). A TURN's also
    /// names each message its text is read from that the reader may read,
    /// so a live view of the turn follows a change to any of them.
    pub source_revision_ids: Vec<String>,
    /// Evidence TURN ids. Populated structurally for MESSAGE items; claim
    /// evidence stamping is the extraction pipeline's later responsibility.
    pub evidence_turn_ids: Vec<String>,
}

/// One memory pack item (S6 schema).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemoryItem {
    /// The ASSET id, when this hit is a media or text asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    /// Raw per-kind evidence from each exact space, before fusion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedding_matches: Vec<crate::store::embedding::EmbeddingMatchEvidence>,
    /// Short ref, hydratable via [`Memory::hydrate`]: the same `name:hash`
    /// a witness receipt returns, never revision-qualified.
    pub short_id: String,
    /// The retained revision (32 hex) retrieval read this item at, when it
    /// pinned one. [`Self::reference`] joins it to `short_id`. A TURN's is
    /// the text revision of the words it serves, its own and those its
    /// cited messages quote: it commits to each source message's state, and
    /// reads those words back after an edit while the messages' history
    /// holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision_ref: Option<String>,
    /// Registry kind string.
    pub kind: String,
    /// Predicate (claims only).
    pub predicate: Option<String>,
    /// Text rendering of the item value/content (capped), as plain text;
    /// `vault.refs.links` with `texts` reads its `oneiron://` links as spans
    /// for the reader.
    pub value_text: String,
    /// Calibrated-absolute confidence in [0, 1] — NEVER set-relative:
    /// read from the claim body, independent of the candidate set.
    pub confidence: f32,
    /// Hedge vocabulary bucket: a claim's stored confidence band, by name
    /// (FIX 7761); a structural record's fixed certainty otherwise.
    pub hedge_bucket: String,
    /// Where a claim's band came from: a calibrated decider, or the house
    /// table for a confidence written as a number alone. `None` for an item
    /// that is not a claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_basis: Option<crate::claim::VerdictBasis>,
    /// Provenance (default-on).
    pub provenance: MemoryProvenance,
    /// Retained foreign content is explicitly stale after its pact stops refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<MemoryStaleStamp>,
    /// World hex, when world-scoped.
    pub world: Option<String>,
    /// Facet hex, when faceted.
    pub facet: Option<String>,
    /// The claim's explicit project audience, not a topic or a WORLD.
    pub project_ref: Option<String>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
    /// A conversation record's current reactions, one grouped line per
    /// glyph (`👍×8 (Anna, Ben, +6)`); a TURN's lines are followed by those of
    /// each message it quotes ([`Self::cited_messages`]). Empty for every
    /// other item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reactions: Vec<String>,
    /// For a TURN item, the messages whose words the query matched, best
    /// first: a hit on a message returns its turn, which quotes the message
    /// here. Empty for every other item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cited_messages: Vec<CitedMessage>,
    /// For a TURN or MESSAGE item, the conversation it is in (32 hex), when
    /// the reader may read that conversation. `None` for every other item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// The item's record as a typed record ref (OF-063), built from the view
    /// the reader's read admitted, with no other read. It carries no
    /// revision pin: [`Self::reference`] still names the revision read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<crate::lens::RecordRef>,
}

/// A MESSAGE a TURN item quotes: the words a query matched, as they were said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CitedMessage {
    /// The message's short ref, the one its witness receipt returned.
    pub short_id: String,
    /// The message's text (capped), as the turn's text revision pins it.
    pub value_text: String,
    /// The message as a typed record ref (OF-063), the one the reader's read
    /// of it admitted, with no other read. It carries no revision pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<crate::lens::RecordRef>,
}

impl MemoryItem {
    /// The ref that hydrates exactly the revision this item was read at:
    /// `short_id@source_revision_ref`, or `short_id` when nothing was pinned.
    #[must_use]
    pub fn reference(&self) -> String {
        match &self.source_revision_ref {
            Some(revision) => format!("{}@{revision}", self.short_id),
            None => self.short_id.clone(),
        }
    }
}

/// Scope honesty (S6): what the scope excluded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopeHonesty {
    /// Worlds holding surfaceable claims outside the requested scope.
    pub out_of_scope_worlds: Vec<String>,
    /// The census stopped at its scan cap or at the answer's deadline, so a
    /// world past it may be missing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub census_capped: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Retrieval accounting (S6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalMeta {
    #[serde(default)]
    pub quality: RetrievalQuality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradation: Vec<RetrievalDegradation>,
    #[serde(default)]
    pub confidence_adjustment: ConfidenceAdjustment,
    /// True when only sparse (lexical/graph) signals ran — no dense
    /// vector signal is available until the embedder lane lands.
    pub sparse: Option<bool>,
    /// Candidates considered by the retrieval pipeline.
    pub total_candidates: u64,
    /// CLAIM items in the returned pack.
    pub claims_returned: u64,
    /// Retained wire field. Always `None`: paid work never pretends to complete.
    pub deep_pending: Option<bool>,
    /// Requested stages skipped or cut at the explicit deadline: the pack
    /// holds what was ready when it came due. Also set when a device that
    /// syncs only what it opened answered without its home
    /// ([`MemoryPack::residence`]).
    #[serde(default)]
    pub partial: bool,
    /// Time phrases read from the query, in order. `used` ones narrowed the
    /// occurred-time window; `unresolved` and `future` ones were skipped and
    /// recall ran on its other signals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporal_hints: Vec<crate::temporal::TemporalHintReport>,
    /// What the rerank stage of a recall at high, xhigh or max did: the
    /// model whose scores ordered the top block, or why it was skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerank: Option<RerankReport>,
    /// The request's `limit` was past the ceiling (1,000 rows) and was
    /// served at it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub limit_clamped: bool,
}

/// The facade projection of a `ContextPack` (S6, `pack_version: 1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemoryPack {
    /// Ranked items.
    pub items: Vec<MemoryItem>,
    /// What the scope excluded.
    pub scope_honesty: ScopeHonesty,
    /// Retrieval accounting.
    pub retrieval_meta: RetrievalMeta,
    /// Schema version (always [`MEMORY_PACK_VERSION`]).
    pub pack_version: u32,
    /// Text rendering in the requested OF-096 format; `None` = typed only.
    pub rendered: Option<String>,
    /// The bound actor's requested/ceiling/intersection receipt for every read in this pack.
    pub narrowing: Box<ScopedReadReceipt>,
    /// The finalized serving run, absent when capture is off or no run published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_run_id: Option<crate::store::RetrievalRunId>,
    /// What a device that syncs only what it opened says of the windows it
    /// does not hold (FIX 2905): local-only and incomplete when it answered
    /// alone, which also marks `retrieval_meta.partial`. The home's
    /// discovery hits are separate references the local pack does not hold,
    /// never items; a hit's window opens it. `None`: this device holds every
    /// window it may read, or runs no sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residence: Option<RecallResidence>,
}

/// The pack a recall answers with when its door stops waiting at the
/// deadline before retrieval finished: nothing was ready, so no items, marked
/// partial, under the reader's own read receipt. The census did not run, so
/// it says it stopped early. An opened device's says it answered alone.
fn cut_pack(vault: &crate::Vault, receipt: &ScopedReadReceipt) -> MemoryPack {
    let quality = RetrievalQuality::Passthrough;
    let mut pack = MemoryPack {
        items: Vec::new(),
        scope_honesty: ScopeHonesty {
            out_of_scope_worlds: Vec::new(),
            census_capped: true,
        },
        retrieval_meta: RetrievalMeta {
            quality,
            confidence_adjustment: quality.confidence_adjustment(),
            sparse: Some(true),
            partial: true,
            ..RetrievalMeta::default()
        },
        pack_version: MEMORY_PACK_VERSION,
        rendered: None,
        narrowing: Box::new(receipt.clone()),
        retrieval_run_id: None,
        residence: None,
    };
    pack.stamp_residence(home::local_residence(vault, None));
    pack
}

impl Memory<'_> {
    /// The worlds one recall reads (ARCH-0022). A named world reads with base
    /// reality; no name reads the actor's default, base plus its active world.
    /// A handle bound to a room turn meets either with the room's Scope.
    fn recall_worlds(
        &self,
        scope: &RecallScope,
    ) -> MemoryResult<Option<crate::claim::world_access::WorldAuthoritySet>> {
        self.room_met(self.selected_worlds(scope)?)
    }

    /// The worlds `requested` names met with a bound room turn's worlds as
    /// they are now.
    fn room_met(
        &self,
        requested: Option<crate::claim::world_access::WorldAuthoritySet>,
    ) -> MemoryResult<Option<crate::claim::world_access::WorldAuthoritySet>> {
        let room = match self.room_turn_now()? {
            Some(turn) => crate::context_board::scope_worlds(&turn.terms.get().worlds)?,
            None => None,
        };
        Ok(match (requested, room) {
            (Some(requested), Some(room)) => Some(requested.meet(&room)),
            (requested, None) => requested,
            (None, room) => room,
        })
    }
}

use crate::memory::affect::QueryAffect;
use crate::retrieval_depth::RecallTelemetry;

/// `vault.recall`'s inputs, spelled exactly as §HEAD-CONTRACT does.
///
/// Every field but `query` is optional and defaults to the contract's default,
/// so an omitting client and a spelling-everything client reach the same
/// engine call.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallRequest {
    pub query: String,
    /// One of the five effort levels, or `call`: call mode for live calls,
    /// light effort under a hard deadline. Omitted means `medium`.
    #[serde(default)]
    pub effort: Option<crate::memory::RecallEffort>,
    #[serde(default)]
    pub scope: Option<crate::memory::RecallScope>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub format: Option<String>,
    /// The token budget `format`'s rendering is cut to; 0 renders it uncut.
    /// Omitted, the window budget of `reader_agent_ref`'s memory profile,
    /// else 4,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<u64>,
    /// An agent definition the caller reads whose memory profile sizes the
    /// rendering when `token_budget` is omitted. It grants no read, and one
    /// the caller cannot read adds no budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_agent_ref: Option<String>,
    /// Unix seconds the query's time words resolve against: `yesterday` is
    /// the day before it. Omitted, they resolve against now.
    #[serde(default)]
    pub as_of: Option<u64>,
    /// A hard deadline, in milliseconds from when the request arrives,
    /// 1 to 60000: at it, recall answers with the best results ready, marked
    /// `partial`. Omitted, recall runs to the end, except call mode, which
    /// takes the vault's call-mode deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// A media query (OF-370): bytes the host embeds into one declared space
    /// through the `ai.embed` rung that space's id names, searched as that
    /// space's list beside the query's. A host that serves no such rung
    /// refuses the recall with `MODEL_UNAVAILABLE`; it never recalls without
    /// the media.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<crate::code_run::vault_read::ContextPackMediaQuery>,
    /// The affect the query is asked in (OF-423), as the context pack takes
    /// it: emotion congruence ranks a candidate by how near its own valence,
    /// arousal and dominance sit. Omitted, recall ranks as before.
    #[serde(
        default,
        alias = "queryAffect",
        skip_serializing_if = "Option::is_none"
    )]
    pub query_affect: Option<QueryAffect>,
    /// Local diagnostics only. Capture stays opt-in at vault configuration;
    /// the request can add stage detail and the host's exact turn identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<RecallTelemetry>,
}
