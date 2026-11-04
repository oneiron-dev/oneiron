use std::collections::{BTreeSet, HashMap};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use heed::RoTxn;

use crate::claim::ClaimBody;
use crate::codebase::{CodebaseScopeKey, RepoRef};
use crate::context_pack::EmptyReason;
use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_MODEL, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_RELATIONSHIP,
    ENTITY_TYPE_SESSION, ENTITY_TYPE_SKILL, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK,
    ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD,
};
use crate::retrieval_quality::RetrievalQualityReport;
use crate::store::{RetrievalRunId, RetrievalSignal, StoreRead};
use crate::temporal::TemporalAnchorMode;

// Referenced only by the intra-doc links below; `cfg(doc)` keeps it out of
// ordinary builds, where it would be an unused import.
#[cfg(doc)]
use super::builder::PipelineBuilder;
use super::support::{read_entity_metadata, read_entity_metadata_row};

pub(crate) const DEFAULT_RESULT_LIMIT: usize = 20;
pub(super) const DEFAULT_SIGMA_SECS: u64 = 86_400;
pub(super) const MIN_WINDOW_RADIUS_SECS: u64 = 7 * 86_400;
pub(super) const TEMPORAL_FLOOR: f64 = 0.05;

/// A scored entity result. Defined in `oneiron-retrieval`, where fusion ranks it.
pub use oneiron_retrieval::pipeline::ScoredEntity;

pub use crate::store::retrieval_signal::Signal;

pub(super) const SECONDS_PER_DAY_F64: f64 = 86_400.0;
pub(super) const RETRIEVAL_TRACE_RRF_K: f32 = 60.0;

pub use crate::memory::retrieval_defaults::DEFAULT_RECENCY_HALF_LIFE_DAYS;

/// RET-010c recency half-life table, keyed by entity type byte. Values are
/// explicit contract rows, not derived from type defaults; unknown dynamic
/// type bytes fall back to [`DEFAULT_RECENCY_HALF_LIFE_DAYS`].
pub(super) const RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE: &[(u8, f32)] = &[
    (ENTITY_TYPE_CLAIM, 28.0),
    (ENTITY_TYPE_TURN, 28.0),
    (ENTITY_TYPE_SESSION, 28.0),
    (ENTITY_TYPE_MESSAGE, 28.0),
    (ENTITY_TYPE_PERSON, 365.0),
    (ENTITY_TYPE_RELATIONSHIP, 180.0),
    (ENTITY_TYPE_EVENT, 30.0),
    (ENTITY_TYPE_SKILL, 90.0),
    (ENTITY_TYPE_SUMMARY, 90.0),
    (ENTITY_TYPE_PLACE, 180.0),
    (ENTITY_TYPE_ASSET_TEXT, 90.0),
    (ENTITY_TYPE_CONVERSATION, 30.0),
    (ENTITY_TYPE_ORG, 180.0),
    (ENTITY_TYPE_FACET, 180.0),
    (ENTITY_TYPE_WORLD, 180.0),
    (ENTITY_TYPE_ASSET, 90.0),
    (ENTITY_TYPE_NOTIFICATION, 7.0),
    (ENTITY_TYPE_TASK_LIST, 30.0),
    (ENTITY_TYPE_TASK, 30.0),
    (ENTITY_TYPE_MACHINE, 180.0),
    (ENTITY_TYPE_CODE_ARTIFACT, 90.0),
    (ENTITY_TYPE_REDACTION_AUDIT, 365.0),
    (ENTITY_TYPE_MODEL, 180.0),
    (ENTITY_TYPE_POLICY_MANIFEST, 365.0),
    (ENTITY_TYPE_FEDERATION_GRANT, 365.0),
    (ENTITY_TYPE_ACCESS_GRANT, 365.0),
    (ENTITY_TYPE_COUNTERPARTY_CONTACT, 365.0),
    (ENTITY_TYPE_OUTBOUND_GRANT, 365.0),
    (ENTITY_TYPE_PSYCH_PROFILE, 365.0),
];

pub(crate) fn retrieval_recency_half_life_days_for_type(entity_type: u8) -> f32 {
    RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE
        .iter()
        .find_map(|(kind, half_life_days)| (*kind == entity_type).then_some(*half_life_days))
        .unwrap_or(DEFAULT_RECENCY_HALF_LIFE_DAYS)
}

/// ARCH-0004 §4.5 table value (`28.0 * 86_400`), derived from
/// [`DEFAULT_RECENCY_HALF_LIFE_DAYS`]. The temporal scorer applies it as
/// the decay constant in `exp(-age / tau)` — existing behavior, kept
/// unchanged.
pub(super) const RECENCY_DECAY_TAU_SECS: f64 =
    DEFAULT_RECENCY_HALF_LIFE_DAYS as f64 * SECONDS_PER_DAY_F64;
pub(super) const ALPHA_BASE: f64 = 0.7;
pub(super) const ALPHA_RANGE: f64 = 0.3;
pub(super) const ALPHA_TAU_SECS: f64 = 90.0 * SECONDS_PER_DAY_F64;
pub(super) const PPR_DAMPING: f32 = 0.15;
pub(super) const ADAPTIVE_ROUNDS: usize = 3;
pub(super) const PER_SCAN_CAP_FACTOR: usize = 4;
pub(super) const MAX_TEMPORAL_SEEK_BUFFER: usize = 8_192;
/// A scoped temporal channel widens to at most this multiple of the rows it
/// was asked for, and to at least [`TEMPORAL_WIDENING_FLOOR`] (ARCH-0004
/// #temporal-bound). The floor is the smallest that kept a reader whose
/// scope holds 0.5% of the vault exact in every call measured at 10k and
/// 100k records; the golden test `scoped_temporal_widening_stops_at_its_bound`
/// holds both.
pub(super) const TEMPORAL_WIDENING_MULTIPLE: usize = 8;
pub(super) const TEMPORAL_WIDENING_FLOOR: usize = 4_000;
pub(super) const COSINE_GHOST_VECTOR_THRESHOLD: f32 = 0.3;
// RET-01 only gates context-pack assembly. These are deliberately
// conservative: the vector floor needs an absent keyword signal too, while
// the score-gap check only compares raw cosine scores from the same channel.
// The floor and the strong-match score belong to the embedding space
// (`Vault::vector_evidence`).
pub(super) const CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO: f32 = 0.1;
pub(super) const CONTEXT_PACK_SCORE_GAP_EPSILON: f32 = f32::EPSILON;
pub(super) const CONTEXT_PACK_ANOMALOUS_REPEAT_RUN: usize = 32;

#[derive(Debug, Clone)]
pub(super) struct TemporalSearchConfig {
    pub(super) anchor_start: u64,
    pub(super) anchor_end: u64,
    pub(super) learned_start: Option<u64>,
    pub(super) learned_end: Option<u64>,
    pub(super) sigma_secs: u64,
    pub(super) anchor_mode: TemporalAnchorMode,
    pub(super) adaptive: bool,
    pub(super) limit: usize,
    /// A scoped call's widening: the rows the channel collects, scores and
    /// returns before the scope narrows them to `limit`. The window grows
    /// until it can fill them, but sigma settles once the window can fill
    /// `limit`, as an unscoped call's does, so a scope never changes sigma.
    /// `None` means `limit`.
    pub(super) widened: Option<usize>,
    /// Query-derived occurred restriction. Applied before temporal scan caps
    /// and score truncation; host-supplied temporal modes leave this unset.
    pub(super) query_occurred_range: Option<(u64, u64)>,
    /// The effort dial's default now anchor, not a host-supplied window.
    /// Only a host window ranks by time on its own and switches the
    /// recency blend off; the default anchor keeps it (ARCH-0004: the
    /// blend is constant at every effort level).
    pub(super) effort_anchor: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct EntityMetadata {
    pub(super) entity_type: u8,
    pub(super) occurred_start: u64,
    pub(super) occurred_end: u64,
    pub(super) learned_at: u64,
}

pub(crate) use crate::store::retrieval_values::{
    CandidateFilter, CandidateGate, SnapshotCandidateFilter,
};

pub(crate) use crate::context_pack::turn_fold::TurnFold;

#[derive(Clone, Copy)]
pub(super) struct PipelineFilterConfig<'a> {
    pub(super) authority_filter: &'a crate::gate::ResolvedRetrievalFilter,
    pub(super) candidate_filter: Option<&'a SnapshotCandidateFilter<'a>>,
    pub(super) type_filter: Option<&'a [u8]>,
    pub(super) criticality: Option<bool>,
    pub(super) since_filter: Option<u64>,
    pub(super) occurred_range: Option<(u64, u64)>,
    pub(super) learned_range: Option<(u64, u64)>,
    pub(super) repo_ref_filter: Option<&'a RepoRef>,
    pub(super) project_id_filter: Option<&'a str>,
    pub(super) facet_filter: Option<(EntityId, FacetMode)>,
    pub(super) relationship_filter: Option<(EntityId, RelMode)>,
    pub(super) world_scope: &'a WorldScope,
    /// The turn's resolved [`WorldScope::ActiveSet`] membership, resolved ONCE
    /// per run under the run's read transaction and borrowed by every
    /// per-candidate check. `None` for every other scope.
    pub(super) world_active_set: Option<&'a WorldAuthoritySet>,
    /// The stale federated worlds, read once per run under
    /// [`WorldScope::All`] when any is stamped: a scope that never named such
    /// a world keeps its claims out of every bounded channel, as the
    /// post-fusion world filter does. `None` otherwise.
    pub(super) stale_worlds:
        Option<&'a std::collections::BTreeMap<EntityId, crate::federation::WorldStaleStamp>>,
    /// The query's project-axis selection; [`CorpusScope::All`] is the
    /// default and a no-op, exactly like [`WorldScope::All`].
    ///
    /// Borrowed, not owned, so this config stays `Copy`
    /// ([`CorpusScope::AnyOf`] carries a `Vec`). The referent is
    /// canonicalized ONCE per run before this config is built, so an empty
    /// `AnyOf` fails the run closed before the first candidate is scanned and
    /// the candidate-scan twin stays a pure predicate.
    pub(super) corpus_scope: &'a CorpusScope,
    /// The device-local worlds, read once per run, when the run reads for a
    /// caller off this device: no candidate a device-local world keeps enters
    /// the run (DEC-0005), so no count, reason or budget sees it. `None` for
    /// a caller on this device.
    pub(super) device_local: Option<&'a BTreeSet<EntityId>>,
    /// The run's deadline. While a channel stage is open every candidate the
    /// scope gate reads is one of its checkpoints.
    pub(super) deadline: Option<&'a crate::retrieval_depth::RetrievalDeadline>,
    /// A pack's disclosure clamp, met at candidate generation (P7): a row the
    /// audience may not read takes no channel slot. `None` with the owner
    /// alone or outside a pack.
    pub(super) disclosure: Option<&'a crate::disclosure::DisclosureContext>,
}

#[derive(Default)]
pub(super) struct EntityMetadataCache {
    pub(super) temporal_report: Option<super::TemporalSearchReport>,
    entries: HashMap<EntityId, Option<EntityMetadata>>,
    /// Archive bits measured by this run's deletion-state reads, keyed as
    /// `entries`: the claim-status gate judges its archive refusal from
    /// the read that produced the metadata instead of reading again.
    archived: HashMap<EntityId, bool>,
    /// Unique evaluated candidates rejected by read authority or D19. Not telemetry.
    pub(super) read_suppressed: std::collections::HashSet<EntityId>,
    // Counts D19 body lookups across all gates sharing this run cache, including
    // probes whose decoded bodies are discarded rather than imported.
    #[cfg(test)]
    pub(super) claim_body_loads: usize,
}

/// Per-run memo for the D19 claim status gate.
///
/// `None` = the type-0 record is suppressed (failed the
/// [`claim_surfaceable`] predicate, or its body bytes failed the pinned
/// structural decode — fail-closed exclusion, AC 7). `Some(body)` = the
/// claim passed the gate; the decoded body is retained so the context-pack
/// hydrator can project fields WITHOUT a second MessagePack decode (AC 9).
/// Non-type-0 entities never enter this map (their bodies are opaque, AC 5).
#[derive(Default)]
pub(super) struct ClaimStatusGateCache {
    pub(super) include_stale: bool,
    /// Authenticated, transaction-local diary admission for this retrieval run.
    pub(super) private_note_ids: Option<std::sync::Arc<crate::claim::ScopedDiaryCandidates>>,
    /// The device-local worlds a caller off this device reads nothing of. A
    /// row they keep is no claim-status decision of this run: it is dropped
    /// before the gate reads it, memoized nowhere and counted nowhere
    /// (DEC-0005).
    pub(super) device_local: Option<std::sync::Arc<BTreeSet<EntityId>>>,
    pub(super) decisions: HashMap<EntityId, Option<ClaimBody>>,
    #[cfg(test)]
    pub(super) body_loads: usize,
}

pub(crate) struct PipelineOutput {
    pub(crate) embedding_matches: HashMap<EntityId, Vec<crate::embed::EmbeddingMatchEvidence>>,
    /// A dense list answered: the text index's or a declared space's.
    pub(crate) vector_completed: bool,
    pub(crate) revisions: HashMap<EntityId, crate::vault::RevisionRef>,
    /// The ids whose words a reranker scored at their pin in `revisions`.
    /// Those words are what the pack serves, never a later projection.
    pub(crate) words_bound: std::collections::HashSet<EntityId>,
    pub(crate) retrieval_quality: RetrievalQualityReport,
    pub(crate) scores: Vec<ScoredEntity>,
    /// The exact engine score evidence, independent of telemetry persistence.
    pub(crate) score_breakdown: Vec<crate::store::RetrievalScoreBreakdown>,
    /// Per TURN in `scores`, the MESSAGE rows it took the place of, best
    /// first. Empty unless the run folds messages into their turns.
    pub(crate) cited_messages: HashMap<EntityId, Vec<EntityId>>,
    pub(crate) capabilities: Vec<ScoredEntity>,
    pub(crate) claim_bodies: HashMap<EntityId, ClaimBody>,
    pub(crate) pending_vectors: Vec<PendingVectorEmbedding>,
    pub(crate) claims_suppressed: usize,
    pub(crate) read_suppressed: usize,
    pub(crate) cosine_ghosts_dampened: usize,
    /// Scored rows the pack's disclosure clamp withheld before selection
    /// (`PipelineBuilder::disclosure_preselect`).
    pub(crate) disclosure_clamped: Vec<EntityId>,
    pub(crate) total_in_scope: usize,
    pub(crate) empty_reason: Option<EmptyReason>,
    pub(crate) telemetry_run_id: Option<RetrievalRunId>,
    pub(crate) signals: Vec<RetrievalSignal>,
    /// Temporal phrases read from the query and what the run did with each.
    pub(crate) temporal_hints: Vec<crate::temporal::TemporalHintReport>,
    pub(crate) temporal_report: Option<super::TemporalSearchReport>,
    /// See `RetrievalTxnOutput::critical` (FIX 9760).
    pub(crate) critical: crate::context_pack::PackCriticalAccounting,
}

pub use crate::store::retrieval_values::{
    PendingVectorEmbedding, RetrievalWithPendingVectors, RetrievalWithTelemetry,
};

impl ClaimStatusGateCache {
    /// Whether a device-local world keeps `id` from this run.
    pub(super) fn keeps_device_local(
        &self,
        store: &StoreRead<'_>,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        match self.device_local.as_deref() {
            Some(flagged) => crate::settings::device_local_keeps_among(store, txn, flagged, id),
            None => Ok(false),
        }
    }

    /// A gate of its own for a probe or a bounded scan, under this run's
    /// stale, diary and device-local terms, with no decision carried over.
    pub(super) fn fresh(&self, include_stale: bool) -> Self {
        Self {
            include_stale,
            private_note_ids: self.private_note_ids.clone(),
            device_local: self.device_local.clone(),
            ..Self::default()
        }
    }
}

impl EntityMetadataCache {
    /// A suppressed private NOTE or pair grant contributes no observable
    /// receipt count, even when a pipeline probe rejected it before the
    /// scoped caller's final admission gate. Nor does a TASK outside the
    /// worlds or facets of the `credential` the run retrieves under, nor any
    /// other row outside its facets (owner ruling FACET-READ), nor a row of
    /// the `device_local` worlds a caller off this device reads nothing of.
    pub(super) fn countable_suppressed(
        &self,
        vault: &crate::Vault,
        store: &StoreRead<'_>,
        txn: &RoTxn<'_>,
        credential: Option<&crate::federation::Scope>,
        device_local: Option<&std::collections::BTreeSet<EntityId>>,
    ) -> Result<usize> {
        let mut count = 0;
        for id in &self.read_suppressed {
            if let Some(flagged) = device_local
                && crate::settings::device_local_keeps_among(store, txn, flagged, id)?
            {
                continue;
            }
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
                continue;
            };
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            let outside = match credential {
                Some(credential) if header.entity_type == crate::registry::ENTITY_TYPE_TASK => {
                    !crate::federation::record_scope::task_inside_credential(
                        store, txn, *id, &raw, credential,
                    )?
                }
                Some(credential) => !crate::federation::facet_read::facets_admit_in(
                    vault,
                    store,
                    txn,
                    *id,
                    &raw,
                    &credential.facets,
                )?,
                None => false,
            };
            count += usize::from(
                !outside
                    && crate::note::countable_read_suppression(
                        header.entity_type,
                        &raw[ENTITY_METADATA_HEADER_LEN..],
                    ),
            );
        }
        Ok(count)
    }

    pub(super) fn get(
        &mut self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityMetadata>> {
        if let Some(cached) = self.entries.get(id) {
            return Ok(*cached);
        }

        let metadata = read_entity_metadata(store, rtxn, id)?;
        self.entries.insert(*id, metadata);
        Ok(metadata)
    }

    /// [`Self::get`] also carrying the decoded record on a cache miss, for
    /// a caller that gates on the row it just read. A hit carries no
    /// record: row bytes are never memoized here.
    pub(super) fn get_row(
        &mut self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<(Option<EntityMetadata>, Option<crate::ports::EntityRecord>)> {
        if let Some(cached) = self.entries.get(id) {
            return Ok((*cached, None));
        }

        let read = read_entity_metadata_row(store, rtxn, id)?;
        self.entries.insert(*id, read.meta);
        if let Some(archived) = read.archived {
            self.archived.insert(*id, archived);
        }
        Ok((read.meta, read.row))
    }

    /// The archive bit for `id`: the one this run's deletion-state read
    /// measured, or, if none did (a plain [`Self::get`] filled the entry,
    /// or a legal hold returned first), the read `is_archived_in_txn`
    /// makes, kept for the rest of the run.
    pub(super) fn archived_bit(
        &mut self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if let Some(archived) = self.archived.get(id) {
            return Ok(*archived);
        }
        let archived = crate::vault_cleanup::is_archived_in_txn(store, rtxn, id)?;
        self.archived.insert(*id, archived);
        Ok(archived)
    }
}

pub use crate::claim::retrieval_scope::{FacetMode, RelMode};

/// World retrieval scope for the post-fusion claim world filter (ARCH-0004
/// claim-filtering: `worldId = vault.baseWorld` unless the query targets a
/// fictional world; ARCH-0022 world model). Selected per query via
/// [`PipelineBuilder::world`]; the default is [`WorldScope::All`].
///
/// A claim's world is the `world` key in its body — an absent key is base
/// reality (the elide-the-default pattern). Non-claim entities belong to base
/// reality. `WorldSet` selects ordinary world ids and explicitly includes or
/// excludes base; `CodebaseSet` selects repository-indexed entity membership.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum WorldScope {
    /// Span every world — base-reality claims plus every fictional / dream
    /// world's claims surface. The default; the context pack groups the
    /// survivors by world (base section first).
    All,
    /// Only base-reality claims — claims with NO `world` key (and all
    /// non-claim entities). Every world-scoped claim is removed.
    Base,
    /// Claims scoped to this world id PLUS base-reality claims. Claims scoped
    /// to any OTHER world are removed.
    World(EntityId),
    /// Entities explicitly indexed under this codebase scope key. This is the
    /// repository-backed world-set clamp and does not include base reality by
    /// default.
    CodebaseSet(CodebaseScopeKey),
    /// Explicit ordinary world ids, with a separately selected base-reality member.
    /// This is a narrowing read filter, never a replacement for principal authority.
    WorldSet(WorldAuthoritySet),
    /// The claim-backed per-turn ActiveSet (ONE-1420): reads are restricted to
    /// the base/world members the turn selected, and the selection itself must
    /// sit inside the owner-granted ALLOWED-SET.
    ///
    /// The selection is NOT carried by the variant — it lives on the builder
    /// sidecar written by [`PipelineBuilder::active_worlds`] /
    /// [`PipelineBuilder::default_active_worlds`], because it is per-turn state
    /// that is never stored. Selecting this variant through
    /// [`PipelineBuilder::world`] alone leaves no selection behind and fails
    /// the run closed with [`Error::InvalidConfig`]; it never degrades to
    /// [`WorldScope::All`].
    ActiveSet,
}

pub use crate::claim::world_access::{
    ActiveWorldSelection, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, ResolvedWorldAuthority, WORLD_ACCESS_SCHEMA_VERSION,
    WorldAuthoritySet, decode_world_access_claim_value, world_access_claim_body,
};

/// Opaque Dreamer working-set cursor.
///
/// The cursor is an offset into the caller's bounded working set. It is not a
/// vault snapshot handle and cannot be used to request the whole vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DreamerWorkingSetCursor {
    offset: usize,
}

impl DreamerWorkingSetCursor {
    #[must_use]
    pub const fn start() -> Self {
        Self { offset: 0 }
    }

    #[must_use]
    pub const fn from_offset(offset: usize) -> Self {
        Self { offset }
    }

    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

/// Hard cap for one Dreamer ingress working set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerWorkingSetBudget {
    max_items: usize,
}

impl DreamerWorkingSetBudget {
    #[must_use]
    pub const fn new(max_items: usize) -> Self {
        Self { max_items }
    }

    #[must_use]
    pub const fn max_items(self) -> usize {
        self.max_items
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerWorkingSetStopReason {
    BudgetExhausted,
    EndOfWorkingSet,
}

/// Budget-capped page of retrieval candidates for Dreamer ingress.
#[derive(Debug, Clone)]
pub struct DreamerWorkingSet {
    /// Execution quality of the retrieval that supplied this bounded page.
    pub retrieval_quality: RetrievalQualityReport,
    pub cursor: DreamerWorkingSetCursor,
    pub next_cursor: Option<DreamerWorkingSetCursor>,
    pub budget: DreamerWorkingSetBudget,
    pub rows: Vec<ScoredEntity>,
    pub stop_reason: Option<DreamerWorkingSetStopReason>,
    pub telemetry_run_id: Option<RetrievalRunId>,
}
