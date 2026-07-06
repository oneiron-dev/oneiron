//! CLAIM body ABI + typed Claim API (ARCH-0003, pinned decisions D11/D17/D18).
//!
//! Type byte 0 is the single SEMANTIC entity type. Its MessagePack body is a
//! pinned storage ABI: the key set in [`CLAIM_BODY_KEYS`] (D11 short keys) is
//! the ON-DISK vocabulary. ARCH-0003's camelCase `Claim` shape is the
//! app-layer view; the engine never stores camelCase keys.
//!
//! Every type-0 write on every path (`Vault::put_entity`, `BatchBuilder`,
//! `TxnBatchBuilder`, sync replay via `apply_ops`) is structurally validated
//! here (D18). Bodies of all OTHER type bytes stay opaque at the storage
//! layer. Validation is fail-closed: a body that does not decode to a
//! MessagePack map carrying exactly the pinned vocabulary with all required
//! fields well-typed is rejected with [`Error::InvalidClaimBody`] and nothing
//! is written.
//!
//! The predicate gate (D17) is part of body validation: predicates must match
//! the pinned grammar (≥2 segments of `[a-z][a-z0-9_]*` joined by `.`, total
//! ≤128 bytes) or the write fails with [`Error::InvalidPredicate`]. The
//! `edge.*` namespace is reserved for the engine's provenance Claims: public
//! writes are rejected with [`Error::ReservedPredicate`]; the doors are the
//! `pub(crate)` reserved-namespace path used by the provenance unit
//! (`TxnBatchBuilder::put_reserved_claim`) and, under the `sync` feature,
//! the replicated-put door (`put_replicated`) used by CRDT replay so remote
//! provenance Claims rematerialize — both still run this full structural
//! validation. Well-formed UNKNOWN predicates are accepted — the crate is
//! predicate-agnostic for semantics (ARCH-0003 §G.1). Crate-owned
//! well-known predicates are listed in [`CLAIM_PREDICATE_REGISTRY`] and carry
//! the first-segment layer prefix `core`, `companion`, or `eiri`; that is a
//! schema/code-review convention, not a package split, plugin runtime,
//! consent matrix, or semantic dispatch registry.

use std::{collections::HashSet, io::Cursor, sync::Mutex};

use rmpv::Value;

use crate::affect::{
    AFFECT_TRIGGER_PREDICATE,
    coping::{COPING_OUTCOME_PREDICATE, validate_coping_outcome_claim_structure},
    validate_affect_trigger_claim_structure,
};
use crate::error::{Error, Result};
use crate::types::{
    ContextEntity, ContextPack, ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, EdgeConfirmationStatus, EdgeInfo,
    EdgeKind, EmptyContext, EmptyReason, EntityId, MemoryTimeline, MemoryTimelineRecord,
    MemoryTimelineRecordState, ScoredEntity,
};
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    gate::PolicyManifestResolution,
};

// Test-only MessagePack decode counter: AC 9 of the D19 unit pins "body
// decoded ONCE per result for gate + projection" — tests assert exact
// decode counts through this counter instead of round-tripping output.
#[cfg(test)]
thread_local! {
    static CLAIM_BODY_DECODE_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_claim_body_decode_count() {
    CLAIM_BODY_DECODE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn claim_body_decode_count() -> usize {
    CLAIM_BODY_DECODE_COUNT.with(std::cell::Cell::get)
}

/// Pinned ON-DISK MessagePack key set for type-0 (CLAIM) bodies (D11).
///
/// Order is canonical: the engine's encoder emits present fields in this
/// order, and the context-pack field profiles are prefixes of this list
/// (Minimal = first 2, Standard = first 5, Full = first 11; the lifecycle
/// keys `appr`/`life`/`stale` drive the D19 read-path status gate
/// (`claim_surfaceable`) and are excluded from every serialization
/// profile).
pub const CLAIM_BODY_KEYS: [&str; 14] = [
    "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope", "appr",
    "life", "stale",
];

pub(crate) const KEY_PRED: &str = CLAIM_BODY_KEYS[0];
pub(crate) const KEY_VAL: &str = CLAIM_BODY_KEYS[1];
pub(crate) const KEY_CONF: &str = CLAIM_BODY_KEYS[2];
pub(crate) const KEY_SAL: &str = CLAIM_BODY_KEYS[3];
pub(crate) const KEY_EVID: &str = CLAIM_BODY_KEYS[4];
pub(crate) const KEY_FROM: &str = CLAIM_BODY_KEYS[5];
pub(crate) const KEY_TO: &str = CLAIM_BODY_KEYS[6];
pub(crate) const KEY_SRC: &str = CLAIM_BODY_KEYS[7];
pub(crate) const KEY_WORLD: &str = CLAIM_BODY_KEYS[8];
pub(crate) const KEY_SUBJ: &str = CLAIM_BODY_KEYS[9];
pub(crate) const KEY_SCOPE: &str = CLAIM_BODY_KEYS[10];
pub(crate) const KEY_APPR: &str = CLAIM_BODY_KEYS[11];
pub(crate) const KEY_LIFE: &str = CLAIM_BODY_KEYS[12];
pub(crate) const KEY_STALE: &str = CLAIM_BODY_KEYS[13];

/// Predicate namespace for productizable memory-API records.
pub const PREDICATE_NAMESPACE_CORE: &str = "core";

/// Predicate namespace for relationship-aware companion extensions.
pub const PREDICATE_NAMESPACE_COMPANION: &str = "companion";

/// Predicate namespace for Eiri persona-specific extensions.
pub const PREDICATE_NAMESPACE_EIRI: &str = "eiri";

/// Layer namespace prefixes allowed for crate-owned predicate ids.
pub const PREDICATE_LAYER_NAMESPACES: [&str; 3] = [
    PREDICATE_NAMESPACE_CORE,
    PREDICATE_NAMESPACE_COMPANION,
    PREDICATE_NAMESPACE_EIRI,
];

/// Predicate used for synthetic prospective-query hint side records.
pub const PREDICATE_LEXICAL_QUERY_HINT: &str = "core.lexical.query_hint";

/// Pinned companion-expression predicate for the relationship/persona layer.
pub const PREDICATE_COMPANION_EXPRESSION: &str = "companion.expression";

/// Claim predicate for an unresolved conflict state.
pub const PREDICATE_CONFLICT_OPEN: &str = "core.conflict.open";

/// Claim predicate for a resolved conflict state.
pub const PREDICATE_CONFLICT_RESOLVED: &str = "core.conflict.resolved";

/// Claim-module well-known predicate registry.
///
/// This is only the crate-owned schema list used by structural validators and
/// namespace-convention tests. Unknown well-formed predicates remain accepted.
pub const CLAIM_PREDICATE_REGISTRY: [&str; 4] = [
    PREDICATE_LEXICAL_QUERY_HINT,
    PREDICATE_COMPANION_EXPRESSION,
    PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED,
];

/// Maximum number of lexical query hints one claim-candidate write may emit.
pub(crate) const MAX_LEXICAL_QUERY_HINTS_PER_CLAIM: usize = 8;

/// Maximum UTF-8 byte length of one prospective query hint.
pub(crate) const MAX_LEXICAL_QUERY_HINT_BYTES: usize = 256;
pub(crate) const LEXICAL_QUERY_HINT_ID_PREFIX: [u8; 2] = *b"LH";

const LEXICAL_HINT_KIND: &str = "prospective_query";
const LEXICAL_HINT_VALUE_KEY_KIND: &str = "kind";
const LEXICAL_HINT_VALUE_KEY_QUERY: &str = "query";
const LEXICAL_HINT_VALUE_KEY_TARGET: &str = "target";

/// Actor key bound to a scoped read lane over the `core:read` surface.
///
/// The fields are private and construction rejects blank actor refs, so a
/// [`ScopedRead`] cannot be built as an unkeyed bulk read handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedReadActorKey {
    actor_ref: String,
    actor_class: Option<String>,
}

impl ScopedReadActorKey {
    #[must_use]
    pub fn new(actor_ref: impl Into<String>) -> Option<Self> {
        Self::from_parts(actor_ref.into(), None)
    }

    #[must_use]
    pub fn with_actor_class(
        actor_ref: impl Into<String>,
        actor_class: impl Into<String>,
    ) -> Option<Self> {
        Self::from_parts(actor_ref.into(), Some(actor_class.into()))
    }

    fn from_parts(actor_ref: String, actor_class: Option<String>) -> Option<Self> {
        if actor_ref.trim().is_empty() {
            return None;
        }
        let actor_class = actor_class
            .and_then(|class| (!class.trim().is_empty()).then(|| class.trim().to_owned()));
        Some(Self {
            actor_ref: actor_ref.trim().to_owned(),
            actor_class,
        })
    }

    #[must_use]
    pub fn actor_ref(&self) -> &str {
        &self.actor_ref
    }

    #[must_use]
    pub fn actor_class(&self) -> Option<&str> {
        self.actor_class.as_deref()
    }
}

/// Actor-keyed read lane for the core read surface.
///
/// All methods preserve the existing claim surface admission gate and
/// then layer policy scoped-grant matching for type-0 CLAIM entities.
pub struct ScopedRead<'a> {
    vault: &'a crate::vault::Vault,
    actor_key: ScopedReadActorKey,
    policy: Mutex<Option<PolicyManifestResolution>>,
}

impl crate::vault::Vault {
    #[must_use]
    pub fn scoped_read(&self, actor_key: ScopedReadActorKey) -> ScopedRead<'_> {
        ScopedRead {
            vault: self,
            actor_key,
            policy: Mutex::new(None),
        }
    }
}

impl<'a> ScopedRead<'a> {
    #[must_use]
    pub fn vault(&self) -> &'a crate::Vault {
        self.vault
    }

    #[must_use]
    pub fn actor_key(&self) -> &ScopedReadActorKey {
        &self.actor_key
    }

    pub fn search(&self, query: &str, vector: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        let fetch_limit = self.search_candidate_limit(limit, true, true)?;
        let results = self
            .vault
            .query()
            .search(query, vector, None, fetch_limit)
            .run()?;
        self.filter_scored_entities_to_limit(results, limit)
    }

    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        let fetch_limit = self.search_candidate_limit(limit, true, false)?;
        let results = self.vault.search_text(query, fetch_limit)?;
        self.filter_scored_entities_to_limit(results, limit)
    }

    pub fn search_vector(&self, query: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        let fetch_limit = self.search_candidate_limit(limit, false, true)?;
        let results = self.vault.search_vector(query, fetch_limit)?;
        self.filter_scored_entities_to_limit(results, limit)
    }

    pub fn get(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        Ok(self.get_entity_parts(id)?.map(|(_, _, body)| body))
    }

    pub fn get_entity_parts(&self, id: &EntityId) -> Result<Option<(u8, u64, Vec<u8>)>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let Some(raw) = self.vault.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(Some((header.entity_type, header.learned_at, body.to_vec())));
        }
        if !self.is_claim_raw_readable_in(&rtxn, id, raw)? {
            return Ok(None);
        }
        Ok(Some((header.entity_type, header.learned_at, body.to_vec())))
    }

    pub fn hydrate_short_id(
        &self,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<crate::HydratedShortId>> {
        let Some(result) = self.vault.hydrate_short_id(short_id, content_hash)? else {
            return Ok(None);
        };
        if result.body.is_none() {
            if result.deletion.is_some() {
                return Ok(Some(result));
            }
            return if result.entity_type == ENTITY_TYPE_CLAIM {
                Ok(None)
            } else {
                Ok(Some(result))
            };
        }
        if result.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(Some(result));
        }
        let Some(body) = result.body.as_deref() else {
            return Ok(None);
        };
        let body = decode_claim_body(body, true)?;
        if self.is_claim_readable_with_body(&result.id, &body)? {
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    pub fn memory_timeline(&self, anchor: &EntityId) -> Result<MemoryTimeline> {
        if !self.is_entity_readable(anchor)? {
            return Ok(MemoryTimeline {
                anchor: *anchor,
                records: Vec::new(),
            });
        }
        let mut timeline = self.vault.memory_timeline(anchor)?;
        timeline.records = self.filter_memory_timeline_records(timeline.records)?;
        Ok(timeline)
    }

    pub fn edges_out(&self, id: &EntityId) -> Result<Option<Vec<EdgeInfo>>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        if !self.is_entity_readable_with_policy_in(&rtxn, &policy, id)? {
            return Ok(None);
        }
        let edges = self.edges_out_in(&rtxn, id)?;
        let mut kept = Vec::with_capacity(edges.len());
        for edge in edges {
            if self.is_entity_readable_with_policy_in(&rtxn, &policy, &edge.target)? {
                kept.push(edge);
            }
        }
        Ok(Some(kept))
    }

    pub fn search_candidate_limit(
        &self,
        requested: usize,
        include_text: bool,
        include_vector: bool,
    ) -> Result<usize> {
        if requested == 0 {
            return Ok(0);
        }

        let rtxn = self.vault.store.env.read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        let diagnostics = policy.diagnostics();
        if !diagnostics.loaded_manifest_forces_fail_closed() && !policy.has_scoped_read_grants() {
            return Ok(requested);
        }
        drop(rtxn);

        self.vault
            .scoped_read_search_candidate_limit(requested, include_text, include_vector)
    }

    pub fn filter_scored_entities(&self, results: Vec<ScoredEntity>) -> Result<Vec<ScoredEntity>> {
        self.filter_scored_entities_to_limit(results, usize::MAX)
    }

    fn filter_scored_entities_to_limit(
        &self,
        results: Vec<ScoredEntity>,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        let mut kept = Vec::with_capacity(results.len());
        for result in results {
            if self.is_entity_readable_with_policy_in(&rtxn, &policy, &result.id)? {
                kept.push(result);
                if kept.len() == limit {
                    break;
                }
            }
        }
        Ok(kept)
    }

    pub fn filter_context_pack(&self, pack: &mut ContextPack) -> Result<()> {
        let rtxn = self.vault.store.env.read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        let previous_count = pack.results.len() + pack.neighbors.len();
        let (results, result_suppressed) =
            self.filter_context_entities(&rtxn, &policy, std::mem::take(&mut pack.results))?;
        let (mut neighbors, neighbor_suppressed) =
            self.filter_context_entities(&rtxn, &policy, std::mem::take(&mut pack.neighbors))?;
        let reachability_suppressed = if result_suppressed > 0 {
            self.retain_neighbors_reachable_from_results(&rtxn, &mut neighbors, &results)?
        } else {
            0
        };
        pack.results = results;
        pack.neighbors = neighbors;
        pack.stats.claims_suppressed +=
            result_suppressed + neighbor_suppressed + reachability_suppressed;

        if previous_count > 0 && pack.results.is_empty() && pack.neighbors.is_empty() {
            pack.empty = Some(EmptyContext {
                reason: EmptyReason::FilterMatchedNone,
                total_in_scope: 0,
                hint: "scoped_read returned no actor-readable entities".to_owned(),
            });
        }
        Ok(())
    }

    pub fn is_entity_readable(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.is_entity_readable_in(&rtxn, id)
    }

    fn is_entity_readable_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let policy = self.policy_manifest_in(rtxn)?;
        self.is_entity_readable_with_policy_in(rtxn, &policy, id)
    }

    pub(crate) fn is_entity_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(raw) = self.vault.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_CLAIM {
            self.is_claim_raw_readable_with_policy_in(rtxn, policy, id, raw)
        } else {
            Ok(true)
        }
    }

    fn is_claim_raw_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let policy = self.policy_manifest_in(rtxn)?;
        self.is_claim_raw_readable_with_policy_in(rtxn, &policy, id, raw)
    }

    fn is_claim_raw_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        if raw.len() == ENTITY_METADATA_HEADER_LEN && self.vault.is_deleted_shell(id)? {
            return Ok(false);
        }
        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        self.is_claim_readable_with_body_and_policy_in(rtxn, policy, id, &body)
    }

    fn is_claim_readable_with_body(&self, id: &EntityId, body: &ClaimBody) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.is_claim_readable_with_body_in(&rtxn, id, body)
    }

    fn is_claim_readable_with_body_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
    ) -> Result<bool> {
        let policy = self.policy_manifest_in(rtxn)?;
        self.is_claim_readable_with_body_and_policy_in(rtxn, &policy, id, body)
    }

    fn is_claim_readable_with_body_and_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        body: &ClaimBody,
    ) -> Result<bool> {
        if !claim_surfaceable(body) {
            return Ok(false);
        }
        let claim_facets = self.vault.claim_facet_refs_in(rtxn, id)?;
        Ok(crate::gate::scoped_read_claim_allowed(
            policy,
            &self.actor_key,
            body,
            &claim_facets,
        ))
    }

    fn filter_context_entities(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        entities: Vec<ContextEntity>,
    ) -> Result<(Vec<ContextEntity>, usize)> {
        let mut kept = Vec::with_capacity(entities.len());
        let mut claims_suppressed = 0;
        for mut entity in entities {
            if self.is_entity_readable_with_policy_in(rtxn, policy, &entity.id)? {
                self.filter_context_entity_edges(rtxn, policy, &mut entity)?;
                kept.push(entity);
            } else if entity.entity_type == ENTITY_TYPE_CLAIM {
                claims_suppressed += 1;
            }
        }
        Ok((kept, claims_suppressed))
    }

    fn retain_neighbors_reachable_from_results(
        &self,
        rtxn: &heed::RoTxn<'_>,
        neighbors: &mut Vec<ContextEntity>,
        results: &[ContextEntity],
    ) -> Result<usize> {
        let mut reachable_ids = HashSet::new();
        for entity in results {
            if let Some(edges) = entity.edges.as_ref() {
                reachable_ids.extend(
                    edges
                        .iter()
                        .filter(|edge| context_pack_edge_can_reach_neighbor(edge))
                        .map(|edge| edge.target),
                );
                continue;
            }
            for edge in self.edges_out_in(rtxn, &entity.id)? {
                if context_pack_edge_can_reach_neighbor(&edge) {
                    reachable_ids.insert(edge.target);
                }
            }
        }
        let mut claims_suppressed = 0;
        neighbors.retain(|entity| {
            let keep = reachable_ids.contains(&entity.id);
            if !keep && entity.entity_type == ENTITY_TYPE_CLAIM {
                claims_suppressed += 1;
            }
            keep
        });
        Ok(claims_suppressed)
    }

    fn edges_out_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<EdgeInfo>> {
        const MAX_SCOPED_READ_EDGE_REACHABILITY_ROWS: usize = 100_000;

        let mut edges = Vec::new();
        for entry in self
            .vault
            .store
            .edges_out
            .prefix_iter(rtxn, id.as_bytes())?
        {
            let (key, value) = entry?;
            if edges.len() >= MAX_SCOPED_READ_EDGE_REACHABILITY_ROWS {
                return Err(Error::IndexOverflow("scoped read edge reachability"));
            }
            edges.push(crate::vault::parse_edge_record(key, value)?);
        }
        Ok(edges)
    }

    fn filter_context_entity_edges(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        entity: &mut ContextEntity,
    ) -> Result<()> {
        let Some(edges) = entity.edges.as_mut() else {
            return Ok(());
        };
        let mut kept = Vec::with_capacity(edges.len());
        for edge in edges.drain(..) {
            if self.is_entity_readable_with_policy_in(rtxn, policy, &edge.target)? {
                kept.push(edge);
            }
        }
        *edges = kept;
        Ok(())
    }

    fn filter_memory_timeline_records(
        &self,
        records: Vec<MemoryTimelineRecord>,
    ) -> Result<Vec<MemoryTimelineRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let policy = self.policy_manifest_in(&rtxn)?;
        let mut kept = Vec::with_capacity(records.len());
        for record in records {
            let readable = match (record.state, record.entity_type) {
                (MemoryTimelineRecordState::Missing, _) => false,
                (_, Some(ENTITY_TYPE_CLAIM)) => {
                    self.is_entity_readable_with_policy_in(&rtxn, &policy, &record.id)?
                }
                (_, Some(_)) => true,
                (_, None) => false,
            };
            if readable {
                kept.push(record);
            }
        }
        let kept_ids: HashSet<EntityId> = kept.iter().map(|record| record.id).collect();
        for record in &mut kept {
            record.supersedes.retain(|id| kept_ids.contains(id));
            record.superseded_by.retain(|id| kept_ids.contains(id));
        }
        Ok(kept)
    }

    pub(crate) fn policy_manifest_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<PolicyManifestResolution> {
        let cached_policy = self
            .policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(policy) = cached_policy {
            return Ok(policy);
        }
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, rtxn)?;
        *self
            .policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(policy.clone());
        Ok(policy)
    }
}

fn context_pack_edge_can_reach_neighbor(edge: &EdgeInfo) -> bool {
    !matches!(edge.kind, EdgeKind::ChildOf | EdgeKind::AssignedTo)
        && !edge
            .provenance
            .is_some_and(|flags| flags.confirmation_status == EdgeConfirmationStatus::Retracted)
}

pub(crate) const COMPANION_EXPRESSION_PROFESSIONAL: &str = "professional";
pub(crate) const COMPANION_EXPRESSION_WARM: &str = "warm";
pub(crate) const COMPANION_EXPRESSION_UNRESTRICTED: &str = "unrestricted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LexicalQueryHintValue {
    pub(crate) target: EntityId,
    pub(crate) query: String,
}

/// Context-pack CLAIM field profiles, derived from [`CLAIM_BODY_KEYS`] so the
/// serializer cannot drift from the storage ABI.
pub(crate) const CLAIM_FIELDS_MINIMAL: &[&str] = claim_keys_prefix(2);
pub(crate) const CLAIM_FIELDS_STANDARD: &[&str] = claim_keys_prefix(5);
pub(crate) const CLAIM_FIELDS_FULL: &[&str] = claim_keys_prefix(11);

const fn claim_keys_prefix(len: usize) -> &'static [&'static str] {
    let whole: &[&str] = &CLAIM_BODY_KEYS;
    whole.split_at(len).0
}

/// Maximum predicate length in bytes (D17).
pub const MAX_PREDICATE_BYTES: usize = 128;

/// Reserved predicate namespace prefix (D17): `edge.*` predicates may only
/// be written through the `pub(crate)` provenance door.
pub const RESERVED_PREDICATE_NAMESPACE: &str = "edge";

/// Length of an EdgeRef subject encoding: source 16 ‖ kind u8 ‖ target 16.
pub(crate) const EDGE_REF_LEN: usize = 33;

/// Claim approval status (`appr`): the ARCH-0003 consent axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimApprovalStatus {
    Auto,
    Proposed,
    Approved,
    Rejected,
}

impl ClaimApprovalStatus {
    /// The pinned on-disk string for this status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Claim lifecycle status (`life`): the ARCH-0003 currentness axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimLifecycleStatus {
    Active,
    Superseded,
    Retracted,
}

impl ClaimLifecycleStatus {
    /// The pinned on-disk string for this status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "retracted" => Some(Self::Retracted),
            _ => None,
        }
    }
}

/// Claim provenance source (`src`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimSource {
    UserStated,
    Observed,
    Inferred,
    Imported,
    ToolOutput,
    Generated,
}

impl ClaimSource {
    /// The pinned on-disk string for this source.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserStated => "user_stated",
            Self::Observed => "observed",
            Self::Inferred => "inferred",
            Self::Imported => "imported",
            Self::ToolOutput => "tool_output",
            Self::Generated => "generated",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "user_stated" => Some(Self::UserStated),
            "observed" => Some(Self::Observed),
            "inferred" => Some(Self::Inferred),
            "imported" => Some(Self::Imported),
            "tool_output" => Some(Self::ToolOutput),
            "generated" => Some(Self::Generated),
            _ => None,
        }
    }

    pub(crate) const fn requires_explicit_auto_permit(self) -> bool {
        matches!(self, Self::Imported | Self::ToolOutput | Self::Generated)
    }
}

const CLAIM_SCOPE_SENSITIVITY_KEY: &str = "sensitivity";
const CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY: &str = "federated_original_source";
#[cfg(feature = "sync")]
const CLAIM_SCOPE_PRE_RESTAMP_SCOPE_KEY: &str = "pre_restamp_scope";
const DEFAULT_CLAIM_SENSITIVITY_BAND: u8 = 0;

enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

pub(crate) fn claim_sensitivity_band(body: &ClaimBody) -> Option<u8> {
    let Some(Value::Map(entries)) = &body.scope else {
        return Some(DEFAULT_CLAIM_SENSITIVITY_BAND);
    };

    match single_map_value(entries, CLAIM_SCOPE_SENSITIVITY_KEY) {
        MapValue::Missing => Some(DEFAULT_CLAIM_SENSITIVITY_BAND),
        MapValue::Present(value) => sensitivity_band_from_value(value),
        MapValue::Duplicate => None,
    }
}

fn claim_federated_original_source(body: &ClaimBody) -> Option<ClaimSource> {
    let Some(Value::Map(entries)) = &body.scope else {
        return None;
    };

    match single_map_value(entries, CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY) {
        MapValue::Missing => None,
        MapValue::Present(value) => value.as_str().and_then(ClaimSource::parse),
        // A duplicated internal origin marker is ambiguous; read admission
        // treats it as generated-origin so authority consumers fail closed.
        MapValue::Duplicate => Some(ClaimSource::Generated),
    }
}

pub(crate) fn claim_generated_origin(body: &ClaimBody) -> bool {
    body.source == Some(ClaimSource::Generated)
        || claim_federated_original_source(body) == Some(ClaimSource::Generated)
}

pub(crate) fn sensitivity_band_from_value(value: &Value) -> Option<u8> {
    if let Some(raw) = value.as_u64() {
        return u8::try_from(raw).ok();
    }

    match value.as_str()? {
        "public" => Some(0),
        "internal" => Some(1),
        "sensitive" => Some(2),
        "restricted" => Some(3),
        _ => None,
    }
}

/// A claim's subject reference (`subj`). Two pinned encodings:
///
/// * 16 bytes — an entity UUID;
/// * 33 bytes — an EdgeRef `(source_id 16 B ‖ edge_kind u8 ‖ target_id 16 B)`
///   addressing an edge (used by `edge.provenance` Claims; the kind byte must
///   parse as a registered [`EdgeKind`]).
///
/// Anything else fails validation with [`Error::InvalidClaimBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSubject {
    /// Subject is an entity (16-byte UUID).
    Entity(EntityId),
    /// Subject is an edge, addressed as a 33-byte EdgeRef.
    Edge {
        source: EntityId,
        kind: EdgeKind,
        target: EntityId,
    },
}

impl ClaimSubject {
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Entity(id) => id.as_bytes().to_vec(),
            Self::Edge {
                source,
                kind,
                target,
            } => {
                let mut out = Vec::with_capacity(EDGE_REF_LEN);
                out.extend_from_slice(source.as_bytes());
                out.push(*kind as u8);
                out.extend_from_slice(target.as_bytes());
                out
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            ENTITY_ID_LEN => {
                let arr: [u8; ENTITY_ID_LEN] = bytes
                    .try_into()
                    .map_err(|_| Error::InvalidClaimBody("subj entity id is malformed"))?;
                let id = EntityId::from_bytes(arr)
                    .map_err(|_| Error::InvalidClaimBody("subj entity id is reserved"))?;
                Ok(Self::Entity(id))
            }
            EDGE_REF_LEN => {
                let source = entity_id_from(&bytes[..ENTITY_ID_LEN], "subj EdgeRef source id")?;
                let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN]).ok_or(
                    Error::InvalidClaimBody("subj EdgeRef kind byte is not a registered EdgeKind"),
                )?;
                let target = entity_id_from(&bytes[ENTITY_ID_LEN + 1..], "subj EdgeRef target id")?;
                Ok(Self::Edge {
                    source,
                    kind,
                    target,
                })
            }
            _ => Err(Error::InvalidClaimBody(
                "subj must be a 16-byte entity id or a 33-byte EdgeRef",
            )),
        }
    }
}

fn entity_id_from(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidClaimBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidClaimBody(context))
}

/// Decoded type-0 (CLAIM) body — the engine-pinned structural fields only.
///
/// Per-predicate columns (ARCH-0003 §G.1) are NOT modeled here: the typed
/// `val` payload is an opaque MessagePack value the crate never interprets.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ClaimBody {
    /// `pred` — predicate string, validated against the D17 grammar. Crate
    /// well-known predicates use the first-segment layer convention
    /// documented by [`PREDICATE_LAYER_NAMESPACES`].
    pub predicate: String,
    /// `subj` — subject reference (entity UUID or EdgeRef).
    pub subject: ClaimSubject,
    /// `val` — typed claim value; opaque MessagePack at the storage layer.
    pub value: Value,
    /// `conf` — confidence, finite in `[0, 1]`.
    pub confidence: f32,
    /// `appr` — approval status.
    pub approval: ClaimApprovalStatus,
    /// `life` — lifecycle status.
    pub lifecycle: ClaimLifecycleStatus,
    /// `sal` — optional salience, finite in `[0, 1]`.
    pub salience: Option<f32>,
    /// `evid` — optional evidence payload (opaque MessagePack).
    pub evidence: Option<Value>,
    /// `from` — optional valid-time start (Unix seconds).
    pub valid_from: Option<u64>,
    /// `to` — optional valid-time end (Unix seconds).
    pub valid_to: Option<u64>,
    /// `src` — optional provenance source.
    pub source: Option<ClaimSource>,
    /// `world` — optional world scope: the 16-byte WORLD entity id this claim
    /// is scoped to (ARCH-0004 claim world filter; ARCH-0022 world model).
    /// ABSENT means base reality (the elide-the-default pattern, like
    /// `stale == false`). On disk it is exactly 16 MessagePack-binary bytes;
    /// any other shape is rejected fail-closed with [`Error::InvalidClaimBody`].
    /// The referenced WORLD entity is NOT required to exist at write time —
    /// extraction may create claims before their world; the read side groups
    /// by id regardless.
    pub world: Option<EntityId>,
    /// `scope` — optional relationship/facet scope (opaque MessagePack).
    pub scope: Option<Value>,
    /// `stale` — derived-data staleness marker; absent on disk means `false`.
    pub stale: bool,
}

impl ClaimBody {
    /// Creates a claim body from the six required fields; all optional
    /// fields start absent and `stale` starts `false`.
    #[must_use]
    pub fn new(
        predicate: impl Into<String>,
        subject: ClaimSubject,
        value: Value,
        confidence: f32,
        approval: ClaimApprovalStatus,
        lifecycle: ClaimLifecycleStatus,
    ) -> Self {
        Self {
            predicate: predicate.into(),
            subject,
            value,
            confidence,
            approval,
            lifecycle,
            salience: None,
            evidence: None,
            valid_from: None,
            valid_to: None,
            source: None,
            world: None,
            scope: None,
            stale: false,
        }
    }
}

/// Validates a predicate against the pinned D17 grammar: ≥2 segments, each
/// matching `[a-z][a-z0-9_]*`, joined by `.`, total ≤128 bytes.
///
/// When `allow_reserved` is `false` (every public write path), well-formed
/// predicates in the reserved `edge.*` namespace are rejected with
/// [`Error::ReservedPredicate`]. The provenance unit writes through the
/// `pub(crate)` door which sets `allow_reserved` to `true`, as does the
/// sync-replay door (`put_replicated`) so replicated provenance Claims
/// rematerialize; reads always allow reserved predicates so stored
/// provenance Claims stay decodable. `allow_reserved` skips ONLY this
/// reserved-namespace arm — the grammar checks above run unconditionally.
pub(crate) fn validate_predicate(predicate: &str, allow_reserved: bool) -> Result<()> {
    if predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "exceeds 128 bytes",
        });
    }

    let mut segments = 0_usize;
    for segment in predicate.split('.') {
        if !valid_predicate_segment(segment) {
            return Err(Error::InvalidPredicate {
                predicate: predicate.to_owned(),
                reason: "segments must match [a-z][a-z0-9_]*",
            });
        }
        segments += 1;
    }
    if segments < 2 {
        return Err(Error::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "requires at least 2 dot-joined segments",
        });
    }

    if !allow_reserved && is_reserved_predicate(predicate) {
        return Err(Error::ReservedPredicate {
            predicate: predicate.to_owned(),
        });
    }

    Ok(())
}

/// Returns `true` when `predicate`'s first dot-separated segment is the
/// reserved `edge` namespace (D17). Reserved-namespace Claims are engine
/// provenance records: their lifecycle (supersede / retract / re-stamp) is
/// owned by the edge-provenance API, so the generic claim lifecycle ops
/// reject them with [`Error::ProvenanceClaimLifecycle`].
pub(crate) fn is_reserved_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(RESERVED_PREDICATE_NAMESPACE)
}

fn valid_predicate_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Encodes a [`ClaimBody`] into the pinned MessagePack ABI: a map carrying
/// the present [`CLAIM_BODY_KEYS`] in canonical order. `stale == false` is
/// omitted (absent means `false` on decode). Encoding performs no
/// validation — every write path re-validates the encoded bytes through
/// [`decode_claim_body`], the single validator.
pub(crate) fn encode_claim_body(body: &ClaimBody) -> Result<Vec<u8>> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(CLAIM_BODY_KEYS.len());
    entries.push((Value::from(KEY_PRED), Value::from(body.predicate.as_str())));
    entries.push((Value::from(KEY_VAL), body.value.clone()));
    entries.push((Value::from(KEY_CONF), Value::F32(body.confidence)));
    if let Some(salience) = body.salience {
        entries.push((Value::from(KEY_SAL), Value::F32(salience)));
    }
    if let Some(evidence) = &body.evidence {
        entries.push((Value::from(KEY_EVID), evidence.clone()));
    }
    if let Some(valid_from) = body.valid_from {
        entries.push((Value::from(KEY_FROM), Value::from(valid_from)));
    }
    if let Some(valid_to) = body.valid_to {
        entries.push((Value::from(KEY_TO), Value::from(valid_to)));
    }
    if let Some(source) = body.source {
        entries.push((Value::from(KEY_SRC), Value::from(source.as_str())));
    }
    if let Some(world) = body.world {
        entries.push((
            Value::from(KEY_WORLD),
            Value::Binary(world.as_bytes().to_vec()),
        ));
    }
    entries.push((Value::from(KEY_SUBJ), Value::Binary(body.subject.encode())));
    if let Some(scope) = &body.scope {
        entries.push((Value::from(KEY_SCOPE), scope.clone()));
    }
    entries.push((Value::from(KEY_APPR), Value::from(body.approval.as_str())));
    entries.push((Value::from(KEY_LIFE), Value::from(body.lifecycle.as_str())));
    if body.stale {
        entries.push((Value::from(KEY_STALE), Value::Boolean(true)));
    }

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("claim body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and structurally validates a type-0 (CLAIM) body (D18).
///
/// This is the single validator: every write path validates through it (via
/// [`validate_claim_body_bytes`]) and `Vault::get_claim` decodes through it.
/// Fail-closed rules:
///
/// * the body must be exactly one MessagePack map (no trailing bytes);
/// * keys must be strings drawn from [`CLAIM_BODY_KEYS`], no duplicates;
/// * required: `pred`, `subj`, `val`, `conf`, `appr`, `life`;
/// * `conf` (and `sal` when present) must be finite numbers in `[0, 1]`;
/// * `from`/`to` must be non-negative integers fitting `u64`;
/// * `src`/`appr`/`life` must be the pinned enum strings;
/// * `stale` must be a boolean (absent = `false`);
/// * `subj` must be a 16-byte entity id or 33-byte EdgeRef ([`ClaimSubject`]);
/// * `pred` must satisfy the D17 grammar; reserved `edge.*` predicates are
///   rejected unless `allow_reserved_predicate` is set (provenance door /
///   read path).
pub(crate) fn decode_claim_body(data: &[u8], allow_reserved_predicate: bool) -> Result<ClaimBody> {
    #[cfg(test)]
    CLAIM_BODY_DECODE_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidClaimBody("body is not valid MessagePack"))?;
    if cursor.position() != data.len() as u64 {
        return Err(Error::InvalidClaimBody("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody("body must be a MessagePack map"));
    };

    let mut predicate: Option<String> = None;
    let mut subject: Option<ClaimSubject> = None;
    let mut claim_value: Option<Value> = None;
    let mut confidence: Option<f32> = None;
    let mut approval: Option<ClaimApprovalStatus> = None;
    let mut lifecycle: Option<ClaimLifecycleStatus> = None;
    let mut salience: Option<f32> = None;
    let mut evidence: Option<Value> = None;
    let mut valid_from: Option<u64> = None;
    let mut valid_to: Option<u64> = None;
    let mut source: Option<ClaimSource> = None;
    let mut world: Option<EntityId> = None;
    let mut scope: Option<Value> = None;
    let mut stale: Option<bool> = None;

    let mut seen = [false; CLAIM_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody("body keys must be strings"));
        };
        let Some(index) = CLAIM_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidClaimBody(
                "body key is not in the pinned CLAIM_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidClaimBody("duplicate body key"));
        }
        seen[index] = true;

        match CLAIM_BODY_KEYS[index] {
            "pred" => {
                let Some(pred) = value.as_str() else {
                    return Err(Error::InvalidClaimBody("pred must be a string"));
                };
                predicate = Some(pred.to_owned());
            }
            "val" => claim_value = Some(value),
            "conf" => {
                confidence = Some(
                    unit_interval_f32(&value)
                        .ok_or(Error::InvalidClaimBody("conf must be finite in [0, 1]"))?,
                );
            }
            "sal" => {
                salience = Some(
                    unit_interval_f32(&value)
                        .ok_or(Error::InvalidClaimBody("sal must be finite in [0, 1]"))?,
                );
            }
            "evid" => evidence = Some(value),
            "from" => {
                valid_from = Some(value.as_u64().ok_or(Error::InvalidClaimBody(
                    "from must be a non-negative integer",
                ))?);
            }
            "to" => {
                valid_to = Some(
                    value
                        .as_u64()
                        .ok_or(Error::InvalidClaimBody("to must be a non-negative integer"))?,
                );
            }
            "src" => {
                let parsed =
                    value
                        .as_str()
                        .and_then(ClaimSource::parse)
                        .ok_or(Error::InvalidClaimBody(
                            "src must be one of user_stated|observed|inferred|imported|tool_output|generated",
                        ))?;
                source = Some(parsed);
            }
            "world" => {
                // ARCH-0004 / ARCH-0022: a present `world` key is the
                // 16-byte WORLD entity id. Anything that is not exactly 16
                // MessagePack-binary bytes (a string, a 15-byte blob, …) is
                // rejected fail-closed — the read side groups claims by this
                // id, so a malformed value can never be silently scoped.
                let Value::Binary(bytes) = &value else {
                    return Err(Error::InvalidClaimBody("world must be MessagePack binary"));
                };
                let arr: [u8; ENTITY_ID_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidClaimBody("world must be a 16-byte world id"))?;
                world = Some(
                    EntityId::from_bytes(arr)
                        .map_err(|_| Error::InvalidClaimBody("world id is reserved"))?,
                );
            }
            "subj" => {
                let Value::Binary(bytes) = &value else {
                    return Err(Error::InvalidClaimBody("subj must be MessagePack binary"));
                };
                subject = Some(ClaimSubject::decode(bytes)?);
            }
            "scope" => scope = Some(value),
            "appr" => {
                let parsed = value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidClaimBody("appr must be one of auto|proposed|approved|rejected"),
                )?;
                approval = Some(parsed);
            }
            "life" => {
                let parsed = value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                    Error::InvalidClaimBody("life must be one of active|superseded|retracted"),
                )?;
                lifecycle = Some(parsed);
            }
            "stale" => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidClaimBody("stale must be a boolean"));
                };
                stale = Some(flag);
            }
            _ => unreachable!("index resolved from CLAIM_BODY_KEYS"),
        }
    }

    let predicate = predicate.ok_or(Error::InvalidClaimBody("missing required field pred"))?;
    validate_predicate(&predicate, allow_reserved_predicate)?;
    let subject = subject.ok_or(Error::InvalidClaimBody("missing required field subj"))?;
    let claim_value = claim_value.ok_or(Error::InvalidClaimBody("missing required field val"))?;
    let confidence = confidence.ok_or(Error::InvalidClaimBody("missing required field conf"))?;
    let approval = approval.ok_or(Error::InvalidClaimBody("missing required field appr"))?;
    let lifecycle = lifecycle.ok_or(Error::InvalidClaimBody("missing required field life"))?;

    Ok(ClaimBody {
        predicate,
        subject,
        value: claim_value,
        confidence,
        approval,
        lifecycle,
        salience,
        evidence,
        valid_from,
        valid_to,
        source,
        world,
        scope,
        stale: stale.unwrap_or(false),
    })
}

/// Structural validation entry point for raw type-0 body bytes (D18).
/// See [`decode_claim_body`] for the rules.
///
/// This is the WRITE-ONLY chokepoint (the read path — `Vault::get_claim` —
/// decodes via [`decode_claim_body`] directly): every type-0 write on every
/// door (`Vault::put_claim`, both batch builders' public puts, the
/// reserved-namespace `put_reserved_claim` door, the `put_replicated`
/// sync-replay doors, and the provenance lifecycle rewrites) validates
/// through it, either up front or via `apply_put`. On top of the D18 rules
/// it runs the predicate-aware structural branch for reserved
/// `edge.provenance` Claims (ONE-1159) — see
/// [`validate_edge_provenance_claim_structure`]. Reads stay untouched:
/// pre-existing stored junk keeps its current read behavior (typed failure
/// at the provenance ops that interpret it), it just can no longer be
/// (re)written.
pub(crate) fn validate_claim_body_and_decode(
    data: &[u8],
    allow_reserved_predicate: bool,
) -> Result<ClaimBody> {
    let body = decode_claim_body(data, allow_reserved_predicate)?;
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        validate_edge_provenance_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_LEXICAL_QUERY_HINT {
        lexical_query_hint_target(&body)?;
    } else if body.predicate == PREDICATE_COMPANION_EXPRESSION {
        validate_companion_expression_claim_structure(&body)?;
    } else if body.predicate == AFFECT_TRIGGER_PREDICATE {
        validate_affect_trigger_claim_structure(&body)?;
    } else if body.predicate == COPING_OUTCOME_PREDICATE {
        validate_coping_outcome_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_CONFLICT_OPEN
        || body.predicate == PREDICATE_CONFLICT_RESOLVED
    {
        validate_conflict_claim_structure(&body)?;
    } else if crate::channel_identity::is_channel_identity_claim_predicate(&body.predicate) {
        crate::channel_identity::validate_channel_identity_claim_structure(&body)?;
    }
    Ok(body)
}

fn validate_companion_expression_claim_structure(body: &ClaimBody) -> Result<()> {
    let Some(expression) = body.value.as_str() else {
        return Err(Error::InvalidClaimBody(
            "companion.expression value must be a string",
        ));
    };
    match expression {
        COMPANION_EXPRESSION_PROFESSIONAL
        | COMPANION_EXPRESSION_WARM
        | COMPANION_EXPRESSION_UNRESTRICTED => Ok(()),
        _ => Err(Error::InvalidClaimBody(
            "expression must be professional|warm|unrestricted",
        )),
    }
}

fn validate_conflict_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "conflict claim subject must be an entity",
        ));
    }
    if matches!(body.value, Value::Nil) {
        return Err(Error::InvalidClaimBody(
            "conflict claim value must not be nil",
        ));
    }
    Ok(())
}

pub(crate) fn validate_claim_body_bytes(data: &[u8], allow_reserved_predicate: bool) -> Result<()> {
    validate_claim_body_and_decode(data, allow_reserved_predicate).map(|_| ())
}

pub(crate) fn normalize_lexical_query_hints(hints: &[&str]) -> Result<Vec<String>> {
    let mut normalized = Vec::<String>::new();
    for hint in hints {
        let hint = hint.trim();
        if hint.is_empty() {
            continue;
        }
        if normalized.iter().any(|existing| existing == hint) {
            continue;
        }
        if normalized.len() == MAX_LEXICAL_QUERY_HINTS_PER_CLAIM {
            break;
        }
        if hint.len() > MAX_LEXICAL_QUERY_HINT_BYTES {
            return Err(Error::InvalidClaimBody(
                "lexical query hint exceeds 256 bytes",
            ));
        }
        normalized.push(hint.to_owned());
    }
    Ok(normalized)
}

#[must_use]
pub(crate) fn encode_lexical_query_hint_value(target: &EntityId, query: &str) -> Value {
    Value::Map(vec![
        (
            Value::from(LEXICAL_HINT_VALUE_KEY_KIND),
            Value::from(LEXICAL_HINT_KIND),
        ),
        (
            Value::from(LEXICAL_HINT_VALUE_KEY_QUERY),
            Value::from(query),
        ),
        (
            Value::from(LEXICAL_HINT_VALUE_KEY_TARGET),
            Value::Binary(target.as_bytes().to_vec()),
        ),
    ])
}

pub(crate) fn decode_lexical_query_hint_value(value: &Value) -> Result<LexicalQueryHintValue> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "lexical query hint value must be a map",
        ));
    };

    let mut kind: Option<&str> = None;
    let mut query: Option<String> = None;
    let mut target: Option<EntityId> = None;
    let mut seen_kind = false;
    let mut seen_query = false;
    let mut seen_target = false;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody(
                "lexical query hint value keys must be strings",
            ));
        };
        match key {
            LEXICAL_HINT_VALUE_KEY_KIND => {
                if seen_kind {
                    return Err(Error::InvalidClaimBody(
                        "duplicate lexical query hint value key",
                    ));
                }
                seen_kind = true;
                kind = value.as_str();
            }
            LEXICAL_HINT_VALUE_KEY_QUERY => {
                if seen_query {
                    return Err(Error::InvalidClaimBody(
                        "duplicate lexical query hint value key",
                    ));
                }
                seen_query = true;
                let Some(raw_query) = value.as_str() else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint query must be a string",
                    ));
                };
                let normalized = normalize_lexical_query_hints(&[raw_query])?;
                let Some(raw_query) = normalized.into_iter().next() else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint query must be non-empty",
                    ));
                };
                query = Some(raw_query);
            }
            LEXICAL_HINT_VALUE_KEY_TARGET => {
                if seen_target {
                    return Err(Error::InvalidClaimBody(
                        "duplicate lexical query hint value key",
                    ));
                }
                seen_target = true;
                let Value::Binary(bytes) = value else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be binary",
                    ));
                };
                let arr: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| {
                    Error::InvalidClaimBody("lexical query hint target must be a 16-byte entity id")
                })?;
                target = Some(EntityId::from_bytes(arr).map_err(|_| {
                    Error::InvalidClaimBody("lexical query hint target id is reserved")
                })?);
            }
            _ => {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint value key is not in the pinned set",
                ));
            }
        }
    }

    if kind != Some(LEXICAL_HINT_KIND) {
        return Err(Error::InvalidClaimBody(
            "lexical query hint kind must be prospective_query",
        ));
    }
    Ok(LexicalQueryHintValue {
        target: target.ok_or(Error::InvalidClaimBody("missing lexical query hint target"))?,
        query: query.ok_or(Error::InvalidClaimBody("missing lexical query hint query"))?,
    })
}

pub(crate) fn lexical_query_hint_target(body: &ClaimBody) -> Result<Option<EntityId>> {
    if body.predicate != PREDICATE_LEXICAL_QUERY_HINT {
        return Ok(None);
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "lexical query hint subject must be an entity",
        ));
    };
    let value = decode_lexical_query_hint_value(&body.value)?;
    if value.target != subject {
        return Err(Error::InvalidClaimBody(
            "lexical query hint subject must match target",
        ));
    }
    Ok(Some(subject))
}

/// ONE-1159 — full structural validation of an `edge.provenance` Claim at
/// the WRITE door.
///
/// D18 treats `val` as opaque MessagePack and `evid` as an opaque payload,
/// so the replicated door admitted D18-valid but STRUCTURALLY invalid
/// provenance Claims (junk `val`, non-record `val` maps, missing
/// actor-class evidence); later provenance ops then failed closed only at
/// read/supersede time. Sync replay is a WRITE PATH — the same fail-closed
/// checks run behind the trusted door:
///
/// * `val` must decode as the pinned `edge.provenance` value record via the
///   SHARED validator [`crate::provenance::validate_edge_provenance_value`]
///   — the pinned key vocabulary lives in exactly one place, so vocabulary
///   growth flows through here with zero edits;
/// * the write-time validated `actor_class` must be persisted in EXACTLY
///   one place: as an `actor_class` key in the value record (accepted only
///   once the shared vocabulary carries that key) or as the engine-owned
///   `{"actor_class": u8}` map on the wrapper's `evid`
///   ([`crate::provenance::decode_actor_class_evidence`]). Present in both
///   → ambiguous, rejected; present in neither → rejected. A provenance
///   Claim without a persisted class can never participate in flag refresh,
///   and the class is never defaulted (D13).
///
/// ONE-1159 fix-wave adds two WRAPPER-axis checks the door previously
/// skipped (D18 treats the wrapper's lifecycle fields as opaque):
///
/// * surfaceability — `appr ∈ {auto, approved}` (the exact set from
///   [`claim_surfaceable`]) and `stale = false`, so a non-surfaceable Claim
///   cannot enter at the write door and silently steer edge flags. Lifecycle
///   is NOT gated (`superseded` / `retracted` are legitimate provenance
///   states the live_/retracted_ scans read);
/// * wrapper↔value-record mirror — `conf == confidence`, `from == valid_from`,
///   `to == valid_to`, so the precedence/display wrapper can never lie about
///   the value record the writer mirrored it from.
///
/// Typed rejections only (the [`Error::InvalidProvenanceBody`] family) — at
/// the sync replay door the caller quarantines them (`x:` row, hash-only
/// per ONE-1124), never drops.
fn validate_edge_provenance_claim_structure(body: &ClaimBody) -> Result<()> {
    // ONE-1159 fix-wave (BLOCKER #2) — decode the value record ONCE via the
    // SHARED decoder so the typed record is held for the wrapper↔value-record
    // mirror checks below. This is exactly what
    // [`crate::provenance::validate_edge_provenance_value`] runs (it is the
    // same call with the record discarded), so the value-record structural
    // rules are unchanged and vocabulary growth (ONE-1138's 10-key shape)
    // flows through this one call with zero edits.
    let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
    // Presence-only probe for the value-record `actor_class` key: VALIDITY
    // of the key's value is the shared decoder's job above (and a body
    // key outside the pinned vocabulary was already rejected there), so
    // this never duplicates shape logic.
    let value_has_actor_class = matches!(
        &body.value,
        Value::Map(entries) if entries.iter().any(|(key, _)| {
            key.as_str() == Some(crate::provenance::EVIDENCE_KEY_ACTOR_CLASS)
        })
    );
    match (value_has_actor_class, body.evidence.as_ref()) {
        (true, Some(_)) => {
            return Err(Error::InvalidProvenanceBody(
                "actor_class present in both the value record and the wrapper evid (ambiguous)",
            ));
        }
        (true, None) => {}
        (false, evidence) => {
            crate::provenance::decode_actor_class_evidence(evidence)?;
        }
    }

    // ONE-1159 fix-wave (BLOCKER #1) — surfaceability-axis guard on the
    // WRAPPER. A provenance Claim only drives edge-flag refresh while it is
    // surfaceable on the read gate; admitting a non-surfaceable wrapper at the
    // replay door would let an `appr=rejected` / `stale=true` Claim silently
    // steer flags. Reuse the EXACT approval set from [`claim_surfaceable`] so
    // the door and the read gate cite one approval rule. Lifecycle is
    // DELIBERATELY not gated here — `superseded` / `retracted` are legitimate
    // provenance lifecycle states the live_/retracted_ scans must read.
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper appr must be auto|approved",
        ));
    }
    if body.stale {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper must not be stale",
        ));
    }

    // ONE-1159 fix-wave (BLOCKER #2) — the wrapper's `conf`/`from`/`to` MUST
    // mirror the value record's `confidence`/`valid_from`/`valid_to`. The
    // local writer guarantees this by construction, and precedence/display
    // read the wrapper, so a mismatched wrapper is a structural lie. `conf`
    // and `confidence` are both required and parsed through the same
    // `unit_interval_f32`/`Value::F32` path, so `==` is the exact VALUE
    // equality the contract pins; `from`/`to` are optional on both sides and
    // compared as `Option` equality (both-present-equal or both-absent).
    if record.confidence != body.confidence {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper conf does not mirror value-record confidence",
        ));
    }
    if record.valid_from != body.valid_from {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper from does not mirror value-record valid_from",
        ));
    }
    if record.valid_to != body.valid_to {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper to does not mirror value-record valid_to",
        ));
    }

    Ok(())
}

/// D19 read-path status gate predicate (ARCH-0003 retrieval rule; ARCH-0004
/// §H "Claim filtering — enumerated requirements" items 1, 2, 4): a Claim
/// may surface on the retrieval read paths (pipeline results across all five
/// channels, context-pack results, and context-pack neighbors) only when
///
/// * `appr ∈ {auto, approved}` — respect consent;
/// * `life = active` — only current beliefs;
/// * `stale = false` — only regenerated content (absent on disk means
///   `false`, [`decode_claim_body`]; absence alone never excludes).
///
/// The gate is an EXCLUSION, not an error: failing claims are silently
/// dropped and counted (`PackStats::claims_suppressed`). Targeted reads stay
/// deliberately UNGATED: [`crate::Vault::get_claim`] is the history /
/// consent-review door and the edge-provenance lifecycle readers must see
/// closed (`superseded` / `retracted`) Claims to compute winner stamps.
/// World/facet filtering (§H item 3) is a separate unit, and
/// deleted-revision contamination (§H item 5) is the M4/M5 sweep scope.
pub(crate) fn claim_surfaceable(body: &ClaimBody) -> bool {
    matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) && body.lifecycle == ClaimLifecycleStatus::Active
        && !body.stale
}

/// Read-admission predicate for authority-consuming consolidation paths.
///
/// This is intentionally stricter than [`claim_surfaceable`]: first-party or
/// replicated `Auto` claims stamped `src = generated` may surface immediately
/// on retrieval/review read paths, but authority-consuming paths must call this
/// predicate at their consolidation/corroboration/effector admission boundary
/// and decline them until they are vetted into `appr = approved`. Federated
/// claims restamped to `src = imported` preserve a generated pre-restamp source
/// in `scope.federated_original_source` for this read-admission check. Existing
/// retrieval and context-pack surfacing paths intentionally remain on
/// [`claim_surfaceable`]. This is a read gate only; replication and replay
/// paths must not re-run policy source-trust checks.
pub(crate) fn claim_consolidatable(body: &ClaimBody) -> bool {
    claim_surfaceable(body)
        && !(body.approval == ClaimApprovalStatus::Auto && claim_generated_origin(body))
}

pub(crate) fn psych_mirror_claim_affect_salience(body: &ClaimBody) -> Result<f32> {
    let salience = body.salience.unwrap_or(0.0);
    let affect = crate::affect::decode_affect_trigger_claim(body)?
        .map(|trigger| {
            let delta = trigger.vad_delta();
            let valence = (delta.valence().abs() / 2.0).clamp(0.0, 1.0);
            let arousal = delta.arousal().abs().clamp(0.0, 1.0);
            let dominance = delta.dominance().abs().clamp(0.0, 1.0);
            ((valence + arousal + dominance) / 3.0) * trigger.confidence()
        })
        .unwrap_or(0.0);
    Ok(salience.max(affect).clamp(0.0, 1.0))
}

#[cfg(feature = "sync")]
pub(crate) fn restamp_federated_claim_source(mut body: ClaimBody) -> ClaimBody {
    if body.source == Some(ClaimSource::Generated) {
        body.scope = Some(match body.scope.take() {
            Some(Value::Map(mut entries)) => {
                entries.retain(|(key, _)| {
                    key.as_str() != Some(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY)
                });
                entries.push((
                    Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
                    Value::from(ClaimSource::Generated.as_str()),
                ));
                Value::Map(entries)
            }
            Some(scope) => Value::Map(vec![
                (
                    Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
                    Value::from(ClaimSource::Generated.as_str()),
                ),
                (Value::from(CLAIM_SCOPE_PRE_RESTAMP_SCOPE_KEY), scope),
            ]),
            None => Value::Map(vec![(
                Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
                Value::from(ClaimSource::Generated.as_str()),
            )]),
        });
    }
    body.source = Some(ClaimSource::Imported);
    body
}

/// Parses a MessagePack number as a finite `f32` in `[0, 1]`. Shared with
/// the provenance module so `conf` and `confidence` validate identically.
pub(crate) fn unit_interval_f32(value: &Value) -> Option<f32> {
    let parsed = match value {
        Value::F32(v) => f64::from(*v),
        Value::F64(v) => *v,
        Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                i as f64
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
        return None;
    }
    Some(parsed as f32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::assert_matches;

    #[test]
    fn psych_mirror_selection_affect_trigger_contributes_affect_salience() -> Result<()> {
        let affected_person = EntityId::from_bytes([0x44; 16]).expect("valid id");
        let trigger_ref = EntityId::from_bytes([0x45; 16]).expect("valid id");
        let value = crate::affect::AffectTriggerValue::new(
            affected_person,
            trigger_ref,
            crate::affect::VadDelta::new(-1.0, 0.5, -0.5)?,
            0.8,
            2,
            4,
        )?;
        let mut body = ClaimBody::new(
            crate::affect::AFFECT_TRIGGER_PREDICATE,
            ClaimSubject::Entity(affected_person),
            crate::affect::affect_trigger_value(&value),
            value.confidence(),
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.salience = Some(0.3);

        let affect_salience = psych_mirror_claim_affect_salience(&body)?;

        assert!((affect_salience - 0.4).abs() < 1e-6);
        Ok(())
    }

    #[test]
    fn psych_mirror_selection_affect_trigger_decode_errors_propagate() {
        let affected_person = EntityId::from_bytes([0x46; 16]).expect("valid id");
        let body = ClaimBody::new(
            crate::affect::AFFECT_TRIGGER_PREDICATE,
            ClaimSubject::Entity(affected_person),
            Value::from("malformed affect trigger"),
            0.8,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );

        assert!(psych_mirror_claim_affect_salience(&body).is_err());
    }

    #[test]
    fn predicate_grammar_accepts_well_formed_unknown_predicates() {
        for predicate in [
            "hobby.collects",
            "profile.lives_in",
            "goal.learning_v2",
            "a.b.c",
        ] {
            validate_predicate(predicate, false).expect("well-formed predicate must pass");
        }
    }

    #[test]
    fn registered_predicates_carry_layer_prefix() {
        assert_eq!(
            PREDICATE_LAYER_NAMESPACES,
            [
                PREDICATE_NAMESPACE_CORE,
                PREDICATE_NAMESPACE_COMPANION,
                PREDICATE_NAMESPACE_EIRI
            ]
        );

        for predicate in CLAIM_PREDICATE_REGISTRY {
            validate_predicate(predicate, false).expect("registered predicate must be valid");
            let layer = predicate
                .split('.')
                .next()
                .expect("valid predicate must have a first segment");
            assert!(
                PREDICATE_LAYER_NAMESPACES.contains(&layer),
                "{predicate} must start with core.*, companion.*, or eiri.*"
            );
        }
    }

    #[test]
    fn predicate_grammar_rejects_violations_typed() {
        // Single segment.
        assert_matches!(
            validate_predicate("profile", false),
            Err(Error::InvalidPredicate { .. })
        );
        // Uppercase.
        assert_matches!(
            validate_predicate("Edge.Provenance", false),
            Err(Error::InvalidPredicate { .. })
        );
        // Empty segment.
        assert_matches!(
            validate_predicate("profile.", false),
            Err(Error::InvalidPredicate { .. })
        );
        // Segment starting with digit / underscore.
        assert_matches!(
            validate_predicate("profile.9lives", false),
            Err(Error::InvalidPredicate { .. })
        );
        assert_matches!(
            validate_predicate("profile._hidden", false),
            Err(Error::InvalidPredicate { .. })
        );
        // Non-ASCII.
        assert_matches!(
            validate_predicate("profilé.name", false),
            Err(Error::InvalidPredicate { .. })
        );
    }

    #[test]
    fn predicate_length_gate_is_128_bytes_inclusive() {
        // 2 segments: "a." + 126 'b's = exactly 128 bytes — accepted.
        let at_limit = format!("a.{}", "b".repeat(126));
        assert_eq!(at_limit.len(), 128);
        validate_predicate(&at_limit, false).expect("128-byte predicate must pass");

        let over_limit = format!("a.{}", "b".repeat(127));
        assert_eq!(over_limit.len(), 129);
        assert_matches!(
            validate_predicate(&over_limit, false),
            Err(Error::InvalidPredicate { .. })
        );
    }

    #[test]
    fn claim_source_parse_accepts_inferred_and_imported_wire_values() {
        for (wire, source) in [
            ("inferred", ClaimSource::Inferred),
            ("imported", ClaimSource::Imported),
        ] {
            assert_eq!(ClaimSource::parse(wire), Some(source), "{wire}");
            assert_eq!(source.as_str(), wire, "{wire} round-trip literal");
        }
    }

    #[test]
    fn lexical_query_hint_cap_ignores_oversize_tail_entries() -> Result<()> {
        let overlong = "x".repeat(MAX_LEXICAL_QUERY_HINT_BYTES + 1);
        let hints = vec![
            "hint zero",
            "hint one",
            "hint two",
            "hint three",
            "hint four",
            "hint five",
            "hint six",
            "hint seven",
            overlong.as_str(),
        ];

        let normalized = normalize_lexical_query_hints(&hints)?;
        assert_eq!(normalized.len(), MAX_LEXICAL_QUERY_HINTS_PER_CLAIM);
        assert!(!normalized.iter().any(|hint| hint == &overlong));
        Ok(())
    }

    #[test]
    fn write_door_validates_lexical_query_hint_claim_structure() -> Result<()> {
        let target = EntityId::from_bytes([0x11; 16]).expect("valid id");
        let other = EntityId::from_bytes([0x22; 16]).expect("valid id");
        let encode = |subject: EntityId, value: Value| -> Result<Vec<u8>> {
            let body = ClaimBody::new(
                PREDICATE_LEXICAL_QUERY_HINT,
                ClaimSubject::Entity(subject),
                value,
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            );
            encode_claim_body(&body)
        };

        validate_claim_body_bytes(
            &encode(
                target,
                encode_lexical_query_hint_value(&target, "future migration question"),
            )?,
            false,
        )?;

        assert_matches!(
            validate_claim_body_bytes(&encode(target, Value::from("not a hint map"))?, false),
            Err(Error::InvalidClaimBody(_))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    other,
                    encode_lexical_query_hint_value(&target, "future migration question"),
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(_))
        );
        Ok(())
    }

    #[test]
    fn write_door_validates_companion_expression_claim_values() -> Result<()> {
        let subject = EntityId::from_bytes([0x33; 16]).expect("valid id");
        let encode = |value: Value| -> Result<Vec<u8>> {
            let body = ClaimBody::new(
                PREDICATE_COMPANION_EXPRESSION,
                ClaimSubject::Entity(subject),
                value,
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            );
            encode_claim_body(&body)
        };

        for expression in [
            COMPANION_EXPRESSION_PROFESSIONAL,
            COMPANION_EXPRESSION_WARM,
            COMPANION_EXPRESSION_UNRESTRICTED,
        ] {
            validate_claim_body_bytes(&encode(Value::from(expression))?, false)?;
        }

        assert_matches!(
            validate_claim_body_bytes(&encode(Value::from("future_closed"))?, false),
            Err(Error::InvalidClaimBody(
                "expression must be professional|warm|unrestricted"
            ))
        );
        assert_matches!(
            validate_claim_body_bytes(&encode(Value::Map(Vec::new()))?, false),
            Err(Error::InvalidClaimBody(
                "companion.expression value must be a string"
            ))
        );
        Ok(())
    }

    #[test]
    fn affect_trigger_write_door_validates_value_shape() -> Result<()> {
        let affected_person = EntityId::from_bytes([0x44; 16]).expect("valid id");
        let trigger_ref = EntityId::from_bytes([0x45; 16]).expect("valid id");
        let value = crate::affect::AffectTriggerValue::new(
            affected_person,
            trigger_ref,
            crate::affect::VadDelta::new(-0.4, 0.2, -0.1)?,
            0.82,
            3,
            12,
        )?;
        let encode_with_confidence =
            |subject: ClaimSubject, value: Value, confidence: f32| -> Result<Vec<u8>> {
                let body = ClaimBody::new(
                    crate::affect::AFFECT_TRIGGER_PREDICATE,
                    subject,
                    value,
                    confidence,
                    ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                );
                encode_claim_body(&body)
            };
        let encode = |subject: ClaimSubject, value: Value| -> Result<Vec<u8>> {
            encode_with_confidence(subject, value, 0.82)
        };
        let duplicate_top_level_value = || {
            let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
                panic!("affect.trigger value is a map");
            };
            entries.push((Value::from("confidence"), Value::F32(value.confidence())));
            Value::Map(entries)
        };
        let duplicate_vad_delta_value = || {
            let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
                panic!("affect.trigger value is a map");
            };
            let Some((_, vad_delta)) = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("vadDelta"))
            else {
                panic!("affect.trigger value has vadDelta");
            };
            let Value::Map(vad_entries) = vad_delta else {
                panic!("vadDelta value is a map");
            };
            vad_entries.push((Value::from("arousal"), Value::F32(0.2)));
            Value::Map(entries)
        };
        let f64_arousal_rounded_into_range_value = || {
            let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
                panic!("affect.trigger value is a map");
            };
            let Some((_, vad_delta)) = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("vadDelta"))
            else {
                panic!("affect.trigger value has vadDelta");
            };
            let Value::Map(vad_entries) = vad_delta else {
                panic!("vadDelta value is a map");
            };
            let Some((_, arousal)) = vad_entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("arousal"))
            else {
                panic!("vadDelta value has arousal");
            };
            *arousal = Value::F64(1.0_f64 + f64::EPSILON);
            Value::Map(entries)
        };
        let impossible_trigger_count_value = || {
            let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
                panic!("affect.trigger value is a map");
            };
            let Some((_, k)) = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("k"))
            else {
                panic!("affect.trigger value has k");
            };
            *k = Value::from(13_u64);
            Value::Map(entries)
        };
        let integer_vad_delta_value = || {
            let Value::Map(mut entries) = crate::affect::affect_trigger_value(&value) else {
                panic!("affect.trigger value is a map");
            };
            let Some((_, vad_delta)) = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("vadDelta"))
            else {
                panic!("affect.trigger value has vadDelta");
            };
            let Value::Map(vad_entries) = vad_delta else {
                panic!("vadDelta value is a map");
            };
            for (_, component) in vad_entries {
                *component = Value::from(0_i64);
            }
            Value::Map(entries)
        };

        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                crate::affect::affect_trigger_value(&value),
            )?,
            false,
        )?;
        for (k, observed_n) in [(0, 1), (1, 1), (12, 12)] {
            let boundary_value = crate::affect::AffectTriggerValue::new(
                affected_person,
                trigger_ref,
                crate::affect::VadDelta::new(-0.4, 0.2, -0.1)?,
                0.82,
                k,
                observed_n,
            )?;
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(affected_person),
                    crate::affect::affect_trigger_value(&boundary_value),
                )?,
                false,
            )?;
        }

        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(trigger_ref),
                    crate::affect::affect_trigger_value(&value),
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(
                "affect.trigger affectedPerson must match subject"
            ))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(affected_person),
                    Value::Map(Vec::new())
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(_))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(affected_person),
                    impossible_trigger_count_value()
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody("k must not exceed observedN"))
        );
        let legacy_impossible_count_value = impossible_trigger_count_value();
        let legacy_trigger =
            crate::affect::decode_affect_trigger_value(&legacy_impossible_count_value)?;
        assert_eq!(legacy_trigger.k(), 13);
        assert_eq!(legacy_trigger.observed_n(), 12);
        let legacy_body = ClaimBody::new(
            crate::affect::AFFECT_TRIGGER_PREDICATE,
            ClaimSubject::Entity(affected_person),
            legacy_impossible_count_value,
            0.82,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        let legacy_salience = psych_mirror_claim_affect_salience(&legacy_body)?;
        assert!(legacy_salience.is_finite());
        validate_claim_body_bytes(
            &encode(
                ClaimSubject::Entity(affected_person),
                integer_vad_delta_value(),
            )?,
            false,
        )?;
        assert_matches!(
            validate_claim_body_bytes(
                &encode_with_confidence(
                    ClaimSubject::Entity(affected_person),
                    crate::affect::affect_trigger_value(&value),
                    0.81
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(
                "affect.trigger wrapper confidence must mirror value confidence"
            ))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(affected_person),
                    duplicate_top_level_value()
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(
                "duplicate affect.trigger value key"
            ))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(affected_person),
                    duplicate_vad_delta_value()
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody("duplicate vadDelta value key"))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    ClaimSubject::Entity(affected_person),
                    f64_arousal_rounded_into_range_value()
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(
                "vadDelta arousal must be finite in [-1, 1]"
            ))
        );
        Ok(())
    }

    #[test]
    fn conflict_predicates_validate_as_ordinary_claims() -> Result<()> {
        let subject = EntityId::from_bytes([0x46; 16]).expect("valid id");
        let encode = |predicate: &str, subject: ClaimSubject, value: Value| -> Result<Vec<u8>> {
            let body = ClaimBody::new(
                predicate,
                subject,
                value,
                0.7,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Superseded,
            );
            encode_claim_body(&body)
        };

        validate_claim_body_bytes(
            &encode(
                PREDICATE_CONFLICT_OPEN,
                ClaimSubject::Entity(subject),
                Value::from("two active interpretations disagree"),
            )?,
            false,
        )?;
        validate_claim_body_bytes(
            &encode(
                PREDICATE_CONFLICT_RESOLVED,
                ClaimSubject::Entity(subject),
                Value::from("resolved by newer observation"),
            )?,
            false,
        )?;

        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    PREDICATE_CONFLICT_OPEN,
                    ClaimSubject::Entity(subject),
                    Value::Nil,
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(
                "conflict claim value must not be nil"
            ))
        );
        assert_matches!(
            validate_claim_body_bytes(
                &encode(
                    PREDICATE_CONFLICT_RESOLVED,
                    ClaimSubject::Edge {
                        source: EntityId::from_bytes([0x47; 16]).expect("valid id"),
                        kind: EdgeKind::Mentions,
                        target: EntityId::from_bytes([0x48; 16]).expect("valid id"),
                    },
                    Value::from("edge-scoped conflict"),
                )?,
                false,
            ),
            Err(Error::InvalidClaimBody(
                "conflict claim subject must be an entity"
            ))
        );
        Ok(())
    }

    #[test]
    fn reserved_namespace_rejected_public_allowed_internal() {
        assert_matches!(
            validate_predicate("edge.provenance", false),
            Err(Error::ReservedPredicate { .. })
        );
        assert_matches!(
            validate_predicate("edge.anything_else", false),
            Err(Error::ReservedPredicate { .. })
        );
        // The internal door allows the reserved namespace…
        validate_predicate("edge.provenance", true).expect("door must allow edge.*");
        // …but grammar still applies through the door.
        assert_matches!(
            validate_predicate("Edge.Provenance", true),
            Err(Error::InvalidPredicate { .. })
        );
        // "edgework.x" is NOT in the reserved namespace (prefix is segment-exact).
        validate_predicate("edgework.tools", false).expect("edgework.* is not reserved");
    }

    /// ONE-1159 — the write-door chokepoint ([`validate_claim_body_bytes`],
    /// shared by `put_reserved_claim` AND both `put_replicated` builders via
    /// `apply_put`) runs FULL structural validation on `edge.provenance`
    /// Claims: pinned value-record shape + persisted actor-class evidence,
    /// typed `InvalidProvenanceBody` rejections. Forged cases are junk
    /// SHAPES (never key-count assumptions), so each stays invalid under any
    /// grown value-record vocabulary.
    #[test]
    fn write_door_validates_edge_provenance_claim_structure() {
        use crate::provenance::{
            EVIDENCE_KEY_ACTOR_CLASS, EdgeProvenanceClaimBody, SupersessionStatus,
            encode_actor_class_evidence, encode_edge_provenance_value,
        };
        use crate::types::EdgeActorClass;

        let actor = EntityId::from_bytes([0x42; 16]).expect("valid id");
        // ONE-1159 fix-wave: a surfaceable wrapper's `conf` MUST mirror the
        // value-record `confidence`. The prior control hardcoded `0.9` ≠ the
        // record's `0.75` — a self-inconsistent "valid" wrapper the new mirror
        // check correctly rejects. Mirror both to one literal (fix the
        // control, not the assertion). The negative cases below all reject on
        // an EARLIER axis (value-record decode / actor-class), so the shared
        // `conf` value never weakens them.
        let confidence = 0.75_f32;
        let valid_value = || {
            encode_edge_provenance_value(&EdgeProvenanceClaimBody::new(
                actor,
                confidence,
                SupersessionStatus::Confirmed,
            ))
        };
        let evid = encode_actor_class_evidence(EdgeActorClass::Human);
        let subject = ClaimSubject::Edge {
            source: EntityId::from_bytes([0x11; 16]).expect("valid id"),
            kind: EdgeKind::Mentions,
            target: EntityId::from_bytes([0x22; 16]).expect("valid id"),
        };
        let encode = |predicate: &str, value: Value, evidence: Option<Value>| {
            let mut body = ClaimBody::new(
                predicate,
                subject,
                value,
                confidence,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.evidence = evidence;
            encode_claim_body(&body).expect("encode")
        };

        // Fully-valid legacy shape (value record + engine-owned evid map):
        // accepted through the reserved door.
        validate_claim_body_bytes(
            &encode("edge.provenance", valid_value(), Some(evid.clone())),
            true,
        )
        .expect("valid edge.provenance claim must pass the write door");

        let missing_actor = {
            let Value::Map(mut entries) = valid_value() else {
                unreachable!("encoder emits a map");
            };
            entries.retain(|(key, _)| key.as_str() != Some("actor_entity_ref"));
            Value::Map(entries)
        };
        let garbage_key = {
            let Value::Map(mut entries) = valid_value() else {
                unreachable!("encoder emits a map");
            };
            entries.push((Value::from("zzz"), Value::from(1_u8)));
            Value::Map(entries)
        };
        let class_in_value_record = {
            let Value::Map(mut entries) = valid_value() else {
                unreachable!("encoder emits a map");
            };
            entries.push((Value::from(EVIDENCE_KEY_ACTOR_CLASS), Value::from(0_u8)));
            Value::Map(entries)
        };

        let rejected: [(&str, Vec<u8>); 6] = [
            (
                "non-map value record",
                encode("edge.provenance", Value::from("junk"), Some(evid.clone())),
            ),
            (
                "value record missing required actor_entity_ref",
                encode("edge.provenance", missing_actor, Some(evid.clone())),
            ),
            (
                "unknown key zzz in value record",
                encode("edge.provenance", garbage_key, Some(evid.clone())),
            ),
            (
                "missing actor_class evidence entirely",
                encode("edge.provenance", valid_value(), None),
            ),
            (
                "malformed actor_class evidence (non-map evid)",
                encode("edge.provenance", valid_value(), Some(Value::from(7_u8))),
            ),
            // Rejected under BOTH vocabularies: today `actor_class` is not a
            // value-record key (unknown-key reject); once the vocabulary
            // carries it, body-key + evid together are the ambiguous
            // two-sources-of-truth shape (both-present reject).
            (
                "actor_class in both the value record and evid",
                encode("edge.provenance", class_in_value_record, Some(evid)),
            ),
        ];
        for (name, data) in rejected {
            assert!(
                matches!(
                    validate_claim_body_bytes(&data, true),
                    Err(Error::InvalidProvenanceBody(_))
                ),
                "{name}: must reject typed (InvalidProvenanceBody) at the write door"
            );
        }

        // Predicate-scoped: the structural branch fires on the pinned
        // edge.provenance literal only. Other reserved-namespace claims and
        // public claims keep their opaque D18 `val`.
        validate_claim_body_bytes(
            &encode("edge.other_records", Value::from("opaque"), None),
            true,
        )
        .expect("non-provenance reserved claim keeps opaque val");
        validate_claim_body_bytes(
            &encode("hobby.collects", Value::from("opaque"), None),
            false,
        )
        .expect("public claim keeps opaque val");
    }

    #[test]
    fn claim_subject_decode_pins_both_encodings() {
        let id = EntityId::from_bytes([0x11; 16]).expect("valid id");
        assert_eq!(
            ClaimSubject::decode(id.as_bytes()).expect("16-byte subj"),
            ClaimSubject::Entity(id)
        );

        let source = EntityId::from_bytes([0x22; 16]).expect("valid id");
        let target = EntityId::from_bytes([0x33; 16]).expect("valid id");
        let mut edge_ref = Vec::new();
        edge_ref.extend_from_slice(source.as_bytes());
        edge_ref.push(9); // Mentions
        edge_ref.extend_from_slice(target.as_bytes());
        assert_eq!(
            ClaimSubject::decode(&edge_ref).expect("33-byte subj"),
            ClaimSubject::Edge {
                source,
                kind: EdgeKind::Mentions,
                target,
            }
        );

        // 17 bytes — neither encoding.
        assert_matches!(
            ClaimSubject::decode(&[0x44; 17]),
            Err(Error::InvalidClaimBody(_))
        );
        // 33 bytes with an unregistered kind byte.
        let mut bad_kind = edge_ref.clone();
        bad_kind[16] = 200;
        assert_matches!(
            ClaimSubject::decode(&bad_kind),
            Err(Error::InvalidClaimBody(_))
        );
        // Reserved entity-id bytes (all zero) rejected.
        assert_matches!(
            ClaimSubject::decode(&[0x00; 16]),
            Err(Error::InvalidClaimBody(_))
        );
    }

    /// ARCH-0004 / ARCH-0022 world write-validation, exercised on the claim
    /// body chokepoint with hand-built MessagePack so a wrong impl that stores
    /// arbitrary `world` bytes FAILS: a present `world` must be exactly 16
    /// binary bytes (→ an `EntityId`), an absent key is base reality (`None`),
    /// and a 15-byte blob or a string is a typed `InvalidClaimBody`.
    #[test]
    fn world_value_must_be_16_byte_binary() {
        let subj = EntityId::from_bytes([0x11; 16]).expect("valid subject id");
        let body_with_world = |world: Option<Value>| -> Vec<u8> {
            let mut entries = vec![
                (Value::from("pred"), Value::from("profile.name")),
                (Value::from("val"), Value::from("x")),
                (Value::from("conf"), Value::F32(1.0)),
            ];
            if let Some(world) = world {
                entries.push((Value::from("world"), world));
            }
            entries.push((Value::from("subj"), Value::Binary(subj.as_bytes().to_vec())));
            entries.push((Value::from("appr"), Value::from("auto")));
            entries.push((Value::from("life"), Value::from("active")));
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode body");
            out
        };

        // Exactly 16 binary bytes → an EntityId.
        let world_id = EntityId::from_bytes([0x5A; 16]).expect("valid world id");
        let good = body_with_world(Some(Value::Binary(world_id.as_bytes().to_vec())));
        assert_eq!(
            decode_claim_body(&good, false)
                .expect("16-byte world passes")
                .world,
            Some(world_id)
        );

        // Absent key = base reality (None), the elide-the-default pattern.
        let base = body_with_world(None);
        assert_eq!(
            decode_claim_body(&base, false)
                .expect("absent world passes")
                .world,
            None
        );

        // 15-byte blob rejected fail-closed.
        assert_matches!(
            decode_claim_body(&body_with_world(Some(Value::Binary(vec![0x5A; 15]))), false),
            Err(Error::InvalidClaimBody(_))
        );

        // String rejected fail-closed (the pre-fix opaque-bytes behavior).
        assert_matches!(
            decode_claim_body(&body_with_world(Some(Value::from("w0"))), false),
            Err(Error::InvalidClaimBody(_))
        );
    }

    #[test]
    fn psych_profile_keeps_legacy_profile_claim_body_backward_compatible() {
        let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
        let mut legacy = ClaimBody::new(
            "profile.preference",
            subject,
            Value::from("prefers concise explanations"),
            0.72,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        legacy.source = Some(ClaimSource::Observed);
        legacy.stale = false;

        let encoded = encode_claim_body(&legacy).expect("legacy profile claim encodes");
        let decoded = decode_claim_body(&encoded, false).expect("legacy profile claim decodes");

        assert_eq!(decoded.predicate, "profile.preference");
        assert_eq!(decoded.value, Value::from("prefers concise explanations"));
        assert_eq!(decoded.source, Some(ClaimSource::Observed));
        assert!(!decoded.stale);
        assert_eq!(
            CLAIM_BODY_KEYS,
            [
                "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj",
                "scope", "appr", "life", "stale",
            ],
            "PsychProfile snapshots must not extend the pinned Claim body ABI"
        );
    }

    #[test]
    fn claim_field_profile_slices_are_prefixes_of_the_pinned_keys() {
        assert_eq!(CLAIM_FIELDS_MINIMAL, &CLAIM_BODY_KEYS[..2]);
        assert_eq!(CLAIM_FIELDS_STANDARD, &CLAIM_BODY_KEYS[..5]);
        assert_eq!(CLAIM_FIELDS_FULL, &CLAIM_BODY_KEYS[..11]);
    }

    /// D19 literal truth table: `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false` — every other combination is excluded (ARCH-0003;
    /// ARCH-0004 §H items 1/2/4).
    #[test]
    fn claim_surfaceable_pins_the_full_status_truth_table() {
        let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
        let body = |appr: ClaimApprovalStatus, life: ClaimLifecycleStatus, stale: bool| {
            let mut body = ClaimBody::new("test.pred", subject, Value::from("v"), 0.5, appr, life);
            body.stale = stale;
            body
        };

        use ClaimApprovalStatus as A;
        use ClaimLifecycleStatus as L;

        // The ONLY surfaceable combinations.
        assert!(claim_surfaceable(&body(A::Auto, L::Active, false)));
        assert!(claim_surfaceable(&body(A::Approved, L::Active, false)));

        // Approval axis excludes independently of lifecycle (AC 3).
        assert!(!claim_surfaceable(&body(A::Proposed, L::Active, false)));
        assert!(!claim_surfaceable(&body(A::Rejected, L::Active, false)));

        // Lifecycle axis excludes independently of approval.
        assert!(!claim_surfaceable(&body(A::Auto, L::Superseded, false)));
        assert!(!claim_surfaceable(&body(A::Auto, L::Retracted, false)));
        assert!(!claim_surfaceable(&body(A::Approved, L::Superseded, false)));
        assert!(!claim_surfaceable(&body(A::Approved, L::Retracted, false)));

        // Staleness excludes even when both status axes pass (AC 1).
        assert!(!claim_surfaceable(&body(A::Auto, L::Active, true)));
        assert!(!claim_surfaceable(&body(A::Approved, L::Active, true)));

        // `ClaimBody::new` leaves `stale` at the decode default (absent =
        // false) — absence alone must not exclude (AC 4).
        assert!(claim_surfaceable(&ClaimBody::new(
            "test.pred",
            subject,
            Value::from("v"),
            0.5,
            A::Auto,
            L::Active,
        )));
    }

    #[test]
    fn claim_consolidatable_excludes_auto_generated_until_vetted() {
        let subject = ClaimSubject::Entity(EntityId::from_bytes([0x12; 16]).expect("valid id"));
        let mut body = ClaimBody::new(
            "test.pred",
            subject,
            Value::from("v"),
            0.5,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );

        body.source = Some(ClaimSource::Generated);
        assert!(
            claim_surfaceable(&body),
            "Auto/Generated claims still surface for read/review"
        );
        assert!(
            !claim_consolidatable(&body),
            "Auto/Generated claims are not authority-admissible"
        );

        body.approval = ClaimApprovalStatus::Approved;
        assert!(
            claim_consolidatable(&body),
            "vetted Generated claims are consolidatable"
        );

        body.approval = ClaimApprovalStatus::Auto;
        body.source = Some(ClaimSource::Inferred);
        assert!(
            claim_consolidatable(&body),
            "non-Generated surfaceable claims keep existing admission"
        );

        body.source = Some(ClaimSource::Imported);
        body.scope = Some(Value::Map(vec![(
            Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
            Value::from(ClaimSource::Generated.as_str()),
        )]));
        assert!(
            !claim_consolidatable(&body),
            "federated Generated origin remains authority-inadmissible after import restamp"
        );

        body.stale = true;
        assert!(
            !claim_consolidatable(&body),
            "consolidation preserves surfaceability's stale exclusion"
        );
    }

    /// ONE-1159 fix-wave — the WRITE door's surfaceability guard reuses the
    /// `claim_surfaceable` approval set: `Approved` is accepted (not only
    /// `Auto`), and `Proposed` is a typed reject. Pins the {auto, approved}
    /// boundary directly on the door function, independent of the read gate.
    #[test]
    fn provenance_door_accepts_approved_and_rejects_proposed_wrappers() {
        let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
        // Valid value record (3 required keys), conf mirrors the wrapper, no
        // valid-time on either side, actor-class on the wrapper `evid`.
        let value_record = Value::Map(vec![
            (
                Value::from("actor_entity_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
            (Value::from("confidence"), Value::F32(0.75)),
            (Value::from("supersession_status"), Value::from(1u8)),
        ]);
        let actor_class_evid = Value::Map(vec![(Value::from("actor_class"), Value::from(0u8))]);
        let wrapper = |appr: ClaimApprovalStatus| {
            let mut body = ClaimBody::new(
                crate::provenance::PREDICATE_EDGE_PROVENANCE,
                subject,
                value_record.clone(),
                0.75,
                appr,
                ClaimLifecycleStatus::Active,
            );
            body.evidence = Some(actor_class_evid.clone());
            body
        };

        // `Approved` is in the surfaceable set → the door passes it.
        validate_edge_provenance_claim_structure(&wrapper(ClaimApprovalStatus::Approved))
            .expect("approved provenance wrapper must pass the door");
        // `Proposed` is outside {auto, approved} → typed reject.
        assert_matches!(
            validate_edge_provenance_claim_structure(&wrapper(ClaimApprovalStatus::Proposed)),
            Err(Error::InvalidProvenanceBody(_))
        );
    }

    #[test]
    fn six_value_src_roundtrip() {
        for source in [
            ClaimSource::UserStated,
            ClaimSource::Observed,
            ClaimSource::Inferred,
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ] {
            assert_eq!(ClaimSource::parse(source.as_str()), Some(source));
        }
    }

    #[test]
    fn claim_source_explicit_auto_permit_set_includes_generated() {
        for source in [
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ] {
            assert!(
                source.requires_explicit_auto_permit(),
                "{} must require explicit auto permit",
                source.as_str()
            );
        }

        for source in [
            ClaimSource::UserStated,
            ClaimSource::Observed,
            ClaimSource::Inferred,
        ] {
            assert!(
                !source.requires_explicit_auto_permit(),
                "{} must not require explicit auto permit",
                source.as_str()
            );
        }
    }
}
