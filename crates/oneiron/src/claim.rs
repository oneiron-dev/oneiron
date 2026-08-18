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
//! `edge.*`, `skill.*` and `actor.*` namespaces are engine-reserved: public
//! writes are rejected with [`Error::ReservedPredicate`]. Crate-private
//! provenance, skill-hub and actor-claim doors own local writes, while the
//! `sync` feature's replicated-put
//! door (`put_replicated`) admits rematerialization; every door still runs
//! full structural validation. Well-formed UNKNOWN predicates are accepted — the crate is
//! predicate-agnostic for semantics (ARCH-0003 §G.1). Crate-owned
//! well-known predicates are listed in [`CLAIM_PREDICATE_REGISTRY`] and carry
//! the first-segment layer prefix `core`, `companion`, `eiri`, or `commitment`; that is a
//! schema/code-review convention, not a package split, plugin runtime,
//! consent matrix, or semantic dispatch registry.

use std::{
    collections::{BTreeMap, HashSet},
    io::Cursor,
    sync::Mutex,
};

use rmpv::Value;

use crate::Vault;
use crate::affect::Vad;
use crate::affect::{
    AFFECT_TRIGGER_PREDICATE,
    coping::{COPING_OUTCOME_PREDICATE, validate_coping_outcome_claim_structure},
    validate_affect_trigger_claim_structure,
};
use crate::batch::ApplyOpsGateMode;
use crate::batch::BatchOp;
use crate::batch::apply_ops;
use crate::batch::apply_ops_with_gate_mode;
use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::EmptyContext;
use crate::context_pack::EmptyReason;
use crate::deletion::MemoryTimeline;
use crate::deletion::MemoryTimelineRecord;
use crate::deletion::MemoryTimelineRecordState;
use crate::edge::{EdgeActorClass, EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::provenance::validate_actor_class;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::GateDecisionRecord;
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
use crate::vault::SUPERSEDES_DEFAULT_WEIGHT;
use crate::vault::edge_kind_prefix;
use crate::vault::parse_edge_record;
use crate::vault::require_key_len;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
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

/// Bound on the supersession-chain walk behind the write-verb validity guard
/// (ONE-1936). Cycles are caught by the walk's visited set; this caps the WORK
/// a single corrupt-but-acyclic chain can demand. Real revision chains are
/// short, so a walk this deep is evidence of a damaged graph, not of long
/// history, and it ends in a typed refusal rather than an unbounded traversal.
const MAX_SUPERSESSION_CHAIN_WALK: usize = 64;

/// Pinned ON-DISK MessagePack key set for type-0 (CLAIM) bodies (D11).
///
/// Order is canonical: the engine's encoder emits present fields in this
/// order, and the context-pack field profiles are prefixes of this list
/// (Minimal = first 2, Standard = first 5, Full = first 12; the lifecycle
/// keys `appr`/`life`/`stale` and optional session tag `sess` are excluded
/// from every serialization profile).
pub const CLAIM_BODY_KEYS: [&str; 16] = [
    "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "rel", "subj", "scope",
    "appr", "life", "stale", "sess",
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
pub(crate) const KEY_REL: &str = CLAIM_BODY_KEYS[9];
pub(crate) const KEY_SUBJ: &str = CLAIM_BODY_KEYS[10];
pub(crate) const KEY_SCOPE: &str = CLAIM_BODY_KEYS[11];
pub(crate) const KEY_APPR: &str = CLAIM_BODY_KEYS[12];
pub(crate) const KEY_LIFE: &str = CLAIM_BODY_KEYS[13];
pub(crate) const KEY_STALE: &str = CLAIM_BODY_KEYS[14];
pub(crate) const KEY_SESSION: &str = CLAIM_BODY_KEYS[15];

/// Predicate namespace for productizable memory-API records.
pub const PREDICATE_NAMESPACE_CORE: &str = "core";

/// Predicate namespace for relationship-aware companion extensions.
pub const PREDICATE_NAMESPACE_COMPANION: &str = "companion";

/// Predicate namespace for Eiri persona-specific extensions.
pub const PREDICATE_NAMESPACE_EIRI: &str = "eiri";

/// Predicate namespace for commitment claim records.
pub const PREDICATE_NAMESPACE_COMMITMENT: &str = "commitment";

/// Layer namespace prefixes allowed for crate-owned predicate ids.
pub const PREDICATE_LAYER_NAMESPACES: [&str; 4] = [
    PREDICATE_NAMESPACE_CORE,
    PREDICATE_NAMESPACE_COMPANION,
    PREDICATE_NAMESPACE_EIRI,
    PREDICATE_NAMESPACE_COMMITMENT,
];

/// Predicate used for synthetic prospective-query hint side records.
pub const PREDICATE_LEXICAL_QUERY_HINT: &str = "core.lexical.query_hint";

/// Pinned companion-expression predicate for the relationship/persona layer.
pub const PREDICATE_COMPANION_EXPRESSION: &str = "companion.expression";
pub const PREDICATE_COMPANION_EXPRESSION_LANGUAGE: &str = "companion.expression.language";
pub const PREDICATE_COMPANION_EXPRESSION_REGISTER: &str = "companion.expression.register";
pub const PREDICATE_COMPANION_EXPRESSION_KEIGO: &str = "companion.expression.keigo";
pub const PREDICATE_COMPANION_EXPRESSION_STYLE: &str = "companion.expression.style";

/// Claim predicate for an unresolved conflict state.
pub const PREDICATE_CONFLICT_OPEN: &str = "core.conflict.open";

/// Claim predicate for a resolved conflict state.
pub const PREDICATE_CONFLICT_RESOLVED: &str = "core.conflict.resolved";

/// Status of a cross-vault coreference link (ONE-1414).
///
/// Subject is the `same_as` EdgeRef itself, never either PERSON: the status is
/// a fact about the LINK, so it cannot be mistaken for a property one endpoint
/// carries and cannot survive the link's absence.
pub const PREDICATE_COREFERENCE_STATUS: &str = "core.coreference.status";

/// Per-pact consent to export a cross-vault coreference link (ONE-1414).
///
/// Consent is scoped to ONE pact by construction — the pact id lives in the
/// value — so a link shared into pact P is not thereby shared into pact Q.
/// Absence of this claim means the link is local-only, which is the default.
pub const PREDICATE_COREFERENCE_SHARE_CONSENT: &str = "core.coreference.share_consent";

/// Namespace prefix shared by every coreference claim predicate.
///
/// The federation export filter excludes the WHOLE namespace by default, so a
/// later `core.coreference.*` predicate is withheld from the moment it exists
/// rather than from the moment someone remembers to list it.
pub const PREDICATE_COREFERENCE_PREFIX: &str = "core.coreference.";

/// `core.coreference.status` value for an asserted, unconfirmed link.
pub const COREFERENCE_STATUS_PROPOSED: &str = "proposed";

/// `core.coreference.status` value for an owner-confirmed link.
pub const COREFERENCE_STATUS_CONFIRMED: &str = "confirmed";

/// The ONE key a `core.coreference.share_consent` value map may carry.
pub const COREFERENCE_SHARE_CONSENT_PACT_KEY: &str = "pact_id";

/// A federation pact id is 32 bytes, carried as 64 LOWERCASE hex characters.
const COREFERENCE_PACT_ID_HEX_LEN: usize = 2 * COREFERENCE_PACT_ID_LEN;

/// Byte length of a federation pact id.
pub(crate) const COREFERENCE_PACT_ID_LEN: usize = 32;

/// Claim-module well-known predicate registry.
///
/// This is only the crate-owned schema list used by structural validators and
/// namespace-convention tests. Unknown well-formed predicates remain accepted.
///
/// APPEND-ONLY, and the length is a consequence rather than a budget: this is a
/// concurrent-append surface (ONE-1538 commitment predicates and ONE-1421
/// expression predicates land on their own schedules), so a rebase that drops
/// a row is a defect. Every entry present must keep its structural-validator
/// seat in [`validate_claim_body_and_decode`].
pub const CLAIM_PREDICATE_REGISTRY: [&str; 11] = [
    PREDICATE_LEXICAL_QUERY_HINT,
    PREDICATE_COMPANION_EXPRESSION,
    PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED,
    PREDICATE_COREFERENCE_STATUS,
    PREDICATE_COREFERENCE_SHARE_CONSENT,
    PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
    PREDICATE_COMPANION_EXPRESSION_REGISTER,
    PREDICATE_COMPANION_EXPRESSION_KEIGO,
    PREDICATE_COMPANION_EXPRESSION_STYLE,
    crate::commitment::PREDICATE_COMMITMENT_RECORD,
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
    /// Session composition (ONE-1728 §7). `None` on the canonical handle,
    /// which therefore reads base only exactly as before; `Some` when the
    /// read was opened through a live session handle, in which case entity
    /// reads compose overlay ∪ base. Every policy/admission predicate above
    /// this field is unchanged — the union widens what is VISIBLE, never what
    /// is permitted.
    session_view: Option<&'a crate::store::SessionStoreView<'a>>,
}

impl crate::vault::Vault {
    #[must_use]
    pub fn scoped_read(&self, actor_key: ScopedReadActorKey) -> ScopedRead<'_> {
        ScopedRead {
            vault: self,
            actor_key,
            policy: Mutex::new(None),
            session_view: None,
        }
    }

    /// A scoped read composed over a live session's overlay: the same
    /// admission and policy gates, applied to the union the room can see.
    ///
    /// `Vault::scoped_read` on the canonical handle keeps seeing base only.
    #[allow(
        dead_code,
        reason = "ONE-1728 arms it through the branch-store oracle's ScopedRead sweep; the \
                  lib-target caller arrives with ONE-1729's session executor binding"
    )]
    pub(crate) fn scoped_read_in_session<'a>(
        &'a self,
        actor_key: ScopedReadActorKey,
        view: &'a crate::store::SessionStoreView<'a>,
    ) -> ScopedRead<'a> {
        ScopedRead {
            vault: self,
            actor_key,
            policy: Mutex::new(None),
            session_view: Some(view),
        }
    }
}

impl<'a> ScopedRead<'a> {
    #[must_use]
    pub fn vault(&self) -> &'a crate::Vault {
        self.vault
    }

    /// The entity accessor this read composes over: the room's union when
    /// opened in-session, base otherwise. Every entity read in this type goes
    /// through here so the two cases cannot diverge site by site.
    fn entities(&self) -> &crate::overlay_db::OverlayDb {
        match self.session_view {
            Some(view) => &view.entities,
            None => &self.vault.store.entities,
        }
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
        let Some(raw) = self.entities().get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(Some((header.entity_type, header.learned_at, body.to_vec())));
        }
        if !self.is_claim_raw_readable_in(&rtxn, id, &raw)? {
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
        let Some(raw) = self.entities().get(rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_CLAIM {
            self.is_claim_raw_readable_with_policy_in(rtxn, policy, id, &raw)
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
            edges.push(crate::vault::parse_edge_record(&key, &value)?);
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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(policy) = cached_policy {
            return Ok(policy);
        }
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, rtxn)?;
        *self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(policy.clone());
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

pub const EXPRESSION_REGISTER_CASUAL: &str = "casual";
pub const EXPRESSION_REGISTER_NEUTRAL: &str = "neutral";
pub const EXPRESSION_REGISTER_FORMAL: &str = "formal";
pub const EXPRESSION_KEIGO_NONE: &str = "none";
pub const EXPRESSION_KEIGO_TEINEIGO: &str = "teineigo";
pub const EXPRESSION_KEIGO_SONKEIGO: &str = "sonkeigo";
pub const EXPRESSION_KEIGO_KENJOGO: &str = "kenjogo";
pub const EXPRESSION_KEIGO_ADAPTIVE: &str = "adaptive";
pub const MAX_EXPRESSION_LANGUAGE_TAG_BYTES: usize = 35;
pub const MAX_EXPRESSION_STYLE_TOKEN_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExpressionPreferenceKind {
    Language,
    Register,
    Keigo,
    Style,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionRegister {
    Casual,
    Neutral,
    Formal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionKeigo {
    None,
    Teineigo,
    Sonkeigo,
    Kenjogo,
    Adaptive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressionPreferenceValue {
    Language(String),
    Register(ExpressionRegister),
    Keigo(ExpressionKeigo),
    Style(String),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionPreferenceOrigin {
    ExplicitUser,
    Inferred,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionPreferenceChange {
    pub subject: EntityId,
    pub value: ExpressionPreferenceValue,
    pub origin: ExpressionPreferenceOrigin,
    pub valid_from: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionPreferenceWriteResult {
    pub claim_id: EntityId,
    pub approval: ClaimApprovalStatus,
    pub superseded_claim_ids: Vec<EntityId>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpressionPreferenceSet {
    pub language: Option<String>,
    pub register: Option<ExpressionRegister>,
    pub keigo: Option<ExpressionKeigo>,
    pub style: Option<String>,
    pub winning_claim_ids: std::collections::BTreeMap<ExpressionPreferenceKind, EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LexicalQueryHintValue {
    pub(crate) target: EntityId,
    pub(crate) query: String,
}

/// Context-pack CLAIM field profiles, derived from [`CLAIM_BODY_KEYS`] so the
/// serializer cannot drift from the storage ABI.
pub(crate) const CLAIM_FIELDS_MINIMAL: &[&str] = claim_keys_prefix(2);
pub(crate) const CLAIM_FIELDS_STANDARD: &[&str] = claim_keys_prefix(5);
pub(crate) const CLAIM_FIELDS_FULL: &[&str] = claim_keys_prefix(12);

const fn claim_keys_prefix(len: usize) -> &'static [&'static str] {
    let whole: &[&str] = &CLAIM_BODY_KEYS;
    whole.split_at(len).0
}

/// Maximum predicate length in bytes (D17).
pub const MAX_PREDICATE_BYTES: usize = 128;

/// Reserved predicate namespace prefix (D17): `edge.*` predicates may only
/// be written through the `pub(crate)` provenance door.
pub const RESERVED_PREDICATE_NAMESPACE: &str = "edge";

/// Reserved skill predicate namespace: `skill.*` claims are authored only by
/// the crate-private skill-hub doors, never by the generic public Claim API.
pub(crate) const RESERVED_SKILL_PREDICATE_NAMESPACE: &str = "skill";

/// Reserved actor predicate namespace (ARCH-0053 §9, ONE-1739): `actor.*`
/// claims are STATES with meaning-by-projection (doc-13 r1/r3) — the
/// attribution projector, the Dreamer distill and the provider-confidence door
/// author them, and nobody else may. Reserving the namespace closes the hole
/// [`crate::provider_confidence`] documented on `actor.confidence_prior`: a
/// policy-authorized generic `put_claim` could plant a trust-bearing head that
/// the read path then honored. Engine doors keep writing through
/// `put_reserved_claim_in_txn`, the same exemption `skill.*` uses.
pub(crate) const RESERVED_ACTOR_PREDICATE_NAMESPACE: &str = "actor";

/// Claim predicate binding a Loro peer id (the device CRDT client id) to the
/// [`crate::write_envelope::WriteActor`] behind it (ED-00, ONE-1756).
///
/// Engine-reserved by construction: it sits in the `actor.*` namespace, so the
/// generic public Claim API rejects it and
/// [`crate::edit_distance::register_peer_actor`] — writing through
/// `put_reserved_claim_in_txn` — is the only author. That is what lets op
/// replay treat a binding as evidence of who a peer is rather than as a
/// caller's assertion. Deliberately NOT in [`CLAIM_PREDICATE_REGISTRY`]: the
/// registry admits only public `core.*`/`companion.*`/`eiri.*` predicates.
pub const PREDICATE_ACTOR_PEER_BINDING: &str = "actor.peer_binding";

/// Per-`(actor, scope)` amendment cost: how much a decider had to edit this
/// actor's proposals in one scope (ARCH-0003 §G.1, ARCH-0056 §5, ED-03).
///
/// Engine-reserved by its `actor.*` namespace, exactly like
/// [`PREDICATE_ACTOR_PEER_BINDING`], and written only through
/// [`crate::actor_claims::write_actor_claim`]'s chokepoint. Never in
/// [`CLAIM_PREDICATE_REGISTRY`]: the registry admits only public
/// `core.*`/`companion.*`/`eiri.*` predicates, and its landed test rejects a
/// reserved namespace outright.
pub const PREDICATE_ACTOR_EDIT_COST: &str = "actor.edit_cost";

/// Per-`(skill, scope)` amendment cost: how much a decider had to edit
/// proposals that rode this skill (ARCH-0003 §G.1, ARCH-0056 §5, ED-03).
///
/// The `skill.*` sibling of [`PREDICATE_ACTOR_EDIT_COST`], on the reserved
/// namespace `skill_hub` and `skill_reliability` already author through
/// `put_reserved_claim_in_txn`. Registry-exempt for the same reason.
pub const PREDICATE_SKILL_EDIT_COST: &str = "skill.edit_cost";

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
/// Scope key carrying the GATE-05 evidence-taint class stamped by the
/// promotion writer when a consolidation meet lands at/below `tool_output`
/// (engine-owned scope-map pattern, like `federated_original_source`).
pub(crate) const CLAIM_SCOPE_EVIDENCE_TAINT_KEY: &str = "evidence_taint";
#[cfg(feature = "sync")]
const CLAIM_SCOPE_PRE_RESTAMP_SCOPE_KEY: &str = "pre_restamp_scope";
/// Provenance inheritance floor (ONE-1645, P3/V2): the band an UNSTAMPED
/// claim reads. A claim with no scope map, or a scope map carrying no
/// `sensitivity` key, has no recorded provenance — so it reads "sensitive"
/// (band 2) and every disclosure surface fails closed against it.
///
/// Positive-evidence rule: public is an explicit act. Only a stored
/// `"sensitivity": "public" | 0` stamp reads band 0; absence never reads
/// public. Band 2 (not 3) is deliberate — it holds unstamped claims out of
/// non-owner disclosure (`disclosure_tier` Rule 3 fails closed at >= 2) while
/// leaving them visible to the OWNER in persona compiles
/// (`TIER_A_MIN_SENSITIVITY_BAND` = 3). Private means not-disclosed-to-others,
/// not invisible-to-self.
pub(crate) const UNSTAMPED_CLAIM_SENSITIVITY_BAND: u8 = 2;

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

/// Reads a claim's sensitivity band. Two distinct fail-closed shapes:
///
/// * **missing** (no scope map, or no `sensitivity` key) ⇒
///   `Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND)` — the ONE-1645 inheritance
///   floor. Unrecorded provenance reads private at every disclosure surface.
/// * **ambiguous** (duplicate `sensitivity` key) ⇒ `None` — unreadable, not
///   merely unstamped; consumers clamp harder on `None` than on the floor.
pub(crate) fn claim_sensitivity_band(body: &ClaimBody) -> Option<u8> {
    let Some(Value::Map(entries)) = &body.scope else {
        return Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND);
    };

    match single_map_value(entries, CLAIM_SCOPE_SENSITIVITY_KEY) {
        MapValue::Missing => Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND),
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

/// GATE-05 evidence-taint reader (ONE-1385): the trust-lattice meet class
/// recorded on a derived claim whose evidence passed through external
/// sources. A duplicated or unparseable taint marker is ambiguous; read
/// admission treats it as maximally tainted (`Imported`, the lattice
/// bottom) so authority consumers fail closed.
pub(crate) fn claim_evidence_taint(body: &ClaimBody) -> Option<ClaimSource> {
    let Some(Value::Map(entries)) = &body.scope else {
        return None;
    };

    match single_map_value(entries, CLAIM_SCOPE_EVIDENCE_TAINT_KEY) {
        MapValue::Missing => None,
        MapValue::Present(value) => Some(
            value
                .as_str()
                .and_then(ClaimSource::parse)
                .unwrap_or(ClaimSource::Imported),
        ),
        MapValue::Duplicate => Some(ClaimSource::Imported),
    }
}

/// A taint meet at/below `tool_output` in the D10 lattice blocks
/// consolidation until a human re-stamp (`Approved`) clears admission.
const fn evidence_taint_blocks_consolidation(taint: ClaimSource) -> bool {
    matches!(taint, ClaimSource::ToolOutput | ClaimSource::Imported)
}

/// D10 trust-lattice rank, high → low:
/// `UserStated > Observed > Inferred = Generated > ToolOutput > Imported`.
/// The single numeric statement of the order
/// [`crate::dreamer_consolidation::source_meet`] folds over — the lineage
/// guard compares ranks so `Inferred` and `Generated` remain one class.
#[must_use]
const fn claim_source_rank(source: ClaimSource) -> u8 {
    match source {
        ClaimSource::Imported => 0,
        ClaimSource::ToolOutput => 1,
        ClaimSource::Inferred | ClaimSource::Generated => 2,
        ClaimSource::Observed => 3,
        ClaimSource::UserStated => 4,
    }
}

/// True when `source` claims MORE trust than the evidence it was derived
/// from (ARCH-0067 §7: "re-stamping tool-output lineage as first-person
/// generated must be impossible"). Every upward move is a widening, not just
/// the `ToolOutput → Generated` one, so no alternate laundering label
/// (`Inferred`, `Observed`, `UserStated`) is left standing.
#[must_use]
pub(crate) const fn claim_source_widens_beyond(
    source: ClaimSource,
    evidence_meet: ClaimSource,
) -> bool {
    claim_source_rank(source) > claim_source_rank(evidence_meet)
}

/// Lineage-forgery guard (ONE-1710, ARCH-0067 §7), run from the write-only
/// chokepoint [`validate_claim_body_and_decode`] so every exposed write door
/// — `Vault::put_claim`, both batch builders, the reserved door, sync replay
/// and the provenance lifecycle rewrites — is covered by construction.
///
/// The invariant is lattice-wide: a stored `src` may never be more trusted
/// than the engine-owned `scope.evidence_taint` meet stamped beside it.
///
/// Two deliberate exits keep it a forgery guard rather than a new schema
/// rule:
///
/// * **Engine-reserved predicates** (`edge.*`, `skill.*`, `actor.*`) are
///   exempt. Those namespaces are unreachable from the generic public Claim
///   API — only crate-private engine doors author them — and they use the
///   two axes independently by design: `actor_claims` records WHO observed a
///   fact (`src = observed`) beside the trust class of the evidence chain it
///   observed (`evidence_taint = tool_output`, ONE-1314), which the
///   consolidation gate reads. Rejecting that shape would break both the
///   attribution projector and sync convergence for already-replicated rows,
///   without closing any agent-reachable path. The exemption is keyed on the
///   PREDICATE, never on `allow_reserved_predicate`: a caller that reaches a
///   reserved-door flag still gets the same predicate-derived answer.
/// * **Sourceless bodies** (legacy rows, sync replay of pre-`src` claims)
///   cannot widen anything, so they pass untouched — preserving convergence.
///
/// [`claim_evidence_taint`] already fails closed (malformed/duplicate taint
/// decodes as `Imported`, the lattice bottom), so a forger cannot escape by
/// corrupting the stamp: it lands at the most restrictive class instead.
pub(crate) fn validate_claim_source_lineage(body: &ClaimBody) -> Result<()> {
    if is_reserved_predicate(&body.predicate) {
        return Ok(());
    }
    let (Some(source), Some(evidence_meet)) = (body.source, claim_evidence_taint(body)) else {
        return Ok(());
    };
    if claim_source_widens_beyond(source, evidence_meet) {
        return Err(Error::InvalidClaimBody(
            "claim source widens beyond evidence lineage",
        ));
    }
    Ok(())
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
    /// `rel` - optional relationship scope: when present, exactly one 16-byte
    /// MessagePack Binary RELATIONSHIP [`EntityId`]; absent means core/all
    /// relationships. The claim codec validates this on-disk shape only and
    /// does not require the referenced relationship to exist at write time,
    /// matching `world`. Retrieval validates the active relationship's
    /// existence and type when relationship filtering executes.
    pub rel: Option<EntityId>,
    /// `scope` — optional relationship/facet scope (opaque MessagePack).
    pub scope: Option<Value>,
    /// `sess` — optional agent-session tag. Proposed claims sharing a tag
    /// form a review bundle; the tag remains as provenance after approval.
    pub session_tag: Option<String>,
    /// `stale` — derived-data staleness marker; absent on disk means `false`.
    pub stale: bool,
}

/// One session-tagged claim returned for bundle review or merge.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionClaimBundleClaim {
    /// Durable CLAIM entity id.
    pub id: EntityId,
    /// Current typed claim body.
    pub body: ClaimBody,
}

/// Coherent proposed-claim bundle for one agent session.
///
/// A bundle is a data-native projection over CLAIM rows sharing `sess` and
/// the envelope-stamped producer actor; it does not introduce an independent
/// branch record or storage table.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionClaimBundle {
    /// Stable tag supplied by the writing agent session.
    pub session_tag: String,
    /// Active proposed claims currently belonging to the session.
    pub claims: Vec<SessionClaimBundleClaim>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionClaimBundleMember {
    pub(crate) id: EntityId,
    pub(crate) body: ClaimBody,
    pub(crate) occurred: TimeRange,
    pub(crate) learned_at: u64,
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
            rel: None,
            scope: None,
            session_tag: None,
            stale: false,
        }
    }
}

/// Grouping unit of a dotted predicate: every segment EXCEPT the last
/// ("drop the leaf" — DESIGN-PIN A0). The grammar guarantees ≥2 segments
/// (`validate_predicate`), so the root is always non-empty on valid
/// predicates. Total on arbitrary namespaces (the wild has `oneiron.*`,
/// `user.*`, …); never panics; no registry or layer-list lookup — an
/// explicit per-predicate family field supersedes this formula when the
/// ONE-252 registry lands.
#[must_use]
pub fn predicate_root(predicate: &str) -> &str {
    match predicate.rfind('.') {
        Some(index) if index > 0 => &predicate[..index],
        _ => predicate,
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

/// Returns `true` when `predicate`'s first dot-separated segment is one of the
/// reserved `edge`, `skill` or `actor` namespaces (D17, ARCH-0053 §9). Their
/// writes and lifecycle transitions are owned by dedicated crate-private doors,
/// so the generic Claim API rejects them.
pub(crate) fn is_reserved_predicate(predicate: &str) -> bool {
    is_edge_reserved_predicate(predicate) || is_engine_owned_reserved_predicate(predicate)
}

fn is_edge_reserved_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(RESERVED_PREDICATE_NAMESPACE)
}

/// The reserved namespaces whose lifecycle the ENGINE drives (`skill.*`,
/// `actor.*`), as opposed to `edge.*`, whose transitions must re-stamp
/// provenance-derived edge state and therefore stay exclusively edge-owned.
fn is_engine_owned_reserved_predicate(predicate: &str) -> bool {
    let namespace = predicate.split('.').next();
    namespace == Some(RESERVED_SKILL_PREDICATE_NAMESPACE)
        || namespace == Some(RESERVED_ACTOR_PREDICATE_NAMESPACE)
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

pub(crate) fn validate_session_tag(session_tag: &str) -> Result<()> {
    if session_tag.trim().is_empty() {
        return Err(Error::InvalidClaimBody(
            "sess must be a non-empty, non-whitespace string",
        ));
    }
    Ok(())
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
    if let Some(rel) = body.rel {
        entries.push((Value::from(KEY_REL), Value::Binary(rel.as_bytes().to_vec())));
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
    if let Some(session_tag) = &body.session_tag {
        entries.push((Value::from(KEY_SESSION), Value::from(session_tag.as_str())));
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
/// * `world` and `rel`, when present, must each be exactly one 16-byte
///   MessagePack Binary [`EntityId`]; their existence and entity-type
///   validation belongs to retrieval, not this codec;
/// * `subj` must be a 16-byte entity id or 33-byte EdgeRef ([`ClaimSubject`]);
/// * `pred` must satisfy the D17 grammar; reserved `edge.*` and `skill.*`
///   predicates are rejected unless `allow_reserved_predicate` is set
///   (crate-private door / read path).
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
    let mut rel: Option<EntityId> = None;
    let mut scope: Option<Value> = None;
    let mut session_tag: Option<String> = None;
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
            "rel" => {
                let Value::Binary(bytes) = &value else {
                    return Err(Error::InvalidClaimBody("rel must be MessagePack binary"));
                };
                let arr: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| {
                    Error::InvalidClaimBody("rel must be a 16-byte relationship id")
                })?;
                rel = Some(
                    EntityId::from_bytes(arr)
                        .map_err(|_| Error::InvalidClaimBody("relationship id is reserved"))?,
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
            "sess" => {
                let Some(tag) = value.as_str() else {
                    return Err(Error::InvalidClaimBody("sess must be a string"));
                };
                validate_session_tag(tag)?;
                session_tag = Some(tag.to_owned());
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
        rel,
        scope,
        session_tag,
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
    // Lineage before predicate shape (ONE-1710): the forgery guard is
    // predicate-agnostic, so it must not sit behind a predicate-specific
    // branch that only some claims enter.
    validate_claim_source_lineage(&body)?;
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        validate_edge_provenance_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_LEXICAL_QUERY_HINT {
        lexical_query_hint_target(&body)?;
    } else if is_expression_preference_predicate(&body.predicate) {
        validate_expression_preference_claim_structure(&body)?;
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
    } else if body.predicate == PREDICATE_COREFERENCE_STATUS {
        validate_coreference_status_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_COREFERENCE_SHARE_CONSENT {
        validate_coreference_share_consent_claim_structure(&body)?;
    } else if body.predicate == crate::identity_topology::PREDICATE_ENTITY_DISTINCT_FROM {
        crate::identity_topology::validate_distinct_from_claim_structure(&body)?;
    } else if crate::channel_identity::is_channel_identity_claim_predicate(&body.predicate) {
        crate::channel_identity::validate_channel_identity_claim_structure(&body)?;
    } else if crate::identity_reputation::is_identity_reputation_claim_predicate(&body.predicate) {
        crate::identity_reputation::validate_identity_reputation_claim_structure(&body)?;
    } else if crate::provider_confidence::is_actor_confidence_prior_claim_predicate(&body.predicate)
    {
        crate::provider_confidence::validate_actor_confidence_prior_claim_structure(&body)?;
    } else if crate::actor_claims::is_actor_claim_predicate(&body.predicate) {
        crate::actor_claims::validate_actor_claim_structure(&body)?;
    } else if crate::counterparty_contact::is_counterparty_contact_claim_predicate(&body.predicate)
    {
        crate::counterparty_contact::validate_counterparty_contact_claim_structure(&body)?;
    } else if crate::commitment::is_commitment_claim_predicate(&body.predicate) {
        crate::commitment::validate_commitment_claim_structure(&body)?;
    } else if crate::calendar::claims::is_calendar_claim_predicate(&body.predicate) {
        crate::calendar::claims::validate_calendar_claim_structure(&body)?;
    } else if crate::campaign::claims::is_campaign_pack_claim_predicate(&body.predicate) {
        // EXACT-predicate match, deliberately ahead of the `comm.` family: the
        // CRM pack owns `comm.do_not_contact` / `comm.bounce` /
        // `comm.jurisdiction` while `comm.rs` keeps `comm.opt_out` and friends.
        crate::campaign::claims::validate_campaign_pack_claim_structure(&body)?;
    } else if crate::comm::is_comm_claim_predicate(&body.predicate) {
        crate::comm::validate_comm_claim_structure(&body)?;
    } else if crate::disclosure::is_disclosure_claim_predicate(&body.predicate) {
        crate::disclosure::validate_disclosure_claim_structure(&body)?;
    } else if crate::delivery_window::is_delivery_window_claim_predicate(&body.predicate) {
        crate::delivery_window::validate_delivery_window_claim_structure(&body)?;
    } else if crate::calendar::claims::is_calendar_claim_predicate(&body.predicate) {
        crate::calendar::claims::validate_calendar_claim_structure(&body)?;
    } else if crate::booking::config::is_booking_claim_predicate(&body.predicate) {
        // EXACT-predicate membership, like every arm above: a `booking.` prefix
        // would silently adopt every future booking predicate into the
        // event-type validator.
        crate::booking::config::validate_event_type_claim(&body)?;
    }
    Ok(body)
}

pub fn is_expression_preference_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_COMPANION_EXPRESSION_LANGUAGE
            | PREDICATE_COMPANION_EXPRESSION_REGISTER
            | PREDICATE_COMPANION_EXPRESSION_KEIGO
            | PREDICATE_COMPANION_EXPRESSION_STYLE
    )
}

fn valid_expression_language(value: &str) -> bool {
    if !(2..=MAX_EXPRESSION_LANGUAGE_TAG_BYTES).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    let parts: Vec<&str> = value.split('-').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || p.len() > 8 || !p.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return false;
    }
    if parts[0].len() < 2 || parts[0].len() > 8 || !parts[0].bytes().all(|b| b.is_ascii_lowercase())
    {
        return false;
    }
    for (i, part) in parts.iter().enumerate().skip(1) {
        let region = part.len() == 2 && part.bytes().all(|b| b.is_ascii_alphabetic());
        if region {
            if !part.bytes().all(|b| b.is_ascii_uppercase()) {
                return false;
            }
        } else if part.len() == 4
            && part.as_bytes()[0].is_ascii_uppercase()
            && part.as_bytes()[1..].iter().all(u8::is_ascii_lowercase)
        {
            // Canonical script subtags are title-cased, e.g. `zh-Hant`.
        } else if !part
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
        let _ = i;
    }
    true
}
fn valid_expression_style(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXPRESSION_STYLE_TOKEN_BYTES
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
pub fn validate_expression_preference_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "expression preference subject must be an entity",
        ));
    }
    let value = body.value.as_str().ok_or(Error::InvalidClaimBody(
        "expression preference value must be a string",
    ))?;
    let valid = match body.predicate.as_str() {
        PREDICATE_COMPANION_EXPRESSION_LANGUAGE => valid_expression_language(value),
        PREDICATE_COMPANION_EXPRESSION_REGISTER => matches!(
            value,
            EXPRESSION_REGISTER_CASUAL | EXPRESSION_REGISTER_NEUTRAL | EXPRESSION_REGISTER_FORMAL
        ),
        PREDICATE_COMPANION_EXPRESSION_KEIGO => matches!(
            value,
            EXPRESSION_KEIGO_NONE
                | EXPRESSION_KEIGO_TEINEIGO
                | EXPRESSION_KEIGO_SONKEIGO
                | EXPRESSION_KEIGO_KENJOGO
                | EXPRESSION_KEIGO_ADAPTIVE
        ),
        PREDICATE_COMPANION_EXPRESSION_STYLE => valid_expression_style(value),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "invalid expression preference value",
        ))
    }
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

/// The subject shape both `core.coreference.*` validators require: an EdgeRef
/// naming a `same_as` edge, and nothing else.
///
/// The kind check is EXACT (byte 20 only), not "some structural kind". A
/// coreference status or consent claim hung off a `belongs_to` or `merged_into`
/// EdgeRef would be a statement about a relation these predicates do not
/// govern, and the export filter reads consent BY LINK — so admitting a
/// foreign-kind subject would let a claim vouch for a link it never described.
/// An entity subject fails for the same reason: status is a fact about the
/// LINK, so it must not be able to outlive it or attach to one endpoint.
fn require_coreference_link_subject(body: &ClaimBody) -> Result<()> {
    match body.subject {
        ClaimSubject::Edge {
            kind: EdgeKind::SameAs,
            ..
        } => Ok(()),
        _ => Err(Error::InvalidClaimBody(
            "coreference claim subject must be a same_as EdgeRef",
        )),
    }
}

/// ONE-1414 — `core.coreference.status`.
///
/// Value is the string `proposed` or `confirmed`, and the approval axis is
/// pinned to it: `confirmed` asserts identity as settled truth and therefore
/// requires an owner `Approved`, while `proposed` is an unsettled assertion and
/// admits only `Auto` or `Proposed`. The two rules are one gate — a `confirmed`
/// row carrying `Auto` would be an unreviewed identity merge wearing a
/// reviewed label.
fn validate_coreference_status_claim_structure(body: &ClaimBody) -> Result<()> {
    require_coreference_link_subject(body)?;
    let Some(status) = body.value.as_str() else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.status value must be a string",
        ));
    };
    let approval_fits = match status {
        COREFERENCE_STATUS_CONFIRMED => body.approval == ClaimApprovalStatus::Approved,
        COREFERENCE_STATUS_PROPOSED => matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
        ),
        _ => {
            return Err(Error::InvalidClaimBody(
                "core.coreference.status value must be proposed|confirmed",
            ));
        }
    };
    if !approval_fits {
        return Err(Error::InvalidClaimBody(
            "confirmed coreference requires approved; proposed requires auto|proposed",
        ));
    }
    Ok(())
}

/// ONE-1414 — `core.coreference.share_consent`.
///
/// Sharing an identity link across a federation boundary is an owner decision,
/// so `Approved` is the only admissible approval; there is no `Auto` path that
/// could let an agent widen disclosure.
fn validate_coreference_share_consent_claim_structure(body: &ClaimBody) -> Result<()> {
    require_coreference_link_subject(body)?;
    coreference_share_consent_pact_id(body)?;
    if body.approval != ClaimApprovalStatus::Approved {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent requires approved",
        ));
    }
    Ok(())
}

/// The pact id a `core.coreference.share_consent` claim names.
///
/// The value vocabulary is EXACTLY one key. A second key — even an inert one —
/// is rejected rather than ignored: this claim is read by the export filter to
/// decide what crosses a grant, and a map with room for unread keys is a place
/// to hide a second, unhonored scope.
pub(crate) fn coreference_share_consent_pact_id(
    body: &ClaimBody,
) -> Result<[u8; COREFERENCE_PACT_ID_LEN]> {
    let Value::Map(entries) = &body.value else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent value must be a map",
        ));
    };
    let [(key, value)] = entries.as_slice() else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent value must carry exactly one key",
        ));
    };
    if key.as_str() != Some(COREFERENCE_SHARE_CONSENT_PACT_KEY) {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent key must be pact_id",
        ));
    }
    let Some(hex) = value.as_str() else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent pact_id must be a string",
        ));
    };
    decode_coreference_pact_id(hex)
}

/// Decodes a 64-character LOWERCASE hex pact id.
///
/// Lowercase-only is a canonicity rule, not fussiness: the selector compares
/// the claim's pact against the export pact, and admitting both cases would
/// give one pact two spellings — hence two consent claims that a
/// string-equality reader could disagree about. Odd length, uppercase, and
/// non-hex bytes all fail here.
fn decode_coreference_pact_id(hex: &str) -> Result<[u8; COREFERENCE_PACT_ID_LEN]> {
    let malformed =
        || Error::InvalidClaimBody("coreference pact_id must be 64 lowercase hex chars");
    if hex.len() != COREFERENCE_PACT_ID_HEX_LEN {
        return Err(malformed());
    }
    let (chunks, rem) = hex.as_bytes().as_chunks::<2>();
    debug_assert!(rem.is_empty());
    let mut bytes = [0_u8; COREFERENCE_PACT_ID_LEN];
    for (slot, &[hi, lo]) in bytes.iter_mut().zip(chunks) {
        let (Some(hi), Some(lo)) = (lowercase_hex_nibble(hi), lowercase_hex_nibble(lo)) else {
            return Err(malformed());
        };
        *slot = (hi << 4) | lo;
    }
    Ok(bytes)
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
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
    if conflict_value_uses_repo_schema(&body.value) {
        crate::repo_mutation::validate_repo_conflict_claim_value(&body.predicate, &body.value)?;
    }
    Ok(())
}

fn conflict_value_uses_repo_schema(value: &Value) -> bool {
    let Value::Map(entries) = value else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        matches!(
            key.as_str(),
            Some(
                "schema_version"
                    | "kind"
                    | "repo_ref"
                    | "branch"
                    | "base_tree"
                    | "ours_tree"
                    | "theirs_tree"
                    | "conflicted_paths"
                    | "open_conflict_claim_id"
                    | "resolved_tree"
                    | "resolved_paths"
            )
        ) || value.as_str() == Some("repo_branch")
    })
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
    // of the key's value is the shared decoder's responsibility above (and a body
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
        && !(claim_evidence_taint(body).is_some_and(evidence_taint_blocks_consolidation)
            && body.approval != ClaimApprovalStatus::Approved)
}

/// GATE-11: a generated-origin claim may never serve as extraction evidence
/// or corroboration for another first-party write — generated output must
/// never corroborate itself into higher trust. Reads declared source AND
/// the federated pre-restamp origin, like [`claim_consolidatable`].
///
/// Unlike consolidatability, approval status does NOT clear evidence
/// admissibility: an `Approved` Generated claim is merge-eligible but still
/// contributes ZERO corroboration. Consumption contract: the promotion
/// writer (ONE-1290) drops any `evidence_turn_refs` entry resolving to a
/// CLAIM entity that fails this predicate, and the consolidation working
/// set (ONE-1289) is TURN-only — claims never enter it.
#[cfg_attr(not(test), allow(dead_code))] // consumed by ONE-1289/ONE-1290
pub(crate) fn claim_evidence_admissible(body: &ClaimBody) -> bool {
    !claim_generated_origin(body)
}

pub(crate) fn psych_mirror_claim_affect_salience(body: &ClaimBody) -> Result<f32> {
    let salience = body.salience.unwrap_or(0.0);
    let affect = crate::affect::decode_affect_trigger_claim(body)?.map_or(0.0, |trigger| {
        let delta = trigger.vad_delta();
        let valence = (delta.valence().abs() / 2.0).clamp(0.0, 1.0);
        let arousal = delta.arousal().abs().clamp(0.0, 1.0);
        let dominance = delta.dominance().abs().clamp(0.0, 1.0);
        ((valence + arousal + dominance) / 3.0) * trigger.confidence()
    });
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

impl Vault {
    /// Writes one typed expression preference through the ordinary claim gate.
    fn expression_source_rank(source: Option<ClaimSource>) -> u8 {
        match source {
            Some(ClaimSource::UserStated) => 3,
            Some(ClaimSource::Observed) => 2,
            Some(ClaimSource::Inferred) => 1,
            _ => 0,
        }
    }

    fn expression_preference_order(
        source: Option<ClaimSource>,
        valid_from: Option<u64>,
        learned_at: u64,
        id: EntityId,
    ) -> (u8, u64, u64, EntityId) {
        (
            Self::expression_source_rank(source),
            valid_from.unwrap_or(0),
            learned_at,
            id,
        )
    }

    fn expression_preference_wins(
        candidate: (Option<ClaimSource>, Option<u64>, u64, EntityId),
        incumbent: (Option<ClaimSource>, Option<u64>, u64, EntityId),
    ) -> bool {
        Self::expression_preference_order(candidate.0, candidate.1, candidate.2, candidate.3)
            > Self::expression_preference_order(incumbent.0, incumbent.1, incumbent.2, incumbent.3)
    }

    pub fn set_expression_preference(
        &self,
        actor: &crate::write_envelope::WriteActor,
        claim_id: EntityId,
        change: ExpressionPreferenceChange,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ExpressionPreferenceWriteResult> {
        if matches!(change.origin, ExpressionPreferenceOrigin::ExplicitUser)
            && !matches!(actor.actor_class(), EdgeActorClass::Human)
        {
            return Err(Error::InvalidClaimBody(
                "explicit expression preference requires a human actor",
            ));
        }
        let (predicate, wire) = match &change.value {
            ExpressionPreferenceValue::Language(v) => {
                (PREDICATE_COMPANION_EXPRESSION_LANGUAGE, v.clone())
            }
            ExpressionPreferenceValue::Register(v) => (
                PREDICATE_COMPANION_EXPRESSION_REGISTER,
                match v {
                    ExpressionRegister::Casual => EXPRESSION_REGISTER_CASUAL,
                    ExpressionRegister::Neutral => EXPRESSION_REGISTER_NEUTRAL,
                    ExpressionRegister::Formal => EXPRESSION_REGISTER_FORMAL,
                }
                .to_owned(),
            ),
            ExpressionPreferenceValue::Keigo(v) => (
                PREDICATE_COMPANION_EXPRESSION_KEIGO,
                match v {
                    ExpressionKeigo::None => EXPRESSION_KEIGO_NONE,
                    ExpressionKeigo::Teineigo => EXPRESSION_KEIGO_TEINEIGO,
                    ExpressionKeigo::Sonkeigo => EXPRESSION_KEIGO_SONKEIGO,
                    ExpressionKeigo::Kenjogo => EXPRESSION_KEIGO_KENJOGO,
                    ExpressionKeigo::Adaptive => EXPRESSION_KEIGO_ADAPTIVE,
                }
                .to_owned(),
            ),
            ExpressionPreferenceValue::Style(v) => {
                (PREDICATE_COMPANION_EXPRESSION_STYLE, v.clone())
            }
        };
        let source = match change.origin {
            ExpressionPreferenceOrigin::ExplicitUser => ClaimSource::UserStated,
            ExpressionPreferenceOrigin::Inferred => ClaimSource::Inferred,
        };
        let candidate = ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(change.subject),
            Value::from(wire),
            1.0,
        )
        .with_validity(Some(change.valid_from), None);
        let provenance = WriteProvenance::new(Value::from("expression_preference"))?;
        let envelope = WriteEnvelope::new(*actor, source, provenance, ClaimApprovalStatus::Auto);
        let mut wtxn = self.store.env.write_txn()?;
        let mut prior_ids = Vec::new();
        for (old_id, body) in self.claims_with_predicate_in_txn(&wtxn, predicate)? {
            if old_id == claim_id
                || body.subject != ClaimSubject::Entity(change.subject)
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let old_learned_at = self
                .store
                .entities
                .get(&wtxn, old_id.as_bytes())?
                .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|h| h.learned_at))
                .ok_or(Error::CorruptedIndex("expression preference header"))?;
            if Self::expression_preference_wins(
                (Some(source), Some(change.valid_from), learned_at, claim_id),
                (body.source, body.valid_from, old_learned_at, old_id),
            ) {
                prior_ids.push(old_id);
            }
        }

        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::ClaimCandidate {
                id: claim_id,
                candidate: Box::new(candidate),
                envelope,
                occurred,
                learned_at,
                internal_lexical_query_hint: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(true, true).with_source_in_gate_input(),
        )?;
        let mut superseded_claim_ids = Vec::new();
        for old_id in prior_ids {
            match self.supersede_claim_in_txn(&mut wtxn, &claim_id, &old_id, learned_at) {
                Ok(()) => superseded_claim_ids.push(old_id),
                Err(Error::InvalidClaimBody(_)) if source == ClaimSource::Inferred => {}
                Err(err) => return Err(err),
            }
        }
        wtxn.commit()?;
        Ok(ExpressionPreferenceWriteResult {
            claim_id,
            approval: ClaimApprovalStatus::Auto,
            superseded_claim_ids,
        })
    }

    /// Resolves active typed preferences with source precedence and recency.
    pub fn expression_preferences(
        &self,
        subject: &EntityId,
        at: u64,
    ) -> Result<ExpressionPreferenceSet> {
        let rtxn = self.store.env.read_txn()?;
        let mut best: BTreeMap<ExpressionPreferenceKind, (EntityId, ClaimBody, u64)> =
            BTreeMap::new();
        for predicate in [
            PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
            PREDICATE_COMPANION_EXPRESSION_REGISTER,
            PREDICATE_COMPANION_EXPRESSION_KEIGO,
            PREDICATE_COMPANION_EXPRESSION_STYLE,
        ] {
            for (id, body) in self.claims_with_predicate_in_txn(&rtxn, predicate)? {
                let learned_at = self
                    .store
                    .entities
                    .get(&rtxn, id.as_bytes())?
                    .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|h| h.learned_at))
                    .ok_or(Error::CorruptedIndex("expression preference header"))?;
                if body.subject != ClaimSubject::Entity(*subject)
                    || body.lifecycle != ClaimLifecycleStatus::Active
                {
                    continue;
                }
                if body.valid_from.is_some_and(|v| v > at) || body.valid_to.is_some_and(|v| v <= at)
                {
                    continue;
                }
                let kind = match predicate {
                    PREDICATE_COMPANION_EXPRESSION_LANGUAGE => ExpressionPreferenceKind::Language,
                    PREDICATE_COMPANION_EXPRESSION_REGISTER => ExpressionPreferenceKind::Register,
                    PREDICATE_COMPANION_EXPRESSION_KEIGO => ExpressionPreferenceKind::Keigo,
                    _ => ExpressionPreferenceKind::Style,
                };
                let replace = best.get(&kind).is_none_or(|(old_id, old, old_learned_at)| {
                    Self::expression_preference_wins(
                        (body.source, body.valid_from, learned_at, id),
                        (old.source, old.valid_from, *old_learned_at, *old_id),
                    )
                });
                if replace {
                    best.insert(kind, (id, body, learned_at));
                }
            }
        }
        let mut out = ExpressionPreferenceSet::default();
        for (kind, (id, body, _learned_at)) in best {
            let Some(v) = body.value.as_str() else {
                continue;
            };
            out.winning_claim_ids.insert(kind, id);
            match kind {
                ExpressionPreferenceKind::Language => out.language = Some(v.to_owned()),
                ExpressionPreferenceKind::Style => out.style = Some(v.to_owned()),
                ExpressionPreferenceKind::Register => {
                    out.register = match v {
                        "casual" => Some(ExpressionRegister::Casual),
                        "neutral" => Some(ExpressionRegister::Neutral),
                        "formal" => Some(ExpressionRegister::Formal),
                        _ => None,
                    }
                }
                ExpressionPreferenceKind::Keigo => {
                    out.keigo = match v {
                        "none" => Some(ExpressionKeigo::None),
                        "teineigo" => Some(ExpressionKeigo::Teineigo),
                        "sonkeigo" => Some(ExpressionKeigo::Sonkeigo),
                        "kenjogo" => Some(ExpressionKeigo::Kenjogo),
                        "adaptive" => Some(ExpressionKeigo::Adaptive),
                        _ => None,
                    }
                }
            };
        }
        Ok(out)
    }

    /// Retracts a typed expression preference claim and restores its direct predecessor.
    pub fn retract_expression_preference(
        &self,
        _actor: &crate::write_envelope::WriteActor,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let (head, _) = self.claim_for_lifecycle_in(&wtxn, claim_id)?;
        if !is_expression_preference_predicate(&head.predicate) {
            return Err(Error::InvalidClaimBody(
                "claim is not an expression preference",
            ));
        }

        let prefix = edge_kind_prefix(claim_id, EdgeKind::Supersedes);
        let mut predecessors = Vec::new();
        for entry in self.store.edges_out.prefix_iter(&wtxn, &prefix)? {
            if predecessors.len() >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("expression preference predecessors"));
            }
            let (key, _) = entry?;
            require_key_len(
                &key,
                ENTITY_ID_LEN + 1 + ENTITY_ID_LEN,
                "supersedes edge key",
            )?;
            let id = EntityId::from_bytes(
                key[ENTITY_ID_LEN + 1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?;
            predecessors.push(id);
        }

        self.retract_claim_in_txn(&mut wtxn, claim_id, now)?;
        let mut ops = Vec::new();
        for id in predecessors {
            let (mut body, header) = self.claim_for_lifecycle_in(&wtxn, &id)?;
            if body.subject != head.subject
                || body.predicate != head.predicate
                || body.lifecycle != ClaimLifecycleStatus::Superseded
            {
                continue;
            }
            body.lifecycle = ClaimLifecycleStatus::Active;
            body.valid_to = None;
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: now,
                },
                learned_at: header.learned_at,
                data: encode_claim_body(&body)?,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
        }
        if !ops.is_empty() {
            apply_ops_with_gate_mode(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                ApplyOpsGateMode::new(false, false),
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Writes a typed CLAIM (type 0) entity with full structural validation
    /// (D11 key set, D17 predicate gate, D18 fail-closed body validation).
    ///
    /// `occurred` and `learned_at` are caller-supplied, exactly like
    /// [`Vault::put_entity`] — the valid_from/to ↔ envelope sentinel mapping
    /// (D15) is the provenance unit's concern, not this method's.
    ///
    /// For an entity subject ([`ClaimSubject::Entity`]) this also writes the
    /// `claim_of` edge (u8 = 5, structural 12 B) Claim → subject in the SAME
    /// write transaction, and rejects with [`Error::EntityNotFound`] if the
    /// subject entity does not exist — nothing is written on rejection. An
    /// EdgeRef subject ([`ClaimSubject::Edge`]) is shape-validated only; its
    /// `claim_of` wiring belongs to the provenance path. Reserved namespaces
    /// are writable only through crate-private owner doors.
    pub fn put_claim(
        &self,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.put_claim_in_txn(&mut wtxn, id, body, occurred, learned_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Transaction-composable [`Vault::put_claim`]. The caller owns commit;
    /// the CLAIM body and its `claim_of` edge are applied to the same `wtxn`.
    pub(crate) fn put_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.put_claim_in_txn_with_reserved(wtxn, id, body, occurred, learned_at, false)
    }

    /// Crate-private transaction-composable door for ENGINE-OWNED Claims:
    /// the reserved namespaces, and the family doors that own their
    /// predicate's decision outright (ONE-1746's `assert_distinct`, whose
    /// ARCH-0055 r3 consent axis rides the op itself). Both skip the
    /// public write gate's criticality ladder — the owning door already
    /// decided — and keep the source-trust check. This is intentionally not
    /// part of the public [`Vault`] API.
    pub(crate) fn put_reserved_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.put_claim_in_txn_with_reserved(wtxn, id, body, occurred, learned_at, true)
    }

    fn put_claim_in_txn_with_reserved(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
        allow_reserved_predicate: bool,
    ) -> Result<()> {
        let data = encode_claim_body(body)?;
        // Full structural validation runs here and again at the BatchOp write
        // chokepoint with the exact same reserved-door setting.
        validate_claim_body_bytes(&data, allow_reserved_predicate)?;

        let mut ops = vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate,
            hub_sync_imported: false,
        }];

        if let ClaimSubject::Entity(subject) = body.subject {
            if self.store.entities.get(wtxn, subject.as_bytes())?.is_none() {
                return Err(Error::EntityNotFound);
            }
            ops.push(BatchOp::Edge {
                src: *id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    pub(crate) fn put_claim_candidate_without_lexical_query_reconcile(
        &self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::ClaimCandidate {
                id: *id,
                candidate: Box::new(candidate),
                envelope: envelope.clone(),
                occurred,
                learned_at,
                internal_lexical_query_hint: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, true).with_source_in_gate_input(),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "code-run write trap commits both typed gate checks and transition atomically"
    )]
    pub(crate) fn supersede_claim_for_code_run_trap(
        &self,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
        envelope: &WriteEnvelope,
        claim_gate_id: EntityId,
        claim_gate_body: &ClaimBody,
        edge_gate_id: EntityId,
        edge_gate_body: &ClaimBody,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let mut wtxn = self.store.env.write_txn()?;
        self.validate_code_run_write_actor_binding_in_txn(&wtxn, envelope)?;
        // The write-verb guard runs BEFORE the gate checks, because those
        // deliberately COMMIT their decision receipts on rejection. A stale
        // target is not a policy question the gate ever gets to answer, and a
        // rejected code-run supersession must leave no receipt behind.
        let (mut old_body, old_header) = self.guarded_claim_target_parts_in(&wtxn, old_id)?;

        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        if let Err(err) = self.check_code_run_write_gate_in_txn(
            &mut wtxn,
            claim_gate_id,
            claim_gate_body,
            envelope,
            &policy,
            false,
        ) {
            wtxn.commit()?;
            return Err(err);
        }
        if let Err(err) = self.check_code_run_write_gate_in_txn(
            &mut wtxn,
            edge_gate_id,
            edge_gate_body,
            envelope,
            &policy,
            false,
        ) {
            wtxn.commit()?;
            return Err(err);
        }

        let (new_body, _new_header) = self.claim_for_lifecycle_in(&wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![
                BatchOp::Put {
                    id: *old_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: old_header.occurred_start,
                        end: now,
                    },
                    learned_at: old_header.learned_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: *new_id,
                    kind: EdgeKind::Supersedes,
                    tgt: *old_id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, false),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "code-run edge trap carries gate material plus edge tuple"
    )]
    pub(crate) fn put_edge_for_code_run_trap(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        envelope: &WriteEnvelope,
        gate_id: EntityId,
        gate_body: &ClaimBody,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.validate_code_run_write_actor_binding_in_txn(&wtxn, envelope)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        if let Err(err) = self.check_code_run_write_gate_in_txn(
            &mut wtxn, gate_id, gate_body, envelope, &policy, false,
        ) {
            wtxn.commit()?;
            return Err(err);
        }

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::Edge {
                src: *src,
                kind,
                tgt: *tgt,
                weight,
                vad: Vad::NEUTRAL,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn validate_code_run_write_actor_binding_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        envelope: &WriteEnvelope,
    ) -> Result<()> {
        crate::gate::validate_write_envelope(envelope)?;
        let actor = envelope.actor();
        let actor_raw = self
            .store
            .entities
            .get(wtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        validate_actor_class(actor_header.entity_type, actor.actor_class())
    }

    fn check_code_run_write_gate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
        policy: &crate::gate::PolicyManifestResolution,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        crate::gate::check_claim_policy_for_write(
            &self.store,
            wtxn,
            &id,
            body,
            Some(envelope),
            policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent,
                include_source_in_gate_input: true,
            },
        )
    }

    /// Retrieves and decodes a CLAIM (type 0) entity body.
    ///
    /// Returns `Ok(None)` when no entity exists under `id`, and a typed
    /// [`Error::InvalidClaimBody`] when the stored entity is not a type-0
    /// CLAIM or its body fails the pinned structural validation. The read
    /// path allows reserved `edge.*` predicates so stored provenance Claims
    /// stay decodable.
    ///
    /// DELIBERATELY UNGATED (D19): unlike the retrieval read paths
    /// (pipeline / context pack), this targeted read returns claims of
    /// EVERY `appr`/`life`/`stale` status — it is the history and
    /// consent-review door ("all non-current states are still stored",
    /// ARCH-0003), and the edge-provenance lifecycle readers likewise must
    /// see closed Claims to compute winner stamps.
    pub fn get_claim(&self, id: &EntityId) -> Result<Option<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_claim_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::get_claim`]: reads and decodes a CLAIM
    /// body through the caller's txn (so it composes inside a write txn, where a
    /// nested read txn would be illegal).
    pub(crate) fn get_claim_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
    }

    pub(crate) fn session_claim_bundle_members_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<Vec<SessionClaimBundleMember>> {
        validate_session_tag(session_tag)?;

        let mut members = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_CLAIM])?
        {
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("claim type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("claim type index"));
            }
            let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.session_tag.as_deref() != Some(session_tag)
                || session_claim_producer(&body).as_ref() != Some(expected_producer)
                || body.approval != ClaimApprovalStatus::Proposed
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            members.push(SessionClaimBundleMember {
                id,
                body,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                learned_at: header.learned_at,
            });
        }
        Ok(members)
    }

    /// Returns the CLAIM entity ids attached to `subject` via inbound
    /// `claim_of` edges — a thin wrapper over
    /// `sources(subject, EdgeKind::ClaimOf, Some(ENTITY_TYPE_CLAIM))`.
    pub fn claims_for_subject(&self, subject: &EntityId) -> Result<Vec<EntityId>> {
        self.sources(subject, EdgeKind::ClaimOf, Some(ENTITY_TYPE_CLAIM))
    }

    /// Transaction-composable [`Vault::claims_for_subject`]: resolves inbound
    /// `claim_of` edges through the caller's txn.
    pub(crate) fn claims_for_subject_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
    ) -> Result<Vec<EntityId>> {
        self.filtered_edge_peers(
            rtxn,
            &self.store.edges_in,
            subject,
            EdgeKind::ClaimOf,
            Some(ENTITY_TYPE_CLAIM),
            "claims for subject",
        )
    }

    /// Every stored CLAIM carrying `predicate`, resolved by scanning the type-0
    /// index — reserved predicates included.
    ///
    /// The read door for engine-authored evidence that has no secondary index
    /// of its own. A local index would be WRITE-side state: a claim that
    /// arrived by replication materializes its entity and its `claim_of` edge
    /// but no local index row, so an index-backed reader and a claim-backed
    /// reader answer differently on a replica. This scan is the one read path
    /// both can share.
    pub(crate) fn claims_with_predicate_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut rows = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_CLAIM])?
        {
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("claim type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("claim type index"));
            }
            let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate == predicate {
                rows.push((id, body));
            }
        }
        Ok(rows)
    }

    pub(crate) fn claim_bodies_for_subjects_matching(
        &self,
        subjects: &[EntityId],
        mut matches: impl FnMut(&ClaimBody, &EntityId) -> bool,
    ) -> Result<Vec<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        let mut claims = Vec::new();
        for subject in subjects {
            let prefix = edge_kind_prefix(subject, EdgeKind::ClaimOf);
            for (scanned, entry) in self.store.edges_in.prefix_iter(&rtxn, &prefix)?.enumerate() {
                if scanned >= MAX_EDGE_QUERY_RESULTS {
                    return Err(Error::IndexOverflow("claim_bodies_for_subjects"));
                }
                let (key, value) = entry?;
                let claim_id = parse_edge_record(&key, &value)?.target;
                let Some(raw) = self.store.entities.get(&rtxn, claim_id.as_bytes())? else {
                    continue;
                };
                let Some(header) = EntityMetadataHeader::parse(&raw) else {
                    continue;
                };
                if header.entity_type != ENTITY_TYPE_CLAIM {
                    continue;
                }
                let body =
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                if matches(&body, subject) {
                    claims.push(body);
                }
            }
        }
        Ok(claims)
    }

    /// Reads, decodes, and gates a claim for a generic lifecycle transition
    /// (`supersede_claim` / `retract_claim`). Fail-closed:
    ///
    /// * no entity under `id` → [`Error::EntityNotFound`];
    /// * entity is not type 0 → [`Error::InvalidClaimBody`];
    /// * any reserved predicate → [`Error::ProvenanceClaimLifecycle`]. Edge
    ///   provenance drives derived hot flags and skill claims are owned by the
    ///   skill-hub doors; generic lifecycle operations never delegate either
    ///   class of reserved record.
    fn claim_for_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if is_reserved_predicate(&body.predicate) {
            return Err(Error::ProvenanceClaimLifecycle {
                predicate: body.predicate,
            });
        }
        Ok((body, header))
    }

    /// Reads a Claim for the reserved lifecycle door. Only the engine-driven
    /// namespaces (`skill.*`, `actor.*`) are admitted: `edge.*` remains
    /// exclusively owned by edge provenance and receives the same typed
    /// rejection as the generic lifecycle API.
    fn reserved_claim_for_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if is_edge_reserved_predicate(&body.predicate) {
            return Err(Error::ProvenanceClaimLifecycle {
                predicate: body.predicate,
            });
        }
        if !is_engine_owned_reserved_predicate(&body.predicate) {
            return Err(Error::InvalidClaimBody(
                "reserved claim lifecycle door only admits skill and actor predicates",
            ));
        }
        Ok((body, header))
    }

    /// Gates a lifecycle transition on the claim still being open: any
    /// non-`active` `life` status is closed history and rejects with
    /// [`Error::ClaimAlreadyClosed`] (ARCH-0003: superseded carries history,
    /// retracted is a deliberate withdrawal — never edited again).
    fn require_active_claim(body: &ClaimBody) -> Result<()> {
        if body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::ClaimAlreadyClosed {
                status: body.lifecycle,
            });
        }
        Ok(())
    }

    /// The write-verb validity guard (ONE-1936): grounds `target` inside the
    /// CALLER'S transaction and returns its body only while it is still the
    /// head of its lifecycle chain.
    ///
    /// The claim id a verb NAMES is its version token — there is no
    /// generation counter, ETag, or revision integer to compare, and this
    /// guard adds none. A target whose `life` has moved off `active` is a
    /// decision made against a replaced view, so it fails with
    /// [`Error::WriteVerbTargetStale`] carrying the terminal head's public
    /// `short_id:content_hash` ref (see
    /// [`Self::successor_chain_head_short_ref_in`]). The caller reads that ref
    /// and issues a NEW decision: the engine never retargets the verb, never
    /// rewrites the caller's ref, and never downgrades to a warning.
    ///
    /// Composing INSIDE the caller's transaction is the whole point. A read
    /// check followed by a second transaction for the mutation would recreate
    /// the grounding-read race this guard closes.
    pub fn require_named_claim_target_active_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<ClaimBody> {
        self.guarded_claim_target_parts_in(rtxn, target)
            .map(|(body, _header)| body)
    }

    /// [`Self::require_named_claim_target_active_in`] keeping the envelope
    /// header, which the in-engine chokepoints need for the closing re-put.
    /// One grounded read serves both the guard and the mutation.
    fn guarded_claim_target_parts_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let (body, header) = self.claim_for_lifecycle_in(rtxn, target)?;
        if body.lifecycle == ClaimLifecycleStatus::Active {
            return Ok((body, header));
        }
        Err(Error::WriteVerbTargetStale {
            target: *target,
            lifecycle: body.lifecycle,
            successor_short_id: self.successor_chain_head_short_ref_in(rtxn, target)?,
        })
    }

    /// [`Self::require_named_claim_target_active_in`] on its own read
    /// transaction — the door for callers that only need to REPORT the stale
    /// condition (an MCP dry run), never for one that goes on to write.
    /// A writer must pass its own transaction so guard and mutation stay
    /// atomic.
    pub fn require_named_claim_target_active(&self, target: &EntityId) -> Result<ClaimBody> {
        let rtxn = self.store.env.read_txn()?;
        self.require_named_claim_target_active_in(&rtxn, target)
    }

    /// Walks the supersession chain from `target` to its unique terminal head
    /// and returns that head's public `short_id:content_hash` ref.
    ///
    /// The stored edge direction is `new_claim ─Supersedes→ old_claim`, so
    /// "newer" is found by following INBOUND `Supersedes` sources. A directly
    /// retracted claim has no newer entity at all: its terminal head is
    /// itself, and the returned ref is its own. Self-reporting is exclusive to
    /// that end state — a SUPERSEDED node with no successor is a missing
    /// supersedes row, not a head.
    ///
    /// Fail-closed at every step — a stale-target report that guessed would be
    /// worse than no report. A cycle, a branch (more than one successor at any
    /// hop, which would mean more than one terminal head), a dangling edge, a
    /// non-CLAIM node, a body that will not decode, a superseded node whose
    /// successor row is gone, or a missing `short_ids_reverse` row all return
    /// typed errors. The successor is never chosen by iteration order, and the
    /// ref is never a hex fallback: a hex id is not resolvable at the public
    /// short-ref doors, so emitting one would hand the caller a token it
    /// cannot re-get with.
    fn successor_chain_head_short_ref_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<String> {
        let mut head = *target;
        let mut visited = HashSet::from([head]);
        for _ in 0..MAX_SUPERSESSION_CHAIN_WALK {
            let next = match self.supersession_successors_in(rtxn, &head)?.as_slice() {
                // Nothing newer. Only a node that ENDED its own lifecycle can
                // be its own terminal head: a retracted claim was withdrawn
                // rather than replaced, and an active claim is the live head.
                // A SUPERSEDED node with no successor means the row recording
                // its replacement is gone (a deleted successor takes both
                // incident edges with it), so there is no head to name —
                // answering with the node's own ref would hand the caller back
                // the very token it already knows is stale.
                [] => return self.terminal_head_short_ref_in(rtxn, &head),
                [only] => *only,
                // Two successors mean two terminal heads. There is no
                // principled choice between them, so the walk refuses rather
                // than taking whichever the index yielded first.
                _ => {
                    return Err(Error::InvariantViolation(
                        "supersession chain branches: a claim has more than one superseding successor",
                    ));
                }
            };
            if !visited.insert(next) {
                return Err(Error::CycleDetected);
            }
            head = next;
        }
        Err(Error::IndexOverflow("supersession chain walk"))
    }

    /// The public ref of a chain node that has no successor — but only when
    /// its own lifecycle says it is genuinely terminal (active = the live
    /// head, retracted = withdrawn, never replaced). A superseded node without
    /// a successor fails closed: its supersedes row is missing, and the
    /// alternative is reporting the stale target as its own successor.
    fn terminal_head_short_ref_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        head: &EntityId,
    ) -> Result<String> {
        if self.chain_node_lifecycle_in(rtxn, head)? == ClaimLifecycleStatus::Superseded {
            return Err(Error::InvariantViolation(
                "superseded claim has no superseding successor: the supersedes row is missing",
            ));
        }
        self.claim_short_ref_in(rtxn, head)
    }

    /// The `life` of one grounded supersession-chain node, under the same
    /// grounding rules as [`Self::supersession_successors_in`]: a missing row,
    /// a non-CLAIM node, or an undecodable body is corruption, never a skip.
    fn chain_node_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<ClaimLifecycleStatus> {
        let raw = self
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("supersession chain node"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody(
                "supersession chain node is not a type-0 CLAIM",
            ));
        }
        Ok(decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?.lifecycle)
    }

    /// The CLAIM entities that supersede `id`, resolved through the inbound
    /// `Supersedes` index. Every candidate is grounded — a dangling edge, a
    /// non-CLAIM node, or an undecodable body is corruption, never a skip.
    fn supersession_successors_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let prefix = edge_kind_prefix(id, EdgeKind::Supersedes);
        let mut successors = Vec::new();
        for entry in self.store.edges_in.prefix_iter(rtxn, &prefix)? {
            if successors.len() >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("supersedes successors"));
            }
            let (key, _) = entry?;
            require_key_len(
                &key,
                ENTITY_ID_LEN + 1 + ENTITY_ID_LEN,
                "supersedes edge key",
            )?;
            let successor = EntityId::from_bytes(
                key[ENTITY_ID_LEN + 1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?;
            let raw = self
                .store
                .entities
                .get(rtxn, successor.as_bytes())?
                .ok_or(Error::CorruptedIndex("supersedes edge without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::InvalidClaimBody(
                    "supersession chain node is not a type-0 CLAIM",
                ));
            }
            decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            successors.push(successor);
        }
        Ok(successors)
    }

    /// The public `short_id:content_hash` ref of a stored claim, read from the
    /// entity-id-keyed `short_ids_reverse` row (ARCH-0019 row n4). A missing
    /// row fails closed: the ref exists to be re-got with, so half a ref is no
    /// ref.
    pub(crate) fn claim_short_ref_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<String> {
        let raw = self
            .store
            .short_ids_reverse
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("claim short id reverse row"))?;
        let (short_id, content_hash) = crate::batch::parse_short_id_value(&raw)?;
        Ok(format!("{short_id}:{content_hash:02x}"))
    }

    /// Blocks generated-origin claims from superseding protected user truth.
    /// New generated code-revision claims are rejected first so they keep the
    /// fail-closed code-revision diagnostic; otherwise old code-revision truth
    /// gets its own diagnostic, and non-code user/legacy truth uses the
    /// general claim-body error. Missing old `src` is protected as legacy
    /// user truth for this guard.
    fn require_source_trust_supersession_rights(
        new_body: &ClaimBody,
        old_body: &ClaimBody,
    ) -> Result<()> {
        let old_is_protected_user_truth =
            matches!(old_body.source, None | Some(ClaimSource::UserStated));
        if !claim_generated_origin(new_body) || !old_is_protected_user_truth {
            return Ok(());
        }
        if new_body.predicate == crate::code_revision::CODE_REVISION_CLAIM_PREDICATE {
            return Err(Error::InvalidCodeArtifactBody(
                "generated code revision claim cannot supersede user-stated truth",
            ));
        }
        if old_body.predicate == crate::code_revision::CODE_REVISION_CLAIM_PREDICATE {
            return Err(Error::InvalidCodeArtifactBody(
                "generated claim cannot supersede user-stated code revision truth",
            ));
        }
        Err(Error::InvalidClaimBody(
            "generated claim cannot supersede user-stated truth",
        ))
    }

    /// Supersedes the active claim `old_id` with the claim `new_id` — the
    /// general ARCH-0003 claim lifecycle mechanics, in ONE write
    /// transaction:
    ///
    /// * the old claim's body is closed: `life` = `superseded`, `to` = `now`;
    /// * the old claim's envelope `occurred_end` is refreshed to `now` (the
    ///   envelope copy mirrors the body's validity window for temporal
    ///   index-key derivation, per the D15 principle);
    /// * a `supersedes` edge (u8 = 3, structural 12 B, weight 0.3) is
    ///   written `new_id` → `old_id` — the edge is canonical; no
    ///   `supersedesId` body field is stored (D11).
    ///
    /// The old claim is KEPT fully readable: superseded carries history —
    /// "all non-current states are still stored — claims are never silently
    /// deleted" (ARCH-0003). Fail-closed, nothing written on any rejection:
    ///
    /// * `new_id == old_id` → [`Error::ClaimSelfSupersession`];
    /// * either id missing → [`Error::EntityNotFound`]; either entity not
    ///   type 0 → [`Error::InvalidClaimBody`];
    /// * either claim carrying a reserved predicate →
    ///   [`Error::ProvenanceClaimLifecycle`] (its crate-private owner door
    ///   owns that lifecycle; see `Vault::claim_for_lifecycle_in`);
    /// * either claim's `life` ≠ `active` → [`Error::ClaimAlreadyClosed`]
    ///   (closed claims neither supersede nor get superseded again).
    ///
    /// Deciding WHICH claims conflict (conflictSet), consent routing, and
    /// predicate semantics stay above the engine (ARCH-0003 §G.1, D20) —
    /// this method is transition mechanics only.
    pub fn supersede_claim(&self, new_id: &EntityId, old_id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.supersede_claim_in_txn(&mut wtxn, new_id, old_id, now)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Supersedes `old_id` with `new_id` INSIDE the caller's write
    /// transaction, running the same fail-closed guards as
    /// [`Vault::supersede_claim`] (self-supersession, type-0 / reserved
    /// predicate, both-`active`, source-trust) but composing into an existing
    /// txn instead of opening its own. A caller that first writes the
    /// replacement head and then supersedes the old head in one `wtxn` commits
    /// or rolls back BOTH together, so a rejected supersession never leaves a
    /// torn two-`active`-heads window. `new_id` must already have been written
    /// into the same `wtxn` before this is called.
    pub(crate) fn supersede_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let (new_body, _new_header) = self.claim_for_lifecycle_in(&*wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        // The NAMED target: stale here means the caller decided against a view
        // the store has replaced, and the guard runs in the caller's txn so a
        // replacement staged earlier in the same txn rolls back with it.
        let (mut old_body, old_header) = self.guarded_claim_target_parts_in(&*wtxn, old_id)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        let ops = vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now.max(old_header.occurred_start),
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: EdgeKind::Supersedes,
                tgt: *old_id,
                weight: SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }

    /// Supersedes an engine-owned `skill.*` / `actor.*` Claim inside the
    /// caller's write transaction. This crate-private door deliberately
    /// continues to reject `edge.*`, whose lifecycle must re-stamp
    /// provenance-derived edge state.
    pub(crate) fn supersede_reserved_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let (new_body, _new_header) = self.reserved_claim_for_lifecycle_in(&*wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        let (mut old_body, old_header) = self.reserved_claim_for_lifecycle_in(&*wtxn, old_id)?;
        Self::require_active_claim(&old_body)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        let ops = vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now,
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: EdgeKind::Supersedes,
                tgt: *old_id,
                weight: SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }

    /// Retracts the active claim `id` — a deliberate withdrawal (ARCH-0003
    /// general claim lifecycle), in ONE write transaction: the body is
    /// closed (`life` = `retracted`, `to` = `now`) and the envelope
    /// `occurred_end` is refreshed to `now` (body ↔ envelope mirror, D15
    /// principle). A parked consent is atomically closed with a terminal
    /// retraction receipt while preserving the consent's original binding.
    /// The record is PRESERVED — retraction never deletes.
    ///
    /// Fail-closed, nothing written on any rejection: missing id →
    /// [`Error::EntityNotFound`]; not type 0 → [`Error::InvalidClaimBody`];
    /// any reserved predicate → [`Error::ProvenanceClaimLifecycle`];
    /// `life` ≠ `active` → [`Error::ClaimAlreadyClosed`]. There is
    /// Public callers intentionally have no reserved retract door: skill-hub
    /// lifecycle is owned by a crate-private door, while edge provenance owns
    /// its retraction mechanics.
    pub fn retract_claim(&self, id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.retract_claim_in_txn(&mut wtxn, id, now)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Transaction-composable [`Vault::retract_claim`]. A pending consent is
    /// closed before the lifecycle write, in the same transaction, so a later
    /// gate or storage failure rolls both changes back. Pending persistence is
    /// disabled for the terminal body write: a policy that evaluates the
    /// retracted body as `pending` must not recreate an actionable tray row.
    /// The caller owns commit/abort; facade callers compose actor binding and
    /// authorship authorization into this same transaction.
    pub(crate) fn retract_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        now: u64,
    ) -> Result<Option<GateDecisionRecord>> {
        // The NAMED target, guarded before the pending-consent closure and the
        // gate receipt below: a stale retract must leave the consent row and
        // every receipt exactly as it found them.
        let (mut body, header) = self.guarded_claim_target_parts_in(&*wtxn, id)?;

        let consent_receipt = self.store.close_pending_gate_consent_in_txn(
            wtxn,
            id,
            now,
            "retracted",
            vec!["gate.pending.claim_retracted".to_owned()],
            None,
        )?;
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(now);
        let data = encode_claim_body(&body)?;

        let mut write_receipt = None;
        if consent_receipt.is_none() {
            let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
            crate::gate::check_claim_policy_for_write_with_record(
                &self.store,
                wtxn,
                id,
                crate::gate::ClaimGateWrite {
                    body: &body,
                    envelope: None,
                    defer_metrics_until_commit: false,
                },
                &policy,
                crate::gate::GateWriteMode {
                    record_decision: true,
                    persist_pending_consent: false,
                    resolve_pending: true,
                    can_resolve_pending_consent: true,
                    include_source_in_gate_input: false,
                },
                &mut write_receipt,
            )?;
        }

        let ops = vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: now.max(header.occurred_start),
            },
            learned_at: header.learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        )?;
        Ok(consent_receipt
            .or(write_receipt.map(super::gate::RecordedClaimGateDecision::into_record)))
    }

    pub(crate) fn claim_facet_refs_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut prefix = [0_u8; ENTITY_ID_LEN + 1];
        prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
        prefix[ENTITY_ID_LEN] = EdgeKind::FacetOf as u8;

        let mut facets = Vec::new();
        for entry in self.store.edges_out.prefix_iter(rtxn, prefix.as_slice())? {
            if facets.len() >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_facet_refs"));
            }
            let (key, _) = entry?;
            require_key_len(&key, ENTITY_ID_LEN + 1 + ENTITY_ID_LEN, "facet edge key")?;
            let target = EntityId::from_bytes(
                key[ENTITY_ID_LEN + 1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("facet edge key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("facet edge key"))?;
            facets.push(target);
        }
        Ok(facets)
    }
}

/// Reads the immutable writer identity already stamped by `WriteEnvelope`
/// into candidate evidence. Missing, duplicate, malformed, or reserved actor
/// refs fail closed by returning no producer match.
pub(crate) fn session_claim_producer(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    let mut producer = None;
    for (key, value) in entries {
        if key.as_str() != Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
            continue;
        }
        if producer.is_some() {
            return None;
        }
        let Value::Binary(bytes) = value else {
            return None;
        };
        let actor_bytes: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
        producer = Some(EntityId::from_bytes(actor_bytes).ok()?);
    }
    producer
}

#[cfg(test)]
mod tests;
