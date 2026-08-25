//! The policy-gated read lane: [`ScopedReadActorKey`], [`ScopedRead`], and the
//! admission/filtering surface that layers `crate::gate` scoped-read grants on
//! top of the claim surfaceability gate.

use std::{collections::HashSet, sync::Mutex};

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_pack::{ContextEntity, ContextPack, EmptyContext, EmptyReason};
use crate::deletion::{MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState};
use crate::edge::{EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::PolicyManifestResolution;
use crate::pipeline::ScoredEntity;
use crate::registry::ENTITY_TYPE_CLAIM;

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

    /// The out-edge accessor this read composes over: the room's union when
    /// opened in-session, base otherwise. Mirrors [`Self::entities`] — an edge
    /// staged in the room joins two entities the room can already see, so a
    /// base-only edge scan would drop it from `edges_out` and from every
    /// reachability sweep built on it.
    fn edges_out_db(&self) -> &crate::overlay_db::OverlayDb {
        match self.session_view {
            Some(view) => &view.edges_out,
            None => &self.vault.store.edges_out,
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
        let claim_facets = self.claim_facet_refs_in(rtxn, id)?;
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

    /// The claim's `FacetOf` targets, read through the same accessor as every
    /// other edge scan in this type.
    ///
    /// A facet-scoped `core:read` grant matches on the facets a claim carries,
    /// so those facets ARE the grant's subject matter. Scanning base
    /// `edges_out` directly is right for the canonical handle and wrong inside
    /// a session: a `FacetOf` edge staged in the room would not authorize, and
    /// one the room tombstoned would go on authorizing — the session's own
    /// view of who may read what, decided against a graph that is not the
    /// session's.
    ///
    /// Composes exactly as [`Self::edges_out_in`] does, over
    /// [`Self::edges_out_db`]. Base-only on the canonical handle, so nothing
    /// outside a session changes.
    fn claim_facet_refs_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
        crate::claim::read::facet_refs_in_db(self.edges_out_db(), rtxn, id)
    }

    fn edges_out_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<EdgeInfo>> {
        const MAX_SCOPED_READ_EDGE_REACHABILITY_ROWS: usize = 100_000;

        let mut edges = Vec::new();
        for entry in self.edges_out_db().prefix_iter(rtxn, id.as_bytes())? {
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
