//! The policy-gated read lane: [`ScopedReadActorKey`], [`ScopedRead`], and the
//! admission/filtering surface that layers `crate::gate` scoped-read grants on
//! top of the claim surfaceability gate.

mod lifecycle;

use std::{collections::HashSet, sync::Mutex};

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_pack::{ContextEntity, ContextPack, EmptyContext, EmptyReason};
use crate::edge::{EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalFilter};
use crate::pipeline::ScoredEntity;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead, PortRows};
use crate::registry::ENTITY_TYPE_CLAIM;

mod graph_reads;
mod note_visibility;
mod pinned_reads;
mod point_reads;
mod receipt;
mod retrieval_visibility;
mod versions;
pub use receipt::{ReadScope, ScopedReadReceipt, ScopedReadResult};

mod access_gate;
mod actor_key;
pub use actor_key::ScopedReadActorKey;

/// Actor-keyed read lane for the core read surface.
///
/// All methods preserve the existing claim surface admission gate and
/// then layer policy scoped-grant matching for type-0 CLAIM entities.
pub struct ScopedRead<'a> {
    vault: &'a crate::vault::Vault,
    actor_key: ScopedReadActorKey,
    audience: Option<Vec<EntityId>>,
    audience_cache: Mutex<crate::conversation::AudienceCache>,
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
            audience: None,
            audience_cache: Mutex::new(Default::default()),
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
            audience: None,
            audience_cache: Mutex::new(Default::default()),
            session_view: Some(view),
        }
    }
}

impl<'a> ScopedRead<'a> {
    /// Conjoin every read with the all-of-audience rule. An explicit empty
    /// audience refuses audience-scoped records rather than widening to speaker-only reads.
    #[must_use]
    pub fn for_audience(mut self, audience: &[EntityId]) -> Self {
        let mut ids = audience.to_vec();
        ids.sort_unstable();
        ids.dedup();
        self.audience = Some(ids);
        self
    }

    /// Number of immutable room ledger snapshots loaded by this read handle.
    pub fn audience_ledger_reads(&self) -> Result<usize> {
        Ok(self
            .audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .ledger_reads())
    }

    fn audience_readable_in(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let Some(audience) = &self.audience else {
            return Ok(true);
        };
        self.audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .readable(self.vault, txn, *id, audience)
    }

    #[must_use]
    pub fn vault(&self) -> &'a crate::Vault {
        self.vault
    }

    /// Both canonical and session reads use the same ports. A session adapter
    /// composes overlay union base without changing policy admission.
    fn entity_record_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityRecord>> {
        match self.session_view {
            Some(view) => view.port_entity_record(txn, id),
            None => self.vault.port_entity_record(txn, id),
        }
    }

    fn out_edges_in<'t>(
        &self,
        txn: &'t heed::RoTxn<'_>,
        id: &EntityId,
        kind: Option<EdgeKind>,
    ) -> Result<PortRows<'t, EdgeInfo>> {
        match self.session_view {
            Some(view) => view.port_edges(txn, id, EdgeDirection::Out, kind, None),
            None => self
                .vault
                .port_edges(txn, id, EdgeDirection::Out, kind, None),
        }
    }

    #[must_use]
    pub fn actor_key(&self) -> &ScopedReadActorKey {
        &self.actor_key
    }

    /// Searches within this actor's resolved read authority. Unset means the floor.
    pub fn search(
        &self,
        query: &str,
        vector: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let (filter, policy) = self.resolve_retrieval_filter(requested)?;
        if filter.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(requested, &policy, &filter, 0),
            });
        }
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, true, true)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .search(query, vector, None, fetch_limit)
            .run_for_pack()?;
        self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed,
            &results.revisions,
        )
    }

    pub fn search_text(
        &self,
        query: &str,
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let result = self.search_text_revisioned(query, limit, requested)?;
        Ok(ScopedReadResult {
            value: result.hits,
            receipt: result.receipt,
        })
    }

    pub fn search_vector(
        &self,
        query: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let result = self.search_vector_revisioned(query, limit, requested)?;
        Ok(ScopedReadResult {
            value: result.hits,
            receipt: result.receipt,
        })
    }

    fn resolve_retrieval_filter(
        &self,
        requested: Option<&RetrievalFilter>,
    ) -> Result<(ResolvedRetrievalFilter, PolicyManifestResolution)> {
        let txn = self.vault.store.env.read_txn()?;
        self.resolve_retrieval_filter_in(&txn, requested)
    }

    fn resolve_retrieval_filter_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<(ResolvedRetrievalFilter, PolicyManifestResolution)> {
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
        let filter = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            requested,
        )?;
        Ok((filter, policy))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "final scoring admission conjoins plan authority, fresh authority and source frontiers"
    )]
    fn filter_search_results(
        &self,
        results: Vec<ScoredEntity>,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        filter: &ResolvedRetrievalFilter,
        policy: &PolicyManifestResolution,
        previously_suppressed: usize,
        revisions: &std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let txn = self.vault.store.env.read_txn()?;
        // The scoring txn may have completed before a revocation. The final
        // read must satisfy BOTH the plan authority and this fresh snapshot.
        let (fresh_filter, fresh_policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::new();
        let mut suppressed = 0;
        for result in results {
            if self.is_entity_retrievable_with_policy_in(&txn, policy, filter, &result.id)?
                && self.is_entity_retrievable_with_policy_in(
                    &txn,
                    &fresh_policy,
                    &fresh_filter,
                    &result.id,
                )?
                && match revisions.get(&result.id) {
                    Some(revision) => {
                        let mode = crate::vault::ReadMode::Pinned(*revision);
                        self.entity_raw_with_mode_in(&txn, policy, filter, &result.id, mode)?
                            .is_some()
                            && self
                                .entity_raw_with_mode_in(
                                    &txn,
                                    &fresh_policy,
                                    &fresh_filter,
                                    &result.id,
                                    mode,
                                )?
                                .is_some()
                    }
                    None => true,
                }
            {
                if value.len() < limit {
                    value.push(result);
                }
            } else if self.entity_record_in(&txn, &result.id)?.is_some() {
                suppressed += 1;
            }
        }
        let mut receipt = self.receipt_for(requested, policy, filter, previously_suppressed);
        receipt.restrict_with(&self.receipt_for(
            requested,
            &fresh_policy,
            &fresh_filter,
            suppressed,
        ));
        Ok(ScopedReadResult { value, receipt })
    }

    /// ONE-207: the effort-dialed read.
    ///
    /// The ONE door a depth request enters this lane through, and deliberately
    /// a THIN one: `retrieval_depth` owns the tier policy, the caps and the
    /// deep-lease rule, while every channel it runs comes back through the
    /// three search doors above and through
    /// `crate::ppr::PprNodeVisibility`, which conjoins
    /// `Self::is_entity_readable_with_policy_in` with the resolved retrieval
    /// floor so graph expansion cannot bypass the direct-search constraints.
    ///
    /// So the effort dial cannot widen admission. It changes how many
    /// admitted channels run, never which entities an admitted channel is
    /// allowed to return, and the deep tier's host-proposed queries are
    /// ordinary text searches on this same lane rather than a second read
    /// path that would need its own gate.
    ///
    /// Errors retain actual reported spend; settle it just as on success.
    pub fn search_with_effort(
        &self,
        request: &crate::retrieval_depth::DepthSearchRequest<'_>,
    ) -> crate::retrieval_depth::RetrievalResult<crate::retrieval_depth::DepthSearchResult> {
        crate::retrieval_depth::execute(self, request)
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
        if self.audience.is_none()
            && !diagnostics.loaded_manifest_forces_fail_closed()
            && !policy.has_scoped_read_grants()
        {
            return Ok(requested);
        }
        drop(rtxn);

        self.vault
            .scoped_read_search_candidate_limit(requested, include_text, include_vector)
    }

    pub fn filter_scored_entities(
        &self,
        results: Vec<ScoredEntity>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        self.filter_scored_entities_requested(results, None)
    }

    pub(crate) fn filter_scored_entities_requested(
        &self,
        results: Vec<ScoredEntity>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let before = results.len();
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(before);
        let mut suppressed = 0;
        for result in results {
            if self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &result.id)? {
                value.push(result);
            } else if self.entity_record_in(&txn, &result.id)?.is_some() {
                suppressed += 1;
            }
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult { value, receipt })
    }

    pub fn filter_context_pack(&self, pack: &mut ContextPack) -> Result<ScopedReadReceipt> {
        let rtxn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&rtxn, None)?;
        let had_l2_base = pack.l2_base.is_some();
        let mut auxiliary_suppressed = 0;
        if let Some(summary) = pack.l2_base.as_ref() {
            let visibility = self.retrieval_visibility_in(&rtxn, None)?;
            let mut admitted = true;
            for id in summary.evidence_ids() {
                if !crate::ppr::PprNodeVisibility::ppr_node_visible(&visibility, &rtxn, id)? {
                    admitted = false;
                    auxiliary_suppressed +=
                        usize::from(self.entity_record_in(&rtxn, id)?.is_some());
                    break;
                }
            }
            if !admitted {
                pack.l2_base = None;
            }
        }
        let had_capabilities = !pack.capabilities.is_empty();
        let mut capabilities = Vec::new();
        for hit in std::mem::take(&mut pack.capabilities) {
            if self.is_entity_retrievable_with_policy_in(&rtxn, &policy, &filter, &hit.id)?
                && let Some(current) =
                    crate::pipeline::capability_hit(&self.vault.store, &rtxn, hit.id)?
            {
                capabilities.push(current);
            } else if self.entity_record_in(&rtxn, &hit.id)?.is_some() {
                auxiliary_suppressed += 1;
            }
        }
        pack.capabilities = capabilities;
        let previously_suppressed = pack.stats.claims_suppressed;
        let previous_results = pack.results.len();
        let previous_count = previous_results + pack.neighbors.len();
        let (results, result_suppressed, result_rows_suppressed) = self.filter_context_entities(
            &rtxn,
            &policy,
            &filter,
            std::mem::take(&mut pack.results),
        )?;
        let (mut neighbors, neighbor_suppressed, neighbor_rows_suppressed) = self
            .filter_context_entities(
                &rtxn,
                &policy,
                &filter,
                std::mem::take(&mut pack.neighbors),
            )?;
        let readable_neighbors = neighbors.len();
        let reachability_suppressed = if results.len() < previous_results {
            self.retain_neighbors_reachable_from_results(&rtxn, &mut neighbors, &results)?
        } else {
            0
        };
        let suppressed = previously_suppressed
            .saturating_add(auxiliary_suppressed)
            .saturating_add(result_rows_suppressed)
            .saturating_add(neighbor_rows_suppressed)
            .saturating_add(readable_neighbors.saturating_sub(neighbors.len()));
        pack.results = results;
        pack.neighbors = neighbors;
        pack.stats.claims_suppressed +=
            result_suppressed + neighbor_suppressed + reachability_suppressed;

        if (previous_count > 0 || had_capabilities || had_l2_base)
            && pack.capabilities.is_empty()
            && pack.results.is_empty()
            && pack.neighbors.is_empty()
            && pack.l2_base.is_none()
        {
            pack.empty = Some(EmptyContext {
                retrieval_quality: pack.retrieval_quality.clone(),
                reason: EmptyReason::FilterMatchedNone,
                total_in_scope: 0,
                hint: "scoped_read returned no actor-readable entities".to_owned(),
            });
        }
        Ok(self.receipt_for(None, &policy, &filter, suppressed))
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
        let filter = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            None,
        )?;
        self.is_entity_retrievable_with_policy_in(rtxn, policy, &filter, id)
    }

    fn is_entity_readable_with_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        let Some(raw) = self.entity_record_in(rtxn, id)?.map(|row| row.encode()) else {
            return Ok(false);
        };
        self.is_entity_raw_readable_with_filter_in(rtxn, policy, id, &raw, filter)
    }

    fn is_entity_raw_readable_with_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if filter.deny_all
            || self
                .vault
                .store
                .validate_entity_type(header.entity_type)
                .is_err()
            || filter
                .entity_types
                .as_ref()
                .is_some_and(|types| !types.contains(&header.entity_type))
        {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        let deletion = match self.session_view {
            Some(view) => crate::ports::TombstoneStoreRead::port_deletion_state(view, rtxn, id)?,
            None => crate::ports::TombstoneStoreRead::port_deletion_state(self.vault, rtxn, id)?,
        };
        if deletion.deleted
            || deletion.stale
            || self.vault.archive_tombstone_in_txn(rtxn, id)?.is_some()
            || (raw.len() == ENTITY_METADATA_HEADER_LEN
                && self
                    .vault
                    .store
                    .entity_deletion_present_in_txn(rtxn, id, header.learned_at)?)
        {
            return Ok(false);
        }
        if !self.relationship_raw_allowed_in(
            rtxn,
            header.entity_type,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )? {
            return Ok(false);
        }
        if !self.audience_readable_in(rtxn, id)? {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
            return self.note_readable_in(rtxn, id, &raw[ENTITY_METADATA_HEADER_LEN..]);
        }
        if header.entity_type == ENTITY_TYPE_CLAIM {
            self.is_claim_raw_readable_with_policy_in(rtxn, policy, id, raw, filter)
        } else {
            Ok(true)
        }
    }

    pub(crate) fn is_claim_raw_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let (filter, policy) = self.resolve_retrieval_filter_in(rtxn, None)?;
        self.is_entity_raw_readable_with_filter_in(rtxn, &policy, id, raw, &filter)
    }

    fn is_claim_raw_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        if raw.len() == ENTITY_METADATA_HEADER_LEN
            && self.vault.store.entity_deletion_present_in_txn(
                rtxn,
                id,
                EntityMetadataHeader::parse(raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?
                    .learned_at,
            )?
        {
            return Ok(false);
        }
        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        self.is_claim_readable_with_body_and_policy_in(rtxn, policy, id, &body, filter)
    }

    fn is_claim_readable_with_body_and_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        body: &ClaimBody,
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        let admitted = crate::pipeline::retrieval_claim_allowed(filter, body);
        if !admitted
            || !self.audience_readable_in(rtxn, id)?
            || !self.relationship_claim_allowed_in(rtxn, body)?
        {
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
        filter: &ResolvedRetrievalFilter,
        entities: Vec<ContextEntity>,
    ) -> Result<(Vec<ContextEntity>, usize, usize)> {
        let mut kept = Vec::with_capacity(entities.len());
        let mut claims_suppressed = 0;
        let mut suppressed = 0;
        for mut entity in entities {
            if self.is_entity_retrievable_with_policy_in(rtxn, policy, filter, &entity.id)?
                && self.context_entity_revision_is_readable_in(rtxn, policy, filter, &entity)?
            {
                self.filter_context_entity_edges(rtxn, policy, filter, &mut entity)?;
                kept.push(entity);
            } else if self.entity_record_in(rtxn, &entity.id)?.is_some() {
                suppressed += 1;
                if entity.entity_type == ENTITY_TYPE_CLAIM {
                    claims_suppressed += 1;
                }
            }
        }
        Ok((kept, claims_suppressed, suppressed))
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
    /// Composes through the same session-aware edge port as reachability.
    fn claim_facet_refs_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
        let mut facets = Vec::new();
        for entry in self.out_edges_in(rtxn, id, Some(EdgeKind::FacetOf))? {
            if facets.len() >= crate::vault::MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_facet_refs"));
            }
            facets.push(entry?.target);
        }
        Ok(facets)
    }

    fn edges_out_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<EdgeInfo>> {
        const MAX_SCOPED_READ_EDGE_REACHABILITY_ROWS: usize = 100_000;

        let mut edges = Vec::new();
        for entry in self.out_edges_in(rtxn, id, None)? {
            let edge = entry?;
            if edges.len() >= MAX_SCOPED_READ_EDGE_REACHABILITY_ROWS {
                return Err(Error::IndexOverflow("scoped read edge reachability"));
            }
            edges.push(edge);
        }
        Ok(edges)
    }

    fn filter_context_entity_edges(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        entity: &mut ContextEntity,
    ) -> Result<()> {
        let Some(edges) = entity.edges.as_mut() else {
            return Ok(());
        };
        let mut kept = Vec::with_capacity(edges.len());
        for edge in edges.drain(..) {
            if self.is_entity_retrievable_with_policy_in(rtxn, policy, filter, &edge.target)? {
                kept.push(edge);
            }
        }
        *edges = kept;
        Ok(())
    }

    pub(crate) fn policy_manifest_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<PolicyManifestResolution> {
        crate::gate::resolve_policy_manifest(&self.vault.store, rtxn)
    }
}

/// ONE-1608 / ARCH-0050 R6 L2: the L2 pull ranks over an ACTOR-SCOPED walk,
/// so `crate::ppr` asks this lane whether a node may carry PPR mass at all.
///
/// The predicate is exactly [`ScopedRead::is_entity_readable_with_policy_in`],
/// the same admission the result-filtering doors above apply, so a scoped walk
/// can neither widen nor narrow what this lane already admits: a CLAIM is
/// traversable exactly when this actor could read it, and an entity kind that
/// carries no CLAIM clamp stays visible exactly as everywhere else. The
/// authority is resolved in the caller's snapshot, never cached across reads.
///
/// IN THE CALLER'S TRANSACTION, deliberately: the walk hands over the `RoTxn`
/// it is already reading from, matching
/// [`ScopedRead::filter_scored_entities`] and
/// [`ScopedRead::filter_context_pack`]. That is why this is not
/// `get_entity_parts`, which opens a transaction of its own.
impl crate::ppr::PprNodeVisibility for ScopedRead<'_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let policy = self.policy_manifest_in(txn)?;
        self.is_entity_readable_with_policy_in(txn, &policy, id)
    }
}

fn context_pack_edge_can_reach_neighbor(edge: &EdgeInfo) -> bool {
    !matches!(edge.kind, EdgeKind::ChildOf | EdgeKind::AssignedTo)
        && !edge
            .provenance
            .is_some_and(|flags| flags.confirmation_status == EdgeConfirmationStatus::Retracted)
}

impl ScopedRead<'_> {
    /// Structured failure corpus, read through this actor's existing scoped door.
    pub fn diagnostic_events(&self) -> Result<Vec<(EntityId, crate::self_heal::DiagnosticEvent)>> {
        let mut events = Vec::new();
        for id in self
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_DIAGNOSTIC)?
        {
            if let Some((_, _, body)) = self.get_entity_parts(&id)? {
                events.push((id, crate::self_heal::decode_diagnostic_event_body(&body)?));
            }
        }
        Ok(events)
    }
}
