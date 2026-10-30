//! `Vault` claim read doors: targeted `get_claim`, the subject/predicate
//! scans, the session-bundle projection, and the facet-ref lookup the scoped
//! read lane gates on.

use rmpv::Value;

use super::*;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{EngineScan, ScanCount};
use crate::temporal::TimeRange;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;

impl Vault {
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

    /// Whether the claim `id` may consolidate or take effect on this device:
    /// no owner answer to a critical confirm is outstanding on it (ARCH-0026
    /// §G3). The owner-answer obligation is this device's own state, so a
    /// peer's revision that lands over an open one stays held here until its
    /// owner answers. A reader that widens, consolidates or acts on a claim
    /// read through [`Vault::get_claim`] asks this; retrieval, history and a
    /// restriction never do. A read fault is an `Err`: the caller treats the
    /// claim as still owed.
    pub fn claim_critical_confirm_settled(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        crate::gate::claim_critical_confirm_settled_in_txn(&self.store, &rtxn, id)
    }

    /// [`Vault::get_claim_in_txn`] for a reader about to ACT on the claim.
    ///
    /// A critical claim whose owner confirmation is outstanding, attached or
    /// timed out, reads as absent here; every retrieval read still returns it
    /// (ARCH-0026 §G3). This is the marker rule only: each caller keeps its
    /// own approval, source and lifecycle rules on the body.
    pub(crate) fn get_claim_for_effect_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        let Some(body) = self.get_claim_in_txn(rtxn, id)? else {
            return Ok(None);
        };
        if !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, rtxn, id)? {
            return Ok(None);
        }
        Ok(Some(body))
    }

    /// For an acting reader that read the claim's body in an earlier
    /// transaction: the claim's confirm is settled and the claim is still
    /// active now. An owner's Decline settles the confirm by retracting the
    /// claim, so a Decline landing between the two reads never passes the
    /// active body the reader already holds.
    pub(crate) fn claim_settled_and_active(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        if !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, &rtxn, id)? {
            return Ok(false);
        }
        Ok(self
            .get_claim_in_txn(&rtxn, id)?
            .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active))
    }

    /// Transaction-composable [`Vault::get_claim`]: reads and decodes a CLAIM
    /// body through the caller's txn (so it composes inside a write txn, where a
    /// nested read txn would be illegal).
    pub(crate) fn get_claim_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        self.claim_in_txn(
            rtxn,
            id,
            super::history_projection::resolved_machine_history,
        )
    }

    /// [`Vault::get_claim_in_txn`] for a door that only restricts the claim:
    /// a MACHINE claim's history folds with its carriers held or not, and
    /// the door's own staging and live-row guard keep any approval from
    /// projecting. Never for a read that could project or approve.
    pub(crate) fn claim_for_restriction_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        self.claim_in_txn(
            rtxn,
            id,
            super::history_projection::machine_history_for_restriction,
        )
    }

    fn claim_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        history: fn(
            &crate::store::Store,
            &heed::RoTxn<'_>,
            &crate::authority::AuthorityFold,
            EntityId,
        ) -> Result<super::transition::ClaimTransitionProjection>,
    ) -> Result<Option<ClaimBody>> {
        let body = crate::ports::ClaimStore::port_claim_get(self, rtxn, id)?;
        let Some(body) = body else { return Ok(None) };
        if crate::authority::machine_claim_needs_history(&self.store, rtxn, &body)?
            || !super::history_store::machine_history_ids_for_target(&self.store, rtxn, *id)?
                .is_empty()
            || self
                .store
                .vault_meta
                .get(rtxn, &super::history_projection::pin_key(*id))?
                .is_some()
        {
            let fold = self.authority_fold_readonly_in_txn(rtxn)?;
            let projection = history(&self.store, rtxn, &fold, *id)?;
            // A superseded history's same-id successor is an ordinary claim.
            if !projection.admits_successor_by(crate::memory::claim_author(&body))
                || crate::authority::machine_claim_needs_history(&self.store, rtxn, &body)?
            {
                return Ok(Some(super::history_projection::project_machine_claim(
                    &projection,
                )));
            }
        }
        Ok(Some(body))
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
            .port_entity_ids_by_type(rtxn, ENTITY_TYPE_CLAIM, None)?
        {
            let id = entry?;
            let raw = self
                .store
                .port_entity_record(rtxn, &id)?
                .map(|row| row.encode())
                .ok_or(Error::CorruptedIndex("claim type index"))?;
            if !crate::ports::raw_readable_in_txn(&self.store, rtxn, &id, &raw)? {
                continue;
            }
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
        crate::ports::ClaimStore::port_claim_list(self, rtxn, subject)
    }

    /// Walks the CLAIMs attached to `subject` via inbound `claim_of` edges and
    /// returns the first thing `found` makes of one.
    ///
    /// The same rows as [`Vault::claims_for_subject_in_txn`] under the same
    /// filter. That sibling MATERIALIZES peers; this one holds nothing but the
    /// current row.
    ///
    /// Inbound claims are attached BY OTHERS, so a peer able to write rows
    /// about a subject controls how many there are. A walk that answered "not
    /// found" or refused past a count would let that peer switch the caller's
    /// dedupe off, so the walk reads every row until `found` answers (FIX
    /// 8660): a match is the only early end, and the count only feeds the
    /// advisory [`EngineScan::EdgePeerRows`] check of the subject's inbound
    /// `claim_of` edges.
    ///
    /// Reads through the caller's txn, so the whole walk sees one snapshot.
    ///
    /// Skips the same rows `filtered_edge_peers` skips — an edge pointing at a
    /// missing entity, an unparsable header, or something that is not a CLAIM.
    /// Every other read failure propagates: an unreadable index is not an
    /// answer of "nothing here".
    pub(crate) fn find_claim_for_subject_in_txn<T>(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
        mut found: impl FnMut(&EntityId, &ClaimBody) -> Option<T>,
    ) -> Result<Option<T>> {
        self.walk_subject_claims_in_txn(rtxn, subject, |id, body| Ok(found(id, &body)))
    }

    /// Hands each CLAIM attached to `subject` by an inbound `claim_of` edge to
    /// `visit`, under the caller's snapshot, until `visit` answers `Some`.
    /// Every row is read, however many a subject holds; the count only feeds
    /// the advisory [`EngineScan::EdgePeerRows`] check, which never refuses,
    /// caps or answers "not found".
    fn walk_subject_claims_in_txn<T>(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
        mut visit: impl FnMut(&EntityId, ClaimBody) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let direction = EdgeDirection::In;
        let kind = EdgeKind::ClaimOf;
        let scope = [
            &[direction as u8][..],
            subject.as_bytes(),
            &[kind as u8][..],
        ]
        .concat();
        let mut count = ScanCount::start(&self.store, rtxn, EngineScan::EdgePeerRows, &scope)?;
        let mut hit = None;
        for entry in self.port_edges(rtxn, subject, direction, Some(kind), None)? {
            count.row();
            let claim_id = entry?.target;
            let Some(body) = self.claim_body_if_claim_in_txn(rtxn, &claim_id)? else {
                continue;
            };
            hit = visit(&claim_id, body)?;
            if hit.is_some() {
                break;
            }
        }
        count.defer(&self.store);
        Ok(hit)
    }

    /// A bounded twin of [`Vault::find_claim_for_subject_in_txn`] that refuses
    /// past `ceiling` rows. No production path calls it.
    #[cfg(test)]
    pub(super) fn find_claim_for_subject_within<T>(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
        ceiling: usize,
        mut found: impl FnMut(&EntityId, &ClaimBody) -> Option<T>,
    ) -> Result<Option<T>> {
        let mut scanned = 0usize;
        for entry in self.port_edges(
            rtxn,
            subject,
            EdgeDirection::In,
            Some(EdgeKind::ClaimOf),
            None,
        )? {
            scanned += 1;
            if scanned > ceiling {
                return Err(Error::IndexOverflow("claim lookup for subject"));
            }
            let claim_id = entry?.target;
            let Some(body) = self.claim_body_if_claim_in_txn(rtxn, &claim_id)? else {
                continue;
            };
            if let Some(hit) = found(&claim_id, &body) {
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    /// This entity's CLAIM body, or `None` when the id names something that is
    /// not one. A decode failure on a row that IS a CLAIM still propagates.
    fn claim_body_if_claim_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        let Some(raw) = self.port_entity_raw(rtxn, id)? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(None);
        };
        if header.entity_type != ENTITY_TYPE_CLAIM
            || !crate::ports::raw_readable_in_txn(&self.store, rtxn, id, &raw)?
        {
            return Ok(None);
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
    }

    /// Every stored CLAIM carrying `predicate`, resolved by scanning the type-0
    /// index — reserved predicates included.
    ///
    /// The read door for engine-authored evidence that has no secondary index
    /// of its own. Every put door, a sync replay's replicated row included,
    /// stages the predicate posting list at the one put chokepoint
    /// (`apply_put` -> `maintain_claim_projection_index`), so a posting-list
    /// reader names the same claims; this scan reads the claims themselves.
    /// The list holds every such claim, however many (FIX
    /// 8656); a reader that need not hold them walks the same claims with
    /// `for_each_readable_claim_with_predicate_in_txn`.
    pub(crate) fn claims_with_predicate_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        crate::ports::ClaimStore::port_claim_list_by_predicate(self, rtxn, predicate)
    }

    /// Every readable CLAIM of each of `subjects` that `matches`, under one
    /// snapshot. Each subject's whole inbound cohort is judged, however large
    /// (FIX 8661); the count only feeds the advisory
    /// [`EngineScan::EdgePeerRows`] check.
    pub(crate) fn claim_bodies_for_subjects_matching(
        &self,
        subjects: &[EntityId],
        mut matches: impl FnMut(&ClaimBody, &EntityId) -> bool,
    ) -> Result<Vec<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        let mut claims = Vec::new();
        for subject in subjects {
            self.walk_subject_claims_in_txn(&rtxn, subject, |_, body| {
                if matches(&body, subject) {
                    claims.push(body);
                }
                Ok(None::<()>)
            })?;
        }
        Ok(claims)
    }
}

/// The `FacetOf` targets of `id` in the caller's composed transaction.
/// Key-only enumeration preserves the facet grant check even if an unrelated
/// edge value is malformed; malformed keys still fail closed.
pub(crate) fn facet_refs_in_port<P: crate::ports::EdgeStoreRead>(
    ports: &P,
    txn: &P::Read<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut facets = Vec::new();
    for peer in
        ports.port_edge_peers(txn, id, crate::ports::EdgeDirection::Out, EdgeKind::FacetOf)?
    {
        if facets.len() >= MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("claim_facet_refs"));
        }
        facets.push(peer?);
    }
    Ok(facets)
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
