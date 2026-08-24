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
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, edge_kind_prefix, parse_edge_record, require_key_len};
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

    /// Walks the CLAIMs attached to `subject` via inbound `claim_of` edges and
    /// returns the first thing `found` makes of one.
    ///
    /// The same rows as [`Vault::claims_for_subject_in_txn`] under the same
    /// filter, without its ceiling. That sibling MATERIALIZES peers and errors
    /// past `MAX_EDGE_QUERY_RESULTS`, which is the right shape for a caller
    /// that needs them all; a caller LOOKING for one row does not, and paying
    /// a ceiling for a list it never wanted means high fan-in turns a lookup
    /// into a failure. Nothing is held here but the current row, so a subject
    /// of any degree is walked.
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
        let prefix = edge_kind_prefix(subject, EdgeKind::ClaimOf);
        for entry in self.store.edges_in.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            let claim_id = parse_edge_record(&key, &value)?.target;
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
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(None);
        };
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
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

}

/// The `FacetOf` targets of `id`, read through whichever out-edge accessor the
/// caller composes over.
///
/// Parameterized rather than pinned to `store.edges_out` because a scoped read
/// opened in a session composes overlay union base, and the facets a claim
/// carries decide what a facet-scoped grant authorizes. Reading base here
/// while every other edge scan in that read reads the union would evaluate a
/// session's grants against a graph the session cannot see.
pub(crate) fn facet_refs_in_db(
    db: &crate::overlay_db::OverlayDb,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut prefix = [0_u8; ENTITY_ID_LEN + 1];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = EdgeKind::FacetOf as u8;

    let mut facets = Vec::new();
    for entry in db.prefix_iter(rtxn, prefix.as_slice())? {
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
