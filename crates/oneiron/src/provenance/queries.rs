//! Vault read scans: named-target guards and live/retracted cohort queries.

use super::{
    EdgeRef, PREDICATE_EDGE_PROVENANCE, StoredProvenanceClaim, active_cohort_winner_short_ref_in,
    closed_cohort_head_short_ref_in, decode_edge_provenance_body, resolve_persisted_actor_class,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::ClaimError;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, edge_kind_prefix, parse_edge_record};

impl Vault {
    /// The write-verb validity guard for a REPLACEMENT-style
    /// `attest_edge_provenance` (ONE-1936): the named prior wrapper must still
    /// be live, or the verb was decided against a view the store has replaced.
    ///
    /// The reported head comes from the D14 cohort winner for the prior's OWN
    /// `EdgeRef` (read off the stored wrapper, never off caller-supplied
    /// arguments) — see `active_cohort_winner_short_ref_in`. A first
    /// attestation names no prior and never reaches here.
    ///
    /// When no LIVE wrapper is left, "no live winner" is not "no newer
    /// wrapper": a RETRACTED target was withdrawn rather than replaced, so —
    /// exactly as a directly retracted claim is its own terminal head — its own
    /// short ref is the answer, while a SUPERSEDED target names the newest
    /// closed cohort member, which is the wrapper whose stamp the edge still
    /// carries (see `closed_cohort_head_short_ref_in`).
    pub fn require_named_provenance_target_active_in(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<()> {
        let claim = self.load_provenance_claim_in_txn(txn, target)?;
        if claim.wrapper.lifecycle == ClaimLifecycleStatus::Active {
            return Ok(());
        }
        let head = match active_cohort_winner_short_ref_in(self, txn, &claim.subject)? {
            Some(head) => head,
            None if claim.wrapper.lifecycle == ClaimLifecycleStatus::Retracted => {
                self.claim_short_ref_in(txn, target)?
            }
            None => closed_cohort_head_short_ref_in(self, txn, &claim.subject, target)?,
        };
        Err(Error::Claim(ClaimError::WriteVerbTargetStale {
            target: *target,
            lifecycle: claim.wrapper.lifecycle,
            successor_short_id: head,
        }))
    }

    /// [`Self::require_named_provenance_target_active_in`] on its own read
    /// transaction — the door for callers that only REPORT the stale condition
    /// (an MCP dry run). A writer must pass its own transaction so guard and
    /// write stay atomic.
    pub fn require_named_provenance_target_active(&self, target: &EntityId) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        self.require_named_provenance_target_active_in(&rtxn, target)
    }

    /// Loads one `edge.provenance` Claim for a lifecycle operation, with the
    /// typed gate chain: missing → [`Error::EntityNotFound`]; not a type-0
    /// Claim or wrong predicate → [`ClaimError::NotAProvenanceClaim`](crate::error::ClaimError::NotAProvenanceClaim); malformed
    /// stored body / record / persisted class → typed decode errors.
    pub(super) fn load_provenance_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<StoredProvenanceClaim> {
        let raw = self
            .store
            .entities
            .get(txn, claim_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::Claim(ClaimError::NotAProvenanceClaim(
                "entity is not a type-0 CLAIM",
            )));
        }
        let wrapper = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
            return Err(Error::Claim(ClaimError::NotAProvenanceClaim(
                "claim predicate is not edge.provenance",
            )));
        }
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = wrapper.subject
        else {
            return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                "edge.provenance claim subject is not a 33-byte EdgeRef",
            )));
        };
        let record = decode_edge_provenance_body(&wrapper.value)?;
        let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
        Ok(StoredProvenanceClaim {
            id: *claim_id,
            occurred_start: header.occurred_start,
            learned_at: header.learned_at,
            subject: EdgeRef::new(source, kind, target),
            wrapper,
            record,
            actor_class,
        })
    }

    /// Enumerates the LIVE (`life` = active) `edge.provenance` Claims for
    /// `subject` — the live cohort the D14 winner stamp is chosen from. Thin
    /// wrapper over [`Self::edge_provenance_claims_in_txn`].
    pub(crate) fn live_edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        self.edge_provenance_claims_in_txn(txn, subject, exclude, &[ClaimLifecycleStatus::Active])
    }

    /// Enumerates the RETRACTED `edge.provenance` Claims for `subject` — the
    /// surviving WITHDRAWN truth the edge's retracted dampening flag caches.
    /// The D16 delete-refresh consults this when NO active Claim survives, to
    /// decide whether the deleted Claim's EdgeRef still has a retracted
    /// truth-Claim to KEEP the 26 B retracted stamp for (else 24 B bare). Thin
    /// wrapper over [`Self::edge_provenance_claims_in_txn`].
    pub(crate) fn retracted_edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        self.edge_provenance_claims_in_txn(
            txn,
            subject,
            exclude,
            &[ClaimLifecycleStatus::Retracted],
        )
    }

    /// Enumerates the `edge.provenance` Claims for `subject` whose wrapping
    /// Claim `life` is one of `lifecycles`, via the inbound `claim_of` edges of
    /// the subject edge's SOURCE entity (D12). Non-claim sources, other
    /// predicates, claims of OTHER EdgeRefs, bodiless SoftErase shells, and
    /// claims of any other lifecycle are skipped; corrupt rows fail closed.
    /// `exclude` drops the claim currently being re-put or deleted.
    pub(super) fn edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
        lifecycles: &[ClaimLifecycleStatus],
    ) -> Result<Vec<StoredProvenanceClaim>> {
        let prefix = edge_kind_prefix(&subject.source, EdgeKind::ClaimOf);
        let mut matched = Vec::new();
        for (scanned, entry) in self.store.edges_in.prefix_iter(txn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("live provenance claims"));
            }
            let (key, value) = entry?;
            let claim_id = parse_edge_record(&key, &value)?.target;
            if exclude == Some(&claim_id) {
                continue;
            }
            let Some(raw) = self.store.entities.get(txn, claim_id.as_bytes())? else {
                return Err(Error::CorruptedIndex("claim_of edge without claim entity"));
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            if raw.len() == ENTITY_METADATA_HEADER_LEN {
                // An ARCH-0038 SoftErase scrubbed this Claim's body but kept
                // its structural edges. A bodiless 25 B Claim shell is a
                // tombstone, never live — skip it. Safe because EVERY local
                // SoftErase (the user_delete branch AND the gdpr/policy
                // pre-purge step) commits the D16 edge refresh in the SAME
                // transaction that scrubs the body, so a shell can never
                // coexist with a stale subject-edge stamp.
                continue;
            }
            let wrapper =
                crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
                continue;
            }
            let ClaimSubject::Edge {
                source,
                kind,
                target,
            } = wrapper.subject
            else {
                continue;
            };
            if EdgeRef::new(source, kind, target) != *subject {
                continue;
            }
            if !lifecycles.contains(&wrapper.lifecycle) {
                continue;
            }
            let record = decode_edge_provenance_body(&wrapper.value)?;
            let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
            matched.push(StoredProvenanceClaim {
                id: claim_id,
                occurred_start: header.occurred_start,
                learned_at: header.learned_at,
                subject: *subject,
                wrapper,
                record,
                actor_class,
            });
        }
        Ok(matched)
    }
}
