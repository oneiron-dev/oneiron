use super::*;

impl Vault {
    /// Pre-purge ARCH-0038 capture for the local delete paths: decodes the
    /// entity ABOUT to be purged or SoftErased and, when it is an
    /// `edge.provenance` Claim, captures the subject EdgeRef (for the D16
    /// flag refresh) plus the `body_snapshot_ref` / `source_revision_ref`
    /// the queued historical-carrier sweep needs to locate residual
    /// snapshot/update bytes.
    ///
    /// Discrimination order — the hook stays inert for everything else:
    /// type byte FIRST (non-CLAIM ⇒ `None`), then the predicate (non-
    /// `edge.provenance` Claim ⇒ `None`). A bodiless 25 B Claim shell ⇒
    /// `None`: every local SoftErase commits the D16 edge refresh in the
    /// SAME transaction that scrubs the body, so a shell's subject edge is
    /// already consistent and the refs the sweep would need are gone with
    /// the body. A type-0 record whose NON-empty body fails
    /// claim/provenance decoding fails CLOSED with the decoder's typed error
    /// — the ONE-1104 invariant (every type-0 write is validated) is broken
    /// and the delete must not guess.
    pub(in crate::deletion) fn capture_provenance_delete(
        &self,
        id: &EntityId,
    ) -> Result<Option<CapturedProvenanceDelete>> {
        let rtxn = self.store.env.read_txn()?;
        self.capture_provenance_delete_in_txn(&rtxn, id)
    }

    /// [`Self::capture_provenance_delete`] against a caller-owned snapshot, so
    /// a batched replay can capture inside the transaction that will scrub the
    /// Claim instead of opening a second, staler read.
    pub(super) fn capture_provenance_delete_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<CapturedProvenanceDelete>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if body.is_empty() {
            return Ok(None);
        }
        let wrapper = crate::claim::decode_claim_body(body, true)?;
        if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
            return Ok(None);
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
        Ok(Some(CapturedProvenanceDelete {
            subject: EdgeRef::new(source, kind, target),
            source_revision_ref: record.source_revision_ref,
            body_snapshot_ref: record.body_snapshot_ref,
        }))
    }

    /// ARCH-0038 DELETE interplay (D16), run in the SAME transaction that
    /// purged / SoftErased the provenance Claim: refresh the subject edge's
    /// cached flags — restamp from the deterministic D14 winner among the
    /// REMAINING live Claims; else, when a RETRACTED `edge.provenance` Claim
    /// for the same EdgeRef still survives, KEEP the 26 B retracted dampening
    /// stamp (the withdrawn provenance must stay dampened — retractionRules
    /// RETRACT); only when NO provenance Claim of ANY lifecycle survives is
    /// the cached flag unauditable and the edge downgraded 26 B → 24 B bare.
    /// Both `edges_out` and `edges_in` carry identical bytes; when the edge
    /// bytes changed, the endpoints' PPR caches are invalidated and the graph
    /// version bumped. A subject edge that no longer exists (deleted
    /// independently of its Claims) leaves nothing to refresh — no-op.
    ///
    /// Returns both endpoints when the edge bytes changed, so the caller's
    /// post-commit notice reaches the `edges_out` and `edges_in` reads.
    pub(in crate::deletion) fn refresh_subject_edge_after_claim_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<Vec<EntityId>> {
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(wtxn, &edge_key)?.is_none() {
            return Ok(Vec::new());
        }
        let survivors =
            self.live_edge_provenance_claims_in_txn(wtxn, subject, Some(deleted_claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = survivors
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        let changed = match winner_index(&precedence) {
            Some(index) => {
                restamp_edge_flags(&self.store, wtxn, subject, survivors[index].flags())?;
                true
            }
            // No ACTIVE survivor. "The derived edge flag follows the Claim"
            // (ARCH-0038 D16) — but a RETRACTED `edge.provenance` Claim is
            // still readable truth, so it KEEPS the 26 B retracted dampening
            // stamp rather than downgrading to a bare 24 B edge that would
            // re-enable PPR propagation of the WITHDRAWN provenance. Only when
            // no provenance Claim of ANY lifecycle survives is the flag
            // unauditable and the edge downgraded to bare.
            None => self.refresh_to_retracted_survivor_or_bare(wtxn, deleted_claim_id, subject)?,
        };
        if !changed {
            return Ok(Vec::new());
        }
        ppr::invalidate_ppr_for_edge(&self.store, wtxn, &subject.source, &subject.target)?;
        ppr::increment_graph_version(&self.store, wtxn)?;
        Ok(vec![subject.source, subject.target])
    }

    /// D16 fallback when the deleted Claim left NO active survivor: if a
    /// RETRACTED `edge.provenance` Claim for `subject` still exists, restamp
    /// the edge with `confirmation_status` = retracted (3) and the retracted
    /// WINNER's persisted `actor_class` — keeping the 26 B retracted dampening
    /// stamp the contract mandates (retractionRules RETRACT), mirroring
    /// `retract_edge_provenance`'s own None-branch so the two paths agree.
    /// Otherwise downgrade 26 B → 24 B bare (no truth-Claim of any lifecycle
    /// survives ⇒ an unauditable cached flag). Returns whether the bytes
    /// changed.
    fn refresh_to_retracted_survivor_or_bare(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<bool> {
        let retracted =
            self.retracted_edge_provenance_claims_in_txn(wtxn, subject, Some(deleted_claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = retracted
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        match winner_index(&precedence) {
            Some(index) => {
                restamp_edge_flags(
                    &self.store,
                    wtxn,
                    subject,
                    EdgeProvenanceFlags {
                        confirmation_status: EdgeConfirmationStatus::Retracted,
                        actor_class: retracted[index].actor_class,
                    },
                )?;
                Ok(true)
            }
            None => downgrade_edge_to_bare(&self.store, wtxn, subject),
        }
    }
}
