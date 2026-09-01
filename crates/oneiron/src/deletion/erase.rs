use std::collections::BTreeSet;

use crate::Vault;
use crate::affect::VadAnnotationCleanup;
use crate::affect::delete_vad_annotation_metadata_for_type_in_txn;
use crate::affect::delete_vad_annotation_metadata_in_txn;
use crate::affect::vad_annotation_delete_scope_exists_in_txn;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::deindex_entity;
use crate::batch::deindex_lexical_query_hints_for_target;
use crate::batch::delete_from_phonetic_postings;
use crate::bm25;
use crate::claim::ClaimSubject;
use crate::edge::EdgeConfirmationStatus;
use crate::edge::EdgeProvenanceFlags;
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::identity_topology::{
    StoredIdentityOpAction, decode_identity_topology_event_body,
    encode_identity_topology_event_body,
};
use crate::ppr;
use crate::provenance::EdgeRef;
use crate::provenance::PREDICATE_EDGE_PROVENANCE;
use crate::provenance::ProvenancePrecedence;
use crate::provenance::StoredProvenanceClaim;
use crate::provenance::decode_edge_provenance_body;
use crate::provenance::downgrade_edge_to_bare;
use crate::provenance::restamp_edge_flags;
use crate::provenance::winner_index;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT};
use crate::store::{GateDecisionId, Store};
use crate::unix_seconds_now;

use super::receipt::{RedactionReceiptInput, RedactionScope};
use super::sweep_queue::HardEraseSweepExtras;
use super::tombstone::{ReplayedTombstoneOutcome, decode_tombstone_value, local_hard_delete_key};

/// ARCH-0038 delete-interplay refs captured from an `edge.provenance` Claim
/// BEFORE its body is purged or SoftErased: the subject EdgeRef whose cached
/// flags must be refreshed post-purge (D16), and the opaque refs the queued
/// historical-carrier sweep rides on (the ONE-1091 executor's seam).
pub(super) struct CapturedProvenanceDelete {
    pub(super) subject: EdgeRef,
    source_revision_ref: Option<[u8; 16]>,
    body_snapshot_ref: Option<[u8; 16]>,
}

/// Whether a stored type-76 action names any of `touched` in the redirect
/// topology it declares — the exact reach of the ARCH-0055 §9 erase walk.
///
/// ONLY the two shell-edge families answer yes: merge and split are the ops
/// the redirect walk reads, so they are the ops whose payloads it touches.
/// Facet, assert_distinct, undo and proposal resolution are outside that
/// reach and stay untouched, which is what keeps the author-stamp rider from
/// becoming a family-wide sweep.
fn identity_op_event_touches(
    action: &StoredIdentityOpAction,
    touched: &BTreeSet<EntityId>,
) -> bool {
    match action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            touched.contains(survivor) || sources.iter().any(|source| touched.contains(source))
        }
        StoredIdentityOpAction::Split { entity, heads, .. } => {
            touched.contains(entity) || heads.iter().any(|head| touched.contains(head))
        }
        StoredIdentityOpAction::Facet { .. }
        | StoredIdentityOpAction::AssertDistinct { .. }
        | StoredIdentityOpAction::Undo { .. }
        | StoredIdentityOpAction::ProposalResolution { .. } => false,
    }
}

/// Builds the queued sweep row's delete-interplay extras from a pre-purge
/// provenance capture: opaque lowercase-hex identifiers only — never content
/// or predicate strings. Empty for non-provenance deletes, so their queued
/// row shape gains nothing.
pub(super) fn sweep_extras(captured: Option<&CapturedProvenanceDelete>) -> HardEraseSweepExtras {
    let Some(captured) = captured else {
        return HardEraseSweepExtras::default();
    };
    HardEraseSweepExtras {
        revision_ids: captured
            .source_revision_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
        body_snapshot_refs: captured
            .body_snapshot_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
    }
}

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
    pub(super) fn capture_provenance_delete(
        &self,
        id: &EntityId,
    ) -> Result<Option<CapturedProvenanceDelete>> {
        let rtxn = self.store.env.read_txn()?;
        self.capture_provenance_delete_in_txn(&rtxn, id)
    }

    /// [`Self::capture_provenance_delete`] against a caller-owned snapshot, so
    /// a batched replay can capture inside the transaction that will scrub the
    /// Claim instead of opening a second, staler read.
    fn capture_provenance_delete_in_txn(
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
            return Err(Error::InvalidProvenanceBody(
                "edge.provenance claim subject is not a 33-byte EdgeRef",
            ));
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
    pub(super) fn refresh_subject_edge_after_claim_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<()> {
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(wtxn, &edge_key)?.is_none() {
            return Ok(());
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
        if changed {
            ppr::invalidate_ppr_for_edge(&self.store, wtxn, &subject.source, &subject.target)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        Ok(())
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

    /// ARCH-0055 §9 (r6): "HardErase walks redirects. Erasing a canonical
    /// head erases its redirect shells' payloads too — leaving a shell
    /// readable would leak what erasure hid."
    ///
    /// MUST run BEFORE the head's purge, in the SAME transaction: the purge
    /// deletes the head's incident edges, and those edges are the shell
    /// walk's primary witness. Same-transaction is not a convenience —
    /// erasing the head while a shell of it stays readable is the leak, so
    /// the two either commit together or neither does.
    ///
    /// The shells are NOT deleted. Merge-away is not deletion (§10), so
    /// there is no tombstone, no `dt:` marker and no new reason: only the
    /// readable payload goes, through the same shell-preserving SoftErase
    /// `user_delete` uses, leaving the 25 B row and the topology that makes
    /// the projection rebuildable exactly where they were.
    ///
    /// Returns the erased shells so the caller can widen its redaction
    /// scope: a shell's historical carriers must ride the head's `h:` sweep
    /// row, or the bytes this clears from the active store simply survive in
    /// history and nothing has been erased at all.
    pub(super) fn cascade_hard_erase_to_redirect_shells_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        head: &EntityId,
    ) -> Result<BTreeSet<EntityId>> {
        let shells = crate::identity_redirect::inbound_redirect_shells_in_txn(
            &self.store,
            &*wtxn,
            &BTreeSet::from([*head]),
        )?;
        if shells.is_empty() {
            return Ok(shells);
        }
        let mut had_vector = false;
        for shell in &shells {
            // Same pre-scrub capture every SoftErase door pays: the subject
            // EdgeRef is only readable while the body is.
            let captured = self.capture_provenance_delete_in_txn(&*wtxn, shell)?;
            let (existed, shell_had_vector) = self.soft_erase_active_store_in_txn(wtxn, shell)?;
            had_vector |= shell_had_vector;
            // D16 in the SAME transaction as the scrub, exactly as the local
            // and replayed SoftErase arms do it.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    wtxn,
                    shell,
                    &captured.subject,
                )?;
            }
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        let mut touched = shells.clone();
        touched.insert(*head);
        self.scrub_identity_op_author_stamps_in_txn(wtxn, &touched)?;
        Ok(shells)
    }

    /// ARCH-0055 §9 author-stamp rider, STRICTLY scoped: drop the deciding
    /// actor's stamp from the type-76 merge/split events whose payloads this
    /// erase walk touched — the records that bound the erased head to the
    /// shells this transaction just emptied. Erasing the subjects of a
    /// decision while the ledger keeps reading "X decided this about them"
    /// leaves the erasure half-done.
    ///
    /// The boundary is the walk's own reach and nothing wider. A general
    /// participant-deletion sweep over the family is a separate obligation
    /// with its own ticket; a rider that grew into it would erase authorship
    /// of decisions this erase never read, on a path with no receipt for
    /// having done so.
    ///
    /// Fail-closed on an undecodable body, like every other reader of this
    /// engine-authored family — and reached only when the head actually had
    /// shells, so an ordinary delete never enumerates the ledger at all.
    fn scrub_identity_op_author_stamps_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let mut scrubbed: Vec<(EntityId, Vec<u8>)> = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&*wtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&*wtxn, event_id.as_bytes())? else {
                continue;
            };
            if raw.len() < ENTITY_METADATA_HEADER_LEN {
                return Err(Error::CorruptedIndex("entity metadata"));
            }
            let event = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
            if !identity_op_event_touches(&event.action, touched) {
                continue;
            }
            let Some(event) = event.without_author_stamp() else {
                continue;
            };
            let mut record = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            record.extend_from_slice(&encode_identity_topology_event_body(&event)?);
            scrubbed.push((event_id, record));
        }
        for (event_id, record) in &scrubbed {
            self.store.entities.put(wtxn, event_id.as_bytes(), record)?;
        }
        Ok(())
    }

    pub(super) fn purge_entity_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        // The content-hash index row is dropped by `deindex_entity` below;
        // ONE-1741 removed the verdict relocation that this hook also carried.
        //
        // ONE-1447 runs BEFORE the tear: the stale fold reads the skills that
        // CITED this id, not this id's own rows, and both acts belong to the
        // one transaction that destroys the evidence.
        self.mark_dependent_skills_stale_in_txn(wtxn, id)?;
        let (existed, had_vector, had_graph_mutation, neighbors) =
            deindex_entity(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &neighbors)?;
        if had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        Ok(existed)
    }

    pub(super) fn soft_erase_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool)> {
        let (hint_had_vector, hint_had_graph_mutation, _hint_neighbors) =
            deindex_lexical_query_hints_for_target(&self.store, wtxn, id)?;
        if hint_had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        bm25::deindex_text(&self.store, wtxn, id)?;
        delete_from_phonetic_postings(&self.store, wtxn, id)?;
        crate::code_revision::delete_code_revision_lifecycle_in_txn(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        let blob_cleanup =
            crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(&self.store, wtxn, id)?;
        if blob_cleanup.had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        self.store.clear_pending_embedding(wtxn, id)?;
        let entity_had_vector = self.store.vectors.delete(wtxn, id.as_bytes())?;
        let mut had_vector = hint_had_vector | entity_had_vector | blob_cleanup.had_vector;
        crate::hnsw::hnsw_deindex(&self.store, wtxn, id)?;

        let Some(entity_record) = self.store.entities.get(wtxn, id.as_bytes())? else {
            let cleanup = delete_vad_annotation_metadata_in_txn(&self.store, wtxn, id)?;
            had_vector |= cleanup.had_vector;
            if cleanup.had_graph_mutation {
                ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
                ppr::increment_graph_version(&self.store, wtxn)?;
            }
            return Ok((false, had_vector));
        };
        let header = EntityMetadataHeader::parse(&entity_record)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        let payload = entity_record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        // Soft-erase truncates the body in place, so unlike the hard-purge path it
        // does not route through `deindex_entity`; drop any content-hash index row
        // here before the body is gone (ONE-1741: scan verdicts anchor to the
        // content bytes, so nothing to relocate). The maintenance helper no-ops for
        // kinds that keep no content-hash index, so the generic delete engine needs
        // no entity-kind branch of its own.
        self.maintain_skill_content_hash_index_on_delete_in_txn(wtxn, id)?;
        // ONE-1447, the other half of the same question: this id may be the
        // conversation a SKILL was converted from, and a skill whose evidence
        // this transaction is erasing must stop loading as canon in that same
        // transaction. Visible and reversible — never a silent orphan, never a
        // cascading delete.
        self.mark_dependent_skills_stale_in_txn(wtxn, id)?;
        let mut cleanup = VadAnnotationCleanup::default();
        delete_vad_annotation_metadata_for_type_in_txn(
            &self.store,
            wtxn,
            id,
            header.entity_type,
            &mut cleanup,
        )?;
        had_vector |= cleanup.had_vector;
        if cleanup.had_graph_mutation {
            ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }

        crate::dreamer_runner::deindex_dreamer_milestone_claim(&self.store, wtxn, id)?;
        crate::llm::deindex_dreamer_step_claim(&self.store, wtxn, id)?;
        self.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        Ok((true, had_vector))
    }

    /// Reason-aware replay of a CRDT tombstone into the LOCAL active store —
    /// the ONE primitive every sync replay surface routes through (Observer
    /// B's tombstone phase and `forward_rematerialize`'s tombstone pass), so
    /// a remote delete can never diverge from the pinned ARCH-0038 reason
    /// semantics. OWNER-DECISION (M4-06 / ONE-1133, fail-closed): replay
    /// routes through this reason-aware delete primitive, never bare purge.
    ///
    /// * KNOWN-soft value (`reason = user_delete`) → shell-preserving
    ///   SoftErase: payload truncated to the 25 B entity header,
    ///   text/phonetic/vector/hnsw deindexed, and — when the entity was a
    ///   live `edge.provenance` Claim — the D16 subject-edge refresh
    ///   committed in the SAME transaction. No receipt, no sweep row
    ///   (contracts.ts `user_delete`: activeStoreHardPurgeV1 = false,
    ///   receipt = false).
    /// * Hard value (known hard reason, legacy 8-byte, reserved 0, unknown
    ///   byte, malformed) → destructive purge of the payload plus every
    ///   active index entry, the D16 refresh in the SAME transaction, and —
    ///   when local state was actually erased — a LOCAL `h:{seq:8BE}`
    ///   historical-carrier sweep row (`deadline_at` ≤ queued_at + 30 d,
    ///   GDPR Art. 12(3)) and a LOCAL REDACTION_AUDIT receipt whose
    ///   `request_id` comes from the wire value (OWNER-DECISION: Art. 5(2)
    ///   accountability attaches to each replica actually erasing, so N
    ///   devices yield N receipts for one request). Ambiguity resolves to
    ///   MORE deletion, never less.
    /// * Never-downgrade on receive: a soft value for an id this replica
    ///   already hard-purged finds no row to scrub and is a no-op — it
    ///   never recreates a shell.
    /// * Idempotent: after a completed hard apply the delete-scope probe
    ///   finds nothing, so re-application (every-boot forward
    ///   re-materialization, repeated delta delivery) is a receipt-free
    ///   no-op.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn apply_replayed_tombstone(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.apply_replayed_tombstone_in_txn(&mut wtxn, id, raw_value)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// [`Self::apply_replayed_tombstone`]'s effect core, against a
    /// caller-owned transaction (ONE-521). Every reason semantic above is
    /// decided here; the wrapper only owns the commit, so a batched replay
    /// (Observer B's tombstone phase) can apply N tombstones — each in its own
    /// nested savepoint — under ONE durable transaction without changing what
    /// any single tombstone does.
    ///
    /// The transaction is the caller's: this function NEVER commits, and an
    /// `Err` return leaves the decision of what to roll back (the whole batch,
    /// or just this item's savepoint) to the caller.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn apply_replayed_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        let decoded = decode_tombstone_value(raw_value);
        if let Some(header) = self.read_entity_header_in_txn(wtxn, id)?
            && crate::registry::is_delete_protected_engine_record(header.entity_type)
        {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-scrub.
        let captured = self.capture_provenance_delete_in_txn(wtxn, id)?;

        if !decoded.is_hard() {
            let had_body = self
                .store
                .entities
                .get(&*wtxn, id.as_bytes())?
                .is_some_and(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(wtxn, id, &captured.subject)?;
            }
            return Ok(ReplayedTombstoneOutcome::SoftErased {
                changed: had_body || had_vector,
            });
        }

        let marker_key = local_hard_delete_key(id);
        let marker_value = decoded.local_hard_delete_marker_value();
        // Probe the FULL delete scope (entity row, vectors, text, phonetic,
        // short-ids, edges): orphan residue without an entities row still
        // counts as local state to erase, mirroring the local
        // `delete_entity_without_header` semantics.
        if !self.active_delete_scope_exists_in_txn(wtxn, id)? {
            // Hard-once-seen is durable LOCAL truth even when nothing local
            // was erased (never-materialized id): the permanent `dt:` marker
            // still gates a future re-put after hostile tombstone-map
            // manipulation. The guarded write keeps every-boot replay a
            // read-only no-op once the marker exists.
            if self.store.sync_state.get(&*wtxn, &marker_key)?.is_none() {
                self.store
                    .sync_state
                    .put(wtxn, &marker_key, &marker_value)?;
            }
            if let Some((request_id, tombstone_reason)) =
                decoded.request_id.zip(raw_value.first().copied())
            {
                let discarded_local_authority =
                    self.store.discard_pending_deletion_gate_decision_in_txn(
                        wtxn,
                        GateDecisionId::from_bytes(request_id),
                        id.as_bytes(),
                        tombstone_reason,
                    )?;
                if discarded_local_authority {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        "remote replay found no local state; discarded the matching local deletion authority sidecar"
                    );
                }
            }
            return Ok(ReplayedTombstoneOutcome::HardPurged {
                erased: false,
                receipt_id: None,
                sweep_key: None,
            });
        }
        // ARCH-0055 §9 (r6) on the RECEIVING side: a remote hard erase must
        // leave this replica as unreadable as the origin, so the local shells
        // of the erased head are cascaded here too — before the purge takes
        // the shell edges with it, in the caller's transaction.
        let cascaded_shells = self.cascade_hard_erase_to_redirect_shells_in_txn(wtxn, id)?;
        self.purge_entity_active_store_in_txn(wtxn, id)?;
        // Receiver-side `dt:` local hard-delete marker (pinned: presence-only
        // value, GLOBAL key, permanent, no GC) — written in the SAME txn as
        // the purge so local delete truth survives CRDT-map manipulation.
        self.store
            .sync_state
            .put(wtxn, &marker_key, &marker_value)?;
        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        if let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(wtxn, id, &captured.subject)?;
        }
        if let Some((request_id, tombstone_reason)) =
            decoded.request_id.zip(raw_value.first().copied())
        {
            let completed_local_authority =
                self.store.append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    GateDecisionId::from_bytes(request_id),
                    id.as_bytes(),
                    tombstone_reason,
                )?;
            if completed_local_authority.is_some() {
                tracing::debug!(
                    entity = %id.to_hex(),
                    "remote replay completed a staged local deletion authority record"
                );
            }
        }
        let applied_at = unix_seconds_now();
        let receipt_id = EntityId::now();
        let mut scope = RedactionScope::entity(id);
        scope
            .entity_ids
            .extend(cascaded_shells.iter().map(EntityId::to_hex));
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: decoded.receipt_request_id(),
                scope,
                reason: decoded.receipt_hard_reason(),
                // The origin's request time, straight off the wire (0 for
                // malformed shapes); completion stamps are device-local
                // facts on the replica that erased.
                requested_at: decoded.deleted_at,
                soft_complete_at: applied_at,
                hard_purge_complete_at: applied_at,
                sweep_queued_at: Some(applied_at),
            },
            sweep_extras(captured.as_ref()),
        )?;
        Ok(ReplayedTombstoneOutcome::HardPurged {
            erased: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    #[cfg(feature = "sync")]
    pub(crate) fn apply_replayed_tombstone_for_sync(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        self.apply_replayed_tombstone(id, raw_value)
    }

    /// [`Vault::read_entity_header`](crate::Vault::read_entity_header) against
    /// a caller-owned snapshot: the delete-protection gate of a batched replay
    /// must read the same state its writes will land in, not a second snapshot
    /// taken outside the caller's transaction.
    fn read_entity_header_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityMetadataHeader>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))
            .map(Some)
    }

    /// Presence-only check for the permanent `dt:{entity_hex}` local
    /// hard-delete marker. Materialization gates OR this with the CRDT
    /// tombstones-map presence so LOCAL delete truth survives hostile
    /// tombstone-map manipulation (a removed tombstone + re-put entity must
    /// not resurrect). The value is NEVER decoded (pinned presence-only
    /// semantics).
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn local_hard_delete_marker_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(self
            .store
            .sync_state
            .get(txn, &local_hard_delete_key(id))?
            .is_some())
    }

    /// Removes a headerless tombstone replay's stale `dt:` poison once a
    /// delete-protected engine row is successfully admitted. This is called
    /// in the SAME transaction as protected-row materialization and tombstone
    /// quarantine; such a marker never represented valid delete authority.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn neutralize_delete_protected_marker_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        entity_type: u8,
    ) -> Result<bool> {
        if !crate::registry::is_delete_protected_engine_record(entity_type) {
            return Err(Error::InvariantViolation(
                "dt: poison neutralization requires a delete-protected engine record",
            ));
        }
        self.store
            .sync_state
            .delete(wtxn, &local_hard_delete_key(id))
    }

    pub(super) fn active_delete_scope_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if self.store.entities.get(txn, id.as_bytes())?.is_some()
            || self.store.vectors.get(txn, id.as_bytes())?.is_some()
            || self.store.text_forward.get(txn, id.as_bytes())?.is_some()
            || self.store.text_meta.get(txn, id.as_bytes())?.is_some()
            || self
                .store
                .text_doc_field_lengths
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .phonetic_forward
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .short_ids_reverse
                .get(txn, id.as_bytes())?
                .is_some()
        {
            return Ok(true);
        }

        let mut edges_out = self.store.edges_out.prefix_iter(txn, id.as_bytes())?;
        if edges_out.next().transpose()?.is_some() {
            return Ok(true);
        }
        let mut edges_in = self.store.edges_in.prefix_iter(txn, id.as_bytes())?;
        if edges_in.next().transpose()?.is_some() {
            return Ok(true);
        }

        vad_annotation_delete_scope_exists_in_txn(&self.store, txn, id)
    }
}
