//! Vault claim-VAD transaction surface: annotation, consolidation, approvals, and state scans.

use std::collections::BTreeSet;

use super::{
    CLAIM_VAD_REAPPRAISAL_PREDICATE, ClaimVadConsolidation, ClaimVadReappraisal,
    ClaimVadTurnEvidence, VAD_ANNOTATION_CLAIM_PREDICATE, Vad, VadAnnotation,
    claim_vad_evidence_value, claim_vad_value, collect_claim_turn_evidence_refs,
    decode_vad_annotation_claim_body_if_present, mean_vad, vad_annotation_claim_body,
    vad_annotation_claim_id, vad_annotation_from_value, vad_annotation_meta_key,
};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    claim_consolidatable, encode_claim_body, validate_claim_body_bytes,
};
use crate::edge::{EdgeKind, EdgeValueLayout, edge_value_layout_for_kind};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::provenance::EdgeRef;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::vault::{
    CLAIM_OF_DEFAULT_WEIGHT, MAX_EDGE_QUERY_RESULTS, SUPERSEDES_DEFAULT_WEIGHT, edge_kind_prefix,
    parse_edge_record,
};
struct StoredClaimVadState {
    id: EntityId,
    header: EntityMetadataHeader,
    body: ClaimBody,
}

impl Vault {
    /// Writes or replaces the VAD annotation metadata for a TURN entity.
    pub fn annotate_turn_vad(
        &self,
        turn_id: &EntityId,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        self.annotate_entity_vad(turn_id, ENTITY_TYPE_TURN, annotation)
    }

    /// Reads the VAD annotation metadata for a TURN entity.
    pub fn get_turn_vad_annotation(&self, turn_id: &EntityId) -> Result<Option<VadAnnotation>> {
        self.get_entity_vad_annotation(turn_id, ENTITY_TYPE_TURN)
    }

    /// Writes or replaces the VAD annotation metadata for a MESSAGE entity.
    pub fn annotate_message_vad(
        &self,
        message_id: &EntityId,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        self.annotate_entity_vad(message_id, ENTITY_TYPE_MESSAGE, annotation)
    }

    /// Reads the VAD annotation metadata for a MESSAGE entity.
    pub fn get_message_vad_annotation(
        &self,
        message_id: &EntityId,
    ) -> Result<Option<VadAnnotation>> {
        self.get_entity_vad_annotation(message_id, ENTITY_TYPE_MESSAGE)
    }

    /// Consolidates turn-level VAD evidence attached to `claim_id` into
    /// claim-level affect state.
    ///
    /// The API is asynchronous so background Dreamer consolidation workers can
    /// await it naturally. The storage work is one LMDB transaction: semantic
    /// edges incident to the claim have only their VAD bytes rewritten,
    /// structural edges are skipped, and a derived `affect.claim_vad` state
    /// claim supersedes the previous active state when evidence changes.
    pub async fn consolidate_claim_vad(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<ClaimVadConsolidation> {
        self.consolidate_claim_vad_now(claim_id, now)
    }

    /// Snapshot only explicit approvals of parked Dreamer members. The write
    /// gate still owns consent binding and admission; this never grants trust.
    pub(crate) fn pending_dreamer_vad_approval_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        approval: ClaimApprovalStatus,
    ) -> Result<bool> {
        if approval != ClaimApprovalStatus::Approved {
            return Ok(false);
        }
        Ok(self
            .store
            .pending_gate_consent_in_txn(txn, id)?
            .is_some_and(|pending| pending.dreamer_run_id.is_some()))
    }

    /// Call after successful apply, but before commit, on snapshotted members.
    /// A batch can overwrite or delete an earlier op, so only its final Approved
    /// body with redeemed consent schedules postcommit work. Do not substitute
    /// the consolidatable predicate here: canonical failures must stay loud.
    pub(crate) fn resolved_dreamer_vad_approvals_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pending_ids: impl IntoIterator<Item = EntityId>,
    ) -> Result<Vec<EntityId>> {
        let mut approved = BTreeSet::new();
        for id in pending_ids {
            if self.store.pending_gate_consent_in_txn(txn, &id)?.is_none()
                && self
                    .get_claim_in_txn(txn, &id)?
                    .is_some_and(|body| body.approval == ClaimApprovalStatus::Approved)
            {
                approved.insert(id);
            }
        }
        Ok(approved.into_iter().collect())
    }

    /// Synchronous entry to the canonical claim VAD transaction.
    ///
    /// Call only after any enclosing write transaction has committed. Retrying
    /// with unchanged evidence reuses the active reappraisal state. Admission
    /// errors, including clear-on-decline, are identical to the async entry.
    pub fn consolidate_claim_vad_now(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<ClaimVadConsolidation> {
        self.consolidate_claim_vad_in_txn(claim_id, now)
    }

    fn consolidate_claim_vad_in_txn(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<ClaimVadConsolidation> {
        let mut wtxn = self.store.env.write_txn()?;
        let claim_body = self.claim_body_for_claim_vad_in_txn(&wtxn, claim_id)?;
        if !claim_consolidatable(&claim_body) {
            if claim_body.lifecycle != ClaimLifecycleStatus::Active {
                return Err(Error::Claim(ClaimError::ClaimAlreadyClosed {
                    status: claim_body.lifecycle,
                }));
            }
            let message = if claim_body.stale {
                "claim is stale and not consolidatable"
            } else {
                "claim is not consolidatable"
            };
            self.clear_claim_vad_outputs_in_txn(&mut wtxn, claim_id, now)?;
            wtxn.commit()?;
            return Err(Error::InvalidClaimBody(message));
        }
        if claim_body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE {
            return Err(Error::InvalidClaimBody(
                "claim VAD state claims cannot be consolidated",
            ));
        }
        if claim_body.predicate == VAD_ANNOTATION_CLAIM_PREDICATE {
            return Err(Error::InvalidClaimBody(
                "turn VAD annotation claims cannot be consolidated",
            ));
        }

        let mut evidence_turns = Vec::new();
        for candidate in collect_claim_turn_evidence_refs(&claim_body) {
            if let Some(annotation) = self.turn_vad_annotation_in_txn(&wtxn, &candidate)? {
                evidence_turns.push(ClaimVadTurnEvidence {
                    turn_id: candidate,
                    annotation,
                });
            }
        }

        let (semantic_edges, structural_edges_skipped) =
            self.claim_vad_incident_edges_in_txn(&wtxn, claim_id)?;
        let active_states = self.active_claim_vad_states_in_txn(&wtxn, claim_id)?;
        let mut ops = Vec::new();

        let (vad, reappraisal) = if let Some(vad) = mean_vad(&evidence_turns) {
            vad.validate()?;
            for edge in &semantic_edges {
                ops.push(BatchOp::SetEdgeVad {
                    src: edge.source,
                    kind: edge.kind,
                    tgt: edge.target,
                    vad,
                });
            }

            let value = claim_vad_value(vad, evidence_turns.len());
            let evidence = claim_vad_evidence_value(&evidence_turns);

            let reappraisal = if active_states.len() == 1
                && active_states[0].body.value == value
                && active_states[0].body.evidence.as_ref() == Some(&evidence)
            {
                ClaimVadReappraisal {
                    active_claim_id: Some(active_states[0].id),
                    created_claim_id: None,
                    superseded_claim_ids: Vec::new(),
                }
            } else {
                let state_claim_id = EntityId::now();
                let mut body = ClaimBody::new(
                    CLAIM_VAD_REAPPRAISAL_PREDICATE,
                    ClaimSubject::Entity(*claim_id),
                    value,
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                );
                body.evidence = Some(evidence);
                body.source = Some(ClaimSource::Inferred);
                body.valid_from = Some(now);
                let data = encode_claim_body(&body)?;
                ops.push(BatchOp::Put {
                    id: state_claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: u64::MAX,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                });
                ops.push(BatchOp::Edge {
                    src: state_claim_id,
                    kind: EdgeKind::ClaimOf,
                    tgt: *claim_id,
                    weight: CLAIM_OF_DEFAULT_WEIGHT,
                    vad: Vad::NEUTRAL,
                });

                let superseded_claim_ids = Self::close_claim_vad_states(
                    &mut ops,
                    active_states,
                    now,
                    Some(state_claim_id),
                )?;

                ClaimVadReappraisal {
                    active_claim_id: Some(state_claim_id),
                    created_claim_id: Some(state_claim_id),
                    superseded_claim_ids,
                }
            };

            (Some(vad), reappraisal)
        } else {
            for edge in &semantic_edges {
                ops.push(BatchOp::SetEdgeVad {
                    src: edge.source,
                    kind: edge.kind,
                    tgt: edge.target,
                    vad: Vad::NEUTRAL,
                });
            }

            let superseded_claim_ids =
                Self::close_claim_vad_states(&mut ops, active_states, now, None)?;
            (
                None,
                ClaimVadReappraisal {
                    active_claim_id: None,
                    created_claim_id: None,
                    superseded_claim_ids,
                },
            )
        };

        if !ops.is_empty() {
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
        }
        wtxn.commit()?;

        Ok(ClaimVadConsolidation {
            claim_id: *claim_id,
            vad,
            evidence_turns,
            semantic_edges_updated: semantic_edges.len(),
            structural_edges_skipped,
            reappraisal,
        })
    }

    fn clear_claim_vad_outputs_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        let (semantic_edges, _) = self.claim_vad_incident_edges_in_txn(&*wtxn, claim_id)?;
        let active_states = self.active_claim_vad_states_in_txn(&*wtxn, claim_id)?;
        if semantic_edges.is_empty() && active_states.is_empty() {
            return Ok(());
        }

        let mut ops = Vec::with_capacity(semantic_edges.len() + active_states.len());
        for edge in semantic_edges {
            ops.push(BatchOp::SetEdgeVad {
                src: edge.source,
                kind: edge.kind,
                tgt: edge.target,
                vad: Vad::NEUTRAL,
            });
        }
        Self::close_claim_vad_states(&mut ops, active_states, now, None)?;
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

    fn close_claim_vad_states(
        ops: &mut Vec<BatchOp>,
        active_states: Vec<StoredClaimVadState>,
        now: u64,
        successor: Option<EntityId>,
    ) -> Result<Vec<EntityId>> {
        let mut superseded_claim_ids = Vec::with_capacity(active_states.len());
        for state in active_states {
            let mut closed = state.body;
            closed.lifecycle = ClaimLifecycleStatus::Superseded;
            closed.valid_to = Some(now);
            let closed_data = encode_claim_body(&closed)?;
            ops.push(BatchOp::Put {
                id: state.id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: state.header.occurred_start,
                    end: now,
                },
                learned_at: state.header.learned_at,
                data: closed_data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
            if let Some(successor) = successor {
                ops.push(BatchOp::EdgeWithCreatedAt {
                    src: successor,
                    kind: EdgeKind::Supersedes,
                    tgt: state.id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                });
            }
            superseded_claim_ids.push(state.id);
        }
        Ok(superseded_claim_ids)
    }

    fn claim_body_for_claim_vad_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<ClaimBody> {
        let raw = self
            .store
            .entities
            .get(txn, claim_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
    }

    fn turn_vad_annotation_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        turn_id: &EntityId,
    ) -> Result<Option<VadAnnotation>> {
        let Some(raw) = self.store.entities.get(txn, turn_id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_TURN {
            return Ok(None);
        }

        let claim_id = vad_annotation_claim_id(ENTITY_TYPE_TURN, turn_id)?;
        if let Some(raw) = self.store.entities.get(txn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
                return Ok(None);
            };
            if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
                || body.subject != ClaimSubject::Entity(*turn_id)
            {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            if body.lifecycle != ClaimLifecycleStatus::Active {
                return Ok(None);
            }
            return vad_annotation_from_value(&body.value).map(Some);
        }

        let key = vad_annotation_meta_key(ENTITY_TYPE_TURN, turn_id);
        let Some(raw) = self.store.vault_meta.get(txn, &key)? else {
            return Ok(None);
        };
        let annotation: VadAnnotation =
            rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("VAD annotation"))?;
        annotation.vad.validate()?;
        Ok(Some(annotation))
    }

    fn claim_vad_incident_edges_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<(Vec<EdgeRef>, usize)> {
        let mut seen = std::collections::HashSet::new();
        let mut semantic_edges = Vec::new();
        let mut structural_edges_skipped = 0;

        for (scanned, entry) in self
            .store
            .edges_out
            .prefix_iter(txn, claim_id.as_bytes())?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_vad_incident_edges"));
            }
            let (key, value) = entry?;
            let info = parse_edge_record(&key, &value)?;
            Self::record_claim_vad_edge(
                EdgeRef::new(*claim_id, info.kind, info.target),
                &mut seen,
                &mut semantic_edges,
                &mut structural_edges_skipped,
            );
        }

        for (scanned, entry) in self
            .store
            .edges_in
            .prefix_iter(txn, claim_id.as_bytes())?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_vad_incident_edges"));
            }
            let (key, value) = entry?;
            let info = parse_edge_record(&key, &value)?;
            Self::record_claim_vad_edge(
                EdgeRef::new(info.target, info.kind, *claim_id),
                &mut seen,
                &mut semantic_edges,
                &mut structural_edges_skipped,
            );
        }

        Ok((semantic_edges, structural_edges_skipped))
    }

    fn record_claim_vad_edge(
        edge: EdgeRef,
        seen: &mut std::collections::HashSet<[u8; crate::claim::EDGE_REF_LEN]>,
        semantic_edges: &mut Vec<EdgeRef>,
        structural_edges_skipped: &mut usize,
    ) {
        if !seen.insert(edge.encode()) {
            return;
        }
        if edge_value_layout_for_kind(edge.kind, false) == EdgeValueLayout::Structural {
            *structural_edges_skipped += 1;
        } else {
            semantic_edges.push(edge);
        }
    }

    fn active_claim_vad_states_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<Vec<StoredClaimVadState>> {
        let prefix = edge_kind_prefix(claim_id, EdgeKind::ClaimOf);
        let mut states = Vec::new();
        for (scanned, entry) in self.store.edges_in.prefix_iter(txn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_vad_states"));
            }
            let (key, value) = entry?;
            let state_id = parse_edge_record(&key, &value)?.target;
            let Some(raw) = self.store.entities.get(txn, state_id.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
                && body.subject == ClaimSubject::Entity(*claim_id)
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                states.push(StoredClaimVadState {
                    id: state_id,
                    header,
                    body,
                });
            }
        }
        states.sort_by_key(|state| state.id);
        Ok(states)
    }

    fn annotate_entity_vad(
        &self,
        id: &EntityId,
        expected_type: u8,
        annotation: VadAnnotation,
    ) -> Result<VadAnnotation> {
        annotation.vad.validate()?;
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        let claim_body = vad_annotation_claim_body(id, &annotation);
        let data = encode_claim_body(&claim_body)?;
        validate_claim_body_bytes(&data, false)?;

        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != expected_type {
            return Err(Error::InvalidEntityType(header.entity_type));
        }

        self.guard_vad_annotation_claim_slot(&wtxn, &claim_id, id)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![
                BatchOp::Put {
                    id: claim_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: annotation.annotated_at,
                        end: annotation.annotated_at,
                    },
                    learned_at: annotation.annotated_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                BatchOp::Edge {
                    src: claim_id,
                    kind: EdgeKind::ClaimOf,
                    tgt: *id,
                    weight: CLAIM_OF_DEFAULT_WEIGHT,
                    vad: Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        let key = vad_annotation_meta_key(expected_type, id);
        self.store.vault_meta.delete(&mut wtxn, &key)?;
        wtxn.commit()?;
        Ok(annotation)
    }

    fn guard_vad_annotation_claim_slot(
        &self,
        rtxn: &heed::RwTxn<'_>,
        claim_id: &EntityId,
        annotated_id: &EntityId,
    ) -> Result<()> {
        let Some(raw) = self.store.entities.get(rtxn, claim_id.as_bytes())? else {
            return Ok(());
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvariantViolation(
                "VAD annotation claim id collision",
            ));
        }
        let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
            return Ok(());
        };
        if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
            || body.subject != ClaimSubject::Entity(*annotated_id)
        {
            return Err(Error::InvariantViolation(
                "VAD annotation claim id collision",
            ));
        }
        Ok(())
    }

    fn get_entity_vad_annotation(
        &self,
        id: &EntityId,
        expected_type: u8,
    ) -> Result<Option<VadAnnotation>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != expected_type {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let claim_id = vad_annotation_claim_id(expected_type, id)?;
        if let Some(raw) = self.store.entities.get(&rtxn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            let Some(body) = decode_vad_annotation_claim_body_if_present(&raw)? else {
                return Ok(None);
            };
            if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
                || body.subject != ClaimSubject::Entity(*id)
            {
                return Err(Error::CorruptedIndex("VAD annotation claim"));
            }
            if body.lifecycle != ClaimLifecycleStatus::Active {
                return Ok(None);
            }
            return vad_annotation_from_value(&body.value).map(Some);
        }

        let key = vad_annotation_meta_key(expected_type, id);
        let Some(raw) = self.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        let annotation: VadAnnotation =
            rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("VAD annotation"))?;
        annotation.vad.validate()?;
        Ok(Some(annotation))
    }
}
