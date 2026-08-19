//! `Vault` claim write doors: the public `put_claim` family, the
//! crate-private reserved-namespace door, the candidate door batch.rs uses,
//! and the code-run trap variants with their write-gate checks.

use super::*;
use crate::Vault;
use crate::affect::Vad;
use crate::batch::{
    ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops, apply_ops_with_gate_mode,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::validate_actor_class;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, SUPERSEDES_DEFAULT_WEIGHT};
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

impl Vault {
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
}
