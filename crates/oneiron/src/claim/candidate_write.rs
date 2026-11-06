//! Canonical claim edits return the row that actually landed.

use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};
use crate::{EntityId, TimeRange, Vault};
use rmpv::Value;

impl Vault {
    pub(super) fn apply_candidate_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![
                BatchOp::ClaimCandidate {
                    id,
                    candidate: Box::new(candidate),
                    envelope: envelope.clone(),
                    occurred,
                    learned_at,
                    internal_lexical_query_hint: false,
                },
                BatchOp::ReconcileLexicalQueryHints {
                    source: id,
                    keep: Vec::new(),
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, true).with_source_in_gate_input(),
        )
    }

    /// A semantic edit of an active, non-MACHINE evidence claim retains the
    /// original and returns its successor. Stable state and non-semantic
    /// updates keep their requested id. The landing and both writes share
    /// one transaction; neither a refused birth nor a refused close commits.
    pub(crate) fn put_claim_candidate_with_landing_returning_actual(
        &self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        landing: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<EntityId> {
        crate::batch::reject_family_owned_candidate(&candidate)?;
        let mut txn = self.store.env.write_txn()?;
        let rekeys = crate::channel_identity::AssignmentRekeys::begin(&self.store);
        landing(&txn)?;
        self.validate_code_run_claim_target_in_txn(&txn, id, Some(candidate.predicate()))?;
        crate::memory::guard_existing_claim_in_txn(self, &txn, envelope.actor(), *id)?;
        let successor = self.candidate_semantic_successor_in_txn(&txn, id, &candidate, envelope)?;
        let (actual, candidate) = match successor {
            Some((prior, next)) => {
                Self::require_source_trust_supersession_rights(&next, &prior)?;
                let fresh = EntityId::now();
                if self.store.port_entity_present(&txn, &fresh)? {
                    return Err(Error::InvariantViolation("claim successor id is occupied"));
                }
                self.validate_code_run_claim_target_in_txn(
                    &txn,
                    &fresh,
                    Some(candidate.predicate()),
                )?;
                crate::memory::guard_existing_claim_in_txn(self, &txn, envelope.actor(), fresh)?;
                // Scope stamps are data, not authority. The ordinary native
                // candidate gate still judges the complete resulting body.
                (
                    fresh,
                    candidate.with_scope_stamps(next.scope_facet, next.scope_project),
                )
            }
            None => (*id, candidate),
        };
        self.apply_candidate_in_txn(&mut txn, actual, candidate, envelope, occurred, learned_at)?;
        if actual != *id {
            self.supersede_claim_in_txn_as(
                &mut txn,
                &actual,
                id,
                learned_at,
                Some(envelope.actor()),
            )?;
        }
        rekeys.finish(&self.store, &mut txn)?;
        txn.commit()?;
        self.store.notify_proactivity_changes();
        Ok(actual)
    }

    fn candidate_semantic_successor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        candidate: &ClaimCandidate,
        envelope: &WriteEnvelope,
    ) -> Result<Option<(ClaimBody, ClaimBody)>> {
        if envelope.machine_signature().is_some() {
            return Ok(None);
        }
        let Some(raw) = self.store.port_entity_raw(txn, id)? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(None);
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        let Ok(prior) =
            crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
        else {
            return Ok(None);
        };
        if prior.lifecycle != ClaimLifecycleStatus::Active
            || (prior.predicate == candidate.predicate()
                && stable_state_predicate(&prior.predicate))
            || crate::authority::machine_claim_needs_history(&self.store, txn, &prior)?
        {
            return Ok(None);
        }
        let facet =
            crate::batch::claim_candidate_apply::claim_candidate_birth_facet(&self.store, txn, id)?;
        let next = candidate.clone().into_claim_body(envelope, facet)?;
        if same_candidate_semantics(&prior, &next)? {
            Ok(None)
        } else {
            Ok(Some((prior, next)))
        }
    }
}

fn stable_state_predicate(predicate: &str) -> bool {
    // Hook bindings and connector subscriptions share the first predicate;
    // VAD annotations have a derived id. Their readers use those stable ids.
    matches!(predicate, "agent.connector_subscription" | "affect.vad")
}

fn same_candidate_semantics(prior: &ClaimBody, next: &ClaimBody) -> Result<bool> {
    Ok(prior.predicate == next.predicate
        && prior.subject == next.subject
        && value_bytes(&prior.value)? == value_bytes(&next.value)?
        && prior.confidence.to_bits() == next.confidence.to_bits()
        && prior.world.unwrap_or_else(crate::claim::base_world_id)
            == next.world.unwrap_or_else(crate::claim::base_world_id)
        && prior.rel == next.rel
        && prior.scope.as_ref().map(value_bytes).transpose()?
            == next.scope.as_ref().map(value_bytes).transpose()?
        && prior.scope_facet == next.scope_facet
        && prior.scope_project == next.scope_project
        && prior.salience.map(f32::to_bits) == next.salience.map(f32::to_bits))
}

fn value_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("claim value encoding"))?;
    Ok(bytes)
}
