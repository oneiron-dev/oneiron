//! Local, content-bound destructive proposals. Replay never invokes this gate.
use super::{ClaimApprovalStatus, ClaimBody, ClaimSource, encode_claim_body};
use crate::gate::{GateReasonCode, PolicyCriticality};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord};
use crate::write_envelope::WriteEnvelope;
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

const CONTRADICTION_PENDING: &str = "gate.pending.contradiction_closure";

#[derive(Serialize, Deserialize)]
pub(super) enum DeferredAction {
    Supersede { old: [u8; 16], old_hash: [u8; 32] },
    Decay(f32),
    Weaken(f32),
    Stale,
}
#[derive(Serialize, Deserialize)]
pub(super) struct DeferredClaim {
    pub(super) action: DeferredAction,
    pub(super) body_hash: [u8; 32],
    pub(super) frontier: [u8; 32],
    pub(super) critical: bool,
}
fn key(id: &EntityId) -> Vec<u8> {
    let mut key = b"claim.deferred.v1:".to_vec();
    key.extend(id.as_bytes());
    key
}
pub(super) fn body_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    let mut body = body.clone();
    body.approval = ClaimApprovalStatus::Proposed;
    Ok(*blake3::hash(&encode_claim_body(&body)?).as_bytes())
}
pub(super) fn load(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<DeferredClaim>> {
    vault
        .store
        .vault_meta
        .get(txn, &key(id))?
        .map(|raw| rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("deferred claim")))
        .transpose()
}
fn attributed(body: &ClaimBody) -> bool {
    // Explicit human testimony is attributed truth, including legacy unlabelled truth.
    matches!(body.source, None | Some(ClaimSource::UserStated))
        || body.evidence.as_ref().is_some_and(has_attributed_hop)
}
fn has_attributed_hop(value: &rmpv::Value) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            rmpv::Value::Map(rows) => {
                for (key, value) in rows {
                    if matches!(key.as_str(), Some("actor_ref" | "attributed_to")) {
                        return true;
                    }
                    pending.push(value);
                }
            }
            rmpv::Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    false
}
impl Vault {
    /// Read-only projection of the prior head named by a parked replacement.
    pub fn pending_claim_supersession(&self, id: &EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.pending_claim_supersession_in_txn(&txn, id)
    }
    pub(crate) fn pending_claim_supersession_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityId>> {
        if self.store.pending_gate_consent_in_txn(txn, id)?.is_none() {
            return Ok(None);
        }
        match load(self, txn, id)?.map(|row| row.action) {
            Some(DeferredAction::Supersede { old, .. }) => Ok(Some(EntityId::from_bytes(old)?)),
            _ => Ok(None),
        }
    }
    /// Read-only action shown by the existing critical-confirm surface.
    pub fn pending_claim_demotion(
        &self,
        id: &EntityId,
    ) -> Result<Option<super::ClaimDemotionAction>> {
        let txn = self.store.env.read_txn()?;
        if self.store.pending_gate_consent_in_txn(&txn, id)?.is_none() {
            return Ok(None);
        }
        Ok(match load(self, &txn, id)?.map(|row| row.action) {
            Some(DeferredAction::Decay(weight)) => Some(super::ClaimDemotionAction::Decay {
                new_claim_of_weight: weight,
            }),
            Some(DeferredAction::Weaken(confidence)) => Some(super::ClaimDemotionAction::Weaken {
                new_confidence: confidence,
            }),
            Some(DeferredAction::Stale) => Some(super::ClaimDemotionAction::MarkStale),
            _ => None,
        })
    }
    pub(crate) fn has_deferred_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(load(self, txn, id)?.is_some())
    }
    pub(crate) fn deferred_claim_is_supersession_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(load(self, txn, id)?
            .is_some_and(|row| matches!(row.action, DeferredAction::Supersede { .. })))
    }
    pub(crate) fn cancel_deferred_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        self.store.vault_meta.delete(txn, &key(id))?;
        Ok(())
    }

    pub(crate) fn supersession_requires_confirmation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        old: &EntityId,
        new: &ClaimBody,
    ) -> Result<bool> {
        let old = self.require_named_claim_target_active_in(txn, old)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        Ok(attributed(&old)
            || attributed(new)
            || policy.criticality_for_predicate(&old.predicate) == PolicyCriticality::Critical
            || policy.criticality_for_predicate(&new.predicate) == PolicyCriticality::Critical)
    }

    pub(crate) fn stage_claim_supersession_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        new: &EntityId,
        old: &EntityId,
        envelope: &WriteEnvelope,
        now: u64,
    ) -> Result<()> {
        if new == old {
            return Err(Error::Claim(
                crate::error::ClaimError::ClaimSelfSupersession,
            ));
        }
        let old_body = self.require_named_claim_target_active_in(txn, old)?;
        let body = self
            .get_claim_in_txn(txn, new)?
            .ok_or(Error::EntityNotFound)?;
        let held = self.supersession_requires_confirmation_in_txn(txn, old, &body)?;
        if body.approval == ClaimApprovalStatus::Auto
            && !held
            && self.store.pending_gate_consent_in_txn(txn, new)?.is_none()
        {
            self.supersede_claim_in_txn(txn, new, old, now)?;
            return super::supersession_provenance::write_companion(
                self, txn, new, old, &body, &old_body, envelope, now,
            );
        }
        if body.approval != ClaimApprovalStatus::Proposed {
            return Err(Error::InvalidClaimBody(
                "destructive replacement requires a proposed claim",
            ));
        }
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let critical = policy.criticality_for_predicate(&old_body.predicate)
            == PolicyCriticality::Critical
            || policy.criticality_for_predicate(&body.predicate) == PolicyCriticality::Critical;
        let proposal = DeferredClaim {
            action: DeferredAction::Supersede {
                old: *old.as_bytes(),
                old_hash: body_hash(&old_body)?,
            },
            body_hash: body_hash(&body)?,
            frontier: policy.read_frontier_hash()?,
            critical,
        };
        put_pending(self, txn, new, &body, proposal, Some(envelope), now)?;
        super::supersession_provenance::write_coaching(self, txn, new, old, &body, envelope, now)
    }

    /// Called only by explicit local approval/authority settlement doors, never reads/replay.
    pub(crate) fn complete_deferred_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        critical_confirmed: bool,
        now: u64,
    ) -> Result<()> {
        let Some(proposal) = load(self, txn, id)? else {
            return Ok(());
        };
        let body = self
            .get_claim_in_txn(txn, id)?
            .ok_or(Error::EntityNotFound)?;
        if proposal.body_hash != body_hash(&body)?
            || proposal.frontier
                != crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?
        {
            return Err(Error::Gate(crate::error::GateError::GateConsentStale {
                claim_id: *id,
            }));
        }
        if proposal.critical {
            let pending = self
                .store
                .pending_gate_consent_in_txn(txn, id)?
                .ok_or(Error::InvalidClaimBody("critical operation has no binding"))?;
            let encoded = rmp_serde::to_vec_named(&proposal)
                .map_err(|_| Error::InvariantViolation("deferred claim encode"))?;
            let (diff, _) = crate::gate::claim_consent_binding_parts(&self.store, txn, &body)?;
            if pending.diff_handle != critical_diff(&diff, &encoded) {
                return Err(Error::Gate(crate::error::GateError::GateConsentStale {
                    claim_id: *id,
                }));
            }
        }
        if proposal.critical && !critical_confirmed {
            return Err(Error::Gate(crate::error::GateError::GateWriteRejected {
                outcome: "pending",
                reason_codes: vec![GateReasonCode::PendingCriticalityFloor.as_str()],
            }));
        }
        match proposal.action {
            DeferredAction::Supersede { old, old_hash } => {
                let old = EntityId::from_bytes(old)?;
                let old_body = self.require_named_claim_target_active_in(txn, &old)?;
                if body_hash(&old_body)? != old_hash {
                    return Err(Error::Gate(crate::error::GateError::GateConsentStale {
                        claim_id: *id,
                    }));
                }
                if !matches!(
                    body.approval,
                    ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
                ) {
                    return Err(Error::InvalidClaimBody("closure has no approval grant"));
                }
                self.supersede_claim_in_txn(txn, id, &old, now)?;
                self.store.close_pending_gate_consent_in_txn(
                    txn,
                    &old,
                    now,
                    "superseded",
                    vec!["gate.supersede.contradiction_closure".to_owned()],
                    None,
                )?;
                let envelope = super::supersession_provenance::envelope(&body)?;
                super::supersession_provenance::write_companion(
                    self, txn, id, &old, &body, &old_body, &envelope, now,
                )?;
            }
            action => {
                let action = match action {
                    DeferredAction::Decay(weight) => super::ClaimDemotionAction::Decay {
                        new_claim_of_weight: weight,
                    },
                    DeferredAction::Weaken(confidence) => super::ClaimDemotionAction::Weaken {
                        new_confidence: confidence,
                    },
                    DeferredAction::Stale => super::ClaimDemotionAction::MarkStale,
                    DeferredAction::Supersede { .. } => unreachable!(),
                };
                self.apply_claim_demotion_in_txn(txn, id, action, now)?;
            }
        }
        self.store.vault_meta.delete(txn, &key(id))?;
        Ok(())
    }
}

pub(super) fn put_pending(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    proposal: DeferredClaim,
    envelope: Option<&WriteEnvelope>,
    now: u64,
) -> Result<()> {
    let encoded = rmp_serde::to_vec_named(&proposal)
        .map_err(|_| Error::InvariantViolation("deferred claim encode"))?;
    if let Some(existing) = vault.store.vault_meta.get(txn, &key(id))? {
        if existing == encoded {
            return Ok(());
        }
        return Err(Error::Gate(crate::error::GateError::GateConsentStale {
            claim_id: *id,
        }));
    }
    let (mut diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(&vault.store, txn, body)?;
    if proposal.critical {
        diff_handle = critical_diff(&diff_handle, &encoded);
    }
    let reason = if proposal.critical {
        "gate.pending.critical_confirm_attached"
    } else {
        CONTRADICTION_PENDING
    };
    let actor = envelope.map(WriteEnvelope::actor);
    let record = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: "pending".to_owned(),
        reason_codes: vec![reason.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor
            .map_or("system", |actor| actor.actor_class().gate_actor_class())
            .to_owned(),
        actor_ref: actor.map(|actor| actor.entity_ref().to_hex()),
        content_kind: "claim".to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: Some(*id.as_bytes()),
        grant_ref: None,
        diff_handle: diff_handle.clone(),
        read_frontier_hash,
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    let run = envelope.and_then(|envelope| match envelope.provenance().value() {
        rmpv::Value::Map(rows) => rows
            .iter()
            .find(|(key, _)| key.as_str() == Some("run"))
            .and_then(|(_, value)| value.as_str())
            .map(str::to_owned),
        _ => None,
    });
    vault.store.put_pending_gate_consent_in_txn(
        txn,
        &PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *id.as_bytes(),
            decision_id: record.decision_id,
            created_at: now,
            diff_handle,
            read_frontier_hash,
            reason_codes: vec![reason.to_owned()],
            dreamer_run_id: run,
        },
    )?;
    vault.store.vault_meta.put(txn, &key(id), &encoded)?;
    Ok(())
}

fn critical_diff(body_diff: &[u8], action: &[u8]) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.critical-claim-action.v1");
    hash.update(body_diff);
    hash.update(action);
    hash.finalize().as_bytes().to_vec()
}
