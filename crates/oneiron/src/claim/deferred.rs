//! Local, content-bound destructive proposals. Replay never invokes this gate.
use super::{ClaimApprovalStatus, ClaimBody, ClaimSource, encode_claim_body};
use crate::gate::{GateReasonCode, PolicyCriticality};
use crate::side_table::{Named, SideTable};
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
impl DeferredAction {
    /// A decay or the stale mark only restricts the claim it rewrites, so it
    /// settles on a held machine history; every other action waits for it.
    fn demotes_in_place(&self) -> bool {
        matches!(self, Self::Decay(_) | Self::Stale)
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct DeferredClaim {
    pub(super) action: DeferredAction,
    pub(super) body_hash: [u8; 32],
    pub(super) frontier: [u8; 32],
    pub(super) critical: bool,
}

/// A destructive claim action parked behind unresolved gate consent. Key: id16.
const DEFERRED: SideTable<EntityId, DeferredClaim, Named> =
    SideTable::new(&crate::side_table::CLAIM_DEFERRED);

pub(super) fn body_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    let mut body = body.clone();
    body.approval = ClaimApprovalStatus::Proposed;
    Ok(*blake3::hash(&encode_claim_body(&body)?).as_bytes())
}
/// Whether a destructive action is parked on `id`, behind the confirm its tray
/// row shows.
pub(crate) fn claim_has_deferred_action_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(DEFERRED.get(store, txn, id)?.is_some())
}

pub(super) fn load(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<DeferredClaim>> {
    DEFERRED.get(&vault.store, txn, id)
}
fn attributed(body: &ClaimBody) -> bool {
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
    /// A parked decay or stale mark: a restriction written in place.
    pub(crate) fn deferred_claim_is_in_place_demotion_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(load(self, txn, id)?.is_some_and(|row| row.action.demotes_in_place()))
    }
    pub(crate) fn cancel_deferred_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        DEFERRED.delete(&self.store, txn, id)?;
        Ok(())
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
        if body.approval != ClaimApprovalStatus::Proposed {
            return Err(Error::InvalidClaimBody(
                "destructive replacement requires a proposed claim",
            ));
        }
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        // Only a class a manifest rule declares critical holds the closure
        // for the owner; the critical default of a predicate no rule names
        // does not stop the write (ARCH-0003 §Criticality, ARCH-0057).
        let critical = policy.declares_predicate_critical(&old_body.predicate)
            || policy.declares_predicate_critical(&body.predicate);
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
        if critical || attributed(&old_body) || attributed(&body) {
            super::supersession_provenance::write_coaching(
                self, txn, new, old, &body, envelope, now,
            )?;
        }
        Ok(())
    }

    /// Re-evaluate an ordinary parked replacement for Auto and close the
    /// prior only after that grant, in the same write transaction. A class a
    /// manifest rule declares critical, or attributed truth, still needs the
    /// owner-confirmation door.
    pub fn grant_deferred_claim_auto(&self, id: &EntityId, now: u64) -> Result<()> {
        self.grant_deferred_claim_auto_with_checker(id, now, None)
    }

    /// The same content-bound Auto grant with the host's bounded checker.
    /// The ordinary claim gate decides whether this particular write needs it.
    pub fn grant_deferred_claim_auto_with_checker(
        &self,
        id: &EntityId,
        now: u64,
        checker: Option<&crate::llm::BoundedAutoChecker>,
    ) -> Result<()> {
        self.grant_deferred_claim_auto_after(id, now, checker, |_| Ok(()), |_| Ok(()))
    }

    /// The same grant, once `precheck` passes inside its transaction: the
    /// Dreamer's live source pins, so a replacement whose cited words moved
    /// after it was staged closes nothing. `then` runs last in the same
    /// transaction, so it reads exactly what the grant wrote.
    pub(crate) fn grant_deferred_claim_auto_after(
        &self,
        id: &EntityId,
        now: u64,
        checker: Option<&crate::llm::BoundedAutoChecker>,
        precheck: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
        then: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        // Read on the calling thread: a grouped commit may run the closure elsewhere.
        let auto_write_rate = crate::own_rate::auto_write_rate();
        // The checker's turn, waited for before the write opens (FIX 8751). A
        // grant names no caller principal, so it waits under its claim's key.
        let checker = checker
            .map(|checker| checker.admit_for_writes(&self.store, *id))
            .transpose()?;
        let checker = checker.as_ref();
        let decision = self.with_write_txn_grouped(|txn| {
            precheck(txn)?;
            let proposal = load(self, txn, id)?.ok_or(Error::EntityNotFound)?;
            let DeferredAction::Supersede { old, old_hash } = proposal.action else {
                return Err(Error::InvalidClaimBody("not a deferred supersession"));
            };
            let old = EntityId::from_bytes(old)?;
            let prior = self.require_named_claim_target_active_in(txn, &old)?;
            let body = self
                .get_claim_in_txn(txn, id)?
                .ok_or(Error::EntityNotFound)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            let parked = self.store.pending_gate_consent_in_txn(txn, id)?;
            // The Dreamer actor that parked this replacement, from the parking
            // decision it wrote; `None` for anything a Dreamer run did not park.
            let dreamer_writer = match parked.as_ref() {
                Some(pending) if pending.dreamer_run_id.is_some() => self
                    .store
                    .gate_decision_in_txn(txn, pending.decision_id)?
                    .and_then(|record| record.actor_ref)
                    .and_then(|actor| EntityId::from_hex(&actor).ok()),
                _ => None,
            };
            if proposal.body_hash != body_hash(&body)?
                || proposal.frontier != policy.read_frontier_hash()?
                || old_hash != body_hash(&prior)?
                || parked.is_none()
            {
                return Err(Error::Gate(crate::error::GateError::GateConsentStale {
                    claim_id: *id,
                }));
            }
            if proposal.critical || attributed(&prior) || attributed(&body) {
                return Err(Error::Gate(crate::error::GateError::GateWriteRejected {
                    outcome: "pending",
                    reason_codes: vec![GateReasonCode::PendingCriticalityFloor.as_str()],
                }));
            }
            let decision = crate::batch::ClaimMaterialization::apply_deferred_auto_grant(
                self, txn, id, checker,
            )?;
            let closure_decision =
                self.complete_deferred_claim_with_checker_in_txn(txn, id, false, now, checker)?;
            // FIX 5993: a granted commitment series projects from its grant.
            self.index_consented_commitment_series_in_txn(txn, &body, id, now)?;
            // A Dreamer replacement granted Auto is an Auto write like any the
            // Dreamer lands, through whichever door granted it, so it counts on
            // that actor's own-rate window. The count never holds the grant.
            if let Some(actor) = dreamer_writer {
                crate::own_rate::count_in_txn(
                    &self.store,
                    txn,
                    crate::own_rate::OwnRateKind::AutoWrite,
                    actor,
                    self.store.clock.now_recorded_at(),
                    auto_write_rate,
                )?;
                #[cfg(test)]
                crate::own_rate::counted_auto_write(crate::own_rate::AutoWriteDoor::DeferredGrant);
            }
            then(txn)?;
            Ok((decision, closure_decision))
        })?;
        for receipt in [decision.0, decision.1].into_iter().flatten() {
            receipt.record_metrics(&self.store.diagnostics.gate);
        }
        Ok(())
    }

    /// Re-parks `pending`'s deferred action under the policy now in force:
    /// the deferred door's fresh verdict (its `critical` flag) becomes a new
    /// pending decision, and the row and its consent bind to the current
    /// frontier. Nothing is applied; a verdict that would now let the action
    /// through still waits for its grant or the owner. Returns whether the
    /// verdict is the one the row was parked under, or `None` when the row
    /// cannot be re-gated (its claim, or the prior it closes, does not read).
    pub(crate) fn restage_deferred_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        pending: &PendingGateConsentRecord,
        now: u64,
    ) -> Result<Option<bool>> {
        let id = EntityId::from_bytes(pending.claim_id)?;
        let Some(proposal) = load(self, txn, &id)? else {
            return Ok(None);
        };
        let Some(body) = crate::gate::readable(self.get_claim_in_txn(txn, &id))? else {
            return Ok(None);
        };
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let critical = match &proposal.action {
            DeferredAction::Supersede { old, .. } => {
                let old = EntityId::from_bytes(*old)?;
                let Some(old_body) = crate::gate::readable(self.get_claim_in_txn(txn, &old))?
                else {
                    return Ok(None);
                };
                policy.declares_predicate_critical(&old_body.predicate)
                    || policy.declares_predicate_critical(&body.predicate)
            }
            // The demotion door's own test (`apply_claim_demotion`).
            _ => policy.criticality_for_predicate(&body.predicate) == PolicyCriticality::Critical,
        };
        let same = critical == proposal.critical && pending.reason_codes == [reason(critical)];
        let parked_by = self.store.gate_decision_in_txn(txn, pending.decision_id)?;
        let parker = Parker {
            actor_class: parked_by
                .as_ref()
                .map_or_else(|| "system".to_owned(), |record| record.actor_class.clone()),
            actor_ref: parked_by.and_then(|record| record.actor_ref),
            run: pending.dreamer_run_id.clone(),
            // A re-staged row is a new pending decision, so a critical
            // confirm it newly needs gets its whole window.
            created_at: if same { pending.created_at } else { now },
        };
        let restaged = DeferredClaim {
            frontier: policy.read_frontier_hash()?,
            critical,
            ..proposal
        };
        DEFERRED.delete(&self.store, txn, &id)?;
        park(self, txn, &id, &body, restaged, parker, now)?;
        Ok(Some(same))
    }

    /// Called only by explicit local approval/authority settlement doors, never reads/replay.
    pub(crate) fn complete_deferred_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        critical_confirmed: bool,
        now: u64,
    ) -> Result<()> {
        self.complete_deferred_claim_with_checker_in_txn(txn, id, critical_confirmed, now, None)
            .map(|_| ())
    }

    fn complete_deferred_claim_with_checker_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        critical_confirmed: bool,
        now: u64,
        checker: Option<&crate::llm::BoundedAutoChecker>,
    ) -> Result<Option<crate::gate::RecordedClaimGateDecision>> {
        let Some(proposal) = load(self, txn, id)? else {
            return Ok(None);
        };
        let body = if proposal.action.demotes_in_place() {
            self.claim_for_restriction_in_txn(txn, id)?
        } else {
            self.get_claim_in_txn(txn, id)?
        }
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
        let closure_decision = match proposal.action {
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
                let decision =
                    self.supersede_granted_deferred_claim_in_txn(txn, id, &old, now, checker)?;
                self.store.close_pending_gate_consent_in_txn(
                    txn,
                    id,
                    now,
                    "superseded",
                    vec!["gate.supersede.contradiction_closure".to_owned()],
                    None,
                )?;
                let envelope = super::supersession_provenance::envelope(&body)?;
                super::supersession_provenance::write_companion(
                    self, txn, id, &old, &body, &old_body, &envelope, now,
                )?;
                decision
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
                None
            }
        };
        DEFERRED.delete(&self.store, txn, id)?;
        Ok(closure_decision)
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
    if let Some(existing) = DEFERRED.get(&vault.store, txn, id)? {
        let existing_encoded = rmp_serde::to_vec_named(&existing)
            .map_err(|_| Error::InvariantViolation("deferred claim encode"))?;
        if existing_encoded == encoded {
            return Ok(());
        }
        return Err(Error::Gate(crate::error::GateError::GateConsentStale {
            claim_id: *id,
        }));
    }
    let actor = envelope.map(WriteEnvelope::actor);
    let parker = Parker {
        actor_class: actor
            .map_or("system", |actor| actor.actor_class().gate_actor_class())
            .to_owned(),
        actor_ref: actor.map(|actor| actor.entity_ref().to_hex()),
        run: envelope.and_then(|envelope| match envelope.provenance().value() {
            rmpv::Value::Map(rows) => rows
                .iter()
                .find(|(key, _)| key.as_str() == Some("run"))
                .and_then(|(_, value)| value.as_str())
                .map(str::to_owned),
            _ => None,
        }),
        created_at: now,
    };
    park(vault, txn, id, body, proposal, parker, now)
}

/// Who parked a deferred action, the run review it shows in, and when.
struct Parker {
    actor_class: String,
    actor_ref: Option<String>,
    run: Option<String>,
    created_at: u64,
}

fn reason(critical: bool) -> &'static str {
    if critical {
        "gate.pending.critical_confirm_attached"
    } else {
        CONTRADICTION_PENDING
    }
}

/// Parks `proposal` behind a fresh pending decision bound to the current
/// policy frontier.
fn park(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    proposal: DeferredClaim,
    parker: Parker,
    now: u64,
) -> Result<()> {
    let encoded = rmp_serde::to_vec_named(&proposal)
        .map_err(|_| Error::InvariantViolation("deferred claim encode"))?;
    let (mut diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(&vault.store, txn, body)?;
    if proposal.critical {
        diff_handle = critical_diff(&diff_handle, &encoded);
    }
    let reason = reason(proposal.critical);
    let record = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: "pending".to_owned(),
        reason_codes: vec![reason.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: parker.actor_class,
        actor_ref: parker.actor_ref,
        content_kind: "claim".to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: Some(*id.as_bytes()),
        grant_ref: None,
        diff_handle: diff_handle.clone(),
        read_frontier_hash,
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    vault.store.put_pending_gate_consent_in_txn(
        txn,
        &PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *id.as_bytes(),
            decision_id: record.decision_id,
            created_at: parker.created_at,
            diff_handle,
            read_frontier_hash,
            reason_codes: vec![reason.to_owned()],
            dreamer_run_id: parker.run,
        },
    )?;
    DEFERRED.put(&vault.store, txn, id, &proposal)?;
    Ok(())
}

fn critical_diff(body_diff: &[u8], action: &[u8]) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.critical-claim-action.v1");
    hash.update(body_diff);
    hash.update(action);
    hash.finalize().as_bytes().to_vec()
}
