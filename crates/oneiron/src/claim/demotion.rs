//! Critical demotion proposals and the transactional monotonic demotion state machine.
use super::*;
use crate::batch::BatchOp;
use crate::edge::{EdgeKind, validate_edge_weight};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;
impl Vault {
    /// Demotes the active claim `claim_id` one rung — decay, weaken, or mark
    /// stale — in ONE write transaction, and returns the rung and the claim
    /// that now carries it. Rungs only ever move forward: a decay after a
    /// weaken or a stale rung rejects with [`Error::InvalidClaimBody`].
    ///
    /// Each rung writes as ARCH-0003's change policy says. Decay sets the
    /// claim_of edge weight in place and the stale mark is an in-place flag. A
    /// weakening changes belief, so it supersedes: a successor claim at the
    /// lower confidence closes `claim_id`, which stays readable as history.
    pub fn apply_claim_demotion(
        &self,
        claim_id: &EntityId,
        action: ClaimDemotionAction,
        now: u64,
    ) -> Result<ClaimDemotion> {
        let mut wtxn = self.store.env.write_txn()?;
        let (body, _) = self.claim_for_lifecycle_in(&wtxn, claim_id)?;
        Self::require_active_claim(&body)?;
        match action {
            ClaimDemotionAction::Decay {
                new_claim_of_weight,
            } => validate_edge_weight(new_claim_of_weight)?,
            ClaimDemotionAction::Weaken { new_confidence }
                if !new_confidence.is_finite() || !(0.0..=1.0).contains(&new_confidence) =>
            {
                return Err(Error::InvalidClaimBody(
                    "confidence must be finite in [0, 1]",
                ));
            }
            _ => {}
        }
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        if policy.criticality_for_predicate(&body.predicate)
            == crate::gate::PolicyCriticality::Critical
        {
            let deferred_action = match action {
                ClaimDemotionAction::Decay {
                    new_claim_of_weight,
                } => super::deferred::DeferredAction::Decay(new_claim_of_weight),
                ClaimDemotionAction::Weaken { new_confidence } => {
                    super::deferred::DeferredAction::Weaken(new_confidence)
                }
                ClaimDemotionAction::MarkStale => super::deferred::DeferredAction::Stale,
            };
            // The target body stays untouched while the bound human action waits.
            super::deferred::put_pending(
                self,
                &mut wtxn,
                claim_id,
                &body,
                super::deferred::DeferredClaim {
                    action: deferred_action,
                    body_hash: super::deferred::body_hash(&body)?,
                    frontier: policy.read_frontier_hash()?,
                    critical: true,
                },
                None,
                now,
            )?;
            wtxn.commit()?;
            return Err(Error::Gate(crate::error::GateError::GateWriteRejected {
                outcome: "pending",
                reason_codes: vec![crate::gate::GateReasonCode::PendingCriticalityFloor.as_str()],
            }));
        }
        let next = self.apply_claim_demotion_in_txn(&mut wtxn, claim_id, action, now)?;
        wtxn.commit()?;
        Ok(next)
    }

    pub(crate) fn apply_claim_demotion_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim_id: &EntityId,
        action: ClaimDemotionAction,
        now: u64,
    ) -> Result<ClaimDemotion> {
        let (mut body, header) = self.claim_for_lifecycle_in(&*wtxn, claim_id)?;
        Self::require_active_claim(&body)?;
        let rung = claim_demotion_rung(&body)?;
        // Only decay and the stale mark write in place; a weakening returns
        // from its arm once its successor has superseded the claim.
        let (next, edge_update, kind, delta) = match action {
            ClaimDemotionAction::Decay {
                new_claim_of_weight,
            } => {
                validate_edge_weight(new_claim_of_weight)?;
                if matches!(
                    rung,
                    Some(ClaimDemotionRung::Weakened | ClaimDemotionRung::Stale)
                ) {
                    return Err(Error::InvalidClaimBody("decay is out of order"));
                }
                let ClaimSubject::Entity(subject) = body.subject else {
                    return Err(Error::InvalidClaimBody("decay requires entity subject"));
                };
                let mut found = None;
                for entry in self.port_edges(
                    &*wtxn,
                    claim_id,
                    EdgeDirection::Out,
                    Some(EdgeKind::ClaimOf),
                    None,
                )? {
                    let edge = entry?;
                    if edge.target == subject {
                        if found.is_some() {
                            return Err(Error::InvalidClaimBody("duplicate ClaimOf edge"));
                        }
                        found = Some(edge.weight);
                    }
                }
                let current = found.ok_or(Error::InvalidClaimBody("ClaimOf edge missing"))?;
                if new_claim_of_weight > current {
                    return Err(Error::InvalidEdgeWeight {
                        value: new_claim_of_weight,
                    });
                }
                (
                    ClaimDemotionRung::Decayed,
                    Some((subject, new_claim_of_weight)),
                    super::transition::ClaimTransitionKind::Decay,
                    super::transition::TransitionDelta::ClaimOfWeight(new_claim_of_weight),
                )
            }
            ClaimDemotionAction::Weaken { new_confidence } => {
                if !matches!(
                    rung,
                    Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened)
                ) {
                    return Err(Error::InvalidClaimBody("weaken requires decayed rung"));
                }
                if !new_confidence.is_finite() || !(0.0..=1.0).contains(&new_confidence) {
                    return Err(Error::InvalidClaimBody(
                        "confidence must be finite in [0, 1]",
                    ));
                }
                if new_confidence > body.confidence {
                    return Err(Error::InvalidClaimBody("confidence increase"));
                }
                let successor = EntityId::now();
                crate::batch::ClaimMaterialization::apply_successor(
                    self,
                    wtxn,
                    claim_id,
                    &successor,
                    super::ClaimSuccession::Weakening {
                        confidence: new_confidence,
                    },
                    now,
                )?;
                self.supersede_claim_in_txn(wtxn, &successor, claim_id, now)?;
                return Ok(ClaimDemotion {
                    rung: ClaimDemotionRung::Weakened,
                    claim: successor,
                });
            }
            ClaimDemotionAction::MarkStale => {
                if rung != Some(ClaimDemotionRung::Weakened) {
                    return Err(Error::InvalidClaimBody("stale requires weakened rung"));
                }
                body.stale = true;
                (
                    ClaimDemotionRung::Stale,
                    None,
                    super::transition::ClaimTransitionKind::Stale,
                    super::transition::TransitionDelta::None,
                )
            }
        };
        let scope = match body.scope.take() {
            None => vec![(
                Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
                Value::from(match next {
                    ClaimDemotionRung::Decayed => "decayed",
                    ClaimDemotionRung::Weakened => "weakened",
                    ClaimDemotionRung::Stale => "stale",
                }),
            )],
            Some(Value::Map(mut entries)) => {
                entries.retain(|(k, _)| k.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
                entries.push((
                    Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
                    Value::from(match next {
                        ClaimDemotionRung::Decayed => "decayed",
                        ClaimDemotionRung::Weakened => "weakened",
                        ClaimDemotionRung::Stale => "stale",
                    }),
                ));
                entries
            }
            Some(_) => return Err(Error::InvalidClaimBody("scope must be a map")),
        };
        body.scope = Some(Value::Map(scope));
        if crate::authority::machine_claim_needs_history(&self.store, wtxn, &body)? {
            body = super::transition::stage_owner_machine_transition(
                self, wtxn, *claim_id, kind, delta, now,
            )?;
        }
        let data = encode_claim_body(&body)?;
        let mut ops = vec![BatchOp::Put {
            id: *claim_id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: now,
            },
            learned_at: header.learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        if let Some((subject, weight)) = edge_update {
            ops.push(BatchOp::SetEdgeWeight {
                src: *claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight,
            });
        }
        crate::batch::ClaimMaterialization::apply_demotion(self, wtxn, ops)?;
        Ok(ClaimDemotion {
            rung: next,
            claim: *claim_id,
        })
    }
}
