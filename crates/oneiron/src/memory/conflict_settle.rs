//! The authorised responder's door to a parked contradiction (OF-023).
//!
//! The vault's root owner, authenticated, settles any open conflict. Anyone
//! else needs a named owner-delegated `memory.conflict_review` Grant on the
//! conflict's subject, the verb the resident dispute door reviews under; a
//! person also authenticates. A decision ladder's answer is never that
//! authority: the Dreamer settles only what its own delegation covers. The
//! marker reads and settlement mechanics live beside the markers, in
//! `crate::dreamer_consolidation::settle`.

use super::authorship::*;
use super::{Memory, MemoryResult};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{
    ConflictSettleReceipt, ConflictSettlement, OpenConflict, apply_settlement_in_txn,
    open_conflict_in_txn, open_conflicts_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::{EntityId, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

const VERB: &str = "memory.conflict_review";
const KIND: &str = "conflict_settlement";
const REASON: &str = "gate.memory.conflict_settlement";

impl Memory<'_> {
    /// The open conflicts this caller may settle, on `subject` alone when one
    /// is named, oldest marker first, at most `limit`. The owner sees every
    /// one; a delegate sees those its Grant covers.
    pub fn open_conflicts(
        &self,
        reviewer: Option<&AuthenticatedOwner>,
        subject: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<Vec<OpenConflict>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let owner = self.conflict_responder_is_owner(&txn, reviewer)?;
        let mut open = Vec::new();
        for conflict in open_conflicts_in_txn(self.vault, &txn, subject)? {
            if open.len() >= limit {
                break;
            }
            if owner
                || self
                    .conflict_review_grant(&txn, conflict.subject)?
                    .is_some()
            {
                open.push(conflict);
            }
        }
        Ok(open)
    }

    /// Settles the open conflict `marker` in ONE transaction: rechecks the
    /// responder's authority and that the marker is still unanswered, applies
    /// `settlement`, and appends the Gate receipt naming the responder and any
    /// Grant it acted under. A person's answer is user-stated and approved; an
    /// agent's is generated and Auto.
    pub fn settle_conflict(
        &self,
        reviewer: Option<&AuthenticatedOwner>,
        marker: EntityId,
        settlement: ConflictSettlement,
        now: u64,
    ) -> MemoryResult<ConflictSettleReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            let owner = self.conflict_responder_is_owner(txn, reviewer)?;
            let conflict = open_conflict_in_txn(self.vault, txn, marker)?;
            let grant_ref = if owner {
                None
            } else {
                Some(
                    self.conflict_review_grant(txn, conflict.subject)?
                        .ok_or_else(|| authority_denied("no named conflict review Grant"))?,
                )
            };
            let actor = WriteActor::new(self.actor, self.actor_class);
            let person = self.actor_class == EdgeActorClass::Human;
            let mut provenance = vec![
                (Value::from("surface"), Value::from(KIND)),
                (
                    Value::from("openMarker"),
                    Value::Binary(marker.as_bytes().to_vec()),
                ),
            ];
            if let Some(reviewer) = reviewer {
                provenance.push((
                    Value::from("ownerAuthentication"),
                    Value::from(reviewer.decision_id().to_hex()),
                ));
            }
            if let Some(grant) = &grant_ref {
                provenance.push((Value::from("grant"), Value::from(grant.as_str())));
            }
            let envelope = WriteEnvelope::new(
                actor,
                if person {
                    ClaimSource::UserStated
                } else {
                    ClaimSource::Generated
                },
                WriteProvenance::new(Value::Map(provenance))?,
                if person {
                    ClaimApprovalStatus::Approved
                } else {
                    ClaimApprovalStatus::Auto
                },
            );
            let settled = apply_settlement_in_txn(
                self.vault,
                txn,
                &conflict,
                settlement,
                &envelope,
                (!owner).then_some(actor),
                person,
                now,
            )?;
            let mut receipt = decision(
                actor,
                KIND,
                "approved",
                REASON,
                Some(settled.resolved),
                marker.as_bytes().to_vec(),
                now,
            );
            receipt.grant_ref = grant_ref;
            self.vault
                .store
                .append_gate_decision_in_txn(txn, &receipt)?;
            Ok(ConflictSettleReceipt {
                marker,
                settlement,
                resolved: settled.resolved,
                superseded: settled.superseded,
                receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
            })
        })
    }

    /// Whether this caller answers as the vault's root owner. An
    /// authentication must name this bound, live person; without one the
    /// caller is never the owner, and a person must authenticate at all.
    fn conflict_responder_is_owner(
        &self,
        txn: &heed::RoTxn<'_>,
        reviewer: Option<&AuthenticatedOwner>,
    ) -> Result<bool, Error> {
        let Some(reviewer) = reviewer else {
            if self.actor_class == EdgeActorClass::Human {
                return Err(authority_denied(
                    "a person settles a conflict with their authentication",
                ));
            }
            verify_live_actor(
                self.vault,
                txn,
                WriteActor::new(self.actor, self.actor_class),
            )?;
            return Ok(false);
        };
        if self.actor != reviewer.revalidate_person_in_txn(self.vault, txn)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied(
                "review authentication must name the bound human",
            ));
        }
        verify_live_actor(
            self.vault,
            txn,
            WriteActor::new(self.actor, EdgeActorClass::Human),
        )?;
        is_root_owner(self.vault, txn, self.actor)
    }

    /// The owner-delegated Grant that lets this caller review conflicts on
    /// `subject`, if one is live.
    fn conflict_review_grant(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: EntityId,
    ) -> Result<Option<String>, Error> {
        let required = action_bound(
            self.vault,
            txn,
            WriteActor::new(self.actor, self.actor_class),
            VERB,
            subject,
        )?;
        delegated_grant(self.vault, txn, &required)
    }
}
