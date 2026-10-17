//! The authorised responder's door to a parked contradiction (OF-023).
//!
//! The vault's root owner, authenticated, settles any open conflict. Anyone
//! else needs a named owner-delegated `memory.conflict_review` Grant on the
//! conflict's subject or on the whole vault, the verb the resident dispute
//! door reviews under; a person also authenticates. A decision ladder's
//! answer is never that authority: the Dreamer settles only what its own
//! delegation covers, and only the owner's explicit act mints one. The
//! marker reads and settlement mechanics live beside the markers, in
//! `crate::dreamer_consolidation::settle`.

use super::authorship::*;
use super::{Memory, MemoryResult};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::dreamer_consolidation::{
    ConflictReviewScope, ConflictSettleReceipt, ConflictSettlement, OpenConflict,
    apply_settlement_in_txn, open_conflict_in_txn, open_conflicts_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::{EntityId, Vault, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

const VERB: &str = "memory.conflict_review";
/// A whole-vault review Grant's one selector, before the vault's root id:
/// no subject's id spells it.
const VAULT_SELECTOR: &str = "vault:";
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
    /// `subject`, its own or the whole vault's, if one is live.
    fn conflict_review_grant(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: EntityId,
    ) -> Result<Option<String>, Error> {
        let actor = WriteActor::new(self.actor, self.actor_class);
        for scope in [
            ConflictReviewScope::Subject(subject),
            ConflictReviewScope::Vault,
        ] {
            let required = review_bound(self.vault, txn, actor, scope)?;
            if let Some(grant) = delegated_grant(self.vault, txn, &required)? {
                return Ok(Some(grant));
            }
        }
        Ok(None)
    }

    /// Lets `delegate` settle the open conflicts `scope` covers: a standing
    /// Grant only the authenticated root owner mints, returned by its ref.
    /// Nothing mints one by default, so the Dreamer settles nothing until
    /// the owner acts (DEC-0006: a grant is never inferred).
    pub fn grant_conflict_review(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        scope: ConflictReviewScope,
    ) -> MemoryResult<String> {
        self.with_verified_actor_write_txn(|txn| {
            self.conflict_review_owner(txn, owner)?;
            verify_live_actor(self.vault, txn, delegate)?;
            let bound = review_bound(self.vault, txn, delegate, scope)?;
            let grant_ref = bound.digest().to_hex();
            self.vault.create_standing_grant_in_txn(txn, owner, bound)?;
            Ok(grant_ref)
        })
    }

    /// Ends the Grant [`Self::grant_conflict_review`] minted for `delegate`
    /// on exactly `scope`; false when none was live. Ending the whole
    /// vault's leaves each subject's own Grant standing.
    pub fn revoke_conflict_review(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        scope: ConflictReviewScope,
    ) -> MemoryResult<bool> {
        self.with_verified_actor_write_txn(|txn| {
            self.conflict_review_owner(txn, owner)?;
            let grant_ref = review_bound(self.vault, txn, delegate, scope)?
                .digest()
                .to_hex();
            Ok(self
                .vault
                .revoke_consent_grant_in_txn(txn, owner, &grant_ref)?
                .is_some())
        })
    }

    /// The owner proof must name this bound person, who owns the vault now.
    fn conflict_review_owner(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<(), Error> {
        if self.actor != verify_owner(self.vault, txn, owner)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied("owner proof must name the bound caller"));
        }
        Ok(())
    }
}

/// The bound a `memory.conflict_review` Grant on `scope` carries, for
/// `actor`: a subject's names that subject, the whole vault's names
/// [`VAULT_SELECTOR`] and its root. Both target the vault root.
fn review_bound(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    scope: ConflictReviewScope,
) -> Result<GrantBound, Error> {
    match scope {
        ConflictReviewScope::Subject(subject) => action_bound(vault, txn, actor, VERB, subject),
        ConflictReviewScope::Vault => {
            let root = root_id(vault, txn)?;
            GrantBound::action(
                ActorBound::new(actor.entity_ref().to_hex())?
                    .with_actor_class(actor.actor_class().gate_actor_class())?,
                ActionClass::new(VERB)?,
                ActionEnvelope::new([format!("{VAULT_SELECTOR}{root}")])?.with_target(root)?,
            )
        }
    }
}
