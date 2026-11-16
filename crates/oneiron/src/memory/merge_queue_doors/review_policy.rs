//! `vault.code.merge_queue.review_policy.get` and `.set` (FIX 8268): the
//! vault's one opt-in review policy for merge queue work. With none set the
//! same checked queue lands inherited work on green (CALL
//! `REVIEW_POLICY_DEFAULT`); while one is set, that work waits for its
//! critics or the owner's Approve. `.set` with `null` clears it.
//!
//! Who may call: every live Owner, co-Owners included, by his own proof
//! from any linked surface, revalidated in the door's own snapshot; or the
//! caller's own live agent Grant from an Owner that lists the row's verb,
//! vault-wide, judged by L02's
//! [`Vault::admit_queue_review_policy_in_txn`](crate::Vault). Grants are
//! never unioned and the host root alone admits no one. `.get` never
//! refuses an Owner, a row that does not read included: it shows it as
//! unreadable with the mode inherited work is in. `.set` writes in the same
//! writer that admits, then wakes the queue's drain, so a clear releases
//! inherited waits at once.

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::consent::AuthenticatedOwner;
use crate::merge_queue::{
    QueueReviewDefault, QueueReviewPolicy, REVIEW_POLICY_DEFAULT, StoredQueueReviewPolicy,
    review_policy_unreadable_hold,
};
use crate::{EdgeActorClass, EntityId};

/// The Scope verb a Grant lists for the read row.
const GET_VERB: &str = "vault.code.merge_queue.review_policy.get";
/// The Scope verb a Grant lists for the set row.
const SET_VERB: &str = "vault.code.merge_queue.review_policy.set";

/// Who calls a review policy door, as its host bound it.
#[derive(Debug, Clone)]
pub enum QueueReviewPolicyProof {
    /// A live Owner's proof, naming this handle's own human actor.
    Owner(AuthenticatedOwner),
    /// This handle's own actor, admitted by one live Grant in the door's
    /// snapshot. It carries no actor, Grant id or authority.
    Grant,
}

#[doc(hidden)]
pub use oneiron_verb_wire::memory::merge_queue_doors::review_policy::{
    QueueReviewMode, QueueReviewPolicyInput, QueueReviewPolicySetRequest, QueueReviewPolicyState,
    QueueReviewPolicyView,
};

/// The view of `stored`.
fn policy_view(stored: StoredQueueReviewPolicy) -> QueueReviewPolicyView {
    match stored {
        StoredQueueReviewPolicy::Absent => QueueReviewPolicyView {
            state: QueueReviewPolicyState::Absent,
            mode: match REVIEW_POLICY_DEFAULT {
                QueueReviewDefault::LandOnGreen => QueueReviewMode::LandOnGreen,
            },
            policy: None,
            hold: None,
        },
        StoredQueueReviewPolicy::Set(active) => QueueReviewPolicyView {
            state: QueueReviewPolicyState::Set,
            mode: QueueReviewMode::Review,
            policy: Some(active.policy),
            hold: None,
        },
        StoredQueueReviewPolicy::Unreadable => QueueReviewPolicyView {
            state: QueueReviewPolicyState::Unreadable,
            mode: QueueReviewMode::Held,
            policy: None,
            hold: Some(review_policy_unreadable_hold()),
        },
    }
}

impl Memory<'_> {
    /// An embedded handle's caller: the vault owner's proof when the handle
    /// is the embedded owner's, else the handle's own actor under its Grant.
    pub fn merge_queue_review_policy_proof(&self, verb: &str) -> QueueReviewPolicyProof {
        self.embedded_owner(verb)
            .map_or(QueueReviewPolicyProof::Grant, QueueReviewPolicyProof::Owner)
    }

    /// `vault.code.merge_queue.review_policy.get`: the vault's review policy
    /// and the mode inherited queue work is in. Writes nothing.
    pub fn merge_queue_review_policy_get_as(
        &self,
        proof: &QueueReviewPolicyProof,
    ) -> MemoryResult<QueueReviewPolicyView> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.review_policy_caller_in_txn(&txn, proof, GET_VERB)?;
        Ok(policy_view(self.vault.queue_review_policy_in_txn(&txn)?))
    }

    /// `vault.code.merge_queue.review_policy.set`: sets the vault's review
    /// policy, or with `null` clears it, in the writer that admits its
    /// caller, then wakes the queue's drain. No seed, no history row and no
    /// floor on its limits; a catalog is validated as every catalog is.
    pub fn merge_queue_review_policy_set_as(
        &self,
        proof: &QueueReviewPolicyProof,
        input: QueueReviewPolicySetRequest,
    ) -> MemoryResult<QueueReviewPolicyView> {
        if let Some(policy) = &input.policy {
            crate::critic::triage_critiques(&policy.catalog, &[], &[]).map_err(|error| {
                MemoryError::bad_request(format!(
                    "the review policy's lens catalog does not validate: {error}"
                ))
            })?;
        }
        let mut txn = self
            .vault
            .store
            .env
            .write_txn()
            .map_err(crate::Error::from)?;
        let actor = self.review_policy_caller_in_txn(&txn, proof, SET_VERB)?;
        let set_at = self.vault.instant_in_txn(&txn)?.secs();
        let row = input.policy.map(|policy| QueueReviewPolicy {
            catalog: policy.catalog,
            thresholds: policy.thresholds,
            set_by: Some(actor),
            set_at,
        });
        self.vault
            .put_queue_review_policy_in_txn(&mut txn, row.as_ref())?;
        let stored = self.vault.queue_review_policy_in_txn(&txn)?;
        txn.commit().map_err(crate::Error::from)?;
        // The queue's drain wakes on it: a clear releases inherited waits.
        self.vault.store.notify_attempt_observers();
        Ok(policy_view(stored))
    }

    /// The caller of `verb` in `txn`: a live Owner whose proof names this
    /// handle's own human actor, or this handle's own actor under its one
    /// vault-wide Grant listing `verb`.
    fn review_policy_caller_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &QueueReviewPolicyProof,
        verb: &str,
    ) -> MemoryResult<EntityId> {
        match proof {
            QueueReviewPolicyProof::Owner(owner) => {
                let actor = owner.revalidate_in_txn(self.vault, txn)?;
                if actor != self.actor || self.actor_class != EdgeActorClass::Human {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("{verb} acts as the authenticated Owner"),
                        &["Present the Owner's own verified, unattenuated credential."],
                    ));
                }
                Ok(actor)
            }
            QueueReviewPolicyProof::Grant => match self.vault.admit_queue_review_policy_in_txn(
                txn,
                self.actor,
                self.actor_class,
                verb,
            )? {
                Ok(_grant) => Ok(self.actor),
                Err(reason) => Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    format!("{reason} ({verb})"),
                    &[
                        "Call as a live Owner, or have an Owner grant this agent the verb by name \
                         in a Grant without repo bounds.",
                    ],
                )),
            },
        }
    }
}
