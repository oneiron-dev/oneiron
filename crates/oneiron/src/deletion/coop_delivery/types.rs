//! Core half of `deletion::coop_delivery::types`: its store-layer items live in `oneiron_store::deletion::coop_delivery::types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::coop_delivery::types::*;

use super::CooperativeDeletionDeliveryStatus;
use crate::deletion::{LegalHold, LegalHoldKind};
use crate::store::legal_hold as hold_store;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::deletion::coop_delivery::types::{
    CooperativeDeletionDisposition, CooperativeLocalRedaction,
};

#[doc(hidden)]
pub use oneiron_verb_wire::deletion::coop_delivery::types::CooperativeDeletionDispositionKind;

/// One filed ask, for the recipient owner's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingCooperativeDeletion {
    /// The ask's nonce, hex.
    pub request_id: String,
    /// The pact, hex.
    pub connection_id: String,
    pub requester_vault_id: String,
    /// The worlds named, hex; none asks about everything the pact delivered.
    pub worlds: Vec<String>,
    pub epoch_cutoff: u64,
    /// The requester's clock when it signed.
    pub requested_at: u64,
    pub received_at: u64,
    /// The signed ask exactly as received.
    pub request: Vec<u8>,
    pub disposition: Option<CooperativeDeletionDisposition>,
    /// Delivery of the owner's answer back to the requester, once one is queued.
    pub reply_status: Option<CooperativeDeletionDeliveryStatus>,
    pub reply_started_at: Option<u64>,
    /// Every customer hold an answer to this ask placed or kept, a later
    /// choice's and an earlier one's alike (FIX 2924).
    pub courtesy_hold_ids: Vec<EntityId>,
    /// Records this ask has restricted; markers say which remain active.
    pub courtesy_restriction_records: Vec<EntityId>,
    /// Prior external-notice attestations, kept across later choices.
    pub restriction_lifts: Vec<CooperativeRestrictionLiftAttestation>,
    /// Local selected-field receipts retained across later choices.
    pub local_redactions: Vec<CooperativeLocalRedaction>,
}

/// What the owner chose for one filed ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionAnswer {
    pub kind: CooperativeDeletionDispositionKind,
    pub reason_code: Option<String>,
    pub review_at: Option<u64>,
    /// Under a delete choice, the records to hard-delete, each once in the
    /// order first named. Each goes through the owner's delete rail, one by
    /// one, once no legal hold keeps any of them.
    pub delete: Vec<EntityId>,
    /// Under a legal hold choice, this vault's records to hold, each once.
    /// They take one customer hold, written with the answer.
    pub hold: Vec<EntityId>,
    /// Under retain-under-basis, the copies, basis code and retention class.
    pub retention: Option<CooperativeDeletionRetention>,
    /// Under restrict-pending-review, copies to place or refresh. Other
    /// restrictions remain until explicitly lifted with prior-notice attestation.
    pub restrict: Vec<EntityId>,
    /// The owner attests the requester was already told externally before
    /// lifting these copies' restrictions under this ask only.
    pub restriction_notice_given: Vec<EntityId>,
    /// Under Redact, exact value-map fields on covered CLAIM copies.
    pub redact: Vec<CooperativeClaimValueRedaction>,
}

impl Vault {
    /// The courtesy holds `ids` name, each as its customer hold row reads
    /// now: standing or lifted, with what it names (FIX 2924). `None` once
    /// that row is gone, as a released hold's row ages out. Only customer
    /// rows are read: a host order is never named here.
    ///
    /// # Errors
    /// Storage errors.
    pub fn courtesy_holds(&self, ids: &[EntityId]) -> Result<Vec<(EntityId, Option<LegalHold>)>> {
        let txn = self.store.env.read_txn()?;
        ids.iter()
            .map(|id| {
                let hold = hold_store::hold_in_txn(&self.store, &txn, id)?
                    .filter(|hold| hold.kind == LegalHoldKind::Customer);
                Ok((*id, hold))
            })
            .collect()
    }
}
