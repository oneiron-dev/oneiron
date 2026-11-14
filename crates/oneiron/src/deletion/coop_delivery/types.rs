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
    CooperativeDeletionDisposition, CooperativeLocalRedaction, IncomingCooperativeDeletion,
};

#[doc(hidden)]
pub use oneiron_verb_wire::deletion::coop_delivery::types::CooperativeDeletionDispositionKind;

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
