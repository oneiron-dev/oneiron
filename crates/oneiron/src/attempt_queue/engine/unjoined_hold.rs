//! The queue's hold on an install born of a restore that has not joined its vault (row
//! RESTORED-UNJOINED-STARTS-NO-WORK; Setting DESIGN pass 15e "Joined"; RULING
//! RESTORED-UNJOINED-OWNER-DIRECT-WORK = A): such a copy starts no work of its own, so no claim
//! leases it a row of a held kind. The row stays ready, passed over as a row of another
//! worker's kind is: no lease and no annotation pause, and the first claim after the copy joins
//! takes it as before, with no restart: the join wakes the queue's observers.
//!
//! Every kind is held but the local and inbound work [`KINDS_KEPT_WHILE_UNJOINED`] names, so a
//! kind added later waits until the join rather than starting on the image. A claim made only
//! to settle its row in the same transaction, with no work started, takes
//! [`AttemptQueue::claim_id_to_settle_in_txn`] and meets no hold.

use crate::error::Result;
use crate::store::Store;

/// The kinds a copy that has not joined still claims: local work and inbound polls, which send
/// nothing, start no agent and run no schedule of the image's (the ruling's "engine housekeeping,
/// sync, pairing and the join door keep running", and inbound polls are no send). A model step
/// is the owner's own live turn or a step of a run that is itself held. A two-way calendar sync
/// writes events out, so it is not kept.
pub(super) const KINDS_KEPT_WHILE_UNJOINED: &[&str] = &[
    crate::model_step_record::MODEL_STEP_ATTEMPT_KIND,
    crate::vault_shape::SHAPE_APPLY_ATTEMPT_KIND,
    crate::vault_shape::SHAPE_ITEM_ATTEMPT_KIND,
    crate::blob_artifact::esign::ESIGN_SEAL_ATTEMPT_KIND,
    crate::calendar::ingest::ICS_POLL_ATTEMPT_KIND,
    crate::calendar::ingest::ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND,
    crate::channel_identity_provider::gmail::GMAIL_INBOX_POLL_ATTEMPT_KIND,
    crate::linkedin_connector::LINKEDIN_INBOX_SYNC_ATTEMPT_KIND,
];

/// One claim's reading of the hold: whether the install is a copy that has not joined, read
/// once, in the claim's own snapshot, on the first row of a held kind it would lease (an install
/// no restore made reads its mark alone), so a claim that leases only kept kinds reads nothing.
#[derive(Debug, Default)]
pub(super) struct UnjoinedHold {
    unjoined: Option<bool>,
}

impl UnjoinedHold {
    /// Whether a row of `kind` waits in `txn`: a held kind on a copy that has not joined.
    ///
    /// # Errors
    /// [`crate::setting::restored::restored_unjoined_in_txn`]'s errors.
    pub(super) fn holds(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        kind: &str,
    ) -> Result<bool> {
        if KINDS_KEPT_WHILE_UNJOINED.contains(&kind) {
            return Ok(false);
        }
        if let Some(unjoined) = self.unjoined {
            return Ok(unjoined);
        }
        let unjoined = crate::setting::restored::restored_unjoined_in_txn(store, txn)?;
        self.unjoined = Some(unjoined);
        Ok(unjoined)
    }
}
