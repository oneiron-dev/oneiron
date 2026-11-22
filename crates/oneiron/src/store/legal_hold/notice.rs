//! What a cooperative restriction tells a reader: absence while it stands.

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

impl Store {
    /// The refusal a named write of `record` meets while a cooperative
    /// restriction keeps it from use: absence while it stands, `None` once
    /// none does.
    pub(crate) fn use_restricted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &EntityId,
    ) -> Result<Option<Error>> {
        cooperative_refusal_in_txn(self, txn, record)
    }
}

fn cooperative_refusal_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<Error>> {
    Ok(
        super::cooperative_restriction_active_in_txn(store, txn, record)?
            .then_some(Error::EntityNotFound),
    )
}
