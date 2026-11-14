//! The owner's payment marks on custody records (L8-60): one row per record
//! he answered for, saying whether it is a payment credential, with the Gate
//! receipt of the act that set it. Custody's payment door
//! (`secret_custody::payment_credential`) sets and reads them; an erase
//! drops a record's mark with its row.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// One custody record's payment mark. Key: id16 (the custody record id).
pub(crate) const PAYMENT_MARK: SideTable<EntityId, SecretPaymentMark, Named> =
    SideTable::new(&side_table::SECRET_PAYMENT_MARK);

/// The owner's stored answer on one custody record: whether it is a payment
/// credential, and the Gate receipt of the act that set it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPaymentMark {
    pub payment: bool,
    pub receipt: String,
}

/// Drops the payment mark on the custody record `custody`, whose row is
/// being erased: the mark must not survive it.
pub(crate) fn erase_secret_payment_mark_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    custody: &EntityId,
) -> Result<()> {
    PAYMENT_MARK.delete(store, wtxn, custody)?;
    Ok(())
}
