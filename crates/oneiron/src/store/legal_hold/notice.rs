//! What a hold's refusals tell the owner (WILL-PLAN L01 rows 01 and 03). A
//! customer hold refuses as it always has, with no hosted-law bound. A host
//! order refuses nothing: what it covers is in its clone, in the host's
//! separate legal-hold store (LEGAL-HOLD-USE = B as a clone, owner
//! 2026-11-05). A record a hosted privacy erasure kept serves only the
//! purpose of the customer holds that keep it, for as long as one stands
//! (C6, FIX 8849).

use heed::RoTxn;

use super::{USE_LIMITS, holds_on_in_txn};
use crate::deletion::{LEGAL_HOLD_REFUSAL, LegalHold, LegalHoldTarget};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;
use crate::store::Store;

/// The refusal a destroying path meets on what standing customer holds keep:
/// the named refusal. Only customer holds keep records in the vault, so no
/// refusal names an order's law or defers in an order's silence.
pub(super) fn held_refusal() -> Error {
    Error::InvalidConfig(LEGAL_HOLD_REFUSAL.to_owned())
}

/// Whether `hold` keeps a record a hosted privacy erasure kept for its own
/// purpose only (C6, FIX 8849): every hold that keeps vault data, a standing
/// customer hold. A host order keeps none, whatever its own terms say: those
/// terms stay the order's data and bind its clone.
pub(super) fn restricts_use(hold: &LegalHold) -> bool {
    hold.keeps_vault_data()
}

/// The standing holds on `record` that keep it for their purpose only: its
/// use limit lasts until the last of them lifts, narrows or lapses.
pub(super) fn retaining_holds_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Vec<LegalHold>> {
    Ok(
        holds_on_in_txn(dbs, txn, &LegalHoldTarget::Record(*record))?
            .into_iter()
            .filter(restricts_use)
            .collect(),
    )
}

impl Store {
    /// The refusal a named write of `record` meets while it is kept from use
    /// (C6, WILL-PLAN L01 row 03): absence while a customer hold keeps it.
    /// `None` once no standing customer hold keeps it, whatever its marker
    /// says.
    pub(crate) fn use_restricted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &EntityId,
    ) -> Result<Option<Error>> {
        if !USE_LIMITS.contains(self, txn, record)? {
            return cooperative_refusal_in_txn(self, txn, record);
        }
        let holds = retaining_holds_in_txn(self, txn, record)?;
        if holds.is_empty() {
            return cooperative_refusal_in_txn(self, txn, record);
        }
        Ok(Some(Error::EntityNotFound))
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
