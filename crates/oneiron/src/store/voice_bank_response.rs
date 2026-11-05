//! The voice reference bank's rows as a store-layer response hook: the bank's seven
//! tables by declaration, and the engine operations the store layer calls.

use heed::RoTxn;

use crate::error::Result;
use crate::side_table::SideTableDecl;
use crate::store::{ResponseOwners, ResponseScan, Store};

/// The bank's seven tables, by declaration.
fn tables() -> [&'static SideTableDecl; 7] {
    [
        &crate::side_table::VOICE_OWNER_REF,
        &crate::side_table::VOICE_REF_IDENTITY,
        &crate::side_table::VOICE_REF_INCARNATION,
        &crate::side_table::VOICE_REF_TARGET,
        &crate::side_table::VOICE_REF_RENDER_CONSENT,
        &crate::side_table::VOICE_REF_RENDER_EVENT,
        &crate::side_table::VOICE_OWNER_REF_OWNER_INDEX,
    ]
}

/// Whether the full `vault_meta` key `key` is a row of the bank.
pub(crate) fn voice_bank_row(key: &[u8]) -> bool {
    tables().iter().any(|decl| key.starts_with(decl.prefix))
}

/// The engine's voice bank response operations the store layer calls. A store holds
/// one implementation from the moment it is assembled (see
/// [`crate::store::StoreHooks`]). Each method is the engine operation of the
/// same name; each store-layer caller calls it at the point, with the
/// arguments and in the order it called the engine operation before.
pub(crate) trait StoreVoiceBankResponse: Send + Sync {
    /// The engine's `voice_identity::ref_bank::voice_bank_scan`: what a
    /// checkpoint carries of the bank row `key` holding `value`.
    fn voice_bank_scan(&self, key: &[u8], value: &[u8]) -> ResponseScan;

    /// The engine's `voice_identity::ref_bank::voice_bank_owners`: who owns
    /// the bank row `key` holding `value`, as far as the bank proves it.
    fn voice_bank_owners(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<ResponseOwners>;
}
