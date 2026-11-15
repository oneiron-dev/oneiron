//! The store's catalogue keys (DESIGN 15-setting-primitive): the owner's retrieval-policy pins.

use crate::Vault;
use crate::error::Result;
use crate::setting::{Kind, Restore, SettingChange};
use crate::store::RetrievalPolicyPins;

/// The pins' hook: holds the served blend weights to the pins now in force, in the write that
/// changed them, as the pins' own door did.
fn hold_weights_to_pins(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    let pins = RETRIEVAL_POLICY_PINS
        .read_in_dbs_txn(&vault.store, txn, &[], None)?
        .value;
    vault.store.hold_weights_to_pins_in_txn(txn, &pins)?;
    Ok(())
}

crate::setting::setting_keys! {
    /// The owner's pins over the retrieval blend weights: a pinned signal's share stays at its
    /// value, and learned updates move only the unpinned remainder. A change holds the served
    /// weights to the new pins in its own write. The pins go with the weights they hold through
    /// a restore, so it gives back one weight state (FIX 22408).
    pub(crate) RETRIEVAL_POLICY_PINS: RetrievalPolicyPins = "retrieval.policy_pins" {
        kind: Kind::new(RetrievalPolicyPins::default),
        restore: Restore::Content,
        on_change: Some(hold_weights_to_pins),
    };
}
