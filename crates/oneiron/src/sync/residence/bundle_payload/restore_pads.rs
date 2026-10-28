//! A kit restore's pads (PAD-1, the narrow kit hook agreed with L03): the
//! pad object's pads land before the base windows import, and a key current
//! retirement names here (its world's keys destroyed, its pad row
//! hard-erased, or current custody retired it) is out of the view that both
//! the pad landing and the kit's section opening read, so no kept object
//! brings back what an erase retired (restricts, ruled). Once the pads land,
//! every restore epoch that still owes one is reconciled through the shared
//! resolver; a kit import makes no epoch. A fault reading retirement keeps
//! the view as it was, warned: the kit and seed alone still restore.

use std::collections::BTreeSet;

use crate::Vault;
use crate::error::Result;
use crate::store::WorldPadCustody;
use crate::world_keys::{
    OpenedKeyPads, WorldKeyId, pad_row_erased_in_txn, world_keys_destroyed_in_txn,
};

/// When a kit restore lands its pads, and which (CALLS: PAD-1 kit pad
/// order).
enum KitPadOrder {
    /// Before the base windows, less the keys current retirement names; the
    /// section opening reads the same view, checked again after the
    /// windows. A fault reading retirement keeps the view as it was.
    BeforeWindowsLessCurrentRetirement,
}

const KIT_PAD_ORDER: KitPadOrder = KitPadOrder::BeforeWindowsLessCurrentRetirement;

/// Drops from `pads` each key current retirement names in `vault` now
/// ([`KIT_PAD_ORDER`]).
pub(super) fn admit_kit_pads(vault: &Vault, pads: &mut OpenedKeyPads) {
    match KIT_PAD_ORDER {
        KitPadOrder::BeforeWindowsLessCurrentRetirement => {}
    }
    match retired_keys(vault, pads) {
        Ok(retired) if !retired.is_empty() => pads.retain_keys(|key| !retired.contains(key)),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "a kit restore's pad retirement did not read; its pads restore as they are"
        ),
    }
}

/// The keys of `pads` an affirmative current retirement in `vault` names.
fn retired_keys(vault: &Vault, pads: &OpenedKeyPads) -> Result<BTreeSet<WorldKeyId>> {
    let txn = vault.store.env.read_txn()?;
    let mut retired = BTreeSet::new();
    for key in pads.keys() {
        let item = key.envelope_key_id();
        if world_keys_destroyed_in_txn(&vault.store, &txn, key.world)?
            || pad_row_erased_in_txn(&vault.store, &txn, &item)?
            || matches!(
                vault.store.world_pad_custody_entry(&item)?,
                WorldPadCustody::Retired
            )
        {
            retired.insert(*key);
        }
    }
    Ok(retired)
}

/// Reconciles, now a kit's pads landed, every restore epoch of `vault` that
/// still owes a pad. A fault leaves each as recorded, warned.
pub(super) fn reconcile_owed_epochs(vault: &Vault) {
    let reconciled = vault.with_write_txn_grouped(|txn| {
        crate::recovery::checkpoint::reconcile_restore_pad_notes_in_txn(
            vault,
            txn,
            None,
            &BTreeSet::new(),
        )
    });
    if let Err(error) = reconciled {
        tracing::warn!(
            kind = ?error.kind(),
            "a kit restore's owed pads did not reconcile; each epoch stays as recorded"
        );
    }
}
