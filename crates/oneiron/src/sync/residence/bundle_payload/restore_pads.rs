//! A kit restore's pads (PAD-1, the narrow kit hook agreed with L03): the
//! pad object's pads land after the base windows, which carry none and whose
//! replacement could tear a pad landed before it, and before every world
//! section that opens with them. A key current retirement names here (its
//! world's keys destroyed, its pad row hard-erased, or current custody
//! retired it) is out of the view that both the pad landing and the kit's
//! section opening read, so no kept object brings back what an erase
//! retired (restricts, ruled). Once the pads land,
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
    /// After the base windows and before the world keys and sections, less
    /// the keys current retirement names then; the section opening reads the
    /// same view. Each key is decided apart: one found retired goes whatever
    /// another's read did, and one whose retirement does not read stays, as
    /// today, warned.
    AfterBaseWindowsLessCurrentRetirement,
}

const KIT_PAD_ORDER: KitPadOrder = KitPadOrder::AfterBaseWindowsLessCurrentRetirement;

/// Drops from `pads` each key current retirement names in `vault` now
/// ([`KIT_PAD_ORDER`]).
pub(super) fn admit_kit_pads(vault: &Vault, pads: &mut OpenedKeyPads) {
    match KIT_PAD_ORDER {
        KitPadOrder::AfterBaseWindowsLessCurrentRetirement => {}
    }
    let retired = retired_keys(vault, pads);
    if !retired.is_empty() {
        pads.retain_keys(|key| !retired.contains(key));
    }
}

/// The keys of `pads` an affirmative current retirement in `vault` names,
/// each decided apart: any one of its checks that reads retired retires it,
/// whatever the others' reads did. A key none of whose checks reads retired
/// while one did not read is kept, warned.
fn retired_keys(vault: &Vault, pads: &OpenedKeyPads) -> BTreeSet<WorldKeyId> {
    let mut retired = BTreeSet::new();
    let txn = match vault.store.env.read_txn() {
        Ok(txn) => txn,
        Err(error) => {
            warn_undecided(&error.into());
            return retired;
        }
    };
    for key in pads.keys() {
        let item = key.envelope_key_id();
        let checks: [Result<bool>; 3] = [
            world_keys_destroyed_in_txn(&vault.store, &txn, key.world),
            pad_row_erased_in_txn(&vault.store, &txn, &item),
            vault
                .store
                .world_pad_custody_entry(&item)
                .map(|custody| matches!(custody, WorldPadCustody::Retired)),
        ];
        if checks.iter().any(|check| matches!(check, Ok(true))) {
            retired.insert(*key);
        } else if let Some(Err(error)) = checks.iter().find(|check| check.is_err()) {
            warn_undecided(error);
        }
    }
    retired
}

/// A key whose retirement did not read: it stays in the view, as today.
fn warn_undecided(error: &crate::error::Error) {
    tracing::warn!(
        kind = ?error.kind(),
        "a kit restore's pad retirement did not read for a key; its pad restores as it is"
    );
}

/// Reconciles, now a kit's pads landed, every restore epoch of `vault` that
/// still owes a pad, then drops the carried pads (PAD-3) none owes once that
/// committed. A fault leaves each as recorded, warned.
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
        return;
    }
    if let Err(error) = crate::recovery::checkpoint::prune_carried_pads(vault) {
        tracing::warn!(kind = ?error.kind(), "carried world pads not pruned after a kit restore");
    }
}
