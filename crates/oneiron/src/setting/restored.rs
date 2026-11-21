//! An install born of a restore that has not joined its vault (stage 7c-4; DESIGN 1.6,
//! "Restore"). A copy restored into an empty place is no machine of its vault until a joined
//! machine's entry descends from its enrolment, or the owner's act joins it (row
//! RESTORED-COPIES-ENROL-EACH-OTHER, `authority::restored_join`). Until then every stored row of
//! the image is a bound on the default the vault accepted and nothing more (the read walk's
//! [`RowReading::Bounds`]), and it changes no `sync: vault` setting (the set door). A direct
//! restore leaves the image's `sync: install` rows behind with its machine identity
//! ([`restore_drops_row`]), and so does an activated archive ([`drop_install_rows_in_txn`]). No
//! row is deleted to hold it back: once the copy joins, every row reads current.

use oneiron_setting_contract::RowKey;

use super::read::{CONTENT_ROWS, ROWS};
use super::{SettingScope, SettingSpec, SettingSync, spec_named};
use crate::error::Result;
use crate::side_table::{self, SideTableDbs};
use crate::store::Store;

/// The set door's refusal of a change to a `sync: vault` key on an install born of a restore that
/// has not joined.
pub(super) const RESTORED_NOT_JOINED_CHANGE: &str = "this install was restored from a checkpoint \
     and has not joined the vault, so it changes no setting the vault's machines share: a machine \
     of the vault that has joined must pair it, or, when no other machine is left, the owner joins \
     it here with an owner key";

/// How a read weighs the stored rows it loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RowReading {
    /// As a machine of its vault reads them: an owner pin releases the rows below it, and the
    /// vault's value row starts the walk in place of the default.
    Current,
    /// As an install born of a restore that has not joined reads them: each row is a bound on
    /// the accepted default and nothing more. A pin is read as a value row, so it releases
    /// nothing.
    Bounds,
}

/// How a read of `spec` in `txn` weighs its rows: [`RowReading::Bounds`] for a `sync: vault`
/// key on an install born of a restore that has not joined ([`restored_unjoined_in_txn`]), else
/// [`RowReading::Current`]. A `sync: install` key's rows are this install's own: the restore
/// left the image's behind.
pub(super) fn row_reading_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<RowReading> {
    Ok(
        if spec.sync == SettingSync::Vault && restored_unjoined_in_txn(dbs, txn)? {
            RowReading::Bounds
        } else {
            RowReading::Current
        },
    )
}

/// Whether the install whose side databases `dbs` holds was born of a restore of a vault a root
/// roots and is no machine of it yet: its restored-from mark stands, and it has no machine id or
/// the vault's fold holds no machine under it. The machine doors' test
/// (`authority::machine_identity::restored_install_refusal`), in the caller's snapshot: it folds
/// through the snapshot's cached fold and writes nothing. An install with no mark reads its mark
/// alone. A vault no root roots has no machine to join, so its copy reads as it is. A target that
/// holds no install rows (no `sync_state`: an open gate, a dry run's ledger) was born of no
/// restore; one that holds the mark but no store whose log it can fold reads as not joined, the
/// stricter reading.
///
/// # Errors
///
/// An install row that does not decode (`CorruptedIndex`); the fold's errors; storage errors.
pub(super) fn restored_unjoined_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<bool> {
    if dbs.side_sync_state_opt().is_none()
        || crate::store::install_identity::restored_from_image_in_dbs_txn(dbs, txn)?.is_none()
    {
        return Ok(false);
    }
    let Some(store) = dbs.side_owning_store() else {
        return Ok(true);
    };
    let fold = crate::authority::authority_view_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    if fold.vault_id.is_none() {
        return Ok(false);
    }
    Ok(
        crate::store::install_identity::machine_id_in_dbs_txn(dbs, txn)?
            .is_none_or(|machine| fold.machine(machine).is_none()),
    )
}

/// Whether a restore that leaves the image's machine identity behind leaves this `SETTING` or
/// `SETTING_CONTENT` row (`full_key`, with its table's prefix) behind too: a value, pin or carried
/// row of a `sync: install` key, a choice about the install that set it (DESIGN 1.6, "Restore").
/// The accepted default (a `Pack` row) stays: its pack's head names it, so the new machine starts
/// at the defaults rather than at a lost one. A row whose key this build does not know stays: no
/// row says what it is about.
pub(crate) fn restore_drops_row(full_key: &[u8]) -> bool {
    [&side_table::SETTING, &side_table::SETTING_CONTENT]
        .iter()
        .find_map(|decl| full_key.strip_prefix(decl.prefix))
        .is_some_and(install_choice)
}

/// Whether the `SETTING` or `SETTING_CONTENT` row of `key` (without its table's prefix) is a
/// choice about the install that set it, as [`restore_drops_row`] reads one.
pub(super) fn install_choice(key: &[u8]) -> bool {
    RowKey::decode(key)
        .filter(|key| !matches!(key.scope, SettingScope::Pack(_)))
        .and_then(|key| spec_named(&key.name).ok())
        .is_some_and(|spec| spec.sync == SettingSync::Install)
}

/// Deletes, in `wtxn`, every `SETTING` and `SETTING_CONTENT` row of `store` that
/// [`restore_drops_row`] names: a vault that forgets its machine and joins as a new one
/// (`identity::drop_machine_identity_in_txn`), as an archive the owner activates beside its
/// replacement does (`Vault::activate_archived`), leaves the choices about the install it was,
/// as a direct restore leaves an image's behind (row SETTING-ACTIVATE-ARCHIVED-INSTALL-ROWS).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn drop_install_rows_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    for table in [ROWS, CONTENT_ROWS] {
        for key in table.scan_keys(store, wtxn, &[])? {
            if install_choice(&key) {
                table.delete(store, wtxn, &key)?;
            }
        }
    }
    Ok(())
}
