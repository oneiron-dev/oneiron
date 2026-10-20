//! Legal holds across a restore and against backup expiry (OF-470;
//! ARCH-0038 #legal-hold: every path that destroys bytes reads a hold).
//!
//! A host order and its host-only log are runtime rows no image carries
//! (`tiers`), so an owner's backup never holds one. A restore that takes a
//! live vault's place, or makes a copy beside it, takes on that vault's whole
//! host-order family: rows, target index, log and erase links, so an order
//! Oneiron must keep never lapses because content came back from an image. A
//! restore with no live vault (a clean host, a wake, a migration) has nowhere
//! to read them: the host carries them itself, from
//! [`Vault::carried_host_order_holds`] before to
//! [`Vault::install_carried_host_order_holds`]
//! after, never inside an owner's artifact.
//!
//! A backup holds every record its image carries, so while any hold stands,
//! customer or host order, none expires ([`Vault::legal_hold_keeps_backups`]).
//! An expiry that unlinks reads the holds under the LMDB writer and unlinks
//! inside it ([`Vault::with_backup_hold_exclusion`]): a hold placed meanwhile
//! commits before the read or after the unlink, never between (FIX 1488).
//! Each committed release, and each maintenance pass, bumps one content-free
//! counter ([`Vault::backup_hold_rechecks`]), so a delete a hold deferred
//! asks again.

use serde::{Deserialize, Serialize};

use super::CanonicalRows;
use crate::{Result, Vault};

/// One vault's host-order legal holds as rows, for a host to carry across a
/// restore with no live vault. Host-only: never an owner's to read.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostOrderHolds {
    rows: CanonicalRows,
}

impl std::fmt::Debug for HostOrderHolds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostOrderHolds({} rows)", self.rows.len())
    }
}

/// Puts a live vault's host-order rows among an image's `vault_meta` rows, in
/// key order, in place of any there.
pub(super) fn carry(
    databases: &mut std::collections::BTreeMap<String, CanonicalRows>,
    host_rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    let rows = databases
        .get_mut("vault_meta")
        .ok_or_else(super::codec_error)?;
    let mut merged: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = std::mem::take(rows)
        .into_iter()
        .filter(|(key, _)| !key.starts_with(super::tiers::HOST_HOLD_PREFIX))
        .collect();
    merged.extend(host_rows.iter().cloned());
    *rows = merged.into_iter().collect();
    Ok(())
}

/// [`carry`] from the live vault `current`, read now.
pub(super) fn carry_current(
    databases: &mut std::collections::BTreeMap<String, CanonicalRows>,
    current: &Vault,
) -> Result<()> {
    let txn = current.store.env.read_txn()?;
    let rows = crate::store::host_hold_rows_in_txn(&current.store, &txn)?;
    carry(databases, &rows)
}

impl Vault {
    /// This vault's host-order legal holds, for the host to carry to the vault
    /// a restore with no live source makes.
    pub fn carried_host_order_holds(&self) -> Result<HostOrderHolds> {
        let txn = self.store.env.read_txn()?;
        Ok(HostOrderHolds {
            rows: crate::store::host_hold_rows_in_txn(&self.store, &txn)?,
        })
    }

    /// Puts `holds`, read from the vault this one was restored from, in place
    /// of this vault's host-order legal holds. Call it before the vault serves.
    pub fn install_carried_host_order_holds(&self, holds: &HostOrderHolds) -> Result<()> {
        self.with_write_txn(|txn| {
            crate::store::replace_host_holds_in_txn(&self.store, txn, &holds.rows)
        })
    }

    /// Whether a standing legal hold keeps every backup of this vault: one
    /// that expires a backup asks first, and keeps them all while it does.
    pub fn legal_hold_keeps_backups(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(backup_holds_in_txn(self, &txn)?.keeps_backups())
    }

    /// How many legal holds stand on this vault, customer and host order
    /// alike, read as [`Self::legal_hold_keeps_backups`] reads them: what a
    /// host asks before it erases the whole vault. A count, nothing of any
    /// hold.
    pub fn standing_legal_holds(&self) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        Ok(backup_holds_in_txn(self, &txn)?.standing)
    }

    /// Runs `expire` with the standing holds that keep this vault's backups,
    /// read as [`Self::legal_hold_keeps_backups`] reads them, while this
    /// call holds the LMDB writer (FIX 1488). A hold writer commits before
    /// the read or after `expire` returns, never between, so an expiry that
    /// unlinks and syncs its directory inside `expire` never destroys a copy
    /// a hold placed meanwhile keeps. Nothing is written: the transaction is
    /// dropped. `expire` must not open a write transaction on this vault.
    ///
    /// # Errors
    ///
    /// The writer or the holds could not be read; `expire` did not run.
    pub fn with_backup_hold_exclusion<R>(
        &self,
        expire: impl FnOnce(&BackupHolds) -> R,
    ) -> Result<R> {
        let wtxn = self.store.env.write_txn()?;
        let holds = backup_holds_in_txn(self, &wtxn)?;
        let expired = expire(&holds);
        drop(wtxn);
        Ok(expired)
    }

    /// A content-free counter that moves after each committed legal-hold
    /// release and each hold maintenance pass on this open vault: a delete a
    /// standing hold deferred asks [`Self::with_backup_hold_exclusion`] again
    /// when it moves (FIX 1488).
    #[must_use]
    pub fn backup_hold_rechecks(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.backup_hold_rechecks.subscribe()
    }

    /// Moves [`Self::backup_hold_rechecks`]; only after a release or a
    /// maintenance pass has committed.
    pub(crate) fn note_backup_hold_recheck(&self) {
        self.store.backup_hold_rechecks.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }
}

/// The holds that keep this vault's backups, as an expiry reads them: every
/// standing legal hold, customer and host order alike. A count, nothing of
/// any hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupHolds {
    /// How many legal holds stand.
    pub standing: u64,
}

impl BackupHolds {
    /// Whether a standing hold keeps every backup: none may expire.
    #[must_use]
    pub fn keeps_backups(&self) -> bool {
        self.standing > 0
    }
}

fn backup_holds_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<BackupHolds> {
    let standing = crate::store::legal_hold::holds_in_txn(&vault.store, txn)?
        .iter()
        .filter(|hold| hold.stands())
        .count();
    Ok(BackupHolds {
        standing: u64::try_from(standing).unwrap_or(u64::MAX),
    })
}
