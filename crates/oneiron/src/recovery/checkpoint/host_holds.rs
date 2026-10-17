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
        Ok(crate::store::legal_hold::holds_in_txn(&self.store, &txn)?
            .iter()
            .any(crate::deletion::LegalHold::stands))
    }
}
