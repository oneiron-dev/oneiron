//! Repo snapshots the historical lift sweep reads again (OF-067, Engine
//! ruling D = a). A new capture keeps a file snapshot custody finds a secret
//! in out of the snapshot: it is stored withheld, its path and mode only
//! (`SnapshotCustody::file`). A snapshot captured before keeps its bytes,
//! which its fork hash names. The sweep reads each file in it again by the
//! custody scan and marks the snapshot with each file it finds a secret in:
//! a restore leaves that file in the checkout as it is, and a mount of the
//! fork reads it as absent, as each does a withheld file.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::oplog::SNAPSHOT;
use super::snapshot::StoredRepoSnapshotEntryKind;
use crate::Vault;
use crate::batch::secret_scan::scan_file_content;
use crate::error::Result;
use crate::secret_custody::{CarrierMark, carrier_mark_in_txn, put_carrier_mark_in_txn};
use crate::side_table;

/// A snapshot's encoded hash, the sweep's mark on it, and each hit in a
/// file the mark does not withhold yet, by path.
type SnapshotHits = ([u8; 32], Option<CarrierMark>, Vec<(String, &'static str)>);

impl Vault {
    /// The custody scan's first hit in a file of the snapshot `key` names
    /// that the sweep has not marked.
    pub(crate) fn repo_snapshot_lift_hit_in_txn(
        &self,
        txn: &RoTxn<'_>,
        key: &str,
    ) -> Result<Option<&'static str>> {
        Ok(snapshot_hits_in_txn(self, txn, key)?
            .and_then(|(_, _, hits)| hits.first().map(|(_, reason)| *reason)))
    }

    /// Marks each file of the snapshot `key` names that the custody scan
    /// finds a secret in, in the caller's transaction. The snapshot's bytes
    /// and its fork hash stay as they are. The first hit's reason, or `None`
    /// when nothing is left to mark.
    pub(crate) fn lift_repo_snapshot_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        key: &str,
    ) -> Result<Option<&'static str>> {
        let Some((version, mark, hits)) = snapshot_hits_in_txn(self, txn, key)? else {
            return Ok(None);
        };
        let Some(&(_, first)) = hits.first() else {
            return Ok(None);
        };
        let marked_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let mut mark = mark.unwrap_or(CarrierMark {
            version,
            reason: first.to_owned(),
            withheld: Vec::new(),
            marked_at,
        });
        mark.withheld.extend(hits.into_iter().map(|(path, _)| path));
        mark.withheld.sort();
        mark.marked_at = marked_at;
        put_carrier_mark_in_txn(
            &self.store,
            txn,
            &side_table::REPO_MUTATION_SNAPSHOT,
            key.as_bytes(),
            &mark,
        )?;
        Ok(Some(first))
    }
}

/// The files the sweep marked in the snapshot `key` names, whose encoded
/// bytes are `raw`: a reader reads each as withheld.
pub(super) fn lifted_entries_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    key: &str,
    raw: &[u8],
) -> Result<BTreeSet<String>> {
    Ok(carrier_mark_in_txn(
        &vault.store,
        txn,
        &side_table::REPO_MUTATION_SNAPSHOT,
        key.as_bytes(),
        blake3::hash(raw).as_bytes(),
    )?
    .map(|mark| mark.withheld.into_iter().collect())
    .unwrap_or_default())
}

fn snapshot_hits_in_txn(vault: &Vault, txn: &RoTxn<'_>, key: &str) -> Result<Option<SnapshotHits>> {
    let Some(snapshot) = SNAPSHOT.get(&vault.store, txn, &key.to_owned())? else {
        return Ok(None);
    };
    let version = *blake3::hash(&SNAPSHOT.encode_value(&snapshot)?).as_bytes();
    let mark = carrier_mark_in_txn(
        &vault.store,
        txn,
        &side_table::REPO_MUTATION_SNAPSHOT,
        key.as_bytes(),
        &version,
    )?;
    let marked: BTreeSet<&str> = mark
        .iter()
        .flat_map(|mark| mark.withheld.iter().map(String::as_str))
        .collect();
    let hits = snapshot
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == StoredRepoSnapshotEntryKind::File && !marked.contains(entry.path.as_str())
        })
        .filter_map(|entry| {
            scan_file_content(&entry.path, &entry.content)
                .map(|reason| (entry.path.clone(), reason))
        })
        .collect();
    Ok(Some((version, mark, hits)))
}
