//! Codebase snapshots the historical lift sweep reads again (OF-067, Engine
//! ruling D = a). A new snapshot keeps a file its custody scan finds a
//! secret in out of its manifest: the file is quarantined and the custody
//! report beside the snapshot files a value-free proposal
//! (`Vault::apply_custody_to_snapshot`). A snapshot stored before keeps its
//! manifest, which its fork hash binds. The sweep reads each of its files
//! again by the same scan, and quarantines each hit in the report beside
//! that fork hash, with its proposal. A mount reads no file the report
//! quarantines, and no hosted reader gets one.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::super::ingest::read_asset_blob_in_txn;
use super::super::snapshot::{CodebaseForkHash, CodebaseSnapshot};
use super::{CUSTODY_REPORTS, SNAPSHOTS, codebase_custody_key};
use crate::Vault;
use crate::batch::secret_scan::scan_file_content;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_snapshot::{SecretLiftProposal, SnapshotCustodyReport, suggested_secret_name};

/// A snapshot, the custody report beside it and each hit in a file the
/// report does not withhold yet, by path.
type SnapshotHits = (
    CodebaseSnapshot,
    SnapshotCustodyReport,
    Vec<(String, &'static str)>,
);

impl Vault {
    /// The custody scan's first hit in a file of the snapshot of
    /// `code_artifact_id` that its custody report does not withhold.
    pub(crate) fn codebase_snapshot_lift_hit_in_txn(
        &self,
        txn: &RoTxn<'_>,
        code_artifact_id: &EntityId,
    ) -> Result<Option<&'static str>> {
        Ok(self
            .codebase_snapshot_hits_in_txn(txn, code_artifact_id)?
            .and_then(|(_, _, hits)| hits.first().map(|(_, reason)| *reason)))
    }

    /// Quarantines each file of the snapshot of `code_artifact_id` the
    /// custody scan finds a secret in, in the report beside its fork hash,
    /// with a value-free proposal for each, in the caller's transaction. The
    /// manifest, its fork hash and the files' ASSETs stay as they are. The
    /// first hit's reason, or `None` when nothing is left to quarantine.
    pub(crate) fn lift_codebase_snapshot_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        code_artifact_id: &EntityId,
    ) -> Result<Option<&'static str>> {
        let Some((snapshot, mut report, hits)) =
            self.codebase_snapshot_hits_in_txn(txn, code_artifact_id)?
        else {
            return Ok(None);
        };
        let Some(&(_, first)) = hits.first() else {
            return Ok(None);
        };
        for (path, reason) in hits {
            report.proposals.push(SecretLiftProposal {
                suggested_secret_name: suggested_secret_name(&path),
                path: path.clone(),
                detector_reason: reason.to_owned(),
                project_id: snapshot.project_id.clone(),
            });
            report.quarantined_paths.push(path);
        }
        CUSTODY_REPORTS.put(
            &self.store,
            txn,
            &codebase_custody_key(&snapshot.fork_hash),
            &report,
        )?;
        Ok(Some(first))
    }

    /// The paths the custody report beside `fork_hash` excludes or
    /// quarantines: no reader of a snapshot at that fork reads them.
    pub(crate) fn codebase_withheld_paths_in_txn(
        &self,
        txn: &RoTxn<'_>,
        fork_hash: &CodebaseForkHash,
    ) -> Result<BTreeSet<String>> {
        Ok(CUSTODY_REPORTS
            .get(&self.store, txn, &codebase_custody_key(fork_hash))?
            .map(|report| withheld(&report))
            .unwrap_or_default())
    }

    fn codebase_snapshot_hits_in_txn(
        &self,
        txn: &RoTxn<'_>,
        code_artifact_id: &EntityId,
    ) -> Result<Option<SnapshotHits>> {
        let Some(snapshot) = SNAPSHOTS.get(&self.store, txn, code_artifact_id)? else {
            return Ok(None);
        };
        let report = CUSTODY_REPORTS
            .get(&self.store, txn, &codebase_custody_key(&snapshot.fork_hash))?
            .unwrap_or_default();
        let withheld = withheld(&report);
        let mut hits = Vec::new();
        for entry in &snapshot.files {
            if withheld.contains(&entry.path) {
                continue;
            }
            let bytes = match read_asset_blob_in_txn(self, txn, &entry.content_hash) {
                Ok(bytes) => bytes,
                // A file whose ASSET is gone or holds other bytes has
                // nothing of its own to read.
                Err(Error::EntityNotFound | Error::CorruptedIndex(_) | Error::Code(_)) => continue,
                Err(error) => return Err(error),
            };
            if let Some(reason) = scan_file_content(&entry.path, &bytes) {
                hits.push((entry.path.clone(), reason));
            }
        }
        Ok(Some((snapshot, report, hits)))
    }
}

fn withheld(report: &SnapshotCustodyReport) -> BTreeSet<String> {
    report
        .excluded_secret_paths
        .iter()
        .chain(&report.quarantined_paths)
        .cloned()
        .collect()
}
