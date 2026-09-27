//! Reclaim excluded historical codebase assets without deleting retained shared blobs.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::snapshot::{CODEBASE_CONTENT_HASH_LEN, CodebaseSnapshot};
use crate::EntityId;
use crate::Vault;
use crate::error::Result;
use crate::secret_snapshot::{SnapshotCustodyReport, SnapshotExclusionSet, snapshot_root};
use crate::side_table::{self, Raw, SideTable};

pub(super) const CODEBASE_SNAPSHOT_KEY_PREFIX: &[u8] = b"codebase:snapshot:v1:";

type ContentHash = [u8; CODEBASE_CONTENT_HASH_LEN];

const SNAPSHOTS: SideTable<EntityId, CodebaseSnapshot, Raw> =
    SideTable::new(&side_table::CODEBASE_SNAPSHOT);

/// Discover older versions of paths excluded by the final writer's custody
/// view, then protect every hash still used at a retained path or in another
/// repository. The current tree alone cannot name a changed or removed blob.
pub(super) fn reclaimable_asset_hashes(
    vault: &Vault,
    wtxn: &RwTxn<'_>,
    current: &CodebaseSnapshot,
    report: &SnapshotCustodyReport,
    retained_hashes: &BTreeSet<ContentHash>,
    current_excluded_hashes: &BTreeSet<ContentHash>,
) -> Result<BTreeSet<ContentHash>> {
    let exclusions = SnapshotExclusionSet::for_project(vault, wtxn, &current.project_id)?;
    let mut candidates = current_excluded_hashes.clone();
    for row in SNAPSHOTS.iter_raw_from(&vault.store, wtxn, &[])? {
        // The old prefix scan ignored row keys; keep that behavior for malformed keys.
        let (_, raw) = row?;
        let prior = SNAPSHOTS.decode_value(&raw)?;
        if prior.project_id != current.project_id
            || !prior.repo_ref.same_repository(&current.repo_ref)
        {
            continue;
        }
        for file in &prior.files {
            if !retained_hashes.contains(&file.content_hash)
                && exclusions.excludes(
                    &file.path,
                    &file.content_hash,
                    snapshot_root(&prior.repo_ref),
                )
            {
                candidates.insert(file.content_hash);
            }
        }
    }
    if candidates.is_empty() {
        return Ok(candidates);
    }

    let quarantined_paths = report
        .quarantined_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    // A scan hit classifies the bytes at this revision, not every older
    // body ever seen under the same path. Declarations remain path-wide.
    let quarantined_blobs = current
        .files
        .iter()
        .filter(|file| quarantined_paths.contains(file.path.as_str()))
        .map(|file| (file.path.as_str(), file.content_hash))
        .collect::<BTreeSet<_>>();
    let mut protected = BTreeSet::new();
    for row in SNAPSHOTS.iter_raw_from(&vault.store, wtxn, &[])? {
        // The old prefix scan ignored row keys; keep that behavior for malformed keys.
        let (_, raw) = row?;
        let prior = SNAPSHOTS.decode_value(&raw)?;
        for file in &prior.files {
            if candidates.contains(&file.content_hash)
                && (prior.project_id != current.project_id
                    || !prior.repo_ref.same_repository(&current.repo_ref)
                    || !(exclusions.excludes(
                        &file.path,
                        &file.content_hash,
                        snapshot_root(&prior.repo_ref),
                    ) || quarantined_blobs.contains(&(file.path.as_str(), file.content_hash))))
            {
                protected.insert(file.content_hash);
            }
        }
    }
    candidates.retain(|hash| !retained_hashes.contains(hash) && !protected.contains(hash));
    Ok(candidates)
}
