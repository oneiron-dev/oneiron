//! Reclaim excluded historical codebase assets without deleting retained shared blobs.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::snapshot::{CODEBASE_CONTENT_HASH_LEN, CodebaseSnapshot, decode_codebase_snapshot};
use crate::Vault;
use crate::error::Result;
use crate::secret_snapshot::{SnapshotCustodyReport, SnapshotExclusionSet, snapshot_root};

pub(super) const CODEBASE_SNAPSHOT_KEY_PREFIX: &[u8] = b"codebase:snapshot:v1:";

type ContentHash = [u8; CODEBASE_CONTENT_HASH_LEN];

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
    for row in vault
        .store
        .vault_meta
        .prefix_iter(wtxn, CODEBASE_SNAPSHOT_KEY_PREFIX)?
    {
        let (_, raw) = row?;
        let prior = decode_codebase_snapshot(&raw)?;
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
    let mut protected = BTreeSet::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(wtxn, CODEBASE_SNAPSHOT_KEY_PREFIX)?
    {
        let (_, raw) = row?;
        let prior = decode_codebase_snapshot(&raw)?;
        for file in &prior.files {
            if candidates.contains(&file.content_hash)
                && (prior.project_id != current.project_id
                    || !prior.repo_ref.same_repository(&current.repo_ref)
                    || !(exclusions.excludes(
                        &file.path,
                        &file.content_hash,
                        snapshot_root(&prior.repo_ref),
                    ) || quarantined_paths.contains(file.path.as_str())))
            {
                protected.insert(file.content_hash);
            }
        }
    }
    candidates.retain(|hash| !retained_hashes.contains(hash) && !protected.contains(hash));
    Ok(candidates)
}
