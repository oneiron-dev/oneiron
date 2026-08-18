//! Snapshot-time secret custody filtering (ARCH-0069 S4/S5).

use std::collections::BTreeSet;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::batch::secret_scan;
use crate::codebase::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::secret_custody::read_secret_custody_in_txn;
use crate::secret_lease::{SECRET_LOCAL_REGISTRATION_PREFIX, decode_local_registration_body};
use crate::vault::Vault;

/// The `vault_meta` key prefix for a snapshot's custody report.
pub const CODEBASE_CUSTODY_KEY_PREFIX: &str = "codebase:custody:v1:";

/// Vault-resident paths which must not enter a codebase snapshot.
#[derive(Debug, Default)]
pub struct SnapshotExclusionSet {
    pub declared_paths: BTreeSet<String>,
    registered_hashes: BTreeSet<[u8; 32]>,
}

impl SnapshotExclusionSet {
    /// Collect declared custody paths and live T2 registrations for one project.
    pub fn for_project(vault: &Vault, txn: &RoTxn<'_>, project_id: &str) -> Result<Self> {
        let mut declared_paths = BTreeSet::new();
        let mut registered_hashes = BTreeSet::new();
        for entry in vault
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_SECRET_CUSTODY])?
        {
            let (key, _) = entry?;
            let Some(raw_id) = key.get(1..) else { continue };
            let Ok(id) = raw_id.try_into() else { continue };
            let Ok(id) = crate::EntityId::from_bytes(id) else {
                continue;
            };
            if let Some(record) = read_secret_custody_in_txn(&vault.store, txn, &id)? {
                declared_paths.extend(record.declared_paths);
            }
        }
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(txn, SECRET_LOCAL_REGISTRATION_PREFIX.as_bytes())?
        {
            let (_, raw) = entry?;
            let registration = decode_local_registration_body(&raw)?;
            if registration.registration.project_id == project_id {
                registered_hashes.insert(registration.registration.content_hash);
                declared_paths.insert(
                    registration
                        .registration
                        .path
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        Ok(Self {
            declared_paths,
            registered_hashes,
        })
    }

    /// Matches exact paths, declared directory prefixes, and registered content
    /// hashes. `root` is this snapshot's repository root, which anchors
    /// absolute declarations; pass `None` when the snapshot has no local root.
    #[must_use]
    pub fn excludes(&self, path: &str, content_hash: &[u8; 32], root: Option<&str>) -> bool {
        self.declared_paths
            .iter()
            .any(|declared| path_matches_declared(path, declared, root))
            || self.registered_hashes.contains(content_hash)
    }
}

/// The repository root that anchors absolute custody declarations. Only local
/// checkouts have one; hosted repo_refs name no path on this machine.
fn snapshot_root(repo_ref: &RepoRef) -> Option<&str> {
    match repo_ref {
        RepoRef::LocalFolder { path, .. } => Some(path.trim_end_matches('/')),
        RepoRef::GitHubAtCommit { .. } => None,
    }
}

/// Closed matching semantics: a declaration excludes a manifest path only when
/// it names that repo-relative path or one of its ancestor directories, and an
/// absolute declaration must additionally resolve inside this snapshot's `root`.
/// Consequences, all intentional: declarations from other checkouts are inert
/// (no suffix matching), absolute directory declarations do exclude children,
/// and a snapshot without a local root falls back to hash-only exclusion so an
/// unanchored absolute declaration can never over-match. Reclaiming blobs
/// persisted by earlier, looser ingests is follow-up ONE-1946.
fn path_matches_declared(path: &str, declared: &str, root: Option<&str>) -> bool {
    if relative_declaration_matches(path, declared) {
        return true;
    }
    if !declared.starts_with('/') {
        return false;
    }
    let Some(root) = root else { return false };
    let Some(rest) = declared.strip_prefix(root) else {
        return false;
    };
    // The remainder must resume at a path boundary, so `/workspace/repository`
    // never anchors on root `/workspace/repo`. A declaration naming the root
    // itself covers the whole tree.
    let Some(rest) = rest.strip_prefix('/') else {
        return rest.is_empty();
    };
    relative_declaration_matches(path, rest)
}

/// Exact path equality or an ancestor-directory prefix, never a bare suffix.
fn relative_declaration_matches(path: &str, declared: &str) -> bool {
    path == declared
        || path
            .strip_prefix(declared)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A value-free proposal to move a detected file secret into the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLiftProposal {
    pub path: String,
    pub detector_reason: String,
    pub suggested_secret_name: String,
    pub project_id: String,
}

/// The durable, value-free outcome of snapshot custody filtering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCustodyReport {
    pub excluded_secret_paths: Vec<String>,
    pub quarantined_paths: Vec<String>,
    pub proposals: Vec<SecretLiftProposal>,
}

impl Vault {
    /// Filters declared files, quarantines unreadable or detected files, and
    /// returns the safe manifest plus its sidecar report.
    pub(crate) fn apply_custody_to_snapshot(
        &self,
        txn: &RoTxn<'_>,
        snapshot: &CodebaseSnapshot,
        file_contents: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(Vec<CodebaseFileEntry>, SnapshotCustodyReport)> {
        let exclusions = SnapshotExclusionSet::for_project(self, txn, &snapshot.project_id)?;
        let root = snapshot_root(&snapshot.repo_ref);
        let mut files = Vec::with_capacity(snapshot.files.len());
        let mut report = SnapshotCustodyReport::default();
        for entry in &snapshot.files {
            if exclusions.excludes(&entry.path, &entry.content_hash, root) {
                report.excluded_secret_paths.push(entry.path.clone());
                continue;
            }
            let Some(bytes) = file_contents(&entry.path) else {
                report.quarantined_paths.push(entry.path.clone());
                continue;
            };
            if bytes.len() as u64 != entry.size_bytes
                || blake3::hash(&bytes).as_bytes() != &entry.content_hash
            {
                report.quarantined_paths.push(entry.path.clone());
                continue;
            }
            if let Some(reason) = secret_scan::scan_file_content(&entry.path, &bytes) {
                report.quarantined_paths.push(entry.path.clone());
                report.proposals.push(SecretLiftProposal {
                    path: entry.path.clone(),
                    detector_reason: reason.to_owned(),
                    suggested_secret_name: suggested_secret_name(&entry.path),
                    project_id: snapshot.project_id.clone(),
                });
                continue;
            }
            files.push(entry.clone());
        }
        Ok((files, report))
    }
}

pub(crate) fn custody_key(fork_hash: &[u8; 32]) -> Vec<u8> {
    format!(
        "{CODEBASE_CUSTODY_KEY_PREFIX}{}",
        crate::entity_id::bytes_to_hex_lower(fork_hash)
    )
    .into_bytes()
}

pub(crate) fn encode_report(report: &SnapshotCustodyReport) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(report)
        .map_err(|_| Error::InvalidCodebaseSnapshotBody("encode custody report"))
}

fn suggested_secret_name(path: &str) -> String {
    let mut name = String::from("snapshot_");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() {
            name.push(char::from(byte.to_ascii_lowercase()));
        } else if !name.ends_with('_') {
            name.push('_');
        }
    }
    name.truncate(96);
    name.trim_end_matches('_').to_owned()
}

#[cfg(test)]
mod tests;
