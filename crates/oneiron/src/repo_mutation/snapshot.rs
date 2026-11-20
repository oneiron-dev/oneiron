//! Capture, validation and restore of repository working-tree snapshots.
//! `restore` owns the re-exported restore entry, `restore_repo_snapshot`.
//! `pinned` owns the re-exported `RepoPinnedBase`; snapshot row definitions are local.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::{Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::secret_snapshot::{SnapshotExclusionSet, SnapshotWithhold};

use super::git::{git_output_optional, validate_relative_repo_path};
use super::oplog::{REPO_MUTATION_OPLOG_SCHEMA_VERSION, SNAPSHOT};
use super::support::{path_arg, utf8_trimmed};
use super::types::RepoForkHash;
use crate::error::CodeError;
use crate::git_wire::bundle_tree::{gitlink_index_entries, gitlink_paths_at};
use crate::git_wire::git_path_text_of_os;

mod capture;
mod checkout;
mod pinned;
mod restore;
pub(crate) use capture::CaptureEntry;
pub(crate) use checkout::visit_code_capture_files;
pub(super) use pinned::RepoPinnedBase;
pub(super) use restore::restore_repo_snapshot;

/// The bytes one snapshot holds in memory: a machine floor, not a count.
const MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredRepoSnapshot {
    pub(super) schema_version: u8,
    pub(super) head: Option<String>,
    pub(super) entries: Vec<StoredRepoSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredRepoSnapshotEntry {
    pub(super) path: String,
    pub(super) kind: StoredRepoSnapshotEntryKind,
    pub(super) executable: bool,
    pub(super) content: Vec<u8>,
    pub(super) symlink_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StoredRepoSnapshotEntryKind {
    File,
    Symlink,
    /// An index gitlink: content is its OID, never the linked repository.
    Gitlink,
    /// A file snapshot custody keeps out ([`SnapshotCustody`]): its path and
    /// mode, none of its bytes. A restore leaves the file the checkout holds
    /// there as it is.
    Withheld,
}

/// Snapshot custody (ARCH-0069 S4/S5) over the checkout a mutation snapshots
/// (OF-067): the declared-path exclusion and undeclared-secret quarantine a
/// codebase snapshot keeps, read once per capture. A file it withholds is
/// stored [`StoredRepoSnapshotEntryKind::Withheld`], so its bytes never reach
/// a snapshot row and a restore never deletes it.
pub(super) struct SnapshotCustody {
    exclusions: SnapshotExclusionSet,
    root: Option<String>,
}

impl SnapshotCustody {
    pub(super) fn of(vault: &Vault, repo_root: &Path) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        Ok(Self {
            exclusions: SnapshotExclusionSet::for_every_project(vault, &txn)?,
            root: repo_root
                .to_str()
                .map(|root| root.trim_end_matches('/').to_owned()),
        })
    }

    /// Why the policy keeps `content` at `path` out of a snapshot, if it does.
    pub(super) fn withholds(&self, path: &str, content: &[u8]) -> Option<SnapshotWithhold> {
        self.exclusions
            .withholds(path, content, self.root.as_deref())
    }

    /// Whether custody declares `path`: a vault-resident path, whose bytes
    /// only the vault writes (a T2 file, ARCH-0069 S4).
    pub(super) fn declares(&self, path: &str) -> bool {
        self.exclusions.declares(path, self.root.as_deref())
    }

    /// A file's entry as the policy keeps it.
    pub(super) fn file(
        &self,
        path: String,
        executable: bool,
        content: Vec<u8>,
    ) -> StoredRepoSnapshotEntry {
        let (kind, content) = match self.withholds(&path, &content) {
            None => (StoredRepoSnapshotEntryKind::File, content),
            Some(_) => (StoredRepoSnapshotEntryKind::Withheld, Vec::new()),
        };
        StoredRepoSnapshotEntry {
            path,
            kind,
            executable,
            content,
            symlink_target: None,
        }
    }

    /// A gitlink's OID under the same path and byte custody as a file.
    pub(super) fn gitlink(&self, path: String, oid: Vec<u8>) -> StoredRepoSnapshotEntry {
        let mut entry = self.file(path, false, oid);
        if entry.kind == StoredRepoSnapshotEntryKind::File {
            entry.kind = StoredRepoSnapshotEntryKind::Gitlink;
        }
        entry
    }

    /// A symlink's entry as the policy keeps it: a target the policy
    /// withholds is kept out as a file's bytes are (FIX 8840).
    pub(super) fn symlink(&self, path: String, target: String) -> StoredRepoSnapshotEntry {
        let (kind, symlink_target) = match self.withholds(&path, target.as_bytes()) {
            None => (StoredRepoSnapshotEntryKind::Symlink, Some(target)),
            Some(_) => (StoredRepoSnapshotEntryKind::Withheld, None),
        };
        StoredRepoSnapshotEntry {
            path,
            kind,
            executable: false,
            content: Vec::new(),
            symlink_target,
        }
    }
}

/// One capture's walk: its entries counted against their threshold row
/// (rule 5, FIX 8835) and the bytes it holds.
struct SnapshotStats {
    files: ScanCount,
    total_bytes: u64,
}

pub(super) fn capture_repo_snapshot(
    vault: &Vault,
    repo_root: &Path,
) -> Result<(RepoForkHash, Vec<u8>)> {
    let head = git_output_optional(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )?
    .map(|bytes| utf8_trimmed(bytes, "git HEAD must be UTF-8"))
    .transpose()?;
    let custody = SnapshotCustody::of(vault, repo_root)?;
    let mut entries = Vec::new();
    // Scoped by the checkout's path, hashed to a fixed width.
    let scope = blake3::hash(repo_root.as_os_str().as_encoded_bytes());
    let mut stats = SnapshotStats {
        files: ScanCount::start_at(
            EngineScan::RepoSnapshotFiles,
            &scope.as_bytes()[..16],
            vault.scan_threshold(EngineScan::RepoSnapshotFiles)?,
        ),
        total_bytes: 0,
    };
    let gitlinks = gitlink_index_entries(repo_root)?;
    let indexed_paths: BTreeSet<_> = gitlinks.keys().cloned().collect();
    let mut linked_paths = indexed_paths.clone();
    if let Some(head) = &head {
        linked_paths.extend(gitlink_paths_at(repo_root, head)?);
    }
    for (path, oid) in &gitlinks {
        validate_relative_repo_path(path)?;
        record_snapshot_entry_size(&mut stats, oid.len() as u64)?;
        entries.push(custody.gitlink(path.clone(), oid.clone()));
    }
    collect_snapshot_entries(
        repo_root,
        repo_root,
        &custody,
        &indexed_paths,
        &linked_paths,
        &mut entries,
        &mut stats,
    )?;
    stats.files.finish(vault);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let snapshot = StoredRepoSnapshot {
        schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
        head,
        entries,
    };
    let encoded = encode_snapshot(&snapshot)?;
    let hash = *blake3::hash(&encoded).as_bytes();
    Ok((hash, encoded))
}

fn collect_snapshot_entries(
    repo_root: &Path,
    dir: &Path,
    custody: &SnapshotCustody,
    indexed_paths: &BTreeSet<String>,
    linked_paths: &BTreeSet<String>,
    entries: &mut Vec<StoredRepoSnapshotEntry>,
    stats: &mut SnapshotStats,
) -> Result<()> {
    checkout::visit_checkout_entries(
        repo_root,
        dir,
        indexed_paths,
        linked_paths,
        &mut |path, relative, metadata| {
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(path)?;
                let target = path_arg(&target)?;
                record_snapshot_entry_size(stats, target.len() as u64)?;
                entries.push(custody.symlink(relative, target));
            } else if metadata.file_type().is_file() {
                if metadata.len() > MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES {
                    return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                        "repo mutation snapshot file exceeds max bytes",
                    )));
                }
                record_snapshot_entry_size(stats, metadata.len())?;
                entries.push(custody.file(relative, is_executable(metadata), fs::read(path)?));
            } else {
                return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                    "repo snapshot supports only files, directories, and symlinks",
                )));
            }
            Ok(())
        },
    )
}

fn record_snapshot_entry_size(stats: &mut SnapshotStats, bytes: u64) -> Result<()> {
    stats.files.row();
    stats.total_bytes = stats
        .total_bytes
        .checked_add(bytes)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_snapshot_bytes"))?;
    if stats.total_bytes > MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo mutation snapshot exceeds max total bytes",
        )));
    }
    Ok(())
}

pub(super) fn snapshot_recorded_for_repo(
    vault: &Vault,
    repo_ref: &RepoRef,
    fork_hash: RepoForkHash,
) -> Result<bool> {
    Ok(vault
        .repo_mutation_oplog_for_canonical(repo_ref)?
        .iter()
        .any(|entry| entry.pre_action_fork_hash == fork_hash)
        || super::proposal::proposal_snapshot_recorded(vault, repo_ref, fork_hash)?)
}

/// A nested checkout stays opaque even after its outer gitlink is removed.
fn nested_repository(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path.join(".git")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The [`SNAPSHOT`] codec, kept callable directly: [`capture_repo_snapshot`]
/// needs the encoded bytes themselves (their hash IS the row's key), and a
/// few readers still hold raw bytes they must reverify before trusting.
pub(super) fn encode_snapshot(snapshot: &StoredRepoSnapshot) -> Result<Vec<u8>> {
    SNAPSHOT.encode_value(snapshot)
}

/// Decodes and re-checks the schema version [`SNAPSHOT`]'s generic codec has
/// no notion of.
pub(super) fn decode_snapshot(bytes: &[u8]) -> Result<StoredRepoSnapshot> {
    require_snapshot_schema(SNAPSHOT.decode_value(bytes)?)
}

pub(super) fn require_snapshot_schema(snapshot: StoredRepoSnapshot) -> Result<StoredRepoSnapshot> {
    if snapshot.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "unsupported repo mutation snapshot schema version",
        )));
    }
    Ok(snapshot)
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(repo_root)
        .map_err(|_| Error::InvariantViolation("repo path escaped root"))?;
    let mut out = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo snapshot path must be normal",
            )));
        };
        // A file name outside UTF-8 keeps its bytes as a Git path's text
        // (FIX 21326), the text the pinned and tree walks give that name.
        let part = git_path_text_of_os(part)?;
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&part);
    }
    validate_relative_repo_path(&out)?;
    Ok(out)
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
