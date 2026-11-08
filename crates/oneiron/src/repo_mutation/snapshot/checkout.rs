//! Recovery traversal and Git opacity inventory for current-folder capture.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use crate::Vault;
use crate::error::Result;
use crate::git_wire::bundle_tree::{gitlink_index_entries, gitlink_paths_at};
use crate::scan_check::{EngineScan, ScanCount};

use super::super::git::git_output_optional;
use super::super::support::utf8_trimmed;
use super::capture::{CaptureEntry, Directory, visit_capture_entries};
use super::{nested_repository, repo_relative_path};

pub(super) fn visit_checkout_entries(
    repo_root: &Path,
    dir: &Path,
    indexed_paths: &BTreeSet<String>,
    linked_paths: &BTreeSet<String>,
    visit: &mut impl FnMut(&Path, String, &fs::Metadata) -> Result<()>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let relative = repo_relative_path(repo_root, &path)?;
        if indexed_paths.contains(&relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            if linked_paths.contains(&relative) || nested_repository(&path)? {
                continue;
            }
            visit_checkout_entries(repo_root, &path, indexed_paths, linked_paths, visit)?;
            continue;
        }
        visit(&path, relative, &metadata)?;
    }
    Ok(())
}

/// Current file entries, without interpreting an index OID as file bytes.
/// Ordinary folders need no Git repository; a checkout's enclosing Git
/// inventory still keeps every linked checkout opaque.
pub(crate) fn visit_code_capture_files(
    vault: &Vault,
    root: &Path,
    mut visit: impl FnMut(String, CaptureEntry<'_>) -> Result<()>,
) -> Result<()> {
    let directory = Directory::open_root(root)?;
    let mut git_root = None;
    for ancestor in root.ancestors() {
        match fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => {
                git_root = Some(ancestor);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut indexed = BTreeSet::new();
    let mut linked = BTreeSet::new();
    if let Some(git_root) = git_root {
        let prefix = root.strip_prefix(git_root).map_err(|_| {
            crate::Error::InvariantViolation("capture root escaped its Git ancestor")
        })?;
        let local = |path: &str| {
            Path::new(path)
                .strip_prefix(prefix)
                .ok()
                .and_then(Path::to_str)
                .map(str::to_owned)
        };
        indexed.extend(
            gitlink_index_entries(git_root)?
                .keys()
                .filter_map(|path| local(path)),
        );
        linked.extend(indexed.iter().cloned());
        if let Some(head) = git_output_optional(
            git_root,
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "HEAD".to_owned(),
            ],
        )? {
            let head = utf8_trimmed(head, "git HEAD must be UTF-8")?;
            linked.extend(
                gitlink_paths_at(git_root, &head)?
                    .iter()
                    .filter_map(|path| local(path)),
            );
        }
    }
    let scope = blake3::hash(root.as_os_str().as_encoded_bytes());
    let mut count = ScanCount::start_at(
        EngineScan::RepoSnapshotFiles,
        &scope.as_bytes()[..16],
        vault.scan_threshold(EngineScan::RepoSnapshotFiles)?,
    );
    visit_capture_entries(&directory, &indexed, &linked, &mut |relative, entry| {
        count.row();
        visit(relative, entry)
    })?;
    count.finish(vault);
    Ok(())
}
