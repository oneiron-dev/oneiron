//! Whether the vault sits in a folder a sync service watches. Vaults live in
//! the app folder, never in a synced folder (CROSS-ARCH-0019 #vault-20-hot,
//! owner card E2-HOT B, 2026-10-09): a sync client copies the vault's files
//! while the engine writes them, and a copy taken mid-write can corrupt the
//! vault. `doctor` and the owner's status report the folder, `init` prints a
//! warning and `serve` logs one; none of them refuses the vault.
//!
//! The folder is read from the path and its markers. iCloud's "Desktop &
//! Documents" sync leaves no marker on the home `Desktop` and `Documents`
//! folders, so it is inferred from iCloud Drive's own folders and reported as
//! likely.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// The sync service's folder that holds a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SyncedFolder {
    /// The sync service, a stable id: `icloud-drive`,
    /// `icloud-desktop-documents`, `dropbox`, `onedrive`, `google-drive`,
    /// `box`, `syncthing`, or, for another macOS cloud storage provider, the
    /// provider part of its folder's name in lower case.
    pub(crate) service: String,
    /// The folder the service syncs: the vault directory or one of its
    /// ancestors, canonical.
    pub(crate) root: PathBuf,
    /// The service is inferred, not seen. Only `icloud-desktop-documents` is:
    /// iCloud Drive's `Desktop` or `Documents` folder beside the home folder
    /// of the same name says the sync is on, or was once, since iCloud Drive
    /// keeps that folder after the sync is turned off.
    pub(crate) likely: bool,
}

impl SyncedFolder {
    /// The warning `init` prints and `serve` logs.
    pub(crate) fn warning(&self) -> String {
        let likely = if self.likely { "likely " } else { "" };
        format!(
            "the vault is {likely}in a folder `{}` syncs ({}): a sync service copies the \
             vault's files while Oneiron writes them, which can corrupt the vault; move the \
             vault to a folder no sync service watches",
            self.service,
            self.root.display()
        )
    }
}

/// The nearest synced folder that holds `vault_path`, the vault directory
/// included. It is read on the canonical path, so a symlink into a synced
/// folder counts; a path that does not exist yet is read as written.
pub(crate) fn enclosing(vault_path: &Path) -> Option<SyncedFolder> {
    let path = vault_path
        .canonicalize()
        .or_else(|_| std::path::absolute(vault_path))
        .unwrap_or_else(|_| vault_path.to_path_buf());
    path.ancestors().find_map(synced_root)
}

/// `dir` as a sync service's root, if it is one.
fn synced_root(dir: &Path) -> Option<SyncedFolder> {
    let seen = |service: &str| {
        Some(SyncedFolder {
            service: service.to_owned(),
            root: dir.to_path_buf(),
            likely: false,
        })
    };
    let name = file_name(dir);
    let parent = dir.parent();
    let parent_name = parent.map_or("", file_name);
    let grandparent_name = parent.and_then(Path::parent).map_or("", file_name);
    if name.eq_ignore_ascii_case("Mobile Documents") && parent_name.eq_ignore_ascii_case("Library")
    {
        // macOS keeps iCloud Drive's containers under ~/Library/Mobile Documents.
        return seen("icloud-drive");
    }
    if parent_name.eq_ignore_ascii_case("CloudStorage")
        && grandparent_name.eq_ignore_ascii_case("Library")
        && !name.is_empty()
    {
        // macOS File Provider folders: `Dropbox`, `OneDrive-Personal`,
        // `GoogleDrive-<account>`, `Box-Box`.
        return seen(cloud_storage_service(name).as_str());
    }
    if name.eq_ignore_ascii_case("iCloudDrive") {
        // iCloud for Windows.
        return seen("icloud-drive");
    }
    if name.eq_ignore_ascii_case("OneDrive") || name.starts_with("OneDrive - ") {
        // The OneDrive folder of a Windows profile, personal or an
        // organisation's.
        return seen("onedrive");
    }
    // The Dropbox client marks its root with a `.dropbox` file; `~/.dropbox`,
    // its settings directory, is not one.
    if dir.join(".dropbox").is_file() {
        return seen("dropbox");
    }
    if dir.join(".stfolder").exists() {
        return seen("syncthing");
    }
    // iCloud's Desktop & Documents sync: the home `Desktop` or `Documents`
    // folder, whose iCloud Drive holds a folder of the same name.
    if matches!(name, "Desktop" | "Documents")
        && parent.is_some_and(|home| {
            home.join("Library/Mobile Documents/com~apple~CloudDocs")
                .join(name)
                .is_dir()
        })
    {
        return Some(SyncedFolder {
            service: "icloud-desktop-documents".to_owned(),
            root: dir.to_path_buf(),
            likely: true,
        });
    }
    None
}

/// The service id of a macOS cloud storage folder: its name's provider part.
fn cloud_storage_service(name: &str) -> String {
    let provider = name.split_once('-').map_or(name, |(provider, _)| provider);
    match provider {
        "GoogleDrive" => "google-drive".to_owned(),
        provider => provider.to_ascii_lowercase(),
    }
}

fn file_name(path: &Path) -> &str {
    path.file_name().and_then(OsStr::to_str).unwrap_or_default()
}
