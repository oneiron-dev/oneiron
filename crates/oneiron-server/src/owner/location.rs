//! Where the owner's data lives: the vault path and size, the backups beside
//! it, and the last time anything left the vault.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::backup::{self, BackupPlan, BackupRecord};

/// The data-location section of `doctor` and `GET /v1/owner/status`.
#[derive(Debug, Serialize)]
pub(crate) struct Location {
    pub(crate) vault: PathBuf,
    /// Bytes the vault directory occupies on disk.
    pub(crate) disk_bytes: u64,
    pub(crate) disk: String,
    pub(crate) backups: Backups,
    /// The last whole-vault export, from the vault's export receipts. `None`
    /// when the vault has never been exported or could not be opened.
    pub(crate) last_export: Option<LastExport>,
    /// The write-door secret scan, when the vault could be read.
    pub(crate) secret_scan: Option<oneiron::policy_model::SecretScanMode>,
    /// Set when the vault is held by a running server; ask it instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Backups {
    pub(crate) dir: PathBuf,
    pub(crate) count: usize,
    pub(crate) last: Option<BackupRecord>,
    /// Hours between scheduled backups; `None` when the schedule is off.
    pub(crate) every_hours: Option<u64>,
    pub(crate) keep: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct LastExport {
    pub(crate) at: String,
    pub(crate) format: String,
    pub(crate) bytes: u64,
    pub(crate) by: String,
}

/// Reports on the vault at `vault_path`. `vault` is the open vault when this
/// process can read it; filesystem facts are reported either way.
pub(crate) fn locate(
    vault_path: &Path,
    vault: Option<&oneiron::Vault>,
    plan: &BackupPlan,
    every_hours: Option<u64>,
) -> anyhow::Result<Location> {
    let disk_bytes = disk_usage(vault_path)?;
    let backups = backup::list(plan)?;
    let (last_export, secret_scan) = match vault {
        Some(vault) => (
            vault.export_receipts()?.pop().map(|receipt| LastExport {
                at: super::stamp::rfc3339(receipt.at.saturating_mul(1_000)),
                format: receipt.format,
                bytes: receipt.bytes,
                by: receipt.by,
            }),
            Some(vault.secret_scan_mode()?),
        ),
        None => (None, None),
    };
    Ok(Location {
        vault: vault_path
            .canonicalize()
            .unwrap_or_else(|_| vault_path.to_path_buf()),
        disk: human_bytes(disk_bytes),
        disk_bytes,
        backups: Backups {
            dir: plan.dir.clone(),
            count: backups.len(),
            last: backups.last().cloned(),
            every_hours,
            keep: plan.keep,
        },
        last_export,
        secret_scan,
        note: None,
    })
}

/// On-disk bytes of every file under `path` (allocated blocks on Unix, so a
/// sparse LMDB map is not counted at its full size).
fn disk_usage(path: &Path) -> anyhow::Result<u64> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() {
        let mut total = 0_u64;
        for entry in std::fs::read_dir(path)? {
            total = total.saturating_add(disk_usage(&entry?.path())?);
        }
        return Ok(total);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(metadata.blocks().saturating_mul(512))
    }
    #[cfg(not(unix))]
    Ok(metadata.len())
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
