//! The owner host a managed vault serves with: its backups and restore
//! rehearsals on the tenant's own disk, in private directories beside its
//! data directory, as plain serve keeps backups beside its vault. In the
//! vault VM they are `/vault/data.backups` and `/vault/data.rehearsals`:
//! never the system temp directory, `/run`, the read-only `/config` or the
//! key directory `/vault/keys`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::config::ServeConfig;
use crate::owner::schedule::OwnerHost;

/// The owner host over the vault `config` serves. `rehearsal_config` is the
/// config the vault was opened with, its page seal cleared: a rehearsal's
/// scratch takes a fresh incarnation of the seal (`owner::backup`).
///
/// Both directories are made here, private, when missing, and checked with a
/// write. One that is missing or cannot be written is said with its reason,
/// and the host is attached all the same: status still answers, and a backup
/// or rehearsal names its own failure until the storage is there.
pub(super) fn owner_host(
    config: &ServeConfig,
    rehearsal_config: oneiron::VaultConfig,
) -> OwnerHost {
    let rehearsals = rehearsal_dir(&config.vault_path);
    let host =
        OwnerHost::from_config(config, rehearsal_config).with_rehearsal_dir(rehearsals.clone());
    for (storage, dir, private) in [
        ("backups", host.backups.dir.as_path(), false),
        ("rehearsals", rehearsals.as_path(), true),
    ] {
        if let Err(error) = prepare(dir, private) {
            tracing::warn!(
                reason = "owner_storage_unavailable",
                storage,
                dir = %dir.display(),
                error = %format!("{error:#}"),
                "owner storage is not usable; its backups or rehearsals fail until it is"
            );
        }
    }
    host
}

/// `<data_dir>.rehearsals`, beside the data directory as its backups are.
fn rehearsal_dir(data_dir: &Path) -> PathBuf {
    let name = data_dir.file_name().map_or_else(
        || "vault".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    data_dir.with_file_name(format!("{name}.rehearsals"))
}

/// Makes `dir` owner-only when it is missing, and proves a file can be
/// written in it. `private` also refuses a directory on the way to it that
/// another user could write, as a rehearsal itself refuses it.
fn prepare(dir: &Path, private: bool) -> anyhow::Result<()> {
    if !dir.is_dir() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(dir)
            .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
    }
    #[cfg(unix)]
    if private {
        oneiron::store::refuse_shared_path(dir)?;
    }
    #[cfg(not(unix))]
    let _ = private;
    // A probe left by a start that stopped midway goes first; a new one is
    // made fresh, never written through a link.
    let probe = dir.join(".oneiron-storage-probe");
    let _ = std::fs::remove_file(&probe);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut file| {
            file.write_all(b"ok")?;
            file.sync_all()
        });
    let _ = std::fs::remove_file(&probe);
    written.map_err(|error| anyhow::anyhow!("write in {}: {error}", dir.display()))
}
