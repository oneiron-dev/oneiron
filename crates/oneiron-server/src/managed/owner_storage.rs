//! The owner host a managed vault serves with: its backups and restore
//! rehearsals on the tenant's own disk, in private directories beside its
//! data directory, as plain serve keeps backups beside its vault. In the
//! vault VM they are `/vault/data.backups` and `/vault/data.rehearsals`:
//! never the system temp directory, `/run`, the read-only `/config` or the
//! key directory `/vault/keys`. A direct Linear mirror's response custody
//! lies beside them, in `/vault/data.linear-responses`, and pack organ builds
//! under the data directory, in `/vault/data/organs`, unless the supervisor
//! names their directory.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::{LinearMode, ServeConfig};
use crate::owner::backup::CustodyAnchorCredentials;
use crate::owner::schedule::OwnerHost;

/// The owner host over the vault `config` serves. `rehearsal_config` is the
/// config the vault was opened with, its page seal cleared: a rehearsal's
/// scratch takes a fresh incarnation of the seal (`owner::backup`). Its
/// declared `outbox:` custody members ship through `custody/` under the
/// escrow outbox `managed` names, which the engine makes itself (FIX 5899),
/// and its custody anchor door is called with `anchor`, the owner credential
/// the supervisor handed on its pipe.
///
/// Both directories are made here, private, when missing, and checked with a
/// write. One that is missing or cannot be written is said with its reason,
/// and the host is attached all the same: status still answers, and a backup
/// or rehearsal names its own failure until the storage is there. One with no
/// fscrypt policy, or whose policy cannot be read, is said too, and used as
/// it is ([`say_if_unencrypted`]).
pub(super) fn owner_host(
    config: &ServeConfig,
    rehearsal_config: oneiron::VaultConfig,
    managed: &super::args::ManagedArgs,
    anchor: Option<Arc<CustodyAnchorCredentials>>,
) -> OwnerHost {
    let rehearsals = rehearsal_dir(&config.vault_path);
    // Its custody anchors where `[backup]` names (FIX 5789), a door called
    // with the supervisor's piped credential and never the environment's.
    // Each backup binds the vault id to the registry's name for the vault
    // (FIX 5826), with or without an escrow outbox.
    let host = OwnerHost::from_config(config, rehearsal_config)
        .with_rehearsal_dir(rehearsals.clone())
        .registered_as(managed.vault_name.clone())
        .anchored_at(&config.backup, anchor)
        .shipping_custody_to(managed.escrow_outbox.as_ref().map(|outbox| {
            oneiron::recovery::checkpoint::CustodyOutbox::at(
                outbox.join("custody"),
                managed.vault_name.clone(),
            )
        }));
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
        } else {
            say_if_unencrypted(storage, dir);
        }
    }
    host
}

/// Makes the direct Linear mirror's response custody `[linear]` names, the
/// host's [`linear_response_dir`], private when missing, and checks it with a
/// write as [`owner_host`] checks its storage. One it cannot make is said
/// with its reason; the mirror then refuses to start without it.
pub(super) fn linear_responses(config: &ServeConfig) {
    let Some(dir) = config
        .linear
        .as_ref()
        .filter(|linear| linear.mode == Some(LinearMode::Direct))
        .and_then(|linear| linear.response_dir.as_deref())
    else {
        return;
    };
    if let Err(error) = prepare(dir, false) {
        tracing::warn!(
            reason = "owner_storage_unavailable",
            storage = "linear-responses",
            dir = %dir.display(),
            error = %format!("{error:#}"),
            "owner storage is not usable; the Linear mirror fails until it is"
        );
    } else {
        say_if_unencrypted("linear-responses", dir);
    }
}

/// Where this vault's pack organ builds are written (FIX 3565): the
/// supervisor's `--organ-dir`, else `organs` under the data directory, on
/// the tenant's own storage either way and never the shared temp directory.
/// It is made private when missing and checked with a write, as
/// [`owner_host`] checks its storage; one it cannot make is said with its
/// reason, and an organ install then names its own failure.
#[cfg(unix)]
pub(super) fn organ_dir(managed: &super::args::ManagedArgs) -> PathBuf {
    let dir = managed
        .organ_dir
        .clone()
        .unwrap_or_else(|| managed.data_dir.join("organs"));
    if let Err(error) = prepare(&dir, true) {
        tracing::warn!(
            reason = "owner_storage_unavailable",
            storage = "organs",
            dir = %dir.display(),
            error = %format!("{error:#}"),
            "owner storage is not usable; pack organ installs fail until it is"
        );
    } else {
        say_if_unencrypted("organs", &dir);
    }
    dir
}

/// `<data_dir>.rehearsals`, beside the data directory as its backups are.
fn rehearsal_dir(data_dir: &Path) -> PathBuf {
    beside(data_dir, "rehearsals")
}

/// `<data_dir>.linear-responses`: the direct Linear mirror's response
/// custody, beside the data directory as its backups are, never under the
/// read-only `/config`.
pub(super) fn linear_response_dir(data_dir: &Path) -> PathBuf {
    beside(data_dir, "linear-responses")
}

/// `<data_dir>.<suffix>`, a sibling of the data directory.
fn beside(data_dir: &Path, suffix: &str) -> PathBuf {
    let name = data_dir.file_name().map_or_else(
        || "vault".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    data_dir.with_file_name(format!("{name}.{suffix}"))
}

/// Says when `dir`, made and written, has no fscrypt policy, or when its
/// policy cannot be read (FIX 5606), opening it read-only and never through a
/// link. It only says so: the storage is used as it is either way, a policy
/// other than the data directory's says nothing, and nothing is changed on
/// disk. fscrypt is Linux's; elsewhere nothing is said.
fn say_if_unencrypted(storage: &str, dir: &Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;

        use super::isolation::{FscryptPolicy, fscrypt_policy};
        let policy = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(dir)
            .map_or_else(FscryptPolicy::Unverified, |held| fscrypt_policy(&held));
        match policy {
            FscryptPolicy::Present => {}
            FscryptPolicy::Absent => tracing::warn!(
                reason = "owner_storage_unencrypted",
                storage,
                dir = %dir.display(),
                "owner storage has no fscrypt policy: fscrypt does not encrypt this directory at \
                 rest; it is used as it is"
            ),
            FscryptPolicy::Unverified(error) => tracing::warn!(
                reason = "owner_storage_encryption_unverified",
                storage,
                dir = %dir.display(),
                %error,
                "could not read owner storage's fscrypt policy; it is used as it is"
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (storage, dir);
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
