//! The backup handoff between a managed vault's engine and its node's
//! supervisor (LC backup shipper rows, Engine 10-20).
//!
//! A label's handoff directory, `[backup].dir/.backup-handoff/<label>/`
//! (0700, its files 0600), pins that label's backups against retention: the
//! engine prunes one only once the supervisor's root-stage ack for it is
//! there and names the file the engine holds, byte for byte. The managed
//! setup installs the directory and its policy file
//! ([`install_backup_handoff_policy`]); a label without one keeps plain
//! retention.
//!
//! The supervisor writes one ack per backup, after its held-descriptor copy
//! to its root stage is checked and synced: `stage-ack-<commitment
//! digest>.json` ([`backup_stage_ack_file_name`]), a [`BackupStageAck`], as a
//! regular 0600 file owned by the vault's user ([`write_private_file`], then
//! its owner set). The engine reads it no-follow and only as such a file
//! ([`read_private_file`]), and checks it against the held backup's size and
//! BLAKE3 under its backup lock. A missing, unreadable, replaced or
//! mismatched ack, or any I/O failure, keeps the backup: pending, never
//! unpinned, evicted or dropped. A stage ack is not a remote delivery.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The directory under `[backup].dir` that holds every label's handoff.
pub const BACKUP_HANDOFF_DIR: &str = ".backup-handoff";
/// The policy file in a label's handoff directory.
pub const BACKUP_HANDOFF_POLICY_FILE: &str = "policy.json";
/// The schema version of the policy file and of an ack.
pub const BACKUP_HANDOFF_SCHEMA_VERSION: u32 = 1;

/// A label's handoff policy: its backups wait for a stage ack before
/// retention prunes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupHandoffPolicy {
    pub schema_version: u32,
    /// The backup label the policy pins.
    pub label: String,
}

/// The supervisor's root-stage ack for one backup: what it copied and checked.
/// Ids and digests are lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupStageAck {
    pub schema_version: u32,
    /// The engine's vault id the artifact names, 64 hex.
    pub engine_vault_id: String,
    /// The backup label.
    pub label: String,
    /// The backup's file name in `[backup].dir`.
    pub file: String,
    /// BLAKE3 of the artifact's signed commitment, 64 hex: the ack's key.
    pub commitment_digest: String,
    /// The artifact's length in bytes.
    pub size: u64,
    /// BLAKE3 of every byte of the artifact, 64 hex.
    pub outer_blake3: String,
    /// The supervisor's id for the stage copy.
    pub stage_id: String,
}

/// The facts of a backup the engine holds, which an ack must name exactly.
#[derive(Debug, Clone, Copy)]
pub struct HeldBackup<'a> {
    pub engine_vault_id: &'a [u8; 32],
    pub label: &'a str,
    pub file: &'a str,
    pub commitment_digest: &'a [u8; 32],
    pub size: u64,
    pub outer_blake3: &'a [u8; 32],
}

impl BackupStageAck {
    /// The ack's JSON.
    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
    }

    /// An ack read back, `None` for bytes that are not one of this schema.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice::<Self>(bytes)
            .ok()
            .filter(|ack| ack.schema_version == BACKUP_HANDOFF_SCHEMA_VERSION)
    }

    /// Whether this ack names exactly `held`: its vault, label, file,
    /// commitment digest, size and outer BLAKE3, with a stage named.
    #[must_use]
    pub fn names(&self, held: &HeldBackup<'_>) -> bool {
        self.schema_version == BACKUP_HANDOFF_SCHEMA_VERSION
            && self.engine_vault_id == crate::hex(held.engine_vault_id)
            && self.label == held.label
            && self.file == held.file
            && self.commitment_digest == crate::hex(held.commitment_digest)
            && self.size == held.size
            && self.outer_blake3 == crate::hex(held.outer_blake3)
            && !self.stage_id.is_empty()
    }
}

/// `label`'s handoff directory under `backup_dir`, or `None` for a label that
/// is not one plain path component.
#[must_use]
pub fn backup_handoff_dir(backup_dir: &Path, label: &str) -> Option<PathBuf> {
    plain_component(label).then(|| backup_dir.join(BACKUP_HANDOFF_DIR).join(label))
}

/// The ack file of the backup whose commitment digest is `commitment_digest`
/// (64 lowercase hex), or `None` for anything else.
#[must_use]
pub fn backup_stage_ack_file_name(commitment_digest: &str) -> Option<String> {
    let hex = commitment_digest.len() == 64
        && commitment_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    hex.then(|| format!("stage-ack-{commitment_digest}.json"))
}

/// Installs `label`'s handoff policy under `backup_dir`: its handoff directory,
/// each level made private (0700) where missing, and the policy file written
/// durably (0600). From then on retention of `label`'s backups waits for the
/// supervisor's stage ack. Installing again rewrites the same policy.
pub fn install_backup_handoff_policy(backup_dir: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let dir = backup_handoff_dir(backup_dir, label)
        .ok_or_else(|| anyhow::anyhow!("a backup label must be one plain path component"))?;
    make_private_dir(backup_dir, true)?;
    make_private_dir(&backup_dir.join(BACKUP_HANDOFF_DIR), false)?;
    make_private_dir(&dir, false)?;
    let policy = BackupHandoffPolicy {
        schema_version: BACKUP_HANDOFF_SCHEMA_VERSION,
        label: label.to_owned(),
    };
    write_private_file(
        &dir,
        BACKUP_HANDOFF_POLICY_FILE,
        &serde_json::to_vec_pretty(&policy)?,
    )?;
    Ok(dir)
}

fn make_private_dir(dir: &Path, recursive: bool) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        other => other,
    }
}

/// Writes `bytes` as `dir/name` durably and privately: a temporary sibling
/// made new at 0600, written and synced, renamed over `name`, then `dir`
/// synced. A crash leaves the whole file or the one before it.
pub fn write_private_file(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|()| std::fs::rename(&tmp, &target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(target)
}

/// What [`read_private_file`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateFile {
    /// Nothing is there.
    Missing,
    /// Something is there that is not a private file of this user: a link, a
    /// directory or device, another owner, other modes, or more than one name.
    NotPrivate,
    /// The file's bytes.
    Bytes(Vec<u8>),
}

/// Reads `path` only as a private file of this process's effective user: not
/// followed through a symlink, a regular file with one link, mode 0600. Where
/// that cannot be checked (not unix), it is [`PrivateFile::NotPrivate`].
pub fn read_private_file(path: &Path) -> std::io::Result<PrivateFile> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PrivateFile::Missing);
            }
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Ok(PrivateFile::NotPrivate);
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        // SAFETY: `geteuid` takes no argument and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_file()
            || metadata.uid() != euid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Ok(PrivateFile::NotPrivate);
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(PrivateFile::Bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(PrivateFile::NotPrivate)
    }
}

/// One path component a label may be: not empty, not hidden, no separator.
fn plain_component(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '\0'])
        && Path::new(name).components().count() == 1
}
