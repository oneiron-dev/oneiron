//! Canonical recovery artifact loader shell.
//!
//! The shell is deliberately small: it validates the self-describing artifact
//! header before handing payload bytes to a caller. Corrupt or unsupported
//! artifacts are moved into a deterministic quarantine path next to the source
//! artifact so the original bytes remain available for later inspection.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Magic prefix for recovery artifacts: `ONEIRONA`.
pub const RECOVERY_ARTIFACT_MAGIC: [u8; 8] = *b"ONEIRONA";
/// Current recovery artifact shell version.
pub const RECOVERY_ARTIFACT_VERSION: u16 = 1;
/// Sibling suffix prefix for invalid recovery artifact quarantine.
pub const RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX: &str = ".invalid-";

const VERSION_OFFSET: usize = RECOVERY_ARTIFACT_MAGIC.len();
const KIND_OFFSET: usize = VERSION_OFFSET + 2;
const LEN_OFFSET: usize = KIND_OFFSET + 2;
const CHECKSUM_OFFSET: usize = LEN_OFFSET + 8;
const HEADER_LEN: usize = CHECKSUM_OFFSET + 32;
const QUARANTINE_SUFFIX_RETRY_LIMIT: usize = 2;

/// Recovery ladder result for a filesystem artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryArtifactLoad {
    /// The artifact passed magic, version, length, and checksum validation.
    Ready(RecoveryArtifact),
    /// No artifact exists at the requested path.
    Missing { path: PathBuf },
    /// The artifact was invalid or unsupported and was moved aside intact.
    Quarantined(QuarantinedArtifact),
}

/// Validated artifact payload and its type discriminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryArtifact {
    artifact_type: u16,
    payload: Vec<u8>,
}

impl RecoveryArtifact {
    #[must_use]
    pub fn artifact_type(&self) -> u16 {
        self.artifact_type
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Quarantine outcome with the typed validation state that triggered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedArtifact {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub failure: RecoveryArtifactFailure,
}

/// Typed validation failures for actionable recovery reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryArtifactFailure {
    Truncated {
        len: usize,
        min_len: usize,
    },
    MagicMismatch {
        found: [u8; 8],
    },
    UnsupportedVersion {
        found: u16,
        supported: u16,
    },
    UnexpectedType {
        found: u16,
        expected: u16,
    },
    LengthMismatch {
        declared: u64,
        actual: u64,
    },
    ChecksumMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl RecoveryArtifactFailure {
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "artifact header is truncated",
            Self::MagicMismatch { .. } => "artifact magic mismatch",
            Self::UnsupportedVersion { .. } => "artifact version is unsupported",
            Self::UnexpectedType { .. } => "artifact type is unsupported",
            Self::LengthMismatch { .. } => "artifact payload length mismatch",
            Self::ChecksumMismatch { .. } => "artifact checksum mismatch",
        }
    }
}

/// Builds canonical shell bytes for a recovery artifact payload.
pub fn encode_recovery_artifact(artifact_type: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let payload_len = payload.len() as u64;
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(&RECOVERY_ARTIFACT_MAGIC);
    bytes.extend_from_slice(&RECOVERY_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&artifact_type.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&recovery_artifact_checksum(artifact_type, payload));
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Validates shell bytes and returns payload only after every gate passes.
pub fn decode_recovery_artifact(
    bytes: &[u8],
    expected_artifact_type: u16,
) -> Result<RecoveryArtifact> {
    validate_recovery_artifact(bytes, expected_artifact_type)
        .map_err(|failure| Error::InvalidRecoveryArtifact(failure.reason()))
}

/// Reads an artifact from `path`; invalid artifacts are quarantined intact.
pub fn load_recovery_artifact(
    path: impl AsRef<Path>,
    expected_artifact_type: u16,
) -> Result<RecoveryArtifactLoad> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(bytes) => match validate_recovery_artifact(&bytes, expected_artifact_type) {
            Ok(artifact) => Ok(RecoveryArtifactLoad::Ready(artifact)),
            Err(failure) => {
                let quarantine_path = quarantine_invalid_artifact(path, &bytes)?;
                Ok(RecoveryArtifactLoad::Quarantined(QuarantinedArtifact {
                    original_path: path.to_path_buf(),
                    quarantine_path,
                    failure,
                }))
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(RecoveryArtifactLoad::Missing {
                path: path.to_path_buf(),
            })
        }
        Err(err) => Err(Error::Io(err)),
    }
}

fn validate_recovery_artifact(
    bytes: &[u8],
    expected_artifact_type: u16,
) -> std::result::Result<RecoveryArtifact, RecoveryArtifactFailure> {
    if bytes.len() < HEADER_LEN {
        return Err(RecoveryArtifactFailure::Truncated {
            len: bytes.len(),
            min_len: HEADER_LEN,
        });
    }

    let magic: [u8; 8] = bytes[..RECOVERY_ARTIFACT_MAGIC.len()]
        .try_into()
        .expect("magic slice length is fixed");
    if magic != RECOVERY_ARTIFACT_MAGIC {
        return Err(RecoveryArtifactFailure::MagicMismatch { found: magic });
    }

    let version = u16::from_le_bytes(
        bytes[VERSION_OFFSET..KIND_OFFSET]
            .try_into()
            .expect("version slice length is fixed"),
    );
    if version != RECOVERY_ARTIFACT_VERSION {
        return Err(RecoveryArtifactFailure::UnsupportedVersion {
            found: version,
            supported: RECOVERY_ARTIFACT_VERSION,
        });
    }

    let artifact_type = u16::from_le_bytes(
        bytes[KIND_OFFSET..LEN_OFFSET]
            .try_into()
            .expect("artifact type slice length is fixed"),
    );
    let declared_len = u64::from_le_bytes(
        bytes[LEN_OFFSET..CHECKSUM_OFFSET]
            .try_into()
            .expect("payload length slice length is fixed"),
    );
    let payload = &bytes[HEADER_LEN..];
    let actual_len = payload.len() as u64;
    if declared_len != actual_len {
        return Err(RecoveryArtifactFailure::LengthMismatch {
            declared: declared_len,
            actual: actual_len,
        });
    }

    let expected_checksum: [u8; 32] = bytes[CHECKSUM_OFFSET..HEADER_LEN]
        .try_into()
        .expect("checksum slice length is fixed");
    let actual_checksum = recovery_artifact_checksum(artifact_type, payload);
    if expected_checksum != actual_checksum {
        return Err(RecoveryArtifactFailure::ChecksumMismatch {
            expected: expected_checksum,
            actual: actual_checksum,
        });
    }
    if artifact_type != expected_artifact_type {
        return Err(RecoveryArtifactFailure::UnexpectedType {
            found: artifact_type,
            expected: expected_artifact_type,
        });
    }

    Ok(RecoveryArtifact {
        artifact_type,
        payload: payload.to_vec(),
    })
}

fn recovery_artifact_checksum(artifact_type: u16, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(artifact_type.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn quarantine_invalid_artifact(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    'suffixes: for suffix in 1..=u16::MAX {
        let candidate = invalid_artifact_path(path, suffix);
        for _attempt in 0..=QUARANTINE_SUFFIX_RETRY_LIMIT {
            match persist_quarantine_bytes(&candidate, bytes) {
                Ok(()) => {
                    remove_original_if_unchanged(path, bytes)?;
                    return Ok(candidate);
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    match artifact_file_matches(&candidate, bytes) {
                        Ok(true) => {
                            remove_original_if_unchanged(path, bytes)?;
                            return Ok(candidate);
                        }
                        Ok(false) => continue 'suffixes,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(Error::Io(err)),
                    }
                }
                Err(err) => return Err(Error::Io(err)),
            }
        }
    }

    Err(Error::RecoveryArtifactQuarantineExhausted {
        path: path.to_path_buf(),
    })
}

fn artifact_file_matches(path: &Path, bytes: &[u8]) -> std::io::Result<bool> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() || path_metadata.len() != bytes.len() as u64 {
        return Ok(false);
    }

    let mut file = File::open(path)?;
    let file_metadata = file.metadata()?;
    if !file_metadata.file_type().is_file() || file_metadata.len() != bytes.len() as u64 {
        return Ok(false);
    }

    let mut offset = 0;
    let mut buffer = [0_u8; 8192];
    while offset < bytes.len() {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(false);
        }
        let end = offset + read;
        if end > bytes.len() || buffer[..read] != bytes[offset..end] {
            return Ok(false);
        }
        offset = end;
    }

    let mut trailing = [0_u8; 1];
    Ok(file.read(&mut trailing)? == 0)
}

fn invalid_artifact_path(path: &Path, suffix: u16) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file_name = path
        .file_name()
        .map_or_else(|| OsString::from("artifact"), OsString::from);
    file_name.push(format!("{RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX}{suffix}"));
    parent.join(file_name)
}

fn persist_quarantine_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(path);
        return Err(err);
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(path);
        return Err(err);
    }
    Ok(())
}

fn remove_original_if_unchanged(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::read(path) {
        Ok(current) if current == bytes => fs::remove_file(path).map_err(Error::Io),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::Io(err)),
    }
}

#[cfg(test)]
mod tests;
