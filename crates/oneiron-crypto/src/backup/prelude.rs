//! The fixed prelude every sealed artifact starts with, and the registry
//! binding a version 2 prelude carries (FIX 5826).
//!
//! ```text
//! v1: "ONEIRONS" ‖ u16be 1 ‖ u8 kind ‖ engine vault id (32) ‖ snapshot (32)
//!       ‖ u32be key header length                                     79 bytes
//! v2: "ONEIRONS" ‖ u16be 2 ‖ u8 kind ‖ engine vault id (32)
//!       ‖ u8 has_registry ‖ binding (32) ‖ snapshot (32)
//!       ‖ u32be key header length                                    112 bytes
//! ```
//!
//! The engine writes and reads version 2 only. Version 1 is read here for a
//! host that still holds artifacts written before it (Hypnos's dual reader).

use std::io::Read;

use super::wire::{ArtifactKind, BACKUP_MAGIC};
use crate::error::{Error, Result};

/// The prelude version written before the registry binding.
pub const ARTIFACT_VERSION_V1: u16 = 1;
/// The prelude version with the registry binding: the one the engine writes.
pub const ARTIFACT_VERSION_V2: u16 = 2;
/// A version 1 prelude's fixed length.
pub const PRELUDE_V1_LEN: usize = 79;
/// A version 2 prelude's fixed length.
pub const PRELUDE_V2_LEN: usize = 112;
/// The bytes of a version 1 prelude that name whose artifact it is: magic,
/// version, kind, engine vault id.
pub const IDENTITY_V1_LEN: usize = 43;
/// The bytes of a version 2 prelude that name whose artifact it is: as
/// version 1's, then the registry binding.
pub const IDENTITY_V2_LEN: usize = 76;
/// The BLAKE3 `derive_key` context of the registry binding.
pub const REGISTRY_BINDING_CONTEXT: &str = "oneiron/backup-registry-binding/v1";

/// Where the version field ends: magic, then `u16be` version.
const VERSION_END: usize = BACKUP_MAGIC.len() + 2;

/// The binding of an engine vault id to the registry's id for that vault:
/// `BLAKE3-derive_key("oneiron/backup-registry-binding/v1", engine vault id ‖
/// u32be registry id length ‖ registry id)`, the id as its UTF-8 bytes. It
/// says which registry vault an artifact was written for; it proves nothing
/// about who wrote it, which only the signature does.
pub fn registry_binding(engine_vault_id: &[u8; 32], registry_id: &str) -> Result<[u8; 32]> {
    let len = u32::try_from(registry_id.len()).map_err(|_| Error::FieldLength {
        field: "registry id",
        len: registry_id.len(),
        min: 0,
        max: u32::MAX as usize,
    })?;
    let mut hasher = blake3::Hasher::new_derive_key(REGISTRY_BINDING_CONTEXT);
    hasher.update(engine_vault_id);
    hasher.update(&len.to_be_bytes());
    hasher.update(registry_id.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

/// An artifact's fixed prelude. Nothing in it is authentic until the
/// artifact's signature verifies against a pinned signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactPrelude {
    /// [`ARTIFACT_VERSION_V1`] or [`ARTIFACT_VERSION_V2`].
    pub version: u16,
    pub kind: ArtifactKind,
    /// The engine's vault id.
    pub engine_vault_id: [u8; 32],
    /// The registry binding ([`registry_binding`]); `None` where a version 2
    /// prelude says it has none, and always for version 1.
    pub registry_binding: Option<[u8; 32]>,
    pub snapshot: [u8; 32],
    /// The length of the key header that follows the prelude.
    pub key_header_len: u32,
}

impl ArtifactPrelude {
    /// The fixed length of a prelude of `version`.
    pub fn fixed_len(version: u16) -> Result<usize> {
        match version {
            ARTIFACT_VERSION_V1 => Ok(PRELUDE_V1_LEN),
            ARTIFACT_VERSION_V2 => Ok(PRELUDE_V2_LEN),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    /// The wire form. A version 1 prelude carries no binding, so one with a
    /// binding is refused.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::fixed_len(self.version)?);
        out.extend_from_slice(BACKUP_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.kind.code());
        out.extend_from_slice(&self.engine_vault_id);
        match (self.version, self.registry_binding) {
            (ARTIFACT_VERSION_V1, None) => {}
            (ARTIFACT_VERSION_V1, Some(_)) => return Err(Error::BackupMalformed("prelude")),
            (_, binding) => {
                out.push(u8::from(binding.is_some()));
                out.extend_from_slice(&binding.unwrap_or([0; 32]));
            }
        }
        out.extend_from_slice(&self.snapshot);
        out.extend_from_slice(&self.key_header_len.to_be_bytes());
        Ok(out)
    }

    /// Reads one prelude, of either version, from the start of `reader`: its
    /// version first, then exactly its fixed length.
    pub fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self> {
        let mut fixed = [0u8; PRELUDE_V2_LEN];
        read_exact(reader, &mut fixed[..VERSION_END], "prelude")?;
        let version = u16::from_be_bytes([fixed[VERSION_END - 2], fixed[VERSION_END - 1]]);
        let len = Self::fixed_len(version)?;
        read_exact(reader, &mut fixed[VERSION_END..len], "prelude")?;
        Self::parse(&fixed[..len])
    }

    /// Parses exactly one prelude's fixed bytes.
    pub fn parse(fixed: &[u8]) -> Result<Self> {
        let head = identity(fixed)?.ok_or(Error::Truncated { field: "prelude" })?;
        let len = Self::fixed_len(head.version)?;
        if fixed.len() != len {
            return Err(Error::FieldLength {
                field: "prelude",
                len: fixed.len(),
                min: len,
                max: len,
            });
        }
        let rest = &fixed[identity_len(head.version)?..];
        let mut snapshot = [0u8; 32];
        snapshot.copy_from_slice(&rest[..32]);
        let mut key_header_len = [0u8; 4];
        key_header_len.copy_from_slice(&rest[32..36]);
        Ok(Self {
            version: head.version,
            kind: head.kind,
            engine_vault_id: head.engine_vault_id,
            registry_binding: head.registry_binding,
            snapshot,
            key_header_len: u32::from_be_bytes(key_header_len),
        })
    }
}

/// Whose artifact a file is, read from its first bytes alone: what a host
/// proving which files are a vault's reads, even of a partial file a crash
/// left. Not authentic: only the signature makes it so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupHead {
    pub version: u16,
    pub kind: ArtifactKind,
    /// The engine's vault id.
    pub engine_vault_id: [u8; 32],
    /// The registry binding; `None` where a version 2 head says it has none,
    /// and always for version 1.
    pub registry_binding: Option<[u8; 32]>,
}

/// How an artifact's registry binding stands against a registry id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryMatch {
    /// The artifact carries no binding: a version 1 artifact, or one written
    /// where no registry id was known.
    Absent,
    /// The binding is the one for this registry id and the artifact's engine
    /// vault id.
    Matches,
    /// The binding names another registry vault.
    Mismatch,
}

impl BackupHead {
    /// How this head's binding stands against `registry_id`.
    pub fn registry_match(&self, registry_id: &str) -> Result<RegistryMatch> {
        match_binding(self.registry_binding, &self.engine_vault_id, registry_id)
    }
}

pub(super) fn match_binding(
    binding: Option<[u8; 32]>,
    engine_vault_id: &[u8; 32],
    registry_id: &str,
) -> Result<RegistryMatch> {
    Ok(match binding {
        None => RegistryMatch::Absent,
        Some(binding) if binding == registry_binding(engine_vault_id, registry_id)? => {
            RegistryMatch::Matches
        }
        Some(_) => RegistryMatch::Mismatch,
    })
}

/// Reads whose artifact `prefix` starts, without refusing a short one: `None`
/// while `prefix` ends before the version's identity (magic, version, kind,
/// engine vault id and, for version 2, the binding), so a short partial a
/// crash left is not refused. What bytes there are must be the format: a
/// wrong magic, version or kind, or a malformed binding, is refused.
pub fn inspect_backup_prefix(prefix: &[u8]) -> Result<Option<BackupHead>> {
    identity(prefix)
}

fn identity_len(version: u16) -> Result<usize> {
    match version {
        ARTIFACT_VERSION_V1 => Ok(IDENTITY_V1_LEN),
        ARTIFACT_VERSION_V2 => Ok(IDENTITY_V2_LEN),
        other => Err(Error::UnsupportedVersion(other)),
    }
}

fn identity(prefix: &[u8]) -> Result<Option<BackupHead>> {
    let magic = &prefix[..prefix.len().min(BACKUP_MAGIC.len())];
    if magic != &BACKUP_MAGIC[..magic.len()] {
        return Err(Error::BadMagic {
            expected: "backup artifact",
        });
    }
    if prefix.len() < VERSION_END {
        return Ok(None);
    }
    let version = u16::from_be_bytes([prefix[VERSION_END - 2], prefix[VERSION_END - 1]]);
    let len = identity_len(version)?;
    let Some(&kind) = prefix.get(VERSION_END) else {
        return Ok(None);
    };
    let kind = ArtifactKind::from_code(kind).ok_or(Error::BackupMalformed("artifact kind"))?;
    if prefix.len() < len {
        return Ok(None);
    }
    let mut engine_vault_id = [0u8; 32];
    engine_vault_id.copy_from_slice(&prefix[VERSION_END + 1..VERSION_END + 33]);
    let registry_binding = if version == ARTIFACT_VERSION_V2 {
        let mut binding = [0u8; 32];
        binding.copy_from_slice(&prefix[IDENTITY_V1_LEN + 1..IDENTITY_V2_LEN]);
        match prefix[IDENTITY_V1_LEN] {
            0 if binding == [0; 32] => None,
            1 => Some(binding),
            _ => return Err(Error::BackupMalformed("registry binding")),
        }
    } else {
        None
    };
    Ok(Some(BackupHead {
        version,
        kind,
        engine_vault_id,
        registry_binding,
    }))
}

/// `read_exact`, a short read being [`Error::Truncated`] at `field` and any
/// other failure [`Error::BackupRead`].
pub(super) fn read_exact<R: Read + ?Sized>(
    reader: &mut R,
    out: &mut [u8],
    field: &'static str,
) -> Result<()> {
    reader.read_exact(out).map_err(|error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => Error::Truncated { field },
        kind => Error::BackupRead(kind),
    })
}
