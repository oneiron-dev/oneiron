//! Canonical skill identity: content hash, tree hash, and hub cross-check.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::record::SkillRecord;
use crate::error::ArtifactError;

/// Byte length of a lowercase-hex SHA-256 canonical content hash on the wire.
pub const SKILL_CONTENT_HASH_HEX_LEN: usize = 64;

/// Upper bound on one canonicalized skill-tree path (relative, `/`-joined).
pub const SKILL_TREE_PATH_MAX_BYTES: usize = 1024;

/// Domain-separation tag for the canonical skill-tree hash. Versioned so a
/// future canonicalization change mints a new tag instead of silently
/// re-keying every stored identity.
pub const SKILL_TREE_HASH_DOMAIN: &[u8] = b"oneiron.skill.tree.v1\0";

/// Canonical skill identity: SHA-256 over the canonicalized file tree
/// (ARCH-0053 §7, ONE-1735). Recomputable from any source, so the same
/// content fetched via two hubs is ONE entity — hub refs live in the
/// separate mutable alias/provenance layer, never in this hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SkillContentHash([u8; 32]);

impl SkillContentHash {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Pinned wire form: 64 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(SKILL_CONTENT_HASH_HEX_LEN);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble < 16"));
            out.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble < 16"));
        }
        out
    }

    /// Parses the pinned wire form: exactly 64 lowercase hex characters.
    pub fn parse_hex(hex: &str) -> Result<Self> {
        const CONTEXT: &str = "contentHash must be 64 lowercase hex characters";
        if hex.len() != SKILL_CONTENT_HASH_HEX_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(chunk[0])
                .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)))?;
            let lo = hex_nibble(chunk[1])
                .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)))?;
            bytes[index] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Computes the canonical identity of a skill file tree (ARCH-0053 §7):
/// SHA-256 over a domain-tagged, length-prefixed, path-sorted encoding of
/// every `(relative path, content)` pair. Input order never matters; the
/// encoding is injective (lengths are prefixed), so no two distinct trees
/// collide by concatenation tricks.
///
/// Path canonicalization is strict and fail-closed: relative, `/`-joined,
/// no empty / `.` / `..` segments, no backslashes, colons (kills `C:/…`
/// drive-absolute paths), or NULs, at most [`SKILL_TREE_PATH_MAX_BYTES`]
/// bytes, no duplicates — duplicate detection ASCII-case-folds (`Foo` vs
/// `foo` alias on default Windows/macOS filesystems; full Unicode folding
/// is out of scope). An empty tree has no identity.
pub fn canonical_skill_tree_hash<'a, I>(files: I) -> Result<SkillContentHash>
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut entries: Vec<(&str, &[u8])> = Vec::new();
    for (path, content) in files {
        validate_skill_tree_path(path)?;
        entries.push((path, content));
    }
    if entries.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "skill tree must contain at least one file",
        )));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    // ASCII case-fold duplicate rejection (subsumes exact duplicates):
    // `Foo` and `foo` alias on default Windows/macOS filesystems, so
    // hashing both could authenticate a different tree from the one that
    // executes.
    let mut folded = HashSet::new();
    for (path, _) in &entries {
        if !folded.insert(path.to_ascii_lowercase()) {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "duplicate skill tree path",
            )));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(SKILL_TREE_HASH_DOMAIN);
    hasher.update((entries.len() as u64).to_be_bytes());
    for (path, content) in entries {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((content.len() as u64).to_be_bytes());
        hasher.update(content);
    }
    Ok(SkillContentHash(hasher.finalize().into()))
}

fn validate_skill_tree_path(path: &str) -> Result<()> {
    const CONTEXT: &str = "skill tree paths must be relative, `/`-joined, without empty/dot segments, backslashes, colons, or NULs";
    if path.is_empty()
        || path.len() > SKILL_TREE_PATH_MAX_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
    {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
    }
    Ok(())
}

/// Cross-checks a hub-declared per-skill hash against the record's canonical
/// identity (ONE-1735; consumed by the skills-hub adapters, e.g. the
/// ONE-1741 native adapter whose hub publishes per-skill SHA-256). Case of
/// the declared hex is normalized; everything else is fail-closed: a record
/// without a canonical hash cannot be cross-checked, and a mismatch is an
/// error, never a warning.
pub fn cross_check_declared_content_hash(record: &SkillRecord, declared_hex: &str) -> Result<()> {
    let Some(canonical) = record.content_hash else {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "cannot cross-check: record carries no canonical content hash",
        )));
    };
    let declared = SkillContentHash::parse_hex(&declared_hex.to_ascii_lowercase())?;
    if declared != canonical {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "declared per-skill hash does not match canonical content hash",
        )));
    }
    Ok(())
}
