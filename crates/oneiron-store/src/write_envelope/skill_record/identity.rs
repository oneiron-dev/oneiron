//! Canonical skill identity: content hash, tree hash, and hub cross-check.

use std::collections::HashSet;

use oneiron_contracts::error::{Error, Result};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

use super::record::SkillRecord;
use oneiron_contracts::error::ArtifactError;

/// Byte length of a lowercase-hex SHA-256 canonical content hash on the wire.
pub const SKILL_CONTENT_HASH_HEX_LEN: usize = 64;

/// Upper bound on one canonicalized skill-tree path (relative, `/`-joined).
pub const SKILL_TREE_PATH_MAX_BYTES: usize = 1024;

/// Domain-separation tag for the canonical skill-tree hash. Versioned so a
/// future canonicalization change mints a new tag instead of silently
/// re-keying every stored identity. It is the tag of
/// `oneiron_contracts::fingerprint::purposes::skill::TREE_HASH`, which writes it.
pub const SKILL_TREE_HASH_DOMAIN: &[u8] = purposes::skill::TREE_HASH.tag().as_bytes();

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
        oneiron_hex::encode(&self.0)
    }

    /// Parses the pinned wire form: exactly 64 lowercase hex characters.
    pub fn parse_hex(hex: &str) -> Result<Self> {
        const CONTEXT: &str = "contentHash must be 64 lowercase hex characters";
        oneiron_hex::decode::<32>(hex)
            .map(Self)
            .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)))
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
/// bytes, no file/directory collisions or duplicates — detection ASCII-case-folds (`Foo` vs
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

    for path in &folded {
        if path
            .match_indices('/')
            .any(|(index, _)| folded.contains(&path[..index]))
        {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "skill tree path is both a file and a directory",
            )));
        }
    }

    let mut digest = LegacyDigest::new(purposes::skill::TREE_HASH);
    digest.len_u64_be(entries.len());
    for (path, content) in entries {
        digest
            .len_u64_be(path.len())
            .raw(path.as_bytes())
            .len_u64_be(content.len())
            .raw(content);
    }
    Ok(SkillContentHash(digest.finish()))
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
