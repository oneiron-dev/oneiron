//! Semantic artifact kinds under the one artifact family (ARCH-0078).
//!
//! These are not byte-allocation families: code and blob have different
//! TypeByteFamily ranges but implement the same artifact-family contract.

/// The single semantic family shared by deliverable kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFamilyId {
    Artifact,
}

/// The registered artifact body kind. Future bodies add variants here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFamilyKindId {
    Code,
    Blob,
}

impl ArtifactFamilyKindId {
    #[must_use]
    pub const fn family(self) -> ArtifactFamilyId {
        ArtifactFamilyId::Artifact
    }
}

/// Returns the semantic artifact kind for a registered entity type, or `None`
/// for unknown bytes and registered non-artifact entity types.
#[must_use]
pub fn artifact_family_kind_of(type_byte: u8) -> Option<ArtifactFamilyKindId> {
    super::entity_type_registry_entry(type_byte).and_then(|entry| entry.artifact_kind)
}
