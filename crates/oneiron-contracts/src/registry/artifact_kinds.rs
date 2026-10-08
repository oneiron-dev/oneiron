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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{
        ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_REGISTRY, TypeByteFamily,
        family_of,
    };

    #[test]
    fn code_and_blob_share_one_artifact_family_not_one_allocation_family() {
        assert_eq!(
            artifact_family_kind_of(ENTITY_TYPE_CODE_ARTIFACT),
            Some(ArtifactFamilyKindId::Code)
        );
        assert_eq!(
            artifact_family_kind_of(ENTITY_TYPE_BLOB_ARTIFACT),
            Some(ArtifactFamilyKindId::Blob)
        );
        assert_eq!(
            ArtifactFamilyKindId::Code.family(),
            ArtifactFamilyId::Artifact
        );
        assert_eq!(
            ArtifactFamilyKindId::Blob.family(),
            ArtifactFamilyId::Artifact
        );
        assert_eq!(
            family_of(ENTITY_TYPE_CODE_ARTIFACT),
            Some(TypeByteFamily::Code)
        );
        assert_eq!(
            family_of(ENTITY_TYPE_BLOB_ARTIFACT),
            Some(TypeByteFamily::Documents)
        );
        for byte in 0..=u8::MAX {
            let expected = match byte {
                ENTITY_TYPE_CODE_ARTIFACT => Some(ArtifactFamilyKindId::Code),
                ENTITY_TYPE_BLOB_ARTIFACT => Some(ArtifactFamilyKindId::Blob),
                _ => None,
            };
            assert_eq!(artifact_family_kind_of(byte), expected, "byte {byte}");
        }
        assert_eq!(
            ENTITY_TYPE_REGISTRY
                .iter()
                .filter(|row| row.artifact_kind.is_some())
                .count(),
            2
        );
    }
}
