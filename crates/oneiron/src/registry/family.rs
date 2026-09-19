//! Shared deliverable-family identity, independent of storage body or export format.
use super::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CODE_ARTIFACT};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactFamilyKind {
    Code,
    Blob,
}
impl ArtifactFamilyKind {
    pub const fn family_id(self) -> &'static str {
        "artifact"
    }
    pub const fn kind_id(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Blob => "blob",
        }
    }
}
/// Unknown bytes never inherit artifact permissions or projections.
pub const fn artifact_family_kind(entity_type: u8) -> Option<ArtifactFamilyKind> {
    match entity_type {
        ENTITY_TYPE_CODE_ARTIFACT => Some(ArtifactFamilyKind::Code),
        ENTITY_TYPE_BLOB_ARTIFACT => Some(ArtifactFamilyKind::Blob),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_registered_artifact_bodies_join_the_family() {
        assert_eq!(
            artifact_family_kind(ENTITY_TYPE_CODE_ARTIFACT),
            Some(ArtifactFamilyKind::Code)
        );
        assert_eq!(
            artifact_family_kind(ENTITY_TYPE_BLOB_ARTIFACT),
            Some(ArtifactFamilyKind::Blob)
        );
        assert_eq!(
            ArtifactFamilyKind::Code.family_id(),
            ArtifactFamilyKind::Blob.family_id()
        );
        for byte in 0..=u8::MAX {
            if ![ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_BLOB_ARTIFACT].contains(&byte) {
                assert!(artifact_family_kind(byte).is_none());
            }
        }
    }
}
