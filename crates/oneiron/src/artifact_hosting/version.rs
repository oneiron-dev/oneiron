//! Pinned export identity. A blob pointer never means the moving head.
use crate::{
    EntityId,
    codebase::CodebaseForkHash,
    error::{Error, Result},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPinnedVersion {
    Code(CodebaseForkHash),
    Blob { artifact_id: EntityId, version: u64 },
}
impl ArtifactPinnedVersion {
    pub(super) fn encode(self, stale_override: bool) -> Vec<u8> {
        let mut bytes = vec![u8::from(stale_override)];
        match self {
            Self::Code(hash) => {
                bytes.push(0);
                bytes.extend_from_slice(&hash);
            }
            Self::Blob {
                artifact_id,
                version,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(artifact_id.as_bytes());
                bytes.extend_from_slice(&version.to_be_bytes());
            }
        }
        bytes
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, bool)> {
        let invalid = || Error::CorruptedIndex("artifact pinned version");
        let stale = match bytes.first() {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(invalid()),
        };
        let version = match (bytes.get(1), bytes.len()) {
            (Some(0), 34) => Self::Code(bytes[2..].try_into().map_err(|_| invalid())?),
            (Some(1), 26) => {
                let artifact_id =
                    EntityId::from_bytes(bytes[2..18].try_into().map_err(|_| invalid())?)?;
                let version = u64::from_be_bytes(bytes[18..].try_into().map_err(|_| invalid())?);
                if version == 0 {
                    return Err(invalid());
                }
                Self::Blob {
                    artifact_id,
                    version,
                }
            }
            _ => return Err(invalid()),
        };
        Ok((version, stale))
    }
}
