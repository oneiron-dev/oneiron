//! Engine comment requests over the docedit organ's PowerPoint comment types.

use crate::entity_id::EntityId;
pub use oneiron_docedit::pptx_comments::{
    PptxAnchorOutcome, PptxAuthor, PptxCommentAction, PptxCommentEffects, PptxCommentTarget,
    PptxDriftReason, PptxError, PptxInspection, PptxShapeIdentity, PptxSlideIdentity,
};
use oneiron_docedit::pptx_comments::{PptxCommentEdit, guid};
use serde::{Deserialize, Serialize};

pub(super) type PatchResult<T> = std::result::Result<T, PptxError>;

/// One narrow operation. `thread_id` is also the exported root comment GUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxCommentPatch {
    /// Engine identities retained independently of the displayed Office author.
    #[serde(with = "entity_ref")]
    pub asked_by: EntityId,
    #[serde(with = "entity_ref")]
    pub answered_by: EntityId,
    pub author: PptxAuthor,
    #[serde(with = "entity_ref")]
    pub thread_id: EntityId,
    /// Unique reply GUID; for Add this must equal `thread_id`.
    #[serde(with = "entity_ref")]
    pub comment_id: EntityId,
    /// UTC Unix milliseconds; serialized as an OOXML dateTime.
    pub at: u64,
    pub action: PptxCommentAction,
}

impl PptxCommentPatch {
    /// The organ's edit: Office identities only, the engine actors kept here.
    pub(super) fn edit(&self) -> PptxCommentEdit {
        PptxCommentEdit {
            author: self.author.clone(),
            thread_id: guid(*self.thread_id.as_bytes()),
            comment_id: guid(*self.comment_id.as_bytes()),
            at: self.at,
            action: self.action.clone(),
        }
    }
}

/// Keeps package refusals typed while retaining the existing vault error as a source.
#[derive(Debug, thiserror::Error)]
pub enum PptxProposalError {
    #[error(transparent)]
    Patch(#[from] PptxError),
    #[error(transparent)]
    Vault(#[from] crate::error::Error),
}

mod entity_ref {
    use crate::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let value = String::deserialize(deserializer)?;
        let id = EntityId::from_hex(&value).map_err(serde::de::Error::custom)?;
        if id.to_hex() != value {
            return Err(serde::de::Error::custom("noncanonical comment entity ref"));
        }
        Ok(id)
    }
}
