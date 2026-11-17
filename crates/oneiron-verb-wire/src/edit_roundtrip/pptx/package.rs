//! Moved from `crates/oneiron/src/edit_roundtrip/pptx/package.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_docedit::pptx_comments::PptxAnchorOutcome;
pub use oneiron_docedit::pptx_comments::PptxAuthor;
pub use oneiron_docedit::pptx_comments::PptxCommentAction;
use oneiron_docedit::pptx_comments::PptxCommentEdit;
pub use oneiron_docedit::pptx_comments::PptxCommentEffects;
pub use oneiron_docedit::pptx_comments::PptxCommentTarget;
pub use oneiron_docedit::pptx_comments::PptxDriftReason;
pub use oneiron_docedit::pptx_comments::PptxError;
pub use oneiron_docedit::pptx_comments::PptxInspection;
pub use oneiron_docedit::pptx_comments::PptxShapeIdentity;
pub use oneiron_docedit::pptx_comments::PptxSlideIdentity;
use oneiron_docedit::pptx_comments::guid;
use serde::Deserialize;
use serde::Serialize;

/// One narrow operation. `thread_id` is also the exported root comment GUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PptxCommentPatch {
    /// Engine identities retained independently of the displayed Office author.
    #[serde(with = "entity_ref")]
    #[schemars(with = "String")]
    pub asked_by: EntityId,
    #[serde(with = "entity_ref")]
    #[schemars(with = "String")]
    pub answered_by: EntityId,
    pub author: PptxAuthor,
    #[serde(with = "entity_ref")]
    #[schemars(with = "String")]
    pub thread_id: EntityId,
    /// Unique reply GUID; for Add this must equal `thread_id`.
    #[serde(with = "entity_ref")]
    #[schemars(with = "String")]
    pub comment_id: EntityId,
    /// UTC Unix milliseconds; serialized as an OOXML dateTime.
    pub at: u64,
    pub action: PptxCommentAction,
}

impl PptxCommentPatch {
    /// The organ's edit: Office identities only, the engine actors kept here.
    pub fn edit(&self) -> PptxCommentEdit {
        PptxCommentEdit {
            author: self.author.clone(),
            thread_id: guid(*self.thread_id.as_bytes()),
            comment_id: guid(*self.comment_id.as_bytes()),
            at: self.at,
            action: self.action.clone(),
        }
    }
}

mod entity_ref {
    use oneiron_contracts::entity_id::EntityId;
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
