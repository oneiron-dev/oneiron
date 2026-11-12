//! Moved from `crates/oneiron/src/mail_pack/attachments.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::state::MailPresence;
use crate::mail_pack::wire::MailAttachmentRef;
use crate::source_audience;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::MAIL_ATTACHMENT;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// Where an opened attachment stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailAttachmentState {
    /// The source's next import step fetches it.
    Waiting,
    /// Its bytes are in its artifact.
    Stored,
    /// The provider no longer had it, or it could not be read.
    Failed,
}

/// `vault.mail.attachments.open`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailAttachmentOpenRequest {
    /// The message's source, 32-hex.
    pub source_ref: String,
    /// The message's TURN, 32-hex (an inbox item's `turn_ref`).
    pub turn_ref: String,
    /// The attachment's MIME part id.
    pub part_id: String,
}

/// An opened attachment, as its reader sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailAttachmentView {
    pub state: MailAttachmentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub media_type: String,
    pub size_bytes: u64,
    /// The artifact its bytes are in, 32-hex, once stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
