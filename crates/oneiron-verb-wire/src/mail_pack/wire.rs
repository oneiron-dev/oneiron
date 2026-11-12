//! Moved from `crates/oneiron/src/mail_pack/wire.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::source::MailProvider;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One attachment a message carries, as described, not its bytes: bytes
/// load only when someone opens it (MAIL-GOOGLE = A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MailAttachmentRef {
    /// The MIME part id within the message.
    pub part_id: String,
    /// The provider's attachment id, when its bytes are fetched apart.
    pub provider_attachment_id: Option<String>,
    pub filename: Option<String>,
    pub media_type: String,
    pub size_bytes: u64,
}
