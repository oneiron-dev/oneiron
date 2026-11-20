//! Moved from `crates/oneiron/src/vault_shape/channel.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ShapeMailScope {
    #[serde(rename = "mail.read")]
    MailRead,
    #[serde(rename = "mail.metadata")]
    MailMetadata,
    #[serde(rename = "mail.send")]
    MailSend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeChannelFulfillment {
    Api,
    Manual,
    Review,
}
