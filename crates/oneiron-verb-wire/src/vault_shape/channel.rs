//! Moved from `crates/oneiron/src/vault_shape/channel.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity::binding::ChannelIdentityFulfillment;
use crate::channel_identity::custody::DelegatedGrantScope;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// Who holds the address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "held", rename_all = "snake_case")]
pub enum ShapeChannelCustody {
    /// The vault holds it, in one of the self-held shapes.
    SelfHeld { shape: ShapeSelfHeld },
    /// A member's mailbox granted through a custody record, by the record's
    /// name, with the scopes the grant covers.
    Delegated {
        custody_record_ref: String,
        scopes: Vec<ShapeMailScope>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeSelfHeld {
    DedicatedAddress,
    DedicatedHandle,
    SharedPresence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ShapeMailScope {
    #[serde(rename = "mail.read")]
    MailRead,
    #[serde(rename = "mail.metadata")]
    MailMetadata,
    #[serde(rename = "mail.send")]
    MailSend,
}

impl From<ShapeMailScope> for DelegatedGrantScope {
    fn from(scope: ShapeMailScope) -> Self {
        match scope {
            ShapeMailScope::MailRead => Self::MailRead,
            ShapeMailScope::MailMetadata => Self::MailMetadata,
            ShapeMailScope::MailSend => Self::MailSend,
        }
    }
}

impl From<DelegatedGrantScope> for ShapeMailScope {
    fn from(scope: DelegatedGrantScope) -> Self {
        match scope {
            DelegatedGrantScope::MailRead => Self::MailRead,
            DelegatedGrantScope::MailMetadata => Self::MailMetadata,
            DelegatedGrantScope::MailSend => Self::MailSend,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeChannelFulfillment {
    Api,
    Manual,
    Review,
}

impl From<ShapeChannelFulfillment> for ChannelIdentityFulfillment {
    fn from(mode: ShapeChannelFulfillment) -> Self {
        match mode {
            ShapeChannelFulfillment::Api => Self::Api,
            ShapeChannelFulfillment::Manual => Self::Manual,
            ShapeChannelFulfillment::Review => Self::Review,
        }
    }
}

impl From<ChannelIdentityFulfillment> for ShapeChannelFulfillment {
    fn from(mode: ChannelIdentityFulfillment) -> Self {
        match mode {
            ChannelIdentityFulfillment::Api => Self::Api,
            ChannelIdentityFulfillment::Manual => Self::Manual,
            ChannelIdentityFulfillment::Review => Self::Review,
        }
    }
}
