//! Moved from `crates/oneiron/src/outbound/weave_digest_send.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity::lifecycle::ChannelIdentityState;
use oneiron_authority::claim_history_handoff::WeaveDigestReader;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::human_task_followup::HumanTaskError;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use oneiron_base::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::communication::PREDICATE_COMM_REACHABLE_VIA;
use serde::Deserialize;
use serde::Serialize;

/// Where the owner sends one reader's digest instead of the reader's primary
/// route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WeaveDigestChannelOverride {
    /// No send: the reader's inbox notice alone.
    Off,
    /// The send goes from this channel identity of the vault's, to the
    /// reader's live contact on it, from the companion agent it is bound to.
    /// While that identity carries no such route, nothing is sent.
    Identity {
        #[schemars(with = "String")]
        channel_identity_ref: EntityId,
    },
}

/// One reader's digest channel, as the owner reads and sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestChannelSetting {
    /// The reader, as 32 hex.
    #[schemars(with = "String")]
    pub reader_ref: EntityId,
    /// The owner's override; `None` is the default: the send on, to the
    /// reader's primary route. Setting `None` removes the row.
    pub route: Option<WeaveDigestChannelOverride>,
}
