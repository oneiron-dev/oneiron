//! Provider-adapter seam for ChannelIdentity fulfillment (OF-347 CID-3).
//!
//! The engine emits CID-2 lifecycle intents through the ExternalEffect door.
//! Host-side adapters consume those intents, fulfill provider work, and report
//! the resulting state transition back through the CID-2 fulfillment path.

mod email_adapter;
pub mod gmail;
mod inbound_types;
mod line_adapter;
mod shared_validate;
mod slack_adapter;
mod slack_validate;
#[cfg(test)]
mod tests;

pub use self::email_adapter::{
    DevEmailIdentityAdapter, DevEmailIdentityAdapterConfig, MockChannelIdentityProviderAdapter,
};
pub use self::inbound_types::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, EmailProviderInbound, LineOfficialAccountInbound,
    SlackProviderInbound,
};
pub use self::line_adapter::{
    LineOfficialAccountAdapter, LineOfficialAccountAdapterConfig, LineOfficialAccountPlanTier,
};
pub use self::shared_validate::{
    CHANNEL_IDENTITY_PROVIDER_ADAPTER_VERSION, DEFAULT_EMAIL_LOCAL_PART_PREFIX,
    DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE, DEV_EMAIL_PROVIDER_KEY, EMAIL_CHANNEL, LINE_CHANNEL,
    LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY, SLACK_CHANNEL, SLACK_SHARED_PRESENCE_PROVIDER_KEY,
};
pub use self::slack_adapter::{
    SlackOutboundMessage, SlackPersonaAttribution, SlackPersonaOutbound,
    SlackSharedPresenceAdapter, SlackSharedPresenceAdapterConfig,
};

// Pre-existing `gmail.rs` keeps its `use super::{...}` paths: these names now
// live in `shared_validate` and are re-imported here so the child resolves.
use self::shared_validate::{
    MAX_EMAIL_PAYLOAD_REF_BYTES, MAX_EMAIL_PROVIDER_EVENT_ID_BYTES, normalize_email_address,
    split_email_address, validate_email_inbound_metadata, validate_max_bytes, validate_non_blank,
};

// Pre-existing `tests.rs` names these bare through `use super::*`.
#[cfg(test)]
use self::shared_validate::{
    MAX_EMAIL_LOCAL_PART_BYTES, MAX_LINE_COMPONENT_BYTES, MAX_LOCAL_PART_PREFIX_BYTES,
};

// The flat channel_identity_provider.rs module used to provide these names to
// the sibling test module through `use super::*`: its own crate/std import
// header items the tests name bare. After the directory split the seam
// re-imports them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    SelfHeldShape,
};
#[cfg(test)]
use crate::channel_identity_lifecycle::{
    ChannelIdentityLifecycleActor, ChannelIdentityLifecycleVerb, ProvisionIntent,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use serde_json::Value;
