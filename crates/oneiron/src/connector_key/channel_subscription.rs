//! The owner's door that lets an agent answer a built-in channel (OF-519):
//! one standing subscription of the agent to the messages that channel's
//! pack routes to it, under the agent's own connector key for the channel.
//! A message the pack routes to the agent then wakes it, and the served
//! responder answers through the ordinary outbound pipeline. The event is
//! data; the subscription is the owner's act.

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::surface_event::SURFACE_CONNECTOR_EVENT_PREDICATE;
use crate::{Vault, agent_dispatch};

use super::events::ConnectorEventFilter;
use super::record::{ConnectorKeyRecord, ConnectorKeyStatus, normalize_connector_key};

/// The connector event kind a channel message routed to its own actor
/// wakes on (`surface_connector_event_kind(ActorSelf)`).
const CHANNEL_MESSAGE_EVENT_KIND: &str = "message";
/// The channels whose inbound messages a served host routes to an agent
/// (its Slack and LINE webhooks).
const SUBSCRIBABLE_CHANNELS: [&str; 2] = [
    crate::channel_identity_provider::SLACK_CHANNEL,
    crate::channel_identity_provider::LINE_CHANNEL,
];

/// One agent's standing subscription to a built-in channel's messages.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelMessageSubscription {
    pub subscription: String,
    pub connector_key: String,
    pub connector: String,
    pub agent: String,
    /// The subscription was already standing; nothing new was written.
    pub existing: bool,
}

impl Vault {
    /// Subscribes `agent` to the messages the built-in `channel` pack routes
    /// to it. The agent's own key for the channel is reused while it is
    /// Active, else minted Active with no budget rows (the owner adds rows
    /// through the key's budget doors). A standing subscription with the
    /// same key and filter is returned as it is.
    ///
    /// # Errors
    /// The channel is not Slack or LINE, its built-in pack is not Active,
    /// the agent cannot be dispatched, or its key for the channel is held
    /// (suspended or pending).
    pub fn subscribe_agent_to_channel_messages(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        channel: &str,
    ) -> Result<ChannelMessageSubscription> {
        let connector = normalize_connector_key(channel);
        if !SUBSCRIBABLE_CHANNELS
            .iter()
            .any(|name| normalize_connector_key(name) == connector)
        {
            return Err(invalid(
                "no served built-in channel routes that channel's messages",
            ));
        }
        self.require_builtin_channel_pack(&connector)?;
        agent_dispatch::AgentDispatcher::new(self)
            .dispatchable_definition(&agent_dispatch::AgentDispatchTarget::Custom(agent))?;
        let key = match self.connector_key_for(&connector, Some(&agent))? {
            Some((id, record)) if record.status == ConnectorKeyStatus::Active => id,
            Some((_, record))
                if record.status != ConnectorKeyStatus::Revoked
                    && record.actor_entity_ref == Some(agent) =>
            {
                return Err(invalid(
                    "the agent's key for this channel is held; resume it first",
                ));
            }
            _ => {
                let id = self.store.clock.entity_id()?;
                let now = crate::unix_seconds_now();
                let minted = self.register_connector_key(
                    &id,
                    ConnectorKeyRecord::active(connector.clone(), Some(agent), Vec::new(), now),
                )?;
                if minted.status != ConnectorKeyStatus::Active {
                    return Err(invalid(
                        "the agent's key for this channel waits on a grant; approve it first",
                    ));
                }
                id
            }
        };
        let filter = ConnectorEventFilter {
            connector: connector.clone(),
            event_kind: Some(CHANNEL_MESSAGE_EVENT_KIND.to_owned()),
            predicate: Some(SURFACE_CONNECTOR_EVENT_PREDICATE.to_owned()),
        };
        let standing = self
            .connector_event_subscriptions(agent)?
            .into_iter()
            .find(|(_, row)| row.active && row.connector_key == key && row.filter == filter);
        let (subscription, existing) = match standing {
            Some((id, _)) => (id, true),
            None => (
                self.subscribe_connector_event(owner, agent, key, filter)?,
                false,
            ),
        };
        Ok(ChannelMessageSubscription {
            subscription: subscription.to_hex(),
            connector_key: key.to_hex(),
            connector,
            agent: agent.to_hex(),
            existing,
        })
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
