//! The receiving personas a served Slack app can route a workspace's events
//! to (OF-519). A Slack event names the workspace and the app, never a
//! persona, so the host picks one from the identities assigned there.

use crate::Vault;
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
use crate::error::Result;
use crate::ports::EntityStore;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;

use super::SLACK_CHANNEL;

impl Vault {
    /// The Active, actor-bound Slack personas of one workspace, earliest
    /// first: every `{workspace_ref}:persona:{persona}` identity.
    /// `workspace_ref` is the stamp
    /// [`super::SlackSharedPresenceAdapter::workspace_ref`] makes.
    pub fn slack_workspace_personas(&self, workspace_ref: &str) -> Result<Vec<String>> {
        let prefix = format!("{workspace_ref}:persona:");
        let ids = self.entities_by_type(ENTITY_TYPE_CHANNEL_IDENTITY)?;
        let txn = self.store.env.read_txn()?;
        let mut personas = Vec::new();
        for id in ids {
            let Some(identity) = self.get_channel_identity(&id)? else {
                continue;
            };
            if identity.channel() != SLACK_CHANNEL
                || identity.state() != ChannelIdentityState::Active
                || !matches!(identity.binding(), ChannelIdentityBinding::Actor { .. })
            {
                continue;
            }
            let Some(persona) = identity.address_or_handle().strip_prefix(&prefix) else {
                continue;
            };
            let since = self
                .port_entity_get(&txn, &id)?
                .map_or(u64::MAX, |record| record.learned_at);
            personas.push((since, persona.to_owned()));
        }
        personas.sort();
        Ok(personas.into_iter().map(|(_, persona)| persona).collect())
    }
}
