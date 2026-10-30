//! The receiving personas a served Slack app can route a workspace's events
//! to (OF-519). A Slack event names the workspace and the app, never a
//! persona, so the host picks one from the identities assigned there.

use crate::Vault;
use crate::channel_identity::{
    ChannelIdentityBinding, InboundDisposition, channel_identity_facts_in_txn,
};
use crate::error::Result;
use crate::ports::EntityStore;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;

use super::SLACK_CHANNEL;

impl Vault {
    /// The actor-bound Slack personas of one workspace that take inbound
    /// now, earliest first: every `{workspace_ref}:persona:{persona}`
    /// identity whose live facts, read on its row's custody, deliver
    /// ([`InboundDisposition::Deliver`] or
    /// [`InboundDisposition::DeliverRetiring`]). A rotating, released or
    /// quarantined persona keeps its inbound; the routing door stamps the
    /// retiring ones. An identity whose live facts do not read is passed
    /// over, with a warning when its row names this workspace, so it never
    /// stops another persona's delivery.
    /// `workspace_ref` is the stamp
    /// [`super::SlackSharedPresenceAdapter::workspace_ref`] makes.
    pub fn slack_workspace_personas(&self, workspace_ref: &str) -> Result<Vec<String>> {
        let prefix = format!("{workspace_ref}:persona:");
        let ids = self.entities_by_type(ENTITY_TYPE_CHANNEL_IDENTITY)?;
        let txn = self.store.env.read_txn()?;
        let mut personas = Vec::new();
        for id in ids {
            let Some(identity) = self.get_channel_identity_in_txn(&txn, &id)? else {
                continue;
            };
            // The channel and handle are the identity's facts (OF-272), so a
            // persona corrected into or out of this workspace is read where
            // its heads put it. Facts that do not read never fail another
            // persona's delivery; only this workspace's row is warned about.
            let facts = match channel_identity_facts_in_txn(&self.store, &txn, &id) {
                Ok(Some(facts)) => facts,
                Ok(None) => continue,
                Err(err) => {
                    if identity.channel() == SLACK_CHANNEL
                        && identity.address_or_handle().starts_with(&prefix)
                    {
                        tracing::warn!(
                            identity = %id.to_hex(),
                            error = %err,
                            "a Slack persona's live facts did not read; it takes no inbound"
                        );
                    }
                    continue;
                }
            };
            let delivers = matches!(
                facts.inbound_with_custody(identity.custody()),
                InboundDisposition::Deliver | InboundDisposition::DeliverRetiring
            );
            if facts.channel != SLACK_CHANNEL
                || !delivers
                || !matches!(facts.binding, ChannelIdentityBinding::Actor { .. })
            {
                continue;
            }
            let Some(persona) = facts.address_or_handle.strip_prefix(&prefix) else {
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
