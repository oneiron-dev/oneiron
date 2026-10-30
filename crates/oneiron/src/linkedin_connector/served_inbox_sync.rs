//! The served LinkedIn inbox sync (FIX 12328): what a served host runs to
//! keep each LinkedIn seat's inbox read. A seat is served while it is an
//! Active LinkedIn channel identity bound to an actor, and an Active LinkedIn
//! connector key with a catalog entry, the connector the owner installed,
//! governs that actor. Each poll runs as the seat's agent over
//! [`LinkedInConnectorCallTransport`], so every tool it calls is an admitted
//! installed-tool call, as the seat's replies are.

use crate::Vault;
use crate::attempt_queue::EnqueueOutcome;
use crate::channel_identity::{ChannelIdentityState, channel_identity_facts_in_txn};
use crate::connector_key::ConnectorKeyStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;

use super::{
    LINKEDIN_CHANNEL, LinkedInConnectorCallTransport, LinkedInInboxSyncConfig,
    LinkedInInboxSyncReport, LinkedInInboxSyncRunner, LinkedInMcpConnectorAdapter,
};

/// A LinkedIn seat a served host syncs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInServedSeat {
    /// The seat's channel identity.
    pub identity: EntityId,
    /// The actor the seat is bound to; each poll runs as this agent.
    pub actor: EntityId,
    pub receiving_address_or_handle: String,
}

impl Vault {
    /// Every LinkedIn seat a served host syncs, in identity order. A seat
    /// bound to the vault rather than an actor has no agent to call the
    /// connector as, and is not one.
    ///
    /// # Errors
    ///
    /// The identities or connector keys could not be read.
    pub fn linkedin_served_seats(&self) -> Result<Vec<LinkedInServedSeat>> {
        let mut bound = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            for entry in
                self.store
                    .port_entity_ids_by_type(&txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)?
            {
                let identity = entry?;
                let Some(facts) = channel_identity_facts_in_txn(&self.store, &txn, &identity)?
                else {
                    continue;
                };
                if facts.channel != LINKEDIN_CHANNEL || facts.state != ChannelIdentityState::Active
                {
                    continue;
                }
                if let Some(actor) = facts.binding.actor_ref() {
                    bound.push(LinkedInServedSeat {
                        identity,
                        actor,
                        receiving_address_or_handle: facts.address_or_handle,
                    });
                }
            }
        }
        let mut seats = Vec::new();
        for seat in bound {
            let installed = self
                .connector_key_for(LINKEDIN_CHANNEL, Some(&seat.actor))?
                .is_some_and(|(_, key)| {
                    key.status == ConnectorKeyStatus::Active && key.catalog.is_some()
                });
            if installed {
                seats.push(seat);
            }
        }
        Ok(seats)
    }

    /// Queues one inbox sync poll for each seat
    /// [`Self::linkedin_served_seats`] names; a seat whose poll is still
    /// pending keeps that one. Returns how many polls were queued.
    ///
    /// # Errors
    ///
    /// The seats could not be read, or a poll could not be queued.
    pub fn enqueue_served_linkedin_inbox_syncs(&self, now: u64) -> Result<usize> {
        let mut enqueued = 0;
        for seat in self.linkedin_served_seats()? {
            let adapter = match LinkedInMcpConnectorAdapter::new(seat.receiving_address_or_handle) {
                Ok(adapter) => adapter,
                Err(error) => {
                    tracing::info!(%error, identity = %seat.identity.to_hex(), "a LinkedIn seat's handle is unreadable; its inbox is not synced");
                    continue;
                }
            };
            let config = LinkedInInboxSyncConfig::from_adapter(&adapter);
            if matches!(
                adapter.enqueue_inbox_sync_poll(self, config, now)?,
                EnqueueOutcome::Enqueued(_)
            ) {
                enqueued += 1;
            }
        }
        Ok(enqueued)
    }

    /// One inbox poll of the seat `config` names, run as the seat's agent
    /// over the installed LinkedIn connector: each new message is archived,
    /// routed and admitted as an inbound surface event. `Ok(None)` when the
    /// seat is served no longer; nothing is read then.
    ///
    /// # Errors
    ///
    /// The host installed no connector calls, a connector call failed, or
    /// the poll could not record what it read.
    pub fn run_served_linkedin_inbox_sync(
        &self,
        config: &LinkedInInboxSyncConfig,
        now: u64,
    ) -> Result<Option<LinkedInInboxSyncReport>> {
        let Some(seat) = self
            .linkedin_served_seats()?
            .into_iter()
            .find(|seat| seat.receiving_address_or_handle == config.receiving_address_or_handle)
        else {
            return Ok(None);
        };
        let calls = self.served_transports().connector_calls().ok_or_else(|| {
            Error::InvalidConfig(
                "this host installed no connector calls; LinkedIn inboxes are not read".to_owned(),
            )
        })?;
        let adapter = config.adapter()?;
        let transport = LinkedInConnectorCallTransport::installed(
            self,
            calls,
            seat.actor,
            EdgeActorClass::Agent,
            &adapter,
        )?;
        LinkedInInboxSyncRunner::new(self, adapter, transport, config.clone())
            .run_once(now)
            .map(Some)
    }
}
