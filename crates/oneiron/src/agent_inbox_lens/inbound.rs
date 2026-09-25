//! Identity-stamped conversation and membership projections; no writes or index repairs.
use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::surface_event::{
    SURFACE_EVENT_ATTEMPT_KIND, SurfaceEventAction, decode_surface_event_attempt_payload,
};
use crate::thread_passport::canonical_message_id;

impl Vault {
    pub(super) fn inbound_inbox_items(
        &self,
        identity: Option<EntityId>,
    ) -> Result<Vec<AgentInboxLensItem>> {
        let rows = AttemptQueue::new(self).list_kind_bounded(
            SURFACE_EVENT_ATTEMPT_KIND,
            crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        )?;
        let mut items = BTreeMap::new();
        for row in rows {
            let payload = decode_surface_event_attempt_payload(&row.payload)?;
            let event = payload.event;
            let identity_ref = EntityId::from_hex(&event.receiving_identity_ref)?;
            if identity.is_some_and(|wanted| wanted != identity_ref) {
                continue;
            }
            let actor_ref = EntityId::from_hex(&event.actor_ref)?;
            let facet_ref = event
                .facet_ref
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?;
            let thread_ref = if let Some(thread) = payload.thread_ref {
                Some(self.canonical_thread_ref(&thread)?)
            } else if matches!(event.channel.as_str(), "mail" | "email") {
                match canonical_message_id(&event.event_id) {
                    Ok(message) => self
                        .thread_passport(&identity_ref, &message)?
                        .map(|passport| self.canonical_thread_ref(&passport.thread_ref))
                        .transpose()?,
                    Err(_) => None,
                }
            } else {
                None
            };
            let item = AgentInboxLensItem {
                item_id: format!("surface:{}:{}", identity_ref.to_hex(), event.correlation_id),
                kind: if matches!(event.action, SurfaceEventAction::Message) {
                    AgentInboxItemKind::Conversation
                } else {
                    AgentInboxItemKind::CoordinationUpdate
                },
                thread_ref,
                identity_ref,
                actor_ref,
                facet_ref,
                impact: InboxImpact(match row.state {
                    AttemptState::Failed | AttemptState::Paused | AttemptState::Abandoned => 100,
                    AttemptState::Completed | AttemptState::Cancelled => 0,
                    _ => 50,
                }),
                occurred_at: event.received_at,
                receipt_ref: None,
                payload_ref: event.payload_ref,
            };
            // Retries retain one correlation. Current state/time breaks ties,
            // not physical queue-row order.
            let key = item.item_id.clone();
            if items.get(&key).is_none_or(|(at, _)| row.updated_at > *at) {
                items.insert(key, (row.updated_at, item));
            }
        }
        let mut out: Vec<_> = items.into_values().map(|(_, item)| item).collect();
        // Membership is independent of an inbound event. A standing thread can
        // appear before this node has received its first SurfaceEvent.
        let identities = self.entities_by_type_page(
            crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY,
            None,
            crate::receipt::MAX_RECEIPT_QUERY_SCAN + 1,
        )?;
        if identities.len() > crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            return Err(Error::IndexOverflow("inbox identities"));
        }
        for identity_ref in identities {
            let Some(channel) = self.get_channel_identity(&identity_ref)? else {
                continue;
            };
            if identity.is_some_and(|wanted| wanted != identity_ref) {
                continue;
            }
            let crate::channel_identity::ChannelIdentityBinding::Actor {
                actor_ref,
                facet_ref,
            } = channel.binding
            else {
                continue;
            };
            let txn = self.store.env.read_txn()?;
            let party =
                crate::comm::resolve_party_ref_in_txn(self, &txn, &channel.address_or_handle)
                    .map_err(comm_error)?;
            let Some(party) = party else { continue };
            for thread in
                crate::comm::active_thread_refs_in_txn(self, &txn, party).map_err(comm_error)?
            {
                if out.iter().any(|item| {
                    item.identity_ref == identity_ref && item.thread_ref.as_deref() == Some(&thread)
                }) {
                    continue;
                }
                out.push(AgentInboxLensItem {
                    item_id: format!("thread:{}:{thread}", identity_ref.to_hex()),
                    kind: AgentInboxItemKind::Conversation,
                    thread_ref: Some(thread),
                    identity_ref,
                    actor_ref,
                    facet_ref,
                    impact: InboxImpact(0),
                    occurred_at: 0,
                    receipt_ref: None,
                    payload_ref: None,
                });
            }
        }
        Ok(out)
    }
}

fn comm_error(error: crate::comm::CommError) -> Error {
    match error {
        crate::comm::CommError::Engine(error) => error,
        _ => Error::InvalidClaimBody("inbox thread membership is malformed"),
    }
}
