//! Identity-stamped conversation and membership projections; no writes or index repairs.
use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::surface_event::{
    SURFACE_EVENT_ATTEMPT_KIND, SurfaceCounterpartyStamp, SurfaceEventAction,
    decode_surface_event_attempt_payload,
};
use crate::write_envelope::thread_claim::canonical_message_id;

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
            // FIX 9745: an inbound message's sender is the known counterparty
            // its routing admitted. An unknown or unparsed sender has no
            // admitted provenance, and a typed interaction is no message.
            let sender = match (&event.action, &event.counterparty) {
                (
                    SurfaceEventAction::Message,
                    SurfaceCounterpartyStamp::Known { counterparty_ref },
                ) => EntityId::from_hex(counterparty_ref).ok(),
                _ => None,
            };
            let item = AgentInboxLensItem {
                item_id: format!("surface:{}:{}", identity_ref.to_hex(), event.correlation_id),
                kind: if matches!(event.action, SurfaceEventAction::Message) {
                    AgentInboxItemKind::Conversation
                } else {
                    AgentInboxItemKind::CoordinationUpdate
                },
                thread_ref,
                identity_ref: Some(identity_ref),
                actor_ref,
                facet_ref,
                participants: vec![AgentInboxParticipant {
                    identity_ref: Some(identity_ref),
                    actor_ref,
                }],
                impact: InboxImpact(match row.state {
                    AttemptState::Failed | AttemptState::Paused | AttemptState::Abandoned => 100,
                    AttemptState::Completed | AttemptState::Cancelled => 0,
                    _ => 50,
                }),
                occurred_at: event.received_at,
                receipt_ref: None,
                payload_ref: event.payload_ref,
                concern: None,
                diary_review: None,
                sender,
                widening: None,
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
        // appear before this node has received its first SurfaceEvent. Every
        // channel identity is read, in this one read, however many there are.
        let txn = self.store.env.read_txn()?;
        for identity_ref in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            &txn,
            crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY,
            None,
        )? {
            let identity_ref = identity_ref?;
            if identity.is_some_and(|wanted| wanted != identity_ref) {
                continue;
            }
            // The binding and address are the identity's facts (OF-272): a
            // corrected address is the party whose threads the inbox lists.
            let Some(facts) = crate::channel_identity::channel_identity_facts_in_txn(
                &self.store,
                &txn,
                &identity_ref,
            )?
            else {
                continue;
            };
            let crate::channel_identity::ChannelIdentityBinding::Actor {
                actor_ref,
                facet_ref,
            } = facts.binding
            else {
                continue;
            };
            let party = crate::comm::resolve_party_ref_in_txn(self, &txn, &facts.address_or_handle)
                .map_err(comm_error)?;
            let Some(party) = party else { continue };
            for thread in
                crate::comm::active_thread_refs_in_txn(self, &txn, party).map_err(comm_error)?
            {
                if out.iter().any(|item| {
                    item.identity_ref == Some(identity_ref)
                        && item.thread_ref.as_deref() == Some(&thread)
                }) {
                    continue;
                }
                out.push(AgentInboxLensItem {
                    item_id: format!("thread:{}:{thread}", identity_ref.to_hex()),
                    kind: AgentInboxItemKind::Conversation,
                    thread_ref: Some(thread),
                    identity_ref: Some(identity_ref),
                    actor_ref,
                    facet_ref,
                    participants: vec![AgentInboxParticipant {
                        identity_ref: Some(identity_ref),
                        actor_ref,
                    }],
                    impact: InboxImpact(0),
                    occurred_at: 0,
                    receipt_ref: None,
                    payload_ref: None,
                    concern: None,
                    diary_review: None,
                    sender: None,
                    widening: None,
                });
            }
        }
        Ok(out)
    }

    /// Exact frozen connector events for the latest surface entry under
    /// each row key. Unmatched entries remain readable without a reply anchor.
    pub(super) fn surface_reply_anchors_for_actor(
        &self,
        actor: EntityId,
    ) -> Result<BTreeMap<String, (Option<String>, u64, String)>> {
        let rows = AttemptQueue::new(self).list_kind_bounded(
            SURFACE_EVENT_ATTEMPT_KIND,
            crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        )?;
        let mut latest = BTreeMap::new();
        for row in rows {
            let payload = decode_surface_event_attempt_payload(&row.payload)?;
            let event = &payload.event;
            if !matches!(event.action, SurfaceEventAction::Message)
                || EntityId::from_hex(&event.actor_ref)? != actor
            {
                continue;
            }
            let identity = EntityId::from_hex(&event.receiving_identity_ref)?;
            let key = format!("surface:{}:{}", identity.to_hex(), event.correlation_id);
            // Keep the same strict updated-at tie rule as the row projection.
            if latest.get(&key).is_none_or(|(at, _)| row.updated_at > *at) {
                latest.insert(key, (row.updated_at, payload));
            }
        }
        let mut anchors = BTreeMap::new();
        for (key, (_, payload)) in latest {
            let Some(woken) =
                self.connector_event_woken(actor, &payload.dispatch_idempotency_key)?
            else {
                continue;
            };
            let event = &payload.event;
            let expected = crate::surface_event::connector_event_from_surface(
                &crate::surface_event::SurfaceEventDispatchRequest {
                    event,
                    route: payload.route,
                    agent_ref: &event.actor_ref,
                    correlation_id: &event.correlation_id,
                    idempotency_key: &payload.dispatch_idempotency_key,
                    thread_ref: payload.thread_ref.as_deref(),
                },
            )?;
            if woken != expected {
                continue;
            }
            anchors.insert(
                key,
                (event.payload_ref.clone(), event.received_at, woken.event_id),
            );
        }
        Ok(anchors)
    }
}

fn comm_error(error: crate::write_envelope::communication::CommError) -> Error {
    match error {
        crate::write_envelope::communication::CommError::Engine(error) => error,
        _ => Error::InvalidClaimBody("inbox thread membership is malformed"),
    }
}
