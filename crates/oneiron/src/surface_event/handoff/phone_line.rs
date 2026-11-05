//! Phone arrival metadata's line-bound, atomic admission.

use super::*;

impl Vault {
    /// A verified channel actor submits arrival metadata, not audio or a recognized caller.
    /// The owner setting, live identity, scoped read and queue all share this writer.
    pub fn enqueue_phone_line_arrival_as(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        identity_ref: crate::EntityId,
        arrival: crate::phone_line::PhoneLineArrival,
        now: u64,
    ) -> Result<crate::phone_line::PhoneLineArrivalReceipt> {
        if arrival.call_id.trim().is_empty() {
            return Err(crate::phone_line::invalid());
        }
        read.persist_grant_clock()?;
        self.with_write_txn_grouped(|txn| {
            let policy = read.live_policy_manifest_in(txn)?;
            if !read.is_ref_readable_with_policy_in(txn, &policy, &identity_ref)? {
                return Err(crate::phone_line::invalid());
            }
            let (line, facts) =
                crate::phone_line::admitted_line_in_txn(self, txn, read, identity_ref)?;
            let key = crate::phone_line::arrival_key(identity_ref, &arrival.call_id);
            let offered = crate::phone_line::input_digest(&arrival)?;
            if let Some(replay) = crate::phone_line::replay_in_txn(self, txn, &key, offered)? {
                return Ok(replay);
            }
            let digest = blake3::Hash::from(key).to_hex().to_string();
            let correlation_id = format!("phone-arrival:{digest}");
            let payload_ref = format!("phone-line:arrival:{digest}");
            // The queue and lens retain no caller or provider-call-id text.
            let input = InboundSurfaceEventInput::new(
                correlation_id.clone(),
                facts.channel.as_str(),
                facts.address_or_handle.as_str(),
                crate::surface_event::SurfaceCounterpartyStamp::unparsed("voice", key),
                now,
                true,
            )
            .with_payload_ref(payload_ref.clone());
            let routed = route_inbound_surface_event_admitting_in_txn(self, txn, input, &|id| {
                read.is_ref_readable_with_policy_in(txn, &policy, id)
            })?;
            let event = routed
                .surface_event
                .ok_or_else(crate::phone_line::invalid)?;
            if event.receiving_identity_ref != identity_ref.to_hex()
                || event.actor_ref != line.agent_ref.to_hex()
            {
                return Err(crate::phone_line::invalid());
            }
            let admitted = admit_surface_event_once_in_txn(self, txn, &event, None, now)?;
            if admitted.replayed {
                // A different intake must not plant an event under this phone-specific key.
                return Err(crate::phone_line::invalid());
            }
            let ack = surface_event_ack(event, &admitted);
            crate::phone_line::keep_arrival_in_txn(
                self,
                txn,
                &key,
                offered,
                crate::phone_line::PhoneLineArrivalRecord {
                    identity_ref,
                    agent_ref: line.agent_ref,
                    bridge_actor: line.bridge_actor,
                    share_scope: line.share_scope,
                    arrival,
                    received_at: ack.accepted_at,
                    payload_ref,
                    correlation_id,
                    attempt_ref: ack.attempt_ref.as_str().to_owned(),
                },
            )
        })
    }
}
