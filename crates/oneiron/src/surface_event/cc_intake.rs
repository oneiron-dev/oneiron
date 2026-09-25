//! Atomic named-address CC intake: passport, membership event, then durable coordination handoff.
use super::handoff::{admit_surface_event_once_in_txn, surface_event_status_path};
use super::{
    InboundSurfaceEventInput, SurfaceEventAck, SurfaceEventAction, SurfaceEventAdmission,
    SurfaceEventAttemptRef, SurfaceEventHandoffState,
};
use crate::thread_passport::{
    ThreadPassportInput, ThreadPassportResolution, canonical_message_id, canonical_message_id_list,
};
use crate::{EntityId, Error, Result, Vault};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcAgentIntakeOutcome {
    pub admission: SurfaceEventAdmission,
    pub thread: Option<ThreadPassportResolution>,
}

impl Vault {
    /// Foreign CC content remains claims, never instructions or permission to book/send.
    /// A successful ack means the owner inbox can read the thread immediately. The
    /// worker receives ProposeConfirm and the sticky thread ref; it must use the
    /// ordinary coordination hold/confirm gates for any later external action.
    pub fn enqueue_cc_agent_email(
        &self,
        input: InboundSurfaceEventInput,
        message_id: &str,
        references: &[String],
        in_reply_to: Option<&str>,
        now: u64,
    ) -> Result<CcAgentIntakeOutcome> {
        if !matches!(input.channel.as_str(), "mail" | "email")
            || input.action != SurfaceEventAction::Message
        {
            return Err(Error::InvalidConfig(
                "CC intake requires an email message".to_owned(),
            ));
        }
        let mut input = input;
        input.foreign_inbound = true;
        let message = canonical_message_id(message_id)?;
        let references = canonical_message_id_list(references)?;
        let reply = in_reply_to.map(canonical_message_id).transpose()?;
        self.with_write_txn(|txn| {
            let routed = self.route_inbound_surface_event(input.clone())?;
            let Some(event) = routed.surface_event.clone() else {
                return Ok(CcAgentIntakeOutcome {
                    admission: SurfaceEventAdmission::Rejected(routed),
                    thread: None,
                });
            };
            let identity = EntityId::from_hex(&event.receiving_identity_ref)?;
            let actor = EntityId::from_hex(&event.actor_ref)?;
            let passport = self.record_thread_passport_in_txn(
                txn,
                ThreadPassportInput {
                    identity_ref: identity,
                    actor_ref: actor,
                    facet_ref: event
                        .facet_ref
                        .as_deref()
                        .map(EntityId::from_hex)
                        .transpose()?,
                    message_id: message.clone(),
                    references: references.clone(),
                    in_reply_to: reply.clone(),
                    observed_at: event.received_at,
                },
            )?;
            let admitted = admit_surface_event_once_in_txn(
                self,
                txn,
                &event,
                Some(&passport.canonical_thread_ref),
                now,
            )?;
            if !admitted.replayed {
                crate::comm::record_comm_thread_event_in_txn(
                    self,
                    txn,
                    &passport.canonical_thread_ref,
                    &event.receiving_address_or_handle,
                    true,
                    event.received_at,
                )
                .map_err(|error| match error {
                    crate::comm::CommError::Engine(error) => error,
                    _ => Error::InvalidClaimBody("CC thread membership refused"),
                })?;
            }
            let ack = SurfaceEventAck {
                status_path: surface_event_status_path(&event.correlation_id),
                correlation_id: event.correlation_id,
                attempt_ref: SurfaceEventAttemptRef::from_attempt_id(admitted.attempt.id),
                state: SurfaceEventHandoffState::from_attempt_state(admitted.attempt.state),
                replayed: admitted.replayed,
                accepted_at: admitted.attempt.created_at,
            };
            Ok(CcAgentIntakeOutcome {
                admission: SurfaceEventAdmission::Accepted(ack),
                thread: Some(passport),
            })
        })
    }
}
