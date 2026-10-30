//! Atomic named-address CC intake: passport, the sender's membership event, then durable coordination handoff.
use super::handoff::{
    SurfaceEventKey, admit_surface_event_once_in_txn, attempts_for_run_in_write_txn,
    decode_surface_event_attempt_payload, matching_surface_event_attempt, surface_event_dedupe_key,
    surface_event_run_id, surface_event_status_path,
};
use super::{
    InboundSurfaceEventInput, SurfaceEvent, SurfaceEventAck, SurfaceEventAction,
    SurfaceEventAdmission, SurfaceEventAttemptRef, SurfaceEventHandoffState,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::channel_identity_provider::EmailThreadHeaders;
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
    /// Mail ingress for every email identity: a delegated mailbox is never
    /// special-cased (R2). With parseable threading headers the message takes
    /// the named-address door below, so it joins its thread across identities.
    /// Without them, or with headers the passport cannot read, it takes the
    /// generic door: a header gap is metadata, not a reason to drop mail.
    pub fn enqueue_inbound_email(
        &self,
        input: InboundSurfaceEventInput,
        headers: Option<&EmailThreadHeaders>,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        let threaded = headers.filter(|headers| {
            canonical_message_id(&headers.message_id).is_ok()
                && canonical_message_id_list(&headers.references).is_ok()
                && headers
                    .in_reply_to
                    .as_deref()
                    .is_none_or(|reply| canonical_message_id(reply).is_ok())
        });
        let Some(headers) = threaded else {
            return self.enqueue_inbound_surface_event(input, now);
        };
        Ok(self
            .enqueue_cc_agent_email(
                input,
                &headers.message_id,
                &headers.references,
                headers.in_reply_to.as_deref(),
                now,
            )?
            .admission)
    }

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
        self.with_write_txn_grouped(|txn| {
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
                record_cc_sender_membership_in_txn(
                    self,
                    txn,
                    &passport.canonical_thread_ref,
                    &event,
                )?;
            }
            let ack = SurfaceEventAck {
                status_path: surface_event_status_path(&event.correlation_id),
                receiving_identity_ref: event.receiving_identity_ref.clone(),
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

impl Vault {
    /// [`Self::enqueue_inbound_email`] for a submitter that reads as `read`
    /// (FIX 974): an email message with parseable threading headers takes
    /// the scoped named-address door ([`Self::enqueue_cc_agent_email_as`]);
    /// without them, with headers the passport cannot read, or for any other
    /// event, the scoped generic door
    /// ([`Self::enqueue_inbound_surface_event_as`]). A header gap is
    /// metadata, not a reason to drop mail.
    pub fn enqueue_inbound_email_as(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        input: InboundSurfaceEventInput,
        headers: Option<&EmailThreadHeaders>,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        // Only an email message takes the CC door; any other event keeps the
        // generic one, thread headers or not.
        let email_message = matches!(input.channel.as_str(), "mail" | "email")
            && input.action == SurfaceEventAction::Message;
        let threaded = headers.filter(|headers| {
            email_message
                && canonical_message_id(&headers.message_id).is_ok()
                && canonical_message_id_list(&headers.references).is_ok()
                && headers
                    .in_reply_to
                    .as_deref()
                    .is_none_or(|reply| canonical_message_id(reply).is_ok())
        });
        let Some(headers) = threaded else {
            return self.enqueue_inbound_surface_event_as(read, input, now);
        };
        Ok(self
            .enqueue_cc_agent_email_as(
                read,
                input,
                &headers.message_id,
                &headers.references,
                headers.in_reply_to.as_deref(),
                now,
            )?
            .admission)
    }

    /// [`Self::enqueue_cc_agent_email`] for a submitter that reads as `read`
    /// (FIX 974): the receiving identity is admitted under that read in the
    /// one writer snapshot that records the passport, the thread membership
    /// and the handoff, as [`Self::enqueue_inbound_surface_event_as`] admits
    /// it. An identity the submitter cannot read routes as an address no
    /// identity holds: nothing is recorded or queued, and the rejection names
    /// no agent the submitter cannot read. A tuple first admitted with no
    /// thread replays that admission (first write wins) and records no
    /// passport; one already CC-bound keeps its strict message and thread
    /// checks. Foreign CC content stays claims, never instructions or
    /// permission to book or send.
    pub fn enqueue_cc_agent_email_as(
        &self,
        read: &crate::claim::ScopedRead<'_>,
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
        read.persist_grant_clock()?;
        self.with_write_txn_grouped(|txn| {
            let routed = {
                let rtxn: &heed::RoTxn<'_> = txn;
                let policy = read.live_policy_manifest_in(rtxn)?;
                super::inbound::route_inbound_surface_event_admitting_in_txn(
                    self,
                    rtxn,
                    input,
                    &|id| read.is_ref_readable_with_policy_in(rtxn, &policy, id),
                )?
            };
            let Some(event) = routed.surface_event.clone() else {
                return Ok(CcAgentIntakeOutcome {
                    admission: SurfaceEventAdmission::Rejected(routed),
                    thread: None,
                });
            };
            // First write wins: a mail first admitted with no thread replays
            // that admission, and no passport or membership is recorded.
            if let Some(held) = threadless_surface_event_in_txn(self, txn, &event)? {
                let ack = SurfaceEventAck {
                    status_path: surface_event_status_path(&event.correlation_id),
                    receiving_identity_ref: event.receiving_identity_ref.clone(),
                    correlation_id: event.correlation_id,
                    attempt_ref: SurfaceEventAttemptRef::from_attempt_id(held.id),
                    state: SurfaceEventHandoffState::from_attempt_state(held.state),
                    replayed: true,
                    accepted_at: held.created_at,
                };
                return Ok(CcAgentIntakeOutcome {
                    admission: SurfaceEventAdmission::Accepted(ack),
                    thread: None,
                });
            }
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
                    message_id: message,
                    references,
                    in_reply_to: reply,
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
                record_cc_sender_membership_in_txn(
                    self,
                    txn,
                    &passport.canonical_thread_ref,
                    &event,
                )?;
            }
            let ack = SurfaceEventAck {
                status_path: surface_event_status_path(&event.correlation_id),
                receiving_identity_ref: event.receiving_identity_ref.clone(),
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

/// Records the CC sender's join of the canonical thread `thread_ref`, in the
/// intake's write: the counterparty who wrote, never our receiving address.
/// A sender key the comm family cannot hold records nothing; the message is
/// admitted either way.
fn record_cc_sender_membership_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    thread_ref: &str,
    event: &SurfaceEvent,
) -> Result<()> {
    let party = event.counterparty.reference_key();
    if crate::comm::validate_comm_party_key(&party).is_err() {
        return Ok(());
    }
    crate::comm::record_comm_thread_event_in_txn(
        vault,
        txn,
        thread_ref,
        &party,
        true,
        event.received_at,
    )
    .map_err(|error| match error {
        crate::comm::CommError::Engine(error) => error,
        _ => Error::InvalidClaimBody("CC thread membership refused"),
    })
}

/// The attempt that already owns `event`'s identity tuple when it was
/// admitted with no email thread (FIX 974): a CC retry of a mail first
/// admitted through the generic door replays that admission, first write
/// wins, before any passport is recorded. `None` for a new tuple, and for
/// one already CC-bound, whose strict replay checks
/// `admit_surface_event_once_in_txn` keeps.
fn threadless_surface_event_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    event: &SurfaceEvent,
) -> Result<Option<AttemptRecord>> {
    let dedupe_key = surface_event_dedupe_key(SurfaceEventKey {
        channel: &event.channel,
        receiving: &event.receiving_identity_ref,
        correlation_id: &event.correlation_id,
    });
    let queue = AttemptQueue::new(vault);
    let run_id = surface_event_run_id(&event.correlation_id);
    let Some(existing) = matching_surface_event_attempt(
        attempts_for_run_in_write_txn(vault, &queue, wtxn, &run_id)?,
        &event.correlation_id,
        &dedupe_key,
    )?
    else {
        return Ok(None);
    };
    let held = decode_surface_event_attempt_payload(&existing.payload)?;
    Ok(held.thread_ref.is_none().then_some(existing))
}
