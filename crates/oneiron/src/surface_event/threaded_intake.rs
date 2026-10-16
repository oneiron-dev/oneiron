//! Atomic threaded email intake (OF-374): passport, canonical thread ref and
//! thread membership in the one write that queues an ordinary inbound event.
//!
//! The CC intake's atomic shape without its coordination stance: the event
//! stays an ordinary identity-stamped inbound SurfaceEvent for the mailbox's
//! agent, not a foreign ProposeConfirm handoff. What it adds over the plain
//! enqueue door is the thread record — the `(identity × Message-ID)` passport
//! joined on References, and the canonical thread ref the inbox lens reads.
use super::handoff::{admit_surface_event_once_in_txn, surface_event_status_path};
use super::inbound::route_inbound_surface_event_in_txn;
use super::{
    InboundSurfaceEventInput, SurfaceEventAck, SurfaceEventAdmission, SurfaceEventAttemptRef,
    SurfaceEventHandoffState,
};
use crate::thread_passport::{
    CanonicalMessageId, ThreadPassportInput, ThreadPassportResolution, canonical_message_id,
};
use crate::{EntityId, Error, Result, Vault};

/// What one threaded intake committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadedEmailIntakeOutcome {
    pub admission: SurfaceEventAdmission,
    pub thread: Option<ThreadPassportResolution>,
}

impl Vault {
    /// Routes, threads and queues one inbound email message in ONE write.
    ///
    /// The routing receipt, the passport (and any alias rows its References
    /// force), the queued event carrying the canonical thread ref, and the
    /// receiving party's thread membership commit together, so a crash never
    /// leaves a queued message whose thread the inbox cannot resolve. A replay
    /// of the same provider event is idempotent on every one of them.
    ///
    /// The threading ids arrive already canonical: the caller decides how a
    /// malformed header degrades (the Gmail runner falls back to plain,
    /// unthreaded delivery), so this door has no parse arm to fail on.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a non-email input, plus routing, passport,
    /// queue and membership storage errors.
    pub fn enqueue_threaded_email_surface_event(
        &self,
        input: InboundSurfaceEventInput,
        message_id: CanonicalMessageId,
        references: Vec<CanonicalMessageId>,
        in_reply_to: Option<CanonicalMessageId>,
        now: u64,
    ) -> Result<ThreadedEmailIntakeOutcome> {
        if !matches!(input.channel.as_str(), "mail" | "email") {
            return Err(Error::InvalidConfig(
                "threaded email intake requires an email message".to_owned(),
            ));
        }
        self.with_write_txn_grouped(|txn| {
            let routed = route_inbound_surface_event_in_txn(self, txn, input)?;
            let Some(event) = routed.surface_event.clone() else {
                return Ok(ThreadedEmailIntakeOutcome {
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
                    message_id,
                    references,
                    in_reply_to,
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
                    _ => Error::InvalidClaimBody("email thread membership refused"),
                })?;
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
            Ok(ThreadedEmailIntakeOutcome {
                admission: SurfaceEventAdmission::Accepted(ack),
                thread: Some(passport),
            })
        })
    }
}

/// Canonicalizes raw RFC threading headers for threaded intake, degrading
/// instead of refusing: no usable `Message-ID` means `None` (deliver
/// unthreaded), and a malformed reference or parent is dropped on its own.
pub(crate) fn canonical_email_threading(
    message_id: Option<&str>,
    references: &[String],
    in_reply_to: Option<&str>,
) -> Option<(
    CanonicalMessageId,
    Vec<CanonicalMessageId>,
    Option<CanonicalMessageId>,
)> {
    let message_id = canonical_message_id(message_id?).ok()?;
    let mut canonical_references = Vec::with_capacity(references.len());
    for reference in references {
        if let Ok(reference) = canonical_message_id(reference)
            && !canonical_references.contains(&reference)
        {
            canonical_references.push(reference);
        }
    }
    let in_reply_to = in_reply_to.and_then(|parent| canonical_message_id(parent).ok());
    Some((message_id, canonical_references, in_reply_to))
}
