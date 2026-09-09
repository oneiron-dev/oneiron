//! UID-once/SEQUENCE admission and outbound passport state moves.

use super::CalendarError;
use super::claims::{
    CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    PREDICATE_CALENDAR_PASSPORT,
};
use super::hygiene::{CalendarInviteHygieneContext, hydrate_calendar_invite_hygiene};
use super::mime::{ics_blob_content_hash, read_calendar_invite_ics};
use super::passport::{
    encode_passport_value, event_ref_for_indexed_uid, live_passport_for, resolve_event_by_uid,
};
use super::payload::{CalendarInviteMethod, CalendarInvitePayload};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;

/// Passport `system` key for our own outbound iMIP writes.
///
/// A passport is scoped `(system × UID)`, so our outbound state never collides
/// with an inbound feed's passport for the same UID: a Google-imported mirror
/// of the same meeting keeps its own row and its own SEQUENCE.
pub const CALENDAR_INVITE_PASSPORT_SYSTEM: &str = "oneiron.imip";

/// The lawful UID/SEQUENCE move one invite makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarInviteStateChange {
    /// First confirm: no outbound passport carries this UID yet.
    MintUid,
    /// Update or cancel: the SAME UID moves to a strictly higher SEQUENCE.
    BumpSequence {
        /// The SEQUENCE the live passport carried before this move.
        from: u32,
    },
    /// The exact same revision of the exact same content: nothing moves.
    Replay,
}

/// One admitted invite: the state move plus everything the durable commit needs.
///
/// Produced by [`admit_calendar_invite`] and consumed by
/// `CalendarInviteAdmission::commit_in_txn` inside the caller's transaction.
#[derive(Debug, Clone)]
pub struct CalendarInviteAdmission {
    event_ref: EntityId,
    change: CalendarInviteStateChange,
    next: CalendarPassportValue,
    hygiene: CalendarInviteHygieneContext,
    organizer: String,
    recipient: String,
}

impl CalendarInviteAdmission {
    /// The EVENT this invite's passport is attached to.
    #[must_use]
    pub const fn event_ref(&self) -> EntityId {
        self.event_ref
    }

    /// The UID/SEQUENCE move this invite makes.
    #[must_use]
    pub const fn state_change(&self) -> CalendarInviteStateChange {
        self.change
    }

    /// The vault-hydrated hygiene facts this invite cleared.
    #[must_use]
    pub const fn hygiene(&self) -> &CalendarInviteHygieneContext {
        &self.hygiene
    }

    /// Whether this admission moves durable passport state at all.
    #[must_use]
    pub const fn moves_state(&self) -> bool {
        !matches!(self.change, CalendarInviteStateChange::Replay)
    }

    /// Applies the passport head INSIDE the caller's write transaction.
    ///
    /// This is the whole point of the type: the caller already holds the
    /// transaction that enqueues the ready attempt and writes the connector
    /// TASK, so the bumped SEQUENCE commits with its frozen intent or rolls
    /// back with it. There is no window in which a sequence has advanced but
    /// nothing was scheduled to use it.
    ///
    /// # Errors
    ///
    /// [`CalendarError::IcsIngest`] on store failures, and
    /// [`CalendarError::InviteRefused`] if the live passport moved out from
    /// under the admission between hydration and commit.
    pub(crate) fn commit_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        now: u64,
    ) -> Result<(), CalendarError> {
        crate::booking::lifecycle::bind_booking_invite_identity_in(
            vault,
            wtxn,
            &self.event_ref,
            &self.organizer,
            &self.recipient,
        )
        .map_err(|error| refused(error.to_string()))?;
        let prior = super::passport::live_passport_for_in_txn(
            vault,
            wtxn,
            &self.event_ref,
            CALENDAR_INVITE_PASSPORT_SYSTEM,
            &self.next.uid,
        )?;
        if !self.moves_state() {
            // last_seen_at is not part of replay content identity.
            if prior.as_ref().is_none_or(|(_, live)| {
                live.last_sequence != self.next.last_sequence
                    || live.content_hash != self.next.content_hash
            }) {
                return Err(refused(
                    "the outbound passport moved during replay admission",
                ));
            }
            return Ok(());
        }
        match (self.change, prior.as_ref()) {
            (CalendarInviteStateChange::MintUid, Some(_)) => {
                return Err(refused("this UID already carries an outbound passport"));
            }
            (CalendarInviteStateChange::BumpSequence { from }, Some((_, live)))
                if live.last_sequence != from =>
            {
                return Err(refused("the outbound passport moved during admission"));
            }
            (CalendarInviteStateChange::BumpSequence { .. }, None) => {
                return Err(refused(
                    "the outbound passport disappeared during admission",
                ));
            }
            _ => {}
        }

        let claim_id = EntityId::now();
        let body = ClaimBody::new(
            PREDICATE_CALENDAR_PASSPORT,
            ClaimSubject::Entity(self.event_ref),
            encode_passport_value(&self.next),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        vault.put_claim_in_txn(wtxn, &claim_id, &body, occurred, now)?;
        if let Some((old_id, _)) = prior {
            vault.supersede_claim_in_txn(wtxn, &claim_id, &old_id, now)?;
        }
        Ok(())
    }
}

/// The fixed-order admission for one outbound iMIP invite.
///
/// Exact decode (the caller already holds the typed payload) → emit/state
/// validation against the live outbound passport → vault-only hygiene
/// hydration → hygiene evaluation. Everything after this — the dispatch gate,
/// the intent ledger, the attempt queue — is the ordinary OF-327 rail, which is
/// why this function deliberately stops at producing a
/// [`CalendarInviteAdmission`] instead of writing anything.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] for a UID/SEQUENCE regression, an unknown
/// UID, a missing or unreadable ICS blob, or any hygiene row refusal;
/// [`CalendarError::IcsIngest`] on store failures.
pub fn admit_calendar_invite(
    vault: &Vault,
    actor: EntityId,
    payload: &CalendarInvitePayload,
    now: u64,
) -> Result<CalendarInviteAdmission, CalendarError> {
    payload.validate_shape()?;

    // --- emit/state validation -----------------------------------------
    let event_ref = resolve_invite_event(vault, &payload.uid)?
        .ok_or_else(|| refused("this invite UID names no EVENT in the vault"))?;
    let content_hash = ics_blob_content_hash(vault, &payload.ics_blob_ref)?;
    let live = live_passport_for(
        vault,
        &event_ref,
        CALENDAR_INVITE_PASSPORT_SYSTEM,
        &payload.uid,
    )?
    .map(|(_, value)| value);
    let change = classify_invite_state(payload, live.as_ref(), content_hash)?;

    // --- vault-only hygiene --------------------------------------------
    let hygiene = hydrate_calendar_invite_hygiene(vault, actor, event_ref, payload)?;
    hygiene.evaluate()?;

    let next = CalendarPassportValue {
        system: CALENDAR_INVITE_PASSPORT_SYSTEM.to_owned(),
        uid: payload.uid.clone(),
        last_sequence: payload.sequence,
        content_hash,
        // Our own writes are outbound-bearing, so the CAL-02 absence law never
        // counts them as a feed vote (`is_inbound_bearing` is false).
        direction: CalendarPassportDirection::Outbound,
        last_seen_at: now,
        presence: CalendarPassportPresence::Live,
    };
    Ok(CalendarInviteAdmission {
        event_ref,
        change,
        next,
        hygiene,
        organizer: super::ics::invite_organizer(&read_calendar_invite_ics(vault, payload)?)?,
        recipient: payload.recipient.clone(),
    })
}

/// The UID/SEQUENCE law, stated once.
///
/// * No live outbound passport ⇒ this is the first confirm: it must be a
///   `REQUEST` at `SEQUENCE 0`. A cancel or a jumped-in sequence for a UID we
///   never invited is a caller bug, not a new meeting.
/// * A live passport ⇒ the same UID moves to a strictly higher SEQUENCE.
/// * The same SEQUENCE with the same content is a replay: nothing moves.
/// * A lower SEQUENCE, or the same SEQUENCE with drifted content, is a
///   regression — a same-or-lower SEQUENCE is silently ignored by real clients,
///   so shipping one would be an invisible failure.
fn classify_invite_state(
    payload: &CalendarInvitePayload,
    live: Option<&CalendarPassportValue>,
    content_hash: [u8; 32],
) -> Result<CalendarInviteStateChange, CalendarError> {
    let Some(live) = live else {
        if payload.method != CalendarInviteMethod::Request {
            return Err(refused("cannot cancel an invite that was never sent"));
        }
        if payload.sequence != 0 {
            return Err(refused("a first confirm must mint its UID at SEQUENCE 0"));
        }
        return Ok(CalendarInviteStateChange::MintUid);
    };
    if payload.sequence > live.last_sequence {
        return Ok(CalendarInviteStateChange::BumpSequence {
            from: live.last_sequence,
        });
    }
    if payload.sequence == live.last_sequence && content_hash == live.content_hash {
        return Ok(CalendarInviteStateChange::Replay);
    }
    Err(refused(format!(
        "SEQUENCE {} does not advance the live outbound passport at {}",
        payload.sequence, live.last_sequence
    )))
}

/// Resolves the EVENT one invite UID names.
///
/// Live passport claims are synced truth and are consulted first; on the first
/// confirm no passport carries the UID yet, so the CAL-02 UID index — which the
/// minting side (booking confirm / ingest) already writes through
/// [`super::passport::index_passport_uid`] — is the fallback. Nothing new is
/// indexed here.
fn resolve_invite_event(vault: &Vault, uid: &str) -> Result<Option<EntityId>, CalendarError> {
    if let Some(event_ref) = resolve_event_by_uid(vault, uid)? {
        return Ok(Some(event_ref));
    }
    event_ref_for_indexed_uid(vault, uid)
}

pub(crate) fn refused(reason: impl Into<String>) -> CalendarError {
    CalendarError::InviteRefused {
        reason: reason.into(),
    }
}

pub(in crate::calendar) fn ingest_reason(reason: String) -> CalendarError {
    CalendarError::IcsIngest { reason }
}
