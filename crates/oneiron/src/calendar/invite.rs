//! Outbound iMIP invite adapter (CAL-04, ONE-1786).
//!
//! One calendar-specific adapter over the already-shipped OF-327 outbound
//! spine. Nothing here mints a second dispatcher, ledger, gate, transport,
//! grant system, connector queue, entity type, edge kind, or claim predicate:
//! the verb `calendar.invite` is registered in the ordinary capability
//! manifest, the payload is frozen by the ordinary dispatch pipeline, the
//! durability and governance rails are the ordinary ones.
//!
//! What this module owns is exactly the calendar half:
//!
//! * **The frozen five-field payload.** [`CalendarInvitePayload`] is C7's exact
//!   contract — `{method, uid, sequence, ics_blob_ref, recipient}`, in that
//!   order, uppercase iMIP method, closed to unknown keys. The frozen body
//!   carries the blob *reference*; raw `.ics` bytes never enter it.
//! * **The UID/SEQUENCE law.** A UID is minted once, at the first confirm, and
//!   reused forever; every update and cancel bumps `SEQUENCE` on the SAME UID.
//!   The state lives in the CAL-00 `calendar.passport` claim
//!   ([`CalendarPassportValue`]) with direction `outbound` — no local passport
//!   type, no new predicate. A connector retry replays the frozen payload and
//!   never re-enters [`admit_calendar_invite`], so it can neither mint a UID
//!   nor bump a sequence.
//! * **Hygiene from vault evidence only.** [`CalendarInviteHygieneContext`] has
//!   no public constructor and no public field: it is hydrated at the
//!   chokepoint from live vault state. A caller cannot hand the engine a
//!   consent boolean, because there is no API that accepts one.
//!
//! ## The order is fixed
//!
//! [`admit_calendar_invite`] runs exact decode → emit/state validation →
//! vault-only hygiene hydration → hygiene evaluation, and hands back a
//! [`CalendarInviteAdmission`] whose [`CalendarInviteAdmission::commit_in_txn`]
//! joins the caller's existing durable transaction. That is what makes "no
//! bumped sequence survives without its frozen intent" true by construction:
//! the passport head and the attempt/TASK land in one write transaction or
//! neither does.

use serde::{Deserialize, Serialize};

use super::CalendarError;
use super::claims::{
    CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    PREDICATE_CALENDAR_ATTENDEE, PREDICATE_CALENDAR_PASSPORT, decode_attendee_value,
};
use super::passport::{
    encode_passport_value, event_ref_for_indexed_uid, live_passport_for, resolve_event_by_uid,
};
use crate::Vault;
use crate::channel_identity::{ChannelIdentity, ChannelIdentityShape, ChannelIdentityState};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::outbound_grant::{StandingOutboundGrantScope, StandingOutboundGrantStatus};
use crate::outbound_intent_ledger::OutboundToolDescriptor;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_OUTBOUND_GRANT};
use crate::temporal::TimeRange;

/// Connector key iMIP invites dispatch through.
///
/// Equal to [`crate::memory::CALENDAR_INVITE_OUTBOUND_CHANNEL`] by law — CAL-09
/// pinned the surface to CAL-04's spelling before CAL-04 existed, and
/// [`tests::verb_and_channel_match_the_cal_09_surface_constants`] keeps the two
/// from drifting.
pub const CALENDAR_INVITE_CHANNEL: &str = "calendar";

/// The outbound verb this adapter registers.
///
/// Sole-owner registration: this exact string is what CAL-04 appends to
/// `COMMON_OUTBOUND_VERB_KINDS` and what the `calendar` connector manifest
/// exposes. No other lane adds it.
pub const CALENDAR_INVITE_VERB: &str = "calendar.invite";

/// Passport `system` key for our own outbound iMIP writes.
///
/// A passport is scoped `(system × UID)`, so our outbound state never collides
/// with an inbound feed's passport for the same UID: a Google-imported mirror
/// of the same meeting keeps its own row and its own SEQUENCE.
pub const CALENDAR_INVITE_PASSPORT_SYSTEM: &str = "oneiron.imip";

/// Media type of the iMIP part and of the blob artifact that carries it.
pub const CALENDAR_INVITE_MEDIA_TYPE: &str = "text/calendar";

/// Attachment filename the connector puts on the `text/calendar` part.
pub const CALENDAR_INVITE_PART_FILENAME: &str = "invite.ics";

/// OF-327 tool descriptor for `calendar.invite`.
///
/// `read_only_hint: Some(false)` keeps the ledger classifier on the Effectful
/// path — an invite is a real external effect and must earn a durable intent.
/// `idempotency_supported_hint: Some(true)` is the truth of iMIP: replaying the
/// same `(UID, SEQUENCE, METHOD)` to the same attendee is a no-op in every
/// conforming client, which is exactly why a retry may replay frozen bytes.
pub const CALENDAR_INVITE_TOOL_DESCRIPTOR: OutboundToolDescriptor = OutboundToolDescriptor {
    read_only_hint: Some(false),
    idempotency_supported_hint: Some(true),
};

/// Channel classes an iMIP invite counts as prior contact on.
///
/// The invite rides email, and the calendar connector is its own class; a live
/// touch on either is a real prior thread with this recipient.
const PRIOR_THREAD_CHANNEL_CLASSES: [&str; 2] = ["email", CALENDAR_INVITE_CHANNEL];

/// iMIP method carried by one invite.
///
/// Closed on purpose. Outlook treats a `VEVENT` with no explicit `METHOD` as a
/// brand-new event rather than an update, so a defaulted method is a duplicate
/// meeting in the recipient's calendar — the set never widens silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CalendarInviteMethod {
    /// `METHOD:REQUEST` — create or update an invitation.
    Request,
    /// `METHOD:CANCEL` — withdraw an invitation.
    Cancel,
}

impl CalendarInviteMethod {
    /// Wire token (`REQUEST` / `CANCEL`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Cancel => "CANCEL",
        }
    }

    /// Parses the wire token; anything outside the closed set is `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "REQUEST" => Some(Self::Request),
            "CANCEL" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// C7's exact frozen invite payload.
///
/// Five typed fields in a fixed order, closed to unknown keys. This is what the
/// dispatch pipeline freezes beside the intent and what the connector-send side
/// exact-decodes; a forged sixth key (a caller-asserted `has_consent`, say) is a
/// decode failure, not an ignored extra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarInvitePayload {
    /// iMIP method.
    pub method: CalendarInviteMethod,
    /// EVENT UID the invite addresses. Minted once, reused forever.
    pub uid: String,
    /// iTIP SEQUENCE of this revision. Strictly increasing on the same UID.
    pub sequence: u32,
    /// Blob-artifact ref of the rendered ICS payload. The bytes stay in the
    /// blob store; only this reference is ever frozen.
    pub ics_blob_ref: String,
    /// Delivery target.
    pub recipient: String,
}

impl CalendarInvitePayload {
    /// Rejects blank required fields before any vault work.
    fn validate_shape(&self) -> Result<(), CalendarError> {
        for (field, value) in [
            ("uid", self.uid.as_str()),
            ("ics_blob_ref", self.ics_blob_ref.as_str()),
            ("recipient", self.recipient.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(refused(format!("{field} must not be blank")));
            }
        }
        Ok(())
    }
}

/// The frozen-payload envelope the dispatch pipeline writes.
///
/// The frozen bytes are the flattened intent plus optional sidecars; this
/// reader picks out the invite sidecar without re-deriving anything else, the
/// same discipline `frozen_payload_hygiene_headers` follows for CA-05 headers.
#[derive(Deserialize)]
struct FrozenInviteEnvelope {
    calendar_invite: CalendarInvitePayload,
}

/// Exact-decodes the invite payload out of frozen outbound bytes.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] when the bytes carry no invite sidecar, or
/// carry one the five-field contract does not accept. A `calendar.invite` call
/// whose payload the engine cannot vouch for never reaches the wire.
pub fn decode_frozen_calendar_invite(
    payload: &[u8],
) -> Result<CalendarInvitePayload, CalendarError> {
    let envelope: FrozenInviteEnvelope = serde_json::from_slice(payload)
        .map_err(|_| refused("frozen payload carries no exact five-field invite body"))?;
    envelope.calendar_invite.validate_shape()?;
    Ok(envelope.calendar_invite)
}

/// Why an invite is allowed to attach a real `.ics` to this recipient.
///
/// Cold outreach NEVER attaches an invite (ARCH-0060 hygiene row): a REQUEST
/// must stand on one of these two, and CAL-04 only ever *verifies* them.
/// BK-03 (ONE-1814) owns minting the booking-page standing grant; until it
/// lands, [`Self::PriorThread`] is the only basis that can exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarInviteConsentBasis {
    /// A live `comm.last_touch` with this recipient on email or calendar.
    PriorThread,
    /// An ACTIVE standing outbound grant covering invites to this recipient.
    ConfirmedBookingGrant {
        /// The grant entity the door verified. Never minted here.
        grant_ref: EntityId,
    },
}

impl CalendarInviteConsentBasis {
    /// Stable receipt/refusal token for this basis.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PriorThread => "prior_thread",
            Self::ConfirmedBookingGrant { .. } => "confirmed_booking_grant",
        }
    }
}

/// The hygiene facts one invite is judged on, hydrated from vault evidence.
///
/// Deliberately opaque: no public constructor, no public field, no `Deserialize`.
/// The forged-context attack this closes is a caller passing
/// `{"has_consent": true}` alongside the payload — there is nowhere to put it,
/// and [`CalendarInvitePayload`] rejects the extra key outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarInviteHygieneContext {
    method: CalendarInviteMethod,
    consent_basis: Option<CalendarInviteConsentBasis>,
    recipient_bound_to_invite: bool,
    sender_domain: Option<String>,
    primary_domain: Option<String>,
    sender_is_shared_presence: bool,
}

impl CalendarInviteHygieneContext {
    /// The consent basis the vault actually carries for this recipient.
    #[must_use]
    pub fn consent_basis(&self) -> Option<&CalendarInviteConsentBasis> {
        self.consent_basis.as_ref()
    }

    /// Whether the recipient is already an attendee of the existing invite.
    #[must_use]
    pub const fn recipient_bound_to_invite(&self) -> bool {
        self.recipient_bound_to_invite
    }

    /// Domain the send will actually leave from.
    #[must_use]
    pub fn sender_domain(&self) -> Option<&str> {
        self.sender_domain.as_deref()
    }

    /// The vault's primary calendar/email domain.
    #[must_use]
    pub fn primary_domain(&self) -> Option<&str> {
        self.primary_domain.as_deref()
    }

    /// Evaluates the ARCH-0060 hygiene rows against these facts.
    ///
    /// # Errors
    ///
    /// [`CalendarError::InviteRefused`] naming the row that refused.
    pub fn evaluate(&self) -> Result<(), CalendarError> {
        // Row: "Real invite AFTER the yes, from the primary calendar domain —
        // never from sequencer-class infrastructure." A shared-presence identity
        // IS that infrastructure, so it can never carry an invite.
        let Some(sender_domain) = self.sender_domain.as_deref() else {
            return Err(refused(
                "no active dedicated sending identity carries this calendar invite",
            ));
        };
        if self.sender_is_shared_presence {
            return Err(refused(
                "a shared-presence sending identity is sequencer-class infrastructure",
            ));
        }
        let Some(primary_domain) = self.primary_domain.as_deref() else {
            return Err(refused("no primary calendar domain is configured"));
        };
        if sender_domain != primary_domain {
            return Err(refused(format!(
                "sender domain {sender_domain:?} is not the primary calendar domain \
                 {primary_domain:?}"
            )));
        }

        match self.method {
            // Row: "Cold outreach NEVER attaches .ics."
            CalendarInviteMethod::Request => {
                if self.consent_basis.is_none() {
                    return Err(refused(
                        "a cold invite has no consent basis: needs a prior thread or a \
                         confirmed booking grant",
                    ));
                }
            }
            // A cancellation may only reach someone the invite already bound;
            // otherwise CANCEL becomes a cold ping wearing a calendar hat.
            CalendarInviteMethod::Cancel => {
                if !self.recipient_bound_to_invite {
                    return Err(refused(
                        "cancel is only deliverable to a recipient already bound to the invite",
                    ));
                }
            }
        }
        Ok(())
    }
}

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
/// [`CalendarInviteAdmission::commit_in_txn`] inside the caller's transaction.
#[derive(Debug, Clone)]
pub struct CalendarInviteAdmission {
    event_ref: EntityId,
    change: CalendarInviteStateChange,
    next: CalendarPassportValue,
    hygiene: CalendarInviteHygieneContext,
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
        if !self.moves_state() {
            return Ok(());
        }
        let prior = live_passport_for(
            vault,
            &self.event_ref,
            CALENDAR_INVITE_PASSPORT_SYSTEM,
            &self.next.uid,
        )?;
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

/// Resolves `ics_blob_ref` to a real blob artifact head and returns its
/// content hash.
///
/// Two jobs in one read: it proves the frozen reference dereferences (I10's
/// precondition — the connector must be able to build the MIME part) and it
/// supplies the passport's content hash, so "same SEQUENCE, drifted content"
/// is decidable without ever putting `.ics` bytes in the frozen body.
fn ics_blob_content_hash(vault: &Vault, blob_ref: &str) -> Result<[u8; 32], CalendarError> {
    let artifact_id = parse_blob_ref(blob_ref)?;
    let head = vault
        .blob_artifact_head(&artifact_id)
        .map_err(CalendarError::from)?
        .ok_or_else(|| refused("ics_blob_ref names no stored blob artifact version"))?;
    Ok(head.content_hash)
}

/// Accepts `blob:<32-hex>` and a bare `<32-hex>` entity id.
fn parse_blob_ref(blob_ref: &str) -> Result<EntityId, CalendarError> {
    let trimmed = blob_ref.trim();
    let hex = trimmed.strip_prefix("blob:").unwrap_or(trimmed);
    EntityId::from_hex(hex).map_err(|_| refused("ics_blob_ref is not a blob artifact entity ref"))
}

/// Resolves the ICS bytes one frozen invite references.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] when the reference does not dereference to
/// stored bytes; [`CalendarError::IcsIngest`] on store failures.
pub fn read_calendar_invite_ics(
    vault: &Vault,
    payload: &CalendarInvitePayload,
) -> Result<Vec<u8>, CalendarError> {
    let artifact_id = parse_blob_ref(&payload.ics_blob_ref)?;
    let head = vault
        .blob_artifact_head(&artifact_id)
        .map_err(CalendarError::from)?
        .ok_or_else(|| refused("ics_blob_ref names no stored blob artifact version"))?;
    vault
        .read_blob_artifact_version(&artifact_id, head.version)
        .map_err(CalendarError::from)?
        .ok_or_else(|| refused("ics_blob_ref head has no stored bytes"))
}

/// The `text/calendar` part one invite send carries beside the ordinary body.
///
/// Not a parallel connector payload: it is the resolved form of the SAME frozen
/// reference, built at the last boundary before transport, exactly like the
/// CA-05 hygiene headers are read from frozen bytes rather than re-derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarInviteMimePart {
    /// Full `Content-Type` header value, method parameter included.
    pub content_type: String,
    /// The iMIP method this part carries.
    pub method: CalendarInviteMethod,
    /// Suggested attachment filename.
    pub filename: String,
    /// The rendered `.ics` bytes, dereferenced from the frozen blob ref.
    pub ics: Vec<u8>,
}

/// Builds the `text/calendar; method=…` part for one frozen invite.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] when the frozen blob ref does not resolve;
/// [`CalendarError::IcsIngest`] on store failures.
pub fn build_calendar_invite_mime_part(
    vault: &Vault,
    payload: &CalendarInvitePayload,
) -> Result<CalendarInviteMimePart, CalendarError> {
    let ics = read_calendar_invite_ics(vault, payload)?;
    Ok(CalendarInviteMimePart {
        content_type: format!(
            "{CALENDAR_INVITE_MEDIA_TYPE}; method={}; charset=utf-8",
            payload.method.as_str()
        ),
        method: payload.method,
        filename: CALENDAR_INVITE_PART_FILENAME.to_owned(),
        ics,
    })
}

// ── vault-only hygiene hydration ────────────────────────────────────────

/// Builds the hygiene context from live vault state and nothing else.
///
/// Every fact below is a read of stored evidence: `comm.last_touch` claims,
/// ACTIVE standing outbound grants, `calendar.attendee` claims on the EVENT,
/// and OF-347 ChannelIdentity rows. No argument here is a caller assertion —
/// the payload contributes only the recipient and the method.
fn hydrate_calendar_invite_hygiene(
    vault: &Vault,
    actor: EntityId,
    event_ref: EntityId,
    payload: &CalendarInvitePayload,
) -> Result<CalendarInviteHygieneContext, CalendarError> {
    let recipient = payload.recipient.trim();
    let consent_basis = resolve_consent_basis(vault, recipient)?;
    let recipient_bound_to_invite = recipient_is_bound_attendee(vault, &event_ref, recipient)?;
    let sender = sending_identity(vault, actor)?;
    let primary_domain = primary_calendar_domain(vault, actor)?;
    let sender_is_shared_presence = sender
        .as_ref()
        .is_some_and(|identity| identity.shape == ChannelIdentityShape::SharedPresence);
    let sender_domain = sender
        .as_ref()
        .and_then(|identity| email_domain(&identity.address_or_handle));
    Ok(CalendarInviteHygieneContext {
        method: payload.method,
        consent_basis,
        recipient_bound_to_invite,
        sender_domain,
        primary_domain,
        sender_is_shared_presence,
    })
}

/// Prior thread first, then a verified standing grant. Never minted here.
fn resolve_consent_basis(
    vault: &Vault,
    recipient: &str,
) -> Result<Option<CalendarInviteConsentBasis>, CalendarError> {
    for channel_class in PRIOR_THREAD_CHANNEL_CLASSES {
        let touched = crate::comm::count_active_comm_claims(
            vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            recipient,
            channel_class,
        )
        .map_err(|err| ingest_reason(err.to_string()))?;
        if touched > 0 {
            return Ok(Some(CalendarInviteConsentBasis::PriorThread));
        }
    }
    Ok(confirmed_booking_grant(vault, recipient)?
        .map(|grant_ref| CalendarInviteConsentBasis::ConfirmedBookingGrant { grant_ref }))
}

/// Verifies — never mints — an ACTIVE standing outbound grant that covers
/// invites to this recipient.
///
/// BK-03 (ONE-1814) owns the booking-page grant and the
/// `BookingPageInvites`-shaped scope; this door reads whatever the existing
/// [`StandingOutboundGrantScope`] vocabulary already expresses: a contact-scoped
/// grant for this exact recipient, or a channel-scoped grant on the calendar
/// connector. Until BK-03 mints one, nothing here can match and only a prior
/// thread can carry a REQUEST — which is exactly the ratified pre-BK-03 state.
fn confirmed_booking_grant(
    vault: &Vault,
    recipient: &str,
) -> Result<Option<EntityId>, CalendarError> {
    let grants = vault
        .entities_by_type(ENTITY_TYPE_OUTBOUND_GRANT)
        .map_err(CalendarError::from)?;
    let mut matched: Option<EntityId> = None;
    for grant_ref in grants {
        let Some(grant) = vault
            .get_standing_outbound_grant(&grant_ref)
            .map_err(CalendarError::from)?
        else {
            continue;
        };
        if grant.status != StandingOutboundGrantStatus::Active || grant.revoked_at.is_some() {
            continue;
        }
        let covers = match &grant.scope {
            StandingOutboundGrantScope::Contact { contact_ref } => {
                contact_ref.trim().eq_ignore_ascii_case(recipient)
            }
            StandingOutboundGrantScope::Channel { channel } => {
                crate::counterparty_contact::normalize_channel_class(channel)
                    == CALENDAR_INVITE_CHANNEL
            }
            _ => false,
        };
        // Converge on one deterministic grant when several cover the same send.
        if covers && matched.is_none_or(|current| grant_ref.as_bytes() < current.as_bytes()) {
            matched = Some(grant_ref);
        }
    }
    Ok(matched)
}

/// Whether a live `calendar.attendee` claim already binds this recipient.
fn recipient_is_bound_attendee(
    vault: &Vault,
    event_ref: &EntityId,
    recipient: &str,
) -> Result<bool, CalendarError> {
    for claim_id in vault
        .claims_for_subject(event_ref)
        .map_err(CalendarError::from)?
    {
        let Some(body) = vault.get_claim(&claim_id).map_err(CalendarError::from)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_ATTENDEE
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let Ok(attendee) = decode_attendee_value(&body.value) else {
            continue;
        };
        if attendee_matches(&attendee.who, recipient) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `MAILTO:` prefixes are vendor spelling, not identity.
fn attendee_matches(who: &str, recipient: &str) -> bool {
    let strip = |value: &str| -> String {
        let trimmed = value.trim();
        let bare = trimmed
            .strip_prefix("mailto:")
            .or_else(|| trimmed.strip_prefix("MAILTO:"))
            .unwrap_or(trimmed);
        bare.to_ascii_lowercase()
    };
    strip(who) == strip(recipient)
}

/// The ACTIVE identity that will actually carry this send.
///
/// The calendar connector's own OF-347 identity wins when one exists; otherwise
/// the invite rides the ordinary email identity, which is what iMIP is. An
/// ambiguous pair on the same channel resolves to `None` and therefore refuses:
/// picking arbitrarily would put a nondeterministic sender on a governed send.
fn sending_identity(
    vault: &Vault,
    actor: EntityId,
) -> Result<Option<ChannelIdentity>, CalendarError> {
    if let Some(identity) = active_identity_for_channel(vault, actor, CALENDAR_INVITE_CHANNEL)? {
        return Ok(Some(identity));
    }
    active_identity_for_channel(vault, actor, "email")
}

/// The vault's primary calendar/email domain: the ACTIVE dedicated email
/// identity bound to this actor.
fn primary_calendar_domain(
    vault: &Vault,
    actor: EntityId,
) -> Result<Option<String>, CalendarError> {
    let Some(identity) = active_identity_for_channel(vault, actor, "email")? else {
        return Ok(None);
    };
    if identity.shape == ChannelIdentityShape::SharedPresence {
        return Ok(None);
    }
    Ok(email_domain(&identity.address_or_handle))
}

/// The single ACTIVE identity bound to `actor` on one channel class.
fn active_identity_for_channel(
    vault: &Vault,
    actor: EntityId,
    channel_class: &str,
) -> Result<Option<ChannelIdentity>, CalendarError> {
    let wanted = crate::counterparty_contact::normalize_channel_class(channel_class);
    let mut found: Option<ChannelIdentity> = None;
    for id in vault
        .entities_by_type(ENTITY_TYPE_CHANNEL_IDENTITY)
        .map_err(CalendarError::from)?
    {
        let Some(identity) = vault
            .get_channel_identity(&id)
            .map_err(CalendarError::from)?
        else {
            continue;
        };
        if identity.state != ChannelIdentityState::Active
            || crate::counterparty_contact::normalize_channel_class(&identity.channel) != wanted
            || identity.binding != crate::channel_identity::ChannelIdentityBinding::agent(actor)
        {
            continue;
        }
        if found.is_some() {
            // Ambiguous: refuse rather than guess which one sends.
            return Ok(None);
        }
        found = Some(identity);
    }
    Ok(found)
}

/// Lowercased domain of an `local@domain` address; `None` for a handle.
fn email_domain(address_or_handle: &str) -> Option<String> {
    let (local, domain) = address_or_handle.trim().rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

fn refused(reason: impl Into<String>) -> CalendarError {
    CalendarError::InviteRefused {
        reason: reason.into(),
    }
}

fn ingest_reason(reason: String) -> CalendarError {
    CalendarError::IcsIngest { reason }
}

/// Standalone-transaction form of [`CalendarInviteAdmission::commit_in_txn`],
/// for unit tests that exercise the passport law without standing up the whole
/// schedule chokepoint. Production always composes into the caller's txn — that
/// composition is the atomicity guarantee — so this is deliberately test-only.
#[cfg(test)]
fn commit_admission(
    vault: &Vault,
    admission: &CalendarInviteAdmission,
    now: u64,
) -> Result<(), CalendarError> {
    let mut wtxn = vault.store.env.write_txn().map_err(crate::Error::from)?;
    admission.commit_in_txn(vault, &mut wtxn, now)?;
    wtxn.commit().map_err(crate::Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::ics::{ImipEmitRequest, emit_imip_ics, persist_imip_blob};
    use crate::calendar::test_support::open_calendar_vault;
    use crate::channel_identity::{ChannelIdentity, ChannelIdentityBinding};
    use crate::edge::EdgeActorClass;
    use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
    use crate::write_envelope::WriteActor;

    const NOW: u64 = 1_800_000_000;
    const UID: &str = "one-1786@oneiron.test";

    fn actor(vault: &Vault) -> EntityId {
        let id = crate::test_util::entity(0x51);
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                b"cal-04 actor",
            )
            .expect("put actor");
        id
    }

    fn event(vault: &Vault) -> EntityId {
        let id = crate::test_util::entity(0x52);
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_EVENT,
                TimeRange {
                    start: NOW,
                    end: NOW + 3_600,
                },
                NOW,
                b"cal-04 event",
            )
            .expect("put event");
        crate::calendar::passport::index_passport_uid(vault, UID, &id).expect("index uid");
        id
    }

    fn identity(vault: &Vault, seed: u8, actor: EntityId, channel: &str, address: &str) {
        let id = crate::test_util::entity(seed);
        let mut identity = ChannelIdentity::requested(
            channel,
            address,
            ChannelIdentityShape::DedicatedAddress,
            ChannelIdentityBinding::agent(actor),
            NOW,
        );
        identity.state = ChannelIdentityState::Active;
        vault
            .create_channel_identity(&id, &identity)
            .expect("create identity");
    }

    fn attendee(vault: &Vault, seed: u8, event_ref: EntityId, who: &str) {
        let claim_id = crate::test_util::entity(seed);
        vault
            .put_claim(
                &claim_id,
                &ClaimBody::new(
                    PREDICATE_CALENDAR_ATTENDEE,
                    ClaimSubject::Entity(event_ref),
                    rmpv::Value::Map(vec![
                        (rmpv::Value::from("who"), rmpv::Value::from(who)),
                        (
                            rmpv::Value::from("role"),
                            rmpv::Value::from("REQ-PARTICIPANT"),
                        ),
                        (rmpv::Value::from("partstat"), rmpv::Value::from("ACCEPTED")),
                    ]),
                    1.0,
                    ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                ),
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("put attendee claim");
    }

    fn emit(sequence: u32, method: CalendarInviteMethod) -> Vec<u8> {
        emit_imip_ics(&ImipEmitRequest {
            method,
            uid: UID.to_owned(),
            sequence,
            organizer: "me@primary.test".to_owned(),
            attendees: vec!["guest@example.test".to_owned()],
            summary: "Design review".to_owned(),
            starts_at_utc: 1_800_003_600,
            ends_at_utc: 1_800_007_200,
            tz_label: "Europe/Warsaw".to_owned(),
            dtstamp_utc: NOW,
        })
        .expect("emit")
    }

    fn blob(vault: &Vault, seed: u8, actor: EntityId, bytes: &[u8]) -> String {
        let artifact = crate::test_util::entity(seed);
        persist_imip_blob(
            vault,
            &artifact,
            "one-1786 invite",
            bytes,
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            WriteActor::new(actor, EdgeActorClass::Human),
            NOW,
        )
        .expect("persist blob")
    }

    /// Prior-thread evidence written the way the comm projector writes it, but
    /// without depending on a projector pass: `comm.last_touch` on the party.
    fn prior_thread(vault: &Vault, seed: u8, party: &str) {
        let party_ref = crate::comm::resolve_or_create_comm_party(vault, party).expect("party");
        let body = crate::comm::CommClaimValue::LastTouch {
            party_ref,
            channel_class: "email".to_owned(),
            occurred_at: NOW,
        }
        .claim_body();
        vault
            .put_claim(
                &crate::test_util::entity(seed),
                &body,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("put last_touch claim");
    }

    /// The whole point of the pre-seam: CAL-09's surface constants and CAL-04's
    /// registration constants are the SAME strings, or the branch is dead.
    #[test]
    fn verb_and_channel_match_the_cal_09_surface_constants() {
        assert_eq!(
            CALENDAR_INVITE_VERB,
            crate::memory::CALENDAR_INVITE_OUTBOUND_VERB
        );
        assert_eq!(
            CALENDAR_INVITE_CHANNEL,
            crate::memory::CALENDAR_INVITE_OUTBOUND_CHANNEL
        );
        assert_eq!(CalendarInviteMethod::Request.as_str(), "REQUEST");
        assert_eq!(CalendarInviteMethod::Cancel.as_str(), "CANCEL");
        assert_eq!(
            CalendarInviteMethod::parse("REQUEST"),
            Some(CalendarInviteMethod::Request)
        );
        assert_eq!(CalendarInviteMethod::parse("request"), None);
    }

    #[test]
    fn calendar_invite_payload_is_exact_five_field_contract() {
        let payload = CalendarInvitePayload {
            method: CalendarInviteMethod::Request,
            uid: UID.to_owned(),
            sequence: 0,
            ics_blob_ref: "blob:c0ffee".to_owned(),
            recipient: "guest@example.test".to_owned(),
        };
        let wire = serde_json::to_value(&payload).expect("serialize");
        let object = wire.as_object().expect("object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["method", "uid", "sequence", "ics_blob_ref", "recipient"]
        );
        assert_eq!(object["method"], serde_json::json!("REQUEST"));

        // A forged hygiene assertion is a decode failure, not an ignored extra:
        // there is no channel by which a caller can hand the engine consent.
        let forged = serde_json::json!({
            "method": "REQUEST",
            "uid": UID,
            "sequence": 0,
            "ics_blob_ref": "blob:c0ffee",
            "recipient": "guest@example.test",
            "has_consent": true,
        });
        assert!(serde_json::from_value::<CalendarInvitePayload>(forged).is_err());

        // And a lowercase method is rejected rather than defaulted.
        let lowercased = serde_json::json!({
            "method": "request",
            "uid": UID,
            "sequence": 0,
            "ics_blob_ref": "blob:c0ffee",
            "recipient": "guest@example.test",
        });
        assert!(serde_json::from_value::<CalendarInvitePayload>(lowercased).is_err());
    }

    #[test]
    fn calendar_invite_frozen_body_references_blob_not_raw_ics() {
        let payload = CalendarInvitePayload {
            method: CalendarInviteMethod::Request,
            uid: UID.to_owned(),
            sequence: 0,
            ics_blob_ref: "blob:c0ffee".to_owned(),
            recipient: "guest@example.test".to_owned(),
        };
        let frozen = serde_json::to_vec(&serde_json::json!({
            "verb": CALENDAR_INVITE_VERB,
            "calendar_invite": payload,
        }))
        .expect("freeze");
        let text = String::from_utf8(frozen.clone()).expect("utf-8");
        assert!(
            !text.contains("BEGIN:VCALENDAR"),
            "frozen body carried raw ICS: {text}"
        );
        assert!(text.contains("blob:c0ffee"));
        assert_eq!(
            decode_frozen_calendar_invite(&frozen).expect("decode"),
            payload
        );

        // Fail closed: a calendar.invite frozen call with no invite sidecar is
        // refused rather than treated as a generic send.
        let bare =
            serde_json::to_vec(&serde_json::json!({"verb": CALENDAR_INVITE_VERB})).expect("freeze");
        assert!(decode_frozen_calendar_invite(&bare).is_err());
    }

    /// One vault with everything a lawful REQUEST needs.
    fn admitted_fixture() -> (tempfile::TempDir, Vault, EntityId, EntityId, String) {
        let (dir, vault) = open_calendar_vault();
        let actor = actor(&vault);
        let event_ref = event(&vault);
        identity(&vault, 0x53, actor, "email", "me@primary.test");
        prior_thread(&vault, 0x60, "guest@example.test");
        let blob_ref = blob(&vault, 0x54, actor, &emit(0, CalendarInviteMethod::Request));
        (dir, vault, actor, event_ref, blob_ref)
    }

    fn request(sequence: u32, blob_ref: &str) -> CalendarInvitePayload {
        CalendarInvitePayload {
            method: CalendarInviteMethod::Request,
            uid: UID.to_owned(),
            sequence,
            ics_blob_ref: blob_ref.to_owned(),
            recipient: "guest@example.test".to_owned(),
        }
    }

    #[test]
    fn calendar_invite_first_confirm_mints_uid_once() {
        let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
        let payload = request(0, &blob_ref);
        let admission =
            admit_calendar_invite(&vault, actor_ref, &payload, NOW).expect("first confirm admits");
        assert_eq!(admission.state_change(), CalendarInviteStateChange::MintUid);
        assert_eq!(admission.event_ref(), event_ref);
        assert_eq!(
            admission.hygiene().consent_basis(),
            Some(&CalendarInviteConsentBasis::PriorThread)
        );

        commit_admission(&vault, &admission, NOW).expect("commit passport");

        let live = super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].1.uid, UID);
        assert_eq!(live[0].1.last_sequence, 0);
        assert_eq!(live[0].1.direction, CalendarPassportDirection::Outbound);

        // A byte-identical re-admission is a replay: no second UID, no bump.
        let replay =
            admit_calendar_invite(&vault, actor_ref, &payload, NOW).expect("replay admits");
        assert_eq!(replay.state_change(), CalendarInviteStateChange::Replay);
        assert!(!replay.moves_state());
    }

    #[test]
    fn calendar_invite_update_reuses_uid_and_increments_sequence() {
        let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
        commit(&vault, actor_ref, &request(0, &blob_ref));

        let update_blob = blob(
            &vault,
            0x55,
            actor_ref,
            &emit(1, CalendarInviteMethod::Request),
        );
        let update = request(1, &update_blob);
        let admission = admit_calendar_invite(&vault, actor_ref, &update, NOW).expect("update");
        assert_eq!(
            admission.state_change(),
            CalendarInviteStateChange::BumpSequence { from: 0 }
        );
        commit(&vault, actor_ref, &update);

        let live = super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports");
        assert_eq!(live.len(), 1, "one live passport per (system x UID)");
        assert_eq!(live[0].1.uid, UID, "the UID is reused, never regenerated");
        assert_eq!(live[0].1.last_sequence, 1);

        // A regression is refused: a same-or-lower SEQUENCE is silently
        // ignored by real clients, so shipping one is an invisible failure.
        let stale = request(0, &blob_ref);
        assert!(matches!(
            admit_calendar_invite(&vault, actor_ref, &stale, NOW),
            Err(CalendarError::InviteRefused { .. })
        ));
    }

    #[test]
    fn calendar_invite_cancel_reuses_uid_and_increments_sequence() {
        let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
        commit(&vault, actor_ref, &request(0, &blob_ref));

        // Cancel needs the recipient already bound to the invite.
        attendee(&vault, 0x56, event_ref, "mailto:guest@example.test");
        let cancel_blob = blob(
            &vault,
            0x57,
            actor_ref,
            &emit(1, CalendarInviteMethod::Cancel),
        );
        let cancel = CalendarInvitePayload {
            method: CalendarInviteMethod::Cancel,
            uid: UID.to_owned(),
            sequence: 1,
            ics_blob_ref: cancel_blob,
            recipient: "guest@example.test".to_owned(),
        };
        let admission = admit_calendar_invite(&vault, actor_ref, &cancel, NOW).expect("cancel");
        assert_eq!(
            admission.state_change(),
            CalendarInviteStateChange::BumpSequence { from: 0 }
        );
        commit(&vault, actor_ref, &cancel);

        let live = super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports");
        assert_eq!(live.len(), 1, "one live passport per (system x UID)");
        assert_eq!(
            live[0].1.uid, UID,
            "a CANCEL rides the SAME UID it invited on"
        );
        assert_eq!(live[0].1.last_sequence, 1);

        // The SEQUENCE the cancel consumed is spent: a later revision claiming
        // it — even a REQUEST with different content — is the regression real
        // clients silently ignore, so it is refused rather than sent.
        assert!(matches!(
            admit_calendar_invite(&vault, actor_ref, &request(1, &blob_ref), NOW),
            Err(CalendarError::InviteRefused { .. })
        ));
    }

    fn commit(vault: &Vault, actor_ref: EntityId, payload: &CalendarInvitePayload) {
        let admission = admit_calendar_invite(vault, actor_ref, payload, NOW).expect("admit");
        commit_admission(vault, &admission, NOW).expect("commit");
    }

    /// The retry lane never re-enters admission, so it cannot mint or bump
    /// anything: it re-sends the FROZEN bytes, and the document it resolves
    /// from them is the same document by reference rather than by re-rendering.
    #[test]
    fn calendar_invite_retry_replays_frozen_payload_without_sequence_bump() {
        let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
        let payload = request(0, &blob_ref);
        commit(&vault, actor_ref, &payload);

        // Shaped like what the dispatch pipeline freezes beside the intent.
        let frozen = serde_json::to_vec(&serde_json::json!({
            "intent": {"channel": CALENDAR_INVITE_CHANNEL, "verb": CALENDAR_INVITE_VERB},
            "calendar_invite": payload,
        }))
        .expect("freeze");

        let first = decode_frozen_calendar_invite(&frozen).expect("decode");
        let retried = decode_frozen_calendar_invite(&frozen).expect("re-decode");
        assert_eq!(first, payload);
        assert_eq!(retried, payload, "a retry decodes the SAME five fields");

        let part = build_calendar_invite_mime_part(&vault, &first).expect("part");
        let retry_part = build_calendar_invite_mime_part(&vault, &retried).expect("retry part");
        assert_eq!(part, retry_part, "byte-identical, not merely equivalent");
        assert_eq!(
            part.ics,
            emit(0, CalendarInviteMethod::Request),
            "the retry resolved the stored document, it did not re-render one"
        );

        // Re-admitting the identical frozen revision is a Replay that writes
        // nothing, so even the path a retry does NOT take moves no state.
        let replay = admit_calendar_invite(&vault, actor_ref, &retried, NOW).expect("replay");
        assert_eq!(replay.state_change(), CalendarInviteStateChange::Replay);
        assert!(!replay.moves_state());
        commit_admission(&vault, &replay, NOW).expect("a replay commit writes nothing");

        let live = super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports");
        assert_eq!(live.len(), 1, "no second UID");
        assert_eq!(live[0].1.uid, UID);
        assert_eq!(live[0].1.last_sequence, 0, "a retry never bumps a SEQUENCE");
    }

    /// No bumped SEQUENCE survives without its frozen intent.
    ///
    /// Production applies the passport head inside the SAME write transaction
    /// that enqueues the ready attempt and writes the connector TASK. This test
    /// injects the failure of that durable commit — the exact window in which an
    /// orphaned bump could otherwise survive — and pins that the passport is
    /// left exactly where the last committed revision put it.
    #[test]
    fn calendar_invite_sequence_and_intent_commit_atomically() {
        let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
        commit(&vault, actor_ref, &request(0, &blob_ref));

        let update_blob = blob(
            &vault,
            0x55,
            actor_ref,
            &emit(1, CalendarInviteMethod::Request),
        );
        let update = request(1, &update_blob);
        let admission =
            admit_calendar_invite(&vault, actor_ref, &update, NOW).expect("update admits");
        assert_eq!(
            admission.state_change(),
            CalendarInviteStateChange::BumpSequence { from: 0 }
        );

        // Stage the head, then fail the transaction that would have carried the
        // attempt and the TASK with it.
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        admission
            .commit_in_txn(&vault, &mut wtxn, NOW)
            .expect("stage the passport head");
        wtxn.abort();

        let live = super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports");
        assert_eq!(live.len(), 1, "the aborted head left no second passport");
        assert_eq!(live[0].1.uid, UID);
        assert_eq!(
            live[0].1.last_sequence, 0,
            "a failed durable commit leaves no orphaned SEQUENCE bump"
        );

        // The SEQUENCE was not consumed either: the same update still admits as
        // the same move and commits cleanly on the next pass.
        let retried =
            admit_calendar_invite(&vault, actor_ref, &update, NOW).expect("re-admits unchanged");
        assert_eq!(
            retried.state_change(),
            CalendarInviteStateChange::BumpSequence { from: 0 }
        );
        commit_admission(&vault, &retried, NOW).expect("commit");
        let live = super::super::passport::live_passports_for_event(&vault, &event_ref)
            .expect("passports");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].1.last_sequence, 1);
    }

    #[test]
    fn calendar_invite_request_denies_without_consent_basis() {
        let (_dir, vault) = open_calendar_vault();
        let actor_ref = actor(&vault);
        let event_ref = event(&vault);
        identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
        let blob_ref = blob(
            &vault,
            0x54,
            actor_ref,
            &emit(0, CalendarInviteMethod::Request),
        );

        let refusal = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
            .expect_err("a cold invite never attaches an .ics");
        let CalendarError::InviteRefused { reason } = refusal else {
            panic!("cold invite must be an invite refusal");
        };
        assert!(
            reason.contains("cold invite"),
            "unexpected reason: {reason}"
        );

        // Nothing was minted behind the refusal: a cold invite leaves no UID.
        assert!(
            super::super::passport::live_passports_for_event(&vault, &event_ref)
                .expect("passports")
                .is_empty()
        );
    }

    /// The first of the two bases that satisfy the no-cold-invite row, and the
    /// only one that can exist before BK-03 (ONE-1814) mints the booking-page
    /// standing grant.
    #[test]
    fn calendar_invite_prior_thread_satisfies_no_cold_invite() {
        let (_dir, vault) = open_calendar_vault();
        let actor_ref = actor(&vault);
        event(&vault);
        identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
        let blob_ref = blob(
            &vault,
            0x54,
            actor_ref,
            &emit(0, CalendarInviteMethod::Request),
        );
        // Cold to begin with: the very same caller bytes are refused while the
        // vault carries no evidence of a thread.
        assert!(admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).is_err());

        // One live `comm.last_touch` on email is a real prior thread.
        prior_thread(&vault, 0x60, "guest@example.test");
        let admission = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
            .expect("prior thread satisfies no-cold-invite");
        assert_eq!(
            admission.hygiene().consent_basis(),
            Some(&CalendarInviteConsentBasis::PriorThread)
        );
        assert_eq!(admission.state_change(), CalendarInviteStateChange::MintUid);
    }

    #[test]
    fn calendar_invite_confirmed_booking_grant_satisfies_no_cold_invite() {
        let (_dir, vault) = open_calendar_vault();
        let actor_ref = actor(&vault);
        event(&vault);
        identity(&vault, 0x53, actor_ref, "email", "me@primary.test");
        let blob_ref = blob(
            &vault,
            0x54,
            actor_ref,
            &emit(0, CalendarInviteMethod::Request),
        );
        assert!(admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW).is_err());

        // CAL-04 VERIFIES the grant; BK-03 mints it. This is the mint door the
        // booking lane will use, driven here only to prove verification works.
        let grant_id = crate::test_util::entity(0x58);
        vault
            .mint_standing_outbound_grant(
                &grant_id,
                &crate::genui::GrantMintIntent {
                    principal_ref: actor_ref.to_hex(),
                    origin_component_id: "one_1786_test".to_owned(),
                    origin_action_id: "confirm_booking".to_owned(),
                    origin_receipt_ref: None,
                    scope: crate::genui::GrantMintIntentScope::Contact {
                        contact_ref: "guest@example.test".to_owned(),
                    },
                },
                NOW,
            )
            .expect("mint booking grant");

        let admission = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
            .expect("a confirmed booking grant satisfies no-cold-invite");
        assert_eq!(
            admission.hygiene().consent_basis(),
            Some(&CalendarInviteConsentBasis::ConfirmedBookingGrant {
                grant_ref: grant_id
            })
        );
    }

    #[test]
    fn calendar_invite_cancel_requires_existing_recipient_binding() {
        let (_dir, vault, actor_ref, event_ref, blob_ref) = admitted_fixture();
        commit(&vault, actor_ref, &request(0, &blob_ref));
        let cancel_blob = blob(
            &vault,
            0x57,
            actor_ref,
            &emit(1, CalendarInviteMethod::Cancel),
        );
        let cancel = CalendarInvitePayload {
            method: CalendarInviteMethod::Cancel,
            uid: UID.to_owned(),
            sequence: 1,
            ics_blob_ref: cancel_blob,
            recipient: "stranger@example.test".to_owned(),
        };
        let refusal = admit_calendar_invite(&vault, actor_ref, &cancel, NOW)
            .expect_err("cancel to an unbound recipient is a cold ping");
        let CalendarError::InviteRefused { reason } = refusal else {
            panic!("unbound cancel must be an invite refusal");
        };
        assert!(
            reason.contains("already bound"),
            "unexpected reason: {reason}"
        );

        attendee(&vault, 0x59, event_ref, "stranger@example.test");
        // The binding alone is not enough for a stranger: consent still rules.
        prior_thread(&vault, 0x61, "stranger@example.test");
        admit_calendar_invite(&vault, actor_ref, &cancel, NOW)
            .expect("a bound recipient may be cancelled");
    }

    #[test]
    fn calendar_invite_denies_non_primary_sender_domain() {
        let (_dir, vault, actor_ref, _event_ref, blob_ref) = admitted_fixture();
        // A calendar-channel identity on a different domain now carries the
        // send: sequencer-class infrastructure, not the primary calendar domain.
        identity(
            &vault,
            0x5A,
            actor_ref,
            CALENDAR_INVITE_CHANNEL,
            "bulk@sequencer.test",
        );
        let refusal = admit_calendar_invite(&vault, actor_ref, &request(0, &blob_ref), NOW)
            .expect_err("an off-domain sender never carries a real invite");
        let CalendarError::InviteRefused { reason } = refusal else {
            panic!("off-domain sender must be an invite refusal");
        };
        assert!(
            reason.contains("primary calendar domain"),
            "unexpected reason: {reason}"
        );
    }

    #[test]
    fn calendar_invite_ignores_caller_hygiene_bools_and_rehydrates_from_vault() {
        let (_dir, vault, actor_ref, _event_ref, blob_ref) = admitted_fixture();
        let payload = request(0, &blob_ref);
        let from_vault = admit_calendar_invite(&vault, actor_ref, &payload, NOW)
            .expect("admits on real evidence");

        // There is no API by which a caller supplies hygiene: the only public
        // input is the five-field payload, and the context it produces is a
        // pure function of stored evidence. Removing the evidence flips the
        // verdict even though the caller's bytes are byte-identical.
        assert_eq!(
            from_vault.hygiene().consent_basis(),
            Some(&CalendarInviteConsentBasis::PriorThread)
        );
        assert_eq!(from_vault.hygiene().sender_domain(), Some("primary.test"));
        assert_eq!(from_vault.hygiene().primary_domain(), Some("primary.test"));

        let (_dir2, bare) = open_calendar_vault();
        let bare_actor = actor(&bare);
        event(&bare);
        identity(&bare, 0x53, bare_actor, "email", "me@primary.test");
        let bare_blob = blob(
            &bare,
            0x54,
            bare_actor,
            &emit(0, CalendarInviteMethod::Request),
        );
        assert!(
            admit_calendar_invite(&bare, bare_actor, &request(0, &bare_blob), NOW).is_err(),
            "the same caller bytes must refuse when the vault carries no consent"
        );
    }

    #[test]
    fn connector_send_builds_text_calendar_method_part() {
        let (_dir, vault, actor_ref, _event_ref, blob_ref) = admitted_fixture();
        let payload = request(0, &blob_ref);
        let part = build_calendar_invite_mime_part(&vault, &payload).expect("mime part");
        assert_eq!(
            part.content_type,
            "text/calendar; method=REQUEST; charset=utf-8"
        );
        assert_eq!(part.filename, CALENDAR_INVITE_PART_FILENAME);
        let text = String::from_utf8(part.ics.clone()).expect("utf-8");
        assert!(text.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(text.contains("METHOD:REQUEST\r\n"));
        assert!(text.contains(&format!("UID:{UID}\r\n")));

        let cancel_blob = blob(
            &vault,
            0x5B,
            actor_ref,
            &emit(1, CalendarInviteMethod::Cancel),
        );
        let cancel = CalendarInvitePayload {
            method: CalendarInviteMethod::Cancel,
            uid: UID.to_owned(),
            sequence: 1,
            ics_blob_ref: cancel_blob,
            recipient: "guest@example.test".to_owned(),
        };
        let part = build_calendar_invite_mime_part(&vault, &cancel).expect("cancel part");
        assert_eq!(
            part.content_type,
            "text/calendar; method=CANCEL; charset=utf-8"
        );
    }

    #[test]
    fn tool_descriptor_keeps_the_invite_effectful_and_idempotent() {
        assert_eq!(CALENDAR_INVITE_TOOL_DESCRIPTOR.read_only_hint, Some(false));
        assert_eq!(
            CALENDAR_INVITE_TOOL_DESCRIPTOR.idempotency_supported_hint,
            Some(true)
        );
    }
}
