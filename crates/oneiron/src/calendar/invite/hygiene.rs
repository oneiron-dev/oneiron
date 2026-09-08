//! Vault-hydrated consent evidence and sending-identity reads.

use super::CalendarError;
use super::admission::{ingest_reason, refused};
use super::claims::{PREDICATE_CALENDAR_ATTENDEE, decode_attendee_value};
use super::payload::{CALENDAR_INVITE_CHANNEL, CalendarInviteMethod, CalendarInvitePayload};
use crate::Vault;
use crate::channel_identity::{ChannelIdentity, ChannelIdentityShape};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::outbound_grant::{StandingOutboundGrantScope, StandingOutboundGrantStatus};
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_OUTBOUND_GRANT};

/// Channel classes an iMIP invite counts as prior contact on.
///
/// The invite rides email, and the calendar connector is its own class; a live
/// touch on either is a real prior thread with this recipient.
const PRIOR_THREAD_CHANNEL_CLASSES: [&str; 2] = ["email", CALENDAR_INVITE_CHANNEL];

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

/// Builds the hygiene context from live vault state and nothing else.
///
/// Every fact below is a read of stored evidence: `comm.last_touch` claims,
/// ACTIVE standing outbound grants, `calendar.attendee` claims on the EVENT,
/// and OF-347 ChannelIdentity rows. No argument here is a caller assertion —
/// the payload contributes only the recipient and the method.
pub(super) fn hydrate_calendar_invite_hygiene(
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
            // BK-03's booking-page grant. The scope names a PAGE, never a
            // recipient, so a bare `true` here would turn one page grant into
            // a licence to invite anyone. The booking layer owns the binding
            // and answers only from persisted claims: a CONFIRMED booking on
            // exactly this page whose recorded booker identity IS this
            // recipient. Any resolution failure refuses.
            StandingOutboundGrantScope::BookingPageInvites { page_ref } => {
                crate::booking::invite_grant::booking_page_grant_covers_recipient(
                    vault, page_ref, recipient,
                )
                .map_err(|err| ingest_reason(err.to_string()))?
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
    if crate::booking::lifecycle::booking_invite_identity(vault, event_ref)
        .map_err(|error| refused(error.to_string()))?
        .is_some_and(|(_, bound)| attendee_matches(&bound, recipient))
    {
        return Ok(true);
    }
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
pub(super) fn sending_identity(
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
pub(super) fn primary_calendar_domain(
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
        if !identity.may_send()
            || crate::counterparty_contact::normalize_channel_class(&identity.channel) != wanted
            || identity.binding.actor_ref() != Some(actor)
        {
            continue;
        }
        if found.is_some() {
            // Do not turn ambiguity into permission to fall back to email.
            return Err(refused("multiple sending identities on this channel"));
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
