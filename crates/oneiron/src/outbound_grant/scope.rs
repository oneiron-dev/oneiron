//! Scope dials, scope vocabularies, mint intents, and scope validation.

use super::codec::{
    canonical_non_empty_str, canonical_scoped_server, invalid_grant, is_mcp_channel,
    is_send_class_verb, non_empty_str, non_empty_string, refs_match,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::genui::GrantMintIntentScope;
use crate::outbound_consent::{DataClass, ScopedMcpGrantRef};

// Append-only: `page_ref` is the tenth key and sits inside the optional range
// `decode_scope` validates, so every row written before it decodes unchanged
// and no existing scope's encoded bytes move.
pub(super) const SCOPE_KEYS: [&str; 10] = [
    "kind",
    "contact_ref",
    "verb_class",
    "channel",
    "brief_ref",
    "server",
    "tool",
    "data_class_ceiling",
    "endpoint_allowlist",
    "page_ref",
];

pub(super) const SCOPE_KIND_CONTACT: &str = "contact";

pub(super) const SCOPE_KIND_VERB_CLASS: &str = "verb_class";

pub(super) const SCOPE_KIND_CHANNEL: &str = "channel";

pub(super) const SCOPE_KIND_BRIEF_VERB_CLASS: &str = "brief_verb_class";

pub(super) const SCOPE_KIND_SCOPED_MCP: &str = "scoped_mcp";

/// On-disk token for the booking-page invite scope. Byte-identical to the
/// receipt vocabulary in `receipt/grant.rs`, so the audit surface and the codec
/// cannot drift.
pub(super) const SCOPE_KIND_BOOKING_PAGE_INVITES: &str = "booking_page_invites";

/// OF-336 origin component recorded on a booking-page invite grant. The mint is
/// the page-publish action, not an ask escalator, so the provenance names it.
pub(super) const BOOKING_PAGE_INVITE_ORIGIN_COMPONENT_ID: &str = "booking.page_publish";

/// OF-336 origin action recorded on a booking-page invite grant.
pub(super) const BOOKING_PAGE_INVITE_ORIGIN_ACTION_ID: &str = "publish_booking_page";

pub(super) const SEND_VERB_CLASS: &str = "send";

/// Scope dial selected by the owner when minting a standing outbound grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandingOutboundGrantScope {
    /// Always allow matching sends to one contact/counterparty.
    Contact { contact_ref: String },
    /// Always allow matching sends for one outbound verb class.
    VerbClass { verb_class: String },
    /// Always allow matching sends on one channel.
    Channel { channel: String },
    /// Bundle approval for one brief and verb class.
    BriefVerbClass {
        brief_ref: String,
        verb_class: String,
    },
    /// Payload-aware standing authority for one external tool.
    ScopedMcp {
        server: String,
        tool: String,
        data_class_ceiling: DataClass,
        endpoint_allowlist: Vec<String>,
    },
    /// Bounded booking-page authority: `calendar.invite` for bookings that a
    /// confirm persisted on exactly this page. The recipient binding is NOT in
    /// this scope — the consent door resolves it from booking claims — so a
    /// live grant never widens past the page it was minted for.
    BookingPageInvites { page_ref: EntityId },
    /// Storage-aware authority; only the atomic envelope door may use it.
    ChannelIdentityEnvelope {
        identity_ref: EntityId,
        envelope_ref: EntityId,
        verb_class: String,
    },
}

/// Authenticated grant-time input for one payload-aware external tool scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopedMcpGrantMintIntent {
    pub principal_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    pub origin_receipt_ref: Option<String>,
    pub server: String,
    pub tool: String,
    pub data_class_ceiling: DataClass,
    pub endpoint_allowlist: Vec<String>,
}

/// Authenticated grant-time input for one booking page's invite scope.
///
/// Deliberately two fields: the page the publish action named and the
/// principal that published it. Nothing about a booker, a recipient, or a
/// verb travels here — the scope authorizes exactly `calendar.invite`, and the
/// recipient binding is resolved from persisted booking claims at the door.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BookingPageInviteGrantMintIntent {
    pub page_ref: EntityId,
    pub publisher_principal: EntityId,
}

impl StandingOutboundGrantScope {
    /// Builds a storage scope from the RCPT-3 grant mint intent scope.
    pub fn from_grant_mint_scope(scope: &GrantMintIntentScope) -> Result<Self> {
        match scope {
            GrantMintIntentScope::JustOnce { .. } => Err(invalid_grant()),
            GrantMintIntentScope::Contact { contact_ref } => Ok(Self::Contact {
                contact_ref: non_empty_string(contact_ref)?,
            }),
            GrantMintIntentScope::VerbClass { verb_class } => Ok(Self::VerbClass {
                verb_class: non_empty_string(verb_class)?,
            }),
            GrantMintIntentScope::Channel { channel } => Ok(Self::Channel {
                channel: non_empty_string(channel)?,
            }),
            GrantMintIntentScope::BundleExactSends { .. } => Err(invalid_grant()),
            GrantMintIntentScope::BriefVerbClass {
                brief_ref,
                verb_class,
            } => Ok(Self::BriefVerbClass {
                brief_ref: non_empty_string(brief_ref)?,
                verb_class: non_empty_string(verb_class)?,
            }),
            // A calendar disclosure grant authorizes a READ at a rung. It must
            // never become a standing permission to send.
            GrantMintIntentScope::Calendar { .. } => Err(invalid_grant()),
        }
    }

    /// Stable dial label for grants-lens rows.
    #[must_use]
    pub const fn dial_label(&self) -> &'static str {
        match self {
            Self::Contact { .. } => "always_this_contact",
            Self::VerbClass { .. } => "always_this_verb_class",
            Self::Channel { .. } => "always_this_channel",
            Self::BriefVerbClass { .. } => "brief_verb_class",
            Self::ScopedMcp { .. } => "scoped_mcp",
            Self::BookingPageInvites { .. } => "booking_page_invites",
            Self::ChannelIdentityEnvelope { .. } => "channel_identity_envelope",
        }
    }

    /// Returns the payload-aware axes when this is a scoped external-tool
    /// grant. Blind grant kinds intentionally return `None`.
    #[must_use]
    pub fn scoped_mcp_grant(&self) -> Option<ScopedMcpGrantRef<'_>> {
        match self {
            Self::ScopedMcp {
                server,
                tool,
                data_class_ceiling,
                endpoint_allowlist,
            } => Some(ScopedMcpGrantRef {
                server,
                tool,
                data_class_ceiling: *data_class_ceiling,
                endpoint_allowlist,
            }),
            _ => None,
        }
    }

    /// Returns whether this grant scope covers a candidate outbound effect.
    #[must_use]
    pub fn matches_effect(
        &self,
        verb: &str,
        channel: &str,
        counterparty: Option<&str>,
        brief_ref: Option<&str>,
    ) -> bool {
        // MCP calls require the payload-aware path. No argument-blind dial is
        // allowed to authorize one, even if its channel string matches.
        if is_mcp_channel(channel) {
            return false;
        }
        match self {
            Self::Contact { contact_ref } => {
                counterparty.is_some_and(|counterparty| refs_match(contact_ref, counterparty))
            }
            Self::VerbClass { verb_class } => verb_class.trim() == verb.trim(),
            Self::Channel {
                channel: grant_channel,
            } => grant_channel.trim() == channel.trim() && is_send_class_verb(verb),
            Self::BriefVerbClass {
                brief_ref: grant_brief,
                verb_class,
            } => {
                verb_class.trim() == verb.trim()
                    && brief_ref.is_some_and(|brief_ref| refs_match(grant_brief, brief_ref))
            }
            Self::ScopedMcp { .. } | Self::ChannelIdentityEnvelope { .. } => false,
            // Exactly one verb. The page and the recipient are NOT decided
            // here: the calendar consent door resolves both from persisted
            // booking claims, so a page grant can never cover a second verb
            // even when the channel string matches.
            Self::BookingPageInvites { .. } => verb.trim() == crate::calendar::CALENDAR_INVITE_VERB,
        }
    }
}

pub(super) fn validate_scope(scope: &StandingOutboundGrantScope) -> Result<()> {
    match scope {
        StandingOutboundGrantScope::Contact { contact_ref } => non_empty_str(contact_ref)?,
        StandingOutboundGrantScope::VerbClass { verb_class } => non_empty_str(verb_class)?,
        StandingOutboundGrantScope::Channel { channel } => non_empty_str(channel)?,
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            non_empty_str(brief_ref)?;
            non_empty_str(verb_class)?;
        }
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            endpoint_allowlist,
        } => {
            // Stored-form == authority-form: the scoped server must ALREADY be
            // the safe canonical segment the capability-key producer and the
            // charter compiler use, or this grant would govern under one
            // spelling and be enforced under another (ONE-1885).
            if canonical_scoped_server(server)? != *server {
                return Err(invalid_grant());
            }
            canonical_non_empty_str(tool)?;
            if !data_class_ceiling.is_grantable() || endpoint_allowlist.is_empty() {
                return Err(invalid_grant());
            }
            for endpoint in endpoint_allowlist {
                canonical_non_empty_str(endpoint)?;
            }
        }
        // An `EntityId` is already the validated form of a page reference;
        // there is no string spelling to canonicalize.
        StandingOutboundGrantScope::BookingPageInvites { .. } => {}
        StandingOutboundGrantScope::ChannelIdentityEnvelope { verb_class, .. } => {
            if !matches!(verb_class.as_str(), "mail.draft" | "mail.send") {
                return Err(invalid_grant());
            }
        }
    }
    Ok(())
}
