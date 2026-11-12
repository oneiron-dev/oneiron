//! Moved from `crates/oneiron/src/mail_pack/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::source::CalendarDetailSetting;
use crate::mail_pack::source::MailCopySetting;
use crate::mail_pack::source::MailProvider;
use crate::mail_pack::source::MailProviderDeleteSetting;
use crate::mail_pack::source::MailSourceKind;
use crate::mail_pack::source::MailSourceStatus;
use crate::mail_pack::source::MailSourceView;
use crate::source_audience;
use crate::source_audience::SourceAudienceEventView;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// `vault.mail.sources.connect`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceConnectRequest {
    pub provider: MailProvider,
    pub kind: MailSourceKind,
    /// The mailbox or group address, or the calendar's provider id.
    pub address: String,
    /// The provider's stable account id (for Google, the account's `sub`;
    /// for Microsoft 365, the tenant and object id). Reconnecting with the
    /// same account and address resumes the same source.
    pub provider_account: String,
    /// The custody record the credential is stored under, through the owner
    /// secrets form. Never the credential itself. The Owner stored it for
    /// this source's person (its bindings' `actor:<PERSON>` scope, or no
    /// holder scope for the Owner's own), or for group addresses (the
    /// `group-address` scope).
    pub custody_ref: String,
    /// A group address only: the PERSONs who read it, 32-hex. A personal
    /// mailbox and a calendar read to the person who connects them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// An Owner or an Admin only: the PERSON, 32-hex, whose personal
    /// mailbox or calendar this is, connected for them with the credential
    /// stored for them. Absent, the source is the caller's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_person: Option<String>,
    /// The delegated channel identity the source reads through, 32-hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_identity_ref: Option<String>,
    /// "Keep a copy of my mail"; all mail when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<MailCopySetting>,
    /// "When I delete at the provider"; keep in memory when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_provider_delete: Option<MailProviderDeleteSetting>,
    /// A calendar only: busy and free only when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_details: Option<CalendarDetailSetting>,
}

/// What a connect did: the source, and whether it resumed one connected
/// before (the same provider, kind, account and address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceConnectReceipt {
    pub source: MailSourceView,
    pub resumed: bool,
}

/// One source, by its ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceRef {
    /// 32-hex.
    pub source_ref: String,
}

/// `vault.mail.sources.settings.set`'s input: each absent setting stays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceSettingsRequest {
    /// 32-hex.
    pub source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<MailCopySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_provider_delete: Option<MailProviderDeleteSetting>,
    /// A calendar only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_details: Option<CalendarDetailSetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MailSourceStatus>,
    /// An IMAP mailbox only: every other address its owner confirms the
    /// mailbox owns, at most 100, each a bare address (fix list row 20400).
    /// It replaces the list kept; an empty list clears it. A reply never
    /// goes to any of them. A Gmail or Microsoft 365 mailbox's own
    /// addresses come from its provider at each sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_addresses: Option<Vec<String>>,
}

/// `vault.mail.sources.members.set`'s input: a group address's readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceMembersRequest {
    /// 32-hex.
    pub source_ref: String,
    /// The PERSONs who read the group address from now on, 32-hex.
    pub members: Vec<String>,
}
