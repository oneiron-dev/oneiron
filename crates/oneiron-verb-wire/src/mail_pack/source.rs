//! Moved from `crates/oneiron/src/mail_pack/source.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Where a source lives (MAIL-PROVIDERS = A, staged in this order).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MailProvider {
    /// A Google Workspace mailbox or calendar (Antevon first).
    GoogleWorkspace,
    /// A Google account outside Workspace.
    Google,
    Microsoft365,
    Imap,
    Caldav,
    /// An ICS file or subscription.
    Ics,
}

impl MailProvider {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleWorkspace => "google_workspace",
            Self::Google => "google",
            Self::Microsoft365 => "microsoft365",
            Self::Imap => "imap",
            Self::Caldav => "caldav",
            Self::Ics => "ics",
        }
    }

    /// Whether this provider carries mail.
    #[must_use]
    pub const fn carries_mail(self) -> bool {
        !matches!(self, Self::Caldav | Self::Ics)
    }

    /// Whether this provider carries calendars.
    #[must_use]
    pub const fn carries_calendars(self) -> bool {
        !matches!(self, Self::Imap)
    }
}

/// What a source is, and so who reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailSourceKind {
    /// One person's own mailbox: it reads to them alone.
    PersonalMailbox,
    /// A group address (`hello@`, `legal@`): connected once as the group,
    /// read by its members.
    GroupAddress,
    /// One person's calendar: busy and free to the vault, details to its
    /// owner unless shared.
    Calendar,
}

impl MailSourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersonalMailbox => "personal_mailbox",
            Self::GroupAddress => "group_address",
            Self::Calendar => "calendar",
        }
    }

    /// Whether this kind is a mailbox.
    #[must_use]
    pub const fn is_mailbox(self) -> bool {
        !matches!(self, Self::Calendar)
    }
}

/// "Keep a copy of my mail" (MAIL COPY SETTING = A, 2026-10-19).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MailCopySetting {
    /// Every message, newest first, filling in behind the live inbox: the
    /// default, and what the owner prefers.
    #[default]
    All,
    /// The messages of the recent months only.
    RecentMonths { months: u16 },
    /// Only what a search fetched, and the headers of what it found.
    SearchOnly,
}

/// "When I delete at the provider" (MAIL-DELETE = A, 2026-11-03).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MailProviderDeleteSetting {
    /// The message leaves the live inbox and stays as a labelled
    /// source-deleted copy; the claims drawn from it are checked again.
    #[default]
    KeepInMemory,
    /// The vault forgets it too.
    ForgetToo,
}

/// How much of a calendar the vault reads (calendar disclosure ruling,
/// 2026-11-03).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CalendarDetailSetting {
    /// Busy and free to the vault; the events' details to their owner.
    #[default]
    BusyFreeOnly,
    /// The owner shared the calendar in detail: its events read to the vault.
    Shared,
}

/// Whether a source syncs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MailSourceStatus {
    #[default]
    Active,
    /// Kept, but not syncing until its owner resumes it.
    Paused,
    /// Its connection was withdrawn; its rows stay under its audience.
    Disconnected,
}

/// One connected source, as its readers see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceView {
    /// 32-hex.
    pub source_ref: String,
    pub provider: MailProvider,
    pub kind: MailSourceKind,
    /// The address or calendar id. Absent for a calendar the reader sees only
    /// as busy and free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Every other address the mailbox owns, canonical: proven by its
    /// provider, or for an IMAP mailbox confirmed by its owner. A reply
    /// never goes to any of them. Shown where `address` is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub own_addresses: Vec<String>,
    /// The owner PERSON of a personal mailbox or a calendar, 32-hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    /// Whether the reader reads this source's rows (its owner, a group
    /// member, or a calendar shared in detail).
    pub reads: bool,
    /// The group's members, 32-hex, shown to its readers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    pub copy: MailCopySetting,
    pub on_provider_delete: MailProviderDeleteSetting,
    pub calendar_details: CalendarDetailSetting,
    pub status: MailSourceStatus,
    pub connected_at: u64,
    pub updated_at: u64,
}
