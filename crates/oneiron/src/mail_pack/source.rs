//! One connected mail or calendar source: what it is, whose it is, what it
//! keeps. Credentials stay in custody; a source names its custody record.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::side_table::{self, Named, SideTable};

/// Every connected source, by its id.
pub(super) const SOURCES: SideTable<EntityId, MailSourceRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_SOURCE);
/// A source's id by the BLAKE3 of its provider, kind, provider account and
/// address ([`source_identity_key`]): reconnecting the same mailbox resumes
/// the same source and the same rows.
pub(super) const SOURCE_INDEX: SideTable<[u8; 32], EntityId, Named> =
    SideTable::new(&side_table::MAIL_PACK_SOURCE_INDEX);

/// The longest address, account id or custody name a source names.
pub(super) const MAX_SOURCE_FIELD_BYTES: usize = 320;

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

/// One stored source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MailSourceRow {
    pub(super) provider: MailProvider,
    pub(super) kind: MailSourceKind,
    /// The mailbox or group address, or the calendar's provider id, as given.
    pub(super) address: String,
    /// The provider's stable account (or tenant and principal) id.
    pub(super) provider_account: String,
    /// The custody record the credential is stored under. Never its value.
    pub(super) custody_ref: String,
    /// The delegated channel identity this source reads through, if any.
    pub(super) channel_identity: Option<EntityId>,
    /// The PERSON who owns a personal mailbox or a calendar; `None` for a
    /// group address, or once that person was erased.
    pub(super) owner: Option<EntityId>,
    /// The source policy its rows are born under
    /// ([`crate::source_audience`]).
    pub(super) audience: EntityId,
    pub(super) copy: MailCopySetting,
    pub(super) on_provider_delete: MailProviderDeleteSetting,
    pub(super) calendar_details: CalendarDetailSetting,
    pub(super) status: MailSourceStatus,
    /// Who connected it; `None` once that actor was erased.
    pub(super) connected_by: Option<EntityId>,
    pub(super) connected_at: u64,
    pub(super) updated_at: u64,
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
    /// Whether the vault's "Owners can export members' mail" is on now (fix
    /// list row 15416): on, a whole-vault export by an Owner of a vault a
    /// person owns carries members' personal mailboxes, each person told.
    /// The vault's setting, read live; no source keeps a copy of it.
    pub owners_export_member_mail: bool,
}

/// The identity key one source is found by again: its provider, kind,
/// provider account and address, the address case-folded.
pub(super) fn source_identity_key(
    provider: MailProvider,
    kind: MailSourceKind,
    provider_account: &str,
    address: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mail_calendar.source.v1\0");
    hasher.update(provider.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(provider_account.as_bytes());
    hasher.update(b"\0");
    hasher.update(address.to_lowercase().as_bytes());
    *hasher.finalize().as_bytes()
}

/// A source field as a connect takes it: nonempty, bounded, no controls.
pub(super) fn valid_field(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_SOURCE_FIELD_BYTES
        && !value.chars().any(char::is_control)
}
