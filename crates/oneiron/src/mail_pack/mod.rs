//! The Mail & Calendar pack, engine half (FIX 12559, 12560; owner MAIL-SHARE,
//! MAIL-DELETE, MAIL-PROVIDERS and MAIL-VIEW = A, 2026-11-03, ledger
//! engine-20261103-mail-four-calls; ARCH-0063 #mail-pack, ARCH-0027
//! #mail-pack-import, ARCH-0060 #calendar-disclosure).
//!
//! Mail and calendars connect into the one shared vault as **sources**
//! ([`source`]), each installed by the pack ([`pack`]): a vault without the
//! pack connects none. A source's rows are born under its source audience
//! ([`crate::source_audience`]):
//!
//! - a **personal mailbox** reads to the person who connected it, and to
//!   their own agents, alone; the facts learned from it stay theirs;
//! - a **group address** is connected once, by an Owner or an Admin, and
//!   reads to the members named;
//! - a **calendar** reads busy and free to the vault, its details to its
//!   owner until the owner shares it in detail;
//! - a **thread** reaches anyone else only by an explicit share ([`share`]).
//!
//! The org's compliance search ([`compliance`]) is the one reader across
//! mailboxes: an admin setting, off by default, every use logged before it
//! answers.
//!
//! Each source keeps the owner's "Keep a copy of my mail" setting (all mail,
//! the default; recent months; search only) and "When I delete at the
//! provider" setting (keep in memory, the default; forget too). The importer
//! ([`importer`]) copies a mailbox through a host's provider wire ([`wire`]),
//! newest first, headers before bodies, live through the provider's change
//! feed; each message lands as imported evidence bound to its thread's
//! audience ([`landing`]), and a provider delete applies the source's setting
//! ([`provider_delete`]). Provider wires land per provider row, Google
//! Workspace first.

mod compliance;
mod doors;
mod importer;
mod inbox;
mod landing;
mod pack;
mod provider_delete;
mod share;
mod source;
mod state;
mod wire;

pub use crate::source_audience::{SourceAudienceEventView, SourceAudienceOp};
pub(crate) use compliance::erase_compliance_actor_in_txn;
pub use compliance::{
    MailComplianceEventKind, MailComplianceEventView, MailComplianceHit, MailComplianceSearchReply,
    MailComplianceSearchRequest, MailComplianceSetRequest, MailComplianceSettingView,
};
pub(crate) use doors::erase_source_actor_in_txn;
pub use doors::{
    MailSourceConnectReceipt, MailSourceConnectRequest, MailSourceMembersRequest, MailSourceRef,
    MailSourceSettingsRequest,
};
pub use importer::{MailSyncBudget, MailSyncReport};
pub use inbox::{
    MailInboxItem, MailInboxPage, MailInboxRequest, MailThreadRequest, MailThreadView,
};
pub use pack::{
    MAIL_CALENDAR_PACK_NAME, install_mail_calendar_pack_embedded, mail_calendar_pack_files,
};
pub use share::{MailThreadShareReceipt, MailThreadShareRequest};
pub use source::{
    CalendarDetailSetting, MailCopySetting, MailProvider, MailProviderDeleteSetting,
    MailSourceKind, MailSourceStatus, MailSourceView,
};
pub(crate) use state::erase_occurrence_rows_in_txn;
pub use state::{MailPresence, MailStage, MailSyncStatusView};
pub use wire::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProviderWire, MailSyncSource,
};
