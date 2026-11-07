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
//! ([`provider_delete`]). Provider wires land per provider row: Gmail for
//! Google Workspace and Google ([`gmail`]), Microsoft Graph for Microsoft 365
//! ([`microsoft365`]), and IMAP4rev1 over TLS for any other mailbox
//! ([`imap`], on the engine's own client [`imap_client`]). Calendar sources land through the calendar engine's
//! connector admission, each EVENT bound to its source at birth
//! ([`calendar`]), read from Google Calendar ([`google_calendar`]), Microsoft 365
//! ([`microsoft365_calendar`]) or an ICS subscription ([`ics_calendar`]).
//! The owner runs a step on this device through [`local_sync`], and imports
//! an mbox file or a Google Takeout export through [`mbox_import`], read by
//! the engine's own MIME reader ([`mime`]).

mod attachments;
mod calendar;
mod compliance;
mod credential;
mod doors;
mod gmail;
mod google_calendar;
mod header_retire;
mod ics_calendar;
mod imap;
mod imap_client;
mod importer;
mod inbox;
mod landing;
mod local_sync;
mod mbox;
mod mbox_import;
mod microsoft365;
mod microsoft365_calendar;
mod mime;
mod pack;
mod provider_delete;
mod reply;
mod reply_mime;
mod reply_send;
mod rest;
mod share;
mod smtp_client;
mod source;
mod state;
mod tls_stream;
mod wire;

pub use crate::source_audience::{SourceAudienceEventView, SourceAudienceOp};
pub(crate) use attachments::collect_after_delete;
pub use attachments::{MailAttachmentOpenRequest, MailAttachmentState, MailAttachmentView};
pub(crate) use calendar::{
    bind_calendar_source_row_in_txn, calendar_source_occupancy, calendar_source_of_system_in,
    merge_busy,
};
pub use calendar::{MailCalendarFeed, MailCalendarPull, MailCalendarRead, MailCalendarWire};
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
pub use gmail::HttpGmailMailWire;
pub use google_calendar::{GOOGLE_CALENDAR_CONNECTOR_EFFECTOR, HttpGoogleCalendarWire};
pub use ics_calendar::{HttpIcsCalendarWire, ICS_CALENDAR_CONNECTOR_EFFECTOR};
pub use imap::{IMAP_CONNECTOR_EFFECTOR, ImapMailWire};
pub use importer::{MailSyncBudget, MailSyncReport};
pub use inbox::{
    MailInboxItem, MailInboxPage, MailInboxRequest, MailThreadRequest, MailThreadView,
};
pub use local_sync::MailSourceSyncRequest;
pub use mbox_import::{MailMboxImportReport, MailMboxImportRequest};
pub use microsoft365::{HttpGraphMailWire, MICROSOFT365_CONNECTOR_EFFECTOR};
pub use microsoft365_calendar::{
    HttpGraphCalendarWire, MICROSOFT365_CALENDAR_CONNECTOR_EFFECTOR,
};
pub use pack::{
    MAIL_CALENDAR_PACK_NAME, install_mail_calendar_pack_embedded, mail_calendar_pack_files,
};
pub(crate) use reply::{approved_source_reply_in_txn, erase_reply_drafter_in_txn};
pub use reply::{
    MailReplyApproveRequest, MailReplyDraftPage, MailReplyDraftRef, MailReplyDraftRequest,
    MailReplyDraftState, MailReplyDraftView, MailReplyDraftsRequest,
};
pub use reply_send::SMTP_SUBMISSION_CONNECTOR_EFFECTOR;
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
