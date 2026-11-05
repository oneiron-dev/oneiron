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
//! provider" setting (keep in memory, the default; forget too). Provider
//! adapters land per provider row, Google Workspace first.

mod compliance;
mod doors;
mod pack;
mod share;
mod source;

pub use crate::source_audience::{SourceAudienceEventView, SourceAudienceOp};
pub use compliance::{
    MailComplianceEventKind, MailComplianceEventView, MailComplianceSetRequest,
    MailComplianceSettingView,
};
pub(crate) use compliance::erase_compliance_actor_in_txn;
pub(crate) use doors::erase_source_actor_in_txn;
pub use doors::{
    MailSourceConnectReceipt, MailSourceConnectRequest, MailSourceMembersRequest, MailSourceRef,
    MailSourceSettingsRequest,
};
pub use pack::{
    MAIL_CALENDAR_PACK_NAME, install_mail_calendar_pack_embedded, mail_calendar_pack_files,
};
pub use share::{MailThreadShareReceipt, MailThreadShareRequest};
pub use source::{
    CalendarDetailSetting, MailCopySetting, MailProvider, MailProviderDeleteSetting,
    MailSourceKind, MailSourceStatus, MailSourceView,
};
