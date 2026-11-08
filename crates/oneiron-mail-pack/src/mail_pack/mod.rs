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
//!
//! Lifted half (core split, `oneiron-mail-pack`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::mail_pack::*;

#[doc(hidden)]
pub mod importer;
#[doc(hidden)]
pub mod local_sync;
#[doc(hidden)]
pub mod pack;

pub use importer::MailPackImporterVaultExt;
pub use local_sync::MailPackLocalSyncVaultExt;
pub use pack::MailPackPackVaultExt;
