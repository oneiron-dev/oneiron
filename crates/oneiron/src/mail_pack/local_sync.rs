//! One import step of a mail or calendar source through this host's wire
//! for its provider: Gmail for Google Workspace and Google mailboxes,
//! Microsoft Graph for Microsoft 365 mailboxes and calendars, IMAP for IMAP
//! mailboxes, Google Calendar for Google calendars, HTTPS for ICS
//! subscriptions. The owner runs
//! it through `vault.mail.sources.sync`, on this device as its embedded owner
//! or on a served vault under the owner's proof; a server host runs it for
//! every due source as the vault's local owner.

use super::caldav_calendar::HttpCalDavCalendarWire;
use super::gmail::{HttpGmailMailWire, reads_google_mail};
use super::google_calendar::HttpGoogleCalendarWire;
use super::ics_calendar::HttpIcsCalendarWire;
use super::imap::ImapMailWire;
use super::importer::{MailSyncBudget, MailSyncReport};
use super::microsoft365::HttpGraphMailWire;
use super::microsoft365_calendar::HttpGraphCalendarWire;
use super::push::MailWatchAct;
use super::source::MailProvider;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::mail_pack::local_sync::MailSourceSyncRequest;

/// The calendar pages one step reads.
const CALENDAR_PAGES_PER_STEP: u32 = 4;

impl Vault {
    /// One bounded import step of the source `source` through this host's
    /// wire for its provider (FIX 12559 rows 1b, 3 and 5), under the vault
    /// owner's write authority. A mailbox: new changes since the source's
    /// anchor, the next newest-first pages under its copy setting, then
    /// waiting bodies. A calendar: the next pages of its listing or its
    /// changes, each event bound to the source at birth. The rows land bound
    /// to the source's audience; the owner's authority lands them and reads
    /// none. It reads the provider over blocking HTTP: call it off any async
    /// runtime.
    ///
    /// # Errors
    ///
    /// No such source, a provider with no wire here yet, or the step's own.
    pub fn mail_source_sync_step(
        &self,
        owner: &AuthenticatedOwner,
        source: EntityId,
        budget: MailSyncBudget,
    ) -> MemoryResult<MailSyncReport> {
        if let Some(calendar) = self.mail_calendar_source(source)? {
            if reads_google_mail(calendar.provider) {
                let wire = HttpGoogleCalendarWire::new(self)?;
                return self.mail_calendar_sync_step(source, &wire, CALENDAR_PAGES_PER_STEP);
            }
            if calendar.provider == MailProvider::Microsoft365 {
                let wire = HttpGraphCalendarWire::new(self)?;
                return self.mail_calendar_sync_step(source, &wire, CALENDAR_PAGES_PER_STEP);
            }
            if calendar.provider == MailProvider::Ics {
                let wire = HttpIcsCalendarWire::new(self)?;
                return self.mail_calendar_sync_step(source, &wire, 1);
            }
            if calendar.provider == MailProvider::Caldav {
                let wire = HttpCalDavCalendarWire::new(self)?;
                return self.mail_calendar_sync_step(source, &wire, CALENDAR_PAGES_PER_STEP);
            }
            return Err(MemoryError::bad_request(
                "this host reads Google, Microsoft 365, CalDAV and ICS calendars",
            ));
        }
        let snapshot = self
            .mail_sync_source(source)?
            .ok_or_else(|| MemoryError::not_found("no mail or calendar source by that ref"))?;
        if reads_google_mail(snapshot.provider) {
            let wire = HttpGmailMailWire::new(self)?;
            return self.mail_sync_step(owner, source, &wire, budget);
        }
        if snapshot.provider == MailProvider::Microsoft365 {
            let wire = HttpGraphMailWire::new(self)?;
            return self.mail_sync_step(owner, source, &wire, budget);
        }
        if snapshot.provider == MailProvider::Imap {
            let wire = ImapMailWire::new(self);
            return self.mail_sync_step(owner, source, &wire, budget);
        }
        Err(MemoryError::bad_request(
            "this host reads Google, Microsoft 365 and IMAP mailboxes",
        ))
    }

    /// One act on the push channel of the mail source `source` through this
    /// host's wire for its provider, under the host's Pub/Sub `topic`
    /// ([`Vault::mail_watch_step`]); `None` for a source whose provider has
    /// no push here (only Gmail's is served). It reads the provider over
    /// blocking HTTP: call it off any async runtime.
    ///
    /// # Errors
    ///
    /// No such source, or the act's own.
    pub fn mail_source_watch_step(
        &self,
        source: EntityId,
        topic: Option<&str>,
    ) -> MemoryResult<Option<MailWatchAct>> {
        let snapshot = self
            .mail_sync_source(source)?
            .ok_or_else(|| MemoryError::not_found("no mail source by that ref"))?;
        if !reads_google_mail(snapshot.provider) {
            return Ok(None);
        }
        let wire = HttpGmailMailWire::new(self)?;
        self.mail_watch_step(source, &wire, topic)
    }
}

impl Memory<'_> {
    /// One bounded import step of a mail or calendar source on this device,
    /// by the vault's owner: [`Vault::mail_source_sync_step`]. It reads the
    /// provider over blocking HTTP: call it off any async runtime, as the
    /// local SDKs do.
    pub fn mail_sources_sync(&self, input: &MailSourceSyncRequest) -> MemoryResult<MailSyncReport> {
        let owner = self.embedded_owner("vault.mail.sources.sync")?;
        let (source, budget) = input.step()?;
        self.vault().mail_source_sync_step(&owner, source, budget)
    }
}
