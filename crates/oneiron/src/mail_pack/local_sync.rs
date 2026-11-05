//! The owner's door that runs one import step of a mail or calendar source
//! on this device (`vault.mail.sources.sync`), through the provider's wire:
//! Gmail for Google Workspace and Google mailboxes, Microsoft Graph for
//! Microsoft 365 ones, Google Calendar for Google calendars.

use serde::{Deserialize, Serialize};

use super::gmail::{HttpGmailMailWire, reads_google_mail};
use super::google_calendar::HttpGoogleCalendarWire;
use super::ics_calendar::HttpIcsCalendarWire;
use super::importer::{MailSyncBudget, MailSyncReport};
use super::microsoft365::HttpGraphMailWire;
use super::source::MailProvider;
use crate::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};

/// The most bodies one step of `vault.mail.sources.sync` fills in.
const MAX_BODIES_PER_STEP: u32 = 500;
/// The calendar pages one step of `vault.mail.sources.sync` reads.
const CALENDAR_PAGES_PER_STEP: u32 = 4;

/// `vault.mail.sources.sync`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceSyncRequest {
    /// The mailbox source, 32-hex.
    pub source_ref: String,
    /// The bodies this step fills in; 50 when absent, at most 500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bodies: Option<u32>,
}

impl Memory<'_> {
    /// One bounded import step of a mail or calendar source on this device,
    /// by the vault's owner (FIX 12559 rows 1b, 3 and 5). A mailbox: new
    /// changes since the source's anchor, the next newest-first pages under
    /// its copy setting, then waiting bodies. A calendar: the next pages of
    /// its listing or its changes, each event bound to the source at birth. The rows land bound to the source's audience; the
    /// owner's authority lands them and reads none. It reads the provider
    /// over blocking HTTP: call it off any async runtime, as the local SDKs
    /// do.
    pub fn mail_sources_sync(&self, input: &MailSourceSyncRequest) -> MemoryResult<MailSyncReport> {
        let owner = self.embedded_owner("vault.mail.sources.sync")?;
        let source = EntityId::from_hex(&input.source_ref)?;
        let vault = self.vault();
        if let Some(calendar) = vault.mail_calendar_source(source)? {
            if reads_google_mail(calendar.provider) {
                let wire = HttpGoogleCalendarWire::new(vault)?;
                return vault.mail_calendar_sync_step(source, &wire, CALENDAR_PAGES_PER_STEP);
            }
            if calendar.provider == MailProvider::Ics {
                let wire = HttpIcsCalendarWire::new(vault)?;
                return vault.mail_calendar_sync_step(source, &wire, 1);
            }
            return Err(MemoryError::bad_request_with(
                "this device reads Google calendars and ICS subscriptions so far",
                &["Connect a Google or ICS calendar; Microsoft 365 and CalDAV calendars follow."],
            ));
        }
        let snapshot = vault
            .mail_sync_source(source)?
            .ok_or_else(|| MemoryError::not_found("no mailbox source by that ref"))?;
        let mut budget = MailSyncBudget::default();
        if let Some(bodies) = input.bodies {
            budget.bodies = bodies.min(MAX_BODIES_PER_STEP);
        }
        if reads_google_mail(snapshot.provider) {
            let wire = HttpGmailMailWire::new(vault)?;
            return vault.mail_sync_step(&owner, source, &wire, budget);
        }
        if snapshot.provider == MailProvider::Microsoft365 {
            let wire = HttpGraphMailWire::new(vault)?;
            return vault.mail_sync_step(&owner, source, &wire, budget);
        }
        Err(MemoryError::bad_request_with(
            "this device reads Google and Microsoft 365 mailboxes so far",
            &["IMAP mailboxes follow; connect a Google or Microsoft 365 mailbox meanwhile."],
        ))
    }
}
