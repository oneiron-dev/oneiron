//! Searching a mailbox at its provider (fix list row 15424, its remote
//! search slice): `vault.mail.sources.search` asks the mailbox's provider
//! for one page of the messages a query finds, in that provider's own search
//! language (Gmail's `q`, Microsoft Graph's `$search`, an IMAP server's
//! `SEARCH` keys, fix list row 19089), and lands each one
//! the vault does not hold yet whole, bound to the source's audience in the
//! same commit as every imported message. A message a search fetched stays
//! kept, so a mailbox whose copy setting is "Search only" holds exactly what
//! its searches found. Trash, spam and drafts are never found. The search
//! runs under the vault owner's write authority, as an import step does, on
//! a mailbox the owner reads; the query and the hits never leave the
//! mailbox's audience.

use super::gmail::{HttpGmailMailWire, reads_google_mail};
use super::imap::ImapMailWire;
use super::landing::{LandOutcome, Landing};
use super::microsoft365::HttpGraphMailWire;
use super::pack::require_pack_active_in;
use super::source::{MailProvider, MailSourceStatus, SOURCES};
use super::state::{MailPresence, MailStage, OCCURRENCES, occurrence_key};
use super::wire::MailProviderWire;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// The hits one search page lands when the caller names no limit.
const DEFAULT_SEARCH_HITS: u32 = 25;
/// The most hits one search page lands.
const MAX_SEARCH_HITS: u32 = 100;
/// The longest query a search takes, in bytes.
const MAX_SEARCH_QUERY_BYTES: usize = 1024;

#[doc(hidden)]
pub use oneiron_verb_wire::mail_pack::search::{MailSearchReport, MailSourceSearchRequest};

/// The query `query`, checked: 1 to 1024 bytes, no control character, its
/// quotes closed and, outside them, its parentheses balanced. So a caller's
/// `)` never closes the group a wire puts the query in. With `escapes`, a
/// backslash inside a quoted string escapes the character after it, as the
/// provider reads it (IMAP); without, a quote always ends the string.
fn valid_query(query: &str, escapes: bool) -> MemoryResult<&str> {
    let query = query.trim();
    if query.is_empty()
        || query.len() > MAX_SEARCH_QUERY_BYTES
        || query.chars().any(char::is_control)
        || !grouped(query, escapes)
    {
        return Err(MemoryError::bad_request(format!(
            "a search query is 1 to {MAX_SEARCH_QUERY_BYTES} bytes, with no control character, \
             its quotes closed and its parentheses balanced"
        )));
    }
    Ok(query)
}

/// Whether `query`'s quotes close and, outside them, each `)` closes a `(`
/// the query opened itself; with `escapes`, a backslash inside quotes takes
/// the character after it as text.
fn grouped(query: &str, escapes: bool) -> bool {
    let mut quoted = false;
    let mut depth = 0_usize;
    let mut chars = query.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted && escapes => {
                if chars.next().is_none() {
                    return false;
                }
            }
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                let Some(open) = depth.checked_sub(1) else {
                    return false;
                };
                depth = open;
            }
            _ => {}
        }
    }
    !quoted && depth == 0
}

impl Vault {
    /// One page of the messages `query` finds in the mailbox source
    /// `source_ref`, through `wire`, each one the vault does not hold yet
    /// landed whole and kept, under the vault owner's write authority. The
    /// owner must read the mailbox: their own, or a group address in whose
    /// audience they are. Managing a group address is not enough. It reads
    /// the provider over blocking HTTP: call it off any async runtime.
    ///
    /// # Errors
    ///
    /// No such Active mailbox the owner reads, a query out of bounds, the
    /// provider's own failure, or a wire that cannot search.
    pub fn mail_search_step(
        &self,
        owner: &AuthenticatedOwner,
        source_ref: EntityId,
        wire: &dyn MailProviderWire,
        query: &str,
        page: Option<&str>,
        limit: u32,
    ) -> MemoryResult<MailSearchReport> {
        let query = valid_query(query, wire.search_escapes())?;
        let actor = owner.revalidate(self)?;
        let unknown = || MemoryError::not_found("no searchable mailbox source by that ref");
        let row = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            require_pack_active_in(self, &txn)?;
            let row = SOURCES
                .get(&self.store, &txn, &source_ref)?
                .filter(|row| row.kind.is_mailbox() && row.status == MailSourceStatus::Active)
                .ok_or_else(unknown)?;
            if !crate::source_audience::actor_reads_in(self, &txn, &row.audience, actor)? {
                return Err(unknown());
            }
            row
        };
        let snapshot = super::wire::MailSyncSource::of(source_ref, &row);
        let hits = wire.search_page(&snapshot, query, limit.clamp(1, MAX_SEARCH_HITS), page)?;
        let at = crate::unix_seconds_now();
        let landing = Landing::new(self, owner, source_ref, at)?;
        let mut report = MailSearchReport {
            source_ref: source_ref.to_hex(),
            found: u32::try_from(hits.messages.len()).unwrap_or(u32::MAX),
            next_page: hits.next_page,
            ..MailSearchReport::default()
        };
        for hit in &hits.messages {
            // Held whole, or forgotten: nothing to fetch. A message held by
            // its headers only is fetched whole and lands its body.
            let held = {
                let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
                OCCURRENCES
                    .get(
                        &self.store,
                        &txn,
                        &occurrence_key(source_ref, &hit.provider_id),
                    )?
                    .is_some_and(|held| {
                        matches!(held.stage, MailStage::Body)
                            || matches!(held.presence, MailPresence::Forgotten { .. })
                    })
            };
            if held {
                report.same += 1;
                continue;
            }
            let Some(full) = wire.full(&snapshot, &hit.provider_id)? else {
                report.skipped += 1;
                continue;
            };
            // Never trash, spam or a draft, whatever the query found.
            if !super::importer::copies(&full.headers, None) {
                report.skipped += 1;
                continue;
            }
            match landing.land(&row, &full.headers, Some(&full), true)? {
                LandOutcome::Landed => report.landed += 1,
                LandOutcome::Same => report.same += 1,
                LandOutcome::Refused(_) => report.skipped += 1,
            }
        }
        Ok(report)
    }

    /// [`Self::mail_search_step`] through this host's wire for the source's
    /// provider: Gmail for Google mailboxes, Microsoft Graph for Microsoft
    /// 365 ones, the mailbox's own server for IMAP ones.
    ///
    /// # Errors
    ///
    /// No such source, a provider this host cannot search, or the step's
    /// own.
    pub fn mail_source_search(
        &self,
        owner: &AuthenticatedOwner,
        input: &MailSourceSearchRequest,
    ) -> MemoryResult<MailSearchReport> {
        let source = EntityId::from_hex(&input.source_ref)?;
        let snapshot = self
            .mail_sync_source(source)?
            .ok_or_else(|| MemoryError::not_found("no searchable mailbox source by that ref"))?;
        let limit = input.limit.unwrap_or(DEFAULT_SEARCH_HITS);
        let page = input.page.as_deref();
        if reads_google_mail(snapshot.provider) {
            let wire = HttpGmailMailWire::new(self)?;
            return self.mail_search_step(owner, source, &wire, &input.query, page, limit);
        }
        if snapshot.provider == MailProvider::Microsoft365 {
            let wire = HttpGraphMailWire::new(self)?;
            return self.mail_search_step(owner, source, &wire, &input.query, page, limit);
        }
        if snapshot.provider == MailProvider::Imap {
            let wire = ImapMailWire::new(self);
            return self.mail_search_step(owner, source, &wire, &input.query, page, limit);
        }
        Err(MemoryError::bad_request(
            "this host searches Google, Microsoft 365 and IMAP mailboxes at their provider",
        ))
    }
}

impl Memory<'_> {
    /// `vault.mail.sources.search` on this device, as its embedded owner:
    /// [`Vault::mail_source_search`]. It reads the provider over blocking
    /// HTTP: call it off any async runtime.
    ///
    /// # Errors
    ///
    /// No embedded owner on this device, or [`Vault::mail_source_search`]'s
    /// own.
    pub fn mail_sources_search(
        &self,
        input: &MailSourceSearchRequest,
    ) -> MemoryResult<MailSearchReport> {
        let owner = self.embedded_owner("vault.mail.sources.search")?;
        self.vault().mail_source_search(&owner, input)
    }
}
