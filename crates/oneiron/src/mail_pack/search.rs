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
use super::setting_keys::MAIL_SEARCH_IN_ROOM;
use super::source::{MailProvider, MailSourceStatus, SOURCES};
use super::state::{MailPresence, MailStage, OCCURRENCES, occurrence_key};
use super::wire::MailProviderWire;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::off_record::OffRecordSession;
use crate::session_overlay::{RouteTarget, SessionWriteRoute};
use crate::setting::SettingScope;
use crate::{EntityId, Vault};

/// The hits one search page lands when the caller names no limit.
const DEFAULT_SEARCH_HITS: u32 = 25;
/// The most hits one search page lands.
const MAX_SEARCH_HITS: u32 = 100;
/// The longest query a search takes, in bytes.
const MAX_SEARCH_QUERY_BYTES: usize = 1024;
/// What a search inside a room's off-record stretch answers while the
/// owner has not allowed mail search in that room (`mail.search.in_room`,
/// off by default; UNBUILT-01-ROOM-READERS, owner 16 Nov 00:44): the room's
/// other members would read the hits, so it is refused before the provider
/// is asked, and nothing is fetched or kept. The words are the UI session's
/// short form (its WORDS-FOR-ENGINE item 3, 15 Nov 20:45), which the owner
/// has not seen yet: change them here.
const ROOM_SEARCH_REFUSAL: &str = "Mail is searched only where you are alone.";

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
        self.search_step(owner, None, source_ref, wire, query, page, limit)
    }

    /// [`Self::mail_search_step`] run inside the off-record session
    /// `session` (ARCH-0063 #searched-mail): while the session is off record,
    /// each hit it keeps stays in the session's overlay and is dropped at
    /// close, and a hit the session reads already, staged there or held in
    /// base, is not fetched again. A session flipped on record keeps its
    /// hits in base, as a search outside one does. In a room's session the
    /// hits stay in the room's overlay, which every member reads until
    /// close, so the search runs there only where the owner allowed mail
    /// search in that room (`mail.search.in_room`, off by default). The
    /// owner proof is the only proof, as outside a session.
    ///
    /// # Errors
    ///
    /// As [`Self::mail_search_step`]; an anonymous session, which keeps
    /// nothing; `FORBIDDEN` in a room's session while the owner has not
    /// allowed mail search in that room, before the provider is asked; a
    /// session that belongs to another vault open, or that closed.
    #[expect(
        clippy::too_many_arguments,
        reason = "the search step's own axes, plus the session it runs in"
    )]
    pub fn mail_search_step_in_session(
        &self,
        owner: &AuthenticatedOwner,
        session: &OffRecordSession<'_>,
        source_ref: EntityId,
        wire: &dyn MailProviderWire,
        query: &str,
        page: Option<&str>,
        limit: u32,
    ) -> MemoryResult<MailSearchReport> {
        self.search_step(owner, Some(session), source_ref, wire, query, page, limit)
    }

    /// The search step, staging into `session`'s overlay while it is off
    /// record, else landing in base.
    #[expect(
        clippy::too_many_arguments,
        reason = "the search step's own axes, plus the session it runs in"
    )]
    fn search_step(
        &self,
        owner: &AuthenticatedOwner,
        session: Option<&OffRecordSession<'_>>,
        source_ref: EntityId,
        wire: &dyn MailProviderWire,
        query: &str,
        page: Option<&str>,
        limit: u32,
    ) -> MemoryResult<MailSearchReport> {
        let query = valid_query(query, wire.search_escapes())?;
        let staging = match session {
            Some(session) => self.session_staging(session)?,
            None => None,
        };
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
            // Inside a session, held means held in what the session reads:
            // its overlay over base.
            let held = {
                let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
                let key = occurrence_key(source_ref, &hit.provider_id);
                match &staging {
                    Some((session, _)) => OCCURRENCES.get(&session.read_view()?, &txn, &key)?,
                    None => OCCURRENCES.get(&self.store, &txn, &key)?,
                }
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
            let outcome = match &staging {
                Some((session, route)) => landing.land_in_session(session, route, &row, &full)?,
                None => landing.land(&row, &full.headers, Some(&full), true)?,
            };
            match outcome {
                LandOutcome::Landed => report.landed += 1,
                LandOutcome::Same => report.same += 1,
                LandOutcome::Refused(_) => report.skipped += 1,
            }
        }
        Ok(report)
    }

    /// Where a search inside `session` keeps its hits: the session and the
    /// overlay route it stages through while the session is off record;
    /// `None` once it is on record, so they land in base. The owner's proof
    /// binds the session at the door (`bind_for`), and every staging writer
    /// checks the session's participant again.
    fn session_staging<'s, 'v>(
        &self,
        session: &'s OffRecordSession<'v>,
    ) -> MemoryResult<Option<(&'s OffRecordSession<'v>, SessionWriteRoute)>> {
        if session.read_view()?.read().base().open_nonce != self.store.open_nonce {
            return Err(MemoryError::bad_request(
                "the off-record session belongs to another vault open",
            ));
        }
        let route = session.write_route()?;
        // An anonymous session keeps nothing, so a search in it keeps no
        // hit anywhere: refused before the provider is asked.
        route.require_recording(session.session_ref())?;
        match route.target() {
            RouteTarget::Overlay => {}
            RouteTarget::Base => return Ok(None),
            RouteTarget::Discard => {
                return Err(MemoryError::bad_request(
                    "an anonymous off-record session keeps no searched mail",
                ));
            }
        }
        // A room's other members read what its overlay holds: a search
        // there keeps its hits only where the owner allowed mail search in
        // that room, read before the provider is asked.
        if let Some(room) = session.room()? {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            let allowed = MAIL_SEARCH_IN_ROOM
                .read_in_txn(self, &txn, &[SettingScope::Thread(room)], None)?
                .value;
            if !allowed {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    ROOM_SEARCH_REFUSAL,
                    &[],
                ));
            }
        }
        Ok(Some((session, route)))
    }

    /// [`Self::mail_source_search`] run inside the off-record session
    /// `session`: [`Self::mail_search_step_in_session`] through this host's
    /// wire for the source's provider.
    ///
    /// # Errors
    ///
    /// As [`Self::mail_source_search`] and
    /// [`Self::mail_search_step_in_session`].
    pub fn mail_source_search_in_session(
        &self,
        owner: &AuthenticatedOwner,
        session: &OffRecordSession<'_>,
        input: &MailSourceSearchRequest,
    ) -> MemoryResult<MailSearchReport> {
        self.source_search(owner, Some(session), input)
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
        self.source_search(owner, None, input)
    }

    /// The source search, inside `session` when one is named.
    fn source_search(
        &self,
        owner: &AuthenticatedOwner,
        session: Option<&OffRecordSession<'_>>,
        input: &MailSourceSearchRequest,
    ) -> MemoryResult<MailSearchReport> {
        let source = EntityId::from_hex(&input.source_ref)?;
        let snapshot = self
            .mail_sync_source(source)?
            .ok_or_else(|| MemoryError::not_found("no searchable mailbox source by that ref"))?;
        let limit = input.limit.unwrap_or(DEFAULT_SEARCH_HITS);
        let page = input.page.as_deref();
        let query = input.query.as_str();
        if reads_google_mail(snapshot.provider) {
            let wire = HttpGmailMailWire::new(self)?;
            return self.search_step(owner, session, source, &wire, query, page, limit);
        }
        if snapshot.provider == MailProvider::Microsoft365 {
            let wire = HttpGraphMailWire::new(self)?;
            return self.search_step(owner, session, source, &wire, query, page, limit);
        }
        if snapshot.provider == MailProvider::Imap {
            let wire = ImapMailWire::new(self);
            return self.search_step(owner, session, source, &wire, query, page, limit);
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
        let vault = self.vault();
        // A handle bound into an off-record session searches inside it, so
        // its hits stay in that session (ARCH-0063 #searched-mail).
        match self.off_record_binding() {
            Some((session_ref, _)) => {
                let session = vault
                    .off_record_session_vault()
                    .bind_for(session_ref, owner.revalidate(vault)?)?;
                vault.mail_source_search_in_session(&owner, &session, input)
            }
            None => vault.mail_source_search(&owner, input),
        }
    }
}
