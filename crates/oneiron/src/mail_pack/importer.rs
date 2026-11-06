//! The mail importer (FIX 12559 row 1; MAIL-GOOGLE = A, 2026-10-19): one
//! bounded step of one source at a time, run by the host. Each step:
//!
//! 1. takes the provider's change anchor the first time, before any listing,
//!    so no change made while the mailbox copies is missed;
//! 2. reads the change feed since the anchor: new mail lands, a provider
//!    delete applies the source's own setting, a move to trash or spam
//!    counts as a delete; an anchor the provider no longer keeps starts the
//!    listing over from a new one, and nothing is read as deleted for it;
//! 3. copies the mailbox newest first, headers first, under "Keep a copy of
//!    my mail": all mail, the recent months only, or none for search only;
//! 4. fills in the bodies of messages that landed with their headers only,
//!    newest first.
//!
//! Trash, spam and drafts never land. Every provider call runs outside any
//! vault transaction; each message lands in its own commit with its source
//! audience binding ([`super::landing`]). Imported mail wakes no agent: it is
//! evidence, not a message to anyone.

use serde::{Deserialize, Serialize};

use super::landing::{LandOutcome, Landing};
use super::pack::require_pack_active_in;
use super::provider_delete::{ProviderDeleteOutcome, apply_provider_delete, update_labels};
use super::source::{MailCopySetting, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::{MailSyncState, OCCURRENCES, SYNC, bodies_waiting_in, occurrence_key};
use super::wire::{
    MailHeaders, MailHistoryChange, MailHistoryRead, MailListQuery, MailProviderWire,
    MailSyncSource,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault};

/// Seconds in the month a "recent months" setting counts.
const MONTH_SECONDS: u64 = 30 * 86_400;

/// How much one step reads from the provider. The host sets its cadence;
/// these bound one step so many sources share a host fairly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSyncBudget {
    /// Change feed pages.
    pub history_pages: u32,
    /// Newest-first listing pages.
    pub list_pages: u32,
    /// Bodies filled in.
    pub bodies: u32,
}

impl Default for MailSyncBudget {
    fn default() -> Self {
        Self {
            history_pages: 10,
            list_pages: 2,
            bodies: 50,
        }
    }
}

/// What one step did.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSyncReport {
    pub source_ref: String,
    /// Revisions that landed (headers or whole messages).
    pub landed: u64,
    /// Messages the vault held already.
    pub same: u64,
    /// Revisions the write door or a gate refused, with why.
    pub refused: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusal_reasons: Vec<String>,
    /// Messages deleted at the provider and kept as source-deleted copies.
    pub kept_deleted: u64,
    /// Messages deleted at the provider and forgotten.
    pub forgotten: u64,
    /// Whether the provider no longer kept history from the anchor, so the
    /// listing starts over.
    pub anchor_expired: bool,
    /// Whether the newest-first copy has reached the oldest message it keeps.
    pub copy_done: bool,
}

impl MailSyncReport {
    fn count(&mut self, outcome: LandOutcome) {
        match outcome {
            LandOutcome::Landed => self.landed += 1,
            LandOutcome::Same => self.same += 1,
            LandOutcome::Refused(reason) => {
                self.refused += 1;
                if self.refusal_reasons.len() < 20 {
                    self.refusal_reasons.push(reason);
                }
            }
        }
    }

    fn count_delete(&mut self, outcome: ProviderDeleteOutcome) {
        match outcome {
            ProviderDeleteOutcome::Kept => self.kept_deleted += 1,
            ProviderDeleteOutcome::Forgotten => self.forgotten += 1,
            ProviderDeleteOutcome::Nothing => {}
        }
    }
}

/// Whether a message's headers say it lands under `row`'s copy setting:
/// never trash, spam or a draft; for recent months, nothing older.
fn copies(headers: &MailHeaders, newer_than: Option<u64>) -> bool {
    !headers.trash_or_spam
        && !headers.draft
        && newer_than.is_none_or(|cutoff| headers.received_at >= cutoff)
}

/// One step of one source's import.
struct Step<'a> {
    vault: &'a Vault,
    source: EntityId,
    row: MailSourceRow,
    wire_source: MailSyncSource,
    wire: &'a dyn MailProviderWire,
    landing: Landing<'a>,
    newer_than: Option<u64>,
    at: u64,
    report: MailSyncReport,
}

impl Step<'_> {
    fn state(&self) -> Result<MailSyncState> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(SYNC
            .get(&self.vault.store, &txn, &self.source)?
            .unwrap_or_default())
    }

    fn write_state(&self, change: impl FnOnce(&mut MailSyncState)) -> Result<()> {
        self.vault.with_write_txn_grouped(|txn| {
            let mut state = SYNC
                .get(&self.vault.store, txn, &self.source)?
                .unwrap_or_default();
            change(&mut state);
            SYNC.put(&self.vault.store, txn, &self.source, &state)
        })
    }

    fn known(&self, provider_id: &str) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        OCCURRENCES.contains(
            &self.vault.store,
            &txn,
            &occurrence_key(self.source, provider_id),
        )
    }

    fn land_headers(&mut self, provider_id: &str) -> MemoryResult<()> {
        if self.known(provider_id)? {
            self.report.same += 1;
            return Ok(());
        }
        let Some(headers) = self.wire.headers(&self.wire_source, provider_id)? else {
            return Ok(());
        };
        if !copies(&headers, self.newer_than) {
            return Ok(());
        }
        let outcome = self.landing.land(&self.row, &headers, None, false)?;
        self.report.count(outcome);
        Ok(())
    }

    fn delete(&mut self, provider_id: &str) -> MemoryResult<()> {
        let outcome =
            apply_provider_delete(self.vault, self.source, &self.row, provider_id, self.at)?;
        self.report.count_delete(outcome);
        Ok(())
    }

    /// The change feed since the anchor, `pages` pages at most. A read the
    /// budget cut short keeps its anchor: the next step reads it again, and
    /// what landed already lands as the same.
    fn history(&mut self, pages: u32) -> MemoryResult<()> {
        let state = self.state()?;
        let Some(anchor) = state.anchor else {
            return Ok(());
        };
        // A feed longer than one step's budget goes on from its kept page.
        let mut page = state
            .history_page
            .filter(|_| state.history_page_anchor.as_deref() == Some(anchor.as_str()));
        for _ in 0..pages {
            let read = self
                .wire
                .history(&self.wire_source, &anchor, page.as_deref())?;
            let MailHistoryRead::Page(read) = read else {
                let fresh = self.wire.current_anchor(&self.wire_source)?;
                self.write_state(|state| {
                    state.anchor = Some(fresh);
                    state.history_page = None;
                    state.history_page_anchor = None;
                    state.backfill_copy = None;
                    state.backfill_page = None;
                    state.backfill_done = false;
                    state.generation += 1;
                })?;
                self.report.anchor_expired = true;
                return Ok(());
            };
            for change in read.changes {
                match change {
                    MailHistoryChange::Added(message) => {
                        if self.row.copy != MailCopySetting::SearchOnly {
                            self.land_headers(&message.provider_id)?;
                        }
                    }
                    MailHistoryChange::Deleted { provider_id } => self.delete(&provider_id)?,
                    MailHistoryChange::Labels {
                        provider_id,
                        labels,
                        trash_or_spam,
                    } => {
                        if trash_or_spam {
                            self.delete(&provider_id)?;
                        } else {
                            update_labels(self.vault, self.source, &provider_id, &labels, self.at)?;
                        }
                    }
                }
            }
            match read.next_page {
                Some(next) => {
                    let from = anchor.clone();
                    let kept = next.clone();
                    self.write_state(|state| {
                        if state.anchor.as_deref() == Some(from.as_str()) {
                            state.history_page = Some(kept);
                            state.history_page_anchor = Some(from);
                        }
                    })?;
                    page = Some(next);
                }
                None => {
                    let reached = read.anchor;
                    self.write_state(|state| {
                        state.anchor = Some(reached);
                        state.history_page = None;
                        state.history_page_anchor = None;
                    })?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// The newest-first copy, `pages` pages at most; none for search only. A
    /// listing runs under the copy setting and the cutoff it started with: a
    /// changed setting (search only included) or an expired anchor starts
    /// it over with a fresh cutoff.
    fn backfill(&mut self, pages: u32) -> MemoryResult<()> {
        let copy = self.row.copy;
        if self.state()?.backfill_copy != Some(copy) {
            let cutoff = self.newer_than;
            self.write_state(|state| {
                state.backfill_copy = Some(copy);
                state.backfill_newer_than = cutoff;
                state.backfill_page = None;
                state.backfill_done = false;
                state.generation += 1;
            })?;
        }
        if copy == MailCopySetting::SearchOnly {
            return Ok(());
        }
        let newer_than = self.state()?.backfill_newer_than;
        for _ in 0..pages {
            let state = self.state()?;
            if state.backfill_done {
                break;
            }
            let listed = self.wire.list_page(
                &self.wire_source,
                &MailListQuery { newer_than },
                state.backfill_page.as_deref(),
            )?;
            for message in &listed.messages {
                self.land_headers(&message.provider_id)?;
            }
            let generation = state.generation;
            let next = listed.next_page;
            self.write_state(|state| {
                // A listing started over meanwhile keeps its own place.
                if state.generation == generation {
                    state.backfill_done = next.is_none();
                    state.backfill_page = next;
                }
            })?;
        }
        Ok(())
    }

    /// Fills in up to `limit` bodies, newest first. A message the provider no
    /// longer holds, or now holds as trash or spam, is deleted at the
    /// provider; a body the write door refuses leaves the message landed by
    /// its headers and off the queue, with a warning that says why.
    fn bodies(&mut self, limit: u32) -> MemoryResult<()> {
        let waiting = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            bodies_waiting_in(self.vault, &txn, self.source, limit as usize)?
        };
        for provider_id in waiting {
            match self.wire.full(&self.wire_source, &provider_id)? {
                None => self.delete(&provider_id)?,
                Some(full) if full.headers.trash_or_spam => self.delete(&provider_id)?,
                Some(full) => {
                    let outcome =
                        self.landing
                            .land(&self.row, &full.headers, Some(&full), false)?;
                    // A refused body never leaves the queue unseen: the
                    // message stays landed by its headers, and the warning
                    // says why.
                    if let LandOutcome::Refused(reason) = &outcome {
                        tracing::warn!(
                            source = %self.source.to_hex(),
                            provider_id = %provider_id,
                            %reason,
                            "a mail body was refused; the message stays landed by its headers"
                        );
                    }
                    if matches!(outcome, LandOutcome::Refused(_) | LandOutcome::Same) {
                        self.landing.drop_from_body_queue(&provider_id)?;
                    }
                    self.report.count(outcome);
                }
            }
        }
        Ok(())
    }
}

impl Vault {
    /// The mailbox sources a host's importer syncs: every connected mailbox
    /// whose status is Active, while the pack is installed Active.
    pub fn mail_sync_sources(&self) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        if require_pack_active_in(self, &txn).is_err() {
            return Ok(Vec::new());
        }
        let mut sources = Vec::new();
        for row in SOURCES.iter_from(&self.store, &txn, &[])? {
            let (id, row) = row?;
            if row.kind.is_mailbox() && row.status == MailSourceStatus::Active {
                sources.push(id);
            }
        }
        Ok(sources)
    }

    /// The wire snapshot of one mailbox source, for a host to choose and
    /// authorize its wire: what it reads, and the custody record of its
    /// credential, never the credential.
    pub fn mail_sync_source(&self, source_ref: EntityId) -> Result<Option<MailSyncSource>> {
        let txn = self.store.env.read_txn()?;
        Ok(SOURCES
            .get(&self.store, &txn, &source_ref)?
            .filter(|row| row.kind.is_mailbox())
            .map(|row| MailSyncSource::of(source_ref, &row)))
    }

    /// Runs one bounded import step of the mailbox source `source_ref`
    /// through `wire`, under the vault owner's write authority (the rows land
    /// bound to the source's audience; the owner's authority reads none of
    /// them). A provider failure is kept on the source for its owner and
    /// returned; what landed before it stays.
    pub fn mail_sync_step(
        &self,
        owner: &AuthenticatedOwner,
        source_ref: EntityId,
        wire: &dyn MailProviderWire,
        budget: MailSyncBudget,
    ) -> MemoryResult<MailSyncReport> {
        let row = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            require_pack_active_in(self, &txn)?;
            SOURCES
                .get(&self.store, &txn, &source_ref)?
                .filter(|row| row.kind != MailSourceKind::Calendar)
                .filter(|row| row.status == MailSourceStatus::Active)
                .ok_or_else(|| MemoryError::bad_request("no syncing mailbox source by that ref"))?
        };
        let at = crate::unix_seconds_now();
        let newer_than = match row.copy {
            MailCopySetting::RecentMonths { months } => {
                Some(at.saturating_sub(u64::from(months) * MONTH_SECONDS))
            }
            MailCopySetting::All | MailCopySetting::SearchOnly => None,
        };
        let mut step = Step {
            vault: self,
            source: source_ref,
            wire_source: MailSyncSource::of(source_ref, &row),
            row,
            wire,
            landing: Landing::new(self, owner, source_ref, at)?,
            newer_than,
            at,
            report: MailSyncReport {
                source_ref: source_ref.to_hex(),
                ..MailSyncReport::default()
            },
        };
        let outcome = (|| -> MemoryResult<()> {
            if step.state()?.anchor.is_none() {
                let anchor = step.wire.current_anchor(&step.wire_source)?;
                step.write_state(|state| state.anchor = Some(anchor))?;
            }
            step.history(budget.history_pages)?;
            step.backfill(budget.list_pages)?;
            step.bodies(budget.bodies)?;
            Ok(())
        })();
        let error = outcome.as_ref().err().map(|error| error.message.clone());
        step.write_state(|state| {
            state.last_step_at = Some(at);
            state.last_error = error;
        })?;
        outcome?;
        step.report.copy_done = step.state()?.backfill_done;
        Ok(step.report)
    }
}

impl crate::memory::Memory<'_> {
    /// Where one source's import stands: whether new mail arrives live, how
    /// far the copy has come, how many bodies wait, and the last failure. Its
    /// readers see it, and an Owner or an Admin a group address's.
    pub fn mail_sources_sync_status(
        &self,
        input: &super::doors::MailSourceRef,
    ) -> MemoryResult<super::state::MailSyncStatusView> {
        let id = EntityId::from_hex(&input.source_ref)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let unknown = || MemoryError::not_found("no mail source by that ref");
        let row = SOURCES.get(&vault.store, &txn, &id)?.ok_or_else(unknown)?;
        let reads =
            crate::source_audience::actor_reads_in(vault, &txn, &row.audience, self.actor())?;
        let manages = row.kind == MailSourceKind::GroupAddress
            && super::compliance::manages_in(vault, &txn, self.actor())?;
        if !reads && !manages {
            return Err(unknown());
        }
        Ok(super::state::status_view_in(vault, &txn, id)?)
    }
}
