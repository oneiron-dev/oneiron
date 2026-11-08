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
use super::provider_delete::{
    ProviderDeleteOutcome, apply_provider_delete, restore_from_provider_trash, resume_owed_forgets,
    update_labels,
};
use super::source::{
    MailCopySetting, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES,
    proven_own_address_set,
};
use super::state::{
    MailPresence, MailRelist, MailSyncState, OCCURRENCES, SYNC, bodies_waiting_in, occurrence_key,
};
use super::wire::{
    MailHeaders, MailHistoryChange, MailHistoryRead, MailListQuery, MailMessageRef,
    MailProviderWire, MailSyncSource,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault};

/// Seconds in the month a "recent months" setting counts.
pub(super) const MONTH_SECONDS: u64 = 30 * 86_400;

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
    /// Opened attachments fetched.
    pub attachments: u32,
}

impl Default for MailSyncBudget {
    fn default() -> Self {
        Self {
            history_pages: 10,
            list_pages: 2,
            bodies: 50,
            attachments: 10,
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
    /// Opened attachments fetched into their artifacts.
    #[serde(default)]
    pub attachments_stored: u64,
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
pub(super) fn copies(headers: &MailHeaders, newer_than: Option<u64>) -> bool {
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
            // A message named again in another folder carries it too.
            if let Some(listed) = self.wire.listed_labels(provider_id) {
                merge_labels(self.vault, self.source, provider_id, &listed, self.at)?;
            }
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

    /// A message the change feed reports added: one that never landed lands
    /// under the copy setting, and a kept copy the provider deleted is live
    /// again when the provider's headers say it is out of trash and spam.
    fn added(&mut self, provider_id: &str) -> MemoryResult<()> {
        if !self.source_deleted(provider_id)? {
            if self.row.copy != MailCopySetting::SearchOnly {
                self.land_headers(provider_id)?;
            }
            return Ok(());
        }
        if let Some(headers) = self.wire.headers(&self.wire_source, provider_id)?
            && !headers.trash_or_spam
        {
            update_labels(
                self.vault,
                self.source,
                provider_id,
                &headers.labels,
                self.at,
            )?;
            restore_from_provider_trash(self.vault, self.source, provider_id, self.at)?;
        }
        Ok(())
    }

    /// Whether the message's copy is a kept one the provider deleted.
    fn source_deleted(&self, provider_id: &str) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(OCCURRENCES
            .get(
                &self.vault.store,
                &txn,
                &occurrence_key(self.source, provider_id),
            )?
            .is_some_and(|occurrence| {
                matches!(occurrence.presence, MailPresence::SourceDeleted { .. })
            }))
    }

    /// A message out of the provider's trash or spam: a kept copy is live
    /// again.
    fn restore(&mut self, provider_id: &str) -> MemoryResult<()> {
        // One that never landed comes as its own Added, under the copy
        // setting: a label change alone fetches nothing.
        if self.known(provider_id)? {
            restore_from_provider_trash(self.vault, self.source, provider_id, self.at)?;
        }
        Ok(())
    }

    fn delete(&mut self, provider_id: &str) -> MemoryResult<()> {
        let outcome =
            apply_provider_delete(self.vault, self.source, &self.row, provider_id, self.at)?;
        self.report.count_delete(outcome);
        Ok(())
    }

    /// A folder or label the provider no longer has: each message copied
    /// under it is looked up again. Gone, or now in trash or spam, it is
    /// deleted at the provider; else it carries its labels now.
    fn label_gone(&mut self, label: &str) -> MemoryResult<()> {
        let under = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            let mut under = Vec::new();
            for occurrence in
                OCCURRENCES.iter_from(&self.vault.store, &txn, self.source.as_bytes())?
            {
                let (_, occurrence) = occurrence?;
                if matches!(occurrence.presence, MailPresence::Present)
                    && occurrence.labels.iter().any(|held| held == label)
                {
                    under.push(occurrence.provider_id);
                }
            }
            under
        };
        for provider_id in under {
            match self.wire.headers(&self.wire_source, &provider_id)? {
                Some(headers) if !headers.trash_or_spam => {
                    update_labels(
                        self.vault,
                        self.source,
                        &provider_id,
                        &headers.labels,
                        self.at,
                    )?;
                }
                _ => self.delete(&provider_id)?,
            }
        }
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
                let at = self.at;
                self.write_state(|state| {
                    state.anchor = Some(fresh);
                    state.history_page = None;
                    state.history_page_anchor = None;
                    state.backfill_copy = None;
                    state.backfill_page = None;
                    state.backfill_done = false;
                    state.generation += 1;
                    // The fresh listing settles what the lost feed missed.
                    state.relist = Some(MailRelist {
                        generation: state.generation,
                        since: at,
                    });
                })?;
                self.report.anchor_expired = true;
                return Ok(());
            };
            for change in read.changes {
                match change {
                    MailHistoryChange::Added(message) => self.added(&message.provider_id)?,
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
                            self.restore(&provider_id)?;
                        }
                    }
                    MailHistoryChange::LabelGone { label } => self.label_gone(&label)?,
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
        // A change-feed round mid-way may not yet have begun a folder the
        // copy would reach (a Microsoft 365 folder's first round): what the
        // copy lands there could be deleted before that round sees it.
        if self.state()?.history_page.is_some() {
            return Ok(());
        }
        let copy = self.row.copy;
        if self.state()?.backfill_copy != Some(copy) {
            let cutoff = self.newer_than;
            self.write_state(|state| {
                state.backfill_copy = Some(copy);
                state.backfill_newer_than = cutoff;
                state.backfill_page = None;
                state.backfill_done = false;
                state.generation += 1;
                // A listing settling an expired anchor goes on as this one.
                if let Some(relist) = &mut state.relist {
                    relist.generation = state.generation;
                }
            })?;
        }
        if copy == MailCopySetting::SearchOnly {
            // No listing runs, so none settles anything.
            if self.state()?.relist.is_some() {
                self.write_state(|state| state.relist = None)?;
            }
            return Ok(());
        }
        // A listing complete but not yet settled (a delete failed) settles
        // again first.
        let state = self.state()?;
        if state.backfill_done
            && let Some(relist) = state
                .relist
                .filter(|relist| relist.generation == state.generation)
        {
            self.settle_relist(relist, state.backfill_newer_than)?;
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
            let relist = state
                .relist
                .filter(|relist| relist.generation == generation);
            if relist.is_some() {
                self.mark_listed(&listed.messages, generation)?;
            }
            let next = listed.next_page;
            self.write_state(|state| {
                // A listing started over meanwhile keeps its own place.
                if state.generation == generation {
                    state.backfill_done = next.is_none();
                    state.backfill_page = next;
                }
            })?;
            let after = self.state()?;
            if let Some(relist) = relist
                && after.backfill_done
                && after.generation == generation
                && after.relist == Some(relist)
            {
                self.settle_relist(relist, after.backfill_newer_than)?;
            }
        }
        Ok(())
    }

    /// Records that the provider still holds `provider_id` as of this
    /// listing (`generation`).
    fn mark_listed_one(&self, provider_id: &str, generation: u64) -> Result<()> {
        self.mark_listed(
            &[MailMessageRef {
                provider_id: provider_id.to_owned(),
                thread_id: None,
            }],
            generation,
        )
    }

    /// Records that this listing (`generation`) named each of `messages`
    /// the vault holds a copy of.
    fn mark_listed(&self, messages: &[MailMessageRef], generation: u64) -> Result<()> {
        self.vault.with_write_txn_grouped(|txn| {
            for message in messages {
                let key = occurrence_key(self.source, &message.provider_id);
                if let Some(mut occurrence) = OCCURRENCES.get(&self.vault.store, txn, &key)?
                    && occurrence.listed_in != Some(generation)
                {
                    occurrence.listed_in = Some(generation);
                    OCCURRENCES.put(&self.vault.store, txn, &key, &occurrence)?;
                }
            }
            Ok(())
        })
    }

    /// Settles a completed listing after an expired anchor (fix list row
    /// 17937): each live copy landed before it began, within its cutoff,
    /// that it never named is asked of the provider again; one it no longer
    /// holds, or holds as trash or spam, was deleted while the feed was lost
    /// and takes the source's delete setting. A delete that fails leaves the
    /// listing unsettled, and the next step settles it again.
    fn settle_relist(&mut self, relist: MailRelist, cutoff: Option<u64>) -> MemoryResult<()> {
        let lost: Vec<String> = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            let mut lost = Vec::new();
            for occurrence in
                OCCURRENCES.iter_from(&self.vault.store, &txn, self.source.as_bytes())?
            {
                let (_, occurrence) = occurrence?;
                if matches!(occurrence.presence, MailPresence::Present)
                    && occurrence.landed_at < relist.since
                    && occurrence.listed_in != Some(relist.generation)
                    && cutoff.is_none_or(|cutoff| occurrence.received_at >= cutoff)
                {
                    lost.push(occurrence.provider_id);
                }
            }
            lost
        };
        let mut settled = true;
        for provider_id in lost {
            // A copy the listing missed may have moved behind its cursor:
            // the provider's own answer decides.
            if let Some(headers) = self.wire.headers(&self.wire_source, &provider_id)?
                && !headers.trash_or_spam
            {
                update_labels(
                    self.vault,
                    self.source,
                    &provider_id,
                    &headers.labels,
                    self.at,
                )?;
                self.mark_listed_one(&provider_id, relist.generation)?;
                continue;
            }
            if self.delete(&provider_id).is_err() {
                settled = false;
            }
        }
        if settled {
            self.write_state(|state| {
                if state.relist == Some(relist) {
                    state.relist = None;
                }
            })?;
        }
        Ok(())
    }

    /// The mailbox's own addresses as its provider proves them now (fix
    /// list row 20400), written to the source in a commit of their own
    /// when they changed, at most once per
    /// [`OWN_ADDRESSES_REFRESH_SECS`](super::state::OWN_ADDRESSES_REFRESH_SECS)
    /// of answers. A provider that proves none, or a read it refuses (a
    /// missing scope) or that fails, keeps the stored set for this step:
    /// never the step's failure.
    fn refresh_own_addresses(&mut self) -> Result<()> {
        if self.state()?.own_addresses_read_at.is_some_and(|read| {
            self.at.saturating_sub(read) < super::state::OWN_ADDRESSES_REFRESH_SECS
        }) {
            return Ok(());
        }
        let Ok(Some(proven)) = self.wire.own_addresses(&self.wire_source) else {
            return Ok(());
        };
        let at = self.at;
        self.write_state(|state| state.own_addresses_read_at = Some(at))?;
        let own = proven_own_address_set(&self.row.address, &proven);
        if own == self.row.own_addresses {
            return Ok(());
        }
        let (vault, source) = (self.vault, self.source);
        vault.with_write_txn_grouped(|txn| {
            if let Some(mut row) = SOURCES.get(&vault.store, txn, &source)?
                && row.own_addresses != own
            {
                row.own_addresses.clone_from(&own);
                SOURCES.put(&vault.store, txn, &source, &row)?;
            }
            Ok(())
        })?;
        self.row.own_addresses = own;
        Ok(())
    }

    /// Fills in up to `limit` bodies, newest first. A message the provider no
    /// longer holds, or now holds as trash or spam, is deleted at the
    /// provider; a body the write door refuses leaves the message landed by
    /// its headers and off the queue.
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

/// Adds `listed` to the labels of the live copy of `provider_id`.
fn merge_labels(
    vault: &Vault,
    source: EntityId,
    provider_id: &str,
    listed: &[String],
    at: u64,
) -> Result<()> {
    let held = {
        let txn = vault.store.env.read_txn()?;
        OCCURRENCES.get(&vault.store, &txn, &occurrence_key(source, provider_id))?
    };
    let Some(held) = held.filter(|held| matches!(held.presence, MailPresence::Present)) else {
        return Ok(());
    };
    if listed.iter().all(|label| held.labels.contains(label)) {
        return Ok(());
    }
    let mut labels = held.labels;
    labels.extend(listed.iter().cloned());
    labels.sort();
    labels.dedup();
    update_labels(vault, source, provider_id, &labels, at)
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
            wire_source: MailSyncSource {
                newer_than,
                ..MailSyncSource::of(source_ref, &row)
            },
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
        // An erased message's attachment artifacts owed their delete go first.
        super::attachments::collect_after_delete(self);
        // Header revisions a body superseded and whose delete did not return
        // go first, whether or not the provider lists them again (FIX 15413).
        super::header_retire::retire_superseded_headers(self, source_ref);
        let mut owed = None;
        let outcome = (|| -> MemoryResult<()> {
            // Then a forget a failure stopped part-way (fix list row 18084).
            owed = resume_owed_forgets(step.vault, step.source)?;
            if step.state()?.anchor.is_none() {
                let anchor = step.wire.current_anchor(&step.wire_source)?;
                step.write_state(|state| state.anchor = Some(anchor))?;
            }
            step.history(budget.history_pages)?;
            step.backfill(budget.list_pages)?;
            step.bodies(budget.bodies)?;
            let stored = super::attachments::fetch_waiting_attachments(
                step.vault,
                step.source,
                &step.wire_source,
                step.wire,
                step.landing.actor(),
                budget.attachments,
            )?;
            step.report.attachments_stored += stored;
            step.refresh_own_addresses()?;
            Ok(())
        })();
        let error = outcome
            .as_ref()
            .err()
            .map(|error| error.message.clone())
            .or(owed);
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
        if row.kind == MailSourceKind::Calendar {
            return Ok(super::calendar::calendar_status_view_in(vault, &txn, id)?);
        }
        Ok(super::state::status_view_in(vault, &txn, id)?)
    }
}
