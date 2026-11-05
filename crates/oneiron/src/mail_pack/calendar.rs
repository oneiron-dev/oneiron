//! The pack's calendar sources (FIX 12559 rows 3 and 5; MAIL-SHARE = A):
//! every person's calendar connects into the one vault; the vault sees its
//! busy and free time; its events' details read only to its owner, unless
//! the owner shares the calendar ("details: shared").
//!
//! A calendar source lands through the engine's calendar connector admission
//! under its own system name, `mail_pack:<source>`
//! ([`calendar_source_system`]). Its EVENTs take ids of their own, derived
//! from the source and the UID (the UID stays in the passport), so two
//! people's copies of one meeting never share a row; each EVENT, and each
//! archived resource it was read from, is bound to the source's audience in
//! its birth commit ([`bind_calendar_source_row_in_txn`]). Busy time is the
//! calendar engine's own projection over the source's system, intervals
//! only ([`calendar_source_occupancy`]).

use serde::{Deserialize, Serialize};

use super::importer::MailSyncReport;
use super::pack::require_pack_active_in;
use super::source::{MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::MailSyncStatusView;
use super::wire::MailSyncSource;
use crate::calendar::{CalendarSel, RemoteCalendarChange};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault};

/// The prefix of a pack calendar source's system name.
pub(crate) const CALENDAR_SOURCE_SYSTEM_PREFIX: &str = "mail_pack:";
/// The most refusal reasons one step reports.
const MAX_REPORTED_REASONS: usize = 20;

/// One calendar source's pull progress, by the source.
const CALENDAR_SYNC: SideTable<EntityId, MailCalendarSyncState, Named> =
    SideTable::new(&side_table::MAIL_PACK_CALENDAR_SYNC);

/// Where one calendar source's pull stands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
struct MailCalendarSyncState {
    /// The wire's cursor for the next pull; `None` starts a full listing.
    cursor: Option<String>,
    /// Whether a full listing has finished, so changes arrive live.
    complete: bool,
    landed: u64,
    deleted_at_provider: u64,
    last_step_at: Option<u64>,
    /// The last step's failure, in words, for the source's owner.
    last_error: Option<String>,
}

/// One page a calendar wire read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailCalendarPull {
    /// The changed resources, each one UID's whole series, in provider order.
    pub changes: Vec<RemoteCalendarChange>,
    /// The cursor the next pull starts from.
    pub next_cursor: Option<String>,
    /// Whether this page ends a listing: the cursor now follows changes.
    pub complete: bool,
}

/// What a calendar wire's pull answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailCalendarRead {
    Pull(MailCalendarPull),
    /// The provider no longer keeps changes from that cursor: the next pull
    /// lists the calendar again.
    Expired,
}

/// A host's calendar wire for one provider. Each call is one provider read,
/// run outside any vault transaction.
pub trait MailCalendarWire {
    /// One page of the calendar's resources after `cursor`; a full listing
    /// when `cursor` is `None`.
    fn pull(&self, source: &MailSyncSource, cursor: Option<&str>) -> Result<MailCalendarRead>;
}

/// The calendar system a pack calendar source lands under.
#[must_use]
pub(crate) fn calendar_source_system(source: EntityId) -> String {
    format!("{CALENDAR_SOURCE_SYSTEM_PREFIX}{}", source.to_hex())
}

/// The pack calendar source `system` names, with its row, if `system` has the
/// pack's prefix.
///
/// # Errors
///
/// A system with the pack's prefix that names no calendar source: such a
/// system never lands unbound.
fn calendar_source_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    system: &str,
) -> Result<Option<(EntityId, MailSourceRow)>> {
    let Some(hex) = system.strip_prefix(CALENDAR_SOURCE_SYSTEM_PREFIX) else {
        return Ok(None);
    };
    let source = EntityId::from_hex(hex)?;
    let row = SOURCES
        .get(&vault.store, txn, &source)?
        .filter(|row| row.kind == MailSourceKind::Calendar)
        .ok_or_else(|| {
            Error::InvalidConfig("the calendar system names no pack calendar source".to_owned())
        })?;
    Ok(Some((source, row)))
}

/// The pack calendar source `system` names and its audience policy, if
/// `system` has the pack's prefix.
///
/// # Errors
///
/// As [`calendar_source_row_in`].
pub(crate) fn calendar_source_of_system_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    system: &str,
) -> Result<Option<(EntityId, EntityId)>> {
    Ok(calendar_source_row_in(vault, txn, system)?.map(|(source, row)| (source, row.audience)))
}

/// Binds a freshly staged row of the calendar system `system` (an EVENT,
/// the artifact its resource is archived in) to its pack calendar source's
/// audience, in the row's birth commit; a no-op for any other system.
///
/// # Errors
///
/// A pack system whose source is not an Active calendar while the pack is
/// installed: its rows never land unbound.
pub(crate) fn bind_calendar_source_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    system: &str,
    record: &EntityId,
) -> Result<()> {
    let Some((_, row)) = calendar_source_row_in(vault, txn, system)? else {
        return Ok(());
    };
    if require_pack_active_in(vault, txn).is_err() || row.status != MailSourceStatus::Active {
        return Err(Error::InvalidConfig(
            "the calendar source is not an Active source of an installed pack".to_owned(),
        ));
    }
    crate::source_audience::bind_record_in_txn(vault, txn, record, &row.audience)
}

/// The busy time of the pack's calendar sources `calendars` selects, over
/// `range`, half-open intervals only, for a person of this vault (MAIL-SHARE
/// = A: the vault sees each person's busy and free time; their events'
/// details stay theirs). Empty for a caller who is no person here, or when
/// the pack is not installed.
///
/// # Errors
///
/// Storage and calendar projection failures.
pub(crate) fn calendar_source_occupancy(
    memory: &Memory<'_>,
    calendars: &[CalendarSel],
    range: TimeRange,
) -> MemoryResult<Vec<(u64, u64)>> {
    let vault = memory.vault();
    let systems = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        if require_pack_active_in(vault, &txn).is_err() || memory.mail_caller_person_in(&txn).is_err()
        {
            return Ok(Vec::new());
        }
        let mut systems = Vec::new();
        for row in SOURCES.iter_from(&vault.store, &txn, &[])? {
            let (source, row) = row?;
            if row.kind != MailSourceKind::Calendar || row.status == MailSourceStatus::Disconnected {
                continue;
            }
            let system = calendar_source_system(source);
            let selected = calendars.is_empty()
                || calendars
                    .iter()
                    .any(|sel| sel.system.as_deref().is_none_or(|named| named == system));
            if selected {
                systems.push(system);
            }
        }
        systems
    };
    let mut busy = Vec::new();
    for system in systems {
        let selector = [CalendarSel {
            system: Some(system),
        }];
        for interval in crate::calendar::freebusy(vault, &selector, range)? {
            busy.push((interval.start_utc, interval.end_utc));
        }
    }
    Ok(busy)
}

/// Half-open busy intervals sorted, with overlapping and touching ones
/// merged.
#[must_use]
pub(crate) fn merge_busy(intervals: impl IntoIterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut intervals: Vec<(u64, u64)> = intervals
        .into_iter()
        .filter(|(start, end)| start < end)
        .collect();
    intervals.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        match merged.last_mut() {
            Some(open) if start <= open.1 => open.1 = open.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// The status view of the calendar source `source` in `txn`.
pub(super) fn calendar_status_view_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<MailSyncStatusView> {
    let state = CALENDAR_SYNC
        .get(&vault.store, txn, &source)?
        .unwrap_or_default();
    Ok(MailSyncStatusView {
        source_ref: source.to_hex(),
        live: state.complete && state.cursor.is_some(),
        copy_done: state.complete,
        landed: state.landed,
        bodies: 0,
        bodies_waiting: 0,
        deleted_at_provider: state.deleted_at_provider,
        last_step_at: state.last_step_at,
        last_error: state.last_error,
    })
}

impl Vault {
    /// The calendar source `source_ref` as a wire is told about it, if it is
    /// a calendar source.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn mail_calendar_source(&self, source_ref: EntityId) -> Result<Option<MailSyncSource>> {
        let txn = self.store.env.read_txn()?;
        Ok(SOURCES
            .get(&self.store, &txn, &source_ref)?
            .filter(|row| row.kind == MailSourceKind::Calendar)
            .map(|row| MailSyncSource::of(source_ref, &row)))
    }

    /// Runs up to `pages` pulls of the calendar source `source_ref` through
    /// `wire` (FIX 12559 rows 3 and 5). Each changed resource is archived
    /// bound to the source's audience and admitted under the source's
    /// system, its EVENTs bound at birth; a provider delete cancels through
    /// the source's own passport, as a connector pull does. A resource the
    /// admission refuses is counted with its reason and the pull goes on.
    /// The step's time and last failure are kept for the source's owner.
    ///
    /// # Errors
    ///
    /// The pack not installed, the source not an Active calendar, a provider
    /// failure (kept on the source too), or storage failures.
    pub fn mail_calendar_sync_step(
        &self,
        source_ref: EntityId,
        wire: &dyn MailCalendarWire,
        pages: u32,
    ) -> MemoryResult<MailSyncReport> {
        let (row, mut state) = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            require_pack_active_in(self, &txn)?;
            let row = SOURCES
                .get(&self.store, &txn, &source_ref)?
                .filter(|row| row.kind == MailSourceKind::Calendar)
                .ok_or_else(|| MemoryError::not_found("no calendar source by that ref"))?;
            let state = CALENDAR_SYNC
                .get(&self.store, &txn, &source_ref)?
                .unwrap_or_default();
            (row, state)
        };
        if row.status != MailSourceStatus::Active {
            return Err(MemoryError::bad_request_with(
                "this calendar source is not syncing",
                &["Resume the source, then sync it."],
            ));
        }
        let source = MailSyncSource::of(source_ref, &row);
        let system = calendar_source_system(source_ref);
        let mut report = MailSyncReport {
            source_ref: source_ref.to_hex(),
            ..MailSyncReport::default()
        };
        let outcome = self.pull_calendar_pages(
            &source,
            &system,
            wire,
            pages.max(1),
            &mut state,
            &mut report,
        );
        state.last_step_at = Some(crate::unix_seconds_now());
        state.last_error = outcome.as_ref().err().map(|error| error.message.clone());
        self.write_calendar_sync_state(source_ref, &state)?;
        report.copy_done = state.complete;
        outcome.map(|()| report)
    }

    fn pull_calendar_pages(
        &self,
        source: &MailSyncSource,
        system: &str,
        wire: &dyn MailCalendarWire,
        pages: u32,
        state: &mut MailCalendarSyncState,
        report: &mut MailSyncReport,
    ) -> MemoryResult<()> {
        for _ in 0..pages {
            let pull = match wire.pull(source, state.cursor.as_deref())? {
                MailCalendarRead::Pull(pull) => pull,
                MailCalendarRead::Expired => {
                    report.anchor_expired = true;
                    state.cursor = None;
                    state.complete = false;
                    self.write_calendar_sync_state(source.source_ref, state)?;
                    continue;
                }
            };
            let at = crate::unix_seconds_now();
            for change in &pull.changes {
                match crate::calendar::ingest::apply_calendar_source_change(self, system, change, at)
                {
                    Ok(crate::calendar::ingest::CalendarSourceChange::Applied) => {
                        report.landed += 1;
                        state.landed += 1;
                    }
                    Ok(crate::calendar::ingest::CalendarSourceChange::Deleted) => {
                        report.kept_deleted += 1;
                        state.deleted_at_provider += 1;
                    }
                    Err(error) => {
                        report.refused += 1;
                        if report.refusal_reasons.len() < MAX_REPORTED_REASONS {
                            report
                                .refusal_reasons
                                .push(format!("{}: {error}", change.uid()));
                        }
                    }
                }
            }
            state.cursor = pull.next_cursor;
            if pull.complete {
                state.complete = true;
            }
            self.write_calendar_sync_state(source.source_ref, state)?;
            if pull.complete {
                break;
            }
        }
        Ok(())
    }

    fn write_calendar_sync_state(
        &self,
        source_ref: EntityId,
        state: &MailCalendarSyncState,
    ) -> MemoryResult<()> {
        self.with_write_txn_grouped(|txn| CALENDAR_SYNC.put(&self.store, txn, &source_ref, state))?;
        Ok(())
    }
}
