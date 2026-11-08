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
//! archived resource it was read from, is stamped with the source's
//! audience and bound to it in its birth commit
//! ([`calendar_source_landing_in`]). Busy time is the calendar engine's own
//! projection over the source's system, intervals only
//! ([`calendar_source_occupancy`]).

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
/// The resources a calendar source's pulls landed, by the source and the
/// BLAKE3 of the provider's resource id.
const CALENDAR_RESOURCES: SideTable<(EntityId, [u8; 32]), MailCalendarResource, Named> =
    SideTable::new(&side_table::MAIL_PACK_CALENDAR_RESOURCE);

/// One resource a calendar source's pulls landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailCalendarResource {
    /// The UID it carried.
    uid: String,
    /// The listing of the source that last saw it
    /// ([`MailCalendarSyncState::listing`]).
    listing: u64,
    /// Its master's start and end, Unix seconds.
    span: Option<(u64, u64)>,
}

fn resource_key(source: EntityId, href: &str) -> (EntityId, [u8; 32]) {
    (source, *blake3::hash(href.as_bytes()).as_bytes())
}

/// The UID the calendar source `source` landed for the provider's resource
/// `href`, if it landed one: how a wire names a deleted event the provider
/// reports by its id alone.
///
/// # Errors
///
/// Storage failures.
pub(super) fn landed_uid(vault: &Vault, source: EntityId, href: &str) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    Ok(CALENDAR_RESOURCES
        .get(&vault.store, &txn, &resource_key(source, href))?
        .map(|resource| resource.uid))
}

/// Forgets the resource row of the provider's resource `href` of the
/// calendar source `source`, its UID untouched: how a wire retires the old
/// place of an event its provider moved to another resource.
///
/// # Errors
///
/// Storage failures.
pub(super) fn forget_resource_href(vault: &Vault, source: EntityId, href: &str) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        CALENDAR_RESOURCES
            .delete(&vault.store, txn, &resource_key(source, href))
            .map(drop)
    })
}

/// Which of `uids` the calendar source `source` landed under a provider's
/// resource other than those in `leaving`: the UIDs a moved event still
/// carries at its new place, which a wire must not delete when it reads the
/// old place gone.
///
/// # Errors
///
/// Storage failures.
pub(super) fn uids_held_outside(
    vault: &Vault,
    source: EntityId,
    uids: &std::collections::BTreeSet<String>,
    leaving: &std::collections::BTreeSet<&str>,
) -> Result<std::collections::BTreeSet<String>> {
    let mut held = std::collections::BTreeSet::new();
    if uids.is_empty() {
        return Ok(held);
    }
    let leaving: std::collections::BTreeSet<[u8; 32]> = leaving
        .iter()
        .map(|href| resource_key(source, href).1)
        .collect();
    let txn = vault.store.env.read_txn()?;
    for row in CALENDAR_RESOURCES.iter_from(&vault.store, &txn, source.as_bytes())? {
        let ((_, href), resource) = row?;
        if !leaving.contains(&href) && uids.contains(&resource.uid) {
            held.insert(resource.uid);
        }
    }
    Ok(held)
}

/// Where one calendar source's pull stands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
struct MailCalendarSyncState {
    /// The wire's cursor for the next pull; `None` starts a full listing.
    cursor: Option<String>,
    /// Whether a full listing has finished, so changes arrive live.
    complete: bool,
    /// The full listings started so far: the one in progress, or the last.
    #[serde(default)]
    listing: u64,
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
    /// The span of start times a listing's pages cover; `None` for the whole
    /// calendar. A resource landed before whose span meets it, omitted by
    /// the finished listing, is marked absent.
    pub covers: Option<TimeRange>,
    /// Each resource, by the provider's id, that holds no longer the UID
    /// landed for it, with no tombstone from the provider (it holds another
    /// UID now, or no event), and that UID, which no resource holds now.
    /// Before the page's changes land, each such UID is marked absent, as a
    /// finished listing marks one it omitted, and the resource's row goes:
    /// a later page that reads the UID under another resource lands it live
    /// again, where a delete would leave it cancelled.
    pub vacated: Vec<(String, String)>,
}

/// One whole calendar a feed wire read (an ICS file or subscription).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailCalendarFeed {
    /// The complete `VCALENDAR` document.
    pub ics: Vec<u8>,
    /// The cursor the next read starts from (an HTTP validator).
    pub next_cursor: Option<String>,
}

/// What a calendar wire's pull answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailCalendarRead {
    Pull(MailCalendarPull),
    /// The whole calendar: every UID it no longer carries is removed.
    Feed(MailCalendarFeed),
    /// The calendar has not changed since the cursor.
    Unchanged,
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

/// The PERSON whose own pack calendar landed the EVENT `event`: the owner
/// the Calendar source row names whose audience the EVENT is bound to, read
/// in `txn` (FIX 16308). `None` for an EVENT no Calendar source binds, and
/// for one whose source names no owner (that person was erased).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn calendar_source_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(policy) = crate::source_audience::binding_in(vault, txn, event)? else {
        return Ok(None);
    };
    Ok(SOURCES
        .scan(&vault.store, txn)?
        .into_iter()
        .find(|(_, row)| row.kind == MailSourceKind::Calendar && row.audience == policy)
        .and_then(|(_, row)| row.owner))
}

/// One write of a pack calendar source's landing: the proof its rows (an
/// EVENT, the artifact its resource is archived in) are stamped under, and
/// the source's audience each is bound to in the same commit (fix list row
/// 16256).
#[derive(Debug)]
pub(crate) struct CalendarSourceLanding {
    birth: crate::source_audience::SourceAudienceBirth,
    audience: EntityId,
}

/// The landing of the calendar system `system` in `txn`; `None` for any
/// system without the pack's prefix, whose rows land unstamped and unbound.
///
/// # Errors
///
/// A pack system whose source is not an Active calendar while the pack is
/// installed, or whose audience is no source policy: its rows never land
/// unbound.
pub(crate) fn calendar_source_landing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    system: &str,
) -> Result<Option<CalendarSourceLanding>> {
    let Some((_, row)) = calendar_source_row_in(vault, txn, system)? else {
        return Ok(None);
    };
    if require_pack_active_in(vault, txn).is_err() || row.status != MailSourceStatus::Active {
        return Err(Error::InvalidConfig(
            "the calendar source is not an Active source of an installed pack".to_owned(),
        ));
    }
    let birth = crate::source_audience::SourceAudienceBirth::mint_in(vault, txn, &row.audience)?;
    Ok(Some(CalendarSourceLanding {
        birth,
        audience: row.audience,
    }))
}

impl CalendarSourceLanding {
    /// The proof the landing's stamped rows are put under
    /// ([`crate::batch::BatchBuilder::put_source_bound`]).
    pub(crate) fn birth(&self) -> &crate::source_audience::SourceAudienceBirth {
        &self.birth
    }

    /// `body`, the body the row `record` is staged with in `txn`, stamped
    /// with the source-audience obligation; the row is marked born.
    ///
    /// # Errors
    ///
    /// A body that is not one unstamped MessagePack map; storage failures.
    pub(crate) fn stamp_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        record: &EntityId,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        self.birth.stamp_in_txn(vault, txn, record, body)
    }

    /// Marks the stamped row `record` born again in `txn`, before a write
    /// of its landing that keeps its stamp (an EVENT's drift), and answers
    /// the proof that write is put under.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn mark_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        record: &EntityId,
    ) -> Result<&crate::source_audience::SourceAudienceBirth> {
        crate::source_audience::mark_birth_in_txn(vault, txn, &self.birth, record)?;
        Ok(&self.birth)
    }

    /// Binds the row `record`, staged stamped in `txn`, to the source's
    /// audience; its birth mark goes.
    ///
    /// # Errors
    ///
    /// A row not stamped, or bound to another policy; storage failures.
    pub(crate) fn bind_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        record: &EntityId,
    ) -> Result<()> {
        crate::source_audience::bind_record_in_txn(vault, txn, record, &self.audience)
    }
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
        if require_pack_active_in(vault, &txn).is_err()
            || memory.mail_caller_person_in(&txn).is_err()
        {
            return Ok(Vec::new());
        }
        let mut systems = Vec::new();
        for row in SOURCES.iter_from(&vault.store, &txn, &[])? {
            let (source, row) = row?;
            if row.kind != MailSourceKind::Calendar || row.status == MailSourceStatus::Disconnected
            {
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
        claim_rechecks_pending: 0,
        claim_rechecks_checked: 0,
        claim_rechecks_review_needed: 0,
        claim_rechecks_obsolete: 0,
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
            // A pull from no cursor starts a full listing.
            if state.cursor.is_none() {
                state.listing += 1;
            }
            let listing = !state.complete;
            let pull = match wire.pull(source, state.cursor.as_deref())? {
                MailCalendarRead::Pull(pull) => pull,
                MailCalendarRead::Feed(feed) => {
                    let at = crate::unix_seconds_now();
                    let events = crate::calendar::ingest::apply_calendar_source_feed(
                        self, system, &feed.ics, at,
                    )
                    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
                    report.landed += events as u64;
                    state.landed += events as u64;
                    state.cursor = feed.next_cursor;
                    state.complete = true;
                    self.write_calendar_sync_state(source.source_ref, state)?;
                    break;
                }
                MailCalendarRead::Unchanged => {
                    state.complete = true;
                    break;
                }
                MailCalendarRead::Expired => {
                    report.anchor_expired = true;
                    state.cursor = None;
                    state.complete = false;
                    self.write_calendar_sync_state(source.source_ref, state)?;
                    continue;
                }
            };
            let at = crate::unix_seconds_now();
            if !pull.vacated.is_empty() {
                let uids: Vec<String> = pull
                    .vacated
                    .iter()
                    .map(|(_, uid)| uid.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                crate::calendar::ingest::apply_calendar_source_omissions(self, system, &uids, at)
                    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
                self.forget_vacated_resources(source.source_ref, &pull.vacated)?;
                report.kept_deleted += uids.len() as u64;
                state.deleted_at_provider += uids.len() as u64;
            }
            for change in &pull.changes {
                let applied =
                    crate::calendar::ingest::apply_calendar_source_change(self, system, change, at);
                self.note_calendar_resource(source.source_ref, change, &applied, state.listing)?;
                match applied {
                    Ok(crate::calendar::ingest::CalendarSourceChange::Applied { .. }) => {
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
            if listing && pull.complete {
                let (omitted, stale) =
                    self.calendar_listing_omissions(source.source_ref, state.listing, pull.covers)?;
                crate::calendar::ingest::apply_calendar_source_omissions(
                    self, system, &omitted, at,
                )
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
                self.forget_calendar_resources(source.source_ref, &omitted)?;
                self.forget_calendar_resource_keys(&stale)?;
                report.kept_deleted += omitted.len() as u64;
                state.deleted_at_provider += omitted.len() as u64;
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

    /// Notes what one pulled change did to its resource: a landed one, or
    /// one the admission refused (its earlier landing stands), is seen by
    /// listing `listing`; a deleted one is forgotten.
    fn note_calendar_resource(
        &self,
        source: EntityId,
        change: &RemoteCalendarChange,
        applied: &std::result::Result<
            crate::calendar::ingest::CalendarSourceChange,
            crate::calendar::CalendarError,
        >,
        listing: u64,
    ) -> MemoryResult<()> {
        self.with_write_txn_grouped(|txn| match change {
            RemoteCalendarChange::Upsert(object) => {
                let key = resource_key(source, &object.href);
                let earlier = CALENDAR_RESOURCES.get(&self.store, txn, &key)?;
                let span = match applied {
                    Ok(crate::calendar::ingest::CalendarSourceChange::Applied { span }) => *span,
                    _ => earlier.as_ref().and_then(|resource| resource.span),
                };
                let resource = MailCalendarResource {
                    uid: object.uid.clone(),
                    listing,
                    span,
                };
                CALENDAR_RESOURCES.put(&self.store, txn, &key, &resource)
            }
            RemoteCalendarChange::Delete { href, .. }
            | RemoteCalendarChange::Omitted { href, .. } => {
                CALENDAR_RESOURCES.delete(&self.store, txn, &resource_key(source, href))?;
                Ok(())
            }
        })?;
        Ok(())
    }

    /// The UIDs the source landed that its finished listing `listing` did
    /// not see, among those whose span meets `covers` (all, when `None`),
    /// and the keys of the resources it did not see whose UID it saw under
    /// another resource (one its provider moved): those rows go, the UID
    /// stays.
    fn calendar_listing_omissions(
        &self,
        source: EntityId,
        listing: u64,
        covers: Option<TimeRange>,
    ) -> MemoryResult<(Vec<String>, Vec<(EntityId, [u8; 32])>)> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let mut unseen = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for row in CALENDAR_RESOURCES.iter_from(&self.store, &txn, source.as_bytes())? {
            let (key, resource) = row?;
            if resource.listing >= listing {
                seen.insert(resource.uid);
                continue;
            }
            let covered = covers.is_none_or(|covered| {
                resource
                    .span
                    .is_some_and(|(start, end)| start <= covered.end && end >= covered.start)
            });
            if covered {
                unseen.push((key, resource.uid));
            }
        }
        let mut omitted = std::collections::BTreeSet::new();
        let mut stale = Vec::new();
        for (key, uid) in unseen {
            if seen.contains(&uid) {
                stale.push(key);
            } else {
                omitted.insert(uid);
            }
        }
        Ok((omitted.into_iter().collect(), stale))
    }

    /// Forgets the resource rows `keys`, their UIDs untouched.
    fn forget_calendar_resource_keys(&self, keys: &[(EntityId, [u8; 32])]) -> MemoryResult<()> {
        if keys.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            for key in keys {
                CALENDAR_RESOURCES.delete(&self.store, txn, key)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Forgets the resource row of each of `vacated`, by the provider's id,
    /// while it still carries the UID named beside it.
    fn forget_vacated_resources(
        &self,
        source: EntityId,
        vacated: &[(String, String)],
    ) -> MemoryResult<()> {
        self.with_write_txn_grouped(|txn| {
            for (href, uid) in vacated {
                let key = resource_key(source, href);
                if CALENDAR_RESOURCES
                    .get(&self.store, txn, &key)?
                    .is_some_and(|resource| resource.uid == *uid)
                {
                    CALENDAR_RESOURCES.delete(&self.store, txn, &key)?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Forgets the source's resources carrying the UIDs `uids`.
    fn forget_calendar_resources(&self, source: EntityId, uids: &[String]) -> MemoryResult<()> {
        if uids.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            let mut gone = Vec::new();
            for row in CALENDAR_RESOURCES.iter_from(&self.store, txn, source.as_bytes())? {
                let (key, resource) = row?;
                if uids.binary_search(&resource.uid).is_ok() {
                    gone.push(key);
                }
            }
            for key in gone {
                CALENDAR_RESOURCES.delete(&self.store, txn, &key)?;
            }
            Ok(())
        })?;
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
