//! Lane admission and fail-closed fact reduction.

use crate::batch::EntityMetadataHeader;
use crate::calendar::claims::{
    CalendarBusyTransparency, CalendarOrigin, CalendarStatus, CalendarTimeKindValue,
    CalendarWallTimeValue, PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND, PREDICATE_CALENDAR_WALL_TIME,
    decode_passport_value, decode_status_value, decode_time_kind_value, decode_wall_time_end,
    decode_wall_time_value, is_calendar_claim_predicate,
};
use crate::claim::{
    ClaimBody, ScopedRead, ScopedReadReceipt, ScopedReadResult, claim_surfaceable,
    decode_claim_body,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::TombstoneStore;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// The two claim-read lanes the calendar surface projects from.
///
/// Both arms enforce claim surfaceability; the scoped arm additionally enforces
/// policy scoped-read grants. Nothing in this module reads a claim any other
/// way, so there is exactly one admission chokepoint for the whole surface.
#[derive(Clone, Copy)]
pub enum CalendarRead<'a> {
    /// Internal engine lane (BK-00's `BusyUnion` consumer rides this).
    Vault(&'a Vault),
    /// Actor lane used by every SDK/MCP surface, with the receipt every claim
    /// read on it folds into.
    Scoped(
        &'a ScopedRead<'a>,
        &'a std::cell::RefCell<ScopedReadReceipt>,
    ),
}

/// Runs one projection on `read`'s actor lane and returns it with the receipt
/// of every claim read the projection made.
pub(in crate::calendar) fn receipted<T>(
    read: &ScopedRead<'_>,
    project: impl FnOnce(&CalendarRead<'_>) -> Result<T>,
) -> Result<ScopedReadResult<T>> {
    let receipt = std::cell::RefCell::new(read.read_receipt(None, 0)?);
    let value = project(&CalendarRead::Scoped(read, &receipt))?;
    Ok(ScopedReadResult {
        value,
        receipt: receipt.into_inner(),
    })
}

impl<'a> CalendarRead<'a> {
    /// The underlying vault.
    #[must_use]
    pub fn vault(&self) -> &'a Vault {
        match self {
            Self::Vault(vault) => vault,
            Self::Scoped(read, _) => read.vault(),
        }
    }

    /// The suppression key of every series exception this lane may not read,
    /// mapped to whether each exception carrying it awaits its owner's
    /// critical confirm.
    pub(in crate::calendar) fn withheld_exception_series(
        &self,
    ) -> Result<std::collections::BTreeMap<(EntityId, String), bool>> {
        let mut withheld = std::collections::BTreeMap::new();
        let Self::Scoped(read, receipt) = self else {
            return Ok(withheld);
        };
        let mut after = None;
        loop {
            let ids = self.vault().entities_by_type_page(
                crate::registry::ENTITY_TYPE_CLAIM,
                after.as_ref(),
                4096,
            )?;
            if ids.is_empty() {
                return Ok(withheld);
            }
            for id in &ids {
                // Only exception claims contribute to the scoped receipt.
                if self
                    .vault()
                    .get_claim(id)?
                    .filter(claim_surfaceable)
                    .is_none_or(|body| {
                        body.predicate
                            != crate::calendar::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION
                    })
                {
                    continue;
                }
                let result = read.read_projected(
                    &[crate::claim::PointRead::id(*id)],
                    None,
                    |txn, rows| -> Result<_> {
                        let Projected {
                            body: Some(body),
                            held,
                            ..
                        } = claim_in_txn(read.vault(), txn, id, true)?
                        else {
                            return Ok(None);
                        };
                        if body.predicate
                            != crate::calendar::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION
                            || rows.into_iter().next().flatten().is_some()
                        {
                            return Ok(None);
                        }
                        // Only the suppression key leaves this internal comparison.
                        let exception =
                            crate::calendar::claims::decode_series_exception_value(&body.value)?;
                        Ok(Some(((exception.master_ref, exception.uid), held)))
                    },
                )?;
                receipt.borrow_mut().restrict_with(&result.receipt);
                if let Some((key, held)) = result.value {
                    *withheld.entry(key).or_insert(true) &= held;
                }
            }
            after = ids.last().copied();
        }
    }
}

/// One claim on an EVENT as a read lane projects it.
struct Projected {
    id: EntityId,
    /// The body this lane admits.
    body: Option<ClaimBody>,
    /// The predicate of a live claim this lane may not read.
    withheld: Option<String>,
    /// The admitted body awaits its owner's critical confirm.
    held: bool,
}

/// What an operational read takes from a claim awaiting its owner's
/// critical confirm.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// Main's read: the claim counts as written.
    Raw,
    /// An action takes nothing from it.
    Settled,
    /// Free/busy: it keeps its EVENT a calendar member and its time busy,
    /// and none of its values frees time.
    Busy,
}

/// A claim the actor's lane read in `txn`: its admitted body, else the
/// predicate of the live claim it withholds, and, when `check_hold`, its hold.
fn scoped_claim_in_txn(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: Option<crate::claim::ReadRow>,
    check_hold: bool,
) -> Result<Projected> {
    let body = row
        .and_then(|row| row.body)
        .map(|raw| decode_claim_body(&raw, true))
        .transpose()?;
    let withheld = if body.is_none() {
        read.vault()
            .get_claim_in_txn(txn, id)?
            .filter(claim_surfaceable)
            .map(|body| body.predicate)
    } else {
        None
    };
    // A claim this lane withholds stays `Withheld`, held or not.
    let held = check_hold
        && body.is_some()
        && !crate::gate::claim_critical_confirm_settled_in_txn(&read.vault().store, txn, id)?;
    Ok(Projected {
        id: *id,
        body,
        withheld,
        held,
    })
}

fn claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    check_hold: bool,
) -> Result<Projected> {
    let body = vault.get_claim_in_txn(txn, id)?.filter(claim_surfaceable);
    let held = check_hold
        && body.is_some()
        && !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, id)?;
    Ok(Projected {
        id: *id,
        body,
        withheld: None,
        held,
    })
}

/// One single-cardinality calendar fact, as a given read lane can see it.
///
/// The three states are not interchangeable, and collapsing `Withheld` into
/// `Absent` inverts the scoped-read policy. `Absent` carries CAL-00's default
/// (no `calendar.time_kind` claim ⇒ busy; no `calendar.status` claim ⇒ not
/// cancelled). `Withheld` means a live claim decides the projection and *this*
/// lane may not read it — resolving it to the default would make an actor's
/// projection WIDER than the internal one and disclose occupancy through a
/// claim the actor cannot read. Every decision site below therefore fails
/// closed on `Withheld`, toward non-busy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneFact<T> {
    /// No live claim carries this fact, or free/busy pins a held one to the
    /// default.
    Absent,
    /// This lane read the deciding claim.
    Read(T),
    /// A live claim decides this fact and this lane may not read it.
    Withheld,
}

/// A `calendar.wall_time` value: its civil start and, for a floating or
/// all-day EVENT, its exclusive civil end.
type WallTimeFact = (CalendarWallTimeValue, Option<CalendarWallTimeValue>);

/// The most a civil time runs ahead of UTC in any zone (UTC+14).
const EASTERNMOST_OFFSET_SECS: u64 = 14 * 3_600;

/// The most a civil time runs behind UTC in any zone (UTC−12).
const WESTERNMOST_OFFSET_SECS: u64 = 12 * 3_600;

/// A civil time's seconds on the UTC clock, or `None` for a leap second or a
/// time before the epoch.
fn civil_seconds(wall: CalendarWallTimeValue) -> Option<u64> {
    let at = chrono::NaiveDate::from_ymd_opt(wall.y, u32::from(wall.mo), u32::from(wall.d))?
        .and_hms_opt(u32::from(wall.h), u32::from(wall.mi), u32::from(wall.s))?;
    u64::try_from(at.and_utc().timestamp()).ok()
}

/// The calendar facts one EVENT's admitted claims carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::calendar) struct CalendarEventFacts {
    origin: LaneFact<CalendarOrigin>,
    time_kind: LaneFact<CalendarTimeKindValue>,
    wall_time: LaneFact<WallTimeFact>,
    status: LaneFact<CalendarStatus>,
    systems: Vec<String>,
    uids: Vec<String>,
    series: Option<crate::calendar::claims::CalendarSeriesMasterValue>,
    exception: Option<crate::calendar::claims::CalendarSeriesExceptionValue>,
    series_withheld: bool,
    exception_withheld: bool,
}

impl CalendarEventFacts {
    pub(in crate::calendar) fn series(
        &self,
    ) -> Option<&crate::calendar::claims::CalendarSeriesMasterValue> {
        self.series.as_ref()
    }
    pub(in crate::calendar) fn exception(
        &self,
    ) -> Option<&crate::calendar::claims::CalendarSeriesExceptionValue> {
        self.exception.as_ref()
    }
    pub(in crate::calendar) fn uids(&self) -> &[String] {
        &self.uids
    }
    pub(in crate::calendar) fn series_withheld(&self) -> bool {
        self.series_withheld
    }
    pub(in crate::calendar) fn exception_withheld(&self) -> bool {
        self.exception_withheld
    }
    fn utc_anchored(&self) -> bool {
        match self.time_kind {
            LaneFact::Read(kind) => matches!(
                kind.kind,
                crate::calendar::claims::CalendarTimeKind::Absolute
                    | crate::calendar::claims::CalendarTimeKind::Zoned
            ),
            LaneFact::Absent => true,
            LaneFact::Withheld => false,
        }
    }

    /// Where a floating or all-day EVENT can fall (FIX 7844). Such an EVENT
    /// names civil time and no instant, so it covers every instant its civil
    /// start and exclusive end span in some zone: from its start where that
    /// comes first (UTC+14) to its end where that comes last (UTC−12). A
    /// window that meets its day in any zone finds it, and free/busy keeps
    /// all of it busy. An all-day EVENT thus covers its whole day span; an
    /// EVENT with no stored end covers its start alone. `None` for an
    /// anchored EVENT, or one whose wall time this lane cannot read.
    fn wall_span(&self) -> Option<TimeRange> {
        let LaneFact::Read(kind) = self.time_kind else {
            return None;
        };
        if !matches!(
            kind.kind,
            crate::calendar::claims::CalendarTimeKind::Floating
                | crate::calendar::claims::CalendarTimeKind::AllDay
        ) {
            return None;
        }
        let LaneFact::Read((start, end)) = self.wall_time else {
            return None;
        };
        let start = civil_seconds(start)?;
        let last = match end {
            Some(end) => civil_seconds(end)?.saturating_sub(1).max(start),
            None => start,
        };
        Some(TimeRange {
            start: start.saturating_sub(EASTERNMOST_OFFSET_SECS),
            end: last.saturating_add(WESTERNMOST_OFFSET_SECS),
        })
    }

    pub(in crate::calendar) fn origin(&self) -> Option<CalendarOrigin> {
        match self.origin {
            LaneFact::Absent => Some(CalendarOrigin::Dreamer),
            LaneFact::Read(origin) => Some(origin),
            LaneFact::Withheld => None,
        }
    }

    /// Whether this EVENT consumes availability.
    ///
    /// CAL-00 mints `busy_transparency` on `calendar.time_kind` with `busy` as
    /// the default, so an EVENT that carries the family but no time-kind claim
    /// still blocks: only an explicit `free` transparency opts out. That
    /// default is scoped to a *genuinely absent* claim — a claim this lane may
    /// not read defaults the other way, or the actor's union would gain an
    /// interval the internal one omits.
    pub(crate) fn blocks_time(&self) -> bool {
        match self.time_kind {
            LaneFact::Read(kind) => kind.busy_transparency == CalendarBusyTransparency::Busy,
            LaneFact::Absent => true,
            LaneFact::Withheld => false,
        }
    }

    /// Whether this EVENT must be treated as cancelled.
    ///
    /// A1's multi-source law never deletes a cancelled EVENT, so cancellation
    /// is only representable as this claim. Freebusy therefore has to read it:
    /// leaving a cancelled EVENT in the union would force BK-00 to re-filter,
    /// which is exactly what the busy-only projection law forbids. A withheld
    /// `calendar.status` reads as cancelled for the same reason `blocks_time`
    /// fails closed — the lane cannot rule a cancellation out.
    pub(crate) fn is_cancelled(&self) -> bool {
        match self.status {
            LaneFact::Read(status) => status == CalendarStatus::Cancelled,
            LaneFact::Absent => false,
            LaneFact::Withheld => true,
        }
    }

    pub(crate) fn systems(&self) -> &[String] {
        &self.systems
    }
}

/// One EVENT row the calendar surface admits.
pub(crate) struct CalendarEventRow {
    pub(crate) id: EntityId,
    /// Inclusive UTC occurrence, or `None` for an EVENT that stores none.
    ///
    /// The anchored/unanchored distinction rides all the way to the consumers
    /// on purpose: flattened to a bare [`TimeRange`], an undated EVENT reads as
    /// the interval `[0, 0]` and starts occupying Unix second zero in both
    /// range search and the busy union.
    pub(crate) occurred: Option<TimeRange>,
    /// Inclusive UTC span a floating or all-day EVENT covers in some zone
    /// (`CalendarEventFacts::wall_span`), which range search and free/busy
    /// read where `occurred` is `None`; `None` for an anchored EVENT.
    pub(in crate::calendar) wall_span: Option<TimeRange>,
    /// The display name the EVENT body carries, read in the row's own
    /// snapshot through the row's lane.
    pub(in crate::calendar) name: Option<String>,
    /// Every claim on the EVENT the row was reduced from, read in the same
    /// snapshot as the EVENT (FIX 5485).
    pub(in crate::calendar) claims: Vec<EntityId>,
    pub(in crate::calendar) facts: CalendarEventFacts,
}

/// Collects the calendar facts an EVENT's admitted claims carry.
///
/// Returns `None` when the entity carries no admitted `calendar.*` claim at
/// all: family membership is CAL-00's exact table, never a `calendar.` prefix
/// match, so an ordinary EVENT is not silently treated as a calendar EVENT.
fn reduce_event_facts(projected: &[Projected], hold: Hold) -> Result<Option<CalendarEventFacts>> {
    let mut family_member = false;
    let mut origin: Option<(EntityId, LaneFact<CalendarOrigin>)> = None;
    let mut time_kind: Option<(EntityId, LaneFact<CalendarTimeKindValue>)> = None;
    let mut wall_time: Option<(EntityId, LaneFact<WallTimeFact>)> = None;
    let mut status: Option<(EntityId, LaneFact<CalendarStatus>)> = None;
    let mut systems = Vec::new();
    let mut uids = Vec::new();
    let mut series = None;
    let mut exception = None;
    let mut series_withheld = false;
    let mut exception_withheld = false;

    for claim in projected {
        let claim_id = claim.id;
        let Some(body) = &claim.body else {
            // A claim this lane hides still decides the projection when it is
            // one of the two single-cardinality facts, so it enters the same
            // lowest-id contest as an admitted one — as `Withheld`, never as a
            // value. Family membership is deliberately NOT set from a withheld
            // claim: an actor who can read no calendar claim on this EVENT
            // sees no calendar EVENT.
            match claim.withheld.as_deref() {
                Some(PREDICATE_CALENDAR_ORIGIN) => {
                    replace_when_lower(&mut origin, claim_id, LaneFact::Withheld);
                }
                Some(PREDICATE_CALENDAR_TIME_KIND) => {
                    replace_when_lower(&mut time_kind, claim_id, LaneFact::Withheld);
                }
                Some(PREDICATE_CALENDAR_WALL_TIME) => {
                    replace_when_lower(&mut wall_time, claim_id, LaneFact::Withheld);
                }
                Some(PREDICATE_CALENDAR_STATUS) => {
                    replace_when_lower(&mut status, claim_id, LaneFact::Withheld);
                }
                Some(crate::calendar::claims::PREDICATE_CALENDAR_SERIES_MASTER) => {
                    series_withheld = true;
                }
                Some(crate::calendar::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION) => {
                    exception_withheld = true;
                }
                _ => {}
            }
            continue;
        };
        if !is_calendar_claim_predicate(&body.predicate) {
            continue;
        }
        // The hold falls on the branch that enables: an action takes no row
        // from a held claim, and free/busy takes its occupancy (membership,
        // CAL-00's busy defaults, a passport's system) but no value that
        // frees time.
        if claim.held && hold != Hold::Raw {
            if hold == Hold::Busy {
                family_member = true;
                match body.predicate.as_str() {
                    PREDICATE_CALENDAR_TIME_KIND => {
                        replace_when_lower(&mut time_kind, claim_id, LaneFact::Absent);
                    }
                    // A wall time only places occupancy; it frees nothing.
                    PREDICATE_CALENDAR_WALL_TIME => {
                        let value = wall_time_fact(&body.value)?;
                        replace_when_lower(&mut wall_time, claim_id, LaneFact::Read(value));
                    }
                    PREDICATE_CALENDAR_STATUS => {
                        replace_when_lower(&mut status, claim_id, LaneFact::Absent);
                    }
                    PREDICATE_CALENDAR_PASSPORT => {
                        let passport = decode_passport_value(&body.value)?;
                        if passport.presence
                            == crate::calendar::claims::CalendarPassportPresence::Live
                        {
                            systems.push(passport.system);
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        family_member = true;
        match body.predicate.as_str() {
            PREDICATE_CALENDAR_ORIGIN => {
                let value = body
                    .value
                    .as_str()
                    .and_then(CalendarOrigin::parse)
                    .ok_or(crate::Error::InvalidClaimBody("calendar origin value"))?;
                replace_when_lower(&mut origin, claim_id, LaneFact::Read(value));
            }
            PREDICATE_CALENDAR_TIME_KIND => {
                let value = decode_time_kind_value(&body.value)?;
                replace_when_lower(&mut time_kind, claim_id, LaneFact::Read(value));
            }
            PREDICATE_CALENDAR_WALL_TIME => {
                let value = wall_time_fact(&body.value)?;
                replace_when_lower(&mut wall_time, claim_id, LaneFact::Read(value));
            }
            PREDICATE_CALENDAR_STATUS => {
                let value = decode_status_value(&body.value)?;
                replace_when_lower(&mut status, claim_id, LaneFact::Read(value.status));
            }
            PREDICATE_CALENDAR_PASSPORT => {
                let passport = decode_passport_value(&body.value)?;
                if passport.presence == crate::calendar::claims::CalendarPassportPresence::Live {
                    systems.push(passport.system);
                    uids.push(passport.uid);
                }
            }
            crate::calendar::claims::PREDICATE_CALENDAR_SERIES_MASTER if series.is_none() => {
                series = Some(crate::calendar::claims::decode_series_master_value(
                    &body.value,
                )?);
            }
            crate::calendar::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION if exception.is_none() => {
                exception = Some(crate::calendar::claims::decode_series_exception_value(
                    &body.value,
                )?);
            }
            _ => {}
        }
    }

    if !family_member {
        return Ok(None);
    }
    systems.sort_unstable();
    systems.dedup();
    // Two calendars may carry one UID for the same EVENT; it is one series
    // either way, and each (UID, original start) is one occurrence (FIX 9653).
    uids.sort_unstable();
    uids.dedup();
    Ok(Some(CalendarEventFacts {
        origin: origin.map_or(LaneFact::Absent, |(_, fact)| fact),
        time_kind: time_kind.map_or(LaneFact::Absent, |(_, fact)| fact),
        wall_time: wall_time.map_or(LaneFact::Absent, |(_, fact)| fact),
        status: status.map_or(LaneFact::Absent, |(_, fact)| fact),
        systems,
        uids,
        series,
        exception,
        series_withheld,
        exception_withheld,
    }))
}

fn wall_time_fact(value: &rmpv::Value) -> Result<WallTimeFact> {
    Ok((decode_wall_time_value(value)?, decode_wall_time_end(value)?))
}

/// Keeps the lowest-`EntityId` claim for a single-cardinality predicate.
///
/// Supersession already guarantees one live claim per `(subject, predicate)`;
/// a second live row is a data defect, and picking the lowest id makes the
/// projection deterministic instead of iteration-order dependent — the same
/// tie-break rule `freebusy`'s merged-interval representative uses.
fn replace_when_lower<T>(slot: &mut Option<(EntityId, T)>, id: EntityId, value: T) {
    match slot {
        Some((current, _)) if *current <= id => {}
        _ => *slot = Some((id, value)),
    }
}

/// Reads one EVENT's admitted calendar row.
pub(super) fn event_row(read: &CalendarRead<'_>, id: EntityId) -> Result<Option<CalendarEventRow>> {
    Ok(event_rows_in(read, id, Hold::Raw)?.map(|(row, _)| row))
}

/// An EVENT's row as written and, unless the hold is `Raw`, its row under
/// that hold.
type EventRows = (CalendarEventRow, Option<CalendarEventRow>);

fn event_rows_in(read: &CalendarRead<'_>, id: EntityId, hold: Hold) -> Result<Option<EventRows>> {
    let vault = read.vault();
    let CalendarRead::Scoped(scoped, receipt) = read else {
        let txn = vault.store.env.read_txn()?;
        return event_rows_in_txn(vault, &txn, id, hold);
    };
    // The EVENT, its body and every claim on it are admitted through the
    // actor's lane in ONE serving snapshot, and the row is built from that
    // snapshot alone (FIX 9651): no header, name or time is read beside the
    // admission. A claim landed after the listing joins the next read.
    let claim_ids = vault.claims_for_subject(&id)?;
    let reads: Vec<_> = std::iter::once(id)
        .chain(claim_ids.iter().copied())
        .map(crate::claim::PointRead::id)
        .collect();
    let result = scoped.read_projected(&reads, None, |txn, rows| -> Result<_> {
        let mut rows = rows.into_iter();
        let Some(event) = rows.next().flatten() else {
            return Ok(None);
        };
        if event.entity_type != ENTITY_TYPE_EVENT
            || event.deletion.is_some()
            || vault.port_tombstone_is_deleted(txn, &id)?
        {
            return Ok(None);
        }
        let header = EntityMetadataHeader {
            entity_type: event.entity_type,
            occurred_start: event.occurred.start,
            occurred_end: event.occurred.end,
            learned_at: event.learned_at,
        };
        let projected = claim_ids
            .iter()
            .zip(rows)
            .map(|(claim, row)| scoped_claim_in_txn(scoped, txn, claim, row, hold != Hold::Raw))
            .collect::<Result<Vec<_>>>()?;
        let name = event.body.as_deref().and_then(super::service::event_name);
        event_rows(&header, id, name, &projected, hold, || {
            crate::calendar::origin::invalidated_in_txn(vault, txn, id)
        })
    })?;
    receipt.borrow_mut().restrict_with(&result.receipt);
    Ok(result.value)
}

fn event_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    hold: Hold,
) -> Result<Option<EventRows>> {
    let Some(header) = vault.entity_header_in_txn(txn, &id)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.port_tombstone_is_deleted(txn, &id)? {
        return Ok(None);
    }
    let projected = vault
        .claims_for_subject_in_txn(txn, &id)?
        .iter()
        .map(|claim| claim_in_txn(vault, txn, claim, hold != Hold::Raw))
        .collect::<Result<Vec<_>>>()?;
    let name = vault
        .get_in_txn(txn, &id)?
        .as_deref()
        .and_then(super::service::event_name);
    event_rows(&header, id, name, &projected, hold, || {
        crate::calendar::origin::invalidated_in_txn(vault, txn, id)
    })
}

fn event_rows(
    header: &EntityMetadataHeader,
    id: EntityId,
    name: Option<String>,
    projected: &[Projected],
    hold: Hold,
    invalidated: impl FnOnce() -> Result<bool>,
) -> Result<Option<EventRows>> {
    let Some(facts) = reduce_event_facts(projected, Hold::Raw)? else {
        return Ok(None);
    };
    if facts.origin().is_none() || invalidated()? {
        return Ok(None);
    }
    let claims: Vec<EntityId> = projected.iter().map(|claim| claim.id).collect();
    let held = if hold == Hold::Raw {
        None
    } else {
        reduce_event_facts(projected, hold)?
            .filter(|facts| facts.origin().is_some())
            .map(|facts| event_row_of(header, id, name.clone(), claims.clone(), facts))
    };
    Ok(Some((event_row_of(header, id, name, claims, facts), held)))
}

fn event_row_of(
    header: &EntityMetadataHeader,
    id: EntityId,
    name: Option<String>,
    claims: Vec<EntityId>,
    facts: CalendarEventFacts,
) -> CalendarEventRow {
    CalendarEventRow {
        id,
        occurred: if facts.utc_anchored() {
            occurred_range(header)
        } else {
            None
        },
        wall_span: facts.wall_span(),
        name,
        claims,
        facts,
    }
}

/// Visits every admitted calendar EVENT in type-index order.
pub(crate) fn visit_calendar_events(
    read: &CalendarRead<'_>,
    mut visit: impl FnMut(CalendarEventRow) -> Result<()>,
) -> Result<()> {
    visit_calendar_events_in(read, Hold::Raw, |row, _| visit(row))
}

/// Visits the calendar rows an action may act on: an EVENT its settled claims
/// alone admit, read as written so a held restriction still applies, and
/// anchored only when the settled claims anchor it too.
pub(crate) fn visit_calendar_events_for_effect(
    read: &CalendarRead<'_>,
    mut visit: impl FnMut(CalendarEventRow) -> Result<()>,
) -> Result<()> {
    visit_calendar_events_in(read, Hold::Settled, |row, settled| {
        let Some(settled) = settled else {
            return Ok(());
        };
        visit(CalendarEventRow {
            occurred: row.occurred.filter(|_| settled.occurred.is_some()),
            wall_span: row.wall_span.filter(|_| settled.wall_span.is_some()),
            ..row
        })
    })
}

/// Visits every admitted calendar EVENT as written and as free/busy reads its
/// held claims.
pub(in crate::calendar) fn visit_calendar_events_busy(
    read: &CalendarRead<'_>,
    visit: impl FnMut(CalendarEventRow, Option<CalendarEventRow>) -> Result<()>,
) -> Result<()> {
    visit_calendar_events_in(read, Hold::Busy, visit)
}

fn visit_calendar_events_in(
    read: &CalendarRead<'_>,
    hold: Hold,
    mut visit: impl FnMut(CalendarEventRow, Option<CalendarEventRow>) -> Result<()>,
) -> Result<()> {
    for id in read.vault().entities_by_type(ENTITY_TYPE_EVENT)? {
        if let Some((row, held)) = event_rows_in(read, id, hold)? {
            visit(row, held)?;
        }
    }
    Ok(())
}

/// Normalizes a stored occurrence to an ordered inclusive interval.
///
/// `None` when the header carries no occurrence at all (both bounds zero) —
/// that state means "undated", not "the first second of 1970".
fn occurred_range(header: &EntityMetadataHeader) -> Option<TimeRange> {
    if header.occurred_start == 0 && header.occurred_end == 0 {
        return None;
    }
    Some(if header.occurred_start <= header.occurred_end {
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        }
    } else {
        TimeRange {
            start: header.occurred_end,
            end: header.occurred_start,
        }
    })
}
