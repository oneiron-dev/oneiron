//! Lane admission and fail-closed fact reduction.

use crate::batch::EntityMetadataHeader;
use crate::calendar::claims::{
    CalendarBusyTransparency, CalendarOrigin, CalendarStatus, CalendarTimeKindValue,
    PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS,
    PREDICATE_CALENDAR_TIME_KIND, decode_passport_value, decode_status_value,
    decode_time_kind_value, is_calendar_claim_predicate,
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

    pub(in crate::calendar) fn withheld_exception_series(
        &self,
        for_effects: bool,
    ) -> Result<std::collections::BTreeSet<(EntityId, String)>> {
        let mut withheld = std::collections::BTreeSet::new();
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
                        let Some(body) = claim_in_txn(read.vault(), txn, id, for_effects)? else {
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
                        Ok(Some((exception.master_ref, exception.uid)))
                    },
                )?;
                receipt.borrow_mut().restrict_with(&result.receipt);
                if let Some(key) = result.value {
                    withheld.insert(key);
                }
            }
            after = ids.last().copied();
        }
    }

    /// Reads a claim and its policy-withheld predicate in the same snapshot.
    fn claim_projection(
        &self,
        id: &EntityId,
        for_effects: bool,
    ) -> Result<(Option<ClaimBody>, Option<String>)> {
        match self {
            Self::Vault(vault) => {
                let txn = vault.store.env.read_txn()?;
                Ok((claim_in_txn(vault, &txn, id, for_effects)?, None))
            }
            Self::Scoped(read, receipt) => {
                let result = read.read_projected(
                    &[crate::claim::PointRead::id(*id)],
                    None,
                    |txn, rows| -> Result<_> {
                        if for_effects
                            && !crate::gate::claim_critical_confirm_settled_in_txn(
                                &read.vault().store,
                                txn,
                                id,
                            )?
                        {
                            return Ok((None, None));
                        }
                        let body = rows
                            .into_iter()
                            .next()
                            .flatten()
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
                        Ok((body, withheld))
                    },
                )?;
                receipt.borrow_mut().restrict_with(&result.receipt);
                Ok(result.value)
            }
        }
    }
}

fn claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    for_effects: bool,
) -> Result<Option<ClaimBody>> {
    let body = if for_effects {
        vault.get_claim_for_effect_in_txn(txn, id)?
    } else {
        vault.get_claim_in_txn(txn, id)?
    };
    Ok(body.filter(claim_surfaceable))
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
    /// No live claim carries this fact.
    Absent,
    /// This lane read the deciding claim.
    Read(T),
    /// A live claim decides this fact and this lane may not read it.
    Withheld,
}

/// The calendar facts one EVENT's admitted claims carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::calendar) struct CalendarEventFacts {
    origin: LaneFact<CalendarOrigin>,
    time_kind: LaneFact<CalendarTimeKindValue>,
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
    pub(in crate::calendar) facts: CalendarEventFacts,
}

/// Collects the calendar facts an EVENT's admitted claims carry.
///
/// Returns `None` when the entity carries no admitted `calendar.*` claim at
/// all: family membership is CAL-00's exact table, never a `calendar.` prefix
/// match, so an ordinary EVENT is not silently treated as a calendar EVENT.
fn event_facts(
    read: &CalendarRead<'_>,
    event: &EntityId,
    for_effects: bool,
) -> Result<Option<CalendarEventFacts>> {
    reduce_event_facts(read.vault().claims_for_subject(event)?, |id| {
        read.claim_projection(id, for_effects)
    })
}

fn event_facts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
    for_effects: bool,
) -> Result<Option<CalendarEventFacts>> {
    reduce_event_facts(vault.claims_for_subject_in_txn(txn, event)?, |id| {
        Ok((claim_in_txn(vault, txn, id, for_effects)?, None))
    })
}

fn reduce_event_facts(
    claim_ids: Vec<EntityId>,
    mut project: impl FnMut(&EntityId) -> Result<(Option<ClaimBody>, Option<String>)>,
) -> Result<Option<CalendarEventFacts>> {
    let mut family_member = false;
    let mut origin: Option<(EntityId, LaneFact<CalendarOrigin>)> = None;
    let mut time_kind: Option<(EntityId, LaneFact<CalendarTimeKindValue>)> = None;
    let mut status: Option<(EntityId, LaneFact<CalendarStatus>)> = None;
    let mut systems = Vec::new();
    let mut uids = Vec::new();
    let mut series = None;
    let mut exception = None;
    let mut series_withheld = false;
    let mut exception_withheld = false;

    for claim_id in claim_ids {
        let (body, withheld) = project(&claim_id)?;
        let Some(body) = body else {
            // A claim this lane hides still decides the projection when it is
            // one of the two single-cardinality facts, so it enters the same
            // lowest-id contest as an admitted one — as `Withheld`, never as a
            // value. Family membership is deliberately NOT set from a withheld
            // claim: an actor who can read no calendar claim on this EVENT
            // sees no calendar EVENT.
            match withheld.as_deref() {
                Some(PREDICATE_CALENDAR_ORIGIN) => {
                    replace_when_lower(&mut origin, claim_id, LaneFact::Withheld);
                }
                Some(PREDICATE_CALENDAR_TIME_KIND) => {
                    replace_when_lower(&mut time_kind, claim_id, LaneFact::Withheld);
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
    Ok(Some(CalendarEventFacts {
        origin: origin.map_or(LaneFact::Absent, |(_, fact)| fact),
        time_kind: time_kind.map_or(LaneFact::Absent, |(_, fact)| fact),
        status: status.map_or(LaneFact::Absent, |(_, fact)| fact),
        systems,
        uids,
        series,
        exception,
        series_withheld,
        exception_withheld,
    }))
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
    event_row_in(read, id, false)
}

fn event_row_in(
    read: &CalendarRead<'_>,
    id: EntityId,
    for_effects: bool,
) -> Result<Option<CalendarEventRow>> {
    let vault = read.vault();
    if matches!(read, CalendarRead::Vault(_)) {
        let txn = vault.store.env.read_txn()?;
        return event_row_in_txn(vault, &txn, id, for_effects);
    }
    let Some(header) = vault.read_entity_header(&id)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.is_deleted_shell(&id)? {
        return Ok(None);
    }
    let Some(facts) = event_facts(read, &id, for_effects)? else {
        return Ok(None);
    };
    if facts.origin().is_none() || crate::calendar::origin::invalidated(vault, id)? {
        return Ok(None);
    }
    Ok(Some(CalendarEventRow {
        id,
        occurred: if facts.utc_anchored() {
            occurred_range(&header)
        } else {
            None
        },
        facts,
    }))
}

/// Reads the operational calendar row in the caller's snapshot.
pub(crate) fn event_row_for_effect_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<CalendarEventRow>> {
    event_row_in_txn(vault, txn, id, true)
}

fn event_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    for_effects: bool,
) -> Result<Option<CalendarEventRow>> {
    let Some(header) = vault.entity_header_in_txn(txn, &id)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.port_tombstone_is_deleted(txn, &id)? {
        return Ok(None);
    }
    let Some(facts) = event_facts_in_txn(vault, txn, &id, for_effects)? else {
        return Ok(None);
    };
    if facts.origin().is_none() || crate::calendar::origin::invalidated_in_txn(vault, txn, id)? {
        return Ok(None);
    }
    Ok(Some(CalendarEventRow {
        id,
        occurred: if facts.utc_anchored() {
            occurred_range(&header)
        } else {
            None
        },
        facts,
    }))
}

/// Visits every admitted calendar EVENT in type-index order.
pub(crate) fn visit_calendar_events(
    read: &CalendarRead<'_>,
    visit: impl FnMut(CalendarEventRow) -> Result<()>,
) -> Result<()> {
    visit_calendar_events_in(read, false, visit)
}

/// Visits the calendar rows an operational projection may use.
pub(crate) fn visit_calendar_events_for_effect(
    read: &CalendarRead<'_>,
    visit: impl FnMut(CalendarEventRow) -> Result<()>,
) -> Result<()> {
    visit_calendar_events_in(read, true, visit)
}

fn visit_calendar_events_in(
    read: &CalendarRead<'_>,
    for_effects: bool,
    mut visit: impl FnMut(CalendarEventRow) -> Result<()>,
) -> Result<()> {
    for id in read.vault().entities_by_type(ENTITY_TYPE_EVENT)? {
        if let Some(row) = event_row_in(read, id, for_effects)? {
            visit(row)?;
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
