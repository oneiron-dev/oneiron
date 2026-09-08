//! Lane admission and fail-closed fact reduction.

use crate::batch::EntityMetadataHeader;
use crate::calendar::claims::{
    CalendarBusyTransparency, CalendarStatus, CalendarTimeKindValue, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND, decode_passport_value,
    decode_status_value, decode_time_kind_value, is_calendar_claim_predicate,
};
use crate::claim::{ClaimBody, ScopedRead, claim_surfaceable, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::Result;
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
    /// Actor lane used by every SDK/MCP surface.
    Scoped(&'a ScopedRead<'a>),
}

impl<'a> CalendarRead<'a> {
    /// The underlying vault.
    #[must_use]
    pub fn vault(&self) -> &'a Vault {
        match self {
            Self::Vault(vault) => vault,
            Self::Scoped(read) => read.vault(),
        }
    }

    /// Reads one claim through this lane, or `None` when the lane does not
    /// admit it.
    fn claim(&self, id: &EntityId) -> Result<Option<ClaimBody>> {
        match self {
            Self::Vault(vault) => Ok(vault.get_claim(id)?.filter(claim_surfaceable)),
            Self::Scoped(read) => read
                .get(id)?
                .map(|raw| decode_claim_body(&raw, true))
                .transpose(),
        }
    }

    /// The predicate of a claim this lane hid but the internal lane admits.
    ///
    /// This is exactly the divergence set between the two lanes. `None` on the
    /// internal lane, which hides nothing from itself, and `None` for a claim
    /// that is not surfaceable at all — that one is absent on *both* lanes, so
    /// it cannot make the projections disagree. Only the predicate is read: a
    /// withheld claim's value never reaches the projection, it only forces the
    /// decision sites to fail closed.
    fn withheld_predicate(&self, id: &EntityId) -> Result<Option<String>> {
        match self {
            Self::Vault(_) => Ok(None),
            Self::Scoped(read) => Ok(read
                .vault()
                .get_claim(id)?
                .filter(claim_surfaceable)
                .map(|body| body.predicate)),
        }
    }
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
pub(crate) struct CalendarEventFacts {
    time_kind: LaneFact<CalendarTimeKindValue>,
    status: LaneFact<CalendarStatus>,
    systems: Vec<String>,
}

impl CalendarEventFacts {
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
    pub(crate) facts: CalendarEventFacts,
}

/// Collects the calendar facts an EVENT's admitted claims carry.
///
/// Returns `None` when the entity carries no admitted `calendar.*` claim at
/// all: family membership is CAL-00's exact table, never a `calendar.` prefix
/// match, so an ordinary EVENT is not silently treated as a calendar EVENT.
fn event_facts(read: &CalendarRead<'_>, event: &EntityId) -> Result<Option<CalendarEventFacts>> {
    let mut family_member = false;
    let mut time_kind: Option<(EntityId, LaneFact<CalendarTimeKindValue>)> = None;
    let mut status: Option<(EntityId, LaneFact<CalendarStatus>)> = None;
    let mut systems = Vec::new();

    for claim_id in read.vault().claims_for_subject(event)? {
        let Some(body) = read.claim(&claim_id)? else {
            // A claim this lane hides still decides the projection when it is
            // one of the two single-cardinality facts, so it enters the same
            // lowest-id contest as an admitted one — as `Withheld`, never as a
            // value. Family membership is deliberately NOT set from a withheld
            // claim: an actor who can read no calendar claim on this EVENT
            // sees no calendar EVENT.
            match read.withheld_predicate(&claim_id)?.as_deref() {
                Some(PREDICATE_CALENDAR_TIME_KIND) => {
                    replace_when_lower(&mut time_kind, claim_id, LaneFact::Withheld);
                }
                Some(PREDICATE_CALENDAR_STATUS) => {
                    replace_when_lower(&mut status, claim_id, LaneFact::Withheld);
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
            PREDICATE_CALENDAR_TIME_KIND => {
                let value = decode_time_kind_value(&body.value)?;
                replace_when_lower(&mut time_kind, claim_id, LaneFact::Read(value));
            }
            PREDICATE_CALENDAR_STATUS => {
                let value = decode_status_value(&body.value)?;
                replace_when_lower(&mut status, claim_id, LaneFact::Read(value.status));
            }
            PREDICATE_CALENDAR_PASSPORT => {
                systems.push(decode_passport_value(&body.value)?.system);
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
        time_kind: time_kind.map_or(LaneFact::Absent, |(_, fact)| fact),
        status: status.map_or(LaneFact::Absent, |(_, fact)| fact),
        systems,
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
pub(crate) fn event_row(read: &CalendarRead<'_>, id: EntityId) -> Result<Option<CalendarEventRow>> {
    let vault = read.vault();
    let Some(header) = vault.read_entity_header(&id)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.is_deleted_shell(&id)? {
        return Ok(None);
    }
    let Some(facts) = event_facts(read, &id)? else {
        return Ok(None);
    };
    Ok(Some(CalendarEventRow {
        id,
        occurred: occurred_range(&header),
        facts,
    }))
}

/// Visits every admitted calendar EVENT in type-index order.
pub(crate) fn visit_calendar_events(
    read: &CalendarRead<'_>,
    mut visit: impl FnMut(CalendarEventRow) -> Result<()>,
) -> Result<()> {
    for id in read.vault().entities_by_type(ENTITY_TYPE_EVENT)? {
        if let Some(row) = event_row(read, id)? {
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
