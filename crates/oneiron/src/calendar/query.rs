//! Calendar EVENT query + projection core (CAL-09).
//!
//! There is no second calendar store: an EVENT's occurrence is the indexed UTC
//! interval already carried by its entity header (`occurred_start`/
//! `occurred_end`, the same pair `pipeline`'s temporal retrieval scores), and
//! everything calendar-specific is a `calendar.*` claim minted by CAL-00. This
//! module reads those two sources and projects them; it mints nothing.
//!
//! Read admission is the existing claim rule, not a calendar-local one. Every
//! claim this module consults passes through [`CalendarRead`], whose two arms
//! are the two lanes the engine already has:
//!
//! * [`CalendarRead::Vault`] — the internal lane. Applies
//!   [`claim_surfaceable`], so proposed, rejected, superseded, retracted, and
//!   stale claims never become calendar truth.
//! * [`CalendarRead::Scoped`] — the actor lane behind [`crate::MemoryFacade`]
//!   and every foreign surface. [`ScopedRead`] applies `claim_surfaceable`
//!   *and* the policy scoped-read grants, so an actor's calendar view can only
//!   ever be a subset of the internal one.
//!
//! Deliberately deferred: `CalendarSel.system` selection waits on CAL-02's
//! passport index (ONE-1784 lands after this ticket), and recurrence expansion
//! waits on CAL-03 (ONE-1785). Both are documented at their call sites rather
//! than faked here.

use std::io::Cursor;

use rmpv::Value;

use super::claims::{
    CalendarBusyTransparency, CalendarStatus, CalendarTimeKindValue, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND, decode_passport_value,
    decode_status_value, decode_time_kind_value, is_calendar_claim_predicate,
};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ScopedRead, claim_surfaceable, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Upper bound on one `calendar.search` page, mirroring the bounded-list
/// convention the rest of the read surface uses.
pub const MAX_CALENDAR_SEARCH_LIMIT: u32 = 200;

/// Body key an EVENT stores its display name under (`serialize.rs` EVENT
/// profile: `name`, `at`, `ppl`, `place`, `desc`).
const EVENT_BODY_NAME_KEY: &str = "name";

/// Serde-safe range DTO.
///
/// [`TimeRange`] carries no serde derives at HEAD (`crate::temporal`), so every
/// serialized calendar request shape carries this inline pair and converts to
/// `TimeRange` at the handler boundary — the same boundary that performs the
/// inclusive-to-half-open checked conversion for freebusy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarRangeDto {
    /// Inclusive start, Unix seconds.
    pub start: u64,
    /// Inclusive end, Unix seconds.
    pub end: u64,
}

impl CalendarRangeDto {
    /// Converts to the engine's inclusive [`TimeRange`].
    #[must_use]
    pub const fn to_time_range(self) -> TimeRange {
        TimeRange {
            start: self.start,
            end: self.end,
        }
    }

    /// True when the pair is a well-formed inclusive interval.
    #[must_use]
    pub const fn is_ordered(self) -> bool {
        self.start <= self.end
    }
}

/// One calendar selector.
///
/// `system` is accepted and deliberately ignored until CAL-02 (ONE-1784) lands
/// the passport index: 1791 precedes 1784 in the frontier, so filtering on a
/// selector that has no index yet would silently empty every result. An empty
/// selector slice likewise means "every calendar EVENT visible under the
/// caller's existing read scope".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarSel {
    /// Calendar system key (e.g. a passport `system`); ignored on this baseline.
    #[serde(default)]
    pub system: Option<String>,
}

/// One projected calendar EVENT.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarEventView {
    /// Hex EVENT entity id.
    pub event_ref: String,
    /// EVENT display name, when the body carries one.
    pub name: Option<String>,
    /// Inclusive UTC occurrence start; `None` when the EVENT stores no
    /// occurrence at all (both header bounds zero).
    pub start_utc: Option<u64>,
    /// Inclusive UTC occurrence end; `None` under the same condition as
    /// [`Self::start_utc`].
    pub end_utc: Option<u64>,
    /// Calendar systems this EVENT holds a passport for, sorted and deduped.
    pub calendar_systems: Vec<String>,
    /// Whether this EVENT consumes availability (the Busy-only law input).
    pub blocks_time: bool,
}

/// `calendar.read` request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarReadRequest {
    /// Hex EVENT entity id.
    pub event_ref: String,
}

/// `calendar.search` request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalendarSearchRequest {
    /// Calendar selectors; see [`CalendarSel`] for the deferred-selection rule.
    pub calendars: Vec<CalendarSel>,
    /// Inclusive UTC window; `None` means unbounded.
    pub range: Option<CalendarRangeDto>,
    /// Case-insensitive substring matched against the EVENT name.
    pub text: Option<String>,
    /// Maximum rows returned, clamped to [`MAX_CALENDAR_SEARCH_LIMIT`].
    pub limit: u32,
}

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
            Self::Vault(vault) => Ok(vault
                .get_claim(id)?
                .filter(|body| claim_surfaceable(body))),
            Self::Scoped(read) => read
                .get(id)?
                .map(|raw| decode_claim_body(&raw, true))
                .transpose(),
        }
    }
}

/// The calendar facts one EVENT's admitted claims carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CalendarEventFacts {
    time_kind: Option<CalendarTimeKindValue>,
    status: Option<CalendarStatus>,
    systems: Vec<String>,
}

impl CalendarEventFacts {
    /// Whether this EVENT consumes availability.
    ///
    /// CAL-00 mints `busy_transparency` on `calendar.time_kind` with `busy` as
    /// the default, so an EVENT that carries the family but no time-kind claim
    /// still blocks: only an explicit `free` transparency opts out.
    pub(crate) fn blocks_time(&self) -> bool {
        self.time_kind
            .is_none_or(|kind| kind.busy_transparency == CalendarBusyTransparency::Busy)
    }

    /// Whether a cancelled `calendar.status` is recorded.
    ///
    /// A1's multi-source law never deletes a cancelled EVENT, so cancellation
    /// is only representable as this claim. Freebusy therefore has to read it:
    /// leaving a cancelled EVENT in the union would force BK-00 to re-filter,
    /// which is exactly what the busy-only projection law forbids.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.status == Some(CalendarStatus::Cancelled)
    }

    pub(crate) fn systems(&self) -> &[String] {
        &self.systems
    }
}

/// One EVENT row the calendar surface admits.
pub(crate) struct CalendarEventRow {
    pub(crate) id: EntityId,
    pub(crate) occurred: TimeRange,
    pub(crate) facts: CalendarEventFacts,
}

/// Collects the calendar facts an EVENT's admitted claims carry.
///
/// Returns `None` when the entity carries no admitted `calendar.*` claim at
/// all: family membership is CAL-00's exact table, never a `calendar.` prefix
/// match, so an ordinary EVENT is not silently treated as a calendar EVENT.
fn event_facts(read: &CalendarRead<'_>, event: &EntityId) -> Result<Option<CalendarEventFacts>> {
    let mut family_member = false;
    let mut time_kind: Option<(EntityId, CalendarTimeKindValue)> = None;
    let mut status: Option<(EntityId, CalendarStatus)> = None;
    let mut systems = Vec::new();

    for claim_id in read.vault().claims_for_subject(event)? {
        let Some(body) = read.claim(&claim_id)? else {
            continue;
        };
        if !is_calendar_claim_predicate(&body.predicate) {
            continue;
        }
        family_member = true;
        match body.predicate.as_str() {
            PREDICATE_CALENDAR_TIME_KIND => {
                let value = decode_time_kind_value(&body.value)?;
                replace_when_lower(&mut time_kind, claim_id, value);
            }
            PREDICATE_CALENDAR_STATUS => {
                let value = decode_status_value(&body.value)?;
                replace_when_lower(&mut status, claim_id, value.status);
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
        time_kind: time_kind.map(|(_, value)| value),
        status: status.map(|(_, value)| value),
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
fn occurred_range(header: &EntityMetadataHeader) -> TimeRange {
    if header.occurred_start <= header.occurred_end {
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        }
    } else {
        TimeRange {
            start: header.occurred_end,
            end: header.occurred_start,
        }
    }
}

/// Rejects structurally unusable selectors.
///
/// Selection itself is deferred to CAL-02, but a blank `system` token is
/// malformed input in every future baseline, so it fails now rather than
/// becoming a silently-ignored no-op once the passport index lands.
pub(crate) fn validate_selectors(calendars: &[CalendarSel]) -> Result<()> {
    for selector in calendars {
        if selector
            .system
            .as_deref()
            .is_some_and(|system| system.trim().is_empty())
        {
            return Err(Error::InvalidKey);
        }
    }
    Ok(())
}

/// Reads one calendar EVENT through the internal lane.
pub fn read_event(vault: &Vault, req: &CalendarReadRequest) -> Result<Option<CalendarEventView>> {
    read_event_in(&CalendarRead::Vault(vault), req)
}

/// Reads one calendar EVENT through an actor's scoped-read lane.
pub fn read_event_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarReadRequest,
) -> Result<Option<CalendarEventView>> {
    read_event_in(&CalendarRead::Scoped(read), req)
}

fn read_event_in(
    read: &CalendarRead<'_>,
    req: &CalendarReadRequest,
) -> Result<Option<CalendarEventView>> {
    let id = EntityId::from_hex(req.event_ref.trim())?;
    let Some(row) = event_row(read, id)? else {
        return Ok(None);
    };
    Ok(Some(project(read.vault(), &row)?))
}

/// Searches calendar EVENTs through the internal lane.
pub fn search_events(vault: &Vault, req: &CalendarSearchRequest) -> Result<Vec<CalendarEventView>> {
    search_events_in(&CalendarRead::Vault(vault), req)
}

/// Searches calendar EVENTs through an actor's scoped-read lane.
pub fn search_events_scoped(
    read: &ScopedRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<Vec<CalendarEventView>> {
    search_events_in(&CalendarRead::Scoped(read), req)
}

fn search_events_in(
    read: &CalendarRead<'_>,
    req: &CalendarSearchRequest,
) -> Result<Vec<CalendarEventView>> {
    validate_selectors(&req.calendars)?;
    let limit = req.limit.min(MAX_CALENDAR_SEARCH_LIMIT) as usize;
    if limit == 0 {
        return Ok(Vec::new());
    }
    let range = req.range.map(CalendarRangeDto::to_time_range);
    let needle = req
        .text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_lowercase);

    let vault = read.vault();
    let mut matched = Vec::new();
    visit_calendar_events(read, |row| {
        if range.is_some_and(|range| !intersects(row.occurred, range)) {
            return Ok(());
        }
        let view = project(vault, &row)?;
        if needle.as_deref().is_some_and(|needle| !matches_text(&view, needle)) {
            return Ok(());
        }
        matched.push((row.occurred.start, row.occurred.end, row.id, view));
        Ok(())
    })?;

    matched.sort_unstable_by(|left, right| {
        (left.0, left.1, left.2).cmp(&(right.0, right.1, right.2))
    });
    matched.truncate(limit);
    Ok(matched.into_iter().map(|(_, _, _, view)| view).collect())
}

/// Inclusive-interval intersection, matching `TimeRange`'s inclusive contract.
fn intersects(event: TimeRange, window: TimeRange) -> bool {
    event.start <= window.end && event.end >= window.start
}

fn matches_text(view: &CalendarEventView, needle: &str) -> bool {
    view.name
        .as_deref()
        .is_some_and(|name| name.to_lowercase().contains(needle))
}

fn project(vault: &Vault, row: &CalendarEventRow) -> Result<CalendarEventView> {
    let anchored = row.occurred.start != 0 || row.occurred.end != 0;
    Ok(CalendarEventView {
        event_ref: row.id.to_hex(),
        name: vault.get(&row.id)?.as_deref().and_then(event_name),
        start_utc: anchored.then_some(row.occurred.start),
        end_utc: anchored.then_some(row.occurred.end),
        calendar_systems: row.facts.systems().to_vec(),
        blocks_time: row.facts.blocks_time(),
    })
}

/// Reads the EVENT body's `name` field, tolerating bodies that are not a
/// MessagePack map: the EVENT profile is app-shaped, not engine-pinned.
fn event_name(body: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(body);
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(EVENT_BODY_NAME_KEY))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::test_support::{
        CalendarEventFixture, event_name_body, open_calendar_vault,
    };

    #[test]
    fn calendar_search_filters_calendar_range_and_text() {
        let (_dir, vault) = open_calendar_vault();
        CalendarEventFixture::new(0x21, "Design review", 1_000, 2_000).store(&vault);
        CalendarEventFixture::new(0x22, "Dentist", 10_000, 11_000).store(&vault);

        let all = search_events(
            &vault,
            &CalendarSearchRequest {
                calendars: Vec::new(),
                range: None,
                text: None,
                limit: 10,
            },
        )
        .expect("search");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name.as_deref(), Some("Design review"));

        let windowed = search_events(
            &vault,
            &CalendarSearchRequest {
                calendars: Vec::new(),
                range: Some(CalendarRangeDto {
                    start: 9_000,
                    end: 12_000,
                }),
                text: None,
                limit: 10,
            },
        )
        .expect("search");
        assert_eq!(windowed.len(), 1);
        assert_eq!(windowed[0].name.as_deref(), Some("Dentist"));

        let texted = search_events(
            &vault,
            &CalendarSearchRequest {
                calendars: Vec::new(),
                range: None,
                text: Some("DESIGN".to_owned()),
                limit: 10,
            },
        )
        .expect("search");
        assert_eq!(texted.len(), 1);
        assert_eq!(texted[0].name.as_deref(), Some("Design review"));
    }

    #[test]
    fn calendar_search_bounds_limit() {
        let (_dir, vault) = open_calendar_vault();
        for (index, seed) in [0x31_u8, 0x32, 0x33, 0x34].into_iter().enumerate() {
            let start = 1_000 + index as u64 * 100;
            CalendarEventFixture::new(seed, "Standup", start, start + 10).store(&vault);
        }

        let request = |limit| CalendarSearchRequest {
            calendars: Vec::new(),
            range: None,
            text: None,
            limit,
        };
        assert_eq!(search_events(&vault, &request(2)).expect("search").len(), 2);
        assert_eq!(search_events(&vault, &request(0)).expect("search").len(), 0);
        assert_eq!(
            search_events(&vault, &request(u32::MAX))
                .expect("search")
                .len(),
            4
        );
    }

    #[test]
    fn calendar_selector_is_ignored_until_passport_index_lands() {
        let (_dir, vault) = open_calendar_vault();
        CalendarEventFixture::new(0x41, "Offsite", 1_000, 2_000).store(&vault);

        // No passport index exists on the 1791 baseline, so a selector must not
        // empty the result set (CAL-02 / ONE-1784 activates real filtering).
        let selected = search_events(
            &vault,
            &CalendarSearchRequest {
                calendars: vec![CalendarSel {
                    system: Some("google".to_owned()),
                }],
                range: None,
                text: None,
                limit: 10,
            },
        )
        .expect("search");
        assert_eq!(selected.len(), 1);

        assert!(
            validate_selectors(&[CalendarSel {
                system: Some("   ".to_owned()),
            }])
            .is_err(),
            "a blank selector token is malformed in every baseline"
        );
    }

    #[test]
    fn calendar_read_projects_only_family_events() {
        let (_dir, vault) = open_calendar_vault();
        let calendar = CalendarEventFixture::new(0x51, "Sync", 1_000, 2_000).store(&vault);
        let plain = crate::test_util::entity(0x52);
        vault
            .put_entity(
                &plain,
                ENTITY_TYPE_EVENT,
                TimeRange {
                    start: 1_000,
                    end: 2_000,
                },
                1,
                &event_name_body("Not a calendar event"),
            )
            .expect("put plain event");

        let view = read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: calendar.to_hex(),
            },
        )
        .expect("read")
        .expect("calendar event is projected");
        assert_eq!(view.name.as_deref(), Some("Sync"));
        assert_eq!(view.start_utc, Some(1_000));
        assert_eq!(view.end_utc, Some(2_000));
        assert!(view.blocks_time);

        assert!(
            read_event(
                &vault,
                &CalendarReadRequest {
                    event_ref: plain.to_hex(),
                },
            )
            .expect("read")
            .is_none(),
            "family membership is CAL-00's exact table, never a bare EVENT"
        );
    }

    #[test]
    fn calendar_surface_admits_only_surfaceable_claims() {
        let (_dir, vault) = open_calendar_vault();
        let proposed = CalendarEventFixture::new(0x53, "Pending import", 1_000, 2_000)
            .proposed()
            .store(&vault);

        assert!(
            read_event(
                &vault,
                &CalendarReadRequest {
                    event_ref: proposed.to_hex(),
                },
            )
            .expect("read")
            .is_none(),
            "an unapproved calendar claim is not calendar truth on any lane"
        );
    }
}
