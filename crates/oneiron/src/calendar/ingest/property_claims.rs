//! Shared ICS-poll and connector property admission through their existing gates.
use crate::calendar::{claims::*, ics::ParsedVEvent};
use crate::{EntityId, Vault, claim::ClaimLifecycleStatus};
use rmpv::Value;
const OWNED: [&str; 7] = [
    PREDICATE_CALENDAR_TIME_KIND,
    PREDICATE_CALENDAR_WALL_TIME,
    PREDICATE_CALENDAR_TZ,
    PREDICATE_CALENDAR_RRULE,
    PREDICATE_CALENDAR_SERIES_MASTER,
    PREDICATE_CALENDAR_ATTENDEE,
    PREDICATE_CALENDAR_MEETING_LINK,
];

/// The new property claims one admission pass admits for one event (FIX
/// 11997). An event past it, a very large attendee set most of all, is
/// signalled, and a queued continuation admits the rest the same way;
/// nothing is refused or cut.
pub(in crate::calendar) const CALENDAR_PROPERTY_ADMISSIONS_PER_PASS: usize = 500;

pub(super) fn preflight(event: &ParsedVEvent) -> crate::Result<()> {
    for (predicate, value) in values(event) {
        validate_calendar_claim_value(predicate, &value)?;
    }
    Ok(())
}

/// Reconciles `event`'s properties from `source_prefix` on `event_ref`:
/// each value the event carries and no live claim holds is admitted through
/// `admit`, at most `budget` of them when one is given, and each live claim
/// the event no longer carries is retracted. Answers how many values past
/// the budget are still owed; a later pass over the same event admits them.
pub(in crate::calendar) fn reconcile<E: From<crate::Error>>(
    vault: &Vault,
    event_ref: EntityId,
    event: &ParsedVEvent,
    source_prefix: &str,
    now: u64,
    budget: Option<usize>,
    mut admit: impl FnMut(&str, Value) -> Result<EntityId, E>,
) -> Result<usize, E> {
    let desired = values(event);
    let mut live = Vec::new();
    for id in vault.claims_for_subject(&event_ref)? {
        if let Some(body) = vault.get_claim(&id)?
            && held_from_source(&body, source_prefix)
        {
            live.push((id, body.predicate, body.value));
        }
    }
    let (mut admitted, mut owed) = (0_usize, 0_usize);
    for (predicate, value) in &desired {
        if !live
            .iter()
            .any(|(_, pred, old)| pred == predicate && old == value)
        {
            if budget.is_some_and(|budget| admitted >= budget) {
                owed += 1;
                continue;
            }
            admit(predicate, value.clone())?;
            admitted += 1;
        }
    }
    for (id, predicate, value) in live {
        if !desired
            .iter()
            .any(|(pred, new)| *pred == predicate && *new == value)
        {
            vault.retract_claim(&id, now)?;
        }
    }
    Ok(owed)
}

/// Gives `event_ref` `zone` as its `calendar.tz` from `source_prefix` in the
/// caller's writer, as [`reconcile`] gives an all-day event the zone it
/// inherits (fix list row 19192). A live claim from that source that holds
/// `zone` stays and no second one is admitted; else `admit` admits `zone`.
/// Any other `calendar.tz` from that source is retracted, every one when
/// `zone` is `None`. No other property moves, so a newer local edit stays.
pub(in crate::calendar) fn reconcile_zone_in_txn<E: From<crate::Error>>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event_ref: EntityId,
    zone: Option<&str>,
    source_prefix: &str,
    now: u64,
    admit: impl FnOnce(&mut heed::RwTxn<'_>, &str, Value) -> Result<EntityId, E>,
) -> Result<(), E> {
    let desired = zone.map(Value::from);
    let mut held = false;
    let mut stale = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &event_ref)? {
        if let Some(body) = vault.get_claim_in_txn(txn, &id)?
            && body.predicate == PREDICATE_CALENDAR_TZ
            && held_from_source(&body, source_prefix)
        {
            if desired.as_ref() == Some(&body.value) {
                held = true;
            } else {
                stale.push(id);
            }
        }
    }
    if !held && let Some(desired) = desired {
        admit(&mut *txn, PREDICATE_CALENDAR_TZ, desired)?;
    }
    for id in stale {
        vault.retract_claim_in_txn(txn, &id, now)?;
    }
    Ok(())
}

/// Whether `body` is a live property claim that `source_prefix` admitted:
/// an imported ICS candidate whose source record starts with that prefix.
fn held_from_source(body: &crate::claim::ClaimBody, source_prefix: &str) -> bool {
    body.lifecycle == ClaimLifecycleStatus::Active
        && OWNED.contains(&body.predicate.as_str())
        && body.source == Some(crate::claim::ClaimSource::Imported)
        && body.evidence.as_ref().is_some_and(|evidence| {
            let candidate = evidence_field(
                evidence,
                crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
            );
            candidate.is_some_and(|value| {
                evidence_field(value, "kind").and_then(Value::as_str) == Some("imported_evidence")
                    && evidence_field(value, "source_id").and_then(Value::as_str)
                        == Some(crate::ingest::ICS_FEED_SOURCE_ID)
                    && evidence_field(value, "source_record_id")
                        .and_then(Value::as_str)
                        .is_some_and(|source| source.starts_with(source_prefix))
            })
        })
}

fn values(event: &ParsedVEvent) -> Vec<(&'static str, Value)> {
    let p = &event.properties;
    let mut values = Vec::new();
    if let Some(kind) = p.time_kind {
        values.push((
            PREDICATE_CALENDAR_TIME_KIND,
            Value::Map(vec![
                ("kind".into(), kind.as_str().into()),
                (
                    "busy_transparency".into(),
                    event.busy_transparency.as_str().into(),
                ),
            ]),
        ));
    }
    if let Some(wall) = p.wall_time {
        let mut fields = wall_fields(wall);
        if let Some(end) = p.wall_end {
            fields.push(("end".into(), Value::Map(wall_fields(end))));
        }
        values.push((PREDICATE_CALENDAR_WALL_TIME, Value::Map(fields)));
    }
    if let Some(zone) = &p.timezone {
        values.push((PREDICATE_CALENDAR_TZ, Value::from(zone.as_str())));
    }
    if let Some(rrule) = &p.rrule {
        values.push((PREDICATE_CALENDAR_RRULE, Value::from(rrule.as_str())));
        let all_day = p.time_kind == Some(CalendarTimeKind::AllDay);
        let seed = match event.starts_at_utc {
            Some(start) => Some((start, rrule.clone(), p.timezone.as_deref().unwrap_or("UTC"))),
            // An all-day or floating series names civil time and no instant:
            // its master steps on the UTC carrier, where its date and floating
            // recurrence ids key too (FIX 16568).
            None if all_day || p.time_kind == Some(CalendarTimeKind::Floating) => p
                .wall_time
                .and_then(crate::calendar::series::civil_start_key)
                .map(|start| {
                    (
                        start,
                        crate::calendar::series::civil_rule(rrule, all_day),
                        "UTC",
                    )
                }),
            None => None,
        };
        if let Some((start, rule, tz)) = seed {
            values.push((
                PREDICATE_CALENDAR_SERIES_MASTER,
                Value::Map(vec![
                    ("rrule".into(), rule.into()),
                    ("dtstart_utc".into(), start.into()),
                    ("tz".into(), tz.into()),
                ]),
            ));
        }
    }
    for attendee in &p.attendees {
        values.push((
            PREDICATE_CALENDAR_ATTENDEE,
            Value::Map(vec![
                ("who".into(), attendee.who.as_str().into()),
                ("role".into(), attendee.role.as_str().into()),
                ("partstat".into(), attendee.partstat.as_str().into()),
            ]),
        ));
    }
    for link in &p.meeting_links {
        values.push((PREDICATE_CALENDAR_MEETING_LINK, Value::from(link.as_str())));
    }
    values
}

/// The six civil fields of one wall time, in `calendar.wall_time` key order.
fn wall_fields(wall: CalendarWallTimeValue) -> Vec<(Value, Value)> {
    vec![
        ("y".into(), wall.y.into()),
        ("mo".into(), wall.mo.into()),
        ("d".into(), wall.d.into()),
        ("h".into(), wall.h.into()),
        ("mi".into(), wall.mi.into()),
        ("s".into(), wall.s.into()),
    ]
}

pub(in crate::calendar) fn source_prefix(system: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("calendar-source:{:x}:", Sha256::digest(system.as_bytes()))
}

fn evidence_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}
