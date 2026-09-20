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
pub(in crate::calendar) fn reconcile<E: From<crate::Error>>(
    vault: &Vault,
    event_ref: EntityId,
    event: &ParsedVEvent,
    source_prefix: &str,
    now: u64,
    mut admit: impl FnMut(&str, Value) -> Result<EntityId, E>,
) -> Result<(), E> {
    let desired = values(event);
    let mut live = Vec::new();
    for id in vault.claims_for_subject(&event_ref)? {
        if let Some(body) = vault.get_claim(&id)?
            && body.lifecycle == ClaimLifecycleStatus::Active
            && OWNED.contains(&body.predicate.as_str())
            && body.source == Some(crate::claim::ClaimSource::Imported)
            && body.evidence.as_ref().is_some_and(|evidence| {
                let candidate = evidence_field(
                    evidence,
                    crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
                );
                candidate.is_some_and(|value| {
                    evidence_field(value, "kind").and_then(Value::as_str)
                        == Some("imported_evidence")
                        && evidence_field(value, "source_id").and_then(Value::as_str)
                            == Some(crate::ingest::ICS_FEED_SOURCE_ID)
                        && evidence_field(value, "source_record_id")
                            .and_then(Value::as_str)
                            .is_some_and(|source| source.starts_with(source_prefix))
                })
            })
        {
            live.push((id, body.predicate, body.value));
        }
    }
    for (predicate, value) in &desired {
        if !live
            .iter()
            .any(|(_, pred, old)| pred == predicate && old == value)
        {
            admit(predicate, value.clone())?;
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
    Ok(())
}
fn values(event: &ParsedVEvent) -> Vec<(&'static str, Value)> {
    let p = &event.properties;
    let mut values = Vec::new();
    if let Some(kind) = p.time_kind {
        values.push((
            PREDICATE_CALENDAR_TIME_KIND,
            Value::Map(vec![
                ("kind".into(), kind.as_str().into()),
                ("busy_transparency".into(), event.busy_transparency.as_str().into()),
            ]),
        ));
    }
    if let Some(wall) = p.wall_time {
        values.push((
            PREDICATE_CALENDAR_WALL_TIME,
            Value::Map(vec![
                ("y".into(), wall.y.into()),
                ("mo".into(), wall.mo.into()),
                ("d".into(), wall.d.into()),
                ("h".into(), wall.h.into()),
                ("mi".into(), wall.mi.into()),
                ("s".into(), wall.s.into()),
            ]),
        ));
    }
    if let Some(zone) = &p.timezone {
        values.push((PREDICATE_CALENDAR_TZ, Value::from(zone.as_str())));
    }
    if let Some(rrule) = &p.rrule {
        values.push((PREDICATE_CALENDAR_RRULE, Value::from(rrule.as_str())));
        if let Some(start) = event.starts_at_utc {
            values.push((
                PREDICATE_CALENDAR_SERIES_MASTER,
                Value::Map(vec![
                    ("rrule".into(), rrule.as_str().into()),
                    ("dtstart_utc".into(), start.into()),
                    ("tz".into(), p.timezone.as_deref().unwrap_or("UTC").into()),
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

pub(super) fn source_prefix(system: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("calendar-source:{:x}:", Sha256::digest(system.as_bytes()))
}

fn evidence_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}
