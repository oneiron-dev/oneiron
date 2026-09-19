//! One UID is one remote resource: master plus every live detached exception.
use super::{outbound::ingest_error, remote::render_component, seat::CalendarConnectorError};
use crate::calendar::{claims::*, passport::live_passports_for_event};
use crate::claim::ClaimLifecycleStatus;
use crate::{EntityId, Vault};

pub(super) fn master_for(
    vault: &Vault,
    event: EntityId,
) -> Result<EntityId, CalendarConnectorError> {
    let mut master = None;
    for id in vault.claims_for_subject(&event)? {
        if let Some(body) = vault.get_claim(&id)?
            && body.lifecycle == ClaimLifecycleStatus::Active
            && body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
        {
            let value = decode_series_exception_value(&body.value)?;
            if master.is_some_and(|prior| prior != value.master_ref) {
                return Err(ingest_error("exception has conflicting masters"));
            }
            master = Some(value.master_ref);
        }
    }
    Ok(master.unwrap_or(event))
}
pub(super) fn members(
    vault: &Vault,
    master: EntityId,
    uid: &str,
) -> Result<Vec<EntityId>, CalendarConnectorError> {
    let mut children = Vec::new();
    let mut after = None;
    loop {
        let ids = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_EVENT,
            after.as_ref(),
            4096,
        )?;
        if ids.is_empty() {
            break;
        }
        for event in &ids {
            if *event == master {
                continue;
            }
            for id in vault.claims_for_subject(event)? {
                if let Some(body) = vault.get_claim(&id)?
                    && body.lifecycle == ClaimLifecycleStatus::Active
                    && body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
                {
                    let value = decode_series_exception_value(&body.value)?;
                    if value.master_ref == master && value.uid == uid {
                        children.push((value.original_start_utc, *event));
                    }
                }
            }
        }
        after = ids.last().copied();
    }
    children.sort();
    children.dedup();
    let mut result = vec![master];
    result.extend(children.into_iter().map(|(_, id)| id));
    Ok(result)
}
pub(super) fn sequence_floor(
    vault: &Vault,
    master: EntityId,
    uid: &str,
) -> Result<u32, CalendarConnectorError> {
    let mut value = 0;
    for id in members(vault, master, uid)? {
        for (_, passport) in live_passports_for_event(vault, &id)? {
            if passport.uid == uid {
                value = value.max(passport.last_sequence);
            }
        }
    }
    Ok(value)
}
pub(super) fn render(
    vault: &Vault,
    master: &EntityId,
    uid: &str,
    sequence: u32,
    now: u64,
) -> Result<Vec<u8>, CalendarConnectorError> {
    let mut out =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//calendar//EN\r\n");
    for event in members(vault, *master, uid)? {
        let rendered = String::from_utf8(render_component(vault, &event, uid, sequence, now)?)
            .map_err(|_| ingest_error("calendar renderer did not return UTF-8"))?;
        let start = rendered
            .find("BEGIN:VEVENT")
            .ok_or_else(|| ingest_error("calendar renderer omitted event"))?;
        let end = rendered
            .find("END:VEVENT")
            .ok_or_else(|| ingest_error("calendar renderer omitted event end"))?;
        out.push_str(&rendered[start..end]);
        let mut has_rrule = false;
        let mut master_rrule = None;
        for id in vault.claims_for_subject(&event)? {
            let Some(body) = vault.get_claim(&id)? else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active {
                continue;
            }
            match body.predicate.as_str() {
                PREDICATE_CALENDAR_RRULE => {
                    line(
                        &mut out,
                        "RRULE",
                        body.value
                            .as_str()
                            .ok_or_else(|| ingest_error("invalid stored RRULE"))?,
                    )?;
                    has_rrule = true;
                }
                PREDICATE_CALENDAR_SERIES_MASTER => {
                    master_rrule = Some(decode_series_master_value(&body.value)?.rrule)
                }
                PREDICATE_CALENDAR_SERIES_EXCEPTION => {
                    let value = decode_series_exception_value(&body.value)?;
                    line(
                        &mut out,
                        "RECURRENCE-ID",
                        &super::remote::format_utc(value.original_start_utc)?,
                    )?;
                }
                PREDICATE_CALENDAR_ATTENDEE => {
                    let value = decode_attendee_value(&body.value)?;
                    for param in [&value.role, &value.partstat] {
                        if param.contains(['\r', '\n', ';', ':', '"']) {
                            return Err(ingest_error(
                                "attendee parameters cannot be rendered safely",
                            ));
                        }
                    }
                    line(
                        &mut out,
                        &format!("ATTENDEE;ROLE={};PARTSTAT={}", value.role, value.partstat),
                        &value.who,
                    )?;
                }
                PREDICATE_CALENDAR_MEETING_LINK => line(
                    &mut out,
                    "URL",
                    body.value
                        .as_str()
                        .ok_or_else(|| ingest_error("invalid stored meeting link"))?,
                )?,
                _ => {}
            }
        }
        if !has_rrule && let Some(rrule) = master_rrule {
            line(&mut out, "RRULE", &rrule)?;
        }
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    Ok(out.into_bytes())
}
fn line(out: &mut String, name: &str, value: &str) -> Result<(), CalendarConnectorError> {
    if value.contains(['\r', '\n']) {
        return Err(ingest_error("calendar property contains a line break"));
    }
    out.push_str(name);
    out.push(':');
    out.push_str(value);
    out.push_str("\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resource_render_keeps_master_exception_uid_timezone_and_full_hash() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:series@test\r\nDTSTART;TZID=America/New_York:20261030T090000\r\nDTEND;TZID=America/New_York:20261030T100000\r\nRRULE:FREQ=DAILY;COUNT=5\r\nSEQUENCE:3\r\nSUMMARY:Daily\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:series@test\r\nRECURRENCE-ID;TZID=America/New_York:20261031T090000\r\nDTSTART;TZID=America/New_York:20261031T110000\r\nDTEND;TZID=America/New_York:20261031T120000\r\nSEQUENCE:4\r\nSUMMARY:Moved\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let parsed = crate::calendar::ics::parse_ics_feed(text.as_bytes()).unwrap();
        for event in &parsed.events {
            crate::calendar::ingest::admit_connector_event(
                &vault,
                "work",
                "fixture://resource",
                event,
                1_800_000_000,
            )
            .unwrap();
        }
        let master = crate::calendar::ingest::connector_event_ref(&vault, &parsed.events[0])
            .unwrap()
            .unwrap();
        let child = crate::calendar::ingest::connector_event_ref(&vault, &parsed.events[1])
            .unwrap()
            .unwrap();
        assert_eq!(master_for(&vault, child).unwrap(), master);
        assert_eq!(sequence_floor(&vault, master, "series@test").unwrap(), 4);
        let bytes = render(&vault, &master, "series@test", 5, 1_800_000_001).unwrap();
        let again = crate::calendar::ics::parse_ics_feed(&bytes).unwrap();
        assert_eq!(again.events.len(), 2);
        assert_eq!(
            again.events[0].properties.rrule,
            parsed.events[0].properties.rrule
        );
        assert_eq!(
            again.events[0].properties.timezone,
            parsed.events[0].properties.timezone
        );
        assert_eq!(
            again.events[1].properties.recurrence_id_utc,
            parsed.events[1].properties.recurrence_id_utc
        );
        let without = render_component(&vault, &master, "series@test", 5, 1_800_000_001).unwrap();
        assert_ne!(
            super::super::remote::ics_content_hash(&bytes, "series@test").unwrap(),
            super::super::remote::ics_content_hash(&without, "series@test").unwrap()
        );
    }
}
