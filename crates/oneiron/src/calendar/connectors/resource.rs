//! One UID is one remote resource: master plus every live detached exception.
use super::{outbound::ingest_error, remote::render_component, seat::CalendarConnectorError};
use crate::calendar::{claims::*, passport::admitted_passports_for_event_in_txn};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::derived_domains::CALENDAR_CONNECTOR_SOURCE_BLOB;
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
/// The highest SEQUENCE an admitted passport on any member records for `uid`.
///
/// Outbound authority: a pending, rejected or stale passport proposal never
/// raises the SEQUENCE a write carries.
pub(super) fn sequence_floor(
    vault: &Vault,
    master: EntityId,
    uid: &str,
) -> Result<u32, CalendarConnectorError> {
    let member_ids = members(vault, master, uid)?;
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut value = 0;
    for id in member_ids {
        for (_, passport) in admitted_passports_for_event_in_txn(vault, &rtxn, &id)? {
            if passport.uid == uid {
                value = value.max(passport.last_sequence);
            }
        }
    }
    Ok(value)
}
/// The bytes and per-EVENT hashes captured by the same resource render.
pub(super) struct RenderedResource {
    pub(super) ics: Vec<u8>,
    pub(super) component_hashes: Vec<(EntityId, [u8; 32])>,
}

/// Renders the resource for `uid` from the EVENT claims, over `source`.
///
/// `source` is the archived ICS this resource was last read from. Each member
/// keeps every property and nested component its source VEVENT carried that
/// the render does not own (`OWNED_PROPERTIES`): DESCRIPTION, LOCATION,
/// ORGANIZER, `X-*` fields and alarms survive a write-back unchanged, and only
/// the owned fields are replaced from the claims.
pub(super) fn render(
    vault: &Vault,
    master: &EntityId,
    uid: &str,
    sequence: u32,
    now: u64,
    source: Option<&[u8]>,
) -> Result<RenderedResource, CalendarConnectorError> {
    let member_ids = members(vault, *master, uid)?;
    let sources = match source {
        Some(bytes) => source_components(bytes)?,
        None => Vec::new(),
    };
    let mut out =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//calendar//EN\r\n");
    for &event in &member_ids {
        let rendered = String::from_utf8(render_component(vault, &event, uid, sequence, now)?)
            .map_err(|_| ingest_error("calendar renderer did not return UTF-8"))?;
        let start = rendered
            .find("\r\nBEGIN:VEVENT\r\n")
            .map(|at| at + 2)
            .ok_or_else(|| ingest_error("calendar renderer omitted event"))?;
        let end = rendered
            .find("\r\nEND:VEVENT\r\n")
            .map(|at| at + 2)
            .ok_or_else(|| ingest_error("calendar renderer omitted event end"))?;
        out.push_str(&rendered[start..end]);
        let mut has_rrule = false;
        let mut master_rrule = None;
        let mut recurrence_id = None;
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
                    master_rrule = Some(decode_series_master_value(&body.value)?.rrule);
                }
                PREDICATE_CALENDAR_SERIES_EXCEPTION => {
                    let value = decode_series_exception_value(&body.value)?;
                    line(
                        &mut out,
                        "RECURRENCE-ID",
                        &super::remote::format_utc(value.original_start_utc)?,
                    )?;
                    recurrence_id = Some(value.original_start_utc);
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
        if let Some(kept) = sources
            .iter()
            .find(|kept| kept.uid == uid && kept.recurrence_id_utc == recurrence_id)
        {
            for kept_line in kept.properties.iter().chain(&kept.components) {
                out.push_str(kept_line);
                out.push_str("\r\n");
            }
        }
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    let ics = out.into_bytes();
    let parsed = crate::calendar::ics::parse_ics_feed(&ics)?;
    if parsed.events.len() != member_ids.len() {
        return Err(ingest_error("rendered resource does not match its members"));
    }
    let component_hashes = member_ids
        .into_iter()
        .zip(parsed.events.into_iter().map(|event| event.content_hash))
        .collect();
    Ok(RenderedResource {
        ics,
        component_hashes,
    })
}
/// Properties the render writes from the EVENT claims; a source line under
/// any of these names is replaced, never repeated. `DURATION` is owned because
/// the render always states the end as `DTEND`.
const OWNED_PROPERTIES: [&str; 13] = [
    "UID",
    "DTSTAMP",
    "DTSTART",
    "DTEND",
    "DURATION",
    "SEQUENCE",
    "SUMMARY",
    "TRANSP",
    "STATUS",
    "RRULE",
    "RECURRENCE-ID",
    "ATTENDEE",
    "URL",
];

/// One VEVENT of an archived source, as the render keeps it.
struct SourceComponent {
    uid: String,
    recurrence_id_utc: Option<u64>,
    /// The VEVENT's own content lines the render does not own, verbatim and
    /// unfolded, in source order.
    properties: Vec<String>,
    /// Its nested components (`VALARM`), BEGIN to END, verbatim.
    components: Vec<String>,
}

/// Splits an archived ICS into its top-level VEVENTs, keeping each one's raw
/// content lines. Lines are kept as written rather than re-rendered from the
/// parsed tree, whose TEXT values are already decoded; each VEVENT's identity
/// comes from the same strict parse every pulled resource crosses.
fn source_components(ics: &[u8]) -> Result<Vec<SourceComponent>, CalendarConnectorError> {
    let text = std::str::from_utf8(ics)
        .map_err(|_| ingest_error("archived calendar source is not UTF-8"))?;
    let unfolded = icalendar::parser::unfold(text);
    let mut open: Vec<String> = Vec::new();
    let mut blocks: Vec<(Vec<&str>, Vec<&str>)> = Vec::new();
    let mut current: Option<(Vec<&str>, Vec<&str>)> = None;
    for raw in unfolded.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let upper = raw.trim_end().to_ascii_uppercase();
        if let Some(name) = upper.strip_prefix("BEGIN:") {
            if current.is_none() && name == "VEVENT" && open.len() == 1 && open[0] == "VCALENDAR" {
                current = Some((Vec::new(), Vec::new()));
            } else if let Some((_, nested)) = current.as_mut() {
                nested.push(raw);
            }
            open.push(name.to_owned());
        } else if let Some(name) = upper.strip_prefix("END:") {
            open.pop();
            if current.is_some() && open.len() == 1 && name == "VEVENT" {
                blocks.extend(current.take());
            } else if let Some((_, nested)) = current.as_mut() {
                nested.push(raw);
            }
        } else if let Some((own, nested)) = current.as_mut() {
            if open.len() == 2 {
                own.push(raw);
            } else {
                nested.push(raw);
            }
        }
    }
    let mut components = Vec::with_capacity(blocks.len());
    for (own, nested) in blocks {
        let mut identity = String::from("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n");
        for raw in &own {
            identity.push_str(raw);
            identity.push_str("\r\n");
        }
        identity.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
        let parsed = crate::calendar::ics::parse_ics_feed(identity.as_bytes())?;
        let [event] = parsed.events.as_slice() else {
            return Err(ingest_error(
                "archived calendar source has a malformed VEVENT",
            ));
        };
        components.push(SourceComponent {
            uid: event.uid.clone(),
            recurrence_id_utc: event.properties.recurrence_id_utc,
            properties: own
                .into_iter()
                .filter(|raw| !OWNED_PROPERTIES.contains(&property_name(raw).as_str()))
                .map(str::to_owned)
                .collect(),
            components: nested.into_iter().map(str::to_owned).collect(),
        });
    }
    Ok(components)
}

/// The upper-cased name of one content line: everything before its first
/// parameter or value separator.
fn property_name(raw: &str) -> String {
    raw.split([';', ':'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase()
}

/// Archives the ICS one connector pull returned for `(system, calendar_ref,
/// uid)`: one BLOB_ARTIFACT per resource, one version per distinct body, so a
/// later write renders over the copy the remote holds. Returns the `hex#vN`
/// reference the remote-object row keeps.
pub(super) fn archive_remote_source(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
    ics: &[u8],
    now: u64,
) -> Result<String, CalendarConnectorError> {
    let artifact_id = EntityId::derive(
        CALENDAR_CONNECTOR_SOURCE_BLOB,
        &[system.as_bytes(), calendar_ref.as_bytes(), uid.as_bytes()],
    )?;
    let at = crate::TimeRange {
        start: now,
        end: now,
    };
    if vault.get_blob_artifact(&artifact_id)?.is_none() {
        vault.put_blob_artifact(
            &artifact_id,
            &crate::blob_artifact::BlobArtifactBody::new(
                format!("calendar-connector:{system}"),
                "text/calendar",
            ),
            at,
            now,
        )?;
    }
    let actor = crate::calendar::ingest::ensure_ics_import_actor(vault, now)?;
    let version = vault.append_blob_artifact_version(
        &artifact_id,
        ics,
        &crate::blob_artifact::BlobVersionProvenance::AgentRun {
            run_ref: format!("calendar-connector:{}", artifact_id.to_hex()),
        },
        crate::WriteActor::new(actor, crate::edge::EdgeActorClass::System),
        at,
        now,
    )?;
    Ok(format!("{}#v{}", artifact_id.to_hex(), version.version))
}

/// The archived source a write of `uid` renders over: the copy this seat last
/// pulled for that UID, else the archived ICS feed version a live passport on
/// `master` cites. `None` when neither exists.
pub(super) fn archived_source(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
    master: EntityId,
) -> Result<Option<Vec<u8>>, CalendarConnectorError> {
    if let Some(blob_ref) = super::outbound::read_remote_object(vault, system, calendar_ref, uid)?
        .and_then(|row| row.source_blob_ref)
        && let Some(bytes) = read_blob_ref(vault, &blob_ref)?
    {
        return Ok(Some(bytes));
    }
    for id in vault.claims_for_subject(&master)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active
            || body.predicate != PREDICATE_CALENDAR_PASSPORT
            || decode_passport_value(&body.value)?.uid != uid
        {
            continue;
        }
        // Feed admissions cite `hex#vN:uid`, the archived feed version.
        let cited = body
            .evidence
            .as_ref()
            .and_then(|evidence| {
                map_field(
                    evidence,
                    crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
                )
            })
            .and_then(|candidate| map_field(candidate, "source_record_id"))
            .and_then(rmpv::Value::as_str)
            .and_then(|record| record.strip_suffix(uid)?.strip_suffix(':'));
        if let Some(blob_ref) = cited
            && let Some(bytes) = read_blob_ref(vault, blob_ref)?
        {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

/// Reads the blob version a `hex#vN` reference names; `None` for any other
/// shape or a version that is not stored.
fn read_blob_ref(vault: &Vault, blob_ref: &str) -> Result<Option<Vec<u8>>, CalendarConnectorError> {
    let Some((hex, version)) = blob_ref.split_once("#v") else {
        return Ok(None);
    };
    let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(hex), version.parse::<u64>()) else {
        return Ok(None);
    };
    Ok(vault.read_blob_artifact_version(&artifact_id, version)?)
}

fn map_field<'a>(value: &'a rmpv::Value, name: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
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
