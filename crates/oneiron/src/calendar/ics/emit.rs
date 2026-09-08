//! ICS emit half (CAL-04, ONE-1786): meeting state into deterministic iMIP bytes.

use crate::calendar::CalendarError;

// ── emit half (CAL-04, ONE-1786) ────────────────────────────────────────
//
// The parse half above turns a foreign feed into calendar rows. This half is
// the mirror: it turns OUR meeting state into the exact `text/calendar` bytes
// an iMIP part carries. Three laws it exists to keep (ARCH-0060 §"emit law"):
//
// * **METHOD is always explicit.** Outlook treats a `VEVENT` with no
//   `METHOD:REQUEST` and no `ORGANIZER` as a brand-new event, so an implicit
//   method grows a duplicate meeting in every recipient's calendar.
// * **UID once, SEQUENCE strictly increasing.** This function does not decide
//   either — [`super::invite`] owns the transition — but it refuses to render
//   an invite with no UID, so the identity can never go out empty.
// * **The zone label is rendered, always.** A silent UTC fallback is what
//   turns "3pm Warsaw" into "3pm somewhere". Instants go out as unambiguous
//   UTC (`…Z`, which needs no `VTIMEZONE` to be read correctly by every
//   client), and the zone the meeting was scheduled in rides beside them as an
//   explicit label that is VALIDATED against the IANA database first.
/// PRODID every emitted invite carries.
pub const IMIP_PRODUCT_ID: &str = "-//oneiron//iMIP//EN";
/// Property name carrying the event's own zone label inside the VEVENT.
pub const IMIP_EVENT_TZID_PROPERTY: &str = "X-ONEIRON-TZID";
/// Upper bound on any single rendered property value.
///
/// The emitter deliberately does NOT fold at RFC 5545's 75-octet content-line
/// limit: the parse half above runs on `icalendar`'s parser, which does not
/// unfold continuation lines, so a folded document we emit is a document our
/// own ingest path cannot read back — and an invite we send is exactly what
/// comes back to us through a subscribed feed. Bounding every value instead
/// keeps lines short in practice, keeps the emit/parse pair coherent, and
/// costs nothing with real clients, which all accept unfolded lines.
const ICS_MAX_VALUE_BYTES: usize = 512;
/// One iMIP invitation to render.
///
/// Calendar-owned types only: no `icalendar` and no chrono-family type crosses
/// this signature, exactly as the parse half above keeps its parser private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImipEmitRequest {
    /// `METHOD` — explicit, never defaulted.
    pub method: super::invite::CalendarInviteMethod,
    /// `UID` — minted once by the invite layer and reused forever.
    pub uid: String,
    /// `SEQUENCE` of this revision.
    pub sequence: u32,
    /// `ORGANIZER` address, on the primary calendar domain.
    pub organizer: String,
    /// `ATTENDEE` addresses. Sorted and de-duplicated on the way out so the
    /// same invitation always renders the same bytes.
    pub attendees: Vec<String>,
    /// `SUMMARY`. Empty renders no property rather than an empty one.
    pub summary: String,
    /// `DTSTART` as UTC seconds.
    pub starts_at_utc: u64,
    /// `DTEND` as UTC seconds.
    pub ends_at_utc: u64,
    /// The IANA zone the meeting was scheduled in. Validated, never guessed.
    pub tz_label: String,
    /// `DTSTAMP` as UTC seconds. Supplied by the caller so the bytes are a
    /// pure function of the inputs — the emitter owns no clock.
    pub dtstamp_utc: u64,
}

/// Renders one deterministic iMIP `REQUEST`/`CANCEL` document.
///
/// # Errors
///
/// [`CalendarError::ImipEmit`] for a missing UID/ORGANIZER/ATTENDEE, an
/// inverted window, or a control character in a rendered value; the CAL-01
/// border errors ([`CalendarError::UnknownTimeZone`],
/// [`CalendarError::TimestampOutOfRange`]) when the zone label or an instant
/// does not resolve.
pub fn emit_imip_ics(request: &ImipEmitRequest) -> Result<Vec<u8>, CalendarError> {
    let uid = require_emit_text(&request.uid, "UID")?;
    let organizer = require_emit_text(&request.organizer, "ORGANIZER")?;
    if request.starts_at_utc > request.ends_at_utc {
        return Err(imip_emit("event window start must not exceed its end"));
    }
    let tz_label = require_emit_text(&request.tz_label, "time zone label")?;
    // Validate the label against the IANA database BEFORE anything is
    // rendered: an unknown zone is a typed refusal, never a silent UTC event.
    super::tz::utc_to_wall(request.starts_at_utc, &tz_label)?;

    let mut attendees = request
        .attendees
        .iter()
        .map(|attendee| require_emit_text(attendee, "ATTENDEE"))
        .collect::<Result<Vec<_>, _>>()?;
    attendees.sort();
    attendees.dedup();
    if attendees.is_empty() {
        return Err(imip_emit("an invitation must carry at least one ATTENDEE"));
    }

    let mut lines = vec![
        "BEGIN:VCALENDAR".to_owned(),
        "VERSION:2.0".to_owned(),
        format!("PRODID:{IMIP_PRODUCT_ID}"),
        "CALSCALE:GREGORIAN".to_owned(),
        format!("METHOD:{}", request.method.as_str()),
        format!("X-WR-TIMEZONE:{}", escape_ics_text(&tz_label)),
        "BEGIN:VEVENT".to_owned(),
        format!("UID:{}", escape_ics_text(&uid)),
        format!("SEQUENCE:{}", request.sequence),
        format!("DTSTAMP:{}", ics_utc_timestamp(request.dtstamp_utc)?),
        format!("DTSTART:{}", ics_utc_timestamp(request.starts_at_utc)?),
        format!("DTEND:{}", ics_utc_timestamp(request.ends_at_utc)?),
        format!("{IMIP_EVENT_TZID_PROPERTY}:{}", escape_ics_text(&tz_label)),
    ];
    // SUMMARY is the one optional property: an empty one renders no line at
    // all rather than an empty value, and a present one is bounded like every
    // other rendered value.
    if !request.summary.trim().is_empty() {
        let summary = require_emit_text(&request.summary, "SUMMARY")?;
        lines.push(format!("SUMMARY:{}", escape_ics_text(&summary)));
    }
    lines.push(format!("ORGANIZER:{}", mailto(&organizer)));
    for attendee in &attendees {
        lines.push(format!(
            "ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:{}",
            mailto(attendee)
        ));
    }
    lines.push(
        match request.method {
            super::invite::CalendarInviteMethod::Request => "STATUS:CONFIRMED",
            super::invite::CalendarInviteMethod::Cancel => "STATUS:CANCELLED",
        }
        .to_owned(),
    );
    lines.push("END:VEVENT".to_owned());
    lines.push("END:VCALENDAR".to_owned());

    let mut out = String::new();
    for line in &lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

/// Stores one rendered invitation as a blob-artifact version and returns the
/// `blob:<hex>` reference the frozen payload carries.
///
/// The artifact store is called, never re-implemented: the append is the
/// existing single-transaction content-addressed write, so re-persisting
/// byte-identical `.ics` output is a dedupe no-op that returns the same head.
/// This is what keeps raw `.ics` bytes out of the frozen outbound body — only
/// the returned reference ever travels.
///
/// # Errors
///
/// [`CalendarError::ImipEmit`] when the artifact cannot be created or
/// appended.
pub fn persist_imip_blob(
    vault: &crate::Vault,
    artifact_id: &crate::entity_id::EntityId,
    name: &str,
    ics: &[u8],
    provenance: &crate::blob_artifact::BlobVersionProvenance,
    actor: crate::write_envelope::WriteActor,
    occurred_at: u64,
) -> Result<String, CalendarError> {
    let occurred = crate::temporal::TimeRange {
        start: occurred_at,
        end: occurred_at,
    };
    if vault
        .get_blob_artifact(artifact_id)
        .map_err(|err| imip_emit(format!("blob artifact read failed: {err}")))?
        .is_none()
    {
        vault
            .put_blob_artifact(
                artifact_id,
                &crate::blob_artifact::BlobArtifactBody::new(
                    name,
                    super::invite::CALENDAR_INVITE_MEDIA_TYPE,
                ),
                occurred,
                occurred_at,
            )
            .map_err(|err| imip_emit(format!("blob artifact create failed: {err}")))?;
    }
    vault
        .append_blob_artifact_version(artifact_id, ics, provenance, actor, occurred, occurred_at)
        .map_err(|err| imip_emit(format!("blob artifact append failed: {err}")))?;
    Ok(format!("blob:{}", artifact_id.to_hex()))
}

/// `YYYYMMDDTHHMMSSZ`, through the CAL-01 border rather than a second
/// datetime implementation.
fn ics_utc_timestamp(utc: u64) -> Result<String, CalendarError> {
    let wall = super::tz::utc_to_wall(utc, "UTC")?;
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        wall.y, wall.mo, wall.d, wall.h, wall.mi, wall.s
    ))
}

/// RFC 5545 TEXT escaping: backslash, semicolon, comma, and newlines.
fn escape_ics_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

/// `mailto:` is the iTIP CAL-ADDRESS form; an address that already carries a
/// scheme is left alone.
fn mailto(address: &str) -> String {
    if address.contains(':') {
        return escape_ics_text(address);
    }
    format!("mailto:{}", escape_ics_text(address))
}

/// Bounded, control-free, non-blank: a rendered value that carries a raw CR/LF
/// would forge a property line.
fn require_emit_text(value: &str, field: &'static str) -> Result<String, CalendarError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(imip_emit(format!("{field} must not be blank")));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(imip_emit(format!("{field} must not contain controls")));
    }
    if trimmed.len() > ICS_MAX_VALUE_BYTES {
        return Err(imip_emit(format!(
            "{field} exceeds {ICS_MAX_VALUE_BYTES} bytes"
        )));
    }
    Ok(trimmed.to_owned())
}

fn imip_emit(reason: impl Into<String>) -> CalendarError {
    CalendarError::ImipEmit {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── emit half (CAL-04) ──────────────────────────────────────────────

    use crate::calendar::ics::parse_ics_feed;
    use crate::calendar::invite::CalendarInviteMethod;

    fn emit_request(method: CalendarInviteMethod, sequence: u32) -> ImipEmitRequest {
        ImipEmitRequest {
            method,
            uid: "one-1786@oneiron.test".to_owned(),
            sequence,
            organizer: "me@primary.test".to_owned(),
            // Deliberately unsorted and duplicated: the emitter normalizes.
            attendees: vec![
                "zoe@example.test".to_owned(),
                "guest@example.test".to_owned(),
                "guest@example.test".to_owned(),
            ],
            summary: "Design review, take 2".to_owned(),
            starts_at_utc: 1_800_003_600,
            ends_at_utc: 1_800_007_200,
            tz_label: "Europe/Warsaw".to_owned(),
            dtstamp_utc: 1_800_000_000,
        }
    }

    #[test]
    fn emit_imip_request_is_deterministic() {
        let request = emit_request(CalendarInviteMethod::Request, 0);
        let bytes = emit_imip_ics(&request).expect("emit");
        assert_eq!(bytes, emit_imip_ics(&request).expect("emit again"));

        let text = String::from_utf8(bytes).expect("utf-8");
        // METHOD/UID/SEQUENCE/ORGANIZER are explicit: Outlook reads a VEVENT
        // without them as a NEW event, which is a duplicate meeting.
        assert!(text.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(text.contains("METHOD:REQUEST\r\n"));
        assert!(text.contains("UID:one-1786@oneiron.test\r\n"));
        assert!(text.contains("SEQUENCE:0\r\n"));
        assert!(text.contains("ORGANIZER:mailto:me@primary.test\r\n"));
        assert!(text.contains("STATUS:CONFIRMED\r\n"));
        assert!(text.ends_with("END:VCALENDAR\r\n"));
        // The zone label is rendered ALWAYS — never a silent UTC fallback.
        assert!(text.contains("X-WR-TIMEZONE:Europe/Warsaw\r\n"));
        assert!(text.contains("X-ONEIRON-TZID:Europe/Warsaw\r\n"));
        // Instants stay unambiguous UTC so no VTIMEZONE is needed to read them.
        assert!(text.contains("DTSTART:20270115T090000Z\r\n"), "{text}");
        assert!(text.contains("DTEND:20270115T100000Z\r\n"), "{text}");
        assert!(text.contains("DTSTAMP:20270115T080000Z\r\n"), "{text}");
        // TEXT escaping is applied, and attendees are sorted + de-duplicated.
        assert!(text.contains("SUMMARY:Design review\\, take 2\r\n"));
        assert_eq!(text.matches("ATTENDEE;").count(), 2);
        let guest = text.find("ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:guest@example.test").expect("guest");
        let zoe = text.find("ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:zoe@example.test").expect("zoe");
        assert!(guest < zoe);

        // The emitted document round-trips through this module's own parser.
        let parsed = parse_ics_feed(text.as_bytes()).expect("emitted feed parses");
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].uid, "one-1786@oneiron.test");
        assert_eq!(parsed.events[0].sequence, 0);
        assert_eq!(parsed.events[0].starts_at_utc, Some(1_800_003_600));
    }

    #[test]
    fn emit_imip_cancel_is_deterministic() {
        let request = emit_request(CalendarInviteMethod::Cancel, 3);
        let bytes = emit_imip_ics(&request).expect("emit");
        assert_eq!(bytes, emit_imip_ics(&request).expect("emit again"));
        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(text.contains("METHOD:CANCEL\r\n"));
        assert!(text.contains("SEQUENCE:3\r\n"));
        assert!(text.contains("STATUS:CANCELLED\r\n"));
        // Same UID as the REQUEST it withdraws: a cancel never regenerates one.
        assert!(text.contains("UID:one-1786@oneiron.test\r\n"));
        assert!(parse_ics_feed(text.as_bytes()).expect("parses").events[0].cancelled);
    }

    #[test]
    fn emit_refuses_a_silent_utc_fallback_and_malformed_values() {
        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.tz_label = "   ".to_owned();
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::ImipEmit { .. })
        ));

        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.tz_label = "Mars/Olympus_Mons".to_owned();
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::UnknownTimeZone { .. })
        ));

        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.uid = String::new();
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::ImipEmit { .. })
        ));

        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.attendees.clear();
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::ImipEmit { .. })
        ));

        // A raw newline would forge a property line.
        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.organizer = "me@primary.test\r\nATTENDEE:mailto:evil@example.test".to_owned();
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::ImipEmit { .. })
        ));

        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.ends_at_utc = request.starts_at_utc - 1;
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::ImipEmit { .. })
        ));
    }

    /// The emitter does not fold, on purpose: `icalendar`'s parser — the one
    /// the ingest half above runs on — does not unfold continuation lines, so a
    /// folded invite is one our own feed ingest cannot read back. Values are
    /// bounded instead, and an over-long one is a typed refusal rather than a
    /// silently truncated invitation.
    #[test]
    fn long_values_stay_unfolded_and_round_trip_or_refuse() {
        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.summary = "x".repeat(300);
        let text = String::from_utf8(emit_imip_ics(&request).expect("emit")).expect("utf-8");
        assert!(text.contains(&format!("SUMMARY:{}\r\n", "x".repeat(300))));
        let parsed = parse_ics_feed(text.as_bytes()).expect("emitted feed parses");
        assert_eq!(
            parsed.events[0].summary.as_deref(),
            Some("x".repeat(300).as_str())
        );

        let mut request = emit_request(CalendarInviteMethod::Request, 0);
        request.summary = "x".repeat(ICS_MAX_VALUE_BYTES + 1);
        assert!(matches!(
            emit_imip_ics(&request),
            Err(CalendarError::ImipEmit { .. })
        ));
    }
}
