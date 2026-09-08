//! Provider-neutral transport seam, change classification, and ICS render.

use serde::{Deserialize, Serialize};

use super::inbound::read_event_name;
use super::outbound::{
    CALENDAR_WRITE_OUTBOX_PREFIX, CalendarRemoteObjectRow, CalendarWriteOutboxRow,
    LOCAL_UID_DOMAIN, OUTBOX_ROW_TAG, StoredOutboxRow, ingest_error, read_outbox_row,
    read_remote_object,
};
use super::seat::CalendarConnectorError;

use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarBusyTransparency, CalendarPassportPresence, CalendarPassportValue, CalendarStatus,
    PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND, decode_status_value,
    decode_time_kind_value,
};
use crate::calendar::ics::{ParsedVEvent, parse_ics_feed};
use crate::calendar::tz::utc_to_wall;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::vault::Vault;

#[cfg(test)]
use super::outbound::{CalendarWriteAction, derive_outbox_id};
#[cfg(test)]
use super::seat::{CalendarConnectorSeatConfig, seat_identity};
#[cfg(test)]
use crate::calendar::claims::CalendarPassportDirection;

/// One remote calendar object as a provider reported it.
///
/// `uid`, `sequence`, and `content_hash` are the transport's reading. The
/// orchestration re-derives all three from `ics` through
/// [`super::ics::parse_ics_feed`] before it classifies anything, so these
/// fields are a convenience for the wire, never the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCalendarObject {
    /// Provider-side resource path.
    pub href: String,
    /// Provider ETag, when it sent one.
    pub etag: Option<String>,
    /// VEVENT UID as the provider reported it.
    pub uid: String,
    /// VEVENT SEQUENCE as the provider reported it.
    pub sequence: u32,
    /// Content hash as the provider reported it.
    pub content_hash: [u8; 32],
    /// The complete `VCALENDAR` document for this resource.
    pub ics: Vec<u8>,
}

/// One row of a provider's incremental change feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCalendarChange {
    /// The object exists remotely with this content.
    Upsert(RemoteCalendarObject),
    /// The object was removed remotely.
    Delete {
        /// Provider-side resource path.
        href: String,
        /// The VEVENT UID that resource carried.
        uid: String,
    },
}

impl RemoteCalendarChange {
    /// The UID this change concerns.
    #[must_use]
    pub fn uid(&self) -> &str {
        match self {
            Self::Upsert(object) => object.uid.as_str(),
            Self::Delete { uid, .. } => uid.as_str(),
        }
    }

    /// The provider-side resource path this change concerns.
    #[must_use]
    pub fn href(&self) -> &str {
        match self {
            Self::Upsert(object) => object.href.as_str(),
            Self::Delete { href, .. } => href.as_str(),
        }
    }
}

/// One incremental pull: the changes plus the cursor the next pull resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSyncBatch {
    /// The cursor to send on the next pull, when the provider issued one.
    pub next_cursor: Option<String>,
    /// The change rows, in provider order.
    pub changes: Vec<RemoteCalendarChange>,
}

/// One conditional remote write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWriteRequest {
    /// The resource to replace; `None` creates one.
    pub href: Option<String>,
    /// The precondition: CalDAV sends it as `If-Match`.
    pub expected_etag: Option<String>,
    /// The UID this write preserves.
    pub uid: String,
    /// The SEQUENCE this write intends.
    pub sequence: u32,
    /// The complete `VCALENDAR` document to store.
    pub ics: Vec<u8>,
}

/// What the provider stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWriteReceipt {
    /// The stored resource path.
    pub href: String,
    /// The stored resource's new ETag, when the provider sent one.
    pub etag: Option<String>,
    /// The UID that was stored.
    pub uid: String,
    /// The SEQUENCE that was stored.
    pub sequence: u32,
    /// The content hash of the stored representation.
    pub content_hash: [u8; 32],
}

/// The provider seam.
///
/// Implementations may use HTTP, WebDAV, and OAuth libraries privately. No
/// library request, response, date, timezone, or token type crosses these
/// signatures, and no method receives a credential — only the custody
/// `secret_ref` the implementation resolves at its own egress door.
pub trait CalendarRemoteTransport {
    /// Stable provider identifier, used for attempt kinds and receipts.
    fn provider_key(&self) -> &'static str;

    /// Pulls the changes after `cursor`.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::Transport`] for provider failures and
    /// [`CalendarConnectorError::CredentialUnavailable`] when custody refuses.
    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError>;

    /// Conditionally stores one VEVENT resource.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::EtagMismatch`] when the precondition fails —
    /// never an unconditional retry — plus the transport/custody variants.
    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;

    /// Conditionally removes one VEVENT resource.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::upsert`].
    fn delete(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;
}

/// What one pulled change means against the passport that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoDisposition {
    /// No passport for this `(system, uid)`: import it.
    ApplyInbound,
    /// Same-or-older SEQUENCE with the same content hash: this is our own write
    /// (or a replay) coming back. Acknowledge; rewrite nothing.
    AcknowledgeEcho,
    /// Newer SEQUENCE, or same SEQUENCE with drifted content: apply once.
    ApplyRemoteUpdate,
    /// The provider removed the resource: mark this source absent, once.
    ApplyRemoteDeletion,
}

/// The echo law, as a pure function.
///
/// SEQUENCE-first, exactly like [`super::passport::classify_passport`]: a higher
/// SEQUENCE applies, an equal SEQUENCE with a drifted hash applies, an equal
/// SEQUENCE with the same hash is an echo, and a *lower* SEQUENCE is a stale
/// replay that never regresses passport state. A passport its source previously
/// marked absent re-applies on any re-appearance.
#[must_use]
pub fn classify_remote_change(
    passport: Option<&CalendarPassportValue>,
    change: &RemoteCalendarChange,
) -> EchoDisposition {
    let object = match change {
        RemoteCalendarChange::Delete { .. } => return EchoDisposition::ApplyRemoteDeletion,
        RemoteCalendarChange::Upsert(object) => object,
    };
    let Some(passport) = passport else {
        return EchoDisposition::ApplyInbound;
    };
    if passport.presence == CalendarPassportPresence::Absent
        || object.sequence > passport.last_sequence
        || (object.sequence == passport.last_sequence
            && object.content_hash != passport.content_hash)
    {
        return EchoDisposition::ApplyRemoteUpdate;
    }
    EchoDisposition::AcknowledgeEcho
}

/// The terminal state of one connector sync run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarSyncOutcome {
    /// The run completed and the next attempt is on the queue.
    Reenqueued {
        /// The provider cursor the next run resumes from.
        next_cursor: Option<String>,
        /// The next attempt's due instant, inside the configured jitter window.
        next_not_before: u64,
        /// Semantic applications (create/attach/update through the Gate).
        applied: u32,
        /// Echo acknowledgements that rewrote nothing.
        acknowledged: u32,
        /// Passports this run flipped to `absent` for their own source only.
        source_absences: u32,
        /// EVENTs this run cancelled under the all-live-inbound-absent law.
        status_cancellations: u32,
    },
    /// The kill switch is engaged: no transport I/O ran and nothing was
    /// enqueued. Existing calendar data is untouched.
    Killed,
}

/// Parses one remote resource and returns the VEVENT it carries for `uid`.
pub(super) fn parse_remote_object(
    object: &RemoteCalendarObject,
) -> Result<ParsedVEvent, CalendarError> {
    let feed = parse_ics_feed(&object.ics)?;
    feed.events
        .iter()
        .find(|event| event.uid == object.uid)
        .or_else(|| feed.events.first())
        .cloned()
        .ok_or_else(|| CalendarError::IcsParse {
            reason: "remote calendar object carries no VEVENT".to_owned(),
        })
}

/// The canonical content hash of a rendered VEVENT, read back through the same
/// parser the pull side uses so a local write and its echo hash identically.
pub(super) fn ics_content_hash(ics: &[u8], uid: &str) -> Result<[u8; 32], CalendarError> {
    let feed = parse_ics_feed(ics)?;
    feed.events
        .iter()
        .find(|event| event.uid == uid)
        .map(|event| event.content_hash)
        .ok_or_else(|| CalendarError::IcsParse {
            reason: "rendered VEVENT did not read back".to_owned(),
        })
}

/// Renders the owner-calendar `VCALENDAR` document for one EVENT.
///
/// Private on purpose: CAL-04 owns the universal invite-out emit half in
/// [`super::ics`]. This is the minimum a conditional own-calendar PUT needs, and
/// every instant it prints crosses [`super::tz::utc_to_wall`] — the module keeps
/// no second date library and no third-party time type.
pub(super) fn render_owner_vevent(
    vault: &Vault,
    event_ref: &EntityId,
    uid: &str,
    sequence: u32,
    now: u64,
) -> Result<Vec<u8>, CalendarConnectorError> {
    let header = vault
        .read_entity_header(event_ref)?
        .ok_or_else(|| ingest_error("write target EVENT has no header"))?;
    let name = vault
        .get(event_ref)?
        .as_deref()
        .and_then(read_event_name)
        .unwrap_or_else(|| uid.to_owned());

    let mut transparency = CalendarBusyTransparency::Busy;
    let mut cancelled = false;
    for claim_id in vault.claims_for_subject(event_ref)? {
        let Some(claim) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if claim.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        if claim.predicate == PREDICATE_CALENDAR_TIME_KIND
            && let Ok(value) = decode_time_kind_value(&claim.value)
        {
            transparency = value.busy_transparency;
        }
        if claim.predicate == PREDICATE_CALENDAR_STATUS
            && let Ok(value) = decode_status_value(&claim.value)
        {
            cancelled = value.status == CalendarStatus::Cancelled;
        }
    }

    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//calendar//EN\r\nBEGIN:VEVENT\r\n",
    );
    out.push_str(&format!("UID:{}\r\n", escape_ics_text(uid)));
    out.push_str(&format!("DTSTAMP:{}\r\n", format_utc(now)?));
    out.push_str(&format!(
        "DTSTART:{}\r\n",
        format_utc(header.occurred_start)?
    ));
    out.push_str(&format!(
        "DTEND:{}\r\n",
        format_utc(header.occurred_end.max(header.occurred_start))?
    ));
    out.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    out.push_str(&format!("SUMMARY:{}\r\n", escape_ics_text(&name)));
    out.push_str(&format!(
        "TRANSP:{}\r\n",
        match transparency {
            CalendarBusyTransparency::Busy => super::claims::ICS_TRANSP_OPAQUE,
            CalendarBusyTransparency::Free => super::claims::ICS_TRANSP_TRANSPARENT,
        }
    ));
    if cancelled {
        out.push_str("STATUS:CANCELLED\r\n");
    }
    out.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    Ok(out.into_bytes())
}

/// `YYYYMMDDTHHMMSSZ` through the CAL-01 border.
fn format_utc(utc: u64) -> Result<String, CalendarError> {
    let wall = utc_to_wall(utc, "UTC")?;
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        wall.y, wall.mo, wall.d, wall.h, wall.mi, wall.s
    ))
}

/// RFC 5545 TEXT escaping for the fields this module renders.
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

/// The UID a sibling source already carries for this EVENT, lexicographically
/// smallest so every node picks the same one.
pub(super) fn shared_uid(passports: &[(EntityId, CalendarPassportValue)]) -> Option<String> {
    passports.iter().map(|(_, value)| value.uid.clone()).min()
}

/// The UID a locally originated EVENT gets on its first outbound write.
pub(super) fn local_uid(event_ref: &EntityId) -> String {
    format!("{}@{LOCAL_UID_DOMAIN}", event_ref.to_hex())
}

/// Every durable write-outbox row, in key order.
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] on store or row-decode failure.
pub fn calendar_write_outbox_rows(
    vault: &Vault,
) -> Result<Vec<CalendarWriteOutboxRow>, CalendarConnectorError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut prefix = CALENDAR_WRITE_OUTBOX_PREFIX.to_vec();
    prefix.extend_from_slice(OUTBOX_ROW_TAG);
    let mut rows = Vec::new();
    for entry in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        let (_, raw) = entry?;
        let stored: StoredOutboxRow = serde_json::from_slice(raw.as_ref())
            .map_err(|_| ingest_error("connector outbox row did not decode"))?;
        rows.push(stored.into_row()?);
    }
    Ok(rows)
}

/// One durable write-outbox row by id.
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] on store or row-decode failure.
pub fn calendar_write_outbox_row(
    vault: &Vault,
    outbox_id: &[u8; 32],
) -> Result<Option<CalendarWriteOutboxRow>, CalendarConnectorError> {
    read_outbox_row(vault, outbox_id)
}

/// The node-local href/ETag cursor for one `(system, calendar_ref, uid)`.
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] on store or row-decode failure.
pub fn calendar_remote_object_row(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    read_remote_object(vault, system, calendar_ref, uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CalendarConnectorSeatConfig {
        CalendarConnectorSeatConfig {
            seat_ref: "seat-1".to_owned(),
            secret_ref: "caldav:work".to_owned(),
            system: "caldav-work".to_owned(),
            calendar_ref: "personal".to_owned(),
            cadence_jitter_min_seconds: 300,
            cadence_jitter_max_seconds: 900,
        }
    }

    fn passport(sequence: u32, hash: [u8; 32]) -> CalendarPassportValue {
        CalendarPassportValue {
            system: "caldav-work".to_owned(),
            uid: "uid-1@example.com".to_owned(),
            last_sequence: sequence,
            content_hash: hash,
            direction: CalendarPassportDirection::TwoWay,
            last_seen_at: 1_800_000_000,
            presence: CalendarPassportPresence::Live,
        }
    }

    fn upsert(sequence: u32, hash: [u8; 32]) -> RemoteCalendarChange {
        RemoteCalendarChange::Upsert(RemoteCalendarObject {
            href: "/cal/uid-1.ics".to_owned(),
            etag: Some("etag-1".to_owned()),
            uid: "uid-1@example.com".to_owned(),
            sequence,
            content_hash: hash,
            ics: Vec::new(),
        })
    }

    #[test]
    fn echo_law_is_sequence_first_then_hash() {
        let live = passport(3, [7_u8; 32]);
        assert_eq!(
            classify_remote_change(None, &upsert(0, [7_u8; 32])),
            EchoDisposition::ApplyInbound
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(3, [7_u8; 32])),
            EchoDisposition::AcknowledgeEcho
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(2, [7_u8; 32])),
            EchoDisposition::AcknowledgeEcho,
            "a stale replay never regresses passport state"
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(3, [9_u8; 32])),
            EchoDisposition::ApplyRemoteUpdate,
            "same-SEQUENCE hash drift applies"
        );
        assert_eq!(
            classify_remote_change(Some(&live), &upsert(4, [7_u8; 32])),
            EchoDisposition::ApplyRemoteUpdate
        );

        let mut absent = passport(3, [7_u8; 32]);
        absent.presence = CalendarPassportPresence::Absent;
        assert_eq!(
            classify_remote_change(Some(&absent), &upsert(3, [7_u8; 32])),
            EchoDisposition::ApplyRemoteUpdate,
            "a source that comes back is applied, not acknowledged"
        );

        assert_eq!(
            classify_remote_change(
                Some(&live),
                &RemoteCalendarChange::Delete {
                    href: "/cal/uid-1.ics".to_owned(),
                    uid: "uid-1@example.com".to_owned(),
                }
            ),
            EchoDisposition::ApplyRemoteDeletion
        );
    }

    #[test]
    fn seat_identity_is_injective_over_colon_bearing_refs() {
        let left = CalendarConnectorSeatConfig {
            system: "a".to_owned(),
            calendar_ref: "b:c".to_owned(),
            ..config()
        };
        let right = CalendarConnectorSeatConfig {
            system: "a:b".to_owned(),
            calendar_ref: "c".to_owned(),
            ..config()
        };
        assert_ne!(
            seat_identity("caldav", &left),
            seat_identity("caldav", &right)
        );
    }

    #[test]
    fn outbox_id_is_deterministic_and_write_scoped() {
        let first = derive_outbox_id("s", "c", "uid", CalendarWriteAction::Upsert);
        assert_eq!(
            first,
            derive_outbox_id("s", "c", "uid", CalendarWriteAction::Upsert)
        );
        assert_ne!(
            first,
            derive_outbox_id("s", "c", "other", CalendarWriteAction::Upsert)
        );
        assert_ne!(
            first,
            derive_outbox_id("s", "c", "uid", CalendarWriteAction::Delete)
        );
    }

    #[test]
    fn rendered_vevent_escapes_text_and_prints_utc_through_the_border() {
        assert_eq!(escape_ics_text("a,b;c\\d"), "a\\,b\\;c\\\\d");
        assert_eq!(
            format_utc(1_786_024_800).expect("in range"),
            "20260806T140000Z"
        );
    }
}
