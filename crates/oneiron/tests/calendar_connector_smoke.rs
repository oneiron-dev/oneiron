//! CAL-05 connector smoke oracle (ONE-1787).
//!
//! Pins the CalDAV + Google-Internal connector laws end to end at the public
//! boundary, offline, over scripted wires:
//!
//! 1. **ICS truth over transport truth.** UID/SEQUENCE/hash come from parsing
//!    the resource body, so these fixtures let the wire report honestly and
//!    the engine re-derive everything.
//! 2. **The echo law.** A same-or-older SEQUENCE with the same content hash
//!    is an acknowledgement; drift applies once; a local write's return is
//!    never re-emitted.
//! 3. **Multi-source law.** Remote deletion marks only its own source absent;
//!    the EVENT cancels only when every live inbound passport reports absence.
//! 4. **Conditional writes.** The durable outbox row lands BEFORE the remote
//!    call, `If-Match` rides as the precondition, and a mismatch reconciles —
//!    never an unconditional overwrite.
//! 5. **Custody.** Configs carry SECRET custody `secret_ref` names only. The
//!    canary test proves credential bytes never appear in config, cursor,
//!    attempt payload, `Debug`, error, receipt, outbox, claim, or EVENT bytes.
//!
//! Vault setup follows the CAL-02 oracle precedent: unseeded vaults, except
//! the cross-gate and custody tests, which run on the seeded default manifest
//! on purpose.

mod common;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use common::entity;

use oneiron::calendar::caldav::{
    CALDAV_PROVIDER_KEY, CalDavConnector, CalDavDiscovery, CalDavWire, caldav_write_status_error,
};
use oneiron::calendar::claims::{
    CalendarPassportDirection, CalendarPassportPresence, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND,
};
use oneiron::calendar::connectors::{
    CALDAV_SYNC_ATTEMPT_KIND, CalendarConnectorError, CalendarConnectorSeatConfig,
    CalendarConnectorSeatState, CalendarConnectorSyncPayload, CalendarRemoteTransport,
    CalendarSyncOutcome, CalendarWriteAction, CalendarWriteOutboxState, RemoteCalendarChange,
    RemoteCalendarObject, RemoteSyncBatch, RemoteWriteReceipt, RemoteWriteRequest,
    calendar_remote_object_row, calendar_sync_attempt_kind, calendar_write_outbox_rows,
    run_calendar_connector_sync, write_calendar_event,
};
use oneiron::calendar::google_internal::{
    GOOGLE_INTERNAL_PROVIDER_KEY, GoogleInternalConnector, GoogleInternalWire,
};
use oneiron::calendar::passport::{live_passports_for_event, resolve_event_by_uid};
use oneiron::calendar::{
    CalendarError, PREDICATE_CALENDAR_EVENT_OUTCOME, WallTime, parse_ics_feed, utc_to_wall,
    wall_to_utc,
};
use oneiron::ingest::ICS_FEED_SOURCE_ID;
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimLifecycleStatus, ClaimOutcome, ClaimSource,
    CompleteAttempt, EntityId, TimeRange, Vault, VaultConfig,
};

/// Fixed run instants.
const T0: u64 = 1_800_000_000;
const T1: u64 = 1_800_000_100;
const T2: u64 = 1_800_000_200;
const T3: u64 = 1_800_000_300;

/// A fixed, in-range occurrence window for written EVENT fixtures.
const WRITE_START: u64 = 1_786_024_800;
const WRITE_END: u64 = 1_786_028_400;

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// One VEVENT in a fixture body.
struct EventSpec {
    uid: &'static str,
    sequence: u32,
    summary: &'static str,
    transp: Option<&'static str>,
    cancelled: bool,
    dtstart: Option<&'static str>,
    dtend: Option<&'static str>,
    dtstart_tzid: Option<&'static str>,
    dtend_tzid: Option<&'static str>,
}

impl EventSpec {
    fn new(uid: &'static str, sequence: u32) -> Self {
        Self {
            uid,
            sequence,
            summary: "standup",
            transp: None,
            cancelled: false,
            dtstart: None,
            dtend: None,
            dtstart_tzid: None,
            dtend_tzid: None,
        }
    }
}

/// Builds a complete VCALENDAR body with a fixed DTSTAMP (excluded from the
/// content hash, so fixture variation stays explicit in the specs).
fn body(events: &[EventSpec]) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for event in events {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{}\r\n", event.uid));
        out.push_str("DTSTAMP:20260805T100000Z\r\n");
        match event.dtstart_tzid {
            Some(tzid) => out.push_str(&format!(
                "DTSTART;TZID={tzid}:{}\r\n",
                event.dtstart.unwrap_or("20260806T140000")
            )),
            None => out.push_str(&format!(
                "DTSTART:{}\r\n",
                event.dtstart.unwrap_or("20260806T140000Z")
            )),
        }
        match event.dtend_tzid {
            Some(tzid) => out.push_str(&format!(
                "DTEND;TZID={tzid}:{}\r\n",
                event.dtend.unwrap_or("20260806T150000")
            )),
            None => out.push_str(&format!(
                "DTEND:{}\r\n",
                event.dtend.unwrap_or("20260806T150000Z")
            )),
        }
        out.push_str(&format!("SEQUENCE:{}\r\n", event.sequence));
        out.push_str(&format!("SUMMARY:{}\r\n", event.summary));
        if let Some(transp) = event.transp {
            out.push_str(&format!("TRANSP:{transp}\r\n"));
        }
        if event.cancelled {
            out.push_str("STATUS:CANCELLED\r\n");
        }
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    out.into_bytes()
}

/// One remote upsert row whose reported UID/SEQUENCE/hash are read back out of
/// the ICS body itself — the same parse the engine performs before classifying.
fn remote_upsert(href: &str, etag: Option<&str>, ics: &[u8]) -> RemoteCalendarObject {
    let feed = parse_ics_feed(ics).expect("fixture ics parses");
    let event = feed.events.first().expect("fixture carries a VEVENT");
    RemoteCalendarObject {
        href: href.to_owned(),
        etag: etag.map(str::to_owned),
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
        ics: ics.to_vec(),
    }
}

/// A one-upsert pull batch.
fn upsert_batch(
    next_cursor: Option<&str>,
    ics: Vec<u8>,
    href: &str,
    etag: Option<&str>,
) -> RemoteSyncBatch {
    RemoteSyncBatch {
        next_cursor: next_cursor.map(str::to_owned),
        changes: vec![RemoteCalendarChange::Upsert(remote_upsert(href, etag, &ics))],
    }
}

/// A one-deletion pull batch.
fn delete_batch(next_cursor: Option<&str>, href: &str, uid: &str) -> RemoteSyncBatch {
    RemoteSyncBatch {
        next_cursor: next_cursor.map(str::to_owned),
        changes: vec![RemoteCalendarChange::Delete {
            href: href.to_owned(),
            uid: uid.to_owned(),
        }],
    }
}

/// The receipt one honest wire returns for a conditional put: every field read
/// back through the ICS parse, so the echo the pull side later sees hashes
/// identically by construction.
fn parsed_receipt(
    calendar_href: &str,
    etag: Option<&str>,
    request: &RemoteWriteRequest,
) -> RemoteWriteReceipt {
    let feed = parse_ics_feed(&request.ics).expect("written ics parses");
    let event = feed
        .events
        .iter()
        .find(|event| event.uid == request.uid)
        .or_else(|| feed.events.first())
        .expect("written ics carries a VEVENT");
    RemoteWriteReceipt {
        href: request
            .href
            .clone()
            .unwrap_or_else(|| format!("{calendar_href}{}.ics", event.uid)),
        etag: etag.map(str::to_owned),
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
    }
}

// ---------------------------------------------------------------------------
// Vault + seat helpers
// ---------------------------------------------------------------------------

/// An unseeded vault: this oracle measures the connector's laws, not the
/// default policy manifest's calendar coverage.
fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), cfg).expect("open vault");
    (dir, vault)
}

/// A seeded vault carrying the shipped default policy manifest.
fn temp_vault_seeded() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    (dir, vault)
}

/// The CalDAV seat config this oracle reuses.
fn caldav_config() -> CalendarConnectorSeatConfig {
    CalendarConnectorSeatConfig {
        seat_ref: "seat:caldav:work".to_owned(),
        secret_ref: "caldav:work".to_owned(),
        system: "caldav-work".to_owned(),
        calendar_ref: "work".to_owned(),
        cadence_jitter_min_seconds: 300,
        cadence_jitter_max_seconds: 900,
    }
}

/// The CalDAV seat, cursor-free and live.
fn caldav_seat() -> CalendarConnectorSeatState {
    CalendarConnectorSeatState::new(caldav_config())
}

/// The Workspace-Internal Google seat config this oracle reuses. The custody
/// name carries the dogfood class prefix or the transport refuses it.
fn google_config() -> CalendarConnectorSeatConfig {
    CalendarConnectorSeatConfig {
        seat_ref: "seat:google:dogfood".to_owned(),
        secret_ref: "google-internal:dogfood".to_owned(),
        system: "google-internal".to_owned(),
        calendar_ref: "primary".to_owned(),
        cadence_jitter_min_seconds: 300,
        cadence_jitter_max_seconds: 900,
    }
}

/// The Google seat, cursor-free and live.
fn google_seat() -> CalendarConnectorSeatState {
    CalendarConnectorSeatState::new(google_config())
}

/// Mints one local EVENT row directly, the state a locally originated write
/// starts from: entity plus no calendar claims yet.
fn mint_local_event(vault: &Vault, seed: u8, name: &str) -> EntityId {
    let id = entity(seed);
    let mut data = Vec::new();
    rmpv::encode::write_value(
        &mut data,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .expect("encode event body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: WRITE_START,
                end: WRITE_END,
            },
            T0,
            &data,
        )
        .expect("put local event");
    id
}

// ---------------------------------------------------------------------------
// Scripted wires (offline fixtures)
// ---------------------------------------------------------------------------

/// One scripted put outcome: either a literal result, or an honest receipt
/// whose UID/SEQUENCE/hash are parsed back out of the request body.
enum PutScript {
    Literal(Result<RemoteWriteReceipt, CalendarConnectorError>),
    AcceptWithEtag(String),
}

/// A scripted CalDAV wire: queued responses, every call recorded. Provider
/// protocol details are exactly what this seam is for, so the stub records
/// `secret_ref` custody NAMES and never sees a credential.
#[derive(Default)]
struct StubCalDavWire {
    discovery: Mutex<Option<CalDavDiscovery>>,
    secret_refs: Mutex<Vec<String>>,
    sync_cursors: Mutex<Vec<Option<String>>>,
    sync_responses: Mutex<VecDeque<Result<RemoteSyncBatch, CalendarConnectorError>>>,
    put_requests: Mutex<Vec<RemoteWriteRequest>>,
    put_scripts: Mutex<VecDeque<PutScript>>,
    delete_calls: Mutex<Vec<(String, Option<String>, String, u32)>>,
}

impl StubCalDavWire {
    fn stub_discovery() -> CalDavDiscovery {
        CalDavDiscovery {
            principal_href: "/principals/stub/".to_owned(),
            calendar_home_href: "/calendars/stub/".to_owned(),
            calendar_href: "/calendars/stub/main/".to_owned(),
        }
    }

    fn queue_sync(&self, response: Result<RemoteSyncBatch, CalendarConnectorError>) {
        self.sync_responses
            .lock()
            .expect("sync responses")
            .push_back(response);
    }

    fn queue_put(&self, script: PutScript) {
        self.put_scripts
            .lock()
            .expect("put scripts")
            .push_back(script);
    }

    fn secret_refs(&self) -> Vec<String> {
        self.secret_refs.lock().expect("secret refs").clone()
    }

    fn sync_cursors(&self) -> Vec<Option<String>> {
        self.sync_cursors.lock().expect("sync cursors").clone()
    }

    fn put_requests(&self) -> Vec<RemoteWriteRequest> {
        self.put_requests.lock().expect("put requests").clone()
    }

    fn delete_calls(&self) -> Vec<(String, Option<String>, String, u32)> {
        self.delete_calls.lock().expect("delete calls").clone()
    }
}

impl CalDavWire for StubCalDavWire {
    fn discover(
        &self,
        secret_ref: &str,
        _calendar_ref: &str,
    ) -> Result<CalDavDiscovery, CalendarConnectorError> {
        self.secret_refs
            .lock()
            .expect("secret refs")
            .push(secret_ref.to_owned());
        Ok(self
            .discovery
            .lock()
            .expect("discovery")
            .clone()
            .unwrap_or_else(Self::stub_discovery))
    }

    fn sync_collection(
        &self,
        _secret_ref: &str,
        _discovery: &CalDavDiscovery,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        self.sync_cursors
            .lock()
            .expect("sync cursors")
            .push(sync_token.map(str::to_owned));
        self.sync_responses
            .lock()
            .expect("sync responses")
            .pop_front()
            .unwrap_or_else(|| {
                Ok(RemoteSyncBatch {
                    next_cursor: None,
                    changes: Vec::new(),
                })
            })
    }

    fn put_vevent(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.put_requests
            .lock()
            .expect("put requests")
            .push(request.clone());
        match self
            .put_scripts
            .lock()
            .expect("put scripts")
            .pop_front()
            .unwrap_or_else(|| PutScript::AcceptWithEtag("v-put-1".to_owned()))
        {
            PutScript::Literal(result) => result,
            PutScript::AcceptWithEtag(etag) => Ok(parsed_receipt(
                &discovery.calendar_href,
                Some(&etag),
                request,
            )),
        }
    }

    fn delete_vevent(
        &self,
        _secret_ref: &str,
        _discovery: &CalDavDiscovery,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.delete_calls.lock().expect("delete calls").push((
            href.to_owned(),
            expected_etag.map(str::to_owned),
            uid.to_owned(),
            sequence,
        ));
        Ok(RemoteWriteReceipt {
            href: href.to_owned(),
            etag: None,
            uid: uid.to_owned(),
            sequence,
            content_hash: [0_u8; 32],
        })
    }
}

/// A scripted Google-Internal wire: same offline posture, REST-shaped calls.
#[derive(Default)]
struct StubGoogleInternalWire {
    secret_refs: Mutex<Vec<String>>,
    list_cursors: Mutex<Vec<Option<String>>>,
    list_responses: Mutex<VecDeque<Result<RemoteSyncBatch, CalendarConnectorError>>>,
    upsert_requests: Mutex<Vec<RemoteWriteRequest>>,
    upsert_scripts: Mutex<VecDeque<PutScript>>,
    delete_calls: Mutex<Vec<(String, Option<String>, String, u32)>>,
}

impl StubGoogleInternalWire {
    fn queue_list(&self, response: Result<RemoteSyncBatch, CalendarConnectorError>) {
        self.list_responses
            .lock()
            .expect("list responses")
            .push_back(response);
    }

    fn list_cursors(&self) -> Vec<Option<String>> {
        self.list_cursors.lock().expect("list cursors").clone()
    }

    fn upsert_requests(&self) -> Vec<RemoteWriteRequest> {
        self.upsert_requests.lock().expect("upsert requests").clone()
    }

    fn delete_calls(&self) -> Vec<(String, Option<String>, String, u32)> {
        self.delete_calls.lock().expect("delete calls").clone()
    }
}

impl GoogleInternalWire for StubGoogleInternalWire {
    fn list_changes(
        &self,
        secret_ref: &str,
        _calendar_ref: &str,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        self.secret_refs
            .lock()
            .expect("secret refs")
            .push(secret_ref.to_owned());
        self.list_cursors
            .lock()
            .expect("list cursors")
            .push(sync_token.map(str::to_owned));
        self.list_responses
            .lock()
            .expect("list responses")
            .pop_front()
            .unwrap_or_else(|| {
                Ok(RemoteSyncBatch {
                    next_cursor: None,
                    changes: Vec::new(),
                })
            })
    }

    fn upsert_event(
        &self,
        _secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.upsert_requests
            .lock()
            .expect("upsert requests")
            .push(request.clone());
        match self
            .upsert_scripts
            .lock()
            .expect("upsert scripts")
            .pop_front()
            .unwrap_or_else(|| PutScript::AcceptWithEtag("g-etag-put".to_owned()))
        {
            PutScript::Literal(result) => result,
            PutScript::AcceptWithEtag(etag) => Ok(parsed_receipt(
                &format!("calendars/{calendar_ref}/events/"),
                Some(&etag),
                request,
            )),
        }
    }

    fn delete_event(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.delete_calls.lock().expect("delete calls").push((
            href.to_owned(),
            expected_etag.map(str::to_owned),
            uid.to_owned(),
            sequence,
        ));
        Ok(RemoteWriteReceipt {
            href: href.to_owned(),
            etag: None,
            uid: uid.to_owned(),
            sequence,
            content_hash: [0_u8; 32],
        })
    }
}

// ---------------------------------------------------------------------------
// Run + claim readers
// ---------------------------------------------------------------------------

/// One connector sync run with the oracle's fixed jitter seed.
fn run_sync(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    now: u64,
) -> CalendarSyncOutcome {
    run_calendar_connector_sync(vault, seat, transport, now, 7).expect("connector sync")
}

/// Destructures a `Reenqueued` outcome's counters.
fn counters(
    outcome: &CalendarSyncOutcome,
) -> (u32, u32, u32, u32) {
    let CalendarSyncOutcome::Reenqueued {
        applied,
        acknowledged,
        source_absences,
        status_cancellations,
        ..
    } = outcome
    else {
        panic!("expected a re-enqueued run, got {outcome:?}");
    };
    (*applied, *acknowledged, *source_absences, *status_cancellations)
}

/// Claims on one EVENT as `(id, body)` pairs, in storage order.
fn claims_on(vault: &Vault, event: &EntityId) -> Vec<(EntityId, oneiron::ClaimBody)> {
    vault
        .claims_for_subject(event)
        .expect("claims for subject")
        .into_iter()
        .map(|id| {
            let body = vault
                .get_claim(&id)
                .expect("get claim")
                .expect("claim exists");
            (id, body)
        })
        .collect()
}

/// Live claims on one EVENT with one predicate.
fn live_claims<'a>(
    claims: &'a [(EntityId, oneiron::ClaimBody)],
    predicate: &str,
) -> Vec<&'a (EntityId, oneiron::ClaimBody)> {
    claims
        .iter()
        .filter(|(_, body)| {
            body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .collect()
}

/// Reads a field out of a claim value's MessagePack map.
fn value_field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

/// The live `calendar.status` claim's `(status, basis, recorded_at)`, if any.
fn live_status(vault: &Vault, event: &EntityId) -> Option<(String, String, u64)> {
    let claims = claims_on(vault, event);
    let live = live_claims(&claims, PREDICATE_CALENDAR_STATUS);
    match live.as_slice() {
        [] => None,
        [(_, body)] => {
            let status = value_field(&body.value, "status")
                .and_then(rmpv::Value::as_str)
                .expect("status token");
            let basis = value_field(&body.value, "basis")
                .and_then(rmpv::Value::as_str)
                .expect("basis token");
            let recorded_at = value_field(&body.value, "recorded_at")
                .and_then(rmpv::Value::as_u64)
                .expect("recorded_at");
            Some((status.to_owned(), basis.to_owned(), recorded_at))
        }
        _ => panic!("at most one live calendar.status claim per EVENT"),
    }
}

/// The live `calendar.time_kind` claim's `(kind, busy_transparency, key-set)`.
fn live_time_kind(vault: &Vault, event: &EntityId) -> (String, String, BTreeSet<String>) {
    let claims = claims_on(vault, event);
    let live = live_claims(&claims, PREDICATE_CALENDAR_TIME_KIND);
    assert_eq!(live.len(), 1, "one live calendar.time_kind claim");
    let rmpv::Value::Map(entries) = &live[0].1.value else {
        panic!("time-kind value is a map");
    };
    let keys = entries
        .iter()
        .filter_map(|(key, _)| key.as_str().map(str::to_owned))
        .collect();
    let kind = value_field(&live[0].1.value, "kind")
        .and_then(rmpv::Value::as_str)
        .expect("kind token")
        .to_owned();
    let transparency = value_field(&live[0].1.value, "busy_transparency")
        .and_then(rmpv::Value::as_str)
        .expect("busy_transparency token")
        .to_owned();
    (kind, transparency, keys)
}

/// Pending connector sync attempt rows of one kind.
fn pending_connector_rows(vault: &Vault, kind: &str) -> Vec<oneiron::AttemptRecord> {
    AttemptQueue::new(vault)
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|record| record.kind == kind)
        .filter(|record| {
            matches!(
                record.state,
                AttemptState::Queued | AttemptState::Leased | AttemptState::Scheduled
            )
        })
        .collect()
}

/// Claims + completes every pending attempt row, modeling the host worker so
/// the next run's re-enqueue mints exactly one next-generation row.
fn drain_pending_attempts(vault: &Vault, now: u64) {
    let queue = AttemptQueue::new(vault);
    while let Ok(ClaimOutcome::Claimed(record)) = queue.claim(ClaimAttempt {
        lease_owner: "test-worker".to_owned(),
        now,
    }) {
        queue
            .complete(CompleteAttempt {
                id: record.id,
                lease_owner: "test-worker".to_owned(),
                attempt_count: record.attempt_count,
                now,
            })
            .expect("complete attempt");
    }
}

// ---------------------------------------------------------------------------
// Custody canaries
// ---------------------------------------------------------------------------

const CALDAV_CANARY: &str = "CANARY-APPPW-4f2a91c8";
const GOOGLE_CANARY: &str = "CANARY-OATOKEN-91bb47d3";

/// Asserts one observable surface carries no credential canary.
fn assert_custody_clean(label: &str, surface: &str) {
    assert!(
        !surface.contains(CALDAV_CANARY),
        "{label} leaked the CalDAV canary"
    );
    assert!(
        !surface.contains(GOOGLE_CANARY),
        "{label} leaked the Google canary"
    );
}

/// Registers a custody record whose VALUE is `canary`, following the CAL-02
/// oracle's body-codec fixture: the value field is crate-private by design, so
/// the fixture encodes the record through the one public codec and lets the
/// store decode it — the same door the manifest flow uses.
fn register_secret_canary(vault: &Vault, name: &str, canary: &str) {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:calendar-smoke")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (
            Value::from("scopes"),
            Value::Array(vec![Value::from("read")]),
        ),
    ]);
    let record_body = Value::Map(vec![
        (Value::from("schema_version"), Value::from(1_u64)),
        (Value::from("name"), Value::from(name)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(canary.as_bytes().to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &record_body).expect("encode custody body");
    let record =
        oneiron::secret_custody::decode_secret_custody_body(&bytes).expect("decode custody body");
    vault.register_secret(record).expect("register canary secret");
}

// ---------------------------------------------------------------------------
// 1. Keystone types are concrete
// ---------------------------------------------------------------------------

#[test]
fn calendar_connector_error_and_sync_outcome_are_concrete() {
    // Every declared error variant constructs, displays, and matches.
    let from_calendar = CalendarConnectorError::from(CalendarError::IcsParse {
        reason: "truncated feed".to_owned(),
    });
    assert!(
        matches!(from_calendar, CalendarConnectorError::Calendar(_)),
        "CalendarError converts into the shared home"
    );
    assert_eq!(from_calendar.to_string(), "ICS feed parse failure: truncated feed");

    let invalid = CalendarConnectorError::InvalidSeatConfig("seat_ref must be non-empty and bounded");
    assert_eq!(
        invalid.to_string(),
        "invalid calendar connector seat config: seat_ref must be non-empty and bounded"
    );
    let killed = CalendarConnectorError::KillSwitchEngaged;
    assert_eq!(killed.to_string(), "calendar connector kill switch is engaged");
    let credential = CalendarConnectorError::CredentialUnavailable {
        secret_ref: "caldav:work".to_owned(),
    };
    assert_eq!(
        credential.to_string(),
        "calendar connector credential unavailable: caldav:work",
        "the custody error names the ref and nothing else"
    );
    let transport = CalendarConnectorError::Transport {
        provider: CALDAV_PROVIDER_KEY,
        operation: "pull",
        detail: "connection reset".to_owned(),
    };
    assert_eq!(
        transport.to_string(),
        "calendar provider caldav pull failed: connection reset"
    );
    let mismatch = CalendarConnectorError::EtagMismatch {
        href: "/cal/1.ics".to_owned(),
        expected: Some("v1".to_owned()),
        actual: Some("v2".to_owned()),
    };
    assert_eq!(mismatch.to_string(), "calendar ETag mismatch for /cal/1.ics");
    let outbox = CalendarConnectorError::Outbox {
        outbox_id: [9_u8; 32],
        detail: "row did not decode".to_owned(),
    };
    let rendered = outbox.to_string();
    assert!(rendered.contains("calendar connector outbox"));
    assert!(rendered.contains("row did not decode"));

    // A seat whose window is degenerate fails validation with the typed
    // variant, not a panic or a silent clamp.
    let bad = CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        cadence_jitter_min_seconds: 0,
        ..caldav_config()
    });
    assert!(matches!(
        bad.validate(),
        Err(CalendarConnectorError::InvalidSeatConfig(_))
    ));

    // Both sync outcomes construct and match — neither is signature-only.
    let reenqueued = CalendarSyncOutcome::Reenqueued {
        next_cursor: Some("tok-1".to_owned()),
        next_not_before: T0 + 300,
        applied: 2,
        acknowledged: 1,
        source_absences: 0,
        status_cancellations: 0,
    };
    let CalendarSyncOutcome::Reenqueued {
        next_cursor,
        next_not_before,
        applied,
        acknowledged,
        ..
    } = &reenqueued
    else {
        panic!("constructed outcome must match its variant");
    };
    assert_eq!(next_cursor.as_deref(), Some("tok-1"));
    assert_eq!(*next_not_before, T0 + 300);
    assert_eq!((*applied, *acknowledged), (2, 1));
    let killed_outcome = CalendarSyncOutcome::Killed;
    assert!(matches!(killed_outcome, CalendarSyncOutcome::Killed));
    assert_ne!(reenqueued, killed_outcome);
}

// ---------------------------------------------------------------------------
// 2. One CalDAV client class, three provider fixtures
// ---------------------------------------------------------------------------

/// A tiny precondition-checking in-memory CalDAV server per provider fixture.
/// The engine type stays one `CalDavConnector`; provider shape differences
/// live here, behind the wire, exactly where the blueprint parks them.
struct MiniProvider {
    discovery: CalDavDiscovery,
    objects: BTreeMap<String, (String, Vec<u8>)>,
    sync_token: String,
}

struct MiniCalDavServer {
    providers: Mutex<BTreeMap<String, MiniProvider>>,
    ops: Mutex<Vec<(String, String)>>,
}

impl MiniCalDavServer {
    fn new() -> Self {
        let fixtures = [
            (
                "icloud-home",
                CalDavDiscovery {
                    principal_href: "/1844210563/principal/".to_owned(),
                    calendar_home_href: "/1844210563/calendars/".to_owned(),
                    calendar_href: "/1844210563/calendars/home/".to_owned(),
                },
                "/1844210563/calendars/home/mini-icloud.ics",
                "\"icloud-c4-etag\"",
                "mini-icloud@x",
                "token-icloud-1",
            ),
            (
                "fastmail-work",
                CalDavDiscovery {
                    principal_href: "/principals/u123456/".to_owned(),
                    calendar_home_href: "/dav/calendars/user/u123456/".to_owned(),
                    calendar_href: "/dav/calendars/user/u123456/work/".to_owned(),
                },
                "/dav/calendars/user/u123456/work/mini-fastmail.ics",
                "\"fme-abc123\"",
                "mini-fastmail@x",
                "token-fastmail-1",
            ),
            (
                "radicale-calendar",
                CalDavDiscovery {
                    principal_href: "/alice/principal/".to_owned(),
                    calendar_home_href: "/alice/".to_owned(),
                    calendar_href: "/alice/calendar.ics/".to_owned(),
                },
                "/alice/calendar.ics/mini-radicale.ics",
                "\"radicale-etag-9\"",
                "mini-radicale@x",
                "token-radicale-1",
            ),
        ];
        let mut providers = BTreeMap::new();
        for (calendar_ref, discovery, href, etag, uid, token) in fixtures {
            let mut objects = BTreeMap::new();
            objects.insert(
                href.to_owned(),
                (etag.to_owned(), body(&[EventSpec::new(uid, 1)])),
            );
            providers.insert(
                calendar_ref.to_owned(),
                MiniProvider {
                    discovery,
                    objects,
                    sync_token: token.to_owned(),
                },
            );
        }
        Self {
            providers: Mutex::new(providers),
            ops: Mutex::new(Vec::new()),
        }
    }

    fn ops(&self) -> Vec<(String, String)> {
        self.ops.lock().expect("ops").clone()
    }

    fn op_counts(&self, provider: &str, op: &str) -> usize {
        self.ops()
            .into_iter()
            .filter(|(entry_op, entry_ref)| entry_op == op && entry_ref == provider)
            .count()
    }

    fn provider_ref_for_home(providers: &BTreeMap<String, MiniProvider>, home: &str) -> String {
        providers
            .iter()
            .find(|(_, provider)| provider.discovery.calendar_href == home)
            .map(|(calendar_ref, _)| calendar_ref.clone())
            .expect("a provider owns the discovered collection")
    }
}

impl CalDavWire for MiniCalDavServer {
    fn discover(
        &self,
        _secret_ref: &str,
        calendar_ref: &str,
    ) -> Result<CalDavDiscovery, CalendarConnectorError> {
        self.ops
            .lock()
            .expect("ops")
            .push(("discover".to_owned(), calendar_ref.to_owned()));
        let providers = self.providers.lock().expect("providers");
        providers
            .get(calendar_ref)
            .map(|provider| provider.discovery.clone())
            .ok_or_else(|| CalendarConnectorError::Transport {
                provider: CALDAV_PROVIDER_KEY,
                operation: "discover",
                detail: "unknown collection".to_owned(),
            })
    }

    fn sync_collection(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        let mut providers = self.providers.lock().expect("providers");
        let calendar_ref = Self::provider_ref_for_home(&providers, &discovery.calendar_href);
        self.ops
            .lock()
            .expect("ops")
            .push(("sync".to_owned(), calendar_ref.clone()));
        let provider = providers.get_mut(&calendar_ref).expect("provider");
        let current = provider.sync_token.clone();
        if sync_token == Some(current.as_str()) {
            // An unchanged token is a true incremental no-op.
            return Ok(RemoteSyncBatch {
                next_cursor: Some(current),
                changes: Vec::new(),
            });
        }
        let changes = provider
            .objects
            .iter()
            .map(|(href, (etag, ics))| {
                RemoteCalendarChange::Upsert(remote_upsert(href, Some(etag), ics))
            })
            .collect();
        Ok(RemoteSyncBatch {
            next_cursor: Some(current),
            changes,
        })
    }

    fn put_vevent(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let mut providers = self.providers.lock().expect("providers");
        let calendar_ref = Self::provider_ref_for_home(&providers, &discovery.calendar_href);
        self.ops
            .lock()
            .expect("ops")
            .push(("put".to_owned(), calendar_ref.clone()));
        let provider = providers.get_mut(&calendar_ref).expect("provider");
        let href = request
            .href
            .clone()
            .unwrap_or_else(|| format!("{}{}.ics", discovery.calendar_href, request.uid));
        if let Some((current_etag, _)) = provider.objects.get(&href)
            && current_etag.as_str() != request.expected_etag.as_deref().unwrap_or("")
        {
            // The precondition failed: reconcile, never overwrite blind.
            return Err(caldav_write_status_error(
                412,
                "put",
                &href,
                request.expected_etag.as_deref(),
                Some(current_etag),
            )
            .expect("412 carries the mismatch"));
        }
        let new_etag = format!("{}-next", request.expected_etag.as_deref().unwrap_or("fresh"));
        provider
            .objects
            .insert(href.clone(), (new_etag.clone(), request.ics.clone()));
        Ok(parsed_receipt(
            &discovery.calendar_href,
            Some(&new_etag),
            request,
        ))
    }

    fn delete_vevent(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let mut providers = self.providers.lock().expect("providers");
        let calendar_ref = Self::provider_ref_for_home(&providers, &discovery.calendar_href);
        self.ops
            .lock()
            .expect("ops")
            .push(("delete".to_owned(), calendar_ref.clone()));
        let provider = providers.get_mut(&calendar_ref).expect("provider");
        let Some((current_etag, _)) = provider.objects.get(href) else {
            return Err(caldav_write_status_error(412, "delete", href, expected_etag, None)
                .expect("412 carries the mismatch"));
        };
        if Some(current_etag.as_str()) != expected_etag {
            return Err(caldav_write_status_error(
                412,
                "delete",
                href,
                expected_etag,
                Some(current_etag),
            )
            .expect("412 carries the mismatch"));
        }
        provider.objects.remove(href);
        Ok(RemoteWriteReceipt {
            href: href.to_owned(),
            etag: None,
            uid: uid.to_owned(),
            sequence,
            content_hash: [0_u8; 32],
        })
    }
}

#[test]
fn caldav_icloud_fastmail_radicale_fixtures_share_one_client() {
    // The shared conditional-status classifier answers exactly the contract.
    assert!(caldav_write_status_error(204, "put", "/x", None, None).is_none());

    let server = MiniCalDavServer::new();
    let connector = CalDavConnector::new(server);
    let providers = ["icloud-home", "fastmail-work", "radicale-calendar"];
    let uids = ["mini-icloud@x", "mini-fastmail@x", "mini-radicale@x"];

    for (provider, uid) in providers.iter().zip(uids.iter()) {
        // One engine seat-config shape for every provider in the class — no
        // provider-specific credential field exists to vary.
        let config = CalendarConnectorSeatConfig {
            seat_ref: format!("seat:{provider}"),
            secret_ref: format!("caldav:{provider}-app-password"),
            system: provider.to_string(),
            calendar_ref: provider.to_string(),
            cadence_jitter_min_seconds: 300,
            cadence_jitter_max_seconds: 900,
        };
        let keys: BTreeSet<String> = serde_json::to_value(&config)
            .expect("config serializes")
            .as_object()
            .expect("config is a map")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "seat_ref".to_owned(),
                "secret_ref".to_owned(),
                "system".to_owned(),
                "calendar_ref".to_owned(),
                "cadence_jitter_min_seconds".to_owned(),
                "cadence_jitter_max_seconds".to_owned(),
            ]),
            "the engine model has exactly the custody-name seat shape"
        );

        // Discovery resolves the provider's principal → home → collection.
        let discovery = connector
            .discover(&config.secret_ref, &config.calendar_ref)
            .expect("discovery");
        assert!(discovery.principal_href.ends_with('/'));
        assert!(!discovery.calendar_home_href.is_empty());
        assert!(!discovery.calendar_href.is_empty());

        // Initial sync-token pull lists the fixture resource.
        let initial = connector
            .pull(&config.secret_ref, &config.calendar_ref, None)
            .expect("initial pull");
        assert_eq!(initial.changes.len(), 1);
        let token = initial.next_cursor.clone().expect("sync token issued");
        let RemoteCalendarChange::Upsert(object) = &initial.changes[0] else {
            panic!("fixture lists an upsert");
        };
        let (href, etag) = (
            object.href.clone(),
            object.etag.clone().expect("fixture carries an ETag"),
        );
        assert_eq!(&object.uid, uid);

        // Resuming with the unchanged token is an incremental no-op.
        let resumed = connector
            .pull(&config.secret_ref, &config.calendar_ref, Some(&token))
            .expect("resume pull");
        assert!(resumed.changes.is_empty(), "unchanged token yields nothing");

        // Conditional PUT with the current ETag stores and bumps the ETag.
        let updated = connector
            .upsert(
                &config.secret_ref,
                &config.calendar_ref,
                &RemoteWriteRequest {
                    href: Some(href.clone()),
                    expected_etag: Some(etag.clone()),
                    uid: uid.to_string(),
                    sequence: 2,
                    ics: body(&[EventSpec::new(uid, 2)]),
                },
            )
            .expect("conditional put");
        let new_etag = updated.etag.clone().expect("receipt ETag");
        assert_ne!(new_etag, etag, "the store ETag updates on write");
        assert_eq!(updated.uid, *uid, "the write preserves the UID");

        // A stale precondition is a typed mismatch, never a blind overwrite.
        let stale_put = connector.upsert(
            &config.secret_ref,
            &config.calendar_ref,
            &RemoteWriteRequest {
                href: Some(href.clone()),
                expected_etag: Some(etag.clone()),
                uid: uid.to_string(),
                sequence: 3,
                ics: body(&[EventSpec::new(uid, 3)]),
            },
        );
        let (expected, actual) = match stale_put {
            Err(CalendarConnectorError::EtagMismatch {
                expected, actual, ..
            }) => (expected, actual),
            other => panic!("stale precondition must reconcile, got {other:?}"),
        };
        assert_eq!(expected.as_deref(), Some(etag.as_str()));
        assert_eq!(actual.as_deref(), Some(new_etag.as_str()));

        // Conditional DELETE: stale precondition rejected, current accepted.
        let stale_delete = connector.delete(
            &config.secret_ref,
            &config.calendar_ref,
            &href,
            Some(&etag),
            uid,
            2,
        );
        assert!(matches!(
            stale_delete,
            Err(CalendarConnectorError::EtagMismatch { .. })
        ));
        connector
            .delete(
                &config.secret_ref,
                &config.calendar_ref,
                &href,
                Some(&new_etag),
                uid,
                2,
            )
            .expect("conditional delete");
        let after = connector
            .pull(&config.secret_ref, &config.calendar_ref, Some("stale-token"))
            .expect("post-delete full sync");
        assert!(after.changes.is_empty(), "the resource is really gone");
    }

    // One client: the same connector instance served all three provider
    // fixtures, each seeing its own discover/sync/put/delete call sequence.
    for provider in providers {
        // discover + sync + (discover+sync) + put + put + delete + delete +
        // (discover+sync): discovery runs before every provider operation.
        assert_eq!(connector.wire().op_counts(provider, "discover"), 8);
        assert_eq!(connector.wire().op_counts(provider, "sync"), 3);
        assert_eq!(connector.wire().op_counts(provider, "put"), 2);
        assert_eq!(connector.wire().op_counts(provider, "delete"), 2);
    }
}

// ---------------------------------------------------------------------------
// 3. Sync-token resume is idempotent
// ---------------------------------------------------------------------------

#[test]
fn caldav_sync_token_resume_is_idempotent() {
    let (_dir, vault) = temp_vault();
    let wire = StubCalDavWire::default();
    wire.queue_sync(Ok(upsert_batch(
        Some("tok-resume-1"),
        body(&[EventSpec::new("uid-resume@x", 1)]),
        "/stub/work/uid-resume.ics",
        Some("v1"),
    )));
    let connector = CalDavConnector::new(wire);
    let seat = caldav_seat();

    let first = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(counters(&first), (1, 0, 0, 0));
    let CalendarSyncOutcome::Reenqueued { next_cursor, .. } = &first else {
        panic!("re-enqueued");
    };
    assert_eq!(next_cursor.as_deref(), Some("tok-resume-1"));
    assert_eq!(connector.wire().sync_cursors(), vec![None]);
    let event = resolve_event_by_uid(&vault, "uid-resume@x")
        .expect("resolve")
        .expect("one event");
    let claims_before = claims_on(&vault, &event);
    let passport_id = live_passports_for_event(&vault, &event)
        .expect("passports")
        .first()
        .map(|(id, _)| *id)
        .expect("one passport");

    drain_pending_attempts(&vault, T0);

    // The host resumes from the returned cursor; the provider repeats the
    // same page (a reconnect replay). Nothing duplicates.
    connector.wire().queue_sync(Ok(upsert_batch(
        Some("tok-resume-1"),
        body(&[EventSpec::new("uid-resume@x", 1)]),
        "/stub/work/uid-resume.ics",
        Some("v1"),
    )));
    let resumed_seat = caldav_seat().with_cursor("tok-resume-1");
    let second = run_sync(&vault, &resumed_seat, &connector, T1);
    assert_eq!(
        counters(&second),
        (0, 1, 0, 0),
        "a repeated page acknowledges, never re-applies"
    );
    assert_eq!(connector.wire().sync_cursors().len(), 2);
    assert_eq!(
        connector.wire().sync_cursors()[1].as_deref(),
        Some("tok-resume-1")
    );

    let again = resolve_event_by_uid(&vault, "uid-resume@x")
        .expect("resolve")
        .expect("still one event");
    assert_eq!(again, event, "no duplicate EVENT minted");
    assert_eq!(
        claims_on(&vault, &again),
        claims_before,
        "no duplicate or rewritten claims"
    );
    let passports = live_passports_for_event(&vault, &again).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0].0, passport_id, "the passport row is untouched");
    assert!(
        calendar_write_outbox_rows(&vault)
            .expect("outbox rows")
            .is_empty(),
        "no outbox row and no remote write came out of a pull"
    );
    assert!(connector.wire().put_requests().is_empty());
    assert_eq!(
        pending_connector_rows(&vault, CALDAV_SYNC_ATTEMPT_KIND).len(),
        1,
        "one live poll chain per seat"
    );
}

// ---------------------------------------------------------------------------
// 4. A local write's echo is acknowledged, never re-emitted
// ---------------------------------------------------------------------------

#[test]
fn caldav_local_write_then_poll_is_acknowledged_not_reemitted() {
    let (_dir, vault) = temp_vault();
    let connector = CalDavConnector::new(StubCalDavWire::default());
    let seat = caldav_seat();
    let event = mint_local_event(&vault, 0x51, "quarterly review");

    // The local write stages its outbox, PUTs conditionally, and records the
    // outbound passport.
    let receipt = write_calendar_event(&vault, &seat, &connector, event, T1).expect("write");
    assert!(receipt.uid.ends_with("@calendar.invalid"));
    let puts = connector.wire().put_requests();
    assert_eq!(puts.len(), 1, "exactly one conditional PUT");
    assert_eq!(puts[0].uid, receipt.uid);
    assert_eq!(puts[0].sequence, receipt.sequence);
    assert_eq!(puts[0].expected_etag, None, "a fresh resource has no ETag");

    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 1);
    let (passport_id, passport) = &passports[0];
    assert_eq!(passport.direction, CalendarPassportDirection::Outbound);
    assert_eq!(passport.last_sequence, receipt.sequence);
    assert_eq!(passport.content_hash, receipt.content_hash);
    let outbox = calendar_write_outbox_rows(&vault).expect("outbox");
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].state, CalendarWriteOutboxState::Committed);

    // The next poll returns the SAME resource: same UID/SEQUENCE/hash.
    let echoed = puts[0].ics.clone();
    let echo_batch = upsert_batch(
        Some("tok-echo-1"),
        echoed,
        &receipt.href,
        receipt.etag.as_deref(),
    );
    if let RemoteCalendarChange::Upsert(object) = &echo_batch.changes[0] {
        assert_eq!(object.uid, receipt.uid);
        assert_eq!(object.sequence, receipt.sequence);
        assert_eq!(object.content_hash, receipt.content_hash);
    }
    connector.wire().queue_sync(Ok(echo_batch));
    let outcome = run_sync(&vault, &seat, &connector, T2);
    assert_eq!(
        counters(&outcome),
        (0, 1, 0, 0),
        "own write returns as an acknowledgement only"
    );

    // Nothing was rewritten and nothing was sent back.
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0].0, *passport_id, "the passport claim is stable");
    assert_eq!(
        connector.wire().put_requests().len(),
        1,
        "no semantic rewrite and no re-PUT echo loop"
    );
    let object_row = calendar_remote_object_row(&vault, "caldav-work", "work", &receipt.uid)
        .expect("object row read")
        .expect("the poll refreshed the remote-object cursor");
    assert_eq!(object_row.etag, receipt.etag);
}

// ---------------------------------------------------------------------------
// 5. The outbox is durable before the remote call
// ---------------------------------------------------------------------------

#[test]
fn caldav_outbox_is_durable_before_remote_call() {
    let (_dir, vault) = temp_vault();
    let wire = StubCalDavWire::default();
    wire.queue_sync(Ok(upsert_batch(
        Some("tok-durable-1"),
        body(&[EventSpec::new("uid-durable@x", 1)]),
        "/stub/work/uid-durable.ics",
        Some("v1"),
    )));
    let connector = CalDavConnector::new(wire);
    let seat = caldav_seat();
    let pulled = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(counters(&pulled), (1, 0, 0, 0));
    let event = resolve_event_by_uid(&vault, "uid-durable@x")
        .expect("resolve")
        .expect("event");

    // Inject a transport failure: the provider call never lands.
    connector.wire().queue_put(PutScript::Literal(Err(
        CalendarConnectorError::Transport {
            provider: CALDAV_PROVIDER_KEY,
            operation: "put",
            detail: "connection reset by peer".to_owned(),
        },
    )));
    let failed = write_calendar_event(&vault, &seat, &connector, event, T1);
    assert!(
        matches!(failed, Err(CalendarConnectorError::Transport { .. })),
        "the transport failure propagates: {failed:?}"
    );

    // ...but the durable intent was already staged BEFORE that call.
    let outbox = calendar_write_outbox_rows(&vault).expect("outbox rows");
    assert_eq!(outbox.len(), 1, "one staged row survived the failure");
    let row = &outbox[0];
    assert_eq!(row.state, CalendarWriteOutboxState::Prepared);
    assert_eq!(row.action, CalendarWriteAction::Upsert);
    assert_eq!(row.event_ref, event);
    assert_eq!(row.provider, CALDAV_PROVIDER_KEY);
    assert_eq!(row.system, "caldav-work");
    assert_eq!(row.calendar_ref, "work");
    assert_eq!(row.uid, "uid-durable@x");
    assert_eq!(row.sequence, 2, "the intended SEQUENCE bump");
    assert_ne!(row.content_hash, [0_u8; 32], "the intended content hash");
    assert_eq!(
        row.expected_etag.as_deref(),
        Some("v1"),
        "the precondition the retry must carry"
    );
    assert_eq!(row.staged_at, T1);
    assert_eq!(row.updated_at, T1);
    let puts = connector.wire().put_requests();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].expected_etag.as_deref(), Some("v1"));

    // The retry resumes from the row: same deterministic id, same intent,
    // original stage time — no re-derived blind write.
    connector
        .wire()
        .queue_put(PutScript::AcceptWithEtag("v2".to_owned()));
    let receipt = write_calendar_event(&vault, &seat, &connector, event, T2).expect("retry lands");
    assert_eq!(receipt.etag.as_deref(), Some("v2"));
    assert_eq!(receipt.sequence, 2);
    let outbox = calendar_write_outbox_rows(&vault).expect("outbox rows");
    assert_eq!(outbox.len(), 1, "the retry resumed the same row");
    assert_eq!(outbox[0].outbox_id, row.outbox_id);
    assert_eq!(outbox[0].state, CalendarWriteOutboxState::Committed);
    assert_eq!(
        outbox[0].staged_at, T1,
        "durable stage time survives the retry"
    );
    assert_eq!(outbox[0].updated_at, T2);
    let puts = connector.wire().put_requests();
    assert_eq!(puts.len(), 2);
    assert_eq!(
        puts[0].uid, puts[1].uid,
        "the retry sends the same intended write"
    );
    assert_eq!(puts[1].expected_etag.as_deref(), Some("v1"));
}

// ---------------------------------------------------------------------------
// 6. If-Match mismatch reconciles before any retry
// ---------------------------------------------------------------------------

#[test]
fn caldav_if_match_mismatch_reconciles_before_retry() {
    let (_dir, vault) = temp_vault();
    let wire = StubCalDavWire::default();
    wire.queue_sync(Ok(upsert_batch(
        Some("tok-mm-1"),
        body(&[EventSpec::new("uid-mismatch@x", 1)]),
        "/stub/work/uid-mismatch.ics",
        Some("v1"),
    )));
    let connector = CalDavConnector::new(wire);
    let seat = caldav_seat();
    let pulled = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(counters(&pulled), (1, 0, 0, 0));
    let event = resolve_event_by_uid(&vault, "uid-mismatch@x")
        .expect("resolve")
        .expect("event");
    let passport_id = live_passports_for_event(&vault, &event)
        .expect("passports")
        .first()
        .map(|(id, _)| *id)
        .expect("one passport");

    // The remote moved: the provider rejects the precondition with 412.
    connector.wire().queue_put(PutScript::Literal(Err(
        CalendarConnectorError::EtagMismatch {
            href: "/stub/work/uid-mismatch.ics".to_owned(),
            expected: Some("v1".to_owned()),
            actual: Some("v2".to_owned()),
        },
    )));
    // Reconciliation pulls the current remote truth (SEQUENCE 3, ETag v2).
    connector.wire().queue_sync(Ok(upsert_batch(
        Some("tok-mm-2"),
        body(&[EventSpec::new("uid-mismatch@x", 3)]),
        "/stub/work/uid-mismatch.ics",
        Some("v2"),
    )));

    let result = write_calendar_event(&vault, &seat, &connector, event, T1);
    let (expected, actual) = match result {
        Err(CalendarConnectorError::EtagMismatch {
            expected, actual, ..
        }) => (expected, actual),
        other => panic!("the caller sees the typed mismatch, got {other:?}"),
    };
    assert_eq!(expected.as_deref(), Some("v1"));
    assert_eq!(actual.as_deref(), Some("v2"));

    // The outbox row records that reconciliation must happen before any retry.
    let outbox = calendar_write_outbox_rows(&vault).expect("outbox rows");
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].state, CalendarWriteOutboxState::ReconcileRequired);

    // Reconciliation refreshed the local view of the remote object — and it
    // did NOT run a semantic apply: the passport stays exactly as pulled.
    let object = calendar_remote_object_row(&vault, "caldav-work", "work", "uid-mismatch@x")
        .expect("object row read")
        .expect("reconciled remote-object row");
    assert_eq!(object.etag.as_deref(), Some("v2"));
    assert_eq!(object.last_sequence, 3, "the fresh remote truth is visible");
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0].0, passport_id, "no semantic rewrite on reconcile");
    assert_eq!(passports[0].1.last_sequence, 1);

    // No unconditional overwrite, no repeated delete, no second write.
    assert_eq!(connector.wire().put_requests().len(), 1);
    assert!(connector.wire().delete_calls().is_empty());
}

// ---------------------------------------------------------------------------
// 7. Same-SEQUENCE hash drift applies once
// ---------------------------------------------------------------------------

#[test]
fn same_sequence_hash_drift_applies_once() {
    let (_dir, vault) = temp_vault();
    let wire = StubCalDavWire::default();
    wire.queue_sync(Ok(upsert_batch(
        Some("tok-drift-1"),
        body(&[EventSpec::new("uid-drift@x", 1)]),
        "/stub/work/uid-drift.ics",
        Some("v1"),
    )));
    let connector = CalDavConnector::new(wire);
    let seat = caldav_seat();
    let first = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(counters(&first), (1, 0, 0, 0));
    let event = resolve_event_by_uid(&vault, "uid-drift@x")
        .expect("resolve")
        .expect("event");
    let before = live_passports_for_event(&vault, &event).expect("passports");
    let before_hash = before[0].1.content_hash;

    // A broken publisher changed content without bumping SEQUENCE.
    let drifted = EventSpec {
        summary: "renamed standup",
        ..EventSpec::new("uid-drift@x", 1)
    };
    connector.wire().queue_sync(Ok(upsert_batch(
        Some("tok-drift-2"),
        body(&[drifted]),
        "/stub/work/uid-drift.ics",
        Some("v2"),
    )));
    let second = run_sync(&vault, &seat, &connector, T1);
    assert_eq!(
        counters(&second),
        (1, 0, 0, 0),
        "same-SEQUENCE drift applies once"
    );
    let after = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(after.len(), 1, "still one live passport");
    assert_eq!(after[0].1.last_sequence, 1, "SEQUENCE did not move");
    assert_ne!(
        after[0].1.content_hash, before_hash,
        "the passport hash tracks the drifted content"
    );
    assert_ne!(after[0].0, before[0].0, "the drift supersedes the passport");

    // Replaying the drifted page is then stable: acknowledgement only.
    connector.wire().queue_sync(Ok(upsert_batch(
        Some("tok-drift-3"),
        body(&[EventSpec {
            summary: "renamed standup",
            ..EventSpec::new("uid-drift@x", 1)
        }]),
        "/stub/work/uid-drift.ics",
        Some("v3"),
    )));
    let third = run_sync(&vault, &seat, &connector, T2);
    assert_eq!(counters(&third), (0, 1, 0, 0));
    let stable = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(stable[0].0, after[0].0, "no churn after the one apply");
}

// ---------------------------------------------------------------------------
// 8. A newer remote SEQUENCE applies without an echo loop
// ---------------------------------------------------------------------------

#[test]
fn newer_remote_sequence_applies_without_echo_loop() {
    let (_dir, vault) = temp_vault();
    let wire = StubCalDavWire::default();
    wire.queue_sync(Ok(upsert_batch(
        Some("tok-newer-1"),
        body(&[EventSpec::new("uid-newer@x", 1)]),
        "/stub/work/uid-newer.ics",
        Some("v1"),
    )));
    let connector = CalDavConnector::new(wire);
    let seat = caldav_seat();
    let first = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(counters(&first), (1, 0, 0, 0));
    let event = resolve_event_by_uid(&vault, "uid-newer@x")
        .expect("resolve")
        .expect("event");
    let (first_id, _) = live_passports_for_event(&vault, &event)
        .expect("passports")
        .first()
        .cloned()
        .expect("one passport");

    connector.wire().queue_sync(Ok(upsert_batch(
        Some("tok-newer-2"),
        body(&[EventSpec::new("uid-newer@x", 2)]),
        "/stub/work/uid-newer.ics",
        Some("v2"),
    )));
    let second = run_sync(&vault, &seat, &connector, T1);
    assert_eq!(counters(&second), (1, 0, 0, 0), "one imported update");

    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 1, "still one live passport");
    assert_eq!(passports[0].1.last_sequence, 2);
    assert_ne!(passports[0].0, first_id, "exactly one supersede");
    let superseded = claims_on(&vault, &event)
        .into_iter()
        .filter(|(id, body)| {
            body.predicate == PREDICATE_CALENDAR_PASSPORT
                && body.lifecycle != ClaimLifecycleStatus::Active
                && *id == first_id
        })
        .count();
    assert_eq!(superseded, 1, "the old passport is superseded, not dropped");

    // Applying the remote change never produced a write back: no PUT, no
    // DELETE, no outbox row. Pull-side application is not an echo loop.
    assert!(connector.wire().put_requests().is_empty());
    assert!(connector.wire().delete_calls().is_empty());
    assert!(
        calendar_write_outbox_rows(&vault)
            .expect("outbox rows")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// 9. Cross-provider UID resolution: one EVENT, two passports
// ---------------------------------------------------------------------------

#[test]
fn cross_provider_same_uid_is_one_event_with_two_passports() {
    let (_dir, vault) = temp_vault();

    let caldav = CalDavConnector::new(StubCalDavWire::default());
    caldav.wire().queue_sync(Ok(upsert_batch(
        Some("tok-shared-c1"),
        body(&[EventSpec::new("uid-shared@x", 1)]),
        "/stub/work/uid-shared.ics",
        Some("cv1"),
    )));
    let caldav_run = run_sync(&vault, &caldav_seat(), &caldav, T0);
    assert_eq!(counters(&caldav_run), (1, 0, 0, 0));

    let google = GoogleInternalConnector::new(StubGoogleInternalWire::default());
    google.wire().queue_list(Ok(upsert_batch(
        Some("tok-shared-g1"),
        body(&[EventSpec::new("uid-shared@x", 1)]),
        "calendars/primary/events/uid-shared",
        Some("gv1"),
    )));
    let google_run = run_sync(&vault, &google_seat(), &google, T0);
    assert_eq!(counters(&google_run), (1, 0, 0, 0));

    // UID-first resolution minted one EVENT and attached both systems.
    let event = resolve_event_by_uid(&vault, "uid-shared@x")
        .expect("resolve")
        .expect("one event");
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 2, "two system-scoped live passports");
    let by_system: BTreeMap<String, CalendarPassportPresence> = passports
        .into_iter()
        .map(|(_, value)| (value.system.clone(), value.presence))
        .collect();
    assert_eq!(
        by_system,
        BTreeMap::from([
            ("caldav-work".to_owned(), CalendarPassportPresence::Live),
            ("google-internal".to_owned(), CalendarPassportPresence::Live),
        ])
    );
}

// ---------------------------------------------------------------------------
// 10. One provider's delete never cancels a shared EVENT
// ---------------------------------------------------------------------------

/// Builds the two-provider shared-EVENT state tests 10 and 11 run against.
fn shared_two_source_event(
    vault: &Vault,
    caldav: &CalDavConnector<StubCalDavWire>,
    google: &GoogleInternalConnector<StubGoogleInternalWire>,
) -> EntityId {
    caldav.wire().queue_sync(Ok(upsert_batch(
        Some("tok-share-c1"),
        body(&[EventSpec::new("uid-multi@x", 1)]),
        "/stub/work/uid-multi.ics",
        Some("cv1"),
    )));
    run_sync(vault, &caldav_seat(), caldav, T0);
    google.wire().queue_list(Ok(upsert_batch(
        Some("tok-share-g1"),
        body(&[EventSpec::new("uid-multi@x", 1)]),
        "calendars/primary/events/uid-multi",
        Some("gv1"),
    )));
    run_sync(vault, &google_seat(), google, T0);
    resolve_event_by_uid(vault, "uid-multi@x")
        .expect("resolve")
        .expect("one event")
}

#[test]
fn single_provider_delete_never_cancels_shared_event() {
    let (_dir, vault) = temp_vault();
    let caldav = CalDavConnector::new(StubCalDavWire::default());
    let google = GoogleInternalConnector::new(StubGoogleInternalWire::default());
    let event = shared_two_source_event(&vault, &caldav, &google);

    // CalDAV reports the resource deleted. Only that passport moves.
    caldav.wire().queue_sync(Ok(delete_batch(
        Some("tok-share-c2"),
        "/stub/work/uid-multi.ics",
        "uid-multi@x",
    )));
    let outcome = run_sync(&vault, &caldav_seat(), &caldav, T1);
    assert_eq!(
        counters(&outcome),
        (0, 0, 1, 0),
        "one source absence, no cancellation"
    );

    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 2, "both passports stay live rows");
    let by_system: BTreeMap<String, CalendarPassportPresence> = passports
        .into_iter()
        .map(|(_, value)| (value.system.clone(), value.presence))
        .collect();
    assert_eq!(
        by_system.get("caldav-work"),
        Some(&CalendarPassportPresence::Absent)
    );
    assert_eq!(
        by_system.get("google-internal"),
        Some(&CalendarPassportPresence::Live)
    );
    assert_eq!(
        live_status(&vault, &event),
        None,
        "one source's delete never touches EVENT status"
    );
    assert_eq!(
        vault.get_entity_type(&event).expect("entity type"),
        Some(ENTITY_TYPE_EVENT),
        "the EVENT row is never deleted"
    );
    assert!(
        caldav.wire().delete_calls().is_empty() && google.wire().delete_calls().is_empty(),
        "a remote deletion is never bounced back to a provider"
    );
}

// ---------------------------------------------------------------------------
// 11. All live inbound deletions cancel once, without bounce
// ---------------------------------------------------------------------------

#[test]
fn all_live_inbound_deletions_cancel_once_without_bounce() {
    let (_dir, vault) = temp_vault();
    let caldav = CalDavConnector::new(StubCalDavWire::default());
    let google = GoogleInternalConnector::new(StubGoogleInternalWire::default());
    let event = shared_two_source_event(&vault, &caldav, &google);

    caldav.wire().queue_sync(Ok(delete_batch(
        Some("tok-share-c2"),
        "/stub/work/uid-multi.ics",
        "uid-multi@x",
    )));
    let first_delete = run_sync(&vault, &caldav_seat(), &caldav, T1);
    assert_eq!(counters(&first_delete), (0, 0, 1, 0));
    assert_eq!(live_status(&vault, &event), None, "google still reports it");

    // The final live inbound source reports deletion: the EVENT cancels with
    // the imported_cancel basis and the run's own recorded_at.
    google.wire().queue_list(Ok(delete_batch(
        Some("tok-share-g2"),
        "calendars/primary/events/uid-multi",
        "uid-multi@x",
    )));
    let final_delete = run_sync(&vault, &google_seat(), &google, T2);
    assert_eq!(
        counters(&final_delete),
        (0, 0, 1, 1),
        "second absence cancels once"
    );
    assert_eq!(
        live_status(&vault, &event),
        Some(("cancelled".to_owned(), "imported_cancel".to_owned(), T2))
    );
    assert_eq!(
        vault.get_entity_type(&event).expect("entity type"),
        Some(ENTITY_TYPE_EVENT),
        "the cancelled EVENT stays auditable"
    );
    assert!(
        live_claims(&claims_on(&vault, &event), PREDICATE_CALENDAR_EVENT_OUTCOME).is_empty(),
        "CAL-07's outcome predicate is never written here"
    );
    assert!(
        caldav.wire().delete_calls().is_empty()
            && google.wire().delete_calls().is_empty()
            && caldav.wire().put_requests().is_empty()
            && google.wire().upsert_requests().is_empty(),
        "no remote write follows a remote deletion"
    );

    // Replaying the deletion is idempotent: no second absence, no new status.
    google.wire().queue_list(Ok(delete_batch(
        Some("tok-share-g3"),
        "calendars/primary/events/uid-multi",
        "uid-multi@x",
    )));
    let replay = run_sync(&vault, &google_seat(), &google, T3);
    assert_eq!(counters(&replay), (0, 0, 0, 0));
    assert_eq!(
        live_claims(&claims_on(&vault, &event), PREDICATE_CALENDAR_STATUS).len(),
        1,
        "the cancellation landed exactly once"
    );
}

// ---------------------------------------------------------------------------
// 12. Busy transparency is CAL-02 ingest truth
// ---------------------------------------------------------------------------

#[test]
fn remote_busy_transparency_uses_cal02_ingest_truth() {
    let (_dir, vault) = temp_vault();
    let wire = StubCalDavWire::default();
    // Opaque or absent TRANSP mints busy; explicit TRANSPARENT mints free.
    wire.queue_sync(Ok(RemoteSyncBatch {
        next_cursor: Some("tok-transp-1".to_owned()),
        changes: vec![
            RemoteCalendarChange::Upsert(remote_upsert(
                "/stub/work/uid-absent-t.ics",
                Some("t1"),
                &body(&[EventSpec::new("uid-absent-t@x", 1)]),
            )),
            RemoteCalendarChange::Upsert(remote_upsert(
                "/stub/work/uid-opaque-t.ics",
                Some("t2"),
                &body(&[EventSpec {
                    transp: Some("OPAQUE"),
                    ..EventSpec::new("uid-opaque-t@x", 1)
                }]),
            )),
            RemoteCalendarChange::Upsert(remote_upsert(
                "/stub/work/uid-free-t.ics",
                Some("t3"),
                &body(&[EventSpec {
                    transp: Some("TRANSPARENT"),
                    ..EventSpec::new("uid-free-t@x", 1)
                }]),
            )),
        ],
    }));
    let connector = CalDavConnector::new(wire);
    let outcome = run_sync(&vault, &caldav_seat(), &connector, T0);
    assert_eq!(counters(&outcome), (3, 0, 0, 0));

    for (uid, expected) in [
        ("uid-absent-t@x", "busy"),
        ("uid-opaque-t@x", "busy"),
        ("uid-free-t@x", "free"),
    ] {
        let event = resolve_event_by_uid(&vault, uid)
            .expect("resolve")
            .expect("event");
        let (kind, transparency, keys) = live_time_kind(&vault, &event);
        assert_eq!(kind, "absolute");
        assert_eq!(transparency, expected, "{uid} transparency");
        assert_eq!(
            keys,
            BTreeSet::from(["kind".to_owned(), "busy_transparency".to_owned()]),
            "the connector mints CAL-02's field and invents no second one"
        );
    }
}

// ---------------------------------------------------------------------------
// 13. Google-Internal dogfood reads and writes its own calendar
// ---------------------------------------------------------------------------

#[test]
fn google_internal_dogfood_reads_and_writes_own_calendar() {
    let (_dir, vault) = temp_vault();
    let wire = StubGoogleInternalWire::default();
    wire.queue_list(Ok(upsert_batch(
        Some("g-tok-1"),
        body(&[EventSpec::new("gid-standup@x", 1)]),
        "calendars/primary/events/gid-standup",
        Some("g-etag-1"),
    )));
    let connector = GoogleInternalConnector::new(wire);
    let seat = google_seat();

    // Incremental read of the seat's OWN calendar.
    let first = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(counters(&first), (1, 0, 0, 0));
    assert_eq!(connector.wire().list_cursors(), vec![None]);
    let event = resolve_event_by_uid(&vault, "gid-standup@x")
        .expect("resolve")
        .expect("event");

    // Resume is incremental: the issued sync token rides on the next call.
    connector.wire().queue_list(Ok(RemoteSyncBatch {
        next_cursor: Some("g-tok-2".to_owned()),
        changes: Vec::new(),
    }));
    let resumed = run_sync(
        &vault,
        &google_seat().with_cursor("g-tok-1"),
        &connector,
        T1,
    );
    assert_eq!(counters(&resumed), (0, 0, 0, 0));
    assert_eq!(
        connector.wire().list_cursors()[1].as_deref(),
        Some("g-tok-1"),
        "the sync token resumes the incremental read"
    );

    // Conditional write to the same calendar: UID preserved, SEQUENCE bumped,
    // the known ETag rides as the precondition.
    let receipt = write_calendar_event(&vault, &seat, &connector, event, T2).expect("write");
    assert_eq!(receipt.uid, "gid-standup@x", "write preserves the UID");
    assert_eq!(receipt.sequence, 2, "the calendar mutation bumps SEQUENCE");
    let upserts = connector.wire().upsert_requests();
    assert_eq!(upserts.len(), 1);
    assert_eq!(upserts[0].uid, "gid-standup@x");
    assert_eq!(upserts[0].expected_etag.as_deref(), Some("g-etag-1"));
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(
        passports[0].1.direction,
        CalendarPassportDirection::TwoWay,
        "a seat that reads and writes the UID is two-way"
    );
    assert_eq!(passports[0].1.last_sequence, 2);

    // Conditional delete through the same transport.
    connector
        .delete(
            &seat.config.secret_ref,
            &seat.config.calendar_ref,
            &receipt.href,
            receipt.etag.as_deref(),
            &receipt.uid,
            receipt.sequence,
        )
        .expect("conditional delete");
    let deletes = connector.wire().delete_calls();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].2, "gid-standup@x");
    assert_eq!(deletes[0].1, receipt.etag);

    // Capability selection: a custody name outside the Workspace-Internal
    // dogfood class is refused BEFORE any provider I/O.
    let refused = connector.pull("google-byo:someone-else", "primary", None);
    assert!(matches!(
        refused,
        Err(CalendarConnectorError::CredentialUnavailable { .. })
    ));
    assert_eq!(
        connector.wire().list_cursors().len(),
        2,
        "the refusal happened before the wire was called"
    );
}

// ---------------------------------------------------------------------------
// 14. Credential canaries never escape custody
// ---------------------------------------------------------------------------

#[test]
fn credential_canaries_never_escape_custody() {
    // Unseeded like the rest of this oracle: the shipped manifest's
    // gate-pending hole for calendar claims (owned by gate.rs, pinned in the
    // CAL-02 oracle header) rejects the write path's passport supersede with
    // `GateConsentStale`, which is not what this test measures. Custody
    // registration works on any vault — the canaries sit behind real
    // `secret_ref` records either way.
    let (_dir, vault) = temp_vault();
    register_secret_canary(&vault, "caldav:work-app-password", CALDAV_CANARY);
    register_secret_canary(&vault, "google-internal:dogfood-token", GOOGLE_CANARY);

    let mut caldav_cfg = caldav_config();
    caldav_cfg.secret_ref = "caldav:work-app-password".to_owned();
    let caldav_seat = CalendarConnectorSeatState::new(caldav_cfg.clone());
    let caldav = CalDavConnector::new(StubCalDavWire::default());
    caldav.wire().queue_sync(Ok(upsert_batch(
        Some("tok-canary-c1"),
        body(&[EventSpec::new("uid-canary@x", 1)]),
        "/stub/work/uid-canary.ics",
        Some("cv1"),
    )));
    let outcome = run_sync(&vault, &caldav_seat, &caldav, T0);
    let event = resolve_event_by_uid(&vault, "uid-canary@x")
        .expect("resolve")
        .expect("event");
    let receipt = write_calendar_event(&vault, &caldav_seat, &caldav, event, T1).expect("write");

    let mut google_cfg = google_config();
    google_cfg.secret_ref = "google-internal:dogfood-token".to_owned();
    let google_seat = CalendarConnectorSeatState::new(google_cfg.clone());
    let google = GoogleInternalConnector::new(StubGoogleInternalWire::default());
    google.wire().queue_list(Ok(upsert_batch(
        Some("tok-canary-g1"),
        body(&[EventSpec::new("uid-canary-g@x", 1)]),
        "calendars/primary/events/uid-canary-g",
        Some("gv1"),
    )));
    let google_outcome = run_sync(&vault, &google_seat, &google, T0);
    let google_event = resolve_event_by_uid(&vault, "uid-canary-g@x")
        .expect("resolve")
        .expect("event");

    // The custody error path names only the ref.
    let custody_error = CalendarConnectorError::CredentialUnavailable {
        secret_ref: "caldav:work-app-password".to_owned(),
    };
    let custody_error_text = custody_error.to_string();
    assert!(custody_error_text.contains("caldav:work-app-password"));

    // The wires were handed the custody NAMES — never a value.
    assert_eq!(
        caldav.wire().secret_refs(),
        vec![
            "caldav:work-app-password".to_owned(),
            "caldav:work-app-password".to_owned(),
        ]
    );

    // Every observable engine surface is canary-free.
    let mut surfaces: Vec<(String, String)> = vec![
        ("config Debug".to_owned(), format!("{caldav_cfg:?}")),
        ("config Debug google".to_owned(), format!("{google_cfg:?}")),
        ("config serde".to_owned(), serde_json::to_string(&caldav_cfg).expect("config serde")),
        (
            "config serde google".to_owned(),
            serde_json::to_string(&google_cfg).expect("config serde"),
        ),
        ("seat state serde".to_owned(), serde_json::to_string(&caldav_seat).expect("seat serde")),
        ("sync outcome Debug".to_owned(), format!("{outcome:?}")),
        ("sync outcome Debug google".to_owned(), format!("{google_outcome:?}")),
        ("receipt Debug".to_owned(), format!("{receipt:?}")),
        ("receipt serde".to_owned(), serde_json::to_string(&receipt).expect("receipt serde")),
        ("custody error Display".to_owned(), custody_error_text),
        ("custody error Debug".to_owned(), format!("{custody_error:?}")),
    ];
    for record in AttemptQueue::new(&vault).list().expect("list attempts") {
        let payload = String::from_utf8_lossy(&record.payload).into_owned();
        let label = format!("attempt attempt-payload-kind-{}", record.kind);
        surfaces.push((label, payload));
        surfaces.push((
            "attempt dedupe key".to_owned(),
            format!("{:?}", record.dedupe_key),
        ));
    }
    for row in calendar_write_outbox_rows(&vault).expect("outbox rows") {
        surfaces.push(("outbox row Debug".to_owned(), format!("{row:?}")));
    }
    for event_ref in [event, google_event] {
        for (_, body) in claims_on(&vault, &event_ref) {
            let mut value_bytes = Vec::new();
            rmpv::encode::write_value(&mut value_bytes, &body.value).expect("claim value encodes");
            surfaces.push((
                "claim value bytes".to_owned(),
                String::from_utf8_lossy(&value_bytes).into_owned(),
            ));
            if let Some(evidence) = &body.evidence {
                let mut evidence_bytes = Vec::new();
                rmpv::encode::write_value(&mut evidence_bytes, evidence)
                    .expect("claim evidence encodes");
                surfaces.push((
                    "claim evidence bytes".to_owned(),
                    String::from_utf8_lossy(&evidence_bytes).into_owned(),
                ));
            }
        }
        let entity_body = vault.get(&event_ref).expect("entity body").expect("body exists");
        surfaces.push((
            "EVENT body bytes".to_owned(),
            String::from_utf8_lossy(&entity_body).into_owned(),
        ));
    }
    if let Some(object) =
        calendar_remote_object_row(&vault, "caldav-work", "work", "uid-canary@x").expect("row")
    {
        surfaces.push(("remote-object row Debug".to_owned(), format!("{object:?}")));
    }
    for (label, surface) in surfaces {
        assert_custody_clean(&label, &surface);
    }

    // The custody NAME does travel (it is the handle), which is what makes
    // the absence of the canary meaningful.
    assert!(format!("{caldav_cfg:?}").contains("caldav:work-app-password"));
    assert!(format!("{google_cfg:?}").contains("google-internal:dogfood-token"));
}

// ---------------------------------------------------------------------------
// 15. Kill switch revokes and stops without erasing
// ---------------------------------------------------------------------------

#[test]
fn calendar_connector_kill_switch_revokes_and_stops() {
    let (_dir, vault) = temp_vault();
    let caldav = CalDavConnector::new(StubCalDavWire::default());
    caldav.wire().queue_sync(Ok(upsert_batch(
        Some("tok-kill-1"),
        body(&[EventSpec::new("uid-kill@x", 1)]),
        "/stub/work/uid-kill.ics",
        Some("kv1"),
    )));
    let seat = caldav_seat();
    assert_eq!(
        seat.verb_catalog(),
        &[
            oneiron::calendar::CALENDAR_CONNECTOR_PULL_VERB,
            oneiron::calendar::CALENDAR_CONNECTOR_WRITE_VERB,
        ][..],
        "a live seat advertises both verbs"
    );
    let live = run_sync(&vault, &seat, &caldav, T0);
    assert_eq!(counters(&live), (1, 0, 0, 0));
    let event = resolve_event_by_uid(&vault, "uid-kill@x")
        .expect("resolve")
        .expect("event");
    drain_pending_attempts(&vault, T0);

    let killed = seat.mark_killed(T1, "ops:incident-42").expect("kill switch");
    assert!(killed.kill_switch_engaged());
    assert_eq!(
        killed.verb_catalog(),
        &[] as &[&str],
        "a killed seat advertises no verbs"
    );
    let state = killed.kill_switch.clone().expect("kill state");
    assert!(state.verbs_revoked && state.polling_stopped);
    assert_eq!(state.killed_at, T1);
    assert_eq!(state.reason_ref, "ops:incident-42");

    // No pull, no write, no next poll — and no data erased.
    let sync_calls_before = caldav.wire().sync_cursors().len();
    let outcome = run_sync(&vault, &killed, &caldav, T2);
    assert!(
        matches!(outcome, CalendarSyncOutcome::Killed),
        "a killed seat reports Killed, got {outcome:?}"
    );
    assert_eq!(
        caldav.wire().sync_cursors().len(),
        sync_calls_before,
        "no transport I/O ran"
    );
    let write = write_calendar_event(&vault, &killed, &caldav, event, T2);
    assert!(matches!(
        write,
        Err(CalendarConnectorError::KillSwitchEngaged)
    ));
    assert!(
        calendar_write_outbox_rows(&vault)
            .expect("outbox rows")
            .is_empty(),
        "a refused write stages nothing"
    );
    assert!(
        pending_connector_rows(&vault, CALDAV_SYNC_ATTEMPT_KIND).is_empty(),
        "no next poll is scheduled past the kill switch"
    );
    let still = resolve_event_by_uid(&vault, "uid-kill@x")
        .expect("resolve")
        .expect("event survives");
    assert_eq!(still, event);
    assert_eq!(
        live_passports_for_event(&vault, &still)
            .expect("passports")
            .len(),
        1,
        "passport evidence survives the kill switch"
    );
    assert_eq!(live_status(&vault, &still), None);
}

// ---------------------------------------------------------------------------
// 16. Poll jitter is bounded and non-zero
// ---------------------------------------------------------------------------

#[test]
fn calendar_connector_poll_jitter_is_bounded_and_nonzero() {
    let seat = caldav_seat();
    let (min, max) = (
        u64::from(seat.config.cadence_jitter_min_seconds),
        u64::from(seat.config.cadence_jitter_max_seconds),
    );
    assert!(min > 0, "the configured window is non-zero");

    // The pure projection stays inside the configured window for any seed.
    for seed in [0_u64, 1, 2, 7, 300, u64::MAX] {
        let due = seat.jittered_next_poll_at(T0, seed).expect("jitter");
        assert!(
            (T0 + min..=T0 + max).contains(&due),
            "seed {seed} landed at {due}, outside [{}, {}]",
            T0 + min,
            T0 + max
        );
        assert!(due > T0, "the next poll is always in the future");
    }

    // Degenerate windows are rejected structurally.
    let zero = CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        cadence_jitter_min_seconds: 0,
        ..caldav_config()
    });
    assert!(matches!(
        zero.validate(),
        Err(CalendarConnectorError::InvalidSeatConfig(_))
    ));
    let reversed = CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        cadence_jitter_min_seconds: 900,
        cadence_jitter_max_seconds: 300,
        ..caldav_config()
    });
    assert!(matches!(
        reversed.validate(),
        Err(CalendarConnectorError::InvalidSeatConfig(_))
    ));

    // The real run enqueues exactly one attempt, inside the window, through
    // the shared attempt queue — no cron, timer, or recurrence type.
    let (_dir, vault) = temp_vault();
    let caldav = CalDavConnector::new(StubCalDavWire::default());
    let outcome = run_sync(&vault, &seat, &caldav, T0);
    let CalendarSyncOutcome::Reenqueued {
        next_not_before, ..
    } = outcome
    else {
        panic!("re-enqueued, got {:?}", CalendarSyncOutcome::Killed);
    };
    assert!(
        (T0 + min..=T0 + max).contains(&next_not_before),
        "next poll due inside [{}, {}], got {next_not_before}",
        T0 + min,
        T0 + max
    );
    assert_eq!(next_not_before, T0 + min + 7 % (max - min + 1));
    assert_eq!(
        calendar_sync_attempt_kind(CALDAV_PROVIDER_KEY),
        CALDAV_SYNC_ATTEMPT_KIND
    );
    assert_eq!(
        calendar_sync_attempt_kind(GOOGLE_INTERNAL_PROVIDER_KEY),
        oneiron::calendar::GOOGLE_INTERNAL_SYNC_ATTEMPT_KIND
    );
    let pending = pending_connector_rows(&vault, CALDAV_SYNC_ATTEMPT_KIND);
    assert_eq!(pending.len(), 1, "exactly one queued poll attempt");
    let payload: CalendarConnectorSyncPayload =
        serde_json::from_slice(&pending[0].payload).expect("payload decodes");
    assert_eq!(payload.not_before, next_not_before);
    assert_eq!(payload.config, seat.config);
}

// ---------------------------------------------------------------------------
// 17. Inbound events cross the existing Gate
// ---------------------------------------------------------------------------

#[test]
fn inbound_events_cross_the_existing_gate() {
    // The seeded default policy manifest is deliberate: this oracle measures
    // that admission crosses the Gate, so the Gate must be present.
    let (_dir, vault) = temp_vault_seeded();

    let caldav = CalDavConnector::new(StubCalDavWire::default());
    caldav.wire().queue_sync(Ok(upsert_batch(
        Some("tok-gate-c1"),
        body(&[EventSpec::new("uid-gate-c@x", 1)]),
        "/stub/work/uid-gate-c.ics",
        Some("gv1"),
    )));
    let caldav_outcome = run_sync(&vault, &caldav_seat(), &caldav, T0);
    assert_eq!(counters(&caldav_outcome), (1, 0, 0, 0));

    let google = GoogleInternalConnector::new(StubGoogleInternalWire::default());
    google.wire().queue_list(Ok(upsert_batch(
        Some("tok-gate-g1"),
        body(&[EventSpec::new("uid-gate-g@x", 1)]),
        "calendars/primary/events/uid-gate-g",
        Some("gg1"),
    )));
    let google_outcome = run_sync(&vault, &google_seat(), &google, T0);
    assert_eq!(counters(&google_outcome), (1, 0, 0, 0));

    for (uid, provider) in [
        ("uid-gate-c@x", CALDAV_PROVIDER_KEY),
        ("uid-gate-g@x", GOOGLE_INTERNAL_PROVIDER_KEY),
    ] {
        let event = resolve_event_by_uid(&vault, uid)
            .expect("resolve")
            .expect("event");
        let claims = claims_on(&vault, &event);
        assert!(
            claims.len() >= 3,
            "origin + time_kind + passport at least, got {claims:?}"
        );
        for (_, body) in &claims {
            assert_eq!(
                body.source,
                Some(ClaimSource::Imported),
                "every connector claim is Imported ({provider})"
            );
            assert_eq!(
                body.approval,
                oneiron::ClaimApprovalStatus::Proposed,
                "imported admission defaults to proposed, never auto"
            );
            let evidence = body.evidence.as_ref().expect(
                "every semantic claim carries the write-envelope evidence the                  imported-evidence door stamps — a direct put_claim writes none",
            );
            let candidate = value_field(evidence, "candidate_evidence").expect("candidate evidence");
            assert_eq!(
                value_field(candidate, "kind").and_then(rmpv::Value::as_str),
                Some("imported_evidence"),
                "the CAL-02 imported-evidence candidate door stamped it"
            );
            assert_eq!(
                value_field(candidate, "source_id").and_then(rmpv::Value::as_str),
                Some(ICS_FEED_SOURCE_ID),
                "the connector uses the CAL-02 calendar import source"
            );
            let source_record_id = value_field(candidate, "source_record_id")
                .and_then(rmpv::Value::as_str)
                .expect("source_record_id");
            assert!(
                source_record_id.starts_with(&format!("calendar-connector:{provider}:")),
                "the provenance ref names the transport, got {source_record_id}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 18. Time only crosses the CAL-01 border
// ---------------------------------------------------------------------------

/// Asserts a serialized public connector row carries plain scalar leaves only:
/// strings, booleans, nulls, and `u64`-representable numbers. No float, no
/// stringly-datetime structure, no third-party time type.
fn assert_scalar_json_leaves(label: &str, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {}
        serde_json::Value::Number(number) => assert!(
            number.is_u64(),
            "{label}: connector rows carry u64 time/count scalars, got {number}"
        ),
        serde_json::Value::Array(items) => {
            for item in items {
                assert_scalar_json_leaves(label, item);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                assert_scalar_json_leaves(label, item);
            }
        }
    }
}

#[test]
fn timezone_conversion_stays_inside_calendar_tz() {
    // Gap: a nonexistent local spring-forward time is the typed verdict.
    let gap = wall_to_utc(
        &WallTime {
            y: 2026,
            mo: 3,
            d: 29,
            h: 1,
            mi: 30,
            s: 0,
        },
        "Europe/London",
    );
    let (gap_wall, gap_tz) = match gap {
        Err(CalendarError::NonexistentWallTime { wall, tz }) => (wall, tz),
        other => panic!("a gap is the typed verdict, got {other:?}"),
    };
    assert_eq!(gap_tz, "Europe/London");
    assert_eq!((gap_wall.h, gap_wall.mi), (1, 30));

    // Fold: an ambiguous local fall-back time picks the earliest instant
    // (the pre-transition offset), deterministically.
    let fold = wall_to_utc(
        &WallTime {
            y: 2026,
            mo: 10,
            d: 25,
            h: 1,
            mi: 30,
            s: 0,
        },
        "Europe/London",
    )
    .expect("a fold resolves");
    let reference = wall_to_utc(
        &WallTime {
            y: 2026,
            mo: 10,
            d: 25,
            h: 0,
            mi: 30,
            s: 0,
        },
        "UTC",
    )
    .expect("utc reference");
    assert_eq!(
        fold, reference,
        "ambiguous 2026-10-25 01:30 Europe/London is the earlier instant, 00:30 UTC"
    );
    assert_eq!(
        utc_to_wall(fold, "Europe/London").expect("round trip"),
        WallTime {
            y: 2026,
            mo: 10,
            d: 25,
            h: 1,
            mi: 30,
            s: 0,
        }
    );

    // The connector's parse side crosses the same border: a TZID VEVENT's
    // fold instant matches the border's verdict bit for bit, and a TZID gap
    // surfaces the same typed error instead of a silent skip.
    let fold_feed = body(&[EventSpec {
        dtstart: Some("20261025T013000"),
        dtend: Some("20261025T023000"),
        dtstart_tzid: Some("Europe/London"),
        dtend_tzid: Some("Europe/London"),
        ..EventSpec::new("uid-fold@x", 1)
    }]);
    let parsed = parse_ics_feed(&fold_feed).expect("fold feed parses");
    assert_eq!(parsed.events[0].starts_at_utc, Some(fold));
    let gap_feed = body(&[EventSpec {
        dtstart: Some("20260329T013000"),
        dtstart_tzid: Some("Europe/London"),
        ..EventSpec::new("uid-gap@x", 1)
    }]);
    assert!(
        matches!(
            parse_ics_feed(&gap_feed),
            Err(CalendarError::NonexistentWallTime { .. })
        ),
        "connector-facing TZID gaps are the typed border verdict"
    );

    // Every public connector row type holds u64/String/owned calendar types
    // only — the serialization witness shows no third-party time structure.
    let payload = CalendarConnectorSyncPayload {
        config: caldav_config(),
        cursor: Some("tok-tz-1".to_owned()),
        not_before: T0,
    };
    let request = RemoteWriteRequest {
        href: Some("/c/1.ics".to_owned()),
        expected_etag: Some("v1".to_owned()),
        uid: "uid-tz@x".to_owned(),
        sequence: 7,
        ics: vec![1_u8, 2, 3],
    };
    let receipt_tz = RemoteWriteReceipt {
        href: "/c/1.ics".to_owned(),
        etag: Some("v2".to_owned()),
        uid: "uid-tz@x".to_owned(),
        sequence: 7,
        content_hash: [5_u8; 32],
    };
    let seat_json = CalendarConnectorSeatState::new(caldav_config()).with_cursor("tok-tz-1");
    for (label, value) in [
        (
            "sync payload",
            serde_json::to_value(&payload).expect("payload serde"),
        ),
        (
            "write request",
            serde_json::to_value(&request).expect("request serde"),
        ),
        (
            "write receipt",
            serde_json::to_value(&receipt_tz).expect("receipt serde"),
        ),
        (
            "seat state",
            serde_json::to_value(&seat_json).expect("seat serde"),
        ),
    ] {
        assert_scalar_json_leaves(label, &value);
    }
}
