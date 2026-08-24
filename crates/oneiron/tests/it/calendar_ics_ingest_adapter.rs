//! CAL-02 ICS ingest adapter oracle (ONE-1784).
//!
//! Pins the adapter's laws end to end at the public boundary:
//!
//! 1. **Custody, never the URL.** Poll payloads carry the SECRET custody
//!    `secret_ref`; the production fetcher resolves it and touches the URL
//!    only inside the HTTP door. The canary test proves the URL appears in no
//!    attempt payload, `Debug` form, receipt, or error string.
//! 2. **Failure is never absence.** A malformed or truncated feed preserves
//!    the last complete cursor, every passport's presence, and every EVENT
//!    status. A 304 is a true no-op plus exactly one re-enqueue.
//! 3. **The multi-source law.** A single source's absence supersedes only
//!    that source's passport; `calendar.status = cancelled` with basis
//!    `imported_absence` lands only when EVERY live inbound passport reports
//!    absence. The EVENT row is never deleted and CAL-07's outcome predicate
//!    is never written here.
//! 4. **Gate-backed admission.** Every semantic claim is
//!    `ClaimSource::Imported`, proposed, and admitted through the
//!    imported-evidence candidate door, with CAL-09's safeguard invoked
//!    immediately before admission and the verdict carried in the typed
//!    `CalendarAdmissionRequest`.
//!
//! Vault setup follows the CAL-07/CAL-09 oracle precedent: unseeded vaults
//! (the shipped default policy manifest holds calendar claims gate-pending —
//! a known hole owned by `gate.rs`, not this lane), except the cross-gate
//! and custody tests, which run on the seeded default manifest on purpose.

use std::sync::Mutex;

use oneiron::calendar::CalendarError;
use oneiron::calendar::claims::{
    CalendarPassportPresence, PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS,
    PREDICATE_CALENDAR_TIME_KIND,
};
use oneiron::calendar::ingest::{
    CustodyDoorIcsFeedFetcher, IcsFeedFetcher, IcsFeedPollConfig, IcsFeedPollPayload,
    IcsFetchResponse, IcsHttpResponse, IcsHttpTransport, IcsPollRunState, enqueue_ics_feed_poll,
    ics_feed_cursor_snapshot, ics_feed_pause_exceptions, ics_feed_poll_dedupe_key,
    run_ics_feed_poll, run_ics_feed_poll_with_screener,
};
use oneiron::calendar::passport::{live_passports_for_event, resolve_event_by_uid};
use oneiron::calendar::safeguard::{
    CalendarBodyScreener, CalendarInboundBody, CalendarScreenVerdict,
};
use oneiron::ingest::{
    ICS_FEED_SOURCE_ID, INGEST_SOURCE_REGISTRY, IngestSourceFormat, KNOWN_INGEST_HARNESS_CONFIG,
};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimLifecycleStatus, ClaimOutcome, ClaimSource,
    CompleteAttempt, EnqueueOutcome, EntityId, Vault, VaultConfig,
};

/// Fixed poll times.
const T0: u64 = 1_800_000_000;
const T1: u64 = 1_800_000_100;
const T2: u64 = 1_800_000_200;
const T3: u64 = 1_800_000_300;

/// One VEVENT in a fixture feed.
struct EventSpec {
    uid: &'static str,
    sequence: u32,
    summary: &'static str,
    transp: Option<&'static str>,
    cancelled: bool,
    description: Option<&'static str>,
    dtstart: Option<&'static str>,
    dtend: Option<&'static str>,
}

impl EventSpec {
    fn new(uid: &'static str, sequence: u32) -> Self {
        Self {
            uid,
            sequence,
            summary: "standup",
            transp: None,
            cancelled: false,
            description: None,
            dtstart: None,
            dtend: None,
        }
    }
}

/// Builds a complete VCALENDAR body with a fixed DTSTAMP (excluded from the
/// content hash, so fixture variation stays explicit in the specs).
fn feed(events: &[EventSpec]) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for event in events {
        out.push_str("BEGIN:VEVENT\r\n");
        out.push_str(&format!("UID:{}\r\n", event.uid));
        out.push_str("DTSTAMP:20260805T100000Z\r\n");
        out.push_str(&format!(
            "DTSTART:{}\r\n",
            event.dtstart.unwrap_or("20260806T140000Z")
        ));
        out.push_str(&format!(
            "DTEND:{}\r\n",
            event.dtend.unwrap_or("20260806T150000Z")
        ));
        out.push_str(&format!("SEQUENCE:{}\r\n", event.sequence));
        out.push_str(&format!("SUMMARY:{}\r\n", event.summary));
        if let Some(transp) = event.transp {
            out.push_str(&format!("TRANSP:{transp}\r\n"));
        }
        if event.cancelled {
            out.push_str("STATUS:CANCELLED\r\n");
        }
        if let Some(description) = event.description {
            out.push_str(&format!("DESCRIPTION:{description}\r\n"));
        }
        out.push_str("END:VEVENT\r\n");
    }
    out.push_str("END:VCALENDAR\r\n");
    out.into_bytes()
}

fn config(system: &str) -> IcsFeedPollConfig {
    IcsFeedPollConfig {
        secret_ref: format!("ics-feed:{system}"),
        system: system.to_owned(),
        cadence_min_seconds: 300,
        cadence_max_seconds: 900,
    }
}

/// An unseeded vault: the oracle measures this adapter's laws, not the
/// default policy manifest's calendar coverage (see the module note).
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

/// A scripted fetcher: replays queued responses, records every call's
/// `secret_ref` and `If-None-Match`.
struct StubFetcher {
    calls: Mutex<Vec<(String, Option<String>)>>,
    responses: Mutex<std::collections::VecDeque<IcsFetchResponse>>,
}

impl StubFetcher {
    fn with(responses: impl IntoIterator<Item = IcsFetchResponse>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl IcsFeedFetcher for StubFetcher {
    fn fetch(
        &self,
        secret_ref: &str,
        if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        self.calls
            .lock()
            .expect("calls")
            .push((secret_ref.to_owned(), if_none_match.map(str::to_owned)));
        self.responses
            .lock()
            .expect("responses")
            .pop_front()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "stub fetcher has no queued response".to_owned(),
            })
    }
}

/// Runs one poll against a scripted response.
fn poll(
    vault: &Vault,
    config: &IcsFeedPollConfig,
    response: IcsFetchResponse,
    now: u64,
) -> Result<IcsPollRunState, CalendarError> {
    let fetcher = StubFetcher::with([response]);
    run_ics_feed_poll(vault, &fetcher, config, now, 7)
}

fn complete(body: Vec<u8>, etag: &str) -> IcsFetchResponse {
    IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body,
    }
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

/// Reads a string field out of a claim value's MessagePack map.
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

/// Every `calendar.ics.poll` attempt row in one state bucket.
fn poll_rows_in(vault: &Vault, pending: bool) -> Vec<oneiron::AttemptRecord> {
    AttemptQueue::new(vault)
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|record| record.kind == oneiron::calendar::ingest::ICS_POLL_ATTEMPT_KIND)
        .filter(|record| {
            let is_pending = matches!(
                record.state,
                AttemptState::Queued | AttemptState::Leased | AttemptState::Scheduled
            );
            is_pending == pending
        })
        .collect()
}

/// Claims + completes the feed's pending poll row, modeling the host worker
/// so the runner's re-enqueue mints the next generation.
fn complete_pending_poll_row(vault: &Vault, now: u64) {
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(record) = queue
        .claim(ClaimAttempt {
            lease_owner: "test-worker".to_owned(),
            now,
        })
        .expect("claim")
    else {
        panic!("a pending poll row must be claimable");
    };
    queue
        .complete(CompleteAttempt {
            id: record.id,
            lease_owner: "test-worker".to_owned(),
            attempt_count: record.attempt_count,
            now,
        })
        .expect("complete");
}

#[test]
fn ics_feed_source_has_registry_parity() {
    let config = INGEST_SOURCE_REGISTRY
        .get_config(ICS_FEED_SOURCE_ID)
        .expect("ics-feed registered");
    assert_eq!(config.source_id, ICS_FEED_SOURCE_ID);
    assert_eq!(config.format, IngestSourceFormat::IcsFeed);
    assert_eq!(config.label, "ICS feed");
    assert!(!config.writes_claims);
    assert_eq!(
        config.adapter_skill.map(|skill| skill.skill_id),
        Some("builtin.ingest.ics-feed")
    );
    assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
    assert_eq!(config.trust_ceiling.max_auto_sensitivity, None);
    assert!(!config.trust_ceiling.receipted);
    assert!(!config.trust_ceiling.warned);
    assert!(!config.trust_ceiling.permits_auto(Some(0)));
    assert_eq!(
        config.default_admission,
        oneiron::ClaimApprovalStatus::Proposed
    );

    // Harness-config parity, and normalization lookup through the registry.
    assert_eq!(
        KNOWN_INGEST_HARNESS_CONFIG.get_config(ICS_FEED_SOURCE_ID),
        Some(config)
    );
    assert!(INGEST_SOURCE_REGISTRY.get(ICS_FEED_SOURCE_ID).is_some());
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(
            ICS_FEED_SOURCE_ID,
            std::str::from_utf8(&feed(&[EventSpec::new("uid-p@x", 1)])).expect("utf8"),
        )
        .expect("normalize");
    assert_eq!(batch.source_id, ICS_FEED_SOURCE_ID);
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].source_record_id, "uid-p@x");
    assert!(batch.claims.is_empty(), "normalize never mints claims");

    // Set membership, never ordinal position: CAL-08 inserts entry #2 later.
    let ids: std::collections::BTreeSet<&str> = INGEST_SOURCE_REGISTRY.source_ids().collect();
    assert!(ids.contains(ICS_FEED_SOURCE_ID));
    assert!(ids.contains(oneiron::ingest::JSONL_TRANSCRIPT_SOURCE_ID));
    assert!(ids.contains(oneiron::ingest::MEETING_TRANSCRIPT_SOURCE_ID));
}

#[test]
fn new_same_updated_and_missing_passport_diff() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");

    // New: no passport anywhere carries the UID, so the first poll creates.
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-a@x", 1)]), "v1"),
        T0,
    )
    .expect("first poll");
    let event_a = resolve_event_by_uid(&vault, "uid-a@x")
        .expect("resolve")
        .expect("event minted");
    let first_passport_id = {
        let passports = live_passports_for_event(&vault, &event_a).expect("passports");
        assert_eq!(passports.len(), 1);
        assert_eq!(passports[0].1.last_sequence, 1);
        assert_eq!(passports[0].1.presence, CalendarPassportPresence::Live);
        passports[0].0
    };

    // Same SEQUENCE and same hash: the re-poll skips — the live passport
    // claim is untouched.
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-a@x", 1)]), "v2"),
        T1,
    )
    .expect("same poll");
    let passports = live_passports_for_event(&vault, &event_a).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0].0, first_passport_id, "same seq+hash must skip");

    // Higher SEQUENCE updates: the passport head moves to sequence 2.
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-a@x", 2)]), "v3"),
        T2,
    )
    .expect("higher sequence poll");
    let passports = live_passports_for_event(&vault, &event_a).expect("passports");
    assert_eq!(passports.len(), 1, "one live passport per (system, uid)");
    assert_eq!(passports[0].1.last_sequence, 2);
    assert_ne!(passports[0].0, first_passport_id, "update supersedes");

    // Same SEQUENCE with content drift (new summary) also updates.
    let drifted = EventSpec {
        summary: "renamed standup",
        ..EventSpec::new("uid-a@x", 2)
    };
    poll(&vault, &cfg, complete(feed(&[drifted]), "v4"), T3).expect("hash drift poll");
    let passports = live_passports_for_event(&vault, &event_a).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0].1.last_sequence, 2);

    // Missing UID, complete feed, and this is the event's ONLY source:
    // absence marks that source passport — and with no other inbound source,
    // the multi-source law then cancels the EVENT. The single-source test
    // below isolates the non-cancelling case.
    poll(&vault, &cfg, complete(feed(&[]), "v5"), T3 + 100).expect("absence poll");
    let passports = live_passports_for_event(&vault, &event_a).expect("passports");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0].1.presence, CalendarPassportPresence::Absent);
    assert_eq!(
        live_status(&vault, &event_a),
        Some((
            "cancelled".to_owned(),
            "imported_absence".to_owned(),
            T3 + 100
        ))
    );
}

#[test]
fn single_source_absence_never_cancels_a_multi_source_event() {
    let (_dir, vault) = temp_vault();
    let work = config("work");
    let home = config("home");

    // One UID through two live inbound passports.
    poll(
        &vault,
        &work,
        complete(feed(&[EventSpec::new("uid-s@x", 1)]), "w1"),
        T0,
    )
    .expect("work poll");
    poll(
        &vault,
        &home,
        complete(feed(&[EventSpec::new("uid-s@x", 1)]), "h1"),
        T0,
    )
    .expect("home poll");
    let event = resolve_event_by_uid(&vault, "uid-s@x")
        .expect("resolve")
        .expect("one event");
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 2);

    // The work feed drops the UID in a COMPLETE feed: only the work passport
    // flips absent; the EVENT's status stays unwritten (confirmed by default).
    poll(&vault, &work, complete(feed(&[]), "w2"), T1).expect("work absence poll");
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 2);
    let by_system: std::collections::BTreeMap<String, CalendarPassportPresence> = passports
        .into_iter()
        .map(|(_, value)| (value.system.clone(), value.presence))
        .collect();
    assert_eq!(
        by_system.get("work"),
        Some(&CalendarPassportPresence::Absent)
    );
    assert_eq!(by_system.get("home"), Some(&CalendarPassportPresence::Live));
    assert_eq!(
        live_status(&vault, &event),
        None,
        "single-source absence never touches EVENT status"
    );
    assert_eq!(
        vault.get_entity_type(&event).expect("entity type"),
        Some(ENTITY_TYPE_EVENT),
        "the EVENT row is never deleted"
    );
}

#[test]
fn all_live_inbound_sources_absent_write_calendar_status() {
    let (_dir, vault) = temp_vault();
    let work = config("work");
    let home = config("home");

    poll(
        &vault,
        &work,
        complete(feed(&[EventSpec::new("uid-m@x", 1)]), "w1"),
        T0,
    )
    .expect("work poll");
    poll(
        &vault,
        &home,
        complete(feed(&[EventSpec::new("uid-m@x", 1)]), "h1"),
        T0,
    )
    .expect("home poll");
    let event = resolve_event_by_uid(&vault, "uid-m@x")
        .expect("resolve")
        .expect("one event");

    poll(&vault, &work, complete(feed(&[]), "w2"), T1).expect("work absence");
    assert_eq!(live_status(&vault, &event), None, "one live source remains");

    // The final live inbound source reports absence: cancellation lands with
    // the imported_absence basis and the run's recorded_at.
    poll(&vault, &home, complete(feed(&[]), "h2"), T2).expect("home absence");
    assert_eq!(
        live_status(&vault, &event),
        Some(("cancelled".to_owned(), "imported_absence".to_owned(), T2))
    );
    assert_eq!(
        vault.get_entity_type(&event).expect("entity type"),
        Some(ENTITY_TYPE_EVENT),
        "the EVENT row is never deleted"
    );
    let claims = claims_on(&vault, &event);
    assert!(
        live_claims(&claims, "calendar.event_outcome").is_empty(),
        "CAL-07's outcome predicate is never written here"
    );
    // Idempotent: a re-poll of the same absence writes no second status.
    poll(&vault, &home, complete(feed(&[]), "h3"), T3).expect("home absence replay");
    assert_eq!(
        live_claims(&claims_on(&vault, &event), PREDICATE_CALENDAR_STATUS).len(),
        1
    );
}

#[test]
fn uid_first_cross_calendar_resolution_is_n_passports_to_one_event() {
    let (_dir, vault) = temp_vault();
    poll(
        &vault,
        &config("work"),
        complete(feed(&[EventSpec::new("uid-x@x", 1)]), "w1"),
        T0,
    )
    .expect("work poll");
    poll(
        &vault,
        &config("home"),
        complete(feed(&[EventSpec::new("uid-x@x", 1)]), "h1"),
        T0,
    )
    .expect("home poll");

    let first = resolve_event_by_uid(&vault, "uid-x@x")
        .expect("resolve")
        .expect("event");
    let second = resolve_event_by_uid(&vault, "uid-x@x")
        .expect("resolve")
        .expect("event");
    assert_eq!(first, second, "one UID index target");
    let passports = live_passports_for_event(&vault, &first).expect("passports");
    assert_eq!(passports.len(), 2, "two live passports on one EVENT");
    let systems: std::collections::BTreeSet<String> = passports
        .into_iter()
        .map(|(_, value)| value.system)
        .collect();
    assert_eq!(
        systems,
        std::collections::BTreeSet::from(["work".to_owned(), "home".to_owned()])
    );
}

#[test]
fn passport_supersede_is_scoped_to_system_and_uid() {
    let (_dir, vault) = temp_vault();
    let work = config("work");
    let home = config("home");
    poll(
        &vault,
        &work,
        complete(feed(&[EventSpec::new("uid-y@x", 1)]), "w1"),
        T0,
    )
    .expect("work poll");
    poll(
        &vault,
        &home,
        complete(feed(&[EventSpec::new("uid-y@x", 1)]), "h1"),
        T0,
    )
    .expect("home poll");
    let event = resolve_event_by_uid(&vault, "uid-y@x")
        .expect("resolve")
        .expect("event");
    let home_claim_id = live_passports_for_event(&vault, &event)
        .expect("passports")
        .into_iter()
        .find(|(_, value)| value.system == "home")
        .map(|(id, _)| id)
        .expect("home passport");

    // The work source bumps SEQUENCE: only the work passport is superseded.
    poll(
        &vault,
        &work,
        complete(feed(&[EventSpec::new("uid-y@x", 2)]), "w2"),
        T1,
    )
    .expect("work update");
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports.len(), 2, "both passports stay live");
    let home = passports
        .iter()
        .find(|(_, value)| value.system == "home")
        .expect("home passport");
    assert_eq!(
        home.0, home_claim_id,
        "the other system's passport is untouched"
    );
    assert_eq!(home.1.last_sequence, 1);
    let work_value = passports
        .iter()
        .find(|(_, value)| value.system == "work")
        .map(|(_, value)| value)
        .expect("work passport");
    assert_eq!(work_value.last_sequence, 2);
}

#[test]
fn busy_transparency_defaults_busy_and_preserves_free() {
    let (_dir, vault) = temp_vault();
    let opaque = EventSpec {
        transp: Some("OPAQUE"),
        ..EventSpec::new("uid-b1@x", 1)
    };
    let missing = EventSpec::new("uid-b2@x", 1);
    let free = EventSpec {
        transp: Some("TRANSPARENT"),
        ..EventSpec::new("uid-b3@x", 1)
    };
    poll(
        &vault,
        &config("work"),
        complete(feed(&[opaque, missing, free]), "v1"),
        T0,
    )
    .expect("poll");

    let transparency_of = |uid: &str| {
        let event = resolve_event_by_uid(&vault, uid)
            .expect("resolve")
            .expect("event");
        let claims = claims_on(&vault, &event);
        let live = live_claims(&claims, PREDICATE_CALENDAR_TIME_KIND);
        let [(_, body)] = live.as_slice() else {
            panic!("one live time_kind claim for {uid}");
        };
        value_field(&body.value, "busy_transparency")
            .and_then(rmpv::Value::as_str)
            .expect("busy_transparency token")
            .to_owned()
    };
    assert_eq!(transparency_of("uid-b1@x"), "busy", "opaque mints busy");
    assert_eq!(
        transparency_of("uid-b2@x"),
        "busy",
        "absent TRANSP defaults busy"
    );
    assert_eq!(
        transparency_of("uid-b3@x"),
        "free",
        "transparent preserves free"
    );
}

#[test]
fn etag_not_modified_is_a_true_noop() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-e@x", 1)]), "v1"),
        T0,
    )
    .expect("first poll");
    let event = resolve_event_by_uid(&vault, "uid-e@x")
        .expect("resolve")
        .expect("event");
    let claims_before = claims_on(&vault, &event);
    let cursor_before = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor after complete");
    assert_eq!(cursor_before.etag.as_deref(), Some("v1"));
    assert_eq!(cursor_before.last_complete_at, Some(T0));
    let pending_before = poll_rows_in(&vault, true).len();

    let state = poll(
        &vault,
        &cfg,
        IcsFetchResponse::NotModified {
            etag: Some("v1".to_owned()),
        },
        T1,
    )
    .expect("304 poll");
    assert!(matches!(state, IcsPollRunState::Reenqueued { .. }));

    // No claim, passport-presence, status, or index movement of any kind.
    let claims_after = claims_on(&vault, &event);
    assert_eq!(claims_before, claims_after, "304 writes no claim mutation");
    // No blob write: the archived head is still the first body.
    let cursor_after = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor after 304");
    assert_eq!(cursor_after, cursor_before, "304 writes no cursor mutation");
    // Exactly one future attempt was enqueued, none other.
    assert_eq!(poll_rows_in(&vault, true).len(), pending_before + 1);
}

#[test]
fn parse_failure_never_marks_prior_uids_missing() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-f@x", 1)]), "v1"),
        T0,
    )
    .expect("first poll");
    let event = resolve_event_by_uid(&vault, "uid-f@x")
        .expect("resolve")
        .expect("event");
    let claims_before = claims_on(&vault, &event);
    let cursor_before = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor after complete");

    // A truncated body parses as a typed failure: the run errors and nothing
    // moves — not the cursor, not presence, not status.
    let truncated = feed(&[EventSpec::new("uid-f@x", 1)]);
    let truncated = &truncated[..truncated.len() - "END:VCALENDAR\r\n".len()];
    let outcome = poll(&vault, &cfg, complete(truncated.to_vec(), "v2"), T1);
    assert!(
        matches!(outcome, Err(CalendarError::IcsParse { .. })),
        "truncated feed is a typed parse failure, got {outcome:?}"
    );
    assert_eq!(claims_on(&vault, &event), claims_before);
    let passports = live_passports_for_event(&vault, &event).expect("passports");
    assert_eq!(passports[0].1.presence, CalendarPassportPresence::Live);
    assert_eq!(live_status(&vault, &event), None);
    let cursor_after = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor preserved");
    assert_eq!(
        cursor_after, cursor_before,
        "the last complete cursor is preserved"
    );
}

#[test]
fn raw_ics_is_archived_before_semantic_admission() {
    let (_dir, vault) = temp_vault();
    let body = feed(&[EventSpec::new("uid-r@x", 1)]);
    let expected_hash = *blake3::hash(&body).as_bytes();
    poll(&vault, &config("work"), complete(body, "v1"), T0).expect("poll");

    // Every semantic candidate's evidence names the archived blob version.
    let event = resolve_event_by_uid(&vault, "uid-r@x")
        .expect("resolve")
        .expect("event");
    let claims = claims_on(&vault, &event);
    assert!(!claims.is_empty());
    let mut artifact_refs = std::collections::BTreeSet::new();
    for (_, claim) in &claims {
        let evidence = claim.evidence.as_ref().expect("write envelope evidence");
        let candidate = value_field(evidence, "candidate_evidence").expect("candidate evidence");
        let source_record_id = value_field(candidate, "source_record_id")
            .and_then(rmpv::Value::as_str)
            .expect("source_record_id");
        let (artifact_hex, _) = source_record_id
            .split_once("#v")
            .expect("blob version provenance");
        artifact_refs.insert(artifact_hex.to_owned());
    }
    assert_eq!(artifact_refs.len(), 1, "one archive backs every candidate");
    let artifact_id =
        EntityId::from_hex(artifact_refs.iter().next().expect("one ref")).expect("hex id");
    let head = vault
        .blob_artifact_head(&artifact_id)
        .expect("head")
        .expect("archived head exists before admission reads it");
    assert_eq!(head.version, 1);
    assert_eq!(
        head.content_hash, expected_hash,
        "content-addressed raw bytes"
    );
}

#[test]
fn imported_calendar_claims_cross_gate() {
    // The seeded default policy manifest is deliberate: this oracle measures
    // that admission crosses the Gate, so the Gate must be present.
    let (_dir, vault) = temp_vault_seeded();
    poll(
        &vault,
        &config("work"),
        complete(feed(&[EventSpec::new("uid-g@x", 1)]), "v1"),
        T0,
    )
    .expect("poll under the default manifest");

    let event = resolve_event_by_uid(&vault, "uid-g@x")
        .expect("resolve")
        .expect("event");
    let claims = claims_on(&vault, &event);
    assert!(
        claims.len() >= 3,
        "origin + time_kind + passport, got {claims:?}"
    );
    for (_, body) in &claims {
        assert_eq!(
            body.source,
            Some(ClaimSource::Imported),
            "every admitted claim is Imported"
        );
        assert_eq!(
            body.approval,
            oneiron::ClaimApprovalStatus::Proposed,
            "imported admission defaults to proposed, never auto"
        );
        let evidence = body.evidence.as_ref().expect("write envelope evidence");
        let candidate = value_field(evidence, "candidate_evidence").expect("candidate evidence");
        assert_eq!(
            value_field(candidate, "kind").and_then(rmpv::Value::as_str),
            Some("imported_evidence"),
            "the candidate door stamps imported-evidence provenance"
        );
        assert_eq!(
            value_field(candidate, "source_id").and_then(rmpv::Value::as_str),
            Some(ICS_FEED_SOURCE_ID),
        );
    }
}

#[test]
fn calendar_safeguard_admission_carries_verdict() {
    struct RecordingScreener {
        bodies: Mutex<Vec<CalendarInboundBody>>,
    }
    impl CalendarBodyScreener for RecordingScreener {
        fn screen(&self, body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
            self.bodies.lock().expect("bodies").push(body.clone());
            Ok(CalendarScreenVerdict::Flagged {
                reason_codes: vec!["calendar.body.test_flag".to_owned()],
            })
        }
    }

    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    let screener = RecordingScreener {
        bodies: Mutex::new(Vec::new()),
    };
    let fetcher = StubFetcher::with([complete(
        feed(&[EventSpec {
            description: Some("bring the roadmap"),
            ..EventSpec::new("uid-sc@x", 1)
        }]),
        "v1",
    )]);
    run_ics_feed_poll_with_screener(&vault, &fetcher, Some(&screener), true, &cfg, T0, 7)
        .expect("poll with safeguard");

    // The hook ran immediately before every admission: origin + time_kind +
    // passport for one event is exactly three screens, each carrying the
    // event's inbound body.
    let bodies = screener.bodies.lock().expect("bodies");
    assert_eq!(bodies.len(), 3, "one screen per imported admission");
    for body in bodies.iter() {
        assert_eq!(body.description, "bring the roadmap");
    }
    drop(bodies);

    // Admission still landed (the hook classifies, it does not adjudicate),
    // and the run's admission-metadata witness carries the verdict.
    let event = resolve_event_by_uid(&vault, "uid-sc@x")
        .expect("resolve")
        .expect("event");
    assert_eq!(
        live_passports_for_event(&vault, &event)
            .expect("passports")
            .len(),
        1
    );
    let cursor = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor after run");
    assert_eq!(
        cursor.last_screen_verdict.as_deref(),
        Some("flagged"),
        "the typed admission request's verdict reaches admission metadata"
    );
}

const CANARY_URL: &str = "https://cal.example.com/secret/CANARY-TOKEN-7f3d9/private.ics";
const CANARY_EFFECTOR: &str = "connector:ics-feed";

/// Registers a custody record whose value is the canary URL, with a `read`
/// binding for the fetcher's effector. The record's value field is
/// crate-private by design (S1), so the fixture builds the body through the
/// one public codec and decodes it — the same door the manifest flow uses.
fn register_canary_secret(vault: &Vault, name: &str) {
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
        (Value::from("effector"), Value::from(CANARY_EFFECTOR)),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (
            Value::from("scopes"),
            Value::Array(vec![Value::from("read")]),
        ),
    ]);
    let body = Value::Map(vec![
        (Value::from("schema_version"), Value::from(1_u64)),
        (Value::from("name"), Value::from(name)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(CANARY_URL.as_bytes().to_vec()),
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
    rmpv::encode::write_value(&mut bytes, &body).expect("encode custody body");
    let record =
        oneiron::secret_custody::decode_secret_custody_body(&bytes).expect("decode custody body");
    vault
        .register_secret(record)
        .expect("register canary secret");
}

/// A recording HTTP transport: captures the URL and precondition it was
/// called with, replies with a scripted response. Shared-handle so the test
/// keeps its side after the fetcher takes ownership.
type TransportCalls = std::sync::Arc<Mutex<Vec<(String, Option<String>)>>>;

#[derive(Clone)]
struct RecordingTransport {
    calls: TransportCalls,
    response: std::sync::Arc<Mutex<Result<IcsHttpResponse, String>>>,
}

impl RecordingTransport {
    fn ok(body: Vec<u8>, etag: &str) -> Self {
        Self {
            calls: std::sync::Arc::new(Mutex::new(Vec::new())),
            response: std::sync::Arc::new(Mutex::new(Ok(IcsHttpResponse {
                status: 200,
                etag: Some(etag.to_owned()),
                body,
            }))),
        }
    }

    fn calls(&self) -> Vec<(String, Option<String>)> {
        self.calls.lock().expect("calls").clone()
    }
}

impl IcsHttpTransport for RecordingTransport {
    fn get(&self, url: &str, if_none_match: Option<&str>) -> Result<IcsHttpResponse, String> {
        self.calls
            .lock()
            .expect("calls")
            .push((url.to_owned(), if_none_match.map(str::to_owned)));
        self.response.lock().expect("response").clone()
    }
}

#[test]
fn secret_url_is_absent_from_attempts_debug_receipts_and_errors() {
    let (_dir, vault) = temp_vault_seeded();
    register_canary_secret(&vault, "ics-feed:canary");
    let cfg = IcsFeedPollConfig {
        secret_ref: "ics-feed:canary".to_owned(),
        ..config("canary")
    };

    // The production poll path, door fetcher and all.
    let transport = RecordingTransport::ok(feed(&[EventSpec::new("uid-c@x", 1)]), "v1");
    let fetcher = CustodyDoorIcsFeedFetcher::new(&vault, CANARY_EFFECTOR, transport.clone());
    enqueue_ics_feed_poll(&vault, cfg.clone(), T0).expect("enqueue");
    let state = run_ics_feed_poll(&vault, &fetcher, &cfg, T0, 7).expect("poll");

    // Resolution happened: the door handed the transport the canary URL.
    let calls = transport.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0, CANARY_URL,
        "the door resolves the custody value"
    );

    // The canary appears in NO attempt payload.
    for record in AttemptQueue::new(&vault).list().expect("list") {
        let payload = String::from_utf8_lossy(&record.payload);
        assert!(
            !payload.contains("CANARY-TOKEN-7f3d9"),
            "attempt payload carries no URL: {payload}"
        );
    }
    // Nor in any Debug form of the config, payload, or run state.
    for debug in [
        format!("{cfg:?}"),
        format!("{state:?}"),
        format!(
            "{:?}",
            IcsFeedPollPayload {
                config: cfg,
                not_before: T0,
            }
        ),
    ] {
        assert!(
            !debug.contains("CANARY-TOKEN-7f3d9"),
            "Debug carries no URL: {debug}"
        );
    }
    // Nor in the custody-door error path: an unregistered ref names only the
    // ref, and a transport error is URL-scrubbed by the door.
    let missing = run_ics_feed_poll(
        &vault,
        &fetcher,
        &IcsFeedPollConfig {
            secret_ref: "ics-feed:missing".to_owned(),
            ..config("missing")
        },
        T1,
        7,
    );
    let Err(err) = missing else {
        panic!("an unregistered secret_ref fails as a custody error");
    };
    let rendered = err.to_string();
    assert!(matches!(err, CalendarError::IcsCredential { .. }));
    assert!(rendered.contains("ics-feed:missing"));
    assert!(!rendered.contains("CANARY-TOKEN-7f3d9"));

    let failing_transport = RecordingTransport {
        calls: std::sync::Arc::new(Mutex::new(Vec::new())),
        response: std::sync::Arc::new(Mutex::new(Err(format!(
            "could not connect to {CANARY_URL}"
        )))),
    };
    let failing = CustodyDoorIcsFeedFetcher::new(&vault, CANARY_EFFECTOR, failing_transport);
    let Err(err) = failing.fetch("ics-feed:canary", None) else {
        panic!("transport failure surfaces as a fetch error");
    };
    let rendered = err.to_string();
    assert!(
        !rendered.contains("CANARY-TOKEN-7f3d9"),
        "door errors are URL-scrubbed: {rendered}"
    );
    assert!(rendered.contains("<redacted-url>"));
}

#[test]
fn production_fetcher_uses_secret_door_and_if_none_match() {
    let (_dir, vault) = temp_vault_seeded();
    register_canary_secret(&vault, "ics-feed:canary");
    let cfg = IcsFeedPollConfig {
        secret_ref: "ics-feed:canary".to_owned(),
        ..config("canary")
    };

    let transport = RecordingTransport::ok(feed(&[EventSpec::new("uid-p@x", 1)]), "v9");
    let fetcher = CustodyDoorIcsFeedFetcher::new(&vault, CANARY_EFFECTOR, transport.clone());

    // First fetch: no cursor, so no precondition.
    let response = fetcher.fetch("ics-feed:canary", None).expect("first fetch");
    let IcsFetchResponse::Complete { etag, body } = &response else {
        panic!("200 maps to a complete response");
    };
    assert_eq!(etag.as_deref(), Some("v9"));
    assert!(!body.is_empty());
    assert_eq!(transport.calls()[0], (CANARY_URL.to_owned(), None));

    // After a complete poll stored the cursor ETag, the next poll's fetch
    // sends it as If-None-Match.
    run_ics_feed_poll(&vault, &fetcher, &cfg, T0, 7).expect("first poll");
    run_ics_feed_poll(&vault, &fetcher, &cfg, T1, 7).expect("second poll");
    let calls = transport.calls();
    assert_eq!(
        calls[2],
        (CANARY_URL.to_owned(), Some("v9".to_owned())),
        "the prior ETag rides as If-None-Match"
    );
    // The fetch response carries no URL anywhere.
    assert!(!format!("{response:?}").contains("CANARY-TOKEN-7f3d9"));

    // The door refuses an effector with no binding, before any HTTP.
    let denied_transport = RecordingTransport::ok(Vec::new(), "x");
    let denied =
        CustodyDoorIcsFeedFetcher::new(&vault, "connector:unbound", denied_transport.clone());
    let Err(err) = denied.fetch("ics-feed:canary", None) else {
        panic!("an unbound effector is refused at the door");
    };
    assert!(matches!(err, CalendarError::IcsCredential { .. }));
    assert!(
        denied_transport.calls().is_empty(),
        "no egress without a binding"
    );
}

#[test]
fn provider_url_reset_pauses_attempt_and_surfaces_exception() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    enqueue_ics_feed_poll(&vault, cfg.clone(), T0).expect("enqueue");
    assert_eq!(poll_rows_in(&vault, true).len(), 1);

    let state = poll(&vault, &cfg, IcsFetchResponse::CredentialReset, T1).expect("reset poll");
    let IcsPollRunState::PausedNeedsInput {
        inbox_exception_ref,
    } = state
    else {
        panic!("a credential reset pauses, got {state:?}");
    };

    // The attempt row carries the pause; no further poll is scheduled.
    let rows = poll_rows_in(&vault, false);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, AttemptState::Paused);
    assert_eq!(
        poll_rows_in(&vault, true).len(),
        0,
        "no retry storm after a reset"
    );

    // Exactly one inbox exception, correlating with the run state.
    let exceptions = ics_feed_pause_exceptions(&vault).expect("exceptions");
    assert_eq!(exceptions.len(), 1);
    assert_eq!(exceptions[0].exception_ref, inbox_exception_ref);
    assert_eq!(exceptions[0].system, "work");
    assert_eq!(exceptions[0].secret_ref, "ics-feed:work");
    assert_eq!(exceptions[0].paused_at, T1);
    let cursor = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor after pause");
    assert!(cursor.paused);

    // No event cancellation machinery moved: nothing was ever admitted.
    assert!(exceptions[0].reason.contains("secret feed URL"));

    // A repeated reset is idempotent: still one exception, no new rows.
    poll(&vault, &cfg, IcsFetchResponse::CredentialReset, T2).expect("reset replay");
    assert_eq!(
        ics_feed_pause_exceptions(&vault).expect("exceptions").len(),
        1
    );
    assert_eq!(poll_rows_in(&vault, true).len(), 0);
}

#[test]
fn poll_cadence_reenqueues_with_bounded_jitter() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");

    // An ordered, non-zero window is required.
    let invalid = IcsFeedPollConfig {
        cadence_min_seconds: 0,
        ..cfg.clone()
    };
    assert!(enqueue_ics_feed_poll(&vault, invalid, T0).is_err());

    enqueue_ics_feed_poll(&vault, cfg.clone(), T0).expect("enqueue");
    complete_pending_poll_row(&vault, T0);

    let state = poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-j@x", 1)]), "v1"),
        T1,
    )
    .expect("poll");
    let IcsPollRunState::Reenqueued { next_not_before } = state else {
        panic!("success re-enqueues, got {state:?}");
    };
    assert!(
        (T1 + 300..=T1 + 900).contains(&next_not_before),
        "due time inside the configured window: {next_not_before}"
    );

    // Exactly one pending row carries that due time in its payload — no
    // timer, cron, Schedule variant, or recurrence primitive was created.
    let pending = poll_rows_in(&vault, true);
    assert_eq!(pending.len(), 1, "exactly one re-enqueue");
    let payload: IcsFeedPollPayload =
        serde_json::from_slice(&pending[0].payload).expect("payload decodes");
    assert_eq!(payload.not_before, next_not_before);
    assert_eq!(payload.config, cfg);
}

#[test]
fn imported_cancel_status_in_feed_writes_imported_cancel_basis() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    let cancelled = EventSpec {
        cancelled: true,
        ..EventSpec::new("uid-x1@x", 1)
    };
    poll(&vault, &cfg, complete(feed(&[cancelled]), "v1"), T0).expect("poll");
    let event = resolve_event_by_uid(&vault, "uid-x1@x")
        .expect("resolve")
        .expect("event");
    assert_eq!(
        live_status(&vault, &event),
        Some(("cancelled".to_owned(), "imported_cancel".to_owned(), T0))
    );
    assert_eq!(
        vault.get_entity_type(&event).expect("entity type"),
        Some(ENTITY_TYPE_EVENT)
    );
}

// ---------------------------------------------------------------------------
// VERDICT-FIX oracles (ONE-1784 finder/verdict round): each test below pins
// one adjudicated REAL finding and was verified red against the pre-fix tree.
// ---------------------------------------------------------------------------

/// The `source_record_id` an admitted claim carries through its write
/// envelope's imported-evidence candidate.
fn claim_source_record_id(body: &oneiron::ClaimBody) -> &str {
    let evidence = body.evidence.as_ref().expect("write envelope evidence");
    let candidate = value_field(evidence, "candidate_evidence").expect("candidate evidence");
    value_field(candidate, "source_record_id")
        .and_then(rmpv::Value::as_str)
        .expect("source_record_id")
}

/// The EVENT body's `name` field, read straight off the entity row.
fn event_name(vault: &Vault, event: &EntityId) -> Option<String> {
    let body = vault.get(event).expect("entity read")?;
    let mut cursor = std::io::Cursor::new(&body);
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    entries.into_iter().find_map(|(key, value)| {
        (key.as_str() == Some("name")).then(|| value.as_str().map(str::to_owned))?
    })
}

/// A screener that always clears and counts how many bodies it saw.
struct CountingScreener {
    seen: Mutex<usize>,
}

impl CalendarBodyScreener for CountingScreener {
    fn screen(&self, _body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        *self.seen.lock().expect("seen") += 1;
        Ok(CalendarScreenVerdict::Clear)
    }
}

#[test]
fn feed_identity_is_injective_over_colon_bearing_fields() {
    // `validate` permits ':' in both fields, and the blueprint's own example
    // secret_ref carries one: the identity encoding must keep the tuple
    // injective or two feeds would share a cursor, ETag, pause, and archive.
    let left = IcsFeedPollConfig {
        secret_ref: "b:c".to_owned(),
        ..config("a")
    };
    let right = IcsFeedPollConfig {
        secret_ref: "c".to_owned(),
        ..config("a:b")
    };
    assert_ne!(
        ics_feed_poll_dedupe_key(&left),
        ics_feed_poll_dedupe_key(&right),
        "(a, b:c) and (a:b, c) are two feeds, never one identity"
    );

    // The two feeds therefore run two independent chains.
    let (_dir, vault) = temp_vault();
    enqueue_ics_feed_poll(&vault, left, T0).expect("left enqueue");
    enqueue_ics_feed_poll(&vault, right, T0).expect("right enqueue");
    assert_eq!(
        poll_rows_in(&vault, true).len(),
        2,
        "colon-bearing feeds must not dedupe against each other"
    );
}

#[test]
fn setup_enqueue_never_forks_a_parallel_poll_chain() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    enqueue_ics_feed_poll(&vault, cfg.clone(), T0).expect("setup enqueue");
    complete_pending_poll_row(&vault, T0);

    // The run re-enqueues exactly one generation-scoped successor.
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-q@x", 1)]), "v1"),
        T1,
    )
    .expect("poll");
    assert_eq!(poll_rows_in(&vault, true).len(), 1, "one live generation");

    // A redundant setup call while that generation is pending must adopt the
    // live chain, never fork a second one under the bare key.
    let again = enqueue_ics_feed_poll(&vault, cfg, T2).expect("idempotent setup");
    assert!(
        matches!(again, EnqueueOutcome::Existing(_)),
        "setup while a generation is pending returns Existing, got {again:?}"
    );
    assert_eq!(
        poll_rows_in(&vault, true).len(),
        1,
        "one feed, one pending attempt — no parallel chains"
    );
}

#[test]
fn superseding_admissions_cross_the_safeguard_hook() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    let screener = CountingScreener {
        seen: Mutex::new(0),
    };
    let fetcher = StubFetcher::with([
        complete(feed(&[EventSpec::new("uid-hk@x", 1)]), "v1"),
        complete(feed(&[EventSpec::new("uid-hk@x", 2)]), "v2"),
        complete(feed(&[]), "v3"),
    ]);

    // Create poll: origin + time_kind + passport = 3 screened admissions.
    run_ics_feed_poll_with_screener(&vault, &fetcher, Some(&screener), true, &cfg, T0, 7)
        .expect("create poll");
    assert_eq!(*screener.seen.lock().expect("seen"), 3);

    // Higher-SEQUENCE update: the superseding passport admission crosses the
    // hook exactly like a fresh one — the run's verdict witness proves it.
    run_ics_feed_poll_with_screener(&vault, &fetcher, Some(&screener), true, &cfg, T1, 7)
        .expect("update poll");
    assert_eq!(
        *screener.seen.lock().expect("seen"),
        4,
        "the superseding passport admission is screened too"
    );
    let cursor = ics_feed_cursor_snapshot(&vault, &cfg)
        .expect("cursor")
        .expect("cursor after update");
    assert_eq!(
        cursor.last_screen_verdict.as_deref(),
        Some("clear"),
        "an update run made of only supersessions still carries a verdict"
    );

    // Complete-feed absence: the absence supersession AND the derived
    // cancellation are both screened admissions.
    run_ics_feed_poll_with_screener(&vault, &fetcher, Some(&screener), true, &cfg, T2, 7)
        .expect("absence poll");
    assert_eq!(
        *screener.seen.lock().expect("seen"),
        6,
        "absence supersession + absence cancellation cross the hook"
    );
}

#[test]
fn superseding_passport_keeps_archive_provenance() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    poll(
        &vault,
        &cfg,
        complete(feed(&[EventSpec::new("uid-pr@x", 1)]), "v1"),
        T0,
    )
    .expect("create poll");
    let event = resolve_event_by_uid(&vault, "uid-pr@x")
        .expect("resolve")
        .expect("event");
    let live_passport_source = |vault: &Vault| {
        let claims = claims_on(vault, &event);
        let live = live_claims(&claims, PREDICATE_CALENDAR_PASSPORT);
        let [(_, body)] = live.as_slice() else {
            panic!("one live passport claim");
        };
        claim_source_record_id(body).to_owned()
    };
    let created = live_passport_source(&vault);
    let (artifact_hex, _) = created.split_once("#v").expect("create provenance");
    assert_eq!(created, format!("{artifact_hex}#v1:uid-pr@x"));

    // Hash-drift update: the new passport head points at the complete 200
    // archive that produced it — never a bare UID.
    let drifted = EventSpec {
        summary: "renamed standup",
        ..EventSpec::new("uid-pr@x", 1)
    };
    poll(&vault, &cfg, complete(feed(&[drifted]), "v2"), T1).expect("drift poll");
    assert_eq!(
        live_passport_source(&vault),
        format!("{artifact_hex}#v2:uid-pr@x"),
        "a superseding passport keeps archive provenance"
    );

    // Absence: the absence passport cites the complete feed that proved the
    // omission.
    poll(&vault, &cfg, complete(feed(&[]), "v3"), T2).expect("absence poll");
    assert_eq!(
        live_passport_source(&vault),
        format!("{artifact_hex}#v3:uid-pr@x"),
        "an absence passport keeps provenance to the proving feed"
    );
}

#[test]
fn update_existing_remints_event_content() {
    let (_dir, vault) = temp_vault();
    let cfg = config("work");
    let original = EventSpec {
        transp: Some("OPAQUE"),
        ..EventSpec::new("uid-up@x", 1)
    };
    poll(&vault, &cfg, complete(feed(&[original]), "v1"), T0).expect("create poll");
    let event = resolve_event_by_uid(&vault, "uid-up@x")
        .expect("resolve")
        .expect("event");
    assert_eq!(event_name(&vault, &event).as_deref(), Some("standup"));

    // Same SEQUENCE, drifted content: SUMMARY, DTSTART, and TRANSP all moved.
    let moved = EventSpec {
        summary: "moved standup",
        transp: Some("TRANSPARENT"),
        dtstart: Some("20260807T090000Z"),
        dtend: Some("20260807T093000Z"),
        ..EventSpec::new("uid-up@x", 1)
    };
    poll(&vault, &cfg, complete(feed(&[moved]), "v2"), T1).expect("drift poll");

    // The EVENT's name follows the drifted SUMMARY...
    assert_eq!(
        event_name(&vault, &event).as_deref(),
        Some("moved standup"),
        "an update re-mints the EVENT row, not just the passport head"
    );
    // ...and `calendar.time` re-mints under supersession: exactly one live
    // claim, now carrying the drifted transparency.
    let claims = claims_on(&vault, &event);
    let live = live_claims(&claims, PREDICATE_CALENDAR_TIME_KIND);
    let [(_, body)] = live.as_slice() else {
        panic!(
            "one live time_kind claim after an update, got {}",
            live.len()
        );
    };
    assert_eq!(
        value_field(&body.value, "busy_transparency").and_then(rmpv::Value::as_str),
        Some("free"),
        "drifted TRANSP re-mints busy_transparency"
    );
}

/// Probes the vault write lock from inside the HTTP call: if the door still
/// holds its custody read txn when egress runs, the probe cannot acquire a
/// write txn and the fetch fails instead of stalling every vault write for
/// the fetch's duration.
struct WriteLockProbeTransport {
    vault: std::sync::Arc<Vault>,
}

impl IcsHttpTransport for WriteLockProbeTransport {
    fn get(&self, _url: &str, _if_none_match: Option<&str>) -> Result<IcsHttpResponse, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let vault = self.vault.clone();
        std::thread::spawn(move || {
            let probe = EntityId::now();
            let _ = vault.put_entity(
                &probe,
                oneiron::registry::ENTITY_TYPE_MACHINE,
                oneiron::temporal::TimeRange { start: 0, end: 0 },
                0,
                b"write-lock probe",
            );
            let _ = tx.send(());
        });
        if rx.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
            return Err("vault write lock held across HTTP egress".to_owned());
        }
        Ok(IcsHttpResponse {
            status: 304,
            etag: None,
            body: Vec::new(),
        })
    }
}

#[test]
fn custody_door_never_holds_the_vault_write_lock_across_egress() {
    let (_dir, vault) = temp_vault_seeded();
    register_canary_secret(&vault, "ics-feed:canary");
    let vault = std::sync::Arc::new(vault);

    let fetcher = CustodyDoorIcsFeedFetcher::new(
        &vault,
        CANARY_EFFECTOR,
        WriteLockProbeTransport {
            vault: vault.clone(),
        },
    );
    let response = fetcher
        .fetch("ics-feed:canary", None)
        .expect("the custody read txn is released before the HTTP door opens");
    assert!(matches!(response, IcsFetchResponse::NotModified { .. }));
}
