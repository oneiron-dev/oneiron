//! The in-process `vault.calendar.*` doors keep the calendar promises (ruling
//! L4-23 = A: each test proves a promise at its public door). Every call
//! enters through `oneiron_testkit::door::invoke`, the generated verb dispatch
//! every transport shares, as the embedded owner.
//!
//! - P1 `canon oneiron/agents/oneiron-arch-0060-event-ics-meetings-v1.md:20`
//!   "ICS is an interchange format, never a database": `vault.calendar.create`
//!   takes no raw ICS, and `vault.calendar.read` serves the vault's own EVENT
//!   view, never ICS text.
//! - P2 `vault.calendar.freebusy` "projects source-redacted busy occupancy":
//!   each interval is two instants, with no name, ref or source.
//! - P3 every calendar read is the caller's scoped read and answers its
//!   mandatory narrowing receipt; on a native EVENT no passport head or
//!   history is served, and a master with no series expands to nothing.
//! - P4 `vault.calendar.search` lists "one page in time order", and `text`
//!   narrows by name.
//! - P5 `vault.calendar.transcript.ingest` "ingests verified uploaded UTF-8
//!   transcript bytes as a closed SESSION with ordered TURNs".
//! - P6 the ingest binds `decoded_text` to the uploaded bytes: text that is
//!   not the upload is refused.
//! - P7 the six calendar rows that need a host (check-ins, ICS import,
//!   instance moves, the outcome policy) refuse an embedded caller with
//!   MODEL_UNAVAILABLE, never run.
//! - P8 a malformed calendar act is refused at the door.
//!
//! Not here: canon :86 (the same UID on many calendars resolves to one EVENT)
//! and :88 (only an admitted passport carries authority) need passport claims,
//! which only the host-only ICS import mints; a passport value's 32-byte
//! content hash has no JSON form, so `vault.claims.seed` cannot stand in.
//! Occurrence masking needs a stored series and detached instances, which also
//! arrive only through the host-only import and move rows.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_calendar_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::Vault;
use oneiron::memory::Memory;
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

/// Monday 2 March 2026, 00:00 UTC: before the fixture clock's now.
const MONDAY: u64 = 1_772_409_600;
const DAY: u64 = 86_400;
const HOUR: u64 = 3_600;

/// Two transcript lines, each `[claimed ms] Speaker: text`.
const TRANSCRIPT_TEXT: &str = "[1700000000000] Ana: hello\n[1700000060000] Bo: hi there";
/// `TRANSCRIPT_TEXT` in RFC 4648 base64 (no trailing newline), the upload's
/// `content_base64`.
const TRANSCRIPT_B64: &str =
    "WzE3MDAwMDAwMDAwMDBdIEFuYTogaGVsbG8KWzE3MDAwMDAwNjAwMDBdIEJvOiBoaSB0aGVyZQ==";
const TRANSCRIPT_ARRIVED_MS: u64 = 1_700_000_100_000;

/// A private copy of the empty fixture, opened with the writer lease as an
/// embedded host's is. The `TestVault` holds the directory and must outlive
/// the `Vault`.
fn owned_vault() -> (TestVault, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open_owned().expect("an owned open");
    (copy, vault)
}

/// Creates a native EVENT over the inclusive range `start..=end`; answers its
/// hex ref.
fn create_native(owner: &Memory<'_>, summary: &str, start: u64, end: u64) -> String {
    let created = door::invoke(
        owner,
        "vault.calendar.create",
        json!({
            "origin": "native",
            "summary": summary,
            "occurredAt": {"start": start, "end": end},
        }),
    )
    .expect("the owner creates a native EVENT");
    assert_eq!(created["origin"], json!("native"), "{created}");
    created["event_ref"]
        .as_str()
        .expect("an event_ref")
        .to_owned()
}

/// The names of a search page's events, in page order.
fn names(page: &Value) -> Vec<String> {
    page["value"]["events"]
        .as_array()
        .expect("an events array")
        .iter()
        .map(|event| event["name"].as_str().expect("a name").to_owned())
        .collect()
}

/// A JSON object's keys, sorted (the workspace's serde_json keeps insertion
/// order).
fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// Uploads `TRANSCRIPT_TEXT` as version 1 of a new blob artifact; answers the
/// artifact's hex ref.
fn upload_transcript(owner: &Memory<'_>) -> String {
    let put = door::invoke(
        owner,
        "vault.artifacts.put",
        json!({
            "name": "standup.txt",
            "media_type": "text/plain",
            "occurred_at": 1_700_000_000u64,
        }),
    )
    .expect("the transcript artifact registers");
    let artifact = put["id_hex"].as_str().expect("an id_hex").to_owned();
    let appended = door::invoke(
        owner,
        "vault.artifacts.append",
        json!({
            "artifact_ref": artifact,
            "content_base64": TRANSCRIPT_B64,
            "occurred_at": 1_700_000_000u64,
        }),
    )
    .expect("the transcript bytes append");
    assert!(
        appended.get("landed").is_some(),
        "the owner's upload lands: {appended}"
    );
    artifact
}

fn ingest(owner: &Memory<'_>, artifact: &str, text: &str) -> Result<Value, String> {
    door::invoke(
        owner,
        "vault.calendar.transcript.ingest",
        json!({
            "source_blob_ref": artifact,
            "decoded_text": text,
            "arrived_at_ms": TRANSCRIPT_ARRIVED_MS,
        }),
    )
    .map_err(|refusal| refusal.code.to_string())
}

#[test]
fn ics_is_neither_taken_nor_served_by_the_calendar_doors() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");

    let refused = door::invoke(
        &owner,
        "vault.calendar.create",
        json!({
            "origin": "native",
            "summary": "Sync",
            "occurredAt": {"start": MONDAY, "end": MONDAY + HOUR},
            "ics": "BEGIN:VEVENT\nUID:sync-1\nEND:VEVENT",
        }),
    )
    .expect_err("raw ICS is no create field");
    assert_eq!(refused.code, "BAD_REQUEST", "{refused:?}");

    let event = create_native(&owner, "Planning", MONDAY, MONDAY + HOUR);
    let read = door::invoke(&owner, "vault.calendar.read", json!({"event_ref": event}))
        .expect("the EVENT reads");
    let view = &read["value"];
    assert_eq!(view["name"], json!("Planning"), "{read}");
    assert_eq!(view["start_utc"], json!(MONDAY), "{read}");
    assert_eq!(view["end_utc"], json!(MONDAY + HOUR), "{read}");
    let text = read.to_string();
    assert!(
        !text.contains("BEGIN:") && !text.contains("UID:"),
        "no ICS text is served: {text}"
    );
    for key in sorted_keys(view) {
        assert!(
            [
                "blocks_time",
                "calendar_systems",
                "civil",
                "end_utc",
                "event_ref",
                "name",
                "origin",
                "start_utc",
            ]
            .contains(&key.as_str()),
            "the view holds only the vault's own EVENT fields, not {key}: {read}"
        );
    }
}

#[test]
fn freebusy_shows_occupancy_and_nothing_else() {
    const SECRET: &str = "Term sheet walkthrough with Acme";
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let start = MONDAY + 9 * HOUR;
    let event = create_native(&owner, SECRET, start, MONDAY + 10 * HOUR);

    let out = door::invoke(
        &owner,
        "vault.calendar.freebusy",
        json!({"calendars": [], "range": {"start": MONDAY, "end": MONDAY + DAY}}),
    )
    .expect("freebusy over the day");
    let intervals = out["value"]["intervals"]
        .as_array()
        .expect("an intervals array");
    assert_eq!(intervals.len(), 1, "one busy interval: {out}");
    assert_eq!(intervals[0]["start_utc"], json!(start), "{out}");
    for interval in intervals {
        let low = interval["start_utc"].as_u64().expect("a start");
        let high = interval["end_utc"].as_u64().expect("an end");
        assert!(low < high, "a non-empty half-open interval: {interval}");
        assert_eq!(
            sorted_keys(interval),
            ["end_utc", "start_utc"],
            "occupancy only: {interval}"
        );
    }
    let text = out.to_string();
    assert!(
        !text.contains(SECRET) && !text.contains(&event),
        "no EVENT detail crosses freebusy: {text}"
    );
}

#[test]
fn every_calendar_read_carries_its_narrowing_receipt() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let event = create_native(&owner, "Standup", MONDAY, MONDAY + HOUR / 2);
    let range = json!({"start": MONDAY, "end": MONDAY + DAY});
    let passport = json!({"event_ref": event, "system": "google", "uid": "standup@google"});
    let reads = [
        ("vault.calendar.read", json!({"event_ref": event})),
        (
            "vault.calendar.search",
            json!({"calendars": [], "range": range, "limit": 50}),
        ),
        (
            "vault.calendar.freebusy",
            json!({"calendars": [], "range": range}),
        ),
        (
            "vault.calendar.occurrences",
            json!({"master_ref": event, "range": range}),
        ),
        ("vault.calendar.passports.read", passport.clone()),
        ("vault.calendar.passports.history", passport),
    ];
    let mut outs = Vec::new();
    for (verb, input) in reads {
        let out = door::invoke(&owner, verb, input).expect("the read runs");
        assert!(
            out.get("narrowing").is_some_and(Value::is_object),
            "{verb} carries its narrowing receipt: {out}"
        );
        outs.push(out);
    }
    assert_eq!(outs[3]["value"]["occurrences"], json!([]), "{}", outs[3]);
    assert_eq!(outs[3]["value"]["complete"], json!(true), "{}", outs[3]);
    assert_eq!(
        outs[4]["value"],
        Value::Null,
        "no passport head: {}",
        outs[4]
    );
    assert_eq!(
        outs[5]["value"],
        json!([]),
        "no passport history: {}",
        outs[5]
    );
}

#[test]
fn search_lists_earliest_first_and_text_narrows_by_name() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    // Created latest-first, so the page order is the search's, not the
    // write order.
    create_native(
        &owner,
        "Beta review",
        MONDAY + 14 * HOUR,
        MONDAY + 15 * HOUR,
    );
    create_native(
        &owner,
        "Alpha meeting",
        MONDAY + 9 * HOUR,
        MONDAY + 10 * HOUR,
    );
    let range = json!({"start": MONDAY, "end": MONDAY + DAY});

    let all = door::invoke(
        &owner,
        "vault.calendar.search",
        json!({"calendars": [], "range": range, "limit": 50}),
    )
    .expect("the day's search");
    assert_eq!(names(&all), ["Alpha meeting", "Beta review"], "{all}");
    assert_eq!(all["value"]["complete"], json!(true), "{all}");

    let narrowed = door::invoke(
        &owner,
        "vault.calendar.search",
        json!({"calendars": [], "range": range, "text": "BETA", "limit": 50}),
    )
    .expect("a text search");
    assert_eq!(names(&narrowed), ["Beta review"], "{narrowed}");
}

#[test]
fn a_transcript_lands_as_a_closed_session_of_ordered_turns() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let artifact = upload_transcript(&owner);

    let out = ingest(&owner, &artifact, TRANSCRIPT_TEXT).expect("the transcript ingests");
    // `session` is answered only once the close landed in the ingest's own
    // transaction.
    assert_eq!(out["outcome"], json!("session"), "{out}");
    let turns = out["turn_refs"].as_array().expect("turn_refs");
    assert_eq!(turns.len(), 2, "one TURN per line: {out}");
    for (ordinal, (turn, (text, label))) in turns
        .iter()
        .zip([("hello", "Ana"), ("hi there", "Bo")])
        .enumerate()
    {
        let read = door::invoke(
            &owner,
            "vault.get",
            json!({"entity_ref": turn.as_str().expect("a TURN ref")}),
        )
        .expect("the TURN reads");
        let body = &read["value"]["body"];
        assert_eq!(body["ordinal"], json!(ordinal), "{read}");
        assert_eq!(body["text"], json!(text), "{read}");
        assert_eq!(body["speaker_label"], json!(label), "{read}");
    }
    let session = out["session_ref"].as_str().expect("a session_ref");
    let read = door::invoke(&owner, "vault.get", json!({"entity_ref": session}))
        .expect("the SESSION reads");
    assert_eq!(read["value"]["id_hex"], json!(session), "{read}");
}

#[test]
fn a_transcript_must_match_its_uploaded_bytes() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let artifact = upload_transcript(&owner);

    assert_eq!(
        ingest(&owner, &artifact, "[1700000000000] Ana: tampered"),
        Err("BAD_REQUEST".to_owned()),
        "text that is not the upload is refused"
    );
    let out = ingest(&owner, &artifact, TRANSCRIPT_TEXT).expect("the upload's own text ingests");
    assert_eq!(out["outcome"], json!("session"), "{out}");
}

#[test]
fn host_only_calendar_rows_refuse_an_embedded_caller() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let event = create_native(&owner, "One-to-one", MONDAY, MONDAY + HOUR / 2);
    // Every input decodes, so the refusal is the host-only one, not a decode
    // error.
    let rows = [
        (
            "vault.calendar.check_in.answer",
            json!({"event_ref": event, "answer": "held"}),
        ),
        ("vault.calendar.check_in.due", json!({"event_ref": event})),
        (
            "vault.calendar.ics.import",
            json!({"system": "google", "source_blob_ref": event, "source_version": 1}),
        ),
        (
            "vault.calendar.instances.move",
            json!({
                "system": "google",
                "source_blob_ref": event,
                "source_version": 1,
                "uid": "one-to-one@google",
                "original_start_utc": MONDAY,
                "start_utc": MONDAY + HOUR,
                "end_utc": MONDAY + 2 * HOUR,
            }),
        ),
        ("vault.calendar.outcome_policy.get", json!({})),
        (
            "vault.calendar.outcome_policy.set",
            json!({"grace_secs": 1800}),
        ),
    ];
    for (verb, input) in rows {
        let refused = door::invoke(&owner, verb, input).expect_err("a host-only row refuses");
        assert_eq!(refused.code, "MODEL_UNAVAILABLE", "{verb}: {refused:?}");
    }
}

#[test]
fn a_malformed_calendar_act_is_refused() {
    let (_copy, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let event = create_native(&owner, "Review", MONDAY, MONDAY + HOUR);
    let backwards = json!({"start": MONDAY + HOUR, "end": MONDAY});
    let rows = [
        (
            "create: an end before the start",
            "vault.calendar.create",
            json!({"origin": "native", "summary": "Backwards", "occurredAt": backwards}),
        ),
        (
            "search: resume_from with no range",
            "vault.calendar.search",
            json!({"calendars": [], "limit": 10, "resume_from": MONDAY}),
        ),
        (
            "freebusy: an end before the start",
            "vault.calendar.freebusy",
            json!({"calendars": [], "range": backwards}),
        ),
        (
            "occurrences: an end before the start",
            "vault.calendar.occurrences",
            json!({"master_ref": event, "range": backwards}),
        ),
        (
            "passports.read: an empty system",
            "vault.calendar.passports.read",
            json!({"event_ref": event, "system": "", "uid": "review@google"}),
        ),
        (
            "passports.history: an empty uid",
            "vault.calendar.passports.history",
            json!({"event_ref": event, "system": "google", "uid": ""}),
        ),
        (
            "read: an unknown field",
            "vault.calendar.read",
            json!({"event_ref": event, "ics": "BEGIN:VCALENDAR"}),
        ),
    ];
    for (case, verb, input) in rows {
        let refused = door::invoke(&owner, verb, input).expect_err(case);
        assert_eq!(refused.code, "BAD_REQUEST", "{case}: {refused:?}");
    }
}
