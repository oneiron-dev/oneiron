//! Served door tests for imported calendar attendees (ARCH-0003 §G.1
//! predicate registry, line 272: `calendar.attendee` is "set — one per
//! attendee", conflict set `(event, who)`; FIX
//! CALENDAR-MULTI-CLAIM-SETTLE-SUPERSEDES). The owner's approval of one
//! attendee through `vault.claims.review` + `vault.claims.settle` never
//! closes another attendee of the same EVENT; it closes only an approved
//! row for the same `who`, here the same person as another calendar system
//! reported them, whichever way that system spells the address (a `MAILTO:`
//! prefix and letter case are vendor spelling, as invite hygiene reads them).
//! `vault.claims.list` reads the rows back.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test calendar_ics_attendee_doors`. The
//! test calls no test door; it needs `oneiron/test-support` for
//! `MemoryKeystore`.
#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// An attendee claim's predicate (`PREDICATE_CALENDAR_ATTENDEE`).
const ATTENDEE_PREDICATE: &str = "calendar.attendee";
/// A filed claim's approval (`ClaimApprovalStatus::as_str`).
const PENDING: &str = "proposed";
/// A settled claim's approval (`ClaimApprovalStatus::as_str`).
const ADMITTED: &str = "approved";
/// A standing claim's lifecycle (`ClaimLifecycleStatus::as_str`).
const ACTIVE: &str = "active";
/// A closed claim's lifecycle (`ClaimLifecycleStatus::as_str`).
const SUPERSEDED: &str = "superseded";

const ADA: &str = "mailto:ada@example.test";
const GRACE: &str = "mailto:grace@example.test";
/// Ada's address as a second calendar system spells it.
const ADA_OTHER_SPELLING: &str = "MAILTO:Ada@Example.test";

/// The facade's generated dispatch polls a frame of several MiB in a dev
/// build, more than a test thread's default stack, so each test runs on
/// threads sized as the server sizes its own.
#[test]
fn approving_a_second_attendee_keeps_the_first() {
    run_on_engine_stack("attendee-second-keeps-first", second_attendee_keeps_first);
}

#[test]
fn an_attendee_approved_again_replaces_only_its_own_row() {
    run_on_engine_stack("attendee-same-who-replaces", same_who_replaces_only_its_row);
}

#[test]
fn an_attendee_spelled_differently_by_another_system_is_one_attendee() {
    run_on_engine_stack(
        "attendee-other-spelling",
        other_spelling_replaces_only_its_row,
    );
}

/// One owner-signed facade call and its status, error code and body.
struct OwnerCaller {
    _dir: tempfile::TempDir,
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
}

impl OwnerCaller {
    async fn call(&self, verb: &str, body: &Value) -> (StatusCode, Option<String>, Value) {
        // Each request proves possession afresh; the host secret is not a bearer.
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("facade response body");
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let code = body["error"]["code"].as_str().map(str::to_owned);
        (status, code, body)
    }
}

/// A fresh vault and server with their owner caller: the host root slip of
/// a device vault, which the owner door admits as the vault's owner.
async fn serve(name: &str) -> OwnerCaller {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(name.into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let token = slip.to_token().expect("owner slip token");
    OwnerCaller {
        _dir: dir,
        app: build_app(server),
        vault,
        issuer,
        slip,
        token,
    }
}

/// A minimal complete VCALENDAR with one VEVENT and one ATTENDEE line per
/// `(who, partstat)`, CRLF line ends.
fn ics_feed(uid: &str, attendees: &[(&str, &str)]) -> String {
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\nBEGIN:VEVENT\r\n",
    );
    out.push_str(&format!("UID:{uid}\r\n"));
    out.push_str("DTSTAMP:20260302T070000Z\r\n");
    out.push_str("DTSTART:20260302T090000Z\r\n");
    out.push_str("DTEND:20260302T093000Z\r\n");
    out.push_str("SEQUENCE:0\r\n");
    out.push_str("SUMMARY:Design review\r\n");
    for (who, partstat) in attendees {
        out.push_str(&format!(
            "ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT={partstat}:{who}\r\n"
        ));
    }
    out.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    out
}

/// Uploads ICS bytes as a `text/calendar` artifact and imports that version
/// for `system`; answers the import receipt.
async fn import_feed(caller: &OwnerCaller, system: &str, name: &str, ics: &str) -> Value {
    let encoded = base64::engine::general_purpose::STANDARD.encode(ics.as_bytes());
    let input = json!({"name": name, "media_type": "text/calendar", "content_base64": encoded});
    let (status, code, body) = caller.call("vault.artifacts.create", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "upload {name}: {body}"
    );
    let view = if body.get("artifact_id").is_some() {
        &body
    } else {
        &body["value"]
    };
    let blob_ref = view["artifact_id"]
        .as_str()
        .unwrap_or_else(|| panic!("artifact id hex: {body}"))
        .to_owned();
    let version = view["head"]
        .as_u64()
        .unwrap_or_else(|| panic!("artifact head: {body}"));
    let input = json!({"system": system, "source_blob_ref": blob_ref, "source_version": version});
    let (status, code, body) = caller.call("vault.calendar.ics.import", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "import for {system}: {body}"
    );
    body
}

/// The single event's ref of an import receipt.
fn receipt_event_ref(receipt: &Value) -> String {
    receipt["events"][0]["event_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("event ref: {receipt}"))
        .to_owned()
}

/// One `calendar.attendee` row as `vault.claims.list` serves it.
#[derive(Debug, Clone)]
struct AttendeeRow {
    claim_ref: String,
    who: String,
    partstat: String,
    approval: String,
    lifecycle: String,
}

/// Every `calendar.attendee` claim on `event_ref`, in every lifecycle.
async fn attendee_rows(caller: &OwnerCaller, event_ref: &str) -> Vec<AttendeeRow> {
    let input = json!({"subject_ref": event_ref, "predicate": ATTENDEE_PREDICATE, "limit": 64});
    let (status, code, body) = caller.call("vault.claims.list", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "list attendees of {event_ref}: {body}"
    );
    let text = |row: &Value, field: &str| {
        row[field]
            .as_str()
            .unwrap_or_else(|| panic!("attendee {field}: {body}"))
            .to_owned()
    };
    body["value"]
        .as_array()
        .unwrap_or_else(|| panic!("listed claims: {body}"))
        .iter()
        .map(|row| AttendeeRow {
            claim_ref: text(row, "claim_ref"),
            who: text(&row["value"], "who"),
            partstat: text(&row["value"], "partstat"),
            approval: text(row, "approval"),
            lifecycle: text(row, "lifecycle"),
        })
        .collect()
}

/// The one pending attendee row for `(who, partstat)`.
fn pending_row(rows: &[AttendeeRow], who: &str, partstat: &str) -> AttendeeRow {
    let mut found = rows
        .iter()
        .filter(|row| row.who == who && row.partstat == partstat && row.approval == PENDING);
    let row = found
        .next()
        .unwrap_or_else(|| panic!("a pending attendee {who} {partstat}: {rows:?}"))
        .clone();
    assert!(
        found.next().is_none(),
        "exactly one pending attendee {who} {partstat}: {rows:?}"
    );
    row
}

/// The row named `claim_ref`.
fn row_named<'a>(rows: &'a [AttendeeRow], claim_ref: &str) -> &'a AttendeeRow {
    rows.iter()
        .find(|row| row.claim_ref == claim_ref)
        .unwrap_or_else(|| panic!("attendee row {claim_ref}: {rows:?}"))
}

/// Reviews then approves `claim_ref` the owner way; both calls answer 200.
async fn approve(caller: &OwnerCaller, claim_ref: &str) {
    let input = json!({"claim_ref": claim_ref});
    let (status, code, body) = caller.call("vault.claims.review", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "review {claim_ref}: {body}"
    );
    let review_id = body["review_id"]
        .as_str()
        .unwrap_or_else(|| panic!("review id: {body}"));
    let input = json!({"claim_ref": claim_ref, "review_id": review_id, "decision": "approve"});
    let (status, code, body) = caller.call("vault.claims.settle", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "settle {claim_ref}: {body}"
    );
}

/// Asserts the row named `claim_ref` stands approved.
fn assert_stands(rows: &[AttendeeRow], claim_ref: &str, what: &str) {
    let row = row_named(rows, claim_ref);
    assert_eq!(
        (row.lifecycle.as_str(), row.approval.as_str()),
        (ACTIVE, ADMITTED),
        "{what} stands approved: {rows:?}"
    );
}

async fn second_attendee_keeps_first() {
    let caller = serve("attendee-second-keeps-first").await;
    let uid = "design-review-41c2@example.test";
    let ics = ics_feed(uid, &[(ADA, "ACCEPTED"), (GRACE, "NEEDS-ACTION")]);
    let receipt = import_feed(&caller, "work-calendar", "work.ics", &ics).await;
    let event = receipt_event_ref(&receipt);

    let rows = attendee_rows(&caller, &event).await;
    assert_eq!(
        rows.len(),
        2,
        "one attendee claim per ATTENDEE line: {rows:?}"
    );
    let ada = pending_row(&rows, ADA, "ACCEPTED");
    let grace = pending_row(&rows, GRACE, "NEEDS-ACTION");

    approve(&caller, &ada.claim_ref).await;
    approve(&caller, &grace.claim_ref).await;

    let rows = attendee_rows(&caller, &event).await;
    assert_stands(
        &rows,
        &ada.claim_ref,
        "the first approved attendee, after the owner approved a second one",
    );
    assert_stands(&rows, &grace.claim_ref, "the second approved attendee");
    let standing = rows.iter().filter(|row| row.lifecycle == ACTIVE).count();
    assert_eq!(
        standing, 2,
        "an approved meeting keeps both attendees: {rows:?}"
    );
}

async fn same_who_replaces_only_its_row() {
    let caller = serve("attendee-same-who-replaces").await;
    let uid = "design-review-41c2@example.test";
    let work = ics_feed(uid, &[(ADA, "NEEDS-ACTION"), (GRACE, "ACCEPTED")]);
    let receipt = import_feed(&caller, "work-calendar", "work.ics", &work).await;
    let event = receipt_event_ref(&receipt);
    // The same UID from a second system resolves to the one EVENT
    // (arch-0060), whose own feed has Ada's later answer.
    let home = ics_feed(uid, &[(ADA, "ACCEPTED")]);
    let receipt = import_feed(&caller, "home-calendar", "home.ics", &home).await;
    assert_eq!(
        receipt_event_ref(&receipt),
        event,
        "the second system's feed lands on the one EVENT: {receipt}"
    );

    let rows = attendee_rows(&caller, &event).await;
    assert_eq!(
        rows.len(),
        3,
        "each system files its own attendee rows: {rows:?}"
    );
    let work_ada = pending_row(&rows, ADA, "NEEDS-ACTION");
    let work_grace = pending_row(&rows, GRACE, "ACCEPTED");
    let home_ada = pending_row(&rows, ADA, "ACCEPTED");

    approve(&caller, &work_ada.claim_ref).await;
    approve(&caller, &work_grace.claim_ref).await;
    approve(&caller, &home_ada.claim_ref).await;

    let rows = attendee_rows(&caller, &event).await;
    assert_stands(
        &rows,
        &work_grace.claim_ref,
        "Grace, whom no later approval names",
    );
    assert_stands(&rows, &home_ada.claim_ref, "Ada's newest approved answer");
    assert_eq!(
        row_named(&rows, &work_ada.claim_ref).lifecycle,
        SUPERSEDED,
        "Ada's older approved row is closed by her newer one (conflict set (event, who)): {rows:?}"
    );
    let standing = rows.iter().filter(|row| row.lifecycle == ACTIVE).count();
    assert_eq!(standing, 2, "one standing row per attendee: {rows:?}");
}

async fn other_spelling_replaces_only_its_row() {
    let caller = serve("attendee-other-spelling").await;
    let uid = "design-review-41c2@example.test";
    let work = ics_feed(uid, &[(ADA, "NEEDS-ACTION"), (GRACE, "ACCEPTED")]);
    let receipt = import_feed(&caller, "work-calendar", "work.ics", &work).await;
    let event = receipt_event_ref(&receipt);
    // The second system spells Ada's address with its own prefix and case.
    let home = ics_feed(uid, &[(ADA_OTHER_SPELLING, "ACCEPTED")]);
    let receipt = import_feed(&caller, "home-calendar", "home.ics", &home).await;
    assert_eq!(
        receipt_event_ref(&receipt),
        event,
        "the second system's feed lands on the one EVENT: {receipt}"
    );

    let rows = attendee_rows(&caller, &event).await;
    assert_eq!(
        rows.len(),
        3,
        "each system files its own attendee rows: {rows:?}"
    );
    let work_ada = pending_row(&rows, ADA, "NEEDS-ACTION");
    let work_grace = pending_row(&rows, GRACE, "ACCEPTED");
    let home_ada = pending_row(&rows, ADA_OTHER_SPELLING, "ACCEPTED");

    approve(&caller, &work_ada.claim_ref).await;
    approve(&caller, &work_grace.claim_ref).await;
    approve(&caller, &home_ada.claim_ref).await;

    let rows = attendee_rows(&caller, &event).await;
    assert_stands(
        &rows,
        &work_grace.claim_ref,
        "Grace, whom no later approval names",
    );
    assert_stands(
        &rows,
        &home_ada.claim_ref,
        "Ada's newest approved answer, in the second system's spelling",
    );
    assert_eq!(
        row_named(&rows, &work_ada.claim_ref).lifecycle,
        SUPERSEDED,
        "Ada's older row is closed by her newer one under another spelling of her address: {rows:?}"
    );
    let standing = rows.iter().filter(|row| row.lifecycle == ACTIVE).count();
    assert_eq!(standing, 2, "one standing row per attendee: {rows:?}");
}
