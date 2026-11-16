//! Served door tests for calendar passports (ARCH-0060; FIX
//! CAL-PASSPORT-PROMISES-NO-INPROCESS-DOOR). The same UID imported from two
//! systems resolves to one EVENT with one passport per system, and only an
//! admitted passport carries authority: a pending revision is recorded in
//! `vault.calendar.passports.history` but is never the
//! `vault.calendar.passports.read` head. The admitted head stays the head
//! until its revision is approved, and a rejected revision leaves it admitted
//! (FIX CAL-PASSPORT-PENDING-REVISION-SUPERSEDES-AT-IMPORT). Only the owner's
//! ICS import (or a feed poll) mints a passport; `vault.claims.seed` cannot,
//! because a passport's `content_hash` must be msgpack Binary.
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
use std::time::Duration;
use tower::ServiceExt;

/// A passport claim's predicate (`PREDICATE_CALENDAR_PASSPORT`).
const PASSPORT_PREDICATE: &str = "calendar.passport";
/// A filed claim's approval (`ClaimApprovalStatus::as_str`).
const PENDING: &str = "proposed";
/// A settled claim's approval (`ClaimApprovalStatus::as_str`).
const ADMITTED: &str = "approved";
/// A declined claim's approval (`ClaimApprovalStatus::as_str`).
const REJECTED: &str = "rejected";
/// A live claim's lifecycle (`ClaimLifecycleStatus::as_str`).
const ACTIVE: &str = "active";
/// A replaced claim's lifecycle (`ClaimLifecycleStatus::as_str`).
const SUPERSEDED: &str = "superseded";

/// The facade's generated dispatch polls a frame of several MiB in a dev
/// build, more than a test thread's default stack, so each test runs on
/// threads sized as the server sizes its own.
#[test]
fn same_uid_from_two_systems_resolves_one_event() {
    run_on_engine_stack("passport-one-event", same_uid_one_event);
}

#[test]
fn pending_passport_revision_is_recorded_but_never_the_head() {
    run_on_engine_stack("passport-pending-head", pending_revision_never_head);
}

#[test]
fn rejected_passport_revision_leaves_the_admitted_head() {
    run_on_engine_stack("passport-rejected-revision", rejected_revision_keeps_head);
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

/// A minimal complete VCALENDAR with one VEVENT, CRLF line ends.
fn ics_feed(uid: &str, sequence: u32, summary: &str) -> String {
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\nBEGIN:VEVENT\r\n",
    );
    out.push_str(&format!("UID:{uid}\r\n"));
    out.push_str("DTSTAMP:20260302T070000Z\r\n");
    out.push_str("DTSTART:20260302T090000Z\r\n");
    out.push_str("DTEND:20260302T093000Z\r\n");
    out.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    out.push_str(&format!("SUMMARY:{summary}\r\n"));
    out.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    out
}

/// Uploads ICS bytes as a `text/calendar` artifact; answers its id hex and
/// head version, the import's `source_blob_ref` and `source_version`.
async fn upload_ics(caller: &OwnerCaller, name: &str, ics: &str) -> (String, u64) {
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
    (blob_ref, version)
}

/// Imports one uploaded ICS version for `system`; answers the import receipt.
async fn import_ics(caller: &OwnerCaller, system: &str, blob_ref: &str, version: u64) -> Value {
    let input = json!({"system": system, "source_blob_ref": blob_ref, "source_version": version});
    let (status, code, body) = caller.call("vault.calendar.ics.import", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "import for {system}: {body}"
    );
    eprintln!("import receipt: {body}");
    body
}

/// The fresh `calendar.passport` claim of the receipt's single event: the one
/// not in `exclude`, since earlier imports' passports share the same EVENT. A
/// fresh passport always files pending.
fn passport_claim_ref(receipt: &Value, exclude: &[String]) -> String {
    let claims = receipt["events"][0]["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("import claims: {receipt}"));
    let mut fresh = claims.iter().filter(|claim| {
        claim["predicate"].as_str() == Some(PASSPORT_PREDICATE)
            && !exclude
                .iter()
                .any(|known| claim["claim_ref"].as_str() == Some(known.as_str()))
    });
    let claim = fresh
        .next()
        .unwrap_or_else(|| panic!("one fresh passport claim: {receipt}"));
    assert!(
        fresh.next().is_none(),
        "exactly one fresh passport claim: {receipt}"
    );
    assert_eq!(
        claim["approval"].as_str(),
        Some(PENDING),
        "a fresh passport is pending: {receipt}"
    );
    claim["claim_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("passport claim ref: {receipt}"))
        .to_owned()
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

/// Reviews then rejects `claim_ref` the owner way; both calls answer 200.
async fn reject(caller: &OwnerCaller, claim_ref: &str) {
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
    let input = json!({"claim_ref": claim_ref, "review_id": review_id, "decision": "reject"});
    let (status, code, body) = caller.call("vault.claims.settle", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "reject {claim_ref}: {body}"
    );
}

/// The admitted passport head for one EVENT, system and UID: `value` holds
/// the revision, or null when no admitted passport exists.
async fn passport_read(caller: &OwnerCaller, event_ref: &str, system: &str, uid: &str) -> Value {
    let input = json!({"event_ref": event_ref, "system": system, "uid": uid});
    let (status, code, body) = caller.call("vault.calendar.passports.read", &input).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "read {system} {uid}: {body}"
    );
    body
}

/// Every recorded revision for one EVENT, system and UID, oldest first.
async fn passport_history(caller: &OwnerCaller, event_ref: &str, system: &str, uid: &str) -> Value {
    let input = json!({"event_ref": event_ref, "system": system, "uid": uid});
    let (status, code, body) = caller
        .call("vault.calendar.passports.history", &input)
        .await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::OK, None),
        "history {system} {uid}: {body}"
    );
    body
}

/// The events of an import receipt.
fn receipt_events(receipt: &Value) -> &[Value] {
    receipt["events"]
        .as_array()
        .unwrap_or_else(|| panic!("import events: {receipt}"))
}

/// The single event's ref of an import receipt.
fn receipt_event_ref(receipt: &Value) -> &str {
    receipt["events"][0]["event_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("event ref: {receipt}"))
}

async fn same_uid_one_event() {
    let caller = serve("passport-one-event").await;
    let uid = "standup-7f3a@example.test";

    let (blob_a, version_a) = upload_ics(&caller, "work.ics", &ics_feed(uid, 0, "Standup")).await;
    let first = import_ics(&caller, "work-calendar", &blob_a, version_a).await;
    assert_eq!(
        receipt_events(&first).len(),
        1,
        "one import mints one EVENT: {first}"
    );
    let event = receipt_event_ref(&first).to_owned();
    let claim_a = passport_claim_ref(&first, &[]);

    let (blob_b, version_b) = upload_ics(&caller, "home.ics", &ics_feed(uid, 0, "Standup")).await;
    let second = import_ics(&caller, "home-calendar", &blob_b, version_b).await;
    let same_event = "the same UID from a second system resolves to the one EVENT \
        (arch-0060 N passports -> 1 entity)";
    assert_eq!(
        receipt_event_ref(&second),
        event.as_str(),
        "{same_event}: {second}"
    );
    let claim_b = passport_claim_ref(&second, &[claim_a.clone()]);
    assert_ne!(claim_b, claim_a, "two systems mint two passports: {second}");

    let system = "work-calendar";
    let history = passport_history(&caller, &event, system, uid).await;
    let revisions = history["value"]
        .as_array()
        .unwrap_or_else(|| panic!("revisions: {history}"));
    assert_eq!(
        revisions.len(),
        1,
        "one work revision is recorded: {history}"
    );
    let rev = &revisions[0];
    assert_eq!(
        rev["claim_ref"].as_str(),
        Some(claim_a.as_str()),
        "names its passport: {history}"
    );
    assert_eq!(
        rev["event_ref"].as_str(),
        Some(event.as_str()),
        "names the EVENT: {history}"
    );
    assert_eq!(
        rev["passport"]["system"].as_str(),
        Some(system),
        "carries its system: {history}"
    );

    let system = "home-calendar";
    let history = passport_history(&caller, &event, system, uid).await;
    let revisions = history["value"]
        .as_array()
        .unwrap_or_else(|| panic!("revisions: {history}"));
    assert_eq!(
        revisions.len(),
        1,
        "one home revision is recorded: {history}"
    );
    let rev = &revisions[0];
    assert_eq!(
        rev["claim_ref"].as_str(),
        Some(claim_b.as_str()),
        "names its passport: {history}"
    );
    assert_eq!(
        rev["event_ref"].as_str(),
        Some(event.as_str()),
        "names the EVENT: {history}"
    );
    assert_eq!(
        rev["passport"]["system"].as_str(),
        Some(system),
        "carries its system: {history}"
    );

    approve(&caller, &claim_a).await;
    approve(&caller, &claim_b).await;

    let head = passport_read(&caller, &event, "work-calendar", uid).await;
    let got = &head["value"];
    assert_eq!(
        got["claim_ref"].as_str(),
        Some(claim_a.as_str()),
        "is the work passport: {head}"
    );
    assert_eq!(
        got["event_ref"].as_str(),
        Some(event.as_str()),
        "names the work EVENT: {head}"
    );
    assert_eq!(
        got["approval"].as_str(),
        Some(ADMITTED),
        "the work head is admitted: {head}"
    );

    let head = passport_read(&caller, &event, "home-calendar", uid).await;
    let got = &head["value"];
    assert_eq!(
        got["claim_ref"].as_str(),
        Some(claim_b.as_str()),
        "is the home passport: {head}"
    );
    assert_eq!(
        got["event_ref"].as_str(),
        Some(event.as_str()),
        "names the home EVENT: {head}"
    );
    assert_eq!(
        got["approval"].as_str(),
        Some(ADMITTED),
        "the home head is admitted: {head}"
    );
}

async fn pending_revision_never_head() {
    let caller = serve("passport-pending-head").await;
    let uid = "standup-7f3a@example.test";

    let (blob0, version0) = upload_ics(&caller, "work.ics", &ics_feed(uid, 0, "Standup")).await;
    let first = import_ics(&caller, "work-calendar", &blob0, version0).await;
    let event = receipt_event_ref(&first).to_owned();
    let rev0 = passport_claim_ref(&first, &[]);

    let head = passport_read(&caller, &event, "work-calendar", uid).await;
    assert!(
        head["value"].is_null(),
        "a pending passport is never the admitted head: {head}"
    );

    let history = passport_history(&caller, &event, "work-calendar", uid).await;
    let revisions = history["value"]
        .as_array()
        .unwrap_or_else(|| panic!("revisions: {history}"));
    assert_eq!(revisions.len(), 1, "one revision is recorded: {history}");
    let rev = &revisions[0];
    assert_eq!(
        rev["claim_ref"].as_str(),
        Some(rev0.as_str()),
        "names the revision: {history}"
    );
    assert_eq!(
        rev["approval"].as_str(),
        Some(PENDING),
        "the revision files pending: {history}"
    );
    let rev0_at = rev["recorded_at"]
        .as_u64()
        .unwrap_or_else(|| panic!("recorded_at: {history}"));

    approve(&caller, &rev0).await;
    let head = passport_read(&caller, &event, "work-calendar", uid).await;
    let got = &head["value"];
    assert_eq!(
        got["claim_ref"].as_str(),
        Some(rev0.as_str()),
        "the head is rev0: {head}"
    );
    assert_eq!(
        got["passport"]["last_sequence"].as_u64(),
        Some(0),
        "is SEQUENCE 0: {head}"
    );

    // History sorts by (recorded_at, claim_ref) at second granularity; wait
    // for the next second so [rev0, rev1] order is deterministic.
    for _ in 0..30 {
        if caller.vault.now_recorded_at() > rev0_at {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (blob1, version1) = upload_ics(
        &caller,
        "work-2.ics",
        &ics_feed(uid, 1, "Standup (revised)"),
    )
    .await;
    let second = import_ics(&caller, "work-calendar", &blob1, version1).await;
    assert_eq!(
        receipt_event_ref(&second),
        event.as_str(),
        "a revision keeps its EVENT: {second}"
    );
    let rev1 = passport_claim_ref(&second, &[rev0.clone()]);
    assert_ne!(rev1, rev0, "a revision mints a new passport: {second}");

    let history = passport_history(&caller, &event, "work-calendar", uid).await;
    let revisions = history["value"]
        .as_array()
        .unwrap_or_else(|| panic!("revisions: {history}"));
    assert_eq!(revisions.len(), 2, "both revisions are recorded: {history}");
    let oldest = &revisions[0];
    let newest = &revisions[1];
    assert_eq!(
        oldest["claim_ref"].as_str(),
        Some(rev0.as_str()),
        "lists rev0 first: {history}"
    );
    assert_eq!(
        newest["claim_ref"].as_str(),
        Some(rev1.as_str()),
        "lists rev1 second: {history}"
    );
    assert_eq!(
        newest["approval"].as_str(),
        Some(PENDING),
        "the revision files pending: {history}"
    );
    let seq = newest["passport"]["last_sequence"].as_u64();
    assert_eq!(seq, Some(1), "the revision carries SEQUENCE 1: {history}");

    // While rev1 waits, rev0 keeps its authority: the pending revision
    // stages its supersession and closes nothing (FIX
    // CAL-PASSPORT-PENDING-REVISION-SUPERSEDES-AT-IMPORT).
    let head = passport_read(&caller, &event, "work-calendar", uid).await;
    eprintln!("pending revision head: {}", head["value"]);
    assert_head(&head, &rev0, 0, "rev0 is still the head while rev1 waits");
    let history = passport_history(&caller, &event, "work-calendar", uid).await;
    assert_revision(&history, &rev0, ADMITTED, ACTIVE, "rev0 stays admitted");

    approve(&caller, &rev1).await;
    let head = passport_read(&caller, &event, "work-calendar", uid).await;
    assert_head(&head, &rev1, 1, "the approval makes rev1 the head");
    let history = passport_history(&caller, &event, "work-calendar", uid).await;
    assert_revision(
        &history,
        &rev0,
        ADMITTED,
        SUPERSEDED,
        "the approval closes rev0",
    );
}

/// A rejected revision leaves the admitted head as it was and stays on record,
/// the same content is not proposed again, a later revision that replaces a
/// pending one still closes the admitted head only when it is approved, and
/// the rejected revision no longer steers the diff once a later one is
/// admitted.
async fn rejected_revision_keeps_head() {
    let caller = serve("passport-rejected-revision").await;
    let uid = "review-91c2@example.test";
    let system = "home-calendar";

    let (blob, version) = upload_ics(&caller, "home.ics", &ics_feed(uid, 0, "Review")).await;
    let first = import_ics(&caller, system, &blob, version).await;
    let event = receipt_event_ref(&first).to_owned();
    let rev0 = passport_claim_ref(&first, &[]);
    approve(&caller, &rev0).await;

    let revised = ics_feed(uid, 1, "Review (moved)");
    let (blob, version) = upload_ics(&caller, "home-1.ics", &revised).await;
    let second = import_ics(&caller, system, &blob, version).await;
    let rev1 = passport_claim_ref(&second, &[rev0.clone()]);
    let head = passport_read(&caller, &event, system, uid).await;
    assert_head(&head, &rev0, 0, "rev0 is still the head while rev1 waits");

    reject(&caller, &rev1).await;
    let head = passport_read(&caller, &event, system, uid).await;
    assert_head(&head, &rev0, 0, "a rejected revision leaves rev0 the head");
    let history = passport_history(&caller, &event, system, uid).await;
    assert_revision(&history, &rev0, ADMITTED, ACTIVE, "rev0 stays admitted");
    assert_revision(&history, &rev1, REJECTED, ACTIVE, "rev1 is rejected");

    // The feed still says SEQUENCE 1: the rejected content is not proposed
    // again.
    let (blob, version) = upload_ics(&caller, "home-1-again.ics", &revised).await;
    import_ics(&caller, system, &blob, version).await;
    let history = passport_history(&caller, &event, system, uid).await;
    assert_eq!(
        revisions(&history).len(),
        2,
        "the rejected content files no new revision: {history}"
    );

    let (blob, version) = upload_ics(&caller, "home-2.ics", &ics_feed(uid, 2, "Review (2)")).await;
    let third = import_ics(&caller, system, &blob, version).await;
    let rev2 = passport_claim_ref(&third, &[rev0.clone(), rev1.clone()]);
    let (blob, version) = upload_ics(&caller, "home-3.ics", &ics_feed(uid, 3, "Review (3)")).await;
    let fourth = import_ics(&caller, system, &blob, version).await;
    let rev3 = passport_claim_ref(&fourth, &[rev0.clone(), rev1.clone(), rev2.clone()]);
    let head = passport_read(&caller, &event, system, uid).await;
    assert_head(&head, &rev0, 0, "rev0 is still the head while rev3 waits");
    let history = passport_history(&caller, &event, system, uid).await;
    assert_revision(
        &history,
        &rev2,
        PENDING,
        SUPERSEDED,
        "rev3 replaces the pending rev2",
    );
    // A Reject is final: no lifecycle transition follows it, so the rejected
    // revision stays on record as it was.
    assert_revision(
        &history,
        &rev1,
        REJECTED,
        ACTIVE,
        "the rejected rev1 stays as it was",
    );

    approve(&caller, &rev3).await;
    let head = passport_read(&caller, &event, system, uid).await;
    assert_head(&head, &rev3, 3, "the approval makes rev3 the head");
    let history = passport_history(&caller, &event, system, uid).await;
    assert_revision(
        &history,
        &rev0,
        ADMITTED,
        SUPERSEDED,
        "the approval closes rev0",
    );
    assert_eq!(
        revisions(&history).len(),
        4,
        "four revisions are recorded: {history}"
    );

    // The feed still says SEQUENCE 3: the diff reads the admitted rev3, not
    // the older rejected rev1, so the head's own content files nothing.
    let (blob, version) =
        upload_ics(&caller, "home-3-again.ics", &ics_feed(uid, 3, "Review (3)")).await;
    import_ics(&caller, system, &blob, version).await;
    let history = passport_history(&caller, &event, system, uid).await;
    assert_eq!(
        revisions(&history).len(),
        4,
        "the admitted head's content files no new revision: {history}"
    );
}

/// Asserts the admitted head is `claim_ref` at SEQUENCE `sequence`.
fn assert_head(head: &Value, claim_ref: &str, sequence: u64, what: &str) {
    let got = &head["value"];
    assert_eq!(got["claim_ref"].as_str(), Some(claim_ref), "{what}: {head}");
    assert_eq!(
        got["passport"]["last_sequence"].as_u64(),
        Some(sequence),
        "{what} (SEQUENCE {sequence}): {head}"
    );
}

/// The recorded revisions of a history read.
fn revisions(history: &Value) -> &[Value] {
    history["value"]
        .as_array()
        .unwrap_or_else(|| panic!("revisions: {history}"))
}

/// Asserts the recorded revision `claim_ref` has `approval` and `lifecycle`.
fn assert_revision(history: &Value, claim_ref: &str, approval: &str, lifecycle: &str, what: &str) {
    let revision = revisions(history)
        .iter()
        .find(|revision| revision["claim_ref"].as_str() == Some(claim_ref))
        .unwrap_or_else(|| panic!("{what}: {claim_ref} is recorded: {history}"));
    assert_eq!(
        (
            revision["approval"].as_str(),
            revision["lifecycle"].as_str()
        ),
        (Some(approval), Some(lifecycle)),
        "{what}: {history}"
    );
}
