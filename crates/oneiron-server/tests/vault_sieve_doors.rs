//! The sieve's fifteen doors (ARCH-0026), entered as the SDK enters them:
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps): the interest queue, retained
//! spans, consumed-span receipts, the sieve and recipe policy rows, the
//! wake-budget lease and its refill, evidence and its replay, the wake
//! cadence, settlements and one settlement, and the budgets lower knob.
//!
//! The promises (canon `oneiron/agents/oneiron-arch-0026-dreamer-v2.md`;
//! mirror `oneiron-docs/generated/llms-full.txt`):
//! "A TURN the Dreamer may not read gives no span." (`:100`, mirror
//! `:343406`); "The queue, the readings and the cursor commit together,
//! so a restart reads nothing twice." (`:97`, mirror `:343403`);
//! "`settled: true` says only that every job ended, never that it
//! succeeded." (`:71`, mirror `:343377`). Beside them: the two policy rows
//! round-trip and validate; a lease refill replaces its total and replays
//! idempotently; `budgets.lower` lowers for the owner, refuses a raise,
//! and refuses a holder without the grant; and the fresh-vault refusal
//! table holds its row for every verb.
//!
//! Each test owns a fresh vault; each sieve pass runs in process on the
//! fixture's own `Arc<Vault>` (no synchronous pass door exists) and every
//! assertion reads through the facade. The vault's keystore is a
//! `MemoryKeystore`, which `oneiron/test-support` forwards
//! (`oneiron-keystore/test-keystore`); no cfg door is used.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_sieve_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, FailAttempt, FailOutcome,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::dreamer_runner::{
    DreamerBudgetReserveOutcome, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, ReserveDreamerBudget,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::{
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use rmpv::Value as MsgpackValue;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

/// The engine refuses a knob to a caller with no grant.
const GRANT_NEEDED: &str = "invalid config: changing this knob needs the owner or its \
    engine.controls class grant";
/// The lower-only door refuses a budget above its value in force.
const LOWER_ONLY: &str = "invalid config: this door only lowers the sieve's per-pass \
    budgets; raising one is the owner's act at vault.sieve.policy.set";
/// A refill below spent and reserved units is refused.
const REFILL_BELOW: &str = "invalid attempt queue record: dreamer budget refill total is below \
    spent and reserved units";

/// The conversation a witnessed turn lands in, as the sieve's own tests use it.
const ROOM_HEX: &str = "52525252525252525252525252525252";
/// Date and name text the rules flag without any model.
const SPAN_TEXT: &str = "We met Alice Smith on October 12, 2026.";
/// The P1 turn's pinned id.
const P1_TURN_HEX: &str = "76767676767676767676767676767676";
/// The P3 turn's pinned id.
const P3_TURN_HEX: &str = "71717171717171717171717171717171";

struct Fixture {
    vault: Arc<Vault>,
    _dir: Option<tempfile::TempDir>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every person credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

/// A live PERSON entity, as `graduation_demote_holder_door.rs` places one.
fn seed_person(vault: &Vault) -> EntityId {
    let who = EntityId::now();
    vault
        .put_entity(
            &who,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    who
}

/// A credential this host mints `who`, holding `read` and `write`:
/// a person's own slip, not owner-grade.
fn mint_person_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
    actor_class: &str,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some(actor_class.to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

async fn setup_in(path: &std::path::Path, keystore: Arc<MemoryKeystore>) -> Fixture {
    let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(keystore);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-sieve-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let who = seed_person(&vault);
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who, "human");
    let person_token = person_slip.to_token().expect("person slip token");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: None,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: who,
        person_slip,
        person_token,
    }
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let path = dir.path().to_owned();
    let mut fixture = setup_in(&path, Arc::new(MemoryKeystore::new())).await;
    fixture._dir = Some(dir);
    fixture
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn credential_binding(fixture: &Fixture, slip: &CapabilitySlip) -> String {
    holder_proof(slip, &holder_key(), fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

fn person_binding(fixture: &Fixture) -> String {
    credential_binding(fixture, &fixture.person_slip)
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let path = format!("/v1/core/facade/{verb}");
    let token = fixture.owner_token.clone();
    post(fixture, &path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let path = format!("/v1/core/facade/{verb}");
    let token = fixture.person_token.clone();
    post(fixture, &path, &token, person_binding(fixture), body).await
}

/// An asserted refusal: its status, its code, and the exact message the
/// source fixes.
fn assert_refusal(
    status: StatusCode,
    refused: &Value,
    expected: StatusCode,
    code: &str,
    message: &str,
    what: &str,
) {
    assert_eq!(status, expected, "{what} is refused: {refused}");
    assert_eq!(
        refused["error"]["code"].as_str(),
        Some(code),
        "{what} names its code: {refused}"
    );
    assert_eq!(
        refused["error"]["message"].as_str(),
        Some(message),
        "{what} names its reason: {refused}"
    );
}

/// A body the typed decode refuses before any hook runs.
fn assert_decode_refusal(status: StatusCode, refused: &Value, what: &str) {
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{what} is refused: {refused}"
    );
    assert_eq!(
        refused["error"]["code"].as_str(),
        Some("BAD_REQUEST"),
        "{what} names its code: {refused}"
    );
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("invalid SDK request: "),
        "{what} names its decode failure: {refused}"
    );
}

/// One witnessed TURN under its pinned id, spoken by the fixture person.
fn witness_turn(
    fixture: &Fixture,
    turn_hex: &str,
    text: &str,
    occurred_at: u64,
    metadata: Option<Value>,
) -> EntityId {
    let turn = WitnessTurn {
        conversation_ref: ROOM_HEX.to_owned(),
        turn_ref: Some(turn_hex.to_owned()),
        thread_audience: None,
        occurred_at,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".to_owned(),
            content: text.to_owned(),
            parts: None,
            metadata,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        assertions: Default::default(),
    };
    fixture
        .vault
        .memory(fixture.person, EdgeActorClass::Human)
        .witness(&turn)
        .expect("witness a turn");
    EntityId::from_hex(turn_hex).expect("turn id")
}

/// The Dreamer's live `MessagesRead` grant over one relationship space.
fn grant_dreamer_messages_read(fixture: &Fixture, grant_byte: u8, space: EntityId) {
    let dreamer = fixture
        .vault
        .dreamer_authority()
        .expect("dreamer authority")
        .entity_ref();
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    fixture
        .vault
        .create_access_grant(
            &EntityId::from_bytes([grant_byte; 16]).expect("grant id"),
            &AccessGrant {
                authority_scope,
                principal_ref: dreamer,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: Some(u64::MAX),
                companion_bounds: None,
            },
        )
        .expect("dreamer read grant");
}

/// Lease units held for a fresh child attempt.
fn reserve_lease_units(
    fixture: &Fixture,
    budget_id: &str,
    budget_total_units: u64,
    reserve_units: u64,
    now: u64,
) {
    let store = DreamerRunnerStore::new(&fixture.vault);
    let outcome = store
        .reserve_budget(ReserveDreamerBudget {
            budget_id: budget_id.to_owned(),
            child_attempt: AttemptId::now(),
            budget_total_units,
            reserve_units,
            now,
        })
        .expect("reserve lease units");
    assert!(
        matches!(outcome, DreamerBudgetReserveOutcome::Reserved(_)),
        "the reserve lands: {outcome:?}"
    );
}

/// One shared-runner root, claimed and failed: its wake hex.
fn enqueue_failed_attempt(fixture: &Fixture, now: u64) -> String {
    let store = DreamerRunnerStore::new(&fixture.vault);
    let outcome = store
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: "sieve-doors-settlement".to_owned(),
            input: MsgpackValue::from("input:sieve-doors-settlement"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue a dreamer attempt");
    let attempt_id = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        _ => panic!("enqueue answers enqueued or existing"),
    };
    let wake_hex = EntityId::from_bytes(*attempt_id.as_bytes())
        .expect("wake id")
        .to_hex();
    let attempts = AttemptQueue::new(&fixture.vault);
    let ClaimOutcome::Claimed(claimed) = attempts
        .claim(ClaimAttempt {
            lease_owner: "sieve-doors".to_owned(),
            now,
        })
        .expect("claim the attempt")
    else {
        panic!("the fresh attempt claims");
    };
    assert_eq!(
        claimed.id, attempt_id,
        "the claim takes the enqueued attempt"
    );
    let FailOutcome::Failed(_) = attempts
        .fail(FailAttempt {
            id: attempt_id,
            lease_owner: "sieve-doors".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "sieve doors prove settled covers failed".to_owned(),
            now,
        })
        .expect("fail the attempt")
    else {
        panic!("the leased attempt fails");
    };
    wake_hex
}

/// The sieve policy row round-trips through its doors and validates:
/// a fresh vault answers the shipped defaults, a set answers the row it
/// wrote, and each invalid row is refused without changing the stored row.
#[test]
fn policy_set_round_trips_and_validates() {
    run_on_engine_stack("sieve-policy", || async {
        let fixture = setup().await;
        let (status, fresh) = post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the fresh policy: {fresh}"
        );
        let shipped = json!({
            "max_turns_per_pass": 64,
            "max_scan_per_pass": 4096,
            "max_text_bytes_per_pass": 32768,
            "date_interest": 100,
            "name_interest": 100,
            "absolute_date_confidence": 90,
            "relative_date_confidence": 80,
            "vague_date_confidence": 50,
            "name_confidence": 70,
            "initial_name_confidence": 40,
            "katakana_name_confidence": 40,
            "uncertain_low": 35,
            "uncertain_high": 75,
        });
        assert_eq!(fresh, shipped, "a fresh vault answers the shipped defaults");

        let mut lowered = shipped.clone();
        lowered["max_turns_per_pass"] = json!(32);
        lowered["name_interest"] = json!(50);
        let (status, written) = post_as_owner(
            &fixture,
            "vault.sieve.policy.set",
            json!({"policy": lowered.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner replaces the policy row: {written}"
        );
        assert_eq!(
            written, lowered,
            "the set answers the row it wrote: {written}"
        );
        let (status, again) = post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the row back: {again}");
        assert_eq!(again, lowered, "the read answers the written row: {again}");

        let mut zero_turns = lowered.clone();
        zero_turns["max_turns_per_pass"] = json!(0);
        let mut short_scan = lowered.clone();
        short_scan["max_scan_per_pass"] = json!(10);
        let mut wild_confidence = lowered.clone();
        wild_confidence["name_confidence"] = json!(101);
        let mut crossed_band = lowered.clone();
        crossed_band["uncertain_low"] = json!(80);
        crossed_band["uncertain_high"] = json!(75);
        let invalid_rows = [
            ("a zero-turns policy", zero_turns),
            ("a scan below its turns", short_scan),
            ("a confidence past a hundred", wild_confidence),
            ("a crossed uncertain band", crossed_band),
        ];
        for (what, row) in invalid_rows {
            let (status, refused) =
                post_as_owner(&fixture, "vault.sieve.policy.set", json!({"policy": row})).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "invalid config: invalid dreamer sieve policy row",
                what,
            );
        }
        let (status, refused) = post_as_owner(&fixture, "vault.sieve.policy.set", json!({})).await;
        assert_decode_refusal(status, &refused, "an empty policy set");
        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.policy.set", json!({"policy": {}})).await;
        assert_decode_refusal(status, &refused, "an empty policy row");

        let (status, kept) = post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the row back: {kept}");
        assert_eq!(kept, lowered, "the refusals keep the stored row: {kept}");
    });
}

/// The wake recipe policy row round-trips through its doors and validates:
/// a fresh vault answers the shipped defaults, a set answers the row it
/// wrote, and each invalid row is refused without changing the stored row.
#[test]
fn recipe_policy_set_round_trips_and_validates() {
    run_on_engine_stack("sieve-recipe-policy", || async {
        let fixture = setup().await;
        let (status, fresh) = post_as_owner(&fixture, "vault.sieve.recipe_policy", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the fresh recipe policy: {fresh}"
        );
        let shipped_scalars = [
            ("continuous_rung_spans", json!(64)),
            ("nightly_spans", json!(128)),
            ("nightly_children", json!(16)),
            ("audit_percent", json!(5)),
            ("audit_spans", json!(8)),
            ("audit_window_share", json!(50)),
            ("audit_window_bytes", json!(2048)),
            ("rung_retry_secs", json!(60)),
            ("arc_min_new_statements", json!(1)),
            ("arc_child_calls_per_wake", json!(16)),
            ("arc_synopsis_enabled", json!(false)),
            ("follower_enabled", json!(true)),
            ("follower_sizing_bytes_per_token", json!(3)),
            ("thing_child_code_mode", json!(true)),
            ("thing_child_input_window_divisor", json!(2)),
            ("thing_child_fallback_window_tokens", json!(32768)),
        ];
        for (field, expected) in shipped_scalars {
            assert_eq!(
                fresh[field], expected,
                "a fresh vault answers the shipped {field}: {fresh}"
            );
        }
        for field in [
            "novelty_instruction",
            "typing_instruction",
            "narrative_instruction",
            "audit_window_instruction",
            "follower_instruction",
            "follower_keyframe_instruction",
            "thing_child_instruction",
        ] {
            assert!(
                !fresh[field].as_str().unwrap_or_default().trim().is_empty(),
                "a fresh vault ships {field}: {fresh}"
            );
        }

        let mut raised = fresh.clone();
        raised["audit_spans"] = json!(9);
        raised["nightly_children"] = json!(8);
        let (status, written) = post_as_owner(
            &fixture,
            "vault.sieve.recipe_policy.set",
            json!({"policy": raised.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner replaces the recipe policy row: {written}"
        );
        assert_eq!(
            written, raised,
            "the set answers the row it wrote: {written}"
        );
        let (status, again) = post_as_owner(&fixture, "vault.sieve.recipe_policy", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the row back: {again}");
        assert_eq!(again, raised, "the read answers the written row: {again}");

        let mut zero_spans = raised.clone();
        zero_spans["continuous_rung_spans"] = json!(0);
        let mut empty_instruction = raised.clone();
        empty_instruction["novelty_instruction"] = json!("  ");
        for (what, row) in [
            ("a zero-spans recipe policy", zero_spans),
            ("an empty novelty instruction", empty_instruction),
        ] {
            let (status, refused) = post_as_owner(
                &fixture,
                "vault.sieve.recipe_policy.set",
                json!({"policy": row}),
            )
            .await;
            assert_refusal(
                status,
                &refused,
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "invalid config: invalid Dreamer recipe policy",
                what,
            );
        }
        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.recipe_policy.set", json!({})).await;
        assert_decode_refusal(status, &refused, "an empty recipe policy set");
        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.recipe_policy.set",
            json!({"policy": {}}),
        )
        .await;
        assert_decode_refusal(status, &refused, "an empty recipe policy row");

        let (status, kept) = post_as_owner(&fixture, "vault.sieve.recipe_policy", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the row back: {kept}");
        assert_eq!(kept, raised, "the refusals keep the stored row: {kept}");
    });
}

/// A lease refill replaces its counter's total and replays idempotently:
/// a fresh lease answers no counter, a refill opens it, the same total
/// replayed changes nothing, and a total below spent and reserved units
/// is refused once units are held.
#[test]
fn lease_refill_replaces_and_replays_idempotently() {
    run_on_engine_stack("sieve-lease", || async {
        let fixture = setup().await;
        let lease = json!({"budget_id": "sieve-doors-lease"});
        let (status, fresh) = post_as_owner(&fixture, "vault.sieve.lease", lease.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the fresh lease: {fresh}"
        );
        assert_eq!(
            fresh["budget_id"],
            json!("sieve-doors-lease"),
            "the lease names its budget: {fresh}"
        );
        assert!(
            fresh["counter"].is_null(),
            "no wake opened the lease yet: {fresh}"
        );

        let refill = json!({"budget_id": "sieve-doors-lease", "total_units": 1000});
        let (status, opened) =
            post_as_owner(&fixture, "vault.sieve.lease.refill", refill.clone()).await;
        assert_eq!(status, StatusCode::OK, "owner refills the lease: {opened}");
        assert_eq!(
            opened["counter"],
            json!({
                "total_units": 1000,
                "remaining_units": 1000,
                "reserved_units": 0,
                "updated_at": opened["counter"]["updated_at"],
            }),
            "the refill opens the counter at its total: {opened}"
        );
        let (status, replayed) = post_as_owner(&fixture, "vault.sieve.lease.refill", refill).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner replays the same total: {replayed}"
        );
        assert_eq!(
            replayed["counter"]["total_units"],
            json!(1000),
            "the replay keeps the total: {replayed}"
        );
        assert_eq!(
            replayed["counter"]["remaining_units"],
            json!(1000),
            "the replay adds nothing twice: {replayed}"
        );
        assert_eq!(
            replayed["counter"]["reserved_units"],
            json!(0),
            "the replay holds nothing back: {replayed}"
        );

        let now = fixture.vault.now_recorded_at();
        reserve_lease_units(&fixture, "sieve-doors-lease", 1000, 400, now);
        let (status, held) = post_as_owner(&fixture, "vault.sieve.lease", lease).await;
        assert_eq!(status, StatusCode::OK, "owner reads the held lease: {held}");
        assert_eq!(
            held["counter"]["reserved_units"],
            json!(400),
            "the reserve holds its units: {held}"
        );
        assert_eq!(
            held["counter"]["remaining_units"],
            json!(600),
            "the reserve leaves the rest: {held}"
        );

        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.lease.refill",
            json!({"budget_id": "sieve-doors-lease", "total_units": 300}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            REFILL_BELOW,
            "a refill below spent and reserved units",
        );
        let (status, kept) = post_as_owner(
            &fixture,
            "vault.sieve.lease",
            json!({"budget_id": "sieve-doors-lease"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the lease back: {kept}");
        assert_eq!(
            kept["counter"]["total_units"],
            json!(1000),
            "the refused refill keeps the total: {kept}"
        );
        assert_eq!(
            kept["counter"]["reserved_units"],
            json!(400),
            "the refused refill keeps the hold: {kept}"
        );
    });
}

/// Sieve P1: a TURN the Dreamer may not read gives no span. A
/// relationship turn witnessed with no Dreamer read grant passes the
/// sieve and shows none of its spans on the queue door; once the grant
/// names the Dreamer, the next pass queues its date and its name.
///
/// Canon `oneiron/agents/oneiron-arch-0026-dreamer-v2.md:100` "A TURN the
/// Dreamer may not read gives no span."
#[test]
fn a_turn_the_dreamer_may_not_read_gives_no_span() {
    run_on_engine_stack("sieve-p1", || async {
        let fixture = setup().await;
        let space = EntityId::from_bytes([0x5A; 16]).expect("space id");
        let now = fixture.vault.now_recorded_at();
        let turn = witness_turn(
            &fixture,
            P1_TURN_HEX,
            SPAN_TEXT,
            now,
            Some(json!({"rel": space.to_hex()})),
        );
        let turn_hex = turn.to_hex();
        fixture.vault.sieve_pass(now).expect("first sieve pass");
        let (status, page) = post_as_owner(&fixture, "vault.sieve.queue", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the queue: {page}");
        assert_eq!(
            page["spans"],
            json!([]),
            "a turn the Dreamer may not read gives no span: {page}"
        );

        grant_dreamer_messages_read(&fixture, 0x5B, space);
        fixture
            .vault
            .sieve_pass(now + 1)
            .expect("second sieve pass");
        let (status, page) = post_as_owner(&fixture, "vault.sieve.queue", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the queue: {page}");
        let spans = page["spans"].as_array().expect("queue spans");
        assert_eq!(
            spans.len(),
            2,
            "the granted turn's spans appear on the queue: {page}"
        );
        for span in spans {
            assert_eq!(
                span["turn"].as_str(),
                Some(turn_hex.as_str()),
                "the span belongs to the granted turn: {page}"
            );
        }
        let mut kinds: Vec<&str> = spans
            .iter()
            .map(|span| span["kind"].as_str().expect("span kind"))
            .collect();
        kinds.sort_unstable();
        assert_eq!(
            kinds,
            ["date", "name"],
            "the date and the name queue: {page}"
        );
        assert_eq!(
            page["skipped_unreadable"],
            json!(0),
            "no span waits on a grant now: {page}"
        );
    });
}

/// Sieve P3: a restart reads nothing twice. A pass queues the turn's
/// spans; a second pass with no new turn leaves the queue door
/// identical, a re-read of unchanged words rewrites nothing, and the
/// queue survives a reopen of the vault on the same directory. The
/// reopen holds the same device keystore across both opens, as a real
/// restart keeps its platform key: a `MemoryKeystore` is per-handle
/// memory, so a fresh one would lose the host issuer seed and the
/// reopened vault would not load its issuer.
///
/// Canon `oneiron/agents/oneiron-arch-0026-dreamer-v2.md:97` "The queue,
/// the readings and the cursor commit together, so a restart reads
/// nothing twice."
#[test]
fn a_restart_reads_nothing_twice() {
    run_on_engine_stack("sieve-p3", || async {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let path = dir.path().to_owned();
        let keystore = Arc::new(MemoryKeystore::new());
        let fixture = setup_in(&path, Arc::clone(&keystore)).await;
        let now = fixture.vault.now_recorded_at();
        let turn = witness_turn(&fixture, P3_TURN_HEX, SPAN_TEXT, now, None);
        fixture.vault.sieve_pass(now).expect("first sieve pass");
        let (status, first) = post_as_owner(&fixture, "vault.sieve.queue", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the queue: {first}");
        assert_eq!(
            first["spans"].as_array().expect("queue spans").len(),
            2,
            "the first pass queues the date and the name: {first}"
        );

        fixture
            .vault
            .sieve_pass(now + 1)
            .expect("second sieve pass");
        let (status, second) = post_as_owner(&fixture, "vault.sieve.queue", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the queue: {second}");
        assert_eq!(
            second, first,
            "a second pass with no new turn leaves the queue identical"
        );

        let (status, replayed) = post_as_owner(
            &fixture,
            "vault.sieve.evidence.replay",
            json!({"turn": turn.to_hex()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner replays the turn's evidence: {replayed}"
        );
        assert_eq!(
            replayed["owed"],
            json!(true),
            "the replay owes the turn a read: {replayed}"
        );
        fixture.vault.sieve_pass(now + 2).expect("third sieve pass");
        let (status, third) = post_as_owner(&fixture, "vault.sieve.queue", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the queue: {third}");
        assert_eq!(
            third, first,
            "a re-read of unchanged words rewrites nothing"
        );

        drop(fixture);
        let fixture = setup_in(&path, keystore).await;
        let (status, reopened) = post_as_owner(&fixture, "vault.sieve.queue", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the queue: {reopened}");
        assert_eq!(reopened, first, "the queue survives a reopen of the vault");
    });
}

/// Sieve P2: `settled: true` says only that every job ended, never that
/// it succeeded. One shared-runner root, claimed and failed, settles
/// with its outcome failed; the settlements page lists it settled.
///
/// Canon `oneiron/agents/oneiron-arch-0026-dreamer-v2.md:71` "`settled:
/// true` says only that every job ended, never that it succeeded."
#[test]
fn settled_true_covers_a_failed_job() {
    run_on_engine_stack("sieve-p2", || async {
        let fixture = setup().await;
        let now = fixture.vault.now_recorded_at();
        let wake_hex = enqueue_failed_attempt(&fixture, now);
        let (status, view) = post_as_owner(
            &fixture,
            "vault.sieve.settlements.get",
            json!({"wake": wake_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the settlement: {view}");
        assert_eq!(view["settled"], json!(true), "every job ended: {view}");
        assert_eq!(
            view["outcome"]["state"],
            json!("failed"),
            "the outcome says failed: {view}"
        );
        assert_eq!(
            view["outcome"]["failed"],
            json!([wake_hex.clone()]),
            "the failed job is named: {view}"
        );
        assert_eq!(
            view["outcome"]["waiting_on"],
            json!([]),
            "no job still waits: {view}"
        );
        assert_eq!(
            view["jobs"].as_array().expect("settlement jobs").len(),
            1,
            "the root stands alone: {view}"
        );
        assert_eq!(
            view["jobs"][0]["attempt"],
            json!(wake_hex.clone()),
            "the job is the wake: {view}"
        );
        assert_eq!(
            view["jobs"][0]["state"],
            json!("Failed"),
            "the job reads failed: {view}"
        );

        let (status, page) = post_as_owner(
            &fixture,
            "vault.sieve.settlements",
            json!({"after": null, "limit": 10}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner lists settlements: {page}");
        assert_eq!(
            page["wakes"].as_array().expect("settlement wakes").len(),
            1,
            "the page lists the one wake: {page}"
        );
        assert_eq!(
            page["wakes"][0]["wake"],
            json!(wake_hex.clone()),
            "the page names the wake: {page}"
        );
        assert_eq!(
            page["wakes"][0]["settled"],
            json!(true),
            "the listed wake settled: {page}"
        );
        assert_eq!(
            page["wakes"][0]["outcome"]["state"],
            json!("failed"),
            "the listed outcome says failed: {page}"
        );
        assert!(page["next"].is_null(), "no further page follows: {page}");
    });
}

/// The budgets knob: the owner lowers the sieve's per-pass budgets and
/// the policy row carries the lower value; raising one is refused at
/// this door, and a holder without the `engine.controls` grant is
/// refused whatever it asks.
#[test]
fn budgets_lower_lowers_for_the_owner_and_refuses_a_raise_and_a_holder_without_the_grant() {
    run_on_engine_stack("sieve-budgets-lower", || async {
        let fixture = setup().await;
        let (status, fresh) = post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the fresh policy: {fresh}"
        );
        assert_eq!(
            fresh["max_scan_per_pass"],
            json!(4096),
            "the scan budget ships at 4096: {fresh}"
        );

        let lower = json!({
            "max_turns_per_pass": 64,
            "max_scan_per_pass": 200,
            "max_text_bytes_per_pass": 32768,
        });
        let (status, receipt) =
            post_as_owner(&fixture, "vault.sieve.budgets.lower", lower.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner lowers the sieve budgets: {receipt}"
        );
        assert_eq!(
            receipt["change"]["knob"],
            json!("DREAMER_SIEVE_POLICY"),
            "the receipt names the knob: {receipt}"
        );
        assert_eq!(
            receipt["change"]["owner"],
            json!(true),
            "the receipt names the owner: {receipt}"
        );
        assert_eq!(
            receipt["change"]["class"],
            json!("work_budget"),
            "the receipt names the work budget class: {receipt}"
        );
        let (status, policy) = post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {policy}");
        assert_eq!(
            policy["max_scan_per_pass"],
            json!(200),
            "the policy row carries the lower scan: {policy}"
        );
        assert_eq!(
            policy["max_turns_per_pass"],
            json!(64),
            "the other budgets stand: {policy}"
        );
        assert_eq!(
            policy["max_text_bytes_per_pass"],
            json!(32768),
            "the other budgets stand: {policy}"
        );

        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.budgets.lower",
            json!({
                "max_turns_per_pass": 64,
                "max_scan_per_pass": 201,
                "max_text_bytes_per_pass": 32768,
            }),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            LOWER_ONLY,
            "a raise at the lower-only door",
        );
        let (status, kept) = post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {kept}");
        assert_eq!(
            kept["max_scan_per_pass"],
            json!(200),
            "the refused raise keeps the lowered scan: {kept}"
        );

        let (status, refused) = post_as_person(&fixture, "vault.sieve.budgets.lower", lower).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            GRANT_NEEDED,
            "a holder without the engine.controls grant",
        );

        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.budgets.lower", json!({})).await;
        assert_decode_refusal(status, &refused, "an empty budgets lower");
    });
}

/// The fresh-vault refusal table: every owner door refuses a person (and
/// an agent) on a body that decodes, malformed bodies never reach a
/// door, unknown ids answer null or not-found, and the receipts door
/// answers its empty page.
#[test]
fn fresh_vault_refusal_table() {
    run_on_engine_stack("sieve-refusals", || async {
        let fixture = setup().await;
        let (status, sieve_defaults) =
            post_as_owner(&fixture, "vault.sieve.policy", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the policy: {sieve_defaults}"
        );
        let (status, recipe_defaults) =
            post_as_owner(&fixture, "vault.sieve.recipe_policy", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the recipe policy: {recipe_defaults}"
        );
        let dead_hex = EntityId::now().to_hex();
        let owner_rows: Vec<(&str, Value)> = vec![
            ("vault.sieve.queue", json!({})),
            ("vault.sieve.retained", json!({})),
            ("vault.sieve.receipts", json!({})),
            ("vault.sieve.policy", json!({})),
            ("vault.sieve.policy.set", json!({"policy": sieve_defaults})),
            ("vault.sieve.recipe_policy", json!({})),
            (
                "vault.sieve.recipe_policy.set",
                json!({"policy": recipe_defaults}),
            ),
            ("vault.sieve.lease", json!({"budget_id": "s1-lease"})),
            (
                "vault.sieve.lease.refill",
                json!({"budget_id": "s1-lease", "total_units": 10}),
            ),
            ("vault.sieve.evidence", json!({"turn": dead_hex.clone()})),
            (
                "vault.sieve.evidence.replay",
                json!({"turn": dead_hex.clone()}),
            ),
            ("vault.sieve.cadence", json!({})),
            (
                "vault.sieve.settlements",
                json!({"after": null, "limit": 10}),
            ),
            (
                "vault.sieve.settlements.get",
                json!({"wake": dead_hex.clone()}),
            ),
        ];
        for (verb, body) in owner_rows {
            let (status, refused) = post_as_person(&fixture, verb, body).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &format!("{verb} is the vault owner's"),
                &format!("a person at {verb}"),
            );
        }

        let agent_holder = seed_person(&fixture.vault);
        let agent_slip = mint_person_credential(
            &fixture.owner_slip,
            &fixture.vault,
            &fixture.issuer,
            agent_holder,
            "agent",
        );
        let agent_token = agent_slip.to_token().expect("agent slip token");
        let (status, refused) = post(
            &fixture,
            "/v1/core/facade/vault.sieve.queue",
            &agent_token,
            credential_binding(&fixture, &agent_slip),
            json!({}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "vault.sieve.queue is the vault owner's",
            "an agent at the queue",
        );

        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.settlements", json!({"limit": 10})).await;
        assert_decode_refusal(status, &refused, "settlements without its after key");
        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.settlements",
            json!({"after": null, "limit": 0}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "invalid config: settlement page limit must be positive",
            "a zero settlement page limit",
        );

        let unknown_hex = EntityId::now().to_hex();
        let (status, missing) = post_as_owner(
            &fixture,
            "vault.sieve.settlements.get",
            json!({"wake": unknown_hex}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unknown wake answers null: {missing}"
        );
        assert!(
            missing.is_null(),
            "an unknown wake is null, not a refusal: {missing}"
        );

        let gone_hex = EntityId::now().to_hex();
        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.evidence", json!({"turn": gone_hex})).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "entity not found",
            "evidence for an unknown turn",
        );
        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.evidence",
            json!({"turn": fixture.person.to_hex()}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "invalid config: sieve evidence must name a TURN",
            "evidence for a live non-turn",
        );

        let raw_turn = EntityId::now();
        fixture
            .vault
            .put_entity(
                &raw_turn,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a raw turn row");
        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.evidence.replay",
            json!({"turn": raw_turn.to_hex()}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "invalid config: TURN is not continuous-sieve evidence",
            "a replay with no continuous-sieve row",
        );

        let (status, fresh_lease) = post_as_owner(
            &fixture,
            "vault.sieve.lease",
            json!({"budget_id": "s13-no-lease"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unknown lease reads: {fresh_lease}"
        );
        assert_eq!(
            fresh_lease["budget_id"],
            json!("s13-no-lease"),
            "the lease names its budget: {fresh_lease}"
        );
        assert!(
            fresh_lease["counter"].is_null(),
            "no wake opened the lease yet: {fresh_lease}"
        );
        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.lease.refill", json!({})).await;
        assert_decode_refusal(status, &refused, "an empty lease refill");

        let (status, filled) = post_as_owner(
            &fixture,
            "vault.sieve.lease.refill",
            json!({"budget_id": "s15-lease", "total_units": 1000}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner refills the lease: {filled}");
        let now = fixture.vault.now_recorded_at();
        reserve_lease_units(&fixture, "s15-lease", 1000, 400, now);
        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.lease.refill",
            json!({"budget_id": "s15-lease", "total_units": 300}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            REFILL_BELOW,
            "a refill below spent and reserved units",
        );

        for verb in [
            "vault.sieve.queue",
            "vault.sieve.policy",
            "vault.sieve.cadence",
        ] {
            let (status, refused) = post_as_owner(&fixture, verb, json!({"nope": 1})).await;
            assert_decode_refusal(status, &refused, &format!("an unknown field at {verb}"));
        }
        let (status, refused) =
            post_as_owner(&fixture, "vault.sieve.evidence", json!({"turn": "zz"})).await;
        assert_decode_refusal(status, &refused, "evidence with a bad turn id");
        let (status, refused) = post_as_owner(
            &fixture,
            "vault.sieve.settlements.get",
            json!({"wake": "zz"}),
        )
        .await;
        assert_decode_refusal(status, &refused, "a settlement with a bad wake id");

        let (status, receipts) = post_as_owner(&fixture, "vault.sieve.receipts", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the fresh receipts: {receipts}"
        );
        assert_eq!(
            receipts["receipts"],
            json!([]),
            "a fresh vault holds no consumed-span receipts: {receipts}"
        );
    });
}
