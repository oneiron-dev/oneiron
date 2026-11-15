// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The person-act sweep's served doors (PR 2 server part + F2 engine rule).
//! A Human credential handed on to another key acts as its key holder, never
//! as the person (HANDED-ON-SLIP-PERSON Q1 = A, Q2 = A): a served batch SKILL
//! birth under it lands Generated, and a turn VAD `user_self_report` under it
//! lands as `model_inference`. The owner's own slip still births UserStated
//! and self-reports. Each red fails at its own assert on the red tree.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test handed_on_person_sweep_server`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{SlipCaveat, holder_proof};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::federation::ScopeAxis;
use oneiron::registry::{ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
use oneiron::write_envelope::skill_record::{SkillLifecycle, SkillRecord, encode_skill_record};
use oneiron::{EntityId, TimeRange, VadAnnotationSource, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: u64 = 1_700_000_000;
const SKILL_SEED: u8 = 0x61;
const TURN_SEED: u8 = 0x62;

fn json_of(value: &RmpValue) -> Value {
    match value {
        RmpValue::Nil => Value::Null,
        RmpValue::Boolean(flag) => json!(*flag),
        RmpValue::Integer(int) => int
            .as_u64()
            .map(Value::from)
            .or_else(|| int.as_i64().map(Value::from))
            .expect("integer"),
        RmpValue::F32(float) => json!(f64::from(*float)),
        RmpValue::F64(float) => json!(*float),
        RmpValue::String(text) => json!(text.as_str().expect("UTF-8")),
        RmpValue::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        RmpValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("string key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("a SKILL body holds no {other:?}"),
    }
}

fn fixture() -> (tempfile::TempDir, Arc<SyncServer>, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("personal vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("handed-on-person-sweep".to_owned()),
                ..Default::default()
            },
        )
        .expect("server"),
    );
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    (dir, server, owner)
}

/// A Human slip for the owner as a served bearer (`token`, `binding`): held
/// by the owner, or handed on to another key first (copied from
/// `handed_on_session_run::Fixture::owner_slip`, adapted to the served form).
fn owner_slip(server: &SyncServer, owner: EntityId, handed_on: bool) -> (String, String) {
    let vault = server.vault();
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("root slip")
        .claims;
    let first = SigningKey::from_bytes(&[0x6A; 32]);
    let second = SigningKey::from_bytes(&[0x6B; 32]);
    claims.slip_id = if handed_on { [0x72; 32] } else { [0x71; 32] };
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = first.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let mut slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("owner slip");
    let holder = if handed_on {
        issuer
            .attenuate_to(
                &mut slip,
                SlipCaveat::default(),
                second.verifying_key().to_bytes(),
            )
            .expect("the slip is handed on");
        &second
    } else {
        &first
    };
    let token = slip.to_token().expect("token");
    let binding = holder_proof(&slip, holder, vault.now_recorded_at()).expect("holder proof");
    (token, binding.to_string())
}

async fn post(
    server: &Arc<SyncServer>,
    uri: &str,
    token: &str,
    binding: &str,
    input: &Value,
) -> (StatusCode, Value) {
    let response = build_app(Arc::clone(server))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("x-oneiron-binding", binding)
                .header("Content-Type", "application/json")
                .body(Body::from(input.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("response body");
    let body: Value = serde_json::from_slice(&body).expect("JSON body");
    (status, body)
}

async fn run_skill_birth(handed_on: bool) {
    let (_dir, server, owner) = fixture();
    let vault = server.vault();
    let id = EntityId::from_bytes([SKILL_SEED; 16]).expect("skill id");
    let record = SkillRecord::new(
        "handed-on-f2",
        "F2 fixture",
        "1",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        RmpValue::Map(vec![]),
    );
    let bytes = encode_skill_record(&record).expect("valid skill");
    let entity = json!({
        "id": id.to_hex(), "entity_type": ENTITY_TYPE_SKILL,
        "occurred_start": NOW + 1, "occurred_end": NOW + 1, "learned_at": NOW + 1,
        "body": json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack")),
    });
    let (token, binding) = owner_slip(&server, owner, handed_on);
    let (status, body) = post(
        &server,
        "/v1/core/batch",
        &token,
        &binding,
        &json!({"entities": [entity]}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "batch SKILL birth refused: {status}: {body}"
    );
    let stored = vault
        .get_skill_record(&id)
        .expect("read the row")
        .expect("the put left a skill");
    if handed_on {
        assert_eq!(
            stored.source,
            ClaimSource::Generated,
            "a handed-on owner slip never births a user-stated skill by batch"
        );
        assert!(stored.generated, "a handed-on birth lands generated");
        assert!(
            !stored.human_authored,
            "a handed-on birth lands not human-authored"
        );
    } else {
        assert_eq!(
            stored.source,
            ClaimSource::UserStated,
            "the owner's own slip still births a user-stated skill by batch"
        );
        assert!(!stored.generated, "an own birth lands not generated");
        assert!(stored.human_authored, "an own birth lands human-authored");
    }
}

async fn run_vad(handed_on: bool) {
    let (_dir, server, owner) = fixture();
    let vault = server.vault();
    let turn = EntityId::from_bytes([TURN_SEED; 16]).expect("turn id");
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"vad fixture turn",
        )
        .expect("seed turn");
    let (token, binding) = owner_slip(&server, owner, handed_on);
    let (status, body) = post(
        &server,
        "/v1/core/turns/annotate",
        &token,
        &binding,
        &json!({
            "turn_id": turn.to_hex(),
            "source": "user_self_report",
            "vad": {"valence": 0.25, "arousal": 0.5, "dominance": 0.75},
            "annotated_at": NOW + 1,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "turn VAD annotate refused: {status}: {body}"
    );
    let stored = vault
        .get_turn_vad_annotation(&turn)
        .expect("read the row")
        .expect("the call left a row");
    if handed_on {
        assert_eq!(
            body["source"],
            Value::from("model_inference"),
            "a handed-on owner slip never self-reports a turn's VAD"
        );
        assert_eq!(
            stored.source,
            VadAnnotationSource::ModelInference,
            "a handed-on VAD lands as model inference"
        );
    } else {
        assert_eq!(
            body["source"],
            Value::from("user_self_report"),
            "the owner's own slip still self-reports a turn's VAD"
        );
        assert_eq!(
            stored.source,
            VadAnnotationSource::UserSelfReport,
            "an own VAD lands as self-report"
        );
    }
}

#[test]
fn a_handed_on_owner_slip_never_births_a_user_stated_skill_by_batch() {
    engine_stack::run_on_engine_stack("handed-on-skill-birth", || run_skill_birth(true));
}

#[test]
fn the_owners_own_slip_still_births_a_user_stated_skill_by_batch() {
    engine_stack::run_on_engine_stack("own-skill-birth", || run_skill_birth(false));
}

#[test]
fn a_handed_on_owner_slip_never_self_reports_a_turns_vad() {
    engine_stack::run_on_engine_stack("handed-on-vad", || run_vad(true));
}

#[test]
fn the_owners_own_slip_still_self_reports_a_turns_vad() {
    engine_stack::run_on_engine_stack("own-vad", || run_vad(false));
}
