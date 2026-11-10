//! Served `vault.batch` follows ARCH-0053:20 on its credential's agent slice.
use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::authority::holder_proof;
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: u64 = 1_700_000_000;
// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds
// (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const AUTHOR: u8 = 0x70;

fn definition(
    name: &str,
    scope: AgentScope,
    ceiling: AgentCeiling,
    generated: bool,
) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "generic writer conformance fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        if generated {
            ClaimSource::Generated
        } else {
            ClaimSource::UserStated
        },
        1.0,
        generated,
        !generated,
        RmpValue::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

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
        other => panic!("an AGENT_DEF body holds no {other:?}"),
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
                auth_secret: Some("served-batch-conformance".to_owned()),
                ..Default::default()
            },
        )
        .expect("server"),
    );
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let author = EntityId::from_bytes([AUTHOR; 16]).expect("author id");
    vault
        .create_agent_definition_as(
            &owner,
            &author,
            &definition(
                "conformance.author",
                AgentScope::Base,
                AgentCeiling::Proposed,
                false,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the Base, ceiling-Proposed author");
    (dir, server, author)
}

#[derive(Clone, Copy)]
enum Slice {
    Wider,
    Within,
}

async fn run_new_definition(candidate_seed: u8, slice: Slice) {
    let (_dir, server, author) = fixture();
    let vault = server.vault();
    let id = EntityId::from_bytes([candidate_seed; 16]).expect("candidate id");
    assert!(vault.get_agent_definition(&id).expect("fresh id").is_none());
    let (scope, ceiling, slice_label) = match slice {
        Slice::Wider => (AgentScope::All, AgentCeiling::Auto, "wider"),
        Slice::Within => (AgentScope::Base, AgentCeiling::Proposed, "within"),
    };
    let bytes = encode_agent_definition(&definition("conformance.candidate", scope, ceiling, true))
        .expect("valid definition");
    let input = json!({"entities": [{
        "id": id.to_hex(), "entity_type": ENTITY_TYPE_AGENT_DEF,
        "occurred_start": NOW + 1, "occurred_end": NOW + 1, "learned_at": NOW + 1,
        "body": json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack")),
    }]});
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("root slip")
        .claims;
    let holder = SigningKey::from_bytes(&[0x6D; 32]);
    claims.slip_id = [candidate_seed; 32];
    claims.parent_id = None;
    claims.holder_ref = author.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("agent credential");
    assert_eq!(slip.claims.holder_ref, author.to_hex());
    assert_eq!(slip.claims.actor_class.as_deref(), Some("agent"));
    let binding = holder_proof(&slip, &holder, vault.now_recorded_at()).expect("holder proof");
    let response = build_app(Arc::clone(&server))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/core/facade/vault.batch")
                .header(
                    "Authorization",
                    format!("Bearer {}", slip.to_token().expect("token")),
                )
                .header("x-oneiron-binding", binding.to_string())
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
    let write: Result<(), String> = if status == StatusCode::OK {
        Ok(())
    } else {
        Err(format!("{status}: {}", String::from_utf8_lossy(&body)))
    };
    let stored = vault.get_agent_definition(&id).expect("read the row");
    let dispatch = match AgentDispatcher::new(vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: NOW + 9,
    }) {
        Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
        Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
        Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
        Ok(_) => "workflow".to_owned(),
        Err(error) => format!("refused: {error}"),
    };
    let standing = stored.as_ref().map_or_else(|| "absent".to_owned(), |def| format!(
        "version={} approval={:?} lifecycle={:?} enabled={} scope={:?} ceiling={:?} source={:?}",
        def.version, def.approval_status, def.lifecycle_status, def.enabled, def.scope, def.ceiling, def.source,
    ));
    let write_label = match &write {
        Ok(()) => "landed".to_owned(),
        Err(error) => format!("refused: {error}"),
    };
    println!(
        "CONFORMANCE case=served/vault.batch/new/{slice_label} door=vault.batch write={write_label} stored=[{standing}] dispatch={dispatch}"
    );
    assert!(
        write.is_ok(),
        "ARCH-0053:20: {slice_label}: the put was refused: {write_label}"
    );
    let def = stored.expect("the put left a definition");
    assert_eq!(
        def.lifecycle_status,
        ClaimLifecycleStatus::Active,
        "a saved definition is live at rest"
    );
    if matches!(slice, Slice::Wider) {
        assert_eq!(
            def.approval_status,
            ClaimApprovalStatus::Proposed,
            "ARCH-0053:20: a definition wider than its author's slice is stored as other than a proposal"
        );
        assert_ne!(
            dispatch, "dispatched",
            "ARCH-0053:20: a wider definition is dispatchable"
        );
    } else {
        assert_eq!(
            def.approval_status,
            ClaimApprovalStatus::Approved,
            "ARCH-0053:20: a definition inside its author's slice is not at the author's approval"
        );
        assert!(def.enabled, "the definition stays enabled");
        assert_eq!(
            dispatch, "dispatched",
            "ARCH-0053:20: a within-slice definition is undispatchable"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn served_batch_stores_no_active_definition_wider_than_its_agent_slice() {
    run_new_definition(0x73, Slice::Wider).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn served_batch_stores_a_definition_inside_its_agent_slice_active() {
    run_new_definition(0x75, Slice::Within).await;
}
