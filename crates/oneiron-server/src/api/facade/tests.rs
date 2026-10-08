use super::*;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use oneiron::memory::caps::{MAX_BATCH_ENTITIES, MAX_ENTITY_PAYLOAD_BYTES, MAX_QUERY_BYTES};
use serde_json::{Value, json};
use tower::ServiceExt;

#[tokio::test]
async fn authenticated_http_ingress_enforces_shared_payload_caps_without_writes() {
    const SECRET: &str = "facade-cap-regression-secret";
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("vault"));
    let actor = vault.ensure_embedded_owner_actor().expect("owner");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .expect("server"),
    );
    let recipe = format!(
        "scope=core:read,core:write;principal_ref={};actor_class=human",
        actor.to_hex()
    );
    let (slip, holder) = crate::test_credentials::credential(&server, &recipe);
    let app = crate::build_app(Arc::clone(&server));
    let before = vault
        .memory(actor, EdgeActorClass::Human)
        .receipts(100)
        .expect("receipts");
    let message = json!({
        "author": "user", "message_type": "text", "content": "small",
        "is_visible": true, "order": 0
    });
    let mut large_message = message.clone();
    large_message["content"] = json!("x".repeat(MAX_ENTITY_PAYLOAD_BYTES + 1));
    let conversation = "12121212121212121212121212121212";
    let claim = json!({
        "predicate": "test.payload", "subject_ref": actor.to_hex(), "value": "small",
        "confidence": 1.0, "source": "user_stated",
        "scope": {"opaque": "x".repeat(MAX_ENTITY_PAYLOAD_BYTES)}
    });
    let requests = [
        (
            "witness",
            json!({"conversation_ref": conversation, "occurred_at": 1, "messages": [large_message]}),
            "message content",
        ),
        (
            "witness",
            json!({"conversation_ref": conversation, "occurred_at": 1, "messages": vec![message; MAX_BATCH_ENTITIES + 1]}),
            "messages",
        ),
        ("claim_upsert", claim, "claim payload"),
        (
            "recall",
            json!({"query": "x".repeat(MAX_QUERY_BYTES + 1)}),
            "query",
        ),
    ];
    for (verb, payload, label) in requests {
        let response = app
            .clone()
            .oneshot(crate::test_credentials::bind_slip_request(
                &server,
                &slip,
                &holder,
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&payload).expect("request JSON"),
                    ))
                    .expect("request"),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{verb}");
        let body = to_bytes(response.into_body(), 8192).await.expect("body");
        let body: Value = serde_json::from_slice(&body).expect("error JSON");
        assert_eq!(body["error"]["code"], MEMORY_CODE_BAD_REQUEST);
        assert!(
            body["error"]["message"]
                .as_str()
                .expect("message")
                .contains(label)
        );
        assert!(
            !body["error"]["suggestions"]
                .as_array()
                .expect("suggestions")
                .is_empty()
        );
    }
    assert!(
        vault
            .get_raw(&EntityId::from_hex(conversation).expect("id"))
            .expect("read")
            .is_none()
    );
    assert_eq!(
        vault
            .memory(actor, EdgeActorClass::Human)
            .receipts(100)
            .expect("receipts"),
        before
    );
}

#[tokio::test]
async fn generated_agent_sdk_http_keeps_first_answer_and_durable_step_wait_semantics() {
    const SECRET: &str = "sdk-agent-verbs";
    async fn post(
        server: &Arc<SyncServer>,
        authorization: &str,
        verb: &str,
        input: Value,
    ) -> (StatusCode, Value) {
        let response = crate::build_app(Arc::clone(server))
            .oneshot(crate::test_credentials::bind_request(
                server,
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", authorization)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&input).unwrap()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let second = EntityId::now();
    vault
        .put_entity(
            &second,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"holder",
        )
        .unwrap();
    let token = |actor: EntityId, scope: &str| {
        format!(
            "{}scope={scope};principal_ref={};actor_class=human",
            crate::test_credentials::RECIPE_PREFIX,
            actor.to_hex()
        )
    };
    let owner_token = token(owner, "core:read,core:write");
    let second_token = token(second, "core:read,core:write");
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            crate::config::SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let question = EntityId::now();
    vault
        .put_entity(
            &question,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &[0xc0],
        )
        .unwrap();
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let bound = oneiron::consent::GrantBound::action(
        oneiron::consent::ActorBound::new(second.to_hex()).unwrap(),
        oneiron::consent::ActionClass::new("review").unwrap(),
        oneiron::consent::ActionEnvelope::new(["project:alpha".into()]).unwrap(),
    )
    .unwrap();
    vault.create_standing_grant(&auth, bound).unwrap();
    let ask_spec = |key: String| {
        json!({
            "intent_key": key,
            "who": {"authority": {"class": "review", "selectors": ["project:alpha"], "target": null, "budget": null, "receipt_required": false}},
            "what": {"reference": {"turn": question.to_hex()}, "revision": 1, "options": {}, "context_refs": [], "label": null, "outcome_binding": null},
            "until": u64::MAX, "decide": "first",
        })
    };
    let (status, _) = post(&server, &format!("Bearer {SECRET}"), "tasks.ask", json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for answer_first in [false, true] {
        let spec = ask_spec(format!("order-{answer_first}"));
        let (status, receipt) = post(&server, &owner_token, "tasks.ask", spec.clone()).await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        let handle = receipt["handle"].clone();
        let (_, retry) = post(&server, &owner_token, "tasks.ask", spec).await;
        assert_eq!(retry["handle"], handle);
        assert_eq!(retry["idempotent_replay"], true);
        let wait = json!({"handle":handle,"step_key":"caller-step"});
        let (status, _) = post(
            &server,
            &token(owner, "core:read"),
            "tasks.wait",
            wait.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        if !answer_first {
            let (status, pending) = post(&server, &owner_token, "tasks.wait", wait.clone()).await;
            assert_eq!(status, StatusCode::OK, "{pending}");
            assert!(pending.get("Pending").is_some());
            // Only that logical step waited: the caller can issue another ask now.
            let (status, other) = post(
                &server,
                &owner_token,
                "tasks.ask",
                ask_spec("kept-working".into()),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{other}");
        }
        let (status, first) = post(
            &server,
            &owner_token,
            "tasks.answer",
            json!({"handle":handle,"word":{"result_ref":owner.to_hex(),"option":null,"inform_for":null,"provenance_refs":[]}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let (status, second_answer) = post(
            &server,
            &second_token,
            "tasks.answer",
            json!({"handle":handle,"word":{"result_ref":second.to_hex(),"option":null,"inform_for":null,"provenance_refs":[]}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{second_answer}");
        assert_eq!(second_answer["actor_ref"], second.to_hex());
        assert_eq!(second_answer["result_ref"], second.to_hex());
        assert_ne!(second_answer["task_ref"], first["task_ref"]);
        let (_, ready) = post(&server, &owner_token, "tasks.wait", wait.clone()).await;
        assert_eq!(ready["Ready"]["decision"]["first"], first);
        let (_, replayed) = post(&server, &owner_token, "tasks.wait", wait).await;
        assert_eq!(replayed["Ready"], ready["Ready"]);
    }
    for i in 0..12 {
        let (status, body) = post(
            &server,
            &owner_token,
            "tasks.ask",
            ask_spec(format!("burst-{i}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["task_refs"].as_array().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn rooms_http_routes_only_the_addressed_companion_and_requires_a_claim() {
    async fn post(
        server: &Arc<SyncServer>,
        authorization: &str,
        verb: &str,
        input: Value,
    ) -> (StatusCode, Value) {
        let response = crate::build_app(Arc::clone(server))
            .oneshot(crate::test_credentials::bind_request(
                server,
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", authorization)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&input).unwrap()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    const SECRET: &str = "room-http-acceptance";
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let addressed = EntityId::now();
    let other = EntityId::now();
    for actor in [addressed, other] {
        vault
            .put_entity(
                &actor,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"companion",
            )
            .unwrap();
    }
    let project = EntityId::now();
    let mut spec = oneiron::workspace_roster::ProjectRecord::new(
        project,
        Some(vault.root_project().unwrap()),
        vault.root_project().unwrap(),
        owner,
    )
    .unwrap();
    spec.roster.extend([addressed.to_hex(), other.to_hex()]);
    vault.put_project(project, &spec, 1).unwrap();
    let room = EntityId::from_hex(&spec.home_room).unwrap();
    vault
        .bind_room_handle(room, "@addressed", addressed)
        .unwrap();
    let token = |actor: EntityId, class: &str| {
        format!(
            "{}scope=core:read,core:write;principal_ref={};actor_class={class}",
            crate::test_credentials::RECIPE_PREFIX,
            actor.to_hex()
        )
    };
    let owner_token = token(owner, "human");
    let addressed_token = token(addressed, "agent");
    let other_token = token(other, "agent");
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            crate::config::SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (status, rooms) = post(&server, &addressed_token, "rooms.list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{rooms}");
    assert_eq!(rooms.as_array().unwrap().len(), 1);
    let turn = EntityId::now().to_hex();
    let incoming = json!({"conversation_ref":room.to_hex(),"turn_ref":turn,"occurred_at":2,
        "messages":[{"author":"user","message_type":"text","content":"@addressed respond",
        "metadata":{"room_mentions":["@addressed"]},"is_visible":true,"order":0}]});
    let (status, receipt) = post(&server, &owner_token, "rooms.speak", incoming).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert!(
        receipt["receipt_ref"]
            .as_str()
            .unwrap()
            .starts_with("witness:")
    );
    let reply = json!({"conversation_ref":room.to_hex(),"turn_ref":EntityId::now().to_hex(),"occurred_at":3,
        "messages":[{"author":"companion","message_type":"text","content":"Answer",
        "metadata":{"room_reply_to":turn},"is_visible":true,"order":0}]});
    let (status, _) = post(&server, &addressed_token, "rooms.speak", reply.clone()).await;
    assert_ne!(status, StatusCode::OK);
    let claim = json!({"room_ref":room.to_hex(),"turn_ref":turn});
    let (status, outcome) = post(&server, &other_token, "rooms.claim", claim.clone()).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(outcome, json!("NotAddressed"));
    let (status, claimed) = post(&server, &addressed_token, "rooms.claim", claim.clone()).await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    assert_eq!(claimed["Claimed"]["actor"], addressed.to_hex());
    assert!(
        claimed["Claimed"]["receipt_ref"]
            .as_str()
            .unwrap()
            .starts_with("rooms.claim:")
    );
    assert_eq!(
        post(&server, &addressed_token, "rooms.claim", claim)
            .await
            .1,
        claimed
    );
    let (status, _) = post(&server, &other_token, "rooms.speak", reply.clone()).await;
    assert_ne!(status, StatusCode::OK);
    let (status, spoken) = post(&server, &addressed_token, "rooms.speak", reply).await;
    assert_eq!(status, StatusCode::OK, "{spoken}");
    let (status, messages) = post(
        &server,
        &owner_token,
        "rooms.messages",
        json!({"room_ref":room.to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{messages}");
    let messages = messages["rows"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["addressed_agents"], json!([addressed.to_hex()]));
    assert_eq!(messages[1]["actor"], addressed.to_hex());
}

#[tokio::test]
async fn keyed_http_round_trip_scope_and_exact_principal_binding() {
    const SECRET: &str = "keyed-facade-test-secret";
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = crate::build_app(Arc::clone(&server));
    let recipe = |claims: &str| format!("{}{claims}", crate::test_credentials::RECIPE_PREFIX);
    let full = recipe(&format!(
        "scope=core:read,core:write;principal_ref={};actor_class=human",
        actor.to_hex()
    ));
    let readonly = recipe(&format!(
        "scope=core:read;principal_ref={};actor_class=human",
        actor.to_hex()
    ));
    let unbound = recipe("scope=core:read,core:write");
    let address = json!({"namespace":["prefs"],"key":"theme"});
    let put = json!({"namespace":["prefs"],"key":"theme","value":{"name":"dark"},"request_id":"http-one","source":"user_stated"});
    let cases = [
        (
            "key_value_put",
            put.clone(),
            &readonly,
            StatusCode::FORBIDDEN,
        ),
        (
            "key_value_get",
            address.clone(),
            &unbound,
            StatusCode::FORBIDDEN,
        ),
        ("key_value_put", put, &full, StatusCode::OK),
        ("key_value_get", address.clone(), &full, StatusCode::OK),
        (
            "key_value_search",
            json!({"namespace_prefix":["prefs"],"limit":1}),
            &full,
            StatusCode::OK,
        ),
        (
            "key_value_namespaces",
            json!({"prefix":["prefs"]}),
            &full,
            StatusCode::OK,
        ),
        (
            "key_value_delete",
            address.clone(),
            &readonly,
            StatusCode::FORBIDDEN,
        ),
        ("key_value_delete", address.clone(), &full, StatusCode::OK),
        ("key_value_get", address, &full, StatusCode::OK),
    ];
    let mut bodies = Vec::new();
    for (verb, payload, token, status) in cases {
        let response = app
            .clone()
            .oneshot(crate::test_credentials::bind_request(
                &server,
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", token)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{verb}");
        bodies.push(
            serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 65536).await.unwrap())
                .unwrap(),
        );
    }
    assert_eq!(bodies[2]["item"]["value"], json!({"name":"dark"}));
    assert_eq!(bodies[3]["value"], bodies[2]["item"]["value"]);
    assert_eq!(bodies[4].as_array().unwrap().len(), 1);
    assert_eq!(bodies[5], json!([["prefs"]]));
    assert_eq!(bodies[7]["existed"], true);
    assert_eq!(bodies[8], Value::Null);
}

#[tokio::test]
async fn generated_facade_read_admission_preserves_defaults_and_record_scope() {
    use oneiron::authority::SlipCaveat;
    use oneiron::federation::{Scope, ScopeAxis, ScopeId};
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("generated-facade-scope".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let recipe = format!(
        "scope=core:read;principal_ref={};actor_class=human",
        actor.to_hex()
    );
    let (slip, holder) = crate::test_credentials::credential(&server, &recipe);
    let mut narrow = slip.clone();
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(actor)]));
    narrow
        .attenuate(
            SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &holder,
        )
        .unwrap();
    let app = crate::build_app(Arc::clone(&server));
    for (credential, verb, input, status) in [
        (&slip, "receipts", json!({}), StatusCode::OK),
        (
            &slip,
            "receipts",
            json!({"limit": 0}),
            StatusCode::BAD_REQUEST,
        ),
        (&narrow, "receipts", json!({}), StatusCode::FORBIDDEN),
        (
            &narrow,
            "recall",
            json!({"query": "hello"}),
            StatusCode::FORBIDDEN,
        ),
        (&slip, "witness", json!({}), StatusCode::FORBIDDEN),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&input).unwrap()))
            .unwrap();
        let response = app
            .clone()
            .oneshot(crate::test_credentials::bind_slip_request(
                &server, credential, &holder, request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{verb}");
    }
}

#[tokio::test]
async fn room_facade_refuses_record_channel_and_world_attenuations() {
    use oneiron::authority::SlipCaveat;
    use oneiron::federation::{Scope, ScopeAxis, ScopeId};
    use oneiron::workspace_roster::ProjectRecord;
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let project = oneiron::EntityId::now();
    let record = ProjectRecord::new(
        project,
        Some(vault.root_project().unwrap()),
        vault.root_project().unwrap(),
        actor,
    )
    .unwrap();
    vault.put_project(project, &record, 1).unwrap();
    let room = oneiron::EntityId::from_hex(&record.home_room).unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("room-facade-narrow".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let recipe = format!(
        "scope=core:read;principal_ref={};actor_class=human",
        actor.to_hex()
    );
    let (slip, holder) = crate::test_credentials::credential(&server, &recipe);
    let mut record_slip = slip.clone();
    record_slip
        .attenuate(
            SlipCaveat {
                records: Some([actor.to_hex()].into()),
                ..Default::default()
            },
            &holder,
        )
        .unwrap();
    let mut channel_slip = slip.clone();
    channel_slip
        .attenuate(
            SlipCaveat {
                channels: Some(["other-channel".to_owned()].into()),
                ..Default::default()
            },
            &holder,
        )
        .unwrap();
    let mut world_slip = slip.clone();
    let mut narrow = Scope::top();
    narrow.worlds = ScopeAxis::Some([ScopeId(actor)].into());
    world_slip
        .attenuate(
            SlipCaveat {
                scope: Some(narrow),
                ..Default::default()
            },
            &holder,
        )
        .unwrap();
    let app = crate::build_app(Arc::clone(&server));
    for (verb, payload) in [
        ("rooms.render", json!({"room_ref":room.to_hex()})),
        ("rooms.find", json!({"room_ref":room.to_hex()})),
        (
            "rooms.get",
            json!({"room_ref":room.to_hex(),"turn_ref":actor.to_hex()}),
        ),
        (
            "rooms.trunk",
            json!({"room_ref":room.to_hex(),"turn_ref":actor.to_hex()}),
        ),
    ] {
        for narrowed in [&record_slip, &channel_slip, &world_slip] {
            let request = Request::builder()
                .method("POST")
                .uri(format!("/v1/core/facade/{verb}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();
            let response = app
                .clone()
                .oneshot(crate::test_credentials::bind_slip_request(
                    &server, narrowed, &holder, request,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{verb}");
        }
        if matches!(verb, "rooms.render" | "rooms.find") {
            let request = Request::builder()
                .method("POST")
                .uri(format!("/v1/core/facade/{verb}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();
            let response = app
                .clone()
                .oneshot(crate::test_credentials::bind_slip_request(
                    &server, &slip, &holder, request,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{verb}");
        }
    }
}

/// Actor A holds an unrestricted-record-scope slip, and the policy manifest
/// gives A one read grant whose entity types exclude TASK. One TASK T exists,
/// and it has failed. Returns the server, A's recipe, the owner and T.
fn task_outside_read_floor() -> (
    tempfile::TempDir,
    Arc<SyncServer>,
    String,
    EntityId,
    EntityId,
) {
    use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome, FailAttempt};
    use oneiron::federation::{Scope, ScopeAxis};
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let reader = EntityId::now();
    vault
        .put_entity(
            &reader,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )
        .unwrap();
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(["read".to_owned()].into());
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        &vault,
        oneiron::WriteActor::new(owner, EdgeActorClass::Human),
        EntityId::now(),
        &json!({
            "schema_version": "1.2", "pack_id": "task-read-floor", "pack_version": "1",
            "min_engine_version": "0.0.0", "defaults": {}, "rules": [], "actor_ceilings": [],
            "scoped_grants": [{
                "actor_ref": reader.to_hex(),
                "effector": "core:read",
                "scope": serde_json::to_value(read).unwrap(),
                "selectors": {"entity_types": [oneiron::registry::ENTITY_TYPE_PERSON]},
                "receipt_required": false,
            }],
        }),
    )
    .unwrap();
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&oneiron::task_verb::TaskCreateSpec::new(
            rmpv::Value::from("unit-task"),
            None,
            None,
            None,
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let queue = oneiron::AttemptQueue::new(&vault);
    let now = vault.now_recorded_at();
    let ClaimOutcome::Claimed(claimed) = queue
        .claim_kind(
            "tasks.realize",
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now,
            },
        )
        .unwrap()
    else {
        panic!("the created task's realization is claimable");
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now,
        })
        .unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("task-read-floor".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let recipe = format!(
        "{}scope=core:read,core:write;principal_ref={};actor_class=human",
        crate::test_credentials::RECIPE_PREFIX,
        reader.to_hex()
    );
    (dir, server, recipe, owner, task)
}

async fn post_task_verb(
    server: &Arc<SyncServer>,
    recipe: &str,
    verb: &str,
    input: Value,
) -> (StatusCode, Value) {
    let response = crate::build_app(Arc::clone(server))
        .oneshot(crate::test_credentials::bind_request(
            server,
            Request::builder()
                .method("POST")
                .uri(format!("/v1/core/facade/{verb}"))
                .header("Authorization", recipe)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&input).unwrap()))
                .unwrap(),
        ))
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// ARCH-0067's 2026-09-22 amendment renamed the four task rows. The old
/// routes are gone, while the same credential still reaches the new ones.
#[tokio::test]
async fn retired_task_routes_are_not_found() {
    let (_dir, server, recipe, _, _) = task_outside_read_floor();
    let status = |verb: &'static str| {
        let server = Arc::clone(&server);
        let recipe = recipe.clone();
        async move {
            crate::build_app(Arc::clone(&server))
                .oneshot(crate::test_credentials::bind_request(
                    &server,
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/core/facade/{verb}"))
                        .header("Authorization", recipe)
                        .header("Content-Type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                ))
                .await
                .unwrap()
                .status()
        }
    };
    for verb in ["tasks.check", "tasks.expand", "tasks.ack", "tasks.cancel"] {
        assert_eq!(status(verb).await, StatusCode::NOT_FOUND, "{verb}");
    }
    assert_eq!(status("describe").await, StatusCode::OK);
}

#[tokio::test]
async fn http_describe_omits_a_task_outside_the_callers_read_floor() {
    let (_dir, server, recipe, _, task) = task_outside_read_floor();
    let (_, section) = post_task_verb(&server, &recipe, "describe", json!({})).await;
    assert!(
        section["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"] != task.to_hex()),
        "{section}"
    );
}

#[tokio::test]
async fn http_describe_card_refuses_a_task_outside_the_callers_read_floor() {
    let (_dir, server, recipe, _, task) = task_outside_read_floor();
    let (status, _) = post_task_verb(
        &server,
        &recipe,
        "describe",
        json!({"task_ref": task.to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http_tasks_update_writes_nothing_on_a_task_outside_the_callers_read_floor() {
    let (_dir, server, recipe, owner, task) = task_outside_read_floor();
    post_task_verb(
        &server,
        &recipe,
        "tasks.update",
        json!({"task_ref": task.to_hex()}),
    )
    .await;
    // A failed task stays on the owner's board until its ack bit is set.
    let oneiron::task_verb::TaskDescription::Section(section) = server
        .vault
        .memory(owner, EdgeActorClass::Human)
        .describe(None)
        .unwrap()
    else {
        panic!("describe without a task returns the TASKS section");
    };
    assert!(section.rows.iter().any(|row| row.id == task.to_hex()));
}

#[tokio::test]
async fn export_projects_five_formats_and_refuses_non_owner_credentials() {
    use oneiron::authority::SlipCaveat;
    use oneiron::federation::{Scope, ScopeAxis, ScopeId};
    use oneiron::note::{NoteKind, NoteScope, NoteWriteEnvelope};
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let other = EntityId::now();
    vault
        .put_entity(
            &other,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"another human",
        )
        .unwrap();
    let note = vault
        .memory(actor, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: actor },
            source_revision_ref: [0x69; 16],
            markdown: "private export owner diary".into(),
            mask: None,
        })
        .unwrap();
    assert!(
        vault
            .memory(other, EdgeActorClass::Human)
            .get_entity(&note.id_hex)
            .unwrap()
            .is_none()
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("facade-export".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let owner_recipe = format!("principal_ref={};actor_class=human", actor.to_hex());
    let reader_recipe = format!(
        "scope=core:read;principal_ref={};actor_class=human",
        other.to_hex()
    );
    let (owner, owner_key) = crate::test_credentials::credential(&server, &owner_recipe);
    let (reader, reader_key) = crate::test_credentials::credential(&server, &reader_recipe);
    let mut narrow = owner.clone();
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(actor)]));
    narrow
        .attenuate(
            SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &owner_key,
        )
        .unwrap();
    let app = crate::build_app(Arc::clone(&server));
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/facade/export")
            .header("Content-Type", "application/json")
            .body(Body::from(json!({"format":format}).to_string()))
            .unwrap();
        let response = app
            .clone()
            .oneshot(crate::test_credentials::bind_slip_request(
                &server, &owner, &owner_key, request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{format}");
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["format"], format);
        let rendered = body["rendered"].as_str().unwrap();
        assert!(rendered.contains("evidence_ledger"));
        assert!(rendered.contains("private export owner diary"));
        if format == "json" {
            let document: Value = serde_json::from_str(rendered).unwrap();
            assert!(
                document["evidence_ledger"]["entities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["id"] == actor.to_hex() && row["short_ref"].as_str().is_some())
            );
        }
    }
    // The host's logged root has no actor binding; its verified full-vault
    // instrument is still an owner, not a read-only scoped slip.
    let (host_slip, host_key) =
        crate::test_credentials::credential(&server, "jti=facade-export-host-root");
    let host = Request::builder()
        .method("POST")
        .uri("/v1/core/facade/export")
        .header("Content-Type", "application/json")
        .body(Body::from(json!({"format":"json"}).to_string()))
        .unwrap();
    let response = app
        .clone()
        .oneshot(crate::test_credentials::bind_slip_request(
            &server, &host_slip, &host_key, host,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("private export owner diary"));

    assert_eq!(
        oneiron::task_verb::sdk::invoke(
            &server.vault.memory(other, EdgeActorClass::Human),
            "export",
            json!({"format":"json"}),
        )
        .unwrap_err()
        .code,
        MEMORY_CODE_FORBIDDEN,
    );
    for (credential, holder, format, status) in [
        (&reader, &reader_key, "json", StatusCode::FORBIDDEN),
        (&narrow, &owner_key, "json", StatusCode::FORBIDDEN),
        (&owner, &owner_key, "gemini", StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/facade/export")
            .header("Content-Type", "application/json")
            .body(Body::from(json!({"format":format}).to_string()))
            .unwrap();
        let response = app
            .clone()
            .oneshot(crate::test_credentials::bind_slip_request(
                &server, credential, holder, request,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{format}");
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(!body.to_string().contains("private export owner diary"));
        assert!(!body.to_string().contains(&note.entity_ref));
    }
    crate::test_credentials::revoke(&server, &owner_recipe);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/core/facade/export")
        .header("Content-Type", "application/json")
        .body(Body::from("{\"format\":\"json\"}"))
        .unwrap();
    let response = app
        .oneshot(crate::test_credentials::bind_slip_request(
            &server, &owner, &owner_key, request,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A served vault, its owner, and a read/write slip bound to that owner.
struct OwnerFacade {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    slip: oneiron::authority::CapabilitySlip,
    holder: ed25519_dalek::SigningKey,
}

impl OwnerFacade {
    fn new(secret: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("vault"),
        );
        let actor = vault.ensure_embedded_owner_actor().expect("owner");
        let server = Arc::new(
            SyncServer::new(
                vault,
                crate::config::SyncServerConfig {
                    auth_secret: Some(secret.to_owned()),
                    ..Default::default()
                },
            )
            .expect("server"),
        );
        let recipe = format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human",
            actor.to_hex()
        );
        let (slip, holder) = crate::test_credentials::credential(&server, &recipe);
        Self {
            _dir: dir,
            server,
            slip,
            holder,
        }
    }

    async fn post(&self, verb: &str, payload: Value) -> (StatusCode, Value) {
        let request = crate::test_credentials::bind_slip_request(
            &self.server,
            &self.slip,
            &self.holder,
            Request::builder()
                .method("POST")
                .uri(format!("/v1/core/facade/{verb}"))
                .header("Content-Type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        );
        let response = crate::build_app(Arc::clone(&self.server))
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (status, serde_json::from_slice(&body).expect("JSON"))
    }

    /// Witnesses one user message per entry and returns their short ids.
    async fn witness(&self, conversation: &str, messages: &[(u64, &str)]) -> Vec<String> {
        let mut said = Vec::new();
        for (at, content) in messages {
            let (status, receipt) = self
                .post(
                    "witness",
                    json!({"conversation_ref": conversation, "occurred_at": at, "messages": [{
                        "author": "user", "message_type": "text", "content": content,
                        "is_visible": true, "order": 0
                    }]}),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{receipt}");
            said.push(
                receipt["message_short_ids"][0]
                    .as_str()
                    .expect("id")
                    .to_owned(),
            );
        }
        said
    }

    /// Recalls, returning each item's `(short_id, kind)` and the time hints.
    async fn recall(&self, request: Value) -> (Vec<(String, String)>, Vec<(String, String)>) {
        let (status, pack) = self.post("recall", request.clone()).await;
        assert_eq!(status, StatusCode::OK, "{request}: {pack}");
        let field = |value: &Value, name: &str| value[name].as_str().unwrap_or_default().to_owned();
        let items = pack["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| (field(item, "short_id"), field(item, "kind")))
            .collect();
        let hints = pack["retrieval_meta"]["temporal_hints"]
            .as_array()
            .map(|hints| {
                hints
                    .iter()
                    .map(|hint| (field(hint, "phrase"), field(hint, "status")))
                    .collect()
            })
            .unwrap_or_default();
        (items, hints)
    }
}

fn ids(items: &[(String, String)]) -> Vec<&str> {
    items.iter().map(|(id, _)| id.as_str()).collect()
}

fn named(hints: &[(&str, &str)]) -> Vec<(String, String)> {
    hints
        .iter()
        .map(|(phrase, status)| ((*phrase).to_owned(), (*status).to_owned()))
        .collect()
}

/// Wave 9 long-context A/B: a recall query with a time word the parser could
/// not resolve (`tomorrow`, `last 2 weeks`, two hints at once) failed the
/// whole request with a 400, and the agent lost its recall. Recall now runs on
/// its other signals, names each hint it used or skipped, and resolves hints
/// against the caller's `as_of`.
#[tokio::test]
async fn recall_reads_time_words_without_refusing_and_resolves_them_as_of() {
    const DAY: u64 = 86_400;
    // 2026-01-01T00:00:00Z.
    const DAY0: u64 = 1_767_225_600;
    let facade = OwnerFacade::new("facade-temporal-hints-secret");
    let said = [
        facade
            .witness(
                "21212121212121212121212121212121",
                &[(
                    DAY0 + 3_600,
                    "Staging rollout runs tomorrow night after the freeze.",
                )],
            )
            .await,
        facade
            .witness(
                "31313131313131313131313131313131",
                &[(
                    DAY0 + DAY + 3_600,
                    "Staging rollout moved again; the canary goes first.",
                )],
            )
            .await,
    ]
    .concat();
    let recall =
        |query: &str, as_of: Option<u64>| facade.recall(json!({"query": query, "as_of": as_of}));
    let both = |found: &[(String, String)]| {
        ids(found).contains(&said[0].as_str()) && ids(found).contains(&said[1].as_str())
    };

    // The A/B's refused query: a future hint is named and not applied.
    let (found, hints) = recall("what runs tomorrow night", None).await;
    assert!(ids(&found).contains(&said[0].as_str()), "{found:?}");
    assert_eq!(hints, named(&[("tomorrow", "future")]));

    let (found, hints) = recall("staging rollout in the last 2 weeks", Some(DAY0 + 3 * DAY)).await;
    assert!(both(&found), "{found:?}");
    assert_eq!(hints, named(&[("last 2 weeks", "used")]));

    let (found, hints) = recall("recent staging rollout yesterday", Some(DAY0 + 2 * DAY)).await;
    assert!(both(&found), "{found:?}");
    assert_eq!(hints, named(&[("recent", "used"), ("yesterday", "used")]));

    let (found, hints) = recall("staging rollout plans for the last several weeks", None).await;
    assert!(both(&found), "{found:?}");
    assert_eq!(hints, named(&[("last several weeks", "unresolved")]));

    // `as_of` moves the day "yesterday" names.
    let (found, _) = recall("staging rollout yesterday", Some(DAY0 + DAY + 7_200)).await;
    assert_eq!(ids(&found), [said[0].as_str()], "{found:?}");
    let (found, _) = recall("staging rollout yesterday", Some(DAY0 + 2 * DAY + 7_200)).await;
    assert_eq!(ids(&found), [said[1].as_str()], "{found:?}");
}

/// Wave 9 long-context A/B: recall named a message `ms87:76@<revision>` where
/// its witness receipt said `ms87:76`, so a client stripped the suffix to join
/// them; and TURN, CONVERSATION and PERSON rows took recall `limit` slots.
/// Recall now returns the receipt's short id with the revision beside it,
/// turns and conversations take no slot unless the scope names their kinds,
/// and the author every message points at ranks below the messages that
/// matched.
#[tokio::test]
async fn recall_returns_witness_short_ids_and_limit_counts_content() {
    let facade = OwnerFacade::new("facade-ids-and-slots-secret");
    let lines: Vec<String> = (0..7)
        .map(|turn| format!("The tide table lists spring tide number {turn}."))
        .collect();
    let at = |turn: usize| 1_767_225_600 + 60 * turn as u64;
    let said = facade
        .witness(
            "71717171717171717171717171717171",
            &lines
                .iter()
                .enumerate()
                .map(|(turn, line)| (at(turn), line.as_str()))
                .collect::<Vec<_>>(),
        )
        .await;

    let (status, pack) = facade
        .post(
            "recall",
            json!({"query": "tide table spring tide", "limit": 5}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    let items = pack["items"].as_array().expect("items");
    assert_eq!(items.len(), 5, "{pack}");
    for item in items {
        assert_eq!(item["kind"], "MESSAGE", "{item}");
        let short_id = item["short_id"].as_str().expect("short id");
        assert!(
            said.iter().any(|id| id == short_id),
            "{short_id} in {said:?}"
        );
        assert_eq!(
            item["source_revision_ref"].as_str().map(str::len),
            Some(32),
            "{item}"
        );
    }

    // People stay in recall: the author comes after every matching message.
    let (found, _) = facade
        .recall(json!({"query": "tide table spring tide", "limit": 10}))
        .await;
    let kinds: Vec<&str> = found.iter().map(|(_, kind)| kind.as_str()).collect();
    assert_eq!(kinds[..7], ["MESSAGE"; 7], "{found:?}");
    assert!(kinds[7..].contains(&"PERSON"), "{found:?}");

    // Containers come back when the scope names them.
    let (found, _) = facade
        .recall(json!({"query": "tide table spring tide", "limit": 5,
            "scope": {"kinds": ["TURN"]}}))
        .await;
    assert!(
        !found.is_empty() && found.iter().all(|(_, kind)| kind == "TURN"),
        "{found:?}"
    );
}

/// Owner ruling (Wave 9a, 2026-10-08): people are memories, so an agent
/// asking "who is Mika?" gets the person by default.
#[tokio::test]
async fn recall_returns_the_person_an_agent_asks_about() {
    use oneiron::memory::{StructuralPutInput, TextIndexField};

    let facade = OwnerFacade::new("facade-person-recall-secret");
    let vault = facade.server.vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let person = vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".into(),
            body: json!({"name": "Mika Tanaka"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".into(),
                value: "Mika Tanaka".into(),
            }]),
            edges: None,
            occurred_at: 1_767_225_600,
            learned_at: None,
        })
        .expect("put person");

    let (found, _) = facade
        .recall(json!({"query": "who is Mika?", "limit": 5}))
        .await;
    assert!(
        found.contains(&(person.entity_ref.clone(), "PERSON".to_owned())),
        "{} in {found:?}",
        person.entity_ref
    );
}
