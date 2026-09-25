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
    assert_eq!(status, StatusCode::FORBIDDEN);
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
    );
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
        .attenuate(SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        })
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

#[tokio::test]
async fn http_tasks_check_omits_a_task_outside_the_callers_read_floor() {
    let (_dir, server, recipe, _, task) = task_outside_read_floor();
    let (_, section) = post_task_verb(&server, &recipe, "tasks.check", json!({})).await;
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
async fn http_tasks_expand_refuses_a_task_outside_the_callers_read_floor() {
    let (_dir, server, recipe, _, task) = task_outside_read_floor();
    let (status, _) = post_task_verb(
        &server,
        &recipe,
        "tasks.expand",
        json!({"task_ref": task.to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http_tasks_ack_writes_nothing_on_a_task_outside_the_callers_read_floor() {
    let (_dir, server, recipe, owner, task) = task_outside_read_floor();
    post_task_verb(
        &server,
        &recipe,
        "tasks.ack",
        json!({"task_ref": task.to_hex()}),
    )
    .await;
    // A failed task stays on the owner's board until its ack bit is set.
    assert!(
        server
            .vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_check()
            .unwrap()
            .rows
            .iter()
            .any(|row| row.id == task.to_hex())
    );
}
