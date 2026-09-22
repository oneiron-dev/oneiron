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
    let app = crate::build_app(server);
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
    async fn post(app: axum::Router, token: &str, verb: &str, input: Value) -> (StatusCode, Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&input).unwrap()))
                    .unwrap(),
            )
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
        crate::auth::mint_core_token_v2(
            SECRET,
            &format!(
                "scope={scope};principal_ref={};actor_class=human",
                actor.to_hex()
            ),
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
    let app = crate::build_app(server);
    let (status, _) = post(app.clone(), SECRET, "tasks.ask", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for answer_first in [false, true] {
        let spec = json!({"question":{"text":"Proceed?"},"holders":[owner.to_hex(),second.to_hex()],"idempotency_key":format!("order-{answer_first}"),"outcome_binding":null});
        let (status, receipt) = post(app.clone(), &owner_token, "tasks.ask", spec.clone()).await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        let handle = receipt["handle"].clone();
        let (_, retry) = post(app.clone(), &owner_token, "tasks.ask", spec).await;
        assert_eq!(retry["handle"], handle);
        assert_eq!(retry["replayed"], true);
        let wait = json!({"handle":handle,"step_key":"caller-step"});
        let (status, _) = post(
            app.clone(),
            &token(owner, "core:read"),
            "tasks.wait",
            wait.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        if !answer_first {
            let (status, pending) =
                post(app.clone(), &owner_token, "tasks.wait", wait.clone()).await;
            assert_eq!(status, StatusCode::OK, "{pending}");
            assert!(pending.get("Pending").is_some());
            // Only that logical step waited: the caller can issue another ask now.
            let (status,other)=post(app.clone(),&owner_token,"tasks.ask",json!({"question":{"text":"Unrelated"},"holders":[owner.to_hex()],"idempotency_key":"kept-working","outcome_binding":null})).await;
            assert_eq!(status, StatusCode::OK, "{other}");
        }
        let (status, first) = post(
            app.clone(),
            &owner_token,
            "tasks.answer",
            json!({"handle":handle,"result_ref":owner.to_hex()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let (status, second_answer) = post(
            app.clone(),
            &second_token,
            "tasks.answer",
            json!({"handle":handle,"result_ref":second.to_hex()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{second_answer}");
        assert_eq!(second_answer, first);
        let (_, ready) = post(app.clone(), &owner_token, "tasks.wait", wait.clone()).await;
        assert_eq!(ready["Ready"], first);
        let (_, replayed) = post(app.clone(), &owner_token, "tasks.wait", wait).await;
        assert_eq!(replayed["AlreadyResumed"], first);
    }
    for i in 0..12 {
        let (status,body)=post(app.clone(),&owner_token,"tasks.ask",json!({"question":{"text":"burst"},"holders":[owner.to_hex()],"idempotency_key":format!("burst-{i}"),"outcome_binding":null})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["count"].as_u64().unwrap() > 0);
    }
}

#[tokio::test]
async fn rooms_http_routes_only_the_addressed_companion_and_requires_a_claim() {
    async fn post(app: axum::Router, token: &str, verb: &str, input: Value) -> (StatusCode, Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&input).unwrap()))
                    .unwrap(),
            )
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
        crate::auth::mint_core_token_v2(
            SECRET,
            &format!(
                "scope=core:read,core:write;principal_ref={};actor_class={class}",
                actor.to_hex()
            ),
        )
    };
    let owner_token = token(owner, "human");
    let addressed_token = token(addressed, "agent");
    let other_token = token(other, "agent");
    let app = crate::build_app(Arc::new(
        SyncServer::new(
            vault.clone(),
            crate::config::SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .unwrap(),
    ));
    let (status, rooms) = post(app.clone(), &addressed_token, "rooms.list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{rooms}");
    assert_eq!(rooms.as_array().unwrap().len(), 1);
    let turn = EntityId::now().to_hex();
    let incoming = json!({"conversation_ref":room.to_hex(),"turn_ref":turn,"occurred_at":2,
        "messages":[{"author":"user","message_type":"text","content":"@addressed respond",
        "metadata":{"room_mentions":["@addressed"]},"is_visible":true,"order":0}]});
    let (status, receipt) = post(app.clone(), &owner_token, "rooms.speak", incoming).await;
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
    let (status, _) = post(app.clone(), &addressed_token, "rooms.speak", reply.clone()).await;
    assert_ne!(status, StatusCode::OK);
    let claim = json!({"room_ref":room.to_hex(),"turn_ref":turn});
    let (status, outcome) = post(app.clone(), &other_token, "rooms.claim", claim.clone()).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(outcome, json!("NotAddressed"));
    let (status, claimed) = post(app.clone(), &addressed_token, "rooms.claim", claim.clone()).await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    assert_eq!(claimed["Claimed"]["actor"], addressed.to_hex());
    assert!(
        claimed["Claimed"]["receipt_ref"]
            .as_str()
            .unwrap()
            .starts_with("rooms.claim:")
    );
    assert_eq!(
        post(app.clone(), &addressed_token, "rooms.claim", claim)
            .await
            .1,
        claimed
    );
    let (status, _) = post(app.clone(), &other_token, "rooms.speak", reply.clone()).await;
    assert_ne!(status, StatusCode::OK);
    let (status, spoken) = post(app.clone(), &addressed_token, "rooms.speak", reply).await;
    assert_eq!(status, StatusCode::OK, "{spoken}");
    let (status, messages) = post(
        app,
        &owner_token,
        "rooms.messages",
        json!({"room_ref":room.to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{messages}");
    let messages = messages.as_array().unwrap();
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
    let app = crate::build_app(server);
    let full = crate::auth::mint_core_token_v2(
        SECRET,
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human",
            actor.to_hex()
        ),
    );
    let readonly = crate::auth::mint_core_token_v2(
        SECRET,
        &format!(
            "scope=core:read;principal_ref={};actor_class=human",
            actor.to_hex()
        ),
    );
    let unbound = crate::auth::mint_core_token_v2(SECRET, "scope=core:read,core:write");
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
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
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
