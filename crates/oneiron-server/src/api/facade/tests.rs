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
    let token = crate::auth::mint_core_token_v2(
        SECRET,
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human",
            actor.to_hex()
        ),
    );
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
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&payload).expect("request JSON"),
                    ))
                    .expect("request"),
            )
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
