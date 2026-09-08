//! OpenAPI route auth, v1/legacy auth plane + revocation + scopes, core idempotency middleware semantics.

use super::*;

#[tokio::test]
async fn openapi_route_serves_json_document() {
    let (_dir, server) = test_server();
    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("OpenAPI response body");
    let body: Value = serde_json::from_slice(&body).expect("OpenAPI JSON body");
    assert!(
        body["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.1")),
        "served OpenAPI version should start with 3.1: {:?}",
        body["openapi"]
    );
}

#[tokio::test]
async fn openapi_route_uses_api_auth() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(SyncServer::new(vault, SyncServerConfig::default()).unwrap());
    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("ApiError response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_eq!(body["code"], Value::from("UNAUTHORIZED"));
}

#[tokio::test]
async fn v1_core_route_missing_auth_returns_typed_error_envelope() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");
    assert_eq!(error_envelope(&body)["details"]["code"], "UNAUTHORIZED");
}

/// The revocation registry has teeth on the wire, not just in the auth unit
/// tests: a revoked bearer gets the same uniform 401 as any other refusal,
/// while a sibling minted from identical claims keeps working.
#[tokio::test]
async fn v1_core_route_rejects_a_revoked_bearer_and_admits_its_sibling() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (revoked, revoked_jti) =
        crate::auth::mint_identified_core_token_v2("secret", "scope=core:read");
    let (sibling, _) = crate::auth::mint_identified_core_token_v2("secret", "scope=core:read");
    let uri = "/v1/core/turns/annotate?turn_id=not-an-entity";

    // Both authenticate before the revocation act (the 400 is the handler
    // rejecting the deliberately malformed turn id — auth already passed).
    for token in [&revoked, &sibling] {
        let (status, _) = route_json(
            server.clone(),
            core_request_with_authz("GET", uri, format!("Bearer {token}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "token must authenticate");
    }

    crate::auth::revoke_token_jti(server.vault(), &revoked_jti).expect("revoke");

    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz("GET", uri, format!("Bearer {revoked}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");

    let (status, _) = route_json(
        server,
        core_request_with_authz("GET", uri, format!("Bearer {sibling}"), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "revoking one token must not revoke its sibling"
    );
}

/// The owner-grade surfaces consult the registry too: revocation binds to the
/// token's identity, not to which plane it is presented on.
#[tokio::test]
async fn legacy_api_route_rejects_a_revoked_owner_grade_bearer() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (token, jti) = crate::auth::mint_identified_core_token_v2("secret", "");
    let uri = "/api/core/discover";

    let (status, _) = route_json(
        server.clone(),
        core_request_with_authz("GET", uri, format!("Bearer {token}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an identified owner token is live");

    crate::auth::revoke_token_jti(server.vault(), &jti).expect("revoke");

    let (status, _) = route_json(
        server,
        core_request_with_authz("GET", uri, format!("Bearer {token}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The owner-grade boundary itself, not revocation: a perfectly live scoped
/// bearer — authentic MAC, unrevoked jti, a scope the route would honor on
/// `/v1` — is still refused on the legacy `/api/*` plane, which reads the
/// whole vault under one actor ref. The same credential works on its own
/// `/v1` route in the same test, so the 401 pins the plane boundary and not
/// a broken token.
#[tokio::test]
async fn legacy_api_route_rejects_a_live_scoped_bearer_that_works_on_v1() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (scoped, jti) = crate::auth::mint_identified_core_token_v2("secret", "scope=core:read");
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {scoped}").parse().expect("bearer header"),
    );
    let auth = CoreAuth::from_headers(&headers, &server.config, server.vault().as_ref())
        .expect("scoped bearer authenticates");
    assert!(
        !auth.is_owner_grade(),
        "the fixture must be a scoped, non-owner-grade credential"
    );
    assert!(
        !crate::auth::is_revoked_or_unreadable(&jti, server.vault().as_ref()),
        "the fixture must be live: this test is about the plane, not revocation"
    );

    // Same credential, same server: accepted on its scoped /v1 route.
    let (status, _) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            "/v1/core/outbound/capabilities",
            format!("Bearer {scoped}"),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a scoped bearer is a /v1-plane instrument and must work there"
    );

    // Refused on every legacy `/api/*` route, read and mutating alike.
    for (method, uri, body) in [
        ("GET", "/api/core/discover", None),
        ("GET", "/api/openapi.json", None),
        ("GET", "/api/skills/oneiron.skills.md", None),
        ("GET", "/api/search/text?query=anything", None),
        (
            "POST",
            "/api/lease/revoke",
            Some(json!({ "client_id": "0000000000000042" })),
        ),
    ] {
        let (status, _) = route_json(
            server.clone(),
            core_request_with_authz(method, uri, format!("Bearer {scoped}"), body.as_ref()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "legacy {method} {uri} must refuse a scoped bearer"
        );
    }
}

#[tokio::test]
async fn v1_core_idempotency_preflight_uses_typed_error_envelope() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .method("POST")
            .uri("/v1/core/turns/annotate")
            .header("Idempotency-Key", "idem-1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "turn_id": "not-an-entity",
                    "source": "model_inference",
                    "vad": {
                        "valence": 0.0,
                        "arousal": 0.0,
                        "dominance": 0.0,
                    },
                    "annotated_at": 1_u64,
                })
                .to_string(),
            ))
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");
}

#[tokio::test]
async fn v1_core_route_rejects_valid_bearer_without_required_scope() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
            .header(AUTHORIZATION, test_bearer("scope=core:write"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:read")
    );
}

#[tokio::test]
async fn v1_core_route_wraps_handler_errors_after_bearer_auth() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
            .header(AUTHORIZATION, test_bearer("scope=core:read"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("turn_id")
    );
}

#[tokio::test]
async fn v1_core_idempotency_read_only_token_cannot_replay_cached_write_success() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let turn = seed_turn(&server, "cached write success");
    let body = turn_annotation_request_body(&turn, 300);

    let (write_status, write_body) = idempotent_core_annotate(
        server.clone(),
        "scoped-write-success",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:write").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(write_status, StatusCode::OK);
    assert_eq!(write_body["turn_id"], Value::from(turn.to_hex()));

    let (read_status, read_body) = idempotent_core_annotate(
        server,
        "scoped-write-success",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:read").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(read_status, StatusCode::FORBIDDEN);
    assert_error_envelope(&read_body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&read_body)["details"]["requiredScope"],
        Value::from("core:write")
    );
}

#[tokio::test]
async fn v1_core_idempotency_write_token_retry_is_not_poisoned_by_read_only_403() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let turn = seed_turn(&server, "read-only poison");
    let body = turn_annotation_request_body(&turn, 301);

    let (read_status, read_body) = idempotent_core_annotate(
        server.clone(),
        "scoped-read-poison",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:read").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(read_status, StatusCode::FORBIDDEN);
    assert_error_envelope(&read_body, "FORBIDDEN");

    let (write_status, write_body) = idempotent_core_annotate(
        server.clone(),
        "scoped-read-poison",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:write").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(write_status, StatusCode::OK);
    assert_eq!(write_body["turn_id"], Value::from(turn.to_hex()));
    assert!(
        server
            .vault
            .get_turn_vad_annotation(&turn)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn v1_core_idempotency_legacy_shared_secret_still_replays_and_conflicts() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let turn = seed_turn(&server, "legacy idempotency");
    let body = turn_annotation_request_body(&turn, 302);

    let (first_status, first_body) = idempotent_core_annotate(
        server.clone(),
        "legacy-core-idem",
        (AUTHORIZATION.as_str(), owner_bearer().as_str()),
        &body,
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (replay_status, replay_body) = idempotent_core_annotate(
        server.clone(),
        "legacy-core-idem",
        (AUTHORIZATION.as_str(), owner_bearer().as_str()),
        &body,
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(replay_body, first_body);

    let changed_body = turn_annotation_request_body(&turn, 303);
    let (conflict_status, conflict_body) = idempotent_core_annotate(
        server,
        "legacy-core-idem",
        (AUTHORIZATION.as_str(), owner_bearer().as_str()),
        &changed_body,
    )
    .await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_error_envelope(&conflict_body, "IDEMPOTENCY_REPLAY_CONFLICT");
}

#[tokio::test]
async fn v1_companion_access_grant_create_replays_idempotency_key() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_ref = seeded_test_entity_id(0x1265_0101).to_hex();
    let person_ref = seeded_test_entity_id(0x1265_0102).to_hex();
    let persona_ref = seeded_test_entity_id(0x1265_0103).to_hex();
    let create_request = json!({
        "principal_ref": principal_ref,
        "scope": {
            "kind": "companion_profile",
            "person_ref": person_ref,
            "persona_ref": persona_ref,
        },
        "created_at": 30_u64,
    });

    let make_request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/companion/access-grants")
            .header(AUTHORIZATION, test_bearer("scope=core:auth"))
            .header("Idempotency-Key", "companion-create-replay")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(create_request.to_string()))
            .expect("request")
    };
    let (first_status, first_body) = route_json(server.clone(), make_request()).await;
    let (replay_status, replay_body) = route_json(server.clone(), make_request()).await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(replay_body, first_body);

    let grant_id = oneiron::EntityId::from_hex(first_body["id"].as_str().expect("grant id"))
        .expect("grant id parses");
    assert_eq!(
        server
            .vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_ACCESS_GRANT)
            .expect("list access grants"),
        vec![grant_id]
    );
    assert_eq!(
        server
            .vault
            .companion_profile_access_grant(
                &oneiron::EntityId::from_hex(&principal_ref).expect("principal id"),
                &oneiron::EntityId::from_hex(&person_ref).expect("person id"),
                &oneiron::EntityId::from_hex(&persona_ref).expect("persona id"),
            )
            .expect("grant lookup"),
        Some(grant_id)
    );
}
