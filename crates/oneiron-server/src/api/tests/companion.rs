//! Companion profile access grants, tiers/missing/stale/refresh reads, register CRUD/retire/end-relationship.

use super::*;

#[tokio::test]
async fn v1_companion_profile_access_grants_allow_deny_and_revoke() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let grant_id = seeded_test_entity_id(0x1265_0001).to_hex();
    let principal_ref = seeded_test_entity_id(0x1265_0002).to_hex();
    let person_ref = seeded_test_entity_id(0x1265_0003).to_hex();
    let persona_ref = seeded_test_entity_id(0x1265_0004).to_hex();
    let other_person_ref = seeded_test_entity_id(0x1265_0005).to_hex();
    let other_principal_ref = seeded_test_entity_id(0x1265_0006).to_hex();
    let cross_principal_grant_id = seeded_test_entity_id(0x1265_0007).to_hex();

    let profile_path_with_override = format!(
        "/v1/companion/profiles/{persona_ref}?principal_ref={principal_ref}&person_ref={person_ref}"
    );
    let (status, body) = route_json(
        server.clone(),
        core_request("GET", &profile_path_with_override, "core:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path_with_override,
            "companion:profile:read",
            &other_principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );

    let profile_path = format!("/v1/companion/profiles/{persona_ref}?person_ref={person_ref}");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("companion_profile.read")
    );

    let create_request = json!({
        "id": grant_id,
        "principal_ref": principal_ref,
        "scope": {
            "kind": "companion_profile",
            "person_ref": person_ref,
            "persona_ref": persona_ref,
        },
        "created_at": 10_u64,
    });
    let cross_principal_create_request = json!({
        "id": cross_principal_grant_id,
        "principal_ref": principal_ref,
        "scope": {
            "kind": "companion_profile",
            "person_ref": person_ref,
            "persona_ref": persona_ref,
        },
        "created_at": 10_u64,
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/companion/access-grants",
            "companion:access-grant:write",
            &other_principal_ref,
            Some(&cross_principal_create_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );
    assert!(
        server
            .vault
            .get_access_grant(
                &oneiron::EntityId::from_hex(&cross_principal_grant_id)
                    .expect("cross-principal grant id")
            )
            .expect("read cross-principal grant")
            .is_none(),
        "cross-principal create must not write an AccessGrant"
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/companion/access-grants",
            "companion:access-grant:write",
            &principal_ref,
            Some(&create_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], Value::from(grant_id.clone()));
    assert_eq!(body["status"], Value::from("active"));
    assert_eq!(body["capability"], Value::from("companion_profile.read"));

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["access"]["grant_id"], Value::from(grant_id.clone()));
    assert_eq!(body["persona_ref"], Value::from(persona_ref.clone()));

    let wrong_scope_path =
        format!("/v1/companion/profiles/{persona_ref}?person_ref={other_person_ref}");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &wrong_scope_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");

    let revoke_path = format!("/v1/companion/access-grants/{grant_id}/revoke");
    let revoke_request = json!({ "revoked_at": 20_u64 });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &revoke_path,
            "companion:access-grant:write",
            &other_principal_ref,
            Some(&revoke_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );
    assert_eq!(
        server
            .vault
            .get_access_grant(&oneiron::EntityId::from_hex(&grant_id).expect("test grant id"))
            .expect("read grant")
            .expect("grant exists")
            .status,
        oneiron::access_grant::AccessGrantStatus::Active,
        "cross-principal revoke must not mutate the grant"
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &revoke_path,
            "companion:access-grant:write",
            &principal_ref,
            Some(&revoke_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], Value::from("revoked"));
    assert_eq!(body["revoked_at"], Value::from(20_u64));

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/companion/access-grants",
            "companion:access-grant:write",
            &principal_ref,
            Some(&create_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_envelope(&body, "INVALID_STATE");
    assert_eq!(
        error_envelope(&body)["details"]["state"],
        Value::from("access_grant_exists")
    );
    assert_eq!(
        server
            .vault
            .get_access_grant(&oneiron::EntityId::from_hex(&grant_id).expect("test grant id"))
            .expect("read grant")
            .expect("grant exists")
            .status,
        oneiron::access_grant::AccessGrantStatus::Revoked
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
}

#[tokio::test]
async fn v1_companion_profile_read_returns_persisted_tiers_snapshot() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let grant_id = seeded_test_entity_id(0x1218_0001);
    let principal_ref = seeded_test_entity_id(0x1218_0002);
    let person_ref = seeded_test_entity_id(0x1218_0003);
    let persona_ref = seeded_test_entity_id(0x1218_0004);
    let source_a = seeded_test_entity_id(0x1218_0005);
    let source_b = seeded_test_entity_id(0x1218_0006);
    seed_companion_profile_access(&server, grant_id, principal_ref, person_ref, persona_ref);

    let profile = oneiron::PsychProfile::new(
        persona_ref,
        "compact tier",
        "retrieval text tier",
        "Narrative profile tier.",
        vec![source_b, source_a],
        oneiron::psych_profile::PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("confidence"),
    )
    .expect("profile");
    server
        .vault
        .put_psych_profile(&persona_ref, &profile)
        .expect("put psych profile");

    let path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds={},{}",
        persona_ref.to_hex(),
        person_ref.to_hex(),
        source_b.to_hex(),
        source_a.to_hex()
    );
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "GET",
            &path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "persona_ref": persona_ref.to_hex(),
            "person_ref": person_ref.to_hex(),
            "access": {
                "grant_id": grant_id.to_hex(),
                "principal_ref": principal_ref.to_hex(),
                "scope": {
                    "kind": "companion_profile",
                    "person_ref": person_ref.to_hex(),
                    "persona_ref": persona_ref.to_hex(),
                },
            },
            "state": "fresh",
            "profile": {
                "subject_ref": persona_ref.to_hex(),
                "compact": "compact tier",
                "text": "retrieval text tier",
                "narrative": "Narrative profile tier.",
                "sourceRevisionIds": [source_a.to_hex(), source_b.to_hex()],
                "confidence": {
                    "compact": 0.8,
                    "text": 0.7,
                    "narrative": 0.6,
                },
                "status": "fresh",
            },
            "stale_reason": null,
            "next_action": null,
            "drift_anchors": [
                {
                    "state": "keep",
                    "sourceRevisionRef": source_a.to_hex(),
                },
                {
                    "state": "keep",
                    "sourceRevisionRef": source_b.to_hex(),
                },
            ],
        })
    );
}

#[tokio::test]
async fn v1_companion_profile_read_returns_missing_and_stale_next_actions() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_ref = seeded_test_entity_id(0x1218_0101);
    let person_ref = seeded_test_entity_id(0x1218_0102);
    let missing_persona_ref = seeded_test_entity_id(0x1218_0103);
    let stale_persona_ref = seeded_test_entity_id(0x1218_0104);
    let source_a = seeded_test_entity_id(0x1218_0105);
    let source_b = seeded_test_entity_id(0x1218_0106);
    let existing_persona_ref = seeded_test_entity_id(0x1218_0109);
    seed_companion_profile_access(
        &server,
        seeded_test_entity_id(0x1218_0107),
        principal_ref,
        person_ref,
        missing_persona_ref,
    );
    seed_companion_profile_access(
        &server,
        seeded_test_entity_id(0x1218_0108),
        principal_ref,
        person_ref,
        stale_persona_ref,
    );
    seed_companion_profile_access(
        &server,
        seeded_test_entity_id(0x1218_010A),
        principal_ref,
        person_ref,
        existing_persona_ref,
    );
    server
        .vault
        .put_entity(
            &existing_persona_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"persona entity without psych profile",
        )
        .expect("seed existing persona entity");
    let stale_profile = oneiron::PsychProfile::new(
        stale_persona_ref,
        "stale compact",
        "stale text",
        "Stale narrative.",
        vec![source_a],
        oneiron::psych_profile::PsychProfileConfidence::new(0.5, 0.5, 0.5).expect("confidence"),
    )
    .expect("profile")
    .marked_stale();
    server
        .vault
        .put_psych_profile(&stale_persona_ref, &stale_profile)
        .expect("put stale profile");

    let missing_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        missing_persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (missing_status, missing_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &missing_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(missing_status, StatusCode::OK);
    assert_eq!(missing_body["state"], Value::from("missing"));
    assert!(missing_body["profile"].is_null());
    assert_eq!(missing_body["next_action"]["kind"], Value::from("refresh"));
    assert_eq!(
        missing_body["next_action"]["reason"],
        Value::from("missing")
    );

    let existing_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        existing_persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (existing_status, existing_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &existing_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(existing_status, StatusCode::OK);
    assert_eq!(existing_body["state"], Value::from("missing"));
    assert!(existing_body["profile"].is_null());
    assert_eq!(
        existing_body["next_action"]["reason"],
        Value::from("missing")
    );

    let stale_path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds={}",
        stale_persona_ref.to_hex(),
        person_ref.to_hex(),
        source_b.to_hex()
    );
    let (stale_status, stale_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &stale_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(stale_status, StatusCode::OK);
    assert_eq!(stale_body["state"], Value::from("stale"));
    assert_eq!(
        stale_body["stale_reason"],
        json!({
            "kind": "marked_stale",
            "expectedSourceRevisionIds": null,
            "actualSourceRevisionIds": null,
        })
    );
    assert_eq!(
        stale_body["next_action"]["sourceRevisionIds"],
        json!([source_b.to_hex()])
    );
    assert_eq!(
        stale_body["drift_anchors"],
        json!([
            {
                "state": "revert",
                "sourceRevisionRef": source_a.to_hex(),
            },
            {
                "state": "tune",
                "sourceRevisionRef": source_b.to_hex(),
            },
        ])
    );

    let stale_fallback_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        stale_persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (fallback_status, fallback_body) = route_json(
        server,
        core_request_with_principal_ref(
            "GET",
            &stale_fallback_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(fallback_status, StatusCode::OK);
    assert_eq!(fallback_body["state"], Value::from("stale"));
    assert_eq!(
        fallback_body["next_action"]["sourceRevisionIds"],
        json!([source_a.to_hex()])
    );
    assert_eq!(
        fallback_body["drift_anchors"],
        json!([
            {
                "state": "keep",
                "sourceRevisionRef": source_a.to_hex(),
            },
        ])
    );
    assert_eq!(
        fallback_body["next_action"]["drift_anchors"],
        fallback_body["drift_anchors"]
    );
}

#[tokio::test]
async fn v1_companion_profile_refresh_preserves_sources_and_drift_anchors() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let grant_id = seeded_test_entity_id(0x1218_0201);
    let principal_ref = seeded_test_entity_id(0x1218_0202);
    let person_ref = seeded_test_entity_id(0x1218_0203);
    let persona_ref = seeded_test_entity_id(0x1218_0204);
    let keep_source = seeded_test_entity_id(0x1218_0205);
    let revert_source = seeded_test_entity_id(0x1218_0206);
    let tune_source = seeded_test_entity_id(0x1218_0207);
    seed_companion_profile_access(&server, grant_id, principal_ref, person_ref, persona_ref);
    let profile = oneiron::PsychProfile::new(
        persona_ref,
        "refresh compact",
        "refresh text",
        "Refresh narrative.",
        vec![revert_source, keep_source],
        oneiron::psych_profile::PsychProfileConfidence::new(0.9, 0.8, 0.7).expect("confidence"),
    )
    .expect("profile");
    let stored_source_revision_ids = profile.source_revision_ids.clone();
    server
        .vault
        .put_psych_profile(&persona_ref, &profile)
        .expect("put profile");

    let refresh_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let refresh_request = json!({
        "sourceRevisionIds": [
            keep_source.to_hex(),
            tune_source.to_hex(),
            tune_source.to_hex(),
        ],
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&refresh_request),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], Value::from("stale"));
    assert_eq!(
        body["profile"]["sourceRevisionIds"],
        json!([keep_source.to_hex(), revert_source.to_hex()])
    );
    assert_eq!(
        body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );
    assert_eq!(
        body["drift_anchors"],
        json!([
            {
                "state": "keep",
                "sourceRevisionRef": keep_source.to_hex(),
            },
            {
                "state": "revert",
                "sourceRevisionRef": revert_source.to_hex(),
            },
            {
                "state": "tune",
                "sourceRevisionRef": tune_source.to_hex(),
            },
        ])
    );
    assert_eq!(body["next_action"]["drift_anchors"], body["drift_anchors"]);
    assert_eq!(
        server
            .vault
            .get_psych_profile(&persona_ref)
            .expect("read profile")
            .expect("profile persists")
            .source_revision_ids,
        stored_source_revision_ids
    );

    let refresh_query_path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds={},{}",
        persona_ref.to_hex(),
        person_ref.to_hex(),
        keep_source.to_hex(),
        tune_source.to_hex()
    );
    let (query_status, query_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&json!({})),
        ),
    )
    .await;
    assert_eq!(query_status, StatusCode::OK);
    assert_eq!(
        query_body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );

    let (bodyless_query_status, bodyless_query_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(bodyless_query_status, StatusCode::OK);
    assert_eq!(
        bodyless_query_body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );

    let malformed_request = Request::builder()
        .method("POST")
        .uri(&refresh_query_path)
        .header(
            AUTHORIZATION,
            test_bearer(&format!(
                "scope=companion:profile:read;principal_ref={}",
                principal_ref.to_hex()
            )),
        )
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{"))
        .expect("request");
    let (malformed_status, malformed_body) = route_json(server.clone(), malformed_request).await;
    assert_eq!(malformed_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&malformed_body, "BAD_REQUEST");

    let reordered_request = json!({
        "sourceRevisionIds": [tune_source.to_hex(), keep_source.to_hex()],
    });
    let (reordered_status, reordered_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&reordered_request),
        ),
    )
    .await;
    assert_eq!(reordered_status, StatusCode::OK);
    assert_eq!(reordered_body["state"], Value::from("stale"));
    assert_eq!(
        reordered_body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );

    let conflict_request = json!({
        "sourceRevisionIds": [keep_source.to_hex()],
    });
    let (conflict_status, conflict_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&conflict_request),
        ),
    )
    .await;
    assert_eq!(conflict_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&conflict_body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&conflict_body)["details"]["field"],
        Value::from("sourceRevisionIds")
    );

    let refresh_empty_query_path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds=",
        persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (empty_query_status, empty_query_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_empty_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&json!({})),
        ),
    )
    .await;
    assert_eq!(empty_query_status, StatusCode::OK);
    assert_eq!(empty_query_body["state"], Value::from("fresh"));
    assert!(empty_query_body["next_action"].is_null());

    let (empty_status, empty_body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            &refresh_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&json!({ "sourceRevisionIds": [] })),
        ),
    )
    .await;
    assert_eq!(empty_status, StatusCode::OK);
    assert_eq!(empty_body["state"], Value::from("fresh"));
    assert!(empty_body["next_action"].is_null());
}

#[tokio::test]
async fn retired_companion_register_routes_are_absent_from_http_and_openapi() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let record = seeded_test_entity_id(0x2284_0001).to_hex();
    for (method, path) in [
        ("POST", "/v1/companion/register/records".to_owned()),
        ("GET", format!("/v1/companion/register/records/{record}")),
        ("POST", format!("/v1/companion/register/records/{record}")),
        (
            "POST",
            format!("/v1/companion/register/records/{record}/retire"),
        ),
        (
            "POST",
            format!("/v1/companion/register/records/{record}/end-relationship"),
        ),
    ] {
        let (status, _, _) = route_bytes(
            server.clone(),
            core_request(method, &path, "core:auth", None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}
