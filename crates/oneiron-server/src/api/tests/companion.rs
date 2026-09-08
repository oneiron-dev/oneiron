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
#[expect(clippy::too_many_lines)]
async fn v1_companion_register_api_create_update_read_and_retire_typed_envelopes() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let neutral_id = seeded_test_entity_id(0x1219_0001).to_hex();
    let personal_id = seeded_test_entity_id(0x1219_0002).to_hex();
    let shared_id = seeded_test_entity_id(0x1219_0003).to_hex();
    let actor_ref = seeded_test_entity_id(0x1219_0004).to_hex();
    let persona_ref = seeded_test_entity_id(0x1219_0005).to_hex();
    let person_ref = seeded_test_entity_id(0x1219_0006).to_hex();
    let source_ref = seeded_test_entity_id(0x1219_0007).to_hex();
    let target_ref = seeded_test_entity_id(0x1219_0008).to_hex();

    let provenance = json!({
        "actor_ref": actor_ref,
        "actor_class": 1,
        "source": "user_stated",
        "approval": "approved",
        "value": { "source": "settings" }
    });
    let neutral_record = json!({
        "kind": "persona",
        "scope": { "kind": "neutral" },
        "subject": { "kind": "persona", "persona_ref": persona_ref },
        "value": { "style": "neutral @Oneiron" },
        "provenance": provenance.clone(),
        "export": "portable"
    });
    let personal_record = json!({
        "kind": "persona",
        "scope": { "kind": "personal", "person_ref": person_ref },
        "subject": { "kind": "persona", "persona_ref": persona_ref },
        "value": { "note": "private per-person companion note" },
        "provenance": provenance.clone(),
        "export": "local_only"
    });
    let shared_record = json!({
        "kind": "relationship",
        "scope": { "kind": "shared_vault", "vault_id": 7_u64 },
        "subject": {
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": source_ref,
                "target_ref": target_ref
            }
        },
        "value": { "note": "shared-vault boundary note" },
        "provenance": provenance.clone(),
        "export": "shared_vault"
    });

    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "core:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_0010).to_hex(),
                "record": neutral_record.clone()
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("companion:register:write")
    );

    for (id, record, learned_at) in [
        (&neutral_id, neutral_record.clone(), 30_u64),
        (&personal_id, personal_record.clone(), 31_u64),
        (&shared_id, shared_record.clone(), 32_u64),
    ] {
        let request = json!({ "id": id, "learned_at": learned_at, "record": record });
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/register/records",
                "companion:register:write",
                Some(&request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], Value::from(id.clone()));
        assert_eq!(body["record"]["lifecycle"], Value::from("active"));
    }

    let mut shared_scope_portable_export = shared_record.clone();
    shared_scope_portable_export["export"] = Value::from("portable");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_0009).to_hex(),
                "record": shared_scope_portable_export
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.export")
    );

    let mut neutral_scope_shared_export = neutral_record.clone();
    neutral_scope_shared_export["export"] = Value::from("shared_vault");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_000A).to_hex(),
                "record": neutral_scope_shared_export
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.export")
    );

    let mut retired_create_record = personal_record.clone();
    retired_create_record["lifecycle"] = Value::from("retracted");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_000C).to_hex(),
                "record": retired_create_record
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.lifecycle")
    );

    let read_path = format!("/v1/companion/register/records/{personal_id}");
    let (status, body) = route_json(
        server.clone(),
        core_request("GET", &read_path, "core:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("companion:register:read")
    );

    let (status, body) = route_json(
        server.clone(),
        core_request("GET", &read_path, "companion:register:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"]["note"],
        Value::from("private per-person companion note")
    );

    let mut scalar_update_record = body["record"].clone();
    scalar_update_record["value"] = Value::from("scalar private per-person note");
    scalar_update_record["provenance"]["value"] = Value::from(true);
    let scalar_update_request = json!({ "learned_at": 32_u64, "record": scalar_update_record });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&scalar_update_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"],
        Value::from("scalar private per-person note")
    );
    assert_eq!(body["record"]["provenance"]["value"], Value::from(true));

    let scalar_roundtrip_request =
        json!({ "learned_at": 33_u64, "record": body["record"].clone() });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&scalar_roundtrip_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"],
        Value::from("scalar private per-person note")
    );

    let updated_record = json!({
        "kind": "persona",
        "scope": { "kind": "personal", "person_ref": person_ref },
        "subject": { "kind": "persona", "persona_ref": persona_ref },
        "value": { "note": "updated private per-person companion note" },
        "provenance": body["record"]["provenance"].clone(),
        "export": "local_only"
    });
    let update_request = json!({ "learned_at": 34_u64, "record": updated_record });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&update_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"]["note"],
        Value::from("updated private per-person companion note")
    );

    let mut retire_via_update_record = updated_record.clone();
    retire_via_update_record["lifecycle"] = Value::from("retracted");
    let retire_via_update = json!({
        "learned_at": 35_u64,
        "record": retire_via_update_record
    });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&retire_via_update),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.lifecycle")
    );

    let retire_path = format!("/v1/companion/register/records/{personal_id}/retire");
    let retire_request = json!({ "retired_at": 36_u64 });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &retire_path,
            "companion:register:write",
            Some(&retire_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["lifecycle"], Value::from("retracted"));

    let reactivate_request = json!({
        "learned_at": 37_u64,
        "record": {
            "kind": "persona",
            "scope": { "kind": "personal", "person_ref": person_ref },
            "subject": { "kind": "persona", "persona_ref": persona_ref },
            "value": { "note": "reactivated private note" },
            "provenance": body["record"]["provenance"].clone(),
            "export": "local_only"
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&reactivate_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");

    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_0009).to_hex(),
                "record": neutral_record
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_envelope(&body, "INVALID_STATE");
    assert_eq!(
        error_envelope(&body)["details"]["state"],
        Value::from("companion_record_exists")
    );

    let ending_id = seeded_test_entity_id(0x1219_0011).to_hex();
    let ending_private_note = "route-private-relationship-note-one1488";
    let ending_record = json!({
        "kind": "relationship",
        "scope": { "kind": "personal", "person_ref": person_ref },
        "subject": {
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": person_ref,
                "target_ref": persona_ref
            }
        },
        "value": { "note": ending_private_note },
        "provenance": provenance.clone(),
        "export": "local_only"
    });
    let (status, _body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": ending_id,
                "learned_at": 38_u64,
                "record": ending_record.clone()
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let general_id = seeded_test_entity_id(0x1219_0013);
    server
        .vault
        .batch()
        .put(
            &general_id,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 38, end: 38 },
            38,
            b"route-general-vault-data",
        )
        .commit()
        .expect("seed general vault data");

    let end_path = format!("/v1/companion/register/records/{ending_id}/end-relationship");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &end_path,
            "companion:register:write",
            Some(&json!({
                "ended_at": 39_u64,
                "ended_badly": false,
                "run_id": "route-goodbye-one1488"
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["lifecycle"], Value::from("retracted"));
    assert_eq!(
        body["record"]["value"]["kind"],
        Value::from("relationship_ended")
    );
    assert_eq!(
        body["record"]["value"]["private_memory"],
        Value::from("removed")
    );
    assert!(
        !body["record"]["value"]
            .to_string()
            .contains(ending_private_note),
        "ended relationship response must not retain private memory"
    );
    assert_eq!(
        server
            .vault
            .get(&general_id)
            .expect("read general data")
            .as_deref(),
        Some(b"route-general-vault-data".as_slice())
    );
    assert_eq!(body["goodbye_artifact"]["status"], Value::from("enqueued"));
    assert_eq!(
        body["goodbye_artifact"]["task"],
        Value::from("goodbye_artifact")
    );
    assert_eq!(
        body["goodbye_artifact"]["run_id"],
        Value::from("route-goodbye-one1488")
    );
    assert_eq!(
        body["goodbye_artifact"]["job_id"]
            .as_str()
            .expect("attempt id")
            .len(),
        32
    );
    let claimed = oneiron::companion::CompanionQueue::new(server.vault.as_ref())
        .claim(oneiron::companion::ClaimCompanionTask {
            lease_owner: "route-goodbye-worker".to_owned(),
            now: 40,
        })
        .expect("claim goodbye artifact task");
    let oneiron::companion::ClaimCompanionTaskOutcome::Claimed(claimed) = claimed else {
        panic!("amicable route ending must enqueue a claimable goodbye task");
    };
    assert_eq!(
        claimed.task.kind,
        oneiron::CompanionTaskKind::GoodbyeArtifact
    );
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &end_path,
            "companion:register:write",
            Some(&json!({
                "ended_at": 41_u64,
                "run_id": "route-goodbye-retry-one1488"
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["goodbye_artifact"]["status"],
        Value::from("already_ended")
    );
    assert!(body["goodbye_artifact"]["job_id"].is_null());
    assert!(
        !body["record"]["value"]
            .to_string()
            .contains(ending_private_note),
        "idempotent route ending must keep private memory scrubbed"
    );

    let bad_end_id = seeded_test_entity_id(0x1219_0012).to_hex();
    let mut bad_end_record = ending_record;
    bad_end_record["subject"]["relationship_ref"]["source_ref"] = Value::from(source_ref);
    bad_end_record["subject"]["relationship_ref"]["target_ref"] = Value::from(target_ref);
    bad_end_record["value"] = json!({ "note": "route-bad-end-private-note-one1488" });
    let (status, _body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": bad_end_id,
                "learned_at": 41_u64,
                "record": bad_end_record
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bad_end_path = format!("/v1/companion/register/records/{bad_end_id}/end-relationship");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &bad_end_path,
            "companion:register:write",
            Some(&json!({
                "ended_at": 42_u64,
                "ended_badly": true,
                "run_id": "route-bad-end-one1488"
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["goodbye_artifact"]["status"],
        Value::from("skipped_bad_end")
    );
    assert!(body["goodbye_artifact"]["job_id"].is_null());
    assert_eq!(
        oneiron::companion::CompanionQueue::new(server.vault.as_ref())
            .claim(oneiron::companion::ClaimCompanionTask {
                lease_owner: "route-goodbye-worker".to_owned(),
                now: 43,
            })
            .expect("bad end should not enqueue another task"),
        oneiron::companion::ClaimCompanionTaskOutcome::Empty
    );

    assert!(
        server
            .vault
            .get_companion_record(
                &oneiron::EntityId::from_hex(&shared_id).expect("shared record id")
            )
            .expect("read shared record")
            .is_some()
    );
}
