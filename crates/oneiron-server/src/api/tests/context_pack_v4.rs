//! Context-board memories/cursor/companion/assets, session scoping, evidence run-id omission.

use super::*;

#[tokio::test]
async fn context_board_companion_resolves_warm_personal_relationship_without_private_note() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let private_note = "private identity note one1266";
    let person_ref = seeded_test_entity_id(0x1266_0001);
    let persona_ref = seeded_test_entity_id(0x1266_0002);
    let turn_id = seeded_test_entity_id(0x1266_0004);
    let principal_ref = seeded_test_entity_id(0x1266_0006);
    let grant_id = seeded_test_entity_id(0x1266_0007);

    for id in [person_ref, persona_ref] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 9, end: 9 },
                9,
                &rmp_serde::to_vec_named(&json!({ "private_note": private_note }))
                    .expect("encode PERSON identity"),
            )
            .expect("create PERSON identity");
    }
    let turn_body = json!({ "txt": "warm companion route needle" });
    let turn_data = rmp_serde::to_vec_named(&turn_body).expect("encode turn body");
    server
        .vault
        .batch()
        .put(
            &turn_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 11, end: 11 },
            11,
            &turn_data,
        )
        .text(&turn_id, &[("body", "warm companion route needle")])
        .commit()
        .expect("seed turn");

    let core_request_body = json!({
        "retrieval": { "query": "warm companion route needle" },
        "memories": { "slots": { "turns": 1, "companions": 0, "other": 0 } },
        "companion": {
            "person_ref": person_ref.to_hex(),
            "persona_ref": persona_ref.to_hex(),
            "expression": "warm"
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref.to_hex(),
            Some(&core_request_body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let companion = &body["memories"]["companion"];
    assert_eq!(companion["scope"], Value::from("neutral"));
    assert_eq!(companion["scope_source"], Value::from("neutral_default"));
    assert_eq!(companion["expression"], Value::from("warm"));
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "unauthorized context board must not leak companion relationship metadata"
    );

    let grant = oneiron::AccessGrant::companion_profile_read(
        principal_ref,
        person_ref,
        Some(persona_ref),
        12,
    );
    server
        .vault
        .create_access_grant(&grant_id, &grant)
        .expect("create profile grant");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref.to_hex(),
            Some(&core_request_body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let companion = &body["memories"]["companion"];
    assert_eq!(companion["scope"], Value::from("personal"));
    assert_eq!(companion["scope_source"], Value::from("person_identity"));
    assert_eq!(companion["expression"], Value::from("warm"));
    assert_eq!(companion["person_ref"], Value::from(person_ref.to_hex()));
    assert_eq!(companion["persona_ref"], Value::from(persona_ref.to_hex()));
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "authorized context board must not leak private register notes"
    );

    let invalid_request = json!({
        "retrieval": { "query": "warm companion route needle" },
        "companion": {
            "person_ref": person_ref.to_hex(),
            "persona_ref": persona_ref.to_hex(),
            "expression": "future_closed"
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref.to_hex(),
            Some(&invalid_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("companion.expression")
    );
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "invalid companion request must not leak private register notes"
    );

    let opaque_request = json!({
        "retrieval": { "query": "warm companion route needle" },
        "companion": {
            "person_ref": "opaque-person-ref",
            "persona_ref": "persona-route-test",
            "expression": "warm"
        }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref.to_hex(),
            Some(&opaque_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let companion = &body["memories"]["companion"];
    assert_eq!(companion["scope"], Value::from("neutral"));
    assert_eq!(companion["scope_source"], Value::from("neutral_default"));
    assert_eq!(companion["expression"], Value::from("warm"));
    assert_eq!(companion["person_ref"], Value::from("opaque-person-ref"));
    assert_eq!(companion["persona_ref"], Value::from("persona-route-test"));
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "opaque companion refs must not leak private register notes"
    );
}

#[tokio::test]
async fn context_board_feeds_explicit_subjects_to_the_l2_producer() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x236_0001);
    let person = seeded_test_entity_id(0x236_0002);
    let persona = seeded_test_entity_id(0x236_0003);
    let user_claim = seeded_test_entity_id(0x236_0004);
    let persona_claim = seeded_test_entity_id(0x236_0005);
    let turn = seeded_test_entity_id(0x236_0006);
    for subject in [person, persona] {
        server
            .vault
            .put_entity(
                &subject,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"subject",
            )
            .unwrap();
    }
    // Deliberately not text-indexed: L2 must not depend on ranked query hits.
    for (id, subject, text) in [
        (user_claim, person, "user base fact"),
        (persona_claim, persona, "persona base fact"),
    ] {
        let mut body = oneiron::ClaimBody::new(
            "profile.route_test",
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            0.9,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from("public"),
        )]));
        server
            .vault
            .put_claim(&id, &body, oneiron::TimeRange { start: 1, end: 1 }, 1)
            .unwrap();
    }
    for (claim, subject) in [(user_claim, person), (persona_claim, persona)] {
        server
            .vault
            .put_edge(&claim, oneiron::EdgeKind::ClaimOf, &subject, 1.0)
            .unwrap();
    }
    let raw = rmp_serde::to_vec_named(&json!({"txt":"l2route delta"})).unwrap();
    server
        .vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &raw,
        )
        .text(&turn, &[("body", "l2route")])
        .commit()
        .unwrap();
    seed_counterparty_contact(
        &server,
        principal,
        seeded_test_entity_id(0x236_0007),
        "l2@example.com",
    );
    seed_disclosure_scope(&server, principal, oneiron::federation::Scope::top());
    let request = json!({
        "session":{"session_id":"l2-observed"},
        "retrieval": {"query":"l2route", "budget":{"max_field_chars":0,"max_item_tokens":0,"token_budget":0}},
        "companion":{"person_ref":person.to_hex(),"persona_ref":persona.to_hex()}
    });
    let call = || {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal.to_hex(),
            Some(&request),
        )
    };
    let (status, first) = route_json(server.clone(), call()).await;
    assert_eq!(status, StatusCode::OK);
    let prefix: Value = serde_json::from_str(
        first["pack"]["l2_base"]["body"]
            .as_str()
            .unwrap_or_else(|| panic!("missing L2 prefix: {first:?}")),
    )
    .unwrap();
    assert_eq!(prefix.as_array().unwrap().len(), 2);
    assert_eq!(first["pack"]["results"][0]["id"], turn.to_hex());
    let (status, second) = route_json(server.clone(), call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["pack"]["l2_base"], second["pack"]["l2_base"]);
    // A computed prefix shed by the response budget was never served.
    let mut shed_request = request.clone();
    shed_request["session"]["session_id"] = json!("l2-shed");
    shed_request["retrieval"]["budget"]["token_budget"] = json!(1);
    let (status, shed) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal.to_hex(),
            Some(&shed_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shed:#}");
    assert!(shed["pack"].get("l2_base").is_none());
    // Allowlisting never overrides an unstamped/private evidence tier. A
    // claim keeps its birth scope: re-putting it without the public scope is
    // refused, so the private belief is a new claim and the old one retires.
    let private = oneiron::ClaimBody::new(
        "profile.route_test",
        oneiron::ClaimSubject::Entity(person),
        rmpv::Value::from("now private"),
        0.9,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    assert!(matches!(
        server.vault.put_claim(
            &user_claim,
            &private,
            oneiron::TimeRange { start: 1, end: 1 },
            1
        ),
        Err(oneiron::Error::InvalidClaimBody(
            "record scope restamp refused"
        ))
    ));
    server.vault.retract_claim(&user_claim, 1).unwrap();
    let private_claim = seeded_test_entity_id(0x236_0008);
    seed_active_claim(&server, private_claim, person, "now private", 1);
    server
        .vault
        .put_edge(&private_claim, oneiron::EdgeKind::ClaimOf, &person, 1.0)
        .unwrap();
    let (status, third) = route_json(server.clone(), call()).await;
    assert_eq!(status, StatusCode::OK);
    let rows: Value =
        serde_json::from_str(third["pack"]["l2_base"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], persona_claim.to_hex());
    server.vault.retract_claim(&persona_claim, 3).unwrap();
    for (session, expected) in [
        (
            "l2-observed",
            json!([
                "changed[2:]{id,to}:",
                format!("{}: retracted", user_claim.to_hex()),
                format!("{}: retracted", persona_claim.to_hex())
            ]),
        ),
        ("l2-shed", json!([])),
        ("l2-unobserved", json!([])),
    ] {
        let (status, board) = route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-board",
                "core:read",
                &principal.to_hex(),
                Some(&json!({"session":{"session_id":session}})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{board:#}");
        assert_eq!(board["changed"], expected, "{session}");
    }
}

#[tokio::test]
async fn pinned_memories_bypass_query_scope_but_not_audience_disclosure() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x1742_0001);
    let pinned = seeded_test_entity_id(0x1742_0002);
    let contact = seeded_test_entity_id(0x1742_0003);
    let bytes = rmp_serde::to_vec_named(&json!({"name":"pin needle"})).unwrap();
    server
        .vault
        .batch()
        .put(
            &pinned,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &bytes,
        )
        .text(&pinned, &[("name", "pin needle")])
        .commit()
        .unwrap();
    let pack = server
        .vault
        .context_pack()
        .search_text("pin needle", 10)
        .run()
        .unwrap();
    let row = pack.results.iter().find(|row| row.id == pinned).unwrap();
    let reference = format!("{}:{:02x}", row.short_id, row.content_hash);
    seed_counterparty_contact(&server, principal, contact, "pin-reader@example.com");
    seed_disclosure_scope(&server, principal, oneiron::federation::Scope::default());
    let request = json!({
        "retrieval": {"query":"unrelated empty query", "limit":1},
        "memories": {"shared_total":0, "pinned_refs":[reference]},
        "session": {"session_id":principal.to_hex()}
    });
    let read = || {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal.to_hex(),
            Some(&request),
        )
    };
    let (status, denied) = route_json(server.clone(), read()).await;
    assert_eq!(status, StatusCode::OK, "{denied}");
    assert!(denied["memories"]["rows"].as_array().unwrap().is_empty());
    assert_eq!(denied["pack"]["pin_narrowing"][0]["suppressed_count"], 1);
    assert!(
        !denied["rendered_memories"]
            .as_str()
            .unwrap()
            .contains(&reference)
    );
    seed_disclosure_scope(&server, principal, oneiron::federation::Scope::top());
    let (status, allowed) = route_json(server, read()).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert!(allowed["pack"]["results"].as_array().unwrap().is_empty());
    assert_eq!(allowed["memories"]["rows"].as_array().unwrap().len(), 1);
    assert_eq!(allowed["memories"]["rows"][0]["tier"], "pinned");
    assert_eq!(allowed["pack"]["pin_narrowing"][0]["suppressed_count"], 0);
    assert!(
        allowed["rendered_memories"]
            .as_str()
            .unwrap()
            .contains(&format!("{reference} trust=unknown tier=PINNED"))
    );
}
