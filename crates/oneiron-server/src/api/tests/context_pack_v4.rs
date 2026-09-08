//! Context-board memories/cursor/companion/assets, session scoping, evidence run-id omission.

use super::*;

#[tokio::test]
async fn context_board_memories_enforces_slots_and_carries_cursor() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_id = seeded_test_entity_id(0x1741_0001);
    let principal_ref = principal_id.to_hex();
    let turn_a = seeded_test_entity_id(0x0012_6301);
    let turn_b = seeded_test_entity_id(0x0012_6302);
    let summary = seeded_test_entity_id(0x0012_6303);
    let body_a = rmp_serde::to_vec_named(&json!({
        "txt": "eiri v4 needle alpha",
        "spkr": "user",
        "at": 700_u64
    }))
    .expect("encode turn body");
    let body_b = rmp_serde::to_vec_named(&json!({
        "txt": "eiri v4 needle beta",
        "spkr": "assistant",
        "at": 701_u64
    }))
    .expect("encode turn body");
    let summary_body = rmp_serde::to_vec_named(&json!({
        "txt": "eiri v4 needle summary"
    }))
    .expect("encode summary body");

    server
        .vault
        .batch()
        .put(
            &turn_a,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 700,
                end: 700,
            },
            700,
            &body_a,
        )
        .text(&turn_a, &[("body", "eiri v4 needle alpha")])
        .put(
            &turn_b,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 701,
                end: 701,
            },
            701,
            &body_b,
        )
        .text(&turn_b, &[("body", "eiri v4 needle beta")])
        .put(
            &summary,
            oneiron::registry::ENTITY_TYPE_SUMMARY,
            oneiron::TimeRange {
                start: 702,
                end: 702,
            },
            702,
            &summary_body,
        )
        .text(&summary, &[("body", "eiri v4 needle summary")])
        .commit()
        .expect("seed context v4 rows");
    // Principal-scoped v1 context packs assemble under AbsenceClamp, so the
    // ported caller is a known contact whose disclosure scope contains the
    // rows exercised by this memory-board contract.
    seed_counterparty_contact(
        &server,
        principal_id,
        seeded_test_entity_id(0x1741_0005),
        "eiri-session-api@example.com",
    );
    seed_disclosure_scope(&server, principal_id, vec![turn_a, turn_b, summary]);

    let persona_ref = seeded_test_entity_id(0x1324_0001).to_hex();
    let request = json!({
        "retrieval": { "query": "eiri v4 needle", "limit": 10 },
        "memories": {
            "slots": {
                "claims": 0,
                "turns": 1,
                "summaries": 1,
                "facets": 0,
                "companions": 0,
                "other": 0
            }
        },
        "session": { "session_id": principal_ref.clone() },
        "companion": { "persona_ref": persona_ref.clone() }
    });

    let board_request = || {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref,
            Some(&request),
        )
    };

    let (status, first_body) = route_json(server.clone(), board_request()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first_body["memories"]["version"], Value::from("v4"));
    assert_eq!(first_body["memories"]["budget"]["turns"], Value::from(1));
    assert_eq!(
        first_body["memories"]["budget"]["summaries"],
        Value::from(1)
    );
    let rows = first_body["memories"]["rows"]
        .as_array()
        .expect("memory board rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["row_index"], Value::from(0));
    assert_eq!(rows[0]["slot"], Value::from("turns"));
    assert_eq!(rows[1]["row_index"], Value::from(1));
    assert_eq!(rows[1]["slot"], Value::from("summaries"));
    assert_eq!(
        first_body["memories"]["companion"]["caller"],
        Value::from(principal_ref.clone())
    );
    assert_eq!(
        first_body["memories"]["companion"]["persona_ref"],
        Value::from(persona_ref)
    );
    assert_eq!(
        first_body["memories"]["companion"]["scope"],
        Value::from("neutral")
    );
    assert_eq!(
        first_body["memories"]["companion"]["scope_source"],
        Value::from("neutral_default")
    );
    assert_eq!(
        first_body["memories"]["companion"]["expression"],
        Value::from("professional")
    );
    assert_eq!(
        first_body["cursor"]["session_id"],
        Value::from(principal_ref.clone())
    );
    assert_eq!(first_body["cursor"]["revision"], Value::from(1));
    assert_eq!(first_body["cursor"]["query_count"], Value::from(1));
    assert!(
        first_body["cursor"]["last_retrieval_run_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(
        first_body["cursor"]["last_result_ids"]
            .as_array()
            .map(Vec::len),
        first_body["pack"]["results"].as_array().map(Vec::len)
    );

    let (status, second_body) = route_json(server.clone(), board_request()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second_body["cursor"]["revision"], Value::from(2));
    assert_eq!(second_body["cursor"]["query_count"], Value::from(2));

    let hydrate_request = core_request_with_principal_ref(
        "POST",
        "/v1/core/context-board",
        "core:read",
        &principal_ref,
        Some(&json!({})),
    );
    let (status, hydrate_body) = route_json(server, hydrate_request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hydrate_body["cursor"]["session_id"],
        Value::from(principal_ref)
    );
    assert_eq!(hydrate_body["cursor"]["query_count"], Value::from(2));
}

#[tokio::test]
async fn context_board_asset_text_consumer_hydrates_asset_text_by_ref() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let asset_text = seeded_test_entity_id(0x1482_0001);
    // ONE-1517: principal_ref tokens assemble under AbsenceClamp, so the
    // consumer principal is a known contact whose disclosure scope
    // allowlists the ASSET_TEXT entity — the intended scoped-read shape.
    let principal_contact = seeded_test_entity_id(0x1482_0002);
    let principal_ref = principal_contact.to_hex();
    seed_counterparty_contact(
        &server,
        principal_contact,
        seeded_test_entity_id(0x1482_0003),
        "asset-consumer@example.com",
    );
    let needle = "one1482 text-only asset transcript";
    let body = rmp_serde::to_vec_named(&json!({
        "txt": needle,
        "source_asset_ref": "asset-source-one1482"
    }))
    .expect("encode ASSET_TEXT body");
    server
        .vault
        .batch()
        .put(
            &asset_text,
            oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
            oneiron::TimeRange {
                start: 1482,
                end: 1482,
            },
            1482,
            &body,
        )
        .text(&asset_text, &[("body", needle)])
        .commit()
        .expect("seed ASSET_TEXT");
    seed_disclosure_scope(&server, principal_contact, vec![asset_text]);

    let request = json!({
        "retrieval": { "query": needle, "limit": 3, "view": "full" },
        "memories": {
            "slots": {
                "claims": 0,
                "turns": 0,
                "summaries": 0,
                "facets": 0,
                "companions": 0,
                "other": 1
            }
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row = &body["memories"]["rows"][0];
    assert_eq!(
        row["entity_type"],
        Value::from(oneiron::registry::ENTITY_TYPE_ASSET_TEXT)
    );
    let asset_ref = row["asset_ref"]
        .as_str()
        .expect("ASSET_TEXT row exposes a core hydrate ref");

    let hydrate_request = json!({
        "ref": asset_ref,
        "view": "full"
    });
    let (status, hydrated) = core_json(
        server,
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&hydrate_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hydrated["status"], Value::from("live"));
    assert_eq!(
        hydrated["entity_type"],
        Value::from(oneiron::registry::ENTITY_TYPE_ASSET_TEXT)
    );
    assert_eq!(hydrated["item"]["txt"], Value::from(needle));
}

#[tokio::test]
async fn context_board_companion_resolves_warm_personal_relationship_without_private_note() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let private_note = "private warm companion note one1266";
    let person_ref = seeded_test_entity_id(0x1266_0001);
    let persona_ref = seeded_test_entity_id(0x1266_0002);
    let companion_id = seeded_test_entity_id(0x1266_0003);
    let turn_id = seeded_test_entity_id(0x1266_0004);
    let actor_ref = seeded_test_entity_id(0x1266_0005);
    let principal_ref = seeded_test_entity_id(0x1266_0006);
    let grant_id = seeded_test_entity_id(0x1266_0007);

    let record = oneiron::CompanionRecord::relationship(
        oneiron::CompanionScope::personal(person_ref),
        person_ref,
        persona_ref,
        oneiron::companion_value_from_json(&json!({ "note": private_note }))
            .expect("companion value"),
        oneiron::CompanionProvenance::new(
            actor_ref,
            oneiron::EdgeActorClass::Agent,
            oneiron::ClaimSource::UserStated,
            oneiron::ClaimApprovalStatus::Approved,
            oneiron::companion_value_from_json(&json!({ "source": "test" }))
                .expect("provenance value"),
        ),
        oneiron::CompanionExportClassification::LocalOnly,
    );
    server
        .vault
        .create_companion_record(&companion_id, &record, 10)
        .expect("create companion record");
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

    let grant =
        oneiron::AccessGrant::companion_profile_read(principal_ref, person_ref, persona_ref, 12);
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
    assert_eq!(
        companion["scope_source"],
        Value::from("relationship_record")
    );
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

#[test]
fn memories_budget_default_other_matches_retrieval_budget() {
    let limit = 24;
    let selected_edges = 8;
    let retrieval_defaults = oneiron::ContextPackRetrievalBudget::from_limit(
        limit,
        oneiron::TokenAllocation::default(),
        selected_edges,
    );

    let defaults = memories_budget(None, limit, selected_edges);
    assert_eq!(defaults.companions, 0);
    assert_eq!(defaults.other, retrieval_defaults.other);
    assert_eq!(
        defaults.companions + defaults.other,
        retrieval_defaults.other
    );

    let split = memories_budget(
        Some(&ContextBoardMemoriesControls {
            enabled: None,
            slots: Some(ContextBoardMemoriesSlotControls {
                companions: Some(2),
                ..Default::default()
            }),
        }),
        limit,
        selected_edges,
    );
    assert_eq!(split.companions, 2);
    assert_eq!(split.other, retrieval_defaults.other.saturating_sub(2));
}

#[test]
fn memories_cursor_store_evicts_oldest_entries_at_capacity() {
    let mut store = MemoriesCursorStore::default();
    for index in 0..=MEMORIES_CURSOR_MAX_ENTRIES {
        let key = format!("vault:{index}");
        let session_id = format!("session-{index}");
        store.current(key, &session_id);
    }

    assert_eq!(store.entries.len(), MEMORIES_CURSOR_MAX_ENTRIES);
    assert!(!store.entries.contains_key("vault:0"));
    assert!(
        store
            .entries
            .contains_key(&format!("vault:{MEMORIES_CURSOR_MAX_ENTRIES}"))
    );
}

#[test]
fn memories_cursor_store_caps_persisted_result_ids() {
    let mut store = MemoriesCursorStore::default();
    let pack = synthetic_context_pack(MEMORIES_CURSOR_LAST_RESULT_IDS_MAX + 5);
    let evidence = CoreContextPackEvidence {
        telemetry_persisted: false,
        retrieval_run_id: Some("test-run".to_owned()),
        result_ids: Vec::new(),
        scores: Vec::new(),
    };

    let state = store.advance(
        "vault:caller".to_owned(),
        "vault:caller:session".to_owned(),
        "session",
        &pack,
        &evidence,
    );

    assert_eq!(
        state.last_result_ids.len(),
        MEMORIES_CURSOR_LAST_RESULT_IDS_MAX
    );
    assert_eq!(state.last_result_ids[0], pack.results[0].id.to_hex());
    assert_eq!(
        state.last_result_ids[MEMORIES_CURSOR_LAST_RESULT_IDS_MAX - 1],
        pack.results[MEMORIES_CURSOR_LAST_RESULT_IDS_MAX - 1]
            .id
            .to_hex()
    );
}

#[tokio::test]
async fn context_board_rejects_oversized_session_id() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_ref = seeded_test_entity_id(0x1741_0002).to_hex();
    let request = json!({
        "retrieval": { "query": "eiri v4 needle" },
        "session": {
            "session_id": "x".repeat(MEMORIES_CURSOR_SESSION_ID_MAX_BYTES + 1)
        }
    });

    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("session.session_id")
    );
}

#[tokio::test]
async fn context_board_rejects_shared_principal_session_scope() {
    let (_dir, server) = test_server();
    let request = json!({
        "retrieval": { "query": "eiri v4 needle" },
        "session": { "session_id": "explicit-session" }
    });

    let (status, body) = route_json(
        server,
        json_request("POST", "/v1/core/context-board", request),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("session.session_id")
    );
}

#[tokio::test]
async fn context_board_cursor_is_partitioned_by_caller() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let caller_a = seeded_test_entity_id(0x1741_0003).to_hex();
    let caller_b = seeded_test_entity_id(0x1741_0004).to_hex();
    let request = json!({
        "retrieval": { "query": "eiri v4 partition needle" },
        "session": { "session_id": "shared-session-name" }
    });

    let board_request = |caller: &str| {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            caller,
            Some(&request),
        )
    };

    let (status, caller_a_first) = route_json(server.clone(), board_request(&caller_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_a_first["memories"]["companion"]["caller"],
        Value::from("shared-session-name")
    );
    assert_eq!(
        caller_a_first["cursor"]["session_id"],
        Value::from("shared-session-name")
    );
    assert_eq!(caller_a_first["cursor"]["query_count"], Value::from(1));

    let (status, caller_a_second) = route_json(server.clone(), board_request(&caller_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caller_a_second["cursor"]["query_count"], Value::from(2));

    let (status, caller_b_first) = route_json(server.clone(), board_request(&caller_b)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caller_b_first["cursor"]["query_count"], Value::from(1));

    let empty = json!({});
    let hydrate_request = |caller: &str| {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            caller,
            Some(&empty),
        )
    };

    let (status, caller_a_board) = route_json(server.clone(), hydrate_request(&caller_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_a_board["cursor"]["session_id"],
        Value::from("shared-session-name")
    );
    assert_eq!(caller_a_board["cursor"]["query_count"], Value::from(2));

    let (status, caller_b_board) = route_json(server, hydrate_request(&caller_b)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_b_board["cursor"]["session_id"],
        Value::from("shared-session-name")
    );
    assert_eq!(caller_b_board["cursor"]["query_count"], Value::from(1));
}

#[test]
fn context_pack_evidence_omits_run_id_without_finalized_telemetry() {
    let (_dir, server) = test_server();
    let evidence = core_context_pack_evidence(&server.vault, Some(oneiron::RetrievalRunId::now()))
        .expect("context-pack evidence");

    assert!(!evidence.telemetry_persisted);
    assert_eq!(evidence.retrieval_run_id, None);
    assert!(evidence.result_ids.is_empty());
    assert!(evidence.scores.is_empty());
}
