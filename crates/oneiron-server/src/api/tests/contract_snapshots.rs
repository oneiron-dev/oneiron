//! v1 core OpenAPI/success/error contract fixture snapshots plus generated-OpenAPI spec assertions.

use super::*;

#[test]
fn v1_core_openapi_documents_invalid_state_envelopes() {
    let spec = generated_spec();
    let turn_create_post_responses =
        spec["paths"]["/v1/core/conversations/{conversation_id}/turns"]["post"]["responses"]
            .as_object()
            .expect("turn create POST responses object");
    assert!(
        turn_create_post_responses.contains_key("409"),
        "turn create POST must document INVALID_STATE conflict responses"
    );
    assert_eq!(
        turn_create_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
        Value::from("#/components/schemas/ApiErrorEnvelope"),
        "turn create 409 must use the ApiErrorEnvelope schema"
    );

    let turn_annotate_post_responses =
        spec["paths"]["/v1/core/turns/annotate"]["post"]["responses"]
            .as_object()
            .expect("turn annotate POST responses object");
    assert!(
        turn_annotate_post_responses.contains_key("409"),
        "turn annotate POST must document Gate INVALID_STATE conflict responses"
    );
    assert_eq!(
        turn_annotate_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
        Value::from("#/components/schemas/ApiErrorEnvelope"),
        "turn annotate 409 must use the ApiErrorEnvelope schema"
    );
}

#[tokio::test]
async fn v1_core_success_contract_snapshot_matches_fixture() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let batch_id = seeded_test_entity_id(0x1221_0001).to_hex();
    let conversation_id = seeded_test_entity_id(0x1221_0002).to_hex();
    let turn_id = seeded_test_entity_id(0x1221_0003).to_hex();
    let board_principal_ref = seeded_test_entity_id(0x1221_0004).to_hex();
    let board_person_ref = seeded_test_entity_id(0x1221_0005).to_hex();
    let board_persona_ref = seeded_test_entity_id(0x1221_0006).to_hex();
    let mut exchanges = Vec::new();

    let batch_request = json!({
        "entities": [{
            "id": batch_id,
            "entity_type": ENTITY_TYPE_TURN,
            "occurred_start": 1_782_357_600_u64,
            "occurred_end": 1_782_357_600_u64,
            "learned_at": 1_782_357_635_u64,
            "body": {
                "txt": "blue hallway contractneedle",
                "spkr": "user",
                "at": 1_782_357_600_u64
            },
            "text": [{ "field": "body", "value": "blue hallway contractneedle" }]
        }]
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/batch",
        "core:write",
        Some(&batch_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "core_batch",
        "POST",
        "/v1/core/batch",
        Some("core:write"),
        Some(batch_request),
        status,
        body,
    ));

    let query_request = json!({
        "query": "contractneedle",
        "limit": 3,
        "view": "full",
        "countMode": "estimate"
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/query",
        "core:read",
        Some(&query_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "core_query",
        "POST",
        "/v1/core/query",
        Some("core:read"),
        Some(query_request),
        status,
        body,
    ));

    let context_pack_request = json!({
        "query": "contractneedle",
        "limit": 3,
        "view": "full",
        "include_edges": false
    });
    // Owner-grade: this exchange documents the un-clamped context-pack shape,
    // so it must travel on the credential that reaches it. On a scoped bearer
    // the same request is disclosure-clamped and returns no results.
    let (status, context_pack_body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&context_pack_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let context_entity = &context_pack_body["results"][0];
    let short_ref = format!(
        "{}:{}",
        context_entity["short_id"].as_str().expect("short id"),
        context_entity["content_hash"]
            .as_str()
            .expect("content hash")
    );
    exchanges.push(contract_exchange_with_auth(
        "core_context_pack",
        "POST",
        "/v1/core/context-pack",
        json!({ "type": "bearer", "grade": "owner" }),
        Some(context_pack_request),
        status,
        context_pack_body,
    ));

    let context_board_request = json!({
        "retrieval": {
            "query": "contractneedle",
            "limit": 3,
            "view": "full",
            "include_edges": false
        },
        "memories": {
            "slots": {
                "claims": 0,
                "turns": 1,
                "summaries": 0,
                "facets": 0,
                "companions": 0,
                "other": 0
            }
        },
        "session": {},
        "companion": {
            "person_ref": board_person_ref,
            "persona_ref": board_persona_ref
        }
    });
    let (status, context_board_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &board_principal_ref,
            Some(&context_board_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        context_board_body["session"]["api_version"],
        Value::from("v1")
    );
    assert_eq!(
        context_board_body["memories"]["budget"]["turns"],
        Value::from(1)
    );
    assert_eq!(context_board_body["cursor"]["query_count"], Value::from(1));
    assert!(
        context_board_body["pack"]["results"].is_array(),
        "the retrieval pack rides the board response"
    );
    exchanges.push(contract_exchange_with_auth(
        "core_context_board",
        "POST",
        "/v1/core/context-board",
        json!({ "type": "bearer", "scope": "core:read", "principal_ref": "bound" }),
        Some(context_board_request),
        status,
        context_board_body,
    ));

    let hydrate_request = json!({
        "ref": short_ref,
        "view": "full"
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&hydrate_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "core_hydrate",
        "POST",
        "/v1/core/hydrate",
        Some("core:read"),
        Some(hydrate_request),
        status,
        body,
    ));

    let conversation_request = json!({
        "id": conversation_id,
        "occurred_start": 1_782_357_700_u64,
        "occurred_end": 1_782_357_700_u64,
        "learned_at": 1_782_357_735_u64,
        "body": { "name": "Contract dream" },
        "text": [{ "field": "name", "value": "Contract dream" }]
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/conversations",
        "core:write",
        Some(&conversation_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "create_core_conversation",
        "POST",
        "/v1/core/conversations",
        Some("core:write"),
        Some(conversation_request),
        status,
        body,
    ));

    let conversations_path = "/v1/core/conversations?view=full&limit=5&countMode=exact";
    let (status, mut body) =
        core_json(server.clone(), "GET", conversations_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    let root_id = server.vault.root_project().expect("root project");
    let root = server
        .vault
        .project(root_id)
        .expect("read root")
        .expect("root exists");
    let items = body["items"].as_array_mut().expect("conversation items");
    // Rows come in id order. The derived home-room id falls on either side of
    // the fixture conversation's, so hold the order here and snapshot the
    // per-vault room last.
    assert!(
        items
            .windows(2)
            .all(|pair| pair[0]["id"].as_str() < pair[1]["id"].as_str())
    );
    let at = items
        .iter()
        .position(|row| row["id"].as_str() == Some(root.home_room.as_str()))
        .expect("house room is projected");
    let mut home = items.remove(at);
    assert_eq!(home["project_id"], json!(root_id.to_hex()));
    assert_eq!(home["memberIds"], json!(root.roster));
    assert_eq!(home["claims_scope_ref"], json!(root.claims_scope_ref));
    // Only the per-vault identities vary. Keep all projected fields in the snapshot.
    home["id"] = json!("<home-room-id>");
    home["label"] = json!("<home-room-id>");
    home["project_id"] = json!("<root-project-id>");
    home["claims_scope_ref"] = json!("<root-project-id>");
    items.push(home);
    exchanges.push(contract_exchange(
        "list_core_conversations",
        "GET",
        conversations_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let turn_request = json!({
        "id": turn_id,
        "occurred_start": 1_782_357_800_u64,
        "occurred_end": 1_782_357_800_u64,
        "learned_at": 1_782_357_835_u64,
        "body": {
            "txt": "turn contract envelope",
            "spkr": "assistant",
            "at": 1_782_357_800_u64
        },
        "text": [{ "field": "body", "value": "turn contract envelope" }]
    });
    let turns_path = format!("/v1/core/conversations/{conversation_id}/turns");
    let (status, body) = core_json(
        server.clone(),
        "POST",
        &turns_path,
        "core:write",
        Some(&turn_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "create_core_conversation_turn",
        "POST",
        &turns_path,
        Some("core:write"),
        Some(turn_request),
        status,
        body,
    ));

    let list_turns_path =
        format!("/v1/core/conversations/{conversation_id}/turns?view=full&limit=5");
    let (status, body) =
        core_json(server.clone(), "GET", &list_turns_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "list_core_conversation_turns",
        "GET",
        &list_turns_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let get_turn_path = format!("/v1/core/turns/{turn_id}?view=full");
    let (status, body) = core_json(server.clone(), "GET", &get_turn_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "get_core_turn",
        "GET",
        &get_turn_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let annotate_request = json!({
        "turn_id": turn_id,
        "source": "model_inference",
        "vad": {
            "valence": 0.25,
            "arousal": 0.5,
            "dominance": 0.75
        },
        "annotated_at": 1_782_357_900_u64
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/turns/annotate",
        "core:write",
        Some(&annotate_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "annotate_turn_vad",
        "POST",
        "/v1/core/turns/annotate",
        Some("core:write"),
        Some(annotate_request),
        status,
        body,
    ));

    let read_annotation_path = format!("/v1/core/turns/annotate?turn_id={turn_id}");
    let (status, body) = core_json(server, "GET", &read_annotation_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "read_turn_vad_annotation",
        "GET",
        &read_annotation_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    assert_json_snapshot(
        Value::Array(exchanges),
        &retrieval_quality_success_snapshot(),
        V1_CORE_SUCCESS_CONTRACT_SNAPSHOT_PATH,
        "v1 core success contract",
    );
}

#[tokio::test]
async fn core_memory_timeline_receipt_covers_absent_and_live_results() {
    let (_dir, server) = auth_test_server();
    let (status, body) = owner_json(
        server.clone(),
        "GET",
        "/v1/core/memory/03030303030303030303030303030303/timeline",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["narrowing"]["suppressed_count"], 0);
    assert!(body["narrowing"]["applied"].is_object());

    let id = oneiron::EntityId::from_bytes([3; 16]).expect("id");
    let payload = rmp_serde::to_vec_named(&json!({"txt": "timeline row"})).unwrap();
    server
        .vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &payload,
        )
        .unwrap();
    let (status, body) = owner_json(
        server,
        "GET",
        "/v1/core/memory/03030303030303030303030303030303/timeline?view=full",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["narrowing"]["suppressed_count"], 0);
    assert_eq!(body["narrowing"]["narrowed_axes"], json!([]));
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["item"]["txt"], "timeline row");
}
