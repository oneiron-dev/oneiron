//! v1 core OpenAPI/success/error contract fixture snapshots plus generated-OpenAPI spec assertions.

use super::*;

#[test]
fn v1_core_openapi_contract_snapshot_matches_fixture() {
    let spec = generated_spec();
    let mut paths = Map::new();
    for &(path, method) in V1_CORE_OPENAPI_CONTRACT_OPERATIONS {
        paths
            .entry(path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("path item object")
            .insert(
                method.to_owned(),
                openapi_operation_contract(&spec["paths"][path][method]),
            );
    }

    let mut schemas = Map::new();
    for name in V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES {
        schemas.insert(
            (*name).to_owned(),
            openapi_schema_contract(openapi_component_schema(&spec, name)),
        );
    }

    assert_json_snapshot(
        json!({
            "paths": paths,
            "components": {
                "schemas": schemas,
                "securitySchemes": spec["components"]["securitySchemes"].clone(),
            },
        }),
        &retrieval_quality_openapi_snapshot(),
        V1_CORE_OPENAPI_CONTRACT_SNAPSHOT_PATH,
        "v1 core OpenAPI contract",
    );
}

#[test]
fn v1_core_openapi_contract_snapshots_referenced_schemas() {
    let spec = generated_spec();
    let mut references = BTreeSet::new();
    for &(path, method) in V1_CORE_OPENAPI_CONTRACT_OPERATIONS {
        collect_schema_refs(
            &openapi_operation_contract(&spec["paths"][path][method]),
            &mut references,
        );
    }
    for name in V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES {
        collect_schema_refs(
            &openapi_schema_contract(openapi_component_schema(&spec, name)),
            &mut references,
        );
    }

    let missing = references
        .into_iter()
        .filter(|name| !V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES.contains(&name.as_str()))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "OpenAPI contract references unsnapshotted schemas: {missing:?}"
    );
}

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

#[test]
fn v1_core_openapi_contract_preserves_nested_error_schema_fidelity() {
    let spec = generated_spec();
    let envelope = openapi_schema_contract(openapi_component_schema(&spec, "ApiErrorEnvelope"));
    assert!(
        envelope
            .pointer("/properties/error/properties/code/enum")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
        "ApiErrorEnvelope.error.code must snapshot the full ErrorCode enum: {envelope}"
    );
    assert!(
        envelope
            .pointer("/properties/error/properties/details/oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
        "ApiErrorEnvelope.error.details must snapshot all ApiErrorDetails variants: {envelope}"
    );

    let api_error = openapi_schema_contract(openapi_component_schema(&spec, "ApiError"));
    assert!(
        api_error
            .pointer("/properties/code/enum")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
        "ApiError.code must snapshot the full ErrorCode enum: {api_error}"
    );
    assert!(
        api_error
            .pointer("/properties/details/oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
        "ApiError.details must snapshot all ApiErrorDetails variants: {api_error}"
    );

    let api_error_details =
        openapi_schema_contract(openapi_component_schema(&spec, "ApiErrorDetails"));
    assert!(
        api_error_details
            .pointer("/oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
        "ApiErrorDetails must snapshot all error detail variants: {api_error_details}"
    );

    let error_code = openapi_schema_contract(openapi_component_schema(&spec, "ErrorCode"));
    assert!(
        error_code
            .pointer("/enum")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
        "ErrorCode must snapshot the full enum catalog: {error_code}"
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
    let eiri_principal_ref = seeded_test_entity_id(0x1221_0004).to_hex();
    let eiri_person_ref = seeded_test_entity_id(0x1221_0005).to_hex();
    let eiri_persona_ref = seeded_test_entity_id(0x1221_0006).to_hex();
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

    let context_pack_v4_request = json!({
        "query": "contractneedle",
        "limit": 3,
        "view": "full",
        "include_edges": false,
        "context_version": "v4",
        "memory_board": {
            "slots": {
                "claims": 0,
                "turns": 1,
                "summaries": 0,
                "facets": 0,
                "companions": 0,
                "other": 0
            }
        },
        "session_rag": {},
        "companion": {
            "person_ref": eiri_person_ref,
            "persona_ref": eiri_persona_ref
        }
    });
    let (status, context_pack_v4_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &eiri_principal_ref,
            Some(&context_pack_v4_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(context_pack_v4_body["context_version"], Value::from("v4"));
    assert_eq!(
        context_pack_v4_body["memory_board"]["budget"]["turns"],
        Value::from(1)
    );
    assert_eq!(
        context_pack_v4_body["session_rag"]["query_count"],
        Value::from(1)
    );
    exchanges.push(contract_exchange_with_auth(
        "core_context_pack_v4",
        "POST",
        "/v1/core/context-pack",
        json!({ "type": "bearer", "scope": "core:read", "principal_ref": "bound" }),
        Some(context_pack_v4_request),
        status,
        context_pack_v4_body,
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
    let (status, body) =
        core_json(server.clone(), "GET", conversations_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
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
async fn v1_core_error_contract_snapshot_matches_fixture() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let missing_id = seeded_test_entity_id(0x1221_00ff).to_hex();
    let deleted_id = seeded_test_entity_id(0x1221_dead);
    let deleted_body = rmp_serde::to_vec_named(&json!({
        "txt": "deleted contract turn",
        "spkr": "user",
        "at": 1_782_358_000_u64,
    }))
    .expect("encode deleted turn");
    server
        .vault
        .batch()
        .put(
            &deleted_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 1_782_358_000_u64,
                end: 1_782_358_000_u64,
            },
            1_782_358_000_u64,
            &deleted_body,
        )
        .text(&deleted_id, &[("body", "deleted contract turn")])
        .commit()
        .expect("seed deleted turn");
    let deleted_pack = server
        .vault
        .context_pack()
        .search_text("deleted contract turn", 1)
        .run()
        .expect("deleted context pack");
    let deleted_entity = deleted_pack
        .results
        .first()
        .expect("deleted entity has short ref");
    let deleted_ref = format!(
        "{}:{:02x}",
        deleted_entity.short_id, deleted_entity.content_hash
    );
    server
        .vault
        .delete_entity_with_reason(&deleted_id, oneiron::DeleteReason::UserDelete)
        .expect("delete seeded turn");

    let mut exchanges = Vec::new();

    let malformed_request = json!({ "ref": "bad-ref" });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&malformed_request),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    exchanges.push(contract_exchange(
        "malformed_request",
        "POST",
        "/v1/core/hydrate",
        Some("core:read"),
        Some(malformed_request),
        status,
        body,
    ));

    let missing_auth_path = "/v1/core/turns/annotate?turn_id=not-an-entity";
    let (status, body) = route_json(
        server.clone(),
        Request::builder()
            .uri(missing_auth_path)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");
    exchanges.push(contract_exchange(
        "missing_auth",
        "GET",
        missing_auth_path,
        None,
        None,
        status,
        body,
    ));

    let wrong_scope_path = "/v1/core/turns/annotate?turn_id=not-an-entity";
    let (status, body) =
        core_json(server.clone(), "GET", wrong_scope_path, "core:write", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    exchanges.push(contract_exchange(
        "wrong_scope",
        "GET",
        wrong_scope_path,
        Some("core:write"),
        None,
        status,
        body,
    ));

    let not_found_path = format!("/v1/core/turns/{missing_id}");
    let (status, body) = core_json(server.clone(), "GET", &not_found_path, "core:read", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_envelope(&body, "NOT_FOUND");
    exchanges.push(contract_exchange(
        "not_found",
        "GET",
        &not_found_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let deleted_request = json!({ "ref": deleted_ref });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&deleted_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], Value::from("deleted"));
    assert!(body.get("item").is_none());
    exchanges.push(contract_exchange(
        "deleted_entity",
        "POST",
        "/v1/core/hydrate",
        Some("core:read"),
        Some(deleted_request),
        status,
        body,
    ));

    assert_json_snapshot(
        Value::Array(exchanges),
        V1_CORE_ERROR_CONTRACT_SNAPSHOT,
        V1_CORE_ERROR_CONTRACT_SNAPSHOT_PATH,
        "v1 core error contract",
    );
}

#[test]
fn generated_openapi_has_descriptions_examples_and_defaults() {
    let spec = generated_spec();

    assert!(
        spec["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.1")),
        "OpenAPI version should start with 3.1: {:?}",
        spec["openapi"]
    );

    let paths = spec["paths"].as_object().expect("paths object");
    for path in [
        "/api/openapi.json",
        "/api/skills/oneiron.skills.md",
        "/api/core/discover",
        "/api/search/vector",
        "/api/search/text",
        "/api/entity/{id}",
        "/api/edges/{id}",
        "/v1/core/batch",
        "/v1/core/query",
        "/v1/core/context-pack",
        "/v1/core/hydrate",
        "/v1/core/conversations",
        "/v1/core/conversations/{conversation_id}/turns",
        "/v1/core/turns/{turn_id}",
        "/v1/core/turns/annotate",
        "/v1/core/outbound/capabilities",
        "/v1/core/outbound/capabilities/{connector}",
        "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
        "/v1/core/surface-events",
        "/v1/core/surface-events/{correlation_id}",
        "/v1/companion/access-grants",
        "/v1/companion/access-grants/{grant_id}/revoke",
        "/v1/companion/profiles/{persona_ref}",
        "/v1/companion/register/records",
        "/v1/companion/register/records/{record_id}",
        "/v1/companion/register/records/{record_id}/retire",
        "/v1/companion/register/records/{record_id}/end-relationship",
        "/api/lease/revoke",
        "/api/health",
        "/v1/consumer/usage",
        "/v1/consumer/usage/details",
        "/v1/consumer/top-up",
    ] {
        assert!(paths.contains_key(path), "missing path {path}");
    }
    assert!(
        !paths.contains_key("/api/context-pack"),
        "legacy context-pack path must be gone"
    );

    let vector_success = &spec["paths"]["/api/search/vector"]["get"]["responses"]["200"]["content"]
        ["application/json"];
    assert!(
        vector_success.get("example").is_some() || vector_success.get("examples").is_some(),
        "vector search 200 response must include an example: {vector_success:?}"
    );
    let vector_example = &vector_success["example"];
    assert!(
        vector_example["items"].is_array(),
        "vector search example must show paginated items: {vector_example:?}"
    );
    assert_eq!(
        vector_example["meta"]["countMode"],
        Value::from("estimate"),
        "vector search example must show estimate count metadata"
    );

    let discover_success = &spec["paths"]["/api/core/discover"]["get"]["responses"]["200"]["content"]
        ["application/json"];
    assert!(
        discover_success.get("example").is_some() || discover_success.get("examples").is_some(),
        "discover 200 response must include an example: {discover_success:?}"
    );

    let skills_pack_success = &spec["paths"]["/api/skills/oneiron.skills.md"]["get"]["responses"]["200"]
        ["content"][skills_pack_artifact::MEDIA_TYPE];
    assert!(
        skills_pack_success.get("example").is_some()
            || skills_pack_success.get("examples").is_some(),
        "skills pack 200 response must include a markdown example: {skills_pack_success:?}"
    );
    let skills_pack_unauthorized = &spec["paths"]["/api/skills/oneiron.skills.md"]["get"]["responses"]
        ["401"]["content"]["application/json"]["example"];
    assert_eq!(
        skills_pack_unauthorized,
        &serde_json::to_value(ApiError::unauthorized()).expect("serialize ApiError"),
        "skills pack 401 response example must match ApiError::unauthorized()"
    );

    assert!(
        spec["paths"]["/api/core/discover"]["get"]["responses"]
            .as_object()
            .is_some_and(|responses| responses.contains_key("401")),
        "discover must document its 401 ApiError response"
    );
    assert_eq!(
        discover_success["example"]["skill_pack"]["endpoint"],
        Value::from("/api/skills/oneiron.skills.md"),
        "discover example must advertise the committed skill pack endpoint"
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
    assert_eq!(
        spec["components"]["schemas"]["DiscoverResponse"]["properties"]["skill_pack"]["$ref"],
        Value::from("#/components/schemas/SkillPackDiscovery"),
        "DiscoverResponse must reference the skill-pack discovery schema"
    );

    assert!(
        spec["components"]["securitySchemes"]
            .get("OneironSecret")
            .is_none(),
        "the removed custom-header scheme must not be documented"
    );
    assert_eq!(
        spec["components"]["securitySchemes"]["CoreBearer"]["scheme"],
        Value::from("bearer"),
        "protected operations must document bearer auth"
    );
    assert!(
        !serde_json::to_string(&spec)
            .expect("serialize spec")
            .contains("x-oneiron-secret"),
        "no description, example, or scheme in the spec may still name the removed header"
    );
    for (path, method) in [
        ("/api/openapi.json", "get"),
        ("/api/skills/oneiron.skills.md", "get"),
        ("/api/core/discover", "get"),
        ("/api/search/vector", "get"),
        ("/api/search/text", "get"),
        ("/api/entity/{id}", "get"),
        ("/api/edges/{id}", "get"),
        ("/api/lease/revoke", "post"),
        ("/v1/consumer/usage", "get"),
        ("/v1/consumer/usage/details", "get"),
        ("/v1/consumer/top-up", "post"),
        ("/v1/core/batch", "post"),
        ("/v1/core/query", "post"),
        ("/v1/core/context-pack", "post"),
        ("/v1/core/hydrate", "post"),
        ("/v1/core/batch/shortId/hydrate", "post"),
        ("/v1/core/run-tree", "get"),
        ("/v1/core/conversations", "get"),
        ("/v1/core/conversations", "post"),
        ("/v1/core/conversations/{conversation_id}/turns", "get"),
        ("/v1/core/conversations/{conversation_id}/turns", "post"),
        ("/v1/core/turns/{turn_id}", "get"),
        ("/v1/core/turns/annotate", "get"),
        ("/v1/core/turns/annotate", "post"),
        ("/v1/core/outbound/capabilities", "get"),
        ("/v1/core/outbound/capabilities/{connector}", "get"),
        (
            "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
            "get",
        ),
        ("/v1/core/surface-events", "post"),
        ("/v1/core/surface-events/{correlation_id}", "get"),
        ("/v1/companion/access-grants", "post"),
        ("/v1/companion/access-grants/{grant_id}/revoke", "post"),
        ("/v1/companion/profiles/{persona_ref}", "get"),
        ("/v1/companion/register/records", "post"),
        ("/v1/companion/register/records/{record_id}", "get"),
        ("/v1/companion/register/records/{record_id}", "post"),
        ("/v1/companion/register/records/{record_id}/retire", "post"),
        (
            "/v1/companion/register/records/{record_id}/end-relationship",
            "post",
        ),
    ] {
        assert_eq!(
            spec["paths"][path][method]["security"],
            json!([{ "CoreBearer": [] }]),
            "{method} {path} must require bearer auth as the single scheme"
        );
    }

    assert!(
        spec["components"]["schemas"].get("ApiError").is_some(),
        "structured ApiError schema must be reusable from components"
    );
    assert!(
        spec["components"]["schemas"]
            .get("ApiErrorEnvelope")
            .is_some(),
        "v1 core ApiErrorEnvelope schema must be reusable from components"
    );
    assert!(
        spec["components"]["schemas"].get("ErrorCode").is_some(),
        "ErrorCode schema must be reusable from components"
    );
    assert!(
        spec["components"]["schemas"]["View"].get("enum").is_some(),
        "View schema must document allowed projection values"
    );

    let entity_octets = &spec["paths"]["/api/entity/{id}"]["get"]["responses"]["200"]["content"]["application/octet-stream"];
    assert_eq!(
        entity_octets["example"],
        Value::from("raw entity bytes"),
        "entity octet-stream example must not be a JSON byte array"
    );
    assert_eq!(
        entity_octets["schema"],
        json!({ "type": "string", "format": "binary" }),
        "entity octet-stream schema must model raw binary"
    );

    let entity_json = &spec["paths"]["/api/entity/{id}"]["get"]["responses"]["200"]["content"]["application/json"];
    assert_eq!(
        entity_json["schema"]["type"],
        Value::from("object"),
        "entity projection response must document a JSON object schema"
    );
    assert!(
        entity_json["examples"]["summary"].is_object(),
        "entity JSON projection response must include a summary example: {entity_json:?}"
    );
    assert!(
        entity_json["examples"]["full"].is_object(),
        "entity JSON projection response must include a full example: {entity_json:?}"
    );

    assert_non_empty_string(
        &spec["components"]["schemas"]["SearchResult"]["properties"]["score"]["description"],
        "SearchResult.score.description",
    );

    let lease_client_description = spec["components"]["schemas"]["LeaseRevokeRequest"]
            ["properties"]["client_id"]["description"]
            .as_str()
            .expect("LeaseRevokeRequest.client_id description");
    assert!(
        lease_client_description
            .to_ascii_lowercase()
            .contains("revoke"),
        "lease revoke client_id description should mention revoke: {lease_client_description}"
    );

    assert_eq!(
        spec["components"]["schemas"]["VectorSearchQuery"]["properties"]["limit"]["default"],
        Value::from(default_limit())
    );

    for schema_name in [
        "HealthResponse",
        "DiscoverResponse",
        "SkillPackDiscovery",
        "BoundContext",
        "DiscoveredEntity",
        "FeatureFlags",
        "RateLimitStatus",
        "RuntimeHealthStatus",
        "RuntimeStatus",
        "RuntimeRoute",
        "RuntimeRouteProvenance",
        "VectorSearchQuery",
        "SearchResult",
        "TextSearchQuery",
        "EdgeResult",
        "CoreBatchRequest",
        "CoreBatchEntityInput",
        "CoreBatchEntityResult",
        "CoreBatchResponse",
        "CoreTextField",
        "CoreQueryRequest",
        "CoreBatchShortIdHydrateItem",
        "CoreBatchShortIdHydrateRequest",
        "CoreBatchShortIdHydrateResponse",
        "CoreHydrateDeletionMetadata",
        "CoreHydrateRequest",
        "CoreHydrateResponse",
        "CoreShortIdHydrateError",
        "ContextPackDepthControls",
        "ContextPackPolicyControls",
        "ContextPackTimeControls",
        "ContextPackRetrievalBudgetControls",
        "ContextPackBudgetControls",
        "CoreContextPackRequest",
        "CoreContextPackResponse",
        "CoreContextEntity",
        "CoreContextEdge",
        "CoreContextPackStats",
        "CoreContextPackItemAccounting",
        "CoreContextPackState",
        "CoreContextPackScoreComponent",
        "CoreContextPackScoreEvidence",
        "CoreContextPackEvidence",
        "CoreEiriCompanionAssembly",
        "CoreEiriMemoryBoard",
        "CoreEiriMemoryBoardBudget",
        "CoreDisclosureAssembly",
        "CoreEiriMemoryBoardRow",
        "CoreEiriSessionRagState",
        "CoreInterlocutorControls",
        "CoreInterlocutorParty",
        "CoreInterlocutorStamp",
        "CoreListQuery",
        "CoreCreateEntityRequest",
        "CoreCreateTurnRequest",
        "CoreEntityWriteResponse",
        "VadPayload",
        "TurnVadAnnotateRequest",
        "TurnVadAnnotateQuery",
        "TurnVadAnnotateResponse",
        "CompanionAccessGrantScopePayload",
        "CompanionAccessGrantResponse",
        "CompanionCreateAccessGrantRequest",
        "CompanionRevokeAccessGrantRequest",
        "CompanionProfileAccess",
        "CompanionProfileConfidencePayload",
        "CompanionProfileDriftAnchor",
        "CompanionProfileNextAction",
        "CompanionProfilePayload",
        "CompanionProfileRefreshRequest",
        "CompanionProfileResponse",
        "CompanionProfileStaleReasonPayload",
        "CompanionRegisterScopePayload",
        "CompanionRegisterRelationshipRefPayload",
        "CompanionRegisterSubjectPayload",
        "CompanionRegisterProvenancePayload",
        "CompanionRegisterRecordPayload",
        "CompanionRegisterCreateRecordRequest",
        "CompanionRegisterUpdateRecordRequest",
        "CompanionRegisterRetireRecordRequest",
        "CompanionEndRelationshipRequest",
        "CompanionGoodbyeArtifactHookPayload",
        "CompanionEndRelationshipResponse",
        "CompanionRegisterRecordResponse",
        "LeaseRevokeRequest",
        "LeaseRevokeResponse",
        "ConsumerAllowanceState",
        "ConsumerAllowanceWarning",
        "ConsumerTopUp",
        "ConsumerTopUpRequest",
        "ConsumerTopUpState",
        "ConsumerUsageDetails",
        "ConsumerUsageState",
    ] {
        let properties = spec["components"]["schemas"][schema_name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema_name} properties object"));
        assert!(
            properties.values().any(|property| property
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())),
            "{schema_name} must have at least one described property"
        );
        for (field_name, property) in properties {
            assert_non_empty_string(
                &property["description"],
                &format!("{schema_name}.{field_name}.description"),
            );
        }
    }
}
