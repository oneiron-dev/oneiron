//! Batch/query/hydrate smoke, memory timeline + verbs, conversations/turns, platform announcements.

use super::*;

#[tokio::test]
async fn v1_core_batch_query_context_pack_and_hydrate_routes_are_live() {
    let (_dir, server) = test_server();

    let (batch_status, batch_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 500_u64,
                    "occurred_start": 500_u64,
                    "occurred_end": 500_u64,
                    "body": {
                        "txt": "blue hallway contextneedle",
                        "spkr": "user",
                        "at": 500_u64
                    }
                }]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK);
    let id = batch_body["entities"][0]["id"]
        .as_str()
        .expect("written id")
        .to_owned();
    assert_eq!(batch_body["count"], Value::from(1));

    let (query_status, query_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/query",
            json!({
                "query": "contextneedle",
                "limit": 5,
                "view": "full"
            }),
        ),
    )
    .await;
    assert_eq!(query_status, StatusCode::OK);
    assert_eq!(query_body["items"][0]["id"], Value::from(id.clone()));
    assert_eq!(
        query_body["items"][0]["txt"],
        Value::from("blue hallway contextneedle")
    );
    assert_eq!(query_body["meta"]["countMode"], Value::from("estimate"));

    let (pack_status, pack_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "contextneedle",
                "limit": 5,
                "view": "full"
            }),
        ),
    )
    .await;
    assert_eq!(pack_status, StatusCode::OK);
    assert_eq!(pack_body["results"][0]["id"], Value::from(id.clone()));
    assert_eq!(
        pack_body["results"][0]["fields"]["txt"],
        Value::from("blue hallway contextneedle")
    );
    assert_eq!(
        pack_body["stats"]["signals_used"],
        Value::Array(vec![Value::from("text")])
    );
    let short_id = pack_body["results"][0]["short_id"]
        .as_str()
        .expect("short id");
    let content_hash = pack_body["results"][0]["content_hash"]
        .as_str()
        .expect("content hash");
    let short_ref = format!("{short_id}:{content_hash}");

    let (hydrate_status, hydrate_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/hydrate",
            json!({
                "ref": short_ref,
                "view": "full"
            }),
        ),
    )
    .await;
    assert_eq!(hydrate_status, StatusCode::OK);
    assert_eq!(hydrate_body["status"], Value::from("live"));
    assert_eq!(hydrate_body["id"], Value::from(id.clone()));
    assert_eq!(
        hydrate_body["item"]["txt"],
        Value::from("blue hallway contextneedle")
    );
}

#[tokio::test]
async fn v1_core_memory_timeline_scrubs_filtered_supersession_links() {
    let (_dir, server) = test_server();
    let subject = seeded_test_entity_id(0x1261_0100);
    let old = seeded_test_entity_id(0x1261_0101);
    let new = seeded_test_entity_id(0x1261_0102);
    server
        .vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("seed subject");
    seed_active_claim(&server, old, subject, "osaka", 100);
    seed_active_claim(&server, new, subject, "tokyo", 200);
    server
        .vault
        .supersede_claim(&new, &old, 777)
        .expect("supersede claim");

    let path = format!("/v1/core/memory/{}/timeline?view=full", new.to_hex());
    let (status, body) = route_json(
        server,
        Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("timeline request"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:#}");
    assert_eq!(body["anchor_id"], Value::from(new.to_hex()));
    let records = body["records"].as_array().expect("timeline records");
    assert_eq!(records.len(), 1, "{body:#}");
    assert_eq!(records[0]["id"], Value::from(new.to_hex()));
    assert_eq!(records[0]["state"], Value::from("live"));
    assert_eq!(records[0]["supersedes"], Value::Array(vec![]));
}

#[tokio::test]
async fn v1_core_memory_verbs_resolve_aliases_to_typed_operations() {
    let (_dir, server) = test_server();
    let remembered = seeded_test_entity_id(0x1261_0200);
    let remember_request = json!({
        "entity": {
            "id": remembered.to_hex(),
            "entity_type": ENTITY_TYPE_TURN,
            "learned_at": 300_u64,
            "occurred_start": 300_u64,
            "occurred_end": 300_u64,
            "body": {
                "txt": "memory verb remembered turn",
                "spkr": "user",
                "at": 300_u64
            },
            "text": [{ "field": "body", "value": "memory verb remembered turn" }]
        }
    });
    let (remember_status, remember_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/memory/verbs/remember", remember_request),
    )
    .await;
    assert_eq!(remember_status, StatusCode::OK, "{remember_body:#}");
    assert_eq!(remember_body["verb"], Value::from("remember"));
    assert_eq!(remember_body["operation"], Value::from("put_entity"));
    assert_eq!(
        remember_body["entity"]["id"],
        Value::from(remembered.to_hex())
    );

    let subject = seeded_test_entity_id(0x1261_0201);
    let old = seeded_test_entity_id(0x1261_0202);
    let new = seeded_test_entity_id(0x1261_0203);
    let retractable = seeded_test_entity_id(0x1261_0204);
    server
        .vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("seed subject");
    seed_active_claim(&server, old, subject, "before", 310);
    seed_active_claim(&server, new, subject, "after", 320);
    seed_active_claim(&server, retractable, subject, "withdraw", 330);

    let (replace_status, replace_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/replace",
            json!({
                "new_id": new.to_hex(),
                "old_id": old.to_hex(),
                "at": 900_u64
            }),
        ),
    )
    .await;
    assert_eq!(replace_status, StatusCode::OK, "{replace_body:#}");
    assert_eq!(replace_body["verb"], Value::from("supersede"));
    assert_eq!(replace_body["operation"], Value::from("supersede_claim"));
    assert_eq!(replace_body["new_id"], Value::from(new.to_hex()));
    assert_eq!(replace_body["old_id"], Value::from(old.to_hex()));

    let (withdraw_status, withdraw_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/withdraw",
            json!({
                "id": retractable.to_hex(),
                "at": 901_u64
            }),
        ),
    )
    .await;
    assert_eq!(withdraw_status, StatusCode::OK, "{withdraw_body:#}");
    assert_eq!(withdraw_body["verb"], Value::from("retract"));
    assert_eq!(withdraw_body["operation"], Value::from("retract_claim"));
    assert_eq!(withdraw_body["id"], Value::from(retractable.to_hex()));

    let (soft_gdpr_status, soft_gdpr_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/delete",
            json!({
                "id": remembered.to_hex(),
                "reason": "gdpr_delete"
            }),
        ),
    )
    .await;
    assert_eq!(soft_gdpr_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&soft_gdpr_body, "BAD_REQUEST");

    let (soft_hard_status, soft_hard_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/delete",
            json!({
                "id": remembered.to_hex(),
                "reason": "user_hard_delete"
            }),
        ),
    )
    .await;
    assert_eq!(soft_hard_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&soft_hard_body, "BAD_REQUEST");

    let (delete_at_status, delete_at_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/delete",
            json!({
                "id": remembered.to_hex(),
                "at": 902_u64
            }),
        ),
    )
    .await;
    assert_eq!(delete_at_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&delete_at_body, "BAD_REQUEST");

    let (hard_user_status, hard_user_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/hard_delete",
            json!({
                "id": remembered.to_hex(),
                "reason": "user_delete"
            }),
        ),
    )
    .await;
    assert_eq!(hard_user_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&hard_user_body, "BAD_REQUEST");

    let (forget_status, forget_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/forget",
            json!({ "id": remembered.to_hex() }),
        ),
    )
    .await;
    assert_eq!(forget_status, StatusCode::OK, "{forget_body:#}");
    assert_eq!(forget_body["verb"], Value::from("delete"));
    assert_eq!(forget_body["operation"], Value::from("delete_entity"));
    assert_eq!(forget_body["delete"]["existed"], Value::from(true));
    assert_eq!(forget_body["delete"]["reason"], Value::from("user_delete"));
    assert_eq!(forget_body["delete"]["hard"], Value::from(false));
    assert!(forget_body.get("at").is_none());

    let deleted_path = format!("/v1/core/memory/{}/timeline", remembered.to_hex());
    let (timeline_status, timeline_body) = route_json(
        server,
        Request::builder()
            .uri(deleted_path)
            .body(Body::empty())
            .expect("deleted timeline request"),
    )
    .await;
    assert_eq!(timeline_status, StatusCode::OK, "{timeline_body:#}");
    let records = timeline_body["records"].as_array().expect("records");
    assert_eq!(records.len(), 1, "{timeline_body:#}");
    assert_eq!(records[0]["id"], Value::from(remembered.to_hex()));
    assert_eq!(records[0]["state"], Value::from("deleted"));
    assert_eq!(records[0]["deletion"]["reason"], Value::from("user_delete"));
    assert!(records[0].get("item").is_none());
}

#[tokio::test]
async fn v1_core_hydrate_distinguishes_malformed_not_found_and_deleted() {
    let (_dir, server) = test_server();
    let entity_id = oneiron::EntityId::now();
    let body = json!({
        "txt": "hydrate deleted needle",
        "spkr": "user",
        "at": 600_u64
    });
    server
        .vault
        .batch()
        .put(
            &entity_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 600,
                end: 600,
            },
            600,
            &rmp_serde::to_vec_named(&body).expect("encode body"),
        )
        .text(&entity_id, &[("body", "hydrate deleted needle")])
        .commit()
        .expect("seed turn");

    let pack = server
        .vault
        .context_pack()
        .search_text("hydrate deleted needle", 1)
        .run()
        .expect("context pack");
    let entity = pack.results.first().expect("hydrated result");
    let short_ref = format!("{}:{:02x}", entity.short_id, entity.content_hash);

    let (malformed_status, malformed_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/hydrate", json!({ "ref": "bad-ref" })),
    )
    .await;
    assert_eq!(malformed_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&malformed_body, "BAD_REQUEST");

    let (not_found_status, not_found_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/hydrate", json!({ "ref": "tn999:aa" })),
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);
    assert_error_envelope(&not_found_body, "NOT_FOUND");

    let empty_id = oneiron::EntityId::now();
    server
        .vault
        .batch()
        .put(
            &empty_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 601,
                end: 601,
            },
            601,
            b"",
        )
        .text(&empty_id, &[("body", "empty live body needle")])
        .commit()
        .expect("seed empty live turn");
    let empty_pack = server
        .vault
        .context_pack()
        .search_text("empty live body needle", 1)
        .run()
        .expect("empty context pack");
    let empty_entity = empty_pack.results.first().expect("empty live result");
    let empty_short_ref = format!(
        "{}:{:02x}",
        empty_entity.short_id, empty_entity.content_hash
    );
    let (empty_status, empty_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/hydrate",
            json!({ "ref": empty_short_ref }),
        ),
    )
    .await;
    assert_eq!(empty_status, StatusCode::OK, "{empty_body:#}");
    assert_eq!(empty_body["status"], Value::from("live"));
    assert_eq!(empty_body["id"], Value::from(empty_id.to_hex()));
    assert_eq!(empty_body["item"]["bodyBytes"], Value::Array(Vec::new()));

    server
        .vault
        .delete_entity_with_reason(&entity_id, oneiron::DeleteReason::UserDelete)
        .expect("soft delete turn");

    let (deleted_status, deleted_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/hydrate", json!({ "ref": short_ref })),
    )
    .await;
    assert_eq!(deleted_status, StatusCode::OK);
    assert_eq!(deleted_body["status"], Value::from("deleted"));
    assert_eq!(deleted_body["id"], Value::from(entity_id.to_hex()));
    assert!(
        matches!(
            deleted_body["deletion"]["source"].as_str(),
            Some("pending_tombstone" | "tombstone")
        ),
        "{deleted_body:#}"
    );
    assert_eq!(
        deleted_body["deletion"]["reason"],
        Value::from("user_delete")
    );
    assert_eq!(deleted_body["deletion"]["hard"], Value::from(false));
    assert!(
        deleted_body["deletion"]["deleted_at"].as_u64().is_some(),
        "{deleted_body:#}"
    );
    assert!(
        deleted_body["deletion"]["request_id"].as_str().is_some(),
        "{deleted_body:#}"
    );
    assert!(deleted_body.get("item").is_none());

    let too_many_refs = vec![empty_short_ref.clone(); CORE_MAX_BATCH_ENTITIES + 1];
    let (too_many_status, too_many_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch/shortId/hydrate",
            json!({ "refs": too_many_refs }),
        ),
    )
    .await;
    assert_eq!(too_many_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&too_many_body, "BAD_REQUEST");

    let (batch_status, batch_body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/core/batch/shortId/hydrate",
            json!({
                "refs": [
                    empty_short_ref,
                    short_ref,
                    "bad-ref",
                    "tn999:aa"
                ]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK, "{batch_body:#}");
    let results = batch_body["results"].as_array().expect("batch results");
    assert_eq!(results.len(), 4);
    assert_eq!(results[0]["outcome"], Value::from("live"));
    assert_eq!(results[0]["result"]["status"], Value::from("live"));
    assert_eq!(results[0]["result"]["id"], Value::from(empty_id.to_hex()));
    assert_eq!(results[1]["outcome"], Value::from("deleted"));
    assert_eq!(results[1]["result"]["status"], Value::from("deleted"));
    assert_eq!(
        results[1]["result"]["deletion"]["reason"],
        Value::from("user_delete")
    );
    assert_eq!(results[2]["outcome"], Value::from("malformed_short_id"));
    assert_eq!(
        results[2]["error"]["kind"],
        Value::from("malformed_short_id")
    );
    assert_eq!(results[3]["outcome"], Value::from("not_found"));
    assert_eq!(results[3]["error"]["kind"], Value::from("not_found"));
}

#[tokio::test]
async fn v1_core_conversation_routes_create_list_and_read_turns() {
    let (_dir, server) = test_server();

    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({
                "learned_at": 700_u64,
                "occurred_start": 700_u64,
                "occurred_end": 700_u64,
                "body": { "name": "Dream session" }
            }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"]
        .as_str()
        .expect("conversation id")
        .to_owned();

    let (conversations_status, conversations_body) = route_json(
        server.clone(),
        Request::builder()
            .uri("/v1/core/conversations?view=full")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(conversations_status, StatusCode::OK);
    assert_eq!(
        conversations_body["items"][0]["id"],
        Value::from(conversation_id.clone())
    );
    assert_eq!(
        conversations_body["items"][0]["name"],
        Value::from("Dream session")
    );

    let (turn_status, turn_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{conversation_id}/turns"),
            json!({
                "learned_at": 701_u64,
                "occurred_start": 701_u64,
                "occurred_end": 701_u64,
                "body": {
                    "txt": "conversation turn needle",
                    "spkr": "assistant",
                    "at": 701_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(turn_status, StatusCode::OK);
    let turn_id = turn_body["id"].as_str().expect("turn id").to_owned();
    assert_eq!(
        turn_body["item"]["txt"],
        Value::from("conversation turn needle")
    );

    let (turns_status, turns_body) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?view=full"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(turns_status, StatusCode::OK);
    assert_eq!(turns_body["items"][0]["id"], Value::from(turn_id.clone()));
    assert_eq!(
        turns_body["items"][0]["txt"],
        Value::from("conversation turn needle")
    );

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=full"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK);
    assert_eq!(read_body["txt"], Value::from("conversation turn needle"));
}

#[tokio::test]
async fn v1_core_conversation_turns_honor_after_and_filter_deleted_shells() {
    let (_dir, server) = test_server();

    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({
                "learned_at": 800_u64,
                "body": { "name": "Cursor session" }
            }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"]
        .as_str()
        .expect("conversation id")
        .to_owned();

    let mut turn_ids = Vec::new();
    for index in 0..3_u64 {
        let (turn_status, turn_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                &format!("/v1/core/conversations/{conversation_id}/turns"),
                json!({
                    "learned_at": 801_u64 + index,
                    "occurred_start": 801_u64 + index,
                    "occurred_end": 801_u64 + index,
                    "body": {
                        "txt": format!("cursor turn {index}"),
                        "spkr": "assistant",
                        "at": 801_u64 + index
                    }
                }),
            ),
        )
        .await;
        assert_eq!(turn_status, StatusCode::OK);
        turn_ids.push(turn_body["id"].as_str().expect("turn id").to_owned());
    }

    let (first_page_status, first_page) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(first_page_status, StatusCode::OK);
    let first_id = first_page["items"][0]["id"]
        .as_str()
        .expect("first page id")
        .to_owned();
    assert_eq!(first_page["nextCursor"], Value::from(first_id.clone()));

    let (second_page_status, second_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none&after={first_id}"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(second_page_status, StatusCode::OK);
    assert_ne!(second_page["items"][0]["id"], Value::from(first_id.clone()));

    let deleted_id = oneiron::EntityId::from_hex(&turn_ids[1]).expect("turn id parses");
    server
        .vault
        .delete_entity_with_reason(&deleted_id, oneiron::DeleteReason::UserDelete)
        .expect("soft delete turn");

    let (deleted_gap_status, deleted_gap_page) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(deleted_gap_status, StatusCode::OK);
    let deleted_gap_first = deleted_gap_page["items"][0]["id"]
        .as_str()
        .expect("deleted gap first id")
        .to_owned();
    assert_ne!(deleted_gap_first, turn_ids[1]);
    assert_eq!(
        deleted_gap_page["nextCursor"],
        Value::from(deleted_gap_first.clone())
    );

    let (after_deleted_gap_status, after_deleted_gap_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none&after={deleted_gap_first}"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(after_deleted_gap_status, StatusCode::OK);
    let after_deleted_gap_id = after_deleted_gap_page["items"][0]["id"]
        .as_str()
        .expect("after deleted gap id");
    assert_ne!(after_deleted_gap_id, deleted_gap_first);
    assert_ne!(after_deleted_gap_id, turn_ids[1]);

    let (filtered_status, filtered_body) = route_json(
        server,
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?view=full&countMode=exact"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(filtered_status, StatusCode::OK);
    let listed_ids: Vec<&str> = filtered_body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("item id"))
        .collect();
    assert_eq!(listed_ids.len(), 2);
    assert!(!listed_ids.contains(&turn_ids[1].as_str()));
    assert_eq!(filtered_body["meta"]["total"], Value::from(2));
}

#[tokio::test]
async fn v1_core_turn_create_maps_childof_constraints_to_invalid_state() {
    let (_dir, server) = test_server();

    let create_conversation = |name: &str| {
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({
                "body": { "name": name }
            }),
        )
    };
    let (first_status, first_body) = route_json(server.clone(), create_conversation("first")).await;
    assert_eq!(first_status, StatusCode::OK);
    let first_conversation = first_body["id"].as_str().expect("first id").to_owned();
    let (second_status, second_body) =
        route_json(server.clone(), create_conversation("second")).await;
    assert_eq!(second_status, StatusCode::OK);
    let second_conversation = second_body["id"].as_str().expect("second id").to_owned();

    let turn_id = oneiron::EntityId::now().to_hex();
    let turn_body = json!({
        "id": turn_id,
        "body": {
            "txt": "cardinality turn",
            "spkr": "assistant",
            "at": 900_u64
        }
    });
    let (first_turn_status, _) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{first_conversation}/turns"),
            turn_body.clone(),
        ),
    )
    .await;
    assert_eq!(first_turn_status, StatusCode::OK);

    let (conflict_status, conflict_body) = route_json(
        server,
        json_request(
            "POST",
            &format!("/v1/core/conversations/{second_conversation}/turns"),
            turn_body,
        ),
    )
    .await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_error_envelope(&conflict_body, "INVALID_STATE");
}

#[tokio::test]
async fn platform_announcement_turn_never_projects_as_eiri_voice() {
    let (_dir, server) = test_server();
    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({ "body": { "name": "Announcement stream" } }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"].as_str().expect("conversation id");
    let turn_id = seeded_test_entity_id(0x1479_0001).to_hex();

    let (turn_status, turn_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{conversation_id}/turns"),
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_001_u64,
                "occurred_start": 1_782_400_001_u64,
                "occurred_end": 1_782_400_001_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Maintenance begins at 22:00 UTC.",
                    "spkr": "Eiri",
                    "speaker": "Eiri",
                    "voice": "eiri",
                    "attribution": "Eiri",
                    "render_voice": "eiri",
                    "at": 1_782_400_001_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(turn_status, StatusCode::OK, "{turn_body:#}");
    let item = &turn_body["item"];
    assert_eq!(
        item["message_type"],
        Value::from(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    );
    assert_eq!(item["spkr"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_eq!(item["speaker"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_eq!(item["voice"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_eq!(
        item["attribution"],
        Value::from(PLATFORM_ANNOUNCEMENT_VOICE)
    );
    assert_eq!(
        item["render_voice"],
        Value::from(PLATFORM_ANNOUNCEMENT_VOICE)
    );
    assert_eq!(item["platform_voice"], Value::from(true));
    assert_eq!(item["is_eiri"], Value::from(false));

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=standard"))
            .body(Body::empty())
            .expect("read request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK, "{read_body:#}");
    assert_eq!(
        read_body["message_type"],
        Value::from(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    );
    assert_eq!(read_body["voice"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_ne!(read_body["voice"], Value::from("eiri"));
}

#[tokio::test]
async fn platform_announcement_correction_and_retraction_update_delivered_turn() {
    let (_dir, server) = test_server();
    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({ "body": { "name": "Ops notices" } }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"].as_str().expect("conversation id");
    let turn_id = seeded_test_entity_id(0x1479_0002).to_hex();
    let turns_path = format!("/v1/core/conversations/{conversation_id}/turns");

    let (create_status, create_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &turns_path,
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_010_u64,
                "occurred_start": 1_782_400_010_u64,
                "occurred_end": 1_782_400_010_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Storage maintenance starts at 20:00 UTC.",
                    "announcement_status": "active",
                    "at": 1_782_400_010_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK, "{create_body:#}");

    let (correct_status, correct_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &turns_path,
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_020_u64,
                "occurred_start": 1_782_400_010_u64,
                "occurred_end": 1_782_400_020_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Storage maintenance starts at 21:00 UTC.",
                    "announcement_status": "corrected",
                    "at": 1_782_400_020_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(correct_status, StatusCode::OK, "{correct_body:#}");
    assert_eq!(
        correct_body["item"]["announcement_status"],
        Value::from(ANNOUNCEMENT_STATUS_CORRECTED)
    );
    assert_eq!(correct_body["item"]["corrected"], Value::from(true));

    let (retract_status, retract_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &turns_path,
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_030_u64,
                "occurred_start": 1_782_400_010_u64,
                "occurred_end": 1_782_400_030_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Storage maintenance announcement retracted.",
                    "retracted": true,
                    "at": 1_782_400_030_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(retract_status, StatusCode::OK, "{retract_body:#}");
    assert_eq!(
        retract_body["item"]["announcement_status"],
        Value::from(ANNOUNCEMENT_STATUS_RETRACTED)
    );
    assert_eq!(retract_body["item"]["retracted"], Value::from(true));

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=full"))
            .body(Body::empty())
            .expect("read request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK, "{read_body:#}");
    assert_eq!(
        read_body["txt"],
        Value::from("Storage maintenance announcement retracted.")
    );
    assert_eq!(
        read_body["announcement_status"],
        Value::from(ANNOUNCEMENT_STATUS_RETRACTED)
    );
    assert_eq!(read_body["voice"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
}

#[tokio::test]
async fn localized_platform_announcement_exposes_original_text_toggle() {
    let (_dir, server) = test_server();
    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({ "body": { "name": "Localized notices" } }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"].as_str().expect("conversation id");
    let turn_id = seeded_test_entity_id(0x1479_0003).to_hex();

    let (turn_status, turn_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{conversation_id}/turns"),
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_040_u64,
                "occurred_start": 1_782_400_040_u64,
                "occurred_end": 1_782_400_040_u64,
                "body": {
                    "messageType": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "メンテナンスは22:00 UTCに開始します。",
                    "locale": "ja-JP",
                    "originalText": "Maintenance begins at 22:00 UTC.",
                    "showOriginal": false,
                    "at": 1_782_400_040_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(turn_status, StatusCode::OK, "{turn_body:#}");
    assert_eq!(turn_body["item"]["localized"], Value::from(true));
    assert_eq!(turn_body["item"]["locale"], Value::from("ja-JP"));
    assert_eq!(
        turn_body["item"]["original_txt"],
        Value::from("Maintenance begins at 22:00 UTC.")
    );
    assert_eq!(turn_body["item"]["show_original"], Value::from(false));

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=standard"))
            .body(Body::empty())
            .expect("read request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK, "{read_body:#}");
    assert_eq!(
        read_body["message_type"],
        Value::from(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    );
    assert_eq!(read_body["show_original"], Value::from(false));
}
