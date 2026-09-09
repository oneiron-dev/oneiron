//! Search count-modes, context-pack budgets/response controls, text-search shape, snapshot/sort unit tests.

use super::*;

#[test]
fn search_response_drops_stale_hydrated_hits() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let scoped_read = vault
        .scoped_read(oneiron::claim::ScopedReadActorKey::new("test-reader").expect("actor key"));
    let stale_hit = oneiron::ScoredEntity {
        id: oneiron::EntityId::now(),
        score: 0.75,
    };

    for view in [View::Summary, View::Full] {
        let response = search_response(&scoped_read, vec![stale_hit], view, 10).unwrap();
        assert!(
            response.is_empty(),
            "{view:?} should skip missing search hits"
        );
    }
}

#[test]
fn search_response_rechecks_projected_claim_body() {
    #[derive(serde::Serialize)]
    struct ClaimSeed<'a> {
        pred: &'a str,
        val: &'a str,
        conf: f32,
        #[serde(with = "serde_bytes")]
        subj: &'a [u8],
        appr: &'static str,
        life: &'static str,
    }

    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let claim_id = seeded_test_entity_id(0x0012_6901);
    let subject = seeded_test_entity_id(0x0012_6902);
    let body = rmp_serde::to_vec_named(&ClaimSeed {
        pred: "profile.projected",
        val: "hidden after update",
        conf: 0.9,
        subj: subject.as_bytes(),
        appr: "proposed",
        life: "active",
    })
    .expect("encode proposed claim");
    vault
        .put_entity(
            &claim_id,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("seed proposed claim");

    let scoped_read = vault
        .scoped_read(oneiron::claim::ScopedReadActorKey::new("test-reader").expect("actor key"));
    let stale_hit = oneiron::ScoredEntity {
        id: claim_id,
        score: 0.75,
    };

    for view in [View::Summary, View::Full] {
        let response = search_response(&scoped_read, vec![stale_hit], view, 10).unwrap();
        assert!(
            response.is_empty(),
            "{view:?} should re-check the exact projected body through ScopedRead"
        );
    }
}

#[test]
fn search_queries_default_to_estimate_count_mode() {
    let text: TextSearchQuery = serde_json::from_value(serde_json::json!({
        "query": "hello"
    }))
    .unwrap();
    assert_eq!(text.limit, default_limit());
    assert_eq!(text.count_mode, CountMode::Estimate);

    let vector: VectorSearchQuery = serde_json::from_value(serde_json::json!({
        "query": "0.0,0.0"
    }))
    .unwrap();
    assert_eq!(vector.limit, default_limit());
    assert_eq!(vector.count_mode, CountMode::Estimate);
}

#[test]
fn search_meta_honors_none_without_counting() {
    assert_eq!(search_meta(CountMode::None, 25), ResponseMeta::none());
    assert_eq!(search_fetch_limit(CountMode::None, 25), 25);
}

#[test]
fn search_meta_reports_estimate_not_exact() {
    assert_eq!(
        search_meta(CountMode::Estimate, 7),
        ResponseMeta::estimate(7)
    );
    assert_eq!(search_fetch_limit(CountMode::Estimate, 7), 8);
    assert_eq!(CountMode::Exact.for_search_response(), CountMode::Estimate);
}

#[test]
fn context_pack_scoped_budget_preserves_default_response_split() {
    let (response, internal) = resolve_context_pack_retrieval_budgets(None, 5, 100, 7);
    let defaults =
        oneiron::ContextPackRetrievalBudget::from_limit(5, oneiron::TokenAllocation::default(), 7);

    assert_eq!(response, defaults);
    assert_eq!(internal.selected_edges, 7);
    assert_eq!(internal.claims, 100);
    assert_eq!(internal.turns, 100);
    assert_eq!(internal.summaries, 100);
    assert_eq!(internal.facets, 100);
    assert_eq!(internal.other, 100);
}

#[test]
fn context_pack_scoped_budget_preserves_explicit_zero_buckets() {
    let controls = ContextPackRetrievalBudgetControls {
        claims: Some(0),
        turns: Some(2),
        selected_edges: Some(3),
        ..Default::default()
    };

    let (response, internal) = resolve_context_pack_retrieval_budgets(Some(&controls), 10, 50, 9);

    assert_eq!(response.claims, 0);
    assert_eq!(internal.claims, 0);
    assert_eq!(response.turns, 2);
    assert_eq!(internal.turns, 50);
    assert_eq!(response.selected_edges, 3);
    assert_eq!(internal.selected_edges, 3);
}

#[test]
fn context_pack_response_limits_scrub_stats_after_scoped_truncation() {
    let mut pack = synthetic_context_pack(0);
    let claim_a = seeded_test_entity_id(0x0012_6501);
    let claim_b = seeded_test_entity_id(0x0012_6502);
    let turn = seeded_test_entity_id(0x0012_6503);
    let neighbor = seeded_test_entity_id(0x0012_6504);
    let entity = |id: oneiron::EntityId, entity_type: u8| oneiron::ContextEntity {
        id,
        short_id: id.to_hex(),
        content_hash: 0,
        entity_type,
        score: 1.0,
        fields: None,
        edges: None,
        vector: None,
    };
    pack.results = vec![
        entity(claim_a, oneiron::registry::ENTITY_TYPE_CLAIM),
        entity(claim_b, oneiron::registry::ENTITY_TYPE_CLAIM),
        entity(turn, ENTITY_TYPE_TURN),
    ];
    pack.neighbors = vec![
        entity(neighbor, oneiron::registry::ENTITY_TYPE_SUMMARY),
        entity(
            seeded_test_entity_id(0x0012_6505),
            oneiron::registry::ENTITY_TYPE_SUMMARY,
        ),
    ];
    pack.stats.candidates_considered = 99;
    pack.stats.entities_hydrated = 88;
    pack.stats.neighbors_hydrated = 77;

    apply_context_pack_response_limits(
        &mut pack,
        ContextPackResponseLimits {
            results: 10,
            neighbors: 1,
            retrieval: oneiron::ContextPackRetrievalBudget::new(1, 1, 0, 0, 0, 0),
        },
    );

    assert_eq!(
        pack.results
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        vec![claim_a, turn]
    );
    assert_eq!(pack.neighbors.len(), 1);
    assert_eq!(pack.stats.candidates_considered, 2);
    assert_eq!(pack.stats.entities_hydrated, 2);
    assert_eq!(pack.stats.neighbors_hydrated, 1);
    assert!(pack.empty.is_none());
}

#[tokio::test]
async fn context_pack_route_projects_json_response_controls() {
    let (_dir, server) = test_server();
    let long_text = format!("projection budget needle {}", "x".repeat(800));
    let (batch_status, batch_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 510_u64,
                    "occurred_start": 510_u64,
                    "occurred_end": 510_u64,
                    "body": {
                        "txt": long_text,
                        "spkr": "user",
                        "at": 510_u64,
                        "sess": "session-alpha",
                        "debug": "private"
                    },
                    "text": [{ "field": "body", "value": "projection budget needle" }]
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

    let (summary_status, summary_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "summary" }
            }),
        ),
    )
    .await;
    assert_eq!(summary_status, StatusCode::OK);
    assert_eq!(summary_body["results"][0]["id"], Value::from(id.clone()));
    let fields = summary_body["results"][0]["fields"]
        .as_object()
        .expect("projected fields");
    assert!(fields.contains_key("txt"));
    assert!(!fields.contains_key("spkr"));
    assert!(!fields.contains_key("at"));
    assert!(!fields.contains_key("sess"));
    assert!(!fields.contains_key("debug"));

    let (budget_status, budget_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "max_item_tokens": 48 }
            }),
        ),
    )
    .await;
    assert_eq!(budget_status, StatusCode::OK);
    assert_eq!(budget_body["results"][0]["id"], Value::from(id.clone()));
    let truncated = budget_body["results"][0]["fields"]["txt"]
        .as_str()
        .expect("truncated text field");
    assert!(truncated.contains("truncated"));
    assert_eq!(
        budget_body["stats"]["items_truncated"]["count"],
        Value::from(1)
    );
    assert_eq!(
        budget_body["evidence"]["result_ids"],
        Value::Array(vec![Value::from(id.clone())])
    );

    let (token_budget_status, token_budget_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "tokenBudget": 16 }
            }),
        ),
    )
    .await;
    assert_eq!(token_budget_status, StatusCode::OK);
    assert_eq!(token_budget_body["results"], Value::Array(Vec::new()));
    assert_eq!(token_budget_body["neighbors"], Value::Array(Vec::new()));
    assert_eq!(
        token_budget_body["stats"]["items_dropped"]["count"],
        Value::from(1)
    );
    assert_eq!(
        token_budget_body["stats"]["items_dropped"]["reason"],
        Value::from("token_budget")
    );
    assert_eq!(
        token_budget_body["state"]["reason"],
        Value::from("filter_matched_none")
    );
    assert!(
        token_budget_body["state"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("budget.token_budget"))
    );
    assert_eq!(
        token_budget_body["evidence"]["result_ids"],
        Value::Array(Vec::new())
    );
    assert_eq!(
        token_budget_body["evidence"]["scores"],
        Value::Array(Vec::new())
    );

    let (dropped_status, dropped_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "max_item_tokens": 1 }
            }),
        ),
    )
    .await;
    assert_eq!(dropped_status, StatusCode::OK);
    assert_eq!(dropped_body["results"], Value::Array(Vec::new()));
    assert_eq!(dropped_body["neighbors"], Value::Array(Vec::new()));
    assert_eq!(dropped_body["state"]["kind"], Value::from("missing_data"));
    assert_eq!(
        dropped_body["state"]["reason"],
        Value::from("filter_matched_none")
    );
    assert!(
        dropped_body["state"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("budget.max_item_tokens"))
    );
    assert_eq!(
        dropped_body["empty"]["reason"],
        Value::from("filter_matched_none")
    );
    assert_eq!(
        dropped_body["stats"]["items_dropped"]["count"],
        Value::from(1)
    );
    assert_eq!(
        dropped_body["evidence"]["result_ids"],
        Value::Array(Vec::new())
    );
    assert_eq!(dropped_body["evidence"]["scores"], Value::Array(Vec::new()));

    let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
    assert_eq!(runs.len(), 1);
    assert!(runs[0].result_ids.is_empty());
    assert!(runs[0].score_breakdown.is_empty());
    assert_eq!(runs[0].empty_reason.as_deref(), Some("ItemBudget"));
}

#[tokio::test]
async fn context_pack_route_rejects_malformed_controls() {
    let (_dir, server) = test_server();
    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "depth": { "edge_hop": oneiron::context_pack::MAX_EDGE_HOP + 1 }
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("depth.edge_hop")
    );
    assert!(
        error_envelope(&body)["message"]
            .as_str()
            .is_some_and(|message| message.contains("edge_hop")),
        "control error should name the malformed field: {body:?}"
    );

    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "edge_hop": oneiron::context_pack::MAX_EDGE_HOP + 1
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("edge_hop")
    );

    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "max_neighbors": oneiron::context_pack::MAX_CONTEXT_NEIGHBORS + 1
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("max_neighbors")
    );

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "time": {
                    "since": 300_u64,
                    "learned_start": 100_u64,
                    "learned_end": 200_u64
                }
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("time.since")
    );
    assert!(
        error_envelope(&body)["message"]
            .as_str()
            .is_some_and(|message| message.contains("learned_end")),
        "control error should name the contradictory learned bound: {body:?}"
    );
}

#[tokio::test]
async fn text_search_response_shape_still_deserializes() {
    let (_dir, server) = test_server();

    let response = search_text(
        HeaderMap::new(),
        State(server),
        Ok(Query(TextSearchQuery {
            query: "shape guard".to_owned(),
            limit: 1,
            view: Some(View::Summary),
            count_mode: CountMode::Estimate,
            // ONE-207: the omission defaults, spelled out because this row
            // constructs the params struct directly and so bypasses serde.
            depth: minimal_effort(),
        })),
    )
    .await
    .expect("text search response");

    let body = serde_json::to_vec(&response.0).expect("serialize response");
    let parsed: Value = serde_json::from_slice(&body).expect("deserialize response");
    assert_eq!(parsed["items"], Value::Array(Vec::new()));
    assert_eq!(parsed["meta"]["countMode"], Value::from("estimate"));
}

#[test]
fn non_empty_query_trims_and_filters_blank_values() {
    assert_eq!(non_empty_query(None), None);
    assert_eq!(non_empty_query(Some("")), None);
    assert_eq!(non_empty_query(Some("   \n\t  ")), None);
    assert_eq!(
        non_empty_query(Some("  recent decisions  ")),
        Some("recent decisions")
    );
}
