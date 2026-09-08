//! Memory-reason route depths/spend/validation, raw-search depth tiers, retrieval-quality markers + snapshots.

use super::*;

/// The response shape is a CONTRACT, so this row spells out the whole key set
/// rather than probing the fields it happens to care about. A field renamed,
/// added, or silently dropped fails here.
#[tokio::test]
async fn memory_reason_defaults_to_standard_and_answers_from_the_evidence() {
    let (_dir, server) = memory_reason_server(None);

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "format": "markdown" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    let keys: BTreeSet<&str> = body
        .as_object()
        .expect("reason response object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "answer",
            "sources",
            "confidence",
            "gaps",
            "reasoning",
            "tokensUsed",
            "quality",
            "confidenceAdjustment"
        ]),
        "exact camelCase response contract: {body:?}"
    );
    assert!(
        body["answer"]
            .as_str()
            .is_some_and(|answer| !answer.is_empty()),
        "{body:?}"
    );
    assert!(
        body["sources"]
            .as_array()
            .is_some_and(|sources| !sources.is_empty()),
        "an extractive answer cites the evidence it shows: {body:?}"
    );
    assert_eq!(
        body["tokensUsed"],
        Value::from(0),
        "the omitted-depth default is model-free and spends nothing"
    );

    // Omitted `depth` means standard, which is the tier that expands.
    let trace_keys: BTreeSet<&str> = body["reasoning"]
        .as_object()
        .expect("standard reports a trace")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        trace_keys,
        BTreeSet::from(["queriesRun", "signalsUsed", "candidatesScanned"])
    );
    let signals: Vec<&str> = body["reasoning"]["signalsUsed"]
        .as_array()
        .expect("signals array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        signals.contains(&"ppr"),
        "standard expands the graph: {signals:?}"
    );
    let queries: Vec<&str> = body["reasoning"]["queriesRun"]
        .as_array()
        .expect("queries array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        queries.first(),
        Some(&"launch date"),
        "the trace opens with the caller's own question: {queries:?}"
    );
}

#[tokio::test]
async fn memory_reason_minimal_reports_no_reasoning_trace() {
    let (_dir, server) = memory_reason_server(None);

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "depth": "minimal" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert!(
        body.get("reasoning").is_none(),
        "a single direct pass has no reasoning to report: {body:?}"
    );
    assert_eq!(body["tokensUsed"], Value::from(0));
}

#[tokio::test]
async fn memory_reason_refuses_malformed_requests_field_by_field() {
    let (_dir, server) = memory_reason_server(None);

    for (payload, field) in [
        (json!({ "query": "   " }), Some("query")),
        (json!({ "query": "launch", "limit": 0 }), Some("limit")),
        (
            json!({ "query": "launch", "tokenBudget": 0 }),
            Some("tokenBudget"),
        ),
        (
            json!({ "query": "launch", "tokenBudget": 65_537 }),
            Some("tokenBudget"),
        ),
        (json!({ "query": "launch", "depth": "high" }), None),
        (json!({ "query": "launch", "curiosity": 3 }), None),
    ] {
        let (status, body) = route_json(
            server.clone(),
            json_request("POST", "/v1/companion/memory/reason", payload.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{payload:?} -> {body:?}");
        assert_error_envelope(&body, "BAD_REQUEST");
        if let Some(field) = field {
            assert_eq!(
                error_envelope(&body)["details"]["field"],
                Value::from(field),
                "{payload:?}"
            );
        }
    }

    // The budget bounds are inclusive at both ends.
    for token_budget in [1, 65_536] {
        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/companion/memory/reason",
                json!({ "query": "launch", "tokenBudget": token_budget }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{token_budget} -> {body:?}");
    }
}

#[tokio::test]
async fn memory_reason_deep_without_a_backend_is_service_unavailable() {
    let (_dir, server) = memory_reason_server(None);

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "depth": "deep" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body:?}");
    assert_error_envelope(&body, "DEEP_RETRIEVAL_UNAVAILABLE");
}

#[tokio::test]
async fn memory_reason_deep_reports_decompose_rerank_and_compose_spend() {
    let backend = Arc::new(StubReasonBackend::answering("the launch moved to March"));
    let (_dir, server) = memory_reason_server(Some(backend));

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "depth": "deep", "tokenBudget": 4096 }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        body["answer"],
        Value::from("the launch moved to March"),
        "{body:?}"
    );
    assert_eq!(
        body["tokensUsed"],
        Value::from(3 + 5 + 9),
        "tokensUsed is the summed backend spend, never the requested budget: {body:?}"
    );
    assert_ne!(
        body["tokensUsed"],
        Value::from(4096),
        "the request budget must never be reported as spend"
    );
}

/// A composer citing something the retrieval never returned does not get to
/// speak: the read falls back to the evidence and says so.
#[tokio::test]
async fn memory_reason_refuses_an_answer_citing_evidence_it_never_retrieved() {
    let mut stub = StubReasonBackend::answering("invented recollection");
    stub.sources = Some(vec!["not-a-retrieved-short-id".to_owned()]);
    let (_dir, server) = memory_reason_server(Some(Arc::new(stub)));

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "depth": "deep" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_ne!(
        body["answer"],
        Value::from("invented recollection"),
        "an unsourced answer must not reach the wire: {body:?}"
    );
    let gaps: Vec<&str> = body["gaps"]
        .as_array()
        .expect("gaps array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        gaps.iter().any(|gap| gap.contains("not usable")),
        "the refusal is reported, not hidden: {gaps:?}"
    );
    assert_eq!(
        body["tokensUsed"],
        Value::from(3 + 5 + 9),
        "the tokens were spent whether or not the answer was usable"
    );
}

#[tokio::test]
async fn raw_search_depth_defaults_to_minimal_and_refuses_unknown_tiers() {
    let (_dir, server) = memory_reason_server(None);

    for uri in [
        "/api/search/text?query=launch",
        "/api/search/text?query=launch&depth=minimal",
        "/api/search/text?query=launch&depth=standard",
    ] {
        let (status, body) = route_json(
            server.clone(),
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{uri} -> {body:?}");
    }

    for uri in [
        "/api/search/text?query=launch&depth=high",
        "/api/search/text?query=launch&depth=med",
        "/api/search/vector?query=0.1,0.2&depth=low",
    ] {
        let (status, body) = route_json(
            server.clone(),
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the chat verb's low/med/high aliases are not this wire: {uri} -> {body:?}"
        );
    }
}

#[tokio::test]
async fn raw_search_deep_needs_query_text_and_a_backend() {
    let (_dir, server) = memory_reason_server(None);

    let (status, body) = route_json(
        server.clone(),
        Request::builder()
            .method("GET")
            .uri("/api/search/vector?query=0.1,0.2&depth=deep")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert_eq!(body["code"], Value::from("BAD_REQUEST"));
    assert_eq!(
        body["details"]["field"],
        Value::from("queryText"),
        "the refusal names the missing field: {body:?}"
    );

    // A vector read WITHOUT text is fine at the tiers that never read it.
    // Full width, because this row is about the depth gate and must not trip
    // over the vault's own dimension check on the way to it.
    let probe = vec!["0.1"; oneiron::VaultConfig::device().dimensions].join(",");
    for depth in ["minimal", "standard"] {
        let (status, body) = route_json(
            server.clone(),
            Request::builder()
                .method("GET")
                .uri(format!("/api/search/vector?query={probe}&depth={depth}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{depth} -> {body:?}");
    }

    // Grounded, but this server has no deep host.
    let (status, body) = route_json(
        server,
        Request::builder()
            .method("GET")
            .uri("/api/search/text?query=launch&depth=deep")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body:?}");
    assert_eq!(body["code"], Value::from("DEEP_RETRIEVAL_UNAVAILABLE"));
}

/// ONE vocabulary for depth on the whole wire.
///
/// The engine's `Effort` is the only depth type the server publishes: no
/// `SearchDepth`, and no `low | med | high` (those are the chat verb's own
/// input aliases and stay there). This row reads the generated document
/// because that is what a client actually sees.
#[test]
fn generated_openapi_publishes_exactly_one_retrieval_depth_vocabulary() {
    let spec = generated_spec();
    let expected = Value::from(vec!["minimal", "standard", "deep"]);

    assert_eq!(
        spec["components"]["schemas"]["RetrievalEffort"]["enum"],
        expected
    );
    assert_eq!(
        spec["components"]["schemas"]["MemoryReasonRequest"]["properties"]["depth"]["enum"],
        expected,
        "the reason request speaks the engine's tiers"
    );

    for path in ["/api/search/vector", "/api/search/text"] {
        let depth = spec["paths"][path]["get"]["parameters"]
            .as_array()
            .expect("query parameters")
            .iter()
            .find(|parameter| parameter["name"] == "depth")
            .unwrap_or_else(|| panic!("{path} must document a depth parameter"));
        assert_eq!(depth["schema"]["enum"], expected, "{path}");
    }

    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("schemas object");
    assert!(
        !schemas.contains_key("SearchDepth"),
        "a second depth type must not exist"
    );
    for name in [
        "MemoryReasonRequest",
        "MemoryReasonResponse",
        "RetrievalEffort",
    ] {
        assert!(schemas.contains_key(name), "missing schema {name}");
    }
    assert!(
        spec["paths"]
            .as_object()
            .expect("paths object")
            .contains_key("/v1/companion/memory/reason"),
        "the reasoning route must be documented"
    );
    assert_eq!(
        spec["paths"]["/v1/companion/memory/reason"]["post"]["security"],
        json!([{ "CoreBearer": [] }]),
        "the reasoning route must require bearer auth as the single scheme"
    );
}

#[test]
fn retrieval_quality_response_meta_is_additive_and_keeps_eq_and_wire_numbers() {
    use oneiron::retrieval_quality::{
        PprCacheOutcome, RetrievalDiagnostics, classify_retrieval_quality,
    };
    use oneiron::store::RetrievalSignal;

    fn requires_eq<T: Eq>(_: &T) {}

    let old = PaginatedResponse::new(vec![json!({"id": "unchanged"})], None, ResponseMeta::none());
    assert_eq!(
        serde_json::to_value(&old).expect("old envelope"),
        json!({
            "items": [{"id": "unchanged"}], "meta": {"total": 0, "countMode": "none"}
        })
    );
    let report = classify_retrieval_quality(&RetrievalDiagnostics {
        attempted: vec![RetrievalSignal::Text, RetrievalSignal::Ppr],
        succeeded: vec![RetrievalSignal::Text, RetrievalSignal::Ppr],
        ppr_cache: Some(PprCacheOutcome::Miss),
        ..Default::default()
    });
    let meta = ResponseMeta::estimate(4).with_quality(&report);
    requires_eq(&meta);
    requires_eq(&old);
    assert_eq!(meta, meta.clone());
    let wire = serde_json::to_value(meta).expect("quality meta");
    assert_eq!(
        wire,
        json!({
            "total": 4, "countMode": "estimate", "quality": "degraded",
            "degradation": ["ppr_cache_miss"], "confidenceAdjustment": -0.15
        })
    );
}

#[test]
fn retrieval_quality_openapi_fields_are_optional_and_use_decimal_number_schema() {
    let spec = generated_spec();
    let expected = retrieval_quality_schema_properties();
    for name in ["ResponseMeta", "CoreContextPackResponse"] {
        let schema = openapi_component_schema(&spec, name);
        for field in ["quality", "degradation", "confidenceAdjustment"] {
            assert_eq!(
                openapi_schema_contract(&schema["properties"][field]),
                expected[field]
            );
            assert!(
                !schema["required"]
                    .as_array()
                    .expect("required fields")
                    .contains(&Value::from(field))
            );
        }
        assert!(schema["properties"].get("confidence_adjustment").is_none());
    }
}

#[tokio::test]
async fn retrieval_quality_raw_empty_search_uses_completed_operation_not_hit_count() {
    let (_dir, server) = test_server();
    let text = search_text(
        HeaderMap::new(),
        State(server.clone()),
        Ok(Query(TextSearchQuery {
            query: "absentqualitytoken".to_owned(),
            limit: 10,
            view: Some(View::Standard),
            count_mode: CountMode::Estimate,
            depth: oneiron::Effort::Minimal,
        })),
    )
    .await
    .expect("text search");
    let mut query = vec!["0"; oneiron::VaultConfig::device().dimensions];
    query[0] = "1";
    let vector = search_vector(
        HeaderMap::new(),
        State(server),
        Ok(Query(VectorSearchQuery {
            query: query.join(","),
            limit: 10,
            view: Some(View::Standard),
            count_mode: CountMode::None,
            depth: oneiron::Effort::Minimal,
            query_text: None,
        })),
    )
    .await
    .expect("vector search");
    for response in [text.0, vector.0] {
        assert!(response.items.is_empty());
        let wire = serde_json::to_value(response).expect("search JSON");
        assert_eq!(wire["meta"]["quality"], "passthrough");
        assert_eq!(wire["meta"]["confidenceAdjustment"], -0.35);
        assert!(wire["meta"].get("degradation").is_none());
        assert!(wire["meta"].get("confidence_adjustment").is_none());
    }
}

#[tokio::test]
async fn retrieval_quality_context_route_carries_report_on_empty_response() {
    let (_dir, server) = test_server();
    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "absentqualitytoken", "limit": 10
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["results"], json!([]));
    assert_eq!(body["quality"], "passthrough");
    assert_eq!(body["confidenceAdjustment"], -0.35);
    assert!(body.get("degradation").is_none());
    assert_eq!(
        body["empty"]["retrievalQuality"]["quality"],
        body["quality"]
    );
    assert_eq!(
        body["empty"]["retrievalQuality"]["confidenceAdjustment"],
        -0.35
    );
    assert_eq!(body["empty"]["reason"], "no_data");
}

#[test]
fn retrieval_quality_server_scope_projection_preserves_degradation() {
    use oneiron::retrieval_quality::{
        PprCacheOutcome, RetrievalDiagnostics, classify_retrieval_quality,
    };
    use oneiron::store::RetrievalSignal;

    let mut pack = synthetic_context_pack(1);
    pack.retrieval_quality = classify_retrieval_quality(&RetrievalDiagnostics {
        attempted: vec![RetrievalSignal::Text, RetrievalSignal::Ppr],
        succeeded: vec![RetrievalSignal::Text, RetrievalSignal::Ppr],
        ppr_cache: Some(PprCacheOutcome::Miss),
        ..Default::default()
    });
    let report = pack.retrieval_quality.clone();
    pack.results.clear();
    scrub_context_pack_visible_stats(&mut pack);
    assert_eq!(pack.retrieval_quality, report);
    assert_eq!(
        pack.empty.as_ref().expect("scoped empty").retrieval_quality,
        report
    );
    let (_dir, server) = test_server();
    let evidence = core_context_pack_evidence(&server.vault, None).expect("empty evidence");
    let response = core_context_pack_response(pack, evidence, None, None, None, None);
    let wire = serde_json::to_value(response).expect("context JSON");
    assert_eq!(wire["quality"], "degraded");
    assert_eq!(wire["degradation"], json!(["ppr_cache_miss"]));
    assert_eq!(wire["confidenceAdjustment"], -0.15);
}
