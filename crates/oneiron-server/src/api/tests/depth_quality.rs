use super::*;
use crate::api::memory_reason::{
    DeepRetrievalHost, MemoryReasonBackend, MemoryReasonComposeRequest, MemoryReasonComposition,
};
use oneiron::llm::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease};
use oneiron::rerank::RerankCandidate;
use oneiron::retrieval_depth::{BackendSpend, DeepSearchBackend, RetrievalResult};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The immutable pre-depth fixture still pins every old error shape. Only the
/// closed catalog's new unit variant is added to the in-memory expectation.
pub(super) fn extend_depth_error_contract(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(values) = object.get_mut("enum").and_then(Value::as_array_mut)
                && values.contains(&json!("BAD_REQUEST"))
                && !values.contains(&json!("DEEP_RETRIEVAL_UNAVAILABLE"))
                && let Some(index) = values.iter().position(|value| value == "MIRROR_NOT_READY")
            {
                values.insert(index + 1, json!("DEEP_RETRIEVAL_UNAVAILABLE"));
            }
            if let Some(variants) = object.get_mut("oneOf").and_then(Value::as_array_mut) {
                let code = |variant: &Value| {
                    variant["properties"]["code"]["const"]
                        .as_str()
                        .or_else(|| variant["properties"]["code"]["enum"][0].as_str())
                        .map(str::to_owned)
                };
                if let Some(index) = variants
                    .iter()
                    .position(|variant| code(variant).as_deref() == Some("MIRROR_NOT_READY"))
                    && !variants.iter().any(|variant| {
                        code(variant).as_deref() == Some("DEEP_RETRIEVAL_UNAVAILABLE")
                    })
                {
                    let mut added = variants
                        .iter()
                        .find(|variant| code(variant).as_deref() == Some("UNAUTHORIZED"))
                        .expect("existing unit variant")
                        .clone();
                    let schema = &mut added["properties"]["code"];
                    if schema.get("const").is_some() {
                        schema["const"] = json!("DEEP_RETRIEVAL_UNAVAILABLE");
                    } else {
                        schema["enum"] = json!(["DEEP_RETRIEVAL_UNAVAILABLE"]);
                    }
                    variants.insert(index + 1, added);
                }
            }
            for child in object.values_mut() {
                extend_depth_error_contract(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                extend_depth_error_contract(child);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn retrieval_quality_depth_search_and_reason_keep_empty_minimal_healthy() {
    let (_dir, server) = test_server();
    for depth in ["minimal", "standard"] {
        let (status, reason) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/companion/memory/reason",
                json!({"query": "absentqualitydepth", "depth": depth}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reason}");
        assert_eq!(reason["quality"], "passthrough");
        assert_eq!(reason["confidenceAdjustment"], -0.35);
        assert!(reason.get("degradation").is_none());
        assert!(reason["sources"].as_array().unwrap().is_empty());
        assert!(!reason["gaps"].as_array().unwrap().is_empty());
        assert_eq!(reason["confidence"], 0.0);
        assert_eq!(reason["tokensUsed"], 0);
        assert_eq!(reason.get("reasoning").is_none(), depth == "minimal");
        let (status, search) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/api/search/text?query=absentqualitydepth&depth={depth}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{search}");
        assert_eq!(search["meta"]["quality"], reason["quality"]);
        assert_eq!(
            search["meta"]["confidenceAdjustment"],
            reason["confidenceAdjustment"]
        );
        assert!(search["meta"].get("degradation").is_none());
    }
}

#[tokio::test]
async fn retrieval_quality_depth_standard_projects_disabled_ppr_without_changing_confidence() {
    let (_dir, server) = test_server();
    seed_text_turn(&server, "qualitydepth retained evidence");
    let (status, reason) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({"query": "qualitydepth", "depth": "standard"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reason}");
    assert_eq!(reason["quality"], "degraded");
    assert_eq!(reason["confidenceAdjustment"], -0.15);
    assert!(reason.get("degradation").is_none());
    assert_eq!(
        reason["confidence"], 1.0,
        "metadata must not adjust structural confidence"
    );
    assert_eq!(reason["tokensUsed"], 0);
    assert_eq!(reason["reasoning"]["signalsUsed"], json!(["text", "ppr"]));
    let (status, search) = route_json(
        server,
        Request::builder()
            .uri("/api/search/text?query=qualitydepth&depth=standard&view=standard")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{search}");
    assert_eq!(search["meta"]["quality"], reason["quality"]);
    assert_eq!(search["meta"]["confidenceAdjustment"], -0.15);
    assert!(search["meta"].get("degradation").is_none());
}

#[tokio::test]
async fn retrieval_quality_depth_minimal_search_keeps_existing_ranked_items() {
    let (_dir, server) = test_server();
    seed_text_turn(&server, "qualitydepth qualitydepth");
    seed_text_turn(&server, "qualitydepth other");
    let scoped = scoped_read_for_legacy_api(&server.vault).unwrap();
    let expected = scoped.search_text("qualitydepth", 11, None).unwrap();
    let expected = search_response(&scoped, expected, View::Standard, 10).unwrap();
    // Apply the same JSON wire roundtrip as route_json before comparing
    // ordered IDs and scores exactly.
    let expected: Value = serde_json::from_slice(&serde_json::to_vec(&expected).unwrap()).unwrap();
    let (status, response) = route_json(
        server.clone(),
        Request::builder()
            .uri("/api/search/text?query=qualitydepth&depth=minimal&view=standard")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["items"], expected);
    assert_eq!(response["meta"]["quality"], "passthrough");
    assert!(response["meta"].get("degradation").is_none());
}

struct DecliningBackend {
    composed: AtomicUsize,
}

impl DeepSearchBackend for DecliningBackend {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        assert!(!lease.id().is_empty());
        Ok(BackendSpend {
            value: Vec::new(),
            tokens_used: 7,
        })
    }
    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
        _token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        assert!(!lease.id().is_empty());
        Ok(BackendSpend {
            value: vec![1.0; candidates.len()],
            tokens_used: 11,
        })
    }
}

impl MemoryReasonBackend for DecliningBackend {
    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        assert!(!lease.id().is_empty());
        assert!(!request.evidence.is_empty());
        self.composed.fetch_add(1, Ordering::SeqCst);
        Ok(BackendSpend {
            value: MemoryReasonComposition {
                answer: "unsupported composition".to_owned(),
                source_short_ids: vec!["not-retrieved:ff".to_owned()],
                confidence: 0.99,
                gaps: vec!["composer gap".to_owned()],
                declined: false,
            },
            tokens_used: 13,
        })
    }
}

#[tokio::test]
async fn retrieval_quality_depth_composition_fallback_keeps_report_and_actual_spend() {
    let (_dir, mut server) = test_server();
    seed_text_turn(&server, "qualitydepth retained evidence");
    let guard = BudgetGuard::with_reserve_units(
        "reason-quality",
        1000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let backend = Arc::new(DecliningBackend {
        composed: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut server).unwrap().deep_retrieval = Some(Arc::new(DeepRetrievalHost::new(
        backend.clone(),
        guard.clone(),
    )));
    for _ in 0..2 {
        let (status, response) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/companion/memory/reason",
                json!({"query": "qualitydepth", "depth": "deep", "format": "plaintext"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["quality"], "degraded");
        assert_eq!(response["confidenceAdjustment"], -0.15);
        assert!(
            response.get("degradation").is_none(),
            "composition is not an embedding timeout or cache miss"
        );
        assert_eq!(response["confidence"], 1.0);
        assert_eq!(response["tokensUsed"], 31);
        assert!(
            response["answer"]
                .as_str()
                .unwrap()
                .contains("retained evidence")
        );
        assert!(
            !response["sources"]
                .as_array()
                .unwrap()
                .contains(&json!("not-retrieved:ff"))
        );
        assert_eq!(response["gaps"].as_array().unwrap().len(), 2);
    }
    assert_eq!(backend.composed.load(Ordering::SeqCst), 2);
    assert_eq!(guard.read().used_units, 62);
    assert_eq!(guard.read().reserved_units, 0);
}

#[tokio::test]
async fn retrieval_quality_depth_unavailable_and_ungrounded_requests_still_refuse() {
    let (_dir, server) = test_server();
    let (status, response) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({"query": "qualitydepth", "depth": "deep"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response["error"]["code"], "DEEP_RETRIEVAL_UNAVAILABLE");
    assert!(response.get("quality").is_none());
    let (status, response) = route_json(
        server.clone(),
        Request::builder()
            .uri("/api/search/text?query=qualitydepth&depth=deep")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response["code"], "DEEP_RETRIEVAL_UNAVAILABLE");
    let (status, response) = route_json(
        server,
        Request::builder()
            .uri("/api/search/vector?query=1,0,0,0&depth=deep&queryText=%20")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["details"]["field"], "queryText");
}

#[test]
fn retrieval_quality_depth_reason_and_search_openapi_keep_shared_wire_names() {
    let spec = generated_spec();
    let schema = openapi_component_schema(&spec, "MemoryReasonResponse");
    for field in ["quality", "degradation", "confidenceAdjustment"] {
        assert!(schema["properties"].get(field).is_some(), "missing {field}");
    }
    assert_eq!(
        schema["properties"]["confidenceAdjustment"]["type"],
        "number"
    );
    assert!(schema["properties"].get("confidence_adjustment").is_none());
    assert!(spec["paths"]["/v1/companion/memory/reason"]["post"].is_object());
    let text = &spec["paths"]["/api/search/text"]["get"]["parameters"];
    let vector = &spec["paths"]["/api/search/vector"]["get"]["parameters"];
    assert!(
        text.as_array()
            .unwrap()
            .iter()
            .any(|parameter| parameter["name"] == "depth")
    );
    assert!(
        !text
            .as_array()
            .unwrap()
            .iter()
            .any(|parameter| parameter["name"] == "queryText")
    );
    assert!(
        vector
            .as_array()
            .unwrap()
            .iter()
            .any(|parameter| parameter["name"] == "queryText")
    );
}

#[tokio::test]
async fn retrieval_quality_depth_reason_requires_read_auth_before_admission() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let body = json!({"query": "qualitydepth", "depth": "deep"});
    let (status, response) = route_json(
        server.clone(),
        json_request("POST", "/v1/companion/memory/reason", body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(response["error"]["code"], "UNAUTHORIZED");
    let (status, response) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/memory/reason",
            "core:write",
            Some(&body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response["error"]["code"], "FORBIDDEN");
    let (status, response) = route_json(
        server,
        core_request(
            "POST",
            "/v1/companion/memory/reason",
            "core:read",
            Some(&body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response["error"]["code"], "DEEP_RETRIEVAL_UNAVAILABLE");
}

#[tokio::test]
async fn retrieval_quality_depth_budget_refusal_does_not_run_backend() {
    let (_dir, mut server) = test_server();
    let guard = BudgetGuard::with_reserve_units(
        "reason-refused-quality",
        0,
        10,
        BudgetExhaustionPolicy::Suspend,
    );
    let backend = Arc::new(DecliningBackend {
        composed: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut server).unwrap().deep_retrieval = Some(Arc::new(DeepRetrievalHost::new(
        backend.clone(),
        guard.clone(),
    )));
    let (status, response) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({"query": "qualitydepth", "depth": "deep"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response["error"]["code"], "DEEP_RETRIEVAL_UNAVAILABLE");
    assert_eq!(backend.composed.load(Ordering::SeqCst), 0);
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 0);
}
