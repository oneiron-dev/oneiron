use super::*;
use oneiron::llm::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease};
use oneiron::retrieval_depth::{BackendSpend, DeepSearchBackend, RetrievalResult};
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailingStage {
    Decompose,
    Rerank,
    Compose,
}

struct RecordingReasonBackend {
    stub: StubReasonBackend,
    fail_at: Option<FailingStage>,
    leases: Mutex<Vec<BudgetLease>>,
    candidates: Mutex<Vec<oneiron::EntityId>>,
}

impl RecordingReasonBackend {
    fn new(fail_at: Option<FailingStage>) -> Self {
        Self {
            stub: StubReasonBackend::answering("from evidence"),
            fail_at,
            leases: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, stage: FailingStage, lease: &BudgetLease) -> oneiron::Result<()> {
        self.leases.lock().unwrap().push(lease.clone());
        if self.fail_at == Some(stage) {
            return Err(oneiron::Error::InvalidConfig(
                "scripted backend failure".to_owned(),
            ));
        }
        Ok(())
    }
}

impl DeepSearchBackend for RecordingReasonBackend {
    fn decompose(
        &self,
        query: &str,
        already_run: &[String],
        max_queries: usize,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        self.record(FailingStage::Decompose, lease)?;
        self.stub.decompose(query, already_run, max_queries, lease)
    }

    fn rerank(
        &self,
        query: &str,
        candidates: &[oneiron::rerank::RerankCandidate<'_>],
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        self.record(FailingStage::Rerank, lease)?;
        *self.candidates.lock().unwrap() =
            candidates.iter().map(|candidate| candidate.id).collect();
        self.stub.rerank(query, candidates, lease)
    }
}

impl MemoryReasonBackend for RecordingReasonBackend {
    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        self.record(FailingStage::Compose, lease)?;
        self.stub.compose(request, lease)
    }
}

fn repair_guard(limit: u64, reserve: u64) -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "memory-reason-repairs",
        limit,
        reserve,
        BudgetExhaustionPolicy::Suspend,
    )
}

fn raw_search_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn memory_reason_text_query_text_never_retargets_the_probe() {
    let backend = Arc::new(StubReasonBackend::answering("from evidence"));
    let (_dir, server) = memory_reason_server(Some(backend));
    for depth in ["minimal", "standard", "deep"] {
        let uri = format!("/api/search/text?query=launch&depth={depth}&view=standard");
        let (status, original) = route_json(server.clone(), raw_search_request(&uri)).await;
        assert_eq!(status, StatusCode::OK, "{original:?}");
        assert!(!original["items"].as_array().unwrap().is_empty());
        let (status, overridden) = route_json(
            server.clone(),
            raw_search_request(&format!("{uri}&queryText=unindexedbudget")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{overridden:?}");
        assert_eq!(overridden, original, "depth={depth}");
    }
    let spec = generated_spec();
    let parameters = spec["paths"]["/api/search/text"]["get"]["parameters"]
        .as_array()
        .unwrap();
    assert!(
        parameters
            .iter()
            .all(|parameter| parameter["name"] != "queryText")
    );
}

#[tokio::test]
async fn memory_reason_standard_vector_query_text_is_not_a_lexical_probe() {
    let (_dir, server) = memory_reason_server(None);
    let probe = vec!["0.1"; oneiron::VaultConfig::device().dimensions].join(",");
    let uri = format!("/api/search/vector?query={probe}&depth=standard&view=standard");
    let (status, original) = route_json(server.clone(), raw_search_request(&uri)).await;
    assert_eq!(status, StatusCode::OK, "{original:?}");
    assert!(original["items"].as_array().unwrap().is_empty());
    let (status, grounded) = route_json(
        server,
        raw_search_request(&format!("{uri}&queryText=launch%20date")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grounded:?}");
    assert_eq!(grounded, original);
}

#[tokio::test]
async fn memory_reason_deep_usage_accumulates_and_one_lease_reaches_all_stages() {
    let guard = repair_guard(34, 17);
    let backend = Arc::new(RecordingReasonBackend::new(None));
    let (_dir, server) = memory_reason_server_with_guard(Some(backend.clone()), guard.clone());
    for expected_used in [17, 34] {
        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/companion/memory/reason",
                json!({ "query": "launch", "depth": "deep", "tokenBudget": 1 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(body["tokensUsed"], Value::from(17));
        assert_eq!(guard.read().used_units, expected_used);
        assert_eq!(guard.read().reserved_units, 0);
    }
    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch", "depth": "deep" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body:?}");
    let leases = backend.leases.lock().unwrap();
    assert_eq!(leases.len(), 6);
    for call in leases.chunks_exact(3) {
        assert_eq!(call[0], call[1]);
        assert_eq!(call[1], call[2]);
    }
    assert_ne!(leases[0], leases[3]);
}

#[tokio::test]
async fn memory_reason_backend_errors_release_each_admitted_reservation() {
    for stage in [
        FailingStage::Decompose,
        FailingStage::Rerank,
        FailingStage::Compose,
    ] {
        let guard = repair_guard(100, 17);
        let backend = Arc::new(RecordingReasonBackend::new(Some(stage)));
        let (_dir, server) = memory_reason_server_with_guard(Some(backend.clone()), guard.clone());
        let per_read_usage = match stage {
            FailingStage::Decompose => 0,
            FailingStage::Rerank => 3,
            FailingStage::Compose => 8,
        };
        for count in 1..=3 {
            let (status, body) = route_json(
                server.clone(),
                json_request(
                    "POST",
                    "/v1/companion/memory/reason",
                    json!({ "query": "launch", "depth": "deep" }),
                ),
            )
            .await;
            let expected = if stage == FailingStage::Compose {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            assert_eq!(status, expected, "{body:?}");
            assert_eq!(guard.read().used_units, per_read_usage * count);
            assert_eq!(guard.read().reserved_units, 0);
            let next = guard.admit().expect("failed request released its lease");
            guard.abort(&next.lease).unwrap();
        }
        assert!(!backend.leases.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn memory_reason_raw_search_errors_and_zero_pages_release_reservations() {
    let guard = repair_guard(17, 17);
    let backend = Arc::new(RecordingReasonBackend::new(None));
    let (_dir, server) = memory_reason_server_with_guard(Some(backend.clone()), guard.clone());
    for _ in 0..3 {
        for (uri, expected) in [
            (
                "/api/search/vector?query=0.1,0.2&depth=deep&queryText=launch",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                "/api/search/text?query=launch&depth=deep&limit=0&countMode=none",
                StatusCode::OK,
            ),
        ] {
            let (status, body) = route_json(server.clone(), raw_search_request(uri)).await;
            assert_eq!(status, expected, "{uri}: {body:?}");
            assert_eq!(guard.read().reserved_units, 0);
        }
    }
    assert!(backend.leases.lock().unwrap().is_empty());
    // A real deep read still fits after errors and empty pages.
    let (status, body) = route_json(
        server,
        raw_search_request("/api/search/text?query=launch&depth=deep&view=standard"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(guard.read().used_units, 8);
}

#[tokio::test]
async fn memory_reason_session_documents_filter_before_limit_and_rerank() {
    let backend = Arc::new(RecordingReasonBackend::new(None));
    let (_dir, server) = memory_reason_server(Some(backend.clone()));
    let inside = seeded_test_entity_id(0x0207_0001);
    let outside = seeded_test_entity_id(0x0207_0002);
    let body = rmp_serde::to_vec_named(&json!({
        "txt": "launch", "spkr": "user", "at": 701_u64
    }))
    .unwrap();
    server
        .vault
        .batch()
        .put(
            &outside,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 701,
                end: 701,
            },
            701,
            &body,
        )
        .text(&outside, &[("body", "launch")])
        .commit()
        .unwrap();
    let short_id = oneiron::retrieval_depth::short_ref_or_hex(&server.vault, &inside).unwrap();
    let scoped = scoped_read_for_legacy_api(&server.vault).unwrap();
    assert_eq!(scoped.search_text("launch", 1, None).unwrap()[0].id, outside);
    for depth in ["minimal", "standard", "deep"] {
        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/companion/memory/reason",
                json!({
                    "query": "launch", "depth": depth, "limit": 1,
                    "sessionContext": { "documentShortIds": [short_id.clone()] }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(
            body["sources"],
            json!([short_id.clone()]),
            "{depth}: {body:?}"
        );
    }
    assert_eq!(*backend.candidates.lock().unwrap(), vec![inside]);
}
