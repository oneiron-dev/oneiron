use super::*;
use oneiron::llm::BudgetLease;
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
    token_budgets: Mutex<Vec<Option<u64>>>,
    candidates: Mutex<Vec<oneiron::EntityId>>,
}

impl RecordingReasonBackend {
    fn new(fail_at: Option<FailingStage>) -> Self {
        Self {
            stub: StubReasonBackend::answering("from evidence"),
            fail_at,
            leases: Mutex::new(Vec::new()),
            token_budgets: Mutex::new(Vec::new()),
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
        token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        self.token_budgets.lock().unwrap().push(token_budget);
        self.record(FailingStage::Decompose, lease)?;
        self.stub
            .decompose(query, already_run, max_queries, token_budget, lease)
    }

    fn rerank(
        &self,
        query: &str,
        candidates: &[oneiron::rerank::RerankCandidate<'_>],
        token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        self.token_budgets.lock().unwrap().push(token_budget);
        self.record(FailingStage::Rerank, lease)?;
        *self.candidates.lock().unwrap() =
            candidates.iter().map(|candidate| candidate.id).collect();
        self.stub.rerank(query, candidates, token_budget, lease)
    }
}

impl MemoryReasonBackend for RecordingReasonBackend {
    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        self.token_budgets
            .lock()
            .unwrap()
            .push(Some(request.token_budget));
        self.record(FailingStage::Compose, lease)?;
        self.stub.compose(request, lease)
    }
}

/// Owner-grade variant for `/api/*` reads on authenticated servers.
fn raw_search_request_auth(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, owner_bearer())
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn memory_reason_text_query_text_never_retargets_the_probe() {
    let backend = Arc::new(StubReasonBackend::answering("from evidence"));
    let (_dir, server) = memory_reason_server_auth(Some(backend));
    for depth in ["light", "medium", "high"] {
        let uri = format!("/api/search/text?query=launch&depth={depth}&view=standard");
        let (status, original) =
            route_json_auth(server.clone(), raw_search_request_auth(&uri)).await;
        assert_eq!(status, StatusCode::OK, "{original:?}");
        assert!(!original["items"].as_array().unwrap().is_empty());
        let (status, overridden) = route_json_auth(
            server.clone(),
            raw_search_request_auth(&format!("{uri}&queryText=unindexedbudget")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{overridden:?}");

        let original_items = original["items"].as_array().unwrap();
        let overridden_items = overridden["items"].as_array().unwrap();
        let identities = |items: &[Value]| {
            items
                .iter()
                .map(|item| item["id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            identities(overridden_items),
            identities(original_items),
            "depth={depth}",
        );

        // Scores are comparable only within a response. Compare their ranking
        // relationships rather than absolute scores across separate reads.
        let score_orderings = |items: &[Value]| {
            let scores = items
                .iter()
                .map(|item| item["score"].as_f64().unwrap())
                .collect::<Vec<_>>();
            let mut orderings = Vec::new();
            for left in &scores {
                for right in &scores {
                    orderings.push(left.partial_cmp(right).unwrap());
                }
            }
            orderings
        };
        assert_eq!(
            score_orderings(overridden_items),
            score_orderings(original_items),
            "depth={depth}",
        );
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
async fn memory_reason_session_documents_filter_before_limit_and_rerank() {
    let backend = Arc::new(RecordingReasonBackend::new(None));
    let (_dir, server) = memory_reason_server_auth(Some(backend.clone()));
    let inside = seeded_test_entity_id(0x0207_0001);
    // Scoped search ranks these TURNs by blended BM25 relevance. The outside
    // row is the shorter exact match and the lower ID, so it ranks first and
    // applying limit before session narrowing would lose the inside row.
    let outside = seeded_test_entity_id(0x0207_0000);
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
    let pinned_ref = server.vault.pinned_short_ref(&inside).unwrap();
    let scoped = scoped_read_for_legacy_api(&server).unwrap();
    let unscoped = scoped.search_text("launch", 2, None).unwrap();
    // ONE-2702: a two-row pool z-normalizes relevance to +1 and -1, so the scores are e and 1/e.
    assert_eq!(
        unscoped
            .iter()
            .map(|hit| (hit.id, hit.score))
            .collect::<Vec<_>>(),
        vec![
            (outside, 1.0_f64.exp() as f32),
            (inside, (-1.0_f64).exp() as f32)
        ]
    );
    assert_eq!(
        scoped.search_text("launch", 1, None).unwrap()[0].id,
        outside
    );
    for depth in ["light", "medium", "high"] {
        let (status, body) = route_json_auth(
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
            json!([pinned_ref.clone()]),
            "{depth}: {body:?}"
        );
    }
    assert_eq!(*backend.candidates.lock().unwrap(), vec![inside]);
    let changed =
        rmp_serde::to_vec_named(&json!({"txt": "changed", "spkr": "user", "at": 701_u64})).unwrap();
    server
        .vault
        .batch()
        .put(
            &inside,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 701,
                end: 701,
            },
            701,
            &changed,
        )
        .commit()
        .unwrap();
    // The record scope stamp binds to the TURN's id, not its body bytes: the
    // edit keeps the birth scope, so row authority still admits the pinned
    // revision.
    for path in ["/v1/core/hydrate", "/v1/core/batch/shortId/hydrate"] {
        let batch = path.contains("/batch/");
        let payload = if batch {
            json!({"refs": [pinned_ref.clone()]})
        } else {
            json!({"ref": pinned_ref.clone()})
        };
        let (status, body) =
            route_json_auth(server.clone(), json_request("POST", path, payload)).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body:?}");
        if batch {
            assert_ne!(
                body["results"][0]["result"],
                Value::Null,
                "{path}: {body:?}"
            );
        }
        assert_eq!(body["narrowing"]["suppressed_count"], 0, "{path}: {body:?}");
    }
}
