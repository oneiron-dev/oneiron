use super::*;
use crate::api::memory_reason::{
    MemoryReasonBackend, MemoryReasonComposeRequest, MemoryReasonComposition,
};
use oneiron::llm::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease};
use oneiron::rerank::RerankCandidate;
use oneiron::retrieval_depth::{BackendSpend, DeepSearchBackend, RetrievalError, RetrievalResult};
use std::sync::Mutex;

#[derive(Clone, Copy)]
enum FailurePoint {
    FreeDecompose,
    SpentDecompose,
    MalformedRerank,
    SpentRerank,
    FreeCompose,
    SpentCompose,
    AbortedLease,
    AbortedMalformedRerank,
}

struct FailingBackend {
    point: FailurePoint,
    guard: BudgetGuard,
    lease: Mutex<Option<BudgetLease>>,
}

fn spent_error(tokens_used: u64) -> RetrievalError {
    RetrievalError {
        error: oneiron::Error::InvalidConfig("backend spent then failed".to_owned()),
        tokens_used,
    }
}

impl DeepSearchBackend for FailingBackend {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        *self.lease.lock().unwrap() = Some(lease.clone());
        match self.point {
            FailurePoint::FreeDecompose => Err(spent_error(0)),
            FailurePoint::SpentDecompose => Err(spent_error(7)),
            _ => Ok(BackendSpend {
                value: Vec::new(),
                tokens_used: 7,
            }),
        }
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
        _token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        assert!(!candidates.is_empty());
        if matches!(self.point, FailurePoint::SpentRerank) {
            return Err(spent_error(11));
        }
        if matches!(
            self.point,
            FailurePoint::AbortedLease | FailurePoint::AbortedMalformedRerank
        ) {
            self.guard.abort(lease).unwrap();
        }
        Ok(BackendSpend {
            value: if matches!(
                self.point,
                FailurePoint::MalformedRerank | FailurePoint::AbortedMalformedRerank
            ) {
                Vec::new()
            } else {
                vec![1.0; candidates.len()]
            },
            tokens_used: 11,
        })
    }
}

impl MemoryReasonBackend for FailingBackend {
    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        match self.point {
            FailurePoint::FreeCompose => Err(spent_error(0)),
            FailurePoint::SpentCompose => Err(spent_error(13)),
            _ => Ok(BackendSpend {
                value: MemoryReasonComposition {
                    answer: "admitted evidence".to_owned(),
                    source_short_ids: request
                        .evidence
                        .iter()
                        .map(|row| row.short_id.clone())
                        .collect(),
                    confidence: 0.8,
                    gaps: Vec::new(),
                    declined: false,
                },
                tokens_used: 13,
            }),
        }
    }
}

fn failing_server(
    point: FailurePoint,
) -> (tempfile::TempDir, Arc<SyncServer>, Arc<FailingBackend>) {
    let backend = Arc::new(FailingBackend {
        point,
        guard: BudgetGuard::with_reserve_units(
            "failed-depth-api",
            1000,
            100,
            BudgetExhaustionPolicy::Suspend,
        ),
        lease: Mutex::new(None),
    });
    let (dir, server) =
        memory_reason_server_with_guard(Some(backend.clone()), backend.guard.clone());
    (dir, server, backend)
}

fn deep_request(reason: bool) -> Request<Body> {
    if reason {
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({"query": "launch", "depth": "deep"}),
        )
    } else {
        Request::builder()
            .uri("/api/search/text?query=launch&depth=deep")
            .body(Body::empty())
            .unwrap()
    }
}

#[tokio::test]
async fn deep_api_malformed_rerank_and_spent_errors_settle_before_return() {
    for reason in [false, true] {
        for (point, expected) in [
            (FailurePoint::SpentDecompose, 7),
            (FailurePoint::MalformedRerank, 18),
            (FailurePoint::SpentRerank, 18),
        ] {
            let (_dir, server, backend) = failing_server(point);
            // Run twice to pin additive accounting, not an absolute meter.
            for count in 1..=2 {
                let (status, response) = route_json(server.clone(), deep_request(reason)).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
                assert!(response.get("answer").is_none());
                assert!(response.get("items").is_none());
                assert_eq!(backend.guard.read().used_units, expected * count);
                assert_eq!(backend.guard.read().reserved_units, 0);
                let lease = backend.lease.lock().unwrap().clone().unwrap();
                assert!(
                    backend.guard.abort(&lease).is_err(),
                    "spent lease was settled"
                );
            }
        }
    }
}

#[tokio::test]
async fn deep_reason_composition_errors_settle_retrieval_and_error_spend() {
    for (point, expected) in [
        (FailurePoint::FreeCompose, 18),
        (FailurePoint::SpentCompose, 31),
    ] {
        let (_dir, server, backend) = failing_server(point);
        // Retrieval costs 18, leaving only 1 for composition. A failed call's
        // actual usage still counts, even when it exceeds that allowance.
        let (status, response) = route_json(
            server,
            json_request(
                "POST",
                "/v1/companion/memory/reason",
                json!({ "query": "launch", "depth": "deep", "tokenBudget": 19 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{response}");
        assert_eq!(response["error"]["code"], "INTERNAL_SERVER_ERROR");
        assert!(response.get("answer").is_none());
        assert_eq!(backend.guard.read().used_units, expected);
        assert_eq!(backend.guard.read().reserved_units, 0);
        let lease = backend.lease.lock().unwrap().clone().unwrap();
        assert!(backend.guard.abort(&lease).is_err());
    }
}

#[tokio::test]
async fn deep_api_aborted_lease_fails_closed_for_success_and_search_error() {
    for reason in [false, true] {
        for point in [
            FailurePoint::AbortedLease,
            FailurePoint::AbortedMalformedRerank,
        ] {
            let (_dir, server, backend) = failing_server(point);
            let (status, response) = route_json(server, deep_request(reason)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
            let error = if reason {
                &response["error"]
            } else {
                &response
            };
            assert_eq!(error["code"], "DEEP_RETRIEVAL_UNAVAILABLE");
            assert!(response.get("answer").is_none());
            assert!(response.get("items").is_none());
            assert_eq!(backend.guard.read().used_units, 0);
            assert_eq!(backend.guard.read().reserved_units, 0);
        }
    }
}

#[tokio::test]
async fn deep_api_zero_usage_errors_abort_instead_of_settling() {
    for reason in [false, true] {
        let (_dir, server, backend) = failing_server(FailurePoint::FreeDecompose);
        let (status, response) = route_json(server, deep_request(reason)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(backend.guard.read().used_units, 0);
        assert_eq!(backend.guard.read().reserved_units, 0);
        let lease = backend.lease.lock().unwrap().clone().unwrap();
        assert!(
            backend.guard.settle_usage(&lease, 0).is_err(),
            "lease was aborted"
        );
    }
}
