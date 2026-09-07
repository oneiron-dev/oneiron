use super::super::{MemoryReasonComposeRequest, MemoryReasonComposition};
use super::*;
use oneiron::llm::BudgetExhaustionPolicy;
use oneiron::rerank::RerankCandidate;
use oneiron::retrieval_depth::{BackendSpend, RetrievalResult};

struct UncalledBackend;

impl DeepSearchBackend for UncalledBackend {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        panic!("admission-only fixture must not execute a backend")
    }

    fn rerank(
        &self,
        _query: &str,
        _candidates: &[RerankCandidate<'_>],
        _token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        panic!("admission-only fixture must not execute a backend")
    }
}

impl MemoryReasonBackend for UncalledBackend {
    fn compose(
        &self,
        _request: &MemoryReasonComposeRequest<'_>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        panic!("admission-only fixture must not execute a backend")
    }
}

fn guard(name: &str) -> BudgetGuard {
    BudgetGuard::with_reserve_units(name, 100, 10, BudgetExhaustionPolicy::Suspend)
}

fn admission(guard: &BudgetGuard, admitted: BudgetAdmission) -> DeepAdmission {
    DeepAdmission {
        host: Arc::new(DeepRetrievalHost::new(
            Arc::new(UncalledBackend),
            guard.clone(),
        )),
        admission: admitted,
        finalized: Cell::new(false),
        tokens_used: Cell::new(0),
    }
}

#[test]
fn deep_admission_later_evidence_error_settles_prior_usage_once() {
    let guard = guard("later-evidence-error");
    let admission = admission(&guard, guard.admit().unwrap());
    let lease = admission.lease().clone();
    admission.record_usage(7);
    admission.record_usage(11);
    let error = ApiError::internal_server_error("memory reason projection failed");
    // The finalizer must preserve errors from ANY later evidence step, not
    // only a usage-bearing backend error. No storage fault hook is needed.
    assert_eq!(
        admission.finish::<()>(Err(error.clone())).unwrap_err(),
        error
    );
    assert_eq!(guard.read().used_units, 18);
    assert_eq!(guard.read().reserved_units, 0);
    drop(admission);
    assert_eq!(guard.read().used_units, 18);
    assert!(
        guard.abort(&lease).is_err(),
        "spent lease must be settled, not aborted"
    );
}

#[test]
fn deep_admission_missing_lease_blocks_completed_and_spent_error_results() {
    for (tokens, success) in [(0, true), (7, true), (7, false)] {
        let owner = guard("lease-owner");
        let missing = guard("missing-lease-meter");
        // Deliberately mismatched fixture: the host meter has no lease row.
        let admission = admission(&missing, owner.admit().unwrap());
        let lease = admission.lease().clone();
        admission.record_usage(tokens);
        let result = if success {
            Ok(())
        } else {
            Err(ApiError::bad_request("original retrieval error", None))
        };
        let error = admission.finish(result).unwrap_err();
        assert_eq!(
            error.code(),
            crate::error::ErrorCode::DeepRetrievalUnavailable
        );
        assert!(!admission.finalized.get());
        drop(admission);
        assert_eq!(missing.read().used_units, 0);
        assert_eq!(owner.read().reserved_units, 10);
        // Only the owner can clean up the deliberately foreign fixture lease.
        owner.settle_usage(&lease, tokens).unwrap();
    }
}

#[test]
fn deep_admission_aborted_lease_blocks_even_zero_usage_success() {
    for tokens in [0, 7] {
        let guard = guard("aborted-lease");
        let admission = admission(&guard, guard.admit().unwrap());
        guard.abort(admission.lease()).unwrap();
        admission.record_usage(tokens);
        let error = admission.finish(Ok(())).unwrap_err();
        assert_eq!(
            error.code(),
            crate::error::ErrorCode::DeepRetrievalUnavailable
        );
        assert!(!admission.finalized.get());
        drop(admission);
        assert_eq!(guard.read().used_units, 0);
        assert_eq!(guard.read().reserved_units, 0);
    }
}

#[test]
fn deep_admission_drop_settles_spend_and_only_aborts_zero_usage() {
    for tokens in [0, 7] {
        let guard = guard("drop-lease");
        let admission = admission(&guard, guard.admit().unwrap());
        let lease = admission.lease().clone();
        admission.record_usage(tokens);
        drop(admission);
        assert_eq!(guard.read().used_units, tokens);
        assert_eq!(guard.read().reserved_units, 0);
        if tokens == 0 {
            assert!(guard.settle_usage(&lease, 0).is_err());
        } else {
            assert!(guard.abort(&lease).is_err());
        }
    }
}
