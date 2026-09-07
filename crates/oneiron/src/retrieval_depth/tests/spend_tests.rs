use super::*;

#[derive(Clone, Copy)]
enum FailurePoint {
    FirstDecompose,
    SecondDecompose,
    Rerank,
    MalformedRerank,
}

struct FailingBackend {
    point: FailurePoint,
    first_spend: u64,
}

impl DeepSearchBackend for FailingBackend {
    fn decompose(
        &self,
        _query: &str,
        already_run: &[String],
        _max_queries: usize,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        if matches!(self.point, FailurePoint::FirstDecompose)
            || (matches!(self.point, FailurePoint::SecondDecompose)
                && already_run.iter().any(|query| query == "laterqualitydepth"))
        {
            return Err(RetrievalError {
                error: Error::InvalidConfig("decompose spent then failed".to_owned()),
                tokens_used: 5,
            });
        }
        Ok(BackendSpend {
            value: if matches!(self.point, FailurePoint::SecondDecompose) {
                vec!["laterqualitydepth".to_owned()]
            } else {
                Vec::new()
            },
            tokens_used: self.first_spend,
        })
    }

    fn rerank(
        &self,
        _query: &str,
        _candidates: &[RerankCandidate<'_>],
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        if matches!(self.point, FailurePoint::MalformedRerank) {
            return Ok(BackendSpend {
                value: Vec::new(),
                tokens_used: 5,
            });
        }
        Err(RetrievalError {
            error: Error::InvalidConfig("rerank spent then failed".to_owned()),
            tokens_used: 5,
        })
    }
}

fn failed_read(point: FailurePoint, first_spend: u64) -> RetrievalError {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    put_text(&vault, 0x71, "qualitydepth laterqualitydepth").unwrap();
    let scoped = vault.scoped_read(ScopedReadActorKey::new("spend-reader").unwrap());
    let guard =
        BudgetGuard::with_reserve_units("failed-depth", 100, 10, BudgetExhaustionPolicy::Suspend);
    let admission = guard.admit().unwrap();
    let backend = FailingBackend { point, first_spend };
    let mut request = text_request(Effort::Deep);
    request.lease = Some(&admission.lease);
    request.backend = Some(&backend);
    let failure = scoped.search_with_effort(&request).unwrap_err();
    guard
        .settle_usage(&admission.lease, failure.tokens_used)
        .unwrap();
    assert_eq!(guard.read().used_units, failure.tokens_used);
    assert_eq!(guard.read().reserved_units, 0);
    failure
}

#[test]
fn deep_malformed_rerank_retains_decompose_and_rerank_spend() {
    let failure = failed_read(FailurePoint::MalformedRerank, 3);
    assert_eq!(failure.tokens_used, 8);
    assert!(
        failure
            .error
            .to_string()
            .contains("one score per candidate")
    );
}

#[test]
fn deep_spent_backend_errors_retain_prior_calls() {
    for (point, expected) in [
        (FailurePoint::FirstDecompose, 5),
        (FailurePoint::SecondDecompose, 8),
        (FailurePoint::Rerank, 8),
    ] {
        let failure = failed_read(point, 3);
        assert_eq!(failure.tokens_used, expected);
        assert!(failure.error.to_string().contains("spent then failed"));
    }
}

#[test]
fn deep_error_spend_saturates_without_wrapping() {
    let failure = failed_read(FailurePoint::Rerank, u64::MAX);
    assert_eq!(failure.tokens_used, u64::MAX);
}

struct CorruptScopeAfterDecompose<'a> {
    vault: &'a Vault,
    id: EntityId,
}

impl DeepSearchBackend for CorruptScopeAfterDecompose<'_> {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        // Fault only after successful initial scope/channel reads. The next
        // session-narrowing lookup fails on a malformed short-id row.
        let mut txn = self.vault.store.env.write_txn().unwrap();
        self.vault
            .store
            .short_ids_reverse
            .put(&mut txn, self.id.as_bytes(), &[0xff])
            .unwrap();
        txn.commit().unwrap();
        Ok(BackendSpend {
            value: vec!["laterqualitydepth".to_owned()],
            tokens_used: 7,
        })
    }

    fn rerank(
        &self,
        _query: &str,
        _candidates: &[RerankCandidate<'_>],
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        panic!("scope failure must stop before rerank")
    }
}

#[test]
fn deep_narrowing_error_after_decompose_retains_spend() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let id = put_text(&vault, 0x72, "qualitydepth laterqualitydepth").unwrap();
    let scope = SessionScope {
        document_short_ids: vec![short_ref_or_hex(&vault, &id).unwrap()],
        ..Default::default()
    };
    let scoped = vault.scoped_read(ScopedReadActorKey::new("spend-reader").unwrap());
    let guard = BudgetGuard::with_reserve_units(
        "scope-error-depth",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
    );
    let admission = guard.admit().unwrap();
    let backend = CorruptScopeAfterDecompose { vault: &vault, id };
    let mut request = text_request(Effort::Deep);
    request.lease = Some(&admission.lease);
    request.backend = Some(&backend);
    request.session_scope = Some(&scope);
    let failure = scoped.search_with_effort(&request).unwrap_err();
    assert_eq!(failure.tokens_used, 7);
    assert!(failure.error.to_string().contains("short id value"));
    guard
        .settle_usage(&admission.lease, failure.tokens_used)
        .unwrap();
    assert_eq!(guard.read().used_units, 7);
    assert_eq!(guard.read().reserved_units, 0);
}
