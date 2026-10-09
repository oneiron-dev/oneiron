use super::*;

mod repairs;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

use std::sync::Mutex;

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
    encode_claim_body,
};
use crate::config::VaultConfig;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::test_util::{authorize_readers, entity, open_test_vault_with};

const READER: &str = "agent:one-207-reader";

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn text_request(query: &str, effort: Effort) -> DepthSearchRequest<'static> {
    DepthSearchRequest {
        probe: SearchProbe::Text {
            query: query.to_owned(),
        },
        effort,
        limit: 10,
        session_scope: None,
        lease: None,
        backend: None,
        deadline: None,
        token_budget: None,
    }
}

fn hosted_request<'a>(
    query: &str,
    effort: Effort,
    lease: Option<&'a BudgetLease>,
    backend: Option<&'a dyn DeepSearchBackend>,
) -> DepthSearchRequest<'a> {
    DepthSearchRequest {
        probe: SearchProbe::Text {
            query: query.to_owned(),
        },
        effort,
        limit: 10,
        session_scope: None,
        lease,
        backend,
        deadline: None,
        token_budget: None,
    }
}

fn hit_ids(result: &DepthSearchResult) -> Vec<EntityId> {
    ids_of(&result.hits)
}

fn ids_of(hits: &[ScoredEntity]) -> Vec<EntityId> {
    hits.iter().map(|hit| hit.id).collect()
}

/// A lease from the ONE mint path. Deep effort must never be reachable
/// through a hand-rolled token, so these rows take the door production takes.
fn minted_lease() -> BudgetLease {
    BudgetGuard::new("one-207-tests", 10_000, BudgetExhaustionPolicy::Suspend)
        .admit()
        .expect("budget admits the deep read")
        .lease
}

#[derive(Default)]
struct BackendCalls {
    decompose: usize,
    rerank: usize,
    max_queries_seen: Vec<usize>,
    candidates_seen: usize,
    leases_seen: Vec<BudgetLease>,
    token_budgets_seen: Vec<Option<u64>>,
    candidate_ids: Vec<EntityId>,
}

/// A host backend that records what the engine asked for and answers with
/// whatever the row scripted — including deliberately over-eager output, so
/// the caps can be watched being applied BY THE ENGINE rather than by the
/// backend's own good behavior.
struct ScriptedBackend {
    rounds: Vec<Vec<String>>,
    decompose_tokens: u64,
    rerank_tokens: u64,
    rerank_scores: Option<Vec<f32>>,
    calls: Mutex<BackendCalls>,
}

impl ScriptedBackend {
    fn new(rounds: Vec<Vec<String>>) -> Self {
        Self {
            rounds,
            decompose_tokens: 0,
            rerank_tokens: 0,
            rerank_scores: None,
            calls: Mutex::new(BackendCalls::default()),
        }
    }

    fn calls(&self) -> std::sync::MutexGuard<'_, BackendCalls> {
        self.calls.lock().expect("backend call log")
    }
}

impl DeepSearchBackend for ScriptedBackend {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        max_queries: usize,
        token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        let mut calls = self.calls();
        let round = calls.decompose;
        calls.decompose += 1;
        calls.max_queries_seen.push(max_queries);
        calls.leases_seen.push(lease.clone());
        calls.token_budgets_seen.push(token_budget);
        drop(calls);
        Ok(BackendSpend {
            value: self.rounds.get(round).cloned().unwrap_or_default(),
            tokens_used: self.decompose_tokens,
        })
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        let mut calls = self.calls();
        calls.rerank += 1;
        calls.candidates_seen = candidates.len();
        calls.candidate_ids = candidates.iter().map(|candidate| candidate.id).collect();
        calls.leases_seen.push(lease.clone());
        calls.token_budgets_seen.push(token_budget);
        drop(calls);
        let value = self
            .rerank_scores
            .clone()
            .unwrap_or_else(|| vec![0.0; candidates.len()]);
        Ok(BackendSpend {
            value,
            tokens_used: self.rerank_tokens,
        })
    }
}

// ── Admission ───────────────────────────────────────────────────────────

/// A claim the actor-keyed door refuses stays refused at EVERY effort,
/// including the deep tier whose extra rounds a host drives. The expansion,
/// the fan-out and the backend's own queries all run through the same
/// admitted channels, so no tier can be dialed into a read that minimal would
/// not have allowed.
#[test]
fn no_effort_widens_what_the_actor_keyed_door_admits() -> TestResult {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    authorize_readers(&vault, &[READER]);
    let subject = entity(0x31);
    let surfaceable = entity(0x32);
    let withheld = entity(0x33);
    let text = "quarterly ledger reconciliation";

    let mut body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(subject),
        Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    let open = encode_claim_body(&body)?;
    body.approval = ClaimApprovalStatus::Proposed;
    let closed = encode_claim_body(&body)?;

    vault
        .batch()
        .put_replicated(&surfaceable, ENTITY_TYPE_CLAIM, range(1), 1, &open)
        .text(&surfaceable, &[("body", text)])
        .put_replicated(&withheld, ENTITY_TYPE_CLAIM, range(1), 1, &closed)
        .text(&withheld, &[("body", text)])
        .edge(
            &surfaceable,
            crate::edge::EdgeKind::Mentions,
            &withheld,
            1.0,
        )
        .commit()?;

    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();
    // A host that keeps asking for exactly the withheld claim's own text.
    let backend = ScriptedBackend::new(vec![vec![text.to_owned()], vec!["ledger".to_owned()]]);

    for effort in [
        Effort::Light,
        Effort::Medium,
        Effort::High,
        Effort::Xhigh,
        Effort::Max,
    ] {
        let request = hosted_request(
            text,
            effort,
            Some(&lease),
            Some(&backend as &dyn DeepSearchBackend),
        );
        let ids = hit_ids(&scoped.search_with_effort(&request)?);
        assert!(
            ids.contains(&surfaceable),
            "{effort:?} must still return the admitted claim: {ids:?}"
        );
        assert!(
            !ids.contains(&withheld),
            "{effort:?} must not surface a claim the door refuses: {ids:?}"
        );
    }
    Ok(())
}
