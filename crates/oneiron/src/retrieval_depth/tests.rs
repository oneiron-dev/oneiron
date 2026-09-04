use super::*;

use std::sync::Mutex;

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
    encode_claim_body,
};
use crate::config::VaultConfig;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with};

const READER: &str = "agent:one-207-reader";

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Three notes: two the direct query matches and one reachable only across
/// the `mentions` edge, so a graph expansion is visible as a hit the direct
/// channel could not have produced.
fn seeded_vault() -> (
    tempfile::TempDir,
    crate::Vault,
    EntityId,
    EntityId,
    EntityId,
) {
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    let anchor = entity(0x21);
    let sibling = entity(0x22);
    let neighbor = entity(0x23);

    vault
        .batch()
        .put(&anchor, ENTITY_TYPE_PERSON, range(1), 1, b"anchor")
        .text(&anchor, &[("body", "launch date decision")])
        .put(&sibling, ENTITY_TYPE_PERSON, range(1), 1, b"sibling")
        .text(&sibling, &[("body", "launch checklist")])
        .put(&neighbor, ENTITY_TYPE_PERSON, range(1), 1, b"neighbor")
        .text(&neighbor, &[("body", "stationery inventory")])
        .edge(&anchor, crate::edge::EdgeKind::Mentions, &neighbor, 1.0)
        .commit()
        .expect("seed notes");

    (dir, vault, anchor, sibling, neighbor)
}

fn text_request(query: &str, effort: Effort) -> DepthSearchRequest<'static> {
    DepthSearchRequest {
        probe: SearchProbe::Text {
            query: query.to_owned(),
        },
        effort,
        limit: 10,
        lease: None,
        backend: None,
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
        lease,
        backend,
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

    fn with_spend(mut self, decompose_tokens: u64, rerank_tokens: u64) -> Self {
        self.decompose_tokens = decompose_tokens;
        self.rerank_tokens = rerank_tokens;
        self
    }

    fn with_rerank_scores(mut self, scores: Vec<f32>) -> Self {
        self.rerank_scores = Some(scores);
        self
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
    ) -> Result<BackendSpend<Vec<String>>> {
        let mut calls = self.calls();
        let round = calls.decompose;
        calls.decompose += 1;
        calls.max_queries_seen.push(max_queries);
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
    ) -> Result<BackendSpend<Vec<f32>>> {
        let mut calls = self.calls();
        calls.rerank += 1;
        calls.candidates_seen = candidates.len();
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

/// A backend that must never be called. It fails the row the moment it runs,
/// which is how "the model-free tiers touch no host" gets proven rather than
/// inferred from a counter after the fact.
struct ForbiddenBackend;

impl DeepSearchBackend for ForbiddenBackend {
    fn decompose(&self, _: &str, _: &[String], _: usize) -> Result<BackendSpend<Vec<String>>> {
        panic!("a model-free tier must not call the deep backend");
    }

    fn rerank(&self, _: &str, _: &[RerankCandidate<'_>]) -> Result<BackendSpend<Vec<f32>>> {
        panic!("a model-free tier must not call the deep backend");
    }
}

// ── The derivation ──────────────────────────────────────────────────────

#[test]
fn deterministic_subqueries_are_pure_deduped_and_capped() {
    let query = "what did we decide about the launch date";
    let first = deterministic_subqueries(query);
    assert_eq!(
        first,
        deterministic_subqueries(query),
        "same query, same fan-out"
    );
    assert!(
        (3..=STANDARD_SUBQUERY_LIMIT).contains(&first.len()),
        "a compound question fans out to 3-4 channels: {first:?}"
    );
    assert_eq!(first[0], query, "the caller's own query leads");
    let mut deduped = first.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        first.len(),
        "no channel runs twice: {first:?}"
    );
    assert!(first.iter().all(|sub| !sub.trim().is_empty()));

    // Nothing to derive: one token, no stop words, so every variant collapses
    // onto the query itself and the tier costs exactly one channel.
    assert_eq!(
        deterministic_subqueries("launch"),
        vec!["launch".to_owned()]
    );
    assert!(deterministic_subqueries("   ").is_empty());

    // Never more than the cap, however long the question.
    let long = deterministic_subqueries("alpha beta gamma delta epsilon zeta eta theta");
    assert!(long.len() <= STANDARD_SUBQUERY_LIMIT, "{long:?}");
}

#[test]
fn deterministic_subqueries_drop_stop_words_and_halve_the_remainder() {
    let subqueries = deterministic_subqueries("what did we decide about the launch date");
    assert!(
        subqueries.iter().any(|sub| sub == "decide launch date"),
        "stop words come out: {subqueries:?}"
    );
    assert!(
        subqueries.iter().any(|sub| sub == "decide launch"),
        "leading half: {subqueries:?}"
    );
    assert!(
        subqueries.iter().any(|sub| sub == "date"),
        "trailing half: {subqueries:?}"
    );
}

// ── Minimal ─────────────────────────────────────────────────────────────

#[test]
fn minimal_runs_one_direct_channel_and_touches_no_host() -> Result<()> {
    let (_dir, vault, anchor, sibling, neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));

    // The host is ATTACHED and still unreachable: minimal must ignore one
    // outright, not merely decline to need one.
    let forbidden = ForbiddenBackend;
    let request = hosted_request(
        "launch",
        Effort::Minimal,
        None,
        Some(&forbidden as &dyn DeepSearchBackend),
    );
    let result = scoped.search_with_effort(&request)?;

    assert_eq!(result.signals_used, vec!["text".to_owned()]);
    assert_eq!(
        result.queries_run,
        vec!["launch".to_owned()],
        "one channel, and it is the caller's own query"
    );
    assert!(!result.backend_used);
    assert_eq!(result.tokens_used, 0);

    let ids = hit_ids(&result);
    assert!(ids.contains(&anchor), "{ids:?}");
    assert!(ids.contains(&sibling), "{ids:?}");
    assert!(
        !ids.contains(&neighbor),
        "minimal must not expand the graph: {ids:?}"
    );
    Ok(())
}

#[test]
fn minimal_returns_exactly_the_actor_keyed_direct_door() -> Result<()> {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));

    let direct = scoped.search_text("launch", 10)?;
    let dialed = scoped.search_with_effort(&text_request("launch", Effort::Minimal))?;
    assert_eq!(
        hit_ids(&dialed),
        ids_of(&direct),
        "the minimal tier IS the existing scoped text door"
    );
    Ok(())
}

// ── Standard ────────────────────────────────────────────────────────────

#[test]
fn standard_expands_one_hop_and_fans_out_deterministically() -> Result<()> {
    let (_dir, vault, anchor, _sibling, neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));

    let forbidden = ForbiddenBackend;
    let request = hosted_request(
        "what did we decide about the launch date",
        Effort::Standard,
        None,
        Some(&forbidden as &dyn DeepSearchBackend),
    );
    let result = scoped.search_with_effort(&request)?;

    assert!(
        result.signals_used.contains(&"ppr".to_owned()),
        "{result:?}"
    );
    assert!(
        result.signals_used.contains(&"subqueries".to_owned()),
        "{result:?}"
    );
    assert!(!result.backend_used, "standard is model-free");
    assert_eq!(result.tokens_used, 0, "standard spends nothing");
    assert_eq!(
        result.queries_run,
        deterministic_subqueries("what did we decide about the launch date"),
        "the tier runs exactly its own derivation, in order"
    );
    assert!(
        (3..=STANDARD_SUBQUERY_LIMIT).contains(&result.queries_run.len()),
        "one direct channel plus its derived siblings: {:?}",
        result.queries_run
    );

    let ids = hit_ids(&result);
    assert!(ids.contains(&anchor), "the direct hit survives: {ids:?}");
    assert!(
        ids.contains(&neighbor),
        "the one-hop neighbor joins: {ids:?}"
    );
    Ok(())
}

#[test]
fn standard_is_reproducible_across_calls() -> Result<()> {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let query = "what did we decide about the launch date";

    let first = scoped.search_with_effort(&text_request(query, Effort::Standard))?;
    let second = scoped.search_with_effort(&text_request(query, Effort::Standard))?;
    assert_eq!(first, second, "a deterministic tier must not drift");
    Ok(())
}

// ── Deep ────────────────────────────────────────────────────────────────

#[test]
fn deep_truncates_and_dedups_an_over_eager_backend() -> Result<()> {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();

    // Eight proposals a round, two of them repeats of the caller's own query:
    // the engine keeps four distinct new ones and stops after two rounds
    // however many more the backend would go on offering.
    let greedy: Vec<String> = [
        "launch",
        "launch",
        "checklist",
        "inventory",
        "decision",
        "date",
        "stationery",
        "anchor",
    ]
    .iter()
    .map(|word| (*word).to_owned())
    .collect();
    let backend =
        ScriptedBackend::new(vec![greedy.clone(), greedy.clone(), greedy.clone(), greedy]);

    let request = hosted_request(
        "launch",
        Effort::Deep,
        Some(&lease),
        Some(&backend as &dyn DeepSearchBackend),
    );
    let result = scoped.search_with_effort(&request)?;
    let standard = scoped.search_with_effort(&text_request("launch", Effort::Standard))?;

    let calls = backend.calls();
    assert_eq!(
        calls.decompose, DEEP_MAX_ROUNDS,
        "the engine stops at its own round cap"
    );
    assert_eq!(calls.rerank, 1, "one cross-encoder pass per read");
    assert!(
        calls
            .max_queries_seen
            .iter()
            .all(|seen| *seen == DEEP_QUERIES_PER_ROUND),
        "the per-round cap is stated to the backend: {:?}",
        calls.max_queries_seen
    );
    drop(calls);

    assert!(result.backend_used);
    assert!(
        result
            .signals_used
            .contains(&"backend_decompose".to_owned()),
        "{result:?}"
    );
    assert!(
        result.signals_used.contains(&"backend_rerank".to_owned()),
        "{result:?}"
    );
    // Round one keeps four of eight proposals and drops the two repeats of
    // the caller's own query; round two has only two proposals left that were
    // not already run. Nothing the backend offered past those survives.
    assert_eq!(
        result.queries_run,
        [
            "launch",
            "checklist",
            "inventory",
            "decision",
            "date",
            "stationery",
            "anchor",
        ]
        .iter()
        .map(|query| (*query).to_owned())
        .collect::<Vec<String>>(),
        "the engine's own truncation and dedupe, visible query by query"
    );
    let deep_only = result.queries_run.len() - standard.queries_run.len();
    assert!(
        deep_only <= DEEP_MAX_ROUNDS * DEEP_QUERIES_PER_ROUND,
        "deep ran {deep_only} extra queries past standard"
    );
    Ok(())
}

#[test]
fn deep_reports_the_summed_backend_spend_not_a_budget() -> Result<()> {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();
    let backend =
        ScriptedBackend::new(vec![vec!["checklist".to_owned()], Vec::new()]).with_spend(7, 11);

    let request = hosted_request(
        "launch",
        Effort::Deep,
        Some(&lease),
        Some(&backend as &dyn DeepSearchBackend),
    );
    let result = scoped.search_with_effort(&request)?;

    let decompose_calls = backend.calls().decompose as u64;
    assert_eq!(
        result.tokens_used,
        7 * decompose_calls + 11,
        "tokens_used is decompose + rerank spend, summed from the backend"
    );
    assert!(result.tokens_used > 0);
    Ok(())
}

#[test]
fn deep_rerank_reorders_without_rewriting_engine_scores() -> Result<()> {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();

    let baseline = scoped.search_with_effort(&text_request("launch", Effort::Standard))?;
    let candidate_count = baseline.hits.len();
    assert!(candidate_count >= 2, "need a ranking to reorder");

    // Ascending scores over the engine order == an exact reversal.
    let backend = ScriptedBackend::new(vec![Vec::new()])
        .with_rerank_scores((0..candidate_count).map(|index| index as f32).collect());
    let request = hosted_request(
        "launch",
        Effort::Deep,
        Some(&lease),
        Some(&backend as &dyn DeepSearchBackend),
    );
    let result = scoped.search_with_effort(&request)?;

    let mut reversed = hit_ids(&baseline);
    reversed.reverse();
    assert_eq!(hit_ids(&result), reversed, "the backend decides the order");
    for hit in &result.hits {
        let engine_score = baseline
            .hits
            .iter()
            .find(|candidate| candidate.id == hit.id)
            .map(|candidate| candidate.score)
            .expect("same candidate set");
        assert_eq!(
            hit.score, engine_score,
            "rerank scores must not leak into the engine score scale"
        );
    }
    Ok(())
}

#[test]
fn deep_refuses_a_rerank_that_does_not_score_every_candidate() {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();
    let backend = ScriptedBackend::new(vec![Vec::new()]).with_rerank_scores(vec![1.0]);

    let request = hosted_request(
        "launch",
        Effort::Deep,
        Some(&lease),
        Some(&backend as &dyn DeepSearchBackend),
    );
    let error = scoped
        .search_with_effort(&request)
        .expect_err("a mis-sized score vector mis-pairs every candidate");
    assert!(
        error.to_string().contains("one score per candidate"),
        "{error}"
    );
}

// ── Refusals ────────────────────────────────────────────────────────────

#[test]
fn deep_without_a_lease_is_the_existing_lease_required_refusal() {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let backend = ScriptedBackend::new(Vec::new());

    let request = hosted_request(
        "launch",
        Effort::Deep,
        None,
        Some(&backend as &dyn DeepSearchBackend),
    );
    let error = scoped
        .search_with_effort(&request)
        .expect_err("deep is lease-gated");
    assert!(
        error.to_string().contains(MEMORY_CODE_LEASE_REQUIRED),
        "the refusal reuses the landed lease vocabulary: {error}"
    );
    assert_eq!(backend.calls().decompose, 0, "no lease, no host call");
}

#[test]
fn deep_without_a_backend_refuses_rather_than_degrading() {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();

    let request = hosted_request("launch", Effort::Deep, Some(&lease), None);
    let error = scoped
        .search_with_effort(&request)
        .expect_err("deep is host-injected only");
    assert!(error.to_string().contains("backend"), "{error}");
}

#[test]
fn deep_vector_without_query_text_refuses() {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();
    let backend = ScriptedBackend::new(Vec::new());
    let embedding = vec![0.0_f32; VaultConfig::default().dimensions];

    let ungrounded = DepthSearchRequest {
        probe: SearchProbe::Vector {
            embedding: embedding.clone(),
            query_text: None,
        },
        effort: Effort::Deep,
        limit: 10,
        lease: Some(&lease),
        backend: Some(&backend),
    };
    let error = scoped
        .search_with_effort(&ungrounded)
        .expect_err("deep decomposition needs the question, not a float vector");
    assert!(error.to_string().contains("query text"), "{error}");
    assert_eq!(backend.calls().decompose, 0, "refused before any host call");

    // The same probe stays open at the tiers that never read the text.
    for effort in [Effort::Minimal, Effort::Standard] {
        let request = DepthSearchRequest {
            probe: SearchProbe::Vector {
                embedding: embedding.clone(),
                query_text: None,
            },
            effort,
            limit: 10,
            lease: None,
            backend: None,
        };
        scoped
            .search_with_effort(&request)
            .unwrap_or_else(|error| panic!("{effort:?} vector search must stay open: {error}"));
    }
}

#[test]
fn every_effort_refuses_a_zero_limit() {
    let (_dir, vault, _anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));

    for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
        let mut request = text_request("launch", effort);
        request.limit = 0;
        let error = scoped
            .search_with_effort(&request)
            .expect_err("a zero-limit read returns nothing and still costs work");
        assert!(
            error.to_string().contains("at least 1"),
            "{effort:?}: {error}"
        );
    }
}

// ── Admission ───────────────────────────────────────────────────────────

/// A claim the actor-keyed door refuses stays refused at EVERY effort,
/// including the deep tier whose extra rounds a host drives. The expansion,
/// the fan-out and the backend's own queries all run through the same
/// admitted channels, so no tier can be dialed into a read that minimal would
/// not have allowed.
#[test]
fn no_effort_widens_what_the_actor_keyed_door_admits() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
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
    );
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

    for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
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

#[test]
fn session_scope_only_ever_narrows() -> Result<()> {
    let (_dir, vault, anchor, _sibling, _neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let wide = scoped.search_with_effort(&text_request("launch", Effort::Standard))?;
    assert!(wide.hits.len() >= 2, "need something to narrow");

    // The empty scope is a no-op: never a widening, and never a wipe.
    let unchanged = narrow_to_session_scope(&scoped, wide.hits.clone(), &SessionScope::default())?;
    assert_eq!(unchanged, wide.hits);

    let scope = SessionScope {
        document_short_ids: vec![short_ref_or_hex(&vault, &anchor)?],
        ..SessionScope::default()
    };
    let narrowed = narrow_to_session_scope(&scoped, wide.hits.clone(), &scope)?;
    assert_eq!(ids_of(&narrowed), vec![anchor]);
    assert!(
        narrowed.len() < wide.hits.len(),
        "a document scope removes hits"
    );

    // A scope naming something outside the result set narrows to nothing; it
    // cannot pull that something in.
    let absent = SessionScope {
        document_short_ids: vec!["no-such-short-id".to_owned()],
        ..SessionScope::default()
    };
    assert!(narrow_to_session_scope(&scoped, wide.hits.clone(), &absent)?.is_empty());

    let unknown_world = SessionScope {
        world_ref: Some(entity(0x51)),
        ..SessionScope::default()
    };
    assert!(narrow_to_session_scope(&scoped, wide.hits, &unknown_world)?.is_empty());
    Ok(())
}
