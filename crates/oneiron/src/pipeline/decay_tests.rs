//! ONE-1402 · read-side memory decay at the pipeline seam.
//!
//! The owning module for the retrieval-side `access_factor` contract: decay
//! is a post-fusion surfacing multiplier that lands EXACTLY ONCE, changes
//! rank and never survival, never shapes graph expansion pre-fusion, never
//! migrates between candidates across a rerank, and never writes a byte.
//! Class arithmetic itself belongs to `claim::decay` and is pinned in
//! `claim::tests`; everything here is the pipeline behavior around it.

use std::collections::HashMap;

use super::ScoredEntity;
use super::tests::{
    approx_eq, captured_retrieval_trace, entity_id, open_test_vault, put_claim_text,
    put_status_claim, to_score_map,
};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::query_expansion::{
    CompletionRequest, EvidenceVerdict, GroundingContext, HydeExpander, HydeExpansion, HydeOptions,
    HydeRequest,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::rerank::{RerankCandidate, RerankOptions, Reranker};
use crate::store::{RetrievalSignal, RetrievalTrace};
use crate::temporal::TimeRange;

const DECAY_NOW: u64 = 1_700_000_000;
const DECAY_DAY_SECS: u64 = 86_400;
const DECAY_UNION_TEXT: &str = "decayunionneedle";
const DECAY_UNION_PHONETIC: &str = "TKNTL";
const DECAY_UNION_VECTOR: [f32; 4] = [0.9, 0.1, 0.0, 0.0];

/// A surfaceable CLAIM body whose only decay-relevant inputs are its
/// predicate root and its validity window; `learned_at` rides the entity
/// row header, so the caller picks the age.
fn decay_claim_body(predicate: &str, valid_to: Option<u64>) -> Result<Vec<u8>> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(entity_id(0x5A)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_to = valid_to;
    crate::claim::encode_claim_body(&body)
}

/// Every entity row and both edge directions, byte for byte: the stored
/// truth a retrieval must leave exactly as it was written. Telemetry rows
/// live in other tables and are deliberately outside this snapshot.
fn stored_entity_and_edge_bytes(vault: &Vault) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for db in [
        &vault.store.entities,
        &vault.store.edges_out,
        &vault.store.edges_in,
    ] {
        for entry in db.iter(&rtxn)? {
            let (key, value) = entry?;
            rows.push((key.into_owned(), value.into_owned()));
        }
    }
    Ok(rows)
}

/// A HyDE host that forces exactly one widened retry: the first evidence
/// assessment is insufficient and the second is sufficient, so the retry
/// attempt's extra text-query list joins the fused union alongside the
/// HyDE probe list.
struct RetryOnceHyde {
    embedding: Vec<f32>,
    subqueries: Vec<String>,
    assess_calls: std::sync::atomic::AtomicUsize,
}

impl HydeExpander for RetryOnceHyde {
    fn id(&self) -> &str {
        "test/hyde-retry-once"
    }
    fn expand(&self, request: &HydeRequest) -> Result<HydeExpansion> {
        Ok(HydeExpansion {
            grounded_query: request.query.clone(),
            hypothetical_answer: String::new(),
            embedding: self.embedding.clone(),
            subqueries: self.subqueries.clone(),
        })
    }
    fn assess_evidence(&self, _: &CompletionRequest) -> Result<EvidenceVerdict> {
        let previous = self
            .assess_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(if previous == 0 {
            EvidenceVerdict::Insufficient {
                gaps: vec!["gap".into()],
            }
        } else {
            EvidenceVerdict::Sufficient
        })
    }
}

/// One frozen-clock retrieval over every ranked list the engine can build:
/// vector, HyDE probe, text, HyDE retry, phonetic, temporal and PPR.
fn decay_union_run(
    vault: &Vault,
    seed: EntityId,
    overrides: Option<&HashMap<EntityId, f32>>,
) -> Result<(Vec<ScoredEntity>, RetrievalTrace)> {
    let host = RetryOnceHyde {
        embedding: DECAY_UNION_VECTOR.to_vec(),
        subqueries: vec![DECAY_UNION_TEXT.to_owned()],
        assess_calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let mut builder = vault
        .query()
        .search_text(DECAY_UNION_TEXT, 10)
        .search_vector(&DECAY_UNION_VECTOR, 10)
        .search_phonetic(&[DECAY_UNION_PHONETIC])
        .search_temporal(DECAY_NOW - 100, DECAY_NOW + 100, 10)
        .search_ppr(&[seed], 2)
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: true,
            },
        )
        .with_temporal_now(DECAY_NOW)
        .capture_retrieval_trace(true);
    if let Some(overrides) = overrides {
        builder = builder.with_access_factor_overrides(overrides);
    }

    let results = builder.run_with_telemetry()?;
    let run_id = results
        .run_id
        .ok_or(Error::InvariantViolation("decay union run id"))?;
    let trace = vault
        .retrieval_run(run_id)?
        .ok_or(Error::InvariantViolation("decay union run"))?
        .trace
        .ok_or(Error::InvariantViolation("decay union trace"))?;
    Ok((results.value, trace))
}

// ── the ONE-1402 contract ───────────────────────────────────────────────

/// Done-mean 1 — the read-side factor is a surfacing multiplier applied
/// EXACTLY ONCE after the fused blend, over the full union of every ranked
/// list (both HyDE lists included). The decayed claim keeps its undecayed
/// score times the factor — never the factor squared — and sinks to last,
/// while every candidate the decay did not touch keeps a bit-identical
/// score and the result set keeps its size: rank changes, never survival.
#[test]
fn access_factor_applied_post_fusion() -> Result<()> {
    const OVERRIDE: f32 = 0.25;

    let (_dir, vault) = open_test_vault();
    let decayed = entity_id(0x41);
    let control = entity_id(0x43);
    let seed = entity_id(0x44);
    let span = TimeRange {
        start: DECAY_NOW,
        end: DECAY_NOW,
    };
    let body = decay_claim_body("test.decay_union", None)?;

    vault
        .batch()
        .put(&seed, ENTITY_TYPE_TURN, span, DECAY_NOW, b"payload")
        .put(&decayed, ENTITY_TYPE_CLAIM, span, DECAY_NOW, &body)
        .text(&decayed, &[("body", DECAY_UNION_TEXT)])
        .vector(&decayed, &DECAY_UNION_VECTOR)
        .phonetic(&decayed, &[DECAY_UNION_PHONETIC])
        .put(&control, ENTITY_TYPE_CLAIM, span, DECAY_NOW, &body)
        .text(&control, &[("body", DECAY_UNION_TEXT)])
        .vector(&control, &DECAY_UNION_VECTOR)
        .phonetic(&control, &[DECAY_UNION_PHONETIC])
        .edge(&seed, EdgeKind::Supports, &decayed, 0.9)
        .edge(&seed, EdgeKind::Supports, &control, 0.9)
        .commit()?;

    let (baseline, trace) = decay_union_run(&vault, seed, None)?;
    let channels: Vec<RetrievalSignal> = trace
        .per_channel
        .iter()
        .map(|channel| channel.signal)
        .collect();
    for signal in [
        RetrievalSignal::Vector,
        RetrievalSignal::Hyde,
        RetrievalSignal::Text,
        RetrievalSignal::HydeRetry,
        RetrievalSignal::Phonetic,
        RetrievalSignal::Temporal,
        RetrievalSignal::Ppr,
    ] {
        assert!(
            channels.contains(&signal),
            "the fused union must carry {signal:?}; got {channels:?}"
        );
    }

    let overrides = HashMap::from([(decayed, OVERRIDE)]);
    let (decayed_run, _) = decay_union_run(&vault, seed, Some(&overrides))?;

    let before = to_score_map(&baseline);
    let after = to_score_map(&decayed_run);
    assert!(
        before.contains_key(&control),
        "the fixture must fuse both claims; got {before:?}"
    );

    let expected = before[&decayed] * OVERRIDE;
    assert!(
        approx_eq(after[&decayed], expected, 1e-6),
        "expected {expected} after one application, got {}",
        after[&decayed]
    );
    assert!(
        !approx_eq(after[&decayed], expected * OVERRIDE, 1e-6),
        "the factor must land once, not once per blend stage"
    );

    for (id, score) in &before {
        if *id != decayed {
            assert_eq!(
                after.get(id),
                Some(score),
                "a candidate the decay did not name must keep its exact score"
            );
        }
    }
    assert_eq!(
        before.len(),
        after.len(),
        "decay changes rank, never survival"
    );

    assert_eq!(
        baseline.first().map(|scored| scored.id),
        Some(decayed),
        "undecayed candidates tie and order by id, so the decayed claim leads"
    );
    assert_eq!(
        decayed_run.last().map(|scored| scored.id),
        Some(decayed),
        "the decayed claim must sink below every undecayed candidate"
    );
    Ok(())
}

/// Done-mean 4 — a demoted fact's retrievability drops while its stored
/// truth does not move. Demonstrated via validity expiry (`valid_to <=
/// now`), the only demotion the D19 gate still lets through: the claim
/// stays listed with factor `0.0` and the raw entity and edge bytes are
/// identical before and after the retrieval.
#[test]
fn truth_unchanged_on_decay() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let expired = entity_id(0x51);
    let live = entity_id(0x52);
    let subject = entity_id(0x53);
    let span = TimeRange {
        start: DECAY_NOW,
        end: DECAY_NOW,
    };

    vault
        .batch()
        .put(&subject, ENTITY_TYPE_TURN, span, DECAY_NOW, b"payload")
        .put(
            &expired,
            ENTITY_TYPE_CLAIM,
            span,
            DECAY_NOW,
            &decay_claim_body("test.truth_decay", Some(DECAY_NOW))?,
        )
        .text(&expired, &[("body", "truthneedle")])
        .put(
            &live,
            ENTITY_TYPE_CLAIM,
            span,
            DECAY_NOW,
            &decay_claim_body("test.truth_decay", None)?,
        )
        .text(&live, &[("body", "truthneedle")])
        .edge(&subject, EdgeKind::Supports, &expired, 0.8)
        .commit()?;

    let before = stored_entity_and_edge_bytes(&vault)?;
    let results = vault
        .query()
        .search_text("truthneedle", 10)
        .with_temporal_now(DECAY_NOW)
        .run()?;
    let after = stored_entity_and_edge_bytes(&vault)?;

    assert_eq!(
        before, after,
        "retrieval must not rewrite a single claim or edge byte"
    );

    let scores = to_score_map(&results);
    assert!(
        scores.contains_key(&expired),
        "an expired but Active claim still passes the D19 gate and stays listed"
    );
    assert_eq!(
        scores[&expired], 0.0,
        "an expired claim's retrievability drops to zero"
    );
    assert!(
        approx_eq(scores[&live], 1.0, 1e-6),
        "the unexpired sibling keeps its undecayed score"
    );
    assert_eq!(
        results.last().map(|scored| scored.id),
        Some(expired),
        "the expired claim is demoted in rank, not deleted"
    );
    Ok(())
}

/// Done-mean 5 — retrieval is a pure read: repeating the same frozen-clock
/// query returns identical scores and leaves the entity and edge bytes
/// identical every time. No access timestamp, no bump counter, no
/// self-amplifying read loop. The aged claim also pins the class formula
/// end to end: exactly one Standard half-life halves its factor to 0.5.
#[test]
fn no_read_bump_loop() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let aged = entity_id(0x61);
    let neighbor = entity_id(0x62);
    let learned_at = DECAY_NOW - 90 * DECAY_DAY_SECS;
    let span = TimeRange {
        start: learned_at,
        end: learned_at,
    };

    vault
        .batch()
        .put(
            &aged,
            ENTITY_TYPE_CLAIM,
            span,
            learned_at,
            &decay_claim_body("test.no_bump", None)?,
        )
        .text(&aged, &[("body", "nobumpneedle")])
        .put(&neighbor, ENTITY_TYPE_TURN, span, DECAY_NOW, b"payload")
        .text(&neighbor, &[("body", "nobumpneedle")])
        .edge(&neighbor, EdgeKind::Supports, &aged, 0.7)
        .commit()?;

    let search = || {
        vault
            .query()
            .search_text("nobumpneedle", 10)
            .with_temporal_now(DECAY_NOW)
            .run()
    };

    let stored_before = stored_entity_and_edge_bytes(&vault)?;
    let first = search()?;
    for repeat in 1..4 {
        assert_eq!(
            search()?,
            first,
            "repeat {repeat}: a read must return the score it returned before"
        );
        assert_eq!(
            stored_entity_and_edge_bytes(&vault)?,
            stored_before,
            "repeat {repeat}: a read must not write a claim or edge byte"
        );
    }

    let scores = to_score_map(&first);
    assert!(
        approx_eq(scores[&aged], 0.5, 1e-6),
        "one Standard half-life halves the surfacing factor, got {}",
        scores[&aged]
    );
    assert!(
        approx_eq(scores[&neighbor], 1.0, 1e-6),
        "a non-claim keeps the neutral factor"
    );
    Ok(())
}

/// Done-mean 9 — the per-entity override is an input seam that fails the
/// run CLOSED: a non-finite or out-of-range factor is a typed
/// [`Error::InvalidConfig`] from `run()`, never a silent skip or a poisoned
/// score. An admissible factor still runs and replaces the class factor.
#[test]
fn access_factor_overrides_reject_invalid_values_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = entity_id(0x71);
    put_claim_text(&vault, claim, "overrideneedle", None)?;

    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.5, 1.5] {
        let overrides = HashMap::from([(claim, bad)]);
        let err = vault
            .query()
            .search_text("overrideneedle", 10)
            .with_temporal_now(DECAY_NOW)
            .with_access_factor_overrides(&overrides)
            .run()
            .expect_err("an inadmissible access factor override must be rejected");
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "expected InvalidConfig for override {bad}, got {err:?}"
        );
    }

    let admissible = HashMap::from([(claim, 0.5_f32)]);
    let scores = vault
        .query()
        .search_text("overrideneedle", 10)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&admissible)
        .run()?;
    assert!(
        approx_eq(to_score_map(&scores)[&claim], 0.5, 1e-6),
        "an admissible override replaces the class-derived factor"
    );
    Ok(())
}

// ── expand_ppr: seed neutrality and exactly-one application ─────────────

/// Read-side decay must not decide WHICH candidates seed an implicit
/// `expand_ppr`: seeds come from the preliminary decay-free blend, so a
/// faded-but-live claim still opens the graph neighborhood only it can
/// reach. The fixture is discriminating on purpose — post-decay the faded
/// claim ranks LAST, so a decay-aware seed pass would have seeded its
/// dead-end sibling and never surfaced the neighbor at all.
#[test]
fn expand_ppr_implicit_seeds_ignore_access_decay() -> Result<()> {
    const OVERRIDE: f32 = 0.05;
    const TEXT: &str = "seeddecayneedle";

    let (_dir, vault) = open_test_vault();
    let faded = entity_id(0x81);
    let neighbor = entity_id(0x82);
    let fresh = entity_id(0x83);
    let span = TimeRange {
        start: DECAY_NOW,
        end: DECAY_NOW,
    };
    let body = decay_claim_body("test.seed_decay", None)?;

    vault
        .batch()
        .put(&faded, ENTITY_TYPE_CLAIM, span, DECAY_NOW, &body)
        .text(&faded, &[("body", TEXT)])
        .put(&fresh, ENTITY_TYPE_CLAIM, span, DECAY_NOW, &body)
        .text(&fresh, &[("body", TEXT)])
        .put(&neighbor, ENTITY_TYPE_TURN, span, DECAY_NOW, b"payload")
        .edge(&faded, EdgeKind::Supports, &neighbor, 0.9)
        .commit()?;

    let overrides = HashMap::from([(faded, OVERRIDE)]);
    let undecayed = vault
        .query()
        .search_text(TEXT, 10)
        .with_temporal_now(DECAY_NOW)
        .limit(10)
        .run()?;
    assert_eq!(
        undecayed.first().map(|scored| scored.id),
        Some(faded),
        "undecayed the two claims tie and order by id, so the faded one leads"
    );
    let decayed = vault
        .query()
        .search_text(TEXT, 10)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .limit(10)
        .run()?;
    assert_eq!(
        decayed.last().map(|scored| scored.id),
        Some(faded),
        "decayed the faded claim must sink below its sibling"
    );

    // `limit(1)` caps implicit seeding at the single top PRE-decay
    // candidate. The faded claim is that candidate and the only path to
    // the neighbor, so the neighbor surfacing proves the seed was chosen
    // before the factor landed.
    let expanded = vault
        .query()
        .search_text(TEXT, 10)
        .expand_ppr(&[], 2)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .limit(1)
        .run()?;
    assert_eq!(
        expanded.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        vec![neighbor],
        "the faded claim must still seed the expansion that reaches its neighbor"
    );

    // Decay-free SEEDING is not decay-free SCORING: the seed itself still
    // carries its once-applied factor in the returned scores.
    let expanded_wide = vault
        .query()
        .search_text(TEXT, 10)
        .expand_ppr(&[], 2)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .limit(10)
        .run()?;
    let base = to_score_map(&undecayed)[&faded];
    let applied = to_score_map(&expanded_wide)[&faded];
    assert!(
        approx_eq(applied, base * OVERRIDE, 1e-6),
        "expected {} after one application, got {applied}",
        base * OVERRIDE
    );
    Ok(())
}

/// The single-application invariant holds through `expand_ppr`, not just
/// `search_ppr`: the run blends twice (preliminary seed pass, then the
/// expansion) and only the expansion applies decay, so the overridden
/// claim carries `base x f` and never `base x f²`.
#[test]
fn expand_ppr_applies_access_factor_exactly_once() -> Result<()> {
    const OVERRIDE: f32 = 0.25;
    const TEXT: &str = "expandonceneedle";

    let (_dir, vault) = open_test_vault();
    let decayed = entity_id(0x84);
    let neighbor = entity_id(0x85);
    let span = TimeRange {
        start: DECAY_NOW,
        end: DECAY_NOW,
    };

    vault
        .batch()
        .put(
            &decayed,
            ENTITY_TYPE_CLAIM,
            span,
            DECAY_NOW,
            &decay_claim_body("test.expand_once", None)?,
        )
        .text(&decayed, &[("body", TEXT)])
        .put(&neighbor, ENTITY_TYPE_TURN, span, DECAY_NOW, b"payload")
        .edge(&decayed, EdgeKind::Supports, &neighbor, 0.9)
        .commit()?;

    let baseline = vault
        .query()
        .search_text(TEXT, 10)
        .expand_ppr(&[], 2)
        .with_temporal_now(DECAY_NOW)
        .limit(10)
        .run()?;
    assert!(
        baseline.iter().any(|scored| scored.id == neighbor),
        "the fixture must actually execute the expansion; got {baseline:?}"
    );
    let base = to_score_map(&baseline)[&decayed];

    let overrides = HashMap::from([(decayed, OVERRIDE)]);
    let applied = vault
        .query()
        .search_text(TEXT, 10)
        .expand_ppr(&[], 2)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .limit(10)
        .run()?;
    let score = to_score_map(&applied)[&decayed];
    assert!(
        approx_eq(score, base * OVERRIDE, 1e-6),
        "expected {} after one application, got {score}",
        base * OVERRIDE
    );
    assert!(
        !approx_eq(score, base * OVERRIDE * OVERRIDE, 1e-6),
        "the factor must land once, not once per blend stage"
    );
    Ok(())
}

/// Configuring `expand_ppr` without reaching a seed still owes the run
/// exactly one decay-applying blend, so the outcome is bit-identical to
/// the same query with no `expand_ppr` at all — including the case where
/// the D19 gate is what emptied the candidate set, which the recovery
/// re-blend re-fuses but must never resurface.
#[test]
fn expand_ppr_configured_but_unseeded_matches_plain_run() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let present = entity_id(0x86);
    let dead = entity_id(0x87);
    put_claim_text(&vault, present, "unseededneedle", None)?;
    put_status_claim(
        &vault,
        dead,
        "deadunseededneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;

    for text in ["nomatchunseededneedle", "deadunseededneedle"] {
        let plain = vault
            .query()
            .search_text(text, 10)
            .with_temporal_now(DECAY_NOW)
            .limit(10)
            .run()?;
        let configured = vault
            .query()
            .search_text(text, 10)
            .expand_ppr(&[], 2)
            .with_temporal_now(DECAY_NOW)
            .limit(10)
            .run()?;

        assert!(
            plain.is_empty(),
            "{text}: the fixture must leave no surfaceable candidate; got {plain:?}"
        );
        assert_eq!(
            plain, configured,
            "{text}: an unseeded expansion must not change the run"
        );
    }

    // A seeded, surfacing run through the same recovery-capable path still
    // applies the factor exactly once.
    let overrides = HashMap::from([(present, 0.5_f32)]);
    let plain = vault
        .query()
        .search_text("unseededneedle", 10)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .limit(10)
        .run()?;
    assert!(
        approx_eq(to_score_map(&plain)[&present], 0.5, 1e-6),
        "a plain run applies the override once"
    );
    Ok(())
}

// ── RET-010 rerank: the ladder is positional, the factor is entity-bound ─

const DECAY_RERANK_TEXT: &str = "rerankdecayneedle";

/// A claim whose CONFIDENCE drives the blend — so the fixture has a
/// strictly decreasing engine ladder instead of the all-ties ladder the
/// non-claim rerank fixtures use — and whose validity window drives the
/// read-side factor.
fn decay_rerank_claim_body(confidence: f32, valid_to: Option<u64>) -> Result<Vec<u8>> {
    let mut body = ClaimBody::new(
        "test.rerank_decay",
        ClaimSubject::Entity(entity_id(0x5A)),
        rmpv::Value::from("v"),
        confidence,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_to = valid_to;
    crate::claim::encode_claim_body(&body)
}

/// Three same-text claims with distinct confidences, returned in engine
/// order (highest confidence first). `expiring_valid_to` closes the
/// LOWEST-confidence claim so it keeps a `0.0` factor while the D19 gate
/// still admits it.
fn decay_rerank_fixture(
    vault: &Vault,
    expiring_valid_to: Option<u64>,
) -> Result<(EntityId, EntityId, EntityId)> {
    let top = entity_id(0x91);
    let middle = entity_id(0x92);
    let bottom = entity_id(0x93);
    let span = TimeRange {
        start: DECAY_NOW,
        end: DECAY_NOW,
    };

    vault
        .batch()
        .put(
            &top,
            ENTITY_TYPE_CLAIM,
            span,
            DECAY_NOW,
            &decay_rerank_claim_body(0.9, None)?,
        )
        .text(&top, &[("body", DECAY_RERANK_TEXT)])
        .put(
            &middle,
            ENTITY_TYPE_CLAIM,
            span,
            DECAY_NOW,
            &decay_rerank_claim_body(0.5, None)?,
        )
        .text(&middle, &[("body", DECAY_RERANK_TEXT)])
        .put(
            &bottom,
            ENTITY_TYPE_CLAIM,
            span,
            DECAY_NOW,
            &decay_rerank_claim_body(0.1, expiring_valid_to)?,
        )
        .text(&bottom, &[("body", DECAY_RERANK_TEXT)])
        .commit()?;

    Ok((top, middle, bottom))
}

/// Promotes one designated entity above every other candidate and leaves
/// the rest in their incoming engine order.
struct PromotingReranker(EntityId);

impl Reranker for PromotingReranker {
    fn id(&self) -> &str {
        "test/reranker-promoting@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok(candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                if candidate.id == self.0 {
                    1.0
                } else {
                    -(index as f32)
                }
            })
            .collect())
    }
}

/// The PRE-DECAY engine ladder the rerank block reassigns, read off a
/// reference vault holding the same three confidences with nothing
/// expired and nothing overridden — so every factor there is `1.0` and
/// the returned scores are the bare `exp(log_blend)` ladder.
fn decay_rerank_base_ladder() -> Result<Vec<f32>> {
    let (_dir, vault) = open_test_vault();
    decay_rerank_fixture(&vault, None)?;
    Ok(vault
        .query()
        .search_text(DECAY_RERANK_TEXT, 10)
        .boost_confidence()
        .with_temporal_now(DECAY_NOW)
        .limit(10)
        .run()?
        .iter()
        .map(|scored| scored.score)
        .collect())
}

/// A zero-factor claim promoted to the top of the block must NOT inherit
/// the live score that used to sit there. The ladder is sourced pre-decay
/// and re-multiplied by the receiving entity's own factor, so an expired
/// claim stays at `0.0` at any position while a decayed ladder would have
/// resurrected it with the block's highest score.
#[test]
fn rerank_preserves_zero_access_factor() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let (top, middle, expiring) = decay_rerank_fixture(&vault, Some(DECAY_NOW))?;
    let base_ladder = decay_rerank_base_ladder()?;
    assert_eq!(base_ladder.len(), 3);

    let reranker = PromotingReranker(expiring);
    let reranked = vault
        .query()
        .search_text(DECAY_RERANK_TEXT, 10)
        .boost_confidence()
        .with_temporal_now(DECAY_NOW)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 3,
                query: Some("rerank decay probe".to_owned()),
            },
        )
        .limit(10)
        .run()?;

    assert_eq!(
        reranked.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        vec![expiring, top, middle],
        "the reranker must promote the expired claim and keep the rest in order"
    );
    assert_eq!(
        reranked[0].score, 0.0,
        "a zero-factor claim keeps score 0.0 at any position"
    );
    assert!(
        base_ladder[0] > 0.0,
        "a decayed ladder would have resurrected it with {}",
        base_ladder[0]
    );
    for (position, scored) in reranked.iter().enumerate().skip(1) {
        assert!(
            approx_eq(scored.score, base_ladder[position], 1e-6),
            "position {position} must carry the pre-decay ladder value times its own live factor"
        );
    }
    Ok(())
}

/// The ladder is positional but the FACTOR is entity-bound: a claim moved
/// across positions takes the pre-decay score of the position it lands in,
/// multiplied by its own override — never the override of whichever entity
/// used to hold that slot, and never a decayed ladder value.
#[test]
fn rerank_binds_low_override_to_entity() -> Result<()> {
    const OVERRIDE: f32 = 0.25;

    let (_dir, vault) = open_test_vault();
    let (top, middle, bottom) = decay_rerank_fixture(&vault, None)?;
    let base_ladder = decay_rerank_base_ladder()?;
    let overrides = HashMap::from([(middle, OVERRIDE)]);

    // Decayed and unreranked, the overridden claim sinks to last, so a
    // decay-sourced ladder for position 0 is the top claim's decayed score.
    let decayed = vault
        .query()
        .search_text(DECAY_RERANK_TEXT, 10)
        .boost_confidence()
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .limit(10)
        .run()?;
    assert_eq!(
        decayed.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        vec![top, bottom, middle]
    );
    let decayed_ladder: Vec<f32> = decayed.iter().map(|scored| scored.score).collect();

    let reranker = PromotingReranker(middle);
    let reranked = vault
        .query()
        .search_text(DECAY_RERANK_TEXT, 10)
        .boost_confidence()
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 3,
                query: Some("rerank decay probe".to_owned()),
            },
        )
        .limit(10)
        .run()?;
    assert_eq!(
        reranked.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        vec![middle, top, bottom]
    );

    let promoted = reranked[0].score;
    assert!(
        approx_eq(promoted, base_ladder[0] * OVERRIDE, 1e-6),
        "expected {} (position 0's pre-decay score times its own override), got {promoted}",
        base_ladder[0] * OVERRIDE
    );
    assert!(
        !approx_eq(promoted, decayed_ladder[0], 1e-6),
        "a decayed ladder would have erased the override entirely"
    );
    assert!(
        !approx_eq(promoted, base_ladder[1] * OVERRIDE, 1e-6),
        "the ladder is positional: the promoted claim must not keep its own base score"
    );
    for (position, scored) in reranked.iter().enumerate().skip(1) {
        assert!(
            approx_eq(scored.score, base_ladder[position], 1e-6),
            "position {position} must carry its pre-decay ladder value times a neutral factor"
        );
    }
    Ok(())
}

/// The rerank ladder must not re-apply a factor the blend already applied:
/// a promoted decayed claim carries `ladder x f`, never `ladder x f²`.
#[test]
fn rerank_factor_applied_once_not_squared() -> Result<()> {
    const OVERRIDE: f32 = 0.5;

    let (_dir, vault) = open_test_vault();
    let (_top, _middle, bottom) = decay_rerank_fixture(&vault, None)?;
    let base_ladder = decay_rerank_base_ladder()?;
    let overrides = HashMap::from([(bottom, OVERRIDE)]);

    let reranker = PromotingReranker(bottom);
    let reranked = vault
        .query()
        .search_text(DECAY_RERANK_TEXT, 10)
        .boost_confidence()
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 3,
                query: Some("rerank decay probe".to_owned()),
            },
        )
        .limit(10)
        .run()?;

    assert_eq!(reranked[0].id, bottom);
    let promoted = reranked[0].score;
    assert!(
        approx_eq(promoted, base_ladder[0] * OVERRIDE, 1e-6),
        "expected {} after one application, got {promoted}",
        base_ladder[0] * OVERRIDE
    );
    assert!(
        !approx_eq(promoted, base_ladder[0] * OVERRIDE * OVERRIDE, 1e-6),
        "the factor must land once, not once in the blend and once in the ladder"
    );
    Ok(())
}

// ── attribution: Some(f) where it happened, None where it did not ───────

/// The multiplier a run applied is recoverable from telemetry without
/// inventing a pre/post score split: the row carries the exact factor, so
/// a consumer reconstructs the pre-decay scale as `final_score / f`. A
/// claim the decay stage resolved to neutral records `Some(1.0)`, while a
/// pre-fusion per-channel row records `None` — "not applicable" and
/// "applied, and it was neutral" are different facts.
#[test]
fn telemetry_score_breakdown_records_access_factor() -> Result<()> {
    const OVERRIDE: f32 = 0.25;
    const TEXT: &str = "attributionneedle";

    let (_dir, vault) = open_test_vault();
    let decayed = entity_id(0x95);
    let control = entity_id(0x96);
    let plain = entity_id(0x97);
    let span = TimeRange {
        start: DECAY_NOW,
        end: DECAY_NOW,
    };
    let body = decay_claim_body("test.attribution", None)?;

    vault
        .batch()
        .put(&decayed, ENTITY_TYPE_CLAIM, span, DECAY_NOW, &body)
        .text(&decayed, &[("body", TEXT)])
        .put(&control, ENTITY_TYPE_CLAIM, span, DECAY_NOW, &body)
        .text(&control, &[("body", TEXT)])
        .put(&plain, ENTITY_TYPE_TURN, span, DECAY_NOW, b"payload")
        .text(&plain, &[("body", TEXT)])
        .commit()?;

    let overrides = HashMap::from([(decayed, OVERRIDE)]);
    let results = vault
        .query()
        .search_text(TEXT, 10)
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .capture_retrieval_trace(true)
        .limit(10)
        .run_with_telemetry()?;
    let run_id = results
        .run_id
        .ok_or(Error::InvariantViolation("attribution run id"))?;
    let run = vault
        .retrieval_run(run_id)?
        .ok_or(Error::InvariantViolation("attribution run"))?;

    for (id, expected, why) in [
        (
            decayed,
            OVERRIDE,
            "the overridden claim records its override",
        ),
        (
            control,
            1.0,
            "an untouched claim records the neutral factor",
        ),
        (plain, 1.0, "a non-claim records the neutral factor"),
    ] {
        let breakdown = run
            .score_breakdown
            .iter()
            .find(|breakdown| breakdown.result_id == *id.as_bytes())
            .expect("every result carries a telemetry breakdown row");
        assert_eq!(breakdown.access_factor, Some(expected), "{why}");
        assert!(
            approx_eq(breakdown.final_score / expected, 1.0, 1e-6),
            "{why}: the pre-decay scale must be recoverable as final_score / f"
        );
    }

    let trace = run
        .trace
        .ok_or(Error::InvariantViolation("attribution trace"))?;
    assert!(
        trace
            .per_channel
            .iter()
            .flat_map(|channel| &channel.candidates)
            .all(|candidate| candidate.access_factor.is_none()),
        "a pre-fusion per-channel row must not attribute a multiplier"
    );
    Ok(())
}

/// Attribution appears exactly where the multiplication happened: the
/// pre-fusion Fused stage records `None`, while Blended, Reranked and
/// Final record the entity-bound factor the single Apply blend assigned.
/// Decay is attribution, never a signal, so the component lists are the
/// same as an undecayed run's.
#[test]
fn retrieval_trace_stages_carry_access_factor_only_post_fusion() -> Result<()> {
    const OVERRIDE: f32 = 0.25;

    let (_dir, vault) = open_test_vault();
    let (_top, middle, _bottom) = decay_rerank_fixture(&vault, None)?;
    let overrides = HashMap::from([(middle, OVERRIDE)]);
    let reranker = PromotingReranker(middle);

    let results = vault
        .query()
        .search_text(DECAY_RERANK_TEXT, 10)
        .boost_confidence()
        .with_temporal_now(DECAY_NOW)
        .with_access_factor_overrides(&overrides)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 3,
                query: Some("rerank decay probe".to_owned()),
            },
        )
        .capture_retrieval_trace(true)
        .limit(10)
        .run_with_telemetry()?;
    let run_id = results
        .run_id
        .ok_or(Error::InvariantViolation("stage attribution run id"))?;
    let trace = vault
        .retrieval_run(run_id)?
        .ok_or(Error::InvariantViolation("stage attribution run"))?
        .trace
        .ok_or(Error::InvariantViolation("stage attribution trace"))?;

    assert!(!trace.fused.candidates.is_empty());
    assert!(
        trace
            .fused
            .candidates
            .iter()
            .all(|candidate| candidate.access_factor.is_none()),
        "the fused stage is pre-blend and must attribute nothing"
    );

    for (stage, record) in [
        ("blended", &trace.blended),
        ("reranked", &trace.reranked),
        ("final", &trace.final_stage),
    ] {
        assert!(!record.candidates.is_empty(), "{stage} stage is empty");
        for candidate in &record.candidates {
            let expected = if candidate.result_id == *middle.as_bytes() {
                OVERRIDE
            } else {
                1.0
            };
            assert_eq!(
                candidate.access_factor,
                Some(expected),
                "{stage} stage must carry the entity-bound factor"
            );
        }
    }
    Ok(())
}

// ── replay: every input that moves a decayed score forks the hash ───────

const DECAY_FORK_TEXT: &str = "forkdecayneedle";

/// A frozen-clock fixture whose only scoring variable is read-side decay:
/// one aged claim, no recency blend, no temporal channel. The age is kept
/// well inside the floor so moving the clock genuinely moves the score.
fn decay_fork_hash_fixture(vault: &Vault) -> Result<EntityId> {
    let aged = entity_id(0x98);
    let learned_at = DECAY_NOW - 30 * DECAY_DAY_SECS;
    vault
        .batch()
        .put(
            &aged,
            ENTITY_TYPE_CLAIM,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &decay_claim_body("test.fork_decay", None)?,
        )
        .text(&aged, &[("body", DECAY_FORK_TEXT)])
        .commit()?;
    Ok(aged)
}

/// The replay key must fork on every explicit input that can change a
/// blended score. Decay reads the run's resolved clock on EVERY retrieval,
/// so two runs that differ only in their explicit clock score differently
/// while recency and temporal are both off — they shared one fork hash,
/// which is the regression this pins.
#[test]
fn retrieval_trace_fork_hash_distinguishes_decay_clock_without_recency() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let aged = decay_fork_hash_fixture(&vault)?;

    let earlier = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text(DECAY_FORK_TEXT, 10)
            .with_temporal_now(DECAY_NOW)
            .limit(10),
    )?;
    let later = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text(DECAY_FORK_TEXT, 10)
            .with_temporal_now(DECAY_NOW + 90 * DECAY_DAY_SECS)
            .limit(10),
    )?;
    let repeat = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text(DECAY_FORK_TEXT, 10)
            .with_temporal_now(DECAY_NOW)
            .limit(10),
    )?;

    assert_ne!(
        earlier.fork_hash, later.fork_hash,
        "two explicit decay clocks are two different scoring inputs"
    );
    assert_eq!(
        earlier.fork_hash, repeat.fork_hash,
        "the same explicit clock must keep one replay key"
    );

    // The scores really do differ, so the fork is not cosmetic.
    let score_of = |trace: &RetrievalTrace| {
        trace
            .final_stage
            .candidates
            .iter()
            .find(|candidate| candidate.result_id == *aged.as_bytes())
            .map(|candidate| candidate.final_score)
    };
    assert_ne!(score_of(&earlier), score_of(&later));
    Ok(())
}

/// One captured fork hash over the decay fixture under a fixed clock,
/// varying only the caller's override map.
fn decay_override_fork_hash<'a>(
    vault: &'a Vault,
    overrides: Option<&'a HashMap<EntityId, f32>>,
) -> Result<crate::store::RetrievalTraceForkHash> {
    let mut builder = vault
        .query()
        .search_text(DECAY_FORK_TEXT, 10)
        .with_temporal_now(DECAY_NOW)
        .limit(10);
    if let Some(overrides) = overrides {
        builder = builder.with_access_factor_overrides(overrides);
    }
    Ok(captured_retrieval_trace(vault, builder)?.fork_hash)
}

/// The override map is a caller-supplied scoring input, so it forks the
/// replay key — canonically: insertion order is not an input, a changed
/// factor is, and a present-but-different map never shares a key with
/// another.
#[test]
fn retrieval_trace_fork_hash_distinguishes_override_maps() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let aged = decay_fork_hash_fixture(&vault)?;
    let other = entity_id(0x99);
    vault
        .batch()
        .put(
            &other,
            ENTITY_TYPE_CLAIM,
            TimeRange {
                start: DECAY_NOW,
                end: DECAY_NOW,
            },
            DECAY_NOW,
            &decay_claim_body("test.fork_decay", None)?,
        )
        .text(&other, &[("body", DECAY_FORK_TEXT)])
        .commit()?;

    let mut forward = HashMap::new();
    forward.insert(aged, 0.5_f32);
    forward.insert(other, 0.25_f32);
    let mut reversed = HashMap::new();
    reversed.insert(other, 0.25_f32);
    reversed.insert(aged, 0.5_f32);
    let changed = HashMap::from([(aged, 0.5_f32), (other, 0.75_f32)]);
    let single = HashMap::from([(aged, 0.5_f32)]);

    let none = decay_override_fork_hash(&vault, None)?;
    let forward_hash = decay_override_fork_hash(&vault, Some(&forward))?;
    let reversed_hash = decay_override_fork_hash(&vault, Some(&reversed))?;
    let changed_hash = decay_override_fork_hash(&vault, Some(&changed))?;
    let single_hash = decay_override_fork_hash(&vault, Some(&single))?;

    assert_eq!(
        forward_hash, reversed_hash,
        "insertion order is not a scoring input: the map is canonicalized"
    );
    assert_ne!(
        none, forward_hash,
        "supplying overrides must fork away from the no-override run"
    );
    assert_ne!(
        forward_hash, changed_hash,
        "one changed factor value must fork the replay key"
    );
    assert_ne!(
        forward_hash, single_hash,
        "dropping an entry must fork the replay key"
    );
    Ok(())
}
