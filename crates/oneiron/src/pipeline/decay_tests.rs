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
use super::tests::{approx_eq, captured_retrieval_trace, entity_id, open_test_vault, to_score_map};
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
    )?;
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

    // ONE-2702: the PPR seed now leads on relevance; the twin claims still tie and order by id.
    assert_eq!(
        baseline.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        vec![seed, decayed, control],
        "undecayed, the decayed claim leads its identical twin"
    );
    assert_eq!(
        decayed_run.last().map(|scored| scored.id),
        Some(decayed),
        "the decayed claim must sink below every undecayed candidate"
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

// ── expand_ppr: seed neutrality and exactly-one application ─────────────

// ── RET-010 rerank: the ladder is positional, the factor is entity-bound ─

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
