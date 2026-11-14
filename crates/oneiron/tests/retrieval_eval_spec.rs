//! Public retrieval-ruler eval inputs refuse nondeterminism and leave serving writes alone.

use std::collections::BTreeMap;
use std::time::Duration;

use oneiron::memory::Effort;
use oneiron::pipeline::retrieval_policy::RetrievalPolicyOptions;
use oneiron::pipeline::{BlendWeightsSource, PipelineBuilder, RetrievalEvalSpec};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::rerank::affect::{ArousalFloor, ArousalReranker};
use oneiron::rerank::{RerankCandidate, RerankOptions, Reranker};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::store::RetrievalBlendWeights;
use oneiron::{EntityId, Error, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DAY: u64 = 86_400;
const NOW: u64 = 1_780_000_000;
const QUERY_VECTOR: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
const QUERY_TEXT: &str = "harbour crossing";
const RECENCY_ONLY: RetrievalBlendWeights = RetrievalBlendWeights {
    recency: 1.0,
    salience: 0.0,
    confidence: 0.0,
    gravity: 0.0,
    relevance: 0.0,
};

fn open_vault(
    embedding_model: Option<&str>,
) -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.dimensions = QUERY_VECTOR.len();
    config.embedding_model = embedding_model.map(str::to_owned);
    config.map_size = 16 * 1024 * 1024;
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(directory.path(), config)?;
    Ok((directory, vault))
}

struct Fixture {
    _directory: tempfile::TempDir,
    vault: Vault,
    older: EntityId,
    newer: EntityId,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let (directory, vault) = open_vault(Some("test/model@v1"))?;
    let older = EntityId::now();
    let newer = EntityId::now();
    let body = BTreeMap::from([("txt", "harbour crossing"), ("spkr", "Owen")]);
    let bytes = rmp_serde::to_vec_named(&body)?;
    for (id, timestamp) in [(older, NOW - 28 * DAY), (newer, NOW)] {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: timestamp,
                    end: timestamp,
                },
                timestamp,
                &bytes,
            )
            .vector(&id, &QUERY_VECTOR)
            .commit()?;
    }
    Ok(Fixture {
        _directory: directory,
        vault,
        older,
        newer,
    })
}

impl Fixture {
    fn query(&self) -> PipelineBuilder<'_> {
        self.vault
            .query()
            .search_vector(&QUERY_VECTOR, 10)
            .search_text(QUERY_TEXT, 10)
            .limit(10)
    }
}

fn learned_spec() -> RetrievalEvalSpec {
    RetrievalEvalSpec {
        now: NOW,
        weights: BlendWeightsSource::LearnedTable,
    }
}

#[test]
fn eval_spec_writes_no_run_row() -> TestResult {
    let fixture = fixture()?;
    let before = fixture.vault.retrieval_runs(100)?.len();
    let control = fixture.query().run_with_telemetry()?;
    assert!(control.run_id.is_some());
    assert_eq!(fixture.vault.retrieval_runs(100)?.len(), before + 1);

    let evaluated = fixture
        .query()
        .eval_spec(learned_spec())?
        .run_with_telemetry()?;
    assert!(evaluated.run_id.is_none());
    assert_eq!(fixture.vault.retrieval_runs(100)?.len(), before + 1);
    Ok(())
}

// TURN recency uses learned_at, not occurred: set both to T and T - 28 days.
// Its 28-day half-life gives r_new = 2^(-1/(28*86400)), r_old = r_new/2.
// z(log1p(r)) is [+1, -1], so recency-only scores are exp(+1), exp(-1).
// At T + 3650 days r_new < 6e-40: the column's stddev is below f64::EPSILON,
// z becomes [0, 0], and both scores become 1. Equal text and vectors give
// relevance z=0; bootstrap recency=0.175 instead yields exp(+/-0.175) at T.
#[test]
fn eval_spec_pins_now_and_weights() -> TestResult {
    let fixture = fixture()?;
    let spec = RetrievalEvalSpec {
        now: NOW,
        weights: BlendWeightsSource::Pinned(RECENCY_ONLY),
    };
    let first = fixture.query().eval_spec(spec.clone())?.run()?;
    let repeated = fixture.query().eval_spec(spec)?.run()?;
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].id, fixture.newer);
    assert_eq!(first[1].id, fixture.older);
    assert!(first[0].score > first[1].score);
    let snapshot = |scores: &[oneiron::pipeline::ScoredEntity]| {
        scores
            .iter()
            .map(|row| (*row.id.as_bytes(), row.score.to_bits()))
            .collect::<Vec<_>>()
    };
    assert_eq!(snapshot(&first), snapshot(&repeated));

    let later = fixture
        .query()
        .eval_spec(RetrievalEvalSpec {
            now: NOW + 3650 * DAY,
            weights: BlendWeightsSource::Pinned(RECENCY_ONLY),
        })?
        .run()?;
    let later_newer = later.iter().find(|row| row.id == fixture.newer).unwrap();
    assert_ne!(first[0].score.to_bits(), later_newer.score.to_bits());

    let learned = fixture.query().eval_spec(learned_spec())?.run()?;
    assert_ne!(snapshot(&first), snapshot(&learned));
    let cleared_override = fixture
        .query()
        .with_blend_weights(RECENCY_ONLY)?
        .eval_spec(learned_spec())?
        .run()?;
    assert_eq!(snapshot(&learned), snapshot(&cleared_override));
    Ok(())
}

struct DefaultReranker;

impl Reranker for DefaultReranker {
    fn id(&self) -> &str {
        "test/default-reranker"
    }

    fn rerank(&self, _: &str, candidates: &[RerankCandidate<'_>]) -> oneiron::Result<Vec<f32>> {
        Ok(candidates.iter().map(|candidate| candidate.score).collect())
    }
}

#[test]
fn eval_spec_refuses_nondeterministic_reranker() -> TestResult {
    let fixture = fixture()?;
    let result = fixture
        .query()
        .eval_spec(learned_spec())?
        .rerank(&DefaultReranker, RerankOptions::default())
        .run();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
    let arousal = ArousalReranker::new(BTreeMap::new(), ArousalFloor::new(0.0)?)?;
    assert!(arousal.deterministic());
    let result = fixture
        .query()
        .eval_spec(learned_spec())?
        .rerank(&arousal, RerankOptions::default())
        .run();
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn eval_spec_refuses_bandit_policy() -> TestResult {
    let fixture = fixture()?;
    let mut policy = RetrievalPolicyOptions::new(EntityId::now(), Effort::Light);
    policy.bandit_enabled = true;
    let result = fixture
        .query()
        .eval_spec(learned_spec())?
        .retrieval_policy(policy)
        .run();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
    policy.bandit_enabled = false;
    assert!(
        fixture
            .query()
            .eval_spec(learned_spec())?
            .retrieval_policy(policy)
            .run()
            .is_ok()
    );
    Ok(())
}

#[test]
fn eval_spec_refuses_deadline() -> TestResult {
    let fixture = fixture()?;
    let deadline = RetrievalDeadline::after(Duration::from_secs(60));
    let result = fixture
        .query()
        .eval_spec(learned_spec())?
        .deadline(&deadline)
        .run();
    assert!(matches!(result, Err(Error::InvalidConfig(_))));
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn eval_spec_enqueues_no_embed_job() -> TestResult {
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::sync::SyncQueue;
    use oneiron::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use std::sync::Arc;

    // A model-free setup marks the claim pending but does not enqueue it at put time.
    // Text retrieval still returns the marker; only the control surfacing enqueues it.
    let (_directory, vault) = open_vault(None)?;
    let vault = Arc::new(vault);
    let occurred = TimeRange {
        start: NOW,
        end: NOW,
    };
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, NOW, b"subject")?;
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("harbour crossing"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    vault.put_claim(&claim, &body, occurred, NOW)?;
    vault
        .batch()
        .text(&claim, &[("body", QUERY_TEXT)])
        .commit()?;
    let queue = SyncQueue::new(Arc::clone(&vault))?;
    assert_eq!(queue.drain_embed_jobs()?.len(), 0);

    let evaluated = vault
        .query()
        .search_text(QUERY_TEXT, 10)
        .eval_spec(learned_spec())?
        .run_with_pending_vectors()?;
    assert!(evaluated.pending_vector_ids.contains(&claim));
    assert!(
        evaluated
            .pending_vectors
            .iter()
            .any(|pending| pending.id == claim)
    );
    assert!(evaluated.run_id.is_none());
    assert_eq!(queue.drain_embed_jobs()?.len(), 0);

    let control = vault
        .query()
        .search_text(QUERY_TEXT, 10)
        .run_with_pending_vectors()?;
    assert!(control.pending_vector_ids.contains(&claim));
    let jobs = queue.drain_embed_jobs()?;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].entity_id, claim);
    Ok(())
}
