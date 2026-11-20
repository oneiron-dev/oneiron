//! Row [RECALL-FUSION-COLUMNS-TWICE]: a blend computes its candidates'
//! normalized signal columns once, for their scores and for the score
//! components the trace and telemetry record, and a rerank stage keeps only
//! its block's rerank components instead of a copy of every candidate's blend
//! components.
//!
//! The fixture: four claims whose blend order comes from their vectors alone,
//! a reranker that inverts the blend, and a block of two. The first two tests
//! count the work through a test door. The third pins the components the run
//! records: the reranked stage and the run's score breakdown give each row its
//! blended-stage components, then its rerank component when the reranker
//! scored it; the final stage gives the blended-stage components alone.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test blend_columns_once`.

#![cfg(oneiron_test_support)]

use std::collections::HashMap;
use std::sync::Mutex;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::rerank::{RerankCandidate, RerankOptions, Reranker};
use oneiron::test_doors::blend_component_work::count_blend_component_work;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId,
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, TimeRange, Vault,
    VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
/// Each claim's cosine to [`QUERY`], strongest first.
const COSINES: [f32; 4] = [1.0, 0.6, 0.55, 0.1];
const TOP_N: usize = 2;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// A host reranker that scores each candidate by its engine rank, so the
/// last of the block comes first. It records the candidates it was sent.
#[derive(Default)]
struct InvertingReranker {
    sent: Mutex<Vec<EntityId>>,
}

impl Reranker for InvertingReranker {
    fn id(&self) -> &str {
        "test/inverting@v1"
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
    ) -> oneiron::Result<Vec<f32>> {
        self.sent
            .lock()
            .expect("sent candidates")
            .extend(candidates.iter().map(|candidate| candidate.id));
        Ok(candidates
            .iter()
            .map(|candidate| candidate.rank as f32)
            .collect())
    }
}

/// Four active claims, each about its own PERSON, at [`COSINES`] to the
/// query, in a vault that records retrieval telemetry.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    claims: [EntityId; 4],
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    let claims = [seed_id(0x31), seed_id(0x32), seed_id(0x33), seed_id(0x34)];
    for (index, (claim, cosine)) in claims.iter().zip(COSINES).enumerate() {
        let subject = seed_id(0x21 + index as u8);
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                occurred(),
                LEARNED_AT,
                b"subject",
            )
            .expect("subject entity");
        let body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(format!("note {index}")),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        vault
            .put_claim(claim, &body, occurred(), LEARNED_AT)
            .expect("claim");
        let vector = [cosine, (1.0 - cosine * cosine).sqrt(), 0.0, 0.0];
        vault
            .batch()
            .vector(claim, &vector)
            .commit()
            .expect("claim vector");
    }
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("idle publish delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publish of staged vectors");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: every claim vector is published: {:?}",
        published.failed
    );
    Fixture {
        _dir: dir,
        vault,
        claims,
    }
}

impl Fixture {
    /// Every claim at access factor 1.0, so the blend alone orders them.
    fn neutral_factors(&self) -> HashMap<EntityId, f32> {
        self.claims.iter().map(|claim| (*claim, 1.0)).collect()
    }
}

fn rerank_options() -> RerankOptions {
    RerankOptions {
        top_n: TOP_N,
        query: Some("note".to_owned()),
    }
}

/// One blend's scores and score components share one pass over its
/// candidates' normalized columns.
#[test]
fn a_blend_normalizes_its_columns_once() {
    let fixture = fixture();
    let neutral = fixture.neutral_factors();
    let reranker = InvertingReranker::default();
    let (rows, work) = count_blend_component_work(|| {
        fixture
            .vault
            .query()
            .search_vector(&QUERY, 10)
            .with_access_factor_overrides(&neutral)
            .rerank(&reranker, rerank_options())
            .limit(10)
            .run()
    });
    let rows = rows.expect("reranked retrieval");
    assert_eq!(rows.len(), 4, "FIXTURE: every claim is returned: {rows:?}");
    assert!(
        work.blends >= 1,
        "FIXTURE: the retrieval blends its candidates: {work:?}"
    );
    assert_eq!(
        work.column_passes, work.blends,
        "each blend computes its normalized columns once, for its scores and its score components: {work:?}"
    );
}

/// A rerank stage's own component map holds the rows it reranked, not a copy
/// of every candidate's blend components.
#[test]
fn a_rerank_stage_keeps_only_its_block_components() {
    let fixture = fixture();
    let neutral = fixture.neutral_factors();
    let reranker = InvertingReranker::default();
    let (rows, work) = count_blend_component_work(|| {
        fixture
            .vault
            .query()
            .search_vector(&QUERY, 10)
            .with_access_factor_overrides(&neutral)
            .rerank(&reranker, rerank_options())
            .limit(10)
            .run()
    });
    let rows = rows.expect("reranked retrieval");
    assert_eq!(rows.len(), 4, "FIXTURE: every claim is returned: {rows:?}");
    let sent = reranker.sent.lock().expect("sent candidates").clone();
    assert_eq!(
        sent,
        fixture.claims[..TOP_N].to_vec(),
        "FIXTURE: the reranker is sent the two strongest claims"
    );
    assert!(
        !work.rerank_component_rows.is_empty(),
        "FIXTURE: a rerank stage ran: {work:?}"
    );
    assert!(
        work.rerank_component_rows.iter().all(|rows| *rows == TOP_N),
        "each rerank stage's component map holds its {TOP_N} reranked rows alone: {work:?}"
    );
}

fn components_by_id(
    candidates: &[RetrievalScoreBreakdown],
) -> HashMap<[u8; 16], Vec<RetrievalScoreComponent>> {
    candidates
        .iter()
        .map(|row| (row.result_id, row.components.clone()))
        .collect()
}

/// The run's recorded components: the reranked stage and the score
/// breakdown give each row its blended-stage components, then its rerank
/// component when the reranker scored it, and the final stage gives the
/// blended-stage components alone.
#[test]
fn the_recorded_components_append_the_rerank_after_the_blend() -> TestResult {
    let fixture = fixture();
    let neutral = fixture.neutral_factors();
    let reranker = InvertingReranker::default();
    let run = fixture
        .vault
        .query()
        .search_vector(&QUERY, 10)
        .with_access_factor_overrides(&neutral)
        .rerank(&reranker, rerank_options())
        .capture_retrieval_trace(true)
        .limit(10)
        .run_with_telemetry()?;
    assert_eq!(run.value.len(), 4, "FIXTURE: every claim is returned");
    let run_id = run
        .run_id
        .ok_or("FIXTURE: a capture run publishes its run id")?;
    let record = fixture
        .vault
        .retrieval_run(run_id)?
        .ok_or("FIXTURE: the run record is readable")?;
    let trace = record.trace.ok_or("FIXTURE: the run captured its trace")?;
    let blended = components_by_id(&trace.blended.candidates);
    assert_eq!(
        blended.len(),
        4,
        "FIXTURE: the blended stage lists every claim: {:?}",
        trace.blended.candidates
    );
    for claim in &fixture.claims {
        assert!(
            blended[claim.as_bytes()]
                .iter()
                .any(|component| component.signal == RetrievalSignal::Relevance),
            "FIXTURE: each blended row carries its relevance component: {:?}",
            blended[claim.as_bytes()]
        );
    }

    // The inverting reranker scores the block's first claim 1 and its second
    // 2, so the second takes rerank rank 1.
    let rerank_component = |id: &[u8; 16]| -> Option<RetrievalScoreComponent> {
        if id == fixture.claims[1].as_bytes() {
            Some(RetrievalScoreComponent {
                signal: RetrievalSignal::Rerank,
                rank: 1,
                score: 2.0,
            })
        } else if id == fixture.claims[0].as_bytes() {
            Some(RetrievalScoreComponent {
                signal: RetrievalSignal::Rerank,
                rank: 2,
                score: 1.0,
            })
        } else {
            None
        }
    };
    let with_rerank = |id: &[u8; 16]| -> Vec<RetrievalScoreComponent> {
        let mut components = blended[id].clone();
        components.extend(rerank_component(id));
        components
    };

    assert_eq!(
        trace.reranked.candidates.len(),
        4,
        "FIXTURE: the reranked stage lists every claim"
    );
    for row in &trace.reranked.candidates {
        assert_eq!(
            row.components,
            with_rerank(&row.result_id),
            "the reranked stage gives row {:?} its blend components, then its rerank component",
            row.result_id
        );
    }
    assert_eq!(
        record.score_breakdown.len(),
        4,
        "FIXTURE: the score breakdown lists every result"
    );
    for row in &record.score_breakdown {
        assert_eq!(
            row.components,
            with_rerank(&row.result_id),
            "the score breakdown gives row {:?} its blend components, then its rerank component",
            row.result_id
        );
    }
    for row in &trace.final_stage.candidates {
        assert_eq!(
            row.components, blended[&row.result_id],
            "the final stage gives row {:?} its blend components alone",
            row.result_id
        );
    }
    Ok(())
}
