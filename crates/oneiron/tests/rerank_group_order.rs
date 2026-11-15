//! RERANK-GROUP-ORDER = A (ARCH-0004 #rerank-door-open: "later stages that
//! respect the reranked group"): no row the reranker did not score ends ahead
//! of a row it did, unless a ruled precedence puts it there (critical first,
//! base before non-base, the OF-023 clamp, the named-entity pass).
//!
//! The rerank ladder gives each reranked row the block's i-th blended score
//! times that row's own access factor. A claim the reranker moves down with a
//! low factor can so score below a row past `top_n`, and every later score
//! sort (the pack's assembly, serialization) then serves that unscored row
//! ahead of it. Before the fix nothing kept the block's boundary.
//!
//! The fixture: four claims whose blended scores b1 > b2 > b3 > b4 come from
//! their vectors alone, `top_n` = 2, a reranker that inverts the blend, and
//! the top claim's access factor `a` chosen from a control run so that it
//! stays first by score (b1 * a >= b2) and its new place scores below the
//! first row past the block (b2 * a < b3).
//!
//! Public crate surface only: `Vault::put_entity`, `Vault::put_claim`, a
//! vector batch, the pipeline and the context pack builder.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test rerank_group_order`

use std::collections::HashMap;
use std::sync::Mutex;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::rerank::{RerankCandidate, RerankOptions, Reranker};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
/// Each claim's cosine to [`QUERY`]. The second sits nearer the third than
/// the first, so b2 * b2 < b1 * b3 (the blend is linear in the log score).
const COSINES: [f32; 4] = [1.0, 0.6, 0.55, 0.1];
const TOP_N: usize = 2;

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
/// last of the block comes first: it inverts the blend. It records how many
/// candidates it was sent.
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
/// query, strongest first.
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
    /// Every claim at access factor 1.0 but `top` (the strongest), at
    /// `factor`.
    fn overrides(&self, factor: f32) -> HashMap<EntityId, f32> {
        let mut overrides: HashMap<EntityId, f32> =
            self.claims.iter().map(|claim| (*claim, 1.0)).collect();
        overrides.insert(self.claims[0], factor);
        overrides
    }

    /// The factor `a` for the strongest claim: from a run with no reranker
    /// and every factor 1.0, the geometric mean of b2 / b1 and b3 / b2, so
    /// b1 * a > b2 and b2 * a < b3.
    fn demoting_factor(&self) -> f32 {
        let neutral = self.overrides(1.0);
        let rows = self
            .vault
            .query()
            .search_vector(&QUERY, 10)
            .with_access_factor_overrides(&neutral)
            .limit(10)
            .run()
            .expect("control retrieval");
        let ids: Vec<EntityId> = rows.iter().map(|row| row.id).collect();
        assert_eq!(
            ids, self.claims,
            "FIXTURE: with no reranker the claims rank by their cosine"
        );
        let [b1, b2, b3, _] = [rows[0].score, rows[1].score, rows[2].score, rows[3].score];
        assert!(
            b2 * b2 < b1 * b3,
            "FIXTURE: the blend leaves room for the factor: b1 {b1}, b2 {b2}, b3 {b3}"
        );
        (b3 / b1).sqrt()
    }
}

/// The pipeline's own scores: every row the reranker scored sits above every
/// row it was not sent, whatever the access factor of a row it moved down.
#[test]
fn a_row_past_the_block_scores_below_every_reranked_row() {
    let fixture = fixture();
    let factor = fixture.demoting_factor();
    let overrides = fixture.overrides(factor);
    let reranker = InvertingReranker::default();
    let rows = fixture
        .vault
        .query()
        .search_vector(&QUERY, 10)
        .with_access_factor_overrides(&overrides)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: TOP_N,
                query: Some("note".to_owned()),
            },
        )
        .limit(10)
        .run()
        .expect("reranked retrieval");
    let sent = reranker.sent.lock().expect("sent candidates").clone();
    assert_eq!(
        sent,
        fixture.claims[..TOP_N].to_vec(),
        "FIXTURE: the reranker is sent the two strongest claims"
    );
    let scores: HashMap<EntityId, f32> = rows.iter().map(|row| (row.id, row.score)).collect();
    assert_eq!(scores.len(), 4, "every claim is returned: {rows:?}");
    let weakest_reranked = sent
        .iter()
        .map(|id| scores[id])
        .fold(f32::INFINITY, f32::min);
    for past in &fixture.claims[TOP_N..] {
        assert!(
            scores[past] < weakest_reranked,
            "the row {} past the block scores {} below the weakest reranked row {weakest_reranked}: {rows:?}",
            past.to_hex(),
            scores[past],
        );
    }
}

/// The context pack serves the reranked block first, in the reranker's
/// order, then the rows past it.
#[test]
fn a_pack_serves_the_reranked_block_before_the_rows_past_it() {
    let fixture = fixture();
    let factor = fixture.demoting_factor();
    let overrides = fixture.overrides(factor);
    let reranker = InvertingReranker::default();
    let pack = fixture
        .vault
        .context_pack()
        .search_vector(&QUERY, 10)
        .with_access_factor_overrides(&overrides)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: TOP_N,
                query: Some("note".to_owned()),
            },
        )
        .limit(10)
        .run()
        .expect("reranked context pack");
    let served: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    let [first, second, third, fourth] = fixture.claims;
    assert_eq!(
        served,
        vec![second, first, third, fourth],
        "the reranked pair leads in the reranker's order, then the rows past it: {:?}",
        pack.results
            .iter()
            .map(|entity| (entity.id.to_hex(), entity.score))
            .collect::<Vec<_>>(),
    );
}
