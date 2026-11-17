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
//! At a weakest reranked score of zero (a zero access factor) no row can
//! score below it, so a row past the block ties with it there (review round
//! 2). The pipeline serves the reranked row first; the third test pins that
//! the rendered pack and its JSON response keep that order among equal
//! scores, where they broke the tie by id before.
//!
//! Public crate surface only: `Vault::put_entity`, `Vault::put_claim`, a
//! vector batch, the pipeline, the context pack builder and
//! `serialize::serialize_pack`.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test rerank_group_order`

use std::collections::HashMap;
use std::sync::Mutex;

use oneiron::context_pack::{DEFAULT_MAX_FIELD_CHARS, TokenAllocation};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::rerank::{RerankCandidate, RerankOptions, Reranker};
use oneiron::serialize::pack_format::{FieldProfile, PackFormat};
use oneiron::serialize::{SerializeConfig, project_pack_for_json_response, serialize_pack};
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

fn serialize_config(format: PackFormat) -> SerializeConfig {
    SerializeConfig {
        format,
        profile: FieldProfile::Minimal,
        budget: 8192,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: DEFAULT_MAX_FIELD_CHARS,
        max_item_tokens: 0,
    }
}

/// The pack as the pipeline serves it at a weakest reranked score of zero:
/// the reranked row first, then a row past the block with a lower id, both
/// at zero. Every rendered format and the JSON response keep that order.
#[test]
fn a_rendered_pack_keeps_the_pack_order_among_equal_scores() {
    let fixture = fixture();
    let mut pack = fixture
        .vault
        .context_pack()
        .search_vector(&QUERY, 10)
        .limit(10)
        .hydrate(true)
        .field_profile(FieldProfile::Minimal)
        .run()
        .expect("context pack");
    let [capped, _, _, reranked] = fixture.claims;
    pack.results
        .retain(|entity| entity.id == reranked || entity.id == capped);
    pack.results
        .sort_by_key(|entity| std::cmp::Reverse(entity.id));
    for entity in &mut pack.results {
        entity.score = 0.0;
    }
    let order: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(
        order,
        vec![reranked, capped],
        "FIXTURE: the reranked row comes first, its id the higher"
    );
    // Each claim's text is its value: `note <index>`.
    let (first, second) = ("note 3", "note 0");
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let rendered = String::from_utf8(serialize_pack(&pack, &serialize_config(format)))
            .expect("rendered pack is UTF-8");
        let at = |text: &str| {
            rendered
                .find(text)
                .unwrap_or_else(|| panic!("{format:?} pack holds {text}: {rendered}"))
        };
        assert!(
            at(first) < at(second),
            "the {format:?} pack keeps the reranked row first at the tie: {rendered}"
        );
    }
    let projected = project_pack_for_json_response(pack, &serialize_config(PackFormat::Json));
    let order: Vec<EntityId> = projected.results.iter().map(|entity| entity.id).collect();
    assert_eq!(
        order,
        vec![reranked, capped],
        "the JSON response keeps the reranked row first at the tie"
    );
}
