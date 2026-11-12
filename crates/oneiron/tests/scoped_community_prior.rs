//! A narrowed Uniform expansion takes the configured community prior
//! (RECALL-SCOPED-PPR-DROPS-COMMUNITY-PRIOR; lead ruling RETRIEVAL-09 = A).
//! Any narrowing (here a type filter; in `vault.recall` the authority filter)
//! sends `expand_ppr` down the scoped walk, which took no prior at all. The
//! prior must come from the admitted scope alone: a row the walk cannot read
//! moves no score.
//!
//! The fixture is 64 TASK rows: two disjoint three-row About cliques A and B,
//! mirrored, plus 58 isolates. Every row but the two clique targets is an
//! explicit seed, so the walk reaches all 64 and a three-row community stays
//! under the 10% size cap. One A seed carries the query's only text match,
//! so A's community is active and B's is not.
//!
//! `cargo test --locked -p oneiron --all-features --test scoped_community_prior`
#![allow(clippy::expect_used)]

use oneiron::habit::TaskRole;
use oneiron::pipeline::ScoredEntity;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};

const LEARNED_AT: u64 = 1_772_400_000;
const QUERY: &str = "scopedcommunityprior";
const ISOLATES: u8 = 58;
const LIMIT: usize = 64;
const BETA: f32 = 0.25;

fn id(group: u8, index: u8) -> EntityId {
    EntityId::from_bytes([
        0x5c, 0x0f, 0x7e, group, index, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33,
    ])
    .expect("a fixture id")
}

/// The rows by role. Ids sort the two targets first (B before A), so a tie
/// lists target B first; then A's seeds, the isolates, and B's seeds, so
/// only A's seeds are among the first five seeds by evidence.
struct Rows {
    target_a: EntityId,
    target_b: EntityId,
    clique_a: [EntityId; 3],
    clique_b: [EntityId; 3],
    seeds: Vec<EntityId>,
    all: Vec<EntityId>,
}

fn rows() -> Rows {
    let target_b = id(0x01, 0x03);
    let target_a = id(0x01, 0x04);
    let a_text = id(0x02, 0x01);
    let a_other = id(0x02, 0x02);
    let b_seed = id(0x04, 0x01);
    let b_other = id(0x04, 0x02);
    let isolates: Vec<_> = (0..ISOLATES).map(|index| id(0x03, index)).collect();
    let mut seeds = vec![a_text, a_other, b_seed, b_other];
    seeds.extend(&isolates);
    seeds.sort();
    let mut all = seeds.clone();
    all.extend([target_a, target_b]);
    all.sort();
    Rows {
        target_a,
        target_b,
        clique_a: [a_text, a_other, target_a],
        clique_b: [b_seed, b_other, target_b],
        seeds,
        all,
    }
}

fn task_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::Task.role_byte()),
        )]),
    )
    .expect("a TASK body");
    body
}

fn at() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// Both directions of each clique pair: two distinct About records give
/// the pair a projected weight above the CPM penalty.
fn clique(vault: &Vault, members: [EntityId; 3]) {
    for source in members {
        for target in members {
            if source != target {
                vault
                    .put_edge(&source, EdgeKind::About, &target, 1.0)
                    .expect("a clique edge");
            }
        }
    }
}

fn vault(beta: f32, rows: &Rows) -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("a vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.ppr_community.beta = beta;
    let vault = Vault::open(directory.path(), config).expect("a vault");
    let body = task_body();
    for row in &rows.all {
        vault
            .put_entity(row, ENTITY_TYPE_TASK, at(), LEARNED_AT, &body)
            .expect("a TASK row");
    }
    clique(&vault, rows.clique_a);
    clique(&vault, rows.clique_b);
    vault
        .batch()
        .text(&rows.clique_a[0], &[("body", QUERY)])
        .commit()
        .expect("the query's one text match");
    let hits: Vec<_> = vault
        .search_text(QUERY, LIMIT)
        .expect("the text index")
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(
        hits,
        vec![rows.clique_a[0]],
        "fixture: the query matches one A seed"
    );
    (directory, vault)
}

fn walk(vault: &Vault, rows: &Rows, narrowed: bool) -> Vec<ScoredEntity> {
    let mut query = vault
        .query()
        .search_text(QUERY, LIMIT)
        .expand_ppr(&rows.seeds, 2);
    if narrowed {
        query = query.filter_types(&[ENTITY_TYPE_TASK]);
    }
    query.limit(LIMIT).run().expect("the walk runs")
}

fn score(scores: &[ScoredEntity], id: EntityId) -> (usize, f32) {
    scores
        .iter()
        .enumerate()
        .find(|(_, row)| row.id == id)
        .map(|(index, row)| (index, row.score))
        .expect("the target is returned")
}

/// Target A's lead over target B, and whether A is listed first.
fn lead(scores: &[ScoredEntity], rows: &Rows) -> (f32, bool) {
    let (index_a, score_a) = score(scores, rows.target_a);
    let (index_b, score_b) = score(scores, rows.target_b);
    (score_a - score_b, index_a < index_b)
}

#[test]
fn a_narrowed_expansion_takes_the_configured_community_prior() {
    let rows = rows();
    let (_off_directory, off) = vault(0.0, &rows);
    let (_on_directory, on) = vault(BETA, &rows);
    let baseline = walk(&off, &rows, true);
    let enabled = walk(&on, &rows, true);
    let (baseline_lead, _) = lead(&baseline, &rows);
    let (enabled_lead, a_first) = lead(&enabled, &rows);
    assert!(
        enabled_lead > baseline_lead,
        "beta {BETA} must raise target A (in the active community) over target B: \
         lead {enabled_lead} at beta {BETA}, {baseline_lead} at beta 0"
    );
    assert!(
        a_first,
        "target A must rank before target B once the prior applies"
    );
}

#[test]
fn a_row_the_walk_cannot_read_moves_no_narrowed_score() {
    let rows = rows();
    let (_directory, vault) = vault(BETA, &rows);
    let bits = |scores: Vec<ScoredEntity>| -> Vec<(EntityId, u32)> {
        scores
            .into_iter()
            .map(|row| (row.id, row.score.to_bits()))
            .collect()
    };
    let before = bits(walk(&vault, &rows, true));
    // A PERSON the type filter hides, joined to all of clique A and to one B
    // row: in the canonical graph it extends A and bridges A to B.
    let hidden = id(0x05, 0x01);
    vault
        .put_entity(&hidden, ENTITY_TYPE_PERSON, at(), LEARNED_AT, b"human")
        .expect("the hidden row");
    for target in rows.clique_a.into_iter().chain([rows.clique_b[0]]) {
        vault
            .put_edge(&hidden, EdgeKind::About, &target, 1.0)
            .expect("a hidden bridge edge");
    }
    // A fresh canonical snapshot holds the hidden row; the narrowed walk must
    // never read it.
    vault
        .refresh_ppr_communities(&[], LEARNED_AT)
        .expect("the canonical communities");
    let after = bits(walk(&vault, &rows, true));
    assert!(
        after.iter().all(|(row, _)| *row != hidden),
        "the hidden row is never returned"
    );
    assert_eq!(
        before, after,
        "a row the walk cannot read must move no returned row or score bit"
    );
}

#[test]
fn an_unnarrowed_expansion_of_the_same_rows_takes_the_prior() {
    let rows = rows();
    let (_off_directory, off) = vault(0.0, &rows);
    let (_on_directory, on) = vault(BETA, &rows);
    let (baseline_lead, _) = lead(&walk(&off, &rows, false), &rows);
    let (enabled_lead, a_first) = lead(&walk(&on, &rows, false), &rows);
    assert!(
        enabled_lead > baseline_lead && a_first,
        "control: the canonical walk of this fixture takes the prior \
         (lead {enabled_lead} at beta {BETA}, {baseline_lead} at beta 0)"
    );
}
