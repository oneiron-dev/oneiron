use rmpv::Value;
use tempfile::tempdir;

use super::*;

mod specificity_visibility;
use crate::batch::EdgeValueFields;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};
use crate::code_memory::{
    AttachCodeMemory, CodeMemoryAnchor, CodeMemoryLocator, CodeMemoryPayloadRef,
    CodeMemoryPullRequest, CodeMemoryPullResult, CodeMemoryRevision, CodeMemorySlotName,
    CodeMemorySlotValue,
};
use crate::{EdgeActorClass, EdgeKind, Error, TimeRange, Vad, Vault, edge::EdgeProvenanceFlags};

use crate::test_util::{
    embedding_test_config, entity, open_test_vault_with, put_policy_manifest_bytes,
};

fn score_for(scores: &[ScoredEntity], id: EntityId) -> f32 {
    scores
        .iter()
        .find(|scored| scored.id == id)
        .map_or(0.0, |scored| scored.score)
}

fn assert_scores_equal(left: &[ScoredEntity], right: &[ScoredEntity]) {
    assert_eq!(left.len(), right.len());
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        assert_eq!(lhs.id, rhs.id);
        assert!((lhs.score - rhs.score).abs() <= 1e-6);
    }
}

/// Plants a `ppr_cache` row directly (header `computed_at` chosen by the
/// test, current graph version, stale = 0) carrying a sentinel score so
/// a later query observably distinguishes "served from cache" (sentinel
/// comes back) from "recomputed" (it does not). Also writes the seed dep
/// rows so cleanup's liveness pass treats the row like a real one.
fn plant_cache_row(
    vault: &Vault,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
    weighting: SeedWeighting,
    computed_at: u64,
    scores: &[ScoredEntity],
) -> Result<[u8; SEED_HASH_LEN]> {
    let hash = hash_seeds(seeds, depth, alpha, 0.0, weighting);
    let version = graph_version(vault)?;
    let value = encode_cache_value(computed_at, version, 0, scores);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.ppr_cache.put(&mut wtxn, &hash, &value)?;
    for seed in seeds {
        let dep_key = encode_dep_key(seed, &hash);
        vault.store.ppr_cache_deps.put(&mut wtxn, &dep_key, &[])?;
    }
    wtxn.commit()?;
    Ok(hash)
}

fn plant_state_cache_row(
    vault: &Vault,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
    computed_at: u64,
    state: &PprCacheState,
) -> Result<[u8; SEED_HASH_LEN]> {
    let hash = hash_seeds(seeds, depth, alpha, 0.0, SeedWeighting::Uniform);
    let version = graph_version(vault)?;
    let value = encode_cache_value_with_state(computed_at, version, 0, state)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.ppr_cache.put(&mut wtxn, &hash, &value)?;
    for dependency in &state.dependencies {
        let dep_key = encode_dep_key(dependency, &hash);
        vault.store.ppr_cache_deps.put(&mut wtxn, &dep_key, &[])?;
    }
    wtxn.commit()?;
    Ok(hash)
}

fn sentinel_entity() -> EntityId {
    entity(0xEE)
}

fn state_magic_prefixed_entity() -> EntityId {
    let mut bytes = [0x11; ENTITY_ID_LEN];
    bytes[..CACHE_STATE_MAGIC.len()].copy_from_slice(CACHE_STATE_MAGIC);
    EntityId::from_bytes(bytes).expect("state-magic prefix is not a reserved entity id")
}

fn sentinel_scores() -> Vec<ScoredEntity> {
    vec![ScoredEntity {
        id: sentinel_entity(),
        score: 0.25,
    }]
}

fn graph_version(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    read_graph_version(&vault.store, &rtxn)
}

fn count_entries(db: &crate::overlay_db::OverlayDb, vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in db.iter(&rtxn)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn dep_exists(vault: &Vault, entity_id: EntityId, seed_hash: &[u8; SEED_HASH_LEN]) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let dep_key = encode_dep_key(&entity_id, seed_hash);
    Ok(vault.store.ppr_cache_deps.get(&rtxn, &dep_key)?.is_some())
}

/// Cache identity hashes `sorted seeds ‖ depth ‖ teleport_alpha ‖ ppr_vad_alpha ‖
/// FORMULA_VERSION ‖ weighting byte` with the LITERAL pinned values:
/// version 7 and mode bytes Uniform = 0 / Specificity = 1 (hand-built
/// here, NOT read from the constants, so a wrong bump fails). The two
/// weighting modes must never collide — `search_ppr` rows are not
/// servable to `expand_ppr` and vice versa.
#[test]
fn hash_seeds_uses_full_xxh3_digest_and_is_order_insensitive() {
    let a = entity(1);
    let b = entity(2);
    let depth: u32 = 3;
    let alpha: f32 = 0.15;

    let mut bytes = Vec::with_capacity(
        ENTITY_ID_LEN * 2 + 2 * std::mem::size_of::<u32>() + 2 * std::mem::size_of::<f32>() + 1,
    );
    bytes.extend_from_slice(a.as_bytes());
    bytes.extend_from_slice(b.as_bytes());
    bytes.extend_from_slice(&depth.to_le_bytes());
    bytes.extend_from_slice(&alpha.to_le_bytes());
    bytes.extend_from_slice(&0.0_f32.to_le_bytes());
    bytes.extend_from_slice(&7_u32.to_le_bytes());

    let mut uniform_bytes = bytes.clone();
    uniform_bytes.push(0_u8);
    let expected_uniform = xxh3_128(&uniform_bytes).to_le_bytes();

    let mut specificity_bytes = bytes;
    specificity_bytes.push(1_u8);
    let expected_specificity = xxh3_128(&specificity_bytes).to_le_bytes();

    assert_eq!(
        PPR_FORMULA_VERSION, 7,
        "project hub traversal must pin formula version 7"
    );
    assert_eq!(
        hash_seeds(&[a, b], depth, alpha, 0.0, SeedWeighting::Uniform),
        expected_uniform
    );
    assert_eq!(
        hash_seeds(&[a, b], depth, alpha, 0.0, SeedWeighting::Specificity),
        expected_specificity
    );
    assert_ne!(
        expected_uniform, expected_specificity,
        "uniform and specificity rows must never share a cache key"
    );
    assert_eq!(
        hash_seeds(&[a, b], depth, alpha, 0.0, SeedWeighting::Uniform),
        hash_seeds(&[b, a], depth, alpha, 0.0, SeedWeighting::Uniform)
    );
}

/// ONE-1100 AC5 — `part_of` hops are capped at exactly 2 (contract:
/// "Hop-limited (max 2)"): mass MUST arrive at 2 part_of hops and MUST
/// NOT arrive at 3. Chain: a −part_of(1.0)→ b −part_of(1.0)→ c
/// −part_of(1.0)→ d, seeds [a], α = 0.15.
///
/// Layer-1 derivation (D7), each hop a single same-kind edge so
/// w/s_out = 1.0 and λ_part_of = 0.8:
///   hop 1: b = 1.0  * (0.8 * 1.0 / 1.0) * 0.85 = 0.68
///   hop 2: c = 0.68 * (0.8 * 1.0 / 1.0) * 0.85 = 0.4624
///   hop 3: d — gated by the cap, never scored
/// At depth 2 the hop-2 contribution is c's ONLY one, so c = 0.4624
/// exactly — an off-by-one cap at 1 hop yields c = 0.0 and fails. The
/// depth-5 run then proves the CAP (not the depth budget) is what blocks
/// d: c keeps accumulating while d stays at exactly 0.0 — a cap at 3
/// hops would score d and fail.
#[test]
fn ppr_part_of_hop_limit_allows_second_hop_blocks_third() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(9);
    let b = entity(10);
    let c = entity(11);
    let d = entity(12);

    vault.put_edge(&a, EdgeKind::PartOf, &b, 1.0)?;
    vault.put_edge(&b, EdgeKind::PartOf, &c, 1.0)?;
    vault.put_edge(&c, EdgeKind::PartOf, &d, 1.0)?;

    let rtxn = vault.store.env.read_txn()?;

    // ALLOW side — exact Layer-1 value at depth 2 (derivation above).
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 2, 0.15)?;
    let c_score = score_for(&scores, c);
    assert!(
        (c_score - 0.4624).abs() <= 1e-6,
        "mass must arrive at exactly 2 part_of hops: got {c_score}, want 0.4624"
    );
    assert_eq!(score_for(&scores, d), 0.0);

    // BLOCK side — depth budget well beyond the cap.
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 5, 0.15)?;
    assert!(score_for(&scores, c) > 0.0);
    assert_eq!(
        score_for(&scores, d),
        0.0,
        "no mass may arrive at 3 part_of hops"
    );
    Ok(())
}

/// ONE-1100 AC1 — `child_of` and `assigned_to` carry zero PPR mass in
/// either traversal direction, regardless of the non-zero stored weight
/// bytes (contract `lambda: null`, "Not traversed.").
#[test]
fn child_of_and_assigned_to_are_never_traversed() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let child = entity(70);
    let parent = entity(0x67);
    let task = entity(72);
    let machine = entity(73);

    // ONE-1376: a ChildOf parent must be a real row. ASSET_TEXT keeps the pair
    // outside the TASK role matrix, which is not what this test is about.
    vault.put_entity(
        &parent,
        crate::registry::ENTITY_TYPE_ASSET_TEXT,
        TimeRange { start: 1, end: 1 },
        1,
        b"tree node",
    )?;
    vault.put_edge(&child, EdgeKind::ChildOf, &parent, 1.0)?;
    vault.put_edge(&task, EdgeKind::AssignedTo, &machine, 0.8)?;

    let rtxn = vault.store.env.read_txn()?;
    for seed in [child, parent, task, machine] {
        let scores = ppr_compute(&vault.store, &rtxn, &[seed], 5, 0.15)?;
        // The only path from every seed is a child_of / assigned_to edge
        // (forward via edges_out or reverse via edges_in) — zero
        // propagated mass means the seed is the single scored entity.
        assert_eq!(
            scores.len(),
            1,
            "seed {seed:?} must not propagate over child_of/assigned_to"
        );
        assert_eq!(scores[0].id, seed);
    }
    Ok(())
}

/// ONE-1100 AC3 — `opposes` blocks at the KIND level: an opposes edge
/// whose STORED weight byte is 1.0 still propagates zero (λ_opposes =
/// 0.0 — contradiction isolation must not depend on the weight byte).
#[test]
fn opposes_blocks_at_kind_level_with_nonzero_stored_weight() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(74);
    let b = entity(75);

    vault.put_edge(&a, EdgeKind::Opposes, &b, 1.0)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
    assert_eq!(scores.len(), 1, "opposes must not propagate");
    assert_eq!(scores[0].id, a);
    assert_eq!(score_for(&scores, b), 0.0);
    Ok(())
}

/// ONE-1100 AC6 (D8) — confirmation_status == retracted (3) skips the
/// edge entirely, INCLUDING its s_out contribution:
/// a −mentions(0.6)→ b (bare 24 B), a −mentions(0.6, retracted)→ c (26 B).
/// s_out(a, mentions) counts only the live edge = 0.6, so at depth 1
///   b = 1.0 * (0.6 * 0.6 / 0.6) * 0.85 = 0.51
///   (0.255 if the retracted edge still consumed normalizer mass)
///   c = 0.0 (skipped entirely — D8 factor 0)
#[test]
fn retracted_edges_skip_propagation_and_strength() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(100);
    let b = entity(101);
    let c = entity(102);

    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.6)?;
    vault
        .batch()
        .edge_with_value_fields(
            &a,
            EdgeKind::Mentions,
            &c,
            EdgeValueFields {
                weight: 0.6,
                created_at: 1,
                vad: Vad::NEUTRAL,
                provenance: Some(EdgeProvenanceFlags {
                    confirmation_status: EdgeConfirmationStatus::Retracted,
                    actor_class: EdgeActorClass::Human,
                }),
            },
        )
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;

    // The stamped row must really be the 26 B provenanced layout with the
    // contract's retracted discriminant (3) at offset 24.
    let key = Store::encode_edge_key(&a, EdgeKind::Mentions, &c);
    let raw = vault
        .store
        .edges_out
        .get(&rtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(raw.len(), 26);
    assert_eq!(raw[24], 3);

    let scores = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;
    let b_score = score_for(&scores, b);
    assert!(
        (b_score - 0.51).abs() <= 1e-6,
        "live edge must own the full normalizer, got {b_score}"
    );
    assert_eq!(score_for(&scores, c), 0.0, "retracted edge must be skipped");
    Ok(())
}

/// ONE-1100 AC6 (D8) — mixed-status edges from ONE source share ONE
/// same-kind normalizer at FULL weight. The per-status test above uses
/// one edge per source, where single-edge Layer-1 normalization cancels
/// ANY per-status weight factor f (w·f / s_out = w·f / w·f = 1.0); here
/// the three edges compete inside the same s_out, so any weight scaling
/// skews the shares and fails.
/// Graph: a −mentions(0.6, proposed)→ t1, a −mentions(0.6, confirmed)→ t2,
/// a −mentions(0.6, disputed)→ t3. Seeds [a], depth 1, α = 0.15:
///   s_out(a, mentions) = 0.6 + 0.6 + 0.6 = 1.8, λ_mentions = 0.6
///   t1 = t2 = t3 = 1.0 * (0.6 * 0.6 / 1.8) * 0.85 = 0.17
/// e.g. a 0.5 weight demotion on disputed gives s_out = 1.5 →
/// t1 = t2 = 0.204, t3 = 0.102 — every share moves off 0.17.
#[test]
fn same_source_mixed_statuses_share_normalizer_at_full_weight() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(130);
    let targets = [
        (entity(131), EdgeConfirmationStatus::Proposed),
        (entity(132), EdgeConfirmationStatus::Confirmed),
        (entity(133), EdgeConfirmationStatus::Disputed),
    ];

    let mut batch = vault.batch();
    for (target, status) in &targets {
        batch = batch.edge_with_value_fields(
            &a,
            EdgeKind::Mentions,
            target,
            EdgeValueFields {
                weight: 0.6,
                created_at: 1,
                vad: Vad::NEUTRAL,
                provenance: Some(EdgeProvenanceFlags {
                    confirmation_status: *status,
                    actor_class: EdgeActorClass::Agent,
                }),
            },
        );
    }
    batch.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;
    for (target, status) in targets {
        let got = score_for(&scores, target);
        assert!(
            (got - 0.17).abs() <= 1e-6,
            "{status:?} share must be 1.0 * (0.6 * 0.6 / 1.8) * 0.85 = 0.17, got {got}"
        );
    }
    Ok(())
}

#[test]
fn legacy_cache_row_with_state_magic_entity_id_stays_servable() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let seed = entity(18);
    let magic_id = state_magic_prefixed_entity();
    let sentinel = [ScoredEntity {
        id: magic_id,
        score: 0.25,
    }];

    plant_cache_row(
        &vault,
        &[seed],
        3,
        0.15,
        SeedWeighting::Uniform,
        crate::unix_seconds_now(),
        &sentinel,
    )?;

    let scores = ppr_query(&vault.store, &vault.config, &[seed], 3, 0.15)?;
    assert_eq!(scores, sentinel);
    Ok(())
}

#[test]
fn ppr_query_rejects_state_cache_hit_with_mismatched_completed_depth() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let seed = entity(18);
    let state = PprCacheState {
        residual: Vec::new(),
        push_threshold: super::walk::SCORE_EPSILON,
        completed_depth: 1,
        scores: sentinel_scores(),
        frontier: Vec::new(),
        dependencies: vec![seed],
    };

    plant_state_cache_row(&vault, &[seed], 3, 0.15, crate::unix_seconds_now(), &state)?;

    match ppr_query(&vault.store, &vault.config, &[seed], 3, 0.15) {
        Err(Error::CorruptedIndex(_)) => {}
        Err(err) => panic!("expected cache corruption, got {err:?}"),
        Ok(scores) => panic!("expected cache corruption, got scores {scores:?}"),
    }
    Ok(())
}

#[test]
fn cache_write_is_skipped_when_graph_version_changes_before_store() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(48);
    let b = entity(49);
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let stale_version = graph_version(&vault)?;
    let mut wtxn = vault.store.env.write_txn()?;
    increment_graph_version(&vault.store, &mut wtxn)?;
    wtxn.commit()?;

    let state = PprCacheState {
        residual: Vec::new(),
        push_threshold: super::walk::SCORE_EPSILON,
        completed_depth: 3,
        scores: vec![ScoredEntity { id: b, score: 1.0 }],
        frontier: Vec::new(),
        dependencies: vec![a],
    };
    let mut wtxn = vault.store.env.write_txn()?;
    let stored = store_cache_entry(
        &vault.store,
        &mut wtxn,
        &seed_hash,
        crate::unix_seconds_now(),
        stale_version,
        &state,
    )?;
    wtxn.commit()?;

    assert!(!stored);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_none());
    Ok(())
}

#[test]
fn store_cache_entry_replaces_dependency_rows_for_same_hash() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let seed = entity(83);
    let stale_dep = entity(84);
    let seed_hash = hash_seeds(&[seed], 3, 0.15, 0.0, SeedWeighting::Uniform);
    let graph_version = graph_version(&vault)?;
    let first_state = PprCacheState {
        residual: Vec::new(),
        push_threshold: super::walk::SCORE_EPSILON,
        completed_depth: 3,
        scores: vec![ScoredEntity {
            id: stale_dep,
            score: 0.25,
        }],
        frontier: Vec::new(),
        dependencies: vec![seed, stale_dep],
    };
    let second_state = PprCacheState {
        residual: Vec::new(),
        push_threshold: super::walk::SCORE_EPSILON,
        completed_depth: 3,
        scores: vec![ScoredEntity {
            id: seed,
            score: 1.0,
        }],
        frontier: Vec::new(),
        dependencies: vec![seed],
    };

    let mut wtxn = vault.store.env.write_txn()?;
    assert!(store_cache_entry(
        &vault.store,
        &mut wtxn,
        &seed_hash,
        crate::unix_seconds_now(),
        graph_version,
        &first_state,
    )?);
    wtxn.commit()?;
    assert!(dep_exists(&vault, stale_dep, &seed_hash)?);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 2);

    let mut wtxn = vault.store.env.write_txn()?;
    assert!(store_cache_entry(
        &vault.store,
        &mut wtxn,
        &seed_hash,
        crate::unix_seconds_now(),
        graph_version,
        &second_state,
    )?);
    wtxn.commit()?;

    assert!(dep_exists(&vault, seed, &seed_hash)?);
    assert!(!dep_exists(&vault, stale_dep, &seed_hash)?);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);
    Ok(())
}

#[test]
fn ppr_query_in_txn_uses_borrowed_snapshot_without_caching_stale_results() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(60);
    let b = entity(61);
    let c = entity(62);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let snapshot = vault.store.env.read_txn()?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 1.0)?;

    let borrowed = ppr_query_in_txn(&vault.store, &snapshot, &[a], 3, 0.15)?;
    assert!(score_for(&borrowed, b) > 0.0);
    assert!(score_for(&borrowed, c) <= SCORE_EPSILON);
    drop(snapshot);

    let latest = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&latest, c) > 0.0);
    Ok(())
}

/// `ppr_query` must reject non-finite persisted edge weights and cached
/// scores with a typed corruption error.
#[test]
fn ppr_query_rejects_non_finite_inputs() -> Result<()> {
    #[derive(Clone, Copy)]
    enum Site {
        EdgeWeight,
        CachedScores,
    }

    let cases: Vec<(&str, Site, u8, u8)> = vec![
        ("persisted_edge_weight", Site::EdgeWeight, 63, 64),
        ("cached_scores", Site::CachedScores, 65, 0x62),
    ];

    for (case_name, site, a_byte, b_byte) in cases {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
        let a = entity(a_byte);
        let b = entity(b_byte);

        let mut wtxn = vault.store.env.write_txn()?;
        match site {
            Site::EdgeWeight => {
                let key = Store::encode_edge_key(&a, EdgeKind::BelongsTo, &b);
                let mut value = [0_u8; EDGE_VALUE_STRUCTURAL_LEN];
                value[..4].copy_from_slice(&f32::NAN.to_le_bytes());
                vault.store.edges_out.put(&mut wtxn, &key, &value)?;
            }
            Site::CachedScores => {
                let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
                let cache = encode_cache_value(
                    crate::unix_seconds_now(),
                    read_graph_version(&vault.store, &wtxn)?,
                    0,
                    &[ScoredEntity {
                        id: b,
                        score: f32::INFINITY,
                    }],
                );
                vault.store.ppr_cache.put(&mut wtxn, &seed_hash, &cache)?;
            }
        }
        wtxn.commit()?;

        let err = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)
            .expect_err("expected corrupted state");
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "case {case_name}: expected CorruptedIndex, got {err:?}",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ONE-1608 / ARCH-0050 R6 L2 — actor-scoped, compute-only PPR
// ---------------------------------------------------------------------------

/// The typed failure [`DeniedNodes::failing`] raises, matched back by the
/// fail-closed test so a swallowed error cannot pass as a denial.
const PROBE_FAILURE: &str = "ppr visibility probe";

/// Test [`PprNodeVisibility`]: a fixed denied set, plus an optional id whose
/// probe FAILS, so the fail-closed path is observable without a policy stack.
struct DeniedNodes {
    denied: HashSet<EntityId>,
    fail_on: Option<EntityId>,
}

impl DeniedNodes {
    fn new(denied: &[EntityId]) -> Self {
        Self {
            denied: denied.iter().copied().collect(),
            fail_on: None,
        }
    }

    fn failing(fail_on: EntityId) -> Self {
        Self {
            denied: HashSet::new(),
            fail_on: Some(fail_on),
        }
    }
}

impl PprNodeVisibility for DeniedNodes {
    fn ppr_node_visible(&self, _txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if self.fail_on == Some(*id) {
            return Err(Error::CorruptedIndex(PROBE_FAILURE));
        }
        Ok(!self.denied.contains(id))
    }
}

fn score_bits(scores: &[ScoredEntity]) -> Vec<(EntityId, u32)> {
    scores
        .iter()
        .map(|scored| (scored.id, scored.score.to_bits()))
        .collect()
}

/// SCOPE BEFORE MASS. A node the actor cannot read is not a node the walk may
/// cross, in EITHER direction: the walk expands `edges_out` and `edges_in`
/// alike, so the fixture hangs one node off each side of the same denied
/// bridge — `far_out` two forward hops away, `far_in` two reverse hops away.
/// The unscoped walk scores both (that is what makes the denial meaningful);
/// the scoped walk scores neither, and never scores the bridge itself.
#[test]
fn scoped_ppr_never_traverses_a_denied_node() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let seed = entity(0x51);
    let bridge = entity(0x52);
    let far_out = entity(0x53);
    let far_in = entity(0x54);

    vault.put_edge(&seed, EdgeKind::About, &bridge, 0.5)?;
    vault.put_edge(&bridge, EdgeKind::About, &far_out, 0.5)?;
    vault.put_edge(&far_in, EdgeKind::About, &bridge, 0.5)?;

    let rtxn = vault.store.env.read_txn()?;
    let unscoped = ppr_query_in_txn(&vault.store, &rtxn, &[seed], 2, 0.15)?;
    assert!(score_for(&unscoped, bridge) > 0.0);
    assert!(
        score_for(&unscoped, far_out) > 0.0,
        "the forward reach exists to be denied"
    );
    assert!(
        score_for(&unscoped, far_in) > 0.0,
        "the reverse reach exists to be denied"
    );

    let visibility = DeniedNodes::new(&[bridge]);
    let scoped = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[seed],
        2,
        0.15,
        0.0,
        SeedWeighting::Uniform,
        &visibility,
    )?;
    assert_eq!(
        score_for(&scoped, bridge),
        0.0,
        "the denied bridge holds no mass of its own"
    );
    assert_eq!(
        score_for(&scoped, far_out),
        0.0,
        "no mass crosses the denied bridge forward"
    );
    assert_eq!(
        score_for(&scoped, far_in),
        0.0,
        "no mass crosses the denied bridge in reverse"
    );
    assert!(
        score_for(&scoped, seed) > 0.0,
        "the readable seed still holds its own mass"
    );
    Ok(())
}

/// The scope boundary's other half is SEED MASS. A denied seed contributes
/// none and dilutes nothing: the survivors renormalize to a full unit of
/// personalization, so the scoped run over `{readable, denied}` is exactly the
/// scoped run over `{readable}`. With every seed denied there is nothing left
/// to personalize, and the answer is empty rather than an unpersonalized
/// vault-wide ranking.
#[test]
fn scoped_ppr_renormalizes_seed_mass_and_empties_when_all_seeds_are_denied() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let readable = entity(0x55);
    let denied_seed = entity(0x56);
    let neighbor = entity(0x57);
    let denied_neighbor = entity(0x58);

    vault.put_edge(&readable, EdgeKind::About, &neighbor, 0.5)?;
    vault.put_edge(&denied_seed, EdgeKind::About, &denied_neighbor, 0.5)?;

    let rtxn = vault.store.env.read_txn()?;
    let visibility = DeniedNodes::new(&[denied_seed]);
    let both = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[readable, denied_seed],
        2,
        0.15,
        0.0,
        SeedWeighting::Uniform,
        &visibility,
    )?;
    let readable_only = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[readable],
        2,
        0.15,
        0.0,
        SeedWeighting::Uniform,
        &visibility,
    )?;
    assert_scores_equal(&both, &readable_only);
    assert_eq!(score_for(&both, denied_seed), 0.0);
    assert_eq!(
        score_for(&both, denied_neighbor),
        0.0,
        "a denied seed's neighbourhood is not reachable through the seed either"
    );

    let all_denied = DeniedNodes::new(&[readable, denied_seed]);
    let nothing = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[readable, denied_seed],
        2,
        0.15,
        0.0,
        SeedWeighting::Uniform,
        &all_denied,
    )?;
    assert!(
        nothing.is_empty(),
        "an all-denied seed set yields no ranking at all"
    );
    Ok(())
}

/// A visibility predicate that cannot ANSWER is not permission to traverse.
/// The error propagates out of the walk — on the seed gate and on the
/// neighbour gate alike — instead of being read as "visible".
#[test]
fn scoped_ppr_fails_closed_when_the_visibility_predicate_errors() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let seed = entity(0x5B);
    let neighbor = entity(0x5C);
    vault.put_edge(&seed, EdgeKind::About, &neighbor, 0.5)?;

    let rtxn = vault.store.env.read_txn()?;
    for failing in [DeniedNodes::failing(neighbor), DeniedNodes::failing(seed)] {
        let error = ppr_query_scoped_in_txn(
            &vault.store,
            &rtxn,
            &[seed],
            2,
            0.15,
            0.0,
            SeedWeighting::Uniform,
            &failing,
        )
        .expect_err("an undecidable node fails the walk closed");
        let is_probe_error = matches!(error, Error::CorruptedIndex(PROBE_FAILURE));
        assert!(is_probe_error, "the walk surfaces the probe's own error");
    }
    Ok(())
}

/// The manifest the end-to-end pull below installs: ONE `core:read` grant, for
/// ONE actor, with no scope and no budget. Any OTHER actor matches no grant
/// while a `core:read` grant exists, which is the landed denial arm of
/// `gate::scoped_read_claim_allowed` — so one manifest gives the fixture both
/// a permitted reader and a denied one.
fn single_reader_policy_manifest(actor_ref: &str) -> Vec<u8> {
    let grant = Value::Map(vec![
        (Value::from("actor_ref"), Value::from(actor_ref)),
        (Value::from("effector"), Value::from("core:read")),
        (
            Value::from("scope"),
            crate::federation::scope_codec::encode_scope_value(
                &crate::federation::scope_codec::read_preset(),
            )
            .unwrap(),
        ),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]);
    let grants = vec![grant];
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.2")),
        (Value::from("pack_id"), Value::from("code-memory-scoped")),
        (Value::from("pack_version"), Value::from("1")),
        (Value::from("min_engine_version"), Value::from("0.0.0")),
        (Value::from("defaults"), Value::Map(Vec::new())),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(Vec::new())),
        (Value::from("scoped_grants"), Value::Array(grants)),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("manifest encodes");
    data
}

fn actor_key(actor_ref: &str) -> ScopedReadActorKey {
    ScopedReadActorKey::new(actor_ref).expect("actor ref")
}

fn fixture_range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn scoped_pull_entity(vault: &Vault, byte: u8, kind: u8) -> Result<EntityId> {
    let id = entity(byte);
    let at = 1_780_000_000;
    vault.put_entity(&id, kind, fixture_range(at), at, b"x")?;
    Ok(id)
}

fn scoped_pull_bridge_claim(vault: &Vault, byte: u8, subject: EntityId) -> Result<EntityId> {
    let id = entity(byte);
    let at = 1_780_000_000;
    let body = ClaimBody::new(
        "code.memory.bridge",
        ClaimSubject::Entity(subject),
        Value::from("opaque bridge"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    vault.put_claim(&id, &body, fixture_range(at), at)?;
    Ok(id)
}

/// Mints one NOTE through the only door that writes a NOTE body, then attaches
/// it to `symbol_id`. The take is about an off-graph PERSON, so the fixture's
/// only paths between symbols are the ones it wires explicitly.
fn scoped_pull_note(
    vault: &Vault,
    author: EntityId,
    subject: EntityId,
    symbol_id: EntityId,
    content: u8,
) -> Result<EntityId> {
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_take(crate::note::TakeTarget::Subject(subject), "fixture take")
        .expect("mint a NOTE through the author_take door");
    let note_id = EntityId::from_hex(&receipt.id_hex).expect("receipt carries a hex id");
    let at = 1_780_000_100;
    let anchor = CodeMemoryAnchor {
        symbol_id,
        locator: CodeMemoryLocator {
            path_at_revision: "src/a.rs".to_owned(),
            revision: CodeMemoryRevision::Commit("9d561405a81ffbf2".to_owned()),
            validity: fixture_range(at),
        },
    };
    let value = CodeMemorySlotValue {
        payload: CodeMemoryPayloadRef::NoteEntity(note_id),
        actor_id: author,
        valid_time: fixture_range(at),
        recorded_at: at,
        content_hash: [content; 32],
        provenance_claim_id: author,
    };
    let slot_name = CodeMemorySlotName::new("interface.contract")?;
    vault.attach_code_memory(AttachCodeMemory {
        anchor,
        slot: slot_name,
        value,
    })?;
    Ok(note_id)
}

struct DeniedBridgeFixture {
    near: EntityId,
    note_near: EntityId,
    note_out: EntityId,
    note_in: EntityId,
}

/// Two `CODE_SYMBOL`s that `near` can reach ONLY through a CLAIM, one on each
/// traversal direction:
///
/// ```text
/// near --about--> bridge_out --about--> far_out     (forward, forward)
/// far_in --about--> bridge_in --about--> near       (reverse, reverse)
/// ```
///
/// Each of the three symbols carries its own attached NOTE; `near`'s is the
/// control that both actors must keep seeing.
fn build_denied_claim_bridge(vault: &Vault) -> Result<DeniedBridgeFixture> {
    let symbol_type = crate::registry::ENTITY_TYPE_CODE_SYMBOL;
    let person_type = crate::registry::ENTITY_TYPE_PERSON;
    let near = scoped_pull_entity(vault, 0x61, symbol_type)?;
    let far_out = scoped_pull_entity(vault, 0x62, symbol_type)?;
    let far_in = scoped_pull_entity(vault, 0x63, symbol_type)?;
    let claim_subject = scoped_pull_entity(vault, 0x64, person_type)?;
    let author = scoped_pull_entity(vault, 0x65, person_type)?;
    let note_subject = scoped_pull_entity(vault, 0x66, person_type)?;
    let bridge_out = scoped_pull_bridge_claim(vault, 0x67, claim_subject)?;
    let bridge_in = scoped_pull_bridge_claim(vault, 0x68, claim_subject)?;

    vault.put_edge(&near, EdgeKind::About, &bridge_out, 0.5)?;
    vault.put_edge(&bridge_out, EdgeKind::About, &far_out, 0.5)?;
    vault.put_edge(&far_in, EdgeKind::About, &bridge_in, 0.5)?;
    vault.put_edge(&bridge_in, EdgeKind::About, &near, 0.5)?;

    Ok(DeniedBridgeFixture {
        near,
        note_near: scoped_pull_note(vault, author, note_subject, near, 0x01)?,
        note_out: scoped_pull_note(vault, author, note_subject, far_out, 0x02)?,
        note_in: scoped_pull_note(vault, author, note_subject, far_in, 0x03)?,
    })
}

fn pulled_payload_ids(result: &CodeMemoryPullResult) -> Vec<EntityId> {
    let mut ids: Vec<EntityId> = result
        .notes
        .iter()
        .map(|note| note.data.payload.entity_id())
        .collect();
    ids.sort_unstable();
    ids
}

/// END TO END: an L2 pull ranks over the ACTOR-SCOPED walk, so a `CODE_SYMBOL`
/// reachable only across a ScopedRead-denied CLAIM contributes nothing to the
/// actor that cannot read the bridge — in EITHER direction — while the actor
/// that can read it still gets those notes. Both actors keep the seed's own
/// note, so the denial is a scope boundary and not an empty pull.
///
/// This is the property a post-ranking payload clamp cannot deliver: the mass
/// had already crossed the CLAIM, so membership AND order encoded structure
/// the denied actor may not see. The same pull writes no `ppr_cache` row, no
/// dependency row, and no graph version.
#[test]
fn pull_code_memory_does_not_rank_across_a_denied_claim_bridge() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let fixture = build_denied_claim_bridge(&vault)?;
    // Installed LAST: every fixture write above predates the manifest, so this
    // grant governs reads only.
    let manifest = single_reader_policy_manifest("code-memory-reader");
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut manifest.as_slice()).expect("manifest")
    else {
        panic!("map");
    };
    let (_, Value::Array(grants)) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scoped_grants"))
        .expect("grants")
    else {
        panic!("grants");
    };
    let mut metadata = crate::federation::scope_codec::read_preset();
    metadata.bands = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        crate::registry::ENTITY_TYPE_CODE_SYMBOL,
        crate::registry::ENTITY_TYPE_NOTE,
    ]));
    grants.push(Value::Map(vec![
        ("actor_ref".into(), "code-memory-intruder".into()),
        ("effector".into(), "core:read".into()),
        (
            "scope".into(),
            crate::federation::scope_codec::encode_scope_value(&metadata)?,
        ),
        ("receipt_required".into(), Value::Boolean(false)),
    ]));
    let mut manifest = Vec::new();
    rmpv::encode::write_value(&mut manifest, &Value::Map(entries)).expect("manifest");
    put_policy_manifest_bytes(&vault, entity(0x69), &manifest)?;

    let cache_before = count_entries(&vault.store.ppr_cache, &vault)?;
    let deps_before = count_entries(&vault.store.ppr_cache_deps, &vault)?;
    let version_before = graph_version(&vault)?;

    let request = CodeMemoryPullRequest::new(vec![fixture.near]);
    let reader = actor_key("code-memory-reader");
    let intruder = actor_key("code-memory-intruder");
    let permitted = vault.pull_code_memory(reader, request.clone())?;
    let denied = vault.pull_code_memory(intruder, request)?;

    let mut expected = vec![fixture.note_near, fixture.note_out, fixture.note_in];
    expected.sort_unstable();
    assert_eq!(
        pulled_payload_ids(&permitted),
        expected,
        "the actor who can read both bridges reaches every note behind them"
    );
    assert_eq!(
        pulled_payload_ids(&denied),
        vec![fixture.note_near],
        "the denied actor keeps the seed's own note and crosses neither bridge"
    );
    assert_eq!(
        count_entries(&vault.store.ppr_cache, &vault)?,
        cache_before,
        "an L2 pull writes no row into the shared, actor-less cache"
    );
    assert_eq!(
        count_entries(&vault.store.ppr_cache_deps, &vault)?,
        deps_before,
        "and no dependency row for a cache row that was never written"
    );
    assert_eq!(
        graph_version(&vault)?,
        version_before,
        "a pull is a read: it never bumps the graph version"
    );
    Ok(())
}

#[test]
fn ppr_vad_gate_carries_canonical_stored_layouts() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    for (target, kind, provenance, len) in [
        (entity(2), EdgeKind::BelongsTo, None, 12),
        (entity(3), EdgeKind::Mentions, None, 24),
        (
            entity(4),
            EdgeKind::Mentions,
            Some(EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Confirmed,
                actor_class: EdgeActorClass::Human,
            }),
            26,
        ),
    ] {
        let vad = if len == 12 {
            Vad::NEUTRAL
        } else {
            Vad {
                valence: -0.8,
                arousal: 0.9,
                dominance: 0.4,
            }
        };
        vault
            .batch()
            .edge_with_value_fields(
                &seed,
                kind,
                &target,
                EdgeValueFields {
                    weight: 0.6,
                    created_at: 1,
                    vad,
                    provenance,
                },
            )
            .commit()?;
        let txn = vault.store.env.read_txn()?;
        let key = Store::encode_edge_key(&seed, kind, &target);
        let value = vault.store.edges_out.get(&txn, &key)?.expect("stored edge");
        assert_eq!(value.len(), len);
        let edge =
            crate::ports::EdgeStoreRead::port_edge_get(&vault.store, &txn, &seed, kind, &target)?
                .expect("stored edge decodes through port");
        let gated = gate_edge(&vault.store, &txn, &seed, &edge, 0)?.expect("traversable");
        assert_eq!(gated.vad, if len == 12 { None } else { Some(vad) });
    }
    Ok(())
}

#[test]
fn scoped_ppr_vad_preserves_visibility_and_no_cache() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    let visible = entity(2);
    let denied = entity(3);
    for target in [visible, denied] {
        vault.put_edge(&seed, EdgeKind::Mentions, &target, 1.0)?;
        vault.set_edge_vad(
            &seed,
            EdgeKind::Mentions,
            &target,
            Vad {
                valence: -1.0,
                arousal: 1.0,
                dominance: 0.0,
            },
        )?;
    }
    // Warm a vault-wide row containing the denied member; scoped calls must
    // neither serve it nor overwrite it, at zero or nonzero alpha.
    ppr_query(&vault.store, &vault.config, &[seed], 1, 0.15)?;
    let cache_before = count_entries(&vault.store.ppr_cache, &vault)?;
    let deps_before = count_entries(&vault.store.ppr_cache_deps, &vault)?;
    let txn = vault.store.env.read_txn()?;
    let visibility = DeniedNodes::new(&[denied]);
    let query = |alpha| {
        ppr_query_scoped_in_txn(
            &vault.store,
            &txn,
            &[seed],
            1,
            0.15,
            alpha,
            SeedWeighting::Specificity,
            &visibility,
        )
    };
    let zero = query(0.0)?;
    assert_eq!(score_bits(&zero), score_bits(&query(-0.0)?));
    assert_eq!(
        score_for(&zero, visible).to_bits(),
        (0.6_f32 * 0.85).to_bits()
    );
    let weighted = query(0.4)?;
    assert!(score_for(&weighted, visible) > score_for(&zero, visible));
    assert_eq!(score_for(&weighted, denied), 0.0);
    assert_eq!(score_bits(&weighted), score_bits(&query(0.4)?));
    for alpha in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 0.41] {
        assert!(matches!(query(alpha), Err(Error::InvalidConfig(_))));
        for seeds in [&[][..], &[denied][..]] {
            assert!(matches!(
                ppr_query_scoped_in_txn(
                    &vault.store,
                    &txn,
                    seeds,
                    0,
                    0.15,
                    alpha,
                    SeedWeighting::Uniform,
                    &visibility
                ),
                Err(Error::InvalidConfig(_))
            ));
        }
    }
    drop(txn);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, cache_before);
    assert_eq!(
        count_entries(&vault.store.ppr_cache_deps, &vault)?,
        deps_before
    );
    Ok(())
}

#[test]
fn pull_code_memory_threads_vad_alpha_and_rejects_invalid_config() -> Result<()> {
    let (_dir, mut vault) = open_test_vault_with(VaultConfig::device());
    let symbol_type = crate::registry::ENTITY_TYPE_CODE_SYMBOL;
    let person_type = crate::registry::ENTITY_TYPE_PERSON;
    let seed = scoped_pull_entity(&vault, 0x71, symbol_type)?;
    let neutral = scoped_pull_entity(&vault, 0x72, symbol_type)?;
    let salient = scoped_pull_entity(&vault, 0x73, symbol_type)?;
    let author = scoped_pull_entity(&vault, 0x74, person_type)?;
    let subject = scoped_pull_entity(&vault, 0x75, person_type)?;
    let _neutral_note = scoped_pull_note(&vault, author, subject, neutral, 1)?;
    let salient_note = scoped_pull_note(&vault, author, subject, salient, 2)?;
    for target in [neutral, salient] {
        vault.put_edge(&seed, EdgeKind::Mentions, &target, 1.0)?;
    }
    vault.set_edge_vad(
        &seed,
        EdgeKind::Mentions,
        &salient,
        Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x79),
        &single_reader_policy_manifest("vad-reader"),
    )?;
    let mut request = CodeMemoryPullRequest::new(vec![seed]);
    request.minimum_relevance = 0.35;
    let cache_before = count_entries(&vault.store.ppr_cache, &vault)?;
    let deps_before = count_entries(&vault.store.ppr_cache_deps, &vault)?;
    for alpha in [0.0, -0.0] {
        vault.config.ppr_vad_alpha = alpha;
        let result = vault.pull_code_memory(actor_key("vad-reader"), request.clone())?;
        assert!(result.notes.is_empty());
    }
    vault.config.ppr_vad_alpha = 0.4;
    let weighted = vault.pull_code_memory(actor_key("vad-reader"), request.clone())?;
    assert_eq!(pulled_payload_ids(&weighted), vec![salient_note]);
    for alpha in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 0.41] {
        vault.config.ppr_vad_alpha = alpha;
        assert!(matches!(
            vault.pull_code_memory(actor_key("vad-reader"), request.clone()),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            vault.pull_code_memory(
                actor_key("vad-reader"),
                CodeMemoryPullRequest::new(Vec::new())
            ),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, cache_before);
    assert_eq!(
        count_entries(&vault.store.ppr_cache_deps, &vault)?,
        deps_before
    );
    Ok(())
}

fn community_ppr_fixture(vault: &Vault) -> Result<()> {
    // Keep 100 fixture nodes without aliasing any production-pinned identity.
    // The low, unpinned IDs used by the graph and query assertions stay unchanged.
    for n in (1..=u8::MAX)
        .filter(|n| !crate::test_util::PINNED_ID_BYTES.contains(n))
        .take(100)
    {
        vault.put_entity(&entity(n), 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
    }
    vault.put_edge(&entity(1), EdgeKind::BelongsTo, &entity(2), 1.0)?;
    vault.put_edge(&entity(1), EdgeKind::Supports, &entity(3), 1.0)?;
    Ok(())
}

fn community_query_for_test(
    vault: &Vault,
    config: &VaultConfig,
    weighting: SeedWeighting,
    depth: u32,
    context: &crate::ppr_community::CommunityBoostContext<'_>,
) -> Result<(
    Vec<ScoredEntity>,
    crate::ppr_community::CommunityBoostReport,
)> {
    let mut seeds: Vec<_> = context.ordered_seeds.iter().map(|seed| seed.id).collect();
    seeds.sort_unstable();
    let (scores, write, report) = {
        let txn = vault.store.env.read_txn()?;
        ppr_query_in_txn_with_community_deferred_cache(
            &vault.store,
            &txn,
            CommunityPprRequest {
                seeds: &seeds,
                depth,
                teleport_alpha: 0.15,
                weighting,
                config,
                context,
            },
        )?
    };
    if let Some(write) = write {
        flush_deferred_ppr_cache_writes(&vault.store, &[write])?;
    }
    Ok((scores, report))
}

#[test]
fn ppr_community_deferred_snapshot_is_not_published_after_graph_race() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &[ScoredEntity {
            id: entity(1),
            score: 1.0,
        }],
        result_limit: 10,
        session_usage: &usage,
    };
    let write = {
        let txn = vault.store.env.read_txn()?;
        let (_, write, _) = ppr_query_in_txn_with_community_deferred_cache(
            &vault.store,
            &txn,
            CommunityPprRequest {
                seeds: &[entity(1)],
                depth: 1,
                teleport_alpha: 0.15,
                weighting: SeedWeighting::Uniform,
                config: &config,
                context: &context,
            },
        )?;
        write.expect("deferred")
    };
    let key = write.seed_hash;
    vault.put_edge(&entity(4), EdgeKind::About, &entity(5), 1.0)?;
    flush_deferred_ppr_cache_writes(&vault.store, &[write])?;
    let txn = vault.store.env.read_txn()?;
    assert!(vault.store.ppr_cache.get(&txn, &key)?.is_none());
    assert!(vault.store.ppr_community_snapshot_in_txn(&txn)?.is_none());
    Ok(())
}

#[test]
fn ppr_community_shared_snapshot_never_enters_the_scoped_hidden_bridge_walk() -> Result<()> {
    struct Visibility;
    impl PprNodeVisibility for Visibility {
        fn ppr_node_visible(&self, _txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
            Ok(*id != entity(2))
        }
    }
    let mut config = embedding_test_config();
    config.ppr_community.beta = 0.2;
    let (_dir, vault) = open_test_vault_with(config);
    for n in 1..=3 {
        vault.put_entity(&entity(n), 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
    }
    vault.put_edge(&entity(1), EdgeKind::BelongsTo, &entity(2), 1.0)?;
    vault.put_edge(&entity(2), EdgeKind::BelongsTo, &entity(3), 1.0)?;
    let mut txn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut txn, b"ppr_community_cache:v0:meta", b"corrupt")?;
    txn.commit()?;
    let txn = vault.store.env.read_txn()?;
    let scores = ppr_query_scoped_in_txn(
        &vault.store,
        &txn,
        &[entity(1)],
        2,
        0.15,
        vault.config.ppr_vad_alpha,
        SeedWeighting::Uniform,
        &Visibility,
    )?;
    assert_eq!(
        scores.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![entity(1)]
    );
    assert_eq!(vault.store.ppr_cache.len(&txn)?, 0);
    Ok(())
}

#[test]
fn ppr_community_indexed_hot_query_ignores_unrelated_rows_but_full_refresh_rejects_them()
-> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let seeds = [ScoredEntity {
        id: entity(1),
        score: 1.0,
    }];
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &seeds,
        result_limit: 10,
        session_usage: &usage,
    };
    let (expected, _) =
        community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    let key = format!("ppr_community_cache:v0:node:{}", entity(100).to_hex());
    let mut txn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut txn, key.as_bytes(), b"corrupt")?;
    txn.commit()?;
    let (actual, _) =
        community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert_scores_equal(&actual, &expected);
    {
        let txn = vault.store.env.read_txn()?;
        assert!(matches!(
            vault.store.ppr_community_snapshot_in_txn(&txn),
            Err(Error::CorruptedIndex(_))
        ));
    }
    // Stale snapshots still validate the entire previous family before refresh.
    vault.put_edge(&entity(1), EdgeKind::About, &entity(3), 1.0)?;
    assert!(matches!(
        community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        vault.refresh_ppr_communities(&[], 44),
        Err(Error::CorruptedIndex(_))
    ));
    Ok(())
}

#[test]
fn ppr_community_indexed_accessed_corruption_fails_before_any_publish() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    community_ppr_fixture(&vault)?;
    vault.refresh_ppr_communities(&[], 42)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let seeds = [ScoredEntity {
        id: entity(1),
        score: 1.0,
    }];
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &seeds,
        result_limit: 10,
        session_usage: &usage,
    };
    let original = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .ppr_community_snapshot_in_txn(&txn)?
            .expect("snapshot")
    };
    let membership = original.nodes[&entity(1)];
    let node = |id: EntityId| format!("ppr_community_cache:v0:node:{}", id.to_hex()).into_bytes();
    let members = |id: crate::ppr_community::CommunityId| {
        format!("ppr_community_cache:v0:members:{}", id.to_hex()).into_bytes()
    };
    let encoded = original.encode_rows().expect("rows");
    let mut wrong_node = encoded[&node(entity(1))].clone();
    wrong_node[..16].copy_from_slice(original.nodes[&entity(3)].fine.as_bytes());
    let mut reversed = encoded[&members(membership.fine)].clone();
    reversed.rotate_left(16);
    let mut reserved = encoded[&members(membership.fine)].clone();
    reserved[..16].fill(0);
    let mut wrong_count = encoded[b"ppr_community_cache:v0:meta".as_slice()].clone();
    wrong_count[21..29].copy_from_slice(&100_001_u64.to_le_bytes());
    let mutations = [
        (node(entity(1)), Some(b"truncated".to_vec())),
        (node(entity(2)), None), // accessed member backlink, not a seed
        (node(entity(2)), Some(wrong_node)),
        (node(entity(3)), Some(b"bad candidate".to_vec())), // PPR candidate, not seed
        (node(entity(3)), None), // missing live singleton must not become unknown
        (members(membership.fine), None),
        (members(membership.fine), Some(reversed)),
        (members(membership.fine), Some(reserved)),
        (b"ppr_community_cache:v0:meta".to_vec(), Some(wrong_count)),
        (b"ppr_community_cache:v0:meta".to_vec(), None),
    ];
    for (key, value) in mutations {
        let mut txn = vault.store.env.write_txn()?;
        vault
            .store
            .replace_ppr_community_cache_in_txn(&mut txn, &original)?;
        if let Some(value) = value {
            vault.store.vault_meta.put(&mut txn, &key, &value)?;
        } else {
            vault.store.vault_meta.delete(&mut txn, &key)?;
        }
        txn.commit()?;
        let before = count_entries(&vault.store.ppr_cache, &vault)?;
        assert!(
            matches!(
                community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context),
                Err(Error::CorruptedIndex(_))
            ),
            "{}",
            String::from_utf8_lossy(&key)
        );
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, before);
    }
    Ok(())
}

#[test]
fn ppr_community_indexed_view_tracks_supplied_transaction_not_latest_commit() -> Result<()> {
    use crate::ppr_community::{CommunityBoostContext, CommunitySnapshot};
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    community_ppr_fixture(&vault)?;
    vault.refresh_ppr_communities(&[], 42)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let seeds = [ScoredEntity {
        id: entity(1),
        score: 1.0,
    }];
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &seeds,
        result_limit: 10,
        session_usage: &usage,
    };
    let query = |txn: &RoTxn<'_>| {
        ppr_query_in_txn_with_community_deferred_cache(
            &vault.store,
            txn,
            CommunityPprRequest {
                seeds: &[entity(1)],
                depth: 1,
                teleport_alpha: 0.15,
                weighting: SeedWeighting::Uniform,
                config: &config,
                context: &context,
            },
        )
    };
    let old_read = vault.store.env.read_txn()?;
    let original = vault
        .store
        .ppr_community_snapshot_in_txn(&old_read)?
        .expect("original");
    let (expected, _, _) = query(&old_read)?;
    let singletons: Vec<_> = original.nodes.keys().map(|&id| vec![id]).collect();
    let replacement = CommunitySnapshot::from_partitions(original.meta, &singletons, &singletons)
        .expect("same-version different partition");
    {
        let mut txn = vault.store.env.write_txn()?;
        vault
            .store
            .replace_ppr_community_cache_in_txn(&mut txn, &replacement)?;
        let (changed, _, _) = query(&txn)?;
        assert_ne!(changed, expected, "read-your-writes must use replacement");
        // Abort must not install any reusable query state.
    }
    assert_eq!(query(&old_read)?.0, expected);
    // LMDB permits only one active read transaction per thread with TLS enabled.
    // Keep old_read on this thread and open fresh snapshots on scoped threads.
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<()> {
                let txn = vault.store.env.read_txn()?;
                assert_eq!(query(&txn)?.0, expected);
                Ok(())
            })
            .join()
            .expect("post-abort reader panicked")
    })?;
    {
        let mut txn = vault.store.env.write_txn()?;
        vault
            .store
            .replace_ppr_community_cache_in_txn(&mut txn, &replacement)?;
        txn.commit()?;
    }
    assert_eq!(
        query(&old_read)?.0,
        expected,
        "old read sees old same-version rows"
    );
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<()> {
                {
                    let txn = vault.store.env.read_txn()?;
                    assert_ne!(
                        query(&txn)?.0,
                        expected,
                        "new read sees committed replacement"
                    );
                }
                // The mutation may open its own read transaction for validation.
                vault.put_edge(&entity(1), EdgeKind::About, &entity(3), 1.0)?;
                Ok(())
            })
            .join()
            .expect("post-commit reader and graph mutation panicked")
    })?;
    assert_eq!(
        query(&old_read)?.0,
        expected,
        "old graph and metadata stay paired"
    );
    drop(old_read);
    {
        let txn = vault.store.env.read_txn()?;
        let (_, pending, _) = query(&txn)?;
        let pending = pending.expect("stale full refresh");
        assert!(pending.community_snapshot.is_some());
        assert_eq!(
            pending.graph_version,
            read_graph_version(&vault.store, &txn)?
        );
    }
    Ok(())
}

#[test]
fn ppr_community_indexed_views_do_not_cross_vaults_at_equal_graph_versions() -> Result<()> {
    use crate::ppr_community::CommunitySnapshot;
    let (_dir_a, a) = open_test_vault_with(VaultConfig::device());
    let (_dir_b, b) = open_test_vault_with(VaultConfig::device());
    community_ppr_fixture(&a)?;
    community_ppr_fixture(&b)?;
    a.refresh_ppr_communities(&[], 42)?;
    b.refresh_ppr_communities(&[], 42)?;
    let read_a = a.store.env.read_txn()?;
    let original = a
        .store
        .ppr_community_snapshot_in_txn(&read_a)?
        .expect("snapshot");
    let singletons: Vec<_> = original.nodes.keys().map(|&id| vec![id]).collect();
    let snapshot = CommunitySnapshot::from_partitions(original.meta, &singletons, &singletons)
        .expect("snapshot");
    let mut write = b.store.env.write_txn()?;
    assert_eq!(
        read_graph_version(&a.store, &read_a)?,
        read_graph_version(&b.store, &write)?
    );
    b.store
        .replace_ppr_community_cache_in_txn(&mut write, &snapshot)?;
    write.commit()?;
    let selected = std::collections::BTreeSet::from([entity(1), entity(2)]);
    let view_a = a
        .store
        .ppr_community_query_view_in_txn(&read_a, &selected)?;
    let read_b = b.store.env.read_txn()?;
    let view_b = b
        .store
        .ppr_community_query_view_in_txn(&read_b, &selected)?;
    assert_eq!(view_a.nodes[&entity(1)], original.nodes[&entity(1)]);
    assert_eq!(view_b.nodes[&entity(1)], snapshot.nodes[&entity(1)]);
    assert_ne!(view_a.nodes[&entity(1)], view_b.nodes[&entity(1)]);
    Ok(())
}

#[test]
fn ppr_community_indexed_nested_members_validate_all_backlinks() -> Result<()> {
    use crate::ppr_community::{CommunityBoostContext, CommunitySnapshot};
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    community_ppr_fixture(&vault)?;
    vault.refresh_ppr_communities(&[], 42)?;
    let original = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .ppr_community_snapshot_in_txn(&txn)?
            .expect("snapshot")
    };
    let mut fine = vec![vec![entity(1), entity(2)], vec![entity(3)]];
    let mut coarse = vec![vec![entity(1), entity(2), entity(3)]];
    for &id in original.nodes.keys() {
        if ![entity(1), entity(2), entity(3)].contains(&id) {
            fine.push(vec![id]);
            coarse.push(vec![id]);
        }
    }
    let nested = CommunitySnapshot::from_partitions(original.meta, &fine, &coarse).expect("nested");
    let selected = std::collections::BTreeSet::from([entity(1)]);
    let mut txn = vault.store.env.write_txn()?;
    vault
        .store
        .replace_ppr_community_cache_in_txn(&mut txn, &nested)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let seeds = [entity(1)];
    let ordered_seeds = [ScoredEntity {
        id: entity(1),
        score: 1.0,
    }];
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &ordered_seeds,
        result_limit: 10,
        session_usage: &usage,
    };
    let query = |txn: &RoTxn<'_>| {
        ppr_query_in_txn_with_community_deferred_cache(
            &vault.store,
            txn,
            CommunityPprRequest {
                seeds: &seeds,
                depth: 1,
                teleport_alpha: 0.15,
                weighting: SeedWeighting::Uniform,
                config: &config,
                context: &context,
            },
        )
    };
    let (scores, _, _) = query(&txn)?;
    assert!(score_for(&scores, entity(2)) > 0.0);
    assert!(score_for(&scores, entity(3)) > 0.0);
    let encoded = nested.encode_rows().expect("rows");
    // The unselected third member is in the accessed coarse row. A valid-size
    // node value that points at another coarse parent is still corruption.
    let key = format!("ppr_community_cache:v0:node:{}", entity(3).to_hex());
    let mut wrong = encoded[key.as_bytes()].clone();
    wrong[16..].copy_from_slice(nested.nodes[&entity(4)].coarse.as_bytes());
    vault
        .store
        .vault_meta
        .put(&mut txn, key.as_bytes(), &wrong)?;
    assert!(matches!(
        vault.store.ppr_community_query_view_in_txn(&txn, &selected),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(query(&txn), Err(Error::CorruptedIndex(_))));
    // Likewise, a valid fine row from elsewhere cannot stand in for this group.
    vault
        .store
        .replace_ppr_community_cache_in_txn(&mut txn, &nested)?;
    let key = format!(
        "ppr_community_cache:v0:members:{}",
        nested.nodes[&entity(1)].fine.to_hex()
    );
    vault
        .store
        .vault_meta
        .put(&mut txn, key.as_bytes(), entity(3).as_bytes())?;
    assert!(matches!(
        vault.store.ppr_community_query_view_in_txn(&txn, &selected),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(query(&txn), Err(Error::CorruptedIndex(_))));
    Ok(())
}

#[test]
fn cache_decoder_refuses_duplicate_scores_and_frontier_residual_keys() -> Result<()> {
    let id = entity(123);
    let entry = super::walk::PprFrontierEntry {
        id,
        structural_hops: 0,
        score: 0.5,
    };
    for duplicate in 0..4 {
        let mut state = PprCacheState {
            completed_depth: 1,
            scores: vec![ScoredEntity { id, score: 1.0 }],
            frontier: vec![entry.clone()],
            dependencies: vec![id],
            residual: vec![],
            push_threshold: SCORE_EPSILON,
        };
        match duplicate {
            0 => state.scores.push(ScoredEntity { id, score: 1.0 }),
            1 => state.frontier.push(entry.clone()),
            2 => state.residual.push(super::walk::PprFrontierEntry {
                score: SCORE_EPSILON / 2.0,
                ..entry.clone()
            }),
            _ => {
                state.frontier.clear();
                state.residual = vec![
                    super::walk::PprFrontierEntry {
                        score: SCORE_EPSILON / 2.0,
                        ..entry.clone()
                    };
                    2
                ];
            }
        }
        let bytes = encode_cache_value_with_state(1, 1, 0, &state)?;
        assert!(matches!(
            decode_cache_state(&bytes[CACHE_HEADER_LEN..]),
            Err(Error::CorruptedIndex(_))
        ));
    }
    Ok(())
}

#[test]
fn cache_state_threshold_is_pinned_to_writer_value() -> Result<()> {
    let id = entity(124);
    let mut state = PprCacheState {
        completed_depth: 0,
        scores: vec![ScoredEntity { id, score: 1.0 }],
        frontier: Vec::new(),
        dependencies: vec![id],
        residual: vec![super::walk::PprFrontierEntry {
            id,
            structural_hops: 0,
            score: SCORE_EPSILON / 2.0,
        }],
        push_threshold: SCORE_EPSILON,
    };
    let bytes = encode_cache_value_with_state(1, 1, 0, &state)?;
    assert!(decode_cache_state(&bytes[CACHE_HEADER_LEN..]).is_ok());
    for threshold in [
        0.0,
        -0.0,
        1.0,
        f32::from_bits(SCORE_EPSILON.to_bits() + 1),
        f32::INFINITY,
        f32::NAN,
    ] {
        let mut payload = bytes[CACHE_HEADER_LEN..].to_vec();
        payload[25..29].copy_from_slice(&threshold.to_le_bytes());
        assert!(matches!(
            decode_cache_state(&payload),
            Err(Error::CorruptedIndex(_))
        ));
        state.push_threshold = threshold;
        assert!(matches!(
            encode_cache_value_with_state(1, 1, 0, &state),
            Err(Error::CorruptedIndex(_))
        ));
    }
    Ok(())
}

#[test]
fn cache_scores_refuse_negative_mass_at_both_codec_doors() -> Result<()> {
    let id = entity(125);
    let mut state = PprCacheState {
        completed_depth: 0,
        scores: vec![ScoredEntity { id, score: 1.0 }],
        frontier: Vec::new(),
        dependencies: vec![id],
        residual: Vec::new(),
        push_threshold: SCORE_EPSILON,
    };
    let bytes = encode_cache_value_with_state(1, 1, 0, &state)?;
    for score in [-1.0, -f32::MIN_POSITIVE, -f32::from_bits(1)] {
        let mut payload = bytes[CACHE_HEADER_LEN..].to_vec();
        payload[45..49].copy_from_slice(&score.to_le_bytes());
        assert!(matches!(
            decode_cache_state(&payload),
            Err(Error::CorruptedIndex(_))
        ));
        state.scores[0].score = score;
        assert!(matches!(
            encode_cache_value_with_state(1, 1, 0, &state),
            Err(Error::CorruptedIndex(_))
        ));
    }
    for score in [0.0, 1.0] {
        state.scores[0].score = score;
        let bytes = encode_cache_value_with_state(1, 1, 0, &state)?;
        assert_eq!(
            decode_cache_state(&bytes[CACHE_HEADER_LEN..])?.scores[0]
                .score
                .to_bits(),
            score.to_bits()
        );
    }
    Ok(())
}
