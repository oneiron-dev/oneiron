use rmpv::Value;
use tempfile::tempdir;

use super::*;
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

fn cache_row(vault: &Vault, seeds: &[EntityId], depth: u32, alpha: f32) -> Result<Vec<u8>> {
    let hash = hash_seeds(
        seeds,
        depth,
        alpha,
        vault.config.ppr_vad_alpha,
        SeedWeighting::Uniform,
    );
    let rtxn = vault.store.env.read_txn()?;
    let row = vault
        .store
        .ppr_cache
        .get(&rtxn, &hash)?
        .ok_or(Error::EntityNotFound)?;
    Ok(row.to_vec())
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

fn cached_state(
    vault: &Vault,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> Result<PprCacheState> {
    let row = cache_row(vault, seeds, depth, alpha)?;
    decode_cache_state(&row[CACHE_HEADER_LEN..])
}

fn dep_exists(vault: &Vault, entity_id: EntityId, seed_hash: &[u8; SEED_HASH_LEN]) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let dep_key = encode_dep_key(&entity_id, seed_hash);
    Ok(vault.store.ppr_cache_deps.get(&rtxn, &dep_key)?.is_some())
}

fn delete_dep_rows_for_hash(vault: &Vault, seed_hash: &[u8; SEED_HASH_LEN]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut keys = Vec::new();
    for entry in vault.store.ppr_cache_deps.iter(&wtxn)? {
        let (key, _) = entry?;
        if key.len() == CACHE_DEP_KEY_LEN && &key[ENTITY_ID_LEN..] == seed_hash {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        vault.store.ppr_cache_deps.delete(&mut wtxn, &key)?;
    }
    wtxn.commit()?;
    Ok(())
}

fn legacy_cache_key(byte: u8) -> [u8; LEGACY_SEED_HASH_LEN] {
    [byte; LEGACY_SEED_HASH_LEN]
}

fn legacy_dep_key(
    entity_id: EntityId,
    seed_hash: [u8; LEGACY_SEED_HASH_LEN],
) -> [u8; LEGACY_CACHE_DEP_KEY_LEN] {
    let mut key = [0_u8; LEGACY_CACHE_DEP_KEY_LEN];
    key[..ENTITY_ID_LEN].copy_from_slice(entity_id.as_bytes());
    key[ENTITY_ID_LEN..].copy_from_slice(&seed_hash);
    key
}

/// Cache identity hashes `sorted seeds ‖ depth ‖ teleport_alpha ‖ ppr_vad_alpha ‖
/// FORMULA_VERSION ‖ weighting byte` with the LITERAL pinned values:
/// version 5 and mode bytes Uniform = 0 / Specificity = 1 (hand-built
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
    bytes.extend_from_slice(&5_u32.to_le_bytes());

    let mut uniform_bytes = bytes.clone();
    uniform_bytes.push(0_u8);
    let expected_uniform = xxh3_128(&uniform_bytes).to_le_bytes();

    let mut specificity_bytes = bytes;
    specificity_bytes.push(1_u8);
    let expected_specificity = xxh3_128(&specificity_bytes).to_le_bytes();

    assert_eq!(
        PPR_FORMULA_VERSION, 5,
        "ONE-215 VAD propagation must pin version 5"
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

#[test]
fn ppr_simple_chain_scores_b_over_c() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(1);
    let b = entity(2);
    let c = entity(3);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
    assert!(score_for(&scores, b) > score_for(&scores, c));
    Ok(())
}

#[test]
fn ppr_weighted_edges_favor_heavier_neighbor() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(4);
    let b = entity(5);
    let c = entity(6);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.9)?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 0.1)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
    assert!(score_for(&scores, b) >= score_for(&scores, c) * 2.0);
    Ok(())
}

#[test]
fn ppr_opposes_weight_zero_blocks_propagation() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(7);
    let b = entity(8);

    vault.put_edge(&a, EdgeKind::Opposes, &b, 0.0)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
    assert!(score_for(&scores, b) <= 1e-6);
    Ok(())
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

/// ONE-1100 AC2 — the λ_τ table must equal the contract's LITERAL
/// `edgeKinds.lambda` column (oneiron-contracts.ts). The five world-model
/// rows deliberately differ from the stored-weight prior (`pprWeight`),
/// so a copy-the-weight-column implementation fails this test.
#[test]
fn lambda_table_matches_contract_literals() {
    let expected: [(EdgeKind, Option<f32>); 20] = [
        (EdgeKind::AuthoredBy, Some(0.9)),
        (EdgeKind::ScopedTo, Some(0.7)),
        (EdgeKind::PartOf, Some(0.8)),
        (EdgeKind::Supersedes, Some(0.3)),
        (EdgeKind::BelongsTo, Some(1.0)),
        (EdgeKind::ClaimOf, Some(1.0)),
        (EdgeKind::ChildOf, None),
        (EdgeKind::AssignedTo, None),
        (EdgeKind::DerivedFrom, Some(0.2)),
        (EdgeKind::Mentions, Some(0.6)),
        (EdgeKind::About, Some(0.5)),
        (EdgeKind::Supports, Some(1.0)),
        (EdgeKind::Opposes, Some(0.0)),
        (EdgeKind::ParticipatesIn, Some(1.0)),
        (EdgeKind::Attached, Some(0.8)),
        (EdgeKind::EmployedBy, Some(0.10)),
        (EdgeKind::HasFacet, Some(0.05)),
        (EdgeKind::FacetOf, Some(0.05)),
        (EdgeKind::InWorld, Some(0.05)),
        (EdgeKind::SetIn, Some(0.05)),
    ];
    for (kind, lambda) in expected {
        assert_eq!(lambda_for_kind(kind), lambda, "λ mismatch for {kind:?}");
    }

    // Pinned ARCH-0039 world-model budgets: employed_by λ = 0.10 vs
    // stored-weight prior 0.8; has_facet / facet_of / in_world / set_in
    // λ = 0.05 vs prior 0.7.
    for kind in [
        EdgeKind::EmployedBy,
        EdgeKind::HasFacet,
        EdgeKind::FacetOf,
        EdgeKind::InWorld,
        EdgeKind::SetIn,
    ] {
        let lambda = lambda_for_kind(kind).expect("world-model kinds are traversed");
        assert_ne!(
            lambda,
            kind.default_weight()
                .expect("world-model kinds carry a stored-weight prior"),
            "λ for {kind:?} must NOT be copied from the stored-weight prior"
        );
    }
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

    // ONE-1376: a ChildOf parent must be a real row. PERSON keeps the pair
    // outside the TASK role matrix, which is not what this test is about.
    vault.put_entity(
        &parent,
        crate::registry::ENTITY_TYPE_PERSON,
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

/// ONE-1100 AC4 — Layer-1 normalization (D7), exact values at depth 1:
///   propagated = score * (λ_τ * w_uv / s_out(u, τ)) * (1 − α)
/// Graph: a −mentions(0.6)→ b, a −mentions(0.2)→ c, a −supports(0.5)→ d.
/// Seeds [a], depth 1, α = 0.15:
///   s_out(a, mentions) = 0.6 + 0.2 = 0.8, λ_mentions = 0.6
///     b = 1.0 * (0.6 * 0.6 / 0.8) * 0.85 = 0.3825
///     c = 1.0 * (0.6 * 0.2 / 0.8) * 0.85 = 0.1275
///   s_out(a, supports) = 0.5 (own kind budget), λ_supports = 1.0
///     d = 1.0 * (1.0 * 0.5 / 0.5) * 0.85 = 0.85
///   a = 1.0 (init) + 1.0 * 0.15 (teleport) = 1.15
/// A λ·w implementation without s_out yields b = 0.306; the legacy
/// stored-weight-only formula yields b = 0.51 — both must fail here.
#[test]
fn layer1_normalization_matches_derived_values() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(76);
    let b = entity(77);
    let c = entity(78);
    let d = entity(79);

    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.6)?;
    vault.put_edge(&a, EdgeKind::Mentions, &c, 0.2)?;
    vault.put_edge(&a, EdgeKind::Supports, &d, 0.5)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;

    let cases = [(a, 1.15_f32), (b, 0.3825), (c, 0.1275), (d, 0.85)];
    for (id, expected) in cases {
        let got = score_for(&scores, id);
        assert!(
            (got - expected).abs() <= 1e-6,
            "score for {id:?}: got {got}, want {expected}"
        );
    }
    Ok(())
}

/// ONE-1100 AC4 (D7) — reverse hops over `edges_in` use the symmetric
/// s_in(u, τ) normalizer with the same λ + gates (engine-defined
/// extension pending the ARCH-0039 pin).
/// Graph: a −belongs_to(1.0)→ b, c −belongs_to(1.0)→ b. Seeds [b],
/// depth 1: b has no outgoing edges; the reverse scan at b sees two
/// inbound belongs_to edges, s_in(b, belongs_to) = 1.0 + 1.0 = 2.0:
///   a = c = 1.0 * (1.0 * 1.0 / 2.0) * 0.85 = 0.425
///   b = 1.0 (init) + 0.15 (teleport) = 1.15
/// An implementation reusing s_out (= 0 at b) would divide by zero; one
/// without reverse normalization would yield 0.85 per neighbor.
#[test]
fn reverse_hops_use_symmetric_s_in_normalizer() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(120);
    let b = entity(121);
    let c = entity(122);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&c, EdgeKind::BelongsTo, &b, 1.0)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[b], 1, 0.15)?;

    let cases = [(a, 0.425_f32), (b, 1.15), (c, 0.425)];
    for (id, expected) in cases {
        let got = score_for(&scores, id);
        assert!(
            (got - expected).abs() <= 1e-6,
            "score for {id:?}: got {got}, want {expected}"
        );
    }
    Ok(())
}

/// ONE-1100 AC2/AC4 — the five pinned world-model budgets BIND in
/// propagation. A single same-kind edge normalizes to w/s = 1.0, so the
/// neighbor score at depth 1 is exactly λ_τ * (1 − α):
///   employed_by: 0.10 * 0.85 = 0.085  (copy-the-weight impl: 0.68)
///   has_facet / facet_of / in_world / set_in: 0.05 * 0.85 = 0.0425
///   (copy-the-weight impl: 0.595)
#[test]
fn world_model_lambda_budgets_bind_in_propagation() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let cases: [(EdgeKind, f32, f32); 5] = [
        (EdgeKind::EmployedBy, 0.8, 0.085),
        (EdgeKind::HasFacet, 0.7, 0.0425),
        (EdgeKind::FacetOf, 0.7, 0.0425),
        (EdgeKind::InWorld, 0.7, 0.0425),
        (EdgeKind::SetIn, 0.7, 0.0425),
    ];

    let mut byte = 80_u8;
    for (kind, stored_weight, expected) in cases {
        let src = entity(byte);
        let tgt = entity(byte + 1);
        byte += 2;
        // The ONE-1645 FacetOf write-time type table requires both endpoints
        // to be established facts with admitted types. EVENT → FACET is the
        // world-model arm of that table (inert on the local query door, though
        // still disclosure-effective on the federation selector), which is
        // exactly the traversal semantics this λ budget pins. The rows are
        // inert for scoring: PPR reads `entities` only for cache TTL, seed
        // liveness (already live via the edge), and the CLAIM-typed
        // lexical-hint check.
        if kind == EdgeKind::FacetOf {
            let tr = TimeRange { start: 1, end: 1 };
            vault.put_entity(&src, crate::registry::ENTITY_TYPE_EVENT, tr, 1, b"src")?;
            vault.put_entity(&tgt, crate::registry::ENTITY_TYPE_FACET, tr, 1, b"tgt")?;
        }
        vault.put_edge(&src, kind, &tgt, stored_weight)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[src], 1, 0.15)?;
        let got = score_for(&scores, tgt);
        assert!(
            (got - expected).abs() <= 1e-6,
            "{kind:?}: got {got}, want {expected} (λ must bind, not the stored weight)"
        );
    }
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

/// ONE-1100 AC6 (D8) — proposed(0) / confirmed(1) / disputed(2)
/// propagate at FULL weight in v1 (no demotion): each equals the
/// bare-edge value λ_mentions * (w/s = 1.0) * (1 − 0.15) = 0.51 at
/// depth 1.
#[test]
fn non_retracted_statuses_propagate_at_full_weight() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let statuses = [
        EdgeConfirmationStatus::Proposed,
        EdgeConfirmationStatus::Confirmed,
        EdgeConfirmationStatus::Disputed,
    ];

    let mut byte = 110_u8;
    for status in statuses {
        let src = entity(byte);
        let tgt = entity(byte + 1);
        byte += 2;
        vault
            .batch()
            .edge_with_value_fields(
                &src,
                EdgeKind::Mentions,
                &tgt,
                EdgeValueFields {
                    weight: 0.6,
                    created_at: 1,
                    vad: Vad::NEUTRAL,
                    provenance: Some(EdgeProvenanceFlags {
                        confirmation_status: status,
                        actor_class: EdgeActorClass::Agent,
                    }),
                },
            )
            .commit()?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[src], 1, 0.15)?;
        let got = score_for(&scores, tgt);
        assert!(
            (got - 0.51).abs() <= 1e-6,
            "{status:?} must propagate at full weight, got {got}"
        );
    }
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
fn ppr_bidirectional_scan_reaches_inbound_neighbors() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(13);
    let b = entity(14);
    let c = entity(15);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&c, EdgeKind::BelongsTo, &b, 1.0)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
    assert!(score_for(&scores, c) > 0.0);
    Ok(())
}

#[test]
fn ppr_query_uses_cache_when_valid() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(16);
    let b = entity(0x60);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_after_first = cache_row(&vault, &[a], 3, 0.15)?;
    let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_after_second = cache_row(&vault, &[a], 3, 0.15)?;

    assert_scores_equal(&first, &second);
    assert_eq!(cache_after_first, cache_after_second);
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
        completed_depth: 1,
        scores: sentinel_scores(),
        frontier: Vec::new(),
        dependencies: vec![seed],
    };

    plant_state_cache_row(&vault, &[seed], 3, 0.15, crate::unix_seconds_now(), &state)?;

    match ppr_query(&vault.store, &vault.config, &[seed], 3, 0.15) {
        Err(Error::CorruptedIndex("ppr cache state")) => {}
        Err(err) => panic!("expected ppr cache state corruption, got {err:?}"),
        Ok(scores) => panic!("expected ppr cache state corruption, got scores {scores:?}"),
    }
    Ok(())
}

#[test]
fn ppr_cache_is_marked_stale_and_refreshed_after_edge_write() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(18);
    let b = entity(19);
    let c = entity(20);

    // Two same-kind edges so a weight rewrite changes b's NORMALIZED
    // share (a single edge always normalizes to w/s = 1.0, which would
    // make the score weight-invariant):
    //   before: b share = 1.0 / (1.0 + 1.0) = 0.5
    //   after:  b share = 0.2 / (0.2 + 1.0) = 1/6
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 1.0)?;

    let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_before = cache_row(&vault, &[a], 3, 0.15)?;
    assert_eq!(cache_before[16], 0);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.2)?;
    let cache_stale = cache_row(&vault, &[a], 3, 0.15)?;
    assert_eq!(cache_stale[16], 1);

    let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_after = cache_row(&vault, &[a], 3, 0.15)?;
    assert_eq!(cache_after[16], 0);
    assert_ne!(cache_stale, cache_after);

    let b_score_before = score_for(&first, b);
    let b_score_after = score_for(&second, b);
    assert!((b_score_before - b_score_after).abs() > SCORE_EPSILON);
    Ok(())
}

#[test]
fn ppr_cache_state_tracks_frontier_and_expanded_dependencies() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(70);
    let b = entity(0x67);
    let c = entity(72);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

    let _ = ppr_query(&vault.store, &vault.config, &[a], 2, 0.15)?;
    let state = cached_state(&vault, &[a], 2, 0.15)?;
    assert_eq!(state.completed_depth, 2);
    assert!(!state.frontier.is_empty());

    let seed_hash = hash_seeds(&[a], 2, 0.15, 0.0, SeedWeighting::Uniform);
    assert!(dep_exists(&vault, a, &seed_hash)?);
    assert!(dep_exists(&vault, b, &seed_hash)?);

    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 0.5)?;
    let cache_stale = cache_row(&vault, &[a], 2, 0.15)?;
    assert_eq!(cache_stale[CACHE_STALE_OFFSET], 1);
    Ok(())
}

#[test]
fn ppr_query_resumes_from_cached_frontier_and_matches_fresh_compute() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(73);
    let b = entity(74);
    let c = entity(75);
    let d = entity(76);
    let e = entity(77);
    let sentinel_dep = entity(78);

    vault.put_entity(
        &sentinel_dep,
        1,
        TimeRange { start: 1, end: 1 },
        1,
        b"sentinel",
    )?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&a, EdgeKind::Supports, &c, 0.8)?;
    vault.put_edge(&b, EdgeKind::Mentions, &d, 0.6)?;
    vault.put_edge(&c, EdgeKind::About, &e, 0.7)?;

    let _ = ppr_query(&vault.store, &vault.config, &[a], 1, 0.15)?;
    let depth_one_hash = hash_seeds(&[a], 1, 0.15, 0.0, SeedWeighting::Uniform);
    let depth_one_row = cache_row(&vault, &[a], 1, 0.15)?;
    let (computed_at, graph_version, stale) = parse_cache_header(&depth_one_row)?;
    assert_eq!(stale, 0);

    let mut state = decode_cache_state(&depth_one_row[CACHE_HEADER_LEN..])?;
    state.dependencies.push(sentinel_dep);
    state
        .dependencies
        .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    state.dependencies.dedup();
    let value = encode_cache_value_with_state(computed_at, graph_version, 0, &state)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .ppr_cache
        .put(&mut wtxn, &depth_one_hash, &value)?;
    let sentinel_dep_key = encode_dep_key(&sentinel_dep, &depth_one_hash);
    vault
        .store
        .ppr_cache_deps
        .put(&mut wtxn, &sentinel_dep_key, &[])?;
    wtxn.commit()?;

    let resumed = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let fresh = {
        let rtxn = vault.store.env.read_txn()?;
        ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?
    };
    assert_scores_equal(&resumed, &fresh);

    let depth_three_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    assert!(
        dep_exists(&vault, sentinel_dep, &depth_three_hash)?,
        "depth-3 cache must inherit dependencies from the resumed state"
    );
    Ok(())
}

#[test]
fn ppr_query_can_resume_from_expired_current_graph_state() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(79);
    let b = entity(80);
    let c = entity(81);
    let sentinel_dep = entity(82);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

    let mut depth_one_state = {
        let rtxn = vault.store.env.read_txn()?;
        ppr_compute_state_weighted(
            &vault.store,
            &rtxn,
            &[a],
            SeedWeighting::Uniform,
            1,
            PprAlphas::default_vad(0.15),
            None,
        )?
    };
    depth_one_state.dependencies.push(sentinel_dep);
    depth_one_state
        .dependencies
        .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    depth_one_state.dependencies.dedup();

    let expired_at = crate::unix_seconds_now().saturating_sub(CACHE_TTL_DORMANT_SECS + 1);
    plant_state_cache_row(&vault, &[a], 1, 0.15, expired_at, &depth_one_state)?;

    let resumed = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let fresh = {
        let rtxn = vault.store.env.read_txn()?;
        ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?
    };
    assert_scores_equal(&resumed, &fresh);

    let depth_three_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    assert!(
        dep_exists(&vault, sentinel_dep, &depth_three_hash)?,
        "depth-3 cache must inherit dependencies from the expired resume state"
    );
    Ok(())
}

#[test]
fn ppr_cache_invalidated_on_entity_delete() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(20);
    let b = entity(21);
    let c = entity(22);

    // Build entity records so delete_entity can find them.
    let tr = TimeRange { start: 1, end: 1 };
    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_entity(&c, 1, tr, 1, b"c-data")?;

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

    // Populate the cache for seeds [a].
    let _scores = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_before = cache_row(&vault, &[a], 3, 0.15)?;
    assert_eq!(cache_before[CACHE_STALE_OFFSET], 0);

    // Delete entity b — removes a->b and b->c edges.
    vault.delete_entity(&b)?;

    // Cache for seeds [a] must now be stale because a's edge to b was removed.
    let cache_after = cache_row(&vault, &[a], 3, 0.15)?;
    assert_eq!(cache_after[CACHE_STALE_OFFSET], 1);
    Ok(())
}

#[test]
fn ppr_cache_key_changes_with_depth_and_alpha() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(23);
    let b = entity(24);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 4, 0.15)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.25)?;

    let hash_depth_3 = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    let hash_depth_4 = hash_seeds(&[a], 4, 0.15, 0.0, SeedWeighting::Uniform);
    let hash_alpha_25 = hash_seeds(&[a], 3, 0.25, 0.0, SeedWeighting::Uniform);

    assert_ne!(hash_depth_3, hash_depth_4);
    assert_ne!(hash_depth_3, hash_alpha_25);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 3);
    Ok(())
}

#[test]
fn batch_graph_mutations_increment_version_once() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(25);
    let b = entity(26);
    let c = entity(27);

    assert_eq!(graph_version(&vault)?, 0);

    vault
        .batch()
        .edge(&a, EdgeKind::BelongsTo, &b, 1.0)
        .edge(&a, EdgeKind::BelongsTo, &c, 0.5)
        .commit()?;

    assert_eq!(graph_version(&vault)?, 1);
    Ok(())
}

#[test]
fn batch_noop_delete_edge_does_not_bump_version_or_stale_cache() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(28);
    let b = entity(29);
    let missing = entity(30);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    let before = graph_version(&vault)?;

    vault
        .batch()
        .delete_edge(&a, EdgeKind::BelongsTo, &missing)
        .commit()?;

    let after = graph_version(&vault)?;
    assert_eq!(after, before);

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .ppr_cache
        .get(&rtxn, &seed_hash)?
        .ok_or(Error::InvalidKey)?;
    let (_, _, stale) = parse_cache_header(&raw)?;
    assert_eq!(stale, 0);
    Ok(())
}

#[test]
fn delete_entity_increments_graph_version_once_when_edges_removed() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(31);
    let b = entity(32);
    let c = entity(33);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_entity(&c, 1, tr, 1, b"c-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

    let before = graph_version(&vault)?;
    assert!(vault.delete_entity(&b)?);
    let after = graph_version(&vault)?;

    assert_eq!(after, before + 1);
    Ok(())
}

#[test]
fn direct_delete_edge_increments_graph_version_and_stales_cache() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(34);
    let b = entity(35);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);

    let before = graph_version(&vault)?;
    assert!(vault.delete_edge(&a, EdgeKind::BelongsTo, &b)?);
    let after = graph_version(&vault)?;
    assert_eq!(after, before + 1);

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .ppr_cache
        .get(&rtxn, &seed_hash)?
        .ok_or(Error::InvalidKey)?;
    let (_, _, stale) = parse_cache_header(&raw)?;
    assert_eq!(stale, 1);
    Ok(())
}

#[test]
fn batch_delete_edge_cleans_inbound_orphans_without_staling_cache() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(50);
    let b = entity(51);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);

    let key_out = Store::encode_edge_key(&a, EdgeKind::BelongsTo, &b);
    let key_in = Store::encode_edge_key(&b, EdgeKind::BelongsTo, &a);
    let mut wtxn = vault.store.env.write_txn()?;
    assert!(vault.store.edges_out.delete(&mut wtxn, &key_out)?);
    wtxn.commit()?;

    let before = graph_version(&vault)?;
    vault
        .batch()
        .delete_edge(&a, EdgeKind::BelongsTo, &b)
        .commit()?;
    let after = graph_version(&vault)?;
    assert_eq!(after, before);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.edges_in.get(&rtxn, &key_in)?.is_none());
    let raw = vault
        .store
        .ppr_cache
        .get(&rtxn, &seed_hash)?
        .ok_or(Error::EntityNotFound)?;
    let (_, _, stale) = parse_cache_header(&raw)?;
    assert_eq!(stale, 0);
    Ok(())
}

/// Deleting an isolated entity must bump GRAPH_VERSION exactly once;
/// a follow-up delete attempt on the now-missing id must not bump it
/// again. Variants run the delete through different API paths.
///
/// Variants:
/// - `direct`: `vault.delete_entity(&a)` — returns `bool` for found/missing.
/// - `batch`: `vault.batch().delete(&a).commit()` — must observe the
///   same "second commit is a no-op" guarantee.
#[test]
fn delete_isolated_entity_increments_graph_version_once() -> Result<()> {
    #[derive(Clone, Copy)]
    enum Path {
        Direct,
        Batch,
    }

    let cases: Vec<(&str, Path, u8)> =
        vec![("direct", Path::Direct, 36), ("batch", Path::Batch, 37)];

    for (case_name, path, byte) in cases {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
        let a = entity(byte);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;

        let before = graph_version(&vault)?;
        match path {
            Path::Direct => {
                assert!(
                    vault.delete_entity(&a)?,
                    "case {case_name}: first direct delete should report found"
                );
            }
            Path::Batch => {
                vault.batch().delete(&a).commit()?;
            }
        }
        let after_delete = graph_version(&vault)?;
        assert_eq!(
            after_delete,
            before + 1,
            "case {case_name}: first delete should bump GRAPH_VERSION by 1"
        );

        match path {
            Path::Direct => {
                assert!(
                    !vault.delete_entity(&a)?,
                    "case {case_name}: second direct delete should report missing"
                );
            }
            Path::Batch => {
                vault.batch().delete(&a).commit()?;
            }
        }
        let after_missing = graph_version(&vault)?;
        assert_eq!(
            after_missing, after_delete,
            "case {case_name}: redundant delete must not bump GRAPH_VERSION"
        );
    }
    Ok(())
}

#[test]
fn cleanup_conservatively_evicts_cache_for_missing_dep_entities() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(38);
    let b = entity(39);
    let missing = entity(40);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);

    let mut wtxn = vault.store.env.write_txn()?;
    let orphan_dep = encode_dep_key(&missing, &seed_hash);
    vault
        .store
        .ppr_cache_deps
        .put(&mut wtxn, &orphan_dep, &[])?;
    wtxn.commit()?;

    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 3);

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert_eq!(report.ppr_caches_evicted, 1);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);
    Ok(())
}

#[test]
fn cleanup_ppr_cache_removes_legacy_rows() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(37);
    let b = entity(38);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;

    let now = crate::unix_seconds_now();
    let legacy_hash = legacy_cache_key(0xAB);
    let legacy_dep = legacy_dep_key(a, legacy_hash);
    let legacy_value = encode_cache_value(now, 0, 0, &[]);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .ppr_cache
        .put(&mut wtxn, &legacy_hash, &legacy_value)?;
    vault
        .store
        .ppr_cache_deps
        .put(&mut wtxn, &legacy_dep, &[])?;
    wtxn.commit()?;

    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 2);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 3);

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert!(report.ppr_caches_evicted >= 1);
    assert!(report.ppr_deps_cleaned >= 1);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 2);
    Ok(())
}

#[test]
fn cleanup_ppr_cache_prunes_malformed_dep_rows() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(52);
    let b = entity(53);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);

    let mut malformed_dep = [0_u8; CACHE_DEP_KEY_LEN];
    malformed_dep[ENTITY_ID_LEN..].copy_from_slice(&seed_hash);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .ppr_cache_deps
        .put(&mut wtxn, &malformed_dep, &[])?;
    wtxn.commit()?;

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert_eq!(report.ppr_caches_evicted, 0);
    assert!(report.ppr_deps_cleaned >= 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_some());
    assert!(
        vault
            .store
            .ppr_cache_deps
            .get(&rtxn, &malformed_dep)?
            .is_none()
    );
    Ok(())
}

#[test]
fn cleanup_ppr_cache_evicts_cache_when_last_dep_row_is_malformed() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(54);
    let b = entity(55);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&a, 1, tr, 1, b"a-data")?;
    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    delete_dep_rows_for_hash(&vault, &seed_hash)?;

    let mut malformed_dep = [0_u8; CACHE_DEP_KEY_LEN];
    malformed_dep[ENTITY_ID_LEN..].copy_from_slice(&seed_hash);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .ppr_cache_deps
        .put(&mut wtxn, &malformed_dep, &[])?;
    wtxn.commit()?;

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert_eq!(report.ppr_caches_evicted, 1);
    assert!(report.ppr_deps_cleaned >= 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_none());
    assert!(
        vault
            .store
            .ppr_cache_deps
            .get(&rtxn, &malformed_dep)?
            .is_none()
    );
    Ok(())
}

#[test]
fn invalidate_ppr_caches_prunes_malformed_cache_rows() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(60);
    let b = entity(61);
    let seed_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    let dep_key = encode_dep_key(&a, &seed_hash);

    vault.put_entity(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"a-data")?;
    vault.put_entity(&b, 1, TimeRange { start: 2, end: 2 }, 2, b"b-data")?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .ppr_cache
        .put(&mut wtxn, &seed_hash, &[1, 2, 3])?;
    vault.store.ppr_cache_deps.put(&mut wtxn, &dep_key, &[])?;
    wtxn.commit()?;

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_none());
    drop(rtxn);
    assert!(vault.edge_exists(&a, EdgeKind::BelongsTo, &b)?);
    Ok(())
}

#[test]
fn edge_invalidation_self_heals_legacy_dep_rows() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(39);
    let b = entity(40);
    let legacy_hash = legacy_cache_key(0xCD);
    let legacy_dep = legacy_dep_key(a, legacy_hash);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .ppr_cache_deps
        .put(&mut wtxn, &legacy_dep, &[])?;
    wtxn.commit()?;

    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);
    Ok(())
}

#[test]
fn cleanup_keeps_graph_only_seed_deps_and_invalidation_still_works() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(41);
    let b = entity(42);
    let c = entity(43);
    let tr = TimeRange { start: 1, end: 1 };

    vault.put_entity(&b, 1, tr, 1, b"b-data")?;
    vault.put_entity(&c, 1, tr, 1, b"c-data")?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&first, b) > 0.0);
    assert!(score_for(&first, c) <= SCORE_EPSILON);

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert_eq!(report.ppr_caches_evicted, 0);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 2);

    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 1.0)?;
    let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&second, c) > 0.0);
    Ok(())
}

#[test]
fn cleanup_evicts_cache_for_dead_seed_without_live_graph_presence() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(44);
    let b = entity(45);

    let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&first, a) > 0.0);
    assert!(score_for(&first, b) <= SCORE_EPSILON);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert_eq!(report.ppr_caches_evicted, 1);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&second, b) > 0.0);
    Ok(())
}

#[test]
fn ppr_query_recomputes_cache_after_graph_version_change() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(46);
    let b = entity(47);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_before = cache_row(&vault, &[a], 3, 0.15)?;
    let (_, version_before, stale_before) = parse_cache_header(&cache_before)?;
    assert_eq!(stale_before, 0);

    let new_version = version_before + 1;
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .hnsw_meta
        .put(&mut wtxn, GRAPH_VERSION_KEY, &new_version.to_le_bytes())?;
    wtxn.commit()?;

    let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    let cache_after = cache_row(&vault, &[a], 3, 0.15)?;
    let (_, version_after, stale_after) = parse_cache_header(&cache_after)?;

    assert_eq!(stale_after, 0);
    assert_eq!(version_after, new_version);
    assert_eq!(first, second);
    assert_ne!(cache_before, cache_after);
    Ok(())
}

#[test]
fn ppr_query_recomputes_after_downstream_graph_change() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(57);
    let b = entity(58);
    let c = entity(59);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
    let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&first, b) > 0.0);
    assert!(score_for(&first, c) <= SCORE_EPSILON);

    vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;
    let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(score_for(&second, c) > 0.0);
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
        completed_depth: 3,
        scores: vec![ScoredEntity {
            id: stale_dep,
            score: 0.25,
        }],
        frontier: Vec::new(),
        dependencies: vec![seed, stale_dep],
    };
    let second_state = PprCacheState {
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

/// `ppr_query` must refuse to produce scores when non-finite values are
/// persisted in either the edge-weight payload or the cached score
/// payload. Variants inject the bad value at a different site.
///
/// Variants:
/// - `persisted_edge_weight`: writes `f32::NAN` into the first 4 bytes
///   of an `edges_out` record. Expected error: `CorruptedIndex("edge record")`.
/// - `cached_scores`: writes `f32::INFINITY` into a `ppr_cache` entry.
///   Expected error: `CorruptedIndex("ppr cache scores")`.
#[test]
fn ppr_query_rejects_non_finite_inputs() -> Result<()> {
    #[derive(Clone, Copy)]
    enum Site {
        EdgeWeight,
        CachedScores,
    }

    let cases: Vec<(&str, Site, u8, u8, &str)> = vec![
        (
            "persisted_edge_weight",
            Site::EdgeWeight,
            63,
            64,
            "edge record",
        ),
        (
            "cached_scores",
            Site::CachedScores,
            65,
            0x62,
            "ppr cache scores",
        ),
    ];

    for (case_name, site, a_byte, b_byte, expected_msg) in cases {
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
                    0,
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
        match err {
            Error::CorruptedIndex(msg) if msg == expected_msg => {}
            other => {
                panic!("case {case_name}: expected CorruptedIndex({expected_msg:?}), got {other:?}")
            }
        }
    }
    Ok(())
}

/// ONE-1116 AC1 (ARCH-0039 Layer 2) — `search_ppr` seed mass is
/// `1/ln(1 + max(passage_count, 1))`, normalized to Σ = 1.0, with
/// `passage_count` = inbound `mentions` edge count. Graph (every
/// mentions edge stores weight 0.6):
///   p1, p2, p3 −mentions→ a   (passage_count(a) = 3)
///   (nothing)  −mentions→ b   (passage_count(b) = 0 → clamped to 1)
///   q1         −mentions→ c   (passage_count(c) = 1)
/// Raw weights 1/ln(4) : 1/ln(2) : 1/ln(2) normalize EXACTLY to
/// 0.2 / 0.4 / 0.4 (ln(4) = 2·ln(2), so the log base cancels).
///
/// Seeds [a, b, c], depth 1, α = 0.15 — hand derivation mirroring the
/// Layer-1 exact-value test (reverse scan over `edges_in`,
/// s_in(a, mentions) = 1.8, s_in(c, mentions) = 0.6, λ_mentions = 0.6):
///   p_i = 0.2 · (0.6 · 0.6 / 1.8) · 0.85 = 0.034
///   q1  = 0.4 · (0.6 · 0.6 / 0.6) · 0.85 = 0.204
///   teleport: a += 1.0 · 0.15 · 0.2 ; b, c += 1.0 · 0.15 · 0.4
///   a = 0.2 + 0.03 = 0.23 ; b = c = 0.4 + 0.06 = 0.46
/// UNIFORM seeding instead yields a = b = c = 0.38333, p_i = 0.0566667,
/// q1 = 0.17 — every value moves, so a uniform implementation fails.
/// A missing clamp (1/ln(1 + 0) = ∞) sends b's normalized weight to 1.0
/// and the rest to 0.0 — it fails as well.
#[test]
fn seed_specificity_weights_match_derived_values() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(1);
    let b = entity(2);
    let c = entity(3);
    let passages = [entity(10), entity(11), entity(12)];
    let q1 = entity(13);

    for passage in &passages {
        vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
    }
    vault.put_edge(&q1, EdgeKind::Mentions, &c, 0.6)?;

    let rtxn = vault.store.env.read_txn()?;

    let weights = specificity_seed_weights(&vault.store, &rtxn, &[a, b, c])?;
    let expected_weights = [0.2_f32, 0.4, 0.4];
    for (got, expected) in weights.iter().zip(expected_weights) {
        assert!(
            (got - expected).abs() <= 1e-6,
            "seed weight: got {got}, want {expected}"
        );
    }

    let scores = ppr_compute_weighted(
        &vault.store,
        &rtxn,
        &[a, b, c],
        SeedWeighting::Specificity,
        1,
        0.15,
    )?;
    let cases = [
        (a, 0.23_f32),
        (b, 0.46),
        (c, 0.46),
        (passages[0], 0.034),
        (passages[1], 0.034),
        (passages[2], 0.034),
        (q1, 0.204),
    ];
    for (id, expected) in cases {
        let got = score_for(&scores, id);
        assert!(
            (got - expected).abs() <= 1e-6,
            "score for {id:?}: got {got}, want {expected}"
        );
    }
    Ok(())
}

/// ONE-1116 AC2 — single-seed normalization cancels: whatever the
/// passage count, the lone seed's normalized weight is exactly 1.0, so
/// specificity seeding equals uniform seeding. Exact values (graph as in
/// AC1's `a` cluster): a = 1.0 init + 0.15 teleport = 1.15; each
/// p_i = 1.0 · (0.6 · 0.6 / 1.8) · 0.85 = 0.17.
#[test]
fn single_seed_specificity_matches_uniform() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(1);
    let passages = [entity(10), entity(11), entity(12)];

    for passage in &passages {
        vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
    }

    let rtxn = vault.store.env.read_txn()?;
    let weighted = ppr_compute_weighted(
        &vault.store,
        &rtxn,
        &[a],
        SeedWeighting::Specificity,
        1,
        0.15,
    )?;
    let uniform = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;

    assert_scores_equal(&weighted, &uniform);
    let cases = [
        (a, 1.15_f32),
        (passages[0], 0.17),
        (passages[1], 0.17),
        (passages[2], 0.17),
    ];
    for (id, expected) in cases {
        let got = score_for(&weighted, id);
        assert!(
            (got - expected).abs() <= 1e-6,
            "score for {id:?}: got {got}, want {expected}"
        );
    }
    Ok(())
}

/// ONE-1116 AC3 — `expand_ppr` seeds stay UNIFORM (ARCH-0039 Layer 2 is
/// `search_ppr`-only). The pipeline's expand pass must write its cache
/// row under the Uniform key, never the Specificity key, and the cached
/// scores must equal the hand-derived UNIFORM values for seeds [a, b]
/// (depth 1, α = 0.15, the AC1 graph where a has 3 inbound mentions and
/// b has 0):
///   weights 0.5 / 0.5 → p_i = 0.5 · (0.6 · 0.6 / 1.8) · 0.85 = 0.085
///   a = b = 0.5 + 0.15 · 0.5 = 0.575
/// Specificity seeding would yield a = 0.3833333, b = 0.7666667,
/// p_i = 0.0566667 instead — those values must NOT appear.
#[test]
fn expand_ppr_pipeline_seeds_stay_uniform() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(1);
    let b = entity(2);
    let passages = [entity(10), entity(11), entity(12)];

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"a-data")
        .text(&a, &[("body", "alpha")])
        .commit()?;
    for passage in &passages {
        vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
    }

    // The text channel ranks [a]; the expand pass dedups it against the
    // explicit seeds, so the PPR seed set is exactly [a, b].
    let _ = vault
        .query()
        .search_text("alpha", 10)
        .expand_ppr(&[a, b], 1)
        .run()?;

    let uniform_hash = hash_seeds(&[a, b], 1, 0.15, 0.0, SeedWeighting::Uniform);
    let specificity_hash = hash_seeds(&[a, b], 1, 0.15, 0.0, SeedWeighting::Specificity);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .ppr_cache
            .get(&rtxn, &specificity_hash)?
            .is_none(),
        "expand_ppr must not write a specificity-keyed cache row"
    );
    let raw = vault
        .store
        .ppr_cache
        .get(&rtxn, &uniform_hash)?
        .ok_or(Error::EntityNotFound)?;
    let scores = decode_cache_scores(&raw[CACHE_HEADER_LEN..])?;

    let cases = [
        (a, 0.575_f32),
        (b, 0.575),
        (passages[0], 0.085),
        (passages[1], 0.085),
        (passages[2], 0.085),
    ];
    for (id, expected) in cases {
        let got = score_for(&scores, id);
        assert!(
            (got - expected).abs() <= 1e-6,
            "expand_ppr cached score for {id:?}: got {got}, want uniform {expected}"
        );
    }
    Ok(())
}

/// ONE-1116 AC1/AC4 — the `search_ppr` pipeline pass seeds by
/// specificity AND keys its cache row with the Specificity byte (never
/// the Uniform key). Cached scores must equal the weighted derivation
/// for seeds [a (3 mentions), b (0 mentions)], depth 1, α = 0.15:
///   weights 1/3, 2/3 → a = 1/3 + 0.15/3 = 0.3833333,
///   b = 2/3 + 0.1 = 0.7666667, p_i = (1/3) · 0.2 · 0.85 = 0.0566667.
/// A second identical query must be served from that row (round-trip:
/// identical results, byte-identical cache row).
#[test]
fn search_ppr_pipeline_applies_specificity_seeding() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(1);
    let b = entity(2);
    let passages = [entity(10), entity(11), entity(12)];

    for passage in &passages {
        vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
    }

    let first = vault.query().search_ppr(&[a, b], 1).run()?;

    let uniform_hash = hash_seeds(&[a, b], 1, 0.15, 0.0, SeedWeighting::Uniform);
    let specificity_hash = hash_seeds(&[a, b], 1, 0.15, 0.0, SeedWeighting::Specificity);
    let raw = {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.ppr_cache.get(&rtxn, &uniform_hash)?.is_none(),
            "search_ppr must not write a uniform-keyed cache row"
        );
        vault
            .store
            .ppr_cache
            .get(&rtxn, &specificity_hash)?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };
    let scores = decode_cache_scores(&raw[CACHE_HEADER_LEN..])?;

    let third = 1.0_f32 / 3.0;
    let cases = [
        (a, third + 0.15 * third),
        (b, 2.0 * third + 0.15 * 2.0 * third),
        (passages[0], third * 0.2 * 0.85),
        (passages[1], third * 0.2 * 0.85),
        (passages[2], third * 0.2 * 0.85),
    ];
    for (id, expected) in cases {
        let got = score_for(&scores, id);
        assert!(
            (got - expected).abs() <= 1e-6,
            "search_ppr cached score for {id:?}: got {got}, want weighted {expected}"
        );
    }

    // Round-trip: the second identical query is served from the row.
    let second = vault.query().search_ppr(&[a, b], 1).run()?;
    assert_scores_equal(&first, &second);
    let rtxn = vault.store.env.read_txn()?;
    let raw_after = vault
        .store
        .ppr_cache
        .get(&rtxn, &specificity_hash)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(*raw, *raw_after, "cache row must be reused, not rewritten");
    Ok(())
}

/// ONE-1116/ONE-1236 — pre-bump PPR rows are unreachable: a row persisted under the
/// pre-bump v2 key (seeds ‖ depth ‖ alpha ‖ version 2, NO weighting
/// byte — the literal pre-ONE-1116 layout) is unreachable even with a
/// fresh `computed_at`, matching graph version, and stale = 0. The
/// query recomputes, lands its row under the current key, and the orphaned
/// v2 row is reaped by the existing cleanup (it has no dep rows).
#[test]
fn pre_bump_formula_v2_rows_are_never_served() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let a = entity(1);
    let b = entity(2);

    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

    let mut legacy_bytes = Vec::new();
    legacy_bytes.extend_from_slice(a.as_bytes());
    legacy_bytes.extend_from_slice(&3_u32.to_le_bytes());
    legacy_bytes.extend_from_slice(&0.15_f32.to_le_bytes());
    legacy_bytes.extend_from_slice(&2_u32.to_le_bytes());
    let legacy_hash = xxh3_128(&legacy_bytes).to_le_bytes();

    let value = encode_cache_value(
        crate::unix_seconds_now(),
        graph_version(&vault)?,
        0,
        &sentinel_scores(),
    );
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.ppr_cache.put(&mut wtxn, &legacy_hash, &value)?;
    wtxn.commit()?;

    let scores = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
    assert!(
        !scores.iter().any(|scored| scored.id == sentinel_entity()),
        "pre-bump v2 cache row must never be served"
    );
    assert!(score_for(&scores, b) > 0.0);

    let current_hash = hash_seeds(&[a], 3, 0.15, 0.0, SeedWeighting::Uniform);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&rtxn, &current_hash)?.is_some());
    }

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert!(report.ppr_caches_evicted >= 1);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.ppr_cache.get(&rtxn, &legacy_hash)?.is_none(),
        "orphaned v2 row must be reaped by cleanup"
    );
    assert!(
        vault.store.ppr_cache.get(&rtxn, &current_hash)?.is_some(),
        "live current-version row must survive cleanup"
    );
    Ok(())
}

/// ONE-1116 AC5 — recency-tier boundaries, pinned against a FIXED clock
/// (no real-time dependence) with the contract's LITERAL TTL values
/// (ARCH-0019 / ARCH-0014): seed recency < 7d → 86 400 s; 7–30 d →
/// 259 200 s (7 d EXACTLY is Recent); ≥ 30 d → 604 800 s (30 d EXACTLY
/// is Dormant). Recency = max(learned_at) over the seed set, so the most
/// recently learned seed wins; future `learned_at` saturates to Active;
/// record-less seed sets and unparsable records fail closed to Active.
#[test]
fn recency_tier_boundaries_match_contract() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let now: u64 = 20_000 * 86_400;
    let day: u64 = 86_400;
    let tr = TimeRange { start: 1, end: 1 };

    // (entity byte, learned_at, expected ttl — LITERAL seconds)
    let cases: [(u8, u64, u64); 8] = [
        (1, now, 86_400),                   // learned this instant
        (2, now - day, 86_400),             // 1 day old
        (3, now - (7 * day - 1), 86_400),   // just inside Active
        (4, now - 7 * day, 259_200),        // exactly 7 d → Recent
        (5, now - (30 * day - 1), 259_200), // just inside Recent
        (6, now - 30 * day, 604_800),       // exactly 30 d → Dormant
        (7, now - 365 * day, 604_800),      // deep dormant
        (8, now + day, 86_400),             // future learned_at saturates
    ];

    for (byte, learned_at, _) in cases {
        vault.put_entity(&entity(byte), 1, tr, learned_at, b"seed")?;
    }

    let rtxn = vault.store.env.read_txn()?;
    for (byte, _, expected_ttl) in cases {
        let ttl = recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(byte)], now)?;
        assert_eq!(ttl, expected_ttl, "ttl for seed byte {byte}");
    }

    // max(learned_at) over the seed set: dormant + active → ACTIVE wins.
    let mixed = recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(7), entity(2)], now)?;
    assert_eq!(mixed, 86_400, "most recent seed must decide the tier");

    // Record-less seeds contribute nothing; alongside a dormant seed the
    // dormant learned_at still decides.
    let with_unknown =
        recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(7), entity(200)], now)?;
    assert_eq!(with_unknown, 604_800);

    // An all-record-less seed set fails closed to the shortest tier.
    let unknown_only = recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(200)], now)?;
    assert_eq!(unknown_only, 86_400);
    drop(rtxn);

    // A present-but-unparsable entity record fails closed to Active,
    // even when a dormant seed is also present.
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, entity(9).as_bytes(), &[1, 2, 3])?;
    wtxn.commit()?;
    let rtxn = vault.store.env.read_txn()?;
    let corrupt = recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(7), entity(9)], now)?;
    assert_eq!(corrupt, 86_400);
    Ok(())
}

/// ONE-1116 AC5 — the read gate enforces the recency-tiered TTL: a
/// planted sentinel row is served while inside its seed-tier TTL and
/// recomputed past it. One-hour margins keep the cases immune to wall
/// clock drift during the run. Covers: active rows expiring at 24 h;
/// recent/dormant rows SURVIVING past 24 h; dormant rows serving up to
/// (but not beyond) 168 h; record-less seeds failing closed to 24 h;
/// and max(learned_at) pulling a mixed dormant+active seed set down to
/// the 24 h tier.
#[test]
fn cache_read_gate_applies_recency_tiered_ttl() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let now = crate::unix_seconds_now();
    let day: u64 = 86_400;
    let hour: u64 = 3_600;
    let tr = TimeRange { start: 1, end: 1 };

    // (name, seed learned-ages in days (None = no entity record),
    //  row age, expect served)
    let cases: [(&str, &[Option<u64>], u64, bool); 8] = [
        (
            "active_served_within_24h",
            &[Some(1)],
            CACHE_TTL_ACTIVE_SECS - hour,
            true,
        ),
        (
            "active_expires_past_24h",
            &[Some(1)],
            CACHE_TTL_ACTIVE_SECS + hour,
            false,
        ),
        (
            "recent_survives_past_24h",
            &[Some(10)],
            CACHE_TTL_ACTIVE_SECS + hour,
            true,
        ),
        (
            "recent_expires_past_72h",
            &[Some(10)],
            CACHE_TTL_RECENT_SECS + hour,
            false,
        ),
        (
            "dormant_survives_to_168h",
            &[Some(40)],
            CACHE_TTL_DORMANT_SECS - hour,
            true,
        ),
        (
            "dormant_expires_past_168h",
            &[Some(40)],
            CACHE_TTL_DORMANT_SECS + hour,
            false,
        ),
        (
            "recordless_seed_fails_closed_to_24h",
            &[None],
            CACHE_TTL_ACTIVE_SECS + hour,
            false,
        ),
        (
            "max_learned_at_wins",
            &[Some(40), Some(1)],
            CACHE_TTL_ACTIVE_SECS + hour,
            false,
        ),
    ];

    let mut byte = 1_u8;
    for (name, seed_ages, row_age, expect_served) in cases {
        let mut seeds = Vec::new();
        for seed_age_days in seed_ages {
            let seed = entity(byte);
            byte += 1;
            if let Some(days) = seed_age_days {
                vault.put_entity(&seed, 1, tr, now - days * day, b"seed")?;
            }
            seeds.push(seed);
        }

        plant_cache_row(
            &vault,
            &seeds,
            3,
            0.15,
            SeedWeighting::Uniform,
            now - row_age,
            &sentinel_scores(),
        )?;

        let scores = ppr_query(&vault.store, &vault.config, &seeds, 3, 0.15)?;
        let served = scores.iter().any(|scored| scored.id == sentinel_entity());
        assert_eq!(served, expect_served, "case {name}");
    }
    Ok(())
}

/// ONE-1116 AC6 — cleanup `max_age_secs` is a HARD bound independent of
/// the tiered serve TTL; with the documented bound (the longest tier,
/// 168 h) cleanup never evicts a row the read gate could still serve.
/// Three planted rows: a dormant-seeded and an active-seeded row both
/// aged 100 h survive cleanup (only the read gate distinguishes them:
/// the dormant row is still served, the active one is not), while a
/// dormant-seeded row aged 169 h (> 168 h) is evicted.
#[test]
fn cleanup_max_age_bound_is_consistent_with_tiered_ttl() -> Result<()> {
    let temp_dir = tempdir()?;
    let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
    let now = crate::unix_seconds_now();
    let day: u64 = 86_400;
    let hour: u64 = 3_600;
    let tr = TimeRange { start: 1, end: 1 };

    let dormant_served = entity(1);
    let active_unserved = entity(2);
    let dormant_expired = entity(3);
    vault.put_entity(&dormant_served, 1, tr, now - 40 * day, b"seed")?;
    vault.put_entity(&active_unserved, 1, tr, now - day, b"seed")?;
    vault.put_entity(&dormant_expired, 1, tr, now - 40 * day, b"seed")?;

    let dormant_hash = plant_cache_row(
        &vault,
        &[dormant_served],
        3,
        0.15,
        SeedWeighting::Uniform,
        now - 100 * hour,
        &sentinel_scores(),
    )?;
    let active_hash = plant_cache_row(
        &vault,
        &[active_unserved],
        3,
        0.15,
        SeedWeighting::Uniform,
        now - 100 * hour,
        &sentinel_scores(),
    )?;
    let expired_hash = plant_cache_row(
        &vault,
        &[dormant_expired],
        3,
        0.15,
        SeedWeighting::Uniform,
        now - 169 * hour,
        &sentinel_scores(),
    )?;

    let report = vault
        .maintain()
        .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
        .run()?;
    assert_eq!(report.ppr_caches_evicted, 1, "only the 169h row may go");

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&rtxn, &dormant_hash)?.is_some());
        assert!(vault.store.ppr_cache.get(&rtxn, &active_hash)?.is_some());
        assert!(vault.store.ppr_cache.get(&rtxn, &expired_hash)?.is_none());
    }

    // Servability is the read gate's call, not cleanup's: the surviving
    // dormant row is still served at 100 h; the surviving active row is
    // past its 24 h tier and recomputes.
    let dormant_scores = ppr_query(&vault.store, &vault.config, &[dormant_served], 3, 0.15)?;
    assert!(
        dormant_scores
            .iter()
            .any(|scored| scored.id == sentinel_entity()),
        "dormant-seeded row aged 100h must still be served"
    );

    let active_scores = ppr_query(&vault.store, &vault.config, &[active_unserved], 3, 0.15)?;
    assert!(
        !active_scores
            .iter()
            .any(|scored| scored.id == sentinel_entity()),
        "active-seeded row aged 100h must NOT be served"
    );
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

/// COMPUTE-ONLY. `ppr_cache` rows are keyed by `(seeds, depth, alpha,
/// weighting)` and carry NO actor, so a scoped ranking may neither be served
/// from that cache nor written into it — either direction would leak one
/// actor's structure into another's answer. Dependency rows follow the row
/// that would own them, and a read never bumps the graph version.
///
/// Asking the same scoped question twice inside ONE transaction returns the
/// same score BITS: nothing about the answer depends on cached state or on how
/// many times it has been asked.
#[test]
fn scoped_ppr_is_compute_only_and_repeats_bit_for_bit() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(0x59);
    let neighbor = entity(0x5A);
    vault.put_edge(&seed, EdgeKind::About, &neighbor, 0.5)?;

    let version_before = graph_version(&vault)?;
    let cache_before = count_entries(&vault.store.ppr_cache, &vault)?;
    let deps_before = count_entries(&vault.store.ppr_cache_deps, &vault)?;

    let visibility = DeniedNodes::new(&[]);
    let rtxn = vault.store.env.read_txn()?;
    let first = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[seed],
        2,
        0.15,
        0.0,
        SeedWeighting::Specificity,
        &visibility,
    )?;
    let second = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[seed],
        2,
        0.15,
        0.0,
        SeedWeighting::Specificity,
        &visibility,
    )?;
    drop(rtxn);

    assert!(
        score_for(&first, neighbor) > 0.0,
        "the walk really ran, so the no-write assertions below are not vacuous"
    );
    assert_eq!(
        score_bits(&first),
        score_bits(&second),
        "two scoped runs in one transaction agree bit for bit"
    );
    assert_eq!(
        count_entries(&vault.store.ppr_cache, &vault)?,
        cache_before,
        "a scoped ranking is never written to the shared, actor-less cache"
    );
    assert_eq!(
        count_entries(&vault.store.ppr_cache_deps, &vault)?,
        deps_before,
        "no dependency row outlives a cache row that was never written"
    );
    assert_eq!(
        graph_version(&vault)?,
        version_before,
        "a read never bumps the graph version"
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
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]);
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("code-memory-scoped")),
        (Value::from("pack_version"), Value::from("1")),
        (Value::from("min_engine_version"), Value::from("0.0.0")),
        (Value::from("defaults"), Value::Map(Vec::new())),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(Vec::new())),
        (Value::from("scoped_grants"), Value::Array(vec![grant])),
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
    );
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
fn ppr_vad_multiplier_contract() {
    for (vad, salience) in [
        (Vad::NEUTRAL, 0.0),
        (
            Vad {
                valence: -1.0,
                arousal: 0.0,
                dominance: 0.0,
            },
            1.0,
        ),
        (
            Vad {
                valence: 1.0,
                arousal: 0.0,
                dominance: 0.0,
            },
            1.0,
        ),
        (
            Vad {
                valence: 0.1,
                arousal: 0.9,
                dominance: 1.0,
            },
            0.9,
        ),
    ] {
        assert_eq!(vad_salience(vad), salience);
        assert_eq!(vad_multiplier(Some(vad), 0.4), 1.0 + 0.4 * salience);
        assert_eq!(vad_multiplier(Some(vad), 0.0).to_bits(), 1.0_f32.to_bits());
    }
    assert_eq!(vad_multiplier(None, 0.4), 1.0);
    // Alpha zero must not evaluate the VAD expression at all.
    assert_eq!(
        vad_multiplier(
            Some(Vad {
                valence: f32::NAN,
                arousal: f32::INFINITY,
                dominance: 0.0
            }),
            0.0
        )
        .to_bits(),
        1.0_f32.to_bits()
    );
}

#[test]
fn ppr_vad_normalized_share_and_zero_baseline_bits() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    let neutral = entity(2);
    let salient = entity(3);
    let structural = entity(4);
    vault.put_edge(&seed, EdgeKind::Mentions, &neutral, 0.25)?;
    vault.put_edge(&seed, EdgeKind::Mentions, &salient, 0.75)?;
    vault.set_edge_vad(
        &seed,
        EdgeKind::Mentions,
        &salient,
        Vad {
            valence: -1.0,
            arousal: 0.8,
            dominance: 0.4,
        },
    )?;
    vault.put_edge(&seed, EdgeKind::BelongsTo, &structural, 1.0)?;
    for alpha in [0.0, 0.4] {
        let mut config = vault.config.clone();
        config.ppr_vad_alpha = alpha;
        let fresh = ppr_query(&vault.store, &config, &[seed], 1, 0.15)?;
        let cached = ppr_query(&vault.store, &config, &[seed], 1, 0.15)?;
        for (left, right) in fresh.iter().zip(&cached) {
            assert_eq!(left.id, right.id);
            assert_eq!(left.score.to_bits(), right.score.to_bits());
        }
        // Literal pre-change formula, with exactly the original operation order.
        let baseline_neutral = 1.0_f32 * (0.6 * 0.25 / 1.0) * (1.0 - 0.15);
        let baseline_salient = 1.0_f32 * (0.6 * 0.75 / 1.0) * (1.0 - 0.15);
        assert_eq!(
            score_for(&fresh, neutral).to_bits(),
            baseline_neutral.to_bits()
        );
        assert_eq!(score_for(&fresh, structural).to_bits(), 0.85_f32.to_bits());
        if alpha == 0.0 {
            assert_eq!(
                score_for(&fresh, salient).to_bits(),
                baseline_salient.to_bits()
            );
        } else {
            let expected = 1.0_f32 * (0.6 * 0.75 / 1.0) * 1.4 * (1.0 - 0.15);
            assert_eq!(score_for(&fresh, salient).to_bits(), expected.to_bits());
        }
    }
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
        let gated = gate_edge(&vault.store, &txn, &key, &value, 0)?.expect("traversable");
        assert_eq!(gated.vad, if len == 12 { None } else { Some(vad) });
    }
    Ok(())
}

#[test]
fn ppr_vad_cache_separates_both_alphas_and_resume_state() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    vault.put_edge(&seed, EdgeKind::Mentions, &entity(2), 1.0)?;
    vault.set_edge_vad(
        &seed,
        EdgeKind::Mentions,
        &entity(2),
        Vad {
            valence: 0.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    let mut hashes = HashSet::new();
    for &alpha in crate::config::PPR_VAD_ALPHA_SWEEP {
        let mut config = vault.config.clone();
        config.ppr_vad_alpha = alpha;
        for teleport_alpha in [0.15, 0.25] {
            assert!(hashes.insert(hash_seeds(
                &[seed],
                2,
                teleport_alpha,
                alpha,
                SeedWeighting::Uniform
            )));
            ppr_query(&vault.store, &config, &[seed], 1, teleport_alpha)?;
            let resumed = ppr_query(&vault.store, &config, &[seed], 2, teleport_alpha)?;
            let txn = vault.store.env.read_txn()?;
            let fresh = ppr_compute_state_weighted(
                &vault.store,
                &txn,
                &[seed],
                SeedWeighting::Uniform,
                2,
                PprAlphas {
                    teleport_alpha,
                    ppr_vad_alpha: alpha,
                },
                None,
            )?;
            assert_scores_equal(&resumed, &fresh.scores);
            let hash = hash_seeds(&[seed], 2, teleport_alpha, alpha, SeedWeighting::Uniform);
            assert!(vault.store.ppr_cache.get(&txn, &hash)?.is_some());
        }
    }
    Ok(())
}

#[test]
fn ppr_vad_invalid_alpha_rejected_before_empty_or_cached_query() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    ppr_query(&vault.store, &vault.config, &[seed], 1, 0.15)?;
    for alpha in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 0.41] {
        let mut config = vault.config.clone();
        config.ppr_vad_alpha = alpha;
        for seeds in [&[][..], &[seed][..]] {
            assert!(matches!(
                ppr_query(&vault.store, &config, seeds, 1, 0.15),
                Err(Error::InvalidConfig(_))
            ));
        }
    }
    Ok(())
}

#[test]
fn ppr_vad_zero_matches_multiround_baseline_and_resume_bits() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    let target = entity(2);
    vault.put_edge(&seed, EdgeKind::Mentions, &target, 0.75)?;
    vault.set_edge_vad(
        &seed,
        EdgeKind::Mentions,
        &target,
        Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.5,
        },
    )?;
    let mut seed_frontier = 1.0_f32;
    let mut target_frontier = 0.0_f32;
    let mut seed_score = 1.0_f32;
    let mut target_score = 0.0_f32;
    for depth in 1..=4 {
        // Independent recurrence of the pre-VAD formula for one bidirectional
        // semantic edge. Two frontier terms make addition order immaterial.
        let total = seed_frontier + target_frontier;
        let next_seed = target_frontier * (0.6 * 0.75 / 0.75) * (1.0 - 0.15) + total * 0.15;
        let next_target = seed_frontier * (0.6 * 0.75 / 0.75) * (1.0 - 0.15);
        seed_score += next_seed;
        target_score += next_target;
        seed_frontier = next_seed;
        target_frontier = next_target;
        let resumed = ppr_query(&vault.store, &vault.config, &[seed], depth, 0.15)?;
        let cached = ppr_query(&vault.store, &vault.config, &[seed], depth, 0.15)?;
        let txn = vault.store.env.read_txn()?;
        let fresh = ppr_compute(&vault.store, &txn, &[seed], depth, 0.15)?;
        for scores in [&resumed, &cached, &fresh] {
            assert_eq!(score_for(scores, seed).to_bits(), seed_score.to_bits());
            assert_eq!(score_for(scores, target).to_bits(), target_score.to_bits());
            assert_eq!(
                scores.iter().map(|row| row.id).collect::<Vec<_>>(),
                vec![seed, target]
            );
        }
    }
    Ok(())
}

#[test]
fn ppr_vad_reverse_hops_use_the_same_salience_multiplier() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let source = entity(1);
    let seed = entity(2);
    let vad = Vad {
        valence: 0.0,
        arousal: 0.9,
        dominance: 1.0,
    };
    vault
        .batch()
        .edge_with_value_fields(
            &source,
            EdgeKind::Mentions,
            &seed,
            EdgeValueFields {
                weight: 0.75,
                created_at: 1,
                vad,
                provenance: Some(EdgeProvenanceFlags {
                    confirmation_status: EdgeConfirmationStatus::Confirmed,
                    actor_class: EdgeActorClass::Human,
                }),
            },
        )
        .commit()?;
    let mut config = vault.config.clone();
    config.ppr_vad_alpha = 0.4;
    let scores = ppr_query(&vault.store, &config, &[seed], 1, 0.15)?;
    let expected = 1.0_f32 * (0.6 * 0.75 / 0.75) * (1.0 + 0.4 * 0.9) * (1.0 - 0.15);
    assert_eq!(score_for(&scores, source).to_bits(), expected.to_bits());
    Ok(())
}

#[test]
fn ppr_vad_signed_zero_reuses_cache_and_exact_scores() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(1);
    let target = entity(2);
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
    let mut config = vault.config.clone();
    config.ppr_vad_alpha = 0.0;
    let positive = ppr_query(&vault.store, &config, &[seed], 2, 0.15)?;
    let cache_before = count_entries(&vault.store.ppr_cache, &vault)?;
    let deps_before = count_entries(&vault.store.ppr_cache_deps, &vault)?;
    config.ppr_vad_alpha = -0.0;
    let negative = ppr_query(&vault.store, &config, &[seed], 2, 0.15)?;
    assert_eq!(score_bits(&positive), score_bits(&negative));
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, cache_before);
    assert_eq!(
        count_entries(&vault.store.ppr_cache_deps, &vault)?,
        deps_before
    );
    for mode in [SeedWeighting::Uniform, SeedWeighting::Specificity] {
        assert_eq!(
            hash_seeds(&[seed], 2, 0.15, 0.0, mode),
            hash_seeds(&[seed], 2, 0.15, -0.0, mode)
        );
    }
    let txn = vault.store.env.read_txn()?;
    let fresh = ppr_compute_state_weighted(
        &vault.store,
        &txn,
        &[seed],
        SeedWeighting::Uniform,
        2,
        PprAlphas {
            teleport_alpha: 0.15,
            ppr_vad_alpha: -0.0,
        },
        None,
    )?;
    assert_eq!(score_bits(&positive), score_bits(&fresh.scores));
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
) -> Result<(Vec<ScoredEntity>, crate::ppr_community::CommunityBoostReport)> {
    let mut seeds: Vec<_> = context.ordered_seeds.iter().map(|seed| seed.id).collect();
    seeds.sort_unstable();
    let (scores, write, report) = {
        let txn = vault.store.env.read_txn()?;
        ppr_query_in_txn_with_community_deferred_cache(&vault.store, &txn, CommunityPprRequest {
            seeds: &seeds,
            depth,
            teleport_alpha: 0.15,
            weighting,
            config,
            context,
        })?
    };
    if let Some(write) = write {
        flush_deferred_ppr_cache_writes(&vault.store, &[write])?;
    }
    Ok((scores, report))
}

#[test]
fn ppr_community_zero_and_specificity_bypass_corrupt_cache_and_invalid_context_exactly() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let seed = entity(1);
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &[ScoredEntity { id: seed, score: f32::NAN }],
        result_limit: 0,
        session_usage: &usage,
    };
    {
        let mut txn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut txn, b"ppr_community_cache:v0:meta", b"corrupt")?;
        txn.commit()?;
    }
    for weighting in [SeedWeighting::Uniform, SeedWeighting::Specificity] {
        let baseline = {
            let txn = vault.store.env.read_txn()?;
            let (scores, write) = ppr_query_in_txn_with_vad_deferred_cache(
                &vault.store, &txn, &[seed], 1, 0.15, 0.0, weighting,
            )?;
            drop(txn);
            if let Some(write) = write {
                flush_deferred_ppr_cache_writes(&vault.store, &[write])?;
            }
            scores
        };
        let before = {
            let txn = vault.store.env.read_txn()?;
            vault.store.ppr_cache.iter(&txn)?.map(|entry| {
                entry.map(|(key, value)| (key.to_vec(), value.to_vec()))
            }).collect::<Result<Vec<_>>>()?
        };
        let mut config = vault.config.clone();
        config.ppr_community.gamma = f32::NAN;
        config.ppr_community.beta = if weighting == SeedWeighting::Uniform { -0.0 } else { f32::NAN };
        let (actual, report) = community_query_for_test(&vault, &config, weighting, 1, &context)?;
        assert_eq!(actual.iter().map(|row| (row.id, row.score.to_bits())).collect::<Vec<_>>(),
            baseline.iter().map(|row| (row.id, row.score.to_bits())).collect::<Vec<_>>());
        assert_eq!(report, crate::ppr_community::CommunityBoostReport::default());
        let txn = vault.store.env.read_txn()?;
        let after = vault.store.ppr_cache.iter(&txn)?.map(|entry| {
            entry.map(|(key, value)| (key.to_vec(), value.to_vec()))
        }).collect::<Result<Vec<_>>>()?;
        assert_eq!(before, after);
    }
    Ok(())
}

#[test]
fn ppr_community_preserves_canonical_vad_keys_and_nonzero_salience() -> Result<()> {
    use crate::ppr_community::{CommunityBoostContext, community_cache_identity};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    vault.set_edge_vad(
        &entity(1),
        EdgeKind::BelongsTo,
        &entity(2),
        Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let usage = HashMap::new();
    let evidence = [ScoredEntity { id: entity(1), score: 1.0 }];
    let context = CommunityBoostContext {
        ordered_seeds: &evidence,
        result_limit: 10,
        session_usage: &usage,
    };
    let identity = community_cache_identity(0.2, graph_version(&vault)?).expect("identity");
    let key_for = |alpha| {
        hash_community_seeds(
            hash_seeds(&[entity(1)], 1, 0.15, alpha, SeedWeighting::Uniform),
            identity,
        )
    };
    let row_for = |key: &[u8; SEED_HASH_LEN]| -> Result<Vec<u8>> {
        let txn = vault.store.env.read_txn()?;
        Ok(vault.store.ppr_cache.get(&txn, key)?.expect("cache row").to_vec())
    };
    config.ppr_vad_alpha = 0.0;
    let (zero, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    let zero_row = row_for(&key_for(0.0))?;
    let cache_count = count_entries(&vault.store.ppr_cache, &vault)?;
    let dep_count = count_entries(&vault.store.ppr_cache_deps, &vault)?;
    config.ppr_vad_alpha = -0.0;
    let (negative_zero, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert_eq!(key_for(0.0), key_for(-0.0));
    assert_eq!(score_bits(&zero), score_bits(&negative_zero));
    assert_eq!(row_for(&key_for(-0.0))?, zero_row);
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, cache_count);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, dep_count);

    config.ppr_vad_alpha = 0.4;
    let (weighted, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert_ne!(key_for(0.0), key_for(0.4));
    assert!(score_for(&weighted, entity(2)) > score_for(&zero, entity(2)));
    let weighted_row = row_for(&key_for(0.4))?;
    let weighted_state = decode_cache_state(&weighted_row[CACHE_HEADER_LEN..])?;
    let zero_state = decode_cache_state(&zero_row[CACHE_HEADER_LEN..])?;
    assert!(score_for(&weighted_state.scores, entity(2)) > score_for(&zero_state.scores, entity(2)));
    let (cached, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert_eq!(score_bits(&weighted), score_bits(&cached));
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, cache_count + 1);
    assert_eq!(row_for(&key_for(0.0))?, zero_row);
    Ok(())
}

#[test]
fn ppr_community_nonzero_cache_contains_base_state_and_session_decay_is_not_cached() -> Result<()> {
    use crate::ppr_community::{CommunityBoostContext, community_cache_identity};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    config.ppr_vad_alpha = 0.4;
    let evidence = [ScoredEntity { id: entity(1), score: 1.0 }];
    let empty_usage = HashMap::new();
    let context = CommunityBoostContext { ordered_seeds: &evidence, result_limit: 10, session_usage: &empty_usage };
    let (fresh, report) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert_eq!(report.boosted_candidates, 2);
    let version = graph_version(&vault)?;
    let base_key = hash_seeds(&[entity(1)], 1, 0.15, 0.4, SeedWeighting::Uniform);
    let key = hash_community_seeds(base_key, community_cache_identity(0.2, version).expect("identity"));
    assert_ne!(key, base_key);
    let (row, base_score, fine) = {
        let txn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&txn, &base_key)?.is_none());
        let row = vault.store.ppr_cache.get(&txn, &key)?.expect("cache").to_vec();
        let state = decode_cache_state(&row[CACHE_HEADER_LEN..])?;
        let base_score = score_for(&state.scores, entity(2));
        let snapshot = vault.store.ppr_community_snapshot_in_txn(&txn)?.expect("published snapshot");
        (row, base_score, snapshot.nodes[&entity(1)].fine)
    };
    assert!(score_for(&fresh, entity(2)) > base_score);
    let usage = HashMap::from([(fine, 10)]);
    let decayed_context = CommunityBoostContext { session_usage: &usage, ..context };
    let (decayed, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &decayed_context)?;
    assert!(score_for(&decayed, entity(2)) < score_for(&fresh, entity(2)));
    assert!(score_for(&decayed, entity(2)) > base_score);
    let txn = vault.store.env.read_txn()?;
    assert_eq!(vault.store.ppr_cache.get(&txn, &key)?.expect("unchanged state").as_ref(), row.as_slice());
    assert_ne!(key, hash_community_seeds(base_key, community_cache_identity(0.2, version + 1).expect("version")));
    assert_ne!(key, hash_community_seeds(base_key, community_cache_identity(0.3, version).expect("beta")));
    assert_eq!(base_key, hash_community_seeds(base_key, community_cache_identity(0.0, version).expect("zero")));
    Ok(())
}

#[test]
fn ppr_community_ordered_evidence_and_safety_knobs_are_reapplied_on_base_cache_hits() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let usage = HashMap::new();
    let dominant = [ScoredEntity { id: entity(1), score: 1.5 }, ScoredEntity { id: entity(3), score: 1.0 }];
    let context = CommunityBoostContext { ordered_seeds: &dominant, result_limit: 10, session_usage: &usage };
    let (boosted, report) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert!(report.boosted_candidates > 0);
    let ambiguous = [ScoredEntity { id: entity(1), score: 1.49 }, ScoredEntity { id: entity(3), score: 1.0 }];
    let inactive = CommunityBoostContext { ordered_seeds: &ambiguous, ..context };
    let (unboosted, report) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &inactive)?;
    assert_eq!(report.activated_communities, 0);
    assert!(score_for(&boosted, entity(2)) > score_for(&unboosted, entity(2)));
    config.ppr_community.multiplier_cap = 1.0;
    let (capped, report) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    assert_eq!(report.boosted_candidates, 0);
    assert_eq!(score_for(&capped, entity(2)).to_bits(), score_for(&unboosted, entity(2)).to_bits());
    Ok(())
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
        ordered_seeds: &[ScoredEntity { id: entity(1), score: 1.0 }],
        result_limit: 10,
        session_usage: &usage,
    };
    let write = {
        let txn = vault.store.env.read_txn()?;
        let (_, write, _) = ppr_query_in_txn_with_community_deferred_cache(&vault.store, &txn, CommunityPprRequest {
            seeds: &[entity(1)], depth: 1, teleport_alpha: 0.15,
            weighting: SeedWeighting::Uniform, config: &config, context: &context,
        })?;
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
fn ppr_community_nonzero_validates_config_evidence_and_cache_before_publishing() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut config = vault.config.clone();
    let usage = HashMap::new();
    let context = CommunityBoostContext { ordered_seeds: &[], result_limit: 0, session_usage: &usage };
    for beta in [f32::NAN, f32::INFINITY, -0.1] {
        config.ppr_community.beta = beta;
        assert!(matches!(community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context), Err(Error::InvalidConfig(_))));
    }
    config.ppr_community.beta = 0.2;
    let context = CommunityBoostContext {
        ordered_seeds: &[ScoredEntity { id: entity(1), score: f32::NAN }],
        ..context
    };
    assert!(community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context).is_err());
    let txn = vault.store.env.read_txn()?;
    assert!(vault.store.ppr_community_snapshot_in_txn(&txn)?.is_none());
    assert_eq!(vault.store.ppr_cache.len(&txn)?, 0);
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
    vault.store.vault_meta.put(&mut txn, b"ppr_community_cache:v0:meta", b"corrupt")?;
    txn.commit()?;
    let txn = vault.store.env.read_txn()?;
    let scores = ppr_query_scoped_in_txn(&vault.store, &txn, &[entity(1)], 2, 0.15,
        vault.config.ppr_vad_alpha, SeedWeighting::Uniform, &Visibility)?;
    assert_eq!(scores.iter().map(|row| row.id).collect::<Vec<_>>(), vec![entity(1)]);
    assert_eq!(vault.store.ppr_cache.len(&txn)?, 0);
    Ok(())
}

#[test]
fn ppr_community_resume_uses_unboosted_frontier_and_never_compounds_the_prior() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &[ScoredEntity { id: entity(1), score: 1.0 }],
        result_limit: 10,
        session_usage: &usage,
    };
    community_query_for_test(&vault, &config, SeedWeighting::Uniform, 1, &context)?;
    let (resumed, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 2, &context)?;
    let (cached, _) = community_query_for_test(&vault, &config, SeedWeighting::Uniform, 2, &context)?;
    assert_eq!(resumed.iter().map(|row| (row.id, row.score.to_bits())).collect::<Vec<_>>(),
        cached.iter().map(|row| (row.id, row.score.to_bits())).collect::<Vec<_>>());
    let txn = vault.store.env.read_txn()?;
    let state = ppr_compute_state_weighted(&vault.store, &txn, &[entity(1)],
        SeedWeighting::Uniform, 2, PprAlphas::default_vad(0.15), None)?;
    let snapshot = vault.store.ppr_community_snapshot_in_txn(&txn)?.expect("snapshot");
    let cache = crate::ppr_community::PprCommunityCache::new(&snapshot, snapshot.meta.graph_version)
        .expect("valid snapshot");
    let mut expected = state.scores;
    crate::ppr_community::apply_community_prior(&mut expected, &cache, &context, &config.ppr_community)
        .expect("one prior application");
    assert_scores_equal(&resumed, &expected);
    Ok(())
}


#[test]
fn community_pipeline_adapter_keeps_full_rounds_until_admitted_final_selection() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.beta = 0.2;
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &[ScoredEntity { id: entity(1), score: 1.0 }],
        result_limit: 1, session_usage: &usage,
    };
    let txn = vault.store.env.read_txn()?;
    let (mut scores, write, diversity) = ppr_expand_in_txn_with_community_deferred_cache(
        &vault.store, &txn, CommunityPprRequest {
            seeds: &[entity(1)], depth: 1, teleport_alpha: 0.15,
            weighting: SeedWeighting::Uniform, config: &config, context: &context,
        },
    )?;
    assert!(scores.len() > context.result_limit, "PPR is a candidate channel, not final top-k");
    assert!(write.is_some());
    assert!(vault.store.ppr_community_snapshot_in_txn(&txn)?.is_none(), "still deferred");
    let diversity = diversity.expect("activated seed");
    let before: HashMap<_, _> = scores.iter().map(|row| (row.id, row.score.to_bits())).collect();
    // The only nonmatching candidate is filtered out after expansion. A cached
    // membership row must not become a new result or refill the protected slot.
    scores.retain(|row| row.id != entity(3));
    diversity.apply(&mut scores, 1, &config.ppr_community)?;
    assert_eq!(scores.len(), 1);
    assert_ne!(scores[0].id, entity(3));
    assert_eq!(scores[0].score.to_bits(), before[&scores[0].id]);
    diversity.apply(&mut scores, 0, &config.ppr_community)?;
    assert!(scores.is_empty());
    Ok(())
}

#[test]
fn community_pipeline_adapter_zero_preserves_original_state_and_key_without_context_reads() -> Result<()> {
    use crate::ppr_community::CommunityBoostContext;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    community_ppr_fixture(&vault)?;
    let mut config = vault.config.clone();
    config.ppr_community.gamma = f32::NAN;
    let mut txn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(&mut txn, b"ppr_community_cache:v0:meta", b"corrupt")?;
    txn.commit()?;
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &[ScoredEntity { id: entity(50), score: f32::NAN }],
        result_limit: 0, session_usage: &usage,
    };
    let txn = vault.store.env.read_txn()?;
    let (expected, expected_write) = ppr_query_in_txn_with_vad_deferred_cache(
        &vault.store, &txn, &[entity(1)], 1, 0.15, config.ppr_vad_alpha, SeedWeighting::Uniform,
    )?;
    for beta in [0.0, -0.0] {
        config.ppr_community.beta = beta;
        let (actual, write, diversity) = ppr_expand_in_txn_with_community_deferred_cache(
            &vault.store, &txn, CommunityPprRequest {
                seeds: &[entity(1)], depth: 1, teleport_alpha: 0.15,
                weighting: SeedWeighting::Uniform, config: &config, context: &context,
            },
        )?;
        assert_eq!(actual.iter().map(|row| (row.id, row.score.to_bits())).collect::<Vec<_>>(),
            expected.iter().map(|row| (row.id, row.score.to_bits())).collect::<Vec<_>>());
        assert_eq!(write.as_ref().map(|write| write.seed_hash), expected_write.as_ref().map(|write| write.seed_hash));
        assert!(diversity.is_none());
    }
    Ok(())
}
