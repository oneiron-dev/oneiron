use core::assert_matches;
use std::collections::{BTreeMap, HashMap};

use heed::types::Bytes;

use crate::config::{HnswConfig, VaultConfig};

use super::*;

fn test_config() -> VaultConfig {
    VaultConfig {
        map_size: 16 * 1024 * 1024,
        dimensions: 4,
        fast_dims: None,
        embedding_model: Some("test-model-v1".to_owned()),
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: crate::config::TextAnalyzerConfig::default(),
        dict_search_paths: Vec::new(),
        skip_text_index_manifest_check: false,
    }
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(test_config())
}

fn entity_id(byte: u8) -> EntityId {
    let byte = match byte {
        0x00 | 0xFF => 0x01,
        other => other,
    };
    EntityId::from_bytes([byte; 16]).expect("test ids should be valid")
}

fn put_entity(
    vault: &Vault,
    id: EntityId,
    entity_type: u8,
    start: u64,
    end: u64,
    learned: u64,
) -> Result<()> {
    vault.put_entity(
        &id,
        entity_type,
        TimeRange { start, end },
        learned,
        b"payload",
    )
}

fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
    put_text_at(vault, id, text, 1)
}

fn put_text_at(vault: &Vault, id: EntityId, text: &str, learned_at: u64) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            1,
            TimeRange { start: 1, end: 1 },
            learned_at,
            b"payload",
        )
        .text(&id, &[("body", text)])
        .commit()
}

fn put_text_with_time(
    vault: &Vault,
    id: EntityId,
    text: &str,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, occurred, learned_at, b"payload")
        .text(&id, &[("body", text)])
        .commit()
}

fn active_claim_body(world: Option<EntityId>) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "test.prefix_scope",
        crate::claim::ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.world = world;
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

fn active_claim_body_with_salience(salience: f32) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "test.blend_salience",
        crate::claim::ClaimSubject::Entity(entity_id(0x7D)),
        rmpv::Value::from("v"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.salience = Some(salience);
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

fn put_claim_text(vault: &Vault, id: EntityId, text: &str, world: Option<EntityId>) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &active_claim_body(world),
        )
        .text(&id, &[("body", text)])
        .commit()
}

fn put_claim_text_with_salience(
    vault: &Vault,
    id: EntityId,
    text: &str,
    salience: f32,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &active_claim_body_with_salience(salience),
        )
        .text(&id, &[("body", text)])
        .commit()
}

fn put_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
    put_vector_at(vault, id, vector, 1)
}

fn put_vector_at(vault: &Vault, id: EntityId, vector: [f32; 4], learned_at: u64) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            1,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"payload",
        )
        .vector(&id, &vector)
        .commit()
}

fn put_text_and_vector(vault: &Vault, id: EntityId, text: &str, vector: [f32; 4]) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&id, &[("body", text)])
        .vector(&id, &vector)
        .commit()
}

fn put_codebase_vector(
    vault: &Vault,
    id: EntityId,
    project_id: &str,
    repo_ref: RepoRef,
    vector: [f32; 4],
) -> Result<()> {
    let canonical_repo_ref = repo_ref.canonical();
    let commit_hash = canonical_repo_ref
        .split_once('#')
        .map(|(_, commit_hash)| commit_hash.to_owned());
    let body = crate::code_artifact::CodeArtifactBody::new(
        "Summarize the codebase snapshot.",
        [0xA5; crate::code_artifact::CODE_ARTIFACT_SUMMARY_HASH_LEN],
        canonical_repo_ref,
    );
    vault.put_code_artifact(&id, &body, TimeRange { start: 1, end: 1 }, 1)?;
    let snapshot = crate::codebase::CodebaseSnapshot::new(
        project_id,
        repo_ref,
        commit_hash,
        vec![crate::codebase::CodebaseFileEntry::new(
            "src/lib.rs",
            [0xC0; crate::codebase::CODEBASE_CONTENT_HASH_LEN],
            1,
        )],
    )?;
    vault.put_codebase_snapshot(&id, &snapshot)?;
    vault.batch().vector(&id, &vector).commit()
}

fn put_text_and_vector_with_time(
    vault: &Vault,
    id: EntityId,
    text: &str,
    vector: [f32; 4],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, occurred, learned_at, b"payload")
        .text(&id, &[("body", text)])
        .vector(&id, &vector)
        .commit()
}

fn scored(id: EntityId, score: f32) -> ScoredEntity {
    ScoredEntity { id, score }
}

fn count_entries(db: &heed::Database<Bytes, Bytes>, vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in db.iter(&rtxn)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn to_score_map(scores: &[ScoredEntity]) -> HashMap<EntityId, f32> {
    scores.iter().map(|entry| (entry.id, entry.score)).collect()
}

fn approx_eq(left: f32, right: f32, eps: f32) -> bool {
    (left - right).abs() <= eps
}

/// ARCH-0004 §4.5: the recency default is a named 28-day constant
/// (`RECENCY_DECAY`, source timestamp = `learned_at` v1), and the
/// temporal scorer's decay constant is the table-pinned
/// `28.0 * 86_400 = 2_419_200` seconds derived from it.
#[test]
fn default_recency_half_life_is_28_days() {
    assert_eq!(DEFAULT_RECENCY_HALF_LIFE_DAYS, 28.0);
    assert_eq!(RECENCY_DECAY_TAU_SECS, 2_419_200.0);
    assert_eq!(RECENCY_DECAY_TAU_SECS, 28.0 * 86_400.0);
}

#[test]
fn recency_half_life_table_is_contract_pinned() {
    assert_eq!(
        RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE,
        &[
            (ENTITY_TYPE_CLAIM, 28.0),
            (ENTITY_TYPE_TURN, 28.0),
            (crate::registry::ENTITY_TYPE_SESSION, 28.0),
            (crate::registry::ENTITY_TYPE_MESSAGE, 28.0),
            (crate::registry::ENTITY_TYPE_PERSON, 365.0),
            (crate::registry::ENTITY_TYPE_RELATIONSHIP, 180.0),
            (ENTITY_TYPE_EVENT, 30.0),
            (crate::registry::ENTITY_TYPE_SKILL, 90.0),
            (ENTITY_TYPE_SUMMARY, 90.0),
            (crate::registry::ENTITY_TYPE_PLACE, 180.0),
            (crate::registry::ENTITY_TYPE_ASSET_TEXT, 90.0),
            (crate::registry::ENTITY_TYPE_CONVERSATION, 30.0),
            (crate::registry::ENTITY_TYPE_ORG, 180.0),
            (ENTITY_TYPE_FACET, 180.0),
            (crate::registry::ENTITY_TYPE_WORLD, 180.0),
            (crate::registry::ENTITY_TYPE_ASSET, 90.0),
            (crate::registry::ENTITY_TYPE_NOTIFICATION, 7.0),
            (crate::registry::ENTITY_TYPE_TASK_LIST, 30.0),
            (crate::registry::ENTITY_TYPE_TASK, 30.0),
            (crate::registry::ENTITY_TYPE_MACHINE, 180.0),
            (crate::registry::ENTITY_TYPE_CODE_ARTIFACT, 90.0),
            (crate::registry::ENTITY_TYPE_REDACTION_AUDIT, 365.0),
            (crate::registry::ENTITY_TYPE_MODEL, 180.0),
            (crate::registry::ENTITY_TYPE_POLICY_MANIFEST, 365.0),
            (crate::registry::ENTITY_TYPE_FEDERATION_GRANT, 365.0),
            (crate::registry::ENTITY_TYPE_ACCESS_GRANT, 365.0),
            (crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT, 365.0),
            (crate::registry::ENTITY_TYPE_OUTBOUND_GRANT, 365.0),
            (crate::registry::ENTITY_TYPE_PSYCH_PROFILE, 365.0),
        ]
    );
    assert!(
        retrieval_recency_half_life_days_for_type(crate::registry::ENTITY_TYPE_PERSON)
            > DEFAULT_RECENCY_HALF_LIFE_DAYS
    );
    assert_eq!(
        retrieval_recency_half_life_days_for_type(250),
        DEFAULT_RECENCY_HALF_LIFE_DAYS
    );
}

#[test]
fn tuned_weight_table_changes_retrieval_scoring_without_recompile() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let high = entity_id(0xB0);
    let mid = entity_id(0xB1);
    let low = entity_id(0xB2);
    put_claim_text_with_salience(&vault, high, "weighttableneedle", 0.9)?;
    put_claim_text_with_salience(&vault, mid, "weighttableneedle", 0.4)?;
    put_claim_text_with_salience(&vault, low, "weighttableneedle", 0.0)?;

    let baseline = vault
        .query()
        .search_text("weighttableneedle", 10)
        .boost_salience()
        .run()?;
    let baseline_score = *to_score_map(&baseline)
        .get(&high)
        .expect("high-salience result is present");

    let run_id = RetrievalRunId::now();
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        200,
        10,
        vec![RetrievalSignal::Text],
        vec![
            RetrievalScoreBreakdown {
                result_id: *high.as_bytes(),
                final_rank: 1,
                final_score: baseline_score,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Salience,
                    rank: 1,
                    score: 1.0,
                }],
            },
            RetrievalScoreBreakdown {
                result_id: *low.as_bytes(),
                final_rank: 2,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Salience,
                    rank: 2,
                    score: -1.0,
                }],
            },
        ],
        2,
        0,
        None,
    );
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let before = vault.retrieval_blend_weight_table()?;
    let updated = vault.tune_retrieval_blend_weights(crate::store::RetrievalBlendTuningConfig {
        max_runs: 10,
        learning_rate: 0.20,
        min_reward_count: 1,
    })?;
    assert!(updated.weights.salience > before.weights.salience);

    let rescored = vault
        .query()
        .search_text("weighttableneedle", 10)
        .boost_salience()
        .run()?;
    let rescored_score = *to_score_map(&rescored)
        .get(&high)
        .expect("high-salience result remains present");

    assert_ne!(baseline_score.to_bits(), rescored_score.to_bits());
    assert!(rescored_score > baseline_score);
    Ok(())
}

#[test]
fn cosine_ghost_is_gravity_signal_not_multiplier() {
    assert_eq!(COSINE_GHOST_VECTOR_THRESHOLD, 0.3);

    let ghost = entity_id(0xA0);
    let vector = vec![scored(ghost, 0.6)];
    let text = Vec::new();
    let ghosts = cosine_ghost_set(&[vector, text], Some(0), Some(1));

    assert_eq!(ghosts.len(), 1);
    assert!(ghosts.contains(&ghost));
}

#[test]
fn threshold_boundary() {
    let boundary = entity_id(0x91);
    let above = entity_id(0x92);
    let vector = vec![scored(boundary, 0.30), scored(above, 0.31)];
    let text = Vec::new();
    let ghosts = cosine_ghost_set(&[vector, text], Some(0), Some(1));

    assert_eq!(ghosts.len(), 1);
    assert!(!ghosts.contains(&boundary));
    assert!(ghosts.contains(&above));
}

#[test]
fn lexical_overlap_protects() {
    let protected = entity_id(0x93);
    let vector = vec![scored(protected, 0.6)];
    let text = vec![scored(protected, 9.0)];
    let ghosts = cosine_ghost_set(&[vector, text], Some(0), Some(1));

    assert!(ghosts.is_empty());
}

#[test]
fn single_channel_noop() {
    let ghost = entity_id(0x94);
    let vector = vec![scored(ghost, 0.6)];
    let ghosts = cosine_ghost_set(std::slice::from_ref(&vector), Some(0), None);

    assert!(ghosts.is_empty());
}

#[test]
fn metric_counts_dampened() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ghost_a = entity_id(0x95);
    let ghost_b = entity_id(0xA6);
    let lexical = entity_id(0xA7);
    let low_similarity = entity_id(0xA8);

    put_vector(&vault, ghost_a, [1.0, 0.0, 0.0, 0.0])?;
    put_vector(&vault, ghost_b, [0.6, 0.8, 0.0, 0.0])?;
    put_text_and_vector(&vault, lexical, "gravityneedle", [0.8, 0.6, 0.0, 0.0])?;
    put_vector(&vault, low_similarity, [0.0, 1.0, 0.0, 0.0])?;

    let output = vault
        .query()
        .search_text("gravityneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_gravity()
        .run_for_pack()?;

    assert_eq!(output.cosine_ghosts_dampened, 2);
    Ok(())
}

#[test]
fn disabled_by_default() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ghost = entity_id(0xA9);
    let lexical = entity_id(0xAA);

    put_vector(&vault, ghost, [1.0, 0.0, 0.0, 0.0])?;
    put_text(&vault, lexical, "defaultoffneedle")?;

    let baseline = vault
        .query()
        .search_text("defaultoffneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run_for_pack()?;
    let boosted = vault
        .query()
        .search_text("defaultoffneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_gravity()
        .run_for_pack()?;

    let baseline_scores = to_score_map(&baseline.scores);
    let boosted_scores = to_score_map(&boosted.scores);

    assert_eq!(baseline.cosine_ghosts_dampened, 0);
    assert!(approx_eq(baseline_scores[&ghost], 1.0, 1e-7));
    assert_eq!(boosted.cosine_ghosts_dampened, 1);
    assert!(boosted_scores[&ghost] < baseline_scores[&ghost]);
    Ok(())
}

#[test]
fn text_only_query() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = entity_id(3);
    let b = entity_id(4);

    put_text(&vault, a, "alpha world")?;
    put_text(&vault, b, "beta world")?;

    let results = vault.query().search_text("alpha", 10).run()?;
    assert!(!results.is_empty());
    assert_eq!(results[0].id, a);
    Ok(())
}

#[test]
fn dreamer_ingress_api_is_working_set_only() {
    let source = include_str!("../pipeline.rs");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("pipeline source has production section");
    let public_dreamer_methods: Vec<_> = production_source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub fn") && line.contains("dreamer"))
        .collect();

    assert_eq!(
        public_dreamer_methods,
        vec!["pub fn run_dreamer_working_set("]
    );
    for forbidden in [
        "DreamerVault",
        "run_dreamer_vault",
        "dreamer_whole_vault",
        "dreamer_all_vault",
    ] {
        assert!(
            !production_source.contains(forbidden),
            "Dreamer ingress must not expose {forbidden}"
        );
    }
}

#[test]
fn dreamer_working_set_cursor_advances_incrementally() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for seed in [0xD1, 0xD2, 0xD3] {
        put_text(&vault, entity_id(seed), "dreamer cursor needle")?;
    }

    let budget = DreamerWorkingSetBudget::new(10);
    let first = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(DreamerWorkingSetCursor::start(), budget, 1)?;

    assert_eq!(first.cursor.offset(), 0);
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.stop_reason, None);
    let next_cursor = first.next_cursor.expect("first page has a cursor");
    assert_eq!(next_cursor.offset(), 1);

    let second = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(next_cursor, budget, 1)?;

    assert_eq!(second.cursor.offset(), 1);
    assert_eq!(second.rows.len(), 1);
    assert_ne!(first.rows[0].id, second.rows[0].id);
    assert_eq!(
        second
            .next_cursor
            .expect("second page has a cursor")
            .offset(),
        2
    );
    Ok(())
}

#[test]
fn dreamer_working_set_budget_cap_stops_ingress() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for seed in [0xE1, 0xE2, 0xE3] {
        put_text(&vault, entity_id(seed), "dreamer budget needle")?;
    }

    let budget = DreamerWorkingSetBudget::new(2);
    let capped = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(DreamerWorkingSetCursor::start(), budget, 10)?;

    assert_eq!(capped.rows.len(), 2);
    assert_eq!(
        capped.stop_reason,
        Some(DreamerWorkingSetStopReason::BudgetExhausted)
    );
    assert_eq!(capped.next_cursor, None);

    let stopped = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(DreamerWorkingSetCursor::from_offset(2), budget, 1)?;

    assert!(stopped.rows.is_empty());
    assert_eq!(
        stopped.stop_reason,
        Some(DreamerWorkingSetStopReason::BudgetExhausted)
    );
    assert_eq!(stopped.telemetry_run_id, None);
    Ok(())
}

#[test]
fn retrieval_telemetry_records_vector_text_and_ppr_runs() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = entity_id(0x31);
    let b = entity_id(0x32);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&a, &[("body", "telemetry alpha")])
        .vector(&a, &[1.0, 0.0, 0.0, 0.0])
        .put(&b, 1, TimeRange { start: 2, end: 2 }, 2, b"payload")
        .vector(&b, &[0.0, 1.0, 0.0, 0.0])
        .edge(&a, EdgeKind::Supports, &b, 1.0)
        .commit()?;

    let vector = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    let text = vault.query().search_text("alpha", 10).run()?;
    let ppr = vault.query().search_ppr(&[a], 2).run()?;
    assert!(!vector.is_empty());
    assert!(!text.is_empty());
    assert!(!ppr.is_empty());

    let runs = vault.retrieval_runs(10)?;
    let vector_run = runs
        .iter()
        .find(|run| run.signals == vec![RetrievalSignal::Vector])
        .expect("vector telemetry run");
    assert_eq!(vector_run.action, RetrievalAction::Pipeline);
    assert!(vector_run.result_ids.contains(a.as_bytes()));
    assert!(vector_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Vector)
    }));

    let text_run = runs
        .iter()
        .find(|run| run.signals == vec![RetrievalSignal::Text])
        .expect("text telemetry run");
    assert!(text_run.result_ids.contains(a.as_bytes()));
    assert!(text_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Text)
    }));

    let ppr_run = runs
        .iter()
        .find(|run| run.signals == vec![RetrievalSignal::Ppr])
        .expect("ppr telemetry run");
    assert!(ppr_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Ppr)
    }));
    Ok(())
}

#[test]
fn retrieval_outcome_writer_is_idempotent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x33);
    put_text(&vault, id, "outcome telemetry")?;

    let results = vault
        .query()
        .search_text("outcome", 10)
        .run_with_telemetry()?;
    assert!(!results.value.is_empty());
    let run_id = results.run_id.expect("outcome telemetry run id");

    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_owned(), "unit-test".to_owned());
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: metadata.clone(),
    })?;
    metadata.insert("revision".to_owned(), "2".to_owned());
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(0.5),
        accepted: Some(false),
        metadata,
    })?;

    let outcomes = vault.retrieval_outcomes(run_id)?;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].key, "click");
    assert_eq!(outcomes[0].reward, Some(0.5));
    assert_eq!(outcomes[0].accepted, Some(false));
    assert_eq!(
        outcomes[0].metadata.get("revision").map(String::as_str),
        Some("2")
    );
    Ok(())
}

#[test]
fn retrieval_outcome_rejects_unknown_run_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let unknown_run_id = RetrievalRunId::now();

    let error = vault
        .record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id: unknown_run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
        .expect_err("unknown run id should be rejected");
    assert!(matches!(error, Error::InvalidConfig(_)));
    assert!(vault.retrieval_outcomes(unknown_run_id)?.is_empty());
    Ok(())
}

#[test]
fn retrieval_outcome_rejects_active_write_transaction() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3C);
    put_text(&vault, id, "outcome active transaction")?;

    let results = vault
        .query()
        .search_text("outcome active", 10)
        .run_with_telemetry()?;
    assert!(!results.value.is_empty());
    let run_id = results.run_id.expect("outcome telemetry run id");

    let error = vault
        .with_write_txn(|_wtxn| {
            vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
        })
        .expect_err("outcome write should fail fast inside active write transaction");
    assert!(matches!(error, Error::ConcurrentWrite(_)));
    assert!(vault.retrieval_outcomes(run_id)?.is_empty());
    Ok(())
}

#[test]
fn context_pack_records_context_pack_telemetry() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x34);
    put_text(&vault, id, "context telemetry")?;

    let pack = vault.context_pack().search_text("context", 10).run()?;
    assert_eq!(pack.results.len(), 1);

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].action, RetrievalAction::ContextPack);
    assert_eq!(runs[0].signals, vec![RetrievalSignal::Text]);
    assert_eq!(runs[0].elapsed_us, pack.stats.query_time_us);
    assert!(runs[0].result_ids.contains(id.as_bytes()));
    Ok(())
}

#[test]
fn weak_evidence_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x36);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "stored evidence unrelated to the requested keyword",
        [0.2, 0.979_795_9, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .run()?;

    assert!(
        pack.results.is_empty(),
        "the context pack must structurally withhold weak evidence"
    );
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.candidates_considered, 1);
    Ok(())
}

#[test]
fn does_not_delete_stored_memory() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x37);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "stored memory remains available after an abstention",
        [0.2, 0.979_795_9, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .run()?;
    assert!(pack.results.is_empty());

    let direct_results = vault.query().search_vector(&query, 10).run()?;
    assert!(
        direct_results.iter().any(|scored| scored.id == id),
        "abstention must not change ordinary retrieval or remove the vector"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.entities.get(&rtxn, id.as_bytes())?.is_some(),
        "abstention must not delete the stored entity"
    );
    Ok(())
}

#[test]
fn confidence_surfaced() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x38);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "stored evidence with an insufficient semantic match",
        [0.2, 0.979_795_9, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .run()?;

    let empty = pack
        .empty
        .as_ref()
        .expect("abstention must surface a typed empty-context response");
    assert_eq!(
        empty.reason,
        crate::context_pack::EmptyReason::BelowThreshold
    );
    let encoded = serde_json::to_value(empty).expect("empty context serializes");
    assert_eq!(encoded["reason"], "below_threshold");
    Ok(())
}

#[test]
fn poor_score_gap_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_vector(&vault, entity_id(0x39), [0.4, 1.0, 0.0, 0.0])?;
    put_vector(&vault, entity_id(0x3A), [0.39, 1.0, 0.0, 0.0])?;

    let pack = vault.context_pack().search_vector(&query, 10).run()?;

    assert!(pack.results.is_empty());
    assert_eq!(
        pack.empty.as_ref().map(|empty| empty.reason),
        Some(crate::context_pack::EmptyReason::BelowThreshold)
    );
    Ok(())
}

#[test]
fn anomalous_text_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3B);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "strong vector candidate must still be withheld for anomalous text",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 10)
        .search_vector(&query, 10)
        .run()?;

    assert!(pack.results.is_empty());
    assert_eq!(
        pack.empty.as_ref().map(|empty| empty.reason),
        Some(crate::context_pack::EmptyReason::BelowThreshold)
    );
    Ok(())
}

#[test]
fn parsed_temporal_bounds_record_temporal_telemetry_signal() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x35);
    put_text_with_time(
        &vault,
        id,
        "recent temporal telemetry",
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        NOW - 60,
    )?;

    let results = vault
        .query()
        .search_text("recent temporal telemetry", 10)
        .with_temporal_now(NOW)
        .run_with_telemetry()?;
    assert_eq!(results.value.len(), 1);
    let run_id = results.run_id.expect("parsed temporal telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(
        runs[0].signals,
        vec![RetrievalSignal::Text, RetrievalSignal::Temporal]
    );
    Ok(())
}

#[test]
fn direct_vault_searches_emit_retrieval_telemetry() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x36);
    put_text_and_vector(&vault, id, "direct telemetry", [1.0, 0.0, 0.0, 0.0])?;

    let vector = vault.search_vector_with_telemetry(&[1.0, 0.0, 0.0, 0.0], 10)?;
    let text = vault.search_text_with_telemetry("direct", 10)?;
    assert_eq!(vector.value.len(), 1);
    assert_eq!(text.value.len(), 1);
    let vector_run_id = vector.run_id.expect("direct vector telemetry run id");
    let text_run_id = text.run_id.expect("direct text telemetry run id");

    let runs = vault.retrieval_runs(10)?;
    let vector_run = runs
        .iter()
        .find(|run| {
            run.action == RetrievalAction::VaultSearch
                && run.signals == vec![RetrievalSignal::Vector]
        })
        .expect("direct vector telemetry run");
    assert_eq!(vector_run.run_id, vector_run_id);
    assert_eq!(vector_run.claims_suppressed, 0);
    assert_eq!(vector_run.result_ids, vec![*id.as_bytes()]);
    assert!(vector_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Vector)
    }));

    let text_run = runs
        .iter()
        .find(|run| {
            run.action == RetrievalAction::VaultSearch && run.signals == vec![RetrievalSignal::Text]
        })
        .expect("direct text telemetry run");
    assert_eq!(text_run.run_id, text_run_id);
    assert_eq!(text_run.claims_suppressed, 0);
    assert_eq!(text_run.result_ids, vec![*id.as_bytes()]);
    assert!(text_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Text)
    }));
    Ok(())
}

#[test]
fn direct_vault_zero_limit_telemetry_has_no_empty_reason() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x37);
    put_text_and_vector(&vault, id, "zero limit telemetry", [1.0, 0.0, 0.0, 0.0])?;

    let text = vault.search_text_with_telemetry("zero limit", 0)?;
    let vector = vault.search_vector_with_telemetry(&[1.0, 0.0, 0.0, 0.0], 0)?;
    assert!(text.value.is_empty());
    assert!(vector.value.is_empty());
    let text_run_id = text.run_id.expect("text zero-limit telemetry run id");
    let vector_run_id = vector.run_id.expect("vector zero-limit telemetry run id");

    let runs = vault.retrieval_runs(10)?;
    let text_run = runs
        .iter()
        .find(|run| run.run_id == text_run_id)
        .expect("text zero-limit telemetry row");
    let vector_run = runs
        .iter()
        .find(|run| run.run_id == vector_run_id)
        .expect("vector zero-limit telemetry row");
    assert!(text_run.result_ids.is_empty());
    assert!(vector_run.result_ids.is_empty());
    assert_eq!(text_run.empty_reason, None);
    assert_eq!(vector_run.empty_reason, None);
    Ok(())
}

#[test]
fn retrieval_telemetry_records_no_hit_empty_reason() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let results = vault
        .query()
        .search_text("definitelymissing", 10)
        .run_with_telemetry()?;
    assert!(results.value.is_empty());
    let run_id = results.run_id.expect("no-hit telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert!(runs[0].result_ids.is_empty());
    assert_eq!(runs[0].empty_reason.as_deref(), Some("NoData"));
    Ok(())
}

#[test]
fn retrieval_trace_capture_is_flag_off_by_default() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0xB0);
    put_text_and_vector(&vault, id, "trace default off", [1.0, 0.0, 0.0, 0.0])?;

    let results = vault
        .query()
        .search_text("trace default", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run_with_telemetry()?;
    assert_eq!(results.value.len(), 1);
    let run_id = results.run_id.expect("trace default off run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].trace, None);
    assert_eq!(runs[0].result_ids, vec![*id.as_bytes()]);
    Ok(())
}

#[test]
fn retrieval_trace_capture_records_all_pipeline_stages() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let text_id = entity_id(0xB1);
    let vector_id = entity_id(0xB2);

    put_text_and_vector(&vault, text_id, "trace stage fixture", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(
        &vault,
        vector_id,
        "trace stage neighbor",
        [0.8, 0.2, 0.0, 0.0],
    )?;

    let results = vault
        .query()
        .search_text("trace stage fixture", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert!(!results.value.is_empty());
    let run_id = results.run_id.expect("trace capture run id");

    let run = vault
        .retrieval_run(run_id)?
        .expect("trace capture telemetry run");
    let trace = run.trace.expect("trace should be captured");

    assert!(trace.per_channel.len() >= 2);
    assert!(
        trace
            .per_channel
            .iter()
            .any(|channel| channel.signal == RetrievalSignal::Text)
    );
    assert!(
        trace
            .per_channel
            .iter()
            .any(|channel| channel.signal == RetrievalSignal::Vector)
    );
    for channel in &trace.per_channel {
        assert_eq!(channel.stage, RetrievalTraceStage::PerChannel);
        assert!(!channel.candidates.is_empty());
        assert!(channel.candidates.iter().all(|candidate| {
            candidate.final_score.is_finite()
                && candidate
                    .components
                    .iter()
                    .any(|component| component.signal == channel.signal)
        }));
    }

    for stage in [
        &trace.fused,
        &trace.blended,
        &trace.reranked,
        &trace.final_stage,
    ] {
        assert!(!stage.candidates.is_empty());
        assert!(
            stage
                .candidates
                .iter()
                .all(|candidate| candidate.final_score.is_finite())
        );
    }
    assert_eq!(trace.fused.stage, RetrievalTraceStage::Fused);
    assert!(
        trace
            .fused
            .candidates
            .iter()
            .all(|candidate| candidate.final_score > 0.0 && candidate.final_score < 1.0),
        "fused trace should carry rank-fusion scores, not neutral blend placeholders"
    );
    assert_eq!(trace.blended.stage, RetrievalTraceStage::Blended);
    assert_eq!(trace.reranked.stage, RetrievalTraceStage::Reranked);
    assert_eq!(trace.final_stage.stage, RetrievalTraceStage::Final);
    assert_eq!(trace.reranked.candidates, trace.final_stage.candidates);
    assert_eq!(
        trace
            .final_stage
            .candidates
            .iter()
            .map(|candidate| candidate.result_id)
            .collect::<Vec<_>>(),
        run.result_ids
    );
    Ok(())
}

fn trace_candidates_contain(candidates: &[RetrievalScoreBreakdown], id: EntityId) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.result_id == *id.as_bytes())
}

fn captured_retrieval_trace(vault: &Vault, builder: PipelineBuilder<'_>) -> Result<RetrievalTrace> {
    captured_retrieval_run_trace(vault, builder).map(|(_, trace)| trace)
}

fn captured_retrieval_run_trace(
    vault: &Vault,
    builder: PipelineBuilder<'_>,
) -> Result<(RetrievalRunId, RetrievalTrace)> {
    let results = builder.capture_retrieval_trace(true).run_with_telemetry()?;
    let run_id = results
        .run_id
        .ok_or(Error::InvariantViolation("trace test missing run id"))?;
    let run = vault
        .retrieval_run(run_id)?
        .ok_or(Error::InvariantViolation("trace test missing run"))?;
    let trace = run
        .trace
        .ok_or(Error::InvariantViolation("trace test missing trace"))?;
    Ok((run_id, trace))
}

#[test]
fn retrieval_trace_fork_hash_replay_key_is_stable_for_same_inputs() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0xD3);
    let second = entity_id(0xD4);
    put_text_and_vector(&vault, first, "forkhash stable alpha", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(&vault, second, "forkhash stable beta", [0.9, 0.1, 0.0, 0.0])?;

    let (first_run_id, first_trace) = captured_retrieval_run_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash stable", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;
    let (second_run_id, second_trace) = captured_retrieval_run_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash stable", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;

    assert_eq!(first_trace.fork_hash, second_trace.fork_hash);
    assert_eq!(
        rmp_serde::to_vec_named(&first_trace).expect("trace msgpack encode"),
        rmp_serde::to_vec_named(&second_trace).expect("trace msgpack encode")
    );
    assert_eq!(
        vault
            .retrieval_trace_by_fork_hash(first_trace.fork_hash)?
            .expect("trace by fork hash"),
        second_trace
    );
    vault.store.delete_retrieval_run(second_run_id)?;
    assert_eq!(
        vault
            .retrieval_trace_by_fork_hash(first_trace.fork_hash)?
            .expect("trace by fork hash after latest delete"),
        first_trace
    );
    vault.store.delete_retrieval_run(first_run_id)?;
    assert!(
        vault
            .retrieval_trace_by_fork_hash(first_trace.fork_hash)?
            .is_none()
    );
    Ok(())
}

#[test]
fn retrieval_trace_fork_hash_canonicalizes_phonetic_query_codes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0xDA);
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .phonetic(&id, &["ALFA", "BETA"])
        .commit()?;

    let first = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_phonetic(&["BETA", "ALFA", "ALFA"])
            .limit(10),
    )?;
    let second = captured_retrieval_trace(
        &vault,
        vault.query().search_phonetic(&["ALFA", "BETA"]).limit(10),
    )?;

    assert_eq!(first.fork_hash, second.fork_hash);
    assert_eq!(
        rmp_serde::to_vec_named(&first).expect("trace msgpack encode"),
        rmp_serde::to_vec_named(&second).expect("trace msgpack encode")
    );
    Ok(())
}

#[test]
fn retrieval_trace_fork_hash_uses_effective_trace_candidate_set() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let live = entity_id(0xDB);
    vault
        .batch()
        .put(
            &live,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
                false,
            ),
        )
        .phonetic(&live, &["EFFECTIVE"])
        .commit()?;

    let before = captured_retrieval_trace(
        &vault,
        vault.query().search_phonetic(&["EFFECTIVE"]).limit(10),
    )?;

    let hidden = entity_id(0xDC);
    vault
        .batch()
        .put(
            &hidden,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Retracted,
                false,
            ),
        )
        .phonetic(&hidden, &["EFFECTIVE"])
        .commit()?;

    let after = captured_retrieval_trace(
        &vault,
        vault.query().search_phonetic(&["EFFECTIVE"]).limit(10),
    )?;

    assert_eq!(
        rmp_serde::to_vec_named(&before).expect("trace msgpack encode"),
        rmp_serde::to_vec_named(&after).expect("trace msgpack encode"),
        "a D19-suppressed raw posting must not enter the emitted trace"
    );
    assert_eq!(
        before.fork_hash, after.fork_hash,
        "fork hash must follow the emitted trace candidate set, not raw pre-gate postings"
    );
    Ok(())
}

#[test]
fn retrieval_trace_fork_hash_changes_for_query_config_flags_weights_and_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0xD5);
    let second = entity_id(0xD6);
    put_text_and_vector(&vault, first, "forkhash alpha base", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(
        &vault,
        second,
        "forkhash alpha neighbor",
        [0.8, 0.2, 0.0, 0.0],
    )?;

    let base = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;
    let query_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash base", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;
    let config_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 1)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .limit(1),
    )?;
    let flags_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .boost_salience()
            .limit(10),
    )?;
    let weights_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .rank_profile(
                crate::config::Bm25RankProfile::default()
                    .with_channel_weight(crate::analyzer::AnalyzerChannel::Surface, 0.5),
            )
            .limit(10),
    )?;

    let added_candidate = entity_id(0xD7);
    put_text_and_vector(
        &vault,
        added_candidate,
        "forkhash alpha extra",
        [0.7, 0.3, 0.0, 0.0],
    )?;
    let candidates_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;

    assert_ne!(base.fork_hash, query_changed.fork_hash);
    assert_ne!(base.fork_hash, config_changed.fork_hash);
    assert_ne!(base.fork_hash, flags_changed.fork_hash);
    assert_ne!(base.fork_hash, weights_changed.fork_hash);
    assert_ne!(base.fork_hash, candidates_changed.fork_hash);
    Ok(())
}

#[test]
fn retrieval_trace_filters_d19_suppressed_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let live = entity_id(0xC3);
    let retracted = entity_id(0xC4);
    put_status_claim(
        &vault,
        live,
        "tracegate tracegate",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
        false,
    )?;
    put_status_claim(
        &vault,
        retracted,
        "tracegate tracegate tracegate",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;

    let results = vault
        .query()
        .search_text("tracegate", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert!(results.value.iter().any(|scored| scored.id == live));
    assert!(!results.value.iter().any(|scored| scored.id == retracted));
    let run = vault
        .retrieval_run(results.run_id.expect("trace run id"))?
        .expect("trace run");
    let trace = run.trace.expect("trace captured");

    let text_channel = trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == RetrievalSignal::Text)
        .expect("text trace channel");
    assert!(trace_candidates_contain(&text_channel.candidates, live));
    assert!(!trace_candidates_contain(
        &text_channel.candidates,
        retracted
    ));
    for stage in [
        &trace.fused,
        &trace.blended,
        &trace.reranked,
        &trace.final_stage,
    ] {
        assert!(!trace_candidates_contain(&stage.candidates, retracted));
    }
    Ok(())
}

#[test]
fn retrieval_trace_filters_scoped_vector_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let out_of_scope = entity_id(0xC5);
    let in_scope = entity_id(0xC6);
    let repo_a =
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")?;
    let repo_b =
        RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    put_codebase_vector(
        &vault,
        out_of_scope,
        "project.alpha",
        repo_a,
        [1.0, 0.0, 0.0, 0.0],
    )?;
    put_codebase_vector(
        &vault,
        in_scope,
        "project.beta",
        repo_b,
        [0.0, 1.0, 0.0, 0.0],
    )?;

    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .filter_project_id("project.beta")
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert_eq!(results.value.len(), 1);
    assert_eq!(results.value[0].id, in_scope);
    let run = vault
        .retrieval_run(results.run_id.expect("trace run id"))?
        .expect("trace run");
    let trace = run.trace.expect("trace captured");

    let vector_channel = trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == RetrievalSignal::Vector)
        .expect("vector trace channel");
    assert!(trace_candidates_contain(
        &vector_channel.candidates,
        in_scope
    ));
    assert!(!trace_candidates_contain(
        &vector_channel.candidates,
        out_of_scope
    ));
    for stage in [
        &trace.fused,
        &trace.blended,
        &trace.reranked,
        &trace.final_stage,
    ] {
        assert!(!trace_candidates_contain(&stage.candidates, out_of_scope));
    }
    Ok(())
}

#[test]
fn retrieval_trace_fused_scores_are_bounded_by_trace_limit() {
    let first = entity_id(0xC1);
    let ignored = entity_id(0xC2);

    let fused = retrieval_trace_fused_scores(
        &[vec![
            ScoredEntity {
                id: first,
                score: 1.0,
            },
            ScoredEntity {
                id: ignored,
                score: 0.9,
            },
        ]],
        1,
    );

    assert_eq!(fused.len(), 1);
    assert_eq!(fused[0].id, first);
}

#[test]
fn retrieval_trace_is_decoupled_from_outcome_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let traced_id = entity_id(0xB3);
    let outcome_only_id = entity_id(0xB4);
    put_text(&vault, traced_id, "traceonlyalpha")?;
    put_text(&vault, outcome_only_id, "outcomeonlybeta")?;

    let traced = vault
        .query()
        .search_text("traceonlyalpha", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert_eq!(traced.value.len(), 1);
    let traced_run_id = traced.run_id.expect("traced run id");
    let traced_run = vault
        .retrieval_run(traced_run_id)?
        .expect("traced telemetry row");
    assert!(traced_run.trace.is_some());
    assert!(vault.retrieval_outcomes(traced_run_id)?.is_empty());

    let outcome_only = vault
        .query()
        .search_text("outcomeonlybeta", 10)
        .run_with_telemetry()?;
    assert_eq!(outcome_only.value.len(), 1);
    let outcome_run_id = outcome_only.run_id.expect("outcome-only run id");
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id: outcome_run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;
    let outcome_run = vault
        .retrieval_run(outcome_run_id)?
        .expect("outcome-only telemetry row");
    assert!(outcome_run.trace.is_none());
    assert_eq!(vault.retrieval_outcomes(outcome_run_id)?.len(), 1);
    Ok(())
}

#[test]
fn retrieval_telemetry_zero_limit_pipeline_has_no_empty_reason() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3E);
    put_text_and_vector(
        &vault,
        id,
        "pipeline zero limit telemetry",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    let results = vault
        .query()
        .search_text("pipeline zero limit", 0)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 0)
        .run_with_telemetry()?;
    assert!(results.value.is_empty());
    let run_id = results.run_id.expect("zero-limit telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert!(runs[0].result_ids.is_empty());
    assert_eq!(runs[0].empty_reason, None);
    Ok(())
}

#[test]
fn retrieval_telemetry_omits_noop_ppr_and_phonetic_signals() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let phonetic = vault.query().search_phonetic(&[]).run_with_telemetry()?;
    assert!(phonetic.value.is_empty());
    let phonetic_run_id = phonetic.run_id.expect("phonetic noop telemetry run id");

    let ppr = vault.query().search_ppr(&[], 2).run_with_telemetry()?;
    assert!(ppr.value.is_empty());
    let ppr_run_id = ppr.run_id.expect("ppr noop telemetry run id");

    let combined_ppr = vault
        .query()
        .search_ppr(&[], 2)
        .expand_ppr(&[], 2)
        .run_with_telemetry()?;
    assert!(combined_ppr.value.is_empty());
    let combined_ppr_run_id = combined_ppr
        .run_id
        .expect("combined ppr noop telemetry run id");

    let runs = vault.retrieval_runs(10)?;
    let phonetic_run = runs
        .iter()
        .find(|run| run.run_id == phonetic_run_id)
        .expect("phonetic noop telemetry row");
    let ppr_run = runs
        .iter()
        .find(|run| run.run_id == ppr_run_id)
        .expect("ppr noop telemetry row");
    let combined_ppr_run = runs
        .iter()
        .find(|run| run.run_id == combined_ppr_run_id)
        .expect("combined ppr noop telemetry row");

    assert!(!phonetic_run.signals.contains(&RetrievalSignal::Phonetic));
    assert!(phonetic_run.score_breakdown.is_empty());
    assert!(!ppr_run.signals.contains(&RetrievalSignal::Ppr));
    assert!(ppr_run.score_breakdown.is_empty());
    assert!(!combined_ppr_run.signals.contains(&RetrievalSignal::Ppr));
    assert!(combined_ppr_run.score_breakdown.is_empty());
    Ok(())
}

#[test]
fn retrieval_telemetry_omits_ppr_for_noop_expansion() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead = entity_id(0x3D);
    put_status_claim(
        &vault,
        dead,
        "noop ppr telemetry",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;

    let results = vault
        .query()
        .search_text("noop ppr telemetry", 10)
        .expand_ppr(&[], 2)
        .run_with_telemetry()?;
    assert!(results.value.is_empty());
    let run_id = results.run_id.expect("noop ppr telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].signals, vec![RetrievalSignal::Text]);
    assert!(!runs[0].signals.contains(&RetrievalSignal::Ppr));
    assert_eq!(runs[0].claims_suppressed, 1);
    assert_eq!(runs[0].empty_reason.as_deref(), Some("AllActivated"));
    Ok(())
}

#[test]
fn retrieval_runs_returns_bounded_newest_first() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first_id = entity_id(0x38);
    let second_id = entity_id(0x39);
    let third_id = entity_id(0x3A);

    put_text(&vault, first_id, "alphaone")?;
    assert_eq!(vault.search_text("alphaone", 10)?.len(), 1);
    let first_run = vault.retrieval_runs(1)?[0].run_id;
    std::thread::sleep(std::time::Duration::from_millis(2));

    put_text(&vault, second_id, "betatwo")?;
    assert_eq!(vault.search_text("betatwo", 10)?.len(), 1);
    let second_run = vault.retrieval_runs(1)?[0].run_id;
    std::thread::sleep(std::time::Duration::from_millis(2));

    put_text(&vault, third_id, "gammathree")?;
    assert_eq!(vault.search_text("gammathree", 10)?.len(), 1);
    let third_run = vault.retrieval_runs(1)?[0].run_id;

    let newest_two = vault.retrieval_runs(2)?;
    assert_eq!(newest_two.len(), 2);
    assert_eq!(newest_two[0].run_id, third_run);
    assert_eq!(newest_two[1].run_id, second_run);
    assert!(!newest_two.iter().any(|run| run.run_id == first_run));
    assert!(vault.retrieval_runs(0)?.is_empty());
    Ok(())
}

#[test]
fn telemetry_write_failure_is_best_effort_for_retrieval() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let id = entity_id(0x3A);
    put_text(&vault, id, "best effort telemetry")?;
    let vault_path = dir.path().canonicalize()?;

    crate::store::test_hooks::fail_next_retrieval_run_write_for(vault_path.clone());
    let pipeline = vault.query().search_text("best effort", 10).run()?;
    assert_eq!(pipeline.len(), 1);
    assert!(vault.retrieval_runs(1)?.is_empty());

    crate::store::test_hooks::fail_next_retrieval_run_write_for(vault_path);
    let direct = vault.search_text("best effort", 10)?;
    assert_eq!(direct.len(), 1);
    assert!(vault.retrieval_runs(1)?.is_empty());
    Ok(())
}

#[test]
fn retrieval_telemetry_skips_active_write_transaction() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3B);
    put_text(&vault, id, "active write telemetry")?;

    vault.with_write_txn(|_wtxn| {
        let direct = vault.search_text("active", 10)?;
        assert_eq!(direct.len(), 1);
        let pipeline = vault.query().search_text("active", 10).run()?;
        assert_eq!(pipeline.len(), 1);
        Ok(())
    })?;

    assert!(vault.retrieval_runs(10)?.is_empty());
    Ok(())
}

#[test]
fn retrieval_telemetry_does_not_mutate_short_id_counters() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x35);
    put_text(&vault, id, "counter telemetry")?;

    let counter_key = crate::store::short_id_counter_key(1);
    let before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &counter_key)?
            .map(<[u8]>::to_vec)
    };

    let results = vault.query().search_text("counter", 10).run()?;
    assert!(!results.is_empty());
    assert_eq!(vault.retrieval_runs(1)?.len(), 1);

    let after = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &counter_key)?
            .map(<[u8]>::to_vec)
    };
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn pipeline_search_fails_closed_on_untrusted_text_index() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let a = entity_id(7);

    {
        let vault = Vault::open(temp_dir.path(), test_config())?;
        put_text(&vault, a, "alpha world")?;
    }

    let mut cfg = test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let err = vault
        .query()
        .search_text("alpha", 10)
        .run()
        .expect_err("pipeline text search must refuse untrusted index");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}",
    );
    Ok(())
}

#[test]
fn vector_only_query() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = entity_id(10);
    let b = entity_id(11);

    put_vector(&vault, a, [1.0, 0.0, 0.0, 0.0])?;
    put_vector(&vault, b, [0.0, 1.0, 0.0, 0.0])?;

    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    assert!(!results.is_empty());
    assert_eq!(results[0].id, a);
    Ok(())
}

#[test]
fn expand_ppr_uses_blended_results_as_seeds() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(20);
    let b = entity_id(21);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
        .text(&a, &[("body", "alpha")])
        .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
        .edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
        .commit()?;

    let baseline = vault.query().search_text("alpha", 10).run()?;
    assert!(!baseline.iter().any(|entry| entry.id == b));

    let expanded = vault
        .query()
        .search_text("alpha", 10)
        .expand_ppr(&[], 3)
        .run()?;
    assert!(expanded.iter().any(|entry| entry.id == b));
    Ok(())
}

#[test]
fn expand_ppr_clamps_internal_seed_growth() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for i in 0..=crate::ppr::MAX_PPR_SEEDS {
        let id = EntityId::from_bytes((i as u128 + 1).to_be_bytes())?;
        vault
            .batch()
            .put(
                &id,
                1,
                TimeRange {
                    start: 10 + i as u64,
                    end: 10 + i as u64,
                },
                10,
                b"payload",
            )
            .text(&id, &[("body", "alpha")])
            .commit()?;
    }

    let expanded = vault
        .query()
        .search_text("alpha", crate::ppr::MAX_PPR_SEEDS + 1)
        .expand_ppr(&[], 3)
        .run()?;

    assert!(!expanded.is_empty());
    Ok(())
}

#[test]
fn search_ppr_as_blend_candidate_signal() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(22);
    let b = entity_id(23);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
        .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
        .edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
        .commit()?;

    let results = vault.query().search_ppr(&[a], 3).run()?;
    assert!(results.iter().any(|entry| entry.id == b));
    Ok(())
}

#[test]
fn search_ppr_warms_cache_after_pipeline_snapshot() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(24);
    let b = entity_id(25);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
        .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
        .edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
        .commit()?;

    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);

    let results = vault.query().search_ppr(&[a], 3).run()?;
    assert!(results.iter().any(|entry| entry.id == b));
    assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
    assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 2);
    Ok(())
}

#[test]
fn search_ppr_rejects_excessive_seed_count_and_depth() {
    let (_dir, vault) = open_test_vault();
    let seeds = vec![entity_id(1); crate::ppr::MAX_PPR_SEEDS + 1];

    let too_many_seeds = vault.query().search_ppr(&seeds, 3).run();
    assert_matches!(too_many_seeds, Err(Error::InvalidConfig(_)));

    let too_deep = vault.query().search_ppr(&[entity_id(1)], 11).run();
    assert_matches!(too_deep, Err(Error::InvalidConfig(_)));
}

#[test]
fn recency_boost_orders_text_only_results() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x10);
    let fresh = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_text_at(&vault, old, "recencyneedle", 1)?;
    put_text_at(&vault, fresh, "recencyneedle", now)?;

    let baseline = vault.query().search_text("recencyneedle", 2).run()?;
    assert_eq!(baseline[0].id, old, "baseline tie breaks by entity id");

    let boosted = vault
        .query()
        .search_text("recencyneedle", 2)
        .boost_recency(0.01)
        .run()?;
    assert_eq!(boosted[0].id, fresh);
    Ok(())
}

#[test]
fn recency_boost_orders_text_channel_before_truncation() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x10);
    let fresh = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_text_at(&vault, old, "limitrecencyneedle", 1)?;
    put_text_at(&vault, fresh, "limitrecencyneedle", now)?;

    let baseline = vault
        .query()
        .search_text("limitrecencyneedle", 1)
        .filter_types(&[1])
        .run()?;
    assert_eq!(baseline[0].id, old, "baseline tie breaks by entity id");

    let boosted = vault
        .query()
        .search_text("limitrecencyneedle", 1)
        .filter_types(&[1])
        .boost_recency(0.01)
        .run()?;
    assert_eq!(
        boosted[0].id, fresh,
        "fresh text hit must win before the BM25 channel is truncated"
    );
    Ok(())
}

#[test]
fn scoped_recency_text_overfetch_is_bounded_after_filtering() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let now = crate::unix_seconds_now();
    let old = [
        entity_id(0x10),
        entity_id(0x20),
        entity_id(0x30),
        entity_id(0x40),
    ];
    let fresh_beyond_overfetch = entity_id(0x50);

    for id in old {
        put_text_at(&vault, id, "scopedrecencycap", 1)?;
    }
    put_text_at(&vault, fresh_beyond_overfetch, "scopedrecencycap", now)?;

    let results = vault
        .query()
        .search_text("scopedrecencycap", 1)
        .filter_types(&[1])
        .boost_recency(0.01)
        .limit(1)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, old[0]);
    assert_ne!(results[0].id, fresh_beyond_overfetch);
    Ok(())
}

#[test]
fn recency_signal_applies_once_to_blended_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old_text = entity_id(0x10);
    let fresh_text = entity_id(0x20);
    let fresh_vector = entity_id(0x30);
    let future = crate::unix_seconds_now() + 3_600;

    put_text_at(&vault, old_text, "fairrecencyneedle stableanchor", 1)?;
    put_text_at(&vault, fresh_text, "fairrecencyneedle", future)?;
    put_vector_at(&vault, fresh_vector, [1.0, 0.0, 0.0, 0.0], future)?;

    let baseline = vault
        .query()
        .search_text("fairrecencyneedle stableanchor", 2)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .run()?;
    assert_eq!(baseline[0].id, old_text, "baseline text rank");

    let boosted = vault
        .query()
        .search_text("fairrecencyneedle stableanchor", 2)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .boost_recency(0.01)
        .run()?;

    assert!(boosted.iter().any(|scored| scored.id == fresh_text));
    assert!(boosted.iter().any(|scored| scored.id == fresh_vector));
    assert_ne!(baseline, boosted);
    Ok(())
}

#[test]
fn recency_signal_applies_to_ppr_expansion_results() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let seed = entity_id(0x13);
    let expanded = entity_id(0x23);
    let future = crate::unix_seconds_now() + 3_600;

    vault
        .batch()
        .put(&seed, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&seed, &[("body", "pprrecencyneedle")])
        .put(
            &expanded,
            1,
            TimeRange {
                start: future,
                end: future,
            },
            future,
            b"payload",
        )
        .edge(&seed, EdgeKind::Supports, &expanded, 1.0)
        .commit()?;

    let baseline = vault
        .query()
        .search_text("pprrecencyneedle", 10)
        .expand_ppr(&[], 2)
        .run()?;
    let boosted = vault
        .query()
        .search_text("pprrecencyneedle", 10)
        .expand_ppr(&[], 2)
        .boost_recency(0.01)
        .run()?;

    let boosted_scores = to_score_map(&boosted);

    assert!(to_score_map(&baseline).contains_key(&expanded));
    assert!(boosted_scores[&expanded] > 0.0);
    assert_ne!(baseline, boosted);
    Ok(())
}

#[test]
fn prefix_probe_claim_gate_does_not_export_pack_stats() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let probe_only_dead_claim = entity_id(0x10);
    let live_result = entity_id(0x20);

    put_status_claim(
        &vault,
        probe_only_dead_claim,
        "probeonlydead",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_text(&vault, live_result, "probeonlylive")?;

    let output = vault.query().search_text("probeonly", 10).run_for_pack()?;

    assert_eq!(output.scores.len(), 1);
    assert_eq!(output.scores[0].id, live_result);
    assert_eq!(output.claims_suppressed, 0);
    assert!(output.claim_bodies.is_empty());
    Ok(())
}

#[test]
fn dead_exact_claim_does_not_truncate_live_prefix_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead_exact = entity_id(0x12);
    let live_prefix = entity_id(0x22);

    put_status_claim(
        &vault,
        dead_exact,
        "claimgateprefix",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_claim_text(&vault, live_prefix, "claimgateprefixalpha", None)?;

    let results = vault.query().search_text("claimgateprefix", 1).run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live_prefix);
    Ok(())
}

#[test]
fn dead_prefix_expanded_claim_does_not_truncate_live_prefix_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead_prefix = entity_id(0x12);
    let live_prefix = entity_id(0x22);

    put_status_claim(
        &vault,
        dead_prefix,
        "prefixgateexpanded prefixgateexpanded prefixgateexpanded",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_claim_text(&vault, live_prefix, "prefixgateexpanded", None)?;

    let results = vault.query().search_text("prefixgate", 1).run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live_prefix);
    Ok(())
}

#[test]
fn live_exact_claim_preserves_search_text_limit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let live_exact = entity_id(0x12);
    let lower_ranked_exact_doc = entity_id(0x22);
    let live_prefix = entity_id(0x32);

    put_claim_text(&vault, live_exact, "livegateprefix", None)?;
    put_text(&vault, lower_ranked_exact_doc, "livegateprefix")?;
    put_claim_text(&vault, live_prefix, "livegateprefixalpha", None)?;

    let results = vault.query().search_text("livegateprefix", 1).run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live_exact);
    Ok(())
}

#[test]
fn fenced_text_rows_do_not_consume_channel_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fenced_a = entity_id(0x01);
    let fenced_b = entity_id(0x02);
    let live_a = entity_id(0x10);
    let live_b = entity_id(0x11);

    put_text(&vault, fenced_a, "fencechannel fencechannel fencechannel")?;
    put_text(&vault, fenced_b, "fencechannel fencechannel")?;
    put_text(&vault, live_a, "fencechannel")?;
    put_text(&vault, live_b, "fencechannel")?;

    let fence_free_results = vault
        .query()
        .search_text("fencechannel", 2)
        .limit(2)
        .run()?;
    assert_eq!(
        fence_free_results
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        vec![fenced_a, fenced_b]
    );

    vault.enter_off_record_session(
        "text-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("text-fence", &fenced_a)?;
    vault.tag_turn_off_record("text-fence", &fenced_b)?;

    let results = vault
        .query()
        .search_text("fencechannel", 2)
        .limit(2)
        .run()?;

    assert_eq!(
        results.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![live_a, live_b]
    );
    Ok(())
}

#[test]
fn fenced_recency_text_rows_do_not_exhaust_overfetch_window() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fenced = [
        entity_id(0x01),
        entity_id(0x02),
        entity_id(0x03),
        entity_id(0x04),
    ];
    let live = [
        entity_id(0x10),
        entity_id(0x11),
        entity_id(0x12),
        entity_id(0x13),
        entity_id(0x14),
    ];
    let now = crate::unix_seconds_now();

    for id in fenced {
        put_text_at(&vault, id, "fencedrecencywindow", now)?;
    }
    for id in live {
        put_text_at(&vault, id, "fencedrecencywindow", now)?;
    }

    vault.enter_off_record_session(
        "text-recency-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    for id in fenced {
        vault.tag_turn_off_record("text-recency-fence", &id)?;
    }

    let results = vault
        .query()
        .search_text("fencedrecencywindow", 1)
        .boost_recency(0.01)
        .limit(1)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live[0]);

    let rtxn = vault.store.env.read_txn()?;
    let mut widened = std::iter::once(fenced[0])
        .chain(live)
        .map(|id| ScoredEntity { id, score: 1.0 })
        .collect();
    apply_off_record_fence_with_cap(&mut widened, &vault.store, &rtxn, 4)?;
    assert_eq!(
        widened.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        live[..4]
    );
    Ok(())
}

#[test]
fn fenced_vector_rows_do_not_consume_channel_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fenced_a = entity_id(0x01);
    let fenced_b = entity_id(0x02);
    let live_a = entity_id(0x10);
    let live_b = entity_id(0x11);

    put_vector(&vault, fenced_a, [1.0, 0.0, 0.0, 0.0])?;
    put_vector(&vault, fenced_b, [0.99, 0.01, 0.0, 0.0])?;
    put_vector(&vault, live_a, [0.0, 1.0, 0.0, 0.0])?;
    put_vector(&vault, live_b, [0.0, 0.0, 1.0, 0.0])?;

    let fence_free_results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .limit(2)
        .run()?;
    assert_eq!(
        fence_free_results
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        vec![fenced_a, fenced_b]
    );

    vault.enter_off_record_session(
        "vector-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("vector-fence", &fenced_a)?;
    vault.tag_turn_off_record("vector-fence", &fenced_b)?;

    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .limit(2)
        .run()?;

    assert_eq!(
        results.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![live_a, live_b]
    );
    Ok(())
}

#[test]
fn unrelated_vector_fence_preserves_scoped_overfetch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fenced = entity_id(0x01);
    let in_scope_a = entity_id(0x10);
    let in_scope_b = entity_id(0x11);
    let repo_a =
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")?;
    let repo_b =
        RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;

    put_codebase_vector(
        &vault,
        fenced,
        "project.alpha",
        repo_a,
        [1.0, 0.0, 0.0, 0.0],
    )?;
    put_codebase_vector(
        &vault,
        in_scope_a,
        "project.beta",
        repo_b.clone(),
        [0.9, 0.1, 0.0, 0.0],
    )?;
    put_codebase_vector(
        &vault,
        in_scope_b,
        "project.beta",
        repo_b,
        [0.8, 0.2, 0.0, 0.0],
    )?;

    vault.enter_off_record_session(
        "unrelated-vector-scope-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("unrelated-vector-scope-fence", &fenced)?;

    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .filter_project_id("project.beta")
        .limit(2)
        .run()?;

    assert_eq!(
        results.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![in_scope_a, in_scope_b]
    );
    Ok(())
}

#[test]
fn vector_fence_replacement_does_not_apply_post_fusion_type_filter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fenced = entity_id(0x01);
    let wrong_type = entity_id(0x10);
    let deeper_match = entity_id(0x20);

    put_vector(&vault, fenced, [1.0, 0.0, 0.0, 0.0])?;
    vault
        .batch()
        .put(
            &wrong_type,
            2,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .vector(&wrong_type, &[0.99, 0.01, 0.0, 0.0])
        .commit()?;
    put_vector(&vault, deeper_match, [0.98, 0.02, 0.0, 0.0])?;

    vault.enter_off_record_session(
        "vector-post-filter-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("vector-post-filter-fence", &fenced)?;

    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .filter_types(&[1])
        .limit(1)
        .run()?;

    assert!(results.is_empty());
    Ok(())
}

#[test]
fn vector_fence_widening_grows_in_bounded_batches() {
    assert_eq!(next_vector_fence_search_limit(10, 9, 10, 10_000), 20);
    assert_eq!(next_vector_fence_search_limit(10, 0, 10, 10_000), 20);
    assert_eq!(next_vector_fence_search_limit(10, 9, 10, 10), 10);
}

#[test]
fn temporal_fence_replacement_scan_budget_is_bounded() {
    assert_eq!(temporal_fence_scan_budget(4, false), 4);
    assert_eq!(temporal_fence_scan_budget(4, true), 16);
    assert_eq!(
        temporal_fence_scan_budget(MAX_TEMPORAL_SEEK_BUFFER, true),
        MAX_TEMPORAL_SEEK_BUFFER
    );
}

#[test]
fn vector_widening_probe_does_not_export_discarded_claim_gate_decisions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fenced = entity_id(0x01);
    let retracted_claim = entity_id(0x10);
    let live_result = entity_id(0x20);

    put_vector(&vault, fenced, [1.0, 0.0, 0.0, 0.0])?;
    vault
        .batch()
        .put(
            &retracted_claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Retracted,
                false,
            ),
        )
        .vector(&retracted_claim, &[0.99, 0.01, 0.0, 0.0])
        .commit()?;
    put_vector(&vault, live_result, [0.98, 0.02, 0.0, 0.0])?;

    vault.enter_off_record_session(
        "vector-claim-gate-probe",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("vector-claim-gate-probe", &fenced)?;

    let output = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .limit(1)
        .run_for_pack()?;

    assert_eq!(output.scores.len(), 1);
    assert_eq!(output.scores[0].id, live_result);
    assert_eq!(output.claims_suppressed, 0);
    assert!(output.claim_bodies.is_empty());
    Ok(())
}

#[test]
fn exact_out_of_scope_text_hit_does_not_suppress_in_scope_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let out_of_scope_exact = entity_id(0x10);
    let in_scope_prefix = entity_id(0x20);

    vault
        .batch()
        .put(
            &out_of_scope_exact,
            2,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&out_of_scope_exact, &[("body", "scopedprefix")])
        .put(
            &in_scope_prefix,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&in_scope_prefix, &[("body", "scopedprefixalpha")])
        .commit()?;

    let results = vault
        .query()
        .search_text("scopedprefix", 1)
        .filter_types(&[1])
        .run()?;

    assert!(results.iter().any(|entry| entry.id == in_scope_prefix));
    assert!(!results.iter().any(|entry| entry.id == out_of_scope_exact));
    Ok(())
}

#[test]
fn prefix_scope_widening_preserves_exact_text_limit_after_type_filter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let out_of_scope_exact = entity_id(0x10);
    let in_scope_preferred = entity_id(0x20);
    let in_scope_extra = entity_id(0x30);

    vault
        .batch()
        .put(
            &out_of_scope_exact,
            2,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(
            &out_of_scope_exact,
            &[(
                "body",
                "limitfilterneedle limitfilterneedle limitfilterneedle",
            )],
        )
        .put(
            &in_scope_preferred,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(
            &in_scope_preferred,
            &[("body", "limitfilterneedle limitfilterneedle")],
        )
        .put(
            &in_scope_extra,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&in_scope_extra, &[("body", "limitfilterneedle")])
        .commit()?;

    let results = vault
        .query()
        .search_text("limitfilterneedle", 1)
        .filter_types(&[1])
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, in_scope_preferred);
    assert!(!results.iter().any(|entry| entry.id == out_of_scope_exact));
    Ok(())
}

#[test]
fn exact_old_text_hit_does_not_suppress_since_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old_exact = entity_id(0x12);
    let recent_prefix = entity_id(0x22);

    vault
        .batch()
        .put(
            &old_exact,
            1,
            TimeRange { start: 1, end: 1 },
            100,
            b"payload",
        )
        .text(&old_exact, &[("body", "sinceprefix")])
        .put(
            &recent_prefix,
            1,
            TimeRange { start: 1, end: 1 },
            200,
            b"payload",
        )
        .text(&recent_prefix, &[("body", "sinceprefixalpha")])
        .commit()?;

    let results = vault
        .query()
        .search_text("sinceprefix", 1)
        .filter_since(200)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == recent_prefix));
    assert!(!results.iter().any(|entry| entry.id == old_exact));
    Ok(())
}

#[test]
fn parsed_recent_query_bounds_text_retrieval() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x13);
    let recent = entity_id(0x23);

    put_text_with_time(
        &vault,
        old,
        "recent parsedbounds",
        TimeRange {
            start: NOW - 7 * 86_400 - 1,
            end: NOW - 7 * 86_400 - 1,
        },
        NOW - 7 * 86_400 - 1,
    )?;
    put_text_with_time(
        &vault,
        recent,
        "recent parsedbounds",
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        NOW - 60,
    )?;

    let results = vault
        .query()
        .search_text("recent parsedbounds", 10)
        .with_temporal_now(NOW)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, recent);
    Ok(())
}

#[test]
fn learned_range_does_not_override_parsed_recent_hint() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x63);
    let recent = entity_id(0x64);

    put_text_with_time(
        &vault,
        old,
        "recent learnedbounds",
        TimeRange {
            start: NOW - 7 * 86_400 - 1,
            end: NOW - 7 * 86_400 - 1,
        },
        200,
    )?;
    put_text_with_time(
        &vault,
        recent,
        "recent learnedbounds",
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        200,
    )?;

    let results = vault
        .query()
        .search_text("recent learnedbounds", 10)
        .filter_learned_range(190, 210)
        .with_temporal_now(NOW)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, recent);
    Ok(())
}

#[test]
fn explicit_time_range_overrides_parsed_recent_hint() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let explicit_keep = entity_id(0x14);
    let parsed_recent_drop = entity_id(0x24);
    let vector = [1.0, 0.0, 0.0, 0.0];

    put_text_and_vector_with_time(
        &vault,
        explicit_keep,
        "recent overridebounds",
        vector,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    put_text_and_vector_with_time(
        &vault,
        parsed_recent_drop,
        "recent overridebounds",
        vector,
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        NOW - 60,
    )?;

    let results = vault
        .query()
        .search(
            "recent overridebounds",
            &vector,
            Some(TimeRange {
                start: 90,
                end: 110,
            }),
            10,
        )
        .with_temporal_now(NOW)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, explicit_keep);
    Ok(())
}

#[test]
fn explicit_time_range_overrides_unsupported_last_phrase() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let explicit_keep = entity_id(0x34);
    let vector = [1.0, 0.0, 0.0, 0.0];

    put_text_and_vector_with_time(
        &vault,
        explicit_keep,
        "last friday overridebounds",
        vector,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;

    let results = vault
        .query()
        .search(
            "last friday overridebounds",
            &vector,
            Some(TimeRange {
                start: 90,
                end: 110,
            }),
            10,
        )
        .with_temporal_now(1_710_504_000)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, explicit_keep);
    Ok(())
}

#[test]
fn unsupported_last_friday_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x15);
    put_text(&vault, id, "last friday failclosed")?;

    let err = vault
        .query()
        .search_text("last friday failclosed", 10)
        .with_temporal_now(1_710_504_000)
        .run()
        .expect_err("unsupported temporal expression must fail closed");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidTemporalExpression
    );
    assert_matches!(
        err,
        Error::InvalidTemporalExpression(
            TemporalExpressionParseError::Unsupported { expression }
        ) if expression == "last friday"
    );
    Ok(())
}

#[test]
fn unsupported_last_two_weeks_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x16);
    put_text(&vault, id, "last 2 weeks failclosed")?;

    let err = vault
        .query()
        .search_text("last 2 weeks failclosed", 10)
        .with_temporal_now(1_710_504_000)
        .run()
        .expect_err("unsupported temporal expression must fail closed");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidTemporalExpression
    );
    assert_matches!(
        err,
        Error::InvalidTemporalExpression(
            TemporalExpressionParseError::Unsupported { expression }
        ) if expression == "last 2 weeks"
    );
    Ok(())
}

#[test]
fn unsupported_last_spelled_quantity_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x17);
    put_text(&vault, id, "last two weeks failclosed")?;

    let err = vault
        .query()
        .search_text("last two weeks failclosed", 10)
        .with_temporal_now(1_710_504_000)
        .run()
        .expect_err("unsupported temporal expression must fail closed");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidTemporalExpression
    );
    assert_matches!(
        err,
        Error::InvalidTemporalExpression(
            TemporalExpressionParseError::Unsupported { expression }
        ) if expression == "last two weeks"
    );
    Ok(())
}

#[test]
fn unsupported_last_subday_quantity_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for (offset, query, expected) in [
        (0, "last 24 hours failclosed", "last 24 hours"),
        (
            1,
            "last twenty four hours failclosed",
            "last twenty four hours",
        ),
    ] {
        put_text(&vault, entity_id(0x18 + offset), query)?;

        let err = vault
            .query()
            .search_text(query, 10)
            .with_temporal_now(1_710_504_000)
            .run()
            .expect_err("unsupported temporal expression must fail closed");

        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::InvalidTemporalExpression
        );
        assert_matches!(
            err,
            Error::InvalidTemporalExpression(
                TemporalExpressionParseError::Unsupported { expression }
            ) if expression == expected
        );
    }
    Ok(())
}

#[test]
fn exact_other_facet_text_hit_does_not_suppress_strict_facet_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_active = entity_id(0x91);
    let facet_other = entity_id(0xB1);
    let other_facet_exact = entity_id(0x10);
    let active_facet_prefix = entity_id(0x20);

    vault
        .batch()
        .put(
            &facet_active,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .put(
            &facet_other,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .commit()?;
    put_claim_text(&vault, other_facet_exact, "facetprefix", None)?;
    put_claim_text(&vault, active_facet_prefix, "facetprefixalpha", None)?;
    vault
        .batch()
        .edge(&other_facet_exact, EdgeKind::FacetOf, &facet_other, 0.7)
        .edge(&active_facet_prefix, EdgeKind::FacetOf, &facet_active, 0.7)
        .commit()?;

    let results = vault
        .query()
        .search_text("facetprefix", 1)
        .facet(&facet_active, FacetMode::Strict)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == active_facet_prefix));
    assert!(!results.iter().any(|entry| entry.id == other_facet_exact));
    Ok(())
}

#[test]
fn exact_other_world_text_hit_does_not_suppress_world_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_active = entity_id(0x92);
    let world_other = entity_id(0xB2);
    let other_world_exact = entity_id(0x11);
    let active_world_prefix = entity_id(0x21);

    put_claim_text(&vault, other_world_exact, "worldprefix", Some(world_other))?;
    put_claim_text(
        &vault,
        active_world_prefix,
        "worldprefixalpha",
        Some(world_active),
    )?;

    let results = vault
        .query()
        .search_text("worldprefix", 1)
        .world(WorldScope::World(world_active))
        .run()?;

    assert!(results.iter().any(|entry| entry.id == active_world_prefix));
    assert!(!results.iter().any(|entry| entry.id == other_world_exact));
    Ok(())
}

#[test]
fn prefix_probe_claim_gate_runs_before_world_scope_decode() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_active = entity_id(0x93);
    let malformed_probe_only = entity_id(0x13);
    let active_world_prefix = entity_id(0x23);

    put_status_claim(
        &vault,
        malformed_probe_only,
        "worldgateprefixdead",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
        false,
    )?;
    let mut junk = Vec::new();
    rmpv::encode::write_value(&mut junk, &rmpv::Value::from("junk")).expect("msgpack encode");
    overwrite_entity_record(&vault, &malformed_probe_only, ENTITY_TYPE_CLAIM, &junk)?;
    put_claim_text(
        &vault,
        active_world_prefix,
        "worldgateprefixlive",
        Some(world_active),
    )?;

    let output = vault
        .query()
        .search_text("worldgateprefix", 10)
        .world(WorldScope::World(world_active))
        .run_for_pack()?;

    assert_eq!(output.scores.len(), 1);
    assert_eq!(output.scores[0].id, active_world_prefix);
    assert_eq!(output.claims_suppressed, 0);
    assert!(output.claim_bodies.contains_key(&active_world_prefix));
    Ok(())
}

#[test]
fn recency_boost_applies_to_vector_only_pipeline() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x10);
    let fresh = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_vector_at(&vault, old, [1.0, 0.0, 0.0, 0.0], 1)?;
    put_vector_at(&vault, fresh, [0.99, 0.01, 0.0, 0.0], now)?;

    let baseline = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .run()?;
    assert_eq!(baseline[0].id, old);

    let boosted = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .boost_recency(0.01)
        .run()?;
    assert_eq!(boosted[0].id, fresh);
    Ok(())
}

#[test]
fn recency_boost_applies_to_mixed_text_and_vector_pipeline() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old_text_only = entity_id(0x10);
    let fresh_vector_only = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_text_at(&vault, old_text_only, "mixedrecencyneedle", 1)?;
    put_vector_at(&vault, fresh_vector_only, [1.0, 0.0, 0.0, 0.0], now)?;

    let baseline = vault
        .query()
        .search_text("mixedrecencyneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    assert_eq!(baseline[0].id, old_text_only);

    let boosted = vault
        .query()
        .search_text("mixedrecencyneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_recency(0.01)
        .run()?;
    assert_eq!(boosted[0].id, fresh_vector_only);
    Ok(())
}

#[test]
fn recency_boost_orders_non_text_scores_before_ppr_expansion_fusion() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x12);
    let fresh = entity_id(0x22);
    let now = crate::unix_seconds_now();

    put_vector_at(&vault, old, [1.0, 0.0, 0.0, 0.0], 1)?;
    put_vector_at(&vault, fresh, [0.99, 0.01, 0.0, 0.0], now)?;

    let boosted = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .boost_recency(0.01)
        .expand_ppr(&[], 2)
        .limit(1)
        .run()?;

    assert_eq!(boosted[0].id, fresh);
    Ok(())
}

#[test]
fn recency_boost_auto_skips_when_temporal_search_present() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    let a = entity_id(30);
    let b = entity_id(31);

    put_entity(&vault, a, 1, anchor, anchor, anchor)?;
    put_entity(&vault, b, 1, anchor + 3_600, anchor + 3_600, anchor + 3_600)?;

    let without_boost = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Auto, 10)
        .run()?;
    let with_boost = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Auto, 10)
        .boost_recency(7.0)
        .run()?;

    assert_eq!(without_boost.len(), with_boost.len());
    for (left, right) in without_boost.iter().zip(with_boost.iter()) {
        assert_eq!(left.id, right.id);
        assert!(approx_eq(left.score, right.score, 1e-6));
    }

    Ok(())
}

#[test]
fn fenced_temporal_rows_do_not_consume_channel_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let anchor = 2_000_000;
    let fenced_a = entity_id(0x01);
    let fenced_b = entity_id(0x02);
    let live_a = entity_id(0x10);
    let live_b = entity_id(0x11);

    for id in [fenced_a, fenced_b, live_a, live_b] {
        put_entity(&vault, id, 1, anchor, anchor, anchor)?;
    }

    let fence_free_results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 2)
        .limit(2)
        .run()?;
    assert_eq!(
        fence_free_results
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        vec![fenced_a, fenced_b]
    );

    vault.enter_off_record_session(
        "temporal-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("temporal-fence", &fenced_a)?;
    vault.tag_turn_off_record("temporal-fence", &fenced_b)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 2)
        .limit(2)
        .run()?;

    assert_eq!(
        results.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![live_a, live_b]
    );
    Ok(())
}

#[test]
fn fenced_temporal_candidates_do_not_stop_adaptive_widening() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let anchor = 2_000_000;
    let fenced = [
        entity_id(0x01),
        entity_id(0x02),
        entity_id(0x03),
        entity_id(0x04),
    ];
    let live = entity_id(0x10);

    for id in fenced {
        put_entity(&vault, id, 1, anchor, anchor, anchor)?;
    }
    put_entity(
        &vault,
        live,
        1,
        anchor + 8 * 86_400,
        anchor + 8 * 86_400,
        anchor,
    )?;

    vault.enter_off_record_session(
        "temporal-adaptive-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    for id in fenced {
        vault.tag_turn_off_record("temporal-adaptive-fence", &id)?;
    }

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .with_temporal_now(anchor)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live);
    Ok(())
}

#[test]
fn unrelated_temporal_fence_does_not_expand_candidate_window() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let anchor = 2_000_000;
    let old_learned_at = 1;
    let close = [
        entity_id(0x01),
        entity_id(0x02),
        entity_id(0x03),
        entity_id(0x04),
    ];
    let outside_cap = entity_id(0x10);
    let unrelated = entity_id(0x20);

    for id in close {
        put_entity(&vault, id, 1, anchor, anchor, old_learned_at)?;
    }
    put_entity(
        &vault,
        outside_cap,
        1,
        anchor + 86_400,
        anchor + 86_400,
        anchor,
    )?;
    put_entity(
        &vault,
        unrelated,
        1,
        anchor + 30 * 86_400,
        anchor + 30 * 86_400,
        anchor,
    )?;

    let before = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .with_temporal_now(anchor)
        .run()?;

    vault.enter_off_record_session(
        "unrelated-temporal-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    vault.tag_turn_off_record("unrelated-temporal-fence", &unrelated)?;

    let after = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .with_temporal_now(anchor)
        .run()?;

    assert_eq!(before, after);
    assert_eq!(after.len(), 1);
    assert_ne!(after[0].id, outside_cap);
    Ok(())
}

#[test]
fn three_index_scan_discovers_end_only_candidate() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    let candidate = entity_id(40);

    put_entity(&vault, candidate, 1, 1_000_000, 1_500_000, 10_000_000)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == candidate));
    Ok(())
}

#[test]
fn long_interval_spanner_is_discovered_via_range_query() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000_u64;
    let candidate = entity_id(41);
    let span = 30_u64 * 86_400;

    put_entity(
        &vault,
        candidate,
        1,
        anchor.saturating_sub(span),
        anchor.saturating_add(span),
        anchor,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == candidate));
    Ok(())
}

#[test]
fn long_interval_scan_counts_only_spanners_toward_cap() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000_u64;
    let window = 86_400_u64;
    let long_span = LONG_INTERVAL_THRESHOLD_SECS + window;

    for i in 0..PER_SCAN_CAP_FACTOR {
        let id = entity_id(120 + i as u8);
        put_entity(
            &vault,
            id,
            1,
            anchor + i as u64,
            anchor + long_span + i as u64,
            anchor,
        )?;
    }

    let spanner = entity_id(140);
    put_entity(
        &vault,
        spanner,
        1,
        anchor.saturating_sub(long_span),
        anchor + long_span + PER_SCAN_CAP_FACTOR as u64,
        anchor,
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let config = TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: window,
        anchor_mode: TemporalAnchorMode::Occurred,
        adaptive: true,
        limit: 1,
    };
    let mut metadata_cache = EntityMetadataCache::default();
    let scoring = TemporalScoringContext {
        sigma: window,
        now: crate::unix_seconds_now(),
        anchor_mid: anchor,
        learned_anchor: (anchor, anchor),
        learned_anchor_mid: anchor,
    };
    let mut candidates = HashSet::new();
    collect_temporal_candidates(
        &vault.store,
        &rtxn,
        &config,
        TemporalCandidateCollectionContext {
            radius: window,
            per_scan_cap: PER_SCAN_CAP_FACTOR,
            off_record_fences_present: false,
        },
        &mut metadata_cache,
        &scoring,
        &mut candidates,
    )?;

    assert!(candidates.contains(&spanner));
    Ok(())
}

#[test]
fn long_interval_scan_keeps_best_spanners_beyond_end_order_cap() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = crate::unix_seconds_now();
    let span = LONG_INTERVAL_THRESHOLD_SECS + 86_400;
    let best = entity_id(214);

    for i in 0..5_u8 {
        let id = entity_id(210 + i);
        let learned_at = if id == best {
            anchor
        } else {
            anchor.saturating_sub((30 + u64::from(i)) * 86_400)
        };
        put_entity(
            &vault,
            id,
            1,
            anchor.saturating_sub(span + 10),
            anchor.saturating_add(span + u64::from(i)),
            learned_at,
        )?;
    }

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .run()?;

    assert_eq!(results[0].id, best);
    Ok(())
}

#[test]
fn long_interval_scan_does_not_spend_cap_on_preexisting_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = crate::unix_seconds_now();
    let span = LONG_INTERVAL_THRESHOLD_SECS + 86_400;
    let best = entity_id(224);
    let mut preexisting = HashSet::new();

    for i in 0..5_u8 {
        let id = entity_id(220 + i);
        let learned_at = if id == best {
            anchor
        } else {
            anchor.saturating_sub((30 + u64::from(i)) * 86_400)
        };
        put_entity(
            &vault,
            id,
            1,
            anchor.saturating_sub(span + 10),
            anchor.saturating_add(span + u64::from(i)),
            learned_at,
        )?;
        if id != best {
            preexisting.insert(id);
        }
    }

    let rtxn = vault.store.env.read_txn()?;
    let config = TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400,
        anchor_mode: TemporalAnchorMode::Occurred,
        adaptive: false,
        limit: 1,
    };
    let scoring = TemporalScoringContext {
        sigma: 86_400,
        now: anchor,
        anchor_mid: anchor,
        learned_anchor: (anchor, anchor),
        learned_anchor_mid: anchor,
    };
    let mut metadata_cache = EntityMetadataCache::default();

    collect_temporal_candidates(
        &vault.store,
        &rtxn,
        &config,
        TemporalCandidateCollectionContext {
            radius: 86_400,
            per_scan_cap: PER_SCAN_CAP_FACTOR,
            off_record_fences_present: false,
        },
        &mut metadata_cache,
        &scoring,
        &mut preexisting,
    )?;

    assert!(preexisting.contains(&best));
    Ok(())
}

#[test]
fn backward_seek_preserves_lowest_ids_with_same_timestamp() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let timestamp = 99;

    for byte in [40_u8, 41, 42, 43, 44] {
        let id = entity_id(byte);
        put_entity(&vault, id, 1, timestamp, timestamp, timestamp)?;
    }

    let rtxn = vault.store.env.read_txn()?;
    let mut out = HashSet::new();
    collect_index_candidates(
        &vault.store.temporal_occurred_start,
        &vault.store,
        &rtxn,
        TemporalIndexCollectionContext {
            window_start: 0,
            window_end: timestamp,
            anchor_mid: 100,
            cap: 4,
            off_record_fences_present: false,
        },
        &mut out,
    )?;

    assert!(out.contains(&entity_id(40)));
    assert!(out.contains(&entity_id(41)));
    assert!(out.contains(&entity_id(42)));
    assert!(out.contains(&entity_id(43)));
    assert!(!out.contains(&entity_id(44)));
    Ok(())
}

#[test]
fn backward_boundary_replay_keeps_live_row_behind_fences() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let timestamp = 99;
    let fenced = [
        entity_id(0x01),
        entity_id(0x02),
        entity_id(0x03),
        entity_id(0x04),
    ];
    let live = entity_id(0x10);

    for id in fenced.into_iter().chain(std::iter::once(live)) {
        put_entity(&vault, id, 1, timestamp, timestamp, timestamp)?;
    }
    vault.enter_off_record_session(
        "backward-boundary-fence",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    for id in fenced {
        vault.tag_turn_off_record("backward-boundary-fence", &id)?;
    }

    let rtxn = vault.store.env.read_txn()?;
    let mut out = HashSet::new();
    collect_index_candidates(
        &vault.store.temporal_occurred_start,
        &vault.store,
        &rtxn,
        TemporalIndexCollectionContext {
            window_start: 0,
            window_end: timestamp,
            anchor_mid: 100,
            cap: 1,
            off_record_fences_present: true,
        },
        &mut out,
    )?;

    assert_eq!(out, HashSet::from([live]));
    Ok(())
}

#[test]
fn future_events_are_scored() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let now = crate::unix_seconds_now();
    let start = now + 7 * 86_400;
    let end = now + 8 * 86_400;
    let id = entity_id(50);

    put_entity(&vault, id, 1, start + 3_600, start + 3_600, now)?;

    let config = TemporalSearchConfig {
        anchor_start: start,
        anchor_end: end,
        learned_start: None,
        learned_end: None,
        sigma_secs: TemporalGranularity::Week.sigma_secs(),
        anchor_mode: TemporalAnchorMode::Auto,
        adaptive: true,
        limit: 10,
    };
    let rtxn = vault.store.env.read_txn()?;
    let mut metadata_cache = EntityMetadataCache::default();
    let results = execute_temporal(
        &vault.store,
        &rtxn,
        &config,
        false,
        now,
        &mut metadata_cache,
    )?;

    let scored = results
        .iter()
        .find(|entry| entry.id == id)
        .expect("missing future entity");
    assert!(scored.score > 0.5_f32);
    Ok(())
}

#[test]
fn temporal_tier_equivalence() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(60);
    let b = entity_id(61);
    let start = 1_000_000;
    let end = 1_200_000;
    let sigma = end - start;

    put_entity(&vault, a, 1, start + 10_000, start + 10_000, start + 10_000)?;
    put_entity(&vault, b, 1, end + 500_000, end + 500_000, end + 500_000)?;

    let tier1 = vault.query().search_temporal(start, end, 10).run()?;
    let tier2 = vault
        .query()
        .search_temporal_with_sigma(start, end, sigma.max(86_400), TemporalAnchorMode::Auto, 10)
        .run()?;

    assert_eq!(tier1.len(), tier2.len());
    for (left, right) in tier1.iter().zip(tier2.iter()) {
        assert_eq!(left.id, right.id);
        assert!(approx_eq(left.score, right.score, 1e-6));
    }

    Ok(())
}

#[test]
fn per_scan_cap_isolation_keeps_learned_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    for i in 0..40_u8 {
        let id = entity_id(80 + i);
        put_entity(
            &vault,
            id,
            1,
            anchor + u64::from(i),
            anchor + u64::from(i),
            9_000_000,
        )?;
    }

    let learned_only = entity_id(70);
    put_entity(
        &vault,
        learned_only,
        1,
        anchor + 10_000_000,
        anchor + 10_000_000,
        anchor,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 3_600, TemporalAnchorMode::Auto, 5)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == learned_only));
    Ok(())
}

#[test]
fn granularity_sigma_ordering() -> Result<()> {
    // For a fixed entity-to-anchor distance, increasing sigma should
    // monotonically increase the temporal-similarity score (wider Gaussian =
    // higher density at the same offset). The two original tests both
    // assert this monotonicity; we collapse them into a single ordering
    // table that walks adjacent sigma pairs.
    //
    // (case_name, distance_secs, sigma_a (smaller), sigma_b (larger))
    // Assertion per case: score_a < score_b for an entity placed
    // `distance_secs` past the anchor.
    let cases: &[(&str, u64, u64, u64)] = &[
        // From sigma_not_clamped_and_granularity_tiers_differ: distance = 20_000s
        (
            "20ks_exact_lt_hour",
            20_000,
            TemporalGranularity::Exact.sigma_secs(),
            TemporalGranularity::Hour.sigma_secs(),
        ),
        (
            "20ks_hour_lt_day",
            20_000,
            TemporalGranularity::Hour.sigma_secs(),
            TemporalGranularity::Day.sigma_secs(),
        ),
        // From granularity_day_vs_year_distributions_differ: distance = 5 days
        (
            "5d_day_lt_year",
            5 * 86_400,
            TemporalGranularity::Day.sigma_secs(),
            TemporalGranularity::Year.sigma_secs(),
        ),
    ];

    // Use a distinct entity per case to keep score lookup unambiguous.
    // entity_id(90) was the original ID in the first test; use 90+i so
    // there's no collision with other tests in this module.
    for (i, (name, distance, sigma_a, sigma_b)) in cases.iter().enumerate() {
        let (_dir, vault) = open_test_vault();
        let anchor: u64 = 1_000_000;
        let id = entity_id(90_u8.saturating_add(i as u8));
        let ts = anchor + *distance;
        put_entity(&vault, id, 1, ts, ts, ts)?;

        let base_config = TemporalSearchConfig {
            anchor_start: anchor,
            anchor_end: anchor,
            learned_start: None,
            learned_end: None,
            sigma_secs: 0,
            anchor_mode: TemporalAnchorMode::Occurred,
            adaptive: true,
            limit: 10,
        };
        let cfg_a = TemporalSearchConfig {
            sigma_secs: *sigma_a,
            ..base_config
        };
        let cfg_b = TemporalSearchConfig {
            sigma_secs: *sigma_b,
            ..base_config
        };

        let rtxn = vault.store.env.read_txn()?;
        let mut metadata_cache = EntityMetadataCache::default();
        let results_a = execute_temporal(
            &vault.store,
            &rtxn,
            &cfg_a,
            false,
            anchor,
            &mut metadata_cache,
        )?;
        let results_b = execute_temporal(
            &vault.store,
            &rtxn,
            &cfg_b,
            false,
            anchor,
            &mut metadata_cache,
        )?;

        let score_a = results_a
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("case {name}: entity missing in sigma_a results"))
            .score;
        let score_b = results_b
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("case {name}: entity missing in sigma_b results"))
            .score;

        assert!(
            score_a < score_b,
            "case {name}: expected score_a < score_b (sigma_a={sigma_a}, sigma_b={sigma_b}, distance={distance}); got score_a={score_a}, score_b={score_b}"
        );
    }

    Ok(())
}

#[test]
fn sigma_driven_discovery_for_year_granularity() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 1_000_000;
    let far = entity_id(100);
    let hundred_days = 100 * 86_400;

    put_entity(
        &vault,
        far,
        1,
        anchor + hundred_days,
        anchor + hundred_days,
        anchor + hundred_days,
    )?;

    let day_results = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Day,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;
    assert!(!day_results.iter().any(|entry| entry.id == far));

    let year_results = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Year,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;
    assert!(year_results.iter().any(|entry| entry.id == far));

    Ok(())
}

#[test]
fn bidirectional_priority_favors_nearest_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    let near = entity_id(110);
    let far_a = entity_id(111);
    let far_b = entity_id(112);

    put_entity(
        &vault,
        near,
        1,
        anchor + 1_000,
        anchor + 1_000,
        anchor + 1_000,
    )?;
    put_entity(
        &vault,
        far_a,
        1,
        anchor - 500_000,
        anchor - 500_000,
        anchor - 500_000,
    )?;
    put_entity(
        &vault,
        far_b,
        1,
        anchor + 500_000,
        anchor + 500_000,
        anchor + 500_000,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .run()?;

    assert_eq!(results[0].id, near);
    Ok(())
}

#[test]
fn adaptive_widening_and_disable() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 5_000_000;
    let target = entity_id(120);

    put_entity(
        &vault,
        target,
        1,
        anchor + 30 * 86_400,
        anchor + 30 * 86_400,
        anchor + 30 * 86_400,
    )?;

    let widened = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Week,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;
    assert!(widened.iter().any(|entry| entry.id == target));

    let exact = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Week,
            TemporalAnchorMode::Occurred,
            10,
        )
        .temporal_adaptive(false)
        .run()?;
    assert!(!exact.iter().any(|entry| entry.id == target));

    Ok(())
}

#[test]
fn contiguity_boost_behavior() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 3_000_000;
    let cluster_a = entity_id(130);
    let cluster_b = entity_id(131);
    let isolated = entity_id(132);

    put_entity(&vault, cluster_a, 1, anchor, anchor, anchor)?;
    put_entity(
        &vault,
        cluster_b,
        1,
        anchor + 3_600,
        anchor + 3_600,
        anchor + 3_600,
    )?;
    put_entity(
        &vault,
        isolated,
        1,
        anchor + 40 * 86_400,
        anchor + 40 * 86_400,
        anchor + 40 * 86_400,
    )?;

    let base = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .run()?;
    let boosted = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .boost_contiguity()
        .run()?;

    let base_map = to_score_map(&base);
    let boosted_map = to_score_map(&boosted);

    assert!(boosted_map[&cluster_a] > base_map[&cluster_a]);
    assert!(boosted_map[&cluster_b] > base_map[&cluster_b]);

    let single_base = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .run()?;
    let single_boost = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .boost_contiguity()
        .run()?;
    assert!(approx_eq(single_base[0].score, single_boost[0].score, 1e-6));

    let text_id = entity_id(133);
    put_text(&vault, text_id, "alpha")?;
    let text_base = vault.query().search_text("alpha", 10).run()?;
    let text_boosted = vault
        .query()
        .search_text("alpha", 10)
        .boost_contiguity()
        .run()?;
    assert!(approx_eq(text_base[0].score, text_boosted[0].score, 1e-6));

    Ok(())
}

#[test]
fn overlap_tiebreak_prefers_closer_midpoint() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor_start = 100;
    let anchor_end = 200;
    let closer = entity_id(140);
    let farther = entity_id(141);

    put_entity(&vault, closer, 1, 120, 130, 150)?;
    put_entity(&vault, farther, 1, 180, 190, 150)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(
            anchor_start,
            anchor_end,
            86_400,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;

    assert_eq!(results[0].id, closer);
    Ok(())
}

#[test]
fn learned_overlap_tiebreak_uses_learned_axis() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor_start = crate::unix_seconds_now() + 100;
    let anchor_end = anchor_start + 100;
    let closer = entity_id(142);
    let farther = entity_id(143);

    put_entity(
        &vault,
        closer,
        1,
        anchor_start,
        anchor_start + 10,
        anchor_start + 49,
    )?;
    put_entity(
        &vault,
        farther,
        1,
        anchor_start + 49,
        anchor_start + 50,
        anchor_start + 80,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(
            anchor_start,
            anchor_end,
            86_400,
            TemporalAnchorMode::Learned,
            10,
        )
        .run()?;

    assert_eq!(results[0].id, closer);
    Ok(())
}

#[test]
fn filters_work() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let keep = entity_id(150);
    let drop = entity_id(151);

    put_entity(&vault, keep, 1, 100, 110, 200)?;
    put_entity(&vault, drop, 1, 300, 310, 150)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(105, 105, 86_400, TemporalAnchorMode::Auto, 10)
        .filter_types(&[1])
        .filter_since(190)
        .filter_occurred_range(100, 120)
        .filter_learned_range(190, 210)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, keep);
    Ok(())
}

#[test]
fn filters_apply_before_contiguity() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 5_000_000;
    for index in 0..5_u8 {
        put_entity(&vault, entity_id(170 + index), 2, anchor, anchor, anchor)?;
    }
    let keep = entity_id(180);
    put_entity(
        &vault,
        keep,
        1,
        anchor + 86_400,
        anchor + 86_400,
        anchor + 86_400,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 20)
        .filter_types(&[1])
        .limit(1)
        .boost_contiguity()
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, keep);
    Ok(())
}

#[test]
fn inverted_ranges_are_rejected_on_put() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // The pre-D3 engine silently swapped reversed intervals into
    // (start: 100, end: 300). The fail-closed gate must reject instead
    // and leave nothing behind (M2 pinned decision D3).
    let id = entity_id(170);
    let err = vault
        .put_entity(
            &id,
            1,
            TimeRange {
                start: 300,
                end: 100,
            },
            400,
            b"payload",
        )
        .expect_err("reversed occurred interval must be rejected");
    assert!(
        matches!(
            err,
            Error::InvalidTimeRange {
                start: 300,
                end: 100
            }
        ),
        "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
    );

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.entities.get(&rtxn, id.as_bytes())?.is_none(),
        "rejected put must not write an entity record"
    );

    Ok(())
}

// ── ARCH-0039 facet filter (ONE-1117) ──────────────────────────

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};

/// The query vector every facet test searches with.
const FACET_QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

/// Neutral four-signal blend score when no optional signals are enabled:
/// all z-normalized signal columns are zero, so `exp(0) = 1`.
const FACET_R0: f32 = 1.0;
const FACET_R1: f32 = 1.0;
const FACET_R2: f32 = 1.0;
const FACET_R3: f32 = 1.0;

struct FacetFixture {
    facet_a: EntityId,
    /// CLAIM, `FacetOf → facet_b`, vector rank 0.
    claim_other: EntityId,
    /// CLAIM, `FacetOf → facet_a`, vector rank 1.
    claim_active: EntityId,
    /// CLAIM, no `FacetOf` edge (core / unfaceted), vector rank 2.
    claim_core: EntityId,
    /// Non-claim (EVENT) carrying a `FacetOf → facet_b` edge, rank 3.
    event_faceted: EntityId,
}

fn facet_claim_body() -> Vec<u8> {
    let body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

fn put_claim_with_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &facet_claim_body(),
        )
        .vector(&id, &vector)
        .commit()
}

/// A vector-ranked CLAIM whose body carries an optional `world` scope
/// (`None` = base reality). Built through the pinned claim encoder so the
/// `world` key is the real 16-byte binary the read side groups by.
fn put_claim_with_vector_world(
    vault: &Vault,
    id: EntityId,
    vector: [f32; 4],
    world: Option<EntityId>,
) -> Result<()> {
    let mut body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.world = world;
    let encoded = crate::claim::encode_claim_body(&body).expect("encode claim body");
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .vector(&id, &vector)
        .commit()
}

/// Two FACET entities + four vector-ranked candidates. Vector channel
/// distances to [`FACET_QUERY`] are strictly increasing, so the fused
/// baseline is exactly `[claim_other R0, claim_active R1, claim_core R2,
/// event_faceted R3]`.
fn setup_facet_fixture(vault: &Vault) -> Result<FacetFixture> {
    let facet_a = entity_id(0x91);
    let facet_b = entity_id(0xB1);
    put_entity(vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;

    let fixture = FacetFixture {
        facet_a,
        claim_other: entity_id(0x21),
        claim_active: entity_id(0x22),
        claim_core: entity_id(0x23),
        event_faceted: entity_id(0x24),
    };

    put_claim_with_vector(vault, fixture.claim_other, [1.0, 0.0, 0.0, 0.0])?;
    put_claim_with_vector(vault, fixture.claim_active, [0.8, 0.6, 0.0, 0.0])?;
    put_claim_with_vector(vault, fixture.claim_core, [0.6, 0.8, 0.0, 0.0])?;
    vault
        .batch()
        .put(
            &fixture.event_faceted,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .vector(&fixture.event_faceted, &[0.0, 1.0, 0.0, 0.0])
        .commit()?;

    vault
        .batch()
        .edge(&fixture.claim_other, EdgeKind::FacetOf, &facet_b, 0.7)
        .edge(&fixture.claim_active, EdgeKind::FacetOf, &facet_a, 0.7)
        .edge(&fixture.event_faceted, EdgeKind::FacetOf, &facet_b, 0.7)
        .commit()?;

    Ok(fixture)
}

fn ordered_results(scores: &[ScoredEntity]) -> Vec<(EntityId, f32)> {
    scores.iter().map(|entry| (entry.id, entry.score)).collect()
}

/// AC 3 — *(no facet)* mode regression pin: a query that never calls
/// `.facet()` returns every candidate, other-facet claims included,
/// with the exact unfiltered/unboosted blend scores in the exact
/// pre-feature order. Any accidental default-on filtering or rescoring
/// fails this literal pin.
#[test]
fn facet_absent_is_a_no_op_regression_pin() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault.query().search_vector(&FACET_QUERY, 10).run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_other, FACET_R0),
            (fixture.claim_active, FACET_R1),
            (fixture.claim_core, FACET_R2),
            (fixture.event_faceted, FACET_R3),
        ],
        "no-facet mode must be identical to the pre-feature pipeline"
    );
    Ok(())
}

/// AC 1 — strict mode: the claim whose `FacetOf` edge targets a
/// different facet is removed; the active-facet claim and the
/// core/unfaceted claim pass with their scores UNTOUCHED (strict never
/// boosts); the non-claim entity passes even though it carries a
/// `FacetOf` edge to the other facet.
#[test]
fn facet_strict_removes_other_facet_claims_only() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_active, FACET_R1),
            (fixture.claim_core, FACET_R2),
            (fixture.event_faceted, FACET_R3),
        ],
        "strict must drop claim_other, keep core + active claims and \
             non-claim entities at unchanged scores"
    );
    Ok(())
}

/// AC 2 — prefer mode: nothing is removed; the active-facet claim's
/// score is multiplied by the caller-supplied boost EXACTLY
/// (`R1 * 3.0`), which reorders it above the baseline rank-0 entity;
/// every other score is byte-identical to the baseline.
#[test]
fn facet_prefer_boosts_active_facet_with_exact_derived_values() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&fixture.facet_a, FacetMode::Prefer { boost: 3.0 })
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_active, FACET_R1 * 3.0),
            (fixture.claim_other, FACET_R0),
            (fixture.claim_core, FACET_R2),
            (fixture.event_faceted, FACET_R3),
        ],
        "prefer must keep all candidates, boost only the active-facet \
             claim, and reorder it by the exact derived score"
    );
    Ok(())
}

/// AC 4 — strict-excluded claims do not consume `result_limit` slots:
/// with `limit(2)` and the top-ranked candidate excluded, BOTH
/// remaining passing candidates fill the page. A filter applied after
/// truncation would return a single result here.
#[test]
fn facet_strict_excluded_claims_free_result_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .limit(2)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_active, FACET_R1),
            (fixture.claim_core, FACET_R2),
        ],
        "the excluded rank-0 claim must free its slot for claim_core"
    );
    Ok(())
}

/// AC 5 — a claim with no `FacetOf` edge surfaces under all three
/// modes with the exact same (never boosted) score.
#[test]
fn facet_unfaceted_claim_passes_all_three_modes_unchanged() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let no_facet = vault.query().search_vector(&FACET_QUERY, 10).run()?;
    let strict = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    let prefer = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&fixture.facet_a, FacetMode::Prefer { boost: 2.5 })
        .run()?;

    for (label, results) in [
        ("no facet", &no_facet),
        ("strict", &strict),
        ("prefer", &prefer),
    ] {
        let score = to_score_map(results)
            .get(&fixture.claim_core)
            .copied()
            .unwrap_or_else(|| panic!("unfaceted claim missing under {label} mode"));
        assert_eq!(
            score, FACET_R2,
            "unfaceted claim score must be exactly R2 under {label} mode"
        );
    }
    Ok(())
}

/// Multi-facet claims: a claim with `FacetOf` edges to BOTH facets is
/// scoped to each of them — strict keeps it for either active facet,
/// removes it for a third facet, and prefer boosts it exactly ONCE.
#[test]
fn facet_multi_scoped_claim_matches_any_of_its_facets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_a = entity_id(0x91);
    let facet_b = entity_id(0xB1);
    let facet_c = entity_id(0xC1);
    put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, facet_c, ENTITY_TYPE_FACET, 1, 1, 1)?;

    let claim_multi = entity_id(0x31);
    put_claim_with_vector(&vault, claim_multi, [1.0, 0.0, 0.0, 0.0])?;
    vault
        .batch()
        .edge(&claim_multi, EdgeKind::FacetOf, &facet_a, 0.7)
        .edge(&claim_multi, EdgeKind::FacetOf, &facet_b, 0.7)
        .commit()?;

    for facet in [facet_a, facet_b] {
        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&facet, FacetMode::Strict)
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![(claim_multi, FACET_R0)],
            "strict must keep a claim scoped to the active facet"
        );
    }

    let strict_c = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&facet_c, FacetMode::Strict)
        .run()?;
    assert!(
        strict_c.is_empty(),
        "strict must remove a claim scoped only to other facets, got {strict_c:?}"
    );

    // Two FacetOf edges, one matching: the boost applies exactly once.
    let prefer = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&facet_a, FacetMode::Prefer { boost: 2.0 })
        .run()?;
    assert_eq!(
        ordered_results(&prefer),
        vec![(claim_multi, FACET_R0 * 2.0)],
        "prefer must apply the boost exactly once per claim"
    );
    Ok(())
}

/// Only the `FacetOf` kind (u8 17) carries claim facet scope: a
/// `HasFacet` (u8 16) edge neither scopes a claim (strict treats it as
/// unfaceted) nor rescues one scoped elsewhere via `FacetOf`.
#[test]
fn facet_filter_reads_only_facet_of_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_a = entity_id(0x91);
    let facet_b = entity_id(0xB1);
    put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;

    // `HasFacet → facet_b` only: NOT facet scope — unfaceted.
    let claim_has_facet = entity_id(0x41);
    // `FacetOf → facet_b` + `HasFacet → facet_a`: scoped to facet_b;
    // the HasFacet edge to the active facet must not rescue it.
    let claim_scoped_b = entity_id(0x42);
    put_claim_with_vector(&vault, claim_has_facet, [1.0, 0.0, 0.0, 0.0])?;
    put_claim_with_vector(&vault, claim_scoped_b, [0.8, 0.6, 0.0, 0.0])?;
    vault
        .batch()
        .edge(&claim_has_facet, EdgeKind::HasFacet, &facet_b, 0.7)
        .edge(&claim_scoped_b, EdgeKind::FacetOf, &facet_b, 0.7)
        .edge(&claim_scoped_b, EdgeKind::HasFacet, &facet_a, 0.7)
        .commit()?;

    let strict = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&facet_a, FacetMode::Strict)
        .run()?;
    assert_eq!(
        ordered_results(&strict),
        vec![(claim_has_facet, FACET_R0)],
        "HasFacet must not scope a claim, and must not rescue a \
             FacetOf-scoped one"
    );

    let prefer = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&facet_b, FacetMode::Prefer { boost: 4.0 })
        .run()?;
    assert_eq!(
        ordered_results(&prefer),
        vec![
            (claim_scoped_b, FACET_R1 * 4.0),
            (claim_has_facet, FACET_R0),
        ],
        "prefer must boost via FacetOf only — a HasFacet edge to the \
             active facet earns no boost"
    );
    Ok(())
}

/// Non-claim entities are never boosted nor removed, whatever edges
/// they carry — the filter discriminates on the type byte first.
#[test]
fn facet_filter_never_rescores_non_claim_entities() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_a = entity_id(0x91);
    put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;

    let event_active = entity_id(0x51);
    vault
        .batch()
        .put(
            &event_active,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .vector(&event_active, &[1.0, 0.0, 0.0, 0.0])
        .edge(&event_active, EdgeKind::FacetOf, &facet_a, 0.7)
        .commit()?;

    for mode in [FacetMode::Strict, FacetMode::Prefer { boost: 5.0 }] {
        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&facet_a, mode)
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![(event_active, FACET_R0)],
            "non-claim entity must pass unchanged under {mode:?}"
        );
    }
    Ok(())
}

/// Fail-closed: a non-finite or non-positive prefer boost is a typed
/// [`Error::InvalidConfig`] from `run()`, never a silent skip or a
/// poisoned score.
#[test]
fn facet_prefer_rejects_invalid_boost_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    for bad_boost in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.0, -1.0] {
        let err = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Prefer { boost: bad_boost })
            .run()
            .expect_err("invalid prefer boost must be rejected");
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "expected InvalidConfig for boost {bad_boost}, got {err:?}"
        );
    }
    Ok(())
}

// ── D19 read-path claim status gate (ONE-1111) ─────────────────

fn claim_body_bytes(appr: ClaimApprovalStatus, life: ClaimLifecycleStatus, stale: bool) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(EntityId::from_bytes([0x7C; 16]).expect("valid id")),
        rmpv::Value::from("v"),
        0.9,
        appr,
        life,
    );
    body.stale = stale;
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

fn put_status_claim(
    vault: &Vault,
    id: EntityId,
    text: &str,
    appr: ClaimApprovalStatus,
    life: ClaimLifecycleStatus,
    stale: bool,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(appr, life, stale),
        )
        .text(&id, &[("body", text)])
        .commit()
}

#[test]
fn pipeline_reports_pending_vector_state_for_retrieved_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = entity_id(0x71);
    put_status_claim(
        &vault,
        claim,
        "pendingvectorneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;

    let pending = vault
        .query()
        .search_text("pendingvectorneedle", 10)
        .run_with_pending_vectors()?;
    assert!(
        pending.value.iter().any(|scored| scored.id == claim),
        "claim should be retrievable through text before embedding fill"
    );
    assert_eq!(pending.pending_vector_ids, vec![claim]);
    let token = pending
        .pending_vectors
        .iter()
        .find(|pending| pending.id == claim)
        .expect("pending marker token for claim")
        .token
        .clone();

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    let filled = vault
        .query()
        .search_text("pendingvectorneedle", 10)
        .run_with_pending_vectors()?;
    assert!(
        filled.value.iter().any(|scored| scored.id == claim),
        "claim should remain retrievable after embedding fill"
    );
    assert!(
        filled.pending_vector_ids.is_empty(),
        "embedding fill should clear pending vector state"
    );
    Ok(())
}

/// Raw-writes an entity record (25-byte envelope + `body`), bypassing
/// every write-path validation — the AC 7 corruption fixture.
fn overwrite_entity_record(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    raw.push(entity_type);
    raw.extend_from_slice(&1_u64.to_be_bytes());
    raw.extend_from_slice(&1_u64.to_be_bytes());
    raw.extend_from_slice(&1_u64.to_be_bytes());
    raw.extend_from_slice(body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &raw)?;
        Ok(())
    })
}

/// AC 1 / AC 3 / AC 4 — the literal status table through the text
/// channel: ONLY `appr ∈ {auto, approved}` ∧ `life = active` ∧
/// `stale ∈ {absent, false}` surfaces. The surfaceable rows are written
/// through `ClaimBody::new` (stale ABSENT on disk), so their presence
/// also pins "absence alone must NOT exclude".
#[test]
fn claim_status_gate_pins_the_literal_status_table() -> Result<()> {
    use ClaimApprovalStatus as A;
    use ClaimLifecycleStatus as L;

    let (_dir, vault) = open_test_vault();

    let cases: &[(u8, A, L, bool, bool)] = &[
        // (id byte, appr, life, stale, must_surface)
        (10, A::Auto, L::Active, false, true),
        (11, A::Approved, L::Active, false, true),
        (12, A::Proposed, L::Active, false, false),
        (13, A::Rejected, L::Active, false, false),
        (14, A::Auto, L::Superseded, false, false),
        (15, A::Auto, L::Retracted, false, false),
        (16, A::Auto, L::Active, true, false),
    ];

    for (byte, appr, life, stale, _) in cases {
        put_status_claim(
            &vault,
            entity_id(*byte),
            "statusneedle",
            *appr,
            *life,
            *stale,
        )?;
    }

    let results = vault.query().search_text("statusneedle", 20).run()?;
    let surfaced = to_score_map(&results);

    for (byte, appr, life, stale, must_surface) in cases {
        assert_eq!(
            surfaced.contains_key(&entity_id(*byte)),
            *must_surface,
            "appr={appr:?} life={life:?} stale={stale} must_surface={must_surface}"
        );
    }
    assert_eq!(results.len(), 2, "exactly the two surfaceable claims");
    Ok(())
}

/// AC 2 — the gate covers all five channels: one claim is reachable via
/// text, vector, phonetic, temporal, and PPR; after `retract_claim`
/// (which re-puts the body ONLY — every index row survives) it must be
/// absent from every channel.
#[test]
fn claim_status_gate_covers_all_five_channels() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 1_000_000_u64;
    let claim = entity_id(20);
    let seed = entity_id(21);

    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange {
                start: anchor,
                end: anchor,
            },
            anchor,
            &claim_body_bytes(
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
                false,
            ),
        )
        .text(&claim, &[("body", "gateneedle")])
        .vector(&claim, &[0.9, 0.1, 0.0, 0.0])
        .phonetic(&claim, &["KTNTL"])
        .commit()?;

    // PPR channel: a TURN seed with a semantic edge onto the claim.
    vault.put_entity(
        &seed,
        1,
        TimeRange {
            start: anchor,
            end: anchor,
        },
        anchor,
        b"payload",
    )?;
    vault.put_edge(&seed, EdgeKind::Supports, &claim, 0.9)?;

    type ChannelQuery = Box<dyn Fn(&Vault) -> Result<Vec<ScoredEntity>>>;
    let channels: Vec<(&str, ChannelQuery)> = vec![
        (
            "text",
            Box::new(|v: &Vault| v.query().search_text("gateneedle", 10).run()),
        ),
        (
            "vector",
            Box::new(|v: &Vault| v.query().search_vector(&[0.9, 0.1, 0.0, 0.0], 10).run()),
        ),
        (
            "phonetic",
            Box::new(|v: &Vault| v.query().search_phonetic(&["KTNTL"]).run()),
        ),
        (
            "temporal",
            Box::new(move |v: &Vault| {
                v.query()
                    .search_temporal(anchor - 100, anchor + 100, 10)
                    .run()
            }),
        ),
        (
            "ppr",
            Box::new(move |v: &Vault| v.query().search_ppr(&[seed], 2).run()),
        ),
    ];

    for (name, query) in &channels {
        assert!(
            to_score_map(&query(&vault)?).contains_key(&claim),
            "channel `{name}` must surface the active claim"
        );
    }

    vault.retract_claim(&claim, anchor + 500)?;

    for (name, query) in &channels {
        assert!(
            !to_score_map(&query(&vault)?).contains_key(&claim),
            "channel `{name}` must NOT surface the retracted claim"
        );
    }
    Ok(())
}

/// Blocker 1 fail-closed: the active facet must resolve to an EXISTING
/// FACET entity. A bogus id and a wrong-type (TURN) id both reject with
/// the typed [`Error::InvalidFacet`] carrying what was actually found; a
/// real FACET passes. A wrong impl that stores arbitrary facet bytes and
/// strict-drops every scoped claim fails the wrong-type leg.
#[test]
fn facet_query_rejects_invalid_active_facet_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    // Bogus id: no such entity → InvalidFacet { found: None }.
    let bogus = entity_id(0xEE);
    let err = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&bogus, FacetMode::Strict)
        .run()
        .expect_err("a bogus active facet must be rejected");
    assert!(
        matches!(err, Error::InvalidFacet { found: None, .. }),
        "expected InvalidFacet {{ found: None }}, got {err:?}"
    );

    // Wrong type: an existing TURN is not a FACET → found = Some(TURN).
    let turn = entity_id(0xDD);
    put_entity(&vault, turn, ENTITY_TYPE_TURN, 1, 1, 1)?;
    let err = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&turn, FacetMode::Strict)
        .run()
        .expect_err("a non-FACET active facet must be rejected");
    assert!(
        matches!(err, Error::InvalidFacet { found: Some(t), .. } if t == ENTITY_TYPE_TURN),
        "expected InvalidFacet {{ found: Some(TURN) }}, got {err:?}"
    );

    // A real FACET entity (the fixture's facet_a) passes.
    let ok = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert!(!ok.is_empty(), "a valid FACET must not be rejected");
    Ok(())
}

/// Blocker 2 world filter visibility matrix: an absent-world (base) claim
/// surfaces under ALL three scopes; a world=W claim surfaces under All and
/// World(W) but NOT under Base nor World(V). Pins the exact membership a
/// wrong (or absent) world filter would violate.
#[test]
fn world_scope_filter_visibility_matrix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_w = entity_id(0xE1);
    let world_v = entity_id(0xE2);

    let claim_base = entity_id(0x61); // no `world` key — base reality
    let claim_w = entity_id(0x62); // `world` = W
    put_claim_with_vector_world(&vault, claim_base, [1.0, 0.0, 0.0, 0.0], None)?;
    put_claim_with_vector_world(&vault, claim_w, [0.8, 0.6, 0.0, 0.0], Some(world_w))?;

    let ids =
        |scores: &[ScoredEntity]| -> HashSet<EntityId> { scores.iter().map(|s| s.id).collect() };

    // All (default): both worlds span.
    let all = ids(&vault.query().search_vector(&FACET_QUERY, 10).run()?);
    assert!(
        all.contains(&claim_base) && all.contains(&claim_w),
        "All scope must span base + world claims, got {all:?}"
    );

    // Base: only the absent-world claim; the W-scoped claim is removed.
    let base = ids(&vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .world(WorldScope::Base)
        .run()?);
    assert!(
        base.contains(&claim_base),
        "base claim must surface in Base"
    );
    assert!(
        !base.contains(&claim_w),
        "W-scoped claim must NOT surface in Base"
    );

    // World(W): the W-scoped claim plus base claims.
    let in_w = ids(&vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .world(WorldScope::World(world_w))
        .run()?);
    assert!(
        in_w.contains(&claim_base) && in_w.contains(&claim_w),
        "World(W) must surface the W claim + base claim, got {in_w:?}"
    );

    // World(V): base claim only — the W claim belongs to another world.
    let in_v = ids(&vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .world(WorldScope::World(world_v))
        .run()?);
    assert!(
        in_v.contains(&claim_base),
        "base claim must surface in World(V)"
    );
    assert!(
        !in_v.contains(&claim_w),
        "W-scoped claim must NOT surface in World(V)"
    );
    Ok(())
}

/// AC 1 — `supersede_claim` closes the OLD claim only: the new claim
/// keeps surfacing, the superseded one disappears (indexes untouched).
#[test]
fn superseded_claim_stops_surfacing_but_successor_does_not() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let old = entity_id(30);
    let new = entity_id(31);
    put_status_claim(
        &vault,
        old,
        "supersedeneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    put_status_claim(
        &vault,
        new,
        "supersedeneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;

    vault.supersede_claim(&new, &old, 2_000)?;

    let surfaced = to_score_map(&vault.query().search_text("supersedeneedle", 10).run()?);
    assert!(!surfaced.contains_key(&old), "superseded claim must hide");
    assert!(surfaced.contains_key(&new), "successor must keep surfacing");
    Ok(())
}

/// AC 5 — non-type-0 entities are NEVER status-gated: their bodies are
/// opaque, even when they happen to spell poisonous claim-status keys
/// or are not MessagePack at all.
#[test]
fn non_claim_entities_are_never_status_gated() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // TURN (type 1) whose body SAYS rejected/retracted/stale.
    let poison = entity_id(40);
    let mut poison_body = Vec::new();
    rmpv::encode::write_value(
        &mut poison_body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("appr"), rmpv::Value::from("rejected")),
            (rmpv::Value::from("life"), rmpv::Value::from("retracted")),
            (rmpv::Value::from("stale"), rmpv::Value::Boolean(true)),
        ]),
    )
    .expect("msgpack encode");
    vault
        .batch()
        .put(&poison, 1, TimeRange { start: 1, end: 1 }, 1, &poison_body)
        .text(&poison, &[("body", "opaqueneedle")])
        .commit()?;

    // PERSON-band entity (type 4) whose body is not MessagePack at all.
    let opaque = entity_id(41);
    vault
        .batch()
        .put(&opaque, 4, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&opaque, &[("body", "opaqueneedle")])
        .commit()?;

    let surfaced = to_score_map(&vault.query().search_text("opaqueneedle", 10).run()?);
    assert!(surfaced.contains_key(&poison));
    assert!(surfaced.contains_key(&opaque));
    Ok(())
}

/// AC 7 — fail-closed hydration on the pipeline: raw-written type-0
/// records whose bodies are not the pinned CLAIM ABI never surface
/// (silent exclusion, not an error).
#[test]
fn claim_status_gate_fails_closed_on_undecodable_bodies() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let control = entity_id(50);
    put_status_claim(
        &vault,
        control,
        "rawneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;

    // Three corrupt type-0 records, each text-indexed before the raw
    // overwrite (retraction-style: indexes survive, body goes bad).
    let non_map = entity_id(51);
    let missing_appr = entity_id(52);
    let empty_body = entity_id(53);
    for id in [non_map, missing_appr, empty_body] {
        put_status_claim(
            &vault,
            id,
            "rawneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
    }

    // (a) body is MessagePack but not a map;
    let mut junk = Vec::new();
    rmpv::encode::write_value(&mut junk, &rmpv::Value::from("junk")).expect("msgpack encode");
    overwrite_entity_record(&vault, &non_map, ENTITY_TYPE_CLAIM, &junk)?;

    // (b) body is a map but missing required `appr`;
    let mut no_appr = Vec::new();
    rmpv::encode::write_value(
        &mut no_appr,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("pred"), rmpv::Value::from("test.bad")),
            (rmpv::Value::from("val"), rmpv::Value::from("v")),
            (rmpv::Value::from("conf"), rmpv::Value::F32(0.5)),
            (
                rmpv::Value::from("subj"),
                rmpv::Value::Binary(vec![0x7C; 16]),
            ),
            (rmpv::Value::from("life"), rmpv::Value::from("active")),
        ]),
    )
    .expect("msgpack encode");
    overwrite_entity_record(&vault, &missing_appr, ENTITY_TYPE_CLAIM, &no_appr)?;

    // (c) body missing entirely (bare 25-byte envelope).
    overwrite_entity_record(&vault, &empty_body, ENTITY_TYPE_CLAIM, &[])?;

    let results = vault.query().search_text("rawneedle", 10).run()?;
    let surfaced = to_score_map(&results);
    assert!(surfaced.contains_key(&control), "control claim surfaces");
    assert_eq!(results.len(), 1, "all three corrupt records suppressed");
    Ok(())
}

/// AC 8 — excluded claims never consume `result_limit` slots: the gate
/// runs before sort/truncate, so retracting the TOP-ranked claim frees
/// its slot for the next survivor.
#[test]
fn excluded_claims_do_not_consume_result_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let c1 = entity_id(60);
    let c2 = entity_id(61);
    let c3 = entity_id(62);
    for (id, text) in [
        (c1, "alpha alpha alpha"),
        (c2, "alpha alpha"),
        (c3, "alpha"),
    ] {
        put_status_claim(
            &vault,
            id,
            text,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
    }

    // Establish the BM25 rank order this test relies on.
    let before = vault.query().search_text("alpha", 10).run()?;
    let before_ids: Vec<EntityId> = before.iter().map(|s| s.id).collect();
    assert_eq!(before_ids, vec![c1, c2, c3], "expected rank order");

    vault.retract_claim(&c1, 2_000)?;

    let after = vault.query().search_text("alpha", 10).limit(2).run()?;
    let after_ids: Vec<EntityId> = after.iter().map(|s| s.id).collect();
    assert_eq!(
        after_ids,
        vec![c2, c3],
        "retracted top claim must not consume a result_limit slot"
    );
    Ok(())
}

/// Pinned decision — the gate runs BEFORE expand_ppr implicit seed
/// selection: a retracted claim never seeds the expansion, so nothing
/// reachable only through its seeding can surface.
#[test]
fn dead_claim_never_seeds_ppr_expansion() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let r = entity_id(70);
    let x = entity_id(71);
    put_status_claim(
        &vault,
        r,
        "seedneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_entity(&x, 4, TimeRange { start: 1, end: 1 }, 1, b"payload")?;
    vault.put_edge(&r, EdgeKind::Supports, &x, 0.9)?;

    // Control: while active, the claim seeds the expansion and pulls in
    // its neighborhood.
    let before = to_score_map(
        &vault
            .query()
            .search_text("seedneedle", 10)
            .expand_ppr(&[], 2)
            .run()?,
    );
    assert!(before.contains_key(&r));
    assert!(
        before.contains_key(&x),
        "active claim must seed expansion and surface its neighbor"
    );

    vault.retract_claim(&r, 2_000)?;

    let after = vault
        .query()
        .search_text("seedneedle", 10)
        .expand_ppr(&[], 2)
        .run()?;
    assert!(
        after.is_empty(),
        "retracted claim must not seed expansion; got {after:?}"
    );
    Ok(())
}

/// Pinned decision — claims PULLED IN by expand_ppr are gated too: the
/// expansion list is status-gated before fusion, so a dead claim found
/// through the graph walk cannot surface.
#[test]
fn expansion_results_are_status_gated() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(80);
    let dead = entity_id(81);
    let live = entity_id(82);
    vault
        .batch()
        .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&a, &[("body", "expneedle")])
        .commit()?;
    put_status_claim(
        &vault,
        dead,
        "deadclaim",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_status_claim(
        &vault,
        live,
        "liveclaim",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_edge(&a, EdgeKind::Supports, &dead, 0.9)?;
    vault.put_edge(&a, EdgeKind::Supports, &live, 0.9)?;

    let surfaced = to_score_map(
        &vault
            .query()
            .search_text("expneedle", 10)
            .expand_ppr(&[], 2)
            .run()?,
    );
    assert!(surfaced.contains_key(&a), "seed turn surfaces");
    assert!(
        surfaced.contains_key(&live),
        "expansion must surface the ACTIVE claim (control: expansion can surface claims)"
    );
    assert!(
        !surfaced.contains_key(&dead),
        "expansion-introduced retracted claim must be gated"
    );
    Ok(())
}

#[test]
fn ppr_reblend_keeps_original_dead_claims_filtered() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let live_seed = entity_id(83);
    let dead_indexed = entity_id(84);
    let expanded = entity_id(85);
    put_status_claim(
        &vault,
        live_seed,
        "reblendneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    put_status_claim(
        &vault,
        dead_indexed,
        "reblendneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_status_claim(
        &vault,
        expanded,
        "expandedclaim",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_edge(&live_seed, EdgeKind::Supports, &expanded, 0.9)?;

    let surfaced = to_score_map(
        &vault
            .query()
            .search_text("reblendneedle", 10)
            .expand_ppr(&[], 2)
            .run()?,
    );

    assert!(surfaced.contains_key(&live_seed), "live seed surfaces");
    assert!(
        surfaced.contains_key(&expanded),
        "gated PPR expansion result surfaces"
    );
    assert!(
        !surfaced.contains_key(&dead_indexed),
        "dead claim from the original ranked lists must not re-enter after PPR reblend"
    );
    Ok(())
}

// ===== RET-010 (ONE-1292) host-injected rerank hook =====

/// Scores candidates ascending by engine rank, so the rerank order is the
/// exact reversal of the engine block order.
struct ReversingReranker;

impl Reranker for ReversingReranker {
    fn id(&self) -> &str {
        "test/reranker-reversing@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok((0..candidates.len()).map(|index| index as f32).collect())
    }
}

struct MismatchReranker;

impl Reranker for MismatchReranker {
    fn id(&self) -> &str {
        "test/reranker-mismatch@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok(vec![0.0; candidates.len() + 1])
    }
}

struct NanReranker;

impl Reranker for NanReranker {
    fn id(&self) -> &str {
        "test/reranker-nan@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        let mut scores = vec![0.0; candidates.len()];
        if let Some(first) = scores.first_mut() {
            *first = f32::NAN;
        }
        Ok(scores)
    }
}

struct FailingReranker;

impl Reranker for FailingReranker {
    fn id(&self) -> &str {
        "test/reranker-failing@v1"
    }

    fn rerank(&self, _query: &str, _candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Err(Error::InvalidConfig("reranker offline".to_owned()))
    }
}

#[derive(Default)]
struct ClaimProbeReranker {
    seen: std::sync::Mutex<Vec<(EntityId, bool)>>,
}

impl Reranker for ClaimProbeReranker {
    fn id(&self) -> &str {
        "test/reranker-claim-probe@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        self.seen.lock().unwrap().extend(
            candidates
                .iter()
                .map(|candidate| (candidate.id, candidate.claim.is_some())),
        );
        Ok(vec![0.0; candidates.len()])
    }
}

/// Five entities with strictly decreasing cosine similarity to
/// `[1, 0, 0, 0]`, so the engine block order is e1..e5 deterministically.
fn rerank_fixture(vault: &Vault) -> Result<Vec<EntityId>> {
    let vectors = [
        [1.0, 0.0, 0.0, 0.0],
        [0.9, 0.1, 0.0, 0.0],
        [0.8, 0.2, 0.0, 0.0],
        [0.7, 0.3, 0.0, 0.0],
        [0.6, 0.4, 0.0, 0.0],
    ];
    let mut ids = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let id = entity_id(0xE1 + index as u8);
        put_text_and_vector(vault, id, "rerank block fixture", *vector)?;
        ids.push(id);
    }
    Ok(ids)
}

fn rerank_query_vector() -> [f32; 4] {
    [1.0, 0.0, 0.0, 0.0]
}

#[test]
fn rerank_reorders_block_with_score_ladder_reassignment() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ids = rerank_fixture(&vault)?;
    let query = rerank_query_vector();

    let baseline = vault.query().search_vector(&query, 10).limit(10).run()?;
    assert_eq!(
        baseline.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        ids,
        "fixture must produce the deterministic engine order"
    );

    let reranker = ReversingReranker;
    let reranked = vault
        .query()
        .search_vector(&query, 10)
        .limit(10)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 5,
                query: Some("rerank probe".to_owned()),
            },
        )
        .run()?;

    let mut reversed_ids: Vec<EntityId> = baseline.iter().map(|scored| scored.id).collect();
    reversed_ids.reverse();
    assert_eq!(
        reranked.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        reversed_ids,
        "reversing reranker must reverse the block order"
    );
    // Score-ladder reassignment: position i keeps the i-th highest ENGINE
    // score; the score vector is unchanged even though ids permuted.
    assert_eq!(
        reranked
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
        baseline
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
    );
    assert!(
        reranked
            .windows(2)
            .all(|pair| pair[0].score >= pair[1].score),
        "scores must stay globally non-increasing"
    );
    Ok(())
}

#[test]
fn rerank_top_n_two_reorders_only_top_block() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ids = rerank_fixture(&vault)?;
    let query = rerank_query_vector();

    let baseline = vault.query().search_vector(&query, 10).limit(10).run()?;
    let reranker = ReversingReranker;
    let reranked = vault
        .query()
        .search_vector(&query, 10)
        .limit(10)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 2,
                query: Some("rerank probe".to_owned()),
            },
        )
        .run()?;

    let reranked_ids: Vec<EntityId> = reranked.iter().map(|scored| scored.id).collect();
    assert_eq!(
        reranked_ids,
        vec![ids[1], ids[0], ids[2], ids[3], ids[4]],
        "only the top-2 block may reorder"
    );
    assert_eq!(
        reranked
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
        baseline
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
        "tail scores and ladder positions must be untouched"
    );
    Ok(())
}

#[test]
fn rerank_trace_and_telemetry_carry_rerank_components() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ids = rerank_fixture(&vault)?;
    let query = rerank_query_vector();
    let reranker = ReversingReranker;

    let results = vault
        .query()
        .search_text("rerank block fixture", 10)
        .search_vector(&query, 10)
        .limit(10)
        .rerank(&reranker, RerankOptions::default())
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let run_id = results.run_id.expect("rerank trace run id");
    let run = vault.retrieval_run(run_id)?.expect("rerank trace run");
    let trace = run.trace.clone().expect("rerank trace");

    let blended_ids: Vec<[u8; 16]> = trace
        .blended
        .candidates
        .iter()
        .map(|candidate| candidate.result_id)
        .collect();
    let reranked_ids: Vec<[u8; 16]> = trace
        .reranked
        .candidates
        .iter()
        .map(|candidate| candidate.result_id)
        .collect();
    assert_ne!(
        blended_ids, reranked_ids,
        "reranked stage must differ from blended under the reversing reranker"
    );
    let mut reversed = blended_ids;
    reversed.reverse();
    assert_eq!(reranked_ids, reversed);

    // Every reranked-stage candidate carries a raw Rerank component appended
    // after any blend components; the blended stage carries none.
    for candidate in &trace.reranked.candidates {
        let rerank_component = candidate
            .components
            .iter()
            .find(|component| component.signal == RetrievalSignal::Rerank)
            .expect("reranked stage candidate must carry a Rerank component");
        assert!(rerank_component.score.is_finite());
    }
    assert!(
        trace.blended.candidates.iter().all(|candidate| {
            candidate
                .components
                .iter()
                .all(|component| component.signal != RetrievalSignal::Rerank)
        }),
        "blended stage must stay rerank-free"
    );

    // `final` stays the post-truncate pack.
    assert_eq!(
        trace
            .final_stage
            .candidates
            .iter()
            .map(|candidate| candidate.result_id)
            .collect::<Vec<_>>(),
        run.result_ids
    );

    // Base telemetry: score_breakdown includes the rerank components for
    // block entries (always-on, not trace-gated).
    for id in &ids {
        let breakdown = run
            .score_breakdown
            .iter()
            .find(|breakdown| breakdown.result_id == *id.as_bytes())
            .expect("block entry in score breakdown");
        assert!(
            breakdown
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Rerank),
            "score_breakdown must carry rerank components for block entries"
        );
    }

    // `signals` stays channels-only.
    assert!(!run.signals.contains(&RetrievalSignal::Rerank));
    assert!(!results.value.is_empty());

    // Inactive passthrough: without rerank the reranked stage mirrors final.
    let passthrough = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("rerank block fixture", 10)
            .search_vector(&query, 10)
            .limit(10),
    )?;
    assert_eq!(
        passthrough.reranked.candidates,
        passthrough.final_stage.candidates
    );
    Ok(())
}

#[test]
fn rerank_fork_hash_distinguishes_configurations() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    rerank_fixture(&vault)?;
    let query = rerank_query_vector();
    let reranker = ReversingReranker;

    let build = |top_n: Option<usize>| {
        let builder = vault
            .query()
            .search_text("rerank block fixture", 10)
            .search_vector(&query, 10)
            .limit(10);
        match top_n {
            None => builder,
            Some(top_n) => builder.rerank(&reranker, RerankOptions { top_n, query: None }),
        }
    };

    let off = captured_retrieval_trace(&vault, build(None))?;
    let on_30 = captured_retrieval_trace(&vault, build(Some(30)))?;
    let on_50 = captured_retrieval_trace(&vault, build(Some(50)))?;
    let on_30_again = captured_retrieval_trace(&vault, build(Some(30)))?;

    assert_ne!(off.fork_hash, on_30.fork_hash, "off vs on must fork");
    assert_ne!(on_30.fork_hash, on_50.fork_hash, "top_n must fork");
    assert_eq!(
        on_30.fork_hash, on_30_again.fork_hash,
        "identical rerank-on runs must replay to the same fork hash"
    );
    Ok(())
}

#[test]
fn rerank_fail_closed_validation_and_invariants() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    rerank_fixture(&vault)?;
    let query = rerank_query_vector();
    let reversing = ReversingReranker;

    let err = vault
        .query()
        .search_vector(&query, 10)
        .rerank(
            &reversing,
            RerankOptions {
                top_n: 0,
                query: Some("q".to_owned()),
            },
        )
        .run()
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "rerank top_n must be greater than zero")
    );

    // No RerankOptions::query and no search_text: fails closed before any
    // channel work.
    let err = vault
        .query()
        .search_vector(&query, 10)
        .rerank(&reversing, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "rerank requires a query: set RerankOptions::query or search_text")
    );

    let mismatch = MismatchReranker;
    let err = vault
        .query()
        .search_text("rerank block fixture", 10)
        .rerank(&mismatch, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvariantViolation("reranker returned mismatched score count")
    ));

    let nan = NanReranker;
    let err = vault
        .query()
        .search_text("rerank block fixture", 10)
        .rerank(&nan, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvariantViolation("reranker returned non-finite score")
    ));

    let failing = FailingReranker;
    let err = vault
        .query()
        .search_text("rerank block fixture", 10)
        .rerank(&failing, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "reranker offline"),
        "a reranker Err must propagate, never degrade to passthrough"
    );
    Ok(())
}

#[test]
fn rerank_claim_candidates_carry_decoded_bodies() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim_id = entity_id(0xE6);
    let plain_id = entity_id(0xE7);
    put_claim_text(&vault, claim_id, "clamprobe fixture", None)?;
    put_text(&vault, plain_id, "clamprobe fixture")?;

    let probe = ClaimProbeReranker::default();
    vault
        .query()
        .search_text("clamprobe fixture", 10)
        .limit(10)
        .rerank(&probe, RerankOptions::default())
        .run()?;

    let seen = probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "both fixture entities must enter the block");
    assert!(
        seen.iter()
            .any(|(id, has_claim)| *id == claim_id && *has_claim),
        "gate-passing claim candidates must carry Some(claim)"
    );
    assert!(
        seen.iter()
            .any(|(id, has_claim)| *id == plain_id && !*has_claim),
        "non-claim candidates must carry None"
    );
    Ok(())
}

// ===== EMB-2 (ONE-1334) funnel fork-hash segments =====

#[test]
fn funnel_fork_hash_distinguishes_fast_dims_and_skip_rescore() -> Result<()> {
    let mut funnel_config = test_config();
    funnel_config.fast_dims = Some(2);
    let (_dir, vault) = crate::test_util::open_test_vault_with(funnel_config);
    let id = entity_id(0xEA);
    put_text_and_vector(&vault, id, "funnel forkhash fixture", [1.0, 0.0, 0.0, 0.0])?;
    let query = [1.0_f32, 0.0, 0.0, 0.0];

    let rescored =
        captured_retrieval_trace(&vault, vault.query().search_vector(&query, 10).limit(10))?;
    let hot_lane = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_vector(&query, 10)
            .skip_vector_rescore(true)
            .limit(10),
    )?;
    assert_ne!(
        rescored.fork_hash, hot_lane.fork_hash,
        "skip_vector_rescore must fork the replay key"
    );

    let (_dir_plain, plain_vault) = open_test_vault();
    put_text_and_vector(
        &plain_vault,
        id,
        "funnel forkhash fixture",
        [1.0, 0.0, 0.0, 0.0],
    )?;
    let plain = captured_retrieval_trace(
        &plain_vault,
        plain_vault.query().search_vector(&query, 10).limit(10),
    )?;
    assert_ne!(
        plain.fork_hash, rescored.fork_hash,
        "fast_dims None vs Some must fork the replay key"
    );
    Ok(())
}

#[derive(Default)]
struct CountingErroringReranker {
    calls: std::sync::Mutex<usize>,
}

impl Reranker for CountingErroringReranker {
    fn id(&self) -> &str {
        "test/reranker-counting-erroring@v1"
    }

    fn rerank(&self, _query: &str, _candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        *self.calls.lock().unwrap() += 1;
        Err(Error::InvalidConfig(
            "reranker must not run on an empty block".to_owned(),
        ))
    }
}

/// Qodo #472-F3: an empty rerank block is a semantic no-op — the host impl
/// must never be invoked, so an otherwise-empty retrieval cannot fail
/// solely on reranker behavior.
#[test]
fn rerank_skips_empty_block_without_invoking_reranker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text(&vault, entity_id(0xE8), "indexed but unrelated")?;

    let reranker = CountingErroringReranker::default();
    let results = vault
        .query()
        .search_text("zeromatch query tokens", 10)
        .limit(10)
        .rerank(&reranker, RerankOptions::default())
        .run()?;

    assert!(results.is_empty(), "the retrieval itself is empty");
    assert_eq!(
        *reranker.calls.lock().unwrap(),
        0,
        "the reranker must never be invoked on an empty block"
    );
    Ok(())
}
