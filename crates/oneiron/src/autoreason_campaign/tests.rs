use rmpv::Value;

use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::critic::{
    CriticLens, CritiqueArtifact, CritiqueProvenance, CritiqueSeverity, CritiqueVerdict,
    LensCatalog,
};
use crate::dreamer_runner::{
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerClaimAuthoringGateDecision, DreamerClaimAuthoringSchedule,
    DreamerClaimAuthoringSinglePassReason, DreamerClaimEvidenceState, DreamerRunTreeRecord,
    DreamerTournamentClaim,
};
use crate::dreamer_tournament::{
    DreamerTournamentAuthorFork, DreamerTournamentBordaBallot, DreamerTournamentBranch,
    DreamerTournamentCandidate, DreamerTournamentJudgeClaim, DreamerTournamentRound,
    DreamerTournamentRun, DreamerTournamentStopReason, DreamerTournamentSynthesisArtifact,
    run_dreamer_claim_tournament,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::extraction_eval::{
    OF360_AR3_METRIC_TIER_INTERFACE_VERSION, OF360_METRIC_DEFINITION_SET_ID,
    OF360_METRIC_DEFINITION_SET_REVISION, OF360_SCHEMA_VERSION, Of360Ar3MetricTier,
    Of360CaseEvalReport, Of360CaseExtractionOutput, Of360ExtractedClaim, Of360ExtractionRun,
    Of360ExtractionScore, Of360GoldDataset, Of360GoldMatch, Of360MetricDefinitionSet,
    Of360MetricDirection, Of360SeededSubsetConfig, generate_of360_seeded_gold_subset,
    of360_ar3_metric_tier, of360_metric_definitions,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::config::campaign_split_dataset_ref;
use super::*;

/// One field mutation applied to a cloned decision in the fabrication tests.
type DecisionMutation = fn(&mut CampaignHeldOutDecision);

/// The module's own source, used by the scope/API audits below. Needles are
/// assembled with `concat!` so the audit text cannot satisfy itself.
const MODULE_SOURCE: &str = concat!(
    include_str!("../autoreason_campaign.rs"),
    include_str!("config.rs"),
    include_str!("report.rs"),
    include_str!("judge.rs"),
    include_str!("verdict.rs"),
    include_str!("tests.rs"),
);
const ARM_ID_TYPE: &str = concat!("Campaign", "ArmId");
const EXTERNAL_ANCHOR_DIGEST: &str = "sha256:of360-held-out-external-anchor";

struct SplitFixture {
    cost_usd: f64,
    score: f64,
    smoke: CampaignSmokeOutcome,
}

impl SplitFixture {
    fn passed(cost_usd: f64, score: f64) -> Self {
        Self {
            cost_usd,
            score,
            smoke: CampaignSmokeOutcome::Passed,
        }
    }

    fn killed(cost_usd: f64, score: f64, reason: &str) -> Self {
        Self {
            cost_usd,
            score,
            smoke: killed_smoke(reason),
        }
    }
}

struct CampaignFixture {
    config: CampaignConfig,
    single_pass: CampaignArmReport,
    tournament: CampaignArmReport,
    decision: CampaignHeldOutDecision,
}

fn killed_smoke(reason: &str) -> CampaignSmokeOutcome {
    CampaignSmokeOutcome::Killed {
        reason: reason.to_owned(),
    }
}

fn split_dataset(seed: u64) -> Of360GoldDataset {
    generate_of360_seeded_gold_subset(Of360SeededSubsetConfig {
        seed,
        max_cases: usize::MAX,
    })
    .expect("seeded gold subset")
}

fn dataset_ref(dataset: &Of360GoldDataset) -> CampaignDatasetRef {
    CampaignDatasetRef {
        dataset_id: dataset.dataset_id.clone(),
        revision: dataset.revision.clone(),
    }
}

fn budget_line() -> CampaignBudgetLine {
    CampaignBudgetLine {
        budget_id: "budget:autoreason-claim-authoring".to_owned(),
        reserve_units_per_step: 8_000,
    }
}

fn test_config() -> CampaignConfig {
    CampaignConfig::of366(
        dataset_ref(&split_dataset(1)),
        dataset_ref(&split_dataset(2)),
        dataset_ref(&split_dataset(3)),
        budget_line(),
    )
    .expect("of366 campaign config")
}

fn extraction_run(dataset: &Of360GoldDataset, run_id: &str) -> Of360ExtractionRun {
    let cases = dataset
        .cases
        .iter()
        .take(1)
        .map(|case| Of360CaseExtractionOutput {
            case_id: case.case_id.clone(),
            extracted_claims: case
                .gold_memory_points
                .iter()
                .take(1)
                .map(|memory| Of360ExtractedClaim {
                    extraction_id: format!("{}-extraction", memory.memory_id),
                    text: memory.claim.clone(),
                    matched_gold: vec![Of360GoldMatch {
                        memory_id: memory.memory_id.clone(),
                        score: Of360ExtractionScore::Full,
                    }],
                    temporal_correct: Some(true),
                    overreach: false,
                    dedup_key: None,
                })
                .collect(),
        })
        .collect();
    Of360ExtractionRun {
        schema_version: OF360_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        system_id: "oneiron-claim-authoring".to_owned(),
        dataset_id: dataset.dataset_id.clone(),
        dataset_revision: dataset.revision.clone(),
        cases,
    }
}

fn cost_row(cost_usd: f64) -> CampaignCost {
    CampaignCost {
        input_tokens: 12_000,
        output_tokens: 2_400,
        cache_read_tokens: 800,
        cache_write_tokens: 120,
        cost_usd,
        elapsed_ms: 4_200,
    }
}

fn taste_row(score: f64) -> CampaignTasteJudgment {
    CampaignTasteJudgment {
        score,
        useful: score > 0.5,
        external_anchor_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
    }
}

fn split_report(
    config: &CampaignConfig,
    arm: CampaignExecutableArm,
    split: CampaignEvaluationSplit,
    dataset: &Of360GoldDataset,
    fixture: SplitFixture,
) -> CampaignSplitReport {
    let run = extraction_run(dataset, "run-autoreason-campaign-fixture");
    build_campaign_split_report(
        config,
        arm,
        split,
        dataset,
        &run,
        cost_row(fixture.cost_usd),
        taste_row(fixture.score),
        fixture.smoke,
    )
    .expect("campaign split report")
}

fn arm_report(
    config: &CampaignConfig,
    arm: CampaignExecutableArm,
    search: SplitFixture,
    held_out: SplitFixture,
) -> CampaignArmReport {
    let search_dataset = split_dataset(1);
    let held_out_dataset = split_dataset(2);
    merge_campaign_arm_report(
        split_report(
            config,
            arm,
            CampaignEvaluationSplit::Search,
            &search_dataset,
            search,
        ),
        split_report(
            config,
            arm,
            CampaignEvaluationSplit::HeldOut,
            &held_out_dataset,
            held_out,
        ),
    )
    .expect("campaign arm report")
}

fn held_out_anchor(config: &CampaignConfig) -> CampaignGoldAnchor {
    CampaignGoldAnchor {
        dataset_id: config.splits.held_out.dataset_id.clone(),
        revision: config.splits.held_out.revision.clone(),
        gold_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
    }
}

fn campaign_fixture(
    single_pass_search: SplitFixture,
    single_pass_held_out: SplitFixture,
    tournament_search: SplitFixture,
    tournament_held_out: SplitFixture,
    cost_penalty: f64,
) -> CampaignFixture {
    let config = test_config();
    let single_pass = arm_report(
        &config,
        CampaignExecutableArm::SinglePass,
        single_pass_search,
        single_pass_held_out,
    );
    let tournament = arm_report(
        &config,
        CampaignExecutableArm::Tournament,
        tournament_search,
        tournament_held_out,
    );
    let decision = build_campaign_held_out_decision(
        &single_pass,
        &tournament,
        cost_penalty,
        held_out_anchor(&config),
    )
    .expect("campaign held-out decision");
    CampaignFixture {
        config,
        single_pass,
        tournament,
        decision,
    }
}

/// Held-out-focused fixture: both search rows are live and uninteresting.
fn held_out_fixture(
    single_pass_held_out: SplitFixture,
    tournament_held_out: SplitFixture,
    cost_penalty: f64,
) -> CampaignFixture {
    campaign_fixture(
        SplitFixture::passed(0.20, 0.60),
        single_pass_held_out,
        SplitFixture::passed(0.90, 0.80),
        tournament_held_out,
        cost_penalty,
    )
}

fn compare(fixture: &CampaignFixture) -> CampaignComparisonReport {
    compare_campaign(
        AttemptId::now(),
        &fixture.config,
        fixture.single_pass.clone(),
        fixture.tournament.clone(),
        fixture.decision.clone(),
    )
    .expect("campaign comparison report")
}

fn of366_claim_authoring_lenses(catalog: &LensCatalog) -> [&CriticLens; 4] {
    [
        catalog
            .lens("groundedness", "claim_authoring")
            .expect("groundedness lens"),
        catalog
            .lens("overreach", "claim_authoring")
            .expect("overreach lens"),
        catalog
            .lens("temporal", "claim_authoring")
            .expect("temporal lens"),
        catalog
            .lens("redundancy", "claim_authoring")
            .expect("redundancy lens"),
    ]
}

fn tournament_candidate(
    subject: EntityId,
    candidate_ref: &str,
    claim_text: &str,
    strategy: &str,
) -> Result<DreamerTournamentCandidate> {
    DreamerTournamentCandidate::new(
        candidate_ref,
        AttemptId::now(),
        EntityId::now(),
        ClaimCandidate::new(
            "pattern.sleep",
            ClaimSubject::Entity(subject),
            Value::from(claim_text),
            0.8,
        )
        .with_evidence(Value::from(format!("evidence:{candidate_ref}"))),
        DreamerTournamentJudgeClaim::new(
            claim_text,
            vec!["obs:campaign:1".to_owned(), "obs:campaign:2".to_owned()],
        )?,
        strategy,
        1,
    )
}

fn accept_branch(
    candidate: DreamerTournamentCandidate,
    catalog: &LensCatalog,
    prefix: &str,
) -> Result<DreamerTournamentBranch> {
    let mut critiques = Vec::new();
    for lens in of366_claim_authoring_lenses(catalog) {
        let provenance = CritiqueProvenance::new(
            format!("critic:{}", lens.id),
            "campaign-fixture-model",
            Some("rev1".to_owned()),
        )?;
        critiques.push(CritiqueArtifact::new(
            format!("{prefix}_{}", lens.id),
            "run-autoreason-campaign",
            candidate.branch_attempt,
            candidate.candidate_ref.clone(),
            lens,
            provenance,
            CritiqueVerdict::Accept,
            CritiqueSeverity::Info,
            lens.hard_check.then_some(true),
            candidate.judge_claim.evidence_refs.clone(),
            None,
            10,
        )?);
    }
    let synthesis =
        DreamerTournamentSynthesisArtifact::survivor(format!("{prefix}_synthesis"), &candidate)?;
    DreamerTournamentBranch::new(candidate, critiques, synthesis)
}

#[test]
fn campaign_config_round_trips_and_validates() {
    let config = test_config();
    config.validate().expect("of366 config validates");

    assert_eq!(config.schema_version, AUTOREASON_CAMPAIGN_SCHEMA_VERSION);
    assert_eq!(config.campaign_id, AUTOREASON_CAMPAIGN_ID);
    assert_eq!(config.default_arm, CampaignArmId::SinglePass);
    assert_eq!(config.tournament.uncertainty_tau, OF366_UNCERTAINTY_TAU);
    assert_eq!(config.tournament.uncertainty_tau, 0.5);
    assert_eq!(config.verdict_epsilon, OF366_VERDICT_EPSILON);
    assert_eq!(config.verdict_epsilon, 0.05);
    assert_eq!(config.corpus.min_sample_count, OF366_MIN_SAMPLE_COUNT);
    assert_eq!(config.corpus.min_sample_count, 3);
    assert_eq!(config.tournament.fanout_m, 2);
    assert_eq!(config.tournament.max_rounds_k, 2);
    assert_eq!(config.corpus.predicate_prefix, "pattern.");
    assert_eq!(config.metric_pin.set_id, OF360_METRIC_DEFINITION_SET_ID);
    assert_eq!(
        config.metric_pin.revision,
        OF360_METRIC_DEFINITION_SET_REVISION
    );

    let encoded = serde_json::to_string(&config).expect("config encodes");
    let decoded: CampaignConfig = serde_json::from_str(&encoded).expect("config decodes");
    assert_eq!(decoded, config);
    decoded.validate().expect("decoded config validates");
}

#[test]
fn campaign_config_rejects_missing_search_or_held_out_or_sealed_split() {
    let blank_ids: [fn(&mut CampaignSplits); 3] = [
        |splits| splits.search.dataset_id = String::new(),
        |splits| splits.held_out.dataset_id = String::new(),
        |splits| splits.sealed.dataset_id = String::new(),
    ];
    for blank in blank_ids {
        let mut config = test_config();
        blank(&mut config.splits);
        assert!(matches!(
            config.validate(),
            Err(CampaignError::InvalidConfig {
                reason: "dataset id is empty",
                ..
            })
        ));
    }

    let blank_revisions: [fn(&mut CampaignSplits); 3] = [
        |splits| splits.search.revision = String::new(),
        |splits| splits.held_out.revision = String::new(),
        |splits| splits.sealed.revision = String::new(),
    ];
    for blank in blank_revisions {
        let mut config = test_config();
        blank(&mut config.splits);
        assert!(matches!(
            config.validate(),
            Err(CampaignError::InvalidConfig {
                reason: "dataset revision is empty",
                ..
            })
        ));
    }

    let mut collided = test_config();
    collided.splits.held_out = collided.splits.search.clone();
    assert!(matches!(
        collided.validate(),
        Err(CampaignError::InvalidConfig {
            field: "splits",
            ..
        })
    ));
}

#[test]
fn campaign_config_rejects_sample_count_below_three() {
    for count in 0..OF366_MIN_SAMPLE_COUNT {
        let mut config = test_config();
        config.corpus.min_sample_count = count;
        assert!(matches!(
            config.validate(),
            Err(CampaignError::InvalidConfig {
                field: "corpus.min_sample_count",
                ..
            })
        ));
    }

    let mut config = test_config();
    config.corpus.min_sample_count = OF366_MIN_SAMPLE_COUNT;
    config.validate().expect("minimum sample count validates");
}

#[test]
fn campaign_config_rejects_invalid_fanout_or_depth() {
    for fanout in [1_u16, 4] {
        let mut config = test_config();
        config.tournament.fanout_m = fanout;
        assert!(matches!(
            config.validate(),
            Err(CampaignError::InvalidConfig {
                field: "tournament.fanout_m",
                ..
            })
        ));
    }

    for fanout in [2_u16, 3] {
        let mut config = test_config();
        config.tournament.fanout_m = fanout;
        config.validate().expect("landed fan-out bounds validate");
    }

    for depth in [1_u16, 3] {
        let mut config = test_config();
        config.tournament.max_rounds_k = depth;
        assert!(matches!(
            config.validate(),
            Err(CampaignError::InvalidConfig {
                field: "tournament.max_rounds_k",
                ..
            })
        ));
    }
}

#[test]
fn campaign_config_requires_budget_line() {
    let mut absent = test_config();
    absent.budget = None;
    assert!(matches!(
        absent.validate(),
        Err(CampaignError::InvalidConfig {
            field: "budget",
            reason: "absent"
        })
    ));

    let mut empty_id = test_config();
    empty_id.budget = Some(CampaignBudgetLine {
        budget_id: String::new(),
        reserve_units_per_step: 8_000,
    });
    assert!(matches!(
        empty_id.validate(),
        Err(CampaignError::InvalidConfig {
            field: "budget.budget_id",
            ..
        })
    ));

    let mut zero_reserve = test_config();
    zero_reserve.budget = Some(CampaignBudgetLine {
        budget_id: "budget:autoreason-claim-authoring".to_owned(),
        reserve_units_per_step: 0,
    });
    assert!(matches!(
        zero_reserve.validate(),
        Err(CampaignError::InvalidConfig {
            field: "budget.reserve_units_per_step",
            ..
        })
    ));

    // A caller that drops the budget line gets a typed error, not a panic.
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let mut budget_less = fixture.config.clone();
    budget_less.budget = None;
    let err = compare_campaign(
        AttemptId::now(),
        &budget_less,
        fixture.single_pass.clone(),
        fixture.tournament.clone(),
        fixture.decision,
    )
    .expect_err("budget-less comparison is refused");
    assert!(matches!(
        err,
        CampaignError::InvalidConfig {
            field: "budget",
            reason: "absent"
        }
    ));
    assert!(matches!(
        budget_less.tournament_budget_axes(),
        Err(CampaignError::InvalidConfig {
            field: "budget",
            reason: "absent"
        })
    ));
}

#[test]
fn campaign_config_rejects_overflowing_reservations() {
    for fanout in [2_u16, 3] {
        let mut config = test_config();
        config.tournament.fanout_m = fanout;
        let steps = u64::from(fanout) * u64::from(config.tournament.max_rounds_k);
        let max_safe = u64::MAX / steps;
        config
            .budget
            .as_mut()
            .expect("budget")
            .reserve_units_per_step = max_safe;
        config
            .validate()
            .expect("largest non-overflowing reservation");
        assert_eq!(
            config
                .tournament_budget_axes()
                .expect("axes")
                .reserve_units()
                .expect("reservation"),
            max_safe * steps
        );

        for units in [max_safe + 1, u64::MAX] {
            config
                .budget
                .as_mut()
                .expect("budget")
                .reserve_units_per_step = units;
            let encoded = serde_json::to_value(&config).expect("config encodes");
            let decoded: CampaignConfig =
                serde_json::from_value(encoded).expect("invalid config still decodes");
            for config in [&config, &decoded] {
                let claim = DreamerTournamentClaim {
                    predicate: "pattern.overflow".to_owned(),
                    sample_count: 3,
                    incumbent_confidence: 0.1,
                    evidence_state: DreamerClaimEvidenceState::Uncontested,
                };
                for result in [
                    config.validate(),
                    config.tournament_budget_axes().map(|_| ()),
                    config.tournament_admission(claim).map(|_| ()),
                ] {
                    assert!(matches!(
                        result,
                        Err(CampaignError::InvalidConfig {
                            field: "budget.reserve_units_per_step",
                            reason: "tournament reservation product overflows u64",
                        })
                    ));
                }
            }
        }
    }
    let config = test_config();
    let mut budget = budget_line();
    budget.reserve_units_per_step = u64::MAX;
    assert!(matches!(
        CampaignConfig::of366(
            config.splits.search,
            config.splits.held_out,
            config.splits.sealed,
            budget,
        ),
        Err(CampaignError::InvalidConfig {
            field: "budget.reserve_units_per_step",
            reason: "tournament reservation product overflows u64",
        })
    ));
}

#[test]
fn strong_critic_variant_is_design_only_and_cannot_be_default() {
    let config = test_config();
    let strong = config
        .arms
        .iter()
        .find(|declared| declared.arm == CampaignArmId::StrongCritic)
        .expect("strong-critic arm is declared");
    assert_eq!(strong.execution, CampaignArmExecution::DesignOnly);
    assert_eq!(strong.critic_tier, CampaignCriticTier::Stronger);
    config
        .validate()
        .expect("a design-only strong critic validates under the single-pass default");

    let mut default_strong = test_config();
    default_strong.default_arm = CampaignArmId::StrongCritic;
    assert!(matches!(
        default_strong.validate(),
        Err(CampaignError::InvalidConfig {
            field: "default_arm",
            ..
        })
    ));

    let mut executable_strong = test_config();
    for declared in &mut executable_strong.arms {
        if declared.arm == CampaignArmId::StrongCritic {
            declared.execution = CampaignArmExecution::Executable;
        }
    }
    assert!(matches!(
        executable_strong.validate(),
        Err(CampaignError::InvalidConfig { field: "arms", .. })
    ));

    // The boundary only ever widens toward the declaration id, and the
    // design-only arm is not a decodable executable arm.
    assert_eq!(
        CampaignArmId::from(CampaignExecutableArm::SinglePass),
        CampaignArmId::SinglePass
    );
    assert_eq!(
        CampaignArmId::from(CampaignExecutableArm::Tournament),
        CampaignArmId::Tournament
    );
    assert!(serde_json::from_str::<CampaignExecutableArm>("\"strong_critic\"").is_err());

    // Source audit: no invocation entry point accepts the declaration id.
    for line in MODULE_SOURCE.lines() {
        let trimmed = line.trim_start();
        let is_parameter = trimmed.starts_with("arm: ") && !trimmed.contains("::");
        if trimmed.starts_with("pub fn ") || is_parameter {
            assert!(
                !line.contains(ARM_ID_TYPE),
                "invocation surface must not accept the declaration-only arm id: {line}"
            );
        }
    }
}

#[test]
fn manual_single_pass_uses_landed_admission() -> Result<()> {
    let config = test_config();
    let admission = config.single_pass_admission();
    assert_eq!(admission, DreamerClaimAuthoringAdmission::single_pass());

    let decision = admission.gate_decision(DreamerClaimAuthoringBatchTier::batch())?;
    assert_eq!(
        decision,
        DreamerClaimAuthoringGateDecision::SinglePass(
            DreamerClaimAuthoringSinglePassReason::Strategy
        )
    );
    Ok(())
}

#[test]
fn manual_tournament_uses_landed_gate_and_runner() -> Result<()> {
    let config = test_config();
    let admission = config
        .tournament_admission(DreamerTournamentClaim {
            predicate: "pattern.sleep".to_owned(),
            sample_count: OF366_MIN_SAMPLE_COUNT,
            incumbent_confidence: 0.30,
            evidence_state: DreamerClaimEvidenceState::Contested,
        })
        .expect("tournament admission");
    let decision = admission.gate_decision(DreamerClaimAuthoringBatchTier::batch())?;
    let DreamerClaimAuthoringGateDecision::Tournament(grant) = decision else {
        panic!("an eligible contested pattern claim must be admitted to the tournament");
    };
    let axes = config.tournament_budget_axes().expect("tournament axes");
    assert_eq!(grant.schedule, DreamerClaimAuthoringSchedule::Batch);
    assert_eq!(grant.fanout_m, config.tournament.fanout_m);
    assert_eq!(grant.depth_k, config.tournament.max_rounds_k);
    assert_eq!(grant.reserve_units, axes.reserve_units()?);

    // Only the tournament path is driven here; arm A relies on the landed
    // Dreamer authoring tests. No model is invoked: this proves tournament
    // wiring, not that a live A/B ran.
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let actor = EntityId::now();
    let subject = EntityId::now();
    let seeded = TimeRange { start: 1, end: 1 };
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, seeded, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, seeded, 1, b"subject")?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("autoreason-campaign-fixture"))?,
        ClaimApprovalStatus::Approved,
    );
    let catalog = LensCatalog::of366_seed()?;
    let left = tournament_candidate(
        subject,
        "campaign-candidate-left",
        "Late caffeine tracks lighter sleep across the campaign corpus.",
        "seed-a",
    )?;
    let right = tournament_candidate(
        subject,
        "campaign-candidate-right",
        "An earlier caffeine cutoff tracks deeper sleep across the campaign corpus.",
        "seed-b",
    )?;
    let winner_id = right.claim_id;
    let fork = DreamerTournamentAuthorFork::new(
        "campaign-author-seed",
        AttemptId::now(),
        vec![left.branch_attempt, right.branch_attempt],
    )?;
    let run = DreamerTournamentRun::new(
        "run-autoreason-campaign",
        fork,
        config.tournament.fanout_m,
        config.tournament.max_rounds_k,
        vec![DreamerTournamentRound::new(
            vec![
                accept_branch(left, &catalog, "campaign_left")?,
                accept_branch(right, &catalog, "campaign_right")?,
            ],
            None,
            vec![
                DreamerTournamentBordaBallot::new("judge-a", vec![1, 0])?,
                DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
            ],
        )?],
        Vec::new(),
        envelope,
        TimeRange { start: 20, end: 20 },
        21,
    )?;

    let result = run_dreamer_claim_tournament(&vault, run)?;
    assert_eq!(result.winner.claim_id, winner_id);
    assert_eq!(result.stop_reason, DreamerTournamentStopReason::Consensus);
    assert_eq!(result.rounds_executed, 1);

    let stored = vault
        .get_claim(&winner_id)?
        .expect("winner claim is readable through the normal claim getter");
    assert_eq!(stored.predicate, "pattern.sleep");
    Ok(())
}

#[test]
fn of360_and_cost_rows_merge_into_comparable_arm_report() {
    let config = test_config();
    let report = arm_report(
        &config,
        CampaignExecutableArm::Tournament,
        SplitFixture::passed(0.90, 0.80),
        SplitFixture::passed(1.10, 0.75),
    );

    assert_eq!(report.arm, CampaignExecutableArm::Tournament);
    assert_eq!(report.search.split, CampaignEvaluationSplit::Search);
    assert_eq!(report.held_out.split, CampaignEvaluationSplit::HeldOut);
    assert_eq!(report.search.dataset, config.splits.search);
    assert_eq!(report.held_out.dataset, config.splits.held_out);
    assert_eq!(
        report.search.of360.interface_version,
        OF360_AR3_METRIC_TIER_INTERFACE_VERSION
    );
    assert!(
        report
            .search
            .of360
            .report
            .metrics
            .halumem_recall
            .value
            .is_some()
    );
    assert_eq!(
        report.search.metric_definition_digest,
        report.held_out.metric_definition_digest
    );
    assert_eq!(report.held_out.cost.cost_usd, 1.10);
    assert_eq!(report.held_out.effective_taste_score, 0.75);
}

fn assert_invalid_of360_comparison(report: CampaignComparisonReport) {
    let encoded = serde_json::to_value(&report).expect("report encodes");
    let decoded: CampaignComparisonReport =
        serde_json::from_value(encoded).expect("invalid metric evidence still decodes");
    for report in [report, decoded] {
        assert!(matches!(report.validate(), Err(CampaignError::Of360(_))));
        assert!(matches!(
            merge_campaign_arm_report(
                report.tournament.search.clone(),
                report.tournament.held_out.clone(),
            ),
            Err(CampaignError::Of360(_))
        ));
        assert!(matches!(
            build_campaign_held_out_decision(
                &report.single_pass,
                &report.tournament,
                report.decision.cost_penalty,
                report.decision.external_anchor.clone(),
            ),
            Err(CampaignError::Of360(_))
        ));
        assert!(matches!(
            compare_campaign(
                report.campaign_ref,
                &test_config(),
                report.single_pass,
                report.tournament,
                report.decision,
            ),
            Err(CampaignError::Of360(_))
        ));
    }
}

#[test]
fn campaign_rejects_inconsistent_of360_metadata() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let base = compare(&fixture);
    let mutations: [fn(&mut Of360Ar3MetricTier); 8] = [
        |tier| {
            tier.interface_version += 1;
        },
        |tier| {
            tier.report.schema_version += 1;
        },
        |tier| {
            tier.metric_definitions.schema_version += 1;
        },
        |tier| {
            tier.report.metric_set_id.push_str("-other");
        },
        |tier| {
            tier.report
                .metric_definition_envelope
                .content_hash
                .push_str("-other");
        },
        |tier| {
            tier.report
                .metric_definition_envelope
                .model_id
                .push_str("-other");
        },
        |tier| {
            tier.report
                .metric_definition_envelope
                .version
                .push_str("-other");
        },
        |tier| {
            tier.report
                .metric_definition_envelope
                .params_hash
                .push_str("-other");
        },
    ];
    for mutate in mutations {
        let mut report = base.clone();
        for split in [
            &mut report.single_pass.search,
            &mut report.single_pass.held_out,
            &mut report.tournament.search,
            &mut report.tournament.held_out,
        ] {
            mutate(&mut split.of360);
            assert!(matches!(split.validate(), Err(CampaignError::Of360(_))));
        }
        assert_invalid_of360_comparison(report);
    }
}

#[test]
fn campaign_rejects_inconsistent_of360_metrics() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let base = compare(&fixture);
    let mutations: [fn(&mut Of360Ar3MetricTier); 10] = [
        |tier| {
            tier.report.metrics.halumem_recall.value = Some(1.0);
        },
        |tier| {
            tier.report.metrics.halumem_recall.value = None;
        },
        |tier| {
            tier.report.metrics.halumem_recall.numerator = -1.0;
        },
        |tier| {
            tier.report.metrics.halumem_recall.denominator = -1.0;
        },
        |tier| {
            tier.report.metrics.halumem_recall =
                crate::extraction_eval::Of360RateMetric::new(2.0, 1.0);
        },
        |tier| {
            tier.report.cases[1].metrics.target_precision.value = Some(0.0);
        },
        |tier| {
            tier.report.cases[0].metrics.halumem_weighted_recall.value = Some(1.0);
        },
        |tier| {
            tier.report.cases[0].metrics.halumem_f1 =
                crate::extraction_eval::Of360RateMetric::new(0.0, 1.0);
        },
        |tier| {
            tier.report.cases[0].metrics.overreach_rate =
                crate::extraction_eval::Of360RateMetric::new(0.0, 2.0);
        },
        |tier| {
            tier.report.metrics = tier.report.cases[0].metrics.clone();
        },
    ];
    for mutate in mutations {
        let mut report = base.clone();
        mutate(&mut report.tournament.held_out.of360);
        assert_invalid_of360_comparison(report);
    }
    // Non-finite floats are public-struct inputs, not representable JSON numbers.
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        for field in [0, 1, 2] {
            let mut split = base.tournament.held_out.clone();
            let rate = &mut split.of360.report.metrics.halumem_recall;
            match field {
                0 => {
                    rate.numerator = value;
                }
                1 => {
                    rate.denominator = value;
                }
                _ => {
                    rate.value = Some(value);
                }
            }
            assert!(matches!(split.validate(), Err(CampaignError::Of360(_))));
        }
    }
}

#[test]
fn campaign_rejects_mutated_of360_metric_definition_payload() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let base = compare(&fixture);
    let canonical = of360_metric_definitions().expect("landed metric definitions");
    let mutations: [fn(&mut Of360MetricDefinitionSet); 11] = [
        |definitions| definitions.metrics.clear(),
        |definitions| {
            definitions.metrics.pop();
        },
        |definitions| definitions.metrics.push(definitions.metrics[0].clone()),
        |definitions| definitions.metrics.swap(0, 1),
        |definitions| definitions.metrics[0].metric_id.push_str("-other"),
        |definitions| definitions.metrics[0].label.push_str("-other"),
        |definitions| definitions.metrics[0].definition.push_str("-other"),
        |definitions| definitions.metrics[0].formula.push_str("-other"),
        |definitions| definitions.metrics[0].direction = Of360MetricDirection::LowerIsBetter,
        |definitions| definitions.metrics[0].primary = !definitions.metrics[0].primary,
        |definitions| definitions.source_refs.clear(),
    ];
    for mutate in mutations {
        let mut report = base.clone();
        // All four rows retain the full configured pin and agree with each other.
        for split in [
            &mut report.single_pass.search,
            &mut report.single_pass.held_out,
            &mut report.tournament.search,
            &mut report.tournament.held_out,
        ] {
            mutate(&mut split.of360.metric_definitions);
            let definitions = &split.of360.metric_definitions;
            assert_eq!(definitions.set_id, canonical.set_id);
            assert_eq!(definitions.revision, canonical.revision);
            assert_eq!(
                definitions.derivation_envelope,
                canonical.derivation_envelope,
            );
            assert!(matches!(
                split.validate(),
                Err(CampaignError::Of360(Of360EvalError::InvalidMetricTier {
                    reason: "metric definition payload differs from the canonical pin",
                }))
            ));
        }
        assert_invalid_of360_comparison(report);
    }
}

fn diagnostic_campaign_report() -> CampaignComparisonReport {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let mut report = compare(&fixture);
    for split in [
        &mut report.single_pass.search,
        &mut report.single_pass.held_out,
        &mut report.tournament.search,
        &mut report.tournament.held_out,
    ] {
        let dataset = split_dataset(match split.split {
            CampaignEvaluationSplit::Search => 1,
            CampaignEvaluationSplit::HeldOut => 2,
        });
        let mut run = extraction_run(&dataset, "run-diagnostic-audit");
        let output = &mut run.cases[0];
        output.extracted_claims[0].matched_gold[0].score = Of360ExtractionScore::Partial;
        output.extracted_claims[0].overreach = true;
        for index in 0..3 {
            output.extracted_claims.push(Of360ExtractedClaim {
                extraction_id: format!("diagnostic-{index}"),
                text: "Unsupported claim".to_owned(),
                matched_gold: Vec::new(),
                temporal_correct: None,
                overreach: index != 1,
                dedup_key: Some("diagnostic-duplicate".to_owned()),
            });
        }
        // Reusing extraction IDs across cases is legal. Leave the other cases empty.
        let mut second_output = output.clone();
        second_output.case_id = dataset.cases[1].case_id.clone();
        let memory = &dataset.cases[1].gold_memory_points[0];
        second_output.extracted_claims[0].text = memory.claim.clone();
        second_output.extracted_claims[0].matched_gold[0].memory_id = memory.memory_id.clone();
        run.cases.push(second_output);
        split.of360 = of360_ar3_metric_tier(&dataset, &run).expect("writer-produced diagnostics");
    }
    report.validate().expect("valid diagnostic fixture");
    report
}

type ExtractionDiagnosticIds = fn(&mut Of360CaseEvalReport) -> &mut Vec<String>;
const EXTRACTION_DIAGNOSTICS: [ExtractionDiagnosticIds; 3] = [
    |case| &mut case.hallucinated_extraction_ids,
    |case| &mut case.overreach_extraction_ids,
    |case| &mut case.redundant_extraction_ids,
];

#[test]
fn campaign_rejects_missing_of360_diagnostic_ids() {
    let base = diagnostic_campaign_report();
    for select in EXTRACTION_DIAGNOSTICS {
        for clear_all in [false, true] {
            let mut report = base.clone();
            let split = &mut report.tournament.held_out;
            let ids = select(&mut split.of360.report.cases[0]);
            assert!(ids.len() >= 2);
            if clear_all {
                ids.clear();
            } else {
                ids.pop();
            }
            assert!(matches!(
                split.validate(),
                Err(CampaignError::Of360(Of360EvalError::InvalidMetricTier {
                    reason: "extraction diagnostic count differs from the metric numerator",
                }))
            ));
            assert_invalid_of360_comparison(report);
        }
    }
}

#[test]
fn campaign_rejects_duplicate_of360_diagnostic_ids() {
    let base = diagnostic_campaign_report();
    for select in EXTRACTION_DIAGNOSTICS {
        let mut report = base.clone();
        let split = &mut report.tournament.held_out;
        let ids = select(&mut split.of360.report.cases[0]);
        assert!(ids.len() >= 2);
        // Keep the correct length, so only the uniqueness check can catch this.
        ids[1] = ids[0].clone();
        assert!(matches!(
            split.validate(),
            Err(CampaignError::Of360(Of360EvalError::InvalidMetricTier {
                reason: "duplicate extraction diagnostic id",
            }))
        ));
        assert_invalid_of360_comparison(report);
    }
}

#[test]
fn campaign_accepts_landed_of360_diagnostic_reports() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let diagnostic = diagnostic_campaign_report();
    let cases = &diagnostic.tournament.held_out.of360.report.cases;
    assert_eq!(cases[0].metrics.hallucination_rate.numerator, 3.0);
    assert_eq!(cases[0].metrics.overreach_rate.numerator, 3.0);
    assert_eq!(cases[0].metrics.redundancy_rate.numerator, 2.0);
    assert!(!cases[0].partial_gold_memory_ids.is_empty());
    assert!(!cases[0].omitted_gold_memory_ids.is_empty());
    assert_eq!(cases[2].metrics.target_precision.value, None);
    assert_eq!(
        cases[0].hallucinated_extraction_ids,
        cases[1].hallucinated_extraction_ids,
    );
    assert!(cases[0].redundant_extraction_ids.iter().any(|id| {
        cases[0].hallucinated_extraction_ids.contains(id)
            && cases[0].overreach_extraction_ids.contains(id)
    }));
    for original in [compare(&fixture), diagnostic] {
        let encoded = serde_json::to_value(&original).expect("report encodes");
        let decoded: CampaignComparisonReport =
            serde_json::from_value(encoded).expect("report decodes");
        assert_eq!(decoded, original);
        for report in [original, decoded] {
            report.validate().expect("landed report remains valid");
            for split in [
                &report.single_pass.search,
                &report.single_pass.held_out,
                &report.tournament.search,
                &report.tournament.held_out,
            ] {
                split.validate().expect("landed split remains valid");
                assert_eq!(
                    split.of360.metric_definitions,
                    of360_metric_definitions().expect("canonical payload"),
                );
            }
            compare_campaign(
                report.campaign_ref,
                &fixture.config,
                report.single_pass,
                report.tournament,
                report.decision,
            )
            .expect("landed evidence remains comparable");
        }
    }
}

#[test]
fn merge_campaign_arm_report_rejects_invalid_struct_literal_split() {
    let config = test_config();
    let search_dataset = split_dataset(1);
    let held_out_dataset = split_dataset(2);
    let search = split_report(
        &config,
        CampaignExecutableArm::SinglePass,
        CampaignEvaluationSplit::Search,
        &search_dataset,
        SplitFixture::passed(0.20, 0.60),
    );
    let base = split_report(
        &config,
        CampaignExecutableArm::SinglePass,
        CampaignEvaluationSplit::HeldOut,
        &held_out_dataset,
        SplitFixture::passed(0.25, 0.90),
    );

    // A hand-built literal: the type has no private field to hide behind,
    // so the refusal has to come from validation.
    let forged = CampaignSplitReport {
        arm: base.arm,
        split: base.split,
        dataset: base.dataset,
        metric_definition_digest: base.metric_definition_digest,
        of360: base.of360,
        cost: base.cost,
        taste: base.taste,
        smoke: killed_smoke("campaign smoke gate tripped"),
        effective_taste_score: 0.9,
    };
    let err = merge_campaign_arm_report(search, forged)
        .expect_err("a smoke-killed row with a live score is refused before assembly");
    assert!(matches!(err, CampaignError::ReportMismatch { .. }));
}

#[test]
fn merge_campaign_arm_report_rejects_different_metric_definition_digests() {
    let mut report = arm_report(
        &test_config(),
        CampaignExecutableArm::SinglePass,
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.25, 0.90),
    );
    report
        .held_out
        .metric_definition_digest
        .push_str("-different");
    report
        .held_out
        .of360
        .metric_definitions
        .derivation_envelope
        .content_hash = report.held_out.metric_definition_digest.clone();

    report.held_out.of360.report.metric_definition_envelope = report
        .held_out
        .of360
        .metric_definitions
        .derivation_envelope
        .clone();

    report.search.validate().expect("valid search report");
    report.held_out.validate().expect("valid held-out report");
    assert_ne!(
        report.search.metric_definition_digest,
        report.held_out.metric_definition_digest
    );
    let err = merge_campaign_arm_report(report.search, report.held_out)
        .expect_err("individually valid reports with different metric digests cannot merge");
    assert!(matches!(
        err,
        CampaignError::ReportMismatch {
            reason: "search and held-out reports have different metric definition digests",
        }
    ));
}

#[test]
fn held_out_decision_rejects_mixed_metric_digests() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    for change_search in [false, true] {
        let mut tournament = fixture.tournament.clone();
        for split in [&mut tournament.search, &mut tournament.held_out] {
            if split.split == CampaignEvaluationSplit::HeldOut || change_search {
                split.metric_definition_digest.push_str("-different");
                split
                    .of360
                    .metric_definitions
                    .derivation_envelope
                    .content_hash = split.metric_definition_digest.clone();
                split.of360.report.metric_definition_envelope =
                    split.of360.metric_definitions.derivation_envelope.clone();
            }
            split.validate().expect("internally consistent split");
        }
        if change_search {
            tournament = merge_campaign_arm_report(tournament.search, tournament.held_out)
                .expect("each arm separately has a consistent metric digest");
        }
        let encoded = serde_json::to_value(&tournament).expect("arm encodes");
        let decoded: CampaignArmReport = serde_json::from_value(encoded).expect("arm decodes");
        for tournament in [tournament, decoded] {
            let err = build_campaign_held_out_decision(
                &fixture.single_pass,
                &tournament,
                0.01,
                held_out_anchor(&fixture.config),
            )
            .expect_err("standalone decision must reject mixed metric digests");
            let expected_reason = if change_search {
                "arms have different metric definition digests"
            } else {
                "search and held-out reports have different metric definition digests"
            };
            assert!(matches!(err, CampaignError::ReportMismatch { reason }
                if reason == expected_reason));
        }
    }
}

#[test]
fn metric_definition_digest_is_carried_and_must_match() {
    let config = test_config();
    let dataset = split_dataset(1);
    let run = extraction_run(&dataset, "run-metric-digest");
    let report = build_campaign_split_report(
        &config,
        CampaignExecutableArm::SinglePass,
        CampaignEvaluationSplit::Search,
        &dataset,
        &run,
        cost_row(0.20),
        taste_row(0.60),
        CampaignSmokeOutcome::Passed,
    )
    .expect("campaign split report");

    assert_eq!(
        report.metric_definition_digest,
        config.metric_pin.derivation_envelope.content_hash
    );
    assert_eq!(
        report.metric_definition_digest,
        report
            .of360
            .metric_definitions
            .derivation_envelope
            .content_hash
    );

    let mut mutated = test_config();
    mutated.metric_pin.derivation_envelope.content_hash =
        "sha256:not-the-landed-envelope".to_owned();
    let err = build_campaign_split_report(
        &mutated,
        CampaignExecutableArm::SinglePass,
        CampaignEvaluationSplit::Search,
        &dataset,
        &run,
        cost_row(0.20),
        taste_row(0.60),
        CampaignSmokeOutcome::Passed,
    )
    .expect_err("a mutated metric pin is refused");
    assert!(matches!(err, CampaignError::MetricPinMismatch));
}

#[test]
fn compare_campaign_binds_every_split_to_full_metric_pin() {
    type MetricMutation = fn(&mut Of360MetricDefinitionSet);

    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let mutations: [(&str, MetricMutation); 6] = [
        ("set_id", |definitions| {
            definitions.set_id.push_str("-other");
        }),
        ("revision", |definitions| {
            definitions.revision.push_str("-other");
        }),
        ("content_hash", |definitions| {
            definitions
                .derivation_envelope
                .content_hash
                .push_str("-other");
        }),
        ("model_id", |definitions| {
            definitions.derivation_envelope.model_id.push_str("-other");
        }),
        ("version", |definitions| {
            definitions.derivation_envelope.version.push_str("-other");
        }),
        ("params_hash", |definitions| {
            definitions
                .derivation_envelope
                .params_hash
                .push_str("-other");
        }),
    ];
    for (field, mutate) in mutations {
        // None forges all four reports consistently. Each Some case also
        // checks that no individual split escapes the full pin check.
        for altered_split in [None, Some(0), Some(1), Some(2), Some(3)] {
            let mut single_pass = fixture.single_pass.clone();
            let mut tournament = fixture.tournament.clone();
            for (index, split) in [
                &mut single_pass.search,
                &mut single_pass.held_out,
                &mut tournament.search,
                &mut tournament.held_out,
            ]
            .into_iter()
            .enumerate()
            {
                if altered_split.is_none() || altered_split == Some(index) {
                    mutate(&mut split.of360.metric_definitions);
                    split.of360.report.metric_set_id =
                        split.of360.metric_definitions.set_id.clone();
                    split.of360.report.metric_definition_envelope =
                        split.of360.metric_definitions.derivation_envelope.clone();
                    split.metric_definition_digest = split
                        .of360
                        .metric_definitions
                        .derivation_envelope
                        .content_hash
                        .clone();
                }
                split.validate().expect("internally consistent split");
            }
            let encoded = serde_json::to_value((&single_pass, &tournament))
                .expect("public arm reports encode");
            let decoded: (CampaignArmReport, CampaignArmReport) =
                serde_json::from_value(encoded).expect("forged arm reports decode");
            for (single_pass, tournament) in [(single_pass, tournament), decoded] {
                let err = compare_campaign(
                    AttemptId::now(),
                    &fixture.config,
                    single_pass,
                    tournament,
                    fixture.decision.clone(),
                )
                .expect_err("public and decoded reports must match the config metric pin");
                let expected = if field == "content_hash" && altered_split.is_some() {
                    matches!(
                        err,
                        CampaignError::ReportMismatch {
                            reason: "search and held-out reports have different metric definition digests",
                        }
                    )
                } else {
                    matches!(err, CampaignError::MetricPinMismatch)
                };
                assert!(
                    expected,
                    "{field}, altered split {altered_split:?}: {err:?}"
                );
            }
        }
    }
}

#[test]
fn comparison_rejects_wrong_split_datasets_in_public_and_decoded_reports() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let base = compare(&fixture);
    for split_kind in [
        CampaignEvaluationSplit::Search,
        CampaignEvaluationSplit::HeldOut,
    ] {
        for change_revision in [false, true] {
            let mut dataset = campaign_split_dataset_ref(&fixture.config, split_kind).clone();
            if change_revision {
                dataset.revision.push_str("-other");
            } else {
                dataset.dataset_id.push_str("-other");
            }
            for altered_arm in [
                None,
                Some(CampaignExecutableArm::SinglePass),
                Some(CampaignExecutableArm::Tournament),
            ] {
                let mut report = base.clone();
                for arm in [&mut report.single_pass, &mut report.tournament] {
                    if altered_arm.is_some() && altered_arm != Some(arm.arm) {
                        continue;
                    }
                    let split = match split_kind {
                        CampaignEvaluationSplit::Search => &mut arm.search,
                        CampaignEvaluationSplit::HeldOut => &mut arm.held_out,
                    };
                    // Keep each public split internally consistent so the
                    // config/pair binding, not local validation, refuses it.
                    split.dataset = dataset.clone();
                    split.of360.report.dataset_id = dataset.dataset_id.clone();
                    split.of360.report.dataset_revision = dataset.revision.clone();
                    split.validate().expect("internally consistent split");
                }
                if altered_arm.is_none() && split_kind == CampaignEvaluationSplit::HeldOut {
                    report.decision.external_anchor.dataset_id = dataset.dataset_id.clone();
                    report.decision.external_anchor.revision = dataset.revision.clone();
                }
                let encoded = serde_json::to_value(&report).expect("public report encodes");
                let decoded: CampaignComparisonReport =
                    serde_json::from_value(encoded).expect("forged report decodes");
                for report in [report, decoded] {
                    let expected_reason = if altered_arm.is_none() {
                        report
                            .validate()
                            .expect("paired refs are internally consistent");
                        "split dataset ref differs from the configured split"
                    } else {
                        assert!(matches!(
                            report.validate(),
                            Err(CampaignError::ReportMismatch {
                                reason: "corresponding arm splits use different dataset refs",
                            })
                        ));
                        "corresponding arm splits use different dataset refs"
                    };
                    let err = compare_campaign(
                        report.campaign_ref,
                        &fixture.config,
                        report.single_pass,
                        report.tournament,
                        report.decision,
                    )
                    .expect_err("wrong split datasets cannot be certified by the config");
                    assert!(
                        matches!(err, CampaignError::ReportMismatch { reason }
                            if reason == expected_reason),
                        "{split_kind:?}, rev {change_revision}, arm {altered_arm:?}: {err:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn campaign_ref_is_exact_run_tree_root() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    // Rootness is the caller's contract; this module echoes the id it is
    // handed and mints no second identity.
    let root = DreamerRunTreeRecord {
        attempt_id: AttemptId::now(),
        parent_attempt: None,
        created_at: 42,
    };
    assert!(root.parent_attempt.is_none());

    let report = compare_campaign(
        root.attempt_id,
        &fixture.config,
        fixture.single_pass.clone(),
        fixture.tournament.clone(),
        fixture.decision.clone(),
    )
    .expect("campaign comparison report");
    assert_eq!(report.campaign_ref, root.attempt_id);
    assert_eq!(report.budget_id, "budget:autoreason-claim-authoring");

    let encoded = serde_json::to_string(&report).expect("report encodes");
    let decoded: CampaignComparisonReport = serde_json::from_str(&encoded).expect("report decodes");
    assert_eq!(decoded.campaign_ref, root.attempt_id);
    decoded.validate().expect("decoded report validates");
}

#[test]
fn sealed_split_has_no_ar3_report_variant() {
    // Exhaustive: the reportable split set is exactly search/held-out.
    for split in [
        CampaignEvaluationSplit::Search,
        CampaignEvaluationSplit::HeldOut,
    ] {
        let encoded = match split {
            CampaignEvaluationSplit::Search => "search",
            CampaignEvaluationSplit::HeldOut => "held_out",
        };
        assert_eq!(
            serde_json::to_value(split).expect("split encodes"),
            serde_json::Value::from(encoded)
        );
    }
    assert!(serde_json::from_str::<CampaignEvaluationSplit>("\"sealed\"").is_err());

    // The sealed ref is pinned by the config and reachable from no report
    // constructor.
    let config = test_config();
    assert_ne!(config.splits.sealed, config.splits.held_out);
    assert_ne!(config.splits.sealed, config.splits.search);
    assert!(!MODULE_SOURCE.contains(concat!("Evaluation", "Split::Sealed")));
}

#[test]
fn held_out_tournament_win_net_of_cost_keeps() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.05,
    );
    assert!(fixture.decision.tournament_wins_held_out);
    assert!(!fixture.decision.ab_dominated);

    let report = compare(&fixture);
    assert_eq!(report.verdict.verdict, ExperimentVerdict::Keep);
    assert_eq!(
        report.verdict.reason,
        CampaignVerdictReason::HeldOutWinNetOfCost
    );
    assert_eq!(report.verdict.verdict.predicate(), EXPERIMENT_VERDICT_KEEP);
    assert_eq!(
        report.verdict.verdict.predicate(),
        "experiment.verdict.keep"
    );
    assert!(report.verdict.net_delta >= report.verdict_epsilon);
}

#[test]
fn ab_domination_discards() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.75),
        SplitFixture::passed(0.90, 0.75),
        0.0,
    );
    assert_eq!(fixture.decision.quality_delta, 0.0);
    assert!(fixture.decision.ab_dominated);

    let report = compare(&fixture);
    assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
    assert_eq!(report.verdict.reason, CampaignVerdictReason::AbDominated);
    assert_ne!(report.verdict.reason, CampaignVerdictReason::NoHeldOutWin);
    assert_eq!(
        report.verdict.verdict.predicate(),
        EXPERIMENT_VERDICT_DISCARD
    );
}

#[test]
fn sub_epsilon_net_gain_discards() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.62),
        0.0,
    );
    assert!(fixture.decision.tournament_wins_held_out);
    assert!(!fixture.decision.ab_dominated);

    let report = compare(&fixture);
    assert!(report.verdict.net_delta < report.verdict_epsilon);
    assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
    assert_eq!(
        report.verdict.reason,
        CampaignVerdictReason::QualityDeltaBelowEpsilon
    );
}

#[test]
fn no_held_out_win_discards_even_if_search_wins() {
    // The tournament arm wins the search split by a wide margin and still
    // loses: only the held-out split can yield a keep.
    let fixture = campaign_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(1.50, 0.80),
        SplitFixture::passed(0.90, 0.95),
        SplitFixture::passed(0.20, 0.70),
        0.0,
    );
    assert!(
        fixture.tournament.search.effective_taste_score
            > fixture.single_pass.search.effective_taste_score
    );
    assert!(!fixture.decision.tournament_wins_held_out);
    assert!(!fixture.decision.ab_dominated);

    let report = compare(&fixture);
    assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
    assert_eq!(report.verdict.reason, CampaignVerdictReason::NoHeldOutWin);
}

#[test]
fn smoke_kill_zeroes_score_and_discards() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::killed(0.90, 0.95, "tournament smoke gate tripped"),
        0.02,
    );

    // Raw metric and cost rows survive the kill; only the effective score
    // is zeroed.
    let held_out = &fixture.tournament.held_out;
    assert_eq!(held_out.effective_taste_score, 0.0);
    assert_eq!(held_out.taste.score, 0.95);
    assert_eq!(held_out.cost.cost_usd, 0.90);
    assert!(held_out.of360.report.metrics.halumem_recall.value.is_some());

    let report = compare(&fixture);
    assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
    assert_eq!(report.verdict.reason, CampaignVerdictReason::SmokeKilled);
    assert_eq!(report.verdict.quality_delta, fixture.decision.quality_delta);
    assert_eq!(report.verdict.cost_penalty, 0.02);
    assert_eq!(
        report.verdict.net_delta,
        fixture.decision.quality_delta - 0.02
    );
    assert!(report.verdict.quality_delta < 0.0);
}

#[test]
fn smoke_killed_baseline_cannot_yield_keep() {
    let fixture = held_out_fixture(
        SplitFixture::killed(0.20, 0.80, "single-pass smoke gate tripped"),
        SplitFixture::passed(0.90, 0.70),
        0.01,
    );
    // Every later rung would have kept: the killed baseline still wins.
    assert!(fixture.decision.tournament_wins_held_out);
    assert!(!fixture.decision.ab_dominated);
    assert!(fixture.decision.quality_delta - fixture.decision.cost_penalty > 0.05);

    let report = compare(&fixture);
    assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
    assert_eq!(report.verdict.reason, CampaignVerdictReason::SmokeKilled);
}

#[test]
fn deserialized_forged_keep_after_smoke_kill_is_rejected() {
    let fixture = held_out_fixture(
        SplitFixture::killed(0.20, 0.80, "single-pass smoke gate tripped"),
        SplitFixture::passed(0.90, 0.70),
        0.01,
    );
    let report = compare(&fixture);
    assert_eq!(report.verdict.reason, CampaignVerdictReason::SmokeKilled);

    // Only the verdict pair is forged: every numeric still matches, so the
    // rejection can only come from replaying the precedence ladder.
    let mut json = serde_json::to_value(&report).expect("report encodes");
    *json.pointer_mut("/verdict/verdict").expect("verdict node") = serde_json::Value::from("keep");
    *json.pointer_mut("/verdict/reason").expect("reason node") =
        serde_json::Value::from("held_out_win_net_of_cost");
    let forged: CampaignComparisonReport =
        serde_json::from_value(json).expect("forged report decodes");
    assert_eq!(forged.verdict.verdict, ExperimentVerdict::Keep);
    assert_eq!(forged.verdict.quality_delta, report.verdict.quality_delta);
    assert_eq!(forged.verdict.net_delta, report.verdict.net_delta);

    let err = forged
        .validate()
        .expect_err("a forged keep after a smoke-killed baseline is refused");
    assert!(matches!(
        err,
        CampaignError::InvalidDecision {
            field: "verdict",
            ..
        }
    ));
}

#[test]
fn live_split_effective_score_equals_taste_score() {
    let config = test_config();
    let dataset = split_dataset(2);
    let passed = split_report(
        &config,
        CampaignExecutableArm::SinglePass,
        CampaignEvaluationSplit::HeldOut,
        &dataset,
        SplitFixture::passed(0.30, 0.72),
    );
    assert_eq!(passed.effective_taste_score, passed.taste.score);
    assert_eq!(passed.effective_taste_score, 0.72);

    let mut json = serde_json::to_value(&passed).expect("report encodes");
    *json
        .pointer_mut("/effective_taste_score")
        .expect("score node") = serde_json::Value::from(0.10);
    let decoded: CampaignSplitReport = serde_json::from_value(json).expect("report decodes");
    assert!(matches!(
        decoded.validate(),
        Err(CampaignError::ReportMismatch { .. })
    ));

    let stopped = split_report(
        &config,
        CampaignExecutableArm::SinglePass,
        CampaignEvaluationSplit::HeldOut,
        &dataset,
        SplitFixture::killed(0.30, 0.72, "smoke gate tripped"),
    );
    assert_eq!(stopped.effective_taste_score, 0.0);

    let mut json = serde_json::to_value(&stopped).expect("report encodes");
    *json
        .pointer_mut("/effective_taste_score")
        .expect("score node") = serde_json::Value::from(0.72);
    let decoded: CampaignSplitReport = serde_json::from_value(json).expect("report decodes");
    assert!(matches!(
        decoded.validate(),
        Err(CampaignError::ReportMismatch { .. })
    ));
}

#[test]
fn fabricated_held_out_win_is_rejected() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.80),
        SplitFixture::passed(0.90, 0.60),
        0.01,
    );
    assert!(!fixture.decision.tournament_wins_held_out);
    assert!(fixture.decision.ab_dominated);

    let fabrications: [(&str, DecisionMutation); 3] = [
        ("tournament_wins_held_out", |decision| {
            decision.tournament_wins_held_out = true;
        }),
        ("quality_delta", |decision| {
            decision.quality_delta = 0.5;
        }),
        ("ab_dominated", |decision| {
            decision.ab_dominated = !decision.ab_dominated;
        }),
    ];
    for (field, fabricate) in fabrications {
        let mut decision = fixture.decision.clone();
        fabricate(&mut decision);
        let err = compare_campaign(
            AttemptId::now(),
            &fixture.config,
            fixture.single_pass.clone(),
            fixture.tournament.clone(),
            decision,
        )
        .expect_err("a fabricated decision field is refused");
        match err {
            CampaignError::InvalidDecision { field: actual, .. } => {
                assert_eq!(actual, field);
            }
            other => panic!("expected an invalid decision field, got {other:?}"),
        }
    }
}

#[test]
fn blind_judge_payload_rejects_strategy_and_round_identity() {
    let config = test_config();
    let payload = BlindCampaignJudgeInput {
        claim: "Late caffeine tracks lighter sleep.".to_owned(),
        evidence_refs: vec!["obs:campaign:1".to_owned()],
        held_out_gold: held_out_anchor(&config),
    };

    let value = serde_json::to_value(&payload).expect("payload encodes");
    let object = value.as_object().expect("payload is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["claim", "evidence_refs", "held_out_gold"]);

    for leak in [
        "strategy",
        "round",
        "run_id",
        "arm",
        "candidate_ref",
        "model_tier",
        "campaign_ref",
    ] {
        let mut leaked = object.clone();
        leaked.insert(leak.to_owned(), serde_json::Value::from("leaked"));
        let decoded =
            serde_json::from_value::<BlindCampaignJudgeInput>(serde_json::Value::Object(leaked));
        assert!(
            decoded.is_err(),
            "the judge payload must refuse a `{leak}` field"
        );
    }
}

#[test]
fn held_out_anchor_must_match_external_gold() {
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.60),
        SplitFixture::passed(0.90, 0.80),
        0.01,
    );
    let anchors = [
        CampaignGoldAnchor {
            dataset_id: fixture.config.splits.search.dataset_id.clone(),
            revision: fixture.config.splits.search.revision.clone(),
            gold_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
        },
        CampaignGoldAnchor {
            dataset_id: "caller-invented-dataset".to_owned(),
            revision: "caller-invented-revision".to_owned(),
            gold_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
        },
        CampaignGoldAnchor {
            gold_digest: "sha256:self-generated-anchor".to_owned(),
            ..held_out_anchor(&fixture.config)
        },
    ];

    for anchor in anchors {
        let err = build_campaign_held_out_decision(
            &fixture.single_pass,
            &fixture.tournament,
            0.01,
            anchor.clone(),
        )
        .expect_err("the decision builder refuses a foreign anchor");
        assert!(matches!(err, CampaignError::HeldOutAnchorMismatch));

        let mut decision = fixture.decision.clone();
        decision.external_anchor = anchor;
        let err = compare_campaign(
            AttemptId::now(),
            &fixture.config,
            fixture.single_pass.clone(),
            fixture.tournament.clone(),
            decision,
        )
        .expect_err("the comparison builder refuses a foreign anchor");
        assert!(matches!(err, CampaignError::HeldOutAnchorMismatch));
    }
}

#[test]
fn campaign_scope_guards_exclude_unrelated_symbols() {
    assert!(!MODULE_SOURCE.contains(concat!("Companion", "Mem")));
    assert!(!MODULE_SOURCE.contains(concat!("oneiron", "_bench")));
    assert!(!MODULE_SOURCE.contains(concat!("interface", "_bench")));
    assert!(!MODULE_SOURCE.contains(concat!("Evaluation", "Split::Sealed")));
}
