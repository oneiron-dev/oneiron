use rmpv::Value;

use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::critic::{
    CriticLens, CritiqueArtifact, CritiqueProvenance, CritiqueSeverity, CritiqueVerdict,
    LensCatalog,
};
use crate::dreamer_runner::{
    DreamerClaimAuthoringBatchTier, DreamerClaimAuthoringGateDecision,
    DreamerClaimAuthoringSchedule, DreamerClaimEvidenceState, DreamerTournamentClaim,
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
    OF360_SCHEMA_VERSION, Of360CaseExtractionOutput, Of360ExtractedClaim, Of360ExtractionRun,
    Of360ExtractionScore, Of360GoldDataset, Of360GoldMatch, Of360SeededSubsetConfig,
    generate_of360_seeded_gold_subset,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::*;

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
}

struct CampaignFixture {
    config: CampaignConfig,
    single_pass: CampaignArmReport,
    tournament: CampaignArmReport,
    decision: CampaignHeldOutDecision,
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
            qa_answers: Vec::new(),
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
fn deserialized_net_delta_drift_is_rejected() {
    // Exact binary verdict operands isolate tampering from decimal round-off.
    let fixture = held_out_fixture(
        SplitFixture::passed(0.20, 0.50),
        SplitFixture::passed(0.90, 0.75),
        0.125,
    );
    let report = compare(&fixture);
    assert_eq!(report.verdict.net_delta, 0.125);

    let encoded = serde_json::to_string(&report).expect("report encodes");
    let decoded: CampaignComparisonReport = serde_json::from_str(&encoded).expect("report decodes");
    assert_eq!(decoded.verdict.net_delta, 0.125);
    assert_eq!(decoded.verdict.quality_delta, report.verdict.quality_delta);
    assert_eq!(decoded.verdict.cost_penalty, report.verdict.cost_penalty);
    assert_eq!(decoded.verdict.verdict, report.verdict.verdict);
    assert_eq!(decoded.verdict.reason, report.verdict.reason);
    decoded.validate().expect("unchanged report validates");

    // Alter only the encoded net delta; the decision and verdict pair stay intact.
    let mut json = serde_json::to_value(&report).expect("report encodes");
    *json
        .pointer_mut("/verdict/net_delta")
        .expect("net delta node") = serde_json::Value::from(1.0);
    let encoded = serde_json::to_string(&json).expect("tampered report encodes");
    let decoded: CampaignComparisonReport =
        serde_json::from_str(&encoded).expect("numeric drift still decodes");
    let mut forged = report;
    forged.verdict.net_delta = 1.0;
    assert_eq!(
        decoded.verdict.net_delta, 1.0,
        "decode must preserve the tampered net delta",
    );
    assert_eq!(decoded.verdict.verdict, forged.verdict.verdict);
    assert_eq!(decoded.verdict.reason, forged.verdict.reason);
    assert_eq!(decoded.verdict.quality_delta, forged.verdict.quality_delta);
    assert_eq!(decoded.verdict.cost_penalty, forged.verdict.cost_penalty);
    assert_eq!(
        decoded.decision.tournament_wins_held_out,
        forged.decision.tournament_wins_held_out,
    );
    assert_eq!(decoded.decision.ab_dominated, forged.decision.ab_dominated);
    assert_eq!(
        decoded.decision.quality_delta,
        forged.decision.quality_delta
    );
    assert_eq!(decoded.decision.cost_penalty, forged.decision.cost_penalty);

    for report in [forged, decoded] {
        assert!(matches!(
            report.validate(),
            Err(CampaignError::InvalidDecision {
                field: "verdict",
                ..
            })
        ));
    }
}
