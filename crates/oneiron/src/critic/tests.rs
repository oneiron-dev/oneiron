use super::*;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::test_util::embedding_test_config;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(embedding_test_config())
}

fn provenance() -> CritiqueProvenance {
    CritiqueProvenance::new("critic_groundedness", "model-a", Some("rev1".to_owned()))
        .expect("valid provenance")
}

fn critique(
    artifact_id: &str,
    lens: &CriticLens,
    verdict: CritiqueVerdict,
    severity: CritiqueSeverity,
    hard_check_passed: Option<bool>,
) -> CritiqueArtifact {
    CritiqueArtifact::new(
        artifact_id,
        "run-a",
        AttemptId::now(),
        "candidate-a",
        lens,
        provenance(),
        verdict,
        severity,
        hard_check_passed,
        vec!["evidence:1".to_owned()],
        Some("tighten scope".to_owned()),
        10,
    )
    .expect("valid critique")
}

#[test]
fn of366_seed_catalog_loads_as_data() -> Result<()> {
    let catalog = LensCatalog::of366_seed()?;
    let ids = catalog
        .lenses
        .iter()
        .map(|lens| lens.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        ids,
        vec!["groundedness", "overreach", "temporal", "redundancy"]
    );
    assert!(
        catalog
            .lens("groundedness", "claim_authoring")
            .expect("seed lens")
            .hard_check
    );
    Ok(())
}

#[test]
fn hard_check_failure_vetoes_to_discard() -> Result<()> {
    let catalog = LensCatalog::of366_seed()?;
    let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();
    let overreach = catalog.lens("overreach", "claim_authoring").unwrap();
    let critiques = vec![
        critique(
            "groundedness_fail",
            groundedness,
            CritiqueVerdict::Revise,
            CritiqueSeverity::Blocking,
            Some(false),
        ),
        critique(
            "overreach_accept",
            overreach,
            CritiqueVerdict::Accept,
            CritiqueSeverity::Info,
            None,
        ),
    ];

    let triage = triage_critiques(&catalog, &critiques, &[])?;

    assert_eq!(triage.verdict, CritiqueVerdict::Discard);
    assert_eq!(triage.hard_veto_artifact_ids, vec!["groundedness_fail"]);
    Ok(())
}

#[test]
fn hard_check_missing_status_vetoes_to_discard() -> Result<()> {
    let catalog = LensCatalog::of366_seed()?;
    let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();
    let critiques = vec![critique(
        "groundedness_missing_status",
        groundedness,
        CritiqueVerdict::Accept,
        CritiqueSeverity::Info,
        None,
    )];

    let triage = triage_critiques(&catalog, &critiques, &[])?;

    assert_eq!(triage.verdict, CritiqueVerdict::Discard);
    assert_eq!(
        triage.hard_veto_artifact_ids,
        vec!["groundedness_missing_status"]
    );
    assert_eq!(
        triage.acted_on_artifact_ids,
        vec!["groundedness_missing_status"]
    );
    Ok(())
}

#[test]
fn beta_weighted_soft_aggregation_uses_ucb_for_cold_lens() -> Result<()> {
    let catalog = LensCatalog::of366_seed()?;
    let overreach = catalog.lens("overreach", "claim_authoring").unwrap();
    let temporal = catalog.lens("temporal", "claim_authoring").unwrap();
    let critiques = vec![
        critique(
            "trusted_accept",
            overreach,
            CritiqueVerdict::Accept,
            CritiqueSeverity::Medium,
            None,
        ),
        critique(
            "cold_revise",
            temporal,
            CritiqueVerdict::Revise,
            CritiqueSeverity::High,
            None,
        ),
    ];
    let reliabilities = vec![CriticReliability::new(
        "overreach",
        "claim_authoring",
        19.0,
        1.0,
        20,
    )?];

    let triage = triage_critiques_with_exploration(&catalog, &critiques, &reliabilities, 0.75)?;

    assert_eq!(triage.verdict, CritiqueVerdict::Revise);
    assert!(triage.scores.revise > triage.scores.accept);
    assert_eq!(triage.acted_on_artifact_ids, vec!["cold_revise"]);
    Ok(())
}

#[test]
fn soft_triage_accept_wins_when_accept_score_is_highest() -> Result<()> {
    let catalog = LensCatalog::of366_seed()?;
    let overreach = catalog.lens("overreach", "claim_authoring").unwrap();
    let temporal = catalog.lens("temporal", "claim_authoring").unwrap();
    let critiques = vec![
        critique(
            "trusted_accept",
            overreach,
            CritiqueVerdict::Accept,
            CritiqueSeverity::Info,
            None,
        ),
        critique(
            "weak_revise",
            temporal,
            CritiqueVerdict::Revise,
            CritiqueSeverity::Info,
            None,
        ),
    ];
    let reliabilities = vec![
        CriticReliability::new("overreach", "claim_authoring", 20.0, 1.0, 21)?,
        CriticReliability::new("temporal", "claim_authoring", 1.0, 20.0, 21)?,
    ];

    let triage = triage_critiques_with_exploration(&catalog, &critiques, &reliabilities, 0.0)?;

    assert_eq!(triage.verdict, CritiqueVerdict::Accept);
    assert!(triage.scores.accept > triage.scores.revise);
    Ok(())
}

#[test]
fn reliability_updates_require_anchored_outcomes() -> Result<()> {
    let mut reliability = CriticReliability::prior("groundedness", "claim_authoring")?;
    let rejected = ReliabilityOutcomeEvent::new(
        "groundedness",
        "claim_authoring",
        ReliabilityOutcomeSource::CriticAgreement,
        true,
        10,
    )?;

    assert!(reliability.apply_outcome(rejected).is_err());
    assert_eq!(reliability.alpha, 1.0);
    assert_eq!(reliability.beta, 1.0);
    assert_eq!(reliability.observations, 0);

    reliability.apply_outcome(ReliabilityOutcomeEvent::new(
        "groundedness",
        "claim_authoring",
        ReliabilityOutcomeSource::Beam,
        false,
        11,
    )?)?;
    assert_eq!(reliability.alpha, 1.0);
    assert_eq!(reliability.beta, 2.0);
    assert_eq!(reliability.observations, 1);
    Ok(())
}

#[test]
fn critique_artifacts_persist_branch_local_and_not_as_claims() -> Result<()> {
    let (_dir, vault) = open_vault();
    let catalog = LensCatalog::of366_seed()?;
    let lens = catalog.lens("groundedness", "claim_authoring").unwrap();
    let branch_attempt = AttemptId::now();
    let mut artifact = critique(
        "groundedness_ok",
        lens,
        CritiqueVerdict::Accept,
        CritiqueSeverity::Info,
        Some(true),
    );
    artifact.branch_attempt = branch_attempt;
    let before_claims = vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?;

    let store = CritiqueArtifactStore::new(&vault);
    store.put(&artifact)?;

    assert_eq!(
        store.get(branch_attempt, "groundedness_ok")?,
        Some(artifact.clone())
    );
    assert_eq!(store.list_branch(branch_attempt)?, vec![artifact]);
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?,
        before_claims
    );
    Ok(())
}

#[test]
fn out_of_scope_critique_artifacts_are_not_persisted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let catalog = LensCatalog::of366_seed()?;
    let lens = catalog.lens("overreach", "claim_authoring").unwrap();
    let branch_attempt = AttemptId::now();
    let mut artifact = critique(
        "overreach_out_of_scope",
        lens,
        CritiqueVerdict::Revise,
        CritiqueSeverity::High,
        None,
    );
    artifact.branch_attempt = branch_attempt;
    artifact.out_of_scope = true;

    let store = CritiqueArtifactStore::new(&vault);
    store.put(&artifact)?;

    assert_eq!(store.get(branch_attempt, "overreach_out_of_scope")?, None);
    assert!(store.list_branch(branch_attempt)?.is_empty());
    Ok(())
}

#[test]
fn two_candidate_four_lens_fixture_triages_independently() -> Result<()> {
    let catalog = LensCatalog::of366_seed()?;
    let reliability = catalog
        .lenses
        .iter()
        .map(|lens| CriticReliability::new(&lens.id, &lens.domain, 4.0, 2.0, 6))
        .collect::<Result<Vec<_>>>()?;

    let candidate_a = catalog
        .lenses
        .iter()
        .map(|lens| {
            critique(
                &format!("candidate_a_{}", lens.id),
                lens,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                lens.hard_check.then_some(true),
            )
        })
        .collect::<Vec<_>>();
    let candidate_b = catalog
        .lenses
        .iter()
        .map(|lens| {
            let verdict = if lens.id == "overreach" || lens.id == "temporal" {
                CritiqueVerdict::Revise
            } else {
                CritiqueVerdict::Accept
            };
            critique(
                &format!("candidate_b_{}", lens.id),
                lens,
                verdict,
                CritiqueSeverity::High,
                lens.hard_check.then_some(true),
            )
        })
        .collect::<Vec<_>>();

    let triage_a = triage_critiques(&catalog, &candidate_a, &reliability)?;
    let triage_b = triage_critiques(&catalog, &candidate_b, &reliability)?;

    assert_eq!(triage_a.verdict, CritiqueVerdict::Accept);
    assert_eq!(triage_b.verdict, CritiqueVerdict::Revise);
    assert_eq!(triage_a.acted_on_artifact_ids, Vec::<String>::new());
    assert_eq!(
        triage_b.acted_on_artifact_ids,
        vec!["candidate_b_overreach", "candidate_b_temporal"]
    );
    Ok(())
}

#[test]
fn reliability_claim_family_is_structured_under_critic_reliability() -> Result<()> {
    let subject = EntityId::now();
    let reliability = CriticReliability::new("temporal", "claim_authoring", 3.0, 1.0, 4)?;
    let body = critic_reliability_claim_body(subject, &reliability, 0.9)?;

    assert_eq!(
        body.predicate,
        "critic_reliability.claim_authoring.temporal"
    );
    assert_eq!(body.subject, ClaimSubject::Entity(subject));
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(body.confidence, 0.9);

    let (_dir, vault) = open_vault();
    let anchor = EntityId::now();
    vault.put_entity(
        &anchor,
        crate::registry::ENTITY_TYPE_TASK,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;
    let mut writable = body;
    writable.subject = ClaimSubject::Entity(anchor);
    vault.put_claim(
        &EntityId::now(),
        &writable,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    Ok(())
}

#[test]
fn critic_reliability_predicate_rejects_claim_predicate_overflow() {
    let domain = "d".repeat(MAX_DOMAIN_BYTES);
    let lens_id = "l".repeat(MAX_ID_BYTES);

    assert!(critic_reliability_predicate(&domain, &lens_id).is_err());
}
