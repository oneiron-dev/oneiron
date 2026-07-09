use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::critic::{
    CriticLens, CritiqueArtifact, CritiqueArtifactStore, CritiqueProvenance, CritiqueSeverity,
    CritiqueVerdict, LensCatalog,
};
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteProvenance;

use super::*;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn test_envelope(vault: &Vault) -> Result<(EntityId, EntityId, WriteEnvelope)> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("of366-tournament-fixture"))?,
        ClaimApprovalStatus::Approved,
    );
    Ok((actor, subject, envelope))
}

fn candidate(
    subject: EntityId,
    candidate_ref: &str,
    branch_job: JobId,
    claim_id: EntityId,
    claim_text: &str,
    strategy: &str,
    round: u16,
) -> Result<DreamerTournamentCandidate> {
    DreamerTournamentCandidate::new(
        candidate_ref,
        branch_job,
        claim_id,
        ClaimCandidate::new(
            "pattern.sleep",
            ClaimSubject::Entity(subject),
            Value::from(claim_text),
            0.8,
        )
        .with_evidence(Value::from(format!("evidence:{candidate_ref}"))),
        DreamerTournamentJudgeClaim::new(
            claim_text,
            vec!["obs:fixture:1".to_owned(), "obs:fixture:2".to_owned()],
        )?,
        strategy,
        round,
    )
}

fn critique(
    candidate: &DreamerTournamentCandidate,
    lens: &CriticLens,
    artifact_id: &str,
    verdict: CritiqueVerdict,
    severity: CritiqueSeverity,
    hard_check_passed: Option<bool>,
) -> Result<CritiqueArtifact> {
    CritiqueArtifact::new(
        artifact_id,
        "run-fixture",
        candidate.branch_job,
        candidate.candidate_ref.clone(),
        lens,
        CritiqueProvenance::new(
            format!("critic:{}", lens.id),
            "fixture-model",
            Some("rev1".to_owned()),
        )?,
        verdict,
        severity,
        hard_check_passed,
        candidate.judge_claim.evidence_refs.clone(),
        None,
        10,
    )
}

fn of366_lenses(catalog: &LensCatalog) -> [&CriticLens; 4] {
    [
        catalog.lens("groundedness", "claim_authoring").unwrap(),
        catalog.lens("overreach", "claim_authoring").unwrap(),
        catalog.lens("temporal", "claim_authoring").unwrap(),
        catalog.lens("redundancy", "claim_authoring").unwrap(),
    ]
}

fn accept_critiques(
    candidate: &DreamerTournamentCandidate,
    catalog: &LensCatalog,
    prefix: &str,
) -> Result<Vec<CritiqueArtifact>> {
    of366_lenses(catalog)
        .iter()
        .map(|lens| {
            critique(
                candidate,
                lens,
                &format!("{prefix}_{}", lens.id),
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                lens.hard_check.then_some(true),
            )
        })
        .collect()
}

fn revise_critiques(
    candidate: &DreamerTournamentCandidate,
    catalog: &LensCatalog,
    prefix: &str,
) -> Result<Vec<CritiqueArtifact>> {
    of366_lenses(catalog)
        .iter()
        .map(|lens| {
            critique(
                candidate,
                lens,
                &format!("{prefix}_{}", lens.id),
                CritiqueVerdict::Revise,
                CritiqueSeverity::Blocking,
                lens.hard_check.then_some(true),
            )
        })
        .collect()
}

fn discard_critiques(
    candidate: &DreamerTournamentCandidate,
    catalog: &LensCatalog,
    prefix: &str,
) -> Result<Vec<CritiqueArtifact>> {
    of366_lenses(catalog)
        .iter()
        .map(|lens| {
            let is_groundedness = lens.id == "groundedness";
            critique(
                candidate,
                lens,
                &format!("{prefix}_{}", lens.id),
                if is_groundedness {
                    CritiqueVerdict::Discard
                } else {
                    CritiqueVerdict::Accept
                },
                if is_groundedness {
                    CritiqueSeverity::Blocking
                } else {
                    CritiqueSeverity::Info
                },
                if is_groundedness { Some(false) } else { None },
            )
        })
        .collect()
}

fn author_fork(
    seed_ref: &str,
    branches: &[&DreamerTournamentCandidate],
) -> Result<DreamerTournamentAuthorFork> {
    DreamerTournamentAuthorFork::new(
        seed_ref,
        JobId::now(),
        branches
            .iter()
            .map(|candidate| candidate.branch_job)
            .collect(),
    )
}

fn accept_branch(
    candidate: DreamerTournamentCandidate,
    catalog: &LensCatalog,
    artifact_prefix: &str,
) -> Result<DreamerTournamentBranch> {
    DreamerTournamentBranch::new(
        candidate.clone(),
        accept_critiques(&candidate, catalog, artifact_prefix)?,
        DreamerTournamentSynthesisArtifact::survivor(
            format!("{artifact_prefix}_synthesis"),
            &candidate,
        )?,
    )
}

#[test]
fn author_fork_must_match_first_round_sibling_branches() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let left = candidate(
        subject,
        "fork-left",
        JobId::now(),
        EntityId::now(),
        "Fork left claim.",
        "seed-a",
        1,
    )?;
    let right = candidate(
        subject,
        "fork-right",
        JobId::now(),
        EntityId::now(),
        "Fork right claim.",
        "seed-b",
        1,
    )?;
    let stray = candidate(
        subject,
        "fork-stray",
        JobId::now(),
        EntityId::now(),
        "Fork stray claim.",
        "seed-c",
        1,
    )?;
    let fork = author_fork("author-seed-mismatch", &[&left, &right])?;

    let run = DreamerTournamentRun::new(
        "run-fork-mismatch",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                accept_branch(left, &catalog, "fork_left")?,
                accept_branch(stray, &catalog, "fork_stray")?,
            ],
            None,
            vec![DreamerTournamentBordaBallot::new("judge-a", vec![0, 1])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    );

    assert!(run.is_err());
    Ok(())
}

#[test]
fn fixture_corpus_tournament_writes_winner_through_normal_claim_path() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;

    let left = candidate(
        subject,
        "candidate-left",
        JobId::now(),
        EntityId::now(),
        "Sleep gets lighter after late caffeine in the fixture corpus.",
        "seed-a",
        1,
    )?;
    let right = candidate(
        subject,
        "candidate-right",
        JobId::now(),
        EntityId::now(),
        "Fixture evidence supports earlier caffeine cutoff improving sleep.",
        "seed-b",
        1,
    )?;
    let winner_id = right.claim_id;
    let fork = author_fork("author-seed-fixture", &[&left, &right])?;

    let run = DreamerTournamentRun::new(
        "run-fixture",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                accept_branch(left, &catalog, "left")?,
                accept_branch(right, &catalog, "right")?,
            ],
            None,
            vec![
                DreamerTournamentBordaBallot::new("judge-a", vec![1, 0])?,
                DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
            ],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;

    let result = run_dreamer_claim_tournament(&vault, run)?;
    assert_eq!(result.winner.claim_id, winner_id);
    assert_eq!(result.stop_reason, DreamerTournamentStopReason::Consensus);
    assert_eq!(result.rounds_executed, 1);

    let stored = vault.get_claim(&winner_id)?.expect("winner claim stored");
    assert_eq!(stored.predicate, "pattern.sleep");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
    assert_eq!(vault.claims_for_subject(&subject)?, vec![winner_id]);
    Ok(())
}

#[test]
fn blind_judging_context_omits_strategy_and_round_metadata() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let left = candidate(
        subject,
        "candidate-alpha",
        JobId::now(),
        EntityId::now(),
        "The corpus supports an evening routine pattern.",
        "strategy-secret-alpha",
        1,
    )?;
    let right = candidate(
        subject,
        "candidate-beta",
        JobId::now(),
        EntityId::now(),
        "The corpus supports a morning focus pattern.",
        "strategy-secret-beta",
        1,
    )?;
    let fork = author_fork("author-seed-blind", &[&left, &right])?;

    let result = run_dreamer_claim_tournament(
        &vault,
        DreamerTournamentRun::new(
            "run-blind",
            fork,
            2,
            2,
            vec![DreamerTournamentRound::new(
                vec![
                    accept_branch(left, &catalog, "alpha")?,
                    accept_branch(right, &catalog, "beta")?,
                ],
                None,
                vec![DreamerTournamentBordaBallot::new("judge", vec![0, 1])?],
            )?],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )?,
    )?;

    for context in result.blind_contexts {
        let debug = format!("{context:?}");
        assert!(!debug.contains("strategy-secret"));
        assert!(!debug.contains("round"));
        assert!(!debug.contains("candidate-alpha"));
        assert!(!debug.contains("candidate-beta"));
    }
    Ok(())
}

#[test]
fn discard_path_preserves_branch_evidence_and_critique_artifacts() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;

    let rejected = candidate(
        subject,
        "candidate-rejected",
        JobId::now(),
        EntityId::now(),
        "Ungrounded fixture generalization.",
        "seed-a",
        1,
    )?;
    let survivor = candidate(
        subject,
        "candidate-survivor",
        JobId::now(),
        EntityId::now(),
        "Grounded fixture generalization.",
        "seed-b",
        1,
    )?;
    let rejected_branch_job = rejected.branch_job;
    let rejected_claim_id = rejected.claim_id;
    let fork = author_fork("author-seed-discard", &[&rejected, &survivor])?;

    let rejected_branch = DreamerTournamentBranch::new(
        rejected.clone(),
        discard_critiques(&rejected, &catalog, "rejected")?,
        DreamerTournamentSynthesisArtifact::discarded("rejected_synthesis", &rejected)?,
    )?;
    let run = DreamerTournamentRun::new(
        "run-discard",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                rejected_branch,
                accept_branch(survivor, &catalog, "survivor")?,
            ],
            None,
            vec![DreamerTournamentBordaBallot::new("judge", vec![0])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;

    let result = run_dreamer_claim_tournament(&vault, run)?;
    assert!(
        result.branch_evidence.iter().any(|evidence| {
            evidence.candidate_ref == "candidate-rejected"
                && evidence.claim_id == rejected_claim_id.to_hex()
                && evidence.verdict == DreamerTournamentBranchVerdict::Discarded
                && evidence.hard_veto_artifact_ids == vec!["rejected_groundedness"]
        }),
        "discarded candidate must stay in branch evidence"
    );
    let persisted = DreamerTournamentEvidenceStore::new(&vault).list_run("run-discard")?;
    assert!(persisted.iter().any(|evidence| {
        evidence.candidate_ref == "candidate-rejected"
            && evidence.verdict == DreamerTournamentBranchVerdict::Discarded
    }));
    let critiques = CritiqueArtifactStore::new(&vault).list_branch(rejected_branch_job)?;
    assert_eq!(critiques.len(), 4);
    assert!(
        critiques
            .iter()
            .any(|critique| critique.artifact_id == "rejected_groundedness")
    );
    Ok(())
}

#[test]
fn k_cap_and_early_stop_behave() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;

    let round1_left = candidate(
        subject,
        "r1-left",
        JobId::now(),
        EntityId::now(),
        "Round one left.",
        "seed-a",
        1,
    )?;
    let round1_right = candidate(
        subject,
        "r1-right",
        JobId::now(),
        EntityId::now(),
        "Round one right.",
        "seed-b",
        1,
    )?;
    let round2_left = candidate(
        subject,
        "r2-left",
        JobId::now(),
        EntityId::now(),
        "Round two left.",
        "seed-a",
        2,
    )?;
    let round2_right = candidate(
        subject,
        "r2-right",
        JobId::now(),
        EntityId::now(),
        "Round two right.",
        "seed-b",
        2,
    )?;
    let should_not_write = candidate(
        subject,
        "r3-left",
        JobId::now(),
        EntityId::now(),
        "Round three must not run.",
        "seed-a",
        2,
    )?;
    let fork = author_fork("author-seed-k-cap", &[&round1_left, &round1_right])?;

    let result = run_dreamer_claim_tournament(
        &vault,
        DreamerTournamentRun::new(
            "run-k-cap",
            fork,
            2,
            2,
            vec![
                DreamerTournamentRound::new(
                    vec![
                        accept_branch(round1_left, &catalog, "r1_left")?,
                        accept_branch(round1_right, &catalog, "r1_right")?,
                    ],
                    None,
                    vec![
                        DreamerTournamentBordaBallot::new("judge-a", vec![0, 1])?,
                        DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
                    ],
                )?,
                DreamerTournamentRound::new(
                    vec![
                        accept_branch(round2_left, &catalog, "r2_left")?,
                        accept_branch(round2_right, &catalog, "r2_right")?,
                    ],
                    None,
                    vec![
                        DreamerTournamentBordaBallot::new("judge-a", vec![1, 0])?,
                        DreamerTournamentBordaBallot::new("judge-b", vec![0, 1])?,
                    ],
                )?,
                DreamerTournamentRound::new(
                    vec![accept_branch(
                        should_not_write.clone(),
                        &catalog,
                        "r3_left",
                    )?],
                    None,
                    vec![DreamerTournamentBordaBallot::new("judge-a", vec![0])?],
                )?,
            ],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )?,
    )?;
    assert_eq!(result.rounds_executed, 2);
    assert_eq!(result.stop_reason, DreamerTournamentStopReason::RoundCap);
    assert!(vault.get_claim(&should_not_write.claim_id)?.is_none());

    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let left = candidate(
        subject,
        "early-left",
        JobId::now(),
        EntityId::now(),
        "Early stop left.",
        "seed-a",
        1,
    )?;
    let right = candidate(
        subject,
        "early-right",
        JobId::now(),
        EntityId::now(),
        "Early stop right.",
        "seed-b",
        1,
    )?;
    let late = candidate(
        subject,
        "late",
        JobId::now(),
        EntityId::now(),
        "Should not run after consensus.",
        "seed-a",
        2,
    )?;
    let fork = author_fork("author-seed-early", &[&left, &right])?;
    let result = run_dreamer_claim_tournament(
        &vault,
        DreamerTournamentRun::new(
            "run-early",
            fork,
            2,
            2,
            vec![
                DreamerTournamentRound::new(
                    vec![
                        accept_branch(left, &catalog, "early_left")?,
                        accept_branch(right, &catalog, "early_right")?,
                    ],
                    None,
                    vec![
                        DreamerTournamentBordaBallot::new("judge-a", vec![0, 1])?,
                        DreamerTournamentBordaBallot::new("judge-b", vec![0, 1])?,
                    ],
                )?,
                DreamerTournamentRound::new(
                    vec![accept_branch(late.clone(), &catalog, "late")?],
                    None,
                    vec![DreamerTournamentBordaBallot::new("judge-a", vec![0])?],
                )?,
            ],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )?,
    )?;
    assert_eq!(result.rounds_executed, 1);
    assert_eq!(result.stop_reason, DreamerTournamentStopReason::Consensus);
    assert!(vault.get_claim(&late.claim_id)?.is_none());
    Ok(())
}

#[test]
fn two_partial_survivors_use_lmx_weave_candidate() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;

    let left = candidate(
        subject,
        "partial-left",
        JobId::now(),
        EntityId::now(),
        "Left partial claim.",
        "seed-a",
        1,
    )?;
    let left_refined = candidate(
        subject,
        "partial-left-refined",
        left.branch_job,
        EntityId::now(),
        "Left refined claim.",
        "synthesis",
        1,
    )?;
    let right = candidate(
        subject,
        "partial-right",
        JobId::now(),
        EntityId::now(),
        "Right partial claim.",
        "seed-b",
        1,
    )?;
    let right_refined = candidate(
        subject,
        "partial-right-refined",
        right.branch_job,
        EntityId::now(),
        "Right refined claim.",
        "synthesis",
        1,
    )?;
    let weave = candidate(
        subject,
        "lmx-weave",
        JobId::now(),
        EntityId::now(),
        "LMX two-parent weave claim.",
        "lmx",
        1,
    )?;
    let weave_id = weave.claim_id;
    let fork = author_fork("author-seed-weave", &[&left, &right])?;
    let weave = DreamerTournamentWeaveArtifact::new(
        "lmx-weave-synthesis",
        vec![
            DreamerTournamentCandidateIdentity::from_candidate(&left_refined),
            DreamerTournamentCandidateIdentity::from_candidate(&right_refined),
        ],
        weave,
    )?;

    let run = DreamerTournamentRun::new(
        "run-weave",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                DreamerTournamentBranch::new(
                    left.clone(),
                    revise_critiques(&left, &catalog, "left")?,
                    DreamerTournamentSynthesisArtifact::refined(
                        "left_synthesis",
                        &left,
                        left_refined,
                    )?,
                )?,
                DreamerTournamentBranch::new(
                    right.clone(),
                    revise_critiques(&right, &catalog, "right")?,
                    DreamerTournamentSynthesisArtifact::refined(
                        "right_synthesis",
                        &right,
                        right_refined,
                    )?,
                )?,
            ],
            Some(weave),
            vec![DreamerTournamentBordaBallot::new("judge", vec![2, 0, 1])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;

    let result = run_dreamer_claim_tournament(&vault, run)?;
    assert_eq!(result.winner.claim_id, weave_id);
    assert!(result.branch_evidence.iter().any(|evidence| {
        evidence.candidate_ref == "lmx-weave"
            && evidence.verdict == DreamerTournamentBranchVerdict::Weaved
            && evidence.parent_candidate_refs.len() == 2
    }));
    assert!(vault.get_claim(&weave_id)?.is_some());
    Ok(())
}

#[test]
fn mc1_requires_four_unique_of366_lenses_and_artifact_ids() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, _envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let candidate = candidate(
        subject,
        "lens-candidate",
        JobId::now(),
        EntityId::now(),
        "Four lens claim.",
        "seed",
        1,
    )?;

    let mut missing = accept_critiques(&candidate, &catalog, "missing")?;
    missing.pop();
    assert!(
        DreamerTournamentBranch::new(
            candidate.clone(),
            missing,
            DreamerTournamentSynthesisArtifact::survivor("missing_synthesis", &candidate)?,
        )
        .is_err()
    );

    let mut duplicate_lens = accept_critiques(&candidate, &catalog, "duplicate_lens")?;
    let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();
    duplicate_lens[3] = critique(
        &candidate,
        groundedness,
        "duplicate_lens_groundedness_second",
        CritiqueVerdict::Accept,
        CritiqueSeverity::Info,
        Some(true),
    )?;
    assert!(
        DreamerTournamentBranch::new(
            candidate.clone(),
            duplicate_lens,
            DreamerTournamentSynthesisArtifact::survivor("duplicate_lens_synthesis", &candidate)?,
        )
        .is_err()
    );

    let mut duplicate_artifact = accept_critiques(&candidate, &catalog, "duplicate_artifact")?;
    duplicate_artifact[1].artifact_id = duplicate_artifact[0].artifact_id.clone();
    assert!(
        DreamerTournamentBranch::new(
            candidate.clone(),
            duplicate_artifact,
            DreamerTournamentSynthesisArtifact::survivor(
                "duplicate_artifact_synthesis",
                &candidate,
            )?,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn synthesis_verdict_must_match_triage() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let left = candidate(
        subject,
        "synthesis-left",
        JobId::now(),
        EntityId::now(),
        "Accepted synthesis claim.",
        "seed-a",
        1,
    )?;
    let right = candidate(
        subject,
        "synthesis-right",
        JobId::now(),
        EntityId::now(),
        "Second synthesis claim.",
        "seed-b",
        1,
    )?;
    let fork = author_fork("author-seed-synthesis", &[&left, &right])?;
    let run = DreamerTournamentRun::new(
        "run-synthesis-mismatch",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                DreamerTournamentBranch::new(
                    left.clone(),
                    accept_critiques(&left, &catalog, "synthesis_left")?,
                    DreamerTournamentSynthesisArtifact::discarded("synthesis_left_bad", &left)?,
                )?,
                accept_branch(right, &catalog, "synthesis_right")?,
            ],
            None,
            vec![DreamerTournamentBordaBallot::new("judge", vec![0, 1])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;
    assert!(run_dreamer_claim_tournament(&vault, run).is_err());
    Ok(())
}

#[test]
fn lmx_weave_must_name_exact_partial_survivor_parents() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let left = candidate(
        subject,
        "parent-left",
        JobId::now(),
        EntityId::now(),
        "Parent left.",
        "seed-a",
        1,
    )?;
    let left_refined = candidate(
        subject,
        "parent-left-refined",
        left.branch_job,
        EntityId::now(),
        "Parent left refined.",
        "synthesis",
        1,
    )?;
    let right = candidate(
        subject,
        "parent-right",
        JobId::now(),
        EntityId::now(),
        "Parent right.",
        "seed-b",
        1,
    )?;
    let right_refined = candidate(
        subject,
        "parent-right-refined",
        right.branch_job,
        EntityId::now(),
        "Parent right refined.",
        "synthesis",
        1,
    )?;
    let wrong_parent = candidate(
        subject,
        "wrong-parent",
        JobId::now(),
        EntityId::now(),
        "Wrong parent.",
        "synthesis",
        1,
    )?;
    let weave = candidate(
        subject,
        "bad-weave",
        JobId::now(),
        EntityId::now(),
        "Bad weave.",
        "lmx",
        1,
    )?;
    let fork = author_fork("author-seed-parent-mismatch", &[&left, &right])?;
    let run = DreamerTournamentRun::new(
        "run-parent-mismatch",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                DreamerTournamentBranch::new(
                    left.clone(),
                    revise_critiques(&left, &catalog, "parent_left")?,
                    DreamerTournamentSynthesisArtifact::refined(
                        "parent_left_synthesis",
                        &left,
                        left_refined.clone(),
                    )?,
                )?,
                DreamerTournamentBranch::new(
                    right.clone(),
                    revise_critiques(&right, &catalog, "parent_right")?,
                    DreamerTournamentSynthesisArtifact::refined(
                        "parent_right_synthesis",
                        &right,
                        right_refined,
                    )?,
                )?,
            ],
            Some(DreamerTournamentWeaveArtifact::new(
                "bad_weave_synthesis",
                vec![
                    DreamerTournamentCandidateIdentity::from_candidate(&left_refined),
                    DreamerTournamentCandidateIdentity::from_candidate(&wrong_parent),
                ],
                weave,
            )?),
            vec![DreamerTournamentBordaBallot::new("judge", vec![2, 0, 1])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;
    assert!(run_dreamer_claim_tournament(&vault, run).is_err());
    Ok(())
}

#[test]
fn evidence_key_keeps_same_candidate_ref_across_rounds() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let shared_id = EntityId::now();
    let shared_job = JobId::now();
    let round1_shared = candidate(
        subject,
        "repeat-ref",
        shared_job,
        shared_id,
        "Repeated round one claim.",
        "seed-a",
        1,
    )?;
    let round1_other = candidate(
        subject,
        "round-one-other",
        JobId::now(),
        EntityId::now(),
        "Round one other claim.",
        "seed-b",
        1,
    )?;
    let round2_shared = candidate(
        subject,
        "repeat-ref",
        shared_job,
        shared_id,
        "Repeated round two claim.",
        "seed-a",
        2,
    )?;
    let fork = author_fork("author-seed-repeat", &[&round1_shared, &round1_other])?;
    let run = DreamerTournamentRun::new(
        "run-repeat-ref",
        fork,
        2,
        2,
        vec![
            DreamerTournamentRound::new(
                vec![
                    accept_branch(round1_shared, &catalog, "repeat_r1")?,
                    accept_branch(round1_other, &catalog, "repeat_other")?,
                ],
                None,
                vec![
                    DreamerTournamentBordaBallot::new("judge-a", vec![0, 1])?,
                    DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
                ],
            )?,
            DreamerTournamentRound::new(
                vec![accept_branch(round2_shared, &catalog, "repeat_r2")?],
                None,
                vec![DreamerTournamentBordaBallot::new("judge-a", vec![0])?],
            )?,
        ],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;
    run_dreamer_claim_tournament(&vault, run)?;
    let persisted = DreamerTournamentEvidenceStore::new(&vault).list_run("run-repeat-ref")?;
    assert_eq!(
        persisted
            .iter()
            .filter(|evidence| evidence.candidate_ref == "repeat-ref")
            .count(),
        2
    );
    Ok(())
}

#[test]
fn late_error_does_not_leave_orphaned_critique_artifacts() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let rejected = candidate(
        subject,
        "late-rejected",
        JobId::now(),
        EntityId::now(),
        "Late rejected claim.",
        "seed-a",
        1,
    )?;
    let survivor = candidate(
        subject,
        "late-survivor",
        JobId::now(),
        EntityId::now(),
        "Late survivor claim.",
        "seed-b",
        1,
    )?;
    let rejected_job = rejected.branch_job;
    let survivor_job = survivor.branch_job;
    let fork = author_fork("author-seed-late-error", &[&rejected, &survivor])?;
    let run = DreamerTournamentRun::new(
        "run-late-error",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                DreamerTournamentBranch::new(
                    rejected.clone(),
                    discard_critiques(&rejected, &catalog, "late_rejected")?,
                    DreamerTournamentSynthesisArtifact::discarded(
                        "late_rejected_synthesis",
                        &rejected,
                    )?,
                )?,
                accept_branch(survivor, &catalog, "late_survivor")?,
            ],
            None,
            vec![DreamerTournamentBordaBallot::new("judge", vec![0, 1])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;
    assert!(run_dreamer_claim_tournament(&vault, run).is_err());
    let store = CritiqueArtifactStore::new(&vault);
    assert!(store.list_branch(rejected_job)?.is_empty());
    assert!(store.list_branch(survivor_job)?.is_empty());
    Ok(())
}

#[test]
fn refined_winner_persists_exact_selected_candidate_with_reused_identity() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let shared_claim_id = EntityId::now();
    let source = candidate(
        subject,
        "same-ref",
        JobId::now(),
        shared_claim_id,
        "Original claim should not be persisted.",
        "seed-a",
        1,
    )?;
    let refined = candidate(
        subject,
        "same-ref",
        source.branch_job,
        shared_claim_id,
        "Refined claim is the selected winner.",
        "synthesis",
        1,
    )?;
    let discarded = candidate(
        subject,
        "discarded-peer",
        JobId::now(),
        EntityId::now(),
        "Discarded peer claim.",
        "seed-b",
        1,
    )?;
    let fork = author_fork("author-seed-reused-winner", &[&source, &discarded])?;
    let run = DreamerTournamentRun::new(
        "run-reused-winner",
        fork,
        2,
        2,
        vec![DreamerTournamentRound::new(
            vec![
                DreamerTournamentBranch::new(
                    source.clone(),
                    revise_critiques(&source, &catalog, "reused_source")?,
                    DreamerTournamentSynthesisArtifact::refined(
                        "reused_source_synthesis",
                        &source,
                        refined,
                    )?,
                )?,
                DreamerTournamentBranch::new(
                    discarded.clone(),
                    discard_critiques(&discarded, &catalog, "reused_discarded")?,
                    DreamerTournamentSynthesisArtifact::discarded(
                        "reused_discarded_synthesis",
                        &discarded,
                    )?,
                )?,
            ],
            None,
            vec![DreamerTournamentBordaBallot::new("judge", vec![0])?],
        )?],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )?;
    let result = run_dreamer_claim_tournament(&vault, run)?;
    assert_eq!(result.winner.claim_id, shared_claim_id);
    let stored = vault
        .get_claim(&shared_claim_id)?
        .expect("refined winner stored");
    assert_eq!(
        stored.value.as_str(),
        Some("Refined claim is the selected winner.")
    );
    Ok(())
}

#[test]
fn candidate_round_mismatch_is_rejected_against_enclosing_round() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let left = candidate(
        subject,
        "wrong-round-left",
        JobId::now(),
        EntityId::now(),
        "Wrong round left.",
        "seed-a",
        2,
    )?;
    let right = candidate(
        subject,
        "wrong-round-right",
        JobId::now(),
        EntityId::now(),
        "Wrong round right.",
        "seed-b",
        1,
    )?;
    let fork = author_fork("author-seed-wrong-round", &[&left, &right])?;
    assert!(
        DreamerTournamentRun::new(
            "run-wrong-round",
            fork,
            2,
            2,
            vec![DreamerTournamentRound::new(
                vec![
                    accept_branch(left, &catalog, "wrong_round_left")?,
                    accept_branch(right, &catalog, "wrong_round_right")?,
                ],
                None,
                vec![DreamerTournamentBordaBallot::new("judge", vec![0, 1])?],
            )?],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn duplicate_judge_ballots_are_rejected() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, _envelope) = test_envelope(&vault)?;
    let catalog = LensCatalog::of366_seed()?;
    let left = candidate(
        subject,
        "duplicate-judge-left",
        JobId::now(),
        EntityId::now(),
        "Duplicate judge left.",
        "seed-a",
        1,
    )?;
    let right = candidate(
        subject,
        "duplicate-judge-right",
        JobId::now(),
        EntityId::now(),
        "Duplicate judge right.",
        "seed-b",
        1,
    )?;
    assert!(
        DreamerTournamentRound::new(
            vec![
                accept_branch(left, &catalog, "duplicate_judge_left")?,
                accept_branch(right, &catalog, "duplicate_judge_right")?,
            ],
            None,
            vec![
                DreamerTournamentBordaBallot::new("judge", vec![0, 1])?,
                DreamerTournamentBordaBallot::new("judge", vec![1, 0])?,
            ],
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn judge_claim_must_match_persisted_candidate_claim_value() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_actor, subject, _envelope) = test_envelope(&vault)?;
    assert!(
        DreamerTournamentCandidate::new(
            "judge-drift",
            JobId::now(),
            EntityId::now(),
            ClaimCandidate::new(
                "pattern.sleep",
                ClaimSubject::Entity(subject),
                Value::from("Persisted claim value."),
                0.8,
            ),
            DreamerTournamentJudgeClaim::new("Different judged claim.", vec!["obs:1".to_owned()])?,
            "seed",
            1,
        )
        .is_err()
    );
    Ok(())
}
