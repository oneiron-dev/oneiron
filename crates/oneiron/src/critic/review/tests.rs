use super::*;
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};

struct Critics;
impl ReviewHost for Critics {
    fn fan_out(&self, inputs: &[CriticReviewInput]) -> Result<Vec<CritiqueArtifact>> {
        inputs
            .iter()
            .map(|input| {
                CritiqueArtifact::new(
                    format!("{}_{}", input.run_id, input.lens.id),
                    &input.run_id,
                    input.branch_attempt,
                    input.target.to_hex(),
                    &input.lens,
                    CritiqueProvenance::new(&input.lens.id, "fixture", None)?,
                    CritiqueVerdict::Revise,
                    CritiqueSeverity::High,
                    None,
                    vec!["evidence:1".into()],
                    Some("tighten scope".into()),
                    10,
                )
            })
            .collect()
    }
}
fn catalog() -> Result<LensCatalog> {
    Ok(LensCatalog {
        schema_version: 1,
        lenses: ["a", "b", "c"]
            .into_iter()
            .map(|id| CriticLens::new(id, "fixture contract", "fixture schema", false, "docs"))
            .collect::<Result<_>>()?,
    })
}
#[test]
fn document_and_claim_reviews_persist_and_learn_dismissals() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let time = TimeRange { start: 10, end: 10 };
    let actor_id = EntityId::now();
    vault.put_entity(
        &actor_id,
        crate::registry::ENTITY_TYPE_PERSON,
        time,
        10,
        b"owner",
    )?;
    let actor = WriteActor::new(actor_id, crate::EdgeActorClass::Human);
    let session = EntityId::now();
    vault.put_entity(&session, ENTITY_TYPE_SESSION, time, 10, b"session")?;
    let document = EntityId::now();
    vault.put_entity(&document, ENTITY_TYPE_TURN, time, 10, b"doc")?;
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "fixture.fact",
        ClaimSubject::Entity(document),
        Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &body, time, 10)?;
    let catalog = catalog()?;
    for (round, (kind, target)) in [
        (ReviewArtifactKind::Document, document),
        (ReviewArtifactKind::ClaimWrite, claim),
    ]
    .into_iter()
    .enumerate()
    {
        let request = ReviewRequest {
            actor,
            target,
            kind,
            session,
            run_id: format!("round_{round}"),
            branch_attempt: AttemptId::now(),
            auto_resolve_threshold: 0.9,
            at: 10,
        };
        let result = review_artifact(&vault, &request, &catalog, &Critics)?;
        assert_eq!(result.artifacts.len(), 3);
        assert_eq!(result.triage.findings.len(), 1);
        assert!(!result.triage.auto_resolved);
        assert_eq!(
            vault.get_claim(&result.verdict_claim)?.unwrap().predicate,
            "review.verdict"
        );
        for artifact in &result.artifacts {
            assert_eq!(
                CritiqueArtifactStore::new(&vault)
                    .get(request.branch_attempt, &artifact.artifact_id)?,
                Some(artifact.clone())
            );
            let outcome = record_review_outcome(
                &vault,
                &result,
                actor,
                &artifact.artifact_id,
                ReliabilityOutcomeSource::OwnerVerdict,
                false,
                11 + round as u64,
            )?;
            assert_eq!(
                record_review_outcome(
                    &vault,
                    &result,
                    actor,
                    &artifact.artifact_id,
                    ReliabilityOutcomeSource::OwnerVerdict,
                    false,
                    20
                )?,
                outcome
            );
        }
        let replay = review_artifact(&vault, &request, &catalog, &NoSecondCall)?;
        assert_eq!(replay.verdict_claim, result.verdict_claim);
        assert_eq!(replay.triage, result.triage);
    }
    // Raw claims are not calibration events, even with a plausible posterior.
    let forged = EntityId::now();
    let mut forged_body = critic_reliability_claim_body(
        session,
        &CriticReliability::new("a", "docs", 99.0, 1.0, 98)?,
        1.0,
    )?;
    forged_body.source = Some(ClaimSource::Observed);
    vault.put_claim(&forged, &forged_body, time, 13)?;
    let learned = read_reliabilities(&vault, &session, &catalog)?;
    assert_eq!(learned.len(), 3);
    assert!(
        learned
            .iter()
            .all(|row| row.alpha == 1.0 && row.beta == 3.0 && row.observations == 2)
    );
    assert_eq!(recurring_findings(&vault, &session)?.len(), 1);
    Ok(())
}

#[test]
fn duplicate_findings_do_not_inflate_votes_and_trusted_findings_resolve() -> Result<()> {
    let catalog = catalog()?;
    let inputs = catalog
        .lenses
        .iter()
        .map(|lens| CriticReviewInput {
            target: EntityId::now(),
            kind: ReviewArtifactKind::Document,
            lens: lens.clone(),
            run_id: "run".into(),
            branch_attempt: AttemptId::now(),
        })
        .collect::<Vec<_>>();
    let mut artifacts = Critics.fan_out(&inputs)?;
    let rows = catalog
        .lenses
        .iter()
        .map(|lens| CriticReliability::new(&lens.id, &lens.domain, 99.0, 1.0, 98))
        .collect::<Result<Vec<_>>>()?;
    let base = triage_critiques(&catalog, &artifacts, &rows)?;
    artifacts.push(artifacts[0].clone());
    let repeated = triage_critiques(&catalog, &artifacts, &rows)?;
    assert_eq!(base.scores, repeated.scores);
    assert_eq!(repeated.findings.len(), 1);
    assert!(repeated.auto_resolved);
    assert!(repeated.findings[0].auto_resolved);
    artifacts[0].suggested_edit = Some("different finding".into());
    artifacts[0].severity = CritiqueSeverity::Blocking;
    let ranked = triage_critiques(&catalog, &artifacts, &rows)?;
    assert_eq!(ranked.findings.len(), 2);
    assert_eq!(ranked.findings[0].severity, CritiqueSeverity::Blocking);
    Ok(())
}

struct NoSecondCall;
impl ReviewHost for NoSecondCall {
    fn fan_out(&self, _: &[CriticReviewInput]) -> Result<Vec<CritiqueArtifact>> {
        panic!("a durable retry must not call critics again")
    }
}
