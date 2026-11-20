//! ARCH-0073 §6, "a re-mention restores the archived record" (FIX
//! DREAMER-DIRECT-CLAIM-WRITERS-LAND-ON-ARCHIVED-PERSON, review round 1 of
//! #9767): the Dreamer's claim tournament commits its winner through the
//! claim-candidate write path. A winner about a PERSON the vault cleanup
//! archived is a new mention of her, and the winner's own write restores her.
//!
//! The run is the crate's own two-branch fixture
//! (`src/dreamer_tournament/tests.rs`) on public paths: one branch the
//! critics accept, one they discard, and one blind ballot for the survivor.
//!
//! Red without the fix: the winner lands and her archive marker stays.
//!
//! Needs the archive door:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tournament_winner_restores_archived_person`.
#![cfg(oneiron_test_support)]

use oneiron::attempt_queue::AttemptId;
use oneiron::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use oneiron::critic::{
    CriticLens, CritiqueArtifact, CritiqueProvenance, CritiqueSeverity, CritiqueVerdict,
    LensCatalog,
};
use oneiron::dreamer_tournament::{
    DreamerTournamentAuthorFork, DreamerTournamentBordaBallot, DreamerTournamentBranch,
    DreamerTournamentCandidate, DreamerTournamentJudgeClaim, DreamerTournamentRound,
    DreamerTournamentRun, DreamerTournamentSynthesisArtifact, run_dreamer_claim_tournament,
};
use oneiron::edge::EdgeActorClass;
use oneiron::learning::{LearningCell, LearningPredicate, TypeRef};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::write_envelope::ClaimCandidate;
use oneiron::{EntityId, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

/// The tournament's run id, which each critique names.
const RUN_ID: &str = "run-archived-person";

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn candidate(
    subject: EntityId,
    candidate_ref: &str,
    claim_id: EntityId,
    claim_text: &str,
    strategy: &str,
) -> DreamerTournamentCandidate {
    DreamerTournamentCandidate::new(
        candidate_ref,
        AttemptId::now(),
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
        )
        .expect("FIXTURE: the judge claim"),
        strategy,
        1,
    )
    .expect("FIXTURE: the candidate")
}

fn critique(
    candidate: &DreamerTournamentCandidate,
    lens: &CriticLens,
    verdict: CritiqueVerdict,
    severity: CritiqueSeverity,
    hard_check_passed: Option<bool>,
) -> CritiqueArtifact {
    let provenance = CritiqueProvenance::new(
        WriteActor::new(EntityId::now(), EdgeActorClass::Agent),
        "fixture-model",
        Some("rev1".to_owned()),
    )
    .expect("FIXTURE: the critic's provenance");
    let calibration = LearningCell::new(LearningPredicate::Reliability, candidate.claim_id)
        .executor(provenance.executor().expect("FIXTURE: the executor"))
        .type_ref(TypeRef {
            node_id: "claim_authoring".to_owned(),
            tree_version: 1,
        })
        .axis("quality");
    CritiqueArtifact::new(
        format!("{}_{}", candidate.candidate_ref, lens.id),
        RUN_ID,
        candidate.branch_attempt,
        candidate.candidate_ref.clone(),
        lens,
        provenance,
        calibration,
        verdict,
        severity,
        hard_check_passed,
        candidate.judge_claim.evidence_refs.clone(),
        None,
        10,
    )
    .expect("FIXTURE: the critique")
}

fn lenses(catalog: &LensCatalog) -> [&CriticLens; 4] {
    ["groundedness", "overreach", "temporal", "redundancy"].map(|id| {
        catalog
            .lens(id, "claim_authoring")
            .expect("FIXTURE: an OF-366 seed lens")
    })
}

/// Every lens accepts `candidate`.
fn accepted(
    candidate: &DreamerTournamentCandidate,
    catalog: &LensCatalog,
) -> Vec<CritiqueArtifact> {
    lenses(catalog)
        .iter()
        .map(|lens| {
            critique(
                candidate,
                lens,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                lens.hard_check.then_some(true),
            )
        })
        .collect()
}

/// The groundedness lens discards `candidate`; the others accept it.
fn discarded(
    candidate: &DreamerTournamentCandidate,
    catalog: &LensCatalog,
) -> Vec<CritiqueArtifact> {
    lenses(catalog)
        .iter()
        .map(|lens| {
            if lens.id == "groundedness" {
                critique(
                    candidate,
                    lens,
                    CritiqueVerdict::Discard,
                    CritiqueSeverity::Blocking,
                    Some(false),
                )
            } else {
                critique(
                    candidate,
                    lens,
                    CritiqueVerdict::Accept,
                    CritiqueSeverity::Info,
                    None,
                )
            }
        })
        .collect()
}

#[test]
fn a_tournament_winner_about_an_archived_person_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"actor")
        .expect("FIXTURE: the author");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")
        .expect("FIXTURE: the subject");
    archive_as_cleanup(&vault, &subject).expect("FIXTURE: the cleanup archives her");
    assert!(
        vault
            .archived_entity(&subject)
            .expect("archive read")
            .is_some(),
        "FIXTURE: the cleanup's archive marker stands on her"
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("of366-tournament-fixture"))
            .expect("FIXTURE: the provenance"),
        ClaimApprovalStatus::Approved,
    );
    let catalog = LensCatalog::of366_seed().expect("FIXTURE: the OF-366 seed catalog");
    let winner_id = EntityId::now();
    let survivor = candidate(
        subject,
        "survivor",
        winner_id,
        "She sleeps late on weekends.",
        "seed-a",
    );
    let loser = candidate(
        subject,
        "discarded",
        EntityId::now(),
        "She never sleeps.",
        "seed-b",
    );
    let fork = DreamerTournamentAuthorFork::new(
        "author-seed-archived-person",
        AttemptId::now(),
        vec![survivor.branch_attempt, loser.branch_attempt],
    )
    .expect("FIXTURE: the author fork");
    let round = DreamerTournamentRound::new(
        vec![
            DreamerTournamentBranch::new(
                survivor.clone(),
                accepted(&survivor, &catalog),
                DreamerTournamentSynthesisArtifact::survivor("survivor_synthesis", &survivor)
                    .expect("FIXTURE: the survivor's synthesis"),
            )
            .expect("FIXTURE: the surviving branch"),
            DreamerTournamentBranch::new(
                loser.clone(),
                discarded(&loser, &catalog),
                DreamerTournamentSynthesisArtifact::discarded("discarded_synthesis", &loser)
                    .expect("FIXTURE: the discarded synthesis"),
            )
            .expect("FIXTURE: the discarded branch"),
        ],
        None,
        vec![DreamerTournamentBordaBallot::new("judge", vec![0]).expect("FIXTURE: the ballot")],
    )
    .expect("FIXTURE: the round");
    let run = DreamerTournamentRun::new(
        RUN_ID,
        fork,
        2,
        1,
        vec![round],
        Vec::new(),
        envelope,
        occurred(20),
        21,
    )
    .expect("FIXTURE: the run");

    let result = run_dreamer_claim_tournament(&vault, run).expect("the tournament runs");
    assert_eq!(
        result.winner.map(|winner| winner.claim_id),
        Some(winner_id),
        "FIXTURE: the surviving branch wins"
    );
    let stored = vault
        .get_claim(&winner_id)
        .expect("claim read")
        .expect("FIXTURE: the winner is stored");
    assert_eq!(
        stored.subject,
        ClaimSubject::Entity(subject),
        "FIXTURE: the winner is about her"
    );
    assert!(
        vault
            .archived_entity(&subject)
            .expect("archive read")
            .is_none(),
        "the winner is a new mention of her: it restored her, and she bears no archive marker"
    );
}
