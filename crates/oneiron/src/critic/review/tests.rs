use super::*;
use crate::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder, DecisionProvider,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use serde_json::json;
use std::time::Duration;

// FIX [T0B-CRITIC-CALIB-REWRITE]: port to ReviewDecisions and learning.reliability cells: session-to-cell scope, forged public calibration claim now refused, cross-area consumers
#[cfg(any())]
struct Critics;
// FIX [T0B-CRITIC-CALIB-REWRITE]: port to ReviewDecisions and learning.reliability cells: session-to-cell scope, forged public calibration claim now refused, cross-area consumers
#[cfg(any())]
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
// FIX [T0B-CRITIC-CALIB-REWRITE]: port to ReviewDecisions and learning.reliability cells: session-to-cell scope, forged public calibration claim now refused, cross-area consumers
#[cfg(any())]
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
    // A predicate no rule names takes the criticality floor and waits for
    // the owner before a reader acts on it; the review family is the
    // fixture's own, so it is normal here and outcomes fold at once.
    crate::test_util::declare_predicates_normal(&vault, &["review."])?;
    let time = TimeRange { start: 10, end: 10 };
    let actor_id = vault
        .ensure_embedded_owner_actor()
        .map_err(|_| crate::Error::InvariantViolation("embedded owner"))?;
    let actor = WriteActor::new(actor_id, crate::EdgeActorClass::Human);
    // A PERSON that names itself human is not the owner (H149).
    let delegate_id = EntityId::now();
    vault.put_entity(&delegate_id, ENTITY_TYPE_PERSON, time, 10, b"delegate")?;
    let delegate = WriteActor::new(delegate_id, crate::EdgeActorClass::Human);
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
    )?;
    vault.put_claim(&claim, &body, time, 10)?;
    let lens_a = put_lens_skill(&vault, "critic-review.lens-a")?;
    let lens_b = put_lens_skill(&vault, "critic-review.lens-b")?;
    let catalog = lens_catalog()?;
    let script = Script {
        by_contract: BTreeMap::from([(CONTRACT_A, REVISE_HIGH), (CONTRACT_B, REVISE_HIGH)]),
    };
    // Both lenses name the same flaw in the target, so each round merges to
    // one finding and each round's outcomes share one finding key.
    let note = json!({
        "evidence_refs": ["fixture-evidence"],
        "suggested_edit": "tighten scope",
        "prediction": null,
        "flaw": {
            "kind": "missing_guard",
            "location": {"type": "body_bytes", "start": 0, "end": 4},
        },
    });
    let notes = JsonNotes {
        by_lens: BTreeMap::from([("lens_a", note.clone()), ("lens_b", note)]),
    };
    let type_ref = TypeRef {
        node_id: "document_review".to_owned(),
        tree_version: 1,
    };
    let mut cells: BTreeMap<String, LearningCell> = BTreeMap::new();
    let mut means: BTreeMap<String, Vec<f64>> = BTreeMap::new();
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
            type_ref: type_ref.clone(),
            axis: "quality".to_owned(),
            critics: [("lens_a", lens_a), ("lens_b", lens_b)]
                .into_iter()
                .map(|(lens_id, lens_ref)| ReviewCritic {
                    lens_id: lens_id.to_owned(),
                    lens_ref,
                    actor,
                })
                .collect(),
            at: 10,
            spawn_attempt: None,
            project: None,
        };
        let review_state = state(target, kind);
        let result = run_review(
            &vault,
            &request,
            &catalog,
            &script,
            Some(&notes),
            &review_state,
        )?;
        assert_eq!(result.artifacts.len(), 2);
        assert_eq!(result.triage.verdict, CritiqueVerdict::Revise);
        assert_eq!(result.triage.findings.len(), 1);
        assert!(!result.triage.findings[0].conflict);
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
            assert!(
                record_review_outcome(
                    &vault,
                    &result,
                    delegate,
                    &artifact.artifact_id,
                    ReliabilityOutcomeSource::OwnerVerdict,
                    false,
                    11 + round as u64,
                )
                .is_err(),
                "only the owner records an owner verdict"
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
        let replay = run_review(
            &vault,
            &request,
            &catalog,
            &NeverAsked,
            Some(&NeverNoted),
            &review_state,
        )?;
        assert_eq!(replay.verdict_claim, result.verdict_claim);
        assert_eq!(replay.triage, result.triage);
        // Each dismissal folds into its lens's reliability cell at once.
        for artifact in &result.artifacts {
            cells.insert(artifact.lens_id.clone(), artifact.calibration.clone());
            let read = crate::learning::read_learning(&vault, &artifact.calibration, &[])?;
            assert!(read.own, "a dismissed lens holds its own runs");
            means
                .entry(artifact.lens_id.clone())
                .or_default()
                .push(read.estimate.mean());
        }
    }
    assert_eq!(cells.len(), 2);
    assert_eq!(means.len(), 2);
    for (lens, lens_means) in &means {
        assert_eq!(lens_means.len(), 2, "{lens} is dismissed once per round");
        assert!(
            lens_means[1] < lens_means[0],
            "a second dismissal moves {lens}'s mean further: {lens_means:?}"
        );
    }
    // Dismissals trained both lenses' cells: runs counted, the mean below
    // the shipped Beta(1, 1) prior's, losses above wins.
    let mut trained: BTreeMap<String, crate::learning::Estimate> = BTreeMap::new();
    for (lens, cell) in &cells {
        let estimate = crate::learning::learning_estimate(&vault, cell)?
            .unwrap_or_else(|| panic!("{lens}'s dismissals project an own head"));
        assert!(
            estimate.runs > 1.0,
            "{lens} counts both dismissals as runs: {}",
            estimate.runs
        );
        assert!(
            estimate.mean() < 0.5,
            "{lens}'s dismissals pull below the shipped prior mean: {}",
            estimate.mean()
        );
        match &estimate.value {
            crate::learning::EstimateValue::Beta { alpha, beta } => {
                assert!(
                    beta > alpha,
                    "{lens}'s losses exceed its wins: {alpha} vs {beta}"
                );
            }
            other => panic!("{lens}'s reliability folds a Beta estimate: {other:?}"),
        }
        trained.insert(lens.clone(), estimate);
    }
    // Raw claims are not calibration events: a forged `learning.reliability`
    // claim, even a plausible Observed one, is refused at the write door,
    // and the cells it aimed at read unchanged.
    let forged = EntityId::now();
    let mut forged_body = ClaimBody::new(
        "learning.reliability",
        ClaimSubject::Entity(lens_a),
        Value::from("forged"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    forged_body.source = Some(ClaimSource::Observed);
    let refused = vault.put_claim(&forged, &forged_body, time, 13);
    assert!(
        matches!(
            refused,
            Err(Error::Claim(
                crate::error::ClaimError::ReservedPredicate { .. }
            ))
        ),
        "a forged calibration claim is refused: {refused:?}"
    );
    assert!(vault.get_claim(&forged)?.is_none());
    for (lens, cell) in &cells {
        let reread = crate::learning::learning_estimate(&vault, cell)?
            .unwrap_or_else(|| panic!("{lens} keeps its head"));
        assert_eq!(reread, trained[lens], "{lens} reads unchanged");
    }
    let recurring = recurring_findings(&vault, &session)?;
    assert_eq!(
        recurring.len(),
        2,
        "each round's outcomes share one finding key: {recurring:?}"
    );
    assert!(recurring.iter().all(|(_, count)| *count == 2));
    Ok(())
}

/// One lens's typed answers.
#[derive(Clone, Copy)]
struct Answers {
    verdict: &'static str,
    severity: &'static str,
}

const CONTRACT_A: &str = "Lens a: judge the target's guards.";
const CONTRACT_B: &str = "Lens b: judge the target's bounds.";
const VERDICT_WORDING: &str = "Which verdict does this lens give?";
const SEVERITY_WORDING: &str = "How severe is the finding?";
const HARD_CHECK_WORDING: &str = "Does the target pass this lens's hard check?";
const OUT_OF_SCOPE_WORDING: &str = "Is the target outside this lens's scope?";

const REVISE_HIGH: Answers = Answers {
    verdict: "revise",
    severity: "high",
};

/// The local rung: it answers each question from the lens's prompt contract
/// and the question's wording, the two parts of the question's text.
struct Script {
    by_contract: BTreeMap<&'static str, Answers>,
}

fn answer(answer: DecisionAnswer, probability: f64) -> ProviderDecision {
    ProviderDecision {
        answer,
        probability: Some(probability),
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

fn noul(value: bool) -> ProviderDecision {
    answer(DecisionAnswer::Noul(value), if value { 0.95 } else { 0.05 })
}

impl DecisionProvider for Script {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "critic-review-fixture".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let (contract, wording) = call
            .question
            .text
            .split_once("\n\n")
            .ok_or_else(|| Error::InvalidConfig("unscripted question".into()))?;
        let answers = self
            .by_contract
            .get(contract)
            .ok_or_else(|| Error::InvalidConfig("unscripted lens".into()))?;
        Ok(match wording {
            VERDICT_WORDING => answer(DecisionAnswer::Choice(answers.verdict.into()), 0.95),
            SEVERITY_WORDING => answer(DecisionAnswer::Choice(answers.severity.into()), 0.95),
            HARD_CHECK_WORDING => noul(true),
            OUT_OF_SCOPE_WORDING => noul(false),
            _ => return Err(Error::InvalidConfig("unscripted wording".into())),
        })
    }
}

struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        Err(Error::InvalidConfig(
            "the critic review fixture queues no person ask".into(),
        ))
    }
}

/// A rung a replayed review must never reach.
struct NeverAsked;

impl DecisionProvider for NeverAsked {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "critic-review-fixture".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _: &DecisionCall<'_>) -> Result<ProviderDecision> {
        panic!("a replayed review asked its questions again");
    }
}

/// Notes read from JSON, one per lens: each call gets one finding.
struct JsonNotes {
    by_lens: BTreeMap<&'static str, serde_json::Value>,
}

impl ReviewNotes for JsonNotes {
    fn notes(&self, findings: &[ReviewFinding]) -> Result<Vec<ReviewNote>> {
        findings
            .iter()
            .map(|finding| {
                let note = self
                    .by_lens
                    .get(finding.input.lens.id.as_str())
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                serde_json::from_value::<ReviewNote>(note)
                    .map_err(|error| Error::InvalidConfig(error.to_string()))
            })
            .collect()
    }
}

/// Notes a replayed review must never ask for.
struct NeverNoted;

impl ReviewNotes for NeverNoted {
    fn notes(&self, _: &[ReviewFinding]) -> Result<Vec<ReviewNote>> {
        panic!("a replayed review asked for its notes again");
    }
}

/// The two-lens catalog the fixture reviews with.
fn lens_catalog() -> Result<LensCatalog> {
    Ok(LensCatalog {
        schema_version: CRITIC_LENS_CATALOG_SCHEMA_VERSION,
        lenses: [("lens_a", CONTRACT_A), ("lens_b", CONTRACT_B)]
            .into_iter()
            .map(|(id, contract)| {
                CriticLens::new(
                    id,
                    contract,
                    "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
                    false,
                    "docs",
                )
            })
            .collect::<Result<_>>()?,
    })
}

/// A lens's stored skill: an owner-authored candidate, which is all a review
/// reads of it.
fn put_lens_skill(vault: &Vault, name: &str) -> Result<EntityId> {
    let id = EntityId::now();
    let tree = crate::skill::canonical_skill_tree_hash([("SKILL.md", name.as_bytes())])?;
    let record = crate::skill::SkillRecord::new(
        name,
        "A critic lens for the review fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        crate::skill::SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(
            Value::from("source"),
            Value::from("critic-review-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault.put_skill_record(&id, &record, TimeRange { start: 12, end: 12 }, 12)?;
    Ok(id)
}

fn wording() -> ReviewWording {
    ReviewWording {
        verdict: VERDICT_WORDING.to_owned(),
        severity: SEVERITY_WORDING.to_owned(),
        hard_check: HARD_CHECK_WORDING.to_owned(),
        out_of_scope: OUT_OF_SCOPE_WORDING.to_owned(),
    }
}

/// The state a host's door builds from the target: the caller's view, whole.
fn state(target: EntityId, kind: ReviewArtifactKind) -> serde_json::Value {
    let kind = match kind {
        ReviewArtifactKind::Document => "document",
        ReviewArtifactKind::Design => "design",
        ReviewArtifactKind::ClaimWrite => "claim_write",
    };
    json!({
        "kind": kind,
        "target": {
            "id": target.to_hex(),
            "occurred_start": 10,
            "occurred_end": 10,
            "learned_at": 10,
            "body": {"text": "alpha beta gamma"},
        },
        "cut_at_bytes": null,
    })
}

/// One review through `local` and `notes`.
fn run_review(
    vault: &Vault,
    request: &ReviewRequest,
    catalog: &LensCatalog,
    local: &dyn DecisionProvider,
    notes: Option<&dyn ReviewNotes>,
    state: &serde_json::Value,
) -> Result<ReviewResult> {
    let decisions = ReviewDecisions {
        ladder: DecisionLadder {
            rule: None,
            local: Some(local),
            system_one: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "critic-review-queue".into(),
                version: "1".into(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        principal: request.actor.entity_ref(),
        dial: REVIEW_DIAL,
        bands: DecisionBandPolicy::default(),
        state,
        budget: Duration::from_secs(3600),
        wording: wording(),
        notes,
    };
    review_artifact(vault, request, catalog, &decisions)
}

// FIX [T0B-CRITIC-CALIB-REWRITE]: port to ReviewDecisions and learning.reliability cells: session-to-cell scope, forged public calibration claim now refused, cross-area consumers
#[cfg(any())]
/// A reviewed session whose lens `a` the owner has calibrated, for the
/// consolidation reader table (`gate::tests::consolidation_readers`).
pub(crate) struct CalibratedSession {
    session: EntityId,
    actor: WriteActor,
    catalog: LensCatalog,
    rounds: usize,
}

// FIX [T0B-CRITIC-CALIB-REWRITE]: port to ReviewDecisions and learning.reliability cells: session-to-cell scope, forged public calibration claim now refused, cross-area consumers
#[cfg(any())]
impl CalibratedSession {
    pub(crate) fn new(vault: &Vault) -> Result<Self> {
        let time = TimeRange { start: 10, end: 10 };
        let actor = EntityId::now();
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            time,
            10,
            b"owner",
        )?;
        let session = EntityId::now();
        vault.put_entity(&session, ENTITY_TYPE_SESSION, time, 10, b"session")?;
        let mut calibrated = Self {
            session,
            actor: WriteActor::new(actor, crate::EdgeActorClass::Human),
            catalog: catalog()?,
            rounds: 0,
        };
        calibrated.train(vault)?;
        Ok(calibrated)
    }

    /// Reviews a fresh document and records the owner's dismissal of lens
    /// `a`'s critique: one anchored outcome, folded into lens `a`'s next
    /// calibration.
    pub(crate) fn train(&mut self, vault: &Vault) -> Result<()> {
        let document = EntityId::now();
        let time = TimeRange { start: 10, end: 10 };
        vault.put_entity(&document, ENTITY_TYPE_TURN, time, 10, b"doc")?;
        let request = ReviewRequest {
            actor: self.actor,
            target: document,
            kind: ReviewArtifactKind::Document,
            session: self.session,
            run_id: format!("table_{}", self.rounds),
            branch_attempt: AttemptId::now(),
            auto_resolve_threshold: 0.9,
            at: 10,
        };
        self.rounds += 1;
        let result = review_artifact(vault, &request, &self.catalog, &Critics)?;
        let artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.lens_id == "a")
            .ok_or(Error::EntityNotFound)?;
        record_review_outcome(
            vault,
            &result,
            self.actor,
            &artifact.artifact_id,
            ReliabilityOutcomeSource::OwnerVerdict,
            false,
            11,
        )?;
        Ok(())
    }

    /// Lens `a`'s calibration heads, in any lifecycle.
    pub(crate) fn calibrations(&self, vault: &Vault) -> Result<Vec<(EntityId, ClaimBody)>> {
        let predicate = critic_reliability_predicate("docs", "a")?;
        let txn = vault.store.env.read_txn()?;
        let mut heads = Vec::new();
        for id in vault.claims_for_subject_in_txn(&txn, &self.session)? {
            if let Some(body) = vault.get_claim_in_txn(&txn, &id)?
                && body.predicate == predicate
            {
                heads.push((id, body));
            }
        }
        Ok(heads)
    }

    /// The calibrations a review of this session is weighted by.
    pub(crate) fn reliabilities(&self, vault: &Vault) -> Result<Vec<CriticReliability>> {
        read_reliabilities(vault, &self.session, &self.catalog)
    }
}
