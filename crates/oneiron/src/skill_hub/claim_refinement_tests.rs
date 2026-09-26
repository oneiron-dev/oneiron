//! Claim refinements use the same typed question and independent held-out rule.
use super::*;
use crate::{
    Vault, VaultConfig,
    claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        encode_claim_body,
    },
    consent::AuthenticatedOwner,
    llm::decision::{
        AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionQuestion,
        DecisionReceipt, DecisionRung, ProviderPin, TypedDecision,
    },
    skill_hub::{
        ClaimRefinementMergeDisposition, HeldOutClaimReplayCase, HeldOutClaimReplayScorer,
        UsefulUpstreamClaimJudge,
    },
};

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}
fn question(id: EntityId) -> DecisionQuestion {
    DecisionQuestion {
        id,
        version: 1,
        text: "Useful upstream?".to_owned(),
        class: DecisionClass::UsefulUpstream,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    base: EntityId,
    resident: EntityId,
    owner: AuthenticatedOwner,
    subject: EntityId,
}
impl Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            at(1),
            1,
            b"owner",
        )?;
        let owner = vault.authenticate_owner(
            subject,
            "principal:claim-refinement",
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let resident = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")?
            .expect("seeded agent")
            .0;
        let base = EntityId::now();
        let mut original = ClaimBody::new(
            "booking.refinement",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("old"),
            0.8,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        original.source = Some(ClaimSource::Inferred);
        vault.put_claim(&base, &original, at(2), 2)?;
        let label = EntityId::now();
        let mut evidence = ClaimBody::new(
            "booking.label",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("adjudicated"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        evidence.source = Some(ClaimSource::UserStated);
        vault.put_claim(&label, &evidence, at(3), 3)?;
        vault.reserve_claim_refinement_holdout(&owner, base, &[label])?;
        Ok(Self {
            vault,
            _dir: dir,
            base,
            resident,
            owner,
            subject,
        })
    }
    fn proposal(&self, value: &str) -> ClaimBody {
        let mut body = ClaimBody::new(
            "booking.refinement",
            ClaimSubject::Entity(self.subject),
            rmpv::Value::from(value),
            0.9,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Inferred);
        body.session_tag = Some("session:claim-refine".to_owned());
        body
    }
    fn submit(&self, value: &str) -> Result<EntityId> {
        self.vault.submit_local_claim_refinement(
            self.base,
            self.resident,
            "session:claim-refine",
            &self.proposal(value),
            at(5),
            5,
        )
    }
}
struct Useful(bool);
impl UsefulUpstreamClaimJudge for Useful {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        _: &ClaimBody,
        _: &ClaimBody,
    ) -> Result<TypedDecision> {
        Ok(TypedDecision {
            answer: DecisionAnswer::Noul(self.0),
            probability: Some(if self.0 { 0.9 } else { 0.1 }),
            evidence: vec![],
            in_band: false,
            receipt: DecisionReceipt {
                question: question.id,
                question_version: question.version,
                principal: resident,
                providers: vec![ProviderPin {
                    rung: DecisionRung::SystemOne,
                    model: "system-one".to_owned(),
                    version: "1".to_owned(),
                }],
                band: DecisionBand::default(),
            },
            human_ask: None,
        })
    }
}
struct Replay;
impl HeldOutClaimReplayScorer for Replay {
    fn score(&self, case: &HeldOutClaimReplayCase<'_>) -> Result<f32> {
        assert_eq!(case.held_out_receipts.len(), 1);
        Ok(if case.claim.value.as_str() == Some("improved") {
            0.9
        } else {
            0.2
        })
    }
}
struct NoReplay;
impl HeldOutClaimReplayScorer for NoReplay {
    fn score(&self, _: &HeldOutClaimReplayCase<'_>) -> Result<f32> {
        panic!("replay must not run")
    }
}
#[test]
fn rejected_branch_claim_stays_local_and_cannot_use_the_generic_claim_door() -> Result<()> {
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    assert_eq!(
        f.vault
            .merge_local_claim_refinement(&ask, &Useful(true), &NoReplay, 6)?,
        ClaimRefinementMergeDisposition::PendingConsent
    );
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    let ClaimRefinementMergeDisposition::Ruled(receipt) =
        f.vault
            .merge_local_claim_refinement(&ask, &Useful(false), &NoReplay, 6)?
    else {
        panic!("consented")
    };
    assert!(!receipt.accepted);
    assert_eq!(receipt.before, None);
    assert_eq!(receipt.resident, f.resident.to_hex());
    assert_eq!(
        f.vault
            .local_claim_refinement(candidate)?
            .unwrap()
            .claim_body()?,
        f.proposal("improved")
    );
    assert!(f.vault.get_claim(&candidate)?.is_none());
    assert!(
        f.vault
            .put_claim(&candidate, &f.proposal("improved"), at(7), 7)
            .is_err()
    );
    assert!(
        f.vault
            .batch()
            .put(
                &candidate,
                crate::registry::ENTITY_TYPE_CLAIM,
                at(7),
                7,
                &encode_claim_body(&f.proposal("improved"))?
            )
            .commit()
            .is_err()
    );
    assert_eq!(
        f.vault.get_claim(&f.base)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        f.vault.claim_refinement_merge_receipt(candidate)?,
        Some(*receipt)
    );
    Ok(())
}
#[test]
fn claim_yes_needs_held_out_win_and_supersedes_only_at_the_merge_door() -> Result<()> {
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    let ClaimRefinementMergeDisposition::Ruled(receipt) =
        f.vault
            .merge_local_claim_refinement(&ask, &Useful(true), &Replay, 8)?
    else {
        panic!("consented")
    };
    assert!(receipt.accepted);
    assert_eq!(receipt.before, Some(0.2));
    assert_eq!(receipt.after, Some(0.9));
    assert_eq!(
        f.vault.get_claim(&candidate)?.unwrap().approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        f.vault.get_claim(&f.base)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert!(f.vault.local_claim_refinement(candidate)?.is_some());
    Ok(())
}
#[test]
fn claim_tie_keeps_the_branch_and_base() -> Result<()> {
    struct Tie;
    impl HeldOutClaimReplayScorer for Tie {
        fn score(&self, _: &HeldOutClaimReplayCase<'_>) -> Result<f32> {
            Ok(0.5)
        }
    }
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    assert!(
        matches!(f.vault.merge_local_claim_refinement(&ask, &Useful(true), &Tie, 8)?,
        ClaimRefinementMergeDisposition::Ruled(receipt) if !receipt.accepted)
    );
    assert!(f.vault.get_claim(&candidate)?.is_none());
    assert!(f.vault.local_claim_refinement(candidate)?.is_some());
    assert_eq!(
        f.vault.get_claim(&f.base)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}
