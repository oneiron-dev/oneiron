//! The externally observable consent, raw-door, held-out, dedup, and shared-merge laws.
use super::*;
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimSource},
    consent::AuthenticatedOwner,
    entity_id::EntityId,
    error::{ErrorKind, Result},
    llm::decision::{
        AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionQuestion,
        DecisionReceipt, DecisionRung, ProviderPin, TypedDecision,
    },
    skill::{SkillLifecycle, SkillRecord},
    skill_optimize::{HeldOutReplayCase, HeldOutReplayScorer},
    temporal::TimeRange,
};
use std::cell::Cell;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}
fn package(name: &str, version: &str, body: &str) -> HubPackage {
    super::folder::package_from_files(vec![HubFile::new(
        "SKILL.md",
        format!("---\nname: {name}\ndescription: fixture\nversion: {version}\n---\n{body}\n")
            .into_bytes(),
    )])
    .expect("package")
}
struct Fixture {
    vault: Vault,
    _temp: tempfile::TempDir,
    owner: AuthenticatedOwner,
    baseline: EntityId,
    resident: EntityId,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(temp.path(), crate::VaultConfig::default()).expect("vault");
        let owner_id = EntityId::now();
        vault
            .put_entity(
                &owner_id,
                crate::registry::ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"owner",
            )
            .expect("person");
        let owner = vault
            .authenticate_owner(
                owner_id,
                "principal:fixture-owner",
                true,
                crate::store::GateDecisionId::now(),
            )
            .expect("owner");
        let baseline = EntityId::now();
        let mut record = package("fixture.base", "1", "baseline").record;
        record.source = ClaimSource::UserStated;
        record.content_hash = None;
        vault
            .put_skill_record(&baseline, &record, at(2), 2)
            .expect("baseline candidate");
        record.lifecycle_status = SkillLifecycle::Active;
        record.approval_status = ClaimApprovalStatus::Approved;
        vault
            .update_skill_record(&baseline, &record, at(3), 3)
            .expect("owner activates authored baseline");
        reserve(&vault, &baseline, "fixture.base");
        let resident = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("resident lookup")
            .expect("seeded resident")
            .0;
        Self {
            _temp: temp,
            vault,
            owner,
            baseline,
            resident,
        }
    }
    fn hub(&self, tier: SkillHubTrustTier) -> (HubRef, ForeignSkillPublisher) {
        let id = EntityId::now();
        let record = SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            "https://example.invalid/index.json",
            tier,
            HubSyncPolicy::ContentHashFrozen,
        )
        .expect("hub");
        self.vault
            .configure_skill_hub(&self.owner, &id, &record, at(10), 10)
            .expect("configure hub");
        let publisher = self
            .vault
            .admit_skill_publisher(&self.owner, "publisher:outside", id)
            .expect("publisher");
        let reference = HubRef::new(
            id,
            "fixture",
            HubPin::ContentHash(
                package("fixture.new", "1", "check result")
                    .content_hash()
                    .expect("hash")
                    .to_hex(),
            ),
        )
        .expect("ref");
        (reference, publisher)
    }
    fn import(&self, source: &HubRef) -> EntityId {
        self.vault
            .import_skill_from_hub(
                source,
                &package("fixture.new", "1", "check result"),
                at(20),
                20,
            )
            .expect("import")
    }
}
use super::test_support::reserve;
struct Replay {
    improve: bool,
}
impl Replay {
    fn new(improve: bool) -> Self {
        Self { improve }
    }
}
struct NoReplay;
impl HeldOutReplayScorer for NoReplay {
    fn score(&self, _: &HeldOutReplayCase<'_>) -> Result<f32> {
        panic!("replay must not run before consent or usefulness");
    }
}
impl HeldOutReplayScorer for Replay {
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        assert!(!case.held_out_receipts.is_empty());
        Ok(
            if case.instructions.contains("check result") && self.improve {
                0.9
            } else {
                0.2
            },
        )
    }
}
#[test]
fn every_hub_tier_requires_human_consent_before_replay_and_activation() -> Result<()> {
    for (tier, surface) in [
        (SkillHubTrustTier::Verified, HubAskSurface::OneTap),
        (
            SkillHubTrustTier::Community,
            HubAskSurface::SummarizedReview,
        ),
        (SkillHubTrustTier::Untrusted, HubAskSurface::FullReview),
    ] {
        let fixture = Fixture::new();
        let (source, publisher) = fixture.hub(tier);
        let id = fixture.import(&source);
        let ask = fixture.vault.prepare_marketplace_activation(
            id,
            &source,
            &publisher,
            fixture.baseline,
        )?;
        assert_eq!(ask.surface(), surface);
        let scorer = Replay::new(true);
        assert_eq!(
            fixture
                .vault
                .admit_marketplace_skill(&ask, &NoReplay, at(30), 30)?,
            HubAdmissionDisposition::PendingConsent
        );
        fixture
            .vault
            .approve_marketplace_activation(&ask, &fixture.owner)?;
        let HubAdmissionDisposition::Ruled(receipt) =
            fixture
                .vault
                .admit_marketplace_skill(&ask, &scorer, at(31), 31)?
        else {
            panic!("consented");
        };
        assert!(receipt.accepted);
        assert_eq!(receipt.publisher, publisher.identity());
        assert_eq!(receipt.hub_id, source.hub_id.to_hex());
        assert_eq!(receipt.consent_digest, ask.effect_digest().to_hex());
        assert_eq!(
            fixture
                .vault
                .get_skill_record(&id)?
                .expect("skill")
                .lifecycle_status,
            SkillLifecycle::Active
        );
        assert_eq!(fixture.vault.hub_admission_receipt(&id)?, Some(*receipt));
    }
    Ok(())
}
#[test]
fn two_hubs_dedup_and_raw_or_replayed_activation_cannot_bypass_rejection() -> Result<()> {
    let fixture = Fixture::new();
    let (first, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    let (second, _) = fixture.hub(SkillHubTrustTier::Community);
    let id = fixture.import(&first);
    assert_eq!(fixture.import(&second), id);
    assert_eq!(fixture.vault.skill_hub_provenance_count(&id)?, 2);
    let mut active = fixture.vault.get_skill_record(&id)?.expect("candidate");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Approved;
    assert_eq!(
        fixture
            .vault
            .update_skill_record(&id, &active, at(25), 25)
            .expect_err("direct")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let encoded = crate::skill::encode_skill_record(&active)?;
    assert!(
        fixture
            .vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_SKILL,
                at(25),
                25,
                &encoded
            )
            .commit()
            .is_err()
    );
    assert!(
        fixture
            .vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_SKILL,
                at(25),
                25,
                &encoded
            )
            .commit()
            .is_err()
    );
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &first, &publisher, fixture.baseline)?;
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(false), at(30), 30)?
    else {
        panic!("consented");
    };
    assert!(!receipt.accepted);
    assert_eq!(receipt.before, receipt.after);
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("skill")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert!(
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(31), 31)
            .is_err()
    );
    Ok(())
}
#[test]
fn raw_create_and_delete_recreate_cannot_launder_import_origin() -> Result<()> {
    let fixture = Fixture::new();
    let id = EntityId::now();
    let mut record = package("fixture.raw", "1", "raw").record;
    fixture.vault.put_skill_record(&id, &record, at(10), 10)?;
    fixture.vault.delete_entity(&id)?;
    record.source = ClaimSource::UserStated;
    assert!(
        fixture
            .vault
            .put_skill_record(&id, &record, at(11), 11)
            .is_err()
    );
    let other = EntityId::now();
    record.source = ClaimSource::Imported;
    record.lifecycle_status = SkillLifecycle::Active;
    assert!(
        fixture
            .vault
            .batch()
            .put_replicated(
                &other,
                crate::registry::ENTITY_TYPE_SKILL,
                at(12),
                12,
                &crate::skill::encode_skill_record(&record)?
            )
            .commit()
            .is_err()
    );
    Ok(())
}
struct MoveBaseline<'a> {
    fixture: &'a Fixture,
    moved: Cell<bool>,
}
impl HeldOutReplayScorer for MoveBaseline<'_> {
    fn score(&self, _: &HeldOutReplayCase<'_>) -> Result<f32> {
        if !self.moved.replace(true) {
            let mut record = self
                .fixture
                .vault
                .get_skill_record(&self.fixture.baseline)?
                .expect("baseline");
            record.version = "2".to_owned();
            record.desc = "changed while scoring".to_owned();
            self.fixture
                .vault
                .update_skill_record(&self.fixture.baseline, &record, at(40), 40)?;
            Ok(0.1)
        } else {
            Ok(0.9)
        }
    }
}
#[test]
fn callback_runs_without_lock_and_changed_basis_or_revoked_publisher_cannot_admit() -> Result<()> {
    let fixture = Fixture::new();
    let (source, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    let id = fixture.import(&source);
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    assert!(
        fixture
            .vault
            .admit_marketplace_skill(
                &ask,
                &MoveBaseline {
                    fixture: &fixture,
                    moved: Cell::new(false)
                },
                at(41),
                41
            )
            .is_err()
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert!(fixture.vault.hub_admission_receipt(&id)?.is_none());
    fixture
        .vault
        .revoke_consent_grant(&fixture.owner, publisher.grant_ref())?;
    assert!(
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)
            .is_err()
    );
    Ok(())
}
fn useful_question(candidate: EntityId) -> DecisionQuestion {
    DecisionQuestion {
        id: candidate,
        version: 1,
        text: "Is this edit useful upstream?".to_owned(),
        class: DecisionClass::UsefulUpstream,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
struct Useful(bool);
impl UsefulUpstreamJudge for Useful {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        base: &SkillRecord,
        candidate: &HubPackage,
        _: &SharedSkillDelta,
    ) -> Result<TypedDecision> {
        assert_eq!(base.skill_id, candidate.record.skill_id);
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
                    model: "fixture-system-one".to_owned(),
                    version: "1".to_owned(),
                }],
                band: DecisionBand::default(),
            },
            human_ask: None,
        })
    }
}
#[test]
fn federation_and_company_merge_only_submitted_bytes_with_useful_and_replay_lineage() -> Result<()>
{
    for lane in [
        SharedSkillLane::FederationMergeBack,
        SharedSkillLane::CompanyPullRequest,
    ] {
        let company = Fixture::new();
        let personal = Fixture::new();
        let fork = EntityId::now();
        personal.vault.fork_skill_record(
            &personal.baseline,
            &fork,
            "fixture.personal-fork",
            at(10),
            10,
        )?;
        personal.vault.write_shared_skill_fork_package(
            &fork,
            &package("fixture.personal-fork", "2", "check result"),
            at(11),
            11,
        )?;
        // An offered delta returns to its shared base namespace. It is a byte value,
        // not a file path or a request for the receiver to inspect the personal vault.
        let submitted = encode_hub_package(&package("fixture.base", "2", "check result"))?;
        drop(personal); // Drops both the vault AND its directory before company ingress.
        let id = company.vault.submit_shared_skill_delta(
            &company.baseline,
            &submitted,
            lane,
            "member:fixture",
            &fork,
            at(20),
            20,
        )?;
        let ask =
            company
                .vault
                .prepare_shared_skill_merge(id, company.resident, useful_question(id))?;
        assert_eq!(
            company.vault.merge_shared_skill_delta(
                &ask,
                &Useful(true),
                &Replay::new(true),
                at(21),
                21
            )?,
            SharedSkillMergeDisposition::PendingConsent
        );
        company
            .vault
            .approve_shared_skill_merge(&ask, &company.owner)?;
        let SharedSkillMergeDisposition::Ruled(receipt) = company.vault.merge_shared_skill_delta(
            &ask,
            &Useful(true),
            &Replay::new(true),
            at(22),
            22,
        )?
        else {
            panic!("consented");
        };
        assert!(receipt.accepted);
        assert!(receipt.useful_upstream);
        assert_eq!(receipt.resident, company.resident.to_hex());
        assert_eq!(
            receipt.decision.receipt.providers[0].rung,
            DecisionRung::SystemOne
        );
        assert_eq!(receipt.delta.submitted_fork, fork.to_hex());
        assert_eq!(receipt.delta.lane, lane);
        assert_eq!(
            company
                .vault
                .get_skill_record(&id)?
                .expect("successor")
                .lifecycle_status,
            SkillLifecycle::Active
        );
        assert_eq!(
            company
                .vault
                .get_skill_record(&company.baseline)?
                .expect("base")
                .lifecycle_status,
            SkillLifecycle::Superseded
        );
        assert_eq!(
            company.vault.shared_skill_merge_receipt(&id)?,
            Some(*receipt)
        );
    }
    Ok(())
}
#[test]
fn useless_shared_delta_never_runs_replay_or_changes_base() -> Result<()> {
    let fixture = Fixture::new();
    let submitted = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    let id = fixture.vault.submit_shared_skill_delta(
        &fixture.baseline,
        &submitted,
        SharedSkillLane::FederationMergeBack,
        "member:fixture",
        &EntityId::now(),
        at(20),
        20,
    )?;
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(id, fixture.resident, useful_question(id))?;
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    let replay = NoReplay;
    let SharedSkillMergeDisposition::Ruled(receipt) =
        fixture
            .vault
            .merge_shared_skill_delta(&ask, &Useful(false), &replay, at(21), 21)?
    else {
        panic!("consented");
    };
    assert!(!receipt.accepted);
    assert_eq!(receipt.before, None);
    assert_eq!(
        fixture
            .vault
            .shared_skill_delta(&id)?
            .expect("offered delta")
            .candidate,
        id.to_hex()
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("branch candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fixture.baseline)?
            .expect("base")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

struct WrongSeat;
impl UsefulUpstreamJudge for WrongSeat {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        base: &SkillRecord,
        candidate: &HubPackage,
        delta: &SharedSkillDelta,
    ) -> Result<TypedDecision> {
        let mut answer = Useful(true).decide(question, resident, base, candidate, delta)?;
        answer.receipt.providers[0].rung = DecisionRung::Local;
        Ok(answer)
    }
}
struct WrongQuestion;
impl UsefulUpstreamJudge for WrongQuestion {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        base: &SkillRecord,
        candidate: &HubPackage,
        delta: &SharedSkillDelta,
    ) -> Result<TypedDecision> {
        let mut answer = Useful(true).decide(question, resident, base, candidate, delta)?;
        answer.receipt.question = EntityId::now();
        Ok(answer)
    }
}
#[test]
fn merge_refuses_non_system_one_and_unbound_receipts_without_spending_consent() -> Result<()> {
    let fixture = Fixture::new();
    let offered = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    let id = fixture.vault.submit_shared_skill_delta(
        &fixture.baseline,
        &offered,
        SharedSkillLane::FederationMergeBack,
        "member:fixture",
        &EntityId::now(),
        at(20),
        20,
    )?;
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(id, fixture.resident, useful_question(id))?;
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    assert!(
        fixture
            .vault
            .merge_shared_skill_delta(&ask, &WrongSeat, &NoReplay, at(21), 21)
            .is_err()
    );
    assert!(
        fixture
            .vault
            .merge_shared_skill_delta(&ask, &WrongQuestion, &NoReplay, at(21), 21)
            .is_err()
    );
    assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_none());
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fixture.baseline)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Active
    );
    // The rejected answer has neither burned the consent nor erased the branch.
    let ruled = fixture.vault.merge_shared_skill_delta(
        &ask,
        &Useful(true),
        &Replay::new(true),
        at(22),
        22,
    )?;
    assert!(matches!(ruled, SharedSkillMergeDisposition::Ruled(receipt) if receipt.accepted));
    Ok(())
}
#[test]
fn local_refinement_stays_a_fork_until_the_same_merge_gate_admits_it() -> Result<()> {
    let fixture = Fixture::new();
    let fork = EntityId::now();
    fixture
        .vault
        .fork_skill_record(&fixture.baseline, &fork, "fixture.branch", at(10), 10)?;
    fixture.vault.write_shared_skill_fork_package(
        &fork,
        &package("fixture.branch", "2", "check result"),
        at(11),
        11,
    )?;
    let forged = encode_hub_package(&package("fixture.base", "2", "different edit"))?;
    assert!(
        fixture
            .vault
            .submit_local_skill_refinement(
                &fixture.baseline,
                &fork,
                &fixture.resident,
                &forged,
                at(20),
                20,
            )
            .is_err()
    );
    let offered = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    let id = fixture.vault.submit_local_skill_refinement(
        &fixture.baseline,
        &fork,
        &fixture.resident,
        &offered,
        at(20),
        20,
    )?;
    assert_eq!(
        fixture
            .vault
            .shared_skill_delta(&id)?
            .unwrap()
            .submitted_fork,
        fork.to_hex()
    );
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(id, fixture.resident, useful_question(id))?;
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    let ruled =
        fixture
            .vault
            .merge_shared_skill_delta(&ask, &Useful(false), &NoReplay, at(21), 21)?;
    assert!(matches!(ruled, SharedSkillMergeDisposition::Ruled(receipt) if !receipt.accepted));
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fork)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fixture.baseline)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}
#[test]
fn local_refinement_yes_needs_independent_held_out_win() -> Result<()> {
    let fixture = Fixture::new();
    let fork = EntityId::now();
    fixture
        .vault
        .fork_skill_record(&fixture.baseline, &fork, "fixture.branch", at(10), 10)?;
    fixture.vault.write_shared_skill_fork_package(
        &fork,
        &package("fixture.branch", "2", "check result"),
        at(11),
        11,
    )?;
    let offered = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    let id = fixture.vault.submit_local_skill_refinement(
        &fixture.baseline,
        &fork,
        &fixture.resident,
        &offered,
        at(20),
        20,
    )?;
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(id, fixture.resident, useful_question(id))?;
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    let ruled = fixture.vault.merge_shared_skill_delta(
        &ask,
        &Useful(true),
        &Replay::new(true),
        at(21),
        21,
    )?;
    assert!(matches!(ruled, SharedSkillMergeDisposition::Ruled(receipt) if receipt.accepted));
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Active
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fixture.baseline)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Superseded
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fork)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}
#[test]
fn rejected_local_delta_cannot_activate_through_same_byte_hub_alias() -> Result<()> {
    let fixture = Fixture::new();
    let fork = EntityId::now();
    fixture
        .vault
        .fork_skill_record(&fixture.baseline, &fork, "fixture.branch", at(10), 10)?;
    fixture.vault.write_shared_skill_fork_package(
        &fork,
        &package("fixture.branch", "2", "check result"),
        at(11),
        11,
    )?;
    let submitted = package("fixture.base", "2", "check result");
    let bytes = encode_hub_package(&submitted)?;
    let id = fixture.vault.submit_local_skill_refinement(
        &fixture.baseline,
        &fork,
        &fixture.resident,
        &bytes,
        at(20),
        20,
    )?;
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(id, fixture.resident, useful_question(id))?;
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    assert!(matches!(
        fixture.vault.merge_shared_skill_delta(&ask, &Useful(false), &NoReplay, at(21), 21)?,
        SharedSkillMergeDisposition::Ruled(receipt) if !receipt.accepted
    ));
    let (source, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    let alias = HubRef::new(
        source.hub_id,
        "same-bytes",
        HubPin::ContentHash(submitted.content_hash()?.to_hex()),
    )?;
    assert_eq!(
        fixture
            .vault
            .import_skill_from_hub(&alias, &submitted, at(22), 22)?,
        id
    );
    assert_eq!(fixture.vault.skill_hub_provenance_count(&id)?, 1);
    assert!(
        fixture
            .vault
            .prepare_marketplace_activation(id, &alias, &publisher, fixture.baseline,)
            .is_err()
    );
    assert!(
        fixture
            .vault
            .supersede_skill_record(&fixture.baseline, &id, at(23), 23)
            .is_err()
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fixture.baseline)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Active
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&fork)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn local_refinement_retargeted_upstream_version_is_independent_of_branch_version() -> Result<()> {
    let fixture = Fixture::new();
    let mut base = fixture.vault.get_skill_record(&fixture.baseline)?.unwrap();
    base.version = "2".to_owned();
    fixture
        .vault
        .update_skill_record(&fixture.baseline, &base, at(8), 8)?;
    let fork = EntityId::now();
    fixture
        .vault
        .fork_skill_record(&fixture.baseline, &fork, "fixture.branch", at(10), 10)?;
    fixture.vault.write_shared_skill_fork_package(
        &fork,
        &package("fixture.branch", "2", "check result"),
        at(11),
        11,
    )?;
    let submitted = encode_hub_package(&package("fixture.base", "3", "check result"))?;
    let id = fixture.vault.submit_local_skill_refinement(
        &fixture.baseline,
        &fork,
        &fixture.resident,
        &submitted,
        at(20),
        20,
    )?;
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(id, fixture.resident, useful_question(id))?;
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    assert!(matches!(
        fixture.vault.merge_shared_skill_delta(&ask, &Useful(true), &Replay::new(true), at(21), 21)?,
        SharedSkillMergeDisposition::Ruled(receipt) if receipt.accepted
    ));
    assert_eq!(fixture.vault.get_skill_record(&id)?.unwrap().version, "3");
    assert_eq!(fixture.vault.get_skill_record(&fork)?.unwrap().version, "2");
    Ok(())
}

#[test]
fn raw_package_cannot_understate_the_file_manifest_capabilities() -> Result<()> {
    let fixture = Fixture::new();
    let (mut source, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    let files = vec![HubFile::new("SKILL.md", b"---\nname: fixture.wide\ndescription: fixture\nversion: 1\nrequires-env: [\"SENSITIVE_INPUT\"]\n---\ncheck result\n".to_vec())];
    let mut package = super::folder::package_from_files(files)?;
    package.capabilities = SkillCapabilitySurface::default();
    source.pin = HubPin::ContentHash(package.content_hash()?.to_hex());
    let candidate = fixture
        .vault
        .import_skill_from_hub(&source, &package, at(30), 30)?;
    assert!(
        fixture
            .vault
            .prepare_marketplace_activation(candidate, &source, &publisher, fixture.baseline)
            .is_err()
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&candidate)?
            .expect("candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn admitted_pack_load_returns_actual_files_and_stamps_once() -> Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome, ManifestKind};
    let fixture = Fixture::new();
    let (source, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    let id = fixture.import(&source);
    let queue = AttemptQueue::new(&fixture.vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "pack.runtime".to_owned(),
        payload: vec![],
        dedupe_key: None,
        run_id: None,
        now: 25,
    })?
    else {
        panic!("new attempt")
    };
    assert!(
        fixture
            .vault
            .load_attempt_skill_pack(attempt.id, &id, 25)
            .is_err()
    );
    assert!(queue.get(attempt.id)?.unwrap().manifest.is_empty());
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(31), 31)?
    else {
        panic!("consented")
    };
    assert!(receipt.accepted);
    let loaded = fixture.vault.load_attempt_skill_pack(attempt.id, &id, 32)?;
    assert_eq!(
        loaded.source_files,
        Some(package("fixture.new", "1", "check result").files)
    );
    assert_eq!(loaded.record.lifecycle_status, SkillLifecycle::Active);
    let manifest = queue.get(attempt.id)?.unwrap().manifest;
    assert_eq!(manifest.len(), 1);
    assert_eq!(manifest[0].kind, ManifestKind::Skill);
    assert_eq!(manifest[0].reference, loaded.record.skill_id);
    Ok(())
}

#[test]
fn native_owner_forks_keep_their_door_but_imported_ancestry_never_launders() -> Result<()> {
    let fixture = Fixture::new();
    let own_fork = EntityId::now();
    let mut own =
        fixture
            .vault
            .fork_skill_record(&fixture.baseline, &own_fork, "own.fork", at(20), 20)?;
    own.lifecycle_status = SkillLifecycle::Active;
    fixture
        .vault
        .update_skill_record(&own_fork, &own, at(21), 21)?;
    let (source, _) = fixture.hub(SkillHubTrustTier::Verified);
    let imported = fixture.import(&source);
    let foreign_fork = EntityId::now();
    fixture
        .vault
        .fork_skill_record(&imported, &foreign_fork, "foreign.fork", at(22), 22)?;
    let descendant = EntityId::now();
    let mut fork = fixture.vault.fork_skill_record(
        &foreign_fork,
        &descendant,
        "foreign.descendant",
        at(23),
        23,
    )?;
    fork.lifecycle_status = SkillLifecycle::Active;
    assert!(
        fixture
            .vault
            .update_skill_record(&descendant, &fork, at(24), 24)
            .is_err()
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&descendant)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn active_hub_sync_proposes_changed_bytes_until_the_scored_admission_door() -> Result<()> {
    let fixture = Fixture::new();
    let (mut source, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    source.pin = HubPin::None;
    let id = fixture.import(&source);
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(31), 31)?
    else {
        panic!("consented")
    };
    assert!(receipt.accepted);
    let before = fixture.vault.get_skill_record(&id)?.unwrap();
    let next = package("fixture.new", "2", "check result carefully");
    let first = fixture.vault.sync_skill_from_hub(
        &id,
        &source,
        &next,
        HubSyncPolicy::MirrorOfHub,
        at(32),
        32,
    )?;
    let HubSyncDisposition::Proposed {
        proposal_id,
        approval,
    } = first
    else {
        panic!("review required")
    };
    assert_eq!(approval, ClaimApprovalStatus::Proposed);
    let body = fixture.vault.get_claim(&proposal_id)?.unwrap();
    assert_eq!(
        map_value(&body.value, "requiresHeldOut").and_then(rmpv::Value::as_bool),
        Some(true)
    );
    assert_eq!(fixture.vault.get_skill_record(&id)?.unwrap(), before);
    assert_eq!(
        fixture.vault.sync_skill_from_hub(
            &id,
            &source,
            &next,
            HubSyncPolicy::MirrorOfHub,
            at(33),
            33
        )?,
        first
    );
    Ok(())
}

#[test]
fn native_source_metadata_needs_the_same_human_and_held_out_admission() -> Result<()> {
    let fixture = Fixture::new();
    let (original, publisher) = fixture.hub(SkillHubTrustTier::Community);
    let mut native = package("fixture.native", "native-revision", "check result");
    native.files = vec![HubFile::new(
        "SKILL.md",
        b"---\nname: source-name\n---\ncheck result\n".to_vec(),
    )];
    native.format = SkillPackageFormat::Native;
    native.record.content_hash = Some(native.content_hash()?);
    let source = HubRef::new(
        original.hub_id,
        "native",
        HubPin::ContentHash(native.content_hash()?.to_hex()),
    )?;
    let id = fixture
        .vault
        .import_skill_from_hub(&source, &native, at(20), 20)?;
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    assert_eq!(
        fixture
            .vault
            .admit_marketplace_skill(&ask, &NoReplay, at(21), 21)?,
        HubAdmissionDisposition::PendingConsent
    );
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(22), 22)?
    else {
        panic!("consented native source")
    };
    assert!(receipt.accepted);
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("active native source")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}
