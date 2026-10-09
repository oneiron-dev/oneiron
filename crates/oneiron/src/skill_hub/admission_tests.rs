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
    skill_optimize::{BlindPreference, HeldOutReplayCase, HeldOutReplayScorer, PreferredResponse},
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
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, _: &HeldOutReplayCase<'_>) -> Result<f32> {
        panic!("replay must not run before consent or usefulness");
    }
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}
impl HeldOutReplayScorer for Replay {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
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
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
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
        assert_eq!(receipt.judge_revision, "fixture-judge@1");
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
fn pending_legacy_admission_cannot_bypass_a_new_owner_hash_block() -> Result<()> {
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
    let hash = package("fixture.new", "1", "check result").content_hash()?;
    fixture
        .vault
        .set_marketplace_blocked_hash(&fixture.owner, hash, true)?;
    assert_eq!(
        fixture
            .vault
            .admit_marketplace_skill(&ask, &NoReplay, at(30), 30)
            .expect_err("a later owner rule overrides the earlier ask")
            .kind(),
        ErrorKind::InvalidSkillBody,
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
    assert_eq!(
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)
            .expect_err("blocked even on new ask")
            .kind(),
        ErrorKind::InvalidSkillBody,
    );
    // The denied attempt spent no pre-existing consent. Unblocking restores
    // the ask without accepting the blocked activation.
    fixture
        .vault
        .set_marketplace_blocked_hash(&fixture.owner, hash, false)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(31), 31)?
    else {
        panic!("unblocked admission");
    };
    assert!(receipt.accepted);
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
    fixture
        .vault
        .delete_entity_with_options(&id, crate::deletion::DeleteEntityOptions { purge: true })?;
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
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
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
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
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
                band_version: 0,
                evidence_versions: Vec::new(),
                cost_per_thousand: None,
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
        let resident = EntityId::now();
        personal.vault.put_entity(
            &resident,
            crate::registry::ENTITY_TYPE_PERSON,
            at(9),
            9,
            b"resident",
        )?;
        personal.vault.fork_skill_for_resident(
            &resident,
            &personal.baseline,
            &fork,
            "fixture.personal-fork",
            at(10),
            10,
        )?;
        assert_eq!(
            crate::skill::resident_of(&personal.vault.get_skill_record(&fork)?.expect("fork"))?,
            Some(resident),
        );
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
        assert_eq!(receipt.judge_revision.as_deref(), Some("fixture-judge@1"));
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
fn resident_fork_delta_without_held_out_gain_cannot_merge_upstream() -> Result<()> {
    let company = Fixture::new();
    let personal = Fixture::new();
    let resident = EntityId::now();
    personal.vault.put_entity(
        &resident,
        crate::registry::ENTITY_TYPE_PERSON,
        at(9),
        9,
        b"resident",
    )?;
    let fork = EntityId::now();
    personal.vault.fork_skill_for_resident(
        &resident,
        &personal.baseline,
        &fork,
        "fixture.resident-fork",
        at(10),
        10,
    )?;
    personal.vault.write_shared_skill_fork_package(
        &fork,
        &package("fixture.resident-fork", "2", "check result"),
        at(11),
        11,
    )?;
    let submitted = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    drop(personal);
    let id = company.vault.submit_shared_skill_delta(
        &company.baseline,
        &submitted,
        SharedSkillLane::FederationMergeBack,
        "member:fixture",
        &fork,
        at(20),
        20,
    )?;
    let ask =
        company
            .vault
            .prepare_shared_skill_merge(id, company.resident, useful_question(id))?;
    company
        .vault
        .approve_shared_skill_merge(&ask, &company.owner)?;
    let SharedSkillMergeDisposition::Ruled(receipt) = company.vault.merge_shared_skill_delta(
        &ask,
        &Useful(true),
        &Replay::new(false),
        at(21),
        21,
    )?
    else {
        panic!("consented")
    };
    assert!(receipt.useful_upstream);
    assert!(!receipt.accepted);
    assert!(receipt.before.is_some() && receipt.after.is_some());
    assert_eq!(
        company
            .vault
            .get_skill_record(&company.baseline)?
            .expect("base")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    assert_eq!(
        company
            .vault
            .get_skill_record(&id)?
            .expect("candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
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

struct SecretProvider(bool);
impl UsefulUpstreamJudge for SecretProvider {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        base: &SkillRecord,
        candidate: &HubPackage,
        delta: &SharedSkillDelta,
    ) -> Result<TypedDecision> {
        let mut decision = Useful(self.0).decide(question, resident, base, candidate, delta)?;
        decision.receipt.providers[0].model =
            crate::test_util::SYNTHETIC_PRIVATE_KEY_BLOCK.to_owned();
        Ok(decision)
    }
}
#[test]
fn shared_merge_scans_questions_and_provider_receipts_before_any_ruling() -> Result<()> {
    for useful in [false, true] {
        let fixture = Fixture::new();
        let replay = Replay::new(true);
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
        let mut unsafe_question = useful_question(id);
        unsafe_question.text = crate::test_util::SYNTHETIC_PRIVATE_KEY_BLOCK.to_owned();
        assert!(
            fixture
                .vault
                .prepare_shared_skill_merge(id, fixture.resident, unsafe_question)
                .is_err()
        );
        assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_none());
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
                .merge_shared_skill_delta(&ask, &SecretProvider(useful), &replay, at(21), 21,)
                .is_err()
        );
        assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_none());
        let txn = fixture.vault.store.env.read_txn()?;
        assert!(
            !super::refinement_custody_exists_in_txn(&fixture.vault.store, &txn, &id)?,
            "no receipt carrier may hold rejected provider metadata"
        );
        drop(txn);
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
        // Secret rejection must not consume approval; a clean answer still works.
        let ruled =
            fixture
                .vault
                .merge_shared_skill_delta(&ask, &Useful(useful), &replay, at(22), 22)?;
        assert!(
            matches!(ruled, SharedSkillMergeDisposition::Ruled(receipt) if receipt.accepted == useful)
        );
    }
    Ok(())
}

#[test]
fn shared_skill_merge_deletion_purges_current_and_every_historical_question() -> Result<()> {
    for admitted in [false, true] {
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
        let mut history = Vec::new();
        for iteration in 0..(if admitted { 1 } else { 2 }) {
            let mut question = useful_question(id);
            question.text = format!("unique-personal-question-{admitted}-{iteration}");
            let ask = fixture
                .vault
                .prepare_shared_skill_merge(id, fixture.resident, question)?;
            fixture
                .vault
                .approve_shared_skill_merge(&ask, &fixture.owner)?;
            let SharedSkillMergeDisposition::Ruled(receipt) =
                fixture.vault.merge_shared_skill_delta(
                    &ask,
                    &Useful(admitted),
                    &Replay::new(true),
                    at(21 + iteration),
                    21 + iteration,
                )?
            else {
                panic!("consented")
            };
            history.push(receipt.receipt_id.clone());
        }
        assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_some());
        let txn = fixture.vault.store.env.read_txn()?;
        let carriers =
            super::refinement_carriers_for_holder_in_txn(&fixture.vault.store, &txn, &id)?;
        assert_eq!(carriers.len(), history.len());
        drop(txn);
        for carrier in &carriers {
            assert!(fixture.vault.get_raw(carrier)?.is_some());
        }
        assert!(fixture.vault.delete_entity(&id)?);
        assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_none());
        let Fixture {
            vault, _temp: dir, ..
        } = fixture;
        drop(vault);
        let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
        assert!(reopened.shared_skill_merge_receipt(&id)?.is_none());
        for carrier in carriers {
            assert!(reopened.get_raw(&carrier)?.is_none());
        }
    }
    Ok(())
}

#[test]
fn replayed_shared_skill_delete_purges_merge_questions_for_both_outcomes() -> Result<()> {
    for reason in [
        crate::deletion::TombstoneReason::UserDelete,
        crate::deletion::TombstoneReason::GdprDelete,
    ] {
        for accepted in [false, true] {
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
            let ask = fixture.vault.prepare_shared_skill_merge(
                id,
                fixture.resident,
                useful_question(id),
            )?;
            fixture
                .vault
                .approve_shared_skill_merge(&ask, &fixture.owner)?;
            let SharedSkillMergeDisposition::Ruled(receipt) =
                fixture.vault.merge_shared_skill_delta(
                    &ask,
                    &Useful(accepted),
                    &Replay::new(true),
                    at(21),
                    21,
                )?
            else {
                panic!("consented")
            };
            let txn = fixture.vault.store.env.read_txn()?;
            let carriers =
                super::refinement_carriers_for_holder_in_txn(&fixture.vault.store, &txn, &id)?;
            assert_eq!(carriers.len(), 1);
            assert_eq!(receipt.delta.candidate, id.to_hex());
            drop(txn);
            let tombstone = crate::deletion::TombstoneValueV2 {
                reason,
                deleted_at: 23,
                request_id: *EntityId::now().as_bytes(),
            }
            .encode();
            fixture.vault.apply_replayed_tombstone(&id, &tombstone)?;
            assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_none());
            for carrier in carriers {
                assert!(fixture.vault.get_raw(&carrier)?.is_none());
            }
        }
    }
    Ok(())
}

#[test]
fn shared_skill_erase_matrix_retains_denial_after_raw_local_and_replayed_delete() -> Result<()> {
    for state in ["pending", "refused", "admitted"] {
        for mode in ["raw", "local", "replayed"] {
            let fixture = Fixture::new();
            let submitted = encode_hub_package(&package("fixture.base", "2", "check result"))?;
            let candidate = fixture.vault.submit_shared_skill_delta(
                &fixture.baseline,
                &submitted,
                SharedSkillLane::FederationMergeBack,
                "member:fixture",
                &EntityId::now(),
                at(20),
                20,
            )?;
            if state != "pending" {
                let ask = fixture.vault.prepare_shared_skill_merge(
                    candidate,
                    fixture.resident,
                    useful_question(candidate),
                )?;
                fixture
                    .vault
                    .approve_shared_skill_merge(&ask, &fixture.owner)?;
                fixture.vault.merge_shared_skill_delta(
                    &ask,
                    &Useful(state == "admitted"),
                    &Replay::new(true),
                    at(21),
                    21,
                )?;
            }
            let mut attempted = fixture
                .vault
                .get_skill_record(&candidate)?
                .expect("candidate");
            attempted.lifecycle_status = SkillLifecycle::Active;
            attempted.approval_status = ClaimApprovalStatus::Approved;
            match mode {
                "raw" => {
                    fixture.vault.batch().delete(&candidate).commit()?;
                }
                "local" => {
                    assert!(fixture.vault.delete_entity(&candidate)?);
                }
                _ => {
                    let tombstone = crate::deletion::TombstoneValueV2 {
                        reason: crate::deletion::TombstoneReason::GdprDelete,
                        deleted_at: 23,
                        request_id: *EntityId::now().as_bytes(),
                    }
                    .encode();
                    fixture
                        .vault
                        .apply_replayed_tombstone(&candidate, &tombstone)?;
                }
            }
            assert!(
                fixture
                    .vault
                    .shared_skill_merge_receipt(&candidate)?
                    .is_none()
            );
            let Fixture {
                vault, _temp: dir, ..
            } = fixture;
            drop(vault);
            let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
            assert!(reopened.shared_skill_merge_receipt(&candidate)?.is_none());
            assert!(
                reopened
                    .batch()
                    .put_replicated(
                        &candidate,
                        crate::registry::ENTITY_TYPE_SKILL,
                        at(30),
                        30,
                        &crate::skill::encode_skill_record(&attempted)?
                    )
                    .commit()
                    .is_err(),
                "{state}/{mode}: erased refinement id cannot become active"
            );
        }
    }
    Ok(())
}

fn replay_native_skill(
    vault: &Vault,
    id: EntityId,
    record: &SkillRecord,
    stamp: u64,
) -> Result<()> {
    let data = crate::skill::encode_skill_record(record)?;
    #[cfg(feature = "sync")]
    {
        crate::sync::replay::replay_entity(
            vault,
            crate::sync::replay::ReplicatedEntity {
                id,
                entity_type: crate::registry::ENTITY_TYPE_SKILL,
                occurred: at(stamp),
                learned_at: stamp,
                body: &data,
            },
            crate::sync::client::ImportTier::OwnDevice,
        )
    }
    #[cfg(not(feature = "sync"))]
    {
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_SKILL,
                at(stamp),
                stamp,
                &data,
            )
            .commit()
    }
}

#[test]
fn replayed_shared_skill_delta_cannot_activate_through_same_byte_marketplace_alias() -> Result<()> {
    let sender = Fixture::new();
    let fork = EntityId::now();
    sender
        .vault
        .fork_skill_record(&sender.baseline, &fork, "fixture.branch", at(10), 10)?;
    sender.vault.write_shared_skill_fork_package(
        &fork,
        &package("fixture.branch", "2", "check result"),
        at(11),
        11,
    )?;
    let offered = package("fixture.base", "2", "check result");
    let submitted = encode_hub_package(&offered)?;
    let candidate = sender.vault.submit_local_skill_refinement(
        &sender.baseline,
        &fork,
        &sender.resident,
        &submitted,
        at(20),
        20,
    )?;
    let native = sender
        .vault
        .get_skill_record(&candidate)?
        .expect("native Candidate");
    let receiver = Fixture::new();
    replay_native_skill(&receiver.vault, candidate, &native, 20)?;
    assert!(
        receiver.vault.shared_skill_delta(&candidate)?.is_none(),
        "the receiver did not submit this delta locally"
    );
    let (hub, publisher) = receiver.hub(SkillHubTrustTier::Verified);
    let alias = HubRef::new(
        hub.hub_id,
        "same-bytes",
        HubPin::ContentHash(offered.content_hash()?.to_hex()),
    )?;
    assert_eq!(
        receiver
            .vault
            .import_skill_from_hub(&alias, &offered, at(22), 22)?,
        candidate
    );
    assert_eq!(receiver.vault.skill_hub_provenance_count(&candidate)?, 1);
    assert!(
        receiver
            .vault
            .prepare_marketplace_activation(candidate, &alias, &publisher, receiver.baseline,)
            .is_err(),
        "marketplace held-out admission cannot replace useful-upstream"
    );
    assert_eq!(
        receiver
            .vault
            .get_skill_record(&candidate)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        receiver
            .vault
            .get_skill_record(&receiver.baseline)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Active
    );
    receiver.vault.batch().delete(&candidate).commit()?;
    let txn = receiver.vault.store.env.read_txn()?;
    assert!(super::skill_refinement_origin_in_txn(
        &receiver.vault.store,
        &txn,
        &candidate
    )?);
    drop(txn);
    assert!(
        replay_native_skill(&receiver.vault, candidate, &native, 30).is_err(),
        "raw deletion cannot free the replayed refinement ID"
    );
    assert!(receiver.vault.get_skill_record(&candidate)?.is_none());
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
            .load_attempt_skill_pack(attempt.id, &id, "worker", 1, "fixture/model@1", 25)
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
    let crate::attempt_queue::ClaimOutcome::Claimed(leased) =
        queue.claim(crate::attempt_queue::ClaimAttempt {
            lease_owner: "worker".to_owned(),
            now: 32,
        })?
    else {
        panic!("claim")
    };
    let loaded = fixture.vault.load_attempt_skill_pack(
        attempt.id,
        &id,
        "worker",
        leased.attempt_count,
        "fixture/model@1",
        32,
    )?;
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

#[test]
fn marketplace_and_shared_merge_keep_scores_but_mark_displaced_judge() -> Result<()> {
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
    let HubAdmissionDisposition::Ruled(admission) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(31), 31)?
    else {
        panic!("admission")
    };
    assert_eq!(admission.judge_revision, "fixture-judge@1");
    assert!(admission.displaced_by_revision.is_none());

    let submitted = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    let merged = fixture.vault.submit_shared_skill_delta(
        &fixture.baseline,
        &submitted,
        SharedSkillLane::CompanyPullRequest,
        "member:fixture",
        &EntityId::now(),
        at(40),
        40,
    )?;
    let merge_ask = fixture.vault.prepare_shared_skill_merge(
        merged,
        fixture.resident,
        useful_question(merged),
    )?;
    fixture
        .vault
        .approve_shared_skill_merge(&merge_ask, &fixture.owner)?;
    let SharedSkillMergeDisposition::Ruled(merge_receipt) = fixture
        .vault
        .merge_shared_skill_delta(&merge_ask, &Useful(true), &Replay::new(true), at(41), 41)?
    else {
        panic!("merged")
    };
    assert_eq!(
        merge_receipt.judge_revision.as_deref(),
        Some("fixture-judge@1")
    );
    let before = (admission.before, admission.after);
    let merge_scores = (merge_receipt.before, merge_receipt.after);
    // No optimizer verdict is needed to establish this vault-wide fence.
    crate::skill_optimize::supersede_skill_edit_judge(
        &fixture.vault,
        "fixture-judge@1",
        "fixture-judge@2",
    )?;
    let old = fixture.vault.hub_admission_receipt(&id)?.unwrap();
    let old_merge = fixture.vault.shared_skill_merge_receipt(&merged)?.unwrap();
    assert_eq!((old.before, old.after), before);
    assert_eq!((old_merge.before, old_merge.after), merge_scores);
    assert_eq!(
        old.displaced_by_revision.as_deref(),
        Some("fixture-judge@2")
    );
    assert_eq!(
        old_merge.displaced_by_revision.as_deref(),
        Some("fixture-judge@2")
    );
    // Outward JSON and MessagePack views carry the derived mark; the stored
    // receipt remains the immutable score pair written before displacement.
    let marketplace_json = serde_json::to_value(&old)
        .map_err(|_| crate::Error::InvariantViolation("marketplace fixture JSON"))?;
    let merge_json = serde_json::to_value(&old_merge)
        .map_err(|_| crate::Error::InvariantViolation("merge fixture JSON"))?;
    assert_eq!(marketplace_json["displaced_by_revision"], "fixture-judge@2");
    assert_eq!(merge_json["displaced_by_revision"], "fixture-judge@2");
    assert_eq!(
        serde_json::from_value::<HubAdmissionReceipt>(marketplace_json)
            .map_err(|_| crate::Error::InvariantViolation("marketplace JSON read"))?,
        old
    );
    assert_eq!(
        serde_json::from_value::<SharedSkillMergeReceipt>(merge_json)
            .map_err(|_| crate::Error::InvariantViolation("merge JSON read"))?,
        old_merge
    );
    let bytes = rmp_serde::to_vec_named(&old)
        .map_err(|_| crate::Error::InvariantViolation("marketplace msgpack"))?;
    assert_eq!(
        rmp_serde::from_slice::<HubAdmissionReceipt>(&bytes)
            .map_err(|_| crate::Error::InvariantViolation("marketplace msgpack read"))?,
        old
    );
    let bytes = rmp_serde::to_vec_named(&old_merge)
        .map_err(|_| crate::Error::InvariantViolation("merge msgpack"))?;
    assert_eq!(
        rmp_serde::from_slice::<SharedSkillMergeReceipt>(&bytes)
            .map_err(|_| crate::Error::InvariantViolation("merge msgpack read"))?,
        old_merge
    );
    Ok(())
}

#[test]
fn judge_replaced_mid_marketplace_or_merge_scoring_cannot_write_a_ruling() -> Result<()> {
    struct Replacing<'a> {
        vault: &'a Vault,
        changed: std::cell::Cell<bool>,
    }
    impl HeldOutReplayScorer for Replacing<'_> {
        fn judge_revision(&self) -> &str {
            "old-hub@1"
        }
        fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
            if !self.changed.replace(true) {
                crate::skill_optimize::supersede_skill_edit_judge(
                    self.vault,
                    "old-hub@1",
                    "new-hub@2",
                )?;
            }
            Ok(if case.instructions.contains("check result") {
                0.9
            } else {
                0.2
            })
        }
    }
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
    let scorer = Replacing {
        vault: &fixture.vault,
        changed: std::cell::Cell::new(false),
    };
    assert!(
        fixture
            .vault
            .admit_marketplace_skill(&ask, &scorer, at(31), 31)
            .is_err()
    );
    assert!(fixture.vault.hub_admission_receipt(&id)?.is_none());
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );

    let other = Fixture::new();
    let submitted = encode_hub_package(&package("fixture.base", "2", "check result"))?;
    let candidate = other.vault.submit_shared_skill_delta(
        &other.baseline,
        &submitted,
        SharedSkillLane::CompanyPullRequest,
        "member:fixture",
        &EntityId::now(),
        at(40),
        40,
    )?;
    let ask = other.vault.prepare_shared_skill_merge(
        candidate,
        other.resident,
        useful_question(candidate),
    )?;
    other.vault.approve_shared_skill_merge(&ask, &other.owner)?;
    let scorer = Replacing {
        vault: &other.vault,
        changed: std::cell::Cell::new(false),
    };
    assert!(
        other
            .vault
            .merge_shared_skill_delta(&ask, &Useful(true), &scorer, at(41), 41)
            .is_err()
    );
    assert!(
        other
            .vault
            .shared_skill_merge_receipt(&candidate)?
            .is_none()
    );
    assert_eq!(
        other
            .vault
            .get_skill_record(&candidate)?
            .unwrap()
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn imported_callable_stays_candidate_without_foreign_sandbox_qualification() -> Result<()> {
    let fixture = Fixture::new();
    let (source, publisher) = fixture.hub(SkillHubTrustTier::Verified);
    let package = super::folder::package_from_files(vec![
        HubFile::new("SKILL.md", b"---\nname: fixture.callable\ndescription: fixture\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\ncheck result\n".to_vec()),
        HubFile::new("scripts/call.js", b"finish(JSON.stringify({result:skillArgs.value+1}));".to_vec()),
    ])?;
    let source = HubRef::new(
        source.hub_id,
        "fixture.callable",
        HubPin::ContentHash(package.content_hash()?.to_hex()),
    )?;
    let id = fixture
        .vault
        .import_skill_from_hub(&source, &package, at(20), 20)?;
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let error = fixture
        .vault
        .admit_marketplace_skill(&ask, &Replay::new(true), at(31), 31)
        .expect_err("text replay does not qualify foreign code execution");
    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn edited_shared_fork_persists_each_role_and_callable_contract_change() -> Result<()> {
    let fixture = Fixture::new();
    let fork_id = EntityId::now();
    fixture.vault.fork_skill_record(
        &fixture.baseline,
        &fork_id,
        "fixture.edited-fork",
        at(40),
        40,
    )?;
    let callable = |version: &str, reference: &str, output: &str| -> Result<HubPackage> {
        super::folder::package_from_files(vec![
            HubFile::new("SKILL.md", format!("---\nname: fixture.edited-fork\ndescription: fixture\nversion: {version}\nrole: callable\ncall:\n  reference: {reference}\n  arguments: {{\"value\":\"integer\"}}\n  returns: {{\"value\":\"{output}\"}}\n---\nBody\n").into_bytes()),
            HubFile::new("scripts/run.js", b"finish(JSON.stringify({value:skillArgs.value}));".to_vec()),
            HubFile::new("scripts/other.js", b"finish(JSON.stringify({value:skillArgs.value}));".to_vec()),
        ])
    };
    fixture.vault.write_shared_skill_fork_package(
        &fork_id,
        &callable("2", "scripts/run.js", "integer")?,
        at(41),
        41,
    )?;
    let first = fixture
        .vault
        .get_skill_record(&fork_id)?
        .expect("callable fork");
    assert_eq!(first.role, crate::skill::SkillRole::Callable);
    assert_eq!(first.call.as_ref().unwrap().reference, "scripts/run.js");
    fixture.vault.write_shared_skill_fork_package(
        &fork_id,
        &callable("3", "scripts/other.js", "number")?,
        at(42),
        42,
    )?;
    let second = fixture
        .vault
        .get_skill_record(&fork_id)?
        .expect("changed call");
    assert_eq!(second.call.as_ref().unwrap().reference, "scripts/other.js");
    assert_eq!(
        second.call.as_ref().unwrap().returns,
        serde_json::json!({"value":"number"})
    );
    let knowledge = super::folder::package_from_files(vec![HubFile::new("SKILL.md",
        b"---\nname: fixture.edited-fork\ndescription: fixture\nversion: 4\nrole: knowledge\n---\nBody\n".to_vec())])?;
    fixture
        .vault
        .write_shared_skill_fork_package(&fork_id, &knowledge, at(43), 43)?;
    let third = fixture
        .vault
        .get_skill_record(&fork_id)?
        .expect("knowledge fork");
    assert_eq!(third.role, crate::skill::SkillRole::Knowledge);
    assert_eq!(third.call, None);
    Ok(())
}
