// GATE-22: ARCH-0053 #promise-gate-22 — held-out fit activates; only a permission widening asks.
// GATE-23: ARCH-0053 #promise-gate-23 — a scanner flag does not hold a same-permission merge.
use std::collections::BTreeMap;
use std::time::Duration;

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, ManifestEntry,
    ManifestKind,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::error::Result;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionClass,
    DecisionDial, DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung,
    HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin, TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    ForeignSkillPublisher, HubAdmissionDisposition, HubFile, HubPackage, HubPin, HubRef,
    HubSyncPolicy, ScanCompleteness, ScanRiskLevel, ScanVerdict, SharedSkillLane,
    SharedSkillMergeDisposition, SkillCapabilitySurface, SkillGovernance, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier, SkillScanReceipt, UsefulUpstreamDecisions,
    encode_hub_package,
};
use oneiron::skill_optimize::{
    HeldOutReplayCase, HeldOutReplayNotes, SkillOptimizeDecisions, SkillReplayResponses,
};
use oneiron::skill_scan::{
    ActivationPosture, scan_gate_for_activation, set_skill_scan_activation_risk_threshold,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

fn package(name: &str, version: &str, instructions: &str, read_file: bool) -> HubPackage {
    let tools = if read_file {
        "allowed-tools: [\"read_file\"]\n"
    } else {
        ""
    };
    let content = format!(
        "---\nname: {name}\ndescription: fixture\nversion: {version}\n{tools}---\n{instructions}\n"
    );
    let record = SkillRecord::new(
        name,
        "fixture",
        version,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("hub-folder"),
        )]),
    );
    let capabilities = if read_file {
        SkillCapabilitySurface::default().with_allowed_tool("read_file")
    } else {
        SkillCapabilitySurface::default()
    };
    let mut package = HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.into_bytes())],
        capabilities,
    );
    package.record.content_hash = Some(package.content_hash().expect("package hash"));
    package
}

struct Fixture {
    vault: Vault,
    _temp: tempfile::TempDir,
    owner: AuthenticatedOwner,
    baseline: EntityId,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(temp.path(), VaultConfig::default()).expect("vault");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(
                owner_id,
                "principal:fixture-owner",
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .expect("authenticated owner");
        let baseline = active_baseline(&vault, "fixture.base", 2);
        Self {
            vault,
            _temp: temp,
            owner,
            baseline,
        }
    }

    fn hub(&self) -> (EntityId, ForeignSkillPublisher) {
        let id = EntityId::now();
        let record = SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            "https://example.invalid/index.json",
            SkillHubTrustTier::Community,
            HubSyncPolicy::ContentHashFrozen,
        )
        .expect("hub record");
        self.vault
            .configure_skill_hub(&self.owner, &id, &record, at(10), 10)
            .expect("configure hub");
        let publisher = self
            .vault
            .admit_skill_publisher(&self.owner, "publisher:outside", id)
            .expect("admitted publisher");
        (id, publisher)
    }

    fn import(
        &self,
        hub: EntityId,
        reference: &str,
        package: &HubPackage,
        now: u64,
    ) -> (EntityId, HubRef) {
        let source = HubRef::new(
            hub,
            reference,
            HubPin::ContentHash(package.content_hash().expect("package hash").to_hex()),
        )
        .expect("pinned source");
        let id = self
            .vault
            .import_skill_from_hub(&source, package, at(now), now)
            .expect("import candidate");
        (id, source)
    }
}

/// An active local skill with a held-out reserve, written at `now` and `now + 1`.
fn active_baseline(vault: &Vault, name: &str, now: u64) -> EntityId {
    let baseline = EntityId::now();
    let mut record = package(name, "1", "baseline", false).record;
    record.source = ClaimSource::UserStated;
    record.content_hash = None;
    vault
        .put_skill_record(&baseline, &record, at(now), now)
        .expect("baseline candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    record.approval_status = ClaimApprovalStatus::Approved;
    vault
        .update_skill_record(&baseline, &record, at(now + 1), now + 1)
        .expect("active baseline");
    reserve(vault, &baseline, &record.skill_id);
    baseline
}

fn reserve(vault: &Vault, skill: &EntityId, skill_id: &str) {
    let queue = AttemptQueue::new(vault);
    let dispatcher = AgentDispatcher::new(vault);
    for _ in 0..200 {
        let now = vault.now_recorded_at();
        let AgentDispatchOutcome::Dispatched(dispatched) = dispatcher
            .dispatch_default_base(None, None, None, now)
            .expect("enqueue typed agent dispatch")
        else {
            panic!("fresh agent dispatch");
        };
        let attempt = dispatched.attempt;
        queue
            .append_manifest_entry(
                attempt.id,
                ManifestEntry::new(ManifestKind::Skill, skill_id, "1", now),
            )
            .expect("skill manifest");
        let ClaimOutcome::Claimed(leased) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "fixture".to_owned(),
                    now: vault.now_recorded_at(),
                },
            )
            .expect("claim")
        else {
            panic!("claimable attempt");
        };
        assert_eq!(leased.id, attempt.id);
        queue
            .set_executor_model(
                attempt.id,
                "fixture",
                leased.attempt_count,
                "fixture/model@1",
            )
            .expect("executor stamp");
        assert!(matches!(
            queue
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: "fixture".to_owned(),
                    attempt_count: leased.attempt_count,
                    now: vault.now_recorded_at(),
                })
                .expect("complete"),
            CompleteOutcome::Completed(_)
        ));
        let receipt = oneiron::receipt::attempt_pack_receipt_id(&attempt.id);
        oneiron::skill_reliability::record_skill_contributing_win(
            vault,
            skill,
            &receipt,
            vault.now_recorded_at(),
        )
        .expect("attribute win");
        if !oneiron::skill_optimize::held_out_receipts(vault, skill)
            .expect("held-out reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}

struct NoPerson;
impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        panic!("fixture must not ask a person");
    }
}

fn ladder(provider: &dyn DecisionProvider) -> DecisionLadder<'_> {
    DecisionLadder {
        rule: None,
        local: None,
        system_one: Some(provider),
        precision: None,
        escalation: None,
        big: None,
        human: &NoPerson,
        human_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: "no-person".to_owned(),
            version: "1".to_owned(),
        },
        ask_to: None,
        paired: None,
        person: None,
        presence: None,
        correlation: None,
    }
}

fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::SystemOne,
        ceiling: DecisionRung::Human,
        band: DecisionBand::default(),
    }
}

fn answer(answer: DecisionAnswer) -> ProviderDecision {
    ProviderDecision {
        answer,
        probability: Some(0.9),
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

struct Replay {
    principal: EntityId,
    deadline: RetrievalDeadline,
    wording: BTreeMap<String, String>,
    /// The score of instructions that "check result"; everything else scores 0.2.
    lift: f64,
}
impl Replay {
    fn new() -> Self {
        Self {
            principal: EntityId::now(),
            deadline: RetrievalDeadline::after(Duration::from_secs(3600)),
            wording: BTreeMap::from([("score".to_owned(), "Score the held-out replay".to_owned())]),
            lift: 0.9,
        }
    }
    /// A judge under which the candidate scores no better than its baseline.
    fn refusing() -> Self {
        Self {
            lift: 0.2,
            ..Self::new()
        }
    }
}
impl DecisionProvider for Replay {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "fixture-judge".to_owned(),
            version: "1".to_owned(),
        }
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        assert!(matches!(
            call.question.contract,
            AnswerContract::Score { .. }
        ));
        assert!(
            !call.state["held_out_receipts"]
                .as_array()
                .expect("held-out receipts")
                .is_empty()
        );
        let instructions = call.state["instructions"].as_str().expect("instructions");
        Ok(answer(DecisionAnswer::Score(
            if instructions.contains("check result") {
                self.lift
            } else {
                0.2
            },
        )))
    }
}
impl HeldOutReplayNotes for Replay {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            ladder: ladder(self),
            principal: self.principal,
            dial: dial(),
            bands: DecisionBandPolicy::default(),
            deadline: &self.deadline,
            wording: &self.wording,
        }
    }
    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        assert!(!case.held_out_receipts.is_empty());
        Ok(json!({ "held_out_receipts": case.held_out_receipts }))
    }
    fn replay_responses(&self, _: &[String]) -> Result<SkillReplayResponses> {
        panic!("admission only asks for whole-reserve replay scores");
    }
    fn record_decision(&self, _: &DecisionQuestion, _: &TypedDecision, _: &Value) -> Result<()> {
        Ok(())
    }
}

struct NoReplay;
impl HeldOutReplayNotes for NoReplay {
    fn judge_revision(&self) -> &str {
        panic!("replay must not run before consent");
    }
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        panic!("replay must not run before consent");
    }
    fn replay_state(&self, _: &HeldOutReplayCase<'_>) -> Result<Value> {
        panic!("replay must not run before consent");
    }
    fn replay_responses(&self, _: &[String]) -> Result<SkillReplayResponses> {
        panic!("replay must not run before consent");
    }
    fn record_decision(&self, _: &DecisionQuestion, _: &TypedDecision, _: &Value) -> Result<()> {
        panic!("replay must not run before consent");
    }
}

struct Useful;
impl DecisionProvider for Useful {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "fixture-system-one".to_owned(),
            version: "1".to_owned(),
        }
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        assert_eq!(call.question.class, DecisionClass::UsefulUpstream);
        assert_eq!(
            call.state["base"]["skill_id"],
            call.state["candidate"]["skill_id"]
        );
        Ok(answer(DecisionAnswer::Noul(true)))
    }
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

#[test]
fn gate_22_a_no_permission_hub_skill_lands_active_on_fit_without_an_owner_answer() -> Result<()> {
    let fixture = Fixture::new();
    let (hub, publisher) = fixture.hub();
    let candidate = package("fixture.new", "1", "check result", false);
    assert_eq!(candidate.capabilities, SkillCapabilitySurface::default());
    let (id, source) = fixture.import(hub, "fixture", &candidate, 20);
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    let replay = Replay::new();
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &replay, at(31), 31)?
    else {
        panic!("a no-permission candidate must activate on fit without an owner answer");
    };
    assert!(receipt.accepted);
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("admitted skill")
            .lifecycle_status,
        SkillLifecycle::Active
    );

    let widened = package("fixture.widened", "1", "check result", true);
    let (widened_id, widened_source) = fixture.import(hub, "widened", &widened, 32);
    let ask = fixture.vault.prepare_marketplace_activation(
        widened_id,
        &widened_source,
        &publisher,
        fixture.baseline,
    )?;
    assert_eq!(
        fixture
            .vault
            .admit_marketplace_skill(&ask, &NoReplay, at(33), 33)?,
        HubAdmissionDisposition::PendingConsent
    );
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &replay, at(34), 34)?
    else {
        panic!("an owner-approved widening must rule");
    };
    assert!(receipt.accepted);
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&widened_id)?
            .expect("admitted widening")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

#[test]
fn gate_22_b_a_refused_no_permission_ask_stays_refused_after_another_baseline_rules() -> Result<()>
{
    let fixture = Fixture::new();
    let second = active_baseline(&fixture.vault, "fixture.second", 4);
    let (hub, publisher) = fixture.hub();
    let candidate = package("fixture.new", "1", "check result", false);
    assert_eq!(candidate.capabilities, SkillCapabilitySurface::default());
    let (id, source) = fixture.import(hub, "fixture", &candidate, 20);
    let first =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    let other = fixture
        .vault
        .prepare_marketplace_activation(id, &source, &publisher, second)?;
    let refusing = Replay::refusing();
    for (ask, now) in [(&first, 31), (&other, 32)] {
        let HubAdmissionDisposition::Ruled(receipt) =
            fixture
                .vault
                .admit_marketplace_skill(ask, &refusing, at(now), now)?
        else {
            panic!("a no-permission candidate must rule without an owner answer");
        };
        assert!(!receipt.accepted);
    }
    assert!(
        fixture
            .vault
            .admit_marketplace_skill(&first, &Replay::new(), at(33), 33)
            .is_err(),
        "a refused ask must not score again once another baseline has ruled"
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&id)?
            .expect("refused candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    let latest = fixture
        .vault
        .hub_admission_receipt(&id)?
        .expect("latest ruling");
    assert!(!latest.accepted);
    assert_eq!(latest.evidence_skill, second.to_hex());
    Ok(())
}

#[test]
fn gate_23_a_scanner_flag_does_not_hold_a_same_permission_shared_merge() -> Result<()> {
    let fixture = Fixture::new();
    let resident = fixture
        .vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("seeded resident")
        .0;
    let delta = package("fixture.base", "2", "check result", false);
    assert_eq!(delta.capabilities, SkillCapabilitySurface::default());
    set_skill_scan_activation_risk_threshold(&fixture.vault, ScanRiskLevel::Low)?;
    let merged = fixture.vault.submit_shared_skill_delta(
        &fixture.baseline,
        &encode_hub_package(&delta)?,
        SharedSkillLane::FederationMergeBack,
        "resident:branch",
        &EntityId::now(),
        at(20),
        20,
    )?;
    let content_hash = delta.content_hash()?;
    let flag = SkillScanReceipt::new(
        "fixture.scanner",
        21,
        ScanVerdict::Suspicious,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    fixture
        .vault
        .ingest_skill_scan_verdict(&merged, content_hash, &flag, at(21), 21)?;
    let scan_rows = fixture
        .vault
        .skill_scan_verdicts_for_content_hash(content_hash)?;
    assert!(!scan_rows.is_empty());
    assert_eq!(
        scan_gate_for_activation(&fixture.vault, content_hash)?,
        ActivationPosture::ProposedRequired {
            risk: ScanRiskLevel::Low
        }
    );
    let ask =
        fixture
            .vault
            .prepare_shared_skill_merge(merged, resident, useful_question(merged))?;
    let useful = Useful;
    let deadline = RetrievalDeadline::after(Duration::from_secs(3600));
    let decisions = UsefulUpstreamDecisions {
        ladder: ladder(&useful),
        dial: dial(),
        bands: DecisionBandPolicy::default(),
        deadline: &deadline,
    };
    let SharedSkillMergeDisposition::Ruled(receipt) =
        fixture
            .vault
            .merge_shared_skill_delta(&ask, &decisions, &Replay::new(), at(22), 22)?
    else {
        panic!("a scanner flag must not hold a same-permission merge");
    };
    assert!(receipt.accepted);
    let record = fixture
        .vault
        .get_skill_record(&merged)?
        .expect("merged skill");
    assert_eq!(record.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(record.content_hash, Some(content_hash));
    assert_eq!(
        fixture
            .vault
            .skill_scan_verdicts_for_content_hash(content_hash)?,
        scan_rows
    );
    Ok(())
}
