// HUB-SYNC-SCAN-FLAG-HOLDS-UPDATE (FIX-LIST l23169; ARCH-0053 #promise-gate-23):
// a scanner flag on a hub sync's bytes holds nothing — the update lands
// with its scan verdict rows and its approval as it was.
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
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue,
    HumanDecisionRequest, ProviderDecision, ProviderPin, TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    ForeignSkillPublisher, HubAdmissionDisposition, HubFile, HubPackage, HubPin, HubRef,
    HubSyncDisposition, HubSyncPolicy, ScanRiskLevel, SkillCapabilitySurface, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier,
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

/// GATE-23 for the sync door: the scanner is a signal, not a hold. A
/// re-sync of already-approved flagged bytes applies with the approval as
/// it was, and the scan verdict rows stay on the bytes.
#[test]
fn hub_sync_flagged_resync_keeps_the_approval_as_it_was() -> Result<()> {
    let fixture = Fixture::new();
    let (hub, publisher) = fixture.hub();
    let first = package("fixture.sync", "1", "check result", true);
    let content_hash = first.content_hash()?;
    let (id, source) = fixture.import(hub, "fixture", &first, 20);
    let ask =
        fixture
            .vault
            .prepare_marketplace_activation(id, &source, &publisher, fixture.baseline)?;
    assert_eq!(
        fixture
            .vault
            .admit_marketplace_skill(&ask, &NoReplay, at(31), 31)?,
        HubAdmissionDisposition::PendingConsent
    );
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(receipt) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(), at(32), 32)?
    else {
        panic!("an owner-approved widening must rule");
    };
    assert!(receipt.accepted);
    let admitted = fixture
        .vault
        .get_skill_record(&id)?
        .expect("admitted skill");
    assert_eq!(admitted.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(
        admitted.approval_status,
        ClaimApprovalStatus::Approved
    );
    // The declared tool keeps its Low static finding; the dial at Low turns
    // the bytes' own scan into a ProposedRequired flag.
    set_skill_scan_activation_risk_threshold(&fixture.vault, ScanRiskLevel::Low)?;
    assert_eq!(
        scan_gate_for_activation(&fixture.vault, content_hash)?,
        ActivationPosture::ProposedRequired {
            risk: ScanRiskLevel::Low
        }
    );
    // Re-sync the very bytes the owner approved: nothing widened, nothing
    // changed, so the update applies — and the flag on those bytes must
    // not rewrite the approval the owner already gave.
    let sync_ref = HubRef::new(hub, "fixture", HubPin::None)?;
    assert_eq!(
        fixture.vault.sync_skill_from_hub(
            &id,
            &sync_ref,
            &first,
            HubSyncPolicy::MirrorOfHub,
            at(33),
            33,
        )?,
        HubSyncDisposition::Applied
    );
    let record = fixture
        .vault
        .get_skill_record(&id)?
        .expect("resynced skill");
    assert_eq!(record.version.as_str(), "1");
    assert_eq!(record.content_hash, Some(content_hash));
    assert_eq!(record.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(
        record.approval_status,
        ClaimApprovalStatus::Approved,
        "a flag on the synced bytes must not rewrite the owner's approval"
    );
    assert!(
        !fixture
            .vault
            .skill_scan_verdicts_for_content_hash(content_hash)?
            .is_empty(),
        "the update keeps its scan verdict rows"
    );
    assert_eq!(
        scan_gate_for_activation(&fixture.vault, content_hash)?,
        ActivationPosture::ProposedRequired {
            risk: ScanRiskLevel::Low
        }
    );
    Ok(())
}
