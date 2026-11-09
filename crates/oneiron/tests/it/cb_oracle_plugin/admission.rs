//! Real marketplace admission for the plugin rendering fixtures.
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionLadder,
    DecisionProvider, DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision,
    ProviderPin, TypedDecision,
};
use oneiron::model_decision::DecisionQuestion;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    ForeignSkillPublisher, HubAdmissionDisposition, HubPackage, HubPin, HubRef, HubSyncPolicy,
    SkillHubKind, SkillHubRecord, SkillHubTrustTier,
};
use oneiron::skill_optimize::{
    HeldOutReplayCase, HeldOutReplayNotes, SkillOptimizeDecisions, SkillReplayResponses,
};
use oneiron::{EntityId, TimeRange, Vault};
use std::collections::BTreeMap;
use std::time::Duration;

pub(super) struct Admission {
    owner: AuthenticatedOwner,
    publisher: ForeignSkillPublisher,
    baseline: EntityId,
    source: HubRef,
}
fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}
impl Admission {
    pub(super) fn new(vault: &Vault, hub: EntityId, package: &HubPackage) -> Self {
        let owner_id = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        let owner = vault
            .authenticate_owner(
                owner_id,
                "principal:plugin-fixture",
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .expect("authenticated owner");
        let baseline = EntityId::now();
        let mut record = SkillRecord::new(
            "plugin.fixture.baseline",
            "baseline instructions",
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Vec::new(),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("fixture"),
            )]),
        );
        vault
            .put_skill_record(&baseline, &record, at(2), 2)
            .expect("native baseline");
        record.lifecycle_status = SkillLifecycle::Active;
        vault
            .update_skill_record(&baseline, &record, at(3), 3)
            .expect("activate native baseline");
        reserve(vault, &baseline, &record.skill_id);
        let configuration = SkillHubRecord::new(
            SkillHubKind::LocalDir,
            "/fixture/crm",
            SkillHubTrustTier::Community,
            HubSyncPolicy::ContentHashFrozen,
        )
        .expect("hub configuration");
        vault
            .configure_skill_hub(&owner, &hub, &configuration, at(4), 4)
            .expect("configure hub");
        let publisher = vault
            .admit_skill_publisher(&owner, "publisher:plugin-fixture", hub)
            .expect("foreign publisher");
        let source = HubRef::new(
            hub,
            "crm-pack@1.0.0",
            HubPin::ContentHash(package.content_hash().expect("hash").to_hex()),
        )
        .expect("source");
        Self {
            owner,
            publisher,
            baseline,
            source,
        }
    }
    pub(super) fn activate(
        &self,
        vault: &Vault,
        skill: EntityId,
        now: u64,
    ) -> oneiron::error::Result<SkillRecord> {
        let ask = vault.prepare_marketplace_activation(
            skill,
            &self.source,
            &self.publisher,
            self.baseline,
        )?;
        vault.approve_marketplace_activation(&ask, &self.owner)?;
        let replay = Replay::new(self.owner.actor());
        let HubAdmissionDisposition::Ruled(receipt) =
            vault.admit_marketplace_skill(&ask, &replay, at(now), now)?
        else {
            panic!("confirmed admission must rule")
        };
        assert!(receipt.accepted);
        Ok(vault.get_skill_record(&skill)?.expect("admitted skill"))
    }
}
/// The marketplace replay judge on the shared decision path (c2a4a506975):
/// admission asks the `score` question of each version over the reserved
/// receipts, and this judge's one Local rung scores the CRM pack's
/// instructions above the baseline's.
struct Replay {
    judge: Judge,
    principal: EntityId,
    deadline: RetrievalDeadline,
    wording: BTreeMap<String, String>,
}
impl Replay {
    fn new(principal: EntityId) -> Self {
        Self {
            judge: Judge,
            principal,
            deadline: RetrievalDeadline::after(Duration::from_secs(3600)),
            wording: BTreeMap::from([(
                "score".to_owned(),
                "How well do these instructions serve the reserved receipts?".to_owned(),
            )]),
        }
    }
}
impl HeldOutReplayNotes for Replay {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            ladder: DecisionLadder {
                rule: None,
                local: Some(&self.judge),
                system_one: None,
                escalation: None,
                big: None,
                human: &NoPerson,
                human_pin: ProviderPin {
                    rung: DecisionRung::Human,
                    model: "fixture-queue".into(),
                    version: "1".into(),
                },
            },
            principal: self.principal,
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Local,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            deadline: &self.deadline,
            wording: &self.wording,
        }
    }
    fn replay_state(
        &self,
        case: &HeldOutReplayCase<'_>,
    ) -> oneiron::error::Result<serde_json::Value> {
        Ok(serde_json::json!({ "receipts": case.held_out_receipts }))
    }
    fn replay_responses(
        &self,
        _receipts: &[String],
    ) -> oneiron::error::Result<SkillReplayResponses> {
        Ok(SkillReplayResponses {
            responses: Vec::new(),
            rubric: None,
        })
    }
    fn record_decision(
        &self,
        _question: &DecisionQuestion,
        _decision: &TypedDecision,
        _state: &serde_json::Value,
    ) -> oneiron::error::Result<()> {
        Ok(())
    }
}
/// The judge's rung: a score per version, read from the instructions the
/// question's state carries.
struct Judge;
impl DecisionProvider for Judge {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "fixture-judge".into(),
            version: "1".into(),
        }
    }
    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::error::Result<ProviderDecision> {
        assert!(
            call.state["held_out_receipts"]
                .as_array()
                .is_some_and(|receipts| !receipts.is_empty())
        );
        let instructions = call.state["instructions"].as_str().unwrap_or_default();
        Ok(ProviderDecision {
            answer: DecisionAnswer::Score(if instructions.contains("CRM contact") {
                0.9
            } else {
                0.2
            }),
            probability: Some(1.0),
            paired: None,
        })
    }
}
/// No person answers on this path.
struct NoPerson;
impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _request: HumanDecisionRequest) -> oneiron::error::Result<()> {
        Err(oneiron::Error::InvalidConfig("no person here".into()))
    }
}
fn reserve(vault: &Vault, skill: &EntityId, skill_id: &str) {
    use oneiron::attempt_queue::{
        AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
        EnqueueOutcome, ManifestEntry, ManifestKind,
    };
    let queue = AttemptQueue::new(vault);
    for index in 0..200 {
        let now = 100 + index * 10;
        let EnqueueOutcome::Enqueued(attempt) = queue
            .enqueue(EnqueueAttempt {
                kind: "hub.fixture".to_owned(),
                payload: vec![],
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue")
        else {
            panic!("fresh attempt");
        };
        queue
            .append_manifest_entry(
                attempt.id,
                ManifestEntry::new(ManifestKind::Skill, skill_id, "1", now),
            )
            .expect("manifest");
        let ClaimOutcome::Claimed(leased) = queue
            .claim(ClaimAttempt {
                lease_owner: "fixture".to_owned(),
                now: now + 1,
            })
            .expect("claim")
        else {
            panic!("claimable attempt");
        };
        queue
            .set_executor_model(
                attempt.id,
                "fixture",
                leased.attempt_count,
                "fixture/model@1",
            )
            .expect("stamp executor");
        assert!(matches!(
            queue
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: "fixture".to_owned(),
                    attempt_count: leased.attempt_count,
                    now: now + 2
                })
                .expect("complete"),
            CompleteOutcome::Completed(_)
        ));
        let receipt = oneiron::receipt::attempt_pack_receipt_id(&attempt.id);
        oneiron::skill_reliability::record_skill_contributing_win(vault, skill, &receipt, now + 3)
            .expect("attribute");
        if !oneiron::skill_optimize::held_out_receipts(vault, skill)
            .expect("reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}
