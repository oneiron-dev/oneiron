//! Imported Active fixtures traverse the same consent and held-out doors as a host.
use super::tests::ladder_fixture::{
    FixtureNotes, FixtureProvider, choice_answer, fixture_notes, noul_answer, score_answer,
};
use super::*;
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimSource},
    entity_id::EntityId,
    error::Result,
    llm::decision::{DecisionQuestion, DecisionRung, ProviderPin, TypedDecision},
    skill::{SkillLifecycle, SkillRecord},
    skill_optimize::{
        GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, HonestyReplay, SkillOptimizeDecisions,
        SkillReplayResponses,
    },
    temporal::TimeRange,
};
use serde_json::Value as Json;
fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

pub(crate) fn admitted_import(vault: &Vault, id: &EntityId, record: SkillRecord) -> SkillRecord {
    assert_eq!(record.source, ClaimSource::Imported);
    let contents = format!(
        "---\nname: {}\ndescription: {}\nversion: {}\n---\nCheck the fixture result.\n",
        record.skill_id, record.desc, record.version
    );
    let mut imported = record;
    imported.content_hash = None;
    imported.lifecycle_status = SkillLifecycle::Candidate;
    let package = HubPackage::new(
        imported,
        vec![HubFile::new("SKILL.md", contents.into_bytes())],
        SkillCapabilitySurface::default(),
    );
    let source = HubRef::new(
        EntityId::now(),
        "fixture",
        HubPin::ContentHash(package.content_hash().expect("hash").to_hex()),
    )
    .expect("ref");
    assert_eq!(
        vault
            .import_skill_from_hub_with_id(&source, &package, *id, at(10), 10)
            .expect("import"),
        *id
    );
    admit_installed(vault, id, &source)
}

pub(crate) fn admit_installed(vault: &Vault, id: &EntityId, source: &HubRef) -> SkillRecord {
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let owner = vault
        .authenticate_owner(
            owner_id,
            "principal:fixture-owner",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    let baseline = EntityId::now();
    let mut base = SkillRecord::new(
        format!("fixture.baseline.{}", baseline.to_hex()),
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
            rmpv::Value::from("admission fixture"),
        )]),
    );
    vault
        .put_skill_record(&baseline, &base, at(2), 2)
        .expect("baseline");
    base.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&baseline, &base, at(3), 3)
        .expect("authored baseline");
    reserve(vault, &baseline, &base.skill_id);
    let hub = source.hub_id;
    let hub_record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "https://example.invalid/index.json",
        SkillHubTrustTier::Community,
        HubSyncPolicy::ContentHashFrozen,
    )
    .expect("hub");
    vault
        .configure_skill_hub(&owner, &hub, &hub_record, at(4), 4)
        .expect("configure");
    let publisher = vault
        .admit_skill_publisher(&owner, "publisher:fixture", hub)
        .expect("publisher");
    let ask = vault
        .prepare_marketplace_activation(*id, source, &publisher, baseline)
        .expect("ask");
    vault
        .approve_marketplace_activation(&ask, &owner)
        .expect("human consent");
    let HubAdmissionDisposition::Ruled(receipt) = vault
        .admit_marketplace_skill(&ask, &FixtureReplay::new(), at(12), 13)
        .expect("held-out")
    else {
        panic!("consented fixture")
    };
    assert!(receipt.accepted);
    vault.get_skill_record(id).expect("read").expect("admitted")
}
/// Fixture replay answers as typed ladder judgments.
///
/// The removed `HeldOutReplayScorer` fake (c2a4a506975) returned fixed values;
/// this provider answers the same values per judgment kind: `score` is 0.9
/// when the instructions carry the fixture marker, else 0.2; `structural`,
/// `contrastive`, `task_success` and `response_score` are 0.5; `preference`
/// picks the first response; `honesty` is false. Any other kind panics: the
/// fixture sets no answer for it.
struct FixtureReplay {
    notes: FixtureNotes<'static>,
}
impl FixtureReplay {
    fn new() -> Self {
        let provider = FixtureProvider::new(
            ProviderPin {
                rung: DecisionRung::SystemOne,
                model: "fixture-judge".to_owned(),
                version: "1".to_owned(),
            },
            "fixture-judge@1",
            move |kind, _, state| match kind.as_deref() {
                Some("score") => {
                    let held = state
                        .get("held_out_receipts")
                        .and_then(Json::as_array)
                        .map(|receipts| receipts.len())
                        .unwrap_or_default();
                    assert!(held > 0);
                    let instructions = state
                        .get("instructions")
                        .and_then(Json::as_str)
                        .unwrap_or_default();
                    Ok(score_answer(
                        if instructions.contains("Check the fixture result.") {
                            0.9
                        } else {
                            0.2
                        },
                    ))
                }
                Some("structural" | "contrastive" | "task_success" | "response_score") => {
                    Ok(score_answer(0.5))
                }
                Some("preference") => Ok(choice_answer("first")),
                Some("honesty") => Ok(noul_answer(false)),
                other => panic!("FixtureReplay asked an unexpected kind: {other:?}"),
            },
        );
        Self {
            notes: fixture_notes("fixture-judge@1", provider),
        }
    }
}
impl HeldOutReplayNotes for FixtureReplay {
    fn judge_revision(&self) -> &str {
        self.notes.judge_revision()
    }
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        self.notes.decisions()
    }
    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Json> {
        self.notes.replay_state(case)
    }
    fn replay_responses(&self, receipts: &[String]) -> Result<SkillReplayResponses> {
        self.notes.replay_responses(receipts)
    }
    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Json,
    ) -> Result<()> {
        self.notes.record_decision(question, decision, state)
    }
    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
        self.notes.honesty_replays(case)
    }
    fn goal_axes(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        self.notes.goal_axes(case)
    }
}
/// Real terminal attempt receipts, attributed through the production reliability door.
pub(crate) fn reserve(vault: &Vault, skill: &EntityId, skill_id: &str) {
    use crate::attempt_queue::{
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
            .expect("stamp model");
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
        let receipt = crate::receipt::attempt_pack_receipt_id(&attempt.id);
        crate::skill_reliability::record_skill_contributing_win(vault, skill, &receipt, now + 3)
            .expect("attribute");
        if !crate::skill_optimize::held_out_receipts(vault, skill)
            .expect("reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}
