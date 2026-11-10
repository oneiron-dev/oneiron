//! The externally observable consent, raw-door, held-out, dedup, and shared-merge laws.
use super::tests::ladder_fixture::{
    FixtureJudge, FixtureNotes, FixtureProvider, fixture_judge, fixture_notes, noul_answer,
    score_answer,
};
use super::*;
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimSource},
    consent::AuthenticatedOwner,
    entity_id::EntityId,
    error::{ErrorKind, Result},
    llm::decision::{
        AnswerContract, DecisionClass, DecisionQuestion, DecisionRung, PairedAnswer, ProviderPin,
        TypedDecision,
    },
    skill::{SkillLifecycle, SkillRecord},
    skill_optimize::{
        GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, HonestyReplay, SkillOptimizeDecisions,
        SkillReplayResponses,
    },
    temporal::TimeRange,
};
use serde_json::Value as Json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

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
/// A delta of the fixture base that also asks for a tool: a permission
/// widening, which still needs the owner's answer to merge.
fn widened_package() -> HubPackage {
    super::folder::package_from_files(vec![HubFile::new(
        "SKILL.md",
        b"---\nname: fixture.base\ndescription: fixture\nversion: 2\nallowed-tools: [\"read_file\"]\n---\ncheck result\n"
            .to_vec(),
    )])
    .expect("widened package")
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
/// Forwards [`HeldOutReplayNotes`] to the shared `notes` shell every fixture
/// scorer holds; the per-test answers live in the fixture provider behind it.
macro_rules! delegate_notes {
    ($ty:ty) => {
        impl HeldOutReplayNotes for $ty {
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
    };
}

/// A useful-upstream judge answering `useful`, on the System One seat.
fn useful_judge(useful: bool) -> FixtureJudge<'static> {
    fixture_judge(
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "fixture-system-one".to_owned(),
            version: "1".to_owned(),
        },
        "fixture-judge@1",
        move |_, _, state| {
            assert_eq!(state["base"]["skill_id"], state["candidate"]["skill_id"]);
            Ok(noul_answer(useful))
        },
    )
}

struct Replay {
    improve: bool,
    notes: FixtureNotes<'static>,
}
impl Replay {
    fn new(improve: bool) -> Self {
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
                        if instructions.contains("check result") && improve {
                            0.9
                        } else {
                            0.2
                        },
                    ))
                }
                other => panic!("Replay asked an unexpected kind: {other:?}"),
            },
        );
        Self {
            improve,
            notes: fixture_notes("fixture-judge@1", provider),
        }
    }
}
delegate_notes!(Replay);
struct NoReplay;
impl HeldOutReplayNotes for NoReplay {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        panic!("replay must not run before consent or usefulness");
    }
    fn replay_state(&self, _case: &HeldOutReplayCase<'_>) -> Result<Json> {
        panic!("replay must not run before consent or usefulness");
    }
    fn replay_responses(&self, _receipts: &[String]) -> Result<SkillReplayResponses> {
        panic!("replay must not run before consent or usefulness");
    }
    fn record_decision(
        &self,
        _question: &DecisionQuestion,
        _decision: &TypedDecision,
        _state: &Json,
    ) -> Result<()> {
        panic!("replay must not run before consent or usefulness");
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
    notes: FixtureNotes<'a>,
}
impl<'a> MoveBaseline<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_in = Arc::clone(&calls);
        let provider = FixtureProvider::with_hook(
            ProviderPin {
                rung: DecisionRung::SystemOne,
                model: "fixture-judge".to_owned(),
                version: "1".to_owned(),
            },
            "fixture-judge@1",
            move || {
                let mut record = fixture
                    .vault
                    .get_skill_record(&fixture.baseline)?
                    .expect("baseline");
                record.version = "2".to_owned();
                record.desc = "changed while scoring".to_owned();
                fixture
                    .vault
                    .update_skill_record(&fixture.baseline, &record, at(40), 40)?;
                Ok(())
            },
            move |kind, _, _| match kind.as_deref() {
                Some("score") => Ok(score_answer(
                    if calls_in.fetch_add(1, Ordering::SeqCst) == 0 {
                        0.1
                    } else {
                        0.9
                    },
                )),
                other => panic!("MoveBaseline asked an unexpected kind: {other:?}"),
            },
        );
        Self {
            notes: fixture_notes("fixture-judge@1", provider),
        }
    }
}
delegate_notes!(MoveBaseline<'_>);
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
            .admit_marketplace_skill(&ask, &MoveBaseline::new(&fixture), at(41), 41)
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
// NOTE (wave 2): the protected `shared_merge_the_scan_flags_waits_for_the_owner`
// test still constructs `Useful(true)` and its body is byte-identical by rule,
// so this shell stays for it. `&UsefulUpstreamDecisions` cannot be built inline
// without touching that body; left unported, see the wave report.
struct Useful(bool);

impl std::ops::Deref for Useful {
    type Target = UsefulUpstreamDecisions<'static>;

    fn deref(&self) -> &Self::Target {
        static YES_JUDGE: std::sync::LazyLock<FixtureJudge<'static>> =
            std::sync::LazyLock::new(|| useful_judge(true));
        static NO_JUDGE: std::sync::LazyLock<FixtureJudge<'static>> =
            std::sync::LazyLock::new(|| useful_judge(false));
        static YES: std::sync::LazyLock<UsefulUpstreamDecisions<'static>> =
            std::sync::LazyLock::new(|| YES_JUDGE.useful_decisions());
        static NO: std::sync::LazyLock<UsefulUpstreamDecisions<'static>> =
            std::sync::LazyLock::new(|| NO_JUDGE.useful_decisions());
        if self.0 { &YES } else { &NO }
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
        // A merge is reversible, so it lands on the useful yes and the
        // held-out win alone: no per-merge approval (ARCH-0053 r4).
        let judge = useful_judge(true);
        let SharedSkillMergeDisposition::Ruled(receipt) = company.vault.merge_shared_skill_delta(
            &ask,
            &judge.useful_decisions(),
            &Replay::new(true),
            at(22),
            22,
        )?
        else {
            panic!("a reversible merge needs no approval");
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
    let judge = useful_judge(true);
    let SharedSkillMergeDisposition::Ruled(receipt) = company.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
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
    let replay = NoReplay;
    let judge = useful_judge(false);
    let SharedSkillMergeDisposition::Ruled(receipt) = fixture.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
        &replay,
        at(21),
        21,
    )?
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

/// A useful-upstream judge answering from the Local seat, which the merge
/// door refuses.
fn wrong_seat_judge() -> FixtureJudge<'static> {
    fixture_judge(
        ProviderPin {
            rung: DecisionRung::Local,
            model: "fixture-system-one".to_owned(),
            version: "1".to_owned(),
        },
        "fixture-judge@1",
        |_, _, _| Ok(noul_answer(true)),
    )
}
#[derive(Clone, Copy)]
enum BadPerson {
    /// P(ask a person) out of range.
    OutOfRange,
    /// The person row reads the question the same provider's paired row read.
    ReadsPaired,
}
/// The house model's decision read, with its paired reading. `self_paired`
/// makes the pair read the question being answered, which no receipt may
/// hold; `person` adds a person row no receipt may hold either.
fn house_read_judge(self_paired: bool, person: Option<BadPerson>) -> FixtureJudge<'static> {
    fixture_judge(
        ProviderPin {
            rung: DecisionRung::Escalation,
            model: "fixture-house".to_owned(),
            version: "1".to_owned(),
        },
        "fixture-judge@1",
        move |_, question, _| {
            let paired = PairedAnswer {
                question: if self_paired {
                    question.id
                } else {
                    EntityId::now()
                },
                question_version: 1,
                probability: 0.3,
            };
            let person = person.map(|bad| match bad {
                BadPerson::OutOfRange => PairedAnswer {
                    question: EntityId::now(),
                    question_version: 1,
                    probability: 2.0,
                },
                BadPerson::ReadsPaired => PairedAnswer {
                    question: paired.question,
                    question_version: 1,
                    probability: 0.5,
                },
            });
            Ok(crate::llm::decision::ProviderDecision {
                answer: crate::llm::decision::DecisionAnswer::Noul(true),
                probability: Some(0.9),
                paired: Some(paired),
                person,
                served: None,
                cost_per_thousand: None,
            })
        },
    )
}
#[test]
fn merge_refuses_a_local_seat_and_unbound_receipts_without_spending_consent() -> Result<()> {
    let fixture = Fixture::new();
    // A widening delta, so the merge spends an owner answer a bad verdict must not burn.
    let offered = encode_hub_package(&widened_package())?;
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
    let wrong_seat = wrong_seat_judge();
    assert!(
        fixture
            .vault
            .merge_shared_skill_delta(&ask, &wrong_seat.useful_decisions(), &NoReplay, at(21), 21)
            .is_err()
    );
    // NOTE (wave 2): a wrong-question receipt is unrepresentable now — the
    // engine stamps the receipt itself (c2a4a506975) — so this answers validly
    // and its refusal assert is reported as unportable.
    let wrong_question = useful_judge(true);
    assert!(
        fixture
            .vault
            .merge_shared_skill_delta(
                &ask,
                &wrong_question.useful_decisions(),
                &NoReplay,
                at(21),
                21
            )
            .is_err()
    );
    for house in [
        house_read_judge(true, None),
        house_read_judge(false, Some(BadPerson::OutOfRange)),
        house_read_judge(false, Some(BadPerson::ReadsPaired)),
    ] {
        assert!(
            fixture
                .vault
                .merge_shared_skill_delta(&ask, &house.useful_decisions(), &NoReplay, at(21), 21)
                .is_err()
        );
    }
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
    // The rejected answer has neither burned the consent nor erased the branch, and
    // the house model's read answers the merge like System One (PR B2).
    let house = house_read_judge(false, None);
    let ruled = fixture.vault.merge_shared_skill_delta(
        &ask,
        &house.useful_decisions(),
        &Replay::new(true),
        at(22),
        22,
    )?;
    let SharedSkillMergeDisposition::Ruled(receipt) = ruled else {
        panic!("the approved merge is ruled");
    };
    assert!(receipt.accepted);
    assert_eq!(
        receipt.decision.receipt.providers[0].rung,
        DecisionRung::Escalation
    );
    assert_eq!(receipt.decision.receipt.paired.len(), 1);
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
    let judge = useful_judge(false);
    let ruled = fixture.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
        &NoReplay,
        at(21),
        21,
    )?;
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
    let judge = useful_judge(true);
    let ruled = fixture.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
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
    let judge = useful_judge(false);
    assert!(matches!(
        fixture.vault.merge_shared_skill_delta(
            &ask,
            &judge.useful_decisions(),
            &NoReplay,
            at(21),
            21
        )?,
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
    let judge = useful_judge(true);
    assert!(matches!(
        fixture.vault.merge_shared_skill_delta(
            &ask,
            &judge.useful_decisions(),
            &Replay::new(true),
            at(21),
            21
        )?,
        SharedSkillMergeDisposition::Ruled(receipt) if receipt.accepted
    ));
    assert_eq!(fixture.vault.get_skill_record(&id)?.unwrap().version, "3");
    assert_eq!(fixture.vault.get_skill_record(&fork)?.unwrap().version, "2");
    Ok(())
}

/// A useful-upstream judge whose provider pin carries secret-shaped text,
/// which the merge's receipt scan must refuse.
fn secret_provider_judge(useful: bool) -> FixtureJudge<'static> {
    fixture_judge(
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: crate::test_util::SYNTHETIC_PRIVATE_KEY_BLOCK.to_owned(),
            version: "1".to_owned(),
        },
        "fixture-judge@1",
        move |_, _, _| Ok(noul_answer(useful)),
    )
}
#[test]
fn shared_merge_scans_questions_and_provider_receipts_before_any_ruling() -> Result<()> {
    for useful in [false, true] {
        let fixture = Fixture::new();
        let replay = Replay::new(true);
        // A widening delta, so the merge spends an owner answer a secret must not burn.
        let offered = encode_hub_package(&widened_package())?;
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
        let secret = secret_provider_judge(useful);
        assert!(
            fixture
                .vault
                .merge_shared_skill_delta(&ask, &secret.useful_decisions(), &replay, at(21), 21,)
                .is_err()
        );
        assert!(fixture.vault.shared_skill_merge_receipt(&id)?.is_none());
        let txn = fixture.vault.store.env.read_txn()?;
        assert!(
            !crate::store::skill_refinement_custody::refinement_custody_exists_in_txn(
                &fixture.vault.store,
                &txn,
                &id
            )?,
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
        let judge = useful_judge(useful);
        let ruled = fixture.vault.merge_shared_skill_delta(
            &ask,
            &judge.useful_decisions(),
            &replay,
            at(22),
            22,
        )?;
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
            let judge = useful_judge(admitted);
            let SharedSkillMergeDisposition::Ruled(receipt) =
                fixture.vault.merge_shared_skill_delta(
                    &ask,
                    &judge.useful_decisions(),
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
            let judge = useful_judge(accepted);
            let SharedSkillMergeDisposition::Ruled(receipt) =
                fixture.vault.merge_shared_skill_delta(
                    &ask,
                    &judge.useful_decisions(),
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
                let judge = useful_judge(state == "admitted");
                fixture.vault.merge_shared_skill_delta(
                    &ask,
                    &judge.useful_decisions(),
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
    let judge = useful_judge(true);
    let SharedSkillMergeDisposition::Ruled(merge_receipt) =
        fixture.vault.merge_shared_skill_delta(
            &merge_ask,
            &judge.useful_decisions(),
            &Replay::new(true),
            at(41),
            41,
        )?
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
    fn replacing_scorer(vault: &Vault) -> FixtureNotes<'_> {
        fixture_notes(
            "old-hub@1",
            FixtureProvider::with_hook(
                ProviderPin {
                    rung: DecisionRung::SystemOne,
                    model: "fixture-judge".to_owned(),
                    version: "1".to_owned(),
                },
                "old-hub@1",
                move || {
                    crate::skill_optimize::supersede_skill_edit_judge(
                        vault,
                        "old-hub@1",
                        "new-hub@2",
                    )?;
                    Ok(())
                },
                move |kind, _, state| match kind.as_deref() {
                    Some("score") => {
                        let instructions = state
                            .get("instructions")
                            .and_then(Json::as_str)
                            .unwrap_or_default();
                        Ok(score_answer(if instructions.contains("check result") {
                            0.9
                        } else {
                            0.2
                        }))
                    }
                    other => panic!("Replacing asked an unexpected kind: {other:?}"),
                },
            ),
        )
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
    let scorer = replacing_scorer(&fixture.vault);
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
    let scorer = replacing_scorer(&other.vault);
    let judge = useful_judge(true);
    assert!(
        other
            .vault
            .merge_shared_skill_delta(&ask, &judge.useful_decisions(), &scorer, at(41), 41)
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

fn submit_fixture_delta(fixture: &Fixture, delta: &HubPackage) -> Result<EntityId> {
    fixture.vault.submit_shared_skill_delta(
        &fixture.baseline,
        &encode_hub_package(delta)?,
        SharedSkillLane::FederationMergeBack,
        "member:fixture",
        &EntityId::now(),
        at(20),
        20,
    )
}

/// REV-9 D1 (ARCH-0053 r4, ARCH-0043, DEC-0006 reversibility-primary): a
/// shared merge is reversible, so it lands on the useful-upstream yes and the
/// held-out win with no per-merge approval. Rolling it back restores the
/// displaced revision's content as the active revision, and every earlier
/// revision stays readable.
#[test]
fn shared_merge_lands_without_approval_and_rolls_back_to_the_old_revision() -> Result<()> {
    let fixture = Fixture::new();
    let original = fixture
        .vault
        .get_skill_record(&fixture.baseline)?
        .expect("baseline");
    // A revision that never had a package rolls back as its record alone.
    assert_eq!(original.content_hash, None);
    let merged = submit_fixture_delta(&fixture, &package("fixture.base", "2", "check result"))?;
    let ask = fixture.vault.prepare_shared_skill_merge(
        merged,
        fixture.resident,
        useful_question(merged),
    )?;
    let judge = useful_judge(true);
    let SharedSkillMergeDisposition::Ruled(receipt) = fixture.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
        &Replay::new(true),
        at(21),
        21,
    )?
    else {
        panic!("a reversible merge needs no approval");
    };
    assert!(receipt.accepted);
    let lifecycle = |id: &EntityId| -> Result<SkillLifecycle> {
        Ok(fixture
            .vault
            .get_skill_record(id)?
            .expect("revision stays readable")
            .lifecycle_status)
    };
    assert_eq!(lifecycle(&merged)?, SkillLifecycle::Active);
    assert_eq!(lifecycle(&fixture.baseline)?, SkillLifecycle::Superseded);

    let SharedSkillRollback::Restored(restored) =
        fixture
            .vault
            .roll_back_shared_skill_merge(&merged, None, at(30), 30)?
    else {
        panic!("a rollback that widens nothing needs no answer");
    };
    let current = fixture
        .vault
        .get_skill_record(&restored)?
        .expect("restoring revision");
    assert_eq!(current.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(current.skill_id, original.skill_id);
    assert_eq!(current.desc, original.desc);
    assert_ne!(current.version, "2");
    assert_eq!(lifecycle(&merged)?, SkillLifecycle::Superseded);
    let mut displaced = original;
    displaced.lifecycle_status = SkillLifecycle::Superseded;
    assert_eq!(
        fixture.vault.get_skill_record(&fixture.baseline)?,
        Some(displaced),
        "the old revision stays readable, unchanged"
    );
    let edges = fixture.vault.edges_out(&restored)?;
    assert!(
        edges.iter().any(|edge| {
            edge.kind == crate::edge::EdgeKind::Supersedes && edge.target == merged
        })
    );
    assert!(edges.iter().any(|edge| {
        edge.kind == crate::edge::EdgeKind::DerivedFrom && edge.target == fixture.baseline
    }));
    assert!(
        fixture
            .vault
            .roll_back_shared_skill_merge(&merged, None, at(31), 31)
            .is_err(),
        "a merge rolls back once; the restoring revision is now current"
    );
    Ok(())
}

/// A delta that widens the skill's permissions still asks, like any widening:
/// the merge waits for the owner's answer on that exact effect.
#[test]
fn shared_merge_that_widens_permissions_waits_for_the_owner() -> Result<()> {
    let fixture = Fixture::new();
    let merged = submit_fixture_delta(&fixture, &widened_package())?;
    let ask = fixture.vault.prepare_shared_skill_merge(
        merged,
        fixture.resident,
        useful_question(merged),
    )?;
    let judge = useful_judge(true);
    assert_eq!(
        fixture.vault.merge_shared_skill_delta(
            &ask,
            &judge.useful_decisions(),
            &Replay::new(true),
            at(21),
            21
        )?,
        SharedSkillMergeDisposition::PendingConsent
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&merged)?
            .expect("candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    let judge = useful_judge(true);
    let SharedSkillMergeDisposition::Ruled(receipt) = fixture.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
        &Replay::new(true),
        at(22),
        22,
    )?
    else {
        panic!("the owner answered the widening");
    };
    assert!(receipt.accepted);
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&merged)?
            .expect("merged")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

/// Greptile #1336 repro: dropping the per-merge approve-once must not drop a
/// review the scan requires. With the dial at `Low`, a delta that keeps the
/// base's admitted tool scans `ProposedRequired`. It widens nothing, and the
/// merge still waits for the owner.
#[test]
fn shared_merge_the_scan_flags_waits_for_the_owner() -> Result<()> {
    let fixture = Fixture::new();
    let delta = widened_package();
    fixture.vault.with_write_txn(|txn| {
        fixture.vault.write_admitted_capability_surface_in_txn(
            txn,
            &fixture.baseline,
            &delta.capabilities,
        )
    })?;
    crate::skill_scan::set_skill_scan_activation_risk_threshold(
        &fixture.vault,
        super::ScanRiskLevel::Low,
    )?;
    let merged = submit_fixture_delta(&fixture, &delta)?;
    let ask = fixture.vault.prepare_shared_skill_merge(
        merged,
        fixture.resident,
        useful_question(merged),
    )?;
    let lifecycle = || -> Result<SkillLifecycle> {
        Ok(fixture
            .vault
            .get_skill_record(&merged)?
            .expect("candidate")
            .lifecycle_status)
    };
    assert_eq!(
        fixture.vault.merge_shared_skill_delta(
            &ask,
            &Useful(true),
            &Replay::new(true),
            at(21),
            21
        )?,
        SharedSkillMergeDisposition::PendingConsent
    );
    assert_eq!(lifecycle()?, SkillLifecycle::Candidate);
    fixture
        .vault
        .approve_shared_skill_merge(&ask, &fixture.owner)?;
    let SharedSkillMergeDisposition::Ruled(receipt) = fixture.vault.merge_shared_skill_delta(
        &ask,
        &Useful(true),
        &Replay::new(true),
        at(22),
        22,
    )?
    else {
        panic!("the owner answered the review");
    };
    assert!(receipt.accepted);
    assert_eq!(lifecycle()?, SkillLifecycle::Active);
    Ok(())
}

/// Astra #1336 R2 repro: a rollback asks where a review is required, as a
/// merge does. Rolling back a merge that narrowed the skill restores the
/// wider admitted surface, so only the owner rolls it back.
#[test]
fn rollback_that_widens_permissions_waits_for_the_owner() -> Result<()> {
    let fixture = Fixture::new();
    fixture.vault.with_write_txn(|txn| {
        fixture.vault.write_admitted_capability_surface_in_txn(
            txn,
            &fixture.baseline,
            &widened_package().capabilities,
        )
    })?;
    let merged = submit_fixture_delta(&fixture, &package("fixture.base", "2", "check result"))?;
    let ask = fixture.vault.prepare_shared_skill_merge(
        merged,
        fixture.resident,
        useful_question(merged),
    )?;
    let judge = useful_judge(true);
    let SharedSkillMergeDisposition::Ruled(receipt) = fixture.vault.merge_shared_skill_delta(
        &ask,
        &judge.useful_decisions(),
        &Replay::new(true),
        at(21),
        21,
    )?
    else {
        panic!("a narrowing merge needs no answer");
    };
    assert!(receipt.accepted);
    assert_eq!(
        fixture
            .vault
            .roll_back_shared_skill_merge(&merged, None, at(30), 30)?,
        SharedSkillRollback::PendingOwner
    );
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&merged)?
            .expect("merged")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    // Astra #1336 R3 repro: another vault's owner proof answers nothing here.
    let elsewhere = Fixture::new();
    // CodeRabbit #1336 repro: a deleted owner keeps a PERSON shell that the
    // owner proof's liveness check still reads as live; only the deletion
    // tombstone tells, and that owner rolls nothing back either.
    let deleted = EntityId::now();
    fixture.vault.put_entity(
        &deleted,
        crate::registry::ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"deleted owner",
    )?;
    let deleted = fixture.vault.authenticate_owner(
        deleted,
        "principal:deleted-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(fixture.vault.delete_entity(&deleted.actor())?);
    for (stranger, why) in [
        (
            &elsewhere.owner,
            "another vault's owner does not roll this one back",
        ),
        (&deleted, "a deleted owner does not roll back"),
    ] {
        let error = fixture
            .vault
            .roll_back_shared_skill_merge(&merged, Some(stranger), at(30), 30)
            .expect_err(why);
        assert_eq!(error.kind(), ErrorKind::ConsentOwnerNotAuthenticated);
        assert_eq!(
            fixture
                .vault
                .get_skill_record(&merged)?
                .expect("merged")
                .lifecycle_status,
            SkillLifecycle::Active
        );
    }
    let SharedSkillRollback::Restored(restored) =
        fixture
            .vault
            .roll_back_shared_skill_merge(&merged, Some(&fixture.owner), at(31), 31)?
    else {
        panic!("the owner rolls back");
    };
    assert_eq!(
        fixture
            .vault
            .get_skill_record(&restored)?
            .expect("restoring revision")
            .lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

/// Scores instructions that say "twice" above any that do not, so a delta can
/// beat a stored revision the default fixture scorer already rates highest.
fn prefers_twice_notes() -> FixtureNotes<'static> {
    fixture_notes(
        "fixture-judge@1",
        FixtureProvider::new(
            ProviderPin {
                rung: DecisionRung::SystemOne,
                model: "fixture-judge".to_owned(),
                version: "1".to_owned(),
            },
            "fixture-judge@1",
            |kind, _, state| match kind.as_deref() {
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
                    Ok(score_answer(if instructions.contains("twice") {
                        0.95
                    } else {
                        0.2
                    }))
                }
                other => panic!("PrefersTwice asked an unexpected kind: {other:?}"),
            },
        ),
    )
}

/// Admits `stored` (version "1": the held-out reserve stamps that version on
/// its receipts) as a stored revision, then merges a delta over it with no
/// approval. Returns the stored revision and the merged one.
fn merge_over_a_stored_revision(
    fixture: &Fixture,
    stored: &HubPackage,
) -> Result<(EntityId, EntityId)> {
    let (original, publisher) = fixture.hub(SkillHubTrustTier::Community);
    let source = HubRef::new(
        original.hub_id,
        "stored",
        HubPin::ContentHash(stored.content_hash()?.to_hex()),
    )?;
    let base = fixture
        .vault
        .import_skill_from_hub(&source, stored, at(20), 20)?;
    let ask = fixture.vault.prepare_marketplace_activation(
        base,
        &source,
        &publisher,
        fixture.baseline,
    )?;
    fixture
        .vault
        .approve_marketplace_activation(&ask, &fixture.owner)?;
    let HubAdmissionDisposition::Ruled(admitted) =
        fixture
            .vault
            .admit_marketplace_skill(&ask, &Replay::new(true), at(22), 22)?
    else {
        panic!("consented stored source")
    };
    assert!(admitted.accepted);
    reserve(&fixture.vault, &base, "fixture.stored");

    let merged = fixture.vault.submit_shared_skill_delta(
        &base,
        &encode_hub_package(&package("fixture.stored", "2", "check the result twice"))?,
        SharedSkillLane::FederationMergeBack,
        "member:fixture",
        &EntityId::now(),
        at(30),
        30,
    )?;
    let merge_ask = fixture.vault.prepare_shared_skill_merge(
        merged,
        fixture.resident,
        useful_question(merged),
    )?;
    let judge = useful_judge(true);
    let prefers_twice = prefers_twice_notes();
    let SharedSkillMergeDisposition::Ruled(receipt) = fixture.vault.merge_shared_skill_delta(
        &merge_ask,
        &judge.useful_decisions(),
        &prefers_twice,
        at(31),
        31,
    )?
    else {
        panic!("a reversible merge needs no approval");
    };
    assert!(receipt.accepted);
    Ok((base, merged))
}

/// Rolling back a merge over a stored revision restores that revision's own
/// source in its own format: a native tree byte for byte (its version is
/// native metadata), a folder tree with only its frontmatter version renewed.
#[test]
fn rollback_restores_a_stored_revision_in_its_own_format() -> Result<()> {
    for format in [SkillPackageFormat::Native, SkillPackageFormat::Folder] {
        let fixture = Fixture::new();
        let mut stored = package("fixture.stored", "1", "check result");
        if format == SkillPackageFormat::Native {
            stored.files = vec![HubFile::new(
                "SKILL.md",
                b"---\nname: source-name\n---\ncheck result\n".to_vec(),
            )];
            stored.format = SkillPackageFormat::Native;
        }
        stored.record.content_hash = Some(stored.content_hash()?);
        let (_, merged) = merge_over_a_stored_revision(&fixture, &stored)?;

        let SharedSkillRollback::Restored(restored) =
            fixture
                .vault
                .roll_back_shared_skill_merge(&merged, None, at(40), 40)?
        else {
            panic!("restoring a stored revision widens nothing");
        };
        let record = fixture
            .vault
            .get_skill_record(&restored)?
            .expect("restoring revision");
        assert_eq!(record.lifecycle_status, SkillLifecycle::Active);
        let txn = fixture.vault.store.env.read_txn()?;
        let source = fixture
            .vault
            .export_hub_package_in_txn(&txn, &restored)?
            .expect("restored source package");
        assert_eq!(source.format, format);
        match format {
            SkillPackageFormat::Native => assert_eq!(source.files, stored.files),
            SkillPackageFormat::Folder => assert_eq!(
                source.files,
                package("fixture.stored", &record.version, "check result").files
            ),
        }
    }
    Ok(())
}

/// Greptile #1336 repro: a rollback never restores a revision without the
/// instructions it had. Deleting the displaced revision's source carrier
/// leaves its record but not its package, so the rollback is refused with a
/// typed error and nothing changes. A revision that never had a package
/// still rolls back as its record alone: see
/// `shared_merge_lands_without_approval_and_rolls_back_to_the_old_revision`.
#[test]
fn rollback_refuses_a_revision_whose_package_is_gone() -> Result<()> {
    let fixture = Fixture::new();
    let mut stored = package("fixture.stored", "1", "check result");
    stored.record.content_hash = Some(stored.content_hash()?);
    let (base, merged) = merge_over_a_stored_revision(&fixture, &stored)?;
    let carrier = super::source_carrier::source_carrier_id(&base, &stored.content_hash()?)?;
    assert!(fixture.vault.delete_entity(&carrier)?);
    let records = || -> Result<_> {
        Ok((
            fixture.vault.get_skill_record(&base)?.expect("displaced"),
            fixture.vault.get_skill_record(&merged)?.expect("merged"),
        ))
    };
    let before = records()?;
    assert!(before.0.content_hash.is_some());
    let error = fixture
        .vault
        .roll_back_shared_skill_merge(&merged, None, at(40), 40)
        .expect_err("the displaced revision's instructions are gone");
    assert_eq!(error.kind(), ErrorKind::SkillPackageUnavailable);
    assert_eq!(records()?, before);
    assert_eq!(before.1.lifecycle_status, SkillLifecycle::Active);
    assert!(
        fixture
            .vault
            .edges_in(&merged)?
            .iter()
            .all(|edge| edge.kind != crate::edge::EdgeKind::Supersedes)
    );
    Ok(())
}
