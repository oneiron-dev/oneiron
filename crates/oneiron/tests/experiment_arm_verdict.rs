//! `vault.arms.verdict` and `vault.arms.review` (design pass 32 r2,
//! sections 3.6, 4.5 and 4.6; row M2-E) through the engine acts the host
//! doors call.
//!
//! - T18: a kill scores the rung at once: its outcome and its receipt
//!   projection land in the verdict's write, and the family's payoff row
//!   counts the loss.
//! - T19: a promote scores nothing until its review confirms it; the
//!   confirm opens the next rung with the engine's promotion record.
//! - T20: an invalid rung writes no outcome and no receipt, also a promote
//!   a review changes to invalid; a reason the rows do not support is
//!   refused; a withdrawal frees the hold.
//! - T21: a reviewer who ran the arm is refused: the admitter, the
//!   promote's author, a reserver at the rung, the declared runner, a lead
//!   of the line under another Grant, a review declaring the runner's
//!   model; a Grant outside the line's reviewers; the owner's proof.
//! - The owner's own proof reviews an arm with no reviewer Grant on the
//!   line, and the review stands as the owner's (Engine ANSWER 11:18 to
//!   NOTE PLAN-M2-E2); the independence holds for the owner too.
//! - T22: two reviewers race and the rung keeps its first outcome; the
//!   generic outcome setter is refused on the arm's receipt.
//! - T23: a second hold is refused, and the first adds no room.
//! - T35: a confirm writes the arm row and the receipt projection, and its
//!   replay changes neither; also at the last rung.
//! - T51: no measured unit, a result that is none of its outputs, a live
//!   claim and a unit of another arm are refused.
//! - T52: a result digest backs one outcome on the line, also across two
//!   pending promotes.
//! - T53: a confirm at the last rung closes the arm.
//!
//! The rig is `experiment_arm_forecast.rs`'s. A unit claim and its
//! terminal (row M2-C's reserve and settlement) are stood by the test door
//! `experiment_arm_rows`.
//!
//! On the base (#10437's head) the two verbs do not exist, so this file
//! does not compile there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test experiment_arm_verdict`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::learning_evidence::Anchor;
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_REVIEW_VERB, ARMS_VERDICT_VERB, ArmAdmitRequest, ArmChangedTo,
    ArmContractAsk, ArmDecision, ArmEvidenceDigest, ArmInvalidReason, ArmReviewRequest,
    ArmReviewVerdict, ArmState, ArmVerdictRequest, ArmView, ExperimentArm, HoldEndCause, RungEnd,
    RungState, RunnerRef, arm_admit_as, arm_review_as, arm_verdict_as, rung_receipt_ref,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_line::{
    BudgetPolicy, ClaimState, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePolicy,
    GpuLineSetRequest, Track, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal, gpu_seconds,
};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult,
};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::team::{TeamOutcome, payoff_table, settle_team_outcome, team_receipt};
use oneiron::test_doors::experiment_arm_rows::put_claim;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::store_writes::last_committed_write;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Error, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0: the admissions.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// When the rig's units settle.
const SETTLED_MS: u64 = NOW_MS + 1_200_000;
/// When the verdicts and reviews are given.
const LATER_MS: u64 = SETTLED_MS + 60_000;
/// Each rung's cap in the rig's policy: one first allowance.
const RUNG_SECS: u64 = 1_800;
/// What a settled unit charged.
const CHARGED_SECS: u64 = 1_200;
/// The market left beside the floor: less than one first allowance.
const MARKET_SECS: u64 = 300;
/// The runner model every rig arm declares.
const RUNNER_MODEL: &str = "open-model-runner";
/// The model a rig review declares.
const REVIEW_MODEL: &str = "another-model-reviewer";

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, and this install's live machine profile
/// (the owner's agent Grant act needs it). As `experiment_arm_admit.rs`
/// builds it.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound to host");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .sign_owner_project(
            &owner_proof,
            &vault
                .owner_project_signer(&issuer)
                .expect("owner project signer"),
            vault.root_project().expect("root project"),
        )
        .expect("the owner signs the root project");
    Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    }
}

/// A line's role lists, by Grant id.
#[derive(Default, Clone)]
struct Roles {
    leads: Vec<EntityId>,
    reviewers: Vec<EntityId>,
}

impl Fixture {
    /// An owner-born project under `parent`, with `depth_remaining` levels
    /// left below it.
    fn project_under(&self, parent: EntityId, depth_remaining: u64) -> EntityId {
        let id = EntityId::now();
        let mut record = ProjectRecord::new(
            id,
            Some(parent),
            self.vault.root_project().expect("root project"),
            self.owner,
        )
        .expect("project record");
        record.depth_remaining = depth_remaining;
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self
                .vault
                .owner_project_signer(&self.issuer)
                .expect("owner project signer"),
            self.owner,
            id,
            &record,
        )
        .unwrap_or_else(|error| {
            panic!("the owner bears project {id:?} under {parent:?}: {error:?}")
        });
        id
    }

    fn root(&self) -> EntityId {
        self.vault.root_project().expect("root project")
    }

    /// A lane under the root, its line set before period 0 with `roles`,
    /// `rungs` rungs and one demand family of `floor_arms` floor arms
    /// seated then, so the first mint funds it. Returns the lane and the
    /// family.
    fn lane(&self, roles: &Roles, floor_arms: u32, rungs: usize) -> (EntityId, EntityId) {
        let lane = self.project_under(self.root(), 2);
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: "set".to_owned(),
                    project: lane,
                    policy: policy(roles, floor_arms, rungs),
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
        let family = self.project_under(lane, 0);
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .admit_gpu_line_family(
                Some(&self.owner_proof),
                &GpuLineFamilyAdmitRequest {
                    intent_key: "seat".to_owned(),
                    project: lane,
                    family,
                    track: Track::Demand,
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner seats the family: {error:?}"));
        (lane, family)
    }

    /// A named agent and the owner's Grant naming it, listing `verbs` (with
    /// `read`, which a Grant needs to confer) over every project. Returns
    /// the agent and the Grant's id.
    fn agent(&self, name: &str, verbs: &[&str]) -> (EntityId, EntityId) {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        authority_scope.audience = ScopeAxis::<ScopeId>::All;
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("the owner mints the agent a Grant");
        assert!(minted.grant.confers, "agent={name} verbs={verbs:?}");
        (agent, minted.grant.grant_ref)
    }

    /// Admits `ask` as the owner (`None`) or as the lead `agent`.
    fn admit_as(&self, caller: Option<EntityId>, ask: &ArmAdmitRequest) -> ExperimentArm {
        let admitted = match caller {
            None => arm_admit_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                ask,
                NOW_MS,
            ),
            Some(agent) => arm_admit_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                ask,
                NOW_MS,
            ),
        };
        admitted
            .unwrap_or_else(|error| panic!("{} is admitted: {error:?}", ask.title))
            .arm
    }

    /// The owner admits arm `title` on contract number `contract` into
    /// `family` of `lane`'s line.
    fn admit(&self, lane: EntityId, family: EntityId, contract: u8, title: &str) -> ExperimentArm {
        self.admit_as(None, &admission(lane, family, contract, title))
    }

    /// A work claim at `rung` of `arm` that settled at `SETTLED_MS`,
    /// charged `CHARGED_SECS`, with `outputs`; reserved by `reserved_by`.
    fn settle(
        &self,
        arm: &ExperimentArm,
        rung: u8,
        unit_key: &str,
        reserved_by: Option<EntityId>,
        outputs: Vec<ArmEvidenceDigest>,
    ) -> UnitClaim {
        let claim = claim(arm, rung, unit_key, UnitPurpose::Work, settled(outputs));
        let claim = UnitClaim {
            reserved_by,
            ..claim
        };
        put_claim(&self.vault, &claim).expect("the test door puts the claim");
        claim
    }

    /// `vault.arms.verdict` at `LATER_MS` as the owner (`None`) or as `agent`.
    fn verdict(&self, caller: Option<EntityId>, ask: &ArmVerdictRequest) -> MemoryResult<ArmView> {
        match caller {
            None => arm_verdict_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                ask,
                LATER_MS,
            ),
            Some(agent) => arm_verdict_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                ask,
                LATER_MS,
            ),
        }
    }

    /// `vault.arms.review` at `LATER_MS` as `agent`.
    fn review(&self, agent: EntityId, ask: &ArmReviewRequest) -> MemoryResult<ArmView> {
        arm_review_as(
            &self.vault.memory(agent, EdgeActorClass::Agent),
            None,
            ask,
            LATER_MS,
        )
    }

    /// `vault.arms.review` at `LATER_MS` under the owner's own proof.
    fn review_as_owner(&self, ask: &ArmReviewRequest) -> MemoryResult<ArmView> {
        arm_review_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            ask,
            LATER_MS,
        )
    }

    /// The stored arm `id`.
    fn arm(&self, id: EntityId) -> ExperimentArm {
        self.vault
            .experiment_arm(&id)
            .expect("read")
            .expect("the arm")
    }

    /// The (wins, losses) of `family`'s one payoff row, `None` with no row.
    fn payoff_of(&self, family: EntityId) -> Option<(u64, u64)> {
        let rows: Vec<_> = payoff_table(&self.vault, None)
            .expect("the payoff view")
            .into_iter()
            .filter(|row| row.project == Some(family))
            .collect();
        assert!(rows.len() <= 1, "one payoff row per family in the rig");
        rows.first().map(|row| (row.wins, row.losses))
    }
}

/// The line's policy: one demand floor of `floor_arms` first allowances, no
/// pinned share, no seat reserve, no new-idea pool, a market smaller than
/// one first allowance, and `rungs` rungs of one first allowance each.
fn policy(roles: &Roles, floor_arms: u32, rungs: usize) -> GpuLinePolicy {
    GpuLinePolicy {
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: Vec::new(),
        machines: Vec::new(),
        leads: roles.leads.clone(),
        reviewers: roles.reviewers.clone(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            allowance_units: u64::from(floor_arms) * RUNG_SECS + MARKET_SECS,
            pinned_parts: (0, 3),
            floor_arms,
            rung_caps_secs: vec![RUNG_SECS; rungs],
            seat_reserve_floors: 0,
            new_idea_slots_per_period: 0,
            ..BudgetPolicy::default()
        },
    }
}

/// The contract sha256 numbered `contract`.
fn contract_sha(contract: u8) -> String {
    format!("{contract:02x}").repeat(32)
}

/// An evidence digest named `name` whose sha256 repeats `byte`.
fn digest(name: &str, byte: u8) -> ArmEvidenceDigest {
    ArmEvidenceDigest {
        name: name.to_owned(),
        sha256: format!("{byte:02x}").repeat(32),
        bytes: 64,
        rows: None,
    }
}

/// An admission of one arm titled `title`, on contract number `contract`,
/// into `family` of `lane`'s line.
fn admission(lane: EntityId, family: EntityId, contract: u8, title: &str) -> ArmAdmitRequest {
    ArmAdmitRequest {
        intent_key: format!("admit-{contract}"),
        line: lane,
        family,
        type_ref: TypeRef::root(1),
        title: title.to_owned(),
        contract: ArmContractAsk {
            path: "contracts/arm.md".to_owned(),
            sha256: contract_sha(contract),
            note: None,
            claimed_frozen_at_ms: Some(BEFORE_MS),
        },
        runner: RunnerRef {
            model: RUNNER_MODEL.to_owned(),
            actor: None,
        },
        supersedes: None,
        ledger_rows: Vec::new(),
        card_digest: None,
    }
}

/// A claim at `rung` of `arm` for `purpose`, in `state`, as row M2-C's
/// reserve and settlement would leave it.
fn claim(
    arm: &ExperimentArm,
    rung: u8,
    unit_key: &str,
    purpose: UnitPurpose,
    state: ClaimState,
) -> UnitClaim {
    UnitClaim {
        id: EntityId::now(),
        arm: arm.id,
        rung,
        unit_key: unit_key.to_owned(),
        attempt: 1,
        line: arm.line,
        family: arm.family,
        period: 0,
        purpose,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: arm.contract.sha256.clone(),
        reserved_secs: RUNG_SECS,
        draws: vec![Draw {
            source: DrawSource::FirstAllowance,
            units: RUNG_SECS,
        }],
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-0".to_owned(),
            generation: 1,
        },
        grant: None,
        reserved_by: None,
        reserved_at_ms: NOW_MS,
        ask_digest: "ad".repeat(32),
        state,
        revision: 1,
    }
}

/// A terminal that ran and settled with `outputs`.
fn settled(outputs: Vec<ArmEvidenceDigest>) -> ClaimState {
    ClaimState::Ended(UnitTerminal {
        end: UnitEnd::Settled,
        charged_secs: CHARGED_SECS,
        measured_secs: CHARGED_SECS,
        lost_secs: 0,
        machine: None,
        device_id: None,
        node_end: Some("exited(0)".to_owned()),
        outputs,
        ended_at_ms: SETTLED_MS,
    })
}

/// A terminal that charged nothing: `end` is not a settlement.
fn ended(end: UnitEnd) -> ClaimState {
    ClaimState::Ended(UnitTerminal {
        end,
        charged_secs: 0,
        measured_secs: 0,
        lost_secs: 0,
        machine: None,
        device_id: None,
        node_end: None,
        outputs: Vec::new(),
        ended_at_ms: SETTLED_MS,
    })
}

/// A verdict of `decision` on rung 1 of `arm` as read, resting on `units`
/// and `result`, under `key`.
fn verdict_ask(
    key: &str,
    arm: &ExperimentArm,
    decision: ArmDecision,
    units: &[EntityId],
    result: Option<&ArmEvidenceDigest>,
) -> ArmVerdictRequest {
    ArmVerdictRequest {
        intent_key: key.to_owned(),
        arm: arm.id,
        rung: arm.rungs.last().map_or(1, |rung| rung.rung),
        arm_revision: arm.revision,
        decision,
        units: units.to_vec(),
        result: result.cloned(),
        numbers: BTreeMap::from([("pass_rate".to_owned(), 0.5)]),
        text: String::new(),
        evidence: Vec::new(),
        ledger_row: None,
        contract_sha256: arm.contract.sha256.clone(),
    }
}

/// A review of `verdict` on the current rung of `arm` as read, citing
/// `result`, under `key`.
fn review_ask(
    key: &str,
    arm: &ExperimentArm,
    verdict: ArmReviewVerdict,
    result: &ArmEvidenceDigest,
) -> ArmReviewRequest {
    ArmReviewRequest {
        intent_key: key.to_owned(),
        arm: arm.id,
        rung: arm.rungs.last().map_or(1, |rung| rung.rung),
        of_arm_revision: arm.revision,
        verdict,
        result: result.clone(),
        evidence: Vec::new(),
        review_ref: digest("REVIEW.md", 0xee),
        ledger_row: None,
        model: REVIEW_MODEL.to_owned(),
    }
}

fn refused_as(error: &MemoryError, code: &str, mark: &str) {
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(mark), "{mark}: {error:?}");
}

/// T18, with the logical key: the same verdict under a new key answers it,
/// another verdict at the same revision is a conflict.
#[test]
fn a_kill_moves_the_payoff_row_at_once() {
    let fixture = fixture();
    let (lane, family) = fixture.lane(&Roles::default(), 1, 2);
    let arm = fixture.admit(lane, family, 1, "killed");
    let result = digest("result.json", 0xa1);
    let unit = fixture.settle(&arm, 1, "check/shard-0", None, vec![result.clone()]);
    assert_eq!(
        fixture.payoff_of(family),
        None,
        "no receipt before the verdict"
    );

    let ask = verdict_ask("kill", &arm, ArmDecision::Kill, &[unit.id], Some(&result));
    let killed = fixture
        .verdict(None, &ask)
        .expect("the lead kills the rung");
    assert!(!killed.replayed);
    assert_eq!(killed.arm.revision, arm.revision + 1);
    assert_eq!(killed.arm.state, ArmState::Killed);
    let rung = &killed.arm.rungs[0];
    assert_eq!(
        rung.state,
        RungState::Closed {
            end: RungEnd::Killed
        }
    );
    let outcome = rung.outcome.clone().expect("a kill is scored at once");
    assert!(!outcome.success);
    assert_eq!(outcome.anchor, Anchor::HeldOut);
    assert_eq!(outcome.at_ms, LATER_MS);
    assert_eq!(rung.work_done_at_ms, Some(SETTLED_MS));
    let receipt_ref = rung_receipt_ref(&arm.id, 1);
    assert_eq!(receipt_ref, format!("arm:{}:r1", arm.id.to_hex()));
    assert_eq!(rung.receipt.as_deref(), Some(receipt_ref.as_str()));
    assert_eq!(
        killed.arm.hold_end.map(|end| end.cause),
        Some(HoldEndCause::RungClosed),
        "rung 1 left Open: the hold ends"
    );

    let receipt = team_receipt(&fixture.vault, &receipt_ref)
        .expect("read")
        .expect("the receipt projection");
    assert_eq!(receipt.project, Some(family));
    assert_eq!(receipt.models, vec![RUNNER_MODEL.to_owned()]);
    assert_eq!(receipt.shape.width, 1);
    assert_eq!(receipt.pattern_skill, None, "it teaches no pattern skill");
    assert_eq!(receipt.spend, Some(1_200.0));
    assert_eq!(receipt.spend_cap, Some(1_800.0));
    let projected = receipt.outcome.expect("the receipt carries the outcome");
    assert_eq!(projected.receipt, receipt_ref);
    assert_eq!(
        (projected.success, projected.anchor),
        (false, Anchor::HeldOut)
    );
    assert_eq!(
        fixture.payoff_of(family),
        Some((0, 1)),
        "the family's payoff row counts the loss"
    );

    let again = fixture
        .verdict(
            None,
            &ArmVerdictRequest {
                intent_key: "kill-again".to_owned(),
                ..ask.clone()
            },
        )
        .expect("the same verdict under a new key");
    assert!(again.replayed);
    assert_eq!(again.arm, killed.arm, "a replay writes nothing");
    let other = fixture
        .verdict(
            None,
            &ArmVerdictRequest {
                intent_key: "kill-other".to_owned(),
                text: "another reading".to_owned(),
                ..ask
            },
        )
        .expect_err("another verdict at the read revision");
    refused_as(&other, MEMORY_CODE_INVALID_STATE, "verdict_set");
}

/// T19.
#[test]
fn a_promote_moves_the_payoff_row_only_when_reviewed() {
    let fixture = fixture();
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: Vec::new(),
        reviewers: vec![reviewer_grant],
    };
    let (lane, family) = fixture.lane(&roles, 1, 2);
    let arm = fixture.admit(lane, family, 1, "promoted");
    let result = digest("result.json", 0xb1);
    let unit = fixture.settle(&arm, 1, "check/shard-0", None, vec![result.clone()]);

    let promoted = fixture
        .verdict(
            None,
            &verdict_ask(
                "promote",
                &arm,
                ArmDecision::Promote,
                &[unit.id],
                Some(&result),
            ),
        )
        .expect("the lead promotes");
    let rung = &promoted.arm.rungs[0];
    assert_eq!(rung.state, RungState::AwaitingReview);
    assert_eq!(rung.outcome, None, "no outcome before the review");
    assert_eq!(rung.receipt, None);
    assert_eq!(
        promoted.arm.hold_end.map(|end| end.cause),
        Some(HoldEndCause::RungClosed),
        "rung 1 left Open"
    );
    let receipt_ref = rung_receipt_ref(&arm.id, 1);
    assert_eq!(
        team_receipt(&fixture.vault, &receipt_ref).expect("read"),
        None
    );
    assert_eq!(fixture.payoff_of(family), None);

    let confirmed = fixture
        .review(
            reviewer,
            &review_ask(
                "confirm",
                &promoted.arm,
                ArmReviewVerdict::Confirmed,
                &result,
            ),
        )
        .expect("the reviewer confirms");
    let rung = &confirmed.arm.rungs[0];
    assert_eq!(
        rung.state,
        RungState::Closed {
            end: RungEnd::Promoted
        }
    );
    let outcome = rung.outcome.clone().expect("the confirm scores the rung");
    assert!(outcome.success);
    assert_eq!(outcome.anchor, Anchor::Audit { rate: 1.0 });
    let review = rung.review.clone().expect("the review");
    assert_eq!(review.grant, Some(reviewer_grant));
    assert_eq!(review.by, Some(reviewer));
    assert_eq!(confirmed.arm.state, ArmState::Open);
    assert_eq!(confirmed.arm.rungs.len(), 2, "rung 2 opens");
    assert_eq!(confirmed.arm.rungs[1].state, RungState::Open);
    let promotion = confirmed.arm.rungs[1]
        .promotion
        .clone()
        .expect("the engine's promotion record");
    assert_eq!(promotion.reviewer, Some(reviewer));
    assert_eq!(promotion.review_at_ms, LATER_MS);
    assert!(
        team_receipt(&fixture.vault, &receipt_ref)
            .expect("read")
            .is_some()
    );
    assert_eq!(fixture.payoff_of(family), Some((1, 0)));
}

/// T20, with a withdrawal and the reasons the rows must support.
#[test]
fn an_invalid_run_writes_no_receipt_and_no_outcome() {
    let fixture = fixture();
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: Vec::new(),
        reviewers: vec![reviewer_grant],
    };
    let (lane, family) = fixture.lane(&roles, 3, 2);

    let measured = fixture.admit(lane, family, 1, "could not measure");
    let unit = fixture.settle(&measured, 1, "check/shard-0", None, Vec::new());
    let withdraw = verdict_ask(
        "withdraw-measured",
        &measured,
        ArmDecision::Invalid {
            reason: ArmInvalidReason::Withdrawn,
        },
        &[],
        None,
    );
    let refused = fixture
        .verdict(None, &withdraw)
        .expect_err("the rung has charged seconds");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "invalid_unsupported");
    let mut bare = verdict_ask(
        "could-not-measure",
        &measured,
        ArmDecision::Invalid {
            reason: ArmInvalidReason::CouldNotMeasure,
        },
        &[unit.id],
        None,
    );
    let refused = fixture
        .verdict(None, &bare)
        .expect_err("no text and no evidence");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "invalid_unsupported");
    bare.intent_key = "could-not-measure-explained".to_owned();
    bare.text = "the harness wrote no metric file".to_owned();
    bare.evidence = vec![digest("harness.log", 0xc2)];
    let invalid = fixture.verdict(None, &bare).expect("a supported invalid");
    assert_eq!(invalid.arm.state, ArmState::Invalid);
    assert_eq!(
        invalid.arm.rungs[0].state,
        RungState::Closed {
            end: RungEnd::Invalid {
                reason: ArmInvalidReason::CouldNotMeasure
            }
        }
    );
    assert_eq!(invalid.arm.rungs[0].outcome, None);
    assert_eq!(invalid.arm.rungs[0].receipt, None);
    assert_eq!(
        team_receipt(&fixture.vault, &rung_receipt_ref(&measured.id, 1)).expect("read"),
        None
    );

    // A promote that the review changes to invalid scores nothing either.
    let changed = fixture.admit(lane, family, 2, "changed to invalid");
    let result = digest("result.json", 0xc3);
    let unit = fixture.settle(&changed, 1, "check/shard-0", None, vec![result.clone()]);
    let promoted = fixture
        .verdict(
            None,
            &verdict_ask(
                "promote-changed",
                &changed,
                ArmDecision::Promote,
                &[unit.id],
                Some(&result),
            ),
        )
        .expect("the lead promotes");
    let reviewed = fixture
        .review(
            reviewer,
            &review_ask(
                "to-invalid",
                &promoted.arm,
                ArmReviewVerdict::Changed {
                    to: ArmChangedTo::Invalid {
                        reason: ArmInvalidReason::ContractChanged,
                    },
                },
                &result,
            ),
        )
        .expect("the reviewer changes it to invalid");
    assert_eq!(reviewed.arm.state, ArmState::Invalid);
    assert_eq!(reviewed.arm.rungs[0].outcome, None);
    assert_eq!(
        team_receipt(&fixture.vault, &rung_receipt_ref(&changed.id, 1)).expect("read"),
        None
    );
    assert_eq!(fixture.payoff_of(family), None, "no generic count moved");

    // A rung with no charged seconds is withdrawn: its hold ends.
    let idle = fixture.admit(lane, family, 3, "withdrawn");
    let withdrawn = fixture
        .verdict(
            None,
            &verdict_ask(
                "withdraw-idle",
                &idle,
                ArmDecision::Invalid {
                    reason: ArmInvalidReason::Withdrawn,
                },
                &[],
                None,
            ),
        )
        .expect("a rung with no charged seconds is withdrawn");
    assert_eq!(withdrawn.arm.state, ArmState::Withdrawn);
    assert_eq!(
        withdrawn.arm.hold_end.map(|end| end.cause),
        Some(HoldEndCause::Withdrawn)
    );
    assert_eq!(withdrawn.arm.rungs[0].outcome, None);
}

/// T21.
#[test]
fn a_reviewer_who_ran_the_arm_is_refused() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.agent("arm-lead", &[ARMS_ADMIT_VERB, ARMS_VERDICT_VERB]);
    let (_, lead_review_grant) = fixture.agent("arm-lead", &[ARMS_REVIEW_VERB]);
    let (runner, runner_grant) = fixture.agent("arm-runner", &[ARMS_REVIEW_VERB]);
    let (reserver, reserver_grant) = fixture.agent("arm-reserver", &[ARMS_REVIEW_VERB]);
    let (also_lead, also_lead_grant) = fixture.agent("also-lead", &[ARMS_VERDICT_VERB]);
    let (_, also_review_grant) = fixture.agent("also-lead", &[ARMS_REVIEW_VERB]);
    let (outsider, _) = fixture.agent("outsider", &[ARMS_REVIEW_VERB]);
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: vec![lead_grant, also_lead_grant],
        reviewers: vec![
            lead_review_grant,
            runner_grant,
            reserver_grant,
            also_review_grant,
            reviewer_grant,
        ],
    };
    let (lane, family) = fixture.lane(&roles, 2, 2);

    // Arm one: the owner admits it with a declared runner actor; the lead
    // gives the promote; another agent reserved a claim at the rung.
    let mut ask = admission(lane, family, 1, "run by the runner");
    ask.runner.actor = Some(runner);
    let arm = fixture.admit_as(None, &ask);
    let result = digest("result.json", 0xd1);
    let unit = fixture.settle(&arm, 1, "check/shard-0", None, vec![result.clone()]);
    fixture.settle(&arm, 1, "check/shard-1", Some(reserver), Vec::new());
    let promoted = fixture
        .verdict(
            Some(lead),
            &verdict_ask(
                "promote-one",
                &arm,
                ArmDecision::Promote,
                &[unit.id],
                Some(&result),
            ),
        )
        .expect("the lead promotes");
    let before = last_committed_write(&fixture.vault);
    for (caller, tie) in [
        (lead, "gave the promote"),
        (reserver, "reserved a claim"),
        (runner, "declared runner"),
        (also_lead, "lead role on the line"),
    ] {
        let refused = fixture
            .review(
                caller,
                &review_ask(
                    "review",
                    &promoted.arm,
                    ArmReviewVerdict::Confirmed,
                    &result,
                ),
            )
            .expect_err("not independent");
        refused_as(&refused, MEMORY_CODE_FORBIDDEN, "reviewer_not_independent");
        assert!(refused.message.contains(tie), "{tie}: {refused:?}");
    }
    let mut runners_model =
        review_ask("model", &promoted.arm, ArmReviewVerdict::Confirmed, &result);
    runners_model.model = RUNNER_MODEL.to_owned();
    let refused = fixture
        .review(reviewer, &runners_model)
        .expect_err("the runner's model");
    refused_as(&refused, MEMORY_CODE_FORBIDDEN, "runner's own model");
    let refused = fixture
        .review(
            outsider,
            &review_ask(
                "outsider",
                &promoted.arm,
                ArmReviewVerdict::Confirmed,
                &result,
            ),
        )
        .expect_err("a Grant outside the line's reviewers");
    refused_as(&refused, MEMORY_CODE_FORBIDDEN, "not_this_line");
    let refused = fixture
        .review_as_owner(&review_ask(
            "owner",
            &promoted.arm,
            ArmReviewVerdict::Confirmed,
            &result,
        ))
        .expect_err("the owner admitted this arm");
    refused_as(&refused, MEMORY_CODE_FORBIDDEN, "admitted the arm");
    assert_eq!(
        last_committed_write(&fixture.vault),
        before,
        "a refused review commits no write"
    );

    // Arm two: the lead admits it and the owner gives the promote.
    let second = fixture.admit_as(Some(lead), &admission(lane, family, 2, "the lead's own"));
    let result_two = digest("result.json", 0xd2);
    let unit_two = fixture.settle(&second, 1, "check/shard-0", None, vec![result_two.clone()]);
    let promoted_two = fixture
        .verdict(
            None,
            &verdict_ask(
                "promote-two",
                &second,
                ArmDecision::Promote,
                &[unit_two.id],
                Some(&result_two),
            ),
        )
        .expect("the owner promotes");
    let refused = fixture
        .review(
            lead,
            &review_ask(
                "review-two",
                &promoted_two.arm,
                ArmReviewVerdict::Confirmed,
                &result_two,
            ),
        )
        .expect_err("the admitter");
    refused_as(&refused, MEMORY_CODE_FORBIDDEN, "admitted the arm");

    // An independent reviewer confirms both.
    for (read, result) in [(&promoted.arm, &result), (&promoted_two.arm, &result_two)] {
        let key = format!("independent-{}", read.title);
        fixture
            .review(
                reviewer,
                &review_ask(&key, read, ArmReviewVerdict::Confirmed, result),
            )
            .unwrap_or_else(|error| panic!("{}: {error:?}", read.title));
    }
}

/// The owner's proof passes the review door (section 5.1 point 4): with no
/// reviewer Grant on the line, the owner confirms a lead's promote and the
/// review stands as the owner's.
#[test]
fn an_owner_review_stands_without_a_reviewer_grant() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.agent("arm-lead", &[ARMS_ADMIT_VERB, ARMS_VERDICT_VERB]);
    let roles = Roles {
        leads: vec![lead_grant],
        reviewers: Vec::new(),
    };
    let (lane, family) = fixture.lane(&roles, 1, 2);
    let arm = fixture.admit_as(Some(lead), &admission(lane, family, 1, "the lead's arm"));
    let result = digest("result.json", 0x0a);
    let unit = fixture.settle(&arm, 1, "check/shard-0", None, vec![result.clone()]);
    let promoted = fixture
        .verdict(
            Some(lead),
            &verdict_ask(
                "promote",
                &arm,
                ArmDecision::Promote,
                &[unit.id],
                Some(&result),
            ),
        )
        .expect("the lead promotes");

    let confirmed = fixture
        .review_as_owner(&review_ask(
            "owner-confirm",
            &promoted.arm,
            ArmReviewVerdict::Confirmed,
            &result,
        ))
        .expect("the owner's review stands");
    let rung = &confirmed.arm.rungs[0];
    assert_eq!(
        rung.state,
        RungState::Closed {
            end: RungEnd::Promoted
        }
    );
    let review = rung.review.clone().expect("the review");
    assert_eq!(review.grant, None, "the owner's proof, no Grant");
    assert_eq!(review.by, Some(fixture.owner));
    assert_eq!(
        rung.outcome.as_ref().map(|outcome| outcome.anchor),
        Some(Anchor::Audit { rate: 1.0 })
    );
    assert_eq!(
        confirmed.arm.rungs[1]
            .promotion
            .as_ref()
            .and_then(|promotion| promotion.reviewer),
        Some(fixture.owner)
    );
    assert_eq!(fixture.payoff_of(family), Some((1, 0)));
}

/// T22.
#[test]
fn a_settled_rung_keeps_its_first_outcome() {
    let fixture = fixture();
    let (first, first_grant) = fixture.agent("first-reviewer", &[ARMS_REVIEW_VERB]);
    let (second, second_grant) = fixture.agent("second-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: Vec::new(),
        reviewers: vec![first_grant, second_grant],
    };
    let (lane, family) = fixture.lane(&roles, 1, 2);
    let arm = fixture.admit(lane, family, 1, "raced");
    let result = digest("result.json", 0xe1);
    let unit = fixture.settle(&arm, 1, "check/shard-0", None, vec![result.clone()]);
    let promoted = fixture
        .verdict(
            None,
            &verdict_ask(
                "promote",
                &arm,
                ArmDecision::Promote,
                &[unit.id],
                Some(&result),
            ),
        )
        .expect("the lead promotes");

    // Both reviewers read the same revision; the first to write wins.
    let confirmed = fixture
        .review(
            first,
            &review_ask("first", &promoted.arm, ArmReviewVerdict::Confirmed, &result),
        )
        .expect("the first review confirms");
    let late = fixture
        .review(
            second,
            &review_ask(
                "second",
                &promoted.arm,
                ArmReviewVerdict::Changed {
                    to: ArmChangedTo::Kill,
                },
                &result,
            ),
        )
        .expect_err("the rung is settled");
    refused_as(&late, MEMORY_CODE_INVALID_STATE, "rung_closed");
    let stored = fixture.arm(arm.id);
    assert_eq!(stored, confirmed.arm, "the second review wrote nothing");
    assert!(
        stored.rungs[0]
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.success)
    );

    // The generic outcome setter is refused on the arm's receipt.
    let receipt_ref = rung_receipt_ref(&arm.id, 1);
    let generic = settle_team_outcome(
        &fixture.vault,
        &receipt_ref,
        &TeamOutcome {
            receipt: "an-owner-verdict".to_owned(),
            anchor: Anchor::OwnerVerdict,
            success: false,
            at: 9,
            critics: None,
        },
    );
    assert!(
        matches!(&generic, Err(Error::InvalidClaimBody(reason)) if reason.contains("arm:")),
        "{generic:?}"
    );
    let receipt = team_receipt(&fixture.vault, &receipt_ref)
        .expect("read")
        .expect("the receipt projection");
    assert!(
        receipt.outcome.expect("its outcome").success,
        "the receipt keeps the first outcome"
    );
    assert_eq!(fixture.payoff_of(family), Some((1, 0)));
}

/// T23.
#[test]
fn a_second_hold_is_refused() {
    let fixture = fixture();
    let (lane, family) = fixture.lane(&Roles::default(), 1, 2);
    let arm = fixture.admit(lane, family, 1, "held");
    let ask = verdict_ask("hold", &arm, ArmDecision::Hold, &[], None);
    let held = fixture.verdict(None, &ask).expect("the first hold");
    let rung = &held.arm.rungs[0];
    assert_eq!(rung.state, RungState::Open);
    assert_eq!(rung.holds, 1);
    assert_eq!(rung.outcome, None);
    assert_eq!(
        held.arm.first_allowance, arm.first_allowance,
        "a hold adds no room"
    );
    assert_eq!(
        held.arm.hold_end, None,
        "the rung stays open inside its hold"
    );

    let again = fixture
        .verdict(
            None,
            &verdict_ask("hold-again", &held.arm, ArmDecision::Hold, &[], None),
        )
        .expect_err("a second hold");
    refused_as(&again, MEMORY_CODE_INVALID_STATE, "hold_once");
    let retry = fixture
        .verdict(
            None,
            &ArmVerdictRequest {
                intent_key: "hold-retry".to_owned(),
                ..ask
            },
        )
        .expect("the first hold, asked again under a new key");
    assert!(retry.replayed);
    assert_eq!(retry.arm.revision, held.arm.revision);
    // Another verdict at the hold's revision is a conflict; one at a
    // revision the arm is not at is stale.
    let conflict = fixture
        .verdict(
            None,
            &verdict_ask(
                "kill-at-hold",
                &arm,
                ArmDecision::Kill,
                &[],
                Some(&digest("r", 1)),
            ),
        )
        .expect_err("the hold was given at this revision");
    refused_as(&conflict, MEMORY_CODE_INVALID_STATE, "verdict_set");
    let mut stale = verdict_ask("kill-stale", &held.arm, ArmDecision::Kill, &[], None);
    stale.result = Some(digest("r", 1));
    stale.arm_revision += 1;
    let stale = fixture
        .verdict(None, &stale)
        .expect_err("the arm is not at that revision");
    refused_as(&stale, MEMORY_CODE_INVALID_STATE, "stale_revision");
}

/// T35.
#[test]
fn a_confirmed_promote_publishes_nothing() {
    let fixture = fixture();
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: Vec::new(),
        reviewers: vec![reviewer_grant],
    };
    let (lane, family) = fixture.lane(&roles, 1, 2);
    let arm = fixture.admit(lane, family, 1, "two rungs");
    for rung in 1..=2_u8 {
        let read = fixture.arm(arm.id);
        let result = digest("result.json", 0xf0 + rung);
        let unit = fixture.settle(&read, rung, "check/shard-0", None, vec![result.clone()]);
        let promoted = fixture
            .verdict(
                None,
                &verdict_ask(
                    &format!("promote-{rung}"),
                    &read,
                    ArmDecision::Promote,
                    &[unit.id],
                    Some(&result),
                ),
            )
            .expect("the lead promotes");
        let ask = review_ask(
            &format!("confirm-{rung}"),
            &promoted.arm,
            ArmReviewVerdict::Confirmed,
            &result,
        );
        let confirmed = fixture.review(reviewer, &ask).expect("the confirm");
        assert_eq!(confirmed.arm.revision, promoted.arm.revision + 1);
        let receipt_ref = rung_receipt_ref(&arm.id, rung);
        let receipt = team_receipt(&fixture.vault, &receipt_ref)
            .expect("read")
            .expect("the receipt projection");
        for replay in [
            ask.clone(),
            ArmReviewRequest {
                intent_key: format!("confirm-{rung}-again"),
                ..ask.clone()
            },
        ] {
            let answered = fixture.review(reviewer, &replay).expect("the replay");
            assert!(answered.replayed);
            assert_eq!(answered.arm, confirmed.arm);
            assert_eq!(fixture.arm(arm.id), confirmed.arm, "a replay writes no arm");
            assert_eq!(
                team_receipt(&fixture.vault, &receipt_ref).expect("read"),
                Some(receipt.clone()),
                "a replay writes no receipt"
            );
        }
    }
    let last = fixture.arm(arm.id);
    assert_eq!(
        last.state,
        ArmState::Succeeded,
        "the last rung closes the arm"
    );
    assert_eq!(last.rungs.len(), 2);
    assert_eq!(fixture.payoff_of(family), Some((2, 0)));
}

/// T51.
#[test]
fn a_verdict_without_a_measured_unit_is_refused() {
    let fixture = fixture();
    let (lane, family) = fixture.lane(&Roles::default(), 2, 2);
    let arm = fixture.admit(lane, family, 1, "unmeasured");
    let result = digest("result.json", 0x51);
    let kill = |key: &str, units: &[EntityId]| {
        fixture
            .verdict(
                None,
                &verdict_ask(key, &arm, ArmDecision::Kill, units, Some(&result)),
            )
            .expect_err("refused")
    };
    let before = last_committed_write(&fixture.vault);
    refused_as(
        &kill("none", &[]),
        MEMORY_CODE_INVALID_STATE,
        "no_measured_unit",
    );

    let live = claim(
        &arm,
        1,
        "check/shard-0",
        UnitPurpose::Work,
        ClaimState::Started,
    );
    put_claim(&fixture.vault, &live).expect("the test door puts the claim");
    let before_live = last_committed_write(&fixture.vault);
    refused_as(
        &kill("live", &[live.id]),
        MEMORY_CODE_INVALID_STATE,
        "units_live",
    );
    let released = UnitClaim {
        state: ended(UnitEnd::Released("launch refused".to_owned())),
        revision: 2,
        ..live
    };
    put_claim(&fixture.vault, &released).expect("the test door ends the claim");
    let lost = claim(
        &arm,
        1,
        "check/shard-1",
        UnitPurpose::Work,
        ended(UnitEnd::BoxLost),
    );
    put_claim(&fixture.vault, &lost).expect("the test door puts the claim");
    let check = claim(
        &arm,
        1,
        "review/check-0",
        UnitPurpose::ReviewCheck,
        settled(vec![result.clone()]),
    );
    put_claim(&fixture.vault, &check).expect("the test door puts the claim");
    let after_puts = last_committed_write(&fixture.vault);
    for (key, unit) in [
        ("released", released.id),
        ("box-lost", lost.id),
        ("review-check", check.id),
    ] {
        refused_as(
            &kill(key, &[unit]),
            MEMORY_CODE_INVALID_STATE,
            "no_measured_unit",
        );
    }
    let measured = fixture.settle(
        &arm,
        1,
        "check/shard-2",
        None,
        vec![digest("other.json", 0x52)],
    );
    let after_settle = last_committed_write(&fixture.vault);
    refused_as(
        &kill("not-an-output", &[measured.id]),
        MEMORY_CODE_INVALID_STATE,
        "result_not_an_output",
    );
    let other = fixture.admit(lane, family, 2, "another arm");
    let foreign = fixture.settle(&other, 1, "check/shard-0", None, vec![result.clone()]);
    let after_foreign = last_committed_write(&fixture.vault);
    refused_as(
        &kill("foreign", &[foreign.id]),
        MEMORY_CODE_INVALID_STATE,
        "unit_not_on_rung",
    );
    assert!(before < before_live && before_live < after_puts);
    assert_eq!(
        last_committed_write(&fixture.vault),
        after_foreign,
        "a refused verdict commits no write"
    );
    assert!(after_settle < after_foreign);
    assert_eq!(fixture.arm(arm.id).revision, arm.revision);
}

/// T52.
#[test]
fn a_result_digest_backs_one_outcome() {
    let fixture = fixture();
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: Vec::new(),
        reviewers: vec![reviewer_grant],
    };
    let (lane, family) = fixture.lane(&roles, 4, 2);

    let shared = digest("result.json", 0x5a);
    let first = fixture.admit(lane, family, 1, "first");
    let second = fixture.admit(lane, family, 2, "second");
    let unit_one = fixture.settle(&first, 1, "check/shard-0", None, vec![shared.clone()]);
    let unit_two = fixture.settle(&second, 1, "check/shard-0", None, vec![shared.clone()]);
    fixture
        .verdict(
            None,
            &verdict_ask(
                "kill-first",
                &first,
                ArmDecision::Kill,
                &[unit_one.id],
                Some(&shared),
            ),
        )
        .expect("the first kill scores the result");
    let refused = fixture
        .verdict(
            None,
            &verdict_ask(
                "kill-second",
                &second,
                ArmDecision::Kill,
                &[unit_two.id],
                Some(&shared),
            ),
        )
        .expect_err("the result backs a scored rung");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "result_scored");

    // Two promotes wait on one result: the first confirm scores it.
    let pending = digest("pending.json", 0x5b);
    let third = fixture.admit(lane, family, 3, "third");
    let fourth = fixture.admit(lane, family, 4, "fourth");
    let mut waiting = Vec::new();
    for arm in [&third, &fourth] {
        let unit = fixture.settle(arm, 1, "check/shard-0", None, vec![pending.clone()]);
        let key = format!("promote-{}", arm.title);
        waiting.push(
            fixture
                .verdict(
                    None,
                    &verdict_ask(&key, arm, ArmDecision::Promote, &[unit.id], Some(&pending)),
                )
                .expect("a promote scores nothing yet")
                .arm,
        );
    }
    fixture
        .review(
            reviewer,
            &review_ask(
                "confirm-third",
                &waiting[0],
                ArmReviewVerdict::Confirmed,
                &pending,
            ),
        )
        .expect("the first confirm");
    let refused = fixture
        .review(
            reviewer,
            &review_ask(
                "confirm-fourth",
                &waiting[1],
                ArmReviewVerdict::Confirmed,
                &pending,
            ),
        )
        .expect_err("the result now backs a scored rung");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "result_scored");
    assert_eq!(
        fixture.arm(fourth.id).rungs[0].state,
        RungState::AwaitingReview
    );
}

/// T53.
#[test]
fn a_confirm_at_the_last_rung_closes_the_arm() {
    let fixture = fixture();
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &[ARMS_REVIEW_VERB]);
    let roles = Roles {
        leads: Vec::new(),
        reviewers: vec![reviewer_grant],
    };
    let (lane, family) = fixture.lane(&roles, 1, 1);
    let arm = fixture.admit(lane, family, 1, "one rung");
    let result = digest("result.json", 0x53);
    let unit = fixture.settle(&arm, 1, "check/shard-0", None, vec![result.clone()]);
    let promoted = fixture
        .verdict(
            None,
            &verdict_ask(
                "promote",
                &arm,
                ArmDecision::Promote,
                &[unit.id],
                Some(&result),
            ),
        )
        .expect("the lead promotes");
    let confirmed = fixture
        .review(
            reviewer,
            &review_ask(
                "confirm",
                &promoted.arm,
                ArmReviewVerdict::Confirmed,
                &result,
            ),
        )
        .expect("the confirm at the last rung");
    assert_eq!(confirmed.arm.state, ArmState::Succeeded);
    assert_eq!(confirmed.arm.rungs.len(), 1, "no further rung opens");
    assert!(!confirmed.open);
    assert!(
        confirmed.arm.rungs[0]
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.success)
    );
}
