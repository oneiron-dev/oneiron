//! The mint's input join and `vault.gpu.lines.families.graduate` (design
//! pass 32 r2, sections 4.1 graduation and 4.3 inputs, 5.2 row 2b; LE-6;
//! row M2-E) through the engine acts the host doors call.
//!
//! - T54: GPU time is cost when it is spent. A settled claim of an open, a
//!   held, an awaiting and a killed rung counts in `cost_secs` at the next
//!   mint; a rung closed invalid before the cutoff counts in `invalid_secs`
//!   alone, which is all that `CountsNowhere` leaves out; a rung closed
//!   invalid after the cutoff is still cost there. A claim that settled
//!   after the cutoff, an open, a released and a box-lost claim are no
//!   input. A kill is a loss, a confirmed promote a win.
//! - T63: a new idea graduates only after a confirmed promote. No promote,
//!   an unreviewed promote and a kill do not qualify; the lead moves it to
//!   demand, the owner to interest. The seat changes in place: one project
//!   never holds two kinds. A demand seat does not graduate.
//! - T5b, the graduation half: a lead and a planner are refused a
//!   graduation to interest.
//! - The lapse (4.1): a new idea with a confirmed promote does not lapse at
//!   the mint after its funded periods, so the lead can still graduate it;
//!   one without lapses.
//!
//! The rig is `experiment_arm_verdict.rs`'s. A unit claim and its terminal
//! (row M2-C's reserve and settlement) are stood by the test door
//! `experiment_arm_rows`.
//!
//! On the base (#10446's head) the graduate verb does not exist, so this
//! file does not compile there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test gpu_line_inputs_and_graduation`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_VERDICT_VERB, ArmAdmitRequest, ArmContractAsk, ArmDecision,
    ArmEvidenceDigest, ArmInvalidReason, ArmReviewRequest, ArmReviewVerdict, ArmVerdictRequest,
    ArmView, ExperimentArm, RungEnd, RungState, RunnerRef, arm_admit_as, arm_review_as,
    arm_verdict_as,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_line::{
    BudgetPolicy, ClaimState, Draw, DrawSource, GpuLine, GpuLineFamilyAdmitRequest,
    GpuLineFamilyGraduateRequest, GpuLinePolicy, GpuLineSetRequest, GpuLineView, Graduation,
    SettledTally, Track, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal,
    VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_FAMILIES_GRADUATE, gpu_seconds,
    settled_tallies_in_txn,
};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryError,
    MemoryResult,
};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::callable_skill::read_txn;
use oneiron::test_doors::experiment_arm_rows::put_claim;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0: the arms are admitted.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// When the rig's units settle, inside period 0.
const SETTLED_MS: u64 = NOW_MS + 1_200_000;
/// The verdicts, inside period 0.
const VERDICT_MS: u64 = SETTLED_MS + 60_000;
/// The reviews, inside period 0.
const REVIEW_MS: u64 = VERDICT_MS + 60_000;
/// The rung-1 cap: one first allowance.
const RUNG_SECS: u64 = 1_800;
/// What one settled unit is charged.
const CHARGED_SECS: u64 = 1_200;
/// The market left beside the floors of the T54 line.
const MARKET_SECS: u64 = 300;
const RUNNER_MODEL: &str = "open-model-runner";
const REVIEW_MODEL: &str = "another-model-reviewer";

/// A moment inside period `index`.
fn in_period(index: u64) -> u64 {
    ANCHOR_MS + index * PERIOD_MS + 5_000
}

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, and this install's live machine profile
/// (the owner's agent Grant act needs it). As `experiment_arm_verdict.rs`
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
    planners: Vec<EntityId>,
}

/// The rig's agents: a lead, and a planner who holds the graduate verb.
struct Agents {
    lead: EntityId,
    planner: EntityId,
    roles: Roles,
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

    /// The lead (admits, gives verdicts, graduates) and the planner (holds
    /// the graduate and family-admit verbs), with the line's role lists.
    fn agents(&self) -> Agents {
        let (lead, lead_grant) = self.agent(
            "line-lead",
            &[
                ARMS_ADMIT_VERB,
                ARMS_VERDICT_VERB,
                VAULT_GPU_LINES_FAMILIES_GRADUATE,
            ],
        );
        let (planner, planner_grant) = self.agent(
            "line-planner",
            &[
                VAULT_GPU_LINES_FAMILIES_ADMIT,
                VAULT_GPU_LINES_FAMILIES_GRADUATE,
            ],
        );
        Agents {
            lead,
            planner,
            roles: Roles {
                leads: vec![lead_grant],
                planners: vec![planner_grant],
            },
        }
    }

    /// A lane under the root with its line set before period 0 under
    /// `budget` and `roles`.
    fn lane(&self, roles: &Roles, budget: BudgetPolicy) -> EntityId {
        let lane = self.project_under(self.root(), 2);
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: "set".to_owned(),
                    project: lane,
                    policy: policy(roles, budget),
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
        lane
    }

    /// The owner sets `lane`'s line again under `budget` and `roles` at
    /// `at_ms`: the set door mints the current period first, from the line
    /// as it stood.
    fn set_again(&self, lane: EntityId, roles: &Roles, budget: BudgetPolicy, at_ms: u64) {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: format!("set-again-{at_ms}"),
                    project: lane,
                    policy: policy(roles, budget),
                },
                at_ms,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line again: {error:?}"));
    }

    /// A child project of `lane` the owner seats as a `track` family before
    /// period 0, so the first mint funds it.
    fn seat(&self, lane: EntityId, track: Track) -> EntityId {
        let family = self.project_under(lane, 0);
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .admit_gpu_line_family(
                Some(&self.owner_proof),
                &GpuLineFamilyAdmitRequest {
                    intent_key: format!("seat-{family:?}"),
                    project: lane,
                    family,
                    track,
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner seats a {track:?} family: {error:?}"));
        family
    }

    /// `lead` admits arm `title` on contract number `contract` into
    /// `family` of `lane`'s line.
    fn admit(
        &self,
        lead: EntityId,
        lane: EntityId,
        family: EntityId,
        contract: u8,
        title: &str,
    ) -> ExperimentArm {
        arm_admit_as(
            &self.vault.memory(lead, EdgeActorClass::Agent),
            None,
            &admission(lane, family, contract, title),
            NOW_MS,
        )
        .unwrap_or_else(|error| panic!("{title} is admitted: {error:?}"))
        .arm
    }

    /// Puts a work claim at rung 1 of `arm` in `state`, as row M2-C's reserve
    /// and settlement would leave it.
    fn put(&self, arm: &ExperimentArm, unit_key: &str, state: ClaimState) -> UnitClaim {
        let claim = claim(arm, unit_key, state);
        put_claim(&self.vault, &claim).expect("the test door puts the claim");
        claim
    }

    /// `lead`'s verdict of `decision` on rung 1 of `arm` at `at_ms`, resting
    /// on `units` and `result`.
    fn verdict(
        &self,
        lead: EntityId,
        arm: &ExperimentArm,
        decision: ArmDecision,
        units: &[EntityId],
        result: Option<&ArmEvidenceDigest>,
        at_ms: u64,
    ) -> ArmView {
        let text = match decision {
            ArmDecision::Invalid { .. } => "the harness could not measure the run".to_owned(),
            _ => String::new(),
        };
        let evidence = match decision {
            ArmDecision::Invalid { .. } => vec![digest("harness.log", 0x1f)],
            _ => Vec::new(),
        };
        let ask = ArmVerdictRequest {
            intent_key: format!("verdict-{:?}", arm.id),
            arm: arm.id,
            rung: 1,
            arm_revision: arm.revision,
            decision,
            units: units.to_vec(),
            result: result.cloned(),
            numbers: BTreeMap::from([("pass_rate".to_owned(), 0.5)]),
            text,
            evidence,
            ledger_row: None,
            contract_sha256: arm.contract.sha256.clone(),
        };
        arm_verdict_as(
            &self.vault.memory(lead, EdgeActorClass::Agent),
            None,
            &ask,
            at_ms,
        )
        .unwrap_or_else(|error| panic!("the lead's verdict on {}: {error:?}", arm.title))
    }

    /// The owner's own review of `verdict` on rung 1 of `arm` as read, at
    /// `REVIEW_MS`: independent of the lead who admitted and promoted it.
    fn review(&self, arm: &ExperimentArm, verdict: ArmReviewVerdict) -> ArmView {
        let result = arm.rungs[0]
            .verdict
            .as_ref()
            .and_then(|verdict| verdict.result.clone())
            .expect("a promote names its result");
        let ask = ArmReviewRequest {
            intent_key: format!("review-{:?}", arm.id),
            arm: arm.id,
            rung: 1,
            of_arm_revision: arm.revision,
            verdict,
            result,
            evidence: Vec::new(),
            review_ref: digest("REVIEW.md", 0xee),
            ledger_row: None,
            model: REVIEW_MODEL.to_owned(),
        };
        arm_review_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            &ask,
            REVIEW_MS,
        )
        .unwrap_or_else(|error| panic!("the owner reviews {}: {error:?}", arm.title))
    }

    /// One settled unit on `arm` with result `result`, the lead's promote,
    /// and the owner's confirm: a confirmed promote at rung 1.
    fn confirmed_promote(&self, lead: EntityId, arm: &ExperimentArm, result: u8) -> ArmView {
        let result = digest("result.json", result);
        let unit = self.put(arm, "work/0", settled(vec![result.clone()], SETTLED_MS));
        let promoted = self.verdict(
            lead,
            arm,
            ArmDecision::Promote,
            &[unit.id],
            Some(&result),
            VERDICT_MS,
        );
        self.review(&promoted.arm, ArmReviewVerdict::Confirmed)
    }

    /// `vault.gpu.lines.families.graduate` of `family` to `to` at `at_ms`,
    /// as the owner (`None`) or as `agent`, under `key`.
    fn graduate(
        &self,
        caller: Option<EntityId>,
        lane: EntityId,
        family: EntityId,
        to: Track,
        key: &str,
        at_ms: u64,
    ) -> MemoryResult<GpuLineView> {
        let ask = GpuLineFamilyGraduateRequest {
            intent_key: key.to_owned(),
            project: lane,
            family,
            to,
        };
        match caller {
            None => self
                .vault
                .memory(self.owner, EdgeActorClass::Human)
                .graduate_gpu_line_family(Some(&self.owner_proof), &ask, at_ms),
            Some(agent) => self
                .vault
                .memory(agent, EdgeActorClass::Agent)
                .graduate_gpu_line_family(None, &ask, at_ms),
        }
    }

    fn line(&self, lane: EntityId) -> GpuLine {
        self.vault.gpu_line(&lane).expect("read").expect("the line")
    }

    /// What the mint of period `index` of `lane`'s line reads, from the rows
    /// as they stand.
    fn tallies(&self, lane: EntityId, index: u32) -> BTreeMap<EntityId, SettledTally> {
        let line = self.line(lane);
        let txn = read_txn(&self.vault).expect("read snapshot");
        settled_tallies_in_txn(&self.vault, &txn, &line, index).expect("the input join")
    }
}

/// The line's policy under `budget`, with `roles`.
fn policy(roles: &Roles, budget: BudgetPolicy) -> GpuLinePolicy {
    GpuLinePolicy {
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: Vec::new(),
        machines: Vec::new(),
        leads: roles.leads.clone(),
        reviewers: Vec::new(),
        planners: roles.planners.clone(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget,
    }
}

/// Two demand floors of `floor_arms` first allowances each, no pinned share,
/// no seat reserve, no new-idea pool, a market smaller than one first
/// allowance, two rungs, and a window of one period.
fn demand_budget(floor_arms: u32) -> BudgetPolicy {
    BudgetPolicy {
        allowance_units: 2 * u64::from(floor_arms) * RUNG_SECS + MARKET_SECS,
        pinned_parts: (0, 3),
        floor_arms,
        rung_caps_secs: vec![RUNG_SECS; 2],
        seat_reserve_floors: 0,
        new_idea_slots_per_period: 0,
        window_periods: 1,
        ..BudgetPolicy::default()
    }
}

/// The open-models lane's preset (pass 34, 3.3; as `gpu_line_doors.rs`
/// sets it): a third pinned to the interest track, a demand seat reserve and
/// four new-idea slots, each funded for the default two periods.
fn new_idea_budget() -> BudgetPolicy {
    BudgetPolicy {
        allowance_units: 345_600,
        pinned_parts: (1, 3),
        floor_arms: 2,
        rung_caps_secs: vec![RUNG_SECS, 10_800, 172_800],
        seat_cap: 6,
        seat_reserve_floors: 1,
        new_idea_slots_per_period: 4,
        review_check_secs: 600,
        max_running_per_family: 1,
        forecast_required: true,
        window_periods: 3,
        ..BudgetPolicy::default()
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
        intent_key: format!("admit-{family:?}-{contract}"),
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

/// A work claim at rung 1 of `arm` in `state`.
fn claim(arm: &ExperimentArm, unit_key: &str, state: ClaimState) -> UnitClaim {
    UnitClaim {
        id: EntityId::now(),
        arm: arm.id,
        rung: 1,
        unit_key: unit_key.to_owned(),
        attempt: 1,
        line: arm.line,
        family: arm.family,
        period: 0,
        purpose: UnitPurpose::Work,
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

/// A terminal that ran and settled at `ended_at_ms`, charged `CHARGED_SECS`,
/// with `outputs`.
fn settled(outputs: Vec<ArmEvidenceDigest>, ended_at_ms: u64) -> ClaimState {
    ClaimState::Ended(UnitTerminal {
        end: UnitEnd::Settled,
        charged_secs: CHARGED_SECS,
        measured_secs: CHARGED_SECS,
        lost_secs: 0,
        machine: None,
        device_id: None,
        node_end: Some("exited(0)".to_owned()),
        outputs,
        ended_at_ms,
    })
}

/// A terminal of `end` that charged nothing, `lost_secs` for a box lost.
fn unsettled(end: UnitEnd, lost_secs: u64) -> ClaimState {
    ClaimState::Ended(UnitTerminal {
        end,
        charged_secs: 0,
        measured_secs: 0,
        lost_secs,
        machine: None,
        device_id: None,
        node_end: None,
        outputs: Vec::new(),
        ended_at_ms: SETTLED_MS,
    })
}

fn refused_as(error: &MemoryError, code: &str, mark: &str) {
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(mark), "{mark}: {error:?}");
}

/// T54.
#[test]
fn gpu_time_is_cost_when_it_is_spent() {
    let fixture = fixture();
    let agents = fixture.agents();
    let lead = agents.lead;
    let lane = fixture.lane(&agents.roles, demand_budget(8));
    let family = fixture.seat(lane, Track::Demand);
    let other = fixture.seat(lane, Track::Demand);

    // One settled unit on each arm; the rung's state differs.
    let arms: Vec<ExperimentArm> = ["open", "held", "awaiting", "killed", "invalid", "late"]
        .iter()
        .zip(1_u8..)
        .map(|(title, contract)| fixture.admit(lead, lane, family, contract, title))
        .collect();
    let units: Vec<(UnitClaim, ArmEvidenceDigest)> = arms
        .iter()
        .zip(0x40_u8..)
        .map(|(arm, byte)| {
            let result = digest("result.json", byte);
            let unit = fixture.put(arm, "work/0", settled(vec![result.clone()], SETTLED_MS));
            (unit, result)
        })
        .collect();
    let [open, held, awaiting, killed, invalid, late] = [0, 1, 2, 3, 4, 5].map(|i| &arms[i]);
    let unit = |i: usize| units[i].0.id;
    let result = |i: usize| &units[i].1;
    fixture.verdict(lead, held, ArmDecision::Hold, &[unit(1)], None, VERDICT_MS);
    fixture.verdict(
        lead,
        awaiting,
        ArmDecision::Promote,
        &[unit(2)],
        Some(result(2)),
        VERDICT_MS,
    );
    fixture.verdict(
        lead,
        killed,
        ArmDecision::Kill,
        &[unit(3)],
        Some(result(3)),
        VERDICT_MS,
    );
    let could_not_measure = ArmDecision::Invalid {
        reason: ArmInvalidReason::CouldNotMeasure,
    };
    fixture.verdict(
        lead,
        invalid,
        could_not_measure.clone(),
        &[unit(4)],
        None,
        VERDICT_MS,
    );

    // No input: a unit that settles after the cutoff, an open claim, a
    // released and a box-lost one.
    fixture.put(open, "work/late", settled(Vec::new(), in_period(1)));
    fixture.put(open, "work/open", ClaimState::Started);
    fixture.put(
        open,
        "work/released",
        unsettled(UnitEnd::Released("withdrawn".to_owned()), 0),
    );
    fixture.put(open, "work/lost", unsettled(UnitEnd::BoxLost, CHARGED_SECS));
    // The other family: a confirmed promote is its win.
    let winner = fixture.admit(lead, lane, other, 9, "winner");
    fixture.confirmed_promote(lead, &winner, 0x60);

    // The owner's edit in period 1 mints its record first, while the last
    // arm's rung is still open (a verdict mints nothing).
    fixture.set_again(lane, &agents.roles, demand_budget(8), in_period(1));
    // The last arm closes invalid after the cutoff: at the mint of period 1
    // its time was still cost.
    fixture.verdict(
        lead,
        late,
        could_not_measure,
        &[unit(5)],
        None,
        in_period(1),
    );

    let tallies = fixture.tallies(lane, 1);
    assert_eq!(
        tallies.get(&family).copied(),
        Some(SettledTally {
            wins: 0,
            losses: 1,
            // open, held, awaiting, killed and the late invalid one.
            cost_secs: 5 * CHARGED_SECS,
            // The rung closed invalid before the cutoff, alone: all that
            // `CountsNowhere` leaves out.
            invalid_secs: CHARGED_SECS,
        }),
        "{tallies:?}"
    );
    assert_eq!(
        tallies.get(&other).copied(),
        Some(SettledTally {
            wins: 1,
            losses: 0,
            cost_secs: CHARGED_SECS,
            invalid_secs: 0,
        })
    );
    assert_eq!(tallies.len(), 2, "no row of another family: {tallies:?}");

    // The mint of period 1 wrote what the join read when the owner's edit
    // minted it (the last rung was still open), and stays as written.
    let record = {
        let txn = read_txn(&fixture.vault).expect("read snapshot");
        oneiron::gpu_line::stored_period_in_txn(&fixture.vault, &txn, &lane, 1)
            .expect("read")
            .expect("the verdict in period 1 minted its record")
    };
    let input = record
        .inputs
        .iter()
        .find(|input| input.family == family)
        .expect("the family's input");
    assert_eq!(
        (
            input.wins,
            input.losses,
            input.cost_secs,
            input.invalid_secs
        ),
        (0, 1, 5 * CHARGED_SECS, CHARGED_SECS)
    );

    // The window of period 2 is period 1: the unit that settled there is
    // its only input, and period 0's results have aged out.
    let next = fixture.tallies(lane, 2);
    assert_eq!(
        next.get(&family).copied(),
        Some(SettledTally {
            cost_secs: CHARGED_SECS,
            ..SettledTally::default()
        }),
        "{next:?}"
    );
    assert_eq!(next.get(&other), None);
}

/// T63.
#[test]
fn a_new_idea_graduates_only_after_a_confirmed_promote() {
    let fixture = fixture();
    let agents = fixture.agents();
    let lead = agents.lead;
    let lane = fixture.lane(&agents.roles, new_idea_budget());
    let idea = fixture.seat(lane, Track::NewIdea);
    let second = fixture.seat(lane, Track::NewIdea);
    let demand = fixture.seat(lane, Track::Demand);
    let seat_before = fixture.line(lane).seat(&idea).expect("the seat").clone();
    // Every write of period 0 comes first: a write never reaches back into
    // a period before the newest one minted.
    let second_arm = fixture.admit(lead, lane, second, 3, "the second idea's arm");
    fixture.confirmed_promote(lead, &second_arm, 0x33);

    // No promote.
    let arm = fixture.admit(lead, lane, idea, 1, "the idea's arm");
    let refused = fixture
        .graduate(Some(lead), lane, idea, Track::Demand, "early", VERDICT_MS)
        .expect_err("no promote yet");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "no_confirmed_promote");

    // A kill on another arm of the seat.
    let killed = fixture.admit(lead, lane, idea, 2, "the killed arm");
    let kill_result = digest("result.json", 0x22);
    let kill_unit = fixture.put(
        &killed,
        "work/0",
        settled(vec![kill_result.clone()], SETTLED_MS),
    );
    fixture.verdict(
        lead,
        &killed,
        ArmDecision::Kill,
        &[kill_unit.id],
        Some(&kill_result),
        VERDICT_MS,
    );
    let refused = fixture
        .graduate(
            Some(lead),
            lane,
            idea,
            Track::Demand,
            "after-kill",
            VERDICT_MS,
        )
        .expect_err("a kill does not qualify");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "no_confirmed_promote");

    // An unreviewed promote.
    let result = digest("result.json", 0x11);
    let unit = fixture.put(&arm, "work/0", settled(vec![result.clone()], SETTLED_MS));
    let promoted = fixture.verdict(
        lead,
        &arm,
        ArmDecision::Promote,
        &[unit.id],
        Some(&result),
        VERDICT_MS,
    );
    assert_eq!(promoted.arm.rungs[0].state, RungState::AwaitingReview);
    let refused = fixture
        .graduate(
            Some(lead),
            lane,
            idea,
            Track::Demand,
            "unreviewed",
            VERDICT_MS,
        )
        .expect_err("an unreviewed promote does not qualify");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "no_confirmed_promote");

    // The confirm: the lead moves the family to demand, in place.
    let confirmed = fixture.review(&promoted.arm, ArmReviewVerdict::Confirmed);
    assert_eq!(
        confirmed.arm.rungs[0].state,
        RungState::Closed {
            end: RungEnd::Promoted
        }
    );
    let revision = fixture.line(lane).revision;
    let graduated = fixture
        .graduate(
            Some(lead),
            lane,
            idea,
            Track::Demand,
            "graduate",
            in_period(1),
        )
        .expect("the lead graduates the new idea to demand");
    assert!(!graduated.replayed);
    let seats: Vec<_> = graduated
        .line
        .families
        .iter()
        .filter(|seat| seat.project == idea)
        .collect();
    assert_eq!(seats.len(), 1, "one project, one seat: {seats:?}");
    let seat = seats[0];
    assert_eq!(seat.track, Track::Demand);
    assert_eq!(
        seat.graduated,
        Some(Graduation {
            from: Track::NewIdea,
            by: Some(lead),
            at_ms: in_period(1),
            arm: arm.id,
            rung: 1,
        })
    );
    assert_eq!(seat.seat, seat_before.seat, "the seat keeps its id");
    assert_eq!(seat.replaces, seat_before.replaces);
    assert_eq!(seat.late_floor, seat_before.late_floor);
    assert_eq!(
        seat.effective_from_period,
        seat_before.effective_from_period
    );
    assert_eq!(seat.asked_track(), Track::NewIdea);
    assert_eq!(graduated.line.revision, revision + 1);

    // The same ask again, under a new key, answers the seat; the line does
    // not move.
    let again = fixture
        .graduate(
            Some(lead),
            lane,
            idea,
            Track::Demand,
            "graduate-again",
            in_period(1),
        )
        .expect("the same graduation answers again");
    assert!(again.replayed);
    assert_eq!(again.line.revision, revision + 1);
    // One project never holds two kinds: it cannot be seated as a new idea
    // beside its demand seat.
    let seated = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .admit_gpu_line_family(
            Some(&fixture.owner_proof),
            &GpuLineFamilyAdmitRequest {
                intent_key: "reseat".to_owned(),
                project: lane,
                family: idea,
                track: Track::NewIdea,
            },
            in_period(1),
        )
        .expect_err("the project holds its demand seat");
    assert_eq!(MemoryError::from(seated).code, MEMORY_CODE_INVALID_STATE);
    // Demand does not graduate again, and no seat graduates to a new idea.
    let refused = fixture
        .graduate(
            None,
            lane,
            idea,
            Track::Interest,
            "demand-to-interest",
            in_period(1),
        )
        .expect_err("a demand seat is not a new idea");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "not_new_idea");
    let refused = fixture
        .graduate(None, lane, demand, Track::Demand, "never-new", in_period(1))
        .expect_err("a demand seat does not graduate");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "not_new_idea");
    let refused = fixture
        .graduate(
            None,
            lane,
            idea,
            Track::NewIdea,
            "to-new-idea",
            in_period(1),
        )
        .expect_err("graduation names demand or interest");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");

    // The owner moves the second new idea to interest.
    let interest = fixture
        .graduate(
            None,
            lane,
            second,
            Track::Interest,
            "to-interest",
            in_period(1),
        )
        .expect("the owner graduates the new idea to interest");
    let seat = interest.line.seat(&second).expect("the seat");
    assert_eq!(seat.track, Track::Interest);
    assert_eq!(
        seat.graduated.as_ref().map(|graduation| graduation.by),
        Some(Some(fixture.owner))
    );
}

/// T5b, the graduation half.
#[test]
fn a_lead_and_a_planner_are_refused_a_graduation_to_interest() {
    let fixture = fixture();
    let agents = fixture.agents();
    let lead = agents.lead;
    let lane = fixture.lane(&agents.roles, new_idea_budget());
    let idea = fixture.seat(lane, Track::NewIdea);
    let arm = fixture.admit(lead, lane, idea, 1, "the idea's arm");
    fixture.confirmed_promote(lead, &arm, 0x44);

    for (agent, key) in [(lead, "lead"), (agents.planner, "planner")] {
        let refused = fixture
            .graduate(Some(agent), lane, idea, Track::Interest, key, in_period(1))
            .expect_err("interest is the owner's");
        refused_as(&refused, MEMORY_CODE_FORBIDDEN, "owner's own act");
    }
    // A planner holds no lead role: demand is refused too.
    let refused = fixture
        .graduate(
            Some(agents.planner),
            lane,
            idea,
            Track::Demand,
            "planner-demand",
            in_period(1),
        )
        .expect_err("only a lead graduates to demand");
    refused_as(&refused, MEMORY_CODE_FORBIDDEN, "not_this_line");
    let seat = fixture.line(lane).seat(&idea).expect("the seat").clone();
    assert_eq!(seat.track, Track::NewIdea, "nothing moved");
    assert_eq!(seat.graduated, None);
}

/// The lapse (4.1): at the mint after its funded periods, a new idea with a
/// confirmed promote stays seated and can still graduate; one without lapses.
#[test]
fn a_new_idea_with_a_confirmed_promote_does_not_lapse() {
    let fixture = fixture();
    let agents = fixture.agents();
    let lead = agents.lead;
    let lane = fixture.lane(&agents.roles, new_idea_budget());
    let promoted = fixture.seat(lane, Track::NewIdea);
    let idle = fixture.seat(lane, Track::NewIdea);
    let arm = fixture.admit(lead, lane, promoted, 1, "the promoted idea's arm");
    fixture.admit(lead, lane, idle, 2, "the idle idea's arm");
    fixture.confirmed_promote(lead, &arm, 0x55);

    // Seated before period 0, both are funded in periods 0 and 1. The first
    // write of period 2 mints it: the graduation itself.
    let graduated = fixture
        .graduate(
            Some(lead),
            lane,
            promoted,
            Track::Demand,
            "late",
            in_period(2),
        )
        .expect("a promoted new idea did not lapse");
    let seat = graduated.line.seat(&promoted).expect("its seat in force");
    assert_eq!(seat.track, Track::Demand);
    assert_eq!(seat.lapsed_from_period, None);
    let lapsed: Vec<_> = graduated
        .line
        .families
        .iter()
        .filter(|seat| seat.project == idle)
        .collect();
    assert_eq!(lapsed.len(), 1);
    assert_eq!(
        lapsed[0].lapsed_from_period,
        Some(2),
        "the idle idea lapsed"
    );
    let refused = fixture
        .graduate(None, lane, idle, Track::Demand, "idle", in_period(2))
        .expect_err("a lapsed seat does not graduate");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "seat_lapsed");
}
