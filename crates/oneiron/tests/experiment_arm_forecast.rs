//! `vault.arms.forecast` and the forecast score view (design pass 32 r2,
//! sections 3.3 and 4.7; row M2-D) through the engine acts the host doors
//! call.
//!
//! - T16: a forecast after the rung's first claim is refused
//!   (`forecast_late`), also after that claim was released.
//! - T17: an invalid rung leaves its forecast unresolved: the score view
//!   counts it and never scores it. The score waits for the line's
//!   `forecast_score_after` resolved forecasts (pass 34: read from the line).
//! - T55: the required forecast is the arm's own runner's: the engine copies
//!   the runner from the arm, and an ask that names an author is refused.
//! - The rung holds one forecast: the same one answers again under any
//!   intent key; another value is `forecast_set`.
//! - Only a lead of the arm's line writes it; a reviewer is refused.
//!
//! The rig is `experiment_arm_admit.rs`'s, cut to what these tests use. A
//! claim (row M2-C's reserve) and a closed rung (row M2-E's verdict) are
//! stood by the test door `experiment_arm_rows`.
//!
//! On the base (#10400's head) `vault.arms.forecast` and the score view do
//! not exist, so this file does not compile there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test experiment_arm_forecast`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::learning_evidence::Anchor;
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_FORECAST_VERB, ARMS_LIST_VERB, ArmAdmitRequest, ArmContractAsk, ArmForecastRequest,
    ArmInvalidReason, ArmListRequest, ArmOutcome, ArmState, ArmView, CALIBRATION_BINS,
    ExperimentArm, ForecastScoreRow, RungEnd, RungState, RunnerRef, arm_admit_as, arm_forecast_as,
    arm_list_as,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_line::{
    BudgetPolicy, ClaimState, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePolicy,
    GpuLineSetRequest, Track, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal, gpu_seconds,
};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryError,
    MemoryResult,
};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::experiment_arm_rows::{put_arm, put_claim};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::store_writes::last_committed_write;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// The rung-1 cap of the rig's policy: one first allowance.
const RUNG_1_SECS: u64 = 1_800;
/// The market left beside the floor: less than one first allowance.
const MARKET_SECS: u64 = 300;
/// The engine's default `forecast_score_after` (M2-A, pass 34).
const DEFAULT_SCORE_AFTER: u32 = 20;
/// The runner model every rig arm declares.
const RUNNER_MODEL: &str = "open-model-runner";

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

    /// The owner sets `lane`'s line at `now_ms` with `roles`, one demand
    /// family of `floor_arms` floor arms, and `score_after` (the engine's
    /// default when `None`).
    fn set_line(
        &self,
        key: &str,
        lane: EntityId,
        roles: &Roles,
        floor_arms: u32,
        score_after: Option<u32>,
        now_ms: u64,
    ) {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: key.to_owned(),
                    project: lane,
                    policy: policy(roles, floor_arms, score_after),
                },
                now_ms,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
    }

    /// A lane under the root, its line set before period 0 with `roles` and
    /// one demand family of `floor_arms` floor arms seated then, so the
    /// first mint funds it. Returns the lane and the family.
    fn lane(&self, roles: &Roles, floor_arms: u32) -> (EntityId, EntityId) {
        let lane = self.project_under(self.root(), 2);
        self.set_line("set", lane, roles, floor_arms, None, BEFORE_MS);
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

    /// The owner admits arm `title` on contract number `contract` into
    /// `family` of `lane`'s line.
    fn admit(&self, lane: EntityId, family: EntityId, contract: u8, title: &str) -> ExperimentArm {
        arm_admit_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            &admission(lane, family, contract, title),
            NOW_MS,
        )
        .unwrap_or_else(|error| panic!("the owner admits {title}: {error:?}"))
        .arm
    }

    /// `vault.arms.forecast` at `NOW_MS` as the owner (`None`) or as `agent`.
    fn forecast(
        &self,
        caller: Option<EntityId>,
        request: &ArmForecastRequest,
    ) -> MemoryResult<ArmView> {
        match caller {
            None => arm_forecast_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                request,
                NOW_MS,
            ),
            Some(agent) => arm_forecast_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                request,
                NOW_MS,
            ),
        }
    }

    /// The forecast score rows of `lane`, as the owner lists them.
    fn scores_of(&self, lane: EntityId) -> Vec<ForecastScoreRow> {
        arm_list_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            &ArmListRequest {
                line: Some(lane.to_hex()),
                family: None,
                open_only: false,
            },
        )
        .expect("the owner lists the lane's arms")
        .forecast_scores
    }

    /// The stored arm `id`.
    fn arm(&self, id: EntityId) -> ExperimentArm {
        self.vault
            .experiment_arm(&id)
            .expect("read")
            .expect("the arm")
    }

    /// Stands arm `id` where row M2-E's verdict leaves it: rung 1 closed
    /// `end` with `outcome`, and the arm `state`.
    fn close(&self, id: EntityId, state: ArmState, end: RungEnd, outcome: Option<bool>) {
        let mut arm = self.arm(id);
        arm.rungs[0].state = RungState::Closed { end };
        arm.rungs[0].outcome = outcome.map(|success| ArmOutcome {
            success,
            anchor: Anchor::HeldOut,
            at_ms: NOW_MS,
        });
        arm.state = state;
        arm.revision += 1;
        put_arm(&self.vault, &arm).expect("the test door puts the arm");
    }
}

/// The line's policy: one demand floor of `floor_arms` first allowances, no
/// pinned share, no seat reserve, no new-idea pool, a market smaller than
/// one first allowance, one rung, and `score_after` resolved forecasts
/// before a score (the engine's default when `None`).
fn policy(roles: &Roles, floor_arms: u32, score_after: Option<u32>) -> GpuLinePolicy {
    let defaults = BudgetPolicy::default();
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
            allowance_units: u64::from(floor_arms) * RUNG_1_SECS + MARKET_SECS,
            pinned_parts: (0, 3),
            floor_arms,
            rung_caps_secs: vec![RUNG_1_SECS],
            seat_reserve_floors: 0,
            new_idea_slots_per_period: 0,
            forecast_score_after: score_after.unwrap_or(defaults.forecast_score_after),
            ..defaults
        },
    }
}

/// The contract sha256 numbered `contract`.
fn contract_sha(contract: u8) -> String {
    format!("{contract:02x}").repeat(32)
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

/// A forecast of `pass_per_mille` for rung 1 of `arm`, under `key`.
fn forecast_ask(key: &str, arm: &ExperimentArm, pass_per_mille: u16) -> ArmForecastRequest {
    ArmForecastRequest {
        intent_key: key.to_owned(),
        arm: arm.id,
        rung: 1,
        pass_per_mille,
        contract_sha256: arm.contract.sha256.clone(),
    }
}

/// A unit claim at rung 1 of `arm` in `state`, as row M2-C's reserve would
/// write it.
fn claim_on(arm: &ExperimentArm, state: ClaimState) -> UnitClaim {
    UnitClaim {
        id: EntityId::now(),
        arm: arm.id,
        rung: 1,
        unit_key: "check/shard-0".to_owned(),
        attempt: 1,
        line: arm.line,
        family: arm.family,
        period: 0,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: arm.contract.sha256.clone(),
        result: None,
        reserved_secs: RUNG_1_SECS,
        draws: vec![Draw {
            source: DrawSource::FirstAllowance,
            units: RUNG_1_SECS,
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

fn refused_as(error: &MemoryError, code: &str, mark: &str) {
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(mark), "{mark}: {error:?}");
}

/// T16.
#[test]
fn a_forecast_after_the_first_claim_is_refused() {
    let fixture = fixture();
    let (lane, family) = fixture.lane(&Roles::default(), 2);
    let claimed = fixture.admit(lane, family, 1, "claimed first");
    let unclaimed = fixture.admit(lane, family, 2, "forecast first");

    let claim = claim_on(&claimed, ClaimState::Claimed);
    put_claim(&fixture.vault, &claim).expect("the test door puts the claim");
    let before = last_committed_write(&fixture.vault);
    let late = fixture
        .forecast(None, &forecast_ask("late", &claimed, 700))
        .expect_err("a claim was made at the rung");
    refused_as(&late, MEMORY_CODE_INVALID_STATE, "forecast_late");
    assert_eq!(
        last_committed_write(&fixture.vault),
        before,
        "a refused forecast commits no write"
    );

    // The claim was released: it never ran, and the attempt is used. A
    // claim was still made, so the rung takes no forecast.
    let released = UnitClaim {
        state: ClaimState::Ended(UnitTerminal {
            end: UnitEnd::Released("launch refused".to_owned()),
            charged_secs: 0,
            measured_secs: 0,
            lost_secs: 0,
            machine: None,
            device_id: None,
            node_end: None,
            outputs: Vec::new(),
            ended_at_ms: NOW_MS,
        }),
        revision: 2,
        ..claim
    };
    put_claim(&fixture.vault, &released).expect("the test door ends the claim");
    let still_late = fixture
        .forecast(None, &forecast_ask("late-again", &claimed, 700))
        .expect_err("a released claim was still made");
    refused_as(&still_late, MEMORY_CODE_INVALID_STATE, "forecast_late");
    assert!(fixture.arm(claimed.id).rungs[0].forecast.is_none());

    // The other arm's rung had no claim: its forecast is written.
    let written = fixture
        .forecast(None, &forecast_ask("early", &unclaimed, 700))
        .expect("a forecast before the first claim");
    assert!(!written.replayed);
    let forecast = written.arm.rungs[0]
        .forecast
        .clone()
        .expect("the rung holds the forecast");
    assert_eq!(forecast.pass_per_mille, 700);
    assert_eq!(forecast.written_at_ms, NOW_MS);
    assert_eq!(written.arm.revision, unclaimed.revision + 1);

    // Its first claim after the forecast changes nothing on it.
    put_claim(&fixture.vault, &claim_on(&written.arm, ClaimState::Claimed))
        .expect("the test door puts the claim");
    assert_eq!(fixture.arm(unclaimed.id).rungs[0].forecast, Some(forecast));
}

/// T17, with the score's threshold read from the line (pass 34).
#[test]
fn an_invalid_rung_leaves_its_forecast_unresolved() {
    let fixture = fixture();
    let roles = Roles::default();
    let (lane, family) = fixture.lane(&roles, 4);
    let killed = fixture.admit(lane, family, 1, "killed");
    let invalid = fixture.admit(lane, family, 2, "invalid");
    let open = fixture.admit(lane, family, 3, "open");
    let promoted = fixture.admit(lane, family, 4, "promoted");
    for (arm, pass_per_mille) in [
        (&killed, 300),
        (&invalid, 900),
        (&open, 500),
        (&promoted, 800),
    ] {
        // An intent key names one ask of its caller, so each arm's forecast
        // takes its own key.
        let key = format!("forecast-{}", arm.title);
        fixture
            .forecast(None, &forecast_ask(&key, arm, pass_per_mille))
            .unwrap_or_else(|error| panic!("{}: {error:?}", arm.title));
    }
    fixture.close(killed.id, ArmState::Killed, RungEnd::Killed, Some(false));
    fixture.close(
        invalid.id,
        ArmState::Invalid,
        RungEnd::Invalid {
            reason: ArmInvalidReason::CouldNotMeasure,
        },
        None,
    );
    fixture.close(
        promoted.id,
        ArmState::Succeeded,
        RungEnd::Promoted,
        Some(true),
    );

    let rows = fixture.scores_of(lane);
    assert_eq!(rows.len(), 1, "one declared runner model: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.line, lane);
    assert_eq!(row.model, RUNNER_MODEL);
    assert_eq!(
        (row.resolved, row.pending, row.invalid),
        (2, 1, 1),
        "the kill and the promote resolve, the open rung is pending, the invalid one never resolves"
    );
    assert_eq!(
        row.needed, DEFAULT_SCORE_AFTER,
        "the line's own setting, at the engine's default"
    );
    assert_eq!(row.score, None, "unknown (2 of 20)");

    // The owner lowers the line's threshold: the two resolved forecasts are
    // scored; the invalid rung's forecast still is not.
    fixture.set_line("score-after", lane, &roles, 4, Some(2), NOW_MS);
    let rows = fixture.scores_of(lane);
    let row = &rows[0];
    assert_eq!(row.needed, 2);
    assert_eq!((row.resolved, row.pending, row.invalid), (2, 1, 1));
    let score = row.score.as_ref().expect("2 of 2 resolved: scored");
    // (0.3 - 0)^2 = 0.09 and (0.8 - 1)^2 = 0.04: the mean is 0.065.
    assert_eq!(score.brier_per_million, 65_000);
    assert_eq!(score.bins.len(), CALIBRATION_BINS);
    let filled: Vec<(u16, u32, u32)> = score
        .bins
        .iter()
        .filter(|bin| bin.forecasts > 0)
        .map(|bin| (bin.from_per_mille, bin.forecasts, bin.passed))
        .collect();
    assert_eq!(
        filled,
        vec![(300, 1, 0), (800, 1, 1)],
        "the invalid rung's 900 is in no bin"
    );
}

/// T55.
#[test]
fn the_required_forecast_is_the_arms_own_runner() {
    let fixture = fixture();
    let verbs = [ARMS_FORECAST_VERB, ARMS_LIST_VERB];
    let (lead, lead_grant) = fixture.agent("arm-lead", &verbs);
    let (runner, _) = fixture.agent("arm-runner", &verbs);
    let roles = Roles {
        leads: vec![lead_grant],
        reviewers: Vec::new(),
    };
    let (lane, family) = fixture.lane(&roles, 1);
    let mut ask = admission(lane, family, 1, "run by the runner");
    ask.runner.actor = Some(runner);
    let arm = arm_admit_as(
        &fixture.vault.memory(fixture.owner, EdgeActorClass::Human),
        Some(&fixture.owner_proof),
        &ask,
        NOW_MS,
    )
    .expect("the owner admits")
    .arm;

    let written = fixture
        .forecast(Some(lead), &forecast_ask("lead", &arm, 650))
        .expect("the lead writes the runner's forecast");
    let forecast = written.arm.rungs[0]
        .forecast
        .clone()
        .expect("the rung holds the forecast");
    assert_eq!(
        forecast.runner, arm.runner,
        "the author is the arm's runner"
    );
    assert_eq!(forecast.runner.actor, Some(runner));
    assert_eq!(forecast.written_by, Some(lead), "the lead wrote it down");
    assert_eq!(forecast.contract_sha256, arm.contract.sha256);

    // The ask has no field that names an author.
    let mut named = serde_json::to_value(forecast_ask("named", &arm, 650)).expect("json");
    named["runner"] = serde_json::json!({ "model": "another-model", "actor": null });
    assert!(
        serde_json::from_value::<ArmForecastRequest>(named).is_err(),
        "an ask that names a runner does not decode"
    );
    let mut authored = serde_json::to_value(forecast_ask("authored", &arm, 650)).expect("json");
    authored["written_by"] = serde_json::json!(lead.to_hex());
    assert!(
        serde_json::from_value::<ArmForecastRequest>(authored).is_err(),
        "an ask that names its writer does not decode"
    );
}

/// The logical key (arm, rung) holds one forecast.
#[test]
fn a_rung_holds_one_forecast() {
    let fixture = fixture();
    // Two floor arms: the second funds the arm the contract and range checks
    // below are asked on.
    let (lane, family) = fixture.lane(&Roles::default(), 2);
    let arm = fixture.admit(lane, family, 1, "one forecast");

    let first = fixture
        .forecast(None, &forecast_ask("first", &arm, 400))
        .expect("the first forecast");
    let again = fixture
        .forecast(None, &forecast_ask("first", &arm, 400))
        .expect("the same ask under the same key");
    assert!(again.replayed);
    assert_eq!(again.arm, first.arm, "a replay writes nothing");
    let fresh_key = fixture
        .forecast(None, &forecast_ask("second", &arm, 400))
        .expect("the same forecast under a new key");
    assert!(fresh_key.replayed);
    assert_eq!(fresh_key.arm.revision, first.arm.revision);

    let changed_key = fixture
        .forecast(None, &forecast_ask("first", &arm, 600))
        .expect_err("the key names another ask");
    assert_eq!(
        changed_key.code, MEMORY_CODE_INVALID_STATE,
        "{changed_key:?}"
    );
    let changed = fixture
        .forecast(None, &forecast_ask("third", &arm, 600))
        .expect_err("a second, different forecast");
    refused_as(&changed, MEMORY_CODE_INVALID_STATE, "forecast_set");

    // The same forecast still answers after a claim, which a lost reply
    // followed by a retry can meet.
    put_claim(&fixture.vault, &claim_on(&arm, ClaimState::Claimed))
        .expect("the test door puts the claim");
    let after_claim = fixture
        .forecast(None, &forecast_ask("fourth", &arm, 400))
        .expect("the stored forecast answers its retry");
    assert!(after_claim.replayed);

    let other = fixture.admit(lane, family, 2, "other contract");
    let mut stale = forecast_ask("stale", &other, 400);
    stale.contract_sha256 = contract_sha(9);
    let refused = fixture
        .forecast(None, &stale)
        .expect_err("not the arm's pin");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "contract_changed");
    let mut above = forecast_ask("above", &other, 1_001);
    above.contract_sha256 = other.contract.sha256.clone();
    let refused = fixture.forecast(None, &above).expect_err("above certain");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    let mut unopened = forecast_ask("rung-2", &other, 400);
    unopened.rung = 2;
    assert!(
        fixture.forecast(None, &unopened).is_err(),
        "rung 2 is not open"
    );
}

/// Section 5.1: the lead of the arm's line writes the forecast; a reviewer
/// of the line, and a Grant the line does not list, are refused.
#[test]
fn only_a_lead_of_the_arms_line_writes_its_forecast() {
    let fixture = fixture();
    let verbs = [ARMS_FORECAST_VERB];
    let (lead, lead_grant) = fixture.agent("arm-lead", &verbs);
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &verbs);
    let (other, _) = fixture.agent("other-line-lead", &verbs);
    let (unnamed, unnamed_grant) = fixture.agent("no-forecast-verb", &[ARMS_LIST_VERB]);
    let roles = Roles {
        leads: vec![lead_grant, unnamed_grant],
        reviewers: vec![reviewer_grant],
    };
    let (lane, family) = fixture.lane(&roles, 1);
    let arm = fixture.admit(lane, family, 1, "the lead's arm");

    let before = last_committed_write(&fixture.vault);
    for (caller, name) in [(reviewer, "reviewer"), (other, "other")] {
        let refused = fixture
            .forecast(Some(caller), &forecast_ask(name, &arm, 500))
            .expect_err("only a lead writes the forecast");
        refused_as(&refused, MEMORY_CODE_FORBIDDEN, "not_this_line");
    }
    let refused = fixture
        .forecast(Some(unnamed), &forecast_ask("unnamed", &arm, 500))
        .expect_err("the Grant does not name the verb");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        last_committed_write(&fixture.vault),
        before,
        "a refused caller commits no write"
    );
    fixture
        .forecast(Some(lead), &forecast_ask("lead", &arm, 500))
        .expect("the lead writes it");
}
