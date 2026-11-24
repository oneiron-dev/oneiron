//! `vault.arms.admit` (design pass 32, sections 3.3, 4.2 and 5 row 4; tests
//! T6 to T8) through the engine act the host door calls.
//!
//! - T6: an admitted arm holds its first allowance (one rung-1 cap) on its
//!   family's floor, so another arm of that family cannot take the room,
//!   while an arm of another family still fits.
//! - T7: an arm is not admitted when no first allowance fits: the refusal is
//!   `budget_denied`, and the write is discarded whole (no arm, no intent).
//! - T8: the intent key replays its answer and refuses a changed ask.
//! - The line cover: an agent admits only into a line its Grant reaches (the
//!   audience axis holds every project, the lane, or an ancestor of the
//!   lane), and only when the Grant lists the verb.
//!
//! A demand family seated inside a period has its floor that period and no
//! market ceiling (the mint divided the market before it was seated), so its
//! room is exactly `floor_arms` first allowances.
//!
//! On the base the module does not exist, so every test fails there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test experiment_arm_admit`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ArmAdmitRequest, ArmContractAsk, ArmListRequest, ArmView, RunnerRef,
    arm_admit_as, arm_list_as,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_line::{
    AllowanceHold, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineSetRequest,
    InvalidCost, PinnedMode, RuleRef, Track,
};
use oneiron::memory::{
    MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryResult,
};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::store_writes::last_committed_write;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// The rung-1 cap: one first allowance.
const RUNG_1_SECS: u64 = 1_800;

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, and this install's live machine profile
/// (the owner's agent Grant act needs it). As `gpu_line_doors.rs` builds it.
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

    /// A lane under the root with its line set by the owner at `NOW_MS`
    /// (which mints period 0), and `families` demand families seated in it.
    fn lane_with_families(&self, floor_arms: u32, families: usize) -> (EntityId, Vec<EntityId>) {
        let lane = self.project_under(self.root(), 2);
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: "set".to_owned(),
                    project: lane,
                    policy: policy(floor_arms),
                },
                NOW_MS,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
        let seated = (0..families)
            .map(|index| {
                let family = self.project_under(lane, 0);
                self.vault
                    .memory(self.owner, EdgeActorClass::Human)
                    .admit_gpu_line_family(
                        Some(&self.owner_proof),
                        &GpuLineFamilyAdmitRequest {
                            intent_key: format!("seat-{index}"),
                            project: lane,
                            family,
                            track: Track::Demand,
                            seed: None,
                        },
                        NOW_MS,
                    )
                    .unwrap_or_else(|error| panic!("the owner seats family {index}: {error:?}"));
                family
            })
            .collect();
        (lane, seated)
    }

    /// The owner's Grant naming `agent`, listing `verbs` (with `read`, which a
    /// Grant needs to confer) over the projects `audience` holds.
    fn grant_over(&self, agent: EntityId, verbs: &[&str], audience: ScopeAxis<ScopeId>) {
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        authority_scope.audience = audience;
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
        assert!(
            minted.grant.confers,
            "agent={agent:?} verbs={verbs:?}: the Grant confers"
        );
    }

    /// `vault.arms.admit` as the owner (`None`) or as `agent`.
    fn admit(&self, caller: Option<EntityId>, request: &ArmAdmitRequest) -> MemoryResult<ArmView> {
        match caller {
            None => arm_admit_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                request,
                NOW_MS,
            ),
            Some(agent) => arm_admit_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                request,
                NOW_MS,
            ),
        }
    }

    /// Every arm of `lane`, as the owner lists them.
    fn arms_of(&self, lane: EntityId) -> Vec<ArmView> {
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
        .arms
    }
}

/// The open-models lane's policy with `floor_arms` floor arms: 96 GPU-hours
/// a fortnight, a third pinned to the interest track, `payoff_share@1`.
fn policy(floor_arms: u32) -> GpuLinePolicy {
    GpuLinePolicy {
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        fleet_who: "open-models".to_owned(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        allowance_units: 345_600,
        pinned_track: Track::Interest,
        pinned_parts: [1, 3],
        pinned_mode: PinnedMode::FloorPlusMarket,
        floor_arms,
        rung_caps_secs: vec![RUNG_1_SECS, 10_800, 172_800],
        forecast_required: true,
        rules: vec![RuleRef::PAYOFF_SHARE_1],
        invalid_cost: InvalidCost::CountsAsCost,
        window_periods: 3,
        hosts: vec!["mel".to_owned()],
    }
}

/// An admission of one arm titled `title` into `family` of `lane`'s line.
fn ask(key: &str, lane: EntityId, family: EntityId, title: &str) -> ArmAdmitRequest {
    ArmAdmitRequest {
        intent_key: key.to_owned(),
        line: lane,
        family,
        type_ref: TypeRef::root(1),
        title: title.to_owned(),
        contract: ArmContractAsk {
            path: "contracts/arm.md".to_owned(),
            sha256: "ab".repeat(32),
            note: None,
        },
        runner: RunnerRef {
            model: "open-model-runner".to_owned(),
            actor: None,
        },
        supersedes: None,
        ledger_rows: Vec::new(),
    }
}

/// The hold an arm admitted in period 0 makes on its family's floor.
fn floor_hold() -> AllowanceHold {
    AllowanceHold {
        period: 0,
        units: RUNG_1_SECS,
        draws: vec![Draw {
            source: DrawSource::Floor,
            units: RUNG_1_SECS,
        }],
    }
}

/// T6.
#[test]
fn an_admitted_arm_holds_its_first_allowance() {
    let fixture = fixture();
    let (lane, families) = fixture.lane_with_families(1, 2);

    let first = fixture
        .admit(None, &ask("a", lane, families[0], "first arm"))
        .expect("the first arm's allowance fits the family's floor");
    assert_eq!(first.arm.first_allowance, Some(floor_hold()));
    assert!(first.open && !first.replayed, "seen {first:?}");
    assert_eq!(first.rung, 1);

    let taken = fixture
        .admit(None, &ask("b", lane, families[0], "second arm"))
        .expect_err("the first arm holds the family's only first allowance");
    assert_eq!(taken.code, MEMORY_CODE_BUDGET_SPENT, "seen {taken:?}");

    let other = fixture
        .admit(None, &ask("c", lane, families[1], "other family"))
        .expect("another family's floor is its own");
    assert_eq!(other.arm.first_allowance, Some(floor_hold()));

    let arms = fixture.arms_of(lane);
    assert_eq!(arms.len(), 2, "seen {arms:?}");
    let held = arms
        .iter()
        .find(|view| view.arm.id == first.arm.id)
        .expect("the first arm");
    assert_eq!(
        held.arm.first_allowance,
        Some(floor_hold()),
        "the first arm still holds its whole allowance"
    );
}

/// T7.
#[test]
fn an_arm_is_not_admitted_when_no_first_allowance_fits() {
    let fixture = fixture();
    let (lane, families) = fixture.lane_with_families(2, 1);
    let family = families[0];
    for key in ["a", "b"] {
        fixture
            .admit(None, &ask(key, lane, family, key))
            .unwrap_or_else(|error| panic!("arm {key} fits the floor: {error:?}"));
    }

    let before = last_committed_write(&fixture.vault);
    let refused = fixture
        .admit(None, &ask("c", lane, family, "third arm"))
        .expect_err("the floor holds two first allowances");
    assert_eq!(refused.code, MEMORY_CODE_BUDGET_SPENT, "seen {refused:?}");
    assert!(
        refused.message.starts_with("budget_denied:") && refused.message.contains("0 s fit now"),
        "seen {}",
        refused.message
    );
    assert_eq!(
        last_committed_write(&fixture.vault),
        before,
        "a refused admission commits no write"
    );
    assert_eq!(fixture.arms_of(lane).len(), 2, "no third arm was written");

    // The refusal kept no intent: the same key with another ask is judged
    // as a new ask, not refused as a changed one.
    let again = fixture
        .admit(None, &ask("c", lane, family, "another third arm"))
        .expect_err("the floor is still spent");
    assert_eq!(again.code, MEMORY_CODE_BUDGET_SPENT, "seen {again:?}");
}

/// T8.
#[test]
fn an_intent_key_replays_its_answer_and_refuses_a_changed_ask() {
    let fixture = fixture();
    let (lane, families) = fixture.lane_with_families(2, 1);
    let family = families[0];

    let admitted = fixture
        .admit(None, &ask("arm-1", lane, family, "first arm"))
        .expect("the first ask admits");
    assert!(!admitted.replayed);
    let replayed = fixture
        .admit(None, &ask("arm-1", lane, family, "first arm"))
        .expect("the same ask under the same key answers again");
    assert!(replayed.replayed, "seen {replayed:?}");
    assert_eq!(replayed.arm, admitted.arm, "nothing new was written");
    assert_eq!(
        fixture.arms_of(lane).len(),
        1,
        "a replay holds no second allowance"
    );

    let changed = fixture
        .admit(None, &ask("arm-1", lane, family, "a changed arm"))
        .expect_err("the key already names another ask");
    assert_eq!(changed.code, MEMORY_CODE_INVALID_STATE, "seen {changed:?}");
    assert_eq!(
        fixture.arms_of(lane).len(),
        1,
        "the changed ask wrote nothing"
    );

    // The room the refused ask would have taken is still there.
    fixture
        .admit(None, &ask("arm-2", lane, family, "second arm"))
        .expect("the second first allowance still fits");
}

/// The line cover on `vault.arms.admit`.
#[test]
fn an_agent_admits_only_into_a_line_its_grant_reaches() {
    let fixture = fixture();
    let (lane, families) = fixture.lane_with_families(4, 1);
    let family = families[0];
    let elsewhere = fixture.project_under(fixture.root(), 0);
    let agent = |name: &str| {
        fixture
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal")
    };
    let named = |project: EntityId| ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));

    let every = agent("arm-lead-every-project");
    fixture.grant_over(every, &[ARMS_ADMIT_VERB], ScopeAxis::All);
    let on_lane = agent("arm-lead-on-lane");
    fixture.grant_over(on_lane, &[ARMS_ADMIT_VERB], named(lane));
    let on_root = agent("arm-lead-on-root");
    fixture.grant_over(on_root, &[ARMS_ADMIT_VERB], named(fixture.root()));
    let off_line = agent("arm-lead-elsewhere");
    fixture.grant_over(off_line, &[ARMS_ADMIT_VERB], named(elsewhere));
    let no_verb = agent("arm-lead-no-verb");
    fixture.grant_over(no_verb, &[], ScopeAxis::All);

    for (lead, key) in [(every, "every"), (on_lane, "lane"), (on_root, "root")] {
        let view = fixture
            .admit(Some(lead), &ask(key, lane, family, key))
            .unwrap_or_else(|error| panic!("the {key} Grant reaches the line: {error:?}"));
        assert_eq!(view.arm.admitted_by, Some(lead));
    }

    let before = last_committed_write(&fixture.vault);
    for (lead, key) in [(off_line, "elsewhere"), (no_verb, "no-verb")] {
        let refused = fixture
            .admit(Some(lead), &ask(key, lane, family, key))
            .expect_err("the Grant does not admit this caller to this line");
        assert_eq!(
            refused.code, MEMORY_CODE_FORBIDDEN,
            "{key}: seen {refused:?}"
        );
    }
    assert_eq!(
        last_committed_write(&fixture.vault),
        before,
        "a refused caller commits no write"
    );
    assert_eq!(
        fixture.arms_of(lane).len(),
        3,
        "seen {:?}",
        fixture.arms_of(lane)
    );
}
