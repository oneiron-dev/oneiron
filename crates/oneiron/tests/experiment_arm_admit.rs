//! `vault.arms.admit` and the arm reads (design pass 32 r2, sections 3.3,
//! 4.2, 5.1, 5.2 and 5.5) through the engine acts the host doors call.
//!
//! - T6: an admitted arm holds its first allowance (one rung-1 cap) on its
//!   family's floor, so another arm of that family cannot take the room,
//!   while an arm of another family still fits.
//! - T7: an arm is not admitted when no first allowance fits: the refusal is
//!   `budget_denied`, and its write holds one `GPU_LINE_REFUSAL` row (no
//!   arm yet, rung 1, the first allowance asked, the bucket that ran out and
//!   what fits) and nothing else: no arm, no intent.
//! - T8: the intent key replays its answer and refuses a changed ask; the
//!   logical key (family, contract sha256) answers the same ask under a new
//!   key and refuses another ask on an open arm's contract.
//! - T41, the arms' half: a lead of one line is refused on another line's
//!   arms, at the admit and at both reads; a reviewer reads but does not
//!   admit; taking a Grant out of the role lists stops its next call at once.
//! - T43: a hold ends and returns its pools once: after `hold_ttl_secs` with
//!   no claim, when rung 1 leaves `Open`, when the arm is withdrawn, and at
//!   its period's end (a hold never crosses a period).
//! - T44: a second arm on one contract needs `supersedes` naming the closed
//!   one, and gets no new hold. The rung cap that carries over is row M2-C's
//!   reserve check; one win per rung is row M2-E's verdict.
//! - The line cover: an agent admits only into a line its Grant reaches.
//!
//! The rig seats every family before period 0, so the first mint funds its
//! floor. Nothing is pinned, no seat reserve or new-idea pool is held, and
//! the market is smaller than one first allowance, so a family's room is
//! exactly its floor's first allowances.
//!
//! A closed rung 1 and a withdrawal are written by row M2-E's verdict; here
//! the test door `experiment_arm_rows` stands the arm in that state.
//!
//! On the base (#10398's head) the r2 arm shape does not exist, so every
//! test fails there. On #10454's head T7 fails: its refusal commits no write.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test experiment_arm_admit`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_GET_VERB, ARMS_LIST_VERB, ArmAdmitRequest, ArmContractAsk,
    ArmListRequest, ArmRef, ArmState, ArmView, ExperimentArm, HoldEnd, HoldEndCause, RungEnd,
    RungState, RunnerRef, arm_admit_as, arm_get_as, arm_list_as,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_line::{
    AllowanceHold, BudgetPolicy, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePolicy,
    GpuLineSetRequest, LineRefusal, LineRefusalKey, Track, gpu_seconds, line_refusals_in_txn,
};
use oneiron::memory::{
    MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::experiment_arm_rows::put_arm;
use oneiron::test_doors::gpu_line_hold_is_the_claim::read_txn;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::store_writes::last_committed_write;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// The rung-1 cap of the default policy: one first allowance.
const RUNG_1_SECS: u64 = 1_800;
/// The market left beside the floors: less than one first allowance.
const MARKET_SECS: u64 = 300;
/// The default `hold_ttl_secs`.
const HOLD_TTL_MS: u64 = 259_200_000;

/// A moment inside period `index`.
fn in_period(index: u64) -> u64 {
    ANCHOR_MS + index * PERIOD_MS + 5
}

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

    /// The owner sets `lane`'s line at `now_ms` with `roles`, sized for
    /// `families` demand families of `floor_arms` floor arms each.
    fn set_line(&self, key: &str, lane: EntityId, roles: &Roles, sized: (u64, u32), now_ms: u64) {
        let (families, floor_arms) = sized;
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: key.to_owned(),
                    project: lane,
                    policy: policy(roles, families, floor_arms),
                },
                now_ms,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
    }

    /// `lane`'s line set before period 0 with `roles`, and `families`
    /// demand families seated in it then, so the first mint funds them.
    fn seat_families(
        &self,
        lane: EntityId,
        roles: &Roles,
        families: u64,
        floor_arms: u32,
    ) -> Vec<EntityId> {
        self.set_line("set", lane, roles, (families, floor_arms), BEFORE_MS);
        (0..families)
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
                        },
                        BEFORE_MS,
                    )
                    .unwrap_or_else(|error| panic!("the owner seats family {index}: {error:?}"));
                family
            })
            .collect()
    }

    /// A lane under the root, set with `roles` and `families` seated.
    fn lane(&self, roles: &Roles, families: u64, floor_arms: u32) -> (EntityId, Vec<EntityId>) {
        let lane = self.project_under(self.root(), 2);
        let seated = self.seat_families(lane, roles, families, floor_arms);
        (lane, seated)
    }

    /// A named agent and the owner's Grant naming it, listing `verbs` (with
    /// `read`, which a Grant needs to confer) over the projects `audience`
    /// holds. Returns the agent and the Grant's id.
    fn agent(
        &self,
        name: &str,
        verbs: &[&str],
        audience: ScopeAxis<ScopeId>,
    ) -> (EntityId, EntityId) {
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
        assert!(minted.grant.confers, "agent={name} verbs={verbs:?}");
        (agent, minted.grant.grant_ref)
    }

    /// `vault.arms.admit` at `now_ms` as the owner (`None`) or as `agent`.
    fn admit_at(
        &self,
        caller: Option<EntityId>,
        request: &ArmAdmitRequest,
        now_ms: u64,
    ) -> MemoryResult<ArmView> {
        match caller {
            None => arm_admit_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                request,
                now_ms,
            ),
            Some(agent) => arm_admit_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                request,
                now_ms,
            ),
        }
    }

    fn admit(&self, caller: Option<EntityId>, request: &ArmAdmitRequest) -> MemoryResult<ArmView> {
        self.admit_at(caller, request, NOW_MS)
    }

    /// `vault.arms.get` as the owner (`None`) or as `agent`.
    fn get_as(&self, caller: Option<EntityId>, arm: EntityId) -> MemoryResult<ArmView> {
        let input = ArmRef { arm: arm.to_hex() };
        match caller {
            None => arm_get_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                &input,
            ),
            Some(agent) => arm_get_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                &input,
            ),
        }
    }

    /// `vault.arms.list` of `lane` as the owner (`None`) or as `agent`.
    fn list_as(&self, caller: Option<EntityId>, lane: EntityId) -> MemoryResult<Vec<ArmView>> {
        let input = ArmListRequest {
            line: Some(lane.to_hex()),
            family: None,
            open_only: false,
        };
        let list = match caller {
            None => arm_list_as(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
                &input,
            ),
            Some(agent) => arm_list_as(
                &self.vault.memory(agent, EdgeActorClass::Agent),
                None,
                &input,
            ),
        }?;
        Ok(list.arms)
    }

    /// Every arm of `lane`, as the owner lists them.
    fn arms_of(&self, lane: EntityId) -> Vec<ArmView> {
        self.list_as(None, lane)
            .expect("the owner lists the lane's arms")
    }

    /// The refusal rows of `lane`'s line in period `period`, in order.
    fn refusals(&self, lane: EntityId, period: u32) -> Vec<(LineRefusalKey, LineRefusal)> {
        let txn = read_txn(&self.vault).expect("read snapshot");
        line_refusals_in_txn(&self.vault, &txn, &lane, period).expect("read refusal rows")
    }

    /// The stored arm `id`.
    fn arm(&self, id: EntityId) -> ExperimentArm {
        self.vault
            .experiment_arm(&id)
            .expect("read")
            .expect("the arm")
    }

    /// Stands arm `id` where row M2-E's verdict leaves it at `at_ms`: rung 1
    /// closed `end` and the arm `state`, its hold (if it has one) ended
    /// `cause`.
    fn close(&self, id: EntityId, state: ArmState, end: RungEnd, cause: HoldEndCause, at_ms: u64) {
        let mut arm = self.arm(id);
        arm.rungs[0].state = RungState::Closed { end };
        arm.state = state;
        let held = arm.first_allowance.is_some();
        assert_eq!(arm.end_hold(at_ms, cause), held, "a live hold ends here");
        arm.revision += 1;
        put_arm(&self.vault, &arm).expect("the test door puts the arm");
    }
}

/// The line's policy: `families` demand floors of `floor_arms` first
/// allowances each, no pinned share, no seat reserve, no new-idea pool, a
/// market smaller than one first allowance, and one rung (every cap must
/// fit the allowance). Every other budget number is its default.
fn policy(roles: &Roles, families: u64, floor_arms: u32) -> GpuLinePolicy {
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
            allowance_units: families * u64::from(floor_arms) * RUNG_1_SECS + MARKET_SECS,
            pinned_parts: (0, 3),
            floor_arms,
            rung_caps_secs: vec![RUNG_1_SECS],
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

/// An admission of one arm titled `title`, on contract number `contract`,
/// into `family` of `lane`'s line.
fn ask(key: &str, lane: EntityId, family: EntityId, contract: u8, title: &str) -> ArmAdmitRequest {
    ArmAdmitRequest {
        intent_key: key.to_owned(),
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
            model: "open-model-runner".to_owned(),
            actor: None,
        },
        supersedes: None,
        ledger_rows: Vec::new(),
        card_digest: None,
    }
}

/// The hold an arm admitted in period `period` makes on its family's floor.
fn floor_hold(period: u32) -> AllowanceHold {
    AllowanceHold {
        period,
        units: RUNG_1_SECS,
        draws: vec![Draw {
            source: DrawSource::Floor,
            units: RUNG_1_SECS,
        }],
    }
}

fn refused_as(error: &MemoryError, code: &str, mark: &str) {
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(mark), "{mark}: {error:?}");
}

/// T6.
#[test]
fn an_admitted_arm_holds_its_first_allowance() {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 2, 1);

    let first = fixture
        .admit(None, &ask("a", lane, families[0], 1, "first arm"))
        .expect("the first arm's allowance fits the family's floor");
    assert_eq!(first.arm.first_allowance, Some(floor_hold(0)));
    assert!(first.open && !first.replayed, "seen {first:?}");
    assert_eq!(first.rung, 1);
    assert_eq!(first.arm.state, ArmState::Open);
    assert_eq!(first.arm.rungs[0].state, RungState::Open);
    assert_eq!(
        first.arm.contract.pinned_at_ms, NOW_MS,
        "the engine's clock"
    );
    assert_eq!(first.arm.contract.claimed_frozen_at_ms, Some(BEFORE_MS));
    let line = fixture.vault.gpu_line(&lane).expect("read").expect("line");
    let seat = line.seat(&families[0]).expect("the family's seat");
    assert_eq!(first.arm.seat, seat.seat, "the seat it was admitted under");
    assert_eq!(first.arm.track, Track::Demand);
    assert_eq!(first.arm.cohort, None, "one rule in force");

    let taken = fixture
        .admit(None, &ask("b", lane, families[0], 2, "second arm"))
        .expect_err("the first arm holds the family's only first allowance");
    refused_as(&taken, MEMORY_CODE_BUDGET_SPENT, "budget_denied");

    let other = fixture
        .admit(None, &ask("c", lane, families[1], 3, "other family"))
        .expect("another family's floor is its own");
    assert_eq!(other.arm.first_allowance, Some(floor_hold(0)));

    let arms = fixture.arms_of(lane);
    assert_eq!(arms.len(), 2, "seen {arms:?}");
    let held = arms
        .iter()
        .find(|view| view.arm.id == first.arm.id)
        .expect("the first arm");
    assert_eq!(
        held.arm.first_allowance,
        Some(floor_hold(0)),
        "the first arm still holds its whole allowance"
    );
}

/// T7.
#[test]
fn an_arm_is_not_admitted_when_no_first_allowance_fits() {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 1, 2);
    let family = families[0];
    for (key, contract) in [("a", 1), ("b", 2)] {
        fixture
            .admit(None, &ask(key, lane, family, contract, key))
            .unwrap_or_else(|error| panic!("arm {key} fits the floor: {error:?}"));
    }

    assert!(
        fixture.refusals(lane, 0).is_empty(),
        "two admissions refused nothing"
    );
    let before = last_committed_write(&fixture.vault);
    let refused = fixture
        .admit(None, &ask("c", lane, family, 3, "third arm"))
        .expect_err("the floor holds two first allowances");
    refused_as(&refused, MEMORY_CODE_BUDGET_SPENT, "budget_denied:");
    assert_ne!(
        last_committed_write(&fixture.vault),
        before,
        "the budget refusal commits its refusal row"
    );
    let rows = fixture.refusals(lane, 0);
    assert_eq!(rows.len(), 1, "one refusal row: {rows:?}");
    let (key, row) = &rows[0];
    assert_eq!(
        *key,
        LineRefusalKey {
            line: lane,
            period: 0,
            sequence: 0,
        }
    );
    assert!(
        row.short.is_some(),
        "the row names the bucket that ran out: {row:?}"
    );
    assert!(
        row.room < RUNG_1_SECS,
        "what fits is less than the ask: {row:?}"
    );
    assert_eq!(
        *row,
        LineRefusal {
            family,
            arm: None,
            rung: 1,
            cohort: None,
            asked_secs: RUNG_1_SECS,
            short: row.short,
            room: row.room,
            reason: "budget_denied".to_owned(),
            by: Some(fixture.owner),
            at_ms: NOW_MS,
        },
        "the row records the ask: no arm yet, rung 1, one first allowance"
    );
    // The answer and the row say the same.
    for mark in [
        format!("{:?} ran out", row.short),
        format!("{} s fit now", row.room),
    ] {
        assert!(
            refused.message.contains(&mark),
            "{mark}: {}",
            refused.message
        );
    }
    assert_eq!(fixture.arms_of(lane).len(), 2, "no third arm was written");

    // The refusal kept no intent: the same key with another ask is judged
    // as a new ask, not refused as a changed one, and writes its own row.
    let again = fixture
        .admit(None, &ask("c", lane, family, 4, "another third arm"))
        .expect_err("the floor is still spent");
    refused_as(&again, MEMORY_CODE_BUDGET_SPENT, "budget_denied:");
    let rows = fixture.refusals(lane, 0);
    assert_eq!(rows.len(), 2, "a second refusal, a second row: {rows:?}");
    assert_eq!(rows[1].0.sequence, 1);
    assert_eq!(fixture.arms_of(lane).len(), 2, "still no third arm");
}

/// T8.
#[test]
fn an_intent_key_replays_its_answer_and_refuses_a_changed_ask() {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 1, 2);
    let family = families[0];

    let admitted = fixture
        .admit(None, &ask("arm-1", lane, family, 1, "first arm"))
        .expect("the first ask admits");
    assert!(!admitted.replayed);
    let replayed = fixture
        .admit(None, &ask("arm-1", lane, family, 1, "first arm"))
        .expect("the same ask under the same key answers again");
    assert!(replayed.replayed, "seen {replayed:?}");
    assert_eq!(replayed.arm, admitted.arm, "nothing new was written");

    let changed = fixture
        .admit(None, &ask("arm-1", lane, family, 2, "a changed arm"))
        .expect_err("the key already names another ask");
    assert_eq!(changed.code, MEMORY_CODE_INVALID_STATE, "seen {changed:?}");

    // The logical key: the same ask on the open arm's contract under a new
    // key answers that arm; another ask on it is a conflict.
    let fresh_key = fixture
        .admit(None, &ask("arm-1-retry", lane, family, 1, "first arm"))
        .expect("the same ask under a fresh key answers the arm");
    assert!(fresh_key.replayed, "seen {fresh_key:?}");
    assert_eq!(fresh_key.arm, admitted.arm);
    let other_ask = fixture
        .admit(None, &ask("arm-1-other", lane, family, 1, "another title"))
        .expect_err("an open arm already pins this contract");
    refused_as(&other_ask, MEMORY_CODE_INVALID_STATE, "contract_conflict");
    assert_eq!(
        fixture.arms_of(lane).len(),
        1,
        "no replay or refusal held a second allowance"
    );

    // The room the refused asks would have taken is still there.
    fixture
        .admit(None, &ask("arm-2", lane, family, 2, "second arm"))
        .expect("the second first allowance still fits");
}

/// T41, the arms' half. One vault holds one line until row M2-I, so another
/// line's lead stands here as a Grant this line does not list.
#[test]
fn a_lead_of_one_line_is_refused_on_another_lines_arm() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let verbs = [ARMS_ADMIT_VERB, ARMS_GET_VERB, ARMS_LIST_VERB];
    let (lead, lead_grant) = fixture.agent("arm-lead", &verbs, ScopeAxis::All);
    let (reviewer, reviewer_grant) = fixture.agent("arm-reviewer", &verbs, ScopeAxis::All);
    let (other, _) = fixture.agent("other-line-lead", &verbs, ScopeAxis::All);
    let roles = Roles {
        leads: vec![lead_grant],
        reviewers: vec![reviewer_grant],
    };
    let families = fixture.seat_families(lane, &roles, 1, 2);
    let family = families[0];
    let arm = fixture
        .admit(Some(lead), &ask("lead", lane, family, 1, "the lead's arm"))
        .expect("the lead admits")
        .arm;
    assert_eq!(arm.admitted_by, Some(lead));

    let before = last_committed_write(&fixture.vault);
    for (caller, name) in [(other, "other"), (reviewer, "reviewer")] {
        let refused = fixture
            .admit(Some(caller), &ask(name, lane, family, 2, name))
            .expect_err("only a lead admits");
        refused_as(&refused, MEMORY_CODE_FORBIDDEN, "not_this_line");
    }
    assert_eq!(
        last_committed_write(&fixture.vault),
        before,
        "a refused caller commits no write"
    );
    let hidden = fixture
        .get_as(Some(other), arm.id)
        .expect_err("another line's lead reads no arm here");
    assert_eq!(hidden.code, MEMORY_CODE_NOT_FOUND, "{hidden:?}");
    assert!(
        fixture
            .list_as(Some(other), lane)
            .expect("a list")
            .is_empty(),
        "another line's lead lists no arm here"
    );
    for caller in [lead, reviewer] {
        assert_eq!(
            fixture
                .get_as(Some(caller), arm.id)
                .expect("a role reads")
                .arm,
            arm
        );
        assert_eq!(
            fixture.list_as(Some(caller), lane).expect("a list").len(),
            1
        );
    }

    // Taking the Grant out of the lists stops its next call at once, reads
    // included.
    fixture.set_line(
        "unlist",
        lane,
        &Roles {
            leads: Vec::new(),
            reviewers: vec![reviewer_grant],
        },
        (1, 2),
        NOW_MS,
    );
    let unlisted = fixture
        .admit(Some(lead), &ask("lead-next", lane, family, 3, "next arm"))
        .expect_err("no longer a lead");
    refused_as(&unlisted, MEMORY_CODE_FORBIDDEN, "not_this_line");
    let gone = fixture
        .get_as(Some(lead), arm.id)
        .expect_err("no longer a role on the line");
    assert_eq!(gone.code, MEMORY_CODE_NOT_FOUND, "{gone:?}");
    assert!(
        fixture
            .list_as(Some(lead), lane)
            .expect("a list")
            .is_empty()
    );
}

/// One floor of one first allowance in one family: the room T43 watches.
fn one_floor_lane() -> (Fixture, EntityId, EntityId) {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 1, 1);
    (fixture, lane, families[0])
}

/// T43.
#[test]
fn a_dormant_hold_lapses_and_returns_its_pools_once() {
    // After `hold_ttl_secs` with no claim ever made.
    let (fixture, lane, family) = one_floor_lane();
    let dormant = fixture
        .admit(None, &ask("a", lane, family, 1, "dormant arm"))
        .expect("the hold fits")
        .arm;
    let early = fixture
        .admit_at(
            None,
            &ask("b", lane, family, 2, "early"),
            NOW_MS + HOLD_TTL_MS - 1,
        )
        .expect_err("the hold still lives one millisecond before its ttl");
    refused_as(&early, MEMORY_CODE_BUDGET_SPENT, "budget_denied");
    let lapsed_at = NOW_MS + HOLD_TTL_MS;
    let taker = fixture
        .admit_at(None, &ask("c", lane, family, 3, "taker"), lapsed_at)
        .expect("the dormant hold gave its floor back");
    assert_eq!(taker.arm.first_allowance, Some(floor_hold(0)));
    let once = fixture
        .admit_at(None, &ask("d", lane, family, 4, "second taker"), lapsed_at)
        .expect_err("the room came back once");
    refused_as(&once, MEMORY_CODE_BUDGET_SPENT, "budget_denied");
    let kept = fixture.arm(dormant.id);
    assert_eq!(kept.state, ArmState::Open, "the arm stays admitted");
    assert_eq!(
        kept.hold_ended_at(lapsed_at, ANCHOR_MS + PERIOD_MS, HOLD_TTL_MS / 1_000, false),
        Some(HoldEnd {
            at_ms: lapsed_at,
            cause: HoldEndCause::Dormant
        })
    );
    assert_eq!(
        kept.hold_ended_at(lapsed_at, ANCHOR_MS + PERIOD_MS, HOLD_TTL_MS / 1_000, true),
        None,
        "a hold a claim drew does not lie dormant"
    );

    // When rung 1 leaves `Open`, and when the arm is withdrawn.
    for (state, end, cause) in [
        (ArmState::Killed, RungEnd::Killed, HoldEndCause::RungClosed),
        (
            ArmState::Withdrawn,
            RungEnd::Invalid {
                reason: oneiron::experiment_arm::ArmInvalidReason::Withdrawn,
            },
            HoldEndCause::Withdrawn,
        ),
    ] {
        let (fixture, lane, family) = one_floor_lane();
        let first = fixture
            .admit(None, &ask("a", lane, family, 1, "first"))
            .expect("the hold fits")
            .arm;
        fixture.close(first.id, state, end, cause, NOW_MS + 10);
        let taker = fixture
            .admit_at(None, &ask("b", lane, family, 2, "taker"), NOW_MS + 20)
            .unwrap_or_else(|error| panic!("{cause:?} gave the floor back: {error:?}"));
        assert_eq!(taker.arm.first_allowance, Some(floor_hold(0)));
        let once = fixture
            .admit_at(None, &ask("c", lane, family, 3, "again"), NOW_MS + 20)
            .expect_err("the room came back once");
        refused_as(&once, MEMORY_CODE_BUDGET_SPENT, "budget_denied");
        let mut ended = fixture.arm(first.id);
        assert_eq!(
            ended.hold_end,
            Some(HoldEnd {
                at_ms: NOW_MS + 10,
                cause
            })
        );
        assert!(!ended.end_hold(NOW_MS + 30, cause), "a hold ends once");
    }

    // At its period's end: a hold never crosses a period.
    let (fixture, lane, family) = one_floor_lane();
    let first = fixture
        .admit(None, &ask("a", lane, family, 1, "period 0"))
        .expect("the hold fits")
        .arm;
    let next = fixture
        .admit_at(None, &ask("b", lane, family, 2, "period 1"), in_period(1))
        .expect("period 1's floor is free of period 0's hold");
    assert_eq!(next.arm.first_allowance, Some(floor_hold(1)));
    let end_ms = ANCHOR_MS + PERIOD_MS;
    assert_eq!(
        fixture
            .arm(first.id)
            .hold_ended_at(end_ms, end_ms, HOLD_TTL_MS / 1_000, true),
        Some(HoldEnd {
            at_ms: end_ms,
            cause: HoldEndCause::PeriodEnded
        })
    );
}

/// T44.
#[test]
fn a_second_arm_on_one_contract_needs_supersedes_and_gets_no_new_cap() {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 1, 2);
    let family = families[0];
    let first = fixture
        .admit(None, &ask("a", lane, family, 7, "first run"))
        .expect("the experiment's first arm")
        .arm;

    let open = fixture
        .admit(None, &ask("b", lane, family, 7, "second run"))
        .expect_err("an open arm pins the contract");
    refused_as(&open, MEMORY_CODE_INVALID_STATE, "contract_conflict");

    fixture.close(
        first.id,
        ArmState::Killed,
        RungEnd::Killed,
        HoldEndCause::RungClosed,
        NOW_MS + 10,
    );
    let unnamed = fixture
        .admit(None, &ask("b", lane, family, 7, "second run"))
        .expect_err("a re-run names the closed arm");
    refused_as(&unnamed, MEMORY_CODE_INVALID_STATE, "supersedes");

    let mut rerun_ask = ask("b-named", lane, family, 7, "second run");
    rerun_ask.supersedes = Some(first.id);
    let rerun = fixture.admit(None, &rerun_ask).expect("the re-run").arm;
    assert_eq!(rerun.supersedes, Some(first.id));
    assert_eq!(rerun.first_allowance, None, "a re-run gets no hold");
    assert_eq!(
        rerun.cohort, first.cohort,
        "it keeps its predecessor's cohort"
    );

    fixture.close(
        rerun.id,
        ArmState::Killed,
        RungEnd::Killed,
        HoldEndCause::RungClosed,
        NOW_MS + 20,
    );
    let mut twice = ask("c", lane, family, 7, "third run");
    twice.supersedes = Some(first.id);
    let refused = fixture
        .admit(None, &twice)
        .expect_err("the first arm already has its successor");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "successor");
    twice.intent_key = "c-newest".to_owned();
    twice.supersedes = Some(rerun.id);
    let third = fixture
        .admit(None, &twice)
        .expect("the newest arm of the experiment is named")
        .arm;
    assert_eq!(third.first_allowance, None);

    // A supersedes target that is still open is refused.
    let live = fixture
        .admit(None, &ask("d", lane, family, 8, "live arm"))
        .expect("a new experiment holds the freed allowance")
        .arm;
    assert!(live.first_allowance.is_some(), "a new contract gets a hold");
    let mut correction = ask("e", lane, family, 9, "correction");
    correction.supersedes = Some(live.id);
    let refused = fixture
        .admit(None, &correction)
        .expect_err("the target is open");
    refused_as(&refused, MEMORY_CODE_INVALID_STATE, "closed arm");
}

/// The line cover on `vault.arms.admit`: an agent whose Grant reaches the
/// line and is a lead there admits; one whose Grant does not reach it, or
/// does not list the verb, is refused, even when it is a lead.
#[test]
fn an_agent_admits_only_into_a_line_its_grant_reaches() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let elsewhere = fixture.project_under(fixture.root(), 0);
    let named = |project: EntityId| ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
    let verbs = [ARMS_ADMIT_VERB];
    let (every, every_grant) = fixture.agent("arm-lead-every-project", &verbs, ScopeAxis::All);
    let (on_lane, lane_grant) = fixture.agent("arm-lead-on-lane", &verbs, named(lane));
    let (on_root, root_grant) = fixture.agent("arm-lead-on-root", &verbs, named(fixture.root()));
    let (off_line, off_grant) = fixture.agent("arm-lead-elsewhere", &verbs, named(elsewhere));
    let (no_verb, no_verb_grant) = fixture.agent("arm-lead-no-verb", &[], ScopeAxis::All);
    let roles = Roles {
        leads: vec![
            every_grant,
            lane_grant,
            root_grant,
            off_grant,
            no_verb_grant,
        ],
        reviewers: Vec::new(),
    };
    let family = fixture.seat_families(lane, &roles, 1, 4)[0];

    for (contract, (lead, key)) in [(every, "every"), (on_lane, "lane"), (on_root, "root")]
        .into_iter()
        .enumerate()
    {
        let contract = u8::try_from(contract).expect("small") + 1;
        let view = fixture
            .admit(Some(lead), &ask(key, lane, family, contract, key))
            .unwrap_or_else(|error| panic!("the {key} Grant reaches the line: {error:?}"));
        assert_eq!(view.arm.admitted_by, Some(lead));
    }

    let before = last_committed_write(&fixture.vault);
    for (lead, key) in [(off_line, "elsewhere"), (no_verb, "no-verb")] {
        let refused = fixture
            .admit(Some(lead), &ask(key, lane, family, 9, key))
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
    assert_eq!(fixture.arms_of(lane).len(), 3);
}
