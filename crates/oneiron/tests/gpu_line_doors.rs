//! The GPU line doors (design pass 32 r2, sections 3.1, 3.2, 4.1 and 5;
//! LE-6, LE-7): `vault.gpu.lines.set`, `.get` and `.families.admit` through
//! the engine acts the host doors call.
//!
//! - T1: a period's record is minted at its first write and never again; a
//!   replay of the mint from the line it read gives the same economic digest.
//! - T5 (door half): a new period opens with exactly its allowance, as a
//!   fresh allocation generation.
//! - T5b: a lead and a planner are refused an interest seat, which the owner
//!   seats (the graduation half is row M2-E's door).
//! - T36: a seat asked after the mint takes a reserved floor of its own side
//!   or waits for the next mint; no issued ceiling changes.
//! - T38: a policy edit never reaches a period that has begun: the set door
//!   mints first.
//! - T41 (the line doors' half): a Grant the line does not list is refused
//!   on its reads and writes (`not_this_line`); a reviewer is no lead.
//! - T42: a demand seat past the cap needs the owner; a seed is refused.
//! - T60: a lead or a planner seats a new idea, which takes a slot at once
//!   and draws it.
//! - T61: a fifth new idea in a period is refused; a lapse after two periods
//!   frees the slot and keeps the project's history.
//! - The intent key and the seat's logical key; setting a line is the
//!   owner's act; one line per account; the schedule is fixed once minted; a
//!   period once passed never reopens; every floor fits its own side.
//! - Review round 1: a caller off the line neither replays a seat nor mints
//!   a period; a lead's cap is the minted period's, so an edit waits for the
//!   next mint.
//! - A two-rule mint commits its cohort seed and hides it until the period
//!   ends; a one-rule mint stores neither.
//!
//! On the base the r2 shapes do not exist, so every test fails there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test gpu_line_doors`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, WalletRef};
use oneiron::gpu_line::{
    BudgetPolicy, Draw, DrawAsk, DrawPurpose, DrawSource, GpuLine, GpuLineError,
    GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineSetRequest, GpuLineView, LineInvalid,
    MintError, PeriodRoom, RuleRef, Side, Track, VAULT_GPU_LINES_FAMILIES_ADMIT,
    VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET, cohort_seed_commit, gpu_seconds, line_allocation_id,
    mint_period, period_balances, plan_draws,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryError,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// One floor of the default policy: two rung-1 allowances.
const FLOOR: u64 = 3_600;

/// A moment inside period `index`.
fn in_period(index: u64) -> u64 {
    ANCHOR_MS + index * PERIOD_MS + 5
}

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, and this install's live machine profile
/// (the owner's agent Grant act needs it).
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

    /// A named agent and the owner's Grant naming it and listing `verbs` (a
    /// Grant confers only with `read` among its verbs). Returns the agent
    /// and the Grant's id, which a line's role lists name.
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

    fn try_set(
        &self,
        key: &str,
        lane: EntityId,
        policy: GpuLinePolicy,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: key.to_owned(),
                    project: lane,
                    policy,
                },
                now_ms,
            )
    }

    fn owner_set(
        &self,
        key: &str,
        lane: EntityId,
        policy: GpuLinePolicy,
        now_ms: u64,
    ) -> GpuLineView {
        self.try_set(key, lane, policy, now_ms)
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"))
    }

    /// Seats `family` at `now_ms`: as `caller`'s agent, or as the owner.
    fn admit_at(
        &self,
        caller: Option<EntityId>,
        key: &str,
        lane: EntityId,
        family: EntityId,
        track: Track,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        let request = GpuLineFamilyAdmitRequest {
            intent_key: key.to_owned(),
            project: lane,
            family,
            track,
        };
        match caller {
            None => self
                .vault
                .memory(self.owner, EdgeActorClass::Human)
                .admit_gpu_line_family(Some(&self.owner_proof), &request, now_ms),
            Some(agent) => self
                .vault
                .memory(agent, EdgeActorClass::Agent)
                .admit_gpu_line_family(None, &request, now_ms),
        }
    }

    fn admit(
        &self,
        caller: Option<EntityId>,
        key: &str,
        lane: EntityId,
        family: EntityId,
        track: Track,
    ) -> Result<GpuLineView, GpuLineError> {
        self.admit_at(caller, key, lane, family, track, NOW_MS)
    }

    /// A read of `lane`'s line at `now_ms`: as `caller`'s agent, or as the
    /// owner.
    fn view_as(
        &self,
        caller: Option<EntityId>,
        lane: EntityId,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        match caller {
            None => self
                .vault
                .memory(self.owner, EdgeActorClass::Human)
                .gpu_line_view(Some(&self.owner_proof), &lane, now_ms),
            Some(agent) => self
                .vault
                .memory(agent, EdgeActorClass::Agent)
                .gpu_line_view(None, &lane, now_ms),
        }
    }

    fn view(&self, lane: EntityId, now_ms: u64) -> GpuLineView {
        self.view_as(None, lane, now_ms)
            .expect("the owner reads the line")
    }

    fn line(&self, lane: EntityId) -> GpuLine {
        self.vault.gpu_line(&lane).expect("read").expect("the line")
    }
}

/// The open-models lane's preset (pass 34, 3.3; EM-21): the lane's own
/// document, which its kit passes to `vault.gpu.lines.set`. The engine's own
/// defaults are neutral.
fn open_models() -> BudgetPolicy {
    BudgetPolicy {
        allowance_units: 345_600,
        pinned_parts: (1, 3),
        floor_arms: 2,
        rung_caps_secs: vec![1_800, 10_800, 172_800],
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

/// The lane's policy under the open-models preset (96 GPU-hours a
/// fortnight, a third pinned to the interest track, `payoff_share@1`) and no
/// role.
fn policy() -> GpuLinePolicy {
    GpuLinePolicy {
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: Vec::new(),
        machines: Vec::new(),
        leads: Vec::new(),
        reviewers: Vec::new(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: open_models(),
    }
}

/// The policy with these role lists.
fn with_roles(leads: &[EntityId], reviewers: &[EntityId], planners: &[EntityId]) -> GpuLinePolicy {
    GpuLinePolicy {
        leads: leads.to_vec(),
        reviewers: reviewers.to_vec(),
        planners: planners.to_vec(),
        ..policy()
    }
}

fn code(error: GpuLineError) -> String {
    MemoryError::from(error).code
}

fn refused_as(error: GpuLineError, expected_code: &str, mark: &str) {
    let error = MemoryError::from(error);
    assert_eq!(error.code, expected_code, "{error:?}");
    assert!(error.message.contains(mark), "{mark}: {error:?}");
}

/// T1.
#[test]
fn a_period_record_is_minted_once_and_replays_its_economic_digest() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);

    let first = fixture.owner_set("set-1", lane, policy(), NOW_MS);
    assert!(!first.preview, "the line's first write mints its period");
    let minted = first.period.clone().expect("period 0 has begun");
    assert_eq!((minted.index, minted.minted_at_ms), (0, NOW_MS));
    assert_eq!(
        fixture.vault.gpu_line_period(&lane, 0).expect("read"),
        Some(minted.clone()),
        "the record is stored"
    );

    // A narrower policy later in the period leaves the record as it was.
    let mut narrower = policy();
    narrower.budget.allowance_units = 200_000;
    let second = fixture.owner_set("set-2", lane, narrower, NOW_MS + 10);
    assert_eq!(second.line.revision, first.line.revision + 1);
    assert_eq!(second.period, Some(minted.clone()), "minted once");

    // The replay of the mint from the line it read, at another time, gives
    // the same economic digest.
    let replay =
        mint_period(&first.line, 0, &BTreeMap::new(), NOW_MS + 999).expect("the replayed mint");
    assert_eq!(replay.economic_digest, minted.economic_digest);
    assert_ne!(replay.minted_at_ms, minted.minted_at_ms);

    // The change applies from the next period, which the read previews.
    let next = fixture.view(lane, in_period(1));
    assert!(next.preview, "nothing wrote in period 1 yet");
    let preview = next.period.expect("period 1 has begun");
    assert_eq!(
        (preview.index, preview.policy.allowance_units),
        (1, 200_000)
    );
}

/// T5, the door half.
#[test]
fn a_new_period_opens_with_exactly_its_allowance() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let set = fixture.owner_set("set", lane, policy(), NOW_MS);
    let demand = fixture.project_under(lane, 0);
    fixture
        .admit(None, "seat", lane, demand, Track::Demand)
        .expect("the owner seats a demand family");

    let record = fixture
        .view(lane, in_period(3))
        .period
        .expect("period 3 has begun");
    assert_eq!(record.index, 3);
    assert!(period_balances(&record), "exactly its allowance");
    assert_eq!(record.floor_of(&demand), FLOOR);
    assert_eq!(record.allocation.id, line_allocation_id(&lane));
    assert_eq!(record.allocation.generation, 4, "one generation per period");
    assert_eq!(record.allocation.units, 345_600);
    assert_eq!(record.allocation.wallet, set.line.wallet);
}

/// T5b.
#[test]
fn an_interest_seat_still_needs_the_owner() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let verbs = [VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET];
    let (lead, lead_grant) = fixture.agent("gpu-line-lead", &verbs);
    let (planner, planner_grant) = fixture.agent("gpu-line-planner", &verbs);
    fixture.owner_set(
        "set",
        lane,
        with_roles(&[lead_grant], &[], &[planner_grant]),
        NOW_MS,
    );
    let demand = fixture.project_under(lane, 0);
    let interest = fixture.project_under(lane, 0);
    let stranger = fixture.project_under(fixture.root(), 0);

    let seated = fixture
        .admit(Some(lead), "demand", lane, demand, Track::Demand)
        .expect("the lead seats a demand family");
    let seat = seated.line.seat(&demand).expect("the demand seat");
    assert_eq!((seat.track, seat.admitted_by), (Track::Demand, Some(lead)));

    for (caller, key) in [(lead, "lead-interest"), (planner, "planner-interest")] {
        let refused = fixture
            .admit(Some(caller), key, lane, interest, Track::Interest)
            .expect_err("an interest seat is the owner's own act");
        assert_eq!(code(refused), MEMORY_CODE_FORBIDDEN);
    }
    assert!(fixture.line(lane).seat(&interest).is_none());
    fixture
        .admit(None, "interest", lane, interest, Track::Interest)
        .expect("the owner seats the interest family");

    let outside = fixture
        .admit(Some(lead), "stranger", lane, stranger, Track::Demand)
        .expect_err("a project outside the lane is no family of it");
    assert!(matches!(outside, GpuLineError::NotChild), "{outside:?}");
    assert_eq!(code(outside), MEMORY_CODE_BAD_REQUEST);
}

/// The intent key names a call; the seat's logical key is its family.
#[test]
fn an_intent_key_replays_its_answer_and_refuses_a_changed_ask() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let (lead, grant) = fixture.agent("gpu-line-lead", &[VAULT_GPU_LINES_FAMILIES_ADMIT]);
    fixture.owner_set("set", lane, with_roles(&[grant], &[], &[]), NOW_MS);
    let first = fixture.project_under(lane, 0);
    let second = fixture.project_under(lane, 0);

    let seated = fixture
        .admit(Some(lead), "seat-1", lane, first, Track::Demand)
        .expect("the first ask seats");
    assert!(!seated.replayed);
    let replayed = fixture
        .admit(Some(lead), "seat-1", lane, first, Track::Demand)
        .expect("the same ask under the same key answers again");
    assert!(replayed.replayed);
    assert_eq!(replayed.line, seated.line, "nothing new was written");

    let changed = fixture
        .admit(Some(lead), "seat-1", lane, second, Track::Demand)
        .expect_err("the key already names another ask");
    assert_eq!(code(changed), MEMORY_CODE_INVALID_STATE);

    // A lost answer retried under a fresh key finds the seat it made.
    let retried = fixture
        .admit(Some(lead), "seat-1-retry", lane, first, Track::Demand)
        .expect("the same seat under a new key");
    assert!(retried.replayed);
    assert_eq!(retried.line.families.len(), 1, "one seat, never two");
    let other_kind = fixture
        .admit(Some(lead), "seat-1-new-idea", lane, first, Track::NewIdea)
        .expect_err("one project holds one seat of one kind");
    assert!(
        matches!(other_kind, GpuLineError::SeatTaken),
        "{other_kind:?}"
    );
    assert!(fixture.line(lane).seat(&second).is_none());
}

#[test]
fn setting_a_line_is_the_owners_act_and_reading_one_needs_a_role() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let (setter, _) = fixture.agent("gpu-line-setter", &[VAULT_GPU_LINES_SET]);
    let set = fixture
        .vault
        .memory(setter, EdgeActorClass::Agent)
        .set_gpu_line(
            None,
            &GpuLineSetRequest {
                intent_key: "agent-set".to_owned(),
                project: lane,
                policy: policy(),
            },
            NOW_MS,
        )
        .expect_err("an agent's Grant does not set a line");
    assert_eq!(code(set), MEMORY_CODE_FORBIDDEN);
    assert_eq!(fixture.vault.gpu_line(&lane).expect("read"), None);

    let (reviewer, reviewer_grant) = fixture.agent("gpu-line-reviewer", &[VAULT_GPU_LINES_GET]);
    fixture.owner_set("set", lane, with_roles(&[], &[reviewer_grant], &[]), NOW_MS);
    let (unlisted, _) = fixture.agent("gpu-line-unlisted", &[VAULT_GPU_LINES_GET]);
    refused_as(
        fixture
            .view_as(Some(unlisted), lane, NOW_MS)
            .expect_err("a Grant the line does not list"),
        MEMORY_CODE_FORBIDDEN,
        "not_this_line",
    );
    let view = fixture
        .view_as(Some(reviewer), lane, NOW_MS)
        .expect("a reviewer of the line reads it");
    assert_eq!(view.line.project, lane);
    assert!(!view.preview);
}

/// T36.
#[test]
fn a_late_seat_takes_a_reserved_floor_or_waits_for_the_next_mint() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let record = fixture
        .owner_set("set", lane, policy(), NOW_MS)
        .period
        .expect("period 0 is minted");
    let first = fixture.project_under(lane, 0);
    let second = fixture.project_under(lane, 0);
    let interest = fixture.project_under(lane, 0);

    let seated = fixture
        .admit(None, "first", lane, first, Track::Demand)
        .expect("the first late seat");
    let seat = seated.line.seat(&first).expect("seated").clone();
    assert_eq!(seat.effective_from_period, 1);
    assert_eq!(
        seat.late_floor,
        Some((0, FLOOR)),
        "the unpinned reserve's floor"
    );
    assert_eq!(
        seated.period,
        Some(record.clone()),
        "the record and its ceilings stand"
    );
    let waits = fixture
        .admit(None, "second", lane, second, Track::Demand)
        .expect("the second late seat");
    let waiting = waits.line.seat(&second).expect("seated");
    assert_eq!(waiting.late_floor, None, "the reserve is spent: it waits");
    assert_eq!(waiting.effective_from_period, 1);

    let room = PeriodRoom::fold(&record, &waits.line.families, &[]);
    assert_eq!(
        room.capacity(oneiron::gpu_line::Bucket::Floor { family: first }),
        FLOOR
    );
    assert_eq!(
        room.capacity(oneiron::gpu_line::Bucket::Floor { family: second }),
        0
    );
    assert_eq!(room.reserve_left(Side::Unpinned), 0);
    assert_eq!(
        room.reserve_left(Side::Pinned),
        FLOOR,
        "the other side's room is untouched"
    );
    assert_eq!(record.ceiling_of(&first, record.policy.rules[0]), 0);

    let pinned = fixture
        .admit(None, "interest", lane, interest, Track::Interest)
        .expect("an interest late seat");
    assert_eq!(
        pinned.line.seat(&interest).expect("seated").late_floor,
        Some((0, FLOOR)),
        "the pinned side's reserve"
    );

    let next = fixture.view(lane, in_period(1)).period.expect("period 1");
    for family in [first, second, interest] {
        assert_eq!(
            next.floor_of(&family),
            FLOOR,
            "the next mint funds every seat"
        );
        assert!(next.ceiling_of(&family, next.policy.rules[0]) > 0);
    }
}

/// T38.
#[test]
fn a_policy_edit_never_reaches_a_period_that_has_begun() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let mut edited = policy();
    edited.budget.allowance_units = 200_000;
    // Period 1 has begun and nothing wrote in it: the set door mints it
    // first, from the line as it stood.
    let view = fixture.owner_set("edit", lane, edited, in_period(1));
    let current = view.period.expect("period 1");
    assert_eq!(current.index, 1);
    assert_eq!(current.policy.allowance_units, 345_600);
    assert_eq!(
        fixture.vault.gpu_line_period(&lane, 1).expect("read"),
        Some(current)
    );
    assert_eq!(view.line.budget.allowance_units, 200_000);
    let next = fixture.view(lane, in_period(2)).period.expect("period 2");
    assert_eq!(next.policy.allowance_units, 200_000, "from the next mint");
}

/// T41, the line doors' half. One vault holds one line until row M2-I, so
/// another line's lead stands here as a Grant this line does not list.
#[test]
fn a_lead_of_one_line_is_refused_on_another_lines_arm() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let verbs = [VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET];
    let (lead, lead_grant) = fixture.agent("gpu-line-lead", &verbs);
    let (reviewer, reviewer_grant) = fixture.agent("gpu-line-reviewer", &verbs);
    let (other, _) = fixture.agent("other-line-lead", &verbs);
    fixture.owner_set(
        "set",
        lane,
        with_roles(&[lead_grant], &[reviewer_grant], &[]),
        NOW_MS,
    );
    let family = fixture.project_under(lane, 0);

    refused_as(
        fixture
            .view_as(Some(other), lane, NOW_MS)
            .expect_err("a read"),
        MEMORY_CODE_FORBIDDEN,
        "not_this_line",
    );
    for caller in [other, reviewer] {
        refused_as(
            fixture
                .admit(Some(caller), "seat", lane, family, Track::Demand)
                .expect_err("a write"),
            MEMORY_CODE_FORBIDDEN,
            "not_this_line",
        );
    }
    fixture
        .view_as(Some(reviewer), lane, NOW_MS)
        .expect("a reviewer reads its line");
    fixture
        .admit(Some(lead), "seat", lane, family, Track::Demand)
        .expect("the lead seats");

    // Taking the Grant out of the list stops its next call at once.
    fixture.owner_set(
        "unlist",
        lane,
        with_roles(&[], &[reviewer_grant], &[]),
        NOW_MS,
    );
    let next = fixture.project_under(lane, 0);
    refused_as(
        fixture
            .admit(Some(lead), "seat-next", lane, next, Track::Demand)
            .expect_err("no longer a lead"),
        MEMORY_CODE_FORBIDDEN,
        "not_this_line",
    );
}

/// T42.
#[test]
fn a_seat_past_the_cap_needs_the_owner() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let (lead, grant) = fixture.agent("gpu-line-lead", &[VAULT_GPU_LINES_FAMILIES_ADMIT]);
    let mut capped = with_roles(&[grant], &[], &[]);
    capped.budget.seat_cap = 2;
    fixture.owner_set("set", lane, capped, NOW_MS);
    let families: Vec<EntityId> = (0..4).map(|_| fixture.project_under(lane, 0)).collect();

    for (n, family) in families[..2].iter().enumerate() {
        fixture
            .admit(
                Some(lead),
                &format!("seat-{n}"),
                lane,
                *family,
                Track::Demand,
            )
            .expect("inside the cap");
    }
    let past = fixture
        .admit(Some(lead), "seat-2", lane, families[2], Track::Demand)
        .expect_err("a third demand seat");
    assert_eq!(code(past), MEMORY_CODE_FORBIDDEN);
    fixture
        .admit(Some(lead), "idea", lane, families[3], Track::NewIdea)
        .expect("the cap counts demand seats; a new idea has its own");
    fixture
        .admit(None, "owner-seat-2", lane, families[2], Track::Demand)
        .expect("past the cap with the owner's proof");

    // The pinned track's seats have their own cap, 0 in the lane's preset:
    // when the owner raises it, a lead seats interest families up to it.
    let interest: Vec<EntityId> = (0..2).map(|_| fixture.project_under(lane, 0)).collect();
    let refused = fixture
        .admit(Some(lead), "interest-0", lane, interest[0], Track::Interest)
        .expect_err("pinned_seat_cap 0: interest seats are the owner's");
    assert_eq!(code(refused), MEMORY_CODE_FORBIDDEN);
    let mut pinned = with_roles(&[grant], &[], &[]);
    pinned.budget.seat_cap = 2;
    pinned.budget.pinned_seat_cap = 1;
    fixture.owner_set("pinned-cap", lane, pinned, NOW_MS);
    // The raised cap applies from the next mint: period 0 keeps its 0
    // (review round 1 of #10398).
    let early = fixture
        .admit(
            Some(lead),
            "interest-0a",
            lane,
            interest[0],
            Track::Interest,
        )
        .expect_err("period 0 was minted with pinned_seat_cap 0");
    assert_eq!(code(early), MEMORY_CODE_FORBIDDEN);
    fixture
        .admit_at(
            Some(lead),
            "interest-0b",
            lane,
            interest[0],
            Track::Interest,
            in_period(1),
        )
        .expect("inside the pinned cap from period 1");
    let past_pinned = fixture
        .admit_at(
            Some(lead),
            "interest-1",
            lane,
            interest[1],
            Track::Interest,
            in_period(1),
        )
        .expect_err("a second interest seat");
    assert_eq!(code(past_pinned), MEMORY_CODE_FORBIDDEN);

    let seeded = serde_json::from_value::<GpuLineFamilyAdmitRequest>(serde_json::json!({
        "intent_key": "seeded",
        "project": lane,
        "family": families[2],
        "track": "demand",
        "seed": { "wins": 3, "losses": 0, "cost_secs": 600 }
    }))
    .expect_err("a seat carries no seed");
    assert!(seeded.to_string().contains("seed"), "{seeded}");
}

/// Review round 1 of #10398: the admit door judges the caller's role on the
/// stored line before an intent replay or a mint. A lead the owner took off
/// the line, whose Grant still names the verb, neither replays the seat it
/// made nor mints the next period with a fresh key.
#[test]
fn a_caller_off_the_line_neither_replays_nor_mints() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let (lead, grant) = fixture.agent("gpu-line-lead", &[VAULT_GPU_LINES_FAMILIES_ADMIT]);
    fixture.owner_set("set", lane, with_roles(&[grant], &[], &[]), NOW_MS);
    let family = fixture.project_under(lane, 0);
    fixture
        .admit(Some(lead), "seat", lane, family, Track::Demand)
        .expect("the lead seats a demand family");
    fixture.owner_set("drop-lead", lane, with_roles(&[], &[], &[]), NOW_MS);

    let replay = fixture
        .admit(Some(lead), "seat", lane, family, Track::Demand)
        .expect_err("no replay for a caller off the line");
    assert_eq!(code(replay), MEMORY_CODE_FORBIDDEN);
    let other = fixture.project_under(lane, 0);
    let fresh = fixture
        .admit_at(
            Some(lead),
            "seat-next",
            lane,
            other,
            Track::Demand,
            in_period(1),
        )
        .expect_err("no seat for a caller off the line");
    assert_eq!(code(fresh), MEMORY_CODE_FORBIDDEN);
    assert!(
        fixture.view(lane, in_period(1)).preview,
        "the refused call minted nothing: period 1 is still a preview"
    );
}

/// T60.
#[test]
fn a_lead_seats_a_new_idea() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let verbs = [VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET];
    let (lead, lead_grant) = fixture.agent("gpu-line-lead", &verbs);
    let (planner, planner_grant) = fixture.agent("gpu-line-planner", &verbs);
    fixture.owner_set(
        "set",
        lane,
        with_roles(&[lead_grant], &[], &[planner_grant]),
        NOW_MS,
    );
    let first = fixture.project_under(lane, 0);
    let second = fixture.project_under(lane, 0);
    let demand = fixture.project_under(lane, 0);

    let by_lead = fixture
        .admit(Some(lead), "idea-1", lane, first, Track::NewIdea)
        .expect("a lead seats a new idea without the owner");
    let seat = by_lead.line.seat(&first).expect("seated");
    assert_eq!(
        (seat.track, seat.late_floor),
        (Track::NewIdea, Some((0, FLOOR)))
    );
    let by_planner = fixture
        .admit(Some(planner), "idea-2", lane, second, Track::NewIdea)
        .expect("a planner seats a new idea");
    refused_as(
        fixture
            .admit(Some(planner), "demand", lane, demand, Track::Demand)
            .expect_err("a planner seats new ideas only"),
        MEMORY_CODE_FORBIDDEN,
        "not_this_line",
    );

    let record = by_planner.period.expect("period 0");
    let room = PeriodRoom::fold(&record, &by_planner.line.families, &[]);
    assert_eq!(room.new_idea_slots_taken(), 2);
    let draws = plan_draws(
        &room,
        &DrawAsk {
            arm: EntityId::now(),
            family: first,
            track: Track::NewIdea,
            cohort: None,
            purpose: DrawPurpose::Unit { rung: 1 },
            units: 1_800,
        },
    )
    .expect("its arm draws the slot at once");
    assert_eq!(
        draws,
        vec![Draw {
            source: DrawSource::Floor,
            units: 1_800
        }]
    );
}

/// T61.
#[test]
fn a_fifth_new_idea_seat_in_a_period_is_refused_at_the_default() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let ideas: Vec<EntityId> = (0..5).map(|_| fixture.project_under(lane, 0)).collect();
    for (n, idea) in ideas[..4].iter().enumerate() {
        fixture
            .admit(None, &format!("idea-{n}"), lane, *idea, Track::NewIdea)
            .expect("four slots a period");
    }
    let fifth = |key: &str, now_ms| {
        fixture
            .admit_at(None, key, lane, ideas[4], Track::NewIdea, now_ms)
            .expect_err("the period's slots are given")
    };
    let full = fifth("idea-4", NOW_MS);
    assert!(
        matches!(full, GpuLineError::NewIdeaSlotsFull { slots: 4 }),
        "{full:?}"
    );
    assert_eq!(code(full), MEMORY_CODE_INVALID_STATE);
    // Period 1 funds the same four seats.
    fifth("idea-4-p1", in_period(1));

    // Period 2's mint lapses them and frees their slots. Seating one of the
    // projects again makes a new seat that continues the old one.
    let old = fixture.line(lane).seat(&ideas[0]).expect("seated").seat;
    let again = fixture
        .admit_at(
            None,
            "idea-0-again",
            lane,
            ideas[0],
            Track::NewIdea,
            in_period(2),
        )
        .expect("a lapsed project seated again");
    let lapsed = again
        .line
        .families
        .iter()
        .filter(|seat| seat.lapsed_from_period == Some(2))
        .count();
    assert_eq!(lapsed, 4, "the four lapse at period 2's mint");
    let renewed = again.line.seat(&ideas[0]).expect("the new seat");
    assert_ne!(renewed.seat, old);
    assert_eq!(renewed.replaces, Some(old), "its history continues");
    fixture
        .admit_at(
            None,
            "idea-4-p2",
            lane,
            ideas[4],
            Track::NewIdea,
            in_period(2),
        )
        .expect("a freed slot");
}

/// One vault account holds one GPU line until row M2-I.
#[test]
fn one_vault_holds_one_line() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let other = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let refused = fixture
        .try_set("set-other", other, policy(), NOW_MS)
        .expect_err("a second line");
    assert!(
        matches!(refused, GpuLineError::OneLinePerAccount),
        "{refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
    assert_eq!(fixture.vault.gpu_line(&other).expect("read"), None);
}

/// The schedule is fixed once a period is minted; before that the owner may
/// move it, and a read before the anchor has no period.
#[test]
fn the_schedule_is_fixed_once_a_period_is_minted() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let mut later = policy();
    later.period_anchor_ms = in_period(10);
    let early = fixture.owner_set("set", lane, later.clone(), NOW_MS);
    assert_eq!(early.period, None, "before the anchor");
    assert_eq!(fixture.view(lane, NOW_MS).period, None);
    later.period_anchor_ms = in_period(20);
    fixture.owner_set("move", lane, later, NOW_MS);
    fixture.owner_set("begin", lane, policy(), NOW_MS);
    let mut moved = policy();
    moved.period_secs = 2 * PERIOD_SECS;
    let refused = fixture
        .try_set("move-again", lane, moved, NOW_MS)
        .expect_err("period 0 is minted");
    assert!(
        matches!(refused, GpuLineError::ScheduleFixed),
        "{refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
}

/// Once a later period is minted, a clock that went back is refused at
/// every door: an earlier period never reopens.
#[test]
fn a_period_once_passed_never_reopens() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let demand = fixture.project_under(lane, 0);
    let seated = fixture
        .admit_at(None, "seat", lane, demand, Track::Demand, in_period(2))
        .expect("a seat in period 2 mints period 2");
    assert_eq!(seated.period.map(|period| period.index), Some(2));
    let before = fixture.line(lane);

    let other = fixture.project_under(lane, 0);
    let refused = fixture
        .admit_at(None, "seat-back", lane, other, Track::Demand, in_period(1))
        .expect_err("the clock went back to period 1");
    assert!(
        matches!(
            refused,
            GpuLineError::Mint(MintError::BehindMintedPeriod {
                index: 1,
                newest: 2
            })
        ),
        "{refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
    let read = fixture
        .view_as(None, lane, in_period(1))
        .expect_err("the read refuses the same period");
    assert!(
        matches!(
            read,
            GpuLineError::Mint(MintError::BehindMintedPeriod { .. })
        ),
        "{read:?}"
    );
    assert_eq!(fixture.vault.gpu_line_period(&lane, 1).expect("read"), None);
    assert_eq!(fixture.line(lane), before, "the refusals wrote nothing");
}

/// `seat_floor_unfunded` at the seat door and `policy_unfunded` at the set
/// door: every floor fits its own side, never the other.
#[test]
fn every_floor_fits_its_own_side_of_the_allowance() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    // A 9,000 s pinned side: the reserve and one interest floor fit.
    let mut narrow = policy();
    narrow.budget.pinned_parts = (25, 960);
    fixture.owner_set("set", lane, narrow, NOW_MS);
    let first = fixture.project_under(lane, 0);
    let second = fixture.project_under(lane, 0);
    fixture
        .admit(None, "first", lane, first, Track::Interest)
        .expect("one interest floor fits");
    let refused = fixture
        .admit(None, "second", lane, second, Track::Interest)
        .expect_err("a second does not");
    assert!(
        matches!(
            refused,
            GpuLineError::SeatFloorUnfunded { side: Side::Pinned }
        ),
        "{refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
    assert!(fixture.line(lane).seat(&second).is_none());

    let mut narrower = policy();
    narrower.budget.pinned_parts = (1, 960);
    let refused = fixture
        .try_set("narrower", lane, narrower, NOW_MS)
        .expect_err("the seated interest family's floor no longer fits");
    assert!(
        matches!(
            refused,
            GpuLineError::Invalid(LineInvalid::Unfunded { side: Side::Pinned })
        ),
        "{refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_BAD_REQUEST);
}

/// A two-rule mint draws a cohort seed and stores its sha256 commit; the get
/// view withholds the seed until the period ends. A one-rule mint stores
/// neither.
#[test]
fn a_two_rule_mint_commits_its_cohort_seed_and_hides_it() {
    let two_rule = fixture();
    let lane = two_rule.project_under(two_rule.root(), 2);
    let mut two = policy();
    two.budget.rules = vec![RuleRef::PAYOFF_SHARE_1, RuleRef::EVEN_SPLIT_1];
    two_rule.owner_set("set", lane, two, NOW_MS);
    let stored = two_rule
        .vault
        .gpu_line_period(&lane, 0)
        .expect("read")
        .expect("period 0");
    let seed = stored.cohort_seed.expect("a two-rule mint draws a seed");
    let commit = stored
        .cohort_seed_commit
        .clone()
        .expect("a two-rule mint commits it");
    assert_eq!(commit, cohort_seed_commit(&seed));
    assert_eq!(commit.len(), 64, "a sha256 in lower hex");
    assert!(
        commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "lower hex: {commit}"
    );
    let shown = two_rule
        .view(lane, NOW_MS)
        .period
        .expect("the view has period 0");
    assert_eq!(shown.cohort_seed, None, "the get view withholds the seed");
    assert_eq!(shown.cohort_seed_commit, Some(commit));

    let single = fixture();
    let other = single.project_under(single.root(), 2);
    single.owner_set("set", other, policy(), NOW_MS);
    let stored = single
        .vault
        .gpu_line_period(&other, 0)
        .expect("read")
        .expect("period 0");
    assert_eq!(stored.cohort_seed, None);
    assert_eq!(stored.cohort_seed_commit, None);
}
