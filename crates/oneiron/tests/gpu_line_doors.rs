//! The GPU line doors (design pass 32, sections 3.1, 3.2 and 5; tests T1,
//! T5 and T5b): `vault.gpu.lines.set`, `.get` and `.families.admit` through
//! the engine acts the host doors call.
//!
//! - T1: a period's record is minted at its first write and never again: a
//!   later policy change leaves it as it was and takes effect at the next
//!   period, and a replay of the mint from the line it read gives the same
//!   bytes.
//! - T5 (door half): a new period opens with exactly its own allowance, as a
//!   fresh allocation generation.
//! - T5b: an agent whose Grant names the admit verb seats a demand family and
//!   is refused an interest seat, which the owner seats; a project outside
//!   the lane and a second seat are refused.
//! - The intent key replays the first answer and refuses a changed ask.
//! - Setting a line is the owner's own act; reading one takes the owner or a
//!   Grant that names the verb.
//! - Astra pass-32 findings 6, 8 and 17 at the doors: a seat counts from the
//!   next mint, and every seat's floor fits its own side; the record freezes
//!   the rung caps and the forecast rule while hosts change at once; a period
//!   once passed never reopens when the clock or the schedule goes back; a
//!   seed past its bounds is refused. Every refusal writes nothing.
//!
//! On the base the module does not exist, so every test fails there.
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
    GpuLineError, GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineSetRequest, GpuLineView,
    InvalidCost, LineInvalid, MAX_SEED_WINS, MintError, PayoffSeed, PinnedMode, RuleRef, Track,
    VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET, mint_period,
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

    /// The owner's Grant naming `agent` and listing `verbs`. A Grant confers
    /// only with `read` among its verbs.
    fn grant(&self, agent: EntityId, verbs: &[&str]) {
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
        assert!(
            minted.grant.confers,
            "agent={agent:?} verbs={verbs:?}: the Grant confers"
        );
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

    fn admit(
        &self,
        caller: Option<EntityId>,
        key: &str,
        lane: EntityId,
        family: EntityId,
        track: Track,
    ) -> Result<GpuLineView, GpuLineError> {
        self.admit_at(caller, key, lane, family, track, None, NOW_MS)
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_at(
        &self,
        caller: Option<EntityId>,
        key: &str,
        lane: EntityId,
        family: EntityId,
        track: Track,
        seed: Option<PayoffSeed>,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        let request = GpuLineFamilyAdmitRequest {
            intent_key: key.to_owned(),
            project: lane,
            family,
            track,
            seed,
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

    /// The owner's read of `lane`'s line at `now_ms`.
    fn view(&self, lane: EntityId, now_ms: u64) -> Result<GpuLineView, GpuLineError> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .gpu_line_view(Some(&self.owner_proof), &lane, now_ms)
    }

    fn line(&self, lane: EntityId) -> oneiron::gpu_line::GpuLine {
        self.vault.gpu_line(&lane).expect("read").expect("the line")
    }
}

/// The open-models lane's policy: 96 GPU-hours a fortnight, a third pinned
/// to the interest track, two floor arms, `payoff_share@1`.
fn policy() -> GpuLinePolicy {
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
        floor_arms: 2,
        rung_caps_secs: vec![1_800, 10_800, 172_800],
        forecast_required: true,
        rules: vec![RuleRef::PAYOFF_SHARE_1],
        invalid_cost: InvalidCost::CountsAsCost,
        window_periods: 3,
        hosts: vec!["mel".to_owned()],
    }
}

fn code(error: GpuLineError) -> String {
    MemoryError::from(error).code
}

/// T1.
#[test]
fn a_period_record_is_minted_once_and_replays_byte_for_byte() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);

    let first = fixture.owner_set("set-1", lane, policy(), NOW_MS);
    assert!(
        first.period_minted,
        "the line's first write mints its period: {first:?}"
    );
    let minted = first.period.clone().expect("period 0 has begun");
    assert_eq!(minted.index, 0);
    assert_eq!(minted.minted_at_ms, NOW_MS);
    assert_eq!(
        fixture.vault.gpu_line_period(&lane, 0).expect("read"),
        Some(minted.clone()),
        "the record is stored"
    );

    // A narrower policy later in the period leaves the record as it was.
    let mut narrower = policy();
    narrower.allowance_units = 100_000;
    let second = fixture.owner_set("set-2", lane, narrower, NOW_MS + 10);
    assert_eq!(second.line.revision, first.line.revision + 1);
    assert_eq!(second.line.allowance_units, 100_000);
    assert_eq!(
        second.period,
        Some(minted.clone()),
        "minted once: the period keeps its record"
    );

    // The replay of the mint from the line it read gives the same bytes.
    let replay = mint_period(&first.line, 0, &BTreeMap::new(), minted.minted_at_ms)
        .expect("the replayed mint");
    assert_eq!(
        rmp_serde::to_vec_named(&replay).expect("encodes"),
        rmp_serde::to_vec_named(&minted).expect("encodes"),
        "same line revision and outcomes, same record"
    );

    // The change takes effect at the next period.
    let next = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .gpu_line_view(Some(&fixture.owner_proof), &lane, ANCHOR_MS + PERIOD_MS + 5)
        .expect("the owner reads the line");
    let preview = next.period.expect("period 1 has begun");
    assert!(
        !next.period_minted,
        "nothing wrote in period 1 yet: {preview:?}"
    );
    assert_eq!((preview.index, preview.allowance_units), (1, 100_000));
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

    let later = ANCHOR_MS + 3 * PERIOD_MS + 5;
    let view = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .gpu_line_view(Some(&fixture.owner_proof), &lane, later)
        .expect("the owner reads the line");
    let record = view.period.expect("period 3 has begun");
    assert_eq!(record.index, 3);
    assert_eq!(record.allowance_units, 345_600);
    let floors: u64 = record.floors.iter().map(|floor| floor.units).sum();
    assert_eq!(
        record.pinned_pool_units() + floors + record.tables[0].pool_units,
        record.allowance_units,
        "the period's buckets are exactly its allowance: nothing carried over"
    );
    let allocation = view.line.period_allocation(3);
    assert_eq!(
        allocation.reference.generation, 4,
        "one generation per period"
    );
    assert_eq!(allocation.units, 345_600);
    assert_eq!(allocation.wallet, Some(set.line.wallet));
}

/// T5b.
#[test]
fn an_interest_seat_needs_the_owner() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let demand = fixture.project_under(lane, 0);
    let interest = fixture.project_under(lane, 0);
    let stranger = fixture.project_under(fixture.root(), 0);
    let lead = fixture
        .vault
        .ensure_agent_principal("gpu-line-lead")
        .expect("named agent principal");
    fixture.grant(lead, &[VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET]);

    let seated = fixture
        .admit(Some(lead), "demand", lane, demand, Track::Demand)
        .expect("the lead's Grant seats a demand family");
    let seat = seated.line.seat(&demand).expect("the demand seat");
    assert_eq!((seat.track, seat.admitted_by), (Track::Demand, Some(lead)));

    let refused = fixture
        .admit(Some(lead), "interest", lane, interest, Track::Interest)
        .expect_err("an interest seat is the owner's own act");
    assert_eq!(code(refused), MEMORY_CODE_FORBIDDEN);

    let owned = fixture
        .admit(None, "interest", lane, interest, Track::Interest)
        .expect("the owner seats the interest family");
    assert_eq!(owned.line.families.len(), 2);

    let outside = fixture
        .admit(Some(lead), "stranger", lane, stranger, Track::Demand)
        .expect_err("a project outside the lane is no family of it");
    assert!(
        matches!(outside, GpuLineError::NotChild),
        "seen {outside:?}"
    );
    assert_eq!(code(outside), MEMORY_CODE_BAD_REQUEST);

    let again = fixture
        .admit(Some(lead), "demand-again", lane, demand, Track::Demand)
        .expect_err("one seat a family");
    assert!(matches!(again, GpuLineError::SeatTaken), "seen {again:?}");
}

#[test]
fn an_intent_key_replays_its_answer_and_refuses_a_changed_ask() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let first = fixture.project_under(lane, 0);
    let second = fixture.project_under(lane, 0);
    let lead = fixture
        .vault
        .ensure_agent_principal("gpu-line-lead")
        .expect("named agent principal");
    fixture.grant(lead, &[VAULT_GPU_LINES_FAMILIES_ADMIT]);

    let seated = fixture
        .admit(Some(lead), "seat-1", lane, first, Track::Demand)
        .expect("the first ask seats");
    assert!(!seated.replayed);
    let replayed = fixture
        .admit(Some(lead), "seat-1", lane, first, Track::Demand)
        .expect("the same ask under the same key answers again");
    assert!(replayed.replayed, "seen {replayed:?}");
    assert_eq!(replayed.line, seated.line, "nothing new was written");

    let changed = fixture
        .admit(Some(lead), "seat-1", lane, second, Track::Demand)
        .expect_err("the key already names another ask");
    assert_eq!(code(changed), MEMORY_CODE_INVALID_STATE);
    let line = fixture
        .vault
        .gpu_line(&lane)
        .expect("read")
        .expect("the line");
    assert!(
        line.seat(&second).is_none(),
        "the refused ask wrote nothing"
    );
}

#[test]
fn setting_a_line_is_the_owners_act_and_reading_one_needs_the_grant() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let agent = fixture
        .vault
        .ensure_agent_principal("gpu-line-reader")
        .expect("named agent principal");
    let memory = fixture.vault.memory(agent, EdgeActorClass::Agent);

    fixture.grant(agent, &[VAULT_GPU_LINES_SET]);
    let set = memory
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
    assert_eq!(
        fixture.vault.gpu_line(&lane).expect("read"),
        None,
        "nothing was written"
    );

    fixture.owner_set("set", lane, policy(), NOW_MS);
    let unread = memory
        .gpu_line_view(None, &lane, NOW_MS)
        .expect_err("no Grant names the read");
    assert_eq!(code(unread), MEMORY_CODE_FORBIDDEN);

    let reader = fixture
        .vault
        .ensure_agent_principal("gpu-line-granted-reader")
        .expect("named agent principal");
    fixture.grant(reader, &[VAULT_GPU_LINES_GET]);
    let view = fixture
        .vault
        .memory(reader, EdgeActorClass::Agent)
        .gpu_line_view(None, &lane, NOW_MS)
        .expect("a Grant that names the read admits it");
    assert_eq!(view.line.project, lane);
    assert!(view.period_minted);
}

/// Finding 6 at the door: a family seated in a period already minted has no
/// floor and no market ceiling there; both start with the next mint.
#[test]
fn a_seat_counts_from_the_next_mint() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let demand = fixture.project_under(lane, 0);
    let seated = fixture
        .admit(None, "seat", lane, demand, Track::Demand)
        .expect("the owner seats a demand family");
    assert!(seated.period_minted);
    let current = seated.period.expect("period 0 has begun");
    assert_eq!(current.floor_of(&demand), 0, "no floor this period");
    assert_eq!(current.ceiling_of(&demand, RuleRef::PAYOFF_SHARE_1), 0);

    let next = fixture
        .view(lane, ANCHOR_MS + PERIOD_MS + 5)
        .expect("the owner reads the line");
    let preview = next.period.expect("period 1 has begun");
    assert_eq!(preview.floor_of(&demand), 3_600, "the next mint seats it");
    assert!(preview.ceiling_of(&demand, RuleRef::PAYOFF_SHARE_1) > 0);
}

/// Finding 6: one more floor than its side holds is refused at the seat, and
/// a policy edit under which the seated floors no longer fit is refused at
/// the set. Neither writes.
#[test]
fn every_floor_fits_its_own_side_of_the_allowance() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    // 10,800 s a period, a third pinned: 3,600 s for the interest floors
    // (one floor) and 7,200 s for the demand floors (two).
    let mut small = policy();
    small.allowance_units = 10_800;
    fixture.owner_set("set", lane, small.clone(), NOW_MS);
    for (n, track) in [Track::Demand, Track::Demand, Track::Interest]
        .into_iter()
        .enumerate()
    {
        let family = fixture.project_under(lane, 0);
        fixture
            .admit(None, &format!("seat-{n}"), lane, family, track)
            .unwrap_or_else(|error| panic!("seat {n} on {track:?} fits: {error:?}"));
    }
    let seated = fixture.line(lane);
    assert_eq!(seated.families.len(), 3);

    for (n, track) in [Track::Demand, Track::Interest].into_iter().enumerate() {
        let family = fixture.project_under(lane, 0);
        let refused = fixture
            .admit(None, &format!("full-{n}"), lane, family, track)
            .expect_err("the side is full");
        assert!(
            matches!(refused, GpuLineError::FloorDoesNotFit),
            "{track:?}: seen {refused:?}"
        );
        assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
    }

    let mut wider_floors = small;
    wider_floors.floor_arms = 3;
    let refused = fixture
        .try_set("set-wider", lane, wider_floors, NOW_MS + 10)
        .expect_err("three floor arms do not fit two demand seats in 7,200 s");
    assert!(
        matches!(refused, GpuLineError::Invalid(LineInvalid::FloorsDoNotFit)),
        "seen {refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_BAD_REQUEST);
    assert_eq!(fixture.line(lane), seated, "the refusals wrote nothing");
}

/// Finding 8: the period record freezes the rung caps and the forecast rule
/// it read; an edit later in the period changes them from the next mint,
/// and only the hosts at once.
#[test]
fn the_period_record_freezes_its_caps_and_its_forecast_rule() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let first = fixture.owner_set("set-1", lane, policy(), NOW_MS);
    let minted = first.period.expect("period 0 has begun");
    assert_eq!(minted.rung_caps_secs, vec![1_800, 10_800, 172_800]);
    assert!(minted.forecast_required);

    let mut edited = policy();
    edited.rung_caps_secs = vec![900, 3_600];
    edited.forecast_required = false;
    edited.hosts = vec!["nelly".to_owned()];
    let second = fixture.owner_set("set-2", lane, edited, NOW_MS + 10);
    let current = second.period.expect("period 0");
    assert_eq!(current, minted, "the minted record stands");
    assert_eq!(
        second.line.hosts,
        vec!["nelly".to_owned()],
        "hosts are read from the line at once"
    );

    let next = fixture
        .view(lane, ANCHOR_MS + PERIOD_MS + 5)
        .expect("the owner reads the line")
        .period
        .expect("period 1 has begun");
    assert_eq!(next.rung_caps_secs, vec![900, 3_600]);
    assert!(!next.forecast_required);
}

/// Finding 8: once a later period is minted, a clock that went back, or a
/// schedule edit that puts the clock before it, is refused at every door:
/// an earlier period never reopens.
#[test]
fn a_period_once_passed_never_reopens() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let period_two = ANCHOR_MS + 2 * PERIOD_MS + 5;
    let demand = fixture.project_under(lane, 0);
    let seated = fixture
        .admit_at(None, "seat", lane, demand, Track::Demand, None, period_two)
        .expect("a seat in period 2 mints period 2");
    assert_eq!(seated.period.map(|period| period.index), Some(2));
    let before = fixture.line(lane);

    let back = ANCHOR_MS + PERIOD_MS + 5;
    let other = fixture.project_under(lane, 0);
    let refused = fixture
        .admit_at(None, "seat-back", lane, other, Track::Demand, None, back)
        .expect_err("the clock went back to period 1");
    assert!(
        matches!(
            refused,
            GpuLineError::Mint(MintError::BehindMintedPeriod {
                index: 1,
                newest: 2
            })
        ),
        "seen {refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
    let read = fixture
        .view(lane, back)
        .expect_err("the read refuses the same period");
    assert!(
        matches!(
            read,
            GpuLineError::Mint(MintError::BehindMintedPeriod { .. })
        ),
        "seen {read:?}"
    );
    assert_eq!(
        fixture.vault.gpu_line_period(&lane, 1).expect("read"),
        None,
        "period 1 was never minted"
    );

    // Three-fortnight periods put period 2's moment in period 0, and a later
    // anchor puts it before period 0: both would reopen a past period.
    let mut longer = policy();
    longer.period_secs = 3 * PERIOD_SECS;
    let mut later_anchor = policy();
    later_anchor.period_anchor_ms = period_two + PERIOD_MS;
    for (key, schedule) in [("set-longer", longer), ("set-later-anchor", later_anchor)] {
        let refused = fixture
            .try_set(key, lane, schedule, period_two)
            .expect_err("the schedule edit puts the clock behind period 2");
        assert!(
            matches!(refused, GpuLineError::ScheduleBehindMint { newest: 2 }),
            "{key}: seen {refused:?}"
        );
        assert_eq!(code(refused), MEMORY_CODE_INVALID_STATE);
    }
    assert_eq!(fixture.line(lane), before, "the refusals wrote nothing");
}

/// Finding 17: a seed past its bounds is refused at the seat.
#[test]
fn a_seed_past_its_bounds_is_refused() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    fixture.owner_set("set", lane, policy(), NOW_MS);
    let family = fixture.project_under(lane, 0);
    let seed = PayoffSeed {
        wins: MAX_SEED_WINS + 1,
        losses: 0,
        cost_secs: 3_600,
        weight_periods: 2,
        origin: "ledger.jsonl sha256:00".to_owned(),
    };
    let refused = fixture
        .admit_at(
            None,
            "seat",
            lane,
            family,
            Track::Demand,
            Some(seed.clone()),
            NOW_MS,
        )
        .expect_err("too many wins");
    assert!(
        matches!(refused, GpuLineError::Invalid(LineInvalid::Seed)),
        "seen {refused:?}"
    );
    assert_eq!(code(refused), MEMORY_CODE_BAD_REQUEST);
    assert!(fixture.line(lane).seat(&family).is_none());

    let seated = fixture
        .admit_at(
            None,
            "seat-bounded",
            lane,
            family,
            Track::Demand,
            Some(PayoffSeed {
                wins: MAX_SEED_WINS,
                ..seed
            }),
            NOW_MS,
        )
        .expect("a seed within its bounds seats");
    assert!(seated.line.seat(&family).is_some());
}
