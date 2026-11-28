//! `vault.planner.card`'s lane part and its line check (design pass 32 r2,
//! sections 5.1 and 5.4; test T57), through the engine door the host calls.
//!
//! - T57: the card never shows vault rows or another line as lane results.
//!   Each payoff row names its scope: a project with no receipts of its own
//!   reads the vault's rows marked `vault_prior`, never `project`; once the
//!   project has its own, every row is `project`. The `lane_arms` part lists
//!   the family's arms on its own line only: an arm of the family on another
//!   line, and an arm of another family on the line, never appear, and the
//!   refusals listed are the family's own.
//! - The line check of section 5.1: a Grant that lists the verb but holds no
//!   role on the family's line is refused `not_this_line`, through the engine
//!   door and the verb call alike; a planner's and a lead's Grant read; a
//!   Grant named a planner whose scope does not reach the line is refused;
//!   a project no line seats keeps the part 1 rule (the Grant alone).
//! - The page: 51 arms answer 50 newest first and a cursor that reads the
//!   last one.
//!
//! The rig seats every family before period 0, as `experiment_arm_admit.rs`
//! builds it: each family's floor holds exactly one first allowance.
//!
//! On the base (main c4cef1fc) the card has no lane part, no scope mark and
//! no line check, so every test fails there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test planner_card_lane_arms`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::learning_evidence::Anchor;
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ArmAdmitRequest, ArmContractAsk, ArmView, ExperimentArm, RunnerRef, arm_admit_as,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_line::{
    Bucket, BudgetPolicy, GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineSetRequest, Track,
    gpu_seconds,
};
use oneiron::memory::{MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::team::pattern::{TeamAxis, TeamPattern};
use oneiron::team::planner_card_door::{
    PLANNER_CARD_ARMS_PAGE, PLANNER_CARD_VERB, PayoffScope, PlannerCardRequest, PlannerCardView,
    planner_card_as, planner_card_as_owner,
};
use oneiron::team::receipt::{DecidedBy, TeamOutcome, TeamReceipt, TeamShape, record_team_receipt};
use oneiron::test_doors::experiment_arm_rows::put_arm;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0: every admission and every read.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// The rung-1 cap of the default policy: one first allowance.
const RUNG_1_SECS: u64 = 1_800;
/// The market left beside the floors: less than one first allowance.
const MARKET_SECS: u64 = 300;

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, and this install's live machine
/// profile, as `experiment_arm_admit.rs` builds it.
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

    /// A lane under the root whose line is set before period 0 with
    /// `roles`, and `families` demand families seated then, each with a
    /// floor of one first allowance.
    fn lane(&self, roles: &Roles, families: u64) -> (EntityId, Vec<EntityId>) {
        let lane = self.project_under(self.root(), 2);
        let owner = self.vault.memory(self.owner, EdgeActorClass::Human);
        owner
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: "set".to_owned(),
                    project: lane,
                    policy: policy(roles, families),
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
        let seated = (0..families)
            .map(|index| {
                let family = self.project_under(lane, 0);
                owner
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
            .collect();
        (lane, seated)
    }

    /// A named agent and the owner's Grant naming it, listing the card's
    /// verb (with `read`, which a Grant needs to confer) over the projects
    /// `audience` holds. Returns the agent and the Grant's id.
    fn agent(&self, name: &str, audience: ScopeAxis<ScopeId>) -> (EntityId, EntityId) {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            ["read", PLANNER_CARD_VERB]
                .into_iter()
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
        assert!(minted.grant.confers, "agent={name}");
        (agent, minted.grant.grant_ref)
    }

    /// `vault.arms.admit` as the owner at [`NOW_MS`].
    fn admit(&self, request: &ArmAdmitRequest) -> MemoryResult<ArmView> {
        arm_admit_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            request,
            NOW_MS,
        )
    }

    /// The card of `project` at the root of its tree as the owner reads it
    /// at [`NOW_MS`], from `cursor`.
    fn owner_card(&self, project: EntityId, cursor: Option<String>) -> PlannerCardView {
        let input = card_request(&self.vault, project, cursor);
        planner_card_as_owner(&self.vault, &self.owner_proof, &input, NOW_MS)
            .unwrap_or_else(|error| panic!("the owner reads the card of {input:?}: {error:?}"))
    }

    /// The card of `project` as `agent` reads it through the engine door.
    fn agent_card(&self, agent: EntityId, project: EntityId) -> MemoryResult<PlannerCardView> {
        planner_card_as(
            &self.vault.memory(agent, EdgeActorClass::Agent),
            None,
            &card_request(&self.vault, project, None),
            NOW_MS,
        )
    }

    /// One settled run of `project` (`None`: the vault's) at the card's type.
    fn record_run(&self, project: Option<EntityId>, card_project: EntityId, team_ref: &str) {
        let type_ref = card_request(&self.vault, card_project, None).type_ref;
        record_team_receipt(
            &self.vault,
            &TeamReceipt {
                team_ref: team_ref.to_owned(),
                project,
                type_ref,
                pattern: TeamPattern::Solo,
                pattern_skill: None,
                axis: TeamAxis::Converge,
                models: vec!["muse-spark-1.3".to_owned()],
                shape: TeamShape {
                    width: 1,
                    roles: BTreeMap::from([("solo".to_owned(), 1)]),
                },
                decided_by: DecidedBy::Leader { actor: self.owner },
                coverage: None,
                confessions: None,
                spend: None,
                spend_cap: None,
                elapsed_secs: 60,
                calls: None,
                outcome: Some(TeamOutcome {
                    receipt: format!("{team_ref}-outcome"),
                    anchor: Anchor::OwnerVerdict,
                    success: true,
                    at: 1,
                    critics: None,
                }),
                at: 1,
            },
        )
        .unwrap_or_else(|error| panic!("the run {team_ref} is recorded: {error:?}"));
    }

    /// The stored arm `id`.
    fn arm(&self, id: EntityId) -> ExperimentArm {
        self.vault
            .experiment_arm(&id)
            .expect("read")
            .expect("the arm")
    }

    /// A copy of arm `id` under a new id, admitted at `admitted_at_ms`, on
    /// `line` and `family`, holding no allowance; put as given.
    fn put_copy(
        &self,
        id: EntityId,
        line: EntityId,
        family: EntityId,
        admitted_at_ms: u64,
    ) -> EntityId {
        let mut arm = self.arm(id);
        arm.id = EntityId::now();
        arm.line = line;
        arm.family = family;
        arm.first_allowance = None;
        arm.admitted_at_ms = admitted_at_ms;
        put_arm(&self.vault, &arm).expect("the test door puts the arm");
        arm.id
    }
}

/// The card of `project` at the root of its tree in force, for one runner
/// model.
fn card_request(vault: &Vault, project: EntityId, cursor: Option<String>) -> PlannerCardRequest {
    let tree = oneiron::task_type::type_tree(vault, Some(project)).expect("the tree in force");
    PlannerCardRequest {
        project_ref: project.to_hex(),
        type_ref: tree.root(),
        models: vec!["muse-spark-1.3".to_owned()],
        cursor,
    }
}

/// The line's policy: `families` demand floors of one first allowance each,
/// no pinned share, no seat reserve, no new-idea pool, a market smaller than
/// one first allowance, and one rung. Every other budget number is its
/// default.
fn policy(roles: &Roles, families: u64) -> GpuLinePolicy {
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
        budget: BudgetPolicy {
            allowance_units: families * RUNG_1_SECS + MARKET_SECS,
            pinned_parts: (0, 3),
            floor_arms: 1,
            rung_caps_secs: vec![RUNG_1_SECS],
            seat_reserve_floors: 0,
            new_idea_slots_per_period: 0,
            ..BudgetPolicy::default()
        },
    }
}

/// An admission of one arm on contract number `contract` into `family` of
/// `lane`'s line.
fn ask(key: &str, lane: EntityId, family: EntityId, contract: u8) -> ArmAdmitRequest {
    ArmAdmitRequest {
        intent_key: key.to_owned(),
        line: lane,
        family,
        type_ref: TypeRef::root(1),
        title: format!("arm {key}"),
        contract: ArmContractAsk {
            path: "contracts/arm.md".to_owned(),
            sha256: format!("{contract:02x}").repeat(32),
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

/// The arm ids the card's lane part lists, in order.
fn listed(card: &PlannerCardView) -> Vec<String> {
    card.lane_arms
        .as_ref()
        .unwrap_or_else(|| panic!("expected a lane part; seen {card:?}"))
        .arms
        .iter()
        .map(|arm| arm.arm.clone())
        .collect()
}

/// T57.
#[test]
fn the_card_never_shows_vault_rows_or_another_line_as_lane_results() {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 2);
    let (family, other_family) = (families[0], families[1]);
    let own = fixture
        .admit(&ask("own", lane, family, 1))
        .expect("the family's arm fits its floor")
        .arm
        .id;
    let neighbour = fixture
        .admit(&ask("neighbour", lane, other_family, 2))
        .expect("the other family's arm fits its own floor")
        .arm
        .id;
    // The family's arm on another lane, newer than its own: it is no result
    // of this line.
    let elsewhere = fixture.project_under(fixture.root(), 2);
    let cross_line = fixture.put_copy(own, elsewhere, family, NOW_MS + 10);
    // One unmet ask of each family.
    for (key, at, contract) in [("own-2", family, 3), ("neighbour-2", other_family, 4)] {
        let refused = fixture
            .admit(&ask(key, lane, at, contract))
            .expect_err("the floor holds one first allowance");
        assert_eq!(refused.code, MEMORY_CODE_BUDGET_SPENT, "{refused:?}");
    }
    fixture.record_run(None, family, "vault-run");

    let card = fixture.owner_card(family, None);
    let lane_arms = card.lane_arms.as_ref().expect("the line seats the family");
    assert_eq!(lane_arms.line, lane.to_hex(), "seen {lane_arms:?}");
    assert_eq!((lane_arms.track, lane_arms.seated), (Track::Demand, true));
    assert_eq!(
        listed(&card),
        vec![own.to_hex()],
        "expected the family's own arm on this line only, not {cross_line:?} (another line) or {neighbour:?} (another family)"
    );
    assert_eq!(lane_arms.next_cursor, None);
    assert_eq!(
        lane_arms
            .refusals
            .iter()
            .map(|refusal| refusal.family)
            .collect::<Vec<_>>(),
        vec![family],
        "expected the family's one refusal and not its neighbour's; seen {:?}",
        lane_arms.refusals
    );
    let room = lane_arms.room.as_ref().expect("period 0 holds now");
    assert_eq!((room.period, room.minted), (0, true), "seen {room:?}");
    let floor = room
        .buckets
        .iter()
        .find(|bucket| bucket.bucket == Bucket::Floor { family })
        .unwrap_or_else(|| panic!("expected the family's floor; seen {room:?}"));
    assert_eq!(
        (floor.capacity, floor.used, floor.left),
        (RUNG_1_SECS, RUNG_1_SECS, 0),
        "expected the own arm's live hold to fill the floor; seen {floor:?}"
    );
    assert!(
        !card.payoff_rows.is_empty(),
        "expected the vault's run as a prior; seen {card:?}"
    );
    for row in &card.payoff_rows {
        assert_eq!(
            (row.scope, row.project_ref.as_deref()),
            (PayoffScope::VaultPrior, None),
            "expected a vault row to be marked a prior, never the project's; seen {row:?}"
        );
    }
    assert!(!card.lane_arms_train_patterns);

    let neighbours = fixture.owner_card(other_family, None);
    assert_eq!(
        listed(&neighbours),
        vec![neighbour.to_hex()],
        "expected the other family's card to list its own arm only"
    );

    fixture.record_run(Some(family), family, "family-run");
    let card = fixture.owner_card(family, None);
    assert!(!card.payoff_rows.is_empty(), "seen {card:?}");
    let family_hex = family.to_hex();
    for row in &card.payoff_rows {
        assert_eq!(
            (row.scope, row.project_ref.as_deref()),
            (PayoffScope::Project, Some(family_hex.as_str())),
            "expected only the project's own rows once it has runs; seen {row:?}"
        );
    }
}

/// Section 5.1: the card of a seated family needs a role on its line.
#[test]
fn a_grant_without_a_role_on_the_family_line_is_refused_the_card() {
    let fixture = fixture();
    let (planner, planner_grant) = fixture.agent("card-planner", ScopeAxis::All);
    let (lead, lead_grant) = fixture.agent("card-lead", ScopeAxis::All);
    let (stranger, _) = fixture.agent("card-stranger", ScopeAxis::All);
    let unrelated = fixture.project_under(fixture.root(), 0);
    let (narrow, narrow_grant) = fixture.agent(
        "card-narrow-planner",
        ScopeAxis::Some(BTreeSet::from([ScopeId(unrelated)])),
    );
    let roles = Roles {
        leads: vec![lead_grant],
        planners: vec![planner_grant, narrow_grant],
    };
    let (_, families) = fixture.lane(&roles, 1);
    let family = families[0];

    let refused = fixture
        .agent_card(stranger, family)
        .expect_err("a Grant with no role on the line");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains("not_this_line"),
        "expected not_this_line; seen {refused:?}"
    );
    let by_verb = invoke(
        &fixture.vault.memory(stranger, EdgeActorClass::Agent),
        PLANNER_CARD_VERB,
        serde_json::to_value(card_request(&fixture.vault, family, None))
            .expect("the card request encodes"),
    );
    match by_verb {
        Err(error) => assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}"),
        Ok(card) => panic!("expected the verb call refused too; seen {card}"),
    }
    let refused = fixture
        .agent_card(narrow, family)
        .expect_err("a planner Grant whose scope does not reach the line");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains("not_this_line"),
        "a Grant that does not reach the line's project is refused not_this_line; seen {refused:?}"
    );

    let owner = fixture.owner_card(family, None);
    for (agent, role) in [(planner, "planner"), (lead, "lead")] {
        let card = fixture
            .agent_card(agent, family)
            .unwrap_or_else(|error| panic!("the {role}'s Grant reads the card: {error:?}"));
        assert!(card.lane_arms.is_some(), "the {role} reads the lane part");
        assert_eq!(
            card.digest, owner.digest,
            "the {role} reads the owner's card"
        );
    }

    let plain = fixture.project_under(fixture.root(), 0);
    let card = fixture
        .agent_card(stranger, plain)
        .unwrap_or_else(|error| panic!("a project no line seats keeps the Grant rule: {error:?}"));
    assert_eq!(card.lane_arms, None, "seen {card:?}");
}

/// The lane part pages the family's arms, newest first.
#[test]
fn the_card_pages_the_family_arms_newest_first() {
    let fixture = fixture();
    let (lane, families) = fixture.lane(&Roles::default(), 1);
    let family = families[0];
    let first = fixture
        .admit(&ask("first", lane, family, 1))
        .expect("the family's arm fits its floor")
        .arm
        .id;
    let page_size = u64::try_from(PLANNER_CARD_ARMS_PAGE).expect("a page size fits u64");
    let newer: Vec<EntityId> = (1..=page_size)
        .map(|step| fixture.put_copy(first, lane, family, NOW_MS + step))
        .collect();

    let page = fixture.owner_card(family, None);
    let expected: Vec<String> = newer.iter().rev().map(EntityId::to_hex).collect();
    assert_eq!(
        listed(&page),
        expected,
        "expected the 50 newest, newest first"
    );
    let cursor = page
        .lane_arms
        .as_ref()
        .and_then(|lane_arms| lane_arms.next_cursor.clone())
        .expect("a 51st arm leaves a next page");

    let rest = fixture.owner_card(family, Some(cursor));
    assert_eq!(
        listed(&rest),
        vec![first.to_hex()],
        "the oldest arm is last"
    );
    assert_eq!(
        rest.lane_arms.and_then(|lane_arms| lane_arms.next_cursor),
        None
    );

    let input = card_request(&fixture.vault, family, Some("not-a-cursor".to_owned()));
    assert!(
        planner_card_as_owner(&fixture.vault, &fixture.owner_proof, &input, NOW_MS).is_err(),
        "a cursor the card did not answer is refused"
    );
}
