//! The comparison's cohorts (design pass 32 r2, section 4.4; row M2-G part
//! G2) through the engine acts the host doors call.
//!
//! - T28: an arm keeps its cohort when the other half has room. Its first
//!   allowance draws only its own rule's table; when that table is spent,
//!   the admission is refused `budget_denied` and its `GPU_LINE_REFUSAL` row
//!   names the cohort, while the family's ceiling in the other half stays
//!   whole and undrawn.
//! - T56 (the door half): a cohort is fixed at admission and reads no room.
//!   The ask at admission position `p` of (period, track) takes
//!   `cohort_rule(period, track, p)` and the block `(period, p)`, and an ask
//!   refused for budget keeps its position. Two lines with other ceilings
//!   and other first allowances give every ask the cohort of its position
//!   under their own seed. The get view withholds the seed while the period
//!   runs.
//! - An arm still open when the comparison turns on is assigned at that
//!   mint, in admission order, and a later admission takes the next
//!   position; a closed arm gets no cohort.
//! - A re-run keeps its predecessor's cohort and takes no position.
//!
//! The rig seats two demand families before period 0, with no floor, no
//! pinned share, no seat reserve and no new-idea pool, so a first allowance
//! draws the market only. With two rules each half is split between the two
//! families, so each family's ceiling in each half is one first allowance.
//!
//! On the base (G1 #10442 merged with #10455) no admission or mint assigns
//! a cohort, so every test fails there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test gpu_line_cohort`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ArmAdmitRequest, ArmContractAsk, ArmState, ArmView, ExperimentArm, HoldEndCause, RungEnd,
    RungState, RunnerRef, arm_admit_as,
};
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    Bucket, BudgetPolicy, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePeriod,
    GpuLinePolicy, GpuLineSetRequest, LineRefusal, RuleRef, Track, cohort_rule, cohort_seed_commit,
    gpu_seconds, line_refusals_in_txn, mint_first_in_txn,
};
use oneiron::memory::{MEMORY_CODE_BUDGET_SPENT, MemoryResult};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::experiment_arm_rows::put_arm;
use oneiron::test_doors::gpu_line_hold_is_the_claim::read_txn;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// The rung-1 cap: one first allowance.
const RUNG_1_SECS: u64 = 1_800;
/// An allowance whose two halves give each of two families one first
/// allowance per half.
const TIGHT_ALLOWANCE: u64 = 4 * RUNG_1_SECS;
/// The comparison: the starter and its default rival.
const TWO_RULES: [RuleRef; 2] = [RuleRef::PAYOFF_SHARE_1, RuleRef::EVEN_SPLIT_1];

/// A moment inside period `index`.
fn in_period(index: u64) -> u64 {
    ANCHOR_MS + index * PERIOD_MS + 5
}

/// A rooted vault with its embedded owner bound to the host and the owner's
/// proof, as `experiment_arm_admit.rs` builds it.
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

/// The line's policy: `rules` in force over `allowance_units`, one rung of
/// `rung_1_secs`, no floor, no pinned share, no seat reserve and no
/// new-idea pool. Every other budget number is its default.
fn policy(rules: &[RuleRef], allowance_units: u64, rung_1_secs: u64) -> GpuLinePolicy {
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
        budget: BudgetPolicy {
            allowance_units,
            pinned_parts: (0, 3),
            floor_arms: 0,
            rung_caps_secs: vec![rung_1_secs],
            seat_reserve_floors: 0,
            new_idea_slots_per_period: 0,
            rules: rules.to_vec(),
            ..BudgetPolicy::default()
        },
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

    /// The owner sets `lane`'s line to `policy` at `now_ms`.
    fn set_line(&self, key: &str, lane: EntityId, policy: GpuLinePolicy, now_ms: u64) {
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
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
    }

    /// A lane under the root whose line the owner sets to `policy` before
    /// period 0, with two demand families seated then.
    fn lane(&self, policy: GpuLinePolicy) -> (EntityId, [EntityId; 2]) {
        let lane = self.project_under(self.vault.root_project().expect("root project"), 2);
        self.set_line("set", lane, policy, BEFORE_MS);
        let families = [0, 1].map(|index| {
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
        });
        (lane, families)
    }

    /// Mints the record of the period of `lane`'s line that holds `now_ms`
    /// (the first write of every door does this), and answers it.
    fn mint(&self, lane: EntityId, now_ms: u64) -> GpuLinePeriod {
        self.vault
            .with_write_txn(|txn| mint_first_in_txn(&self.vault, txn, &lane, now_ms))
            .expect("the mint's write")
            .expect("the line mints")
            .expect("the line is set")
            .period
            .expect("the period has begun")
    }

    /// `vault.arms.admit` as the owner at `now_ms`.
    fn admit_at(&self, request: &ArmAdmitRequest, now_ms: u64) -> MemoryResult<ArmView> {
        arm_admit_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            request,
            now_ms,
        )
    }

    /// The refusal rows of `lane`'s line in period `period`, in order.
    fn refusals(&self, lane: EntityId, period: u32) -> Vec<LineRefusal> {
        let txn = read_txn(&self.vault).expect("read snapshot");
        line_refusals_in_txn(&self.vault, &txn, &lane, period)
            .expect("read refusal rows")
            .into_iter()
            .map(|(_, refusal)| refusal)
            .collect()
    }

    /// The stored arm `id`.
    fn arm(&self, id: EntityId) -> ExperimentArm {
        self.vault
            .experiment_arm(&id)
            .expect("read")
            .expect("the arm")
    }

    /// Stands arm `id` where row M2-E's kill leaves it at `at_ms`: rung 1
    /// closed `Killed`, the arm killed and its hold ended.
    fn kill(&self, id: EntityId, at_ms: u64) {
        let mut arm = self.arm(id);
        arm.rungs[0].state = RungState::Closed {
            end: RungEnd::Killed,
        };
        arm.state = ArmState::Killed;
        arm.end_hold(at_ms, HoldEndCause::RungClosed);
        arm.revision += 1;
        put_arm(&self.vault, &arm).expect("the test door puts the arm");
    }
}

/// The contract sha256 numbered `contract`.
fn contract_sha(contract: u8) -> String {
    format!("{contract:02x}").repeat(32)
}

/// An admission of one arm on contract number `contract` into `family` of
/// `lane`'s line.
fn ask(key: &str, lane: EntityId, family: EntityId, contract: u8) -> ArmAdmitRequest {
    ArmAdmitRequest {
        intent_key: key.to_owned(),
        line: lane,
        family,
        type_ref: TypeRef::root(1),
        title: format!("arm on contract {contract}"),
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

/// The rule of the demand arm at `position` in `period`'s comparison.
fn rule_at(period: &GpuLinePeriod, position: u32) -> RuleRef {
    cohort_rule(period, Track::Demand, position).expect("a two-rule period assigns a cohort")
}

/// T28.
#[test]
fn an_arm_keeps_its_cohort_when_the_other_half_has_room() {
    let fx = fixture();
    let (lane, [first, second]) = fx.lane(policy(&TWO_RULES, TIGHT_ALLOWANCE, RUNG_1_SECS));
    let period = fx.mint(lane, NOW_MS);
    let own = rule_at(&period, 0);
    let other = *TWO_RULES
        .iter()
        .find(|rule| **rule != own)
        .expect("two rules in force");
    for family in [first, second] {
        for rule in TWO_RULES {
            assert_eq!(
                period.ceiling_of(&family, rule),
                RUNG_1_SECS,
                "each family's ceiling in each half is one first allowance"
            );
        }
    }

    // The first block holds two arms of each rule. Every ask of `own`'s
    // positions is the first family's, every other one the second's, so the
    // first family's ceiling in the other half is never asked for.
    let mut asked = Vec::new();
    for position in 0..4u32 {
        let rule = rule_at(&period, position);
        let family = if rule == own { first } else { second };
        let contract = u8::try_from(position + 1).expect("a small contract number");
        let answer = fx.admit_at(
            &ask(&format!("arm-{position}"), lane, family, contract),
            NOW_MS,
        );
        asked.push((position, rule, family, answer));
    }

    let mut admitted_of_first = Vec::new();
    for (position, rule, family, answer) in &asked {
        let earlier_of_rule = asked
            .iter()
            .filter(|(at, ruled, _, _)| at < position && ruled == rule)
            .count();
        if earlier_of_rule == 0 {
            let view = answer
                .as_ref()
                .unwrap_or_else(|error| panic!("position {position} fits its half: {error:?}"));
            let arm = fx.arm(view.arm.id);
            assert_eq!(arm.cohort, Some(*rule), "position {position}");
            assert_eq!(arm.cohort_block, Some((0, *position)));
            let hold = arm.first_allowance.as_ref().expect("a first allowance");
            assert_eq!(
                hold.draws,
                vec![Draw {
                    source: DrawSource::Market { rule: *rule },
                    units: RUNG_1_SECS,
                }],
                "the hold draws its own rule's table only"
            );
            if *family == first {
                admitted_of_first.push(arm);
            }
        } else {
            let error = answer
                .as_ref()
                .expect_err("the second ask of a rule finds its half spent");
            assert_eq!(error.code, MEMORY_CODE_BUDGET_SPENT, "{error:?}");
            assert!(error.message.contains("budget_denied"), "{error:?}");
        }
    }
    assert_eq!(
        admitted_of_first.len(),
        1,
        "one arm of the first family fits"
    );

    let refusals = fx.refusals(lane, 0);
    assert_eq!(refusals.len(), 2, "one refusal row per refused admission");
    let of_first = refusals
        .iter()
        .find(|refusal| refusal.family == first)
        .expect("the first family's refusal row");
    assert_eq!(of_first.arm, None, "an admission refusal has no arm yet");
    assert_eq!(of_first.rung, 1);
    assert_eq!(of_first.cohort, Some(own), "the refusal names the cohort");
    assert_eq!(of_first.asked_secs, RUNG_1_SECS);
    assert_eq!(
        of_first.short,
        Some(Bucket::Market {
            family: first,
            rule: own,
        }),
        "its own half ran out"
    );
    assert_eq!(of_first.room, 0, "the other half is not drawn");
    assert_eq!(of_first.reason, "budget_denied");
    let of_second = refusals
        .iter()
        .find(|refusal| refusal.family == second)
        .expect("the second family's refusal row");
    assert_eq!(of_second.cohort, Some(other));

    // The first family's ceiling in the other half was whole the whole time:
    // no hold of the family draws it.
    assert_eq!(period.ceiling_of(&first, other), RUNG_1_SECS);
    for arm in &admitted_of_first {
        let hold = arm.first_allowance.as_ref().expect("a first allowance");
        assert!(
            hold.draws
                .iter()
                .all(|draw| draw.source != DrawSource::Market { rule: other }),
            "the other half is never drawn: {hold:?}"
        );
    }
}

/// Admits eight asks into `lane`, alternating its two families, and checks
/// that each takes the cohort and block of its admission position under
/// `period`'s seed, refused or not. Answers how many were refused.
fn admit_in_order(
    fx: &Fixture,
    lane: EntityId,
    families: [EntityId; 2],
    period: &GpuLinePeriod,
) -> usize {
    let mut refusals_seen = 0;
    for position in 0..8u32 {
        let family = families[(position % 2) as usize];
        let contract = u8::try_from(position + 1).expect("a small contract number");
        let rule = rule_at(period, position);
        match fx.admit_at(
            &ask(&format!("arm-{position}"), lane, family, contract),
            NOW_MS,
        ) {
            Ok(view) => {
                assert_eq!(view.arm.cohort, Some(rule), "the arm view shows the cohort");
                let arm = fx.arm(view.arm.id);
                assert_eq!(arm.cohort, Some(rule), "position {position}");
                assert_eq!(arm.cohort_block, Some((period.index, position)));
            }
            Err(error) => {
                assert_eq!(error.code, MEMORY_CODE_BUDGET_SPENT, "{error:?}");
                let refusals = fx.refusals(lane, period.index);
                assert_eq!(refusals.len(), refusals_seen + 1, "one row per refusal");
                let refusal = refusals.last().expect("this refusal's row");
                assert_eq!(refusal.family, family);
                assert_eq!(
                    refusal.cohort,
                    Some(rule),
                    "a refused ask keeps the cohort of its position {position}"
                );
                refusals_seen += 1;
            }
        }
    }
    refusals_seen
}

/// T56, the door half.
#[test]
fn a_cohort_is_fixed_at_admission_and_reads_no_room() {
    let tight = fixture();
    let (tight_lane, tight_families) = tight.lane(policy(&TWO_RULES, TIGHT_ALLOWANCE, RUNG_1_SECS));
    let tight_period = tight.mint(tight_lane, NOW_MS);
    let refused = admit_in_order(&tight, tight_lane, tight_families, &tight_period);
    assert!(
        refused >= 4,
        "each family fits one first allowance per half, so at least four of eight asks are refused: {refused}"
    );

    // Other ceilings and another first allowance: nothing is refused, and
    // every ask still takes the cohort of its position.
    let roomy = fixture();
    let (roomy_lane, roomy_families) =
        roomy.lane(policy(&TWO_RULES, 40 * TIGHT_ALLOWANCE, 2 * RUNG_1_SECS));
    let roomy_period = roomy.mint(roomy_lane, NOW_MS);
    assert_eq!(
        admit_in_order(&roomy, roomy_lane, roomy_families, &roomy_period),
        0,
        "every ask fits"
    );

    // The seed stays hidden while the period runs; its commit is shown.
    let seed = tight_period
        .cohort_seed
        .expect("a two-rule mint draws a seed");
    let shown = tight
        .vault
        .memory(tight.owner, EdgeActorClass::Human)
        .gpu_line_view(Some(&tight.owner_proof), &tight_lane, NOW_MS)
        .expect("the owner reads the line")
        .period
        .expect("the view has period 0");
    assert_eq!(shown.cohort_seed, None, "the get view withholds the seed");
    assert_eq!(shown.cohort_seed_commit, Some(cohort_seed_commit(&seed)));
}

#[test]
fn an_arm_open_when_the_comparison_turns_on_is_assigned_at_that_mint() {
    let fx = fixture();
    let (lane, [first, second]) = fx.lane(policy(
        &[RuleRef::PAYOFF_SHARE_1],
        TIGHT_ALLOWANCE,
        RUNG_1_SECS,
    ));
    let mut admitted = Vec::new();
    for (index, family) in [first, second, first].into_iter().enumerate() {
        let contract = u8::try_from(index + 1).expect("a small contract number");
        let view = fx
            .admit_at(
                &ask(&format!("arm-{index}"), lane, family, contract),
                NOW_MS,
            )
            .unwrap_or_else(|error| panic!("arm {index} fits the one-rule market: {error:?}"));
        assert_eq!(view.arm.cohort, None, "one rule in force: no cohort");
        assert_eq!(view.arm.cohort_block, None);
        admitted.push(view.arm.id);
    }
    fx.kill(admitted[1], NOW_MS + 10);

    // The owner turns the comparison on; it takes effect at the next mint.
    fx.set_line(
        "set-two",
        lane,
        policy(&TWO_RULES, TIGHT_ALLOWANCE, RUNG_1_SECS),
        NOW_MS + 20,
    );
    let current = fx.mint(lane, NOW_MS + 30);
    assert_eq!(current.index, 0);
    assert_eq!(current.tables.len(), 1, "period 0 keeps its one rule");
    assert_eq!(fx.arm(admitted[0]).cohort, None);

    let next = fx.mint(lane, in_period(1));
    assert_eq!(next.tables.len(), 2, "period 1 runs the comparison");
    let open_first = fx.arm(admitted[0]);
    assert_eq!(open_first.cohort, Some(rule_at(&next, 0)));
    assert_eq!(open_first.cohort_block, Some((1, 0)));
    let open_last = fx.arm(admitted[2]);
    assert_eq!(open_last.cohort, Some(rule_at(&next, 1)), "admission order");
    assert_eq!(open_last.cohort_block, Some((1, 1)));
    let closed = fx.arm(admitted[1]);
    assert_eq!(closed.cohort, None, "a closed arm gets no cohort");
    assert_eq!(closed.cohort_block, None);

    // A later admission takes the next position of the period.
    let view = fx
        .admit_at(&ask("arm-late", lane, second, 9), in_period(1))
        .expect("the second family's half has room");
    assert_eq!(view.arm.cohort, Some(rule_at(&next, 2)));
    assert_eq!(view.arm.cohort_block, Some((1, 2)));
}

#[test]
fn a_rerun_keeps_its_predecessors_cohort_and_takes_no_position() {
    let fx = fixture();
    let (lane, [first, second]) = fx.lane(policy(&TWO_RULES, TIGHT_ALLOWANCE, RUNG_1_SECS));
    let period = fx.mint(lane, NOW_MS);
    let predecessor = fx
        .admit_at(&ask("arm-0", lane, first, 1), NOW_MS)
        .expect("the first arm fits its half")
        .arm;
    assert_eq!(predecessor.cohort, Some(rule_at(&period, 0)));
    fx.kill(predecessor.id, NOW_MS + 10);

    let mut rerun_ask = ask("arm-rerun", lane, first, 1);
    rerun_ask.supersedes = Some(predecessor.id);
    let rerun = fx
        .admit_at(&rerun_ask, NOW_MS + 20)
        .expect("a re-run is admitted with no hold")
        .arm;
    assert_eq!(
        rerun.cohort, predecessor.cohort,
        "the experiment keeps its cohort"
    );
    assert_eq!(rerun.cohort_block, None, "a re-run takes no position");
    assert_eq!(rerun.first_allowance, None, "a re-run gets no hold");

    let next = fx
        .admit_at(&ask("arm-1", lane, second, 2), NOW_MS + 30)
        .expect("the second family's half has room")
        .arm;
    assert_eq!(next.cohort, Some(rule_at(&period, 1)));
    assert_eq!(
        next.cohort_block,
        Some((0, 1)),
        "the re-run took no position"
    );
}
