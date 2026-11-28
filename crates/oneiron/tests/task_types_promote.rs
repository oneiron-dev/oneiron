//! The owner's pinned task-type tree goes in force at once (lead
//! COORD-E2E-TREE-PIN = A, 24 Nov 2026 22:45; ARCH-0079 #seed-pin: the
//! owner's pin is fixed, a seed of infinite weight).
//!
//! - `vault.task_types.pin` stores a changed tree on an open team-shape fork
//!   at a new skill version of that fork. Red on main: the fork kept skill
//!   version "1" while its package changed, and the update door refused it
//!   ("version must change when updating skill body").
//! - `vault.task_types.promote` puts that tree in force for the vault in one
//!   write: a new revision of the team-shape head, owner-pinned, which
//!   supersedes the head. No gate scores it.
//! - A promote takes only the tree the owner's pin stored on the fork, as it
//!   stored it: not the seed a fresh fork copies, nor a tree another writer
//!   stored there after the pin. Red with the stage check undone: both
//!   promoted.
//! - The same tree pinned again after a version clash keeps the version its
//!   first pin stored, so the first receipt still promotes. Red with the
//!   version reuse undone: the retry stored the next version.
//! - The Coach's gate, on an admitting ruling over a pinned head, puts
//!   nothing in force, and answers the proposal so the Coach's next one is
//!   not held behind it. Red with the answer undone: the proposal stayed
//!   open.
//! - The owner reverts through the same door: a third revision carries the
//!   earlier tree, and the pinned tree's version still reads from the chain.
//!
//! The team-shape head is the shipped skill, seeded as a later engine's open
//! seeds it (`seed_bootstrap_skills_adding`), with its seeded tree.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_types_promote`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{
    load_team_type_tree, load_team_type_tree_at, store_team_type_tree, team_shape_skill,
    team_shape_skill_in_force,
};
use oneiron::claim::ClaimApprovalStatus;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::maintenance::type_tree_upkeep::TreeGateOutcome;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_optimize::SkillEditDisposition;
use oneiron::store::GateDecisionId;
use oneiron::task_type::TaskTypeTree;
use oneiron::team::doors::{pin_tree_as, promote_tree_as};
use oneiron::team::{TaskTypeNodeSpec, TaskTypeTreePin, TaskTypeTreePromote};
use oneiron::test_doors::bootstrap_skills::seed_bootstrap_skills_adding;
use oneiron::test_doors::team_tree_promote::{coach_proposal_over, coach_tree_gate_last_step};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The shipped team-shape skill.
const TEAM_SHAPE: &str = include_str!("../../../skills/team-shape/SKILL.md");

fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The seeded team-shape head.
    head: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A vault whose team-shape head is the shipped skill with its seeded
    /// tree.
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        seed_bootstrap_skills_adding(&vault, &[("team-shape", TEAM_SHAPE)])
            .map_err(at("seed team-shape"))?;
        let head = team_shape_skill().map_err(at("team-shape id"))?;
        assert_eq!(
            team_shape_skill_in_force(&vault, None).map_err(at("head"))?,
            Some(head),
            "the seeded team-shape skill is the vault head"
        );
        Ok(Self {
            vault,
            owner,
            head,
            _dir: dir,
        })
    }

    fn owner(&self) -> TestResult<AuthenticatedOwner> {
        Ok(self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .map_err(at("owner proof"))?)
    }

    fn record(&self, id: &EntityId) -> TestResult<SkillRecord> {
        Ok(self
            .vault
            .get_skill_record(id)
            .map_err(at("skill read"))?
            .ok_or("the skill record is missing")?)
    }

    fn in_force(&self) -> TestResult<EntityId> {
        Ok(team_shape_skill_in_force(&self.vault, None)
            .map_err(at("head in force"))?
            .ok_or("no team-shape head in force")?)
    }

    /// An open fork, named `skill_id`, of the head in force.
    fn fork(&self, skill_id: &str) -> TestResult<EntityId> {
        let fork = EntityId::now();
        self.vault
            .fork_skill_record(
                &self.in_force()?,
                &fork,
                skill_id,
                TimeRange { start: 1, end: 1 },
                1,
            )
            .map_err(at("fork"))?;
        Ok(fork)
    }

    /// The owner's pin of a tree with one child `child` under the root on
    /// `fork`, at the version above the seed's: the version stored.
    fn pin(&self, fork: EntityId, child: &str) -> TestResult<u64> {
        Ok(self
            .pin_at(fork, TaskTypeTree::seeded().version + 1, child)?
            .0)
    }

    /// The owner's pin of a tree with one child `child` under the root on
    /// `fork`, at `tree_version`: the version stored, and the version
    /// requested when the pin stored another.
    fn pin_at(
        &self,
        fork: EntityId,
        tree_version: u64,
        child: &str,
    ) -> TestResult<(u64, Option<u64>)> {
        let receipt = pin_tree_as(
            &self.vault,
            &self.owner()?,
            TaskTypeTreePin {
                fork_ref: fork,
                tree_version,
                nodes: nodes(child),
                project_ref: None,
            },
        )
        .map_err(at("pin"))?;
        assert_eq!(receipt.in_force, Some(false), "a pin stores a candidate");
        Ok((receipt.stored.tree_version, receipt.requested_tree_version))
    }

    /// The owner's promote of `input`.
    fn promote(
        &self,
        input: TaskTypeTreePromote,
    ) -> TestResult<oneiron::team::TaskTypeTreePromoteReceipt> {
        Ok(promote_tree_as(&self.vault, &self.owner()?, input).map_err(at("promote"))?)
    }
}

/// A root and one child `child` under it.
fn nodes(child: &str) -> Vec<TaskTypeNodeSpec> {
    vec![
        TaskTypeNodeSpec {
            node_id: "root".to_owned(),
            parent: None,
            name: "Any task".to_owned(),
        },
        TaskTypeNodeSpec {
            node_id: child.to_owned(),
            parent: Some("root".to_owned()),
            name: format!("{child} work"),
        },
    ]
}

fn pinned(fork: EntityId, tree_version: u64) -> TaskTypeTreePromote {
    TaskTypeTreePromote {
        fork_ref: Some(fork),
        tree_version: Some(tree_version),
        restore_ref: None,
    }
}

fn restore(revision: EntityId) -> TaskTypeTreePromote {
    TaskTypeTreePromote {
        fork_ref: None,
        tree_version: None,
        restore_ref: Some(revision),
    }
}

#[test]
fn a_changed_tree_pins_onto_its_fork_at_a_new_skill_version() -> TestResult {
    let fx = Fixture::open()?;
    let fork = fx.fork("team-shape-owner-staging")?;
    let born = fx.record(&fork)?.version;
    let stored = fx.pin(fork, "research")?;
    assert_eq!(stored, TaskTypeTree::seeded().version + 1);
    let after = fx.record(&fork)?;
    assert_ne!(
        after.version, born,
        "a changed tree moves the fork's skill version"
    );
    assert_eq!(after.lifecycle_status, SkillLifecycle::Candidate);
    fx.pin(fork, "research")?;
    assert_eq!(
        fx.record(&fork)?.version,
        after.version,
        "the same tree stored again keeps the version"
    );
    assert_eq!(fx.in_force()?, fx.head, "a pin puts nothing in force");
    Ok(())
}

#[test]
fn the_owners_pin_is_in_force_at_once() -> TestResult {
    let fx = Fixture::open()?;
    let fork = fx.fork("team-shape-owner-staging")?;
    let stored = fx.pin(fork, "research")?;
    let receipt = fx.promote(pinned(fork, stored))?;
    assert_eq!(receipt.superseded_skill_ref, fx.head);
    assert_ne!(receipt.in_force_skill_ref, fx.head);
    assert_eq!(fx.in_force()?, receipt.in_force_skill_ref);
    assert_eq!(receipt.tree.tree_version, stored);
    let tree = load_team_type_tree(&fx.vault, None).map_err(at("tree in force"))?;
    assert_eq!(tree.version, stored);
    assert!(tree.nodes.contains_key("research"), "{tree:?}");
    let head = fx.record(&receipt.in_force_skill_ref)?;
    let old = fx.record(&fx.head)?;
    assert_eq!(head.skill_id, old.skill_id, "a revision of the same skill");
    assert_ne!(head.version, old.version);
    assert_eq!(head.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(head.approval_status, ClaimApprovalStatus::Approved);
    assert_eq!(head.governance_tier, old.governance_tier);
    assert_eq!(old.lifecycle_status, SkillLifecycle::Superseded);
    assert_eq!(
        fx.record(&fork)?.lifecycle_status,
        SkillLifecycle::Candidate,
        "the staging fork is never put in force itself"
    );
    Ok(())
}

#[test]
fn a_promote_takes_only_the_version_the_pin_stored() -> TestResult {
    let fx = Fixture::open()?;
    let fork = fx.fork("team-shape-owner-staging")?;
    let stored = fx.pin(fork, "research")?;
    let owner = fx.owner()?;
    assert!(promote_tree_as(&fx.vault, &owner, pinned(fork, stored + 1)).is_err());
    let neither = TaskTypeTreePromote {
        fork_ref: Some(fork),
        tree_version: None,
        restore_ref: None,
    };
    assert!(promote_tree_as(&fx.vault, &owner, neither).is_err());
    assert!(promote_tree_as(&fx.vault, &owner, restore(fx.head)).is_err());
    assert_eq!(fx.in_force()?, fx.head, "a refused promote changes nothing");
    Ok(())
}

#[test]
fn a_promote_takes_only_the_tree_the_owners_pin_stored() -> TestResult {
    let fx = Fixture::open()?;
    let owner = fx.owner()?;
    let seed = TaskTypeTree::seeded().version;
    // A fresh fork holds the seed its birth copied; no pin stored it.
    let fork = fx.fork("team-shape-owner-staging")?;
    assert!(
        promote_tree_as(&fx.vault, &owner, pinned(fork, seed)).is_err(),
        "a fork's copied seed is not the owner's pin"
    );
    // A tree another writer (the Coach's fork store) puts on the fork after
    // the owner's pin is not the owner's either.
    let stored = fx.pin(fork, "research")?;
    let written = store_team_type_tree(&fx.vault, fork, &TaskTypeTree::seeded(), None, 20)
        .map_err(at("another writer's store"))?;
    assert_eq!(written, seed);
    assert!(
        promote_tree_as(&fx.vault, &owner, pinned(fork, written)).is_err(),
        "a tree stored after the pin is not the owner's"
    );
    assert!(
        promote_tree_as(&fx.vault, &owner, pinned(fork, stored)).is_err(),
        "the pinned version no longer names the fork's tree"
    );
    assert_eq!(fx.in_force()?, fx.head, "a refused promote changes nothing");
    // The owner's pin again stages the fork's tree, and it promotes.
    let again = fx.pin(fork, "research")?;
    let receipt = fx.promote(pinned(fork, again))?;
    assert_eq!(fx.in_force()?, receipt.in_force_skill_ref);
    Ok(())
}

#[test]
fn a_retried_pin_after_a_clash_keeps_its_stored_version() -> TestResult {
    let fx = Fixture::open()?;
    let fork = fx.fork("team-shape-owner-staging")?;
    let seed = TaskTypeTree::seeded().version;
    // The seed holds the requested version with another structure.
    let (stored, requested) = fx.pin_at(fork, seed, "research")?;
    assert_eq!(requested, Some(seed), "the pin clashed with the seed");
    assert!(stored > seed);
    let skill_version = fx.record(&fork)?.version;
    let (again, requested) = fx.pin_at(fork, seed, "research")?;
    assert_eq!(
        again, stored,
        "the same tree pinned again keeps the version its first pin stored"
    );
    assert_eq!(requested, Some(seed));
    assert_eq!(
        fx.record(&fork)?.version,
        skill_version,
        "the same tree stored again keeps the fork's skill version"
    );
    let receipt = fx.promote(pinned(fork, stored))?;
    assert_eq!(
        receipt.tree.tree_version, stored,
        "the first receipt promotes"
    );
    Ok(())
}

#[test]
fn a_later_coach_win_over_the_pin_only_proposes() -> TestResult {
    let fx = Fixture::open()?;
    let fork = fx.fork("team-shape-owner-staging")?;
    let stored = fx.pin(fork, "research")?;
    let pinned_head = fx.promote(pinned(fork, stored))?.in_force_skill_ref;
    let revision = coach_proposal_over(&fx.vault, &pinned_head, 10).map_err(at("proposal"))?;
    assert_eq!(
        fx.record(&revision)?.approval_status,
        ClaimApprovalStatus::Proposed,
        "the Coach's revision is born an open proposal"
    );
    let outcome = coach_tree_gate_last_step(
        &fx.vault,
        &revision,
        &pinned_head,
        SkillEditDisposition::Accepted,
        10,
    )
    .map_err(at("gate over the pin"))?;
    assert_eq!(
        outcome,
        TreeGateOutcome::Ruled(SkillEditDisposition::Accepted)
    );
    assert_eq!(fx.in_force()?, pinned_head, "the pin stays in force");
    let answered = fx.record(&revision)?;
    assert_eq!(
        answered.lifecycle_status,
        SkillLifecycle::Candidate,
        "the Coach's revision never goes in force"
    );
    assert_eq!(
        answered.approval_status,
        ClaimApprovalStatus::Rejected,
        "the ruling answered it, so the Coach's next proposal is not held behind it"
    );
    assert!(
        load_team_type_tree(&fx.vault, None)
            .map_err(at("tree in force"))?
            .nodes
            .contains_key("research")
    );
    // Control: over an unpinned head the same step goes on to the
    // optimizer admission, which refuses this revision; the pin is what
    // ruled above.
    let control = Fixture::open()?;
    let revision = control.fork("team-shape-coach-revision")?;
    let outcome = coach_tree_gate_last_step(
        &control.vault,
        &revision,
        &control.head,
        SkillEditDisposition::Accepted,
        10,
    );
    assert!(
        !matches!(outcome, Ok(TreeGateOutcome::Ruled(_))),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn a_revert_restores_the_previous_tree_and_keeps_it_pinned() -> TestResult {
    let fx = Fixture::open()?;
    let fork = fx.fork("team-shape-owner-staging")?;
    let stored = fx.pin(fork, "research")?;
    let pinned_head = fx.promote(pinned(fork, stored))?.in_force_skill_ref;
    let reverted = fx.promote(restore(fx.head))?;
    assert_eq!(reverted.superseded_skill_ref, pinned_head);
    let restored = reverted.in_force_skill_ref;
    assert!(restored != pinned_head && restored != fx.head);
    assert_eq!(fx.in_force()?, restored);
    let seed = TaskTypeTree::seeded();
    let tree = load_team_type_tree(&fx.vault, None).map_err(at("tree in force"))?;
    assert_eq!(tree.version, seed.version);
    assert_eq!(
        tree.nodes.keys().collect::<Vec<_>>(),
        seed.nodes.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        fx.record(&pinned_head)?.lifecycle_status,
        SkillLifecycle::Superseded
    );
    assert_eq!(
        fx.record(&fx.head)?.lifecycle_status,
        SkillLifecycle::Superseded
    );
    let kept = load_team_type_tree_at(&fx.vault, None, stored)
        .map_err(at("kept tree"))?
        .ok_or("the pinned tree's version no longer reads")?;
    assert!(kept.nodes.contains_key("research"));
    // The restored tree is pinned too: the Coach's win over it proposes.
    let revision = fx.fork("team-shape-coach-revision")?;
    let outcome = coach_tree_gate_last_step(
        &fx.vault,
        &revision,
        &restored,
        SkillEditDisposition::Accepted,
        10,
    )
    .map_err(at("gate over the restored tree"))?;
    assert_eq!(
        outcome,
        TreeGateOutcome::Ruled(SkillEditDisposition::Accepted)
    );
    assert_eq!(fx.in_force()?, restored);
    Ok(())
}
