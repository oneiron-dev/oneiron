//! ROLES-CHECKIN PR 3, P3.6: cancel runs under check-in's own mode, and the
//! children rule is ARCH-0082 #children. The cancel's mode type is folded
//! into `CheckInMode` with its wire tokens unchanged (`auto`, `full-access`,
//! `manual`), and `manual` still proposes. An agent stops the children and
//! forks it started, and their whole subtree, with no ask; a cancel of an
//! agent it did not start stays a proposal.
//!
//! `cargo test --locked -p oneiron --all-features --test check_in_cancel_fold`.
//! RED PIN: main plus the children-rule arms (the mode arms need the fold).

use oneiron::EdgeActorClass;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptState, InterveneAttempt,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::config::VaultConfig;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCancelTarget;
use oneiron::task_verb::run_cancel::RunCancelOutcome;
use oneiron::{EntityId, TimeRange, Vault};

const NOW: u64 = 120;

/// A vault where `own` is an agent of its own (a fork of `sys.keeper`)
/// holding the standing `cancel` grant, and `other` is a second actor.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    own: EntityId,
    other: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let own = EntityId::from_bytes([0xE1; 16]).expect("own id");
    let (keeper_id, keeper) = vault
        .get_seeded_agent_definition_by_logical_id("sys.keeper")
        .expect("resolve keeper")
        .expect("keeper exists");
    let mut fork = keeper.clone();
    fork.agent_id = "spawn-owner".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(keeper_id);
    fork.ceiling = keeper.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = ClaimSource::UserStated;
    fork.provenance = rmpv::Value::Map(vec![(
        rmpv::Value::from("forkOf"),
        rmpv::Value::from(keeper_id.to_hex()),
    )]);
    vault
        .put_agent_definition(
            &own,
            &fork,
            TimeRange {
                start: 1,
                end: u64::MAX,
            },
            1,
        )
        .expect("fork agent");
    let other = EntityId::from_bytes([0xE2; 16]).expect("other id");
    vault
        .put_entity(
            &other,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"other",
        )
        .expect("put other");
    // A standing outbound grant is the vault owner's act (FIX 11874).
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let proof = vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    for (actor, seed) in [(own, 0xD8), (other, 0xD9)] {
        vault
            .mint_standing_outbound_grant(
                &proof,
                EntityId::from_bytes([seed; 16]).expect("grant id"),
                &GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "cancel".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "cancel".to_owned(),
                    },
                },
            )
            .expect("mint cancel grant");
    }
    Fixture {
        _dir: dir,
        vault,
        own,
        other,
    }
}

fn dispatched(outcome: AgentDispatchOutcome) -> AgentDispatchStatus {
    match outcome {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::ProposedWiden(_)
        | AgentDispatchOutcome::WorkflowDispatched(_)
        | AgentDispatchOutcome::WorkflowExisting(_)
        | AgentDispatchOutcome::Existing(_) => panic!("a fresh ordinary dispatch"),
    }
}

/// `own`'s run, the child it spawned (the default base), and the
/// grandchild that child spawned: (child, grandchild).
fn spawn_tree(f: &Fixture) -> (AttemptId, AttemptId) {
    let dispatcher = AgentDispatcher::new(&f.vault);
    let parent = dispatched(
        dispatcher
            .dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(f.own),
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now: NOW,
            })
            .expect("dispatch parent"),
    );
    let child = dispatched(
        dispatcher
            .dispatch_default_base(Some(parent.attempt.id), None, None, NOW + 1)
            .expect("dispatch child"),
    );
    let grandchild = dispatched(
        dispatcher
            .dispatch_default_base(Some(child.attempt.id), None, None, NOW + 2)
            .expect("dispatch grandchild"),
    );
    (child.attempt.id, grandchild.attempt.id)
}

fn state(f: &Fixture, id: AttemptId) -> AttemptState {
    AttemptQueue::new(&f.vault)
        .get(id)
        .expect("read attempt")
        .expect("attempt exists")
        .state
}

#[test]
fn a_spawner_stops_its_own_spawns_subtree_with_no_ask() {
    let f = fixture();
    let (child, grandchild) = spawn_tree(&f);
    let cancel = f
        .vault
        .memory(f.own, EdgeActorClass::Agent)
        .cancel(TaskCancelTarget::Spawn(grandchild))
        .expect("cancel the grandchild");
    assert!(
        cancel.effected,
        "the grandchild's root spawner stops it: {cancel:?}"
    );
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert!(cancel.proposal_ref.is_none());
    assert_eq!(state(&f, grandchild), AttemptState::Cancelled);
    assert_eq!(state(&f, child), AttemptState::Queued);
}

#[test]
fn a_spawner_stops_a_run_tree_branch_below_its_spawn_with_no_ask() {
    let f = fixture();
    let (child, grandchild) = spawn_tree(&f);
    let outcome = f
        .vault
        .memory(f.own, EdgeActorClass::Agent)
        .cancel_run_branch(InterveneAttempt {
            id: grandchild,
            kind: AttemptInterventionKind::Cancel,
            actor: f.own.to_hex(),
            note: Some("the root spawner stops this branch".to_owned()),
            now: NOW + 3,
        })
        .expect("run-tree cancel");
    assert!(
        matches!(outcome, RunCancelOutcome::Applied(_)),
        "the root spawner's run-tree cancel applies: {outcome:?}"
    );
    assert_eq!(state(&f, grandchild), AttemptState::Cancelled);
    assert_eq!(state(&f, child), AttemptState::Queued);
}

#[test]
fn a_cancel_of_a_run_it_did_not_start_proposes() {
    let f = fixture();
    let (child, grandchild) = spawn_tree(&f);
    let foreign = f.vault.memory(f.other, EdgeActorClass::Agent);
    for target in [child, grandchild] {
        let cancel = foreign
            .cancel(TaskCancelTarget::Spawn(target))
            .expect("foreign cancel");
        assert!(!cancel.effected);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert!(cancel.proposal_ref.is_some());
        let outcome = foreign
            .cancel_run_branch(InterveneAttempt {
                id: target,
                kind: AttemptInterventionKind::Cancel,
                actor: f.other.to_hex(),
                note: None,
                now: NOW + 3,
            })
            .expect("foreign run-tree cancel");
        assert!(matches!(outcome, RunCancelOutcome::Proposed { .. }));
        assert_eq!(state(&f, target), AttemptState::Queued);
    }
}
