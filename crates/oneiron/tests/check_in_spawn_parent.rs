//! FIX CHECK-IN-SPAWN-PARENT-PRINCIPAL (UNBUILT-09; ARCH-0082 #ladder, rung
//! 2: "The parent of a spawned child"; Engine RULING UNBUILT09-RUNG-ORDER = B
//! and the lead's line on it, 15 Nov 21:21-21:23): a check-in that a spawned
//! child's run opens through `vault.check_in.open` asks the agent whose
//! attempt spawned it, on rung 2.
//!
//! - The dispatch writer freezes the parent's principal on the child's
//!   attempt. The verb reads it from the run's attempt that the host bound
//!   from its live lease, and the open stores it on the row.
//! - Rung 2 pins the spawning agent, not the owner who minted the child's
//!   own Grant.
//! - A spawn parent that is no longer a live agent skips rung 2 and names
//!   why, and the owner is asked on rung 4.
//! - The parent's answer counts only within its own Permitted: an act its
//!   own check-in would let it do, that is no widening. An act its Grant
//!   does not hold, and a widening (an add to a room), pass up to the owner.
//! - A root run's ask still pins the owner who granted it.
//! - The parent's erase takes its id off the child's open ask, as the
//!   table's actor scrub takes it off every pinned rung (review of
//!   UNBUILT-09, P3).
//! - A frozen spawn parent counts only when the attempt's own stored parent
//!   link derives it again: handover enqueues a replicated run TASK's
//!   payload as it came (Astra review of UNBUILT-09, F1; Engine RULING
//!   U09-ASTRA-F1 = A, 16 Nov 10:04).
//! - A workflow leaf's stored parent is the workflow's inert wrapper; the
//!   link crosses it to the run that dispatched the workflow, so rung 2 still
//!   pins that run's agent (Sol review of the F1 commit, P2).
//!
//! On main the first, second and fourth cases fail at their first rung
//! assert: the child's Grant names the owner as `delegated_by`, so rung 2
//! pins the owner. Before the scrub took the spawn parent too, the erase
//! case failed at its assert on the scrubbed row. Before the reader derived
//! the parent again, the last case failed at its first assert: the open
//! stored the forged parent. Before the link crossed a workflow wrapper, the
//! workflow case failed at its assert: the wrapper is no agent dispatch, so
//! the open stored no parent and rung 2 pinned the owner.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_spawn_parent`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
    decode_agent_dispatch_input, encode_agent_dispatch_input,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::check_in::{HolderAnswer, PendingCheckIn, PendingState, Rung};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::HostBinding;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::check_in::{FixedVerdicts, open_as_caller};
use oneiron::test_doors::inquiry::erase_actor_in_tables_in_order;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const OPEN: &str = "vault.check_in.open";
/// `spawn`, neutral: a Delegate asks when unsure, and no decision model is
/// sure, so the child's ask waits; the parent, judging on its own, goes.
const SPAWN: &str = "self.agents.spawn";
/// `room_add`, a widening: a Delegate whose Grant names it asks when unsure,
/// as for a spawn.
const INVITE: &str = "vault.rooms.invite";
/// The lease owner this file claims attempts as.
const WORKER: &str = "check-in-spawn-parent";

const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled, so the owner's Grant acts
    /// on `ThisInstall` land.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("open vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _dir: dir,
            owner,
            owner_proof,
        }
    }

    /// An enabled, active agent definition the owner creates, with the
    /// owner's live Grant naming `read` and `verbs` over every world.
    fn granted_agent(&self, name: &str, verbs: &[&str]) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("{name}-{}", id.to_hex()),
                    "desc": "check-in spawn parent fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
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
                agent: id,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        id
    }

    /// A fresh attempt of `agent`, a root when `parent` is `None`, else the
    /// child `parent`'s run spawns.
    fn dispatch(&self, agent: EntityId, parent: Option<AttemptId>) -> AttemptId {
        let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&self.vault)
            .dispatch_with_context(
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(agent),
                    parent_attempt: parent,
                    dedupe_key: None,
                    run_id: None,
                    now: T0,
                },
                AgentSpawnContext::default(),
            )
            .expect("the dispatch is admitted")
        else {
            panic!("expected one fresh attempt");
        };
        assert_eq!(
            status.input.target,
            AgentDispatchTarget::Custom(agent),
            "the attempt runs as the agent itself, not as a narrowed fork"
        );
        status.attempt.id
    }

    /// A fresh attempt of `agent` whose frozen dispatch input names
    /// `spawn_parent`, enqueued as handover enqueues a replicated run TASK's
    /// payload: a root dispatch's payload of `agent`, with `spawn_parent`
    /// written into its input and `parent_link` as its stored parent attempt.
    fn forged_child(
        &self,
        agent: EntityId,
        spawn_parent: EntityId,
        parent_link: Option<AttemptId>,
    ) -> AttemptId {
        let queue = AttemptQueue::new(&self.vault);
        let root = queue
            .get(self.dispatch(agent, None))
            .expect("read")
            .expect("the root's row");
        let mut payload = decode_dreamer_attempt_payload(&root.payload).expect("a dreamer payload");
        let mut input = decode_agent_dispatch_input(&payload.input).expect("a dispatch input");
        input.spawn_parent = Some(spawn_parent);
        payload.input = encode_agent_dispatch_input(&input).expect("encode the input");
        payload.parent_attempt = parent_link;
        let EnqueueOutcome::Enqueued(forged) = queue
            .enqueue(EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: encode_dreamer_attempt_payload(&payload).expect("encode the payload"),
                dedupe_key: None,
                run_id: None,
                now: T0,
            })
            .expect("enqueue")
        else {
            panic!("expected one fresh attempt");
        };
        forged.id
    }

    /// An inert workflow wrapper whose recorded parent is `parent`, the run
    /// that dispatched the workflow, as the workflow writer enqueues it: a
    /// root's payload with the wrapper's attempt type (`agent.workflow`,
    /// `WORKFLOW_ATTEMPT_TYPE`). Each leaf's stored parent is this wrapper.
    fn workflow_wrapper(&self, parent: AttemptId) -> AttemptId {
        let queue = AttemptQueue::new(&self.vault);
        let row = queue.get(parent).expect("read").expect("the parent's row");
        let mut payload = decode_dreamer_attempt_payload(&row.payload).expect("a dreamer payload");
        payload.attempt_type = "agent.workflow".to_owned();
        payload.parent_attempt = Some(parent);
        let EnqueueOutcome::Enqueued(wrapper) = queue
            .enqueue(EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: encode_dreamer_attempt_payload(&payload).expect("encode the payload"),
                dedupe_key: None,
                run_id: None,
                now: T0,
            })
            .expect("enqueue")
        else {
            panic!("expected one fresh attempt");
        };
        wrapper.id
    }

    /// `id`, leased to this file's worker. Rows queued before it are leased
    /// on the way.
    fn claim(&self, id: AttemptId) -> AttemptRecord {
        let queue = AttemptQueue::new(&self.vault);
        for _ in 0..64 {
            let ClaimOutcome::Claimed(row) = queue
                .claim_kind(
                    DREAMER_RUNNER_ATTEMPT_KIND,
                    ClaimAttempt {
                        lease_owner: WORKER.to_owned(),
                        now: u64::MAX,
                    },
                )
                .expect("claim")
            else {
                break;
            };
            if row.id == id {
                return queue
                    .get(id)
                    .expect("read")
                    .expect("a claimed row reads back");
            }
        }
        panic!("the attempt is ready to claim");
    }

    /// `agent`'s surface inside its leased run `leased`, as the run's host
    /// binds it from the lease it holds.
    fn in_run(&self, agent: EntityId, leased: &AttemptRecord) -> Memory<'_> {
        self.vault
            .memory(agent, EdgeActorClass::Agent)
            .with_task_host(HostBinding::from_leased(leased, None).expect("a live lease"))
    }

    /// A parent agent granted `parent_verbs`, its root run leased, and the
    /// run of a child agent granted `child_verbs` that it spawns, leased:
    /// (parent, child, the child's leased attempt).
    fn spawned(
        &self,
        parent_verbs: &[&str],
        child_verbs: &[&str],
    ) -> (EntityId, EntityId, AttemptRecord) {
        let parent = self.granted_agent("check-in-parent", parent_verbs);
        let child = self.granted_agent("check-in-child", child_verbs);
        let root = self.dispatch(parent, None);
        self.claim(root);
        let spawned = self.dispatch(child, Some(root));
        (parent, child, self.claim(spawned))
    }

    /// The pending row of a `wait` verdict, which an act asked when unsure
    /// answers.
    fn waiting_row(&self, verdict: &Value) -> PendingCheckIn {
        assert_eq!(
            (verdict["outcome"].as_str(), verdict["reason"].as_str()),
            (Some("wait"), Some("unsure")),
            "the child's act asked when unsure waits: {verdict}"
        );
        let id = EntityId::from_hex(verdict["handle"]["handle"].as_str().expect("a handle"))
            .expect("a handle id");
        self.vault
            .pending_check_in(&id)
            .expect("read")
            .expect("the row is stored")
    }
}

/// An ask for `verb`'s act at the vault scope over the effect `byte`.
fn ask(verb: &str, byte: u8) -> Value {
    json!({ "verb": verb, "effect_digest": format!("{byte:02x}").repeat(32) })
}

/// The ask opened as `memory`'s caller through the verb: its pending row.
fn open(fx: &Fixture, memory: &Memory<'_>, verb: &str, byte: u8) -> PendingCheckIn {
    let verdict = invoke(memory, OPEN, ask(verb, byte))
        .unwrap_or_else(|error| panic!("{OPEN} of {verb}: {error:?}"));
    fx.waiting_row(&verdict)
}

/// The ask opened as `memory`'s caller through the verb's own open, with
/// the agent holders' `verdicts`: its pending row.
fn open_with(
    fx: &Fixture,
    memory: &Memory<'_>,
    verb: &str,
    byte: u8,
    verdicts: &FixedVerdicts,
) -> PendingCheckIn {
    let request = serde_json::from_value(ask(verb, byte)).expect("an open request");
    let verdict = open_as_caller(memory, request, verdicts)
        .unwrap_or_else(|error| panic!("{OPEN} of {verb}: {error:?}"));
    fx.waiting_row(&serde_json::to_value(verdict).expect("a verdict"))
}

/// Each rung the ask entered: the rung, its missing link, its holders.
fn rungs(row: &PendingCheckIn) -> Vec<(&'static str, Option<String>, Vec<EntityId>)> {
    row.rungs
        .iter()
        .map(|entry| {
            (
                entry.rung.as_str(),
                entry.skipped.clone(),
                entry
                    .holders
                    .iter()
                    .map(|holder| holder.principal)
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn rung_two_asks_the_spawning_agents_principal() {
    let fx = Fixture::rooted();
    let (parent, child, leased) = fx.spawned(&[SPAWN], &[SPAWN]);
    let row = open(&fx, &fx.in_run(child, &leased), SPAWN, 0x61);
    assert_eq!(
        rungs(&row).first().cloned(),
        Some(("grantor", None, vec![parent])),
        "rung 2 pins the agent whose run spawned the child, not the owner {:?}",
        fx.owner
    );
}

#[test]
fn rung_two_skips_a_spawn_parent_that_is_no_live_agent() {
    let fx = Fixture::rooted();
    let (parent, child, leased) = fx.spawned(&[SPAWN], &[SPAWN]);
    let mut switched_off = fx
        .vault
        .get_agent_definition(&parent)
        .expect("read")
        .expect("the parent's definition");
    switched_off.enabled = false;
    switched_off.version = "2.0.0".to_owned();
    fx.vault
        .update_agent_definition_as(
            &fx.owner_proof,
            &parent,
            &switched_off,
            TimeRange {
                start: T0 + 1,
                end: T0 + 1,
            },
            T0 + 1,
        )
        .expect("the owner switches the parent off");
    let row = open(&fx, &fx.in_run(child, &leased), SPAWN, 0x62);
    let rungs = rungs(&row);
    assert_eq!(
        rungs
            .first()
            .map(|(rung, skipped, _)| (*rung, skipped.as_deref())),
        Some((
            "grantor",
            Some("the grantor is no live person or agent other than the asker")
        )),
        "a switched-off spawn parent skips rung 2 and names why: {rungs:?}"
    );
    assert_eq!(
        rungs
            .last()
            .map(|(rung, _, holders)| (*rung, holders.clone())),
        Some(("owner", vec![fx.owner])),
        "the owner is asked on rung 4: {rungs:?}"
    );
}

#[test]
fn parent_answer_bounded_by_its_own_permitted() {
    let fx = Fixture::rooted();
    let (parent, child, leased) = fx.spawned(&[SPAWN, INVITE], &[SPAWN, INVITE]);
    let approves = FixedVerdicts::default().with(parent, HolderAnswer::Approve);
    let in_child = fx.in_run(child, &leased);

    // (1) Inside: a spawn moves no access, and the parent's own check-in for
    // it would go. Its answer settles the ask on rung 2.
    let inside = open_with(&fx, &in_child, SPAWN, 0x71, &approves);
    assert!(
        matches!(
            inside.state,
            PendingState::Answered {
                answer: HolderAnswer::Approve,
                by: Some(by),
                rung: Rung::Grantor,
                ..
            } if by == parent
        ),
        "the parent approves an act inside its own Permitted: {:?}",
        inside.state
    );

    // (2) A widening: an add to a room. The parent's Grant names it and its
    // own check-in would go, as for the spawn, yet an agent's widening
    // passes up to a person: its answer does not count, rung 2 pins no one,
    // and the owner is asked.
    let widening = open_with(&fx, &in_child, INVITE, 0x72, &approves);
    let widening_rungs = rungs(&widening);
    assert_eq!(
        widening.state,
        PendingState::Open,
        "the parent's answer to a widening does not count: {widening_rungs:?}"
    );
    assert_eq!(
        (
            widening_rungs.first().map(|(rung, skipped, holders)| (
                *rung,
                skipped.is_some(),
                holders.len()
            )),
            widening_rungs
                .last()
                .map(|(rung, _, holders)| (*rung, holders.clone())),
        ),
        (Some(("grantor", true, 0)), Some(("owner", vec![fx.owner]))),
        "a widening passes rung 2 and rung 3 up to the owner: {widening_rungs:?}"
    );

    // (3) Outside: a parent whose Grant does not hold the spawn. Its answer
    // does not count, and the ask passes up to the owner.
    let (narrow_parent, narrow_child, narrow_leased) = fx.spawned(&[INVITE], &[SPAWN]);
    let outside = open_with(
        &fx,
        &fx.in_run(narrow_child, &narrow_leased),
        SPAWN,
        0x73,
        &FixedVerdicts::default().with(narrow_parent, HolderAnswer::Approve),
    );
    let outside_rungs = rungs(&outside);
    assert_eq!(
        (
            outside.state,
            outside_rungs.first().map(|(rung, skipped, holders)| (
                *rung,
                skipped.is_some(),
                holders.len()
            )),
            outside_rungs
                .last()
                .map(|(rung, _, holders)| (*rung, holders.clone())),
        ),
        (
            PendingState::Open,
            Some(("grantor", true, 0)),
            Some(("owner", vec![fx.owner]))
        ),
        "an act outside the parent's own Grant passes up to the owner: {outside_rungs:?}"
    );
}

#[test]
fn a_root_runs_rung_two_still_asks_the_owner_who_granted_it() {
    let fx = Fixture::rooted();
    let agent = fx.granted_agent("check-in-root", &[SPAWN]);
    let root = fx.dispatch(agent, None);
    let leased = fx.claim(root);
    let row = open(&fx, &fx.in_run(agent, &leased), SPAWN, 0x63);
    assert_eq!(
        rungs(&row).first().cloned(),
        Some(("grantor", None, vec![fx.owner])),
        "a root run has no spawn parent: rung 2 pins the owner who minted its Grant"
    );
}

#[test]
fn erasing_the_spawn_parent_takes_its_id_off_the_open_ask() {
    let fx = Fixture::rooted();
    let (parent, child, leased) = fx.spawned(&[SPAWN], &[SPAWN]);
    let row = open(&fx, &fx.in_run(child, &leased), SPAWN, 0x64);
    assert_eq!(
        row.spawn_parent,
        Some(parent),
        "the open stores the spawn parent"
    );

    assert_eq!(
        erase_actor_in_tables_in_order(&fx.vault, &parent, &["CHECK_IN_PENDING"])
            .expect("the pending check-in actor erase runs"),
        1,
        "the pending check-in table registers an actor erase"
    );
    let scrubbed = fx
        .vault
        .pending_check_in(&row.id)
        .expect("read")
        .expect("the child's ask stays");
    assert_eq!(
        (scrubbed.spawn_parent, scrubbed.asker, &scrubbed.state),
        (None, child, &PendingState::Open),
        "the erased parent's id is gone from the child's ask, which stays open"
    );
    let rungs = rungs(&scrubbed);
    assert!(
        rungs
            .iter()
            .all(|(_, _, holders)| !holders.contains(&parent)),
        "no rung pins the erased parent: {rungs:?}"
    );
}

#[test]
fn rung_two_ignores_a_spawn_parent_the_parent_link_does_not_derive() {
    let fx = Fixture::rooted();
    let parent = fx.granted_agent("check-in-parent", &[SPAWN]);
    let child = fx.granted_agent("check-in-child", &[SPAWN]);
    let other = fx.granted_agent("check-in-other", &[SPAWN]);
    let other_root = fx.dispatch(other, None);
    // No parent link, and a link to a live attempt of another agent.
    for (parent_link, byte) in [(None, 0x65), (Some(other_root), 0x66)] {
        let leased = fx.claim(fx.forged_child(child, parent, parent_link));
        let row = open(&fx, &fx.in_run(child, &leased), SPAWN, byte);
        assert_eq!(
            (row.spawn_parent, rungs(&row).first().cloned()),
            (None, Some(("grantor", None, vec![fx.owner]))),
            "a frozen spawn parent {parent:?} that the parent link {parent_link:?} does not \
             derive is not stored: rung 2 pins the owner who minted the child's Grant"
        );
    }
}

#[test]
fn rung_two_asks_the_agent_whose_run_dispatched_the_workflow() {
    let fx = Fixture::rooted();
    let parent = fx.granted_agent("check-in-parent", &[SPAWN]);
    let child = fx.granted_agent("check-in-child", &[SPAWN]);
    let root = fx.dispatch(parent, None);
    // A leaf of a workflow the parent's run dispatched: its frozen spawn
    // parent is the parent, its stored parent the workflow's inert wrapper.
    let leaf = fx.forged_child(child, parent, Some(fx.workflow_wrapper(root)));
    let row = open(&fx, &fx.in_run(child, &fx.claim(leaf)), SPAWN, 0x67);
    assert_eq!(
        (row.spawn_parent, rungs(&row).first().cloned()),
        (Some(parent), Some(("grantor", None, vec![parent]))),
        "a workflow leaf's parent link crosses the wrapper to the run that dispatched the \
         workflow: rung 2 pins that run's agent, not the owner {:?}",
        fx.owner
    );
}
