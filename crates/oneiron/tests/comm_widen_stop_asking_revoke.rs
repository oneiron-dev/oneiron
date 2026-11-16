//! The revoke row of a recorded approve-and-stop-asking choice (FIX-LIST row
//! COMM-WIDEN-REVOKE-EFFECT-NO-DOOR): when the owner revokes, the recorded
//! choice stays as it was answered, the asking run keeps the reach it was
//! approved once, and its descendants ask again.
//!
//! One end-to-end sequence over the production doors only: a root run refused
//! at its narrow dial raises the widen ask to the owner, the owner answers
//! approve-and-stop-asking, the run's send lands, a child born under the
//! standing choice lands with no ask of its own, the owner revokes, the child
//! is refused with a fresh ask while the asking run still lands, and a child
//! born after the revoke is refused too. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test comm_widen_stop_asking_revoke`.

use oneiron::agent_dispatch::{
    AgentDispatchInput, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    AgentSpawnContext, CommReach, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::agent_inbox_lens::AgentInboxLensQuery;
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::Scope;
use oneiron::memory::{
    Memory, MemoryError, MessagePersonReceipt, MessagePersonRequest, PeopleListRequest,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{HostBinding, TaskAskHandle, TaskAskOptionId, TaskAskStatus, TaskAskWord};
use oneiron::verbs::{CommWidenRevokeRequest, revoke_comm_widen_as};
use oneiron::{AttemptId, AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// The run every attempt of this test's tree belongs to.
const RUN: &str = "run-comm-widen-revoke";
/// The lease owner this test claims rows as.
const WORKER: &str = "comm-widen-revoke";
/// The owner's stop-asking answer on a widen ask to the owner.
const APPROVE_AND_STOP_ASKING: &str = "approve_and_stop_asking";

/// A process-owned vault at `dir`, as an embedded owner opens it.
fn open_vault(dir: &std::path::Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// A root run of the seeded default agent under `run`, with one level of
/// delegation left: its attempt, its frozen input and the actor it runs as.
fn root_run(
    vault: &Vault,
    run: &str,
    now: u64,
) -> Result<(AttemptId, AgentDispatchInput, EntityId), TestError> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )?
    else {
        return Err("expected one fresh root run".into());
    };
    let actor = agent_dispatch_actor(&status.input)?.entity_ref();
    Ok((status.attempt.id, status.input, actor))
}

/// A child of `parent`, spawned as the run's dispatcher spawns one: the
/// default agent again, under the parent's run, keyed by `key`. Returns its
/// attempt and its frozen input; its actor reads off the input.
fn spawn_child(
    vault: &Vault,
    parent: AttemptId,
    run: &str,
    key: &str,
    now: u64,
) -> Result<(AttemptId, AgentDispatchInput), TestError> {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_default_base(
            Some(parent),
            Some(key.to_owned()),
            Some(run.to_owned()),
            now,
        )?
    else {
        return Err("expected one fresh child".into());
    };
    Ok((status.attempt.id, status.input))
}

/// Leases `id` to this test's worker and answers its row. The runner's rows
/// are claimed oldest first, so rows queued before it are claimed past.
fn claim(vault: &Vault, id: AttemptId) -> Result<AttemptRecord, TestError> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(queue.get(id)?.ok_or("a claimed row reads back")?);
        }
    }
    Err("the attempt is ready to claim".into())
}

/// `actor`'s Memory bound to `leased`'s lease, as the host binds an agent's call.
fn hosted(vault: &Vault, actor: EntityId, leased: &AttemptRecord) -> Result<Memory<'_>, TestError> {
    let binding = HostBinding::from_leased(leased, None)?;
    Ok(vault
        .memory(actor, EdgeActorClass::Agent)
        .with_task_host(binding))
}

/// A PERSON named `name`.
fn person(vault: &Vault, name: &str) -> Result<EntityId, TestError> {
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &rmp_serde::to_vec_named(&serde_json::json!({ "name": name }))?,
    )?;
    Ok(id)
}

/// The `pr` handle the owner's people list reads for `target`, every page.
fn handle_of(vault: &Vault, owner: EntityId, target: EntityId) -> Result<String, TestError> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for page in 0.. {
        let listed = memory.people_list(&PeopleListRequest {
            vault: None,
            page: Some(page),
        })?;
        if let Some(row) = listed.people.iter().find(|row| row.person == target) {
            return Ok(row.handle.clone());
        }
        if listed.more == 0 {
            break;
        }
    }
    Err("the owner reads the target person".into())
}

/// An agent actor's doors to read the vault and to write under its own Auto
/// ceiling, idempotent: the read grant its people roster needs, and the
/// ceiling its sends and asks go through.
fn ensure_actor_doors(vault: &Vault, proof: &AuthenticatedOwner, actor: EntityId) -> TestResult {
    let view = policy_manifests_as_owner(vault, proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let hex = actor.to_hex();
    let ceilinged = default
        .manifest
        .actor_ceilings
        .iter()
        .any(|ceiling| ceiling.actor_ref.as_deref() == Some(hex.as_str()));
    let granted = default
        .manifest
        .scoped_grants
        .clone()
        .unwrap_or_default()
        .iter()
        .any(|row| row.actor_ref.as_deref() == Some(hex.as_str()));
    if ceilinged && granted {
        return Ok(());
    }
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(hex.clone()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(hex),
        effector: "core:read".into(),
        scope: Scope::top(),
        selectors: None,
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// One `self.message` from `memory` to `pr`.
fn send(memory: &Memory<'_>, pr: &str, text: &str) -> Result<MessagePersonReceipt, MemoryError> {
    memory.message_person(&MessagePersonRequest {
        pr: pr.to_owned(),
        text: text.to_owned(),
        mention: None,
        from_project: None,
        to_project: None,
    })
}

/// The widen ask a refusal raised, from its typed denial.
fn ask_of(error: &MemoryError) -> Option<String> {
    error.gate_denial.as_ref()?.ask_ref.clone()
}

/// The pending comm widen asks, as their hex refs.
fn comm_widen_asks(vault: &Vault) -> Result<Vec<String>, TestError> {
    Ok(vault
        .agent_inbox_lens(AgentInboxLensQuery {
            identity_ref: None,
            limit: 64,
            before: None,
        })?
        .into_iter()
        .filter_map(|row| row.item_id.strip_prefix("comm_widen:").map(str::to_owned))
        .collect())
}

/// 32 hex of an attempt, as receipts spell it.
fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn a_revoked_stop_asking_choice_covers_only_the_asking_run() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let proof = owner_memory.embedded_owner("vault.tasks.comm_widen.revoke")?;

    // 1. The target: a plain human person, in no project, running no dispatch.
    let target = person(&vault, "Theo Target")?;
    let pr = handle_of(&vault, owner, target)?;

    // 2. The root run at its narrow worker dial, with one level left to spend.
    let (a, input_a, actor_a) = root_run(&vault, RUN, 1)?;
    assert_eq!(
        input_a.comm,
        CommReach::Parent,
        "the root run's frozen dial is the worker's"
    );
    ensure_actor_doors(&vault, &proof, actor_a)?;

    // 3. The run's send is refused for reach, and the refusal raises the ask.
    // The route is decided before any write, so a refused send lands nothing.
    let leased_a = claim(&vault, a)?;
    let memory_a = hosted(&vault, actor_a, &leased_a)?;
    let refused = send(&memory_a, &pr, "the forecast is in")
        .expect_err("a run at Parent cannot address a stranger");
    assert!(
        refused.message.contains("outbound_reach"),
        "refused for reach: {}",
        refused.message
    );
    let ask_a = ask_of(&refused).ok_or("the refusal names the widen ask")?;
    assert!(
        refused.message.contains(&ask_a),
        "the refusal text names it too: {}",
        refused.message
    );
    assert_eq!(
        comm_widen_asks(&vault)?,
        vec![ask_a.clone()],
        "the one pending widen ask is A's"
    );

    // 4. The owner answers approve-and-stop-asking; the one word settles it.
    let mut word = TaskAskWord::new(owner);
    word.option = Some(TaskAskOptionId::new(APPROVE_AND_STOP_ASKING)?);
    let handle_a = TaskAskHandle {
        group_ref: EntityId::from_hex(&ask_a)?,
    };
    let answer = owner_memory.tasks_answer(&handle_a, &word)?;
    assert_eq!(answer.actor_ref, owner, "the owner's own word settles it");
    assert!(
        matches!(
            owner_memory.tasks_ask_status(handle_a)?,
            TaskAskStatus::Settled(_)
        ),
        "one answer settles the ask at once"
    );
    assert!(
        comm_widen_asks(&vault)?.is_empty(),
        "no widen ask waits once the owner answered"
    );

    // 5. The asking run's next send lands.
    let landed = send(&memory_a, &pr, "the forecast is in, approved")?;
    assert!(!landed.room.is_empty(), "the send lands in the pair's room");

    // 6. A child born under the standing choice lands with no ask of its own.
    let (b, input_b) = spawn_child(&vault, a, RUN, "child-b", 2)?;
    assert_eq!(
        input_b.comm,
        CommReach::Parent,
        "the child freezes its own narrow dial"
    );
    let actor_b = agent_dispatch_actor(&input_b)?.entity_ref();
    ensure_actor_doors(&vault, &proof, actor_b)?;
    let leased_b = claim(&vault, b)?;
    let memory_b = hosted(&vault, actor_b, &leased_b)?;
    send(&memory_b, &pr, "the child writes too")?;
    assert!(
        comm_widen_asks(&vault)?.is_empty(),
        "the standing choice covers the child: no fresh ask"
    );

    // 7. The owner revokes the standing choice.
    let receipt = revoke_comm_widen_as(
        &owner_memory,
        &proof,
        CommWidenRevokeRequest {
            attempt: EntityId::from_bytes(*a.as_bytes())?,
        },
    )?;
    assert!(receipt.revoked, "this call ends the standing");
    assert_eq!(
        receipt.reach,
        CommReach::Vault,
        "the choice approved the vault's reach"
    );
    assert_eq!(receipt.attempt, hex(a), "the receipt names the asking run");

    // 8. The child's next send is refused, raising its own fresh ask.
    let refused_b = send(&memory_b, &pr, "the child writes again")
        .expect_err("a revoked standing covers no descendant");
    assert!(
        refused_b.message.contains("outbound_reach"),
        "refused for reach: {}",
        refused_b.message
    );
    let ask_b = ask_of(&refused_b).ok_or("the refusal names the fresh ask")?;
    assert_ne!(ask_b, ask_a, "the fresh ask is the child's own, not A's");
    assert_eq!(
        comm_widen_asks(&vault)?,
        vec![ask_b.clone()],
        "the one pending widen ask is B's"
    );

    // 9. The asking run still lands: the revoke takes only the standing.
    send(&memory_a, &pr, "the asking run keeps its reach")?;

    // 10. A child born after the revoke is refused too.
    let (c, input_c) = spawn_child(&vault, a, RUN, "child-c", 3)?;
    assert_eq!(
        input_c.comm,
        CommReach::Parent,
        "the late child freezes its own narrow dial"
    );
    let actor_c = agent_dispatch_actor(&input_c)?.entity_ref();
    ensure_actor_doors(&vault, &proof, actor_c)?;
    let leased_c = claim(&vault, c)?;
    let memory_c = hosted(&vault, actor_c, &leased_c)?;
    let refused_c = send(&memory_c, &pr, "the late child writes")
        .expect_err("a child born after the revoke asks again");
    assert!(
        refused_c.message.contains("outbound_reach"),
        "refused for reach: {}",
        refused_c.message
    );
    let ask_c = ask_of(&refused_c).ok_or("the refusal names the late ask")?;
    assert_ne!(ask_c, ask_a);
    assert_ne!(ask_c, ask_b);
    Ok(())
}
