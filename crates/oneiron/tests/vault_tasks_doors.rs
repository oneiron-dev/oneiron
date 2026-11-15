//! The `vault.tasks.*` doors keep the force-stop, stop-asking and Linear
//! mirror promises (ruling L4-23 = A: each test proves a promise at its
//! public door). Every call enters through `oneiron_testkit::door::invoke`,
//! the generated verb dispatch every transport shares. `cancel.force` and
//! `comm_widen.revoke` are the owner's, so the vault is opened with the
//! process writer lease (`Vault::open_owned`), as an embedded host's is.
//!
//! - P1 canon `oneiron/planning/agent-mind-design-v1.md:403` "the owner may
//!   kill a run. A kill is a control act, not an automatic stop.":
//!   `vault.tasks.cancel.force` stops every live branch of the TASK on the
//!   owner's word and leaves a terminal try as it was; its receipt and the
//!   branches read name the cancellation with the owner's reason; a second
//!   force stops nothing; no one but the owner forces.
//! - P2 canon `oneiron/decisions/oneiron-dec-0006-unified-consent-mode.md:71`
//!   "Stop asking writes a standing row with a bound" and
//!   `oneiron/agents/oneiron-arch-0028-mcp-external-agent-surface-v1.md:653`
//!   "Widening is one signal to the parent, approve-and-stop-asking.": the
//!   owner's `vault.tasks.comm_widen.revoke` ends the standing of a run's
//!   recorded stop-asking choice once, keeps its bound in the receipt and says
//!   when it ended; a second revoke answers the first; a run whose choice was
//!   approve once, or that recorded none, has no standing to end. The choice
//!   is stored by the `oneiron_test_support` door
//!   `test_doors::comm_widen_standing` (no public door writes one: only a
//!   host-bound run's refused send raises the widen ask).
//! - P3 (no canon line; nearest
//!   `oneiron/code-in-oneiron/oneiron-arch-0068-repo-custody-v1.md:138` "A
//!   Linear sync adapter ... mirrors TASK<->issue both ways"; the rows' own
//!   descriptions, OF-427 C6/C7): `mapping.edit` at the revision the caller
//!   read writes the next one and `mapping` reads it back; a replay answers
//!   the first receipt; a stale revision is refused; `provenance` lists the
//!   one edit and names its editor; a TASK a credential does not read is not
//!   found on all three rows.
//! - Refusals, one table: a non-owner on the owner rows, a non-party on the
//!   mapping edit, malformed bodies and unknown ids.
//!
//! Not in this file: "Only the agent running a task can refuse that task"
//! (`oneiron-arch-0079-agent-coordination-v1.md:52`, promise-gate-08) is the
//! ordinary cancel's refusal (`AttemptQueue::reject_cancel` on the live
//! lease), which none of these five rows reaches. That a revoked standing
//! makes descendants ask again and leaves the run its approved reach is read
//! only inside the engine (`effective_comm_in_txn`); no door reads it. The
//! in-process `mapping.edit` passes no tracker team (the server passes the
//! host's), so `link` refuses here and the round trip uses `mirror`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_tasks_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::agent_dispatch::{CommReach, DEFAULT_BASE_LOGICAL_ID};
use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome, RetryAttempt};
use oneiron::authority::SlipCaveat;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::genui::ConsentConfirmOutcome;
use oneiron::memory::Memory;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::comm_widen_standing::record_owner_comm_choice;
use oneiron::{AttemptId, AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The first-party actor the default policy manifest grants an Auto ceiling,
/// so its TASK create takes direct effect (as run_tree_reader.rs).
const CREATOR_BYTES: [u8; 16] = [0xE1; 16];
/// The agent's own words kept on its failed try.
const AGENT_ERROR: &str = "the agent's own words about its failure";
/// What the owner says as it stops the TASK.
const OWNER_REASON: &str = "the owner's own words about the stop";
/// The challenge the narrowed credential is verified on.
const CHALLENGE: &[u8] = b"oneiron-request:vault-tasks-doors";

/// A process-owned vault, as an embedded owner opens it: it holds the
/// writer lease, so the owner rows admit the embedded owner.
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    Ok((dir, vault))
}

fn person(vault: &Vault, id: EntityId) -> Result<EntityId, Box<dyn std::error::Error>> {
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person of the vault",
    )?;
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A TASK the first-party creator assigns the seeded default agent: its ref,
/// the agent, and the attempt that realizes it (queued, not claimed).
fn assigned_task(
    vault: &Vault,
) -> Result<(EntityId, EntityId, AttemptId), Box<dyn std::error::Error>> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let creator = person(vault, EntityId::from_bytes(CREATOR_BYTES)?)?;
    let receipt = vault.memory(creator, EdgeActorClass::Agent).tasks_create(
        &TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("stop me".to_owned()),
            Some(creator),
            None,
        )
        .with_assignee(TaskAssignee::AgentDef {
            agent_def_ref: agent,
        }),
    )?;
    let task_ref = receipt.task_ref.ok_or("the TASK is minted")?;
    let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = receipt.route else {
        return Err("an agent-definition assignee routes to an agent dispatch".into());
    };
    Ok((task_ref, agent, attempt_ref))
}

/// An assigned TASK with two branches: its first try, claimed and failed
/// with the agent's words, and the scheduled retry that replaces it. Answers
/// the TASK, the agent and the failed try's hex.
fn task_with_retry(
    vault: &Vault,
) -> Result<(EntityId, EntityId, String), Box<dyn std::error::Error>> {
    let (task_ref, agent, attempt_ref) = assigned_task(vault)?;
    let queue = AttemptQueue::new(vault);
    let mut claimed = None;
    // Other runner rows the fresh vault queued are claimed past.
    for _ in 0..32 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "vault-tasks-doors".to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == attempt_ref {
            claimed = Some(row);
            break;
        }
    }
    let claimed = claimed.ok_or("the TASK's attempt is ready to claim")?;
    let claimed_at = claimed.claimed_at.ok_or("a claim records its time")?;
    queue.retry(RetryAttempt {
        id: claimed.id,
        lease_owner: "vault-tasks-doors".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: claimed_at + 3_600_000,
        last_error: Some(AGENT_ERROR.to_owned()),
        now: claimed_at,
    })?;
    Ok((task_ref, agent, hex(attempt_ref.as_bytes())))
}

/// A TASK the embedded owner creates and owns, with no assignee: the Linear
/// rows' TASK.
fn owner_task(owner: &Memory<'_>, vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let receipt = owner.tasks_create(&TaskCreateSpec::new(
        rmpv::Value::Nil,
        Some("mirror me".to_owned()),
        Some(vault.ensure_embedded_owner_actor()?),
        Some(vault.now_recorded_at()),
    ))?;
    Ok(receipt.task_ref.ok_or("the TASK creation took effect")?)
}

/// The branch `branch` of a branches page.
fn branch<'v>(page: &'v Value, branch: &str) -> Result<&'v Value, Box<dyn std::error::Error>> {
    Ok(page["branches"]
        .as_array()
        .ok_or("the page lists branches")?
        .iter()
        .find(|read| read["branch"] == branch)
        .ok_or("the page holds the branch")?)
}

/// The one branch of a branches page that is not `except`.
fn other_branch<'v>(
    page: &'v Value,
    except: &str,
) -> Result<&'v Value, Box<dyn std::error::Error>> {
    let others: Vec<&Value> = page["branches"]
        .as_array()
        .ok_or("the page lists branches")?
        .iter()
        .filter(|read| read["branch"] != except)
        .collect();
    assert_eq!(others.len(), 1, "one branch besides {except}: {page}");
    Ok(others[0])
}

/// A `mapping.edit` body.
fn edit(task: &str, revision: u64, key: &str, op: Value) -> Value {
    json!({
        "task_ref": task,
        "expected_mapping_revision": revision,
        "intent_key": key,
        "op": op,
    })
}

/// P1: the owner's force stops every live branch and leaves a terminal try
/// as it was; a second force stops nothing; only the owner forces.
#[test]
fn the_owners_force_stops_every_live_branch() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let (task_ref, agent, failed) = task_with_retry(&vault)?;
    let task = task_ref.to_hex();

    let forced = door::invoke(
        &owner,
        "vault.tasks.cancel.force",
        json!({"task_ref": task, "reason": OWNER_REASON}),
    )?;
    assert_eq!(forced["task_ref"], task);
    assert_eq!(forced["effected"], true, "{forced}");
    assert_eq!(forced["forced"], 1, "{forced}");
    assert_eq!(
        forced["branches"].as_array().map(Vec::len),
        Some(2),
        "{forced}"
    );
    // The failed try is terminal: the force leaves it as it was.
    let kept = branch(&forced, &failed)?;
    assert_eq!(kept["state"], "Failed", "{kept}");
    assert_eq!(kept["last_error"], AGENT_ERROR);
    assert_eq!(kept["cancel_state"]["cancellation"], Value::Null, "{kept}");
    // The live retry is stopped on the owner's word.
    let stopped = other_branch(&forced, &failed)?;
    let live = stopped["branch"]
        .as_str()
        .ok_or("the branch's id")?
        .to_owned();
    assert_eq!(stopped["state"], "Cancelled", "{stopped}");
    assert_eq!(stopped["agent_status"], "cancelled", "{stopped}");
    assert_eq!(
        stopped["cancel_state"]["cancellation"]["reason"], OWNER_REASON,
        "{stopped}"
    );
    assert!(
        stopped["cancel_state"]["receipts"]
            .as_array()
            .is_some_and(|receipts| !receipts.is_empty()),
        "the stopped branch carries its cancel receipt: {stopped}"
    );

    // The branches read shows the same stop.
    let read = door::invoke(&owner, "vault.runs.branches.get", json!({"task_ref": task}))?;
    let reread = branch(&read, &live)?;
    assert_eq!(reread["state"], "Cancelled", "{reread}");
    assert_eq!(reread["agent_status"], "cancelled", "{reread}");
    assert_eq!(
        reread["cancel_state"]["cancellation"]["reason"], OWNER_REASON,
        "{reread}"
    );
    assert_eq!(branch(&read, &failed)?["state"], "Failed");

    // A second force stops nothing and reads the branches as stored.
    let again = door::invoke(
        &owner,
        "vault.tasks.cancel.force",
        json!({"task_ref": task}),
    )?;
    assert_eq!(again["effected"], false, "{again}");
    assert_eq!(again["forced"], 0, "{again}");
    let still = branch(&again, &live)?;
    assert_eq!(still["state"], "Cancelled");
    assert_eq!(
        still["cancel_state"]["cancellation"],
        stopped["cancel_state"]["cancellation"]
    );

    // The run's own agent is no owner: it forces nothing.
    let refused = door::invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        "vault.tasks.cancel.force",
        json!({"task_ref": task}),
    )
    .expect_err("the run's agent is no owner");
    assert_eq!(refused.code, oneiron::MEMORY_CODE_FORBIDDEN, "{refused:?}");
    Ok(())
}

/// P2: the owner ends a recorded stop-asking choice's standing once; the
/// receipt keeps its bound and says when it ended; a second revoke answers
/// the first.
#[test]
fn the_owner_ends_a_stop_asking_standing_once() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let (_, agent, run) = assigned_task(&vault)?;
    record_owner_comm_choice(
        &vault,
        run,
        owner_id,
        CommReach::Subtree,
        ConsentConfirmOutcome::ApproveAndStopAsking,
        1,
    )?;
    let attempt = hex(run.as_bytes());

    // Only the owner revokes: the run's own agent is refused, and its
    // refusal ends nothing.
    let refused = door::invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        "vault.tasks.comm_widen.revoke",
        json!({"attempt": attempt}),
    )
    .expect_err("the run's agent is no owner");
    assert_eq!(refused.code, oneiron::MEMORY_CODE_FORBIDDEN, "{refused:?}");

    let revoked = door::invoke(
        &owner,
        "vault.tasks.comm_widen.revoke",
        json!({"attempt": attempt}),
    )?;
    assert_eq!(revoked["attempt"], attempt);
    assert_eq!(revoked["reach"], "subtree", "{revoked}");
    assert_eq!(revoked["revoked"], true, "{revoked}");
    let ended = revoked["revoked_at"].as_u64().ok_or("revoked_at")?;
    assert!(ended > 0, "{revoked}");

    // A second revoke answers the first: the same bound and end time.
    let again = door::invoke(
        &owner,
        "vault.tasks.comm_widen.revoke",
        json!({"attempt": attempt}),
    )?;
    assert_eq!(again["revoked"], false, "{again}");
    assert_eq!(again["revoked_at"], ended, "{again}");
    assert_eq!(again["reach"], "subtree");
    Ok(())
}

/// P2: only a stop-asking choice has a standing to end: an approve-once
/// choice, a denial and a run that recorded nothing are not found.
#[test]
fn only_a_stop_asking_choice_has_a_standing_to_end() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let (_, _, run) = assigned_task(&vault)?;
    record_owner_comm_choice(
        &vault,
        run,
        owner_id,
        CommReach::Project,
        ConsentConfirmOutcome::ApproveOnce,
        1,
    )?;
    let denied = AttemptId::from_bytes(&[0x9d; 16])?;
    record_owner_comm_choice(
        &vault,
        denied,
        owner_id,
        CommReach::Vault,
        ConsentConfirmOutcome::Deny,
        1,
    )?;
    let nothing = AttemptId::from_bytes(&[0x9e; 16])?;
    for (what, attempt) in [
        ("approve once", run),
        ("deny", denied),
        ("no choice", nothing),
    ] {
        let refused = door::invoke(
            &owner,
            "vault.tasks.comm_widen.revoke",
            json!({"attempt": hex(attempt.as_bytes())}),
        )
        .expect_err("no standing to end");
        assert_eq!(
            refused.code,
            oneiron::MEMORY_CODE_NOT_FOUND,
            "{what}: {refused:?}"
        );
    }
    Ok(())
}

/// P3: the mapping round-trips at its revision; a replay answers the first
/// receipt; a stale revision and a reused key are refused.
#[test]
fn the_linear_mapping_round_trips_at_its_revision() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let task = owner_task(&owner, &vault)?.to_hex();

    let before = door::invoke(
        &owner,
        "vault.tasks.linear.mapping",
        json!({"task_ref": task}),
    )?;
    assert_eq!(before["task_ref"], task);
    assert_eq!(before["mapping_revision"], 0, "{before}");
    assert_eq!(before["link"], Value::Null, "{before}");
    assert_eq!(before["opted_out"], false, "{before}");

    // In-process, `link` has no tracker team to name: it is refused and
    // writes nothing.
    let no_team = door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(
            &task,
            0,
            "link-1",
            json!({"kind": "link", "issue_id": "issue-1", "identifier": "ENG-1"}),
        ),
    )
    .expect_err("a link with no tracker team is refused");
    assert_eq!(
        no_team.code,
        oneiron::MEMORY_CODE_INVALID_STATE,
        "{no_team:?}"
    );

    let edited = door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-1", json!({"kind": "mirror"})),
    )?;
    assert_eq!(edited["task_ref"], task);
    assert_eq!(edited["op"], "mirror", "{edited}");
    assert_eq!(edited["mapping_revision"], 1, "{edited}");
    assert_eq!(edited["opted_out"], false, "{edited}");
    assert_eq!(edited["replayed"], false, "{edited}");
    let event = edited["event_ref"]
        .as_str()
        .ok_or("the edit's event")?
        .to_owned();

    let after = door::invoke(
        &owner,
        "vault.tasks.linear.mapping",
        json!({"task_ref": task}),
    )?;
    assert_eq!(after["mapping_revision"], 1, "{after}");
    assert_eq!(after["opted_out"], false, "{after}");
    assert!(
        after["dirty_revision"].is_u64(),
        "a mirror marks the TASK to push: {after}"
    );
    assert!(
        after["newest_event_refs"]
            .as_array()
            .is_some_and(|events| events.iter().any(|seen| seen == event.as_str())),
        "the mapping names its newest edit: {after}"
    );

    // The same key and edit answer the first receipt.
    let replayed = door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-1", json!({"kind": "mirror"})),
    )?;
    assert_eq!(replayed["replayed"], true, "{replayed}");
    assert_eq!(replayed["mapping_revision"], 1);
    assert_eq!(replayed["event_ref"], event.as_str());
    assert_eq!(replayed["at"], edited["at"]);

    // The same key with another edit is refused.
    let reused = door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-1", json!({"kind": "unlink"})),
    )
    .expect_err("a key names one edit");
    assert_eq!(reused.code, oneiron::MEMORY_CODE_BAD_REQUEST, "{reused:?}");

    // An edit at a revision the mapping moved past is refused.
    let stale = door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-2", json!({"kind": "mirror"})),
    )
    .expect_err("the mapping moved");
    assert_eq!(stale.code, oneiron::MEMORY_CODE_INVALID_STATE, "{stale:?}");
    let last = door::invoke(
        &owner,
        "vault.tasks.linear.mapping",
        json!({"task_ref": task}),
    )?;
    assert_eq!(last["mapping_revision"], 1, "{last}");
    Ok(())
}

/// P3: provenance lists the one edit that landed, names its editor, and
/// leaves out what was refused or replayed.
#[test]
fn provenance_names_each_mapping_edit_and_its_editor() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let task = owner_task(&owner, &vault)?.to_hex();

    let empty = door::invoke(
        &owner,
        "vault.tasks.linear.provenance",
        json!({"task_ref": task}),
    )?;
    assert_eq!(empty["events"], json!([]), "{empty}");

    let edited = door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-1", json!({"kind": "mirror"})),
    )?;
    let event = edited["event_ref"]
        .as_str()
        .ok_or("the edit's event")?
        .to_owned();
    // A replay and a refused stale edit leave no row.
    door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-1", json!({"kind": "mirror"})),
    )?;
    door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-2", json!({"kind": "mirror"})),
    )
    .expect_err("the mapping moved");

    let page = door::invoke(
        &owner,
        "vault.tasks.linear.provenance",
        json!({"task_ref": task}),
    )?;
    assert_eq!(page["task_ref"], task);
    let events = page["events"].as_array().ok_or("the page lists events")?;
    assert_eq!(events.len(), 1, "{page}");
    assert_eq!(events[0]["event_ref"], event.as_str(), "{page}");
    let row = &events[0]["event"];
    assert_eq!(row["direction"], "mapping_edit", "{row}");
    assert_eq!(row["status"], "mirror", "{row}");
    assert_eq!(row["task_ref"], task, "{row}");
    assert_eq!(row["writer_actor"], owner_id.to_hex(), "{row}");
    assert_eq!(page["next_cursor"], Value::Null, "{page}");
    Ok(())
}

/// P3: a TASK a bound credential does not read is not found on the Linear
/// rows, as a TASK that does not exist is.
#[test]
fn a_task_the_credential_does_not_read_is_not_found() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = door::owner(&vault)?;
    let task = owner_task(&owner, &vault)?.to_hex();
    door::invoke(
        &owner,
        "vault.tasks.linear.mapping.edit",
        edit(&task, 0, "mirror-1", json!({"kind": "mirror"})),
    )?;

    // A reader whose credential names one other record, as the esign
    // admission tests narrow theirs.
    let reader = person(&vault, EntityId::now())?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let mut claims = root.claims;
    claims.slip_id = [0x74; 32];
    claims.holder_ref = reader.to_hex();
    claims.actor_class = Some("human".to_owned());
    let mut slip = vault.mint_capability_slip(&issuer, claims)?;
    issuer.attenuate(
        &mut slip,
        SlipCaveat {
            records: Some(std::iter::once(reader.to_hex()).collect()),
            ..Default::default()
        },
    )?;
    let binding = issuer.binding_proof(&slip, CHALLENGE)?;
    let proof = vault.verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &binding)?;
    let bound = vault
        .memory(reader, EdgeActorClass::Human)
        .with_read_proof(&proof);

    for (verb, body) in [
        ("vault.tasks.linear.mapping", json!({"task_ref": task})),
        ("vault.tasks.linear.provenance", json!({"task_ref": task})),
        (
            "vault.tasks.linear.mapping.edit",
            edit(&task, 1, "reader-1", json!({"kind": "mirror"})),
        ),
    ] {
        let refused = door::invoke(&bound, verb, body).expect_err("the credential reads no TASK");
        assert_eq!(
            refused.code,
            oneiron::MEMORY_CODE_NOT_FOUND,
            "{verb}: {refused:?}"
        );
    }
    // The refused edit left no row: the owner's one edit is all there is.
    let page = door::invoke(
        &owner,
        "vault.tasks.linear.provenance",
        json!({"task_ref": task}),
    )?;
    assert_eq!(page["events"].as_array().map(Vec::len), Some(1), "{page}");
    Ok(())
}

/// One table: the owner rows refuse a non-owner; the mapping edit refuses a
/// caller that is no party to the TASK as not found; unknown ids are not
/// found; malformed bodies are bad requests.
#[test]
fn a_foreign_or_malformed_task_act_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = door::owner(&vault)?;
    let (assigned, agent, _) = assigned_task(&vault)?;
    let assigned = assigned.to_hex();
    let owned = owner_task(&owner, &vault)?.to_hex();
    let attempt = hex(&[0x9e; 16]);
    let unknown = EntityId::from_bytes([0x9f; 16])?.to_hex();
    let stranger = vault.memory(person(&vault, EntityId::now())?, EdgeActorClass::Agent);
    let human = vault.memory(person(&vault, EntityId::now())?, EdgeActorClass::Human);
    let as_agent = vault.memory(agent, EdgeActorClass::Agent);

    // The owner rows: no caller but the embedded owner.
    for (who, caller) in [
        ("stranger agent", &stranger),
        ("other human", &human),
        ("run's agent", &as_agent),
    ] {
        for (verb, body) in [
            ("vault.tasks.cancel.force", json!({"task_ref": assigned})),
            ("vault.tasks.comm_widen.revoke", json!({"attempt": attempt})),
        ] {
            let refused = door::invoke(caller, verb, body).expect_err("no owner");
            assert_eq!(
                refused.code,
                oneiron::MEMORY_CODE_FORBIDDEN,
                "{who} {verb}: {refused:?}"
            );
        }
    }

    // The mapping edit: a caller that is no party to the owner's TASK finds
    // none, and its refusal leaves no mapping row.
    let refused = door::invoke(
        &stranger,
        "vault.tasks.linear.mapping.edit",
        edit(&owned, 0, "stranger-1", json!({"kind": "mirror"})),
    )
    .expect_err("no party");
    assert_eq!(refused.code, oneiron::MEMORY_CODE_NOT_FOUND, "{refused:?}");
    let page = door::invoke(
        &owner,
        "vault.tasks.linear.provenance",
        json!({"task_ref": owned}),
    )?;
    assert_eq!(page["events"], json!([]), "{page}");

    // Unknown ids.
    for (verb, body) in [
        ("vault.tasks.cancel.force", json!({"task_ref": unknown})),
        ("vault.tasks.comm_widen.revoke", json!({"attempt": attempt})),
        (
            "vault.tasks.linear.provenance",
            json!({"task_ref": unknown}),
        ),
        (
            "vault.tasks.linear.mapping.edit",
            edit(&unknown, 0, "unknown-1", json!({"kind": "mirror"})),
        ),
    ] {
        let refused = door::invoke(&owner, verb, body).expect_err("unknown ids stay unknown");
        assert_eq!(
            refused.code,
            oneiron::MEMORY_CODE_NOT_FOUND,
            "{verb}: {refused:?}"
        );
    }

    // Malformed bodies: unknown fields, missing fields, bad values.
    for (verb, body) in [
        (
            "vault.tasks.cancel.force",
            json!({"task_ref": assigned, "nope": 1}),
        ),
        ("vault.tasks.cancel.force", json!({})),
        (
            "vault.tasks.comm_widen.revoke",
            json!({"attempt": attempt, "nope": 1}),
        ),
        (
            "vault.tasks.comm_widen.revoke",
            json!({"attempt": "not-hex"}),
        ),
        (
            "vault.tasks.linear.mapping",
            json!({"task_ref": owned, "nope": 1}),
        ),
        (
            "vault.tasks.linear.provenance",
            json!({"task_ref": owned, "nope": 1}),
        ),
        (
            "vault.tasks.linear.provenance",
            json!({"task_ref": owned, "cursor": "not-a-cursor"}),
        ),
        (
            "vault.tasks.linear.mapping.edit",
            json!({"task_ref": owned, "expected_mapping_revision": 0, "intent_key": "k", "op": {"kind": "mirror"}, "nope": 1}),
        ),
        (
            "vault.tasks.linear.mapping.edit",
            edit(&owned, 0, "   ", json!({"kind": "mirror"})),
        ),
        (
            "vault.tasks.linear.mapping.edit",
            edit(&owned, 0, "k", json!({"kind": "teleport"})),
        ),
    ] {
        let refused = door::invoke(&owner, verb, body.clone()).expect_err("malformed");
        assert_eq!(
            refused.code,
            oneiron::MEMORY_CODE_BAD_REQUEST,
            "{verb} {body}: {refused:?}"
        );
    }
    Ok(())
}
