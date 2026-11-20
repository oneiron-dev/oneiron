//! A second, different task assignment is refused with a typed 409 (FIX
//! [TASK-ASSIGNED-FORK-ON-CONCURRENT-AMENDED-SETTLES]).
//!
//! Two of the owner's devices approve ONE task proposal with different amended
//! assignees. When the other device's Assigned fact is already here, the local
//! approve answers 409 INVALID_STATE with typed fields (the task id, the held
//! assignee and the offered one), not success and not 400. The proposal stays
//! pending and the task's facts still fold on the held assignment. A fork that
//! did commit still fails closed at every read.
//!
//! Red at HEAD (the approve returns Ok and lands the second binding, so the
//! first assert fails); green with the fix.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_assignment_conflict_refused`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, MEMORY_CODE_INVALID_STATE,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_authority::TaskMaker;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskKind};
use oneiron::test_doors::task_fact_actor::mint_fact;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    ClaimApprovalStatus, EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SUBKIND,
    TaskAuthorityFactKind, TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::entity_id::derived_domains::TASK_SETTLE;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

/// Lands one TASK row as another of the owner's devices sends it: the own-device replay
/// door admits role 6 like any other TASK row.
fn replay_task_row(vault: &Vault, row: EntityId, body: &[u8]) -> oneiron::Result<()> {
    let now = vault.now_recorded_at();
    replay_entity(
        vault,
        ReplicatedEntity {
            id: row,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
}

/// [`replay_task_row`], and the row's `ScopedTo` link to `task`.
fn land_replicated_fact(vault: &Vault, row: EntityId, task: EntityId, body: &[u8]) {
    replay_task_row(vault, row, body).expect("the own-device replay door lands the row");
    vault
        .batch()
        .edge(&row, EdgeKind::ScopedTo, &task, SCOPED_TO_WEIGHT)
        .commit()
        .expect("the row's link to its task");
}

/// The authority fact rows linked to `task`, as `(id, body)`.
fn fact_rows(vault: &Vault, task: EntityId) -> Vec<(EntityId, Vec<u8>)> {
    vault
        .edges_in(&task)
        .expect("the task's links")
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::ScopedTo)
        .filter_map(|edge| {
            let raw = vault.get_raw(&edge.target).expect("the linked row")?;
            let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
            let text = String::from_utf8_lossy(&body);
            text.contains(TASK_AUTHORITY_FACT_SUBKIND)
                .then_some((edge.target, body))
        })
        .collect()
}

/// The `assigned_ref` hex one fact body names, if it names one.
fn assigned_ref_of(body: &[u8]) -> Option<String> {
    let Value::Map(entries) = rmpv::decode::read_value(&mut &body[..]).ok()? else {
        return None;
    };
    for (key, value) in entries {
        if key.as_str() == Some("assigned_ref") {
            return value.as_str().map(str::to_owned);
        }
    }
    None
}

/// A rooted vault on a hosted node: its install's profile stands in its own fold, its
/// install signer is loaded, and its owner is bound, so its doors sign every fact.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    vault_id: [u8; 32],
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .prepare_install_signing()
        .expect("the host's install signer");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the host's fold")
        .vault_id
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        _issuer: issuer,
        owner,
        vault_id,
    }
}

/// The owner's device: its own install, which the owner enrols as his on the host, holding
/// the vault's authority history as sync gives it.
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn device(host: &Host) -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("the device's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("the device's enrolment request");
    let owner = host
        .vault
        .authenticate_owner(
            host.owner,
            &host.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof");
    host.vault
        .enroll_machine(
            &owner,
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the device as his");
    let history = host
        .vault
        .export_signed_authority_history()
        .expect("the host's history");
    vault
        .import_signed_authority_history(&history)
        .expect("the device takes the history");
    Device { _dir: dir, vault }
}

fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person of the vault",
        )
        .expect("the person row");
}

#[test]
fn a_second_different_assignment_is_refused_with_typed_conflict() {
    let host = host();
    let device = device(&host);
    let held = EntityId::from_bytes([0xA1; 16]).expect("the held assignee id");
    let offered = EntityId::from_bytes([0xA2; 16]).expect("the offered assignee id");
    let proposer = EntityId::from_bytes([0xE2; 16]).expect("the proposer's id");
    for person in [held, offered, proposer] {
        put_person(&host.vault, person);
    }
    // P parks: the foreign agent's create proposes, its ceiling is not Auto.
    let receipt = host
        .vault
        .memory(proposer, EdgeActorClass::Agent)
        .tasks_create(
            &TaskCreateSpec::new(
                Value::Nil,
                Some("assign me".to_owned()),
                Some(host.owner),
                Some(host.vault.now_recorded_at()),
            )
            .with_kind(TaskKind::Standard)
            .with_assignee(TaskAssignee::Peer { actor_ref: offered }),
        )
        .expect("the foreign create parks its proposal");
    assert!(receipt.task_ref.is_none(), "nothing lands before approval");
    assert_eq!(receipt.approval, ClaimApprovalStatus::Proposed);
    let proposal = receipt.proposal_ref.expect("the parked proposal P");
    // The task id P's settle derives: its proposer makes it for its owner under the
    // settle nonce of its claim.
    let nonce =
        EntityId::derive(TASK_SETTLE, &[proposal.as_bytes()]).expect("the settle nonce derives");
    let task = TaskMaker {
        maker_ref: proposer,
        nonce,
    }
    .task_ref(host.owner)
    .expect("the settled task id derives");
    // The other device assigned the task to `held`; its fact lands here without the
    // TASK row.
    let row = mint_fact(
        &device.vault,
        task,
        TaskAuthorityFactKind::Assigned,
        host.owner,
        Some(held),
    )
    .expect("the device assigns the task to held");
    let body = fact_rows(&device.vault, task)
        .into_iter()
        .find_map(|(id, body)| (id == row).then_some(body))
        .expect("the device holds the assigned fact row");
    land_replicated_fact(&host.vault, row, task, &body);
    // The owner approves P, whose value names `offered`.
    let owner = host
        .vault
        .authenticate_owner(
            host.owner,
            &host.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof");
    let memory = host.vault.memory(host.owner, EdgeActorClass::Human);
    let review = memory
        .claim_review_as_owner(
            &owner,
            &ClaimProposalReviewRequest {
                claim_ref: proposal.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the parked proposal");
    let err = memory
        .claim_settle_as_owner(
            &owner,
            &ClaimSettleRequest {
                claim_ref: proposal.to_hex(),
                review_id: review.review_id.clone(),
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
        .expect_err("a second, different assignment is refused");
    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    let conflict =
        &serde_json::to_value(&err).expect("the error serializes")["task_assignment_conflict"];
    assert_eq!(conflict["task_ref"], task.to_hex());
    assert_eq!(conflict["held_assignee"], held.to_hex());
    assert_eq!(conflict["offered_assignee"], offered.to_hex());
    // The proposal stays pending and the facts still fold on the held binding.
    let parked = host
        .vault
        .get_claim(&proposal)
        .expect("the proposal reads")
        .expect("the proposal is still here");
    assert_eq!(parked.approval, ClaimApprovalStatus::Proposed);
    host.vault
        .task_authority_state(task)
        .expect("the task's facts still fold");
    let assigned: Vec<String> = fact_rows(&host.vault, task)
        .iter()
        .filter_map(|(_, body)| assigned_ref_of(body))
        .collect();
    assert_eq!(assigned, vec![held.to_hex()]);
}
