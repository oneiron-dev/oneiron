//! The run TASK's writer proof (FIX AGENT-RUN-HANDOVER-TRUSTS-REPLICATED-PAYLOAD):
//! the handover re-creates an agent run from its TASK's frozen payload only
//! when a machine of the owner's signed it.
//!
//! A run TASK rides every machine's window and its bytes name no signer, so
//! the TASK of a run a peer machine holds may come from any writer. On main
//! the reaper re-creates the run's try here from whatever payload the TASK
//! carries (run_handover.rs take_expired_agent_run_in_txn): its agent, its
//! requester, its scope, depth, budget and parent link.
//!
//! Fixture: an owned vault whose install is profiled as the owner's own
//! machine, as tests/peer_route_full_copy.rs builds it, with one more
//! machine enrolled as the owner's own and one enrolled as rented. A
//! dispatch of the seeded base agent here gives a real frozen payload. The
//! door `agent_run_handover::put_peer_agent_run_task` puts the run TASK a
//! peer machine syncs for a run it holds under a fresh attempt id, with
//! that payload (or a forged one), its lease long expired, and the writer
//! proof each test names. Each test runs the host's reaper pass,
//! `Vault::reap_agent_run_leases`, which takes the peer's run when it may.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test agent_run_handover_writer_proof`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::attempt_queue::AttemptQueue;
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::agent_run_handover::{
    PeerWriter, agent_run_task_writer, put_peer_agent_run_task, queue_payload, with_dispatch_input,
};
use oneiron::{AttemptId, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The client id of the peer machine whose run lease expired.
const PEER_NODE: u64 = 0x5EED_0000_0000_0001;

/// An owned vault, its install the owner's own machine, a run dispatched
/// here, and two more machines with the keys that sign as them.
struct Fixture {
    vault: Vault,
    /// This install's machine.
    local: EntityId,
    /// The root run dispatched here.
    dispatched: AttemptId,
    /// The frozen payload that dispatch queued.
    payload: Vec<u8>,
    /// A machine the owner enrolled as his own.
    mine: (EntityId, SigningKey),
    /// A machine the owner enrolled as rented: not his own.
    rented: (EntityId, SigningKey),
}

fn fixture() -> TestResult<(Fixture, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let person = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"agent run handover writer proof test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))?;
    vault.prepare_install_signing()?;
    let local = vault
        .local_machine()?
        .ok_or("FIXTURE: this install has a machine once it is profiled")?
        .id;
    let owner = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    let mine = enroll(
        &vault,
        &owner,
        0xA7,
        MachineRole::Owned(MachineOwnership::Yours),
    )?;
    let rented = enroll(
        &vault,
        &owner,
        0xB7,
        MachineRole::Owned(MachineOwnership::Rented),
    )?;
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("FIXTURE: the seeded base agent")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("agent-run-handover-writer-proof".to_owned()),
                now: vault.now_recorded_at(),
            },
            AgentSpawnContext::default(),
        )?
    else {
        return Err("FIXTURE: the root run dispatches".into());
    };
    let dispatched = status.attempt.id;
    let payload = queue_payload(&vault, dispatched)?;
    Ok((
        Fixture {
            vault,
            local,
            dispatched,
            payload,
            mine,
            rented,
        },
        dir,
    ))
}

/// Enrols a fresh machine from `seed` in `role`, and answers its id with
/// the install key that signs as it: the enrolment proof its own key signs
/// for this vault, computer class (as test_doors::full_copy_mark does).
fn enroll(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: u8,
    role: MachineRole,
) -> TestResult<(EntityId, SigningKey)> {
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or("FIXTURE: the vault has a genesis-bound id")?;
    let machine = EntityId::from_bytes([seed; 16])?;
    let key = SigningKey::from_bytes(&[seed; 32]);
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let request = MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class,
        encryption_key: encryption_key.clone(),
        machine_proof: key
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes(),
    };
    vault.enroll_machine(owner, ActSurface::ThisInstall, &request, role, None)?;
    Ok((machine, key))
}

/// One reaper pass that runs every agent run its checks let it: answers how
/// many runs it took and how many it left waiting.
fn reap(vault: &Vault) -> TestResult<(usize, usize)> {
    let reap = vault.reap_agent_run_leases(&|_: &AgentDefinition| true)?;
    Ok((reap.taken, reap.waiting))
}

/// Whether this machine's queue holds a try under `attempt`.
fn queued_here(vault: &Vault, attempt: AttemptId) -> TestResult<bool> {
    Ok(AttemptQueue::new(vault).get(attempt)?.is_some())
}

#[test]
fn a_peer_run_task_with_no_writer_proof_is_not_taken() -> TestResult {
    let (fx, _dir) = fixture()?;
    let peer = put_peer_agent_run_task(&fx.vault, &fx.payload, PEER_NODE, None)?;
    assert_eq!(
        reap(&fx.vault)?,
        (0, 1),
        "a run TASK no machine signed waits; on main the reaper takes it (1, 0)"
    );
    assert!(
        !queued_here(&fx.vault, peer)?,
        "no try of the unproven run is queued here"
    );
    Ok(())
}

#[test]
fn a_run_task_whose_writer_is_no_machine_of_the_owners_is_not_taken() -> TestResult {
    let (fx, _dir) = fixture()?;
    let (machine, key) = &fx.rented;
    let peer = put_peer_agent_run_task(
        &fx.vault,
        &fx.payload,
        PEER_NODE,
        Some(PeerWriter {
            machine: *machine,
            key,
            signed_payload: None,
        }),
    )?;
    assert_eq!(
        reap(&fx.vault)?,
        (0, 1),
        "a run TASK a rented machine signed waits; on main the reaper takes it (1, 0)"
    );
    assert!(
        !queued_here(&fx.vault, peer)?,
        "no try of a run a rented machine signed is queued here"
    );
    Ok(())
}

#[test]
fn a_run_task_changed_after_its_writer_signed_it_is_not_taken() -> TestResult {
    let (fx, _dir) = fixture()?;
    let forged = with_dispatch_input(&fx.payload, |input| {
        input.depth_remaining = Some(64);
        input.budget = Some(u64::MAX);
    })?;
    assert_ne!(forged, fx.payload, "FIXTURE: the forged payload differs");
    let (machine, key) = &fx.mine;
    let peer = put_peer_agent_run_task(
        &fx.vault,
        &forged,
        PEER_NODE,
        Some(PeerWriter {
            machine: *machine,
            key,
            signed_payload: Some(&fx.payload),
        }),
    )?;
    assert_eq!(
        reap(&fx.vault)?,
        (0, 1),
        "a payload changed after its proof waits; on main the reaper takes it (1, 0)"
    );
    assert!(
        !queued_here(&fx.vault, peer)?,
        "no try of the forged payload is queued here"
    );
    Ok(())
}

#[test]
fn a_run_task_a_machine_of_the_owners_signed_is_taken() -> TestResult {
    let (fx, _dir) = fixture()?;
    let (machine, key) = &fx.mine;
    let peer = put_peer_agent_run_task(
        &fx.vault,
        &fx.payload,
        PEER_NODE,
        Some(PeerWriter {
            machine: *machine,
            key,
            signed_payload: None,
        }),
    )?;
    assert_eq!(
        agent_run_task_writer(&fx.vault, peer)?,
        Some(*machine),
        "FIXTURE: the peer's run TASK carries the proof of the owner's machine"
    );
    assert_eq!(
        reap(&fx.vault)?,
        (1, 0),
        "a run TASK a machine of the owner's signed is taken"
    );
    let queued = AttemptQueue::new(&fx.vault)
        .get(peer)?
        .ok_or("the taken run's live try is queued here under its own id")?;
    assert_eq!(
        queued.payload, fx.payload,
        "the try runs the payload the owner's machine signed"
    );
    Ok(())
}

#[test]
fn a_dispatch_here_signs_its_run_task() -> TestResult {
    let (fx, _dir) = fixture()?;
    assert_eq!(
        agent_run_task_writer(&fx.vault, fx.dispatched)?,
        Some(fx.local),
        "the run TASK a dispatch here mints carries this install's proof"
    );
    Ok(())
}
