//! Primitive A, slice 6.4f (SLICE6-MAP row A; relay STEWARD-LANDED): the
//! Steward arm of the run reader. A Steward of this shared vault (the role
//! as #6886 defines it) reads another agent's run through `vault.runs.step`
//! and `vault.runs.checkpoint`; a member without the role stays refused. On
//! 6.4e a Steward that is not the run's actor is refused.
//!
//! The member grants are stood through the `oneiron_test_support` door
//! (`oneiron::test_doors::membership`), because an invited member joins only
//! on its own acceptance proof:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test primitive_a_steward_run_reader`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::engine_executor::checkpoint_read::CheckpointReadRequest;
use oneiron::federation::FederationGrantRole;
use oneiron::llm::model_step::SettledStepRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SHARED: u64 = 42;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    Ok((dir, vault))
}

fn person(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person of the shared vault",
    )?;
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_steward_reads_another_agents_run_and_a_member_cannot() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.initialize_shared_vault(&proof, SHARED, None, &[], 1)?;
    let steward = person(&vault)?;
    let member = person(&vault)?;
    stand_member_grant(&vault, steward, SHARED, FederationGrantRole::Steward)?;
    stand_member_grant(&vault, member, SHARED, FederationGrantRole::Member)?;

    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    let step = SettledStepRequest {
        job_ref: hex(status.attempt.id.as_bytes()),
        step_hash: "00".repeat(32),
    };
    let checkpoint = CheckpointReadRequest {
        run_ref: EntityId::now().to_hex(),
        from_step: 0,
        limit: None,
    };

    // The Steward is no actor of the agent's attempt, and reads it: no step
    // is recorded under this hash, and an unknown run reads as absent.
    let as_steward = vault.memory(steward, EdgeActorClass::Human);
    assert!(oneiron::verbs::vault_runs_step(&as_steward, step.clone())?.is_none());
    assert!(oneiron::verbs::vault_runs_checkpoint(&as_steward, checkpoint.clone())?.is_none());

    // A member without the role stays refused.
    let as_member = vault.memory(member, EdgeActorClass::Human);
    assert!(oneiron::verbs::vault_runs_step(&as_member, step).is_err());
    assert!(oneiron::verbs::vault_runs_checkpoint(&as_member, checkpoint).is_err());
    Ok(())
}
