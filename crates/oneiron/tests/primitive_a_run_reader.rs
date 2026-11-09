//! Primitive A, slice 6.4c (SLICE6-MAP row A; ENGINE CALL S64-3 = A):
//! `vault.runs.step` and `vault.runs.checkpoint` keep their names, and their
//! admission widens from the owner alone to the owner or the run's own actor.
//! On main an agent asking for its own attempt's step is refused as the
//! owner's door; here it is admitted (and, with no step under that hash,
//! answers none), while a caller that is not the run's actor stays refused.
//!
//! Public paths only: the generated engine fns in `oneiron::verbs`.

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::engine_executor::checkpoint_read::CheckpointReadRequest;
use oneiron::llm::model_step::SettledStepRequest;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open(dir.path(), config)?;
    Ok((dir, vault))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn an_agent_reads_its_own_attempts_steps_and_no_one_elses() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    let agent = status.input.target.agent_definition_ref()?;
    let request = SettledStepRequest {
        job_ref: hex(status.attempt.id.as_bytes()),
        step_hash: "00".repeat(32),
    };

    // The run's own actor is admitted; no step is recorded under this hash.
    let own = oneiron::verbs::vault_runs_step(
        &vault.memory(agent, EdgeActorClass::Agent),
        request.clone(),
    )?;
    assert!(own.is_none());

    // A person who is not the run's actor stays refused.
    let stranger = EntityId::now();
    vault.put_entity(
        &stranger,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"not the run's actor",
    )?;
    assert!(
        oneiron::verbs::vault_runs_step(
            &vault.memory(stranger, EdgeActorClass::Human),
            request.clone()
        )
        .is_err()
    );

    // The owner reads any attempt, as before.
    let owner = vault.ensure_embedded_owner_actor()?;
    assert!(
        oneiron::verbs::vault_runs_step(&vault.memory(owner, EdgeActorClass::Human), request)?
            .is_none()
    );
    Ok(())
}

#[test]
fn a_caller_that_is_not_a_code_runs_actor_is_refused_its_checkpoints() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let stranger = EntityId::now();
    vault.put_entity(
        &stranger,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"not the run's actor",
    )?;
    let request = CheckpointReadRequest {
        run_ref: EntityId::now().to_hex(),
        from_step: 0,
        limit: None,
    };
    assert!(
        oneiron::verbs::vault_runs_checkpoint(
            &vault.memory(stranger, EdgeActorClass::Human),
            request.clone()
        )
        .is_err()
    );
    // The owner's read is unchanged: an unknown run reads as absent.
    let owner = vault.ensure_embedded_owner_actor()?;
    assert!(
        oneiron::verbs::vault_runs_checkpoint(
            &vault.memory(owner, EdgeActorClass::Human),
            request
        )?
        .is_none()
    );
    Ok(())
}
