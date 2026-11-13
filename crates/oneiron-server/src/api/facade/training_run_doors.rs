//! The owner's role-training prepare door (ROLE-TRAINING-RUN, LEARN-TRAIN Q1).
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    RoleTrainingPrepareRequest, RoleTrainingPrepared, TRAINING_RUN_PREPARE_VERB,
};

use super::host_doors::support::{MaybeListed, internal, owner_proof};
use crate::ai_host::training_pack::trainer_binding;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.coach.training_runs.prepare`: the owner's role run with no Train
/// offer, on a trainer connector this host names. It exports the consented
/// corpus and pins the spec; nothing runs until the owner authorizes that
/// spec. The door lists the rows the run was prepared from (FIX 5760),
/// unknown when the run's are; a refusal lists none.
pub(crate) async fn vault_coach_training_runs_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RoleTrainingPrepareRequest,
) -> MaybeListed<RoleTrainingPrepared> {
    let owner = match owner_proof(auth, server, TRAINING_RUN_PREPARE_VERB) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Some(Vec::new())),
    };
    let server = Arc::clone(server);
    let prepared = super::clock_ingress::run_blocking(move || -> MemoryResult<_> {
        let binding = trainer_binding(&server, &input.connector).ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                format!("this host names no trainer connector {:?}", input.connector),
                &["Name a connector from this host's [models.training.connectors]."],
            )
        })?;
        server
            .vault()
            .prepare_training_pack(
                &owner,
                &input.draft,
                input.scope.reservoir_scope(),
                &binding,
            )
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(TRAINING_RUN_PREPARE_VERB))
    .and_then(|prepared| prepared);
    match prepared {
        Ok(run) => (Ok(RoleTrainingPrepared::of(&run)), run.source_rows),
        Err(error) => (Err(error), Some(Vec::new())),
    }
}
