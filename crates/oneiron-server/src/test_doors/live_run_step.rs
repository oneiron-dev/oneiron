//! Door for `tests/run_step_live_run.rs` ([RUN-STEP-DOOR-SERVER-TEST]): a
//! leased agent run on a test's server, registered as the resident pump's
//! entry registers it, so the run's own agent attaches to it over
//! `POST /v1/core/live-runs/{run}/attach` and calls `ai.steps.submit` with
//! the handle.

use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::SpendScopeId;
use oneiron::attempt_queue::AttemptRecord;
use oneiron::code_run::{
    CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism, CodeRunReplayRecord, HostSelfDispatcher,
};
use oneiron::{EntityId, Result, WriteActor};

use crate::server::SyncServer;

/// Registers run `run` of `actor`, whose leased try is `leased`, on
/// `server`'s live runs, as the pump's entry does (`enter_run`): under the
/// try's lease proof, from its frozen `definition`, executing on `model`,
/// spending under `spend_scope`. A run with no replay record gets its first
/// one, as the entry's first start saves it; an attach before that answers
/// busy.
///
/// # Errors
///
/// The lease proof's refusal (the try no longer holds that lease), and
/// storage errors.
pub fn register_live_run(
    server: &SyncServer,
    run: EntityId,
    actor: WriteActor,
    leased: &AttemptRecord,
    model: &str,
    definition: AgentDefinition,
    spend_scope: Option<SpendScopeId>,
) -> Result<()> {
    let vault = server.vault();
    let proof = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, leased)?
        .live_run_host_binding(run)?;
    if vault.get_code_run_replay_record(&run)?.is_none() {
        let determinism =
            CodeRunDeterminism::new(vault.now_recorded_ms(), [0; CODE_RUN_RNG_SEED_LEN]);
        vault.put_code_run_replay_record(&CodeRunReplayRecord::new(run, determinism))?;
    }
    server.live_runs.register(
        vault,
        run,
        actor,
        leased,
        proof,
        None,
        model.to_owned(),
        None,
        definition,
        spend_scope,
    )?;
    Ok(())
}
