//! A run's own skill pack load on the caller's attached live run (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.pack.load`. The grant is the
//! caller's own run: the live-run guard holds it and rechecks its lease and
//! attachment, the load checks that lease again in its own transaction, and
//! the skill must be one the caller's credential reads. No owner proof
//! stands in for a run.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{self, LiveRunRequest, SkillPackLoadRequest, SkillPackLoaded};

use super::host_doors::support::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.skills.pack.load` (`host_door_lists`): the pack's files, beside the
/// rows its instructions were read from (the loaded SKILL or proposal and
/// any replicated package carrier). A refusal lists none.
pub(crate) async fn vault_skills_pack_load(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<SkillPackLoadRequest>,
) -> Listed<SkillPackLoaded> {
    match pack_load(server, auth, session, input).await {
        Ok((loaded, rows)) => (Ok(loaded), rows),
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

async fn pack_load(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<SkillPackLoadRequest>,
) -> MemoryResult<(SkillPackLoaded, Vec<oneiron::EntityId>)> {
    const VERB: &str = "vault.skills.pack.load";
    let (writer, run, held) =
        super::live_run_doors::hold_live_run(server, auth, session, &input.live_run).await?;
    let executor = run.planner().1.to_owned();
    let auth = auth.clone();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        // Keep the run held until the load and its stamp land.
        let _held = held;
        let binding = _held.proof();
        let memory = crate::api::credential_memory(
            server.vault(),
            Some(&auth),
            writer.entity_ref(),
            writer.actor_class(),
        )
        .at(auth.locality());
        if memory
            .get_entity(&input.spec.skill.to_hex())?
            .value
            .is_none()
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a pack load requires a skill this run's own credential reads",
                &[],
            ));
        }
        sdk::skill_pack_load_on_live_run(server.vault(), &binding, &executor, &input.spec)
    })
    .await
    .map_err(|_| internal(VERB))?
}
