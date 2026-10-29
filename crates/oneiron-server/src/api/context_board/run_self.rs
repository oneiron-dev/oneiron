//! A pumped run's own `describe(self)` (FIX 2086): the self brief of the
//! run's agent, rendered by the renderer the authenticated path uses
//! ([`super::describe_self_for_auth`]) from the run snapshot a trusted host
//! installed ([`crate::server::SyncServer::install_self_brief_session`]).
//! A run's snapshot is keyed by its agent and its own board connection
//! (`run:<run id>`), never by a credential's session, and goes when that
//! connection does. Nothing here resolves authority: a run with no snapshot
//! installed is told so, as a credential's run is.

use oneiron::context_board::StreamConnectionId;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::DescribeRequest;

use crate::server::SyncServer;

/// Answers a pumped run's `describe(self)` for its agent `actor`, over the
/// run's own board `connection`: the brief of the run's installed snapshot,
/// with the agent's loaded skills from the run's own session reads and the
/// PEOPLE its own lane reads, and beside it the rows the brief is derived
/// from ([`oneiron::context_board::SelfBrief::sources`]). The wire value is
/// the credential path's `TaskDescription::SelfCard`.
pub(crate) async fn describe_self_for_run(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &StreamConnectionId,
    request: &DescribeRequest,
) -> MemoryResult<(serde_json::Value, Vec<oneiron::EntityId>)> {
    // describe(self) names the run's own brief and nothing else (FIX 3256).
    request.validate()?;
    if !request.self_target {
        return Err(MemoryError::bad_request("describe(self) names the run's own brief"));
    }
    let people = run_people(server, actor)?;
    let reads = crate::api::run_session_reads(server, actor, connection).await;
    let runs = server.self_brief_sessions.lock().await;
    let run = runs
        .get(&(actor.entity_ref(), connection.0.clone()))
        .ok_or_else(|| MemoryError::bad_request("run has no self brief"))?;
    let brief = run.state.describe(&server.vault, &reads, Some(&people))?;
    let sources = brief.sources(&server.vault, Some(&people))?;
    drop(runs);
    let value = serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard {
        tail: brief.render(),
    })
    .map_err(|_| internal("self brief encoding failed"))?;
    Ok((value, sources))
}

/// The vault's people as the agent's own lane on this device reads them,
/// each `about` the stored line of the highest band that lane reads, and
/// the names it may be told disclosed.
fn run_people(
    server: &SyncServer,
    actor: oneiron::WriteActor,
) -> MemoryResult<oneiron::context_board::People> {
    let key = oneiron::claim::ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| internal("run actor key invalid"))?;
    let read = server
        .vault
        .scoped_read(key.at(oneiron::claim::CallerLocality::OnDevice));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let mut people = oneiron::context_board::People::load(&server.vault, now, &mut |person| {
        read.is_entity_readable(&person)
    })?;
    let applied = read.read_receipt(None, 0)?.applied;
    let ceiling = (!applied.deny_all).then_some(applied.max_sensitivity_band);
    people.set_about(&mut |person| server.vault.person_about(person, ceiling))?;
    people.disclose_names(&server.vault, read.actor_key())?;
    Ok(people)
}

fn internal(message: &str) -> MemoryError {
    MemoryError::new(
        oneiron::memory::MEMORY_CODE_INTERNAL,
        message,
        &["Report this host-door failure."],
    )
}
