//! A pumped run's own `describe(self)` (FIX 2086): the self brief of the
//! run's agent, rendered by the self-brief renderer the authenticated path
//! uses ([`super::describe_self_for_auth`]).
//!
//! A snapshot a trusted host installed for the run
//! ([`crate::server::SyncServer::install_self_brief_session`], keyed by the
//! agent and the run's own board connection `run:<run id>`) renders whole,
//! and goes when that connection does. Without one, the brief is resolved
//! from the run itself: the agent, the person its subject anchor names, the
//! owner's agent Grants that stand for the agent, the run, credential and
//! parent ceilings its host holds the facts for ([`BriefHostFacts`]), the
//! line the run's entry spends on, the clock and the skills the run's own
//! session loaded. Every field no host resolves is left out of the brief
//! and named on one unavailable line
//! ([`oneiron::context_board::SelfBrief::render`]), never stated as a value.

use oneiron::context_board::{
    BriefCredentialCeiling, BriefRunCeiling, BriefWorkingSet, CommunicationLimits, SelfBriefState,
    SessionReadSet, StreamConnectionId,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::DescribeRequest;

use crate::server::SyncServer;

/// What the host that resolves a brief holds for it (FIX 17594, Engine
/// ruling 21:47), each `None` where it holds none: the run ceiling of the
/// dispatch attempt its run's entry in flight serves, and the credential
/// ceiling of the verified slip it admitted. A credential's call is bound
/// to no attempt, so it holds no run ceiling; an ordinary pumped run holds
/// no verified slip, so it holds no credential ceiling.
#[derive(Debug, Default)]
pub(crate) struct BriefHostFacts {
    pub(crate) run_ceiling: Option<BriefRunCeiling>,
    pub(crate) credential_ceiling: Option<BriefCredentialCeiling>,
}

/// Answers a pumped run's `describe(self)` for its agent `actor`, over the
/// run's own board `connection`, its entry spending on `line`: the run's
/// brief with the agent's loaded skills from the run's own session reads,
/// the PEOPLE its own lane reads and the ceilings its door holds the facts
/// for (`host`), and beside it the rows the brief is derived from
/// ([`oneiron::context_board::SelfBrief::sources`]). The wire value is the
/// credential path's `TaskDescription::SelfCard`.
pub(crate) async fn describe_self_for_run(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &StreamConnectionId,
    line: Option<&RunAdmission>,
    host: &BriefHostFacts,
    request: &DescribeRequest,
) -> MemoryResult<(serde_json::Value, Vec<oneiron::EntityId>)> {
    // describe(self) names the run's own brief and nothing else (FIX 3256).
    request.validate()?;
    if !request.self_target {
        return Err(MemoryError::bad_request(
            "describe(self) names the run's own brief",
        ));
    }
    let people = run_people(server, actor)?;
    let reads = crate::api::run_session_reads(server, actor, connection).await;
    let installed = server
        .self_brief_sessions
        .lock()
        .await
        .get(&(actor.entity_ref(), connection.0.clone()))
        .map(|run| run.state.clone());
    let state = match installed {
        Some(state) => state,
        None => resolved_state(server, actor, line, &reads, host)?,
    };
    let brief = state.describe(&server.vault, &reads, Some(&people))?;
    let tail = brief.render();
    let sources = brief.sources(&server.vault, Some(&people))?;
    let value = serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard { tail })
        .map_err(|_| internal("self brief encoding failed"))?;
    Ok((value, sources))
}

/// The run's brief state as the run itself resolves it for its agent
/// `actor`, with the ceilings its host holds the facts for (`host`). Each
/// field no host produces for a run (FIX-LIST: the self-brief producers) is
/// `None`; so is the principal when no subject anchor names the person
/// behind the agent, so are the grants and the parent ceiling when their
/// read fails, so are the run and parent ceilings when the host bound no
/// dispatch attempt, so is the credential ceiling when it verified no slip,
/// and so are the budget lease and budget when no line binds the run's
/// entry. [`oneiron::context_board::SelfBrief::render`] leaves each `None`
/// field out and names it unavailable. A credentialed agent's
/// describe(self) with no installed snapshot resolves its brief here too,
/// over its own session's reads and with no line (FIX 11461).
pub(super) fn resolved_state(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    line: Option<&RunAdmission>,
    reads: &SessionReadSet,
    host: &BriefHostFacts,
) -> MemoryResult<SelfBriefState> {
    let self_ref = actor.entity_ref();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let clock_ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
    // Subject anchors are dated in milliseconds, as PEOPLE reads them.
    let principal =
        oneiron::subject_model::actor_subject_anchor(&server.vault, &self_ref, clock_ms)?;
    // The skills the run's own session loaded, each one whose record
    // stands: a brief describes a skill from its record.
    let mut skill_index = Vec::new();
    for (id, _) in reads.loaded_skills() {
        let Ok(id) = oneiron::EntityId::from_hex(id) else {
            continue;
        };
        if !skill_index.contains(&id) && server.vault.get_skill_record(&id)?.is_some() {
            skill_index.push(id);
        }
    }
    // GRANT (FIX 17594): the owner's agent Grants that stand for the agent,
    // read in one snapshot. A failed read leaves them unavailable; it never
    // fails the describe.
    let grants = server
        .vault
        .self_brief_grants(actor)
        .inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the self brief's grants did not read; the brief names them unavailable"
            );
        })
        .ok();
    // PARENT (FIX 17594): each delegation ancestor of the attempt the host
    // bound the run to, read in one snapshot. A host bound to no attempt has
    // no chain to read; a failed read leaves it unavailable.
    let parent_ceiling = host.run_ceiling.as_ref().and_then(|run| {
        server
            .vault
            .self_brief_parent_ceiling(actor, run.attempt)
            .inspect_err(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the self brief's parent ceiling did not read; the brief names it unavailable"
                );
            })
            .ok()
            .flatten()
    });
    Ok(SelfBriefState {
        self_ref,
        principal,
        grants,
        run_ceiling: host.run_ceiling.clone(),
        credential_ceiling: host.credential_ceiling.clone(),
        parent_ceiling,
        communication: CommunicationLimits {
            reach: None,
            credential_ceiling: None,
        },
        ceilings: None,
        budget_lease_id: line.map(|line| line.run().to_owned()),
        budget: line.map(RunAdmission::read),
        clock_ms,
        skill_index,
        working_set: BriefWorkingSet {
            scratchpad: None,
            pins: None,
            replay: None,
        },
    })
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
    people.set_about(&mut |person| server.vault.person_about_sourced(person, ceiling))?;
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
