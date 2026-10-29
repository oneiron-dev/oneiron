//! A pumped run's own `describe(self)` (FIX 2086): the self brief of the
//! run's agent, rendered by the self-brief renderer the authenticated path
//! uses ([`super::describe_self_for_auth`]).
//!
//! A snapshot a trusted host installed for the run
//! ([`crate::server::SyncServer::install_self_brief_session`], keyed by the
//! agent and the run's own board connection `run:<run id>`) renders whole,
//! and goes when that connection does. Without one, the brief is resolved
//! from the run itself: the agent, the person its subject anchor names, the
//! line the run's entry spends on, the clock and the skills the run's own
//! session loaded. Every field no host resolves is left out and named as
//! unavailable, never stated as a value.

use oneiron::context_board::{
    CommunicationLimits, SelfBriefState, SessionReadSet, StreamConnectionId,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::DescribeRequest;

use crate::server::SyncServer;

/// The brief fields no host resolves for a run (FIX-LIST: the self-brief
/// producers): left out of a resolved brief and named as unavailable.
const RUN_BRIEF_UNRESOLVED: [&str; 6] = [
    "cast",
    "grant_revision",
    "effective_scope",
    "communication",
    "classes",
    "working_set",
];

/// Answers a pumped run's `describe(self)` for its agent `actor`, over the
/// run's own board `connection`, its entry spending on `line`: the run's
/// brief with the agent's loaded skills from the run's own session reads
/// and the PEOPLE its own lane reads, and beside it the rows the brief is
/// derived from ([`oneiron::context_board::SelfBrief::sources`]). The wire value is the credential
/// path's `TaskDescription::SelfCard`.
pub(crate) async fn describe_self_for_run(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &StreamConnectionId,
    line: Option<&RunAdmission>,
    request: &DescribeRequest,
) -> MemoryResult<(serde_json::Value, Vec<oneiron::EntityId>)> {
    // describe(self) names the run's own brief and nothing else (FIX 3256).
    request.validate()?;
    if !request.self_target {
        return Err(MemoryError::bad_request("describe(self) names the run's own brief"));
    }
    let people = run_people(server, actor)?;
    let reads = crate::api::run_session_reads(server, actor, connection).await;
    let installed = server
        .self_brief_sessions
        .lock()
        .await
        .get(&(actor.entity_ref(), connection.0.clone()))
        .map(|run| run.state.clone());
    let (brief, tail) = match installed {
        Some(state) => {
            let brief = state.describe(&server.vault, &reads, Some(&people))?;
            let tail = brief.render();
            (brief, tail)
        }
        None => {
            let (state, unavailable) = resolved_state(server, actor, line, &reads)?;
            let brief = state.describe(&server.vault, &reads, Some(&people))?;
            let tail = brief.render_available(&unavailable);
            (brief, tail)
        }
    };
    let sources = brief.sources(&server.vault, Some(&people))?;
    let value = serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard { tail })
        .map_err(|_| internal("self brief encoding failed"))?;
    Ok((value, sources))
}

/// The run's brief state as the run itself resolves it, and the fields it
/// could not: [`RUN_BRIEF_UNRESOLVED`] always, the principal when no subject
/// anchor names the person behind the agent, and the budget when no line
/// binds the run's entry. Each unresolved field holds an empty value the
/// render leaves out.
fn resolved_state(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    line: Option<&RunAdmission>,
    reads: &SessionReadSet,
) -> MemoryResult<(SelfBriefState, Vec<&'static str>)> {
    let mut unavailable = RUN_BRIEF_UNRESOLVED.to_vec();
    let self_ref = actor.entity_ref();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let principal =
        oneiron::subject_model::actor_subject_anchor(&server.vault, &self_ref, now.as_secs())?
            .unwrap_or_else(|| {
                unavailable.push("principal");
                self_ref
            });
    let (budget_lease_id, budget) = match line {
        Some(line) => (line.run().to_owned(), line.read()),
        None => {
            unavailable.extend(["budget_lease_id", "budget"]);
            (String::new(), unresolved_budget())
        }
    };
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
    Ok((
        SelfBriefState {
            self_ref,
            principal,
            cast: Vec::new(),
            grant_revision: 0,
            effective_scope: oneiron::federation::Scope::default(),
            communication: CommunicationLimits {
                scope: oneiron::federation::Scope::default(),
                recipients: Vec::new(),
                max_messages: None,
            },
            classes: Vec::new(),
            budget_lease_id,
            budget,
            clock_ms: u64::try_from(now.as_millis()).unwrap_or(u64::MAX),
            skill_index,
            working_set: Vec::new(),
        },
        unavailable,
    ))
}

/// The empty budget an unmetered run's brief holds and never renders.
fn unresolved_budget() -> oneiron::llm::BudgetRead {
    oneiron::llm::BudgetRead {
        attempt_id: String::new(),
        limit_units: 0,
        cap_units: 0,
        used_units: 0,
        reserved_units: 0,
        remaining_units: 0,
        on_budget_exhausted: oneiron::BudgetExhaustionPolicy::Suspend,
        fired_thresholds: Vec::new(),
    }
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
