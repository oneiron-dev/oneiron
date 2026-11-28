//! Door for `tests/turn_program_caller_rows.rs` ([RSI-PROJECT-WORKFLOW]):
//! one verb call on a run's own host door, as a run's entry makes it,
//! under its own agent: a turn program's door (with its five lane-economy
//! rows) or a pumped run's (without them).

use std::sync::Arc;

use oneiron::code_run::{AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, SelfAgentVerbCall};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::test_doors::project_run::agent_write_origin;
use oneiron::{EdgeActorClass, EntityId, Error, Result, WriteActor};
use serde_json::Value;

use crate::server::{RunHostDoor, SyncServer};

/// `verb` with `input`, called once by the agent `agent` on the door run
/// `run_id` binds on `server`, its rows answered on `runtime`: a turn
/// program's door when `program`, which serves the five lane-economy rows,
/// else a pumped run's. Blocking: call it off the runtime's own threads.
///
/// # Errors
///
/// A verb name no row has; the door's own fault (a hook stop, a model
/// outage).
pub fn run_door_call(
    server: &Arc<SyncServer>,
    agent: EntityId,
    runtime: tokio::runtime::Handle,
    program: bool,
    verb: &str,
    input: Value,
) -> Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
    let verb = AgentVerb::from_name(verb)
        .ok_or_else(|| Error::InvalidConfig(format!("{verb} is no verb row")))?;
    let run_id = EntityId::now();
    let door = RunHostDoor::new(
        server,
        WriteActor::new(agent, EdgeActorClass::Agent),
        runtime,
        run_id,
    );
    let door = if program {
        door.with_program_caller_rows()
    } else {
        door
    };
    let origin = agent_write_origin(agent)?;
    door.call(
        &SelfAgentVerbCall { verb, input },
        &origin,
        InvocationId::mint(),
    )
}
