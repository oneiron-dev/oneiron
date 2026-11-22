//! Door for `tests/run_brief_prefix_recheck.rs`
//! ([BRIEF-PREFIX-STALE-PAST-REVOKE]): the self-brief port a pumped run's
//! entry lends its native executor, over the run's own door, installed as
//! the resident pump's entry installs it.

use std::sync::Arc;

use oneiron::engine_executor::SelfBriefPort;
use oneiron::{EntityId, Result, WriteActor};

use crate::server::{RunHostDoor, SyncServer};

/// The port run `run_id` of `actor` carries its self brief through on
/// `server`: the brief installed afresh under the run's own board
/// connection from what a door with no line bound holds, each of the port's
/// calls answered on `runtime`. `None` when a newer installation holds the
/// key.
///
/// # Errors
///
/// The brief's state did not resolve or install, or `runtime` did not
/// answer.
pub fn resident_self_brief(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    run_id: EntityId,
    runtime: tokio::runtime::Handle,
) -> Result<Option<Box<dyn SelfBriefPort>>> {
    let door = Arc::new(RunHostDoor::new(server, actor, runtime, run_id));
    Ok(door
        .install_self_brief(None)?
        .map(|port| Box::new(port) as Box<dyn SelfBriefPort>))
}
