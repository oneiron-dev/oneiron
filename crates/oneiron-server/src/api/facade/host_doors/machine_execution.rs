//! `vault.machines.execution.clear_drain` (pass 33 row R4, door 12): clears the issuer's drain
//! of one machine. The owner under their own proof, or an agent whose own Grant lists the verb
//! (`verb_grant_caller`); the engine's act then judges the caller against the machine's
//! setting `machines.drain.clear_by` (`oneiron::job_dispatch::machine_records`).

use std::sync::Arc;

use oneiron::job_dispatch::machine_records::{
    CLEAR_DRAIN_VERB, MachineDrainClearRequest, MachineDrainCleared, clear_drain_as,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.machines.execution.clear_drain`: the issuer takes new jobs on `input.machine` again.
pub(crate) async fn vault_machines_execution_clear_drain(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MachineDrainClearRequest,
) -> Listed<MachineDrainCleared> {
    verb_grant_door(server, auth, CLEAR_DRAIN_VERB, move |_, memory, owner| {
        clear_drain_as(memory, owner, &input)
    })
    .await
}
