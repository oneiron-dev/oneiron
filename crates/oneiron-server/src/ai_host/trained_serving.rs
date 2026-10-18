//! Whether this host serves a trained checkpoint its role binds (OF-577,
//! FIX 857).
//!
//! An approved swap writes the role's binding and its custody receipt and
//! marks the run `Bound`; serving the returned weights takes a host loader
//! that resolves that custody pin and checks the host can run it. No
//! trained-weight loader exists yet, so every trained checkpoint reads
//! unavailable here: a `Bound` receipt is never reported as deployed or
//! serving. The custody pin a loader would load is shown beside it.

use oneiron::llm::manifest::ModelRole;
use oneiron::training_pack::PinnedCheckpoint;
use serde::Serialize;

use crate::server::SyncServer;

/// Why no trained checkpoint serves on this host.
const NO_LOADER: &str = "no trained-weight loader on this host";

/// Whether a trained checkpoint serves on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ServingState {
    /// Nothing here loads it.
    Unavailable,
}

/// How a trained checkpoint serves on this host.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TrainedServing {
    state: ServingState,
    reason: &'static str,
    /// The custody pin a loader would load for the role: the role's bound
    /// checkpoint while it is this one, the manifest still binds it and its
    /// custody verifies; `None` otherwise.
    custody: Option<PinnedCheckpoint>,
}

/// How `checkpoint` serves for `role` on this host.
///
/// # Errors
///
/// Storage errors, or a bound checkpoint whose custody does not verify.
pub(crate) fn trained_serving(
    server: &SyncServer,
    role: ModelRole,
    checkpoint: &PinnedCheckpoint,
) -> oneiron::Result<TrainedServing> {
    let custody = server
        .vault()
        .training_role_checkpoint(role)?
        .filter(|pin| pin == checkpoint);
    Ok(TrainedServing {
        state: ServingState::Unavailable,
        reason: NO_LOADER,
        custody,
    })
}
