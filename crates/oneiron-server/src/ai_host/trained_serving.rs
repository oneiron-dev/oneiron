//! Actual trained-checkpoint serving, separate from a bound custody receipt.

use oneiron::llm::manifest::ModelRole;
use oneiron::training_pack::PinnedCheckpoint;
use serde::Serialize;

use crate::server::SyncServer;

const NO_LOADER: &str = "no trained-weight loader on this host";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ServingState {
    Unavailable,
    Serving,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TrainedServing {
    state: ServingState,
    reason: &'static str,
    custody: Option<PinnedCheckpoint>,
}

/// Serving needs the actual bound role, current text-slot selection, matching
/// declared space, and a live local runtime. Loading alone never means serving.
///
/// # Errors
/// Storage errors or a custody pin that no longer verifies.
pub(crate) fn trained_serving(
    server: &SyncServer,
    role: ModelRole,
    checkpoint: &PinnedCheckpoint,
) -> oneiron::Result<TrainedServing> {
    let custody = server
        .vault()
        .training_role_checkpoint(role)?
        .filter(|pin| pin == checkpoint);
    let serving = role == ModelRole::RetrievalEmbedder
        && custody.is_some()
        && server.serves_training_checkpoint(checkpoint)?;
    Ok(TrainedServing {
        state: if serving {
            ServingState::Serving
        } else {
            ServingState::Unavailable
        },
        reason: if serving {
            "the bound checkpoint serves the active text space"
        } else if role == ModelRole::RetrievalEmbedder {
            "no active local runtime serves this checkpoint's text space"
        } else {
            NO_LOADER
        },
        custody,
    })
}
