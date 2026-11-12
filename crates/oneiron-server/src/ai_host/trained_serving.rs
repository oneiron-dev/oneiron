//! Actual trained-checkpoint serving, separate from a bound custody receipt.
//!
//! A question head the owner bound to a typed question (FIX 3864) serves on
//! this host's Local rung (`QuestionHeadRung`) once the host's decision ladder
//! is staffed, from its first call on: it loads once from custody, and a head
//! that cannot load or read steps to the next rung.

use oneiron::EntityId;
use oneiron::llm::manifest::ModelRole;
use oneiron::training_pack::PinnedCheckpoint;
use serde::Serialize;

use crate::server::SyncServer;

const NO_LOADER: &str = "no trained-weight loader on this host";
/// Why a question head serves.
const HEAD_SERVES: &str = "the bound head answers its question on this host's Local rung, for calls \
                           whose state carries its input (a target and a context list); every other \
                           call of the question, and a head that cannot load or read, keeps its model \
                           call";
/// Why an unbound question head does not serve.
const HEAD_UNBOUND: &str =
    "no typed question is bound to this head; its question keeps its model call";
/// Why a bound head does not serve on a host whose ladder is unstaffed.
const NO_LADDER: &str = "no [models] config staffs this host's decision ladder";

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

/// How question run `run`'s returned `checkpoint` serves on this host: it
/// serves while a typed question is bound to it and the host's decision
/// ladder is staffed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn question_head_serving(
    server: &SyncServer,
    run: &EntityId,
    checkpoint: &PinnedCheckpoint,
) -> oneiron::Result<TrainedServing> {
    let custody = server
        .vault()
        .training_run_question_head(run)?
        .map(|binding| binding.checkpoint)
        .filter(|pin| pin == checkpoint);
    let (state, reason) = match &custody {
        None => (ServingState::Unavailable, HEAD_UNBOUND),
        Some(_) if server.decision_ladder().local.is_none() => {
            (ServingState::Unavailable, NO_LADDER)
        }
        Some(_) => (ServingState::Serving, HEAD_SERVES),
    };
    Ok(TrainedServing {
        state,
        reason,
        custody,
    })
}
