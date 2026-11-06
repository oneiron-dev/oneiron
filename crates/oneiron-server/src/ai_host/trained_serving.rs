//! Whether this host serves a trained checkpoint (OF-577, FIX 857, FIX
//! 3864).
//!
//! An approved role swap writes the role's binding and its custody receipt
//! and marks the run `Bound`; serving the returned weights takes a host
//! loader that resolves that custody pin and checks the host can run it. No
//! role loader exists yet, so a role's checkpoint reads unavailable here: a
//! `Bound` receipt is never reported as deployed or serving. The custody pin
//! a loader would load is shown beside it.
//!
//! A question head the owner bound to a typed question serves on this
//! host's Local rung (`QuestionHeadRung`) once the host's decision ladder is
//! staffed, from its first call on: it loads once from custody, and a head
//! that cannot load or read steps to the next rung.

use oneiron::EntityId;
use oneiron::llm::manifest::ModelRole;
use oneiron::training_pack::PinnedCheckpoint;
use serde::Serialize;

use crate::server::SyncServer;

/// Why no role checkpoint serves on this host.
const NO_LOADER: &str = "no trained-weight loader on this host";
/// Why a question head serves.
const HEAD_SERVES: &str = "the bound head answers its question on this host's Local rung; a head \
                           that cannot load or read steps to the next rung";
/// Why an unbound question head does not serve.
const HEAD_UNBOUND: &str =
    "no typed question is bound to this head; its question keeps its model call";
/// Why a bound head does not serve on a host whose ladder is unstaffed.
const NO_LADDER: &str = "no [models] config staffs this host's decision ladder";

/// Whether a trained checkpoint serves on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ServingState {
    /// It answers calls here.
    Serving,
    /// Nothing here loads it.
    Unavailable,
}

/// How a trained checkpoint serves on this host.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TrainedServing {
    state: ServingState,
    reason: &'static str,
    /// The custody pin a loader loads: for a role, the role's bound
    /// checkpoint while it is this one, the manifest still binds it and its
    /// custody verifies; for a question head, its bound checkpoint while it
    /// is this one; `None` otherwise.
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
