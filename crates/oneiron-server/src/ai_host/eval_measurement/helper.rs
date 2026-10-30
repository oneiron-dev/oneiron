//! The helper gate's measurement (FIX 10677, 12069): each callable helper
//! awaiting its gate asks for the paired measurement of its exact content
//! against its parent's, on the seat whose code mode calls helpers, with
//! both arms answered by that seat's served model at its registry revision.
//! The same request again keeps its row, so a measured helper is not
//! measured twice. With no judge, no served seat or no live cohort, nothing
//! is asked.

use oneiron::llm::manifest::ModelRole;
use oneiron::skill::helper::callable_helper_measurement_requests;
use oneiron::skill_optimize::offer_pilot::model_offer_pin;
use oneiron::skill_optimize::{HeldOutReplayNotes, model_role_seat};
use oneiron::{Error, Vault};

use crate::server::SyncServer;

/// The role a helper's legs answer as: agents call helpers from the code
/// mode the generative reasoner serves (CALL).
const HELPER_ROLE: ModelRole = ModelRole::GenerativeReasoner;

/// Asks for each awaiting helper's measurement against its parent.
/// # Errors
/// Storage errors.
pub(in crate::ai_host) fn request_helper_measurements(
    server: &SyncServer,
    vault: &Vault,
    now: u64,
) -> oneiron::Result<()> {
    let Some(judge) = crate::replay_judge::registered() else {
        return Ok(());
    };
    let runtime = server.ai.model_runtime();
    let Some(seat) = runtime.seat(HELPER_ROLE) else {
        return Ok(());
    };
    let Ok(route) = runtime.route_role(vault, HELPER_ROLE, seat) else {
        return Ok(());
    };
    let Some((pin, _)) = vault
        .model_registry_rows()?
        .iter()
        .find(|row| row.catalog.model.as_str() == route.model.as_str())
        .and_then(model_offer_pin)
    else {
        return Ok(());
    };
    let requests = callable_helper_measurement_requests(
        vault,
        &model_role_seat(HELPER_ROLE),
        (&pin.model, &pin.revision),
        judge.judge_revision(),
    )?;
    for (helper, request) in requests {
        match vault.request_eval_measurement(&request, now) {
            Ok(_) => {}
            // A pair the measurement door refuses is measured by nothing.
            Err(Error::InvalidConfig(reason)) => {
                tracing::debug!(
                    helper = %helper.to_hex(),
                    %reason,
                    "the helper's pair has no eval measurement"
                );
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
