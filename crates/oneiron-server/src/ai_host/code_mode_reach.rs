//! How far a pumped run's code-mode calls may go, judged before any of them
//! is admitted (RUN-BRIEF-ROUTE-AWARE-ROSTER). The run's self brief reads
//! its PEOPLE for a caller on this device only while no call the run may
//! make leaves the device: a brief rides every request until its next
//! boundary, so it follows its strictest destination (DEC-0005:476), and a
//! run whose every route stays on the device reads as DEC-0005:564's caller
//! on this device.
//!
//! The reach follows `admit_code_mode_call` in `ai_host/code_mode.rs` path
//! by path: a new admission path there widens [`code_mode_reach`] too.

use oneiron::llm::manifest::ModelRole;
use oneiron::{ModelId, ModelLocality, Vault};

use super::CHAT_ROLE;
use crate::config::models::BROWSER_PLANNER_ROLE;
use crate::models::ModelRuntime;

/// What one entry of a pumped run binds its code-mode calls to: the model
/// and locality of the durable seat that bore the run, whose every call is
/// seat-bound, and those of a planned child its host pinned to its pick
/// (FIX 2310), whose call takes that pick while its admission holds. Neither
/// for a run no seat bore and no plan pinned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CodeModeRoute {
    pub(crate) seat: Option<(ModelId, ModelLocality)>,
    pub(crate) pinned: Option<(ModelId, ModelLocality)>,
}

/// As far as any code-mode call of a run bound to `route` may go now: where
/// it is admitted, and the widest rung or fallback of the ladder that sends
/// it, as the chat board reads a route's reach (FIX 6922).
///
/// - A seated run's calls keep the seat's model: its reach where that model
///   is served ([`ModelRuntime::seat_bound_reach`]). A seat that admission
///   refuses now reads as a third party's.
/// - Any other run's calls take the chat role's live route, a third party's
///   when that route is not read. A pinned pick widens it while its
///   admission holds; a pick refused now sends its call on that route.
/// - A browser subgoal's step takes the browser planner's live route while a
///   rung serves that role. With none, the step takes the run's own path
///   above; a route that refuses it sends nothing.
///
/// `OnDevice` only when no rung any call may reach leaves the device.
pub(crate) fn code_mode_reach(
    models: &ModelRuntime,
    vault: &Vault,
    route: &CodeModeRoute,
) -> ModelLocality {
    let live = |role: ModelRole| {
        let seat = models.seat(role)?;
        Some(
            models
                .route_role(vault, role, seat)
                .map(|route| route.locality.max(route.ladder.prompt_locality_bound())),
        )
    };
    let run = match (&route.seat, &route.pinned) {
        (Some((model, locality)), _) => models
            .seat_bound_reach(vault, CHAT_ROLE, model, *locality)
            .unwrap_or(ModelLocality::ThirdParty),
        (None, pinned) => {
            let chat = match live(CHAT_ROLE) {
                Some(Ok(reach)) => reach,
                _ => ModelLocality::ThirdParty,
            };
            pinned
                .as_ref()
                .and_then(|(model, locality)| {
                    models
                        .seat_bound_reach(vault, CHAT_ROLE, model, *locality)
                        .ok()
                })
                .map_or(chat, |pick| chat.max(pick))
        }
    };
    match live(BROWSER_PLANNER_ROLE) {
        Some(Ok(browser)) => run.max(browser),
        _ => run,
    }
}
