//! `vault.planner.card` (design pass 32 r2, sections 5.1 and 5.4, row 12):
//! the planner card of one project and task type, with the digest of the
//! answer. A read: the owner under their own proof, or an agent whose own
//! Grant lists the verb (`verb_grant_caller`) and, for a project a GPU line
//! seats, holds a role on that line. The engine reads at the host's clock
//! (`oneiron::team::planner_card_door`); the door writes nothing and lists
//! every row the card was read from, so the facade withholds a card one of
//! them keeps from the caller's destination.

use std::sync::Arc;

use oneiron::team::planner_card_door::{
    PLANNER_CARD_VERB, PlannerCardRequest, PlannerCardView, planner_card_as,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// `vault.planner.card`: the card the planner's deterministic floor reads
/// for `input`'s project, task type and executor models.
pub(crate) async fn vault_planner_card(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PlannerCardRequest,
) -> Listed<PlannerCardView> {
    verb_grant_door(server, auth, PLANNER_CARD_VERB, move |_, memory, owner| {
        planner_card_as(memory, owner, &input, now_ms())
    })
    .await
}
