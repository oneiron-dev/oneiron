//! A machine's report of the items one board showed (lead ruling PREDICTED-BOARD-SEED-SIGNAL = A,
//! 21 Nov): `residence.board_seeds` records them in the home's touch log as prefetch seeds of the
//! machine's prediction (ARCH-0023b #predicted-residence), on every home, hosted included. The
//! machine is the one its socket proved, whoever ran the board, an agent included; each item is
//! judged under that machine's own admission, and one it may not hold is left out.

use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::BOARD_SEEDS_MAX;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, admitted, bound_selector};
use crate::handler::selector_scope::SelectorLane;
use crate::server::SyncServer;

/// One board's report: the reporting connection's selector and the board's item ids, each as 32
/// lowercase hex characters.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoardSeedsRequest {
    selector: String,
    items: Vec<String>,
}

/// Records the items one board showed on the proved machine as touches in its touch log, and
/// answers how many it recorded. More than [`BOARD_SEEDS_MAX`] items, or an id that is not 32
/// lowercase hex characters, is refused before anything is recorded; an unproved peer is
/// unauthorized, and an engine refusal answers as a bad request carrying its text.
pub(super) fn board_seeds(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: BoardSeedsRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let PeerMachine::Proven { .. } = peer else {
        return Err(AppError::unauthorized());
    };
    if input.items.len() > BOARD_SEEDS_MAX {
        return Err(AppError::bad_request(
            "a board's report names at most 64 items",
            None,
        ));
    }
    let mut items = Vec::with_capacity(input.items.len());
    for hex in &input.items {
        let id = EntityId::from_hex(hex).map_err(|_| AppError::invalid_params())?;
        if id.to_hex() != *hex {
            return Err(AppError::invalid_params());
        }
        items.push(id);
    }
    // A report is an owner machine's, never a member lane's
    // (`handler::member_lane::member_admits_rpc_method`): its selector is checked on the
    // own-device lane, as a prediction ask's is.
    let selector = bound_selector(server, auth, &SelectorLane::OwnDevice, &input.selector)?;
    let admission = admitted(server, auth, peer, &SelectorLane::OwnDevice, &selector)?;
    match server.vault.record_board_seeds(peer, &admission, &items) {
        Ok(recorded) => Ok((json!({ "recorded": recorded }), None)),
        Err(oneiron::Error::InvalidConfig(reason)) => Err(AppError::bad_request(reason, None)),
        Err(_) => Err(AppError::internal_server_error("board seeds unavailable")),
    }
}
