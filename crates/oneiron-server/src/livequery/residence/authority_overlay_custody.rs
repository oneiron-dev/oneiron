//! `residence.authority_overlay.offer` and `.keys` (census L5-22 1a-iii
//! commit 7): this node as the residence home through which the owner's
//! machines carry the authority overlay's erasable keys. A machine of the
//! owner's its socket proved offers one page of its inventory with a session
//! for the keys this node sends it; the answer names this node's erased
//! subjects, its keys the machine lacks sealed to that session, the keys it
//! wants and a session for them; `.keys` installs those. Key refs, subjects
//! and seals only. A refused call looks missing.
//!
//! Both calls write, and both run with only the socket's machine proof, as
//! the home handoff's do ([`run_machine`]); each is judged for the machine
//! the socket proved, as on a bound one.

use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    authority_overlay_keys, authority_overlay_offer, overlay_answer_to_wire,
    overlay_keys_from_wire, overlay_offer_from_wire,
};
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope};
use crate::server::SyncServer;

fn missing(_: oneiron::Error) -> AppError {
    AppError::not_found("authority overlay custody", None)
}

/// The calls the authority overlay's key round makes, and the only ones a
/// socket bound to no actor runs beside the home handoff's.
const MACHINE_METHODS: [&str; 2] = [
    "residence.authority_overlay.offer",
    "residence.authority_overlay.keys",
];

/// Whether `method` is one of the authority overlay's own calls.
pub(in crate::livequery) fn machine_method(method: &str) -> bool {
    MACHINE_METHODS.contains(&method)
}

/// Every `residence.authority_overlay.*` call; any other method is an
/// unknown residence RPC. Both calls write, so both need the write scope.
pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    method: &str,
    params: Value,
) -> Result<Answer, AppError> {
    if machine_method(method) {
        auth.require(CoreScope::Write)?;
    }
    run_machine(server, peer, method, params)
}

/// One of the overlay's calls on a socket that bound no actor. Its
/// owner-grade upgrade holds every scope; the doors judge `peer`, the
/// machine the socket proved, as on a bound socket.
pub(in crate::livequery) fn run_machine(
    server: &SyncServer,
    peer: PeerMachine,
    method: &str,
    params: Value,
) -> Result<Answer, AppError> {
    match method {
        "residence.authority_overlay.offer" => offer(server, peer, params),
        "residence.authority_overlay.keys" => keys(server, peer, params),
        _ => Err(AppError::bad_request(
            "unknown residence RPC",
            Some("method"),
        )),
    }
}

fn offer(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let offer = overlay_offer_from_wire(params).ok_or_else(AppError::invalid_params)?;
    let answer = authority_overlay_offer(&server.vault, peer, &offer).map_err(missing)?;
    Ok((overlay_answer_to_wire(&answer), None))
}

fn keys(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let keys = overlay_keys_from_wire(params).ok_or_else(AppError::invalid_params)?;
    let installed = authority_overlay_keys(&server.vault, peer, keys).map_err(missing)?;
    Ok((json!({"installed": installed}), None))
}
