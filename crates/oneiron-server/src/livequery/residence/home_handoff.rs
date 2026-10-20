//! `residence.home_handoff.status`, `.part`, `.commit` and `.cancel`: this
//! node as the new home a home handoff moves to (FIX 5661 C2a, C2b). The old
//! home, a machine of the owner's its socket proved, reads where the handoff
//! stands here (the staged position, or the saved ack), stages its sealed
//! bytes in parts and commits; the commit adopts every registered table in
//! one transaction and answers the ack this node signed and saved. A cancel
//! (FIX 5931) fences the handoff in the adopting writer, or answers the ack
//! when it adopted first. The engine's doors own every check and write; this
//! file only reads the parameters. Sealed bytes, ids and acks only. A
//! refused call looks missing.

use base64::Engine;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    HomeHandoffCancel, HomeHandoffStanding, home_handoff_cancel, home_handoff_commit,
    home_handoff_part, home_handoff_status, sealed_digest_from_hex,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope};
use crate::server::SyncServer;

/// A handoff (64 hex) and the digest of its sealed bytes (64 hex).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffRequest {
    id: String,
    digest: String,
}

/// Part `index` of `count` of a handoff's sealed bytes, in base64.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PartRequest {
    id: String,
    digest: String,
    index: u32,
    count: u32,
    part: String,
}

fn hash(hex: &str) -> Result<[u8; 32], AppError> {
    sealed_digest_from_hex(hex).ok_or_else(AppError::invalid_params)
}

fn missing(_: oneiron::Error) -> AppError {
    AppError::not_found("home handoff", None)
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Every `residence.home_handoff.*` call; any other method is an unknown
/// residence RPC.
pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    method: &str,
    params: Value,
) -> Result<Answer, AppError> {
    match method {
        "residence.home_handoff.status" => status(server, peer, params),
        "residence.home_handoff.part" => {
            auth.require(CoreScope::Write)?;
            part(server, peer, params)
        }
        "residence.home_handoff.commit" => {
            auth.require(CoreScope::Write)?;
            commit(server, peer, params)
        }
        "residence.home_handoff.cancel" => {
            auth.require(CoreScope::Write)?;
            cancel(server, peer, params)
        }
        _ => Err(AppError::bad_request(
            "unknown residence RPC",
            Some("method"),
        )),
    }
}

fn status(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: HandoffRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let standing = home_handoff_status(&server.vault, peer, hash(&input.id)?, hash(&input.digest)?)
        .map_err(missing)?;
    let reply = match standing {
        HomeHandoffStanding::Staged { parts } => json!({"staged": parts}),
        HomeHandoffStanding::Adopted { ack } => json!({"ack": encode(&ack)}),
    };
    Ok((reply, Some(Vec::new())))
}

fn part(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: PartRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&input.part)
        .map_err(|_| AppError::invalid_params())?;
    let staged = home_handoff_part(
        &server.vault,
        peer,
        hash(&input.id)?,
        hash(&input.digest)?,
        input.index,
        input.count,
        &bytes,
    )
    .map_err(missing)?;
    Ok((json!({"staged": staged}), Some(Vec::new())))
}

fn commit(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: HandoffRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let ack = home_handoff_commit(&server.vault, peer, hash(&input.id)?, hash(&input.digest)?)
        .map_err(missing)?;
    Ok((json!({"ack": encode(&ack)}), Some(Vec::new())))
}

fn cancel(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: HandoffRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let answer = home_handoff_cancel(&server.vault, peer, hash(&input.id)?, hash(&input.digest)?)
        .map_err(missing)?;
    let reply = match answer {
        HomeHandoffCancel::Fenced => json!({"fenced": true}),
        HomeHandoffCancel::Adopted { ack } => json!({"ack": encode(&ack)}),
    };
    Ok((reply, Some(Vec::new())))
}
