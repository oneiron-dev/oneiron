//! `residence.machine-history` (FIX 3820): a target's machine-claim history,
//! a page at a time, for a machine that holds a handoff packet without its
//! ancestors. The target passes the touch's gate: a bound selector, then the
//! credential's read of the exact target on the machine this socket proved.
//! The rows are this home's stored history under its pin; a home whose own
//! copy does not resolve answers `pending` and serves none of it. Nothing in
//! the reply is trusted there: the machine lands each row through its replay
//! door and derives any pin itself.

use base64::Engine;
use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::claim::MachineHistoryFreshnessChallenge;
use oneiron::sync::residence::{MachineHistoryCursor, MachineHistoryPage, machine_history_page};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, admitted, bound_selector};
use crate::server::SyncServer;

/// The target's id in hex and the cursor a page before returned, if any.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MachineHistoryRequest {
    selector: String,
    target: String,
    #[serde(default)]
    cursor: Option<String>,
}

pub(super) fn machine_history(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: MachineHistoryRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let target = EntityId::from_hex(&input.target).map_err(|_| AppError::invalid_params())?;
    let cursor = input
        .cursor
        .as_deref()
        .map(|cursor| MachineHistoryCursor::decode(cursor).ok_or_else(AppError::invalid_params))
        .transpose()?;
    let selector = bound_selector(server, auth, &input.selector)?;
    // As a touch: the actor's live scoped-read floor and the destination
    // machine's world read settings must admit the exact target. Either
    // denial looks missing.
    let admission = admitted(server, auth, peer, &selector)?;
    if !admission
        .allows_item(target)
        .map_err(|_| AppError::internal_server_error("item admission unavailable"))?
    {
        return Err(AppError::not_found("item", None));
    }
    let page = machine_history_page(&server.vault, target, cursor)
        .map_err(|_| AppError::internal_server_error("machine history unavailable"))?;
    let MachineHistoryPage::Rows { rows, cursor, more } = page else {
        return Ok((
            json!({ "target": target.to_hex(), "pending": true, "rows": [] }),
            Some(Vec::new()),
        ));
    };
    let ids = rows.iter().map(|(id, _)| *id).collect();
    let rows: Vec<Value> = rows
        .iter()
        .map(|(id, raw)| {
            json!({
                "id": id.to_hex(),
                "raw": base64::engine::general_purpose::STANDARD.encode(raw),
            })
        })
        .collect();
    Ok((
        json!({
            "target": target.to_hex(),
            "pending": false,
            "rows": rows,
            "cursor": cursor.encode(),
            "more": more,
        }),
        Some(ids),
    ))
}

/// A machine's freshness challenge for one target's pin (FIX 4294), in
/// base64.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreshnessRequest {
    selector: String,
    challenge: String,
}

/// `residence.machine-history.freshness` (FIX 4294): this home's signed
/// answer naming the handoff it holds pinned for the challenge's target,
/// bound to the asking machine's own challenge. The challenge must name the
/// machine this socket proved, and the target passes the touch's gate as a
/// history page's does. A home with no pin for the target, or no host root
/// to sign with, answers `pending`. The machine judges the answer itself.
pub(super) fn freshness(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: FreshnessRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let challenge = base64::engine::general_purpose::STANDARD
        .decode(&input.challenge)
        .ok()
        .and_then(|bytes| MachineHistoryFreshnessChallenge::decode(&bytes))
        .ok_or_else(AppError::invalid_params)?;
    if !matches!(peer, PeerMachine::Proven { machine, .. } if machine == challenge.machine) {
        return Err(AppError::not_found("item", None));
    }
    let selector = bound_selector(server, auth, &input.selector)?;
    let admission = admitted(server, auth, peer, &selector)?;
    if !admission
        .allows_item(challenge.target)
        .map_err(|_| AppError::internal_server_error("item admission unavailable"))?
    {
        return Err(AppError::not_found("item", None));
    }
    let answer = match server.host_issuer() {
        Some(issuer) => server
            .vault
            .answer_machine_history_freshness(&challenge, issuer)
            .map_err(|_| {
                AppError::internal_server_error("machine history freshness unavailable")
            })?,
        None => None,
    };
    let target = challenge.target.to_hex();
    let Some(response) = answer.and_then(|answer| answer.encode()) else {
        return Ok((
            json!({ "target": target, "pending": true }),
            Some(Vec::new()),
        ));
    };
    Ok((
        json!({
            "target": target,
            "pending": false,
            "response": base64::engine::general_purpose::STANDARD.encode(response),
        }),
        Some(vec![challenge.target]),
    ))
}
