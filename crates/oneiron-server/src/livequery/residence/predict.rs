//! The home's prediction asks (ARCH-0023b #predicted-residence; Engine ruling L7-46-MERGE A):
//! `residence.predict` computes the asking machine's prediction on its fresh per-request admission
//! and pushes it as a residence directive, and `residence.predicted_set` serves that machine its
//! pushed set body in parts, by digest.

use base64::Engine;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::PredictedResidenceAnswer;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, admitted, bound_selector};
use crate::server::SyncServer;

/// How many set-body bytes one predicted-set part carries.
const PREDICTED_SET_PART_BYTES: usize = 256 * 1024;

/// One prediction ask: the asking connection's selector.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PredictRequest {
    selector: String,
}

/// One predicted-set fetch: the set's digest and the byte offset the part starts at.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PredictedSetRequest {
    digest: String,
    offset: u64,
}

/// Parses a predicted-set digest as the wire spells it: 64 lowercase hex characters.
fn digest_from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

/// The machine's ask for its prediction: computed on its fresh admission and pushed as a
/// residence directive replacing its last one. An engine refusal answers as a bad request
/// carrying its text.
pub(super) fn predict(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: PredictRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let PeerMachine::Proven { machine, .. } = peer else {
        return Err(AppError::unauthorized());
    };
    let selector = bound_selector(server, auth, &input.selector)?;
    let admission = admitted(server, auth, peer, &selector)?;
    let issuer = server.host_root_issuer.as_deref().ok_or_else(|| {
        AppError::internal_server_error("this host holds no signing key for a prediction")
    })?;
    match server
        .vault
        .predict_residence_for(issuer, machine, &admission)
    {
        Ok(PredictedResidenceAnswer::Pushed(state)) => Ok((
            json!({
                "state": "pushed",
                "directive": state.directive.id.to_hex(),
            }),
            None,
        )),
        Ok(PredictedResidenceAnswer::Unchanged) => Ok((json!({ "state": "unchanged" }), None)),
        Err(oneiron::Error::InvalidConfig(reason)) => Err(AppError::bad_request(reason, None)),
        Err(_) => Err(AppError::internal_server_error("prediction unavailable")),
    }
}

/// One part of the proved machine's own pushed set body, by digest. An offset past the end is a
/// bad request; a digest this home holds no body for looks missing.
pub(super) fn predicted_set(
    server: &SyncServer,
    _auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: PredictedSetRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let PeerMachine::Proven { machine, .. } = peer else {
        return Err(AppError::unauthorized());
    };
    let digest = digest_from_hex(&input.digest).ok_or_else(AppError::invalid_params)?;
    let body = server
        .vault
        .predicted_residence_body(machine, &digest)
        .map_err(|_| AppError::internal_server_error("predicted set unavailable"))?
        .ok_or_else(|| AppError::not_found("predicted set", None))?;
    let total = u64::try_from(body.len())
        .map_err(|_| AppError::internal_server_error("predicted set unavailable"))?;
    if input.offset > total {
        return Err(AppError::bad_request(
            "the offset is past the predicted set's end",
            None,
        ));
    }
    let offset = usize::try_from(input.offset).map_err(|_| AppError::invalid_params())?;
    let end = offset
        .saturating_add(PREDICTED_SET_PART_BYTES)
        .min(body.len());
    let part = base64::engine::general_purpose::STANDARD.encode(&body[offset..end]);
    Ok((
        json!({
            "digest": input.digest,
            "offset": input.offset,
            "total": total,
            "part": part,
        }),
        None,
    ))
}
