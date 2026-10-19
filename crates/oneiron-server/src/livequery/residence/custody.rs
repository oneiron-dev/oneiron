//! `residence.custody.status`, `.frames`, `.put` and `.commit`: this home as
//! the residence target of its owner's machines' key custody (KS-4A2, FIX
//! 5685). A machine reads the position of the head the home holds of its
//! lineage, ships the log frames the home lacks, stages its sealed head in
//! parts and commits it; the commit answers the ack the home persisted,
//! attested as this home's machine. Sealed bytes, ids and positions only. A
//! refused call looks missing; no door asks where the caller runs.

use base64::Engine;
use oneiron::authority::PeerMachine;
use oneiron::store::custody_protocol::{AckPosition, Lineage, ResidenceCommit};
use oneiron::sync::residence::{
    custody_residence_commit, custody_residence_frames, custody_residence_held,
    custody_residence_stage, sealed_digest_from_hex,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope};
use crate::server::SyncServer;

/// The lineage a call names: vault (64 hex) and namespace (32 hex).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageRequest {
    vault: String,
    namespace: String,
}

/// Log frames of the lineage: each its sequence number and base64 bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FramesRequest {
    vault: String,
    namespace: String,
    frames: Vec<(u64, String)>,
}

/// One part of the head the operation (64 hex) stages, at `offset`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutRequest {
    vault: String,
    namespace: String,
    operation: String,
    offset: u64,
    part: String,
}

/// The commit of a staged head.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitRequest {
    set_revision: u64,
    position: AckPosition,
    head_object_id: String,
    operation_id: String,
}

fn lineage(vault: &str, namespace: &str) -> Result<Lineage, AppError> {
    Lineage::from_hex(vault, namespace).ok_or_else(AppError::invalid_params)
}

fn digest(hex: &str) -> Result<[u8; 32], AppError> {
    sealed_digest_from_hex(hex).ok_or_else(AppError::invalid_params)
}

fn base64(text: &str) -> Result<Vec<u8>, AppError> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| AppError::invalid_params())
}

fn missing(_: oneiron::Error) -> AppError {
    AppError::not_found("custody", None)
}

/// Every `residence.custody.*` call, and any other method's refusal as an
/// unknown residence RPC.
pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    method: &str,
    params: Value,
) -> Result<Answer, AppError> {
    match method {
        "residence.custody.status" => status(server, peer, params),
        "residence.custody.frames" => {
            auth.require(CoreScope::Write)?;
            frames(server, peer, params)
        }
        "residence.custody.put" => {
            auth.require(CoreScope::Write)?;
            put(server, peer, params)
        }
        "residence.custody.commit" => {
            auth.require(CoreScope::Write)?;
            commit(server, peer, params)
        }
        _ => Err(AppError::bad_request(
            "unknown residence RPC",
            Some("method"),
        )),
    }
}

fn status(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: LineageRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let held = custody_residence_held(
        &server.vault,
        peer,
        lineage(&input.vault, &input.namespace)?,
    )
    .map_err(missing)?;
    let reply = json!({
        "epoch": held.map(|held| held.epoch.get()),
        "seq": held.map(|held| held.seq),
    });
    Ok((reply, Some(Vec::new())))
}

fn frames(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: FramesRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let lineage = lineage(&input.vault, &input.namespace)?;
    let frames = input
        .frames
        .iter()
        .map(|(seq, frame)| base64(frame).map(|bytes| (*seq, bytes)))
        .collect::<Result<Vec<_>, AppError>>()?;
    custody_residence_frames(&server.vault, peer, lineage, &frames).map_err(missing)?;
    Ok((json!({"kept": frames.len()}), Some(Vec::new())))
}

fn put(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: PutRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let lineage = lineage(&input.vault, &input.namespace)?;
    let part = base64(&input.part)?;
    let staged = custody_residence_stage(
        &server.vault,
        peer,
        lineage,
        digest(&input.operation)?,
        input.offset,
        &part,
    )
    .map_err(missing)?;
    Ok((json!({"staged": staged}), Some(Vec::new())))
}

fn commit(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: CommitRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let commit = ResidenceCommit {
        set_revision: input.set_revision,
        position: input
            .position
            .position()
            .ok_or_else(AppError::invalid_params)?,
        head_object_id: digest(&input.head_object_id)?,
        operation_id: digest(&input.operation_id)?,
    };
    let ack = custody_residence_commit(&server.vault, peer, &commit).map_err(missing)?;
    Ok((json!({"ack": ack}), Some(Vec::new())))
}
