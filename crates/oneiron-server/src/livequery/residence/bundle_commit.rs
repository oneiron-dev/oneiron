//! Bundle execution and owner-request publication receipts are distinct.
//! A work id is known before the first commit send; none is bearer authority.

use super::{Answer, AppError, CoreAuth, CoreScope, bundle_entry, bundle_generation};
use crate::server::SyncServer;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    SealedBundleCommitInput, SealedBundleWorkOutcome, SealedBundleWorkStatus,
    begin_sealed_bundle_work_authorized, sealed_bundle_commit_receipt,
    sealed_bundle_work_for_request, sealed_bundle_work_status, sealed_digest_from_hex,
    sealed_digest_hex, sealed_generation_hex, step_sealed_bundle_work_authorized,
};
use oneiron::world_keys::RecoveryRootId;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleCommitRequest {
    work_id: String,
    generation: String,
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    request: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleCommitStatusRequest {
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    work_id: Option<String>,
}

fn digest(hex: &str) -> Result<[u8; 32], AppError> {
    sealed_digest_from_hex(hex).ok_or_else(AppError::invalid_params)
}

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Begin(SealedBundleCommitInput, [u8; 32]),
    Status([u8; 32]),
}

pub(super) fn operation(method: &str, params: Value) -> Result<Operation, AppError> {
    if method == "residence.bundle.commit" {
        let input: BundleCommitRequest =
            serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
        Ok(Operation::Begin(
            SealedBundleCommitInput {
                generation: bundle_generation(&input.generation)?,
                parent: input.parent.as_deref().map(bundle_generation).transpose()?,
                root: input
                    .root
                    .as_deref()
                    .map(|root| digest(root).map(RecoveryRootId))
                    .transpose()?,
                request: input.request.as_deref().map(digest).transpose()?,
            },
            digest(&input.work_id)?,
        ))
    } else {
        let input: BundleCommitStatusRequest =
            serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
        match (input.request, input.work_id) {
            (None, Some(id)) => Ok(Operation::Status(digest(&id)?)),
            _ => Err(AppError::invalid_params()),
        }
    }
}

pub(super) fn start(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    operation: Operation,
) -> Result<Option<SealedBundleWorkStatus>, AppError> {
    auth.require(CoreScope::Read)?;
    auth.require(CoreScope::Write)?;
    if !auth.credential_is_live(server.vault()) {
        return Err(AppError::unauthorized());
    }
    match operation {
        Operation::Begin(input, id) => {
            begin_sealed_bundle_work_authorized(server.vault(), peer, input, Some(id), &|txn| {
                auth.credential_is_live_in_write_txn(server.vault(), txn)
            })
            .map(Some)
        }
        Operation::Status(id) => sealed_bundle_work_status(server.vault(), peer, id),
    }
    .map_err(|_| AppError::not_found("sealed bundle", None))
}

pub(super) fn status_value(status: &SealedBundleWorkStatus) -> Value {
    let (state, entry) = match status.outcome {
        SealedBundleWorkOutcome::Pending => ("pending", None),
        SealedBundleWorkOutcome::Committed(entry) => ("committed", Some(bundle_entry(&entry))),
        SealedBundleWorkOutcome::NeedsRebase => ("needsRebase", None),
        SealedBundleWorkOutcome::Refused => ("refused", None),
    };
    json!({
        "workId": sealed_digest_hex(&status.work_id), "state": state,
        "home": status.home.map(|id| id.to_hex()), "executor": status.executor.to_hex(),
        "generation": sealed_generation_hex(&status.input.generation),
        "parent": status.input.parent.as_ref().map(sealed_generation_hex),
        "request": status.input.request.as_ref().map(sealed_digest_hex),
        "bundleDigest": sealed_digest_hex(&status.bundle_digest),
        "padsDigest": sealed_digest_hex(&status.pads_digest),
        "progress": status.prepared, "total": status.total, "phase": status.phase, "entry": entry,
    })
}

/// Non-socket callers drain the same execution engine. Socket dispatch takes
/// the tracked work driver instead, and keeps receiving frames meanwhile.
pub(super) fn bundle_commit(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let operation = operation("residence.bundle.commit", params)?;
    let mut status = server
        .transfers
        .sealed_stage_change(server.vault(), || start(server, auth, peer, operation))?
        .ok_or_else(|| AppError::not_found("sealed bundle", None))?;
    while matches!(status.outcome, SealedBundleWorkOutcome::Pending) {
        let next =
            step_sealed_bundle_work_authorized(server.vault(), peer, status.work_id, &|txn| {
                !server.residence_work_stopping()
                    && match txn {
                        Some(txn) => auth.credential_is_live_in_write_txn(server.vault(), txn),
                        None => auth.credential_is_live(server.vault()),
                    }
            })
            .map_err(|_| AppError::not_found("sealed bundle", None))?;
        let advanced = next.phase != status.phase || next.prepared != status.prepared;
        status = next;
        if !advanced {
            break;
        }
    }
    server.transfers.reconcile_sealed_stages(server.vault());
    Ok((json!({"work": status_value(&status)}), Some(Vec::new())))
}

/// A request selector reads only, including pending execution metadata. A
/// work selector resumes, and therefore uses the write-authorized driver.
pub(super) fn bundle_commit_status(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: BundleCommitStatusRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    match (input.request, input.work_id) {
        (Some(request), None) => {
            let request = digest(&request)?;
            let receipt = sealed_bundle_commit_receipt(server.vault(), peer, request)
                .map_err(|_| AppError::not_found("sealed bundle", None))?;
            let work = if receipt.is_none() {
                sealed_bundle_work_for_request(server.vault(), peer, request)
                    .map_err(|_| AppError::not_found("sealed bundle", None))?
            } else {
                None
            };
            Ok((
                json!({"receipt": receipt.map(|receipt| json!({
                "generation": sealed_generation_hex(&receipt.generation),
                "bundleDigest": sealed_digest_hex(&receipt.bundle_digest),
            })), "work": work.as_ref().map(status_value)}),
                Some(Vec::new()),
            ))
        }
        (None, Some(id)) => {
            let work = start(server, auth, peer, Operation::Status(digest(&id)?))?;
            Ok((
                json!({"work": work.as_ref().map(status_value)}),
                Some(Vec::new()),
            ))
        }
        _ => Err(AppError::invalid_params()),
    }
}
