//! `residence.bundle.commit` and `residence.bundle.commit.status`: the end of
//! a sealed bundle upload, and the home's record of a commit made for the
//! owner's bundle publication request (FIX 922, 4787).
//!
//! A commit may name the request it publishes for; the home records it, in
//! the commit's own transaction, once the request names this home and the
//! committing machine as its executor. The status read answers that record
//! to the machine that made it, so an executor whose acknowledgement was lost
//! enacts the request instead of publishing again. Ids and the sealed
//! bundle's ciphertext digest only. A refused call looks missing; no door
//! asks where the caller runs.

use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    commit_sealed_bundle, sealed_bundle_commit_receipt, sealed_digest_from_hex, sealed_digest_hex,
    sealed_generation_hex,
};
use oneiron::world_keys::RecoveryRootId;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope, bundle_entry, bundle_generation};
use crate::server::SyncServer;

/// The end of an upload: the home commits the generation whole while its
/// newest is still `parent`. `root` is the recovery root the machine pins, in
/// hex, whose kit the home then serves the generation to. `request` is the
/// owner's bundle publication request it publishes for, in hex, when it
/// publishes on his ask.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleCommitRequest {
    generation: String,
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    request: Option<String>,
}

/// The request whose recorded commit a machine reads, in hex.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleCommitStatusRequest {
    request: String,
}

fn request_hash(hex: &str) -> Result<[u8; 32], AppError> {
    sealed_digest_from_hex(hex).ok_or_else(AppError::invalid_params)
}

/// Commits the generation the machine staged whole as the vault's newest,
/// while the newest is still the parent it names (FIX 922); a slot may take
/// more than one, each with its commit order (FIX 8885). The root it names is kept for the kit door, and the request it names
/// gets the commit recorded (FIX 4787). A refused machine, parent, root or
/// upload looks missing.
pub(super) fn bundle_commit(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let input: BundleCommitRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let generation = bundle_generation(&input.generation)?;
    let parent = input.parent.as_deref().map(bundle_generation).transpose()?;
    let root = match input.root.as_deref() {
        Some(root) => Some(RecoveryRootId(
            sealed_digest_from_hex(root).ok_or_else(AppError::invalid_params)?,
        )),
        None => None,
    };
    let request = input.request.as_deref().map(request_hash).transpose()?;
    let entry = commit_sealed_bundle(&server.vault, peer, generation, parent, root, request);
    // The stages the commit dropped give their room back.
    server.transfers.reconcile_sealed_stages(&server.vault);
    let entry = entry.map_err(|_| AppError::not_found("sealed bundle", None))?;
    Ok((bundle_entry(&entry), Some(Vec::new())))
}

/// The commit the home recorded for the named request, for the machine that
/// made it (FIX 4787): its generation and bundle digest, or none. It reads
/// for a machine of the owner's, or the one the request asked to publish
/// here; any other looks missing.
pub(super) fn bundle_commit_status(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: BundleCommitStatusRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let request = request_hash(&input.request)?;
    let receipt = sealed_bundle_commit_receipt(&server.vault, peer, request)
        .map_err(|_| AppError::not_found("sealed bundle", None))?;
    let receipt = receipt.map(|receipt| {
        json!({
            "generation": sealed_generation_hex(&receipt.generation),
            "bundleDigest": sealed_digest_hex(&receipt.bundle_digest),
        })
    });
    Ok((json!({"receipt": receipt}), Some(Vec::new())))
}
