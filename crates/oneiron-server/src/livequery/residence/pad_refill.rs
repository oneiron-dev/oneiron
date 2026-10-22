//! `residence.bundle.pads.refill` (FIX 9362, L03 half): the end of a
//! machine's upload of a kept pad object whose bytes the home lacks. The
//! machine stages the object through `residence.bundle.put` as any pad object
//! is staged, then names it here, with the revision of the index it listed;
//! the home fills that generation's kept object again under that revision and
//! reads it back (`oneiron::sync::residence::sealed_bundle_refill`). An index
//! that moved since answers `CURRENT_CHANGED`, for the machine to list again.
//! A refused machine or stage looks missing.

use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    PadObjectRefill, sealed_bundle_refill, sealed_digest_from_hex, sealed_digest_hex,
    sealed_generation_hex,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope, bundle_entry, bundle_generation};
use crate::server::SyncServer;

/// A refill of `generation`'s kept pad object from the object the machine
/// staged, with `digest`, the object's BLAKE3, under the index `revision`
/// names; each in hex.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundlePadsRefillRequest {
    generation: String,
    digest: String,
    revision: String,
}

/// Fills a kept pad object's bytes again from the whole object the machine
/// staged for it (FIX 9362): the generation's entry once read back, or the
/// outcome that wrote nothing. Its stage gives its room on the disk back.
pub(super) fn bundle_pads_refill(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let input: BundlePadsRefillRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let generation = bundle_generation(&input.generation)?;
    let digest = sealed_digest_from_hex(&input.digest).ok_or_else(AppError::invalid_params)?;
    let revision = sealed_digest_from_hex(&input.revision).ok_or_else(AppError::invalid_params)?;
    let refill = sealed_bundle_refill(&server.vault, peer, generation, &digest, &revision);
    server.transfers.reconcile_sealed_stages(&server.vault);
    let refill = refill.map_err(|_| AppError::not_found("sealed bundle", None))?;
    let mut answer = json!({ "outcome": refill.outcome() });
    match &refill {
        PadObjectRefill::Refilled(entry) => answer["entry"] = bundle_entry(entry),
        PadObjectRefill::CurrentChanged => {}
        PadObjectRefill::Unavailable(unavailable) => {
            answer["generation"] = json!(sealed_generation_hex(&unavailable.generation));
            answer["digest"] = json!(sealed_digest_hex(&unavailable.digest));
            answer["offset"] = json!(unavailable.offset);
        }
    }
    Ok((answer, Some(Vec::new())))
}
