//! `residence.bundle.access` (FIX 4271): a late joiner's access to the kept
//! sealed pad objects, one tagged call.
//!
//! - `ensure` (write): asks access for machines the owner admitted, in every
//!   kept generation or those named. Only the machine itself, by the proof on
//!   this socket, sets an offer it could not use back to pending.
//! - `pending` (read): the grants a machine of the owner's whose proof stands
//!   here may issue, and the generations it waits on a grant of itself.
//! - `offer` (write): one sealed grant. Its own signature is its authority:
//!   the home checks the issuer's standing, the generation and the recipient.
//! - `get` (read): one generation's grants for the machine this socket
//!   proved, never one the request names.
//!
//! The home opens nothing. A refused call looks missing; no door asks where
//! the caller runs.

use base64::Engine;
use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    PadAccessRequest, PadAccessState, ensure_sealed_pad_access, offer_sealed_pad_access,
    pending_sealed_pad_access, sealed_digest_from_hex, sealed_digest_hex, sealed_generation_hex,
    sealed_pad_access,
};
use oneiron::world_keys::{PadAdmissionTarget, SealedPadAdmissionGrant};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope, bundle_generation};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum AccessRequest {
    Ensure { targets: Vec<AccessTarget> },
    Pending,
    Offer { grant: String },
    Get { generation: String },
}

/// One machine, by its id and the digest of its encryption key, both hex.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccessTarget {
    machine: String,
    key: String,
    /// The kept generations asked for; absent for every one.
    #[serde(default)]
    generations: Option<Vec<String>>,
    /// Generations whose offer the machine itself could not use.
    #[serde(default)]
    invalid: Vec<String>,
}

fn missing() -> AppError {
    AppError::not_found("sealed bundle", None)
}

fn target(machine: &str, key: &str) -> Result<PadAdmissionTarget, AppError> {
    Ok(PadAdmissionTarget {
        machine: EntityId::from_hex(machine).map_err(|_| AppError::invalid_params())?,
        encryption_key_digest: sealed_digest_from_hex(key).ok_or_else(AppError::invalid_params)?,
    })
}

fn target_json(target: &PadAdmissionTarget) -> Value {
    json!({
        "machine": target.machine.to_hex(),
        "key": sealed_digest_hex(&target.encryption_key_digest),
    })
}

pub(super) fn bundle_access(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AccessRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let reply = match input {
        AccessRequest::Ensure { targets } => {
            auth.require(CoreScope::Write)?;
            let requests = targets
                .iter()
                .map(|wire| {
                    let generations = |list: &[String]| {
                        list.iter()
                            .map(String::as_str)
                            .map(bundle_generation)
                            .collect::<Result<Vec<_>, _>>()
                    };
                    Ok(PadAccessRequest {
                        target: target(&wire.machine, &wire.key)?,
                        generations: wire.generations.as_deref().map(generations).transpose()?,
                        invalid: generations(&wire.invalid[..])?,
                    })
                })
                .collect::<Result<Vec<_>, AppError>>()?;
            let taken =
                ensure_sealed_pad_access(&server.vault, peer, &requests).map_err(|_| missing())?;
            json!({ "taken": taken.iter().map(target_json).collect::<Vec<_>>() })
        }
        AccessRequest::Pending => {
            let list = pending_sealed_pad_access(&server.vault, peer).map_err(|_| missing())?;
            let pending: Vec<Value> = list
                .pending
                .iter()
                .map(|row| {
                    let mut wire = target_json(&row.target);
                    wire["generation"] = sealed_generation_hex(&row.generation).into();
                    wire["root"] = row.kit_root.map(|root| sealed_digest_hex(&root.0)).into();
                    wire
                })
                .collect();
            let waiting: Vec<String> = list.waiting.iter().map(sealed_generation_hex).collect();
            json!({ "pending": pending, "waiting": waiting })
        }
        AccessRequest::Offer { grant } => {
            auth.require(CoreScope::Write)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(grant)
                .map_err(|_| AppError::invalid_params())?;
            let grant = SealedPadAdmissionGrant::from_bytes(&bytes)
                .map_err(|_| AppError::invalid_params())?;
            offer_sealed_pad_access(&server.vault, &grant).map_err(|_| missing())?;
            json!({ "offered": true })
        }
        AccessRequest::Get { generation } => {
            let generation = bundle_generation(&generation)?;
            let grants: Vec<Value> = sealed_pad_access(&server.vault, peer, generation)
                .map_err(|_| missing())?
                .into_iter()
                .map(|(target, state)| {
                    let grant = match state {
                        PadAccessState::Pending => None,
                        PadAccessState::Offered(grant) => grant
                            .to_bytes()
                            .ok()
                            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
                    };
                    json!({
                        "key": sealed_digest_hex(&target.encryption_key_digest),
                        "grant": grant,
                    })
                })
                .collect();
            json!({ "grants": grants })
        }
    };
    Ok((reply, Some(Vec::new())))
}
