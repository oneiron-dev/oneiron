//! The machine a request names.
//!
//! A request may carry `x-oneiron-machine: {"machine","signature"}` beside its
//! slip proof. The machine's install key signs the same token, timestamp and
//! nonce, so the claim is as fresh, and as single-use, as the proof it rides.
//! It is independent of the actor: it never widens or narrows `CoreAuth`.
use axum::http::HeaderMap;
use oneiron::authority::PeerMachine;
use serde::Deserialize;

use super::{BindingProof, parse_signature};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineClaim {
    machine: String,
    signature: String,
}

/// What one admitted request proves about its machine. Anything missing,
/// malformed or unverifiable is `Unknown`: an unknown destination, never this
/// machine or one of the owner's. It never refuses the request, so a machine
/// whose profile has not reached this vault yet still syncs.
pub(super) fn peer_machine(
    headers: &HeaderMap,
    token: &str,
    proof: &BindingProof,
    vault: &oneiron::Vault,
) -> PeerMachine {
    let Some(claim) = headers
        .get(oneiron::authority::MACHINE_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| serde_json::from_str::<MachineClaim>(raw).ok())
    else {
        return PeerMachine::Unknown;
    };
    let (Ok(machine), Some(signature)) = (
        oneiron::EntityId::from_hex(&claim.machine),
        parse_signature(&claim.signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok()),
    ) else {
        return PeerMachine::Unknown;
    };
    vault
        .verify_machine_connection_proof(machine, &signature, token, proof.timestamp, &proof.nonce)
        .unwrap_or(PeerMachine::Unknown)
}
