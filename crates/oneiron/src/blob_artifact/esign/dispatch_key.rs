//! Core half of `blob_artifact::esign::dispatch_key`: its store-layer items live in `oneiron_store::blob_artifact::esign::dispatch_key` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::blob_artifact::esign::dispatch_key::*;

use super::outbound::EsignOutboundVerb;
use crate::store::verb_invocation::InvocationId;
use crate::{EntityId, Vault};
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// One e-sign act's OF-327 intent ref: its logical send ref and ledger
/// identity, carrying its retry key.
pub(super) fn esign_intent_ref(verb: EsignOutboundVerb, document: EntityId, key: &str) -> String {
    format!("esign:{}:{}:{key}", verb.as_str(), document.to_hex())
}

/// The retry key an e-sign act of `actor` runs under: the caller's own
/// `idempotency_key`; for a call with none, one derived from `invocation`,
/// the call's own id, when its transport named one, else a fresh nonce
/// minted for this call.
/// # Errors
/// An empty `idempotency_key`, or the nonce's mint failing.
pub(super) fn esign_dispatch_key(
    vault: &Vault,
    verb: EsignOutboundVerb,
    document: EntityId,
    actor: EntityId,
    on_behalf_of: Option<&str>,
    idempotency_key: Option<&str>,
    invocation: Option<InvocationId>,
) -> MemoryResult<String> {
    match (idempotency_key, invocation) {
        (Some(key), _) if key.trim().is_empty() => {
            Err(MemoryError::bad_request("idempotency_key is empty"))
        }
        (Some(key), _) => Ok(key.to_owned()),
        (None, Some(invocation)) => Ok(invocation_key(
            verb,
            document,
            actor,
            on_behalf_of,
            invocation,
        )),
        (None, None) => Ok(vault.new_entity_id()?.to_hex()),
    }
}

/// The key a no-key call named `invocation` derives: BLAKE3 over the domain,
/// the actor, the act, the document and the invocation, each length-framed
/// (u64 little-endian), and the principal tagged present (1) or absent (0).
fn invocation_key(
    verb: EsignOutboundVerb,
    document: EntityId,
    actor: EntityId,
    on_behalf_of: Option<&str>,
    invocation: InvocationId,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NO_KEY_CALL_DOMAIN);
    for part in [
        actor.to_hex().as_str(),
        verb.as_str(),
        document.to_hex().as_str(),
        invocation.to_hex().as_str(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    match on_behalf_of {
        Some(principal) => {
            hasher.update(&[1]);
            hasher.update(&(principal.len() as u64).to_le_bytes());
            hasher.update(principal.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    crate::entity_id::bytes_to_hex_lower(&hasher.finalize().as_bytes()[..NO_KEY_CALL_KEY_BYTES])
}
