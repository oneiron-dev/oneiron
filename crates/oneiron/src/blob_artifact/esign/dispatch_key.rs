//! FIX 6424 (Engine 10-20 20:4x): an e-sign act called with no retry key is
//! keyed on its own call. An owner's one-time press approves exactly one
//! prepared send, and that send's logical ref (`esign:<verb>:<document>:<key>`)
//! is part of what it approves, so two separate calls stay two sends: two
//! keys, two intent refs, two gate decisions, each with its own press.
//!
//! A call whose transport named its invocation (`x-oneiron-invocation`, MCP
//! `_meta`, a code-mode step) derives its key from that id, so a true retry
//! of the call, naming it again, prepares the same send and spends the same
//! press. A call that names none mints a fresh nonce, as every no-key call
//! did before; its view's `intent_ref` ends in that key, and its retry passes
//! the key as `idempotency_key`. No key is stored and no ledger row is read,
//! so a damaged earlier row never blocks a new call (CALLS `FIX 6424 e-sign
//! no-key key chain`).

use super::outbound::EsignOutboundVerb;
use crate::memory::{MemoryError, MemoryResult};
use crate::runtime_hooks::InvocationId;
use crate::{EntityId, Vault};

/// The BLAKE3 domain of a no-key act's key derived from its invocation.
const NO_KEY_CALL_DOMAIN: &[u8] = b"oneiron.esign.dispatch.no_key.call.v1";
/// How many bytes of that digest the key keeps, as lower hex: a fresh
/// nonce's length.
const NO_KEY_CALL_KEY_BYTES: usize = 16;

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
