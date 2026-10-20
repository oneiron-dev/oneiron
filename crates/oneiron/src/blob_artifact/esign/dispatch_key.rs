//! FIX 6424 (Engine 10-20 17:4x): an e-sign act called with no retry key
//! keeps the first key it was prepared under across the owner's ask and the
//! retry. An owner's one-time press approves exactly one prepared send, and
//! that send's logical ref (`esign:<verb>:<document>:<key>`) is part of what
//! it approves: a key minted anew on each call would make every retry a new
//! send the press does not cover.
//!
//! The key is the first link of the caller's own chain, for this act on this
//! document and principal, that no admission has used yet. A gate that holds
//! or refuses the act writes no ledger row, so its retry finds the same key;
//! once a send is admitted under a link, the next act takes the next one, so
//! each admitted act stays its own send, as each no-key call was before. No
//! key is stored, and none is minted after the press.

use super::model::invalid;
use super::outbound::EsignOutboundVerb;
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};
use crate::{EntityId, Result, Vault};

/// The BLAKE3 domain of a no-key act's key chain.
const NO_KEY_CHAIN_DOMAIN: &[u8] = b"oneiron.esign.dispatch.no_key.v1";

/// One e-sign act's OF-327 intent ref: its logical send ref and ledger
/// identity, carrying its retry key.
pub(super) fn esign_intent_ref(verb: EsignOutboundVerb, document: EntityId, key: &str) -> String {
    format!("esign:{}:{}:{key}", verb.as_str(), document.to_hex())
}

/// The retry key a no-key act of `actor` runs under: the first link of its
/// chain whose act no admission has recorded on the ledger yet.
/// # Errors
/// A storage failure, or a ledger row that does not read.
pub(super) fn first_unadmitted_key(
    vault: &Vault,
    verb: EsignOutboundVerb,
    document: EntityId,
    actor: EntityId,
    on_behalf_of: Option<&str>,
) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NO_KEY_CHAIN_DOMAIN);
    for part in [
        actor.to_hex().as_str(),
        verb.as_str(),
        document.to_hex().as_str(),
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
    let mut link = hasher.finalize();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    loop {
        let key = crate::entity_id::bytes_to_hex_lower(&link.as_bytes()[..16]);
        let attempt =
            crate::outbound::outbound_dispatch_attempt_id(&esign_intent_ref(verb, document, &key))
                .map_err(|_| invalid("dispatch attempt id"))?;
        let admitted = read_intent_for_attempt_in_txn(vault, &txn, attempt, 0).map_err(
            |error| match error {
                IntentLedgerError::Engine(error) => error,
                _ => invalid("dispatch ledger row"),
            },
        )?;
        if admitted.is_none() {
            return Ok(key);
        }
        let mut next = blake3::Hasher::new();
        next.update(NO_KEY_CHAIN_DOMAIN);
        next.update(link.as_bytes());
        link = next.finalize();
    }
}
