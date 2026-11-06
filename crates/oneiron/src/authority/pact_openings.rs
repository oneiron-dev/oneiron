//! This install's live check of each pact's scope commitment (FIX 11730).
//!
//! The fold takes a Connect's or re-pact's signed commitment as it stands,
//! the disclosed scope only canonical, so every machine folds one log to one
//! state (canon D3). Signed-history import, replicated rows and the generic
//! authority put reach the fold without the typed doors' keyed check, so a
//! signed entry may disclose a scope other than the one the peer's gesture
//! committed to. Where custody holds the live opening key of the epoch that
//! keyed a pact's current ceiling, this install's authority view recomputes
//! the keyed digest over the folded scope and the signed nonce. A pact whose
//! scope does not match is held inactive here: suspended in the view, its
//! plaintext scope dropped as an ended pact's is, so selector authorization,
//! document reads and guest slips refuse its grant. A fresh dual-signed
//! re-pact heals it, as it heals any suspended pact.
//!
//! No live key (never installed here, retired at a revoke, or the vault
//! archived) leaves the pact as the fold left it. A key that does not read
//! is logged and leaves the pact as it is (rubric 1, as an agent act's
//! unread Grant in [`super::carried_act`]).

use std::collections::BTreeSet;

use oneiron_authority::federation::encode_federation_pact_scope;

use crate::store::Store;
use crate::store::grant_scope_custody::scope_key_in_txn;

use super::*;

/// Each non-terminal pact of `fold` whose folded scope does not match its
/// signed commitment under the live opening this install holds for the
/// epoch that keyed it.
pub(super) fn scope_commitment_mismatches(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> BTreeSet<[u8; 32]> {
    fold.federation_pacts
        .iter()
        .filter(|(_, pact)| !pact.status.is_terminal())
        .filter_map(|(pact_id, pact)| {
            let key = match scope_key_in_txn(store, txn, &pact.grant_ref, pact_id, pact.scope_epoch)
            {
                Ok(Some(key)) => key,
                Ok(None) => return None,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        pact = %crate::entity_id::bytes_to_hex_lower(pact_id),
                        "a pact's scope opening did not read; the pact stands as folded"
                    );
                    return None;
                }
            };
            let matches = encode_federation_pact_scope(&pact.pact_scope).is_ok_and(|canonical| {
                federation_scope_digest(&key, &pact.pact_nonce, &canonical) == pact.scope_digest
            });
            (!matches).then_some(*pact_id)
        })
        .collect()
}

/// `fold` with each pact of `mismatched` held inactive on this install:
/// suspended, its plaintext scope dropped, its keyed digest kept.
pub(super) fn hold_mismatched_pacts(fold: &mut AuthorityFold, mismatched: &BTreeSet<[u8; 32]>) {
    for pact_id in mismatched {
        if let Some(pact) = fold.federation_pacts.get_mut(pact_id) {
            pact.status = FederationPactStatus::Suspended;
            pact.erase_scope();
            tracing::warn!(
                pact = %crate::entity_id::bytes_to_hex_lower(pact_id),
                reason = "scope_commitment_mismatch",
                "a pact's folded scope does not match its signed commitment under this install's live opening; the pact is held inactive here"
            );
        }
    }
}
