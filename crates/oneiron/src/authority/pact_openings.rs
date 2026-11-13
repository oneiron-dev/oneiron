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
//!
//! A cached fold keeps its last answer ([`OpeningAnswer`], FIX 23233) with
//! the rows of each pact's opening it was read under, and a warm hit whose
//! snapshot reads the same rows takes it without opening custody's files.
//! The rows and the authority generation tell every change custody's files
//! make to a committed opening. A key enters custody only in the writer
//! that logs its Connect or re-pact, and a committed key is staged to
//! retire only in the writer that ends its pact (a disconnect or a guest
//! revoke, [`crate::store::grant_scope_custody::retire_scope_keys`]): both
//! move the authority generation, which starts a new cached fold. Custody's
//! finisher clears a staged intent in the rows once it has retired the
//! file. An archived vault or one with no custody reads no row, and a live
//! key's bytes never change. An answer that met an unread row or key is
//! not kept, so the next read tries again, and each unread one is logged
//! once per authority generation.

use std::collections::BTreeSet;

use oneiron_authority::federation::encode_federation_pact_scope;

use crate::store::Store;
use crate::store::grant_scope_custody::{ScopeOpeningRow, scope_key_of, scope_opening_row_in_txn};

use super::readonly_fold::UnreadLogged;
use super::*;

/// The pacts a read held inactive for a scope commitment mismatch, with the
/// opening rows of each non-terminal pact it read them under (FIX 23233).
#[derive(Clone)]
pub(super) struct OpeningAnswer {
    rows: Vec<([u8; 32], Option<ScopeOpeningRow>)>,
    mismatched: BTreeSet<[u8; 32]>,
}

/// Each non-terminal pact of `fold` whose folded scope does not match its
/// signed commitment under the live opening this install holds for the
/// epoch that keyed it. `kept` is the last answer for `fold`: taken when
/// `txn` reads the same opening rows, else replaced by this read's unless a
/// row or key did not read. Each unread one is logged once in `logged`.
pub(super) fn scope_commitment_mismatches(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    kept: &mut Option<OpeningAnswer>,
    logged: &mut UnreadLogged,
) -> BTreeSet<[u8; 32]> {
    let mut unread = false;
    let rows: Vec<([u8; 32], Option<ScopeOpeningRow>)> = fold
        .federation_pacts
        .iter()
        .filter(|(_, pact)| !pact.status.is_terminal())
        .filter_map(|(pact_id, pact)| {
            match scope_opening_row_in_txn(store, txn, &pact.grant_ref, pact_id, pact.scope_epoch) {
                Ok(row) => Some((*pact_id, row)),
                Err(error) => {
                    unread = true;
                    log_unread_opening(logged, pact_id, &error);
                    None
                }
            }
        })
        .collect();
    if !unread && let Some(answer) = kept.as_ref().filter(|answer| answer.rows == rows) {
        return answer.mismatched.clone();
    }
    let mut mismatched = BTreeSet::new();
    for (pact_id, row) in &rows {
        let (Some(row), Some(pact)) = (row, fold.federation_pacts.get(pact_id)) else {
            continue;
        };
        let key = match scope_key_of(store, row) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                unread = true;
                log_unread_opening(logged, pact_id, &error);
                continue;
            }
        };
        let matches = encode_federation_pact_scope(&pact.pact_scope).is_ok_and(|canonical| {
            federation_scope_digest(&key, &pact.pact_nonce, &canonical) == pact.scope_digest
        });
        if !matches {
            mismatched.insert(*pact_id);
        }
    }
    if !unread {
        *kept = Some(OpeningAnswer {
            rows,
            mismatched: mismatched.clone(),
        });
    }
    mismatched
}

/// Logs pact `pact_id`'s opening that did not read, the first time `logged`
/// meets it.
fn log_unread_opening(logged: &mut UnreadLogged, pact_id: &[u8; 32], error: &crate::error::Error) {
    if logged.first_opening(*pact_id) {
        tracing::warn!(
            %error,
            pact = %crate::entity_id::bytes_to_hex_lower(pact_id),
            "a pact's scope opening did not read; the pact stands as folded"
        );
    }
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
