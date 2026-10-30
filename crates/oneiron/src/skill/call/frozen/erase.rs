//! An erase among the frozen callable cases (FIX 12093). Both hooks run in
//! the erase's own transaction and rewrite a case in its own encoding, never
//! through the side-row wall: forgetting an id adds nothing to admit.

use super::{CASES, CaseCaller, FrozenCall};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// How an erased actor's id reads in a frozen case's texts.
const ERASED_SPELLING: &str = "erased";

/// Keeps every frozen case naming erased actor `actor` in its erased form,
/// under its own key, so the case still counts: a case made for it names no
/// caller, and each spelling of its id in the arguments or the answer reads
/// [`ERASED_SPELLING`]. Registered on the case table's declaration.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_callable_case_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let lower = actor.to_hex();
    let spellings = [lower.to_ascii_uppercase(), lower];
    for (key, mut row) in cases_in_txn(&vault.store, wtxn)? {
        let mut named = row.caller == CaseCaller::Actor(*actor);
        if named {
            row.caller = CaseCaller::Erased;
        }
        for text in [&mut row.arguments, &mut row.answer] {
            for spelling in &spellings {
                if text.contains(spelling.as_str()) {
                    *text = text.replace(spelling.as_str(), ERASED_SPELLING);
                    named = true;
                }
            }
        }
        if named {
            rewrite_in_txn(&vault.store, wtxn, &key, &row)?;
        }
    }
    Ok(())
}

/// The frozen cases an erased record reaches, at both delete doors (one line
/// of `deletion::derived_rows`):
/// - an erased skill's own cases go, by its id16 prefix;
/// - a case whose known source rows name `id` goes;
/// - a case whose sources are unknown goes when its receipt names `id` as
///   its job, trigger, trace or a field. Its actor is the actor scrub's.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_callable_cases_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    CASES.delete_from(store, wtxn, id.as_bytes())?;
    let spelled = id.to_hex();
    for (key, row) in cases_in_txn(store, wtxn)? {
        let named = match &row.source_rows {
            Some(rows) => rows.contains(id),
            None => crate::receipt::attempt_pack_receipt_in_txn(store, wtxn, &row.receipt)?
                .is_some_and(|receipt| {
                    let names = |text: &str| text.to_ascii_lowercase().contains(&spelled);
                    receipt.job_ref.as_deref().is_some_and(names)
                        || receipt.trigger_ref.as_deref().is_some_and(names)
                        || receipt.policy_trace.iter().any(|step| names(step.as_str()))
                        || receipt.fields.values().any(|value| names(value.as_str()))
                }),
        };
        if named {
            CASES.delete(store, wtxn, &key)?;
        }
    }
    Ok(())
}

/// Every frozen case. A row that no longer decodes names nothing either
/// hook can match: it is deleted, and the count is said.
fn cases_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<Vec<(Vec<u8>, FrozenCall)>> {
    let raw = CASES
        .iter_raw_from(store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut rows = Vec::with_capacity(raw.len());
    let mut dropped = 0_usize;
    for (key, value) in raw {
        match CASES.decode_value(&value) {
            Ok(row) => rows.push((key, row)),
            Err(_) => {
                CASES.delete(store, wtxn, &key)?;
                dropped += 1;
            }
        }
    }
    if dropped > 0 {
        tracing::warn!(dropped, "an erase deleted frozen callable cases that no longer decode");
    }
    Ok(rows)
}

fn rewrite_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key: &Vec<u8>,
    row: &FrozenCall,
) -> Result<()> {
    store
        .vault_meta
        .put(wtxn, &CASES.key_bytes(key), &CASES.encode_value(row)?)?;
    Ok(())
}
