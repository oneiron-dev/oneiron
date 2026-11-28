//! Whether a row a result answers is the owner's own signed word (row
//! OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, LIMIT-1
//! RESULT-NEEDS-EXECUTOR-KEY): the signed-evidence branch of the owner
//! reserve's judge of an answered row, which the door reads, and alone the
//! source a result writer's owner key proof rests on.

use super::*;

/// Whether a slip issuer of `structure` that `fold` holds as a live owner on
/// its roster, retired by no handoff, signs or cosigns `entry`: the owner
/// key branch of [`super::signs_for_the_owner`]. A row that passes through
/// is judged by its signed envelope (census L5-22 1a-iii).
pub(super) fn an_owner_key_signs(
    structure: &AuthorityStructure,
    fold: &AuthorityFold,
    row: &FoldRow,
) -> bool {
    std::iter::once(row.signer())
        .chain(row.cosigns())
        .any(|signature| {
            let key = &signature.public_key;
            structure.issuers.contains(key)
                && !fold.retired_keys.contains(key)
                && roster_has_live_owner(&fold.roster, key)
        })
}

/// The row `hash` a result answers: the stored one, else, on a vault that
/// adopted a checkpoint image, the body the image carries of that covered
/// row. `None` for a row neither stored nor carried whole.
pub(super) fn answered_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
) -> crate::error::Result<Option<FoldRow>> {
    match crate::authority::retired_signers::stored_authority_fold_row(store, txn, hash)? {
        Some(asked) => Ok(Some(asked)),
        None => Ok(crate::authority::adopted_evidence::CarriedRows::default()
            .get(store, txn, hash)?
            .map(FoldRow::Open)),
    }
}

/// Whether the request or residence directive `hash` this install's result
/// answers is the owner's own signed word, the one source a result's owner
/// key proof may rest on
/// (row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, LIMIT-1
/// RESULT-NEEDS-EXECUTOR-KEY): a slip issuer `fold` holds as a live owner,
/// retired by no handoff, signs or cosigns the row ([`an_owner_key_signs`]),
/// the stored one or the body an adopted image carries ([`answered_row`]).
/// The signed-evidence branch of [`super::asks_the_owners_work`] alone, a
/// writer's check, never the door's: a row this install's own key carries
/// ([`super::carries_own_will`]) proves nothing here, since a holder's edit,
/// an agent's Grant, automatic upkeep and a queued retry carry their
/// requests under that key too, and an own anchor signs no request a machine
/// executes. An unproven request stays unproven in its answer, whoever
/// carried it and whatever key the executor holds now; a request whose
/// owner key was revoked since proves none either.
pub(crate) fn answers_the_owners_signed_work_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    hash: &AuthorityEntryHash,
) -> crate::error::Result<bool> {
    let Some(asked) = answered_row(store, txn, hash)? else {
        return Ok(false);
    };
    let view = door_view(store, txn)?;
    Ok(an_owner_key_signs(&view.structure, fold, &asked))
}
