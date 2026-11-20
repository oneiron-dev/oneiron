//! The retired-standing checks of a signed-history import and of a delivery
//! page: an arriving row never stands on a key a handoff retired.

use super::*;

/// Refuses the import when an arriving row stands on a key a handoff retired
/// in `fold` ([`retired_standing`]).
pub(super) fn refuse_retired_standing(
    store: &crate::store::Store,
    fold: &AuthorityFold,
    merged: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    evidence: Option<&AdoptedEvidence>,
    arriving: &[AuthorityEntryHash],
    held: &mut dyn FnMut(&AuthorityEntryHash) -> Result<bool>,
) -> Result<()> {
    match retired_standing(store, fold, merged, evidence, arriving, held)? {
        Some(_) => Err(retired_standing_refusal()),
        None => Ok(()),
    }
}

/// Whether an arriving row stands on a key a handoff retired in `fold`, as
/// [`retired_standing`] reads it, recording nothing (FIX 2536). The fold
/// before staging may lack a handoff's own ancestry, so an import it flags is
/// judged again on the merged history it stages, and refused, with its
/// evidence, only when that history still retires the key. An import it does
/// not flag lands as before.
pub(super) fn flags_retired_standing(
    fold: &AuthorityFold,
    merged: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    evidence: Option<&AdoptedEvidence>,
    arriving: &[AuthorityEntryHash],
) -> Result<bool> {
    for hash in arriving {
        let Some((_, entry)) = merged.get(hash) else {
            continue;
        };
        if fold.stands_on_retired_key(hash, entry, &mut |parent| match merged.get(parent) {
            Some((_, row)) => Ok(Some(row.clone())),
            None => evidence.map_or(Ok(None), |evidence| evidence.ancestor(parent)),
        })? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn retired_standing_refusal() -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(
        "authority history standing on a key a handoff retired",
    ))
}

/// The first arriving row that stands on a key a handoff retired in `fold`:
/// such a key signs nothing new into this history, and nothing new stands on
/// a row one signed. `merged` holds the resident and arriving rows. On a
/// vault that adopted a checkpoint image (`evidence`), an ancestor `merged`
/// lacks is what the image holds of it
/// ([`crate::authority::adopted_evidence::AdoptedEvidence::ancestor`]), its refusal
/// for history the image does not carry included. `held` says whether this
/// vault held a row before the import
/// ([`crate::authority::retired_signers::import_row_held`]): only such a handoff stands
/// in the refusal's equivocation evidence.
pub(super) fn retired_standing(
    store: &crate::store::Store,
    fold: &AuthorityFold,
    merged: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    evidence: Option<&AdoptedEvidence>,
    arriving: &[AuthorityEntryHash],
    held: &mut dyn FnMut(&AuthorityEntryHash) -> Result<bool>,
) -> Result<Option<AuthorityEntryHash>> {
    for hash in arriving {
        let Some((_, entry)) = merged.get(hash) else {
            continue;
        };
        if crate::authority::door_refuses_retired_standing(
            store,
            fold,
            hash,
            entry,
            &mut |parent| match merged.get(parent) {
                Some((_, row)) => Ok(Some(row.clone())),
                None => evidence.map_or(Ok(None), |evidence| evidence.ancestor(parent)),
            },
            held,
        )? {
            return Ok(Some(*hash));
        }
    }
    Ok(None)
}
