//! The parents a residence result names on a vault that adopted a
//! checkpoint image (FIX 5412, CALLS "FIX 5412 result parents").
//!
//! A result names its directive and the rows its signer's standing rests on.
//! Where some of those are covered rows off the image's frontier, the result
//! is a late fork: the fold past the image folds it only where the image
//! keeps their states, and asks for the whole history otherwise. Each such
//! row is named instead through the image's frontier rows above it, where a
//! tail row folds on the image's own states, when every frontier row so named
//! is one the reference fold schedules a child on as it does here: valid, and
//! holding no state a world refold set ([`super::super::world_refold`]). The
//! directive then stands beneath the result's parents, as the fold's
//! transitive arm judges it (`entry_transition::residence_result_stands`).

use std::collections::BTreeSet;

use super::*;
use crate::store::Store;

/// `explicit`, the parents a residence result names, with each covered row
/// off the frontier of the image this vault adopted named through the
/// frontier rows above it. None names `explicit` as before: no adoption, no
/// such row, one no frontier row above it names as the reference fold would,
/// more parents than an entry holds, or a fault reading the image.
pub(crate) fn proven_residence_result_parents_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    explicit: &BTreeSet<AuthorityEntryHash>,
) -> Option<BTreeSet<AuthorityEntryHash>> {
    let evidence = super::super::adopted_evidence::adopted_evidence_in_txn(store, txn).ok()??;
    let image = evidence.image();
    let frontier: BTreeSet<AuthorityEntryHash> = image.frontier.iter().copied().collect();
    let off: BTreeSet<AuthorityEntryHash> = explicit
        .iter()
        .filter(|hash| image.rows.contains_key(*hash) && !frontier.contains(*hash))
        .copied()
        .collect();
    if off.is_empty() {
        return None;
    }
    let mut parents: BTreeSet<AuthorityEntryHash> = explicit.difference(&off).copied().collect();
    let mut reached = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for head in &image.frontier {
        // A result is a main-log row: it names a valid main-log head.
        let row = image.rows.get(head)?;
        if row.world.is_some() || !fold.valid_entries.contains(head) {
            continue;
        }
        let mut below = BTreeSet::new();
        let mut stack = row.parents.clone();
        while let Some(at) = stack.pop() {
            if !seen.insert(at) {
                continue;
            }
            if off.contains(&at) {
                below.insert(at);
            }
            stack.extend(image.rows.get(&at)?.parents.iter().copied());
        }
        if below.is_empty() {
            continue;
        }
        if !reference_parent(image, row)? {
            return None;
        }
        parents.insert(*head);
        reached.extend(below);
    }
    (reached == off && parents.len() <= MAX_PARENTS).then_some(parents)
}

/// Whether the reference fold schedules a child of the valid frontier row
/// `row` as the fold past the image does (FIX 11371): `row` holds no state a
/// world refold set. A row of a kind no refold folds again holds its own
/// state; any other row holds it only where no main-log row beneath it is
/// one the image's fold did not keep. None where the image does not hold a
/// row beneath it.
fn reference_parent(image: &AuthorityCheckpointV2, row: &AuthorityCheckpointRow) -> Option<bool> {
    let own_state = row
        .body
        .as_ref()
        .and_then(|body| decode_authority_log_entry_body(body).ok())
        .is_some_and(|entry| {
            !super::super::world_refold::refolds(&entry.op, |request| {
                super::super::world_refold::carried_request_kind(image, request)
            })
        });
    if own_state {
        return Some(true);
    }
    let kept = &image.fold().valid_entries;
    let mut stack = row.parents.clone();
    let mut seen = BTreeSet::new();
    while let Some(at) = stack.pop() {
        if !seen.insert(at) {
            continue;
        }
        let ancestor = image.rows.get(&at)?;
        if ancestor.world.is_none() && !kept.contains(&at) {
            return Some(false);
        }
        stack.extend(ancestor.parents.iter().copied());
    }
    Some(true)
}
