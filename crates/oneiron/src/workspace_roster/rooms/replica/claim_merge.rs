//! A claim another machine of this vault carried, merged with this vault's
//! claim of the same turn (FIX 1794, ROOM-CLAIM-TAKEOVER = A,
//! HOMERETRY-CLAIM-AUTHOR = B). Entry: `merge_carried_claim_in_txn`.

use super::*;

/// Merges `claim`, carried, as [`merge_replicated_side_row_in_txn`] merges
/// a claim: written once, or settled with the held claim of its turn.
pub(super) fn merge_carried_claim_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: &RoomClaimReceipt,
) -> Result<SideMerge> {
    let store = &vault.store;
    // FIX 4870: the carried claim names no one here for an actor
    // this vault erased, as a carried turn's actor does (FIX 6543).
    let mut carried = claim.clone();
    if let Ok(actor) = EntityId::from_hex(&carried.actor)
        && vault.carrier_actor_erased_in_txn(txn, &actor)?
    {
        carried.actor = crate::receipt::ERASED_CALL_IDENTITY.to_owned();
    }
    // A Retry's claim names its author no more than its holder
    // (HOMERETRY-CLAIM-AUTHOR = B).
    if let Some(author) = super::super::witness::retry_claim_author(&carried.receipt_ref)
        && vault.carrier_actor_erased_in_txn(txn, &author)?
    {
        super::super::witness::erase_claim_actor(&mut carried, &author);
    }
    let claim = &carried;
    let turn = EntityId::from_hex(&claim.turn_id)?;
    if TURNS
        .get_lenient(store, txn, &turn)?
        .is_some_and(|held| held.room_id != claim.room_id)
    {
        return Ok(SideMerge::Refused(TurnMergeRefusal::FixedFieldsConflict));
    }
    if let Some(held) = CLAIMS.get_lenient(store, txn, &turn)? {
        if held == *claim {
            return Ok(SideMerge::Held);
        }
        // REVIEW-4366 round 4: the same receipt's two actor
        // forms meet here; the erased form wins where the copies
        // meet, as a carried turn's actor does, whether or not
        // this vault holds the actor's marker. A Retry's author
        // merges the same way. Once the two copies are one receipt,
        // the merge holds it or writes the merged form; the order
        // below is for two receipts, where "erased" would sort after
        // an id and give back a name (REVIEW-9153 round 2).
        if held.at == claim.at
            && held.room_id == claim.room_id
            && held.generation == claim.generation
            && let Some(receipt_ref) =
                super::super::witness::merged_receipt_ref(&held.receipt_ref, &claim.receipt_ref)
            && let Some(actor) = crate::deletion::carrier_actor_merged(
                held.actor.as_str(),
                claim.actor.as_str(),
                crate::receipt::ERASED_CALL_IDENTITY,
            )
            .map(str::to_owned)
        {
            if actor == held.actor && receipt_ref == held.receipt_ref {
                return Ok(SideMerge::Held);
            }
            let mut merged = held.clone();
            merged.actor = actor;
            merged.receipt_ref = receipt_ref;
            CLAIMS.put(store, txn, &turn, &merged)?;
            return Ok(SideMerge::Written);
        }
        // REVIEW-9956 own review: one receipt's copies settle by that
        // rule alone, so no live copy returns over the erased form.
        if (held.at, &held.receipt_ref) == (claim.at, &claim.receipt_ref) {
            return Ok(SideMerge::Conflict);
        }
        // REVIEW-9956 round 2: an answer seals its claim against a
        // concurrent takeover no answer followed, in either order,
        // as the turn's responses settle it too.
        // An erased answerer seals nothing.
        let answerer = match RESPONSE.get_lenient(store, txn, &turn)? {
            Some(response) => TURNS
                .get_lenient(store, txn, &response)?
                .and_then(|spoken| named(&spoken.actor)),
            None => None,
        };
        if let Some(answerer) = answerer {
            match (
                named(&held.actor) == Some(answerer),
                named(&claim.actor) == Some(answerer),
            ) {
                (true, false) => return Ok(SideMerge::Conflict),
                (false, true) => {
                    CLAIMS.put(store, txn, &turn, claim)?;
                    return Ok(SideMerge::Conflict);
                }
                _ => {}
            }
        }
        // ROOM-CLAIM-TAKEOVER = A: a takeover stands over the claim
        // it replaced on every replica, so the higher generation
        // stands, and a copy of a replaced claim changes nothing.
        match claim.generation.cmp(&held.generation) {
            std::cmp::Ordering::Greater => {
                CLAIMS.put(store, txn, &turn, claim)?;
                return Ok(SideMerge::Written);
            }
            std::cmp::Ordering::Less => return Ok(SideMerge::Held),
            std::cmp::Ordering::Equal => {}
        }
        if (held.at, &held.receipt_ref) > (claim.at, &claim.receipt_ref) {
            CLAIMS.put(store, txn, &turn, claim)?;
        }
        return Ok(SideMerge::Conflict);
    }
    CLAIMS.put(store, txn, &turn, claim)?;
    Ok(SideMerge::Written)
}
