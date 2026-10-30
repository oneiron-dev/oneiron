//! Erasure and demotion of TURNs out of the projection: the rounds a
//! removed turn gave words to are retired, and the live turns they consumed
//! go back on the carrier to be read again.

use super::*;

/// Takes an erased TURN's words out of the projection: every round it gave
/// words to holds nothing more. The riders that round consumed are
/// re-dirtied, so a live repeat of what the turn said is read as new, and so
/// are the other turns of a round still queued, whose attempt cannot read
/// its batch without the erased turn. The turn rides nothing more: a TURN
/// erased itself (`gone`) is read no more, and a TURN that lost a MESSAGE
/// is read again, since no attempt has read the words it keeps.
pub(crate) fn erase_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    gone: bool,
) -> Result<()> {
    if unride_in_txn(store, txn, turn)? && !gone {
        reread_in_txn(store, txn, turn)?;
    }
    let Some(given) = GIVEN.get(store, txn, turn)? else {
        return Ok(());
    };
    for id in &given.rounds {
        let Some(round) = ROUND.get(store, txn, id)? else {
            continue;
        };
        for at in &round.riders {
            if let Some(rider) = RIDER.get(store, txn, at)? {
                RIDER_OF.delete(store, txn, &(rider.after.1, *at))?;
            }
            RIDER.delete(store, txn, at)?;
            RIDES.delete(store, txn, &at.1)?;
            reread_in_txn(store, txn, &at.1)?;
        }
        let batch: &[_] = if round.applied { &[] } else { &round.turns };
        for member in batch.iter().filter(|member| *member != turn) {
            reread_in_txn(store, txn, member)?;
        }
        if let Some(mut latest) = LATEST.get(store, txn, &())?
            && latest.round == *id
        {
            latest.reading = None;
            LATEST.put(store, txn, &(), &latest)?;
        }
        ROUND.delete(store, txn, id)?;
    }
    GIVEN.delete(store, txn, turn)?;
    Ok(())
}

/// Takes the TURNs a window demotion removes out of the projection, in the
/// remover's transaction before their rows go (OF-534). Their words are
/// away, not erased: each round one gave words to holds nothing more and is
/// retired as [`erase_turn_in_txn`] retires it, but only kept live turns go
/// back on the carrier, its riders and, while it is queued, its other
/// turns. A round with a participant under a legal hold stays whole, since
/// retiring it would change that record's projection; it only stops
/// holding, and the removed turn keeps its entry for it. A removed turn
/// rides nothing more. Attempts and their receipts are not read.
#[cfg(feature = "sync")]
pub(crate) fn demote_turns_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turns: &BTreeSet<EntityId>,
) -> Result<()> {
    if let Some(latest) = LATEST.get(store, txn, &())?
        && turns.contains(&latest.key.1)
    {
        release_hold_in_txn(store, txn, &latest.round)?;
    }
    for turn in turns {
        unride_in_txn(store, txn, turn)?;
        let Some(given) = GIVEN.get(store, txn, turn)? else {
            continue;
        };
        let mut kept = Vec::new();
        for id in given.rounds {
            let Some(round) = ROUND.get(store, txn, &id)? else {
                continue;
            };
            release_hold_in_txn(store, txn, &id)?;
            if round_held_in_txn(store, txn, &round)? {
                kept.push(id);
                continue;
            }
            for at in &round.riders {
                if let Some(rider) = RIDER.get(store, txn, at)? {
                    RIDER_OF.delete(store, txn, &(rider.after.1, *at))?;
                }
                RIDER.delete(store, txn, at)?;
                RIDES.delete(store, txn, &at.1)?;
                if !turns.contains(&at.1) {
                    reread_in_txn(store, txn, &at.1)?;
                }
            }
            let batch: &[_] = if round.applied { &[] } else { &round.turns };
            for member in batch.iter().filter(|member| !turns.contains(*member)) {
                reread_in_txn(store, txn, member)?;
            }
            ROUND.delete(store, txn, &id)?;
        }
        if kept.is_empty() {
            GIVEN.delete(store, txn, turn)?;
        } else {
            let given = Given {
                rounds: kept,
                taken: None,
            };
            GIVEN.put(store, txn, turn, &given)?;
        }
    }
    Ok(())
}
