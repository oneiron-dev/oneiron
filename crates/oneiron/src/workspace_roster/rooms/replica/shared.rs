//! Replicated room join, offer and response merging.
//! Entry: `merge_replicated_shared_row_in_txn`.
//! Carrier and refusal types stay in `replica`.

use super::*;

/// Merges a join receipt or an offer card another machine of this vault
/// carried (FIX 1794), as room turn rows merge: one this vault lacks is
/// written as carried, and one it holds takes the carried copy by
/// [`merged_join`] or [`merged_offer`], or quarantines, logged and left
/// out. Where one voter's two ballots differ the later stamp stands. The
/// Ready and current-card indexes are rebuilt from what merged; nothing is
/// decided again, and no seat, companion, participation, acceptance or
/// diary effect runs. Returns what the merge did, whether the carried copy
/// now holds everything this vault's does, and the other card of its agent
/// there that the merge replaced (FIX 3322), whose window copy lacks that.
pub(crate) fn merge_replicated_shared_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RoomSideRow,
) -> Result<(SideMerge, bool, Option<String>)> {
    let Some((room, branch)) = row.place().filter(|_| row.well_formed()) else {
        return Ok((SideMerge::Refused(TurnMergeRefusal::InvalidIds), true, None));
    };
    if let Some(refusal) = side_refusal_in(vault, txn, room, branch)? {
        return Ok((SideMerge::Refused(refusal), true, None));
    }
    merge_shared_in_txn(vault, txn, row)
}

/// [`merge_replicated_shared_row_in_txn`] once the row's place is admitted.
pub(super) fn merge_shared_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RoomSideRow,
) -> Result<(SideMerge, bool, Option<String>)> {
    let store = &vault.store;
    // FIX 4227, 4228: both copies as this vault knows who they name, each
    // in its history form where it names an erased party by id.
    let (carried, held, changed) = match carrier_erase::shared_here(vault, txn, row)? {
        carrier_erase::SharedHere::Live {
            carried,
            held,
            changed,
        } => (carried, held, changed),
        carrier_erase::SharedHere::Settled(merge) => return Ok((merge, true, None)),
    };
    // The window's copy is judged as this vault knows it: a name only the
    // export scrub can take out of it is no part it lacks.
    let merged = match held {
        None => carried.clone(),
        Some(held) => match merged_shared_row(&carried, &held) {
            Ok(merged) if merged == held && !changed => {
                return Ok((SideMerge::Held, merged == carried, None));
            }
            Ok(merged) => merged,
            Err(refusal) => return Ok((SideMerge::Refused(refusal), true, None)),
        },
    };
    let mut replaced = None;
    match &merged {
        RoomSideRow::Join { receipt } => {
            JOINS.put(store, txn, &receipt.join_ref, receipt)?;
            index_ready_in_txn(vault, txn, receipt)?;
        }
        RoomSideRow::Offer { offer } => {
            OFFERS.put(store, txn, &offer.card.offer_id, offer)?;
            replaced = index_current_offer_in_txn(vault, txn, offer)?;
        }
        _ => {}
    }
    // FIX 3322: a carried card that lost currency is replaced here, which
    // the window's copy lacks; another card it displaced is handed back.
    let own = row.merged_place().map(|(_, reference)| reference);
    let holds = merged == carried && replaced.as_deref() != own;
    Ok((
        SideMerge::Written,
        holds,
        replaced.filter(|id| Some(id.as_str()) != own),
    ))
}

/// The window's copy `theirs` of a join or offer card merged with this
/// vault's copy `ours` (FIX 1794), the same on every machine whichever
/// arrived first. The error names why the two quarantine.
pub(crate) fn merged_shared_row(
    theirs: &RoomSideRow,
    ours: &RoomSideRow,
) -> std::result::Result<RoomSideRow, TurnMergeRefusal> {
    match (theirs, ours) {
        (RoomSideRow::Join { receipt: theirs }, RoomSideRow::Join { receipt: ours }) => {
            merged_join(ours, theirs).map(|receipt| RoomSideRow::Join { receipt })
        }
        (RoomSideRow::Offer { offer: theirs }, RoomSideRow::Offer { offer: ours }) => {
            merged_offer(ours, theirs).map(|offer| RoomSideRow::Offer { offer })
        }
        _ => Err(TurnMergeRefusal::FixedFieldsConflict),
    }
}

/// Two copies of one join receipt as one (FIX 1794), as L09 ruled. The
/// filing (request, digest and history) must match, or the receipt
/// quarantines. Answers union by their ref and keep the fold's order, by
/// time and then ref; one ref with two answers quarantines. A settled copy
/// wins over a held one, and two settled copies that decide otherwise
/// quarantine. Of two settled copies the first to settle stands, and of two
/// held ones the latest decision; their encoding breaks a tie.
pub(super) fn merged_join(
    ours: &JoinReceipt,
    theirs: &JoinReceipt,
) -> std::result::Result<JoinReceipt, TurnMergeRefusal> {
    if ours.join_ref != theirs.join_ref
        || ours.intent_digest != theirs.intent_digest
        || ours.request != theirs.request
        || ours.history != theirs.history
    {
        return Err(TurnMergeRefusal::FixedFieldsConflict);
    }
    if ours.is_settled() && theirs.is_settled() && ours.decision != theirs.decision {
        return Err(TurnMergeRefusal::DecisionConflict);
    }
    let mut answers = ours.answers.clone();
    for answer in &theirs.answers {
        // Who an answer names settles by the carrier rule (FIX 4227).
        match answers
            .iter_mut()
            .find(|held| held.answer_ref == answer.answer_ref)
        {
            Some(held) => {
                *held = carrier_erase::answer_erased_wins(held, answer)
                    .ok_or(TurnMergeRefusal::FixedFieldsConflict)?;
            }
            None => answers.push(answer.clone()),
        }
    }
    answers.sort_by(|a, b| (a.at, &a.answer_ref).cmp(&(b.at, &b.answer_ref)));
    let order = |receipt: &JoinReceipt| {
        let settled = receipt.is_settled();
        let decided = if settled {
            u64::MAX - receipt.decided_at
        } else {
            receipt.decided_at
        };
        let rest = JoinReceipt {
            answers: Vec::new(),
            ..receipt.clone()
        };
        (
            settled,
            decided,
            serde_json::to_vec(&rest).unwrap_or_default(),
        )
    };
    let (mut merged, other) = if order(ours) >= order(theirs) {
        (ours.clone(), theirs)
    } else {
        (theirs.clone(), ours)
    };
    merged.answers = answers;
    carrier_erase::join_erased_with(&mut merged, other);
    Ok(merged)
}

/// Two copies of one offer card as one (FIX 1794), as L09 ruled. The card's
/// birth must match, or it quarantines. An answered card, or one whose
/// acceptance landed, wins over one without; two that differ quarantine.
/// Otherwise the later reopening wins, and within one a settled card wins
/// over an open one; their encoding breaks a tie. Ballots of the latest
/// reopening union per voter, and a lower reopening's are dropped; of one
/// voter's two ballots the later stamp stands ([`ROOM_OFFER_VOTE_ORDER`]),
/// whichever copy carried it (FIX 3323). The latest engagement stands.
pub(super) fn merged_offer(
    ours: &StoredOffer,
    theirs: &StoredOffer,
) -> std::result::Result<StoredOffer, TurnMergeRefusal> {
    let (card, other) = (&ours.card, &theirs.card);
    if card.offer_id != other.offer_id
        || card.room != other.room
        || card.branch != other.branch
        || card.agent != other.agent
        || card.what != other.what
        || card.artifact_ref != other.artifact_ref
        || card.lease_cap != other.lease_cap
        || card.payer != other.payer
        || card.spend_scope != other.spend_scope
        || card.join_ref != other.join_ref
        || card.created_at != other.created_at
        || ours.draft_digest != theirs.draft_digest
    {
        return Err(TurnMergeRefusal::FixedFieldsConflict);
    }
    // Who minted and answered the card settles by the carrier rule (FIX 4227).
    let minted_by = crate::deletion::carrier_actor_merged(
        ours.minted_by,
        theirs.minted_by,
        crate::workspace_roster::RosterActor::Erased,
    )
    .ok_or(TurnMergeRefusal::FixedFieldsConflict)?;
    let landed = |offer: &StoredOffer| {
        offer.answer.is_some()
            || matches!(
                offer.card.state,
                OfferState::Joined { .. } | OfferState::NotNow { .. }
            )
    };
    let answer = carrier_erase::offer_answer_erased_wins(&ours.answer, &theirs.answer);
    if landed(ours) && landed(theirs) && (answer.is_none() || ours.card.state != theirs.card.state)
    {
        return Err(TurnMergeRefusal::DecisionConflict);
    }
    let order = |offer: &StoredOffer| {
        (
            landed(offer),
            offer.reopen_epoch,
            !matches!(offer.card.state, OfferState::Open { .. }),
            serde_json::to_vec(&(&offer.card.state, offer.card.until, &offer.answer))
                .unwrap_or_default(),
        )
    };
    let mut merged = if order(ours) >= order(theirs) {
        ours.clone()
    } else {
        theirs.clone()
    };
    merged.minted_by = minted_by;
    if let Some(answer) = answer.filter(|_| landed(ours) && landed(theirs)) {
        merged.answer = answer;
    }
    merged.reopen_epoch = ours.reopen_epoch.max(theirs.reopen_epoch);
    merged.card.last_engaged_at = ours.card.last_engaged_at.max(theirs.card.last_engaged_at);
    merged.votes = BTreeMap::new();
    for offer in [ours, theirs] {
        if offer.reopen_epoch != merged.reopen_epoch {
            continue;
        }
        for (voter, ballot) in &offer.votes {
            let stands = match merged.votes.get(voter) {
                None => false,
                Some(held) if held == ballot => true,
                Some(held) if ROOM_OFFER_VOTE_ORDER(held) == ROOM_OFFER_VOTE_ORDER(ballot) => {
                    return Err(ROOM_OFFER_VOTE_EQUAL_STAMP);
                }
                Some(held) => ROOM_OFFER_VOTE_ORDER(held) > ROOM_OFFER_VOTE_ORDER(ballot),
            };
            if !stands {
                merged.votes.insert(*voter, *ballot);
            }
        }
    }
    Ok(merged)
}

/// The stamp one voter's two ballots on a card settle by (FIX 3323; a call,
/// canon is silent): the later revision wins, and of two cast at one
/// revision on two machines at once, the greater client id. No wall time
/// orders them.
pub(super) const ROOM_OFFER_VOTE_ORDER: fn(&OfferBallot) -> (u64, u64) =
    |ballot: &OfferBallot| (ballot.revision, ballot.client_id);

/// What one voter's two ballots that differ under one stamp do (FIX 3323; a
/// call, canon is silent): no machine casts two at one stamp, so the two
/// copies quarantine, as two answers do.
pub(super) const ROOM_OFFER_VOTE_EQUAL_STAMP: TurnMergeRefusal = TurnMergeRefusal::DecisionConflict;

/// Points the Ready index at `receipt`, a merged copy, when it is the latest
/// Ready receipt for its subject in its room or thread (FIX 1794): the
/// latest decision stands, and the greater join ref breaks a tie. The index
/// is never carried, and the proof still decides the receipt again against
/// live facts.
pub(super) fn index_ready_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &JoinReceipt,
) -> Result<()> {
    if receipt.decision != JoinDecision::Ready {
        return Ok(());
    }
    let store = &vault.store;
    let request = &receipt.request;
    let key = ready_key(request.room, &request.subject, request.branch);
    if let Some(standing) = READY.get_lenient(store, txn, &key)? {
        if standing == receipt.join_ref {
            return Ok(());
        }
        if let Some(standing) = JOINS.get_lenient(store, txn, &standing)?
            && standing.decision == JoinDecision::Ready
            && (standing.decided_at, &standing.join_ref) > (receipt.decided_at, &receipt.join_ref)
        {
            return Ok(());
        }
    }
    READY.put(store, txn, &key, &receipt.join_ref)
}

/// Points the current-card index at `offer`, a merged copy, when it is the
/// latest open or current mint for its agent in its room or thread (FIX
/// 1794): the latest `created_at` stands, and the greater offer id breaks a
/// tie. A replaced card never becomes current, and the index is never
/// carried. Of the two mints the one that loses is replaced while it is
/// open, as a local mint replaces the card it follows, in whichever order
/// the two arrived (FIX 3322); an answered or aged-out card keeps its
/// state. Returns the id of the card it replaced.
pub(super) fn index_current_offer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    offer: &StoredOffer,
) -> Result<Option<String>> {
    let card = &offer.card;
    if matches!(card.state, OfferState::Superseded { .. }) {
        return Ok(None);
    }
    let store = &vault.store;
    let key = current_key(card.room, card.branch, card.agent);
    let mut replaced = None;
    if let Some(standing) = OFFER_CURRENT.get_lenient(store, txn, &key)? {
        if standing == card.offer_id {
            return Ok(None);
        }
        if let Some(standing) = OFFERS.get_lenient(store, txn, &standing)?
            && !matches!(standing.card.state, OfferState::Superseded { .. })
        {
            if (standing.card.created_at, &standing.card.offer_id)
                > (card.created_at, &card.offer_id)
            {
                return supersede_open_in_txn(vault, txn, offer.clone(), &standing.card.offer_id);
            }
            replaced = supersede_open_in_txn(vault, txn, standing, &card.offer_id)?;
        }
    }
    OFFER_CURRENT.put(store, txn, &key, &card.offer_id)?;
    Ok(replaced)
}

/// Marks `offer` replaced by card `by` while it is open (FIX 3322), as a
/// local mint marks the card it follows. Returns its id when it did.
pub(super) fn supersede_open_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mut offer: StoredOffer,
    by: &str,
) -> Result<Option<String>> {
    if !matches!(offer.card.state, OfferState::Open { .. }) {
        return Ok(None);
    }
    offer.card.state = OfferState::Superseded { by: by.to_owned() };
    OFFERS.put(&vault.store, txn, &offer.card.offer_id, &offer)?;
    Ok(Some(offer.card.offer_id))
}

/// The order two payloads under one fact key settle by: the earlier
/// `(at, cause)` stands, and the receipt it stood on breaks a tie.
pub(super) fn fact_order(fact: &participation::Fact) -> (u64, Vec<u8>, Option<String>) {
    (
        fact.at,
        serde_json::to_vec(&fact.cause).unwrap_or_default(),
        fact.join_ref.clone(),
    )
}

/// Settles which turn answers claimed turn `parent` (FIX 1794), from the
/// response this vault holds and each carried one: the response whose
/// speaker holds the turn's claim stands, and among those, or when none
/// does, the earliest `(at, response)`. A response that loses keeps its
/// TURN, which was spoken; it loses only the slot, and is logged.
pub(crate) fn merge_replicated_responses_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: EntityId,
    carried: &[RoomSideRow],
) -> Result<SideMerge> {
    let store = &vault.store;
    let parent_room = TURNS
        .get_lenient(store, txn, &parent)?
        .map(|turn| turn.room_id);
    let mut candidates: Vec<(EntityId, Option<EntityId>, u64)> = Vec::new();
    let mut refused = None;
    for row in carried {
        let RoomSideRow::Response {
            room,
            parent: answered,
            response,
            actor,
            at,
        } = row
        else {
            continue;
        };
        if *answered != parent
            || parent_room
                .as_ref()
                .is_some_and(|held| *held != room.to_hex())
        {
            refused = Some(TurnMergeRefusal::FixedFieldsConflict);
            continue;
        }
        if let Some(refusal) = side_refusal_in(vault, txn, *room, None)? {
            refused = Some(refusal);
            continue;
        }
        if !candidates.iter().any(|(id, ..)| id == response) {
            candidates.push((*response, Some(*actor), *at));
        }
    }
    if candidates.is_empty() {
        return Ok(refused.map_or(SideMerge::Held, SideMerge::Refused));
    }
    let held = RESPONSE.get_lenient(store, txn, &parent)?;
    if let Some(held) = held
        && !candidates.iter().any(|(id, ..)| *id == held)
    {
        let spoken = TURNS.get_lenient(store, txn, &held)?;
        candidates.push((
            held,
            spoken.as_ref().and_then(|turn| named(&turn.actor)),
            spoken.map_or(u64::MAX, |turn| turn.at),
        ));
    }
    let claimant = CLAIMS
        .get_lenient(store, txn, &parent)?
        .and_then(|claim| named(&claim.actor));
    let Some(&(winner, ..)) = candidates.iter().min_by_key(|(response, actor, at)| {
        (claimant.is_some() && *actor != claimant, *at, *response)
    }) else {
        return Ok(SideMerge::Held);
    };
    if held != Some(winner) {
        RESPONSE.put(store, txn, &parent, &winner)?;
    }
    Ok(if candidates.len() > 1 {
        SideMerge::Conflict
    } else if held == Some(winner) {
        SideMerge::Held
    } else {
        SideMerge::Written
    })
}
