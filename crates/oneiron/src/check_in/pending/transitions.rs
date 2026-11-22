//! What holders and spenders do to a pending check-in row: answers,
//! extensions, objections, and spending, with the guards they share.

use super::*;

/// A holder's answer to a pending check-in, in `txn` at `now`. The person is
/// revalidated in `txn`; the answer lands only while the ask is open, before
/// `until`, before its delay window's end, before the current rung's wait
/// ends, from a person pinned on the current rung who `chain` says may still
/// answer (their live grant and own check-in, P22-SHAPE Q9), over the exact
/// effect digest. The first valid answer lands and every other holder reads
/// who gave it. The public answer verb is 2l.
///
/// # Errors
///
/// A dead or foreign proof; no such row; a final state; `until`, the delay
/// window's end or the rung's wait passed; a mismatched digest; a person not
/// pinned on the current rung, or one who may no longer answer; storage
/// errors.
pub(crate) fn answer_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: &AuthenticatedOwner,
    id: &EntityId,
    reply: HolderReply,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<PendingCheckIn> {
    let HolderReply {
        effect_digest,
        answer,
    } = reply;
    let by = person.revalidate_person_in_txn(vault, txn)?;
    let mut row = open_row_in_txn(&vault.store, txn, id, now)?;
    if row.effect_digest != effect_digest {
        return Err(refuse("the answer is over another effect"));
    }
    let rung = pinned_person_rung(&row, by, now)?;
    require_may_answer(vault, txn, &row, by, chain, now)?;
    row.state = PendingState::Answered {
        answer,
        by: Some(by),
        rung,
        at: now,
    };
    let fields = ReceiptFields::new(&row)
        .with("rung", rung.as_str().to_owned())
        .with("by", by.to_hex())
        .with("answer", answer.as_str().to_owned());
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Answered,
        Some(by),
        fields,
        now,
    )?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(row)
}

/// A holder's "give me until `until`" on the current rung, in `txn` at
/// `now`, receipted. It only lengthens the rung's wait, never past the
/// asker's `until` (P22-SHAPE Q5, Q6).
///
/// # Errors
///
/// A dead or foreign proof; no such row; a final state; `until`, the delay
/// window's end or the rung's wait passed; a person not pinned on the
/// current rung, or one who may no longer answer; an extension that does not
/// lengthen the wait or passes the asker's `until`; storage errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2l extends through it; until then only the test door does"
    )
)]
pub(crate) fn extend_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: &AuthenticatedOwner,
    id: &EntityId,
    until: u64,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<PendingCheckIn> {
    let by = person.revalidate_person_in_txn(vault, txn)?;
    let mut row = open_row_in_txn(&vault.store, txn, id, now)?;
    let rung = pinned_person_rung(&row, by, now)?;
    require_may_answer(vault, txn, &row, by, chain, now)?;
    if row.until.is_some_and(|cutoff| until > cutoff) {
        return Err(refuse("an extension may not pass the asker's until"));
    }
    let entry = row
        .rungs
        .last_mut()
        .ok_or(Error::InvariantViolation("an open check-in is on a rung"))?;
    if until <= entry.due_at() {
        return Err(refuse("an extension only lengthens the rung's wait"));
    }
    entry.extension = Some(Extension {
        until,
        by: Some(by),
        at: now,
    });
    let fields = ReceiptFields::new(&row)
        .with("rung", rung.as_str().to_owned())
        .with("by", by.to_hex())
        .with("due_at", until.to_string());
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Extended,
        Some(by),
        fields,
        now,
    )?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(row)
}

/// Keeps an objection to the row's delay window that canon's PR 4 producer
/// admitted, in `txn` at `now`. Who may object is that producer's check.
///
/// # Errors
///
/// No such row; a final state; no delay window, or one already ended;
/// storage errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "canon's PR 4 producer admits objections; until then only the test door does"
    )
)]
pub(crate) fn record_objection_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    by: EntityId,
    now: u64,
) -> Result<PendingCheckIn> {
    let mut row = open_row_in_txn(store, txn, id, now)?;
    let window = row
        .delay_window
        .as_mut()
        .filter(|window| now < window.ends_at)
        .ok_or_else(|| refuse("no open delay window"))?;
    window.objections.push(Objection {
        by: Some(by),
        at: now,
    });
    store_pending_in_txn(store, txn, &row)?;
    Ok(row)
}

/// The row `id` as [`consume_pending_check_in_in_txn`] finds it before it
/// spends it: asked for `effect_digest`, eligible, and not yet spent; with
/// its eligible basis.
fn spendable_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    effect_digest: &[u8; 32],
) -> Result<(PendingCheckIn, EligibleBasis)> {
    let row = PENDING.get(store, txn, id)?.ok_or(Error::EntityNotFound)?;
    if row.effect_digest != *effect_digest {
        return Err(refuse("the act is another effect than the one asked"));
    }
    let basis = row
        .eligible_basis()
        .ok_or_else(|| refuse("the check-in did not make the act eligible"))?;
    if row.consumed_at.is_some() {
        return Err(refuse("the act this check-in held already ran"));
    }
    Ok((row, basis))
}

/// Checks in `txn`, writing nothing, that [`consume_pending_check_in_in_txn`]
/// would spend `id` for `effect_digest`: for an act whose spend lands in a
/// later writer, so a row it could not spend refuses it before its first
/// write.
///
/// # Errors
///
/// As [`consume_pending_check_in_in_txn`].
pub(crate) fn check_pending_check_in_spendable_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    effect_digest: &[u8; 32],
) -> Result<()> {
    spendable_row_in_txn(store, txn, id, effect_digest).map(|_| ())
}

/// Spends the settled row `id` for the act it held, in the act's own `txn`
/// at `now` (Engine ruling P23-SHAPE Q2 = A): the commit that runs the
/// effect is the commit that marks the row used, so a replay or a second
/// worker finds it used, and an abort leaves it eligible. Only the exact
/// effect digest spends it, on an eligible basis
/// ([`PendingCheckIn::eligible_basis`]). Writes a `consumed` receipt naming
/// the basis. The membership doors spend it through `effect` (P2.4b); PR
/// 3's act gate spends it for the act verbs.
///
/// # Errors
///
/// No such row; another effect; a state that makes nothing eligible; a row
/// already used; storage errors.
pub(crate) fn consume_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    effect_digest: &[u8; 32],
    now: u64,
) -> Result<EligibleBasis> {
    let (mut row, basis) = spendable_row_in_txn(&vault.store, txn, id, effect_digest)?;
    row.consumed_at = Some(now);
    let fields = ReceiptFields::new(&row).with("basis", basis.as_str().to_owned());
    let asker = row.asker;
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Consumed,
        Some(asker),
        fields,
        now,
    )?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(basis)
}

/// The row `id`, open at `now`: not final, its `until` not passed and its
/// delay window not ended. From either instant on, only the tick
/// (`advance_pending_check_in_in_txn`) moves the row, in its order: let-go
/// at `until`, then the window's end (an objection holds the act, silence is
/// the proof). No answer, extension or objection lands there.
fn open_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    now: u64,
) -> Result<PendingCheckIn> {
    let row = PENDING.get(store, txn, id)?.ok_or(Error::EntityNotFound)?;
    if row.state != PendingState::Open {
        return Err(Error::ConcurrentWrite("the check-in is settled"));
    }
    if row.until.is_some_and(|until| now >= until) {
        return Err(refuse("the asker's until has passed: the ask let go"));
    }
    if row
        .delay_window
        .as_ref()
        .is_some_and(|window| now >= window.ends_at)
    {
        return Err(refuse(
            "the delay window has ended: its end settles the ask",
        ));
    }
    Ok(row)
}

/// The current rung, when `by` is a person pinned on it and its wait has
/// not ended at `now`. Past the last rung, while a delay window still runs,
/// the Owner rung's holders may still answer.
fn pinned_person_rung(row: &PendingCheckIn, by: EntityId, now: u64) -> Result<Rung> {
    let entry = row
        .current_rung()
        .ok_or(Error::InvariantViolation("an open check-in is on a rung"))?;
    if row.chain_exhausted_at.is_none() && now >= entry.due_at() {
        return Err(refuse("the rung's wait has ended"));
    }
    let pinned = entry
        .holders
        .iter()
        .any(|holder| holder.principal == by && holder.kind == HolderKind::Person);
    if !pinned {
        return Err(refuse("only a person pinned on the current rung answers"));
    }
    Ok(entry.rung)
}

/// Refuses a pinned person `by` whom `chain` no longer lets answer.
fn require_may_answer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &PendingCheckIn,
    by: EntityId,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<()> {
    let holder = RungHolder {
        principal: by,
        kind: HolderKind::Person,
    };
    if chain.may_answer(vault, txn, row, &holder, now)? {
        Ok(())
    } else {
        Err(refuse(
            "the holder's live grant or own check-in no longer admits this act",
        ))
    }
}
