//! The settlement item (kind 3): an agent answers one open conflict its live
//! `derive` grant reaches, through the conflict settlement's own door, with
//! the guards a responder meets (a person alone closes user-stated truth;
//! the owner's revert and review hold stand, whichever actor asks). The
//! marker and every member are read under the actor's own read first: a
//! conflict it does not read answers as a row that is no open conflict. An
//! imported Keep stages and lands its proposal pending approval, with the
//! marker open (FIX 5754).

use std::cell::Cell;

use rmpv::Value;

use super::batch::{DerivedSettle, DerivedSettlement};
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::dreamer_consolidation::{
    ConflictSettlement, KeepAs, SettlementApplied, SettlementSettler, apply_settlement_in_txn,
    open_conflict_in_txn,
};
use crate::error::{Error, GateError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{EntityId, Vault};

/// The refusal of a settlement the conflict's own door refuses: the marker
/// is no open conflict the actor reads whole, the kept claim is no member,
/// or only a person may close what it would close.
pub const SETTLE_REFUSED: &str = "gate.deny.derive.settle_refused";

/// The refusal of a settlement the owner reverted, or whose review the owner
/// holds. The one hold an owner mints names the Dreamer, and it leaves the
/// subject's conflicts to the owner whichever actor asks.
pub const SETTLE_OWNER_HOLD: &str = "gate.deny.derive.settle_owner_hold";

/// The reason a landed settlement's receipt names.
const SETTLE_ALLOWED: &str = "gate.allow.derive.settle";

/// The provenance surface of a settlement's answer. An answer cites no
/// evidence: it answers an open marker, so the derivation floors that hold
/// a derived claim (`surface = vault.derive`, GATE-12) do not hold it, as
/// they hold no conflict answer of the Dreamer's.
const SETTLE_SURFACE: &str = "vault.derive.settle";

/// Stages `item`: the marker under the actor's own read, the derive verdict
/// over it, its members under that read, the owner's revert and hold, then
/// the settlement in a savepoint of `txn`. An imported Keep stages and
/// lands its proposal pending approval, leaving the marker open (FIX 5754).
///
/// # Errors
///
/// Storage errors, and any error the settlement raises other than its
/// refusal: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedSettle,
) -> Result<ItemOutcome> {
    let marker = context.resolve(&item.marker)?;
    let settlement = match &item.settlement {
        DerivedSettlement::Keep(kept) => ConflictSettlement::Keep(context.resolve(kept)?),
        DerivedSettlement::HoldBoth => ConflictSettlement::HoldBoth,
        DerivedSettlement::Dismiss => ConflictSettlement::Dismiss,
    };
    let actor = context.stamp.actor;
    // At every status the record verbs serve: a marker waits as a proposal
    // in its own review.
    let read =
        super::actor_read(vault, actor)?.with_claim_status(crate::ports::ClaimReadStatus::Recorded);
    if !reads_every_row(&read, txn, &[marker])? {
        return refuse(vault, txn, context, marker, &[SETTLE_REFUSED]);
    }
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Derive,
        Some(marker),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, marker, &[refusal.token()]),
    };
    let conflict = match open_conflict_in_txn(vault, txn, marker) {
        Ok(conflict) => conflict,
        Err(Error::EntityNotFound | Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return refuse(vault, txn, context, marker, &[SETTLE_REFUSED]);
        }
        Err(error) => return Err(error),
    };
    // A landed settlement closes members and answers their ids, so each is
    // one the actor reads.
    if !reads_every_row(&read, txn, &conflict.members)? {
        return refuse(vault, txn, context, marker, &[SETTLE_REFUSED]);
    }
    if conflict.reverted
        || crate::memory::dreamer_conflict_review_held_in(vault, txn, conflict.subject)?.is_some()
    {
        return refuse(vault, txn, context, marker, &[SETTLE_OWNER_HOLD]);
    }
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from(SETTLE_SURFACE)),
            (
                Value::from(super::DERIVE_BATCH_KEY),
                Value::from(context.batch.to_hex()),
            ),
            (Value::from("item"), Value::from(item.local.as_str())),
            (
                Value::from("openMarker"),
                Value::Binary(marker.as_bytes().to_vec()),
            ),
        ]))?,
        ClaimApprovalStatus::Auto,
    );
    let held = Cell::new(false);
    let mut refused = vec![SETTLE_REFUSED];
    // Hand queued work to this write's owner (FIX DERIVE-COMMIT-ITEM-SAVEPOINTS-DROP-POSTCOMMIT-WORK).
    let Some((applied, approval)) = crate::batch::savepoint_in_txn(vault, txn, |savepoint| {
        match apply_settlement_in_txn(
            vault,
            savepoint,
            &conflict,
            settlement,
            &envelope,
            Some(actor),
            SettlementSettler::Delegate,
            KeepAs::Auto(&held),
            context.now.saturating_mul(1_000),
        ) {
            Ok(SettlementApplied::Settled(settled)) => {
                Ok(Some((SettlementApplied::Settled(settled), None)))
            }
            Ok(SettlementApplied::ImportReviewPending(staged)) => {
                let approval = vault
                    .get_claim_in_txn(savepoint, &staged.staged)?
                    .ok_or(Error::InvalidClaimBody("the staged Keep is missing"))?
                    .approval;
                Ok(Some((
                    SettlementApplied::ImportReviewPending(staged),
                    Some(approval),
                )))
            }
            Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
                refused = reason_codes;
                Ok(None)
            }
            Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => Ok(None),
            Err(error) => Err(error),
        }
    })?
    else {
        return refuse(vault, txn, context, marker, &refused);
    };
    match applied {
        SettlementApplied::Settled(settled) => {
            let receipt = allowance_receipt_in_txn(
                vault,
                txn,
                context,
                Some(marker),
                &[SETTLE_ALLOWED.to_owned()],
                &allowance,
            )?;
            // The answer first: a revert reverts the settlement by it. The
            // marker, members and any newly landed winner follow, so a later
            // change to any of them leaves the whole settlement alone.
            let mut rows = vec![settled.resolved, marker];
            rows.extend(conflict.members.iter().copied());
            if let Some(winner) = settled.materialized
                && !rows.contains(&winner)
            {
                rows.push(winner);
            }
            Ok(ItemOutcome::Landed {
                rows,
                approval: None,
                receipt: Some(receipt),
            })
        }
        SettlementApplied::ImportReviewPending(staged) => {
            let receipt = allowance_receipt_in_txn(
                vault,
                txn,
                context,
                Some(marker),
                &[SETTLE_ALLOWED.to_owned()],
                &allowance,
            )?;
            // The proposal first: a revert retracts it without closing the
            // marker or changing any member (FIX 5754).
            Ok(ItemOutcome::Landed {
                rows: vec![staged.staged, marker],
                approval,
                receipt: Some(receipt),
            })
        }
    }
}

/// Whether `read` serves every one of `rows` in `txn`. A read whose
/// credential no longer stands serves no row.
fn reads_every_row(
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    rows: &[EntityId],
) -> Result<bool> {
    match read.get_entities_parts_in_txn(txn, rows) {
        Ok(served) => Ok(served.iter().all(Option::is_some)),
        Err(Error::InvalidClaimBody(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    marker: EntityId,
    reasons: &[&str],
) -> Result<ItemOutcome> {
    let reasons: Vec<String> = reasons.iter().map(|reason| (*reason).to_owned()).collect();
    let receipt = refusal_receipt_in_txn(vault, txn, context, Some(marker), &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
