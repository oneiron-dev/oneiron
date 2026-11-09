//! The settlement item (kind 3): an agent answers one open conflict its live
//! `derive` grant reaches, through the conflict settlement's own door, with
//! the guards a responder meets (a person alone closes user-stated truth;
//! the owner's revert and review hold stand).

use std::cell::Cell;

use rmpv::Value;

use super::batch::{DerivedSettle, DerivedSettlement};
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::dreamer_consolidation::{
    ConflictSettlement, KeepAs, SettlementApplied, apply_settlement_in_txn, open_conflict_in_txn,
};
use crate::error::{Error, GateError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{EntityId, Vault};

/// The refusal of a settlement the conflict's own door refuses: the marker
/// is no open conflict, the kept claim is no member, or only a person may
/// close what it would close.
pub const SETTLE_REFUSED: &str = "gate.deny.derive.settle_refused";

/// The refusal of a settlement the owner reverted, or whose review the owner
/// holds.
pub const SETTLE_OWNER_HOLD: &str = "gate.deny.derive.settle_owner_hold";

/// The refusal of a Keep that waits in its import's review instead of
/// settling.
pub const SETTLE_IMPORT_REVIEW: &str = "gate.pending.derive.settle_import_review";

/// The reason a landed settlement's receipt names.
const SETTLE_ALLOWED: &str = "gate.allow.derive.settle";

/// Stages `item`: the derive verdict over the marker, the owner's revert and
/// hold, then the settlement in a savepoint of `txn`.
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
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return refuse(vault, txn, context, marker, &[SETTLE_REFUSED]);
        }
        Err(error) => return Err(error),
    };
    if conflict.reverted
        || crate::memory::conflict_review_held_in(vault, txn, actor, conflict.subject)?.is_some()
    {
        return refuse(vault, txn, context, marker, &[SETTLE_OWNER_HOLD]);
    }
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from(super::DERIVE_SURFACE)),
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
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let applied = apply_settlement_in_txn(
        vault,
        &mut savepoint,
        &conflict,
        settlement,
        &envelope,
        Some(actor),
        false,
        KeepAs::Auto(&held),
        context.now.saturating_mul(1_000),
    );
    match applied {
        Ok(SettlementApplied::Settled(_)) => {
            savepoint.commit()?;
            let receipt = allowance_receipt_in_txn(
                vault,
                txn,
                context,
                Some(marker),
                &[SETTLE_ALLOWED.to_owned()],
                &allowance,
            )?;
            let mut rows = vec![marker];
            rows.extend(conflict.members.iter().copied());
            Ok(ItemOutcome::Landed {
                rows,
                approval: None,
                receipt: Some(receipt),
            })
        }
        Ok(SettlementApplied::ImportReviewPending(_)) => {
            savepoint.abort();
            refuse(vault, txn, context, marker, &[SETTLE_IMPORT_REVIEW])
        }
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            savepoint.abort();
            refuse(vault, txn, context, marker, &reason_codes)
        }
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            savepoint.abort();
            refuse(vault, txn, context, marker, &[SETTLE_REFUSED])
        }
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
