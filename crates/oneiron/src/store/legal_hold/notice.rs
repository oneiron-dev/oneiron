//! What a hold's refusals tell the owner (WILL-PLAN L01 rows 01 and 03). A
//! standing host order the owner may see names its bound, the law, and what
//! self-hosting changes. A customer hold refuses as it always has, with no
//! hosted-law bound. While only secret orders hold, nothing is said. A
//! record a hosted privacy erasure kept serves only the purpose of the holds
//! that keep it, for as long as one stands (C6, FIX 8849).

use heed::RoTxn;

use super::{USE_LIMITS, holds_on_in_txn};
use crate::deletion::{
    LEGAL_HOLD_DEFERRAL, LEGAL_HOLD_REFUSAL, LEGAL_HOLD_SELF_HOSTED_NOTE, LegalHold, LegalHoldKind,
    LegalHoldTarget,
};
use crate::entity_id::EntityId;
use crate::error::{
    Error, LegalHoldBound, LegalHoldBoundKind, LegalHoldNotice, LegalHoldState, Result,
};
use crate::side_table::SideTableDbs;
use crate::store::Store;

/// The notice naming the law bound of the standing host orders in `holds`
/// the owner may see at `now`: the one that ends last, since it keeps the
/// bytes longest. `None` when there is none: only customer holds, or only
/// orders whose silence runs.
pub(crate) fn law_notice(
    holds: &[LegalHold],
    now: u64,
    state: LegalHoldState,
) -> Option<LegalHoldNotice> {
    let order = holds
        .iter()
        .filter(|hold| {
            hold.kind == LegalHoldKind::HostOrder && hold.stands() && hold.owner_may_see(now)
        })
        .max_by_key(|hold| hold.ends_at)?;
    Some(LegalHoldNotice {
        state,
        bound: LegalHoldBound {
            kind: LegalHoldBoundKind::Law,
            order_ref: order.matter_ref.clone(),
            legal_basis_ref: order.legal_basis_ref.clone(),
            jurisdiction: order.jurisdiction.clone(),
            issuing_authority_ref: order.issuing_authority_ref.clone(),
            ends_at: order.ends_at,
        },
        works_self_hosted: true,
        self_hosted_note: LEGAL_HOLD_SELF_HOSTED_NOTE.to_owned(),
    })
}

/// The refusal a destroying path meets on what the standing `holds` hold at
/// `now`: an order the owner may see is `retained_for_law` with its bound;
/// otherwise the named refusal, or the deferral when only secret orders
/// hold, which says nothing of them.
pub(super) fn held_refusal(holds: &[LegalHold], now: u64) -> Error {
    if let Some(notice) = law_notice(holds, now, LegalHoldState::RetainedForLaw) {
        return Error::LegalHold(Box::new(notice));
    }
    let refusal = if holds.iter().all(|hold| hold.secret_at(now)) {
        LEGAL_HOLD_DEFERRAL
    } else {
        LEGAL_HOLD_REFUSAL
    };
    Error::InvalidConfig(refusal.to_owned())
}

/// Whether `hold` keeps a record a hosted privacy erasure kept for its own
/// legal purpose only (C6, FIX 8849): every standing hold, a customer hold
/// or a host order, whether or not the order's own terms forbid use. Those
/// terms stay the order's data, never what makes the limit.
pub(super) fn restricts_use(hold: &LegalHold) -> bool {
    hold.stands()
}

/// The standing holds on `record` that keep it for their purpose only: its
/// use limit lasts until the last of them lifts, narrows or lapses.
pub(super) fn retaining_holds_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Vec<LegalHold>> {
    Ok(
        holds_on_in_txn(dbs, txn, &LegalHoldTarget::Record(*record))?
            .into_iter()
            .filter(restricts_use)
            .collect(),
    )
}

impl Store {
    /// The refusal a named write of `record` meets while it is kept from use
    /// (C6, WILL-PLAN L01 row 03): `use_restricted` with the bound of a host
    /// order the owner may see, or absence while only customer holds or
    /// orders whose silence runs keep it. `None` once no standing hold keeps
    /// it, whatever its marker says.
    pub(crate) fn use_restricted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &EntityId,
    ) -> Result<Option<Error>> {
        if !USE_LIMITS.contains(self, txn, record)? {
            return Ok(None);
        }
        let holds = retaining_holds_in_txn(self, txn, record)?;
        if holds.is_empty() {
            return Ok(None);
        }
        let now = self.clock.now_recorded_at();
        let refusal = match law_notice(&holds, now, LegalHoldState::UseRestricted) {
            Some(notice) => Error::LegalHold(Box::new(notice)),
            None => Error::EntityNotFound,
        };
        Ok(Some(refusal))
    }
}
