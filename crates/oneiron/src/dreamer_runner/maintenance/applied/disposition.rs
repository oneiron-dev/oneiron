//! The ledger row and receipt of one background identity disposition: an
//! abstention or a settle the identity recheck decided (FIX 11001 keeps the
//! held ask's rows on its receipt).
use super::{
    APPLIED, APPLY_REASON, AppliedRow, IDENTITY_PROVISIONAL_KIND, IDENTITY_SETTLE_KIND,
    MaintenanceInverse, MaintenanceTarget, decision, decision_context,
};
use crate::dreamer_runner::maintenance::identity::IdentityAsk;
use crate::{EntityId, Result, Vault, WriteActor};

/// Records one background identity abstention or settle in its transaction:
/// the inverse row under the ask (a settle's mention keys it as its ask
/// would) and the Dreamer's receipt naming it. A later abstention or settle
/// on the same key (its candidates or tags changed and it was decided again)
/// takes the row over; the ledger keeps every receipt.
#[expect(
    clippy::too_many_arguments,
    reason = "one disposition's ask key, facet, writer, inverse and rows"
)]
pub(in crate::dreamer_runner::maintenance) fn record_disposition_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: [u8; 32],
    facet: &str,
    actor: WriteActor,
    inverse: MaintenanceInverse,
    held: &IdentityAsk,
    settled: Option<EntityId>,
    now: u64,
) -> Result<()> {
    let target = MaintenanceTarget::IdentityAsk(ask);
    let kind = match inverse {
        MaintenanceInverse::IdentitySettle(_) => IDENTITY_SETTLE_KIND,
        _ => IDENTITY_PROVISIONAL_KIND,
    };
    let mut receipt = decision(actor, kind, APPLY_REASON, target, ask.to_vec(), now);
    receipt.context = decision_context::disposition(facet, held, settled);
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
    APPLIED.put(
        &vault.store,
        txn,
        &target,
        &AppliedRow {
            inverse,
            attempt: None,
            facet: facet.to_owned(),
            finding_revision: None,
            applied_at: now,
            receipt: receipt.decision_id,
            reverted: None,
        },
    )
}
