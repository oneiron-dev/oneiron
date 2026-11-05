//! A sync write's text holding a hit no rule places (FIX 11792). The sync
//! scan admits the text and records the hit as the sweep records an
//! unplaceable live hit: one value-free proposal on the record's own row,
//! with the needs-you notice when it files. The write that files it is no
//! run's walk, so the filer is a clock id, as the typed-body frontier read's
//! is; a row already holding an open proposal, or one the owner closed,
//! files nothing and raises no notice.

use heed::RwTxn;

use super::{LiftCause, LiftFamily, file_in_txn, notice};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Files the owner's proposal for `entity`'s sync text holding a hit no rule
/// places, in the caller's writer: the sweep's `unplaceable` proposal on the
/// record's own row, value-free, and the needs-you notice when it files anew.
pub(crate) fn propose_sync_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    reason: &'static str,
) -> Result<()> {
    // The write that filed it: no run's walk did.
    let filer = vault.store.clock.entity_id()?;
    if file_in_txn(
        vault,
        txn,
        filer,
        LiftFamily::Records,
        entity.as_bytes(),
        LiftCause::Unplaceable,
        reason,
    )? {
        let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        notice::after_run_in_txn(vault, txn, filer, 1, at)?;
    }
    Ok(())
}
