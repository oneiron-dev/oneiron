//! Session-only release of reply occurrences. The rows stay in the overlay;
//! canonical custody and its retirement journal are never involved.

use super::replay_capsule::actor_gone_in_store;
use super::response_owners::{ResponseOwner, response_owner_in_txn};
use super::wait_delivery::canonical_store;
use crate::code_run::{CodeRunRawOutput, ResultOccurrence};
use crate::engine_executor::holds_reply_content;
use crate::side_table::RoutedDbs;
use crate::store::owned_body::{BODY, BODY_DIGEST};
use crate::{EntityId, Result};

/// Releases only these reply occurrences and their own marks. Every digest
/// remains queued until the session collector can retire its bytes safely.
pub(super) fn release_reply_outputs_in_txn(
    dbs: &RoutedDbs<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    outputs: &[CodeRunRawOutput],
) -> Result<()> {
    let RoutedDbs::Session(view) = dbs else {
        return Ok(());
    };
    let view = *view;
    for output in outputs
        .iter()
        .filter(|output| holds_reply_content(&output.path))
    {
        let occurrence = ResultOccurrence::owned(owner, &output.path)?;
        let marks = occurrence.mark_key(&output.handle);
        super::secret_lift::drop_code_run_result_marks_in_txn(view, txn, &marks)?;
        let key = (owner, occurrence.id());
        let Some(body) = BODY.get(view, txn, &key)? else {
            continue;
        };
        BODY.delete(view, txn, &key)?;
        if let Some(held) = body.state.held() {
            BODY_DIGEST.delete(view, txn, &(held.blake3, occurrence.id()))?;
            crate::provenance::body::queue_pruned_file_in_txn(view, txn, &held.blake3)?;
        }
    }
    Ok(())
}

/// A body published after its run's erase meets the same fence in its own
/// writer, even before a later replay record names the output.
pub(super) fn release_erased_output_in_txn(
    dbs: &RoutedDbs<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    output: &CodeRunRawOutput,
) -> Result<()> {
    let response = response_owner_in_txn(dbs, txn, &owner)?;
    if response.is_some_and(ResponseOwner::erased)
        || response
            .and_then(ResponseOwner::actor)
            .is_some_and(|actor| actor_gone_in_store(canonical_store(dbs), txn, &actor))
    {
        release_reply_outputs_in_txn(dbs, txn, owner, std::slice::from_ref(output))?;
    }
    Ok(())
}
