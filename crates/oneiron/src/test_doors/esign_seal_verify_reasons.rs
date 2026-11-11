//! Door for `tests/esign_seal_verify_reasons.rs`, declared inside e-sign so
//! it can reach the ledger writer without changing that writer's visibility.
//! Reached as `oneiron::blob_artifact::esign::esign_seal_verify_reasons`, not
//! re-exported by `test_doors`; compiled only under `oneiron_test_support`.

use crate::blob_artifact::esign::{EsignAuditActor, EsignEvent, EsignState};
use crate::{EntityId, Result, Vault};

/// Appends an event in the same write transaction as the lib test helper.
///
/// # Errors
/// The ledger's or the write transaction's.
pub fn append_event(
    vault: &Vault,
    id: EntityId,
    event: EsignEvent,
    actor: EsignAuditActor,
    at: u64,
) -> Result<EsignState> {
    vault.with_write_txn(|txn| super::ledger::append(vault, txn, id, event, actor, at))
}
