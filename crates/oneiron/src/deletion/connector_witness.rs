//! A reply job participant's erase reaches the conversation rows its
//! exchange was witnessed into (FIX 10897).
//!
//! The witness lands the message a connector reply answers, and the
//! delivered reply, each as one TURN of one MESSAGE in the connector
//! conversation: the sender's words with `import.said_by`, and the agent's
//! answer. They are ordinary imported memory rows, so the reply job's own
//! erase (FIX 2405) never reached them. A hard erase of anyone the job
//! names soft-erases both, as the actor sweep erases a contribution pair's
//! copies: the MESSAGEs first, then each TURN that holds only erased
//! MESSAGEs. A legal hold keeps its row, logged, and with it the TURN that
//! holds it; the conversation and its other turns stay.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::secret_custody::EraseOwnerAct;
use crate::side_table::HexId;

use super::tombstone::ROW_DELETION_FENCE;

/// Soft-erases the witnessed exchange of each reply job naming `id`, in the
/// erase's transaction under `act`. An erase calls it before its provenance
/// pass clears those jobs' events, while they still name the rows.
///
/// # Errors
/// As [`erase_connector_witness_rows_in_txn`].
pub(super) fn erase_connector_witness_of_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<()> {
    let rows = crate::outbound::connector_witness_rows_in_txn(vault, wtxn, &BTreeSet::from([*id]))?;
    erase_connector_witness_rows_in_txn(vault, wtxn, &rows, act)
}

/// Soft-erases `rows`, the (MESSAGE, TURN) ids reply jobs' witnesses land
/// at ([`crate::outbound::connector_witness_rows_in_txn`]), in the erase's
/// transaction under `act`. A row that is absent, of another type or
/// already erased is left alone, so a replay or a restore's rerun erases
/// nothing twice.
///
/// # Errors
/// Storage errors, or a refusal the soft erase raises other than a hold.
pub(super) fn erase_connector_witness_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    rows: &BTreeSet<(EntityId, EntityId)>,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<()> {
    let mut had_vector = false;
    for (message, _) in rows {
        had_vector |= erase_witness_row_in_txn(vault, wtxn, message, ENTITY_TYPE_MESSAGE, act)?;
    }
    let turns: BTreeSet<EntityId> = rows.iter().map(|(_, turn)| *turn).collect();
    for turn in &turns {
        let messages = vault
            .store
            .port_edge_peers(wtxn, turn, EdgeDirection::In, crate::EdgeKind::PartOf)?
            .collect::<Result<Vec<EntityId>>>()?;
        let mut holds_live = false;
        for message in &messages {
            holds_live |= !row_erased_in_txn(vault, wtxn, message)?;
        }
        if !holds_live {
            had_vector |= erase_witness_row_in_txn(vault, wtxn, turn, ENTITY_TYPE_TURN, act)?;
        }
    }
    if had_vector {
        crate::store::vector_index::increment_vector_version(&vault.store, wtxn)?;
    }
    Ok(())
}

/// Whether `id`'s row is gone or already soft-erased here.
fn row_erased_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(vault.store.port_entity_record(txn, id)?.is_none()
        || ROW_DELETION_FENCE.contains(&vault.store, txn, &HexId(*id))?)
}

/// Soft-erases one witnessed row of `entity_type`, returning whether its
/// vectors went. A hold keeps it, logged, and the rest of the erase goes on.
fn erase_witness_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<bool> {
    let Some(record) = vault.store.port_entity_record(wtxn, id)? else {
        return Ok(false);
    };
    if record.entity_type != entity_type
        || ROW_DELETION_FENCE.contains(&vault.store, wtxn, &HexId(*id))?
    {
        return Ok(false);
    }
    if let Err(error) = vault.store.reject_legal_hold_in_txn(wtxn, id.as_bytes()) {
        if !crate::store::legal_hold::held_in_txn(&vault.store, wtxn, id.as_bytes())? {
            return Err(error);
        }
        tracing::warn!(
            row = %id.to_hex(),
            "connector witness erase: a hold keeps the witnessed row"
        );
        return Ok(false);
    }
    let (_, had_vector, _) = vault.soft_erase_active_store_in_txn(wtxn, id, true, act)?;
    Ok(had_vector)
}
