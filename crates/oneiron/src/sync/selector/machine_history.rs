//! Complete authenticated machine-claim history required beside a selected row.

use crate::error::Result;
use crate::{EntityId, Vault};

/// The rows a machine CLAIM's authenticated history needs beside it in an
/// export, read from stored truth: its birth event, each transition event of
/// the chain's union and every handoff of its chain. `None` when that history
/// does not resolve whole (a missing or malformed row, a cycle in the chain).
pub(super) fn machine_history_controls(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<Vec<EntityId>>> {
    // The rows' one chain reader walks every packet back to genesis, so the
    // events and handoffs below are the whole history, not the tip's delta.
    let Ok(rows) = crate::claim::history_projection::machine_history_rows(&vault.store, rtxn, id)
    else {
        return Ok(None);
    };
    let mut required = vec![rows.birth.event_id()?];
    for event in &rows.events {
        required.push(crate::claim::transition::machine_claim_transition_event_id(
            event,
        )?);
    }
    for handoff in &rows.chain {
        let hash = handoff
            .content_hash()
            .map_err(|_| crate::Error::InvalidClaimBody("machine handoff hash"))?;
        required.push(EntityId::from_bytes(
            hash[..16]
                .try_into()
                .map_err(|_| crate::Error::InvalidClaimBody("machine handoff id"))?,
        )?);
    }
    Ok(Some(required))
}
