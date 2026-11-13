//! A durable code run's pads at its end (OF-548): each live run writes its
//! own pads under its run pointer, so the run's end seals exactly those.

use super::{PAD, PadKey, TAG_RUN, seal_pad_in_txn};
use crate::EntityId;

/// Seals, in the caller's write, every live pad durable code run `run`
/// wrote, and answers every pad it wrote in key order: those sealed now and
/// those its own seal closed earlier. One bounded read of the run's own
/// pointers: no other run's or session's pad is read or sealed.
pub(crate) fn seal_run_pads_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    run: EntityId,
) -> crate::Result<Vec<EntityId>> {
    let mut prefix = Vec::with_capacity(1 + 16);
    prefix.push(TAG_RUN);
    prefix.extend_from_slice(run.as_bytes());
    let pointers = PAD.scan_from(&vault.store, txn, &prefix)?;
    let mut pads = Vec::with_capacity(pointers.len());
    for (key, row) in pointers {
        let PadKey::Run { actor, session, .. } = key else {
            return Err(crate::Error::CorruptedIndex(
                "scratchpad pointer does not match its pad",
            ));
        };
        if row.actor != *actor.as_bytes() || row.session != session {
            return Err(crate::Error::CorruptedIndex(
                "scratchpad pointer does not match its pad",
            ));
        }
        let pad = EntityId::from_bytes(row.pad)?;
        seal_pad_in_txn(vault, txn, pad, actor)?;
        pads.push(pad);
    }
    Ok(pads)
}

impl crate::Vault {
    /// Seals every pad a completed canonical code run wrote
    /// ([`seal_run_pads_in_txn`]): the end of a run that has no attempt row,
    /// such as an MCP `execute_code` run. An attempt's run ends in its
    /// terminal write instead. A run not yet complete keeps its pads live.
    pub fn seal_code_run_scratchpads(&self, run: EntityId) -> crate::Result<()> {
        self.try_with_write_txn_grouped(|txn| {
            if !crate::engine_executor::code_run_complete_in_txn(self, &*txn, run)? {
                return Ok(());
            }
            seal_run_pads_in_txn(self, txn, run)?;
            Ok(())
        })
    }
}
