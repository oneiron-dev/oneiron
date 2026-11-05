//! Exact-pad ownership at a durable code run's close.

use super::{Memory, MemoryResult, PAD, PadKey};
use crate::EntityId;

/// A successful foreign or unbound append makes the label shared. Keep its
/// existing manual lifetime; never rebind it to whichever run writes last.
pub(super) fn observe_append_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    session: &str,
    pad: EntityId,
) -> MemoryResult<()> {
    let key = PadKey::Session {
        actor: memory.actor(),
        session: session.to_owned(),
    };
    let store = &memory.vault().store;
    let Some(mut row) = PAD.get(store, txn, &key)? else {
        return Ok(());
    };
    if row.pad == *pad.as_bytes()
        && row.close_run.is_some()
        && row.close_run != memory.bound_code_run().map(|run| *run.as_bytes())
    {
        row.close_run = None;
        PAD.put(store, txn, &key, &row)?;
    }
    Ok(())
}

impl crate::Vault {
    /// Seals only the pads still owned by this completed canonical code run.
    /// Shared/manual pads, other runs and resumable runs keep their lifetime.
    pub fn seal_code_run_scratchpads(&self, run: EntityId) -> crate::Result<()> {
        self.try_with_write_txn_grouped(|txn| {
            if !crate::engine_executor::code_run_complete_in_txn(self, &*txn, run)? {
                return Ok(());
            }
            for (key, mut row) in PAD.scan_from(&self.store, txn, &[super::TAG_SESSION])? {
                if row.close_run != Some(*run.as_bytes()) {
                    continue;
                }
                let PadKey::Session { actor, session } = &key else {
                    continue;
                };
                if row.actor != *actor.as_bytes() || row.session != *session {
                    return Err(crate::Error::CorruptedIndex(
                        "scratchpad pointer does not match its pad",
                    ));
                }
                let pad = EntityId::from_bytes(row.pad)?;
                if super::seal_session_pad_in_txn(self, txn, *actor, session)? == Some(pad) {
                    row.close_run = None;
                    PAD.put(&self.store, txn, &key, &row)?;
                }
            }
            Ok(())
        })
    }
}
