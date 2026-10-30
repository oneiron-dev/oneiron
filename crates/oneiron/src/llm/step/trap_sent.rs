//! Device-local presence index for traps whose current head is `Sent`.

use super::types::DreamerTrapState;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

const TRAP_SENT: SideTable<EntityId, (), Named> = SideTable::new(&side_table::DREAMER_TRAP_SENT);

pub(super) fn mark_sent_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    anchor: &EntityId,
) -> Result<()> {
    TRAP_SENT.put(&vault.store, wtxn, anchor, &())
}

pub(super) fn unmark_sent_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    anchor: &EntityId,
) -> Result<()> {
    TRAP_SENT.delete(&vault.store, wtxn, anchor)?;
    Ok(())
}

pub(super) fn unmark_sent(vault: &Vault, anchor: &EntityId) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| unmark_sent_in_txn(vault, wtxn, anchor))
}

pub(super) fn sent_anchors(vault: &Vault) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    TRAP_SENT.scan_keys(&vault.store, &rtxn, &[])
}

/// Heals pre-index rows and drift during boot or provider recovery: every
/// attempt-scoped binding whose head is Sent gains its missing marker in the
/// same write transaction. Step-only waits never enter the attempt sweep.
/// This rare full scan is not a migration step or part of a pump pass.
pub fn heal_sent_markers(vault: &Vault) -> Result<usize> {
    vault.with_write_txn_grouped(|wtxn| {
        let mut healed = 0;
        for (anchor, binding) in super::trap_binding::trap_binding_rows_in_txn(vault, wtxn)? {
            if binding.park_owner != super::trap::trap_park_owner(&anchor) {
                continue;
            }
            let Ok((_, head)) = super::trap::trap_head_in_txn(vault, wtxn, &anchor) else {
                continue;
            };
            if head.state != DreamerTrapState::Sent
                || TRAP_SENT.contains(&vault.store, wtxn, &anchor)?
            {
                continue;
            }
            mark_sent_in_txn(vault, wtxn, &anchor)?;
            healed += 1;
        }
        Ok(healed)
    })
}
