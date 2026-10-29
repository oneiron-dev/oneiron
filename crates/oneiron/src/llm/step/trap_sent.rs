//! Device-local presence index for traps whose current head is `Sent`.

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
