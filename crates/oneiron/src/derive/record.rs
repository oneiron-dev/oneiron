//! The batch record: what one derivation commit did, item by item.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// One derivation batch as it committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationBatchRecord {
    /// The committing actor.
    pub actor: EntityId,
    /// Its actor class, as the gate names it.
    pub actor_class: String,
    /// The run the batch belongs to.
    pub run: Option<String>,
    /// When it committed, Unix seconds (the write's recorded clock).
    pub committed_at: u64,
    /// Each item, in batch order.
    pub items: Vec<ItemRecord>,
}

/// One item of a committed batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    /// Its name inside the batch.
    pub local: String,
    /// Its kind (`claim`, ...).
    pub kind: String,
    /// Whether it landed.
    pub landed: bool,
    /// The rows it landed: empty when refused.
    pub rows: Vec<EntityId>,
    /// The approval a landed claim reached (`auto`, `proposed`), when the
    /// item is a claim.
    pub approval: Option<String>,
    /// The refusal's reason tokens: empty when landed.
    pub reasons: Vec<String>,
    /// The gate decision that decided it, landed or refused, when one was
    /// recorded.
    pub receipt: Option<[u8; 16]>,
}

const BATCHES: SideTable<[u8; 16], DerivationBatchRecord, Named> =
    SideTable::new(&side_table::DERIVE_BATCH);

/// Each actor's batches in commit order: actor, commit time, batch.
const BY_ACTOR: SideTable<(EntityId, u64, EntityId), (), Named> =
    SideTable::new(&side_table::DERIVE_BATCH_BY_ACTOR);

/// Records `batch` under its id and its actor's index.
pub(super) fn put_batch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    batch: EntityId,
    record: &DerivationBatchRecord,
) -> Result<()> {
    BATCHES.put(&vault.store, txn, batch.as_bytes(), record)?;
    BY_ACTOR.put(
        &vault.store,
        txn,
        &(record.actor, record.committed_at, batch),
        &(),
    )
}

/// The batch `batch` as it committed, if recorded.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
fn batch_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    batch: EntityId,
) -> Result<Option<DerivationBatchRecord>> {
    BATCHES.get(&vault.store, txn, batch.as_bytes())
}

impl Vault {
    /// The derivation batch `batch` as it committed, if recorded.
    ///
    /// # Errors
    ///
    /// Storage errors, and a row that does not decode.
    pub fn derive_batch(&self, batch: EntityId) -> Result<Option<DerivationBatchRecord>> {
        let txn = self.store.env.read_txn()?;
        batch_record_in_txn(self, &txn, batch)
    }

    /// The derivation batches `actor` committed, oldest first.
    ///
    /// # Errors
    ///
    /// Storage errors, and a row that does not decode.
    pub fn derive_batches_of(&self, actor: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        batches_of_actor_in_txn(self, &txn, actor)
    }
}

/// The batches `actor` committed, oldest first.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
fn batches_of_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<Vec<EntityId>> {
    Ok(BY_ACTOR
        .scan_keys(&vault.store, txn, actor.as_bytes())?
        .into_iter()
        .map(|(_, _, batch)| batch)
        .collect())
}
