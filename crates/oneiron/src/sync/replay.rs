//! Explicit-tier entity replay for importers outside the window carrier.
use super::client::ImportTier;
use crate::{EntityId, TimeRange, Vault};

/// A raw replicated entity. Authority comes from the caller's import tier,
/// never from source/confidence fields inside these bytes.
pub struct ReplicatedEntity<'a> {
    pub id: EntityId,
    pub entity_type: u8,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub body: &'a [u8],
}

/// The transaction-scoped `put_replicated` tier fork. Federated input runs the
/// same grading as window admission; own-device replay remains trust-blind.
pub fn replay_entity(
    vault: &Vault,
    entity: ReplicatedEntity<'_>,
    tier: ImportTier,
) -> crate::Result<()> {
    replay_entity_with_birth(vault, entity, None, tier)
}

/// [`replay_entity`] with the row's carried Rule A birth, stamped in the
/// transaction that admits the row. A malformed or conflicting birth is left
/// out; the row stands.
pub fn replay_entity_with_birth(
    vault: &Vault,
    entity: ReplicatedEntity<'_>,
    birth: Option<&crate::provenance::birth::RowBirth>,
    tier: ImportTier,
) -> crate::Result<()> {
    let replayed = vault.with_write_txn_grouped(|txn| {
        vault
            .batch_in()
            .with_import_tier(tier)
            .put_replicated(
                &entity.id,
                entity.entity_type,
                entity.occurred,
                entity.learned_at,
                entity.body,
            )
            .apply(txn)?;
        if let Some(birth) = birth
            && crate::vault::live_entity_row_in_txn(&vault.store, txn, &entity.id)?.is_live()
        {
            super::row_birth::stamp_birth_or_warn(vault, txn, &entity.id, birth)?;
        }
        // FIX 3821: a landed machine-history row may advance its target's pin.
        vault.receive_own_machine_history_row_in_txn(txn, &entity.id)?;
        Ok(())
    });
    if replayed.is_err() {
        // A task authority fact deleted here before it arrived is refused
        // above, and the refusal rolls its transaction back: its task is
        // marked in a transaction of its own, as window ingest marks it.
        vault.with_write_txn_grouped(|txn| {
            crate::task_authority::note_fenced_fact_in_txn(
                &vault.store,
                txn,
                &entity.id,
                entity.entity_type,
                entity.body,
            )
        })?;
    }
    replayed
}
