//! Doors for `tests/phonetic_g2p_npd.rs`: an entity born with a stamped
//! Rule A class, which only crate-private batch writers stamp, so a sound
//! match can be read under the call's `made_by` predicate.

use crate::error::{Error, Result};
use crate::provenance::made_by::MadeByClass;
use crate::store::row_birth::RowBirth;
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};

/// Puts a fresh entity of `entity_type` with body `data`, as
/// [`Vault::put_entity`] does (its put publishes the name's phonetic codes),
/// and stamps its birth as `class`, made from `inputs`. A concluded birth
/// names at least one input.
///
/// # Errors
///
/// A concluded birth with no input, or the vault's write error.
#[doc(hidden)]
pub fn put_born(
    vault: &Vault,
    entity_type: u8,
    data: &[u8],
    class: MadeByClass,
    inputs: &[EntityId],
) -> Result<EntityId> {
    let id = EntityId::now();
    let writer = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let birth = RowBirth::written(writer, class, "test.sound_match_birth", inputs, &[], 1)
        .ok_or_else(|| Error::InvalidConfig("a concluded birth names its inputs".into()))?;
    vault.with_write_txn_grouped(|txn| {
        vault
            .batch_in()
            .put(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, data)
            .made_by(&id, Some(birth))
            .apply(txn)
    })?;
    Ok(id)
}
