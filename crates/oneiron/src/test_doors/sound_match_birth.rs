//! Doors for `tests/phonetic_g2p_npd.rs` and
//! `tests/made_by_bounded_channels.rs`: an entity born with a stamped Rule A
//! class, which only crate-private batch writers stamp, so a sound match or
//! a bounded channel can be read under the call's `made_by` predicate.

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
    put_born_at(vault, entity_type, data, class, inputs, 1)
}

/// [`put_born`], with the entity occurring and learned at `at` (seconds), so
/// a temporal channel ranks it by its distance from an anchor.
///
/// # Errors
///
/// A concluded birth with no input, or the vault's write error.
#[doc(hidden)]
pub fn put_born_at(
    vault: &Vault,
    entity_type: u8,
    data: &[u8],
    class: MadeByClass,
    inputs: &[EntityId],
    at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    let writer = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let birth = RowBirth::written(writer, class, "test.sound_match_birth", inputs, &[], at)
        .ok_or_else(|| Error::InvalidConfig("a concluded birth names its inputs".into()))?;
    vault.with_write_txn_grouped(|txn| {
        vault
            .batch_in()
            .put(&id, entity_type, TimeRange { start: at, end: at }, at, data)
            .made_by(&id, Some(birth))
            .apply(txn)
    })?;
    Ok(id)
}
