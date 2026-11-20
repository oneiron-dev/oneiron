//! Doors for `tests/phonetic_g2p_npd.rs` and
//! `tests/made_by_bounded_channels.rs`: an entity born with a stamped Rule A
//! class, which only crate-private batch writers stamp, so a sound match or
//! a bounded channel can be read under the call's `made_by` predicate; and a
//! query under a retrieval authority narrowed to some entity types, as a
//! grant narrows a scoped read's.

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
    put_born_over(
        vault,
        entity_type,
        data,
        class,
        inputs,
        TimeRange { start: at, end: at },
        at,
    )
}

/// [`put_born`], with the entity occurring over `occurred` and learned at
/// `learned_at` (seconds), so a temporal channel reads a long interval.
///
/// # Errors
///
/// A concluded birth with no input, or the vault's write error.
#[doc(hidden)]
pub fn put_born_over(
    vault: &Vault,
    entity_type: u8,
    data: &[u8],
    class: MadeByClass,
    inputs: &[EntityId],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    let writer = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let birth = RowBirth::written(
        writer,
        class,
        "test.sound_match_birth",
        inputs,
        &[],
        learned_at,
    )
    .ok_or_else(|| Error::InvalidConfig("a concluded birth names its inputs".into()))?;
    vault.with_write_txn_grouped(|txn| {
        vault
            .batch_in()
            .put(&id, entity_type, occurred, learned_at, data)
            .made_by(&id, Some(birth))
            .apply(txn)
    })?;
    Ok(id)
}

/// `query` retrieving under the owner's floor narrowed to `entity_types`,
/// as a grant narrows a scoped read's retrieval authority: entity-type
/// authority then drops every other kind from each ranked list before
/// fusion.
///
/// # Errors
///
/// The vault's read error, or a policy manifest or filter that does not
/// resolve.
#[doc(hidden)]
pub fn retrieving_only<'a>(
    vault: &Vault,
    query: crate::PipelineBuilder<'a>,
    entity_types: &[u8],
) -> Result<crate::PipelineBuilder<'a>> {
    let txn = vault.store.env.read_txn()?;
    let floor =
        crate::gate::resolve_policy_manifest(&vault.store, &txn)?.retrieval_floor_for_actor(None);
    let requested = crate::gate::RetrievalFilter {
        entity_types: Some(entity_types.iter().copied().collect()),
        ..Default::default()
    };
    Ok(query.authority_filter(crate::gate::narrow_retrieval_filter(
        &floor,
        Some(&requested),
    )?))
}
