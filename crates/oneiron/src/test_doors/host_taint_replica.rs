//! The own-device replay of chosen rows from one vault into another, for the
//! test that a host's taint mark reaches a synced replica (census L6-32).
//! Each row goes through the sync replay door with its stored header, as an
//! own device takes it; the replicated put itself stays crate-private.
use crate::blob_artifact::{BlobArtifactBody, encode_blob_artifact_body};
use crate::error::Error;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::source_audience::{self, SourceAudienceBirth};
use crate::store::source_audience_obligation::SourceAudienceObligation;
use crate::sync::client::ImportTier;
use crate::sync::replay::{ReplicatedEntity, replay_entity};
use crate::temporal::TimeRange;
use crate::{EntityId, Result, Vault};

/// Lands a BLOB_ARTIFACT named `name` the way a mail landing keeps an
/// attachment (`mail_pack/attachments.rs`): stamped under a new source
/// policy that `reader` reads, put through the source-bound door, and bound
/// to that policy, in one write. Returns the artifact's id.
///
/// # Errors
///
/// Storage, encoding, or source-audience admission failures.
pub fn land_source_bound_artifact(vault: &Vault, reader: EntityId, name: &str) -> Result<EntityId> {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    let body = encode_blob_artifact_body(&BlobArtifactBody::new(name, "application/pdf"))?;
    vault.with_write_txn(|txn| {
        let policy = source_audience::create_source_policy_in_txn(
            vault,
            txn,
            [reader].into_iter().collect(),
            false,
            reader,
            at,
        )?;
        let birth = SourceAudienceBirth::mint_in(vault, txn, &policy)?;
        let stamped = birth.stamp_in_txn(vault, txn, &id, &body)?;
        vault
            .batch_in()
            .put_source_bound(
                &id,
                ENTITY_TYPE_BLOB_ARTIFACT,
                TimeRange { start: at, end: at },
                at,
                &stamped,
                &birth,
            )
            .apply(txn)?;
        source_audience::bind_record_in_txn(vault, txn, &id, &policy)?;
        Ok(id)
    })
}

/// Whether the row `id`, as `vault` stores it, states the source-audience
/// stamp in its own bytes.
///
/// # Errors
///
/// Storage failures.
pub fn states_source_audience(vault: &Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .port_entity_raw_wiped(&rtxn, id)?
        .is_some_and(|raw| {
            source_audience::row_obligation(&raw) == SourceAudienceObligation::Required
        }))
}

/// Replays each row of `ids`, as `from` stores it now, into `to`.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for an id `from` holds no row for, or the
/// replay door's refusal.
pub fn replicate_entities(from: &Vault, to: &Vault, ids: &[EntityId]) -> Result<()> {
    let rows = {
        let rtxn = from.store.env.read_txn()?;
        ids.iter()
            .map(|id| {
                from.store
                    .port_entity_record(&rtxn, id)?
                    .map(|row| (*id, row))
                    .ok_or(Error::EntityNotFound)
            })
            .collect::<Result<Vec<_>>>()?
    };
    for (id, row) in &rows {
        replay_entity(
            to,
            ReplicatedEntity {
                id: *id,
                entity_type: row.entity_type,
                occurred: row.occurred,
                learned_at: row.learned_at,
                row_version: row.row_version,
                body: &row.body,
            },
            ImportTier::OwnDevice,
        )?;
    }
    Ok(())
}
