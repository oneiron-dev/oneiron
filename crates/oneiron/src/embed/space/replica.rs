//! Native rows of a declared media space, read and landed in one snapshot.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    InputKind, MEDIA_VECTOR, clear_media_refusal_in_txn, embedding_space_in_txn,
    put_media_vector_in_txn,
};
use crate::embed::{EmbeddingProvenance, device, media, space_move};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::{EntityId, Vault};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaVectorReplica {
    pub(crate) space: String,
    pub(crate) kind: InputKind,
    pub(crate) input_hash: [u8; 32],
    pub(crate) row: Vec<u8>,
    pub(crate) provenance: Option<EmbeddingProvenance>,
    /// Full native source carriers, not a claim about the model's runtime.
    pub(crate) sources: Vec<(EntityId, [u8; 32])>,
}

pub(crate) fn media_vector_replicas_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    space_id: &str,
) -> Result<Vec<MediaVectorReplica>> {
    if !media_record(vault, txn, id)? {
        return Ok(Vec::new());
    }
    let Some(space) = embedding_space_in_txn(&vault.store, txn, space_id)? else {
        return Ok(Vec::new());
    };
    let key = (space.key(), *id);
    let Some(row) = MEDIA_VECTOR.get(&vault.store, txn, &key)? else {
        return Ok(Vec::new());
    };
    let fills = space_move::space_fill_kinds_in_txn(&vault.store, txn, &space)?;
    if !fills.contains(&row.kind) {
        return Ok(Vec::new());
    }
    let Some((input_hash, source_ids)) =
        media::media_vector_input_in_txn(vault, txn, id, row.kind, &fills)?
    else {
        return Ok(Vec::new());
    };
    if row.input_hash != Some(input_hash) {
        return Ok(Vec::new());
    }
    let mut sources = Vec::with_capacity(source_ids.len());
    for source in source_ids {
        let Some(digest) = source_digest_in_txn(vault, txn, &source)? else {
            return Ok(Vec::new());
        };
        sources.push((source, digest));
    }
    Ok(vec![MediaVectorReplica {
        space: space.id,
        kind: row.kind,
        input_hash,
        row: row.row,
        provenance: device::media_provenance_in_txn(&vault.store, txn, &key)?,
        sources,
    }])
}

/// Reuses the row only under the receiver's actual current space and source image.
/// The transport independently proves who brought the exact carrier.
pub(crate) fn install_media_vector_replica_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    replica: &MediaVectorReplica,
) -> Result<bool> {
    if !media_record(vault, txn, id)? {
        return Ok(false);
    }
    let Some(space) = embedding_space_in_txn(&vault.store, txn, &replica.space)? else {
        return Ok(false);
    };
    let fills = space_move::space_fill_kinds_in_txn(&vault.store, txn, &space)?;
    if !fills.contains(&replica.kind) || !space.accepts.contains(&replica.kind) {
        return Ok(false);
    }
    let Some((input_hash, source_ids)) =
        media::media_vector_input_in_txn(vault, txn, id, replica.kind, &fills)?
    else {
        return Ok(false);
    };
    if input_hash != replica.input_hash
        || !source_ids
            .iter()
            .eq(replica.sources.iter().map(|(id, _)| id))
    {
        return Ok(false);
    }
    for (source, digest) in &replica.sources {
        let Some(current) = source_digest_in_txn(vault, txn, source)? else {
            return Ok(false);
        };
        if &current != digest {
            return Ok(false);
        }
    }
    let Ok(vector) = crate::store::decode_vector_row(&replica.row, space.dimensions) else {
        return Ok(false);
    };
    let vector = Zeroizing::new(vector);
    if crate::Error::invalid_vector_component(&vector).is_some() {
        return Ok(false);
    }
    put_media_vector_in_txn(
        &vault.store,
        txn,
        &space,
        &fills,
        id,
        replica.kind,
        Some(replica.input_hash),
        &vector,
        replica.provenance.as_ref(),
    )?;
    clear_media_refusal_in_txn(&vault.store, txn, &space, id)?;
    Ok(true)
}

impl MediaVectorReplica {
    #[must_use]
    pub fn space_id(&self) -> &str {
        &self.space
    }

    #[must_use]
    pub fn sources(&self) -> &[(EntityId, [u8; 32])] {
        &self.sources
    }
}

impl Vault {
    /// Native stored vectors whose kind and exact current input are still held here.
    pub fn media_vector_replicas(
        &self,
        id: &EntityId,
        space_id: &str,
    ) -> Result<Vec<MediaVectorReplica>> {
        let txn = self.store.env.read_txn()?;
        media_vector_replicas_in_txn(self, &txn, id, space_id)
    }
}

pub(crate) async fn reuse_home_media_vectors(
    vault: &Vault,
    space_id: &str,
    max_items: usize,
) -> Result<usize> {
    let Some(home) = vault.home_search() else {
        return Ok(0);
    };
    let ids: Vec<EntityId> = {
        let txn = vault.store.env.read_txn()?;
        let Some(space) = embedding_space_in_txn(&vault.store, &txn, space_id)? else {
            return Ok(0);
        };
        let kinds = space_move::space_fill_kinds_in_txn(&vault.store, &txn, &space)?;
        if kinds.is_empty() {
            return Ok(0);
        }
        let mut report = crate::embed::MediaEmbedReport::default();
        let mut ids = Vec::new();
        for item in vault.media_backlog_in_txn(&txn, &space, &kinds, max_items, &mut report)? {
            if media_record(vault, &txn, &item.id)? {
                ids.push(item.id);
            }
        }
        ids
    };
    if ids.is_empty() {
        return Ok(0);
    }
    let Ok(replicas) = home.media_vectors_for(space_id, &ids).await else {
        return Ok(0);
    };
    if replicas.is_empty() {
        return Ok(0);
    }
    let requested: std::collections::BTreeSet<_> = ids.into_iter().collect();
    let mut txn = vault.store.env.write_txn()?;
    let mut reused = 0;
    for (id, replica) in replicas {
        if requested.contains(&id)
            && replica.space == space_id
            && install_media_vector_replica_in_txn(vault, &mut txn, &id, &replica)?
        {
            reused += 1;
        }
    }
    txn.commit()?;
    Ok(reused)
}

/// The full logical row a native whole-body residence read serves.
fn source_digest_in_txn(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<[u8; 32]>> {
    let Some(raw) = vault
        .get_raw_in(txn, id)?
        .and_then(|raw| crate::world_keys::live_route_row(&vault.store, raw))
    else {
        return Ok(None);
    };
    let raw = vault.materialized_row_in_txn(txn, id, raw)?;
    Ok(Some(*blake3::hash(&raw).as_bytes()))
}

fn media_record(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(vault.store.port_entity_record(txn, id)?.is_some_and(|row| {
        matches!(
            row.entity_type,
            ENTITY_TYPE_CLAIM | ENTITY_TYPE_SUMMARY | ENTITY_TYPE_TURN | ENTITY_TYPE_ASSET
        )
    }))
}
