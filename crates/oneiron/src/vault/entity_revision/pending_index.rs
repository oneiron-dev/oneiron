//! Caller-supplied index inputs retained until atomic idle publication.
use super::RevisionRef;
use super::storage::{key, state};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Error, Result};

const PENDING: &[u8] = b"entity_revision:index_inputs:";

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(super) struct Inputs {
    pub(super) fields: Option<Vec<(String, String)>>,
    pub(super) vector: Option<Vec<f32>>,
    pub(super) pending_embedding_token: Option<Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Pending {
    revision: RevisionRef,
    inputs: Inputs,
}

pub(crate) fn defer_index_inputs(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    fields: Option<&[(String, String)]>,
    vector: Option<&[f32]>,
    token: Option<&[u8]>,
) -> Result<bool> {
    let Some(current) = state(store, txn, id)? else {
        return Ok(false);
    };
    if current.live == current.indexed {
        return Ok(false);
    }
    let mut inputs = load(store, txn, id, current.live)?;
    if let Some(fields) = fields {
        inputs.fields = Some(fields.to_vec());
    }
    if let Some(vector) = vector {
        inputs.vector = Some(vector.to_vec());
        inputs.pending_embedding_token = token.map(<[u8]>::to_vec);
    }
    let bytes = rmp_serde::to_vec_named(&Pending {
        revision: current.live,
        inputs,
    })
    .map_err(|_| Error::InvariantViolation("pending index inputs encode"))?;
    store.vault_meta.put(txn, &key(PENDING, id), &bytes)?;
    Ok(true)
}

pub(super) fn load(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Inputs> {
    Ok(store
        .vault_meta()
        .get(txn, &key(PENDING, id))?
        .map(|raw| {
            rmp_serde::from_slice::<Pending>(&raw)
                .map_err(|_| Error::CorruptedIndex("pending index inputs"))
        })
        .transpose()?
        .filter(|pending| pending.revision == revision)
        .map(|pending| pending.inputs)
        .unwrap_or_default())
}

pub(super) fn clear(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta().delete(txn, &key(PENDING, id))?;
    Ok(())
}
