//! Caller-supplied index inputs retained until atomic idle publication.
use super::RevisionRef;
use super::storage::state;
use crate::side_table::{self, Named, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Result};

const PENDING: SideTable<EntityId, Pending, Named> =
    SideTable::new(&side_table::ENTITY_REVISION_PENDING_INDEX_INPUTS);

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
    PENDING.put(
        store,
        txn,
        id,
        &Pending {
            revision: current.live,
            inputs,
        },
    )?;
    Ok(true)
}

pub(super) fn load(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Inputs> {
    Ok(PENDING
        .get(store, txn, id)?
        .filter(|pending| pending.revision == revision)
        .map(|pending| pending.inputs)
        .unwrap_or_default())
}

pub(super) fn clear(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    PENDING.delete(store, txn, id)?;
    Ok(())
}

/// Keeps staged work attached when only record metadata changes.
pub(super) fn retarget_revision(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    prior: RevisionRef,
    next: RevisionRef,
) -> Result<()> {
    let Some(mut pending) = PENDING.get(store, txn, id)? else {
        return Ok(());
    };
    if pending.revision == prior {
        pending.revision = next;
        PENDING.put(store, txn, id, &pending)?;
    }
    Ok(())
}
