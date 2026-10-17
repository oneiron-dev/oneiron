//! Caller-supplied index inputs retained until atomic idle publication.
use super::RevisionRef;
use super::storage::state;
use crate::embed::EmbeddingProvenance;
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
    /// Who computed the staged vector; a row staged before it was kept has
    /// none.
    #[serde(default)]
    pub(super) provenance: Option<EmbeddingProvenance>,
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
    vector: Option<(&[f32], Option<&EmbeddingProvenance>)>,
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
    if let Some((vector, provenance)) = vector {
        inputs.vector = Some(vector.to_vec());
        inputs.pending_embedding_token = token.map(<[u8]>::to_vec);
        inputs.provenance = provenance.cloned();
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

/// Drops every staged vector, with the token it was staged under, and keeps
/// the staged text and the revision it belongs to.
///
/// Runs inside the embedding-space swap. A staged vector carries no record of
/// the model that made it, and idle publication prefers one over calling the
/// embedder, so one left behind would be published into the new space; without
/// it the idle pass embeds the revision with the new model.
pub(crate) fn drop_staged_vectors(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    for (id, mut pending) in PENDING.scan(store, txn)? {
        if pending.inputs.vector.is_none() && pending.inputs.pending_embedding_token.is_none() {
            continue;
        }
        pending.inputs.vector = None;
        pending.inputs.pending_embedding_token = None;
        pending.inputs.provenance = None;
        if pending.inputs.fields.is_none() {
            PENDING.delete(store, txn, &id)?;
        } else {
            PENDING.put(store, txn, &id, &pending)?;
        }
    }
    Ok(())
}

/// Every text field staged for `id`, whatever revision it was staged for:
/// the historical lift sweep reads them for secrets (OF-067).
pub(crate) fn staged_index_fields(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<(String, String)>> {
    Ok(PENDING
        .get_lenient(store, txn, id)?
        .and_then(|pending| pending.inputs.fields)
        .unwrap_or_default())
}

/// The text fields `id` staged for its live revision, while that revision
/// waits for idle publication: what the lift sweep sends through the batch
/// door again, masked, in their place (OF-067).
pub(crate) fn staged_live_index_fields(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<(String, String)>>> {
    let Some(current) = state(store, txn, id)? else {
        return Ok(None);
    };
    if current.live == current.indexed {
        return Ok(None);
    }
    Ok(load(store, txn, id, current.live)?.fields)
}

/// Drops the text staged for `id` and keeps a staged vector: its publication
/// then reads the text from the live body (OF-067's lift sweep, for staged
/// text that still holds a secret).
pub(crate) fn drop_staged_index_fields(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(mut pending) = PENDING.get_lenient(store, txn, id)? else {
        return Ok(());
    };
    if pending.inputs.fields.take().is_none() {
        return Ok(());
    }
    if pending.inputs.vector.is_none() && pending.inputs.pending_embedding_token.is_none() {
        PENDING.delete(store, txn, id)?;
    } else {
        PENDING.put(store, txn, id, &pending)?;
    }
    Ok(())
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
