//! A staged job's artifact erased with its TASK (FIX 7502, 7614).

use std::collections::BTreeSet;

use crate::codebase::entity_id_from_hash_material;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::store::Store;

use super::BYOA_STAGED_INPUT_ARTIFACT_ID_DOMAIN;

/// Erases each staged job `jobs` names by its digest, in the erase's
/// transaction (FIX 7502, 7614): the bodies its artifact owns retire as an
/// erase's do, then the artifact is removed whole through the physical
/// deindex, its version chain, head and byte references by the artifact
/// delete's own rules (its bytes with them once nothing else holds them),
/// and its row, whose name holds the job's digest, with them. Its graph,
/// vector and neighbor indexes are invalidated. No hard-delete marker is
/// written for the content-addressed id, so the same job staged again later
/// stages afresh. A legal hold on the artifact keeps it whole, as every
/// erase door keeps a held row's bodies: the refusal goes to the hold's log
/// and the rest of the erase goes on. An id that holds no artifact here is
/// left alone. The attempt payload pass erases the pins themselves.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_staged_input_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    jobs: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    for digest in jobs {
        let artifact = entity_id_from_hash_material(
            BYOA_STAGED_INPUT_ARTIFACT_ID_DOMAIN,
            &[digest.as_slice()],
        )?;
        let stored = EntityStoreRead::port_entity_raw(store, txn, &artifact)?
            .as_deref()
            .and_then(crate::batch::EntityMetadataHeader::parse)
            .map(|header| header.entity_type);
        if stored != Some(crate::registry::ENTITY_TYPE_BLOB_ARTIFACT) {
            continue;
        }
        if let Err(error) = store.reject_legal_hold_in_txn(txn, artifact.as_bytes()) {
            if !crate::store::legal_hold::held_in_txn(store, txn, artifact.as_bytes())? {
                return Err(error);
            }
            tracing::warn!(
                artifact = %artifact.to_hex(),
                "staged job erase: a legal hold keeps the job's artifact; its pins are erased"
            );
            continue;
        }
        crate::provenance::erase_row_provenance_without_attempt_payloads_in_txn(
            store, txn, &artifact, true,
        )?;
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &artifact)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &artifact, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, txn)?;
        }
    }
    Ok(())
}
