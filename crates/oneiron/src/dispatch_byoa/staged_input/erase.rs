//! A staged job's artifact erased with its TASK (FIX 7502, 7614, 7612).

use std::collections::BTreeSet;

use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::BYOA_STAGED_INPUT_ARTIFACT_ID_DOMAIN;

/// One staged-artifact erase still owed, and the erased owners whose
/// completion waits on it (FIX 7612).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwedStagedErase {
    owners: BTreeSet<EntityId>,
}

/// Staged-job digests whose artifact erase a legal hold still owes. Key: hash32 (job).
const OWED_STAGED_ERASES: SideTable<[u8; 32], OwedStagedErase, Named> =
    SideTable::new(&side_table::BYOA_STAGED_INPUT_ERASE);

/// Erases each staged job `jobs` names by its digest, in the erase's
/// transaction (FIX 7502, 7614): the bodies its artifact owns retire as an
/// erase's do, then the artifact is removed whole through the physical
/// deindex, its version chain, head and byte references by the artifact
/// delete's own rules (its bytes with them once nothing else holds them),
/// and its row, whose name holds the job's digest, with them. Its graph,
/// vector and neighbor indexes are invalidated. No hard-delete marker is
/// written for the content-addressed id, so the same job staged again later
/// stages afresh. A legal hold on the artifact keeps it whole and owes its
/// erase to the next due legal-hold pass that finds no hold on it (FIX 7612).
/// Re-staging never drops that owe. An id that holds no artifact here clears
/// any stale owe and is left alone. The attempt payload pass erases the pins.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_staged_input_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    jobs: &BTreeSet<[u8; 32]>,
    owners: &BTreeSet<EntityId>,
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
            OWED_STAGED_ERASES.delete(store, txn, digest)?;
            continue;
        }
        if let Err(error) = store.reject_legal_hold_in_txn(txn, artifact.as_bytes()) {
            if !crate::store::legal_hold::held_in_txn(store, txn, artifact.as_bytes())? {
                return Err(error);
            }
            let mut owed = OWED_STAGED_ERASES
                .get(store, txn, digest)?
                .unwrap_or_default();
            owed.owners.extend(owners.iter().copied());
            OWED_STAGED_ERASES.put(store, txn, digest, &owed)?;
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
        OWED_STAGED_ERASES.delete(store, txn, digest)?;
    }
    Ok(())
}

impl Store {
    /// Whether one of `sources` still waits for a held staged artifact's
    /// erase to settle (FIX 7612). A live pin does not make the receipt Due
    /// early: the due pass must first see and honor it.
    pub(crate) fn staged_erases_owed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        sources: &[EntityId],
    ) -> Result<bool> {
        for (_, owed) in OWED_STAGED_ERASES.scan(self, txn)? {
            if sources.iter().any(|source| owed.owners.contains(source)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Settles every staged-artifact erase whose legal hold has lifted, in
    /// the due pass's writer. A still-held digest keeps its owe and bytes. A
    /// live pin keeps the bytes too, clearing the owe; otherwise the ordinary
    /// whole-artifact erase runs. Re-staging never cancels this check.
    ///
    /// # Errors
    ///
    /// Storage errors from the hold or live-pin read, or the ordinary erase.
    pub(crate) fn settle_owed_staged_erases_in_txn(&self, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let mut due = BTreeSet::new();
        for digest in OWED_STAGED_ERASES.scan_keys(self, &*txn, &[])? {
            let artifact = entity_id_from_hash_material(
                BYOA_STAGED_INPUT_ARTIFACT_ID_DOMAIN,
                &[digest.as_slice()],
            )?;
            if crate::store::legal_hold::held_in_txn(self, txn, artifact.as_bytes())? {
                continue;
            }
            if self.live_staged_input_pin_in_txn(txn, &digest)? {
                OWED_STAGED_ERASES.delete(self, txn, &digest)?;
                continue;
            }
            due.insert(digest);
        }
        erase_staged_input_in_txn(self, txn, &due, &BTreeSet::new())
    }
}
