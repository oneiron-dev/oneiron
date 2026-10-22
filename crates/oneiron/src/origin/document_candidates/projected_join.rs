//! A received row's projection join (FIX 7608 slice 2b-ii-B2): which copy
//! and canonical store a row received into a masked copy's private ingress
//! stands for, the ingress stores a canonical queue's intake reads, a
//! projected candidate's hold refresh and its attachment's source proof.
//! Each join reads the records the receive wrote (the ingress store's own
//! record and the operation's ingress proof under the same copy), never a
//! path, a placeholder or a trailer.

use heed::RoTxn;

use super::super::document_candidate_types::{
    CodePushCandidate, ReceivedCandidateRef, ReceivedRefIngress,
};
use super::super::document_ingress::{CODE_OPERATIONS, ProvenanceRefKey};
use super::CandidateQueue;
use super::projected_source::{
    record_projected_translation_in_txn, require_projected_candidate_source_in_txn,
};
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_projection::claims::{RepoProjectionClaim, RepoProjectionRecord};
use crate::origin::secret_projection::clearance::RepoProjectionHoldCause;
use crate::origin::secret_projection::git::existing_projection_ingress_root;
use crate::{EntityId, Vault};

/// A received row's projection source: the copy graph its ingress was
/// seeded from, the canonical store it stands for, the receive operation
/// (the admission id, never the per-ref outcome id) and the ingress proof
/// record that operation was received under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedRowSource {
    pub(crate) graph: EntityId,
    pub(crate) canonical_store: EntityId,
    pub(crate) operation: EntityId,
    pub(crate) ingress: EntityId,
}

/// The receive operation the per-ref outcome claim `provenance` records.
pub(crate) fn receive_operation_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    provenance: EntityId,
) -> Result<Option<EntityId>> {
    let Some(body) = vault.get_claim_in_txn(txn, &provenance)? else {
        return Ok(None);
    };
    Ok(body
        .value
        .as_map()
        .and_then(|map| {
            map.iter()
                .find(|(key, _)| key.as_str() == Some("operation_id"))
                .and_then(|(_, value)| value.as_str())
        })
        .and_then(|id| EntityId::from_hex(id).ok()))
}

impl Vault {
    /// The projection source of `row`, received into a private ingress and
    /// joined to the canonical store `canonical_store`; `None` for any
    /// other row (an ordinary one included).
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn projected_row_source_in_txn(
        &self,
        txn: &RoTxn<'_>,
        row: &ReceivedRefIngress,
        provenance: EntityId,
        canonical_store: EntityId,
    ) -> Result<Option<ProjectedRowSource>> {
        let Some((graph, store)) =
            RepoProjectionClaim::load_ingress_store_in_txn(self, txn, &row.source.object_store)?
        else {
            return Ok(None);
        };
        if store.canonical_store != canonical_store {
            return Ok(None);
        }
        let Some(operation) = receive_operation_in_txn(self, txn, provenance)? else {
            return Ok(None);
        };
        let Some(ingress) =
            RepoProjectionClaim::load_ingress_in_txn(self, txn, &graph, &operation)?
        else {
            return Ok(None);
        };
        if ingress.ingress_store != row.source.object_store
            || ingress.canonical_store != canonical_store
        {
            return Ok(None);
        }
        let ingress =
            RepoProjectionClaim::of(graph, RepoProjectionRecord::Ingress(ingress)).id()?;
        Ok(Some(ProjectedRowSource {
            graph,
            canonical_store,
            operation,
            ingress,
        }))
    }

    /// Whether `row`, received into a masked copy's private ingress,
    /// stands for the canonical store whose identity is `canonical`, by its
    /// projection join in `txn` (the owner workbench's cross-store read).
    ///
    /// # Errors
    /// A store failure, or a record that does not decode.
    pub(crate) fn received_ingress_targets_canonical_in_txn(
        &self,
        txn: &RoTxn<'_>,
        row: &ReceivedRefIngress,
        provenance: EntityId,
        canonical: &str,
    ) -> Result<bool> {
        let store = lfs_repo_id(canonical)?;
        Ok(self
            .projected_row_source_in_txn(txn, row, provenance, store)?
            .is_some())
    }

    /// The identities of every private ingress seeded for the canonical
    /// store whose identity is `canonical`, each confirmed by its own
    /// record. None for a store no copy was ever received for.
    ///
    /// # Errors
    /// A store or directory failure.
    pub(crate) fn projected_ingress_stores(&self, canonical: &str) -> Result<Vec<String>> {
        let store = lfs_repo_id(canonical)?;
        let root = existing_projection_ingress_root(self, store);
        if !root.is_dir() {
            return Ok(Vec::new());
        }
        let txn = self.store.env.read_txn()?;
        let mut stores = Vec::new();
        for entry in std::fs::read_dir(&root)? {
            let Ok(identity) = GitWire::projection_ingress_identity(&entry?.path()) else {
                continue;
            };
            if RepoProjectionClaim::load_ingress_store_in_txn(self, &txn, &identity)?
                .is_some_and(|(_, record)| record.canonical_store == store)
            {
                stores.push(identity);
            }
        }
        stores.sort();
        Ok(stores)
    }

    /// Every received ref of a private ingress seeded for the canonical
    /// store `canonical` that still needs the intake: unresolved, or
    /// resolved from a masked copy (its projection hold is refreshed).
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn pending_projected_candidates(
        &self,
        canonical: &str,
    ) -> Result<Vec<ReceivedCandidateRef>> {
        let stores = self.projected_ingress_stores(canonical)?;
        if stores.is_empty() {
            return Ok(Vec::new());
        }
        let txn = self.store.env.read_txn()?;
        let mut pending = Vec::new();
        for row in CODE_OPERATIONS.iter_from(&self.store, &txn, &[])? {
            let (key, row) = row?;
            if stores.contains(&row.source.object_store)
                && row.candidate.as_ref().is_none_or(|candidate| {
                    candidate.resolved.is_none() || candidate.projected.is_some()
                })
            {
                pending.push(ReceivedCandidateRef {
                    object_store: row.source.object_store,
                    provenance: key.provenance,
                    ref_name: row.source.ref_name,
                });
            }
        }
        Ok(pending)
    }

    /// The projection source of the retained row `row` for the canonical
    /// store `repo`, read once.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn projected_row_source(
        &self,
        row: &ReceivedRefIngress,
        provenance: EntityId,
        repo: &GitWireRepo,
    ) -> Result<Option<ProjectedRowSource>> {
        let canonical_store = lfs_repo_id(&repo.identity().as_hex())?;
        let txn = self.store.env.read_txn()?;
        self.projected_row_source_in_txn(&txn, row, provenance, canonical_store)
    }

    /// Re-judges a resolved projected candidate's hold: only its projection
    /// cause is refreshed, never its resolution, and an unchanged hold
    /// writes nothing.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn refresh_projected_candidate_hold_of(
        &self,
        key: &ProvenanceRefKey,
        provenance: EntityId,
    ) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(mut current) = CODE_OPERATIONS.get(&self.store, &wtxn, key)? else {
            return Ok(false);
        };
        let Some(candidate) = current.candidate.as_mut() else {
            return Ok(false);
        };
        let Some(pins) = candidate.projected.clone() else {
            return Ok(false);
        };
        if candidate.hold.as_ref().is_some_and(|held| {
            held.reason != RepoProjectionHoldCause::SealedFileEdited.as_str()
                && held.reason != RepoProjectionHoldCause::ProjectionEditConflict.as_str()
        }) {
            return Ok(false);
        }
        let cause =
            self.projected_candidate_clearance_in_txn(&wtxn, provenance, candidate.candidate)?;
        let next = super::projected::refresh_projected_candidate_hold(&pins, cause);
        if candidate.hold == next {
            return Ok(false);
        }
        candidate.hold = next;
        CODE_OPERATIONS.put(&self.store, &mut wtxn, key, &current)?;
        wtxn.commit()?;
        Ok(true)
    }

    /// Matches one projected row under the canonical repository writer and
    /// writes its candidate: an attachment, or a changed hold.
    ///
    /// # Errors
    /// An object store or store failure. A hold is no error.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn match_projected_candidate(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        queue: &CandidateQueue,
        key: &ProvenanceRefKey,
        provenance: EntityId,
        row: &ReceivedRefIngress,
        id: EntityId,
        digest: [u8; 32],
        source: &ProjectedRowSource,
    ) -> Result<bool> {
        let decided = self
            .decide_projected_candidate(wire, repo, queue, provenance, row, id, digest, source)?;
        let Some(decided) = decided else {
            return Ok(false);
        };
        let mut wtxn = self.store.env.write_txn()?;
        let written = match decided {
            Err((held, pins)) => self.attach_received_code_hold_in_txn(
                &mut wtxn,
                key,
                row,
                CodePushCandidate {
                    candidate: id,
                    source_digest: digest,
                    resolved: None,
                    hold: Some(held),
                    projected: pins,
                },
            )?,
            Ok(prepared) => {
                self.attach_received_code_candidate_in_txn(&mut wtxn, key, row, &prepared)?
            }
        };
        if written {
            wtxn.commit()?;
        }
        Ok(written)
    }

    /// Records a projected attachment's translation in its writer and
    /// proves its source there: the ingress proof of its operation under
    /// its graph and the translation record, each exactly as written. An
    /// ordinary candidate writes nothing.
    ///
    /// # Errors
    /// A source that no longer stands, or a store failure.
    pub(super) fn record_projected_attachment_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        provenance: EntityId,
        candidate: &CodePushCandidate,
    ) -> Result<()> {
        let (Some(pins), Some(resolved)) = (&candidate.projected, &candidate.resolved) else {
            return Ok(());
        };
        let operation = receive_operation_in_txn(self, wtxn, provenance)?.ok_or(
            Error::ConcurrentWrite("a projected candidate's receive is gone"),
        )?;
        record_projected_translation_in_txn(
            self,
            wtxn,
            pins,
            candidate.candidate,
            operation,
            resolved.resolved_at,
        )?;
        if !require_projected_candidate_source_in_txn(
            self,
            wtxn,
            pins,
            candidate.candidate,
            operation,
        )? {
            return Err(Error::ConcurrentWrite(
                "a projected candidate source changed",
            ));
        }
        Ok(())
    }
}
