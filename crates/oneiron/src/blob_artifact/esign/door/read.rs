//! `vault.esign.get` and `vault.esign.seal.get`. FIX 6403: a world-, facet-
//! or record-scoped credential reads a signing document whose overlay and
//! every artifact it names its own read lane reaches
//! ([`super::super::lane_scope`]), judged in the snapshot the door reads; an
//! unrestricted caller reads as before.
use super::super::delivery_settlement::delivery_receipts_in;
use super::super::document_view::{EsignDocumentTrail, EsignDocumentView, EsignSealTrail};
use super::super::lane_scope::EsignScope;
use super::super::ledger::trail_read_in;
use super::super::seal::CANONICAL;
use super::{
    EsignGetRequest, EsignSealAttemptView, EsignSealGetRequest, EsignSealView, EsignSealedItemView,
    EsignSealedView, document_id,
};
use crate::memory::{Memory, MemoryError, MemoryResult};

impl Memory<'_> {
    /// `vault.esign.get`: the document's folded state and its trail, with
    /// its delivery receipts. The row's refs admission reads `document_ref`
    /// under the caller's scope first, so a project's document reads only in
    /// its audience. A document whose own trail does not read, or folds to
    /// no document, answers `trail` `unreadable` with that error and still
    /// lists its receipts, its `document_unreadable` waits among them
    /// (FIX 6481); nothing its trail alone proves is filled in. A narrowed
    /// credential's lane judges the overlay, and every item its trail
    /// names, in the snapshot the view reads (FIX 6403).
    /// # Errors
    /// A `document_ref` that is no id, a document a narrowed lane does not
    /// reach in whole, or the store's own failure, its receipts' read
    /// included.
    pub fn esign_get(&self, input: &EsignGetRequest) -> MemoryResult<EsignDocumentView> {
        let document = document_id(&input.document_ref)?;
        let scope = self.esign_scope()?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        scope.admit_in(&txn, document)?;
        let trail = match trail_read_in(vault, &txn, document)? {
            Ok((state, audit, held)) => {
                scope.admit_draft_in(&txn, &state.document)?;
                EsignDocumentTrail::readable(state, audit, held)
            }
            Err(unreadable) => EsignDocumentTrail::Unreadable {
                error: MemoryError::from(unreadable),
            },
        };
        let delivery_receipts = delivery_receipts_in(vault, &txn, document)?;
        Ok(EsignDocumentView {
            document_ref: document.to_hex(),
            delivery_receipts,
            trail,
        })
    }

    /// `vault.esign.seal.get`: where the document's seal task stands:
    /// every `esign.seal` attempt the queue holds for it in creation
    /// order, the sealed manifest once one attempt sealed it, its delivery
    /// receipts, and its folded status. The row's refs admission reads
    /// `document_ref` under the caller's scope first, as `vault.esign.get`
    /// does. A document whose own trail does not read, or folds to no
    /// document, answers `trail` `unreadable` with that error, its seal
    /// attempts, manifest and delivery receipts still listed (FIX 6554). A
    /// narrowed credential's lane judges the overlay before the queue is
    /// read and again in the snapshot the rest reads, with every item its
    /// trail names and every original and sealed artifact its manifest
    /// names (FIX 6403).
    /// # Errors
    /// A `document_ref` that is no id, a document a narrowed lane does not
    /// reach in whole, or the store's own failure.
    pub fn esign_seal_get(&self, input: &EsignSealGetRequest) -> MemoryResult<EsignSealView> {
        let document = document_id(&input.document_ref)?;
        let scope = self.esign_scope()?;
        let vault = self.vault();
        if matches!(scope, EsignScope::Credential(_)) {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            scope.admit_in(&txn, document)?;
        }
        let attempts = crate::attempt_queue::AttemptQueue::new(vault)
            .list_kind_bounded(super::super::ESIGN_SEAL_ATTEMPT_KIND, usize::MAX)?
            .into_iter()
            .filter(|record| record.payload.as_slice() == document.as_bytes().as_slice())
            .map(|record| EsignSealAttemptView {
                attempt_ref: crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                kind: record.kind,
                state: record.state.as_str().to_owned(),
                dedupe_key: record.dedupe_key,
                lease_owner: record.lease_owner,
                attempt_count: record.attempt_count,
                created_at: record.created_at,
                updated_at: record.updated_at,
                last_error: record.last_error,
            })
            .collect();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        scope.admit_in(&txn, document)?;
        let trail = match trail_read_in(vault, &txn, document)? {
            Ok((state, _, _)) => {
                scope.admit_draft_in(&txn, &state.document)?;
                EsignSealTrail::Readable {
                    status: state.status,
                }
            }
            Err(unreadable) => EsignSealTrail::Unreadable {
                error: MemoryError::from(unreadable),
            },
        };
        let manifest = CANONICAL.get(&vault.store, &txn, &document)?;
        if let Some(manifest) = &manifest {
            scope.admit_sealed_in(&txn, manifest)?;
        }
        let sealed = manifest.map(|manifest| EsignSealedView {
            attempt_ref: manifest.attempt_ref,
            audit_chain_sha256: crate::entity_id::bytes_to_hex_lower(
                manifest.audit_chain_sha256.as_slice(),
            ),
            rejected: manifest.rejected,
            items: manifest
                .items
                .into_iter()
                .map(|item| EsignSealedItemView {
                    original_artifact: item.original_artifact,
                    original_version: item.original_version,
                    sealed_artifact: item.sealed_artifact,
                    sealed_version: item.sealed_version,
                    sha256: crate::entity_id::bytes_to_hex_lower(item.sha256.as_slice()),
                })
                .collect(),
        });
        let delivery_receipts = delivery_receipts_in(vault, &txn, document)?;
        Ok(EsignSealView {
            document_ref: document.to_hex(),
            attempts,
            sealed,
            delivery_receipts,
            trail,
        })
    }
}
