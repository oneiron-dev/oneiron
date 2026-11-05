//! Consume the real record phases before publishing either native view.

mod pending;
pub(crate) use pending::PendingRecordDocument;

use heed::RwTxn;

use super::{RecordDocumentCandidate, document_rows_digest};
use crate::batch::AdmittedRecordDocumentPut;
use crate::entity_doc::native_skill_state::{NativeMapInventory, inspect_inventory};
use crate::entity_doc::{EntityDoc, invalid, storage};
use crate::error::{Error, Result};
use crate::ports::{DocumentRowStore, DocumentSlot, EntityStoreRead};
use crate::{EntityId, Vault};

/// The private installer owns the exact authenticated source continuation,
/// not just a decoded inventory. Only the actual P1..P4 phase product enters.
pub(in crate::entity_doc) struct AdmittedRecordDocument<'a> {
    phases: AdmittedRecordDocumentPut<'a>,
    inventory: NativeMapInventory,
    full_snapshot: bool,
}

/// The installed view checked by P6. No pre-install HEAD/slot recheck can be
/// used after the installer has intentionally replaced those rows.
pub(crate) struct InstalledRecordDocument<'a> {
    admitted: AdmittedRecordDocument<'a>,
    head: Vec<u8>,
    documents: Vec<(DocumentSlot, [u8; 32])>,
}

pub(crate) fn install_record_document_in_txn<'a>(
    phases: AdmittedRecordDocumentPut<'a>,
    txn: &mut RwTxn<'_>,
) -> Result<InstalledRecordDocument<'a>> {
    let candidate = phases.candidate();
    if !candidate.recheck_staged_in_txn(txn)? {
        return Err(invalid("record document changed after body staging"));
    }
    let inventory = inspect_inventory(&candidate.document)?;
    let full_snapshot = candidate.left_document.is_some()
        || candidate
            .local_snapshot
            .as_deref()
            .map(|snapshot| {
                let prior = EntityDoc::from_snapshot(snapshot)?;
                Ok::<_, Error>(
                    prior.doc.shallow_since_vv().to_vv()
                        != candidate.document.doc.shallow_since_vv().to_vv(),
                )
            })
            .transpose()?
            .unwrap_or(false);
    // This stages the exact transported FIRST only inside the real phase
    // continuation, after physical staging and before native publication.
    phases.refinement().stage_in_txn(&phases, txn)?;
    let admitted = AdmittedRecordDocument {
        phases,
        inventory,
        full_snapshot,
    };
    let candidate = admitted.candidate();
    let entity = candidate.entity()?;
    let mut head = candidate.head.clone();
    storage::persist_admitted_record_document(txn, &mut head, &admitted)?;
    let store = &admitted.vault().store;
    if candidate.document.doc.is_shallow() {
        store.port_document_shallow_since_put(
            txn,
            storage::document_slot(&head)?,
            &candidate.document.doc.shallow_since_vv().encode(),
        )?;
    }
    if let Some(left) = &candidate.left_document {
        storage::drop_document(store, txn, left)?;
    }
    let head = storage::record_head_bytes(store, txn, &entity)?
        .ok_or(Error::CorruptedIndex("installed record document head"))?;
    let documents = candidate
        .prior_documents
        .iter()
        .map(|(slot, _)| Ok((*slot, document_rows_digest(store, txn, *slot)?)))
        .collect::<Result<_>>()?;
    Ok(InstalledRecordDocument {
        admitted,
        head,
        documents,
    })
}

impl<'a> AdmittedRecordDocument<'a> {
    fn candidate(&self) -> &'a RecordDocumentCandidate<'a, 'a> {
        self.phases.candidate()
    }

    pub(in crate::entity_doc) fn vault(&self) -> &Vault {
        self.candidate().selected.vault()
    }

    pub(in crate::entity_doc) fn document(&self) -> &EntityDoc {
        &self.candidate().document
    }

    pub(in crate::entity_doc) fn entity(&self) -> Result<EntityId> {
        self.candidate().entity()
    }

    pub(in crate::entity_doc) fn before(&self) -> Option<&loro::VersionVector> {
        (!self.full_snapshot)
            .then_some(self.candidate().before.as_ref())
            .flatten()
    }

    /// The storage terminal accepts this source owner, never a supplied raw
    /// snapshot or token set. It is consumed before HEAD changes in this writer.
    pub(in crate::entity_doc) fn require_document(
        &self,
        txn: &mut RwTxn<'_>,
        head: &storage::Head,
    ) -> Result<std::collections::BTreeSet<EntityId>> {
        let candidate = self.candidate();
        let expected = &candidate.head;
        if !candidate.recheck_staged_in_txn(txn)?
            || !self
                .phases
                .refinement()
                .installed_origin_matches(&self.vault().store, txn)?
            || head.entity != expected.entity
            || head.incarnation != expected.incarnation
            || head.document != expected.document
            || head.storage_document != expected.storage_document
            || head.sequence_document != expected.sequence_document
            || head.field != expected.field
            || head.generation != expected.generation
            || head.pending != expected.pending
            || head.birth_frontier != expected.birth_frontier
            || inspect_inventory(&candidate.document)? != self.inventory
        {
            return Err(invalid("record document differs from its admitted source"));
        }
        self.inventory.writer_tokens()
    }
}

impl InstalledRecordDocument<'_> {
    /// The same physical row, installed HEAD/slots and source FIRST must still
    /// be present. The old selected HEAD/slots are deliberately not expected.
    pub(crate) fn require_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut RwTxn<'_>,
        entity: &EntityId,
        data: &[u8],
    ) -> Result<bool> {
        self.require_identity_in_txn(store, txn, entity, data)?;
        if !self
            .admitted
            .phases
            .refinement()
            .installed_origin_matches(store, txn)?
        {
            return Err(invalid(
                "installed record document changed before projections",
            ));
        }
        self.require_documents_in_txn(store, txn)?;
        Ok(self.admitted.phases.refinement().has_source_origin())
    }

    fn require_rows_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut RwTxn<'_>,
        entity: &EntityId,
        data: &[u8],
    ) -> Result<()> {
        self.require_identity_in_txn(store, txn, entity, data)?;
        self.require_documents_in_txn(store, txn)
    }

    fn require_identity_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut RwTxn<'_>,
        entity: &EntityId,
        data: &[u8],
    ) -> Result<()> {
        let candidate = self.admitted.candidate();
        if !candidate.applies_to(store, entity, data)
            || !candidate.selected.recheck_transport_in_txn(store, txn)?
            || store.port_entity_raw(txn, entity)?.as_deref() != Some(candidate.physical_raw())
            || storage::record_head_bytes(store, txn, entity)?.as_deref()
                != Some(self.head.as_slice())
        {
            return Err(invalid(
                "installed record document changed before projections",
            ));
        }
        Ok(())
    }

    fn require_documents_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        for (slot, digest) in &self.documents {
            if document_rows_digest(store, txn, *slot)? != *digest {
                return Err(invalid(
                    "installed record document rows changed before projections",
                ));
            }
        }
        Ok(())
    }
}
