//! Entity document access through the vault's canonical window/selector owner.
use super::WindowManager;
use crate::error::{Error, Result};
use crate::sync::{WindowKey, documents::DocumentRegistry, selector};
use std::sync::Arc;

impl WindowManager {
    /// The live-edit-only entity document registry.
    pub fn documents(self: &Arc<Self>) -> &DocumentRegistry {
        self.attach_to_vault();
        &self.documents
    }

    pub(crate) fn compact_closed_document(
        &self,
        id: crate::EntityId,
        erased: bool,
    ) -> Result<bool> {
        self.documents.compact_closed(id, erased)
    }

    pub(crate) fn notify_note(&self, id: crate::EntityId) {
        self.documents.notify_note(id);
    }

    /// Grant-backed text-plane export. The entity's canonical ledger supplies
    /// all world/facet/band decisions, never a peer-supplied substitute.
    pub fn export_document(
        self: &Arc<Self>,
        id: crate::EntityId,
        scope: crate::FederationGrantScope,
        selector: &selector::SyncSelector,
        remote_vv: &[u8],
    ) -> Result<Vec<u8>> {
        selector::authorize_sync_selector(&self.vault, scope, selector)?;
        let raw = self.vault.get_raw(&id)?.ok_or_else(|| {
            Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
        })?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(|| {
            Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
        })?;
        let key = WindowKey::from_timestamp(header.learned_at);
        let window = self.open_window(&key)?;
        self.documents
            .export_selected(id, &window.doc, &key, scope, selector, remote_vv)
    }
}
