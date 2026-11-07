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

    pub(crate) fn notify_note_forks(&self, id: crate::EntityId) {
        self.documents.notify_note_forks(id);
    }
    /// The owner lane's text-plane export for an own device: NOTE documents
    /// only, with no selector, under the state-copy and resync rule of the
    /// selector export.
    pub fn export_owner_document(
        self: &Arc<Self>,
        id: crate::EntityId,
        remote_vv: &[u8],
    ) -> Result<Vec<u8>> {
        self.documents
            .open(id)?
            .export_owner(remote_vv, crate::sync::window::Withhold::Unknown)
    }

    /// [`Self::export_owner_document`] judged for the machine `peer` the lane
    /// proved: it reads the NOTEs of the private worlds that machine may read.
    pub fn export_owner_document_for(
        self: &Arc<Self>,
        id: crate::EntityId,
        remote_vv: &[u8],
        peer: crate::authority::PeerMachine,
    ) -> Result<Vec<u8>> {
        self.documents
            .open(id)?
            .export_owner(remote_vv, crate::sync::window::Withhold::Peer(peer))
    }

    /// The pending forks of the NOTE `id` for an own device, judged for the
    /// machine `peer` the lane proved (FIX 12789): each fork's state, then
    /// their set. None from a replica, which is no authority.
    ///
    /// # Errors
    ///
    /// An owner admission denial for that machine, or a storage error.
    pub fn export_owner_note_forks_for(
        self: &Arc<Self>,
        id: crate::EntityId,
        peer: crate::authority::PeerMachine,
    ) -> Result<Vec<Vec<u8>>> {
        self.documents
            .export_owner_note_forks(id, crate::sync::window::Withhold::Peer(peer))
    }

    /// Grant-backed text-plane export for a caller-selected window. The
    /// window is validated by the same selector as the ledger first touch,
    /// including world-plus-month keys.
    pub fn export_document_in_window(
        self: &Arc<Self>,
        id: crate::EntityId,
        window: &WindowKey,
        scope: crate::FederationGrantScope,
        selector: &selector::SyncSelector,
        remote_vv: &[u8],
    ) -> Result<Vec<u8>> {
        self.export_document_in_window_with(
            id,
            window,
            scope,
            selector,
            crate::sync::window::Withhold::Unknown,
            remote_vv,
        )
    }

    /// [`Self::export_document_in_window`] for the machine a residence read
    /// serves: `withhold` names the worlds kept off it.
    pub fn export_document_in_window_with(
        self: &Arc<Self>,
        id: crate::EntityId,
        window: &WindowKey,
        scope: crate::FederationGrantScope,
        selector: &selector::SyncSelector,
        withhold: crate::sync::window::Withhold<'_>,
        remote_vv: &[u8],
    ) -> Result<Vec<u8>> {
        selector::authorize_sync_selector(&self.vault, scope, selector)?;
        // FIX 7608 slice 4: a copy id reads its marked source's document.
        let id = selector::repo_document_source(&self.vault, id)?;
        let source = self.open_window(window)?;
        self.documents.export_selected(
            id,
            &source.doc,
            window,
            scope,
            selector,
            withhold,
            remote_vv,
        )
    }

    /// A thin read's document and its optional source-world evidence. The
    /// evidence is captured in the document's own exporting transaction;
    /// projected copies or a different stored row leave it unknown.
    pub fn export_read_cache_document_in_window_with(
        self: &Arc<Self>,
        id: crate::EntityId,
        window: &WindowKey,
        scope: crate::FederationGrantScope,
        selector: &selector::SyncSelector,
        withhold: crate::sync::window::Withhold<'_>,
        remote_vv: &[u8],
        blob: &[u8],
    ) -> Result<(Vec<u8>, Option<crate::sync::residence::CachedItemWorlds>)> {
        selector::authorize_sync_selector(&self.vault, scope, selector)?;
        let source_id = selector::repo_document_source(&self.vault, id)?;
        let source = self.open_window(window)?;
        self.documents.export_selected_with_cache(
            source_id,
            &source.doc,
            window,
            scope,
            selector,
            withhold,
            remote_vv,
            Some((id, blob)),
        )
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
        self.export_document_with(
            id,
            scope,
            selector,
            crate::sync::window::Withhold::Unknown,
            remote_vv,
        )
    }

    /// Text-plane export for the physical machine proven by the transport.
    /// Actor grants still apply, independently of the world's machine policy.
    pub fn export_document_for_peer(
        self: &Arc<Self>,
        id: crate::EntityId,
        scope: crate::FederationGrantScope,
        selector: &selector::SyncSelector,
        remote_vv: &[u8],
        peer: crate::authority::PeerMachine,
    ) -> Result<Vec<u8>> {
        self.export_document_with(
            id,
            scope,
            selector,
            crate::sync::window::Withhold::Peer(peer),
            remote_vv,
        )
    }

    /// [`Self::export_document`] for the machine the socket proved:
    /// `withhold` names the worlds kept off it.
    pub fn export_document_with(
        self: &Arc<Self>,
        id: crate::EntityId,
        scope: crate::FederationGrantScope,
        selector: &selector::SyncSelector,
        withhold: crate::sync::window::Withhold<'_>,
        remote_vv: &[u8],
    ) -> Result<Vec<u8>> {
        selector::authorize_sync_selector(&self.vault, scope, selector)?;
        // FIX 7608 slice 4: a copy id reads its marked source's document.
        let id = selector::repo_document_source(&self.vault, id)?;
        let raw = self.vault.get_raw(&id)?.ok_or_else(|| {
            Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
        })?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(|| {
            Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
        })?;
        let key = match crate::sync::types::entity_world(&raw)? {
            Some(world) => WindowKey::for_world(header.learned_at, world),
            None => WindowKey::from_timestamp(header.learned_at),
        };
        let window = self.open_window(&key)?;
        self.documents
            .export_selected(id, &window.doc, &key, scope, selector, withhold, remote_vv)
    }
}
