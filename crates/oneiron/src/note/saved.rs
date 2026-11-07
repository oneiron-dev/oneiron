//! Native preparation and landing of a selected, already-admitted room NOTE.

use super::document::NoteDocument;
use super::documents::invalid;
use crate::batch::{BatchBuilder, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::off_record::PromoteReplayGrant;
use crate::ports::EntityStoreRead;
use crate::scan_check::PendingScanChecks;
use crate::session_overlay::{OverlayKeyspace, OverlaySnapshot};
use crate::store::SessionStoreView;
use crate::{EntityId, Result, Vault, WriteActor};

/// The source is an actual staged NOTE and its complete canonical document,
/// not caller-supplied NOTE bytes or a claim to be its historical author.
pub(crate) struct PreparedSavedNote {
    id: EntityId,
    header: EntityMetadataHeader,
    body: Vec<u8>,
    head: EntityId,
    sequence: u64,
    document: NoteDocument,
}

impl PreparedSavedNote {
    pub(crate) fn from_room_in_txn(
        vault: &Vault,
        view: &SessionStoreView<'_>,
        snapshot: &OverlaySnapshot,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        pending: &PendingScanChecks,
    ) -> Result<Self> {
        let raw = view
            .port_entity_raw(txn, &id)?
            .ok_or(crate::Error::EntityNotFound)?;
        let staged = snapshot.staged_value(OverlayKeyspace::Entities, id.as_bytes());
        if staged != Some(raw.as_slice()) {
            return Err(crate::Error::EntityNotFound);
        }
        let (header, _) = super::verbs::note_core_in(vault, view, txn, id)?;
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        // The native staging program admitted this exact birth body. Loading a
        // merely deserializable body must never earn its authorship bypass.
        if !snapshot.journal_entries().iter().any(|entry| {
            matches!(&entry.op,
                BatchOp::Put { id: source, entity_type, data, allow_maintenance: false,
                    allow_reserved_predicate: false, hub_sync_imported: false, .. }
                    if *source == id && *entity_type == crate::registry::ENTITY_TYPE_NOTE
                        && *data == body
            )
        }) {
            return Err(invalid("selected NOTE has no admitted room birth"));
        }
        let document = super::document_store::load_in(vault, view, txn, id, pending)?;
        let (head, sequence) = super::documents::head_in(view, txn, id)?;
        if vault.store.port_entity_present(txn, &id)? {
            let target = super::document_store::load(vault, txn, id)?;
            if super::documents::head_in(&vault.store, txn, id)? != (head, sequence)
                || target.snapshot()? != document.snapshot()?
            {
                return Err(invalid("selected NOTE conflicts with its durable document"));
            }
        }
        Ok(Self {
            id,
            header,
            body,
            head,
            sequence,
            document,
        })
    }

    pub(crate) fn document_slot(&self) -> EntityId {
        self.head
    }

    pub(crate) fn dependencies(&self) -> Result<Vec<EntityId>> {
        Ok(self
            .document
            .pins()?
            .into_iter()
            .flat_map(|pin| [pin.claim, pin.document])
            .collect())
    }

    pub(crate) fn land_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        saver: WriteActor,
        grant: &PromoteReplayGrant,
        edges: Vec<BatchOp>,
    ) -> Result<()> {
        if !grant.exempts(&self.id) || grant.selected_saver() != Some(saver) {
            return Err(invalid("selected NOTE does not belong to this save"));
        }
        let birth_mask = edges.iter().find_map(|op| match op {
            BatchOp::EdgeWithCreatedAt {
                src,
                kind: crate::edge::EdgeKind::FacetOf,
                tgt,
                ..
            }
            | BatchOp::PublicEdgeWithCreatedAt {
                src,
                kind: crate::edge::EdgeKind::FacetOf,
                tgt,
                ..
            } if *src == self.id => Some(*tgt),
            _ => None,
        });
        let mut ops = vec![BatchOp::Put {
            id: self.id,
            entity_type: crate::registry::ENTITY_TYPE_NOTE,
            occurred: crate::TimeRange {
                start: self.header.occurred_start,
                end: self.header.occurred_end,
            },
            learned_at: self.header.learned_at,
            row_version: Some(self.header.row_version),
            data: self.body.clone(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        ops.extend(edges);
        BatchBuilder::promotion_replay(vault, ops, grant)
            .mask(birth_mask)
            .apply_actor(txn, &saver, crate::core_write::CoreWriteLaneRef::Unbound)?;
        if self.head != self.id || self.sequence != 0 {
            super::documents::set_head(&vault.store, txn, self.id, self.head, self.sequence)?;
        }
        let mut content = crate::federation::ActorContentTxn::new(
            vault,
            txn,
            saver,
            crate::core_write::CoreWriteLaneRef::Unbound,
        )?;
        content.update_note(self.id, |txn, _| -> Result<()> {
            super::document_store::persist_saved_authoritative(vault, txn, &self.document, grant)
        })?;
        content.finish()
    }
}
