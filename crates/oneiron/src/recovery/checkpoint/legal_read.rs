//! A legal read of one of this vault's own checkpoints, for a HOST order's
//! artifact capture (LEGAL-HOLD-USE = B as a clone, FIX 13863): the HOST
//! hands over the artifact's file; it opens through the real opener under
//! this vault's checkpoint key, its identity is the one the opening
//! verified, and the selected messages' stored rows are read out of its
//! image and out of the payload compartments this vault's live custody
//! still opens. A compartment an erase or purge retired since the cut stays
//! shut, so what the vault erased never comes back. Nothing is restored,
//! forked or written, and no other owner's rows leave this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

use super::payload::{Getter, SelectedPayload, open_selected_payload};
use super::{CanonicalRows, CheckpointKey, artifact, image};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::DocumentSlot;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::side_table;
use crate::store::LiveCustody;
use crate::store::checkpoint_payload::rows::{
    OpenedOwnerRows, OwnerRef, RowDb, RowLocator, RowPart, actor_keyed_row,
};

/// The identity an artifact's opening verified, never a request's echo: the
/// vault its prelude and manifest name (the key's own), its checkpoint id
/// (the image's BLAKE3) and the BLAKE3 of its signed commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedArtifact {
    pub(crate) vault_id: [u8; 32],
    pub(crate) checkpoint_id: [u8; 32],
    pub(crate) commitment_digest: [u8; 32],
}

/// Which part of a selected message's record a row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactComponent {
    /// The message's entity row.
    Row,
    /// Its document head, a slot row or one update.
    Document,
    /// One outgoing edge row.
    Edge,
    /// One row of its revision ledger.
    Revision,
}

/// One stored row of a selected message, as the artifact holds it: its full
/// stored key and its value.
pub(crate) struct ArtifactRow {
    pub(crate) component: ArtifactComponent,
    pub(crate) family: &'static str,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

/// A selected message as the artifact holds it.
pub(crate) enum ArtifactMessage {
    /// Its rows, entity row first, then its document, its outgoing edges and
    /// its revision ledger, each in key order.
    Held(Vec<ArtifactRow>),
    /// The artifact holds no readable MESSAGE row for it: its entity tree's
    /// compartment did not open (erased or purged since the cut), the
    /// payload holds none for it (an artifact that carries no compartments
    /// proves nothing about an erase since), or its row is absent or not a
    /// MESSAGE.
    Missed,
}

/// Why a legal read refuses an artifact before any row of it is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactRefusal {
    /// The verified identity is not the one the request names.
    IdentityMismatch,
}

/// Opens the artifact in `file` with `key` through the real opener (vault,
/// signed commitment, manifest, chunks and image checked, the signer under
/// the key's trust), checks its verified identity against `expected`, then
/// reads each of `ids` out of it under a custody plan built from `live`
/// (`preflight_legal_read_rejected`). Only the selected messages' entity
/// trees and every actor group open; the rows naming an owner that did not
/// open are taken out first, as a restore takes them.
///
/// # Errors
///
/// An artifact that does not open or decode, another vault's, a signer the
/// key does not trust, an identity other than `expected`
/// ([`ArtifactRefusal`]), custody of another lineage
/// (`custody_lineage_mismatch`) or missing, and a compartment or row that
/// does not read back as sealed.
pub(crate) fn read_artifact_messages(
    file: File,
    key: &CheckpointKey,
    expected: &VerifiedArtifact,
    live: &LiveCustody,
    ids: &[[u8; 16]],
) -> std::result::Result<Vec<([u8; 16], ArtifactMessage)>, LegalReadError> {
    let opened = artifact::open_artifact_file(file, key)?;
    let verified = VerifiedArtifact {
        vault_id: key.vault_id,
        checkpoint_id: opened.image_id,
        commitment_digest: opened.commitment_digest,
    };
    if verified != *expected {
        return Err(LegalReadError::Refused(ArtifactRefusal::IdentityMismatch));
    }
    let (mut image, _, mut bodies, _) = image::decode_image(opened)?;
    let vault_meta = image
        .databases
        .get("vault_meta")
        .ok_or(Error::CorruptedIndex("checkpoint image vault_meta"))?;
    let mut custody =
        crate::store::preflight_legal_read_rejected(vault_meta, live).map_err(Error::from)?;
    let entities = ids
        .iter()
        .map(|id| EntityId::from_bytes(*id))
        .collect::<Result<Vec<_>>>()?;
    let selected: BTreeSet<OwnerRef> = entities.iter().map(OwnerRef::entity).collect();
    let payload = open_selected_payload(
        bodies.payload.take(),
        custody.plan_mut(),
        &mut image,
        &selected,
    )
    .map_err(Error::from)?;
    let mut messages = Vec::with_capacity(ids.len());
    for (id, entity) in ids.iter().zip(&entities) {
        let source = MessageSource::new(&image.databases, payload.as_ref(), entity)?;
        messages.push((*id, source.message(id, entity)?));
    }
    Ok(messages)
}

/// A legal read's failure: a refusal of the artifact, or an error.
#[derive(Debug)]
pub(crate) enum LegalReadError {
    Refused(ArtifactRefusal),
    Failed(Error),
}

impl From<Error> for LegalReadError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// One selected message's rows, from its opened compartment's parts (exact
/// rows, actor-keyed rows whose actor opened, joined document groups) over
/// the image's own rows. A message reads only when the payload holds its
/// entity tree's compartment and live custody opened it: a row the image
/// keeps whole proves nothing about an erase since the cut.
struct MessageSource<'a> {
    databases: &'a BTreeMap<String, CanonicalRows>,
    parts: BTreeMap<(RowDb, Vec<u8>), Vec<u8>>,
    readable: bool,
}

impl<'a> MessageSource<'a> {
    fn new(
        databases: &'a BTreeMap<String, CanonicalRows>,
        payload: Option<&SelectedPayload>,
        entity: &EntityId,
    ) -> Result<Self> {
        let owner = OwnerRef::entity(entity);
        let mut parts = BTreeMap::new();
        let mut readable = false;
        if let Some(payload) = payload {
            readable = payload.opened(owner);
            for getter in [Getter::Entities, Getter::EntityDoc, Getter::EntityRevision] {
                for opened in payload.contents(owner, getter) {
                    owner_parts(opened, &mut parts)?;
                    if getter == Getter::EntityDoc {
                        for (at, value) in
                            crate::entity_doc::checkpoint::join_entity_documents(opened)?
                        {
                            parts.insert((at.db, at.key), value);
                        }
                    }
                }
            }
        }
        Ok(Self {
            databases,
            parts,
            readable,
        })
    }

    /// The row at `key` in `db`: an opened part's, else the image's.
    fn get(&self, db: RowDb, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(value) = self.parts.get(&(db, key.to_vec())) {
            return Some(value.clone());
        }
        let rows = self.databases.get(database_name(db))?;
        let at = rows
            .binary_search_by(|(row, _)| row.as_slice().cmp(key))
            .ok()?;
        Some(rows[at].1.clone())
    }

    /// Every row in `db` whose key starts with `prefix`, in key order, an
    /// opened part's over the image's.
    fn scan(&self, db: RowDb, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        if let Some(image) = self.databases.get(database_name(db)) {
            let start = image.partition_point(|(key, _)| key.as_slice() < prefix);
            for (key, value) in &image[start..] {
                if !key.starts_with(prefix) {
                    break;
                }
                rows.insert(key.clone(), value.clone());
            }
        }
        for ((part_db, key), value) in &self.parts {
            if *part_db == db && key.starts_with(prefix) {
                rows.insert(key.clone(), value.clone());
            }
        }
        rows.into_iter().collect()
    }

    fn message(&self, id: &[u8; 16], entity: &EntityId) -> Result<ArtifactMessage> {
        if !self.readable {
            return Ok(ArtifactMessage::Missed);
        }
        let Some(row) = self.get(RowDb::Entities, id) else {
            return Ok(ArtifactMessage::Missed);
        };
        if EntityMetadataHeader::parse(&row).map(|header| header.entity_type)
            != Some(ENTITY_TYPE_MESSAGE)
        {
            return Ok(ArtifactMessage::Missed);
        }
        let mut rows = vec![ArtifactRow {
            component: ArtifactComponent::Row,
            family: "entities",
            key: id.to_vec(),
            value: row,
        }];
        self.document_rows(entity, &mut rows)?;
        for (key, value) in self.scan(RowDb::EdgesOut, id) {
            rows.push(ArtifactRow {
                component: ArtifactComponent::Edge,
                family: "edges_out",
                key,
                value,
            });
        }
        self.revision_rows(id, &mut rows)?;
        Ok(ArtifactMessage::Held(rows))
    }

    /// Its document head, then that slot's rows and updates, as the live
    /// capture orders them.
    fn document_rows(&self, entity: &EntityId, rows: &mut Vec<ArtifactRow>) -> Result<()> {
        let head_key = crate::entity_doc::record_head_key(entity);
        let Some(head) = self.get(RowDb::VaultMeta, &head_key) else {
            return Ok(());
        };
        let slot: DocumentSlot = crate::entity_doc::record_head_slot(entity, &head)?;
        rows.push(ArtifactRow {
            component: ArtifactComponent::Document,
            family: "entity_doc:head",
            key: head_key,
            value: head,
        });
        let slot = slot.to_hex();
        for (family, prefix) in [
            ("document:snapshot", side_table::DOCUMENT_SNAPSHOT.prefix),
            (
                "document:state_vector",
                side_table::DOCUMENT_STATE_VECTOR.prefix,
            ),
            (
                "document:shallow_since",
                side_table::DOCUMENT_SHALLOW_SINCE.prefix,
            ),
            (
                "document:update_sequence",
                side_table::SYNC_M_U_SEQ_E.prefix,
            ),
        ] {
            let key = [prefix, slot.as_bytes()].concat();
            if let Some(value) = self.get(RowDb::SyncState, &key) {
                rows.push(ArtifactRow {
                    component: ArtifactComponent::Document,
                    family,
                    key,
                    value,
                });
            }
        }
        let updates = [side_table::DOCUMENT_UPDATE.prefix, slot.as_bytes(), b":"].concat();
        for (key, value) in self.scan(RowDb::SyncState, &updates) {
            rows.push(ArtifactRow {
                component: ArtifactComponent::Document,
                family: "document:update",
                key,
                value,
            });
        }
        Ok(())
    }

    /// Its revision ledger, as the live capture orders it: the history
    /// document, the state, each frontier in key order, then each of those
    /// frontiers' reverse identity rows that names this message.
    fn revision_rows(&self, id: &[u8; 16], rows: &mut Vec<ArtifactRow>) -> Result<()> {
        for (family, prefix) in [
            (
                "entity_revision:doc",
                side_table::ENTITY_REVISION_DOC.prefix,
            ),
            (
                "entity_revision:state",
                side_table::ENTITY_REVISION_STATE.prefix,
            ),
        ] {
            let key = [prefix, id.as_slice()].concat();
            if let Some(value) = self.get(RowDb::VaultMeta, &key) {
                rows.push(ArtifactRow {
                    component: ArtifactComponent::Revision,
                    family,
                    key,
                    value,
                });
            }
        }
        let frontiers = [side_table::ENTITY_REVISION_FRONTIER.prefix, id.as_slice()].concat();
        let mut revisions = Vec::new();
        for (key, value) in self.scan(RowDb::VaultMeta, &frontiers) {
            let revision = key
                .get(frontiers.len()..)
                .filter(|revision| revision.len() == 16)
                .ok_or(Error::CorruptedIndex("checkpoint revision frontier key"))?
                .to_vec();
            revisions.push(revision);
            rows.push(ArtifactRow {
                component: ArtifactComponent::Revision,
                family: "entity_revision:frontier",
                key,
                value,
            });
        }
        for revision in revisions {
            // Only the reverse identity that names this message is its own.
            let key = [side_table::ENTITY_REVISION_IDENTITY.prefix, &revision].concat();
            if let Some(value) = self.get(RowDb::VaultMeta, &key)
                && value.as_slice() == id.as_slice()
            {
                rows.push(ArtifactRow {
                    component: ArtifactComponent::Revision,
                    family: "entity_revision:identity",
                    key,
                    value,
                });
            }
        }
        Ok(())
    }
}

/// An opened owner's whole rows: each exact part, and each actor-keyed row
/// whose actor opened, as a restore composes it; a part an owner that did
/// not open holds up is left out, as a restore leaves it.
fn owner_parts(
    opened: &OpenedOwnerRows,
    parts: &mut BTreeMap<(RowDb, Vec<u8>), Vec<u8>>,
) -> Result<()> {
    let held = opened.held_up();
    for part in &opened.rows {
        let at = part.at();
        if held.contains(at) {
            continue;
        }
        match part {
            // A whole row; a member fragment is no stored row.
            RowPart::Exact { value, .. } if at.path.is_empty() => {
                parts.insert((at.db, at.key.clone()), value.clone());
            }
            RowPart::Exact { .. } => {}
            // Its placeholder's path names the actor-keyed slot; the row's
            // own key and value are in the actor part naming it.
            RowPart::ActorKeyed { .. } => {
                let actors: Vec<_> = opened
                    .actor_parts
                    .iter()
                    .filter(|actor| &actor.content_locator == at)
                    .collect();
                if let Some((row, value)) = actor_keyed_row(at, &actors)? {
                    let RowLocator { db, key, .. } = row;
                    parts.insert((db, key), value);
                }
            }
            // A no-one-form part is its getter's join's: the document join
            // above, or a family this extent does not carry.
            RowPart::NoActor { .. } => {}
        }
    }
    Ok(())
}

/// The image database a row's database is.
fn database_name(db: RowDb) -> &'static str {
    match db {
        RowDb::Entities => "entities",
        RowDb::EdgesOut => "edges_out",
        RowDb::EdgesIn => "edges_in",
        RowDb::VaultMeta => "vault_meta",
        RowDb::SyncState => "sync_state",
        RowDb::SyncQueue => "sync_queue",
    }
}
