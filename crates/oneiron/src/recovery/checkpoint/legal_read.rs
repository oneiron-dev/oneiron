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
use std::io::Read;

use super::artifact::SealedBodies;
use super::payload::{Getter, SelectedPayload, open_selected_payload};
use super::{CanonicalRows, CheckpointImage, CheckpointKey, artifact, image};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::DocumentSlot;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::side_table;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{
    OpenedOwnerRows, OwnerRef, RowDb, RowLocator, RowPart, actor_keyed_row,
};
use crate::store::{
    CheckpointCustody, LiveCustody, SealedStream, body_key_in, require_body_instances,
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

/// One opened artifact a legal read draws on: its image (the rows naming an
/// owner that did not open already out), the bodies it carries, the custody
/// plan the read built and the selected owners' opened compartments.
pub(crate) struct ArtifactRead<'k> {
    image: CheckpointImage,
    bodies: SealedBodies<'k>,
    custody: CheckpointCustody,
    payload: Option<SelectedPayload>,
}

/// Opens the artifact in `file` with `key` through the real opener (vault,
/// signed commitment, manifest, chunks and image checked, the signer under
/// the key's trust), checks its verified identity against `expected`, then
/// builds its custody plan from `live` (`preflight_legal_read_rejected`) and
/// opens the compartments of `ids` alone: each one's entity tree and the
/// attachment occurrences it holds, beside every actor group. The rows
/// naming an owner that did not open are taken out first, as a restore
/// takes them.
///
/// # Errors
///
/// An artifact that does not open or decode, another vault's, a signer the
/// key does not trust, an identity other than `expected`
/// ([`ArtifactRefusal`]), custody of another lineage
/// (`custody_lineage_mismatch`) or missing, and a compartment that does not
/// read back as sealed.
pub(crate) fn open_artifact_read<'k>(
    file: File,
    key: &'k CheckpointKey,
    expected: &VerifiedArtifact,
    live: &LiveCustody,
    ids: &[[u8; 16]],
) -> std::result::Result<ArtifactRead<'k>, LegalReadError> {
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
    let selected: BTreeSet<[u8; 16]> = ids.iter().copied().collect();
    let payload = open_selected_payload(
        bodies.payload.take(),
        custody.plan_mut(),
        &mut image,
        |owner| {
            matches!(
                owner.subtype,
                Subtype::EntityTree | Subtype::AttachmentOccurrence
            ) && owner.owner32[..16]
                .try_into()
                .is_ok_and(|id: [u8; 16]| selected.contains(&id))
                && (owner.subtype == Subtype::AttachmentOccurrence
                    || owner.owner32[16..].iter().all(|byte| *byte == 0))
        },
    )
    .map_err(Error::from)?;
    Ok(ArtifactRead {
        image,
        bodies,
        custody,
        payload,
    })
}

impl ArtifactRead<'_> {
    /// Selected message `id` as the artifact holds it.
    pub(crate) fn message(&self, id: &[u8; 16]) -> Result<ArtifactMessage> {
        let entity = EntityId::from_bytes(*id)?;
        MessageSource::new(&self.image.databases, self.payload.as_ref(), &entity)?
            .message(id, &entity)
    }

    /// The exact body descriptor row `message` holds for its attachment
    /// `occurrence`, read from that occurrence's own compartment when it
    /// opened; none otherwise.
    pub(crate) fn result_descriptor(
        &self,
        message: &EntityId,
        occurrence: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let owner = OwnerRef::occurrence(message, occurrence);
        let Some(payload) = self
            .payload
            .as_ref()
            .filter(|payload| payload.opened(owner))
        else {
            return Ok(None);
        };
        let key = crate::store::owned_body::BODY.key_bytes(&(*message, *occurrence));
        let mut parts = BTreeMap::new();
        for opened in payload.contents(owner, Getter::ProvenanceBody) {
            owner_parts(opened, &mut parts)?;
        }
        Ok(parts.remove(&(RowDb::VaultMeta, key)))
    }

    /// The result body the artifact carries for the raw-output row at `key`
    /// with BLAKE3 `digest` and length `len`, read back through its sealed
    /// chunks and opened under current custody of its instance, each frame
    /// checked as it is read. None when the artifact carries no such body,
    /// or custody no longer opens its instance (an erase or release retired
    /// it): uncaptured, never another source's bytes.
    pub(crate) fn result_body(
        &mut self,
        key: &[u8],
        digest: [u8; 32],
        len: u64,
    ) -> Option<Box<dyn Read + '_>> {
        let files = self.image.bodies.len();
        let inline = self.image.inline_bodies.iter().position(|carried| {
            carried.database == "vault_meta"
                && carried.key == key
                && carried.digest == digest
                && carried.len == len
                && carried.retired.is_none()
                && carried.replay.is_none()
                && !carried.opaque
        });
        let found = match inline {
            Some(index) => Some((files + index, self.image.inline_bodies[index].instance)),
            None => self
                .image
                .bodies
                .iter()
                .position(|body| *body == (digest, len))
                .and_then(|index| {
                    let file = self.image.sealed_bodies.get(&(index as u64))?;
                    Some((index, file.instance))
                }),
        };
        let (stream, instance) = found?;
        let plan = self.custody.plan_mut();
        let binding = plan.source().cloned()?;
        // Retired, or with no custody here: the body stays uncaptured.
        if !require_body_instances(&BTreeSet::from([instance]), plan)
            .is_ok_and(|retired| retired.is_empty())
        {
            return None;
        }
        let file_key = body_key_in(&binding, &instance).ok()?;
        Some(Box::new(SealedStream::plaintext(
            self.bodies.body(stream),
            file_key,
            digest,
            len,
        )))
    }
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
