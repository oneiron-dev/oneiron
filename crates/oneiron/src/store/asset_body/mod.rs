//! Core half of `store::asset_body`: its store-layer items live in `oneiron_store::asset_body` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::asset_body::*;

use super::{BodyDir, BodyFile, BodyKeyRow, ManifestDbs, Store, body_file_name};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::{ASSET_BODY_FILE, ASSET_BODY_HELD};
use crate::error::{Error, Result};
use crate::provenance::body::{
    publish_body_in_txn, release_body_in_txn, release_owner_bodies_in_txn,
};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::body_descriptor::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::store::owned_body::owned_body_in_txn;
use heed::{RoTxn, RwTxn};
pub(crate) use spool::AssetBodySpool;
pub(crate) use stage::{StagedAssetBody, StagedHold};
use std::io::{self, Read, Write};

mod read;
#[allow(dead_code, reason = "FIX 5489 PR3's body receive calls this")]
mod spool;
mod stage;

/// What the file plane may hold `body` as, judged whole; `None` keeps it in
/// its row. Neither kind is UTF-8 text, a body an owning adapter reads (the
/// serializer would attach it as a file), a container the secret mask reads
/// into, or a refinement carrier.
///
/// - [`AssetFileKind::Opaque`]: no MessagePack map with a string key leads
///   it, so no reader of ASSET bodies interprets it.
/// - [`AssetFileKind::Record`] (FIX 12150): it is one such map, ending where
///   the body ends, which the readers that decode it (a docs page's, an
///   export's) read whole through the file plane, and from which the
///   readers of a stored row ([`row_readers_read_nothing`]) read nothing.
///
/// A body led by a keyed map that runs on past it, or one a stored-row
/// reader reads, keeps the readers that read it whole in its row.
fn asset_file_kind(body: &[u8]) -> Option<AssetFileKind> {
    if !crate::serialize::attaches_as_file(ENTITY_TYPE_ASSET, body)
        || crate::batch::secret_scan::is_container(body)
        || crate::store::refinement_carrier::refinement_carrier_payload(body).is_some()
    {
        return None;
    }
    match keyed_map_len(body) {
        None => Some(AssetFileKind::Opaque),
        Some(len) if len == body.len() as u64 && row_readers_read_nothing(body) => {
            Some(AssetFileKind::Record)
        }
        Some(_) => None,
    }
}

/// Whether the readers that decode a stored ASSET row read nothing from the
/// record `body`: no `stale` mark, no named-entity query prefix and no
/// phonetic code. They read nothing from a manifest either, so a record that
/// keeps one in its row reads to them as it would whole (FIX 12150).
fn row_readers_read_nothing(body: &[u8]) -> bool {
    !crate::ports::body_is_stale(body)
        && !crate::ports::indexes_named_entity(ENTITY_TYPE_ASSET, body)
        && crate::batch::phonetic_codes::codes_for_body(ENTITY_TYPE_ASSET, body).is_empty()
}

/// The manifest of ASSET `id`'s body file when the row `body` it stores is
/// one: the ASSET owns a complete file descriptor at its current-file
/// occurrence, for the digest and length the manifest names. `None` for an
/// inline body, whatever its bytes, and for a body-less shell.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when the descriptor and the row disagree;
/// storage errors as they occur.
pub(crate) fn asset_file_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<AssetFileManifest>> {
    let occurrence = current_occurrence(id)?;
    let Some(held) = owned_body_in_txn(store, txn, id, &occurrence)? else {
        return Ok(None);
    };
    if body.is_empty() {
        return Ok(None);
    }
    // A room's inline row does not inherit the base row's file descriptor.
    if store.entities().stages_row(id.as_bytes())
        && !store
            .vault_meta()
            .stages_row(&super::owned_body::BODY.key_bytes(&(*id, occurrence)))
    {
        return Ok(None);
    }
    let manifest =
        AssetFileManifest::decode(body).ok_or(Error::CorruptedIndex("asset body manifest"))?;
    if held.state
        != (BodyState::Complete {
            body: manifest.facts.body_ref(),
        })
    {
        return Err(Error::CorruptedIndex("asset body manifest"));
    }
    Ok(Some(manifest))
}

/// [`asset_file_in_txn`] for a stored row, header and body: `None` for any
/// row that is not an ASSET's.
pub(crate) fn asset_file_of_raw_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<AssetFileManifest>> {
    match EntityMetadataHeader::parse(raw) {
        Some(header) if header.entity_type == ENTITY_TYPE_ASSET => {
            asset_file_in_txn(store, txn, id, &raw[ENTITY_METADATA_HEADER_LEN..])
        }
        _ => Ok(None),
    }
}

/// The body file a raw `entities` row names, as its digest and length:
/// `Some` only for a file-plane ASSET. A checkpoint reads its rows raw, so
/// this is how it finds the ASSET files beside them.
///
/// # Errors
///
/// A key that is no entity id, and [`asset_file_in_txn`]'s errors.
pub(crate) fn asset_body_file_of_row(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Option<([u8; 32], u64)>> {
    let id = EntityId::from_bytes(
        key.try_into()
            .map_err(|_| Error::CorruptedIndex("entity key"))?,
    )?;
    Ok(asset_file_of_raw_in_txn(store, txn, &id, value)?
        .map(|manifest| (manifest.facts.blake3, manifest.facts.len)))
}

/// The content-hash byte a short reference to the stored row `raw` of `id`
/// carries: its logical body's, so a file-plane ASSET's comes from its
/// manifest, never from the manifest's own bytes.
///
/// # Errors
///
/// [`asset_file_in_txn`]'s errors.
pub(crate) fn short_content_hash_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<u8> {
    Ok(match asset_file_of_raw_in_txn(store, txn, id, raw)? {
        Some(manifest) => manifest.facts.short_hash(),
        None => crate::batch::short_id_content_hash(
            raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default(),
        ),
    })
}

/// FIX 3677: the body file a local ASSET put's `data` would go to when it
/// is one ([`ASSET_INLINE_BODY_BYTES`], [`asset_file_kind`], a file the
/// secret mask did not mark). This runs inside the batch writer, and a body
/// file is one vault instance whose key is minted before any writer opens
/// (KS-2A): so the body stays in its row, which a checkpoint seals under an
/// instance of its own. A put that files a long body stages it before its
/// writer ([`crate::Vault::stage_asset_body`]). `None` keeps the body in its
/// row.
///
/// # Errors
///
/// Storage errors as they occur.
pub(crate) fn file_put_body_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity_type: u8,
    data: &[u8],
) -> Result<Option<(Vec<u8>, AssetBodyFacts)>> {
    if entity_type != ENTITY_TYPE_ASSET
        || data.len() as u64 <= ASSET_INLINE_BODY_BYTES
        || !ASSET_FILE_PLANE
        || asset_file_kind(data).is_none()
    {
        return Ok(None);
    }
    // A marked file keeps its row: a serving door reads its keys' spans over
    // the bytes it holds. Any other stays there too, with no instance minted
    // inside this writer.
    crate::store::file_key_masks::masked_file_in_txn(store, txn, &AssetBodyFacts::of(data).blake3)?;
    Ok(None)
}

/// Binds ASSET `id`'s body file to the row a put just staged, in the put's
/// transaction: `file` is the body's facts when the row `body` is its
/// manifest, `None` when the row holds the body itself. The file the row
/// held before is released, unless a legal hold stands on the record: then
/// it stays, held by the record, until the record is erased.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when `file` and the row's manifest
/// disagree, or the file is not published; storage errors as they occur.
pub(crate) fn stage_asset_body_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
    file: Option<AssetBodyFacts>,
) -> Result<()> {
    let occurrence = current_occurrence(id)?;
    let next = match file {
        Some(facts) => {
            if AssetFileManifest::decode(body).is_none_or(|manifest| manifest.facts != facts) {
                return Err(Error::InvariantViolation(
                    "an asset body file's row holds its own manifest",
                ));
            }
            // The bytes are durable before any row names them, and a sealed
            // file's key row before the row naming it (FIX 5348).
            let key = super::body_key_row_in_txn(store, txn, &facts.blake3)?;
            if store
                .body_dir()?
                .open_reader(&facts.blake3, facts.len, key.as_ref())?
                .is_none()
            {
                return Err(Error::InvariantViolation(
                    "an asset body file is published before its row",
                ));
            }
            Some(OwnedBody {
                owner: *id,
                occurrence,
                state: BodyState::Complete {
                    body: facts.body_ref(),
                },
                result: None,
            })
        }
        None => None,
    };
    let prior = owned_body_in_txn(store, txn, id, &occurrence)?;
    if prior == next {
        return Ok(());
    }
    if crate::store::legal_hold::held_in_txn(store, txn, id.as_bytes())? {
        if let Some(superseded) = prior.as_ref().and_then(|prior| prior.state.held()) {
            publish_body_in_txn(
                store,
                txn,
                &OwnedBody {
                    owner: *id,
                    occurrence: held_occurrence(id, superseded)?,
                    state: BodyState::Complete {
                        body: superseded.clone(),
                    },
                    result: None,
                },
            )?;
        }
        release_body_in_txn(store, txn, id, &occurrence)?;
    } else {
        release_owner_bodies_in_txn(store, txn, id)?;
    }
    if let Some(next) = next {
        publish_body_in_txn(store, txn, &next)?;
    }
    Ok(())
}

impl BodyDir {
    /// Copies in the ASSET body file with `digest` from `source`, checking
    /// its digest and length as it streams, unless this directory holds it
    /// already. Raw: no line index, no preview, no scan, whatever its size.
    /// A sealed directory imports through its envelope.
    pub(crate) fn import_asset_body(
        &self,
        digest: &[u8; 32],
        len: u64,
        source: &mut impl Read,
    ) -> Result<()> {
        if self.sealed.is_some() {
            return Err(Error::InvariantViolation(
                "a sealed body directory imports through its envelope",
            ));
        }
        if self.open_body(digest, len)?.is_some() {
            return Ok(());
        }
        let (mut file, temp) = self.create_temp()?;
        let mut hasher = blake3::Hasher::new();
        let mut copied = 0u64;
        let mut frame = vec![0; super::LINE_INDEX_BLOCK_BYTES as usize];
        let written = loop {
            let read = match source.read(&mut frame) {
                Ok(0) => break Ok(()),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => break Err(Error::from(error)),
            };
            hasher.update(&frame[..read]);
            copied = copied.saturating_add(read as u64);
            if let Err(error) = file.write_all(&frame[..read]) {
                break Err(error.into());
            }
        };
        let checked = written.and_then(|()| {
            if copied == len && *hasher.finalize().as_bytes() == *digest {
                Ok(())
            } else {
                Err(Error::CorruptedIndex("restored asset body digest"))
            }
        });
        if let Err(error) = checked {
            self.discard(&temp);
            return Err(error);
        }
        self.publish(file, &temp, &body_file_name(digest))
    }
}

/// One ASSET body file read as it streams, checked against its manifest's
/// length and BLAKE3: the read that reaches its end fails if either differs.
pub(crate) struct CheckedAssetBody {
    file: BodyFile,
    facts: AssetBodyFacts,
    hasher: blake3::Hasher,
    read: u64,
    checked: bool,
}

impl CheckedAssetBody {
    /// The body file `facts` names in `dir`, as `key`, its key row in the
    /// snapshot that found its row, names it.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when the file is missing or of another
    /// length.
    pub(crate) fn open(
        dir: &BodyDir,
        facts: &AssetBodyFacts,
        key: Option<&BodyKeyRow>,
    ) -> Result<Self> {
        let file = dir
            .open_reader(&facts.blake3, facts.len, key)?
            .ok_or(Error::CorruptedIndex("asset body file missing"))?;
        Ok(Self {
            file,
            facts: *facts,
            hasher: blake3::Hasher::new(),
            read: 0,
            checked: false,
        })
    }

    /// Reads whatever the reader left, so a reader that stopped early still
    /// has the whole body checked.
    ///
    /// # Errors
    ///
    /// The check's error, or the file's.
    pub(crate) fn finish(mut self) -> Result<()> {
        io::copy(&mut self, &mut io::sink())?;
        Ok(())
    }

    /// The whole body, checked.
    ///
    /// # Errors
    ///
    /// As [`Self::open`], and the check's error.
    pub(crate) fn read_all(
        dir: &BodyDir,
        facts: &AssetBodyFacts,
        key: Option<&BodyKeyRow>,
    ) -> Result<Vec<u8>> {
        let mut reader = Self::open(dir, facts, key)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(facts.len)
                .map_err(|_| Error::InvariantViolation("asset body past this machine's memory"))?,
        );
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Read for CheckedAssetBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let read = self.file.read(out)?;
        if read == 0 {
            if !self.checked {
                if self.read != self.facts.len
                    || *self.hasher.finalize().as_bytes() != self.facts.blake3
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "asset body file digest",
                    ));
                }
                self.checked = true;
            }
            return Ok(0);
        }
        self.read = self.read.saturating_add(read as u64);
        if self.read > self.facts.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "asset body file length",
            ));
        }
        self.hasher.update(&out[..read]);
        Ok(read)
    }
}
