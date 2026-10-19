//! ASSET bodies on the file plane (FIX 3677; Engine rule (b), 10-18).
//!
//! An ASSET body longer than [`ASSET_INLINE_BODY_BYTES`] whose bytes no
//! reader interprets ([`opaque_body`]: no UTF-8 text, no owning adapter's
//! envelope, no container the secret mask reads into, no structured record,
//! no file the mask marked) lives in the vault's `bodies/` directory as one
//! file named by its BLAKE3, beside the result bodies and under their
//! lifetime. It is written to a `.tmp-` file, synced, renamed into place and
//! the directory synced before any row names it. Its ASSET row keeps a small
//! manifest instead of the bytes ([`AssetFileManifest`]), and the ASSET owns
//! the file through one provenance body descriptor, published in the
//! transaction that writes the row.
//!
//! The row bytes never decide which a row is: an ASSET row is a file exactly
//! when the ASSET owns a complete file descriptor at its current-file
//! occurrence, for the digest and length its manifest names
//! ([`asset_file_in_txn`]). An inline ASSET may hold any bytes, a manifest's
//! included; the descriptor moves with every write of the row.
//!
//! Every other body stays in its row as before, and so does every body of a
//! sealed (maximum-tier) vault until a per-file key envelope lands (FIX
//! 3677, L04). The bound picks where a body lives and never refuses one
//! (Rule 5).
//!
//! A crash before the rename leaves a `.tmp-` file, which the writer-open
//! sweep removes. A crash or abort after it leaves a file no descriptor
//! names, which the result body collector's orphan sweep removes. The row
//! and its descriptor publish together, after the bytes are durable, so no
//! incomplete ASSET is ever visible (CALLS "ASSET body file crash").
//!
//! A write that replaces the body releases the file it superseded, which
//! goes once no descriptor and no reader pin holds its digest; under a legal
//! hold on the record the superseded file is kept, held by the record, until
//! the record is erased (CALLS "ASSET body file revisions").

mod read;
mod stage;

use std::fs::File;
use std::io::{self, Read, Write};

use heed::{RoTxn, RwTxn};

use super::{BodyDir, ManifestDbs, Store, body_file_name};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::{ASSET_BODY_FILE, ASSET_BODY_HELD};
use crate::error::{Error, Result};
use crate::provenance::body::{
    BodyLocation, BodyRef, BodyState, OwnedBody, owned_body_in_txn, publish_body_in_txn,
    release_body_in_txn, release_owner_bodies_in_txn,
};
use crate::registry::ENTITY_TYPE_ASSET;

/// FIX 3677 (CALLS "ASSET inline body bound"): an opaque ASSET body longer
/// than this lives in a body file; a body this long or shorter, and every
/// body that is not opaque, stays in its row. It picks where a body lives
/// and never refuses one (Rule 5). The sync transport's frame holds as much.
pub(crate) const ASSET_INLINE_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// A manifest's first byte: no UTF-8 text and no MessagePack value starts
/// with it, so no reader of ASSET bodies takes a manifest for text, a record
/// or an owning adapter's envelope. It frames the manifest; it decides
/// nothing about the row.
const MANIFEST_LEAD: u8 = 0xc1;
const MANIFEST_TAG: &[u8] = b"oneiron.asset-file.v1\0";

/// What the file plane holds an ASSET body as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssetFileKind {
    /// Bytes no reader interprets, kept exactly as written.
    Opaque,
}

impl AssetFileKind {
    const fn code(self) -> u8 {
        match self {
            Self::Opaque => 1,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Opaque),
            _ => None,
        }
    }
}

/// An ASSET body's facts, measured as it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssetBodyFacts {
    pub(crate) blake3: [u8; 32],
    pub(crate) len: u64,
    /// `xxh32(body, 0)`: a short reference hashes the logical body, never
    /// its manifest.
    pub(crate) xxh32: u32,
}

impl AssetBodyFacts {
    pub(crate) fn of(body: &[u8]) -> Self {
        Self {
            blake3: *blake3::hash(body).as_bytes(),
            len: body.len() as u64,
            xxh32: xxhash_rust::xxh32::xxh32(body, 0),
        }
    }

    /// The content-hash byte a short reference to this body carries, as
    /// [`crate::batch::short_id_content_hash`] reads a row's bytes.
    pub(crate) const fn short_hash(&self) -> u8 {
        (self.xxh32 % 256) as u8
    }

    const fn body_ref(&self) -> BodyRef {
        BodyRef {
            blake3: self.blake3,
            bytes: self.len,
            location: BodyLocation::File,
        }
    }
}

/// What a file-plane ASSET row holds in place of its body: the body's
/// length, BLAKE3 and `xxh32`, its kind and its media type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetFileManifest {
    pub(crate) facts: AssetBodyFacts,
    pub(crate) kind: AssetFileKind,
    pub(crate) mime: Option<String>,
}

impl AssetFileManifest {
    /// The row bytes: the lead byte and tag, the digest, the length (u64
    /// big-endian), `xxh32` (u32 big-endian), the kind byte, a media-type
    /// presence byte, its length (u16 big-endian) and its UTF-8.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a media type past 65535 bytes, the
    /// format's bound.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mime = self.mime.as_deref().unwrap_or_default();
        let mime_len = u16::try_from(mime.len()).map_err(|_| {
            Error::InvalidConfig("an asset body's media type is past 65535 bytes".to_owned())
        })?;
        let mut bytes = Vec::with_capacity(MANIFEST_TAG.len() + 49 + mime.len());
        bytes.push(MANIFEST_LEAD);
        bytes.extend_from_slice(MANIFEST_TAG);
        bytes.extend_from_slice(&self.facts.blake3);
        bytes.extend_from_slice(&self.facts.len.to_be_bytes());
        bytes.extend_from_slice(&self.facts.xxh32.to_be_bytes());
        bytes.push(self.kind.code());
        bytes.push(u8::from(self.mime.is_some()));
        bytes.extend_from_slice(&mime_len.to_be_bytes());
        bytes.extend_from_slice(mime.as_bytes());
        Ok(bytes)
    }

    /// The manifest `bytes` encode, read strictly: `None` for any other
    /// bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (&lead, rest) = bytes.split_first()?;
        if lead != MANIFEST_LEAD {
            return None;
        }
        let rest = rest.strip_prefix(MANIFEST_TAG)?;
        let (blake3, rest) = rest.split_first_chunk::<32>()?;
        let (len, rest) = rest.split_first_chunk::<8>()?;
        let (xxh32, rest) = rest.split_first_chunk::<4>()?;
        let (&kind, rest) = rest.split_first()?;
        let (&has_mime, rest) = rest.split_first()?;
        let (mime_len, rest) = rest.split_first_chunk::<2>()?;
        if rest.len() != usize::from(u16::from_be_bytes(*mime_len)) {
            return None;
        }
        let mime = match has_mime {
            0 if rest.is_empty() => None,
            1 => Some(std::str::from_utf8(rest).ok()?.to_owned()),
            _ => return None,
        };
        Some(Self {
            facts: AssetBodyFacts {
                blake3: *blake3,
                len: u64::from_be_bytes(*len),
                xxh32: u32::from_be_bytes(*xxh32),
            },
            kind: AssetFileKind::from_code(kind)?,
            mime,
        })
    }
}

/// The occurrence of ASSET `id`'s current body file: one per ASSET, moved
/// as its row changes.
fn current_occurrence(id: &EntityId) -> Result<EntityId> {
    EntityId::derive(ASSET_BODY_FILE, &[id.as_bytes()])
}

/// The occurrence a legal hold keeps a superseded body file of `id` under.
fn held_occurrence(id: &EntityId, body: &BodyRef) -> Result<EntityId> {
    EntityId::derive(
        ASSET_BODY_HELD,
        &[id.as_bytes(), &body.blake3, &body.bytes.to_be_bytes()],
    )
}

/// FIX 3677: the file plane stays off until the raw ASSET readers other lanes
/// own (sync egress, scoped reads, blob holders, taint, federation export,
/// codebase ingest) read a manifest's file; the PR's FIX lines name each one.
/// Off, every ASSET body stays in its row exactly as before; on is this line.
pub(crate) const ASSET_FILE_PLANE: bool = false;

/// Whether every ASSET body stays in its row: the file plane is off, or this
/// store's pages are sealed (the maximum tier), which keeps bodies inline
/// until a per-file key envelope makes a file's unlink a crypto-shred
/// (FIX 3677, L04).
fn keeps_bodies_inline(store: &Store) -> bool {
    !ASSET_FILE_PLANE || heed::Env::is_sealed(&store.env)
}

/// Whether `body` is bytes no reader of ASSET bodies interprets: no UTF-8
/// text and no body an owning adapter reads (the serializer would attach it
/// as a file), no container the secret mask reads into, no refinement
/// carrier, and no MessagePack map with a string key (a record a named
/// index, a media reader or the stale mark reads). Only such a body lives in
/// a file; the others keep the readers that read them whole.
fn opaque_body(body: &[u8]) -> bool {
    crate::serialize::attaches_as_file(ENTITY_TYPE_ASSET, body)
        && !crate::batch::secret_scan::is_container(body)
        && crate::skill_hub::refinement_carrier_payload(body).is_none()
        && !leads_with_keyed_map(body)
}

/// Whether `body`'s first MessagePack value is a map with a string key.
fn leads_with_keyed_map(body: &[u8]) -> bool {
    match rmpv::decode::read_value(&mut io::Cursor::new(body)) {
        Ok(rmpv::Value::Map(entries)) => entries.iter().any(|(key, _)| key.is_str()),
        _ => false,
    }
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
    let Some(held) = owned_body_in_txn(store, txn, id, &current_occurrence(id)?)? else {
        return Ok(None);
    };
    if body.is_empty() {
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

/// FIX 3677: the body file a local ASSET put's `data` goes to when it is one
/// ([`ASSET_INLINE_BODY_BYTES`], [`opaque_body`], an unsealed vault, a file
/// the secret mask did not mark): the file is published from `data` as it
/// is, no second copy, and the manifest the row keeps instead is returned
/// with the body's facts. `None` keeps the body in its row.
///
/// # Errors
///
/// Storage and filesystem errors as they occur.
pub(crate) fn file_put_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity_type: u8,
    data: &[u8],
) -> Result<Option<(Vec<u8>, AssetBodyFacts)>> {
    if entity_type != ENTITY_TYPE_ASSET
        || data.len() as u64 <= ASSET_INLINE_BODY_BYTES
        || keeps_bodies_inline(store)
        || !opaque_body(data)
    {
        return Ok(None);
    }
    let facts = AssetBodyFacts::of(data);
    // A marked file keeps its row: a serving door reads its keys' spans over
    // the bytes it holds.
    if crate::secret_custody::masked_file_in_txn(store, txn, &facts.blake3)?.is_some() {
        return Ok(None);
    }
    store.body_dir()?.publish_asset_body(&facts, data)?;
    let manifest = AssetFileManifest {
        facts,
        kind: AssetFileKind::Opaque,
        mime: None,
    };
    Ok(Some((manifest.encode()?, facts)))
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
            // The bytes are durable before any row names them.
            let dir = store.body_dir()?;
            if dir.open_body(&facts.blake3, facts.len)?.is_none() {
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
    /// Publishes `body`, whose facts are `facts`, as its file, unless this
    /// directory holds it already.
    pub(crate) fn publish_asset_body(&self, facts: &AssetBodyFacts, body: &[u8]) -> Result<()> {
        if self.open_body(&facts.blake3, facts.len)?.is_some() {
            return Ok(());
        }
        let (mut file, temp) = self.create_temp()?;
        if let Err(error) = file.write_all(body) {
            self.discard(&temp);
            return Err(error.into());
        }
        self.publish(file, &temp, &body_file_name(&facts.blake3))
    }

    /// Copies in the ASSET body file with `digest` from `source`, checking
    /// its digest and length as it streams, unless this directory holds it
    /// already. Raw: no line index, no preview, no scan, whatever its size.
    pub(crate) fn import_asset_body(
        &self,
        digest: &[u8; 32],
        len: u64,
        source: &mut impl Read,
    ) -> Result<()> {
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
    file: File,
    facts: AssetBodyFacts,
    hasher: blake3::Hasher,
    read: u64,
    checked: bool,
}

impl CheckedAssetBody {
    /// The body file `facts` names in `dir`.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when the file is missing or of another
    /// length.
    pub(crate) fn open(dir: &BodyDir, facts: &AssetBodyFacts) -> Result<Self> {
        let file = dir
            .open_body(&facts.blake3, facts.len)?
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
    pub(crate) fn read_all(dir: &BodyDir, facts: &AssetBodyFacts) -> Result<Vec<u8>> {
        let mut reader = Self::open(dir, facts)?;
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
