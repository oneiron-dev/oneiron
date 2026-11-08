//! ASSET bodies on the file plane (FIX 3677; Engine rule (b), 10-18).
//!
//! An ASSET body longer than [`ASSET_INLINE_BODY_BYTES`] that the file plane
//! holds ([`asset_file_kind`]: bytes no reader interprets, a MessagePack
//! record whose readers read it whole (FIX 12150), text or a container the
//! batch door reads whole (FIX 22075), or an owning adapter's carrier its
//! adapter reads whole (FIX 22091); never a file the mask marked) lives in
//! the vault's `bodies/` directory as one file named by its
//! BLAKE3, beside the result bodies and under their lifetime. It is written
//! to a `.tmp-` file, synced, renamed into place and the directory synced
//! before any row names it. Its ASSET row keeps a small
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
//! Every other body stays in its row as before. A sealed (maximum-tier)
//! vault's body file is an envelope under a key of its own, whose key row
//! commits with the row and descriptor (FIX 5348, `body_envelope`). The bound
//! picks where a body lives and never refuses one (Rule 5).
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
#[allow(dead_code, reason = "FIX 5489 PR3's body receive calls this")]
mod spool;
mod stage;

pub(crate) use read::asset_carrier_body_in_txn;
pub(crate) use spool::AssetBodySpool;
pub(crate) use stage::{StagedAssetBody, StagedHold};

use std::io::{self, Read, Write};

use heed::{RoTxn, RwTxn};

use super::{BodyDir, BodyFile, BodyKeyRow, ManifestDbs, Store, body_file_name};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::{ASSET_BODY_FILE, ASSET_BODY_HELD, ASSET_BODY_REVISION};
use crate::error::{Error, Result};
use crate::provenance::body::{owned_bodies_in_txn, publish_body_in_txn, release_body_in_txn};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::body_descriptor::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::store::owned_body::owned_body_in_txn;

/// FIX 3677 (CALLS "ASSET inline body bound"): an ASSET body longer than
/// this lives in a body file when it is staged with an instance, an owning
/// adapter's carrier too (FIX 22091); a body this long or shorter stays in
/// its row.
/// It picks where a body lives and never refuses one (Rule 5). The sync
/// transport's frame holds as much.
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
    /// One MessagePack map with a string key, kept exactly as written (FIX
    /// 12150): the readers that decode it read it whole through the file
    /// plane, which hands back the same bytes, and the readers of a stored
    /// row read nothing from it, as from its manifest.
    Record,
    /// Bytes a reader interprets: UTF-8 text, a container (ZIP, gzip, PDF
    /// and the rest the secret scan opens), or a body a stream rule of the
    /// write door hits, kept exactly as written (FIX 22075). The batch
    /// door's secret scan and mask read the file's bytes as they read a body
    /// in its row, and mark it by its digest; its readers read it whole
    /// through the file plane.
    Interpreted,
    /// An owning adapter's carrier, valid or not ([`owning_adapter_reads`]:
    /// a hub source or package, a pack source, a receipt archive source, a
    /// refinement receipt, an agent's birth source, a vault shape seed), kept
    /// exactly as written (FIX 22091). Its adapter's readers and put checks
    /// read it whole through [`asset_carrier_body_in_txn`]; no other file
    /// kind holds a carrier, so they never read one. The batch door's secret
    /// scan and mask read its bytes as they read an interpreted file's.
    Carrier,
}

impl AssetFileKind {
    /// The kind's byte, in a manifest and in a sync body reference alike.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Opaque => 1,
            Self::Record => 2,
            Self::Interpreted => 3,
            Self::Carrier => 4,
        }
    }

    /// The kind a [`Self::code`] byte names.
    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Opaque),
            2 => Some(Self::Record),
            3 => Some(Self::Interpreted),
            4 => Some(Self::Carrier),
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

/// The occurrence `id`'s revisions keep the body file of its stored row
/// `row` under once a later write supersedes that row (FIX 22091): one per
/// stored row, header and manifest, so it names the exact row a revision
/// holds and never another row with the same bytes in its body; apart from
/// a legal hold's, so either lets go alone.
fn revision_occurrence(id: &EntityId, row: &[u8]) -> Result<EntityId> {
    EntityId::derive(ASSET_BODY_REVISION, &[id.as_bytes(), row])
}

/// The manifest `row`, a stored row of `id`, holds: `None` for any row that
/// is not an ASSET's or whose body is no manifest.
fn manifest_of_row(row: &[u8]) -> Option<AssetFileManifest> {
    EntityMetadataHeader::parse(row)
        .filter(|header| header.entity_type == ENTITY_TYPE_ASSET)
        .and_then(|_| row.get(ENTITY_METADATA_HEADER_LEN..))
        .and_then(AssetFileManifest::decode)
}

/// ASSET `id`'s stored row, when its body is a manifest: what a put that
/// replaces it hands [`stage_asset_body_in_txn`], which keeps its file for
/// the revision that row becomes when the current descriptor shows it was
/// filed (FIX 22091). Read before the put stages its own row.
///
/// # Errors
///
/// Storage errors as they occur.
pub(crate) fn superseded_file_row_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, id, |row| {
            Ok(manifest_of_row(row).map(|_| row.to_vec()))
        })?
        .flatten(),
    )
}

/// The body file a stored revision `raw` of ASSET `id` names, when `id`'s
/// revisions keep it: a later write superseded that exact row while it was
/// filed (FIX 22091). `None` for any row that is not an ASSET's, an inline
/// revision whatever its bytes, and a file no descriptor keeps for it,
/// which keeps the manifest it was stored as. The live row is the current
/// descriptor's to resolve.
///
/// # Errors
///
/// Storage errors as they occur.
pub(crate) fn revision_file_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<AssetFileManifest>> {
    let Some(manifest) = manifest_of_row(raw) else {
        return Ok(None);
    };
    let kept = owned_body_in_txn(store, txn, id, &revision_occurrence(id, raw)?)?;
    Ok(kept
        .is_some_and(|kept| {
            kept.state
                == BodyState::Complete {
                    body: manifest.facts.body_ref(),
                }
        })
        .then_some(manifest))
}

/// [`short_content_hash_in_txn`] for a selected revision `raw` of `id`, the
/// one hash every pinned reference to a revision is minted and checked by:
/// the live row's as that; an older one's from the manifest of the file its
/// revisions keep ([`revision_file_in_txn`]), else from its stored body, as
/// an inline revision's.
///
/// # Errors
///
/// [`short_content_hash_in_txn`]'s errors, and storage errors.
pub(crate) fn revision_content_hash_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<u8> {
    let live =
        crate::ports::EntityStoreRead::port_entity_with_raw(
            store,
            txn,
            id,
            |live| Ok(live == raw),
        )?;
    if live == Some(true) {
        return short_content_hash_in_txn(store, txn, id, raw);
    }
    Ok(match revision_file_in_txn(store, txn, id, raw)? {
        Some(manifest) => manifest.facts.short_hash(),
        None => crate::batch::short_id_content_hash(
            raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default(),
        ),
    })
}

/// Releases `id`'s current body file and each one a legal hold kept, once
/// the hold has lifted; the files its revisions keep stay (FIX 22091).
fn release_unkept_bodies_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    current: &EntityId,
) -> Result<()> {
    for owned in owned_bodies_in_txn(store, txn, id)? {
        let released = owned.occurrence == *current
            || match owned.state.held() {
                Some(body) => owned.occurrence == held_occurrence(id, body)?,
                None => false,
            };
        if released {
            release_body_in_txn(store, txn, id, &owned.occurrence)?;
        }
    }
    Ok(())
}

/// Publishes `id`'s descriptor of the superseded body file `body` under
/// `occurrence`.
fn keep_superseded_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    occurrence: EntityId,
    body: &BodyRef,
) -> Result<()> {
    publish_body_in_txn(
        store,
        txn,
        &OwnedBody {
            owner: *id,
            occurrence,
            mark_occurrence: occurrence,
            state: BodyState::Complete { body: body.clone() },
            result: None,
            code_run_output: None,
        },
    )
}

/// FIX 3677: the file plane is on. A long opaque ASSET body lives in its
/// body file; sync carries its row by reference and moves the body outside
/// Loro (FIX 5489), an offline bundle carries it as a file part and a point
/// read serves it whole (FIX 5532). Off, every ASSET body stays in its row
/// exactly as before; off is this line. A sealed vault's files are
/// envelopes (FIX 5348).
pub(crate) const ASSET_FILE_PLANE: bool = true;

/// What the file plane may hold `body` as, judged whole; `None` keeps it in
/// its row.
///
/// - [`AssetFileKind::Carrier`] (FIX 22091): an owning adapter reads it
///   ([`owning_adapter_reads`]), whose readers and put checks read it whole
///   through [`asset_carrier_body_in_txn`].
/// - [`AssetFileKind::Interpreted`] (FIX 22075): UTF-8 text or a container
///   the secret scan opens, which the batch door reads whole.
/// - [`AssetFileKind::Opaque`]: no MessagePack map with a string key leads
///   it, so no reader of ASSET bodies interprets it.
/// - [`AssetFileKind::Record`] (FIX 12150): it is one such map, ending where
///   the body ends, which the readers that decode it (a docs page's, an
///   export's) read whole through the file plane.
///
/// The readers of a stored row read nothing from any file
/// ([`row_readers_read_nothing`]), so a body they read keeps its row, as
/// does one led by a keyed map that runs on past it.
fn asset_file_kind(body: &[u8]) -> Option<AssetFileKind> {
    let kind = if owning_adapter_reads(body) {
        AssetFileKind::Carrier
    } else if std::str::from_utf8(body).is_ok() || crate::batch::secret_scan::is_container(body) {
        AssetFileKind::Interpreted
    } else {
        return match keyed_map_len(body) {
            None => Some(AssetFileKind::Opaque),
            Some(len) if len == body.len() as u64 && row_readers_read_nothing(body) => {
                Some(AssetFileKind::Record)
            }
            Some(_) => None,
        };
    };
    row_readers_read_nothing(body).then_some(kind)
}

/// Whether an owning adapter reads `body` as its carrier, valid or not, as
/// its decoder names one (FIX 22091): a hub source or a hub package
/// envelope, a pack source, a receipt archive source, a refinement receipt,
/// an agent's birth source or a vault shape seed. Its put checks refuse an
/// invalid one; the file plane holds either as a carrier, so the readers
/// that would refuse it read it.
fn owning_adapter_reads(body: &[u8]) -> bool {
    !matches!(
        crate::store::skill_source_carrier::decode_source_carrier(body),
        Ok(None)
    ) || crate::skill_hub::pack_catalog::names_pack_source(body)
        || crate::store::receipt_identity::is_receipt_archive_source(body)
        || crate::store::refinement_carrier::refinement_carrier_payload(body).is_some()
        || crate::agent_def::is_birth_source_candidate(body)
        || crate::vault_shape::names_shape_seed(body)
}

/// The length of `body`'s first MessagePack value when it is a map with a
/// string key, `None` for any other body.
fn keyed_map_len(body: &[u8]) -> Option<u64> {
    let mut cursor = io::Cursor::new(body);
    match rmpv::decode::read_value(&mut cursor) {
        Ok(rmpv::Value::Map(entries)) if entries.iter().any(|(key, _)| key.is_str()) => {
            Some(cursor.position())
        }
        _ => None,
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

/// FIX 3677: the body file a local ASSET put's `data` goes to when it is
/// one ([`ASSET_INLINE_BODY_BYTES`], [`asset_file_kind`], a file the secret
/// mask did not mark): the manifest its row keeps, and the body's facts.
/// This runs inside the batch writer, after the door's scan and mask read
/// the body. A body file is one vault instance whose key is minted before
/// any writer opens (KS-2A), so the file takes one the store's pool minted
/// before this write took the writer (FIX 22091); the file is published
/// and its key row bound here, and the put binds its descriptor. A dry pool
/// keeps the body in its row, which a checkpoint seals under an instance of
/// its own. `None` keeps the body in its row. Text, a container and an
/// owning adapter's carrier are filed too: the door read their bytes in the
/// op, and the put's checks read the bytes it filed (FIX 22091).
///
/// # Errors
///
/// Storage, custody and filesystem errors as they occur.
pub(crate) fn file_put_body_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
) -> Result<Option<(Vec<u8>, AssetBodyFacts)>> {
    if entity_type != ENTITY_TYPE_ASSET
        || data.len() as u64 <= ASSET_INLINE_BODY_BYTES
        || !ASSET_FILE_PLANE
    {
        return Ok(None);
    }
    let Some(kind) = asset_file_kind(data) else {
        return Ok(None);
    };
    let facts = AssetBodyFacts::of(data);
    // A local pack map carrier keeps its row: its reader hashes the stored
    // row against the head pin (FIX 22091).
    if crate::registry::pack_byte_map::names_pack_map_carrier(id, &facts.blake3) {
        return Ok(None);
    }
    // A marked file keeps its row: a serving door reads its keys' spans over
    // the bytes it holds.
    if crate::store::file_key_masks::masked_file_in_txn(store, txn, &facts.blake3)?.is_some() {
        return Ok(None);
    }
    let Some(mint) = store.body_instance_pool.draw() else {
        return Ok(None);
    };
    // Published before the row that names it, its key row bound in this
    // writer: the writer that would collect it or retire its instance
    // cannot run until this one commits.
    let dir = store.body_dir()?;
    let key = dir.import_sealing(
        &facts.blake3,
        facts.len,
        &mut io::Cursor::new(data),
        false,
        mint.mint()?,
    )?;
    crate::store::bind_body_key_in_txn(store, txn, &dir, &key)?;
    // Filed with no pin: the collector's notes on its digest, from before
    // it was named again, go (FIX 22101).
    store.result_body_pins.named_again(&facts.blake3);
    let manifest = AssetFileManifest {
        facts,
        kind,
        mime: None,
    }
    .encode()?;
    Ok(Some((manifest, facts)))
}

/// Binds ASSET `id`'s body file to the row a put just staged, in the put's
/// transaction: `file` is the body's facts when the row `body` is its
/// manifest, `None` when the row holds the body itself. `superseded` is the
/// stored row the put replaced when its body is a manifest
/// ([`superseded_file_row_in_txn`]): the put captured it among `id`'s
/// revisions, so the file it names stays for that revision while the
/// current descriptor shows it was filed (FIX 22091), until the record's
/// teardown. The current descriptor is released otherwise, and a legal
/// hold keeps the file the row held before under its own occurrence until
/// the record is erased.
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
    superseded: Option<&[u8]>,
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
                mark_occurrence: occurrence,
                state: BodyState::Complete {
                    body: facts.body_ref(),
                },
                result: None,
                code_run_output: None,
            })
        }
        None => None,
    };
    let prior = owned_body_in_txn(store, txn, id, &occurrence)?;
    let prior_file = prior.as_ref().and_then(|prior| prior.state.held());
    // The put captured the row it replaces among `id`'s revisions, manifest
    // and all. When the current descriptor holds the very file that row
    // names, the row was filed: its file stays for that revision, under that
    // row alone, so a revision read resolves its body as an inline
    // revision keeps its bytes (FIX 22091), a metadata-only change's too.
    if let (Some(row), Some(file)) = (superseded, prior_file)
        && manifest_of_row(row).is_some_and(|manifest| manifest.facts.body_ref() == *file)
    {
        keep_superseded_in_txn(store, txn, id, revision_occurrence(id, row)?, file)?;
    }
    if prior == next {
        return Ok(());
    }
    if crate::store::legal_hold::held_in_txn(store, txn, id.as_bytes())? {
        if let Some(file) = prior_file {
            keep_superseded_in_txn(store, txn, id, held_occurrence(id, file)?, file)?;
        }
        release_body_in_txn(store, txn, id, &occurrence)?;
    } else {
        release_unkept_bodies_in_txn(store, txn, id, &occurrence)?;
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
