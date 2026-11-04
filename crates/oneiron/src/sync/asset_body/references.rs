//! The reference a by-reference ASSET body travels under (FIX 5489).
//!
//! A window's `asset_body_refs` map ([`ASSET_BODY_REFS_MAP`]) holds one
//! beside the carrier `entities[id]` of each ASSET whose body moves by
//! reference, never alone. The carrier is the row's metadata header and the
//! manifest of its body file, made only from a local row whose descriptor
//! proves it a file row. The reference binds that exact carrier by the
//! BLAKE3 of all its bytes, and names the body as the manifest does: its
//! BLAKE3, u64 length and `xxh32`, its kind and its media type.
//!
//! Without a reference a carrier is an ordinary inline body, whatever its
//! bytes: a peer's bytes are read as a manifest only where a reference
//! declares them one. Key: the owner's canonical (lowercase) hex id. Value:
//! [`AssetBodyRef::encode`]. The window mirror writes a reference in the
//! commit that writes its carrier ([`mirror_ref`]); while the file plane is
//! off ([`crate::store::ASSET_FILE_PLANE`]) nothing reads or writes the map.
//!
//! [`ASSET_BODY_REFS_MAP`]: crate::sync::schema::ASSET_BODY_REFS_MAP

use loro::LoroDoc;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::{
    ASSET_FILE_PLANE, AssetBodyFacts, AssetFileKind, AssetFileManifest, asset_file_in_txn,
};
use crate::sync::loro_support::{
    map_delete, map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
};
use crate::sync::schema::ASSET_BODY_REFS_MAP;

/// The value's first byte: its format.
const REF_FORMAT: u8 = 1;

/// The value's bytes before its media type: format, id, the two digests,
/// length, `xxh32`, kind, media-type presence and its length.
const FIXED_LEN: usize = 1 + 16 + 32 + 32 + 8 + 4 + 1 + 1 + 2;

/// One by-reference ASSET body's reference: the carrier it binds and the
/// body that carrier's manifest names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetBodyRef {
    pub(crate) id: EntityId,
    /// BLAKE3 of the whole carrier `entities[id]` holds, header included.
    pub(crate) carrier_blake3: [u8; 32],
    pub(crate) body_blake3: [u8; 32],
    pub(crate) len: u64,
    pub(crate) kind: AssetFileKind,
    pub(crate) mime: Option<String>,
    /// `xxh32(body, 0)`: what a short reference's hash byte comes from, not
    /// a second identity of the body.
    pub(crate) xxh32: u32,
}

impl AssetBodyRef {
    /// The reference to `carrier`, the stored row of ASSET `id`, whose body
    /// file `manifest` names. The caller has read `manifest` through the
    /// row's descriptor ([`crate::store::asset_file_in_txn`]).
    pub(crate) fn of_carrier(id: EntityId, carrier: &[u8], manifest: &AssetFileManifest) -> Self {
        Self {
            id,
            carrier_blake3: *blake3::hash(carrier).as_bytes(),
            body_blake3: manifest.facts.blake3,
            len: manifest.facts.len,
            kind: manifest.kind,
            mime: manifest.mime.clone(),
            xxh32: manifest.facts.xxh32,
        }
    }

    /// The body's length, BLAKE3 and `xxh32`.
    pub(crate) const fn facts(&self) -> AssetBodyFacts {
        AssetBodyFacts {
            blake3: self.body_blake3,
            len: self.len,
            xxh32: self.xxh32,
        }
    }

    /// The manifest the bound carrier holds after its header.
    pub(crate) fn manifest(&self) -> AssetFileManifest {
        AssetFileManifest {
            facts: self.facts(),
            kind: self.kind,
            mime: self.mime.clone(),
        }
    }

    /// The reference's key in its map: the owner's canonical hex id.
    pub(crate) fn key(&self) -> String {
        self.id.to_hex()
    }

    /// The value bytes: the format byte, the id, the carrier's and the
    /// body's BLAKE3, the length (u64 big-endian), `xxh32` (u32
    /// big-endian), the kind byte, a media-type presence byte, its length
    /// (u16 big-endian) and its UTF-8.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a media type past 65535 bytes.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mime = self.mime.as_deref().unwrap_or_default();
        let mime_len = u16::try_from(mime.len()).map_err(|_| {
            Error::InvalidConfig("an asset body's media type is past 65535 bytes".to_owned())
        })?;
        let mut bytes = Vec::with_capacity(FIXED_LEN + mime.len());
        bytes.push(REF_FORMAT);
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(&self.carrier_blake3);
        bytes.extend_from_slice(&self.body_blake3);
        bytes.extend_from_slice(&self.len.to_be_bytes());
        bytes.extend_from_slice(&self.xxh32.to_be_bytes());
        bytes.push(kind_code(self.kind));
        bytes.push(u8::from(self.mime.is_some()));
        bytes.extend_from_slice(&mime_len.to_be_bytes());
        bytes.extend_from_slice(mime.as_bytes());
        Ok(bytes)
    }

    /// The reference `bytes` encode under `key`, read strictly: `None` for
    /// any other bytes, an unknown kind, or a key that is not the canonical
    /// hex of the id the bytes carry.
    pub(crate) fn decode(key: &str, bytes: &[u8]) -> Option<Self> {
        let (&format, rest) = bytes.split_first()?;
        if format != REF_FORMAT {
            return None;
        }
        let (id, rest) = rest.split_first_chunk::<16>()?;
        let (carrier, rest) = rest.split_first_chunk::<32>()?;
        let (body, rest) = rest.split_first_chunk::<32>()?;
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
        let id = EntityId::from_bytes(*id).ok()?;
        if id.to_hex() != key {
            return None;
        }
        Some(Self {
            id,
            carrier_blake3: *carrier,
            body_blake3: *body,
            len: u64::from_be_bytes(*len),
            kind: kind_of(kind)?,
            mime,
            xxh32: u32::from_be_bytes(*xxh32),
        })
    }

    /// Whether `carrier`, the bytes `entities[id]` holds beside this
    /// reference, is the carrier it binds: the BLAKE3 of all its bytes the
    /// reference's, an ASSET's metadata header, then exactly the manifest
    /// the reference names.
    pub(crate) fn binds(&self, carrier: &[u8]) -> bool {
        *blake3::hash(carrier).as_bytes() == self.carrier_blake3
            && EntityMetadataHeader::parse(carrier)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_ASSET)
            && carrier
                .get(ENTITY_METADATA_HEADER_LEN..)
                .and_then(AssetFileManifest::decode)
                .is_some_and(|manifest| manifest == self.manifest())
    }
}

/// The reference `doc` binds `carrier`, the bytes its `entities[id]` holds,
/// with: `None` for an ordinary inline body, which no reference names, or
/// whose reference binds another carrier, or one that does not decode.
/// Always `None` while the file plane is off.
pub(crate) fn bound_in(doc: &LoroDoc, id: &EntityId, carrier: &[u8]) -> Option<AssetBodyRef> {
    if !ASSET_FILE_PLANE {
        return None;
    }
    let key = id.to_hex();
    let bytes = map_get_bytes(&doc.get_map(ASSET_BODY_REFS_MAP), &key)?;
    AssetBodyRef::decode(&key, &bytes).filter(|body| body.binds(carrier))
}

/// Every reference `doc` holds that binds the carrier its `entities` map
/// holds for the same id: the bodies the window moves by reference.
pub(crate) fn bound_refs(doc: &LoroDoc) -> Vec<AssetBodyRef> {
    let mut bound = Vec::new();
    if !ASSET_FILE_PLANE {
        return bound;
    }
    let entities = doc.get_map("entities");
    map_for_each_value_bytes(&doc.get_map(ASSET_BODY_REFS_MAP), |key, bytes| {
        if let Some(body) = bytes.and_then(|bytes| AssetBodyRef::decode(key, bytes))
            && map_get_bytes(&entities, key).is_some_and(|carrier| body.binds(&carrier))
        {
            bound.push(body);
        }
    });
    bound
}

/// Writes, in the commit that just wrote `raw`, the local row of `id`, as
/// `entities[id]`, the reference that carrier owes (FIX 5489, FIX 5490): a
/// file-plane ASSET's row is the carrier of its manifest, and takes its
/// reference; any other row is an inline body and takes away a reference an
/// earlier write left. The entity is written first and the reference second
/// in every commit, so the two keys resolve together. Off the file plane
/// nothing is read or written.
///
/// # Errors
///
/// Storage errors, a descriptor that disagrees with its row, and the map
/// write's.
pub(crate) fn mirror_ref(vault: &Vault, doc: &LoroDoc, id: &EntityId, raw: &[u8]) -> Result<()> {
    if !ASSET_FILE_PLANE {
        return Ok(());
    }
    let manifest = match EntityMetadataHeader::parse(raw) {
        Some(header) if header.entity_type == ENTITY_TYPE_ASSET => {
            let txn = vault.store.env.read_txn()?;
            asset_file_in_txn(&vault.store, &txn, id, &raw[ENTITY_METADATA_HEADER_LEN..])?
        }
        _ => None,
    };
    let refs = doc.get_map(ASSET_BODY_REFS_MAP);
    let key = id.to_hex();
    match manifest {
        Some(manifest) => map_insert_bytes(
            &refs,
            &key,
            &AssetBodyRef::of_carrier(*id, raw, &manifest).encode()?,
        ),
        None if refs.get(&key).is_some() => map_delete(&refs, &key),
        None => Ok(()),
    }
}

/// Copies into `out` each reference of `source` whose exact carrier `out`
/// holds, and commits them: a filtered copy of a window carries a reference
/// only beside the owner it kept, never alone. Nothing is written while the
/// file plane is off.
///
/// # Errors
///
/// The map write's.
pub(crate) fn copy_refs_within(source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    let kept = out.get_map("entities");
    let mut copied = false;
    for body in bound_refs(source) {
        let key = body.key();
        if map_get_bytes(&kept, &key).is_some_and(|carrier| body.binds(&carrier)) {
            map_insert_bytes(&out.get_map(ASSET_BODY_REFS_MAP), &key, &body.encode()?)?;
            copied = true;
        }
    }
    if copied {
        out.commit();
    }
    Ok(())
}

/// A kind's byte in a reference: the manifest's code for it.
const fn kind_code(kind: AssetFileKind) -> u8 {
    match kind {
        AssetFileKind::Opaque => 1,
        AssetFileKind::Record => 2,
    }
}

const fn kind_of(code: u8) -> Option<AssetFileKind> {
    match code {
        1 => Some(AssetFileKind::Opaque),
        2 => Some(AssetFileKind::Record),
        _ => None,
    }
}
