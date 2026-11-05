//! ASSET bodies on the file plane (FIX 3677; Engine rule (b), 10-18).
//!
//! An ASSET body longer than [`ASSET_INLINE_BODY_BYTES`] whose bytes no
//! reader interprets ([`asset_file_kind`]: no UTF-8 text, no owning
//! adapter's envelope, no container the secret mask reads into, no file the
//! mask marked), or a MessagePack record whose readers read it whole (FIX
//! 12150), lives in the vault's `bodies/` directory as one file named by its
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

pub mod stage;

use std::io::{self, Read, Write};

use heed::{RoTxn, RwTxn};

use crate::body_descriptor::BodyLocation;
use crate::body_descriptor::BodyRef;
use crate::body_descriptor::BodyState;
use crate::body_descriptor::OwnedBody;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::ASSET_BODY_FILE;
use oneiron_contracts::entity_id::derived_domains::ASSET_BODY_HELD;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;

/// FIX 3677 (CALLS "ASSET inline body bound"): an opaque ASSET body longer
/// than this lives in a body file; a body this long or shorter, and every
/// body that is not opaque, stays in its row. It picks where a body lives
/// and never refuses one (Rule 5). The sync transport's frame holds as much.
pub const ASSET_INLINE_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// A manifest's first byte: no UTF-8 text and no MessagePack value starts
/// with it, so no reader of ASSET bodies takes a manifest for text, a record
/// or an owning adapter's envelope. It frames the manifest; it decides
/// nothing about the row.
const MANIFEST_LEAD: u8 = 0xc1;
const MANIFEST_TAG: &[u8] = b"oneiron.asset-file.v1\0";

/// What the file plane holds an ASSET body as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetFileKind {
    /// Bytes no reader interprets, kept exactly as written.
    Opaque,
    /// One MessagePack map with a string key, kept exactly as written (FIX
    /// 12150): the readers that decode it read it whole through the file
    /// plane, which hands back the same bytes, and the readers of a stored
    /// row read nothing from it, as from its manifest.
    Record,
}

impl AssetFileKind {
    /// The kind's byte, in a manifest and in a sync body reference alike.
    pub const fn code(self) -> u8 {
        match self {
            Self::Opaque => 1,
            Self::Record => 2,
        }
    }

    /// The kind a [`Self::code`] byte names.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Opaque),
            2 => Some(Self::Record),
            _ => None,
        }
    }
}

/// An ASSET body's facts, measured as it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetBodyFacts {
    pub blake3: [u8; 32],
    pub len: u64,
    /// `xxh32(body, 0)`: a short reference hashes the logical body, never
    /// its manifest.
    pub xxh32: u32,
}

impl AssetBodyFacts {
    pub fn of(body: &[u8]) -> Self {
        Self {
            blake3: *blake3::hash(body).as_bytes(),
            len: body.len() as u64,
            xxh32: xxhash_rust::xxh32::xxh32(body, 0),
        }
    }

    /// The content-hash byte a short reference to this body carries, as
    /// [`crate::batch::short_id_content_hash`] reads a row's bytes.
    pub const fn short_hash(&self) -> u8 {
        (self.xxh32 % 256) as u8
    }

    pub const fn body_ref(&self) -> BodyRef {
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
pub struct AssetFileManifest {
    pub facts: AssetBodyFacts,
    pub kind: AssetFileKind,
    pub mime: Option<String>,
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
    pub fn encode(&self) -> Result<Vec<u8>> {
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
    pub fn decode(bytes: &[u8]) -> Option<Self> {
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
pub fn current_occurrence(id: &EntityId) -> Result<EntityId> {
    EntityId::derive(ASSET_BODY_FILE, &[id.as_bytes()])
}

/// The occurrence a legal hold keeps a superseded body file of `id` under.
pub fn held_occurrence(id: &EntityId, body: &BodyRef) -> Result<EntityId> {
    EntityId::derive(
        ASSET_BODY_HELD,
        &[id.as_bytes(), &body.blake3, &body.bytes.to_be_bytes()],
    )
}

/// FIX 3677: the file plane is on. A long opaque ASSET body lives in its
/// body file; sync carries its row by reference and moves the body outside
/// Loro (FIX 5489), an offline bundle carries it as a file part and a point
/// read serves it whole (FIX 5532). Off, every ASSET body stays in its row
/// exactly as before; off is this line. A sealed vault's files are
/// envelopes (FIX 5348).
pub const ASSET_FILE_PLANE: bool = true;

/// The length of `body`'s first MessagePack value when it is a map with a
/// string key, `None` for any other body.
pub fn keyed_map_len(body: &[u8]) -> Option<u64> {
    let mut cursor = io::Cursor::new(body);
    match rmpv::decode::read_value(&mut cursor) {
        Ok(rmpv::Value::Map(entries)) if entries.iter().any(|(key, _)| key.is_str()) => {
            Some(cursor.position())
        }
        _ => None,
    }
}
