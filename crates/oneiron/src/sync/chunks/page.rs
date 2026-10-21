//! One page of a chunk exchange (FIX 8860, 8183): a manifest's canonical bytes
//! from an offset, or a WANT's chunks from an index, within
//! [`CHUNK_PAGE_BYTES`] of encoding. Every page judges the whole exchange
//! again: no hash count, page count or object size refuses one.

use std::collections::BTreeSet;

use super::{
    CHUNK_PAGE_BYTES, ChunkMark, ChunkPage, ChunkPageCursor, ChunkSyncRequest, ChunkSyncResponse,
    MAX_WANT_CHUNKS, ManifestPage, invalid,
};
use crate::EntityId;
use crate::Vault;
use crate::error::Result;
use crate::origin::lfs::{LfsManifest, LfsOid};

/// The most a list's header takes in MessagePack.
const LIST_HEADER: usize = 5;

/// The page `request` asks for of the object `oid`, whose stored manifest
/// is `manifest`: the manifest's bytes from its cursor on, or the WANT's
/// chunks from its cursor's index on, as far as one page holds and at least
/// one on. The HAVE must name the manifest's chunks; the whole WANT must too,
/// each once and none it holds. A cursor names a page of this manifest only.
pub(super) fn reply(
    vault: &Vault,
    oid: LfsOid,
    manifest: &LfsManifest,
    request: ChunkSyncRequest,
    read: Option<EntityId>,
    mark: Option<ChunkMark>,
) -> Result<ChunkSyncResponse> {
    let pin = manifest.hash()?;
    let start = match request.cursor {
        None => 0,
        Some(cursor) if cursor.manifest == pin => {
            usize::try_from(cursor.offset).map_err(|_| invalid())?
        }
        Some(_) => return Err(invalid()),
    };
    let held: BTreeSet<[u8; 32]> = manifest.chunks.iter().map(|chunk| chunk.hash).collect();
    if request.have.iter().any(|hash| !held.contains(hash)) {
        return Err(invalid());
    }
    let next = |offset: usize| ChunkPageCursor {
        manifest: pin,
        offset: offset as u64,
    };
    let Some(want) = request.want else {
        let bytes = manifest.encode()?;
        if start >= bytes.len() {
            return Err(invalid());
        }
        let end = page_end(&bytes, start);
        return Ok(ChunkSyncResponse::Manifest(ManifestPage {
            request: request.request,
            manifest: pin,
            offset: start as u64,
            total: bytes.len() as u64,
            bytes: bytes[start..end].to_vec(),
            next: (end < bytes.len()).then(|| next(end)),
            read,
            mark,
        }));
    };
    let have: BTreeSet<&[u8; 32]> = request.have.iter().collect();
    let mut seen = BTreeSet::new();
    for hash in &want {
        if have.contains(hash) || !seen.insert(*hash) || !held.contains(hash) {
            return Err(invalid());
        }
    }
    // An empty WANT is answered by one empty page.
    if start > want.len() || (start == want.len() && start > 0) {
        return Err(invalid());
    }
    let mut chunks = Vec::new();
    let mut room = CHUNK_PAGE_BYTES;
    for hash in want.iter().skip(start).take(MAX_WANT_CHUNKS) {
        let body = vault.lfs_object_chunk(oid, *hash)?.ok_or_else(invalid)?;
        let cost = encoded_cost(&body);
        if cost > room && !chunks.is_empty() {
            break;
        }
        room = room.saturating_sub(cost);
        chunks.push((*hash, body));
    }
    let end = start + chunks.len();
    Ok(ChunkSyncResponse::Chunks(ChunkPage {
        request: request.request,
        offset: start as u64,
        chunks,
        next: (end < want.len()).then(|| next(end)),
        read,
    }))
}

/// Where a page of `bytes` that starts at `start` ends: as far as
/// [`CHUNK_PAGE_BYTES`] of encoding holds, and at least one byte on.
fn page_end(bytes: &[u8], start: usize) -> usize {
    let mut cost = LIST_HEADER;
    for (at, byte) in bytes.iter().enumerate().skip(start) {
        cost += byte_cost(*byte);
        if cost > CHUNK_PAGE_BYTES {
            return at.max(start + 1);
        }
    }
    bytes.len()
}

/// What `bytes` take in a page's encoding: MessagePack writes a byte list as
/// one integer per byte, behind its header.
fn encoded_cost(bytes: &[u8]) -> usize {
    LIST_HEADER + bytes.iter().map(|byte| byte_cost(*byte)).sum::<usize>()
}

/// One byte as MessagePack writes it in a list: two bytes from 0x80 up.
fn byte_cost(byte: u8) -> usize {
    if byte < 0x80 { 1 } else { 2 }
}

/// A manifest as its pages arrive (FIX 8860): each page goes on where the
/// last ended, in the manifest the first named, until the whole of it is
/// held. No length or page count bounds it.
#[derive(Default)]
pub(super) struct ManifestPages {
    pin: Option<([u8; 32], u64)>,
    bytes: Vec<u8>,
}

impl ManifestPages {
    /// Takes `page`, a reply to request `request`: the cursor the next
    /// request names, or `None` once the manifest is whole.
    pub(super) fn take(
        &mut self,
        request: u64,
        page: ManifestPage,
    ) -> Result<Option<ChunkPageCursor>> {
        if page.request != request
            || page.offset != self.bytes.len() as u64
            || page.bytes.is_empty()
            || *self.pin.get_or_insert((page.manifest, page.total)) != (page.manifest, page.total)
        {
            return Err(invalid());
        }
        self.bytes.extend_from_slice(&page.bytes);
        let held = self.bytes.len() as u64;
        match page.next {
            Some(next) if next.manifest == page.manifest && next.offset == held => {
                if held < page.total {
                    Ok(Some(next))
                } else {
                    Err(invalid())
                }
            }
            None if held == page.total => Ok(None),
            _ => Err(invalid()),
        }
    }

    /// The whole manifest, decoded, as the first page named it.
    pub(super) fn manifest(&self) -> Result<LfsManifest> {
        let manifest = LfsManifest::decode(&self.bytes)?;
        if self.pin.map(|(pin, _)| pin) != Some(manifest.hash()?) {
            return Err(invalid());
        }
        Ok(manifest)
    }
}
