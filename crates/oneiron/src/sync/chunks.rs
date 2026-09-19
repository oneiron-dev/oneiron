//! Authenticated manifest-scoped have/want exchange. Byte assets never use Loro.
//!
//! The same bounded binary envelope is carried by HTTP or a sync frame. The
//! server passes the authenticated principal, not a caller-claimed identity.

use super::loro_support::{map_for_each_value_bytes, map_insert_bytes};
use super::schema::create_window_doc;
use super::selector::{
    SyncSelector, decode_sync_selector, encode_sync_selector, filtered_window_doc,
};
use super::types::WindowKey;
use crate::error::{ArtifactError, Error, Result};
use crate::federation::FederationGrantScope;
use crate::origin::lfs::{LfsManifest, LfsOid, LfsPutOutcome};
use crate::{EntityId, TimeRange, Vault};

/// Binary-envelope schema, independent from Git-LFS basic transfer.
pub const CHUNK_SYNC_VERSION: u8 = 1;
/// Hard bound on one control/data envelope, not an object-size cap.
pub const MAX_CHUNK_SYNC_FRAME: usize = 8 * 1024 * 1024;
/// Maximum requested hashes per frame (4 MiB of chunk bytes).
pub const MAX_WANT_CHUNKS: usize = 32;

/// A manifest request, or the hashes the receiver still wants after its have pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkSyncRequest {
    /// SHA-256 pointer that scopes this exchange to one object.
    pub oid: [u8; 32],
    /// Existing grant-backed selector codec bytes.
    pub selector: Vec<u8>,
    /// Already-held ids in this bounded negotiation page.
    pub have: Vec<[u8; 32]>,
    /// None requests a manifest; Some requests only these missing hashes.
    pub want: Option<Vec<[u8; 32]>>,
}

/// Bounded reply: metadata or requested missing bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ChunkSyncResponse {
    /// Canonical BLAKE3 manifest, authenticated again on the receiving side.
    Manifest(Vec<u8>),
    /// Exactly the requested chunks, with no unsolicited extras.
    Chunks(Vec<([u8; 32], Vec<u8>)>),
}

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidLfsObject(
        "invalid chunk sync exchange",
    ))
}
pub(super) fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = vec![CHUNK_SYNC_VERSION];
    bytes.extend(rmp_serde::to_vec(value).map_err(|_| invalid())?);
    if bytes.len() > MAX_CHUNK_SYNC_FRAME {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(super) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.first() != Some(&CHUNK_SYNC_VERSION) || bytes.len() > MAX_CHUNK_SYNC_FRAME {
        return Err(invalid());
    }
    let mut cursor = std::io::Cursor::new(&bytes[1..]);
    let value =
        T::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor)).map_err(|_| invalid())?;
    if cursor.position() != (bytes.len() - 1) as u64 {
        return Err(invalid());
    }
    Ok(value)
}

/// Encodes one bounded request for HTTP or WebSocket transport.
pub fn encode_chunk_request(request: &ChunkSyncRequest) -> Result<Vec<u8>> {
    if request.have.len() > MAX_WANT_CHUNKS
        || request
            .want
            .as_ref()
            .is_some_and(|hashes| hashes.len() > MAX_WANT_CHUNKS)
    {
        return Err(invalid());
    }
    encode(request)
}

/// Handles a request after transport authentication. The selector must name that
/// exact principal. Grant revocation/expiry and the effective scope are checked
/// for every request, including every subsequent want frame.
pub fn serve_chunk_request(
    vault: &Vault,
    principal: EntityId,
    scope: FederationGrantScope,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let request: ChunkSyncRequest = decode(bytes)?;
    if request.have.len() > MAX_WANT_CHUNKS
        || request
            .want
            .as_ref()
            .is_some_and(|hashes| hashes.len() > MAX_WANT_CHUNKS)
    {
        return Err(invalid());
    }
    let selector = decode_sync_selector(&request.selector)?;
    if selector.member_ref != principal {
        return Err(invalid());
    }
    super::selector::authorize_sync_selector(vault, scope, &selector)?;
    let oid = LfsOid::from_bytes(request.oid);
    let object = vault.lfs_object(oid)?.ok_or_else(invalid)?;
    // Use the standing entity selector, not a second interpretation of bands
    // or empty axes. No fabricated facet edge can widen a manifest's scope.
    let source = create_window_doc("lfs-chunk-scope", &WindowKey::new("1970-01"));
    let raw = vault.get_raw(&object.asset_id)?.ok_or_else(invalid)?;
    map_insert_bytes(&source.get_map("entities"), &object.asset_id.to_hex(), &raw)?;
    source.commit();
    let selected =
        filtered_window_doc(vault, &source, &WindowKey::new("1970-01"), scope, &selector)?;
    let mut admitted = false;
    map_for_each_value_bytes(&selected.get_map("entities"), |key, value| {
        if key == object.asset_id.to_hex() && value.is_some() {
            admitted = true;
        }
    });
    if !admitted {
        return Err(invalid());
    }
    respond(vault, request)
}

/// Owner-socket sibling. Only the transport's owner-authenticated sync lane may
/// call this; narrowed credentials must use `serve_chunk_request` instead.
pub fn serve_owner_chunk_request(vault: &Vault, bytes: &[u8]) -> Result<Vec<u8>> {
    let request: ChunkSyncRequest = decode(bytes)?;
    if !request.selector.is_empty()
        || request.have.len() > MAX_WANT_CHUNKS
        || request
            .want
            .as_ref()
            .is_some_and(|hashes| hashes.len() > MAX_WANT_CHUNKS)
    {
        return Err(invalid());
    }
    respond(vault, request)
}

fn respond(vault: &Vault, request: ChunkSyncRequest) -> Result<Vec<u8>> {
    let oid = LfsOid::from_bytes(request.oid);
    let manifest = vault.lfs_manifest(oid)?.ok_or_else(invalid)?;
    if request
        .have
        .iter()
        .any(|hash| !manifest.chunks.iter().any(|c| &c.hash == hash))
    {
        return Err(invalid());
    }
    let response = if let Some(want) = request.want {
        let mut chunks = Vec::with_capacity(want.len());
        let mut seen = std::collections::BTreeSet::new();
        for hash in want {
            if request.have.contains(&hash)
                || !seen.insert(hash)
                || !manifest.chunks.iter().any(|c| c.hash == hash)
            {
                return Err(invalid());
            }
            chunks.push((
                hash,
                vault.lfs_object_chunk(oid, hash)?.ok_or_else(invalid)?,
            ));
        }
        ChunkSyncResponse::Chunks(chunks)
    } else {
        ChunkSyncResponse::Manifest(manifest.encode()?)
    };
    encode(&response)
}

/// Pulls an object through a bounded authenticated transport exchange. The HAVE
/// pass is local: existing verified chunk ids never appear in WANT. Every
/// received chunk is verified, scanned and staged through the same writer as
/// HTTP upload. The result publishes only after whole-object SHA verification.
///
/// `exchange` must use the host's authenticated connection. It carries opaque
/// bounded frames, so the engine never handles bearer credentials itself.
pub fn pull_lfs_object<F>(
    target: &Vault,
    oid: LfsOid,
    selector: &SyncSelector,
    occurred: TimeRange,
    learned_at: u64,
    mut exchange: F,
) -> Result<LfsPutOutcome>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let selector = encode_sync_selector(selector)?;
    let request = ChunkSyncRequest {
        oid: *oid.as_bytes(),
        selector,
        have: Vec::new(),
        want: None,
    };
    let response: ChunkSyncResponse = decode(&exchange(&encode_chunk_request(&request)?)?)?;
    let ChunkSyncResponse::Manifest(bytes) = response else {
        return Err(invalid());
    };
    let manifest = LfsManifest::decode(&bytes)?;
    // A remote manifest may use another vault's private chunk parameters. It
    // remains a valid manifest; ingestion never changes this vault's seed.
    let mut have = Vec::new();
    target.install_lfs_manifest(oid, &manifest, occurred, learned_at, |chunk| {
        if let Some(bytes) = target.lfs_chunk_if_present(chunk)? {
            if have.len() < MAX_WANT_CHUNKS && !have.contains(&chunk.hash) {
                have.push(chunk.hash);
            }
            return Ok(bytes);
        }
        let mut want = request.clone();
        want.want = Some(vec![chunk.hash]);
        want.have.clone_from(&have);
        let reply: ChunkSyncResponse = decode(&exchange(&encode_chunk_request(&want)?)?)?;
        let ChunkSyncResponse::Chunks(mut chunks) = reply else {
            return Err(invalid());
        };
        if chunks.len() != 1 || chunks[0].0 != chunk.hash {
            return Err(invalid());
        }
        let (_, bytes) = chunks.pop().expect("one verified entry");
        if bytes.len() != chunk.size as usize || blake3::hash(&bytes).as_bytes() != &chunk.hash {
            return Err(invalid());
        }
        Ok(bytes)
    })
}

mod download;
pub use download::ChunkDownload;

#[cfg(test)]
mod tests;
