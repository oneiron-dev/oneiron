//! Authenticated manifest-scoped have/want exchange. Byte assets never use Loro.
//!
//! The same bounded binary envelope is carried by HTTP or a sync frame. The
//! server passes the authenticated principal, not a caller-claimed identity.

use super::loro_support::{map_for_each_value_bytes, map_insert_bytes};
use super::schema::create_window_doc;
use super::selector::{
    SyncSelector, decode_sync_selector, encode_sync_selector, filtered_window_doc,
    filtered_window_doc_for_peer,
};
use super::types::WindowKey;
use crate::authority::PeerMachine;
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
    serve_chunk_request_for(vault, principal, scope, bytes, PeerMachine::Unknown)
}

/// [`serve_chunk_request`] for the machine `peer` its transport already
/// proved for this request (FIX 4937): the selector's export and the
/// manifest are judged for that machine, its proof revalidated in each read;
/// an unproved peer is judged exactly as before.
pub fn serve_chunk_request_for(
    vault: &Vault,
    principal: EntityId,
    scope: FederationGrantScope,
    bytes: &[u8],
    peer: PeerMachine,
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
    // A manifest no frame carries is never served (its own request fails at
    // the frame), so a want for its object never reads it whole either: an
    // exchange's working set stays within the frames its server counted.
    if !row_fits_a_frame(vault, &object.asset_id)? {
        return Err(invalid());
    }
    // Use the standing entity selector, not a second interpretation of bands
    // or empty axes. No fabricated facet edge can widen a manifest's scope.
    let source = create_window_doc("lfs-chunk-scope", &WindowKey::new("1970-01"));
    let raw = vault.get_raw(&object.asset_id)?.ok_or_else(invalid)?;
    map_insert_bytes(&source.get_map("entities"), &object.asset_id.to_hex(), &raw)?;
    // The ASSET's stored birth stamp rides with it, so a named facet can seed it.
    for edge in vault.edges_out(&object.asset_id)? {
        if edge.kind == crate::edge::EdgeKind::FacetOf {
            map_insert_bytes(
                &source.get_map("edges"),
                &super::bridge::format_edge_key(&object.asset_id, edge.kind, &edge.target),
                &super::bridge::encode_edge_value_for_crdt(
                    edge.kind,
                    edge.weight,
                    edge.created_at,
                    edge.vad,
                    edge.provenance,
                )?,
            )?;
        }
    }
    source.commit();
    let window = WindowKey::new("1970-01");
    let selected = match peer {
        PeerMachine::Proven { .. } => {
            filtered_window_doc_for_peer(vault, &source, &window, scope, &selector, peer)?
        }
        PeerMachine::Unknown => filtered_window_doc(vault, &source, &window, scope, &selector)?,
    };
    let mut admitted = false;
    map_for_each_value_bytes(&selected.get_map("entities"), |key, value| {
        if key == object.asset_id.to_hex() && value.is_some() {
            admitted = true;
        }
    });
    if !admitted {
        return Err(invalid());
    }
    respond(vault, request, peer)
}

/// Whether a device-only world keeps an object's bytes on this device: every
/// row its ASSET is attached to (an `Attached` edge either way) is a row the
/// flag keeps. An object a portable row also owns, or one attached to nothing,
/// stays portable. Read for every manifest and WANT request, and again when a
/// queued reply is released, so neither a known OID nor an earlier manifest
/// is standing authority to export.
pub fn lfs_object_withheld(vault: &Vault, oid: LfsOid) -> Result<bool> {
    lfs_object_withheld_for(vault, oid, PeerMachine::Unknown)
}

/// [`lfs_object_withheld`] for the machine `peer` proved on the connection
/// that asks (mesh PR2b): the device-only worlds are those the world settings
/// keep off that machine, its proof revalidated in this read; an unproved
/// peer is an unknown destination.
pub fn lfs_object_withheld_for(vault: &Vault, oid: LfsOid, peer: PeerMachine) -> Result<bool> {
    Ok(lfs_object_hold_for(vault, oid, peer)?.is_some())
}

/// Why an LFS object's bytes stay on this device (FIX 4939), content-free:
/// never a world's, a row's or the object's name or id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsHold {
    /// The lift sweep marked a secret-scan hit in it (OF-067).
    Secret,
    /// Every row it is attached to is held from the destination: why the
    /// first of them is.
    Release(crate::settings::ReleaseHold),
}

impl LfsHold {
    /// The hold as a refusal states it.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Secret => LFS_SECRET_HOLD,
            Self::Release(hold) => hold.reason(),
        }
    }
}

/// What a refusal says of an object a secret-scan hit keeps here (CALLS
/// `FIX 4939 refusal reasons`).
const LFS_SECRET_HOLD: &str = "a secret scan hit keeps this object on this device";

/// Why [`lfs_object_withheld_for`] keeps an object's bytes on this device,
/// or `None` while they may go to `peer`: the same verdict, read in the same
/// snapshot, with its reason (FIX 4939). A secret hold comes first; an
/// object a portable row also owns, or one attached to nothing, stays
/// portable; only once every owner is withheld is the first of them named,
/// as the owner's recipient choice or an integrity hold.
pub fn lfs_object_hold_for(
    vault: &Vault,
    oid: LfsOid,
    peer: PeerMachine,
) -> Result<Option<LfsHold>> {
    use crate::ports::{EdgeDirection, EdgeStoreRead};
    // An object the lift sweep marked holds a hit a new upload is refused
    // for (OF-067): it stays on this device.
    if vault.lfs_object_secret_withheld(oid)? {
        return Ok(Some(LfsHold::Secret));
    }
    let _accepting = vault.device_only_acceptance();
    let object = vault.lfs_object(oid)?.ok_or_else(invalid)?;
    let txn = vault.store.env.read_txn()?;
    let destination = crate::settings::ReadDestination::toward(peer);
    let flagged = crate::settings::device_local_worlds_for(vault, &txn, &destination)?;
    if flagged.is_empty() {
        return Ok(None);
    }
    let mut owners = std::collections::BTreeSet::new();
    for edge in vault.store.port_edges(
        &txn,
        &object.asset_id,
        EdgeDirection::Both,
        Some(crate::edge::EdgeKind::Attached),
        None,
    )? {
        owners.insert(edge?.target);
    }
    owners.remove(&object.asset_id);
    for owner in &owners {
        if !crate::settings::device_only_withholds(&vault.store, &txn, &flagged, owner)? {
            return Ok(None);
        }
    }
    Ok(owners.first().map(|owner| {
        LfsHold::Release(crate::settings::withheld_row_hold_in(
            vault,
            &txn,
            &flagged,
            owner,
            &destination,
        ))
    }))
}

/// The object a chunk request names, so a transport can check its reply
/// again with [`lfs_object_withheld`] when it releases it.
pub fn chunk_request_object(bytes: &[u8]) -> Result<LfsOid> {
    Ok(LfsOid::from_bytes(decode::<ChunkSyncRequest>(bytes)?.oid))
}

/// Owner-socket sibling. Only the transport's owner-authenticated sync lane may
/// call this; narrowed credentials must use `serve_chunk_request` instead.
pub fn serve_owner_chunk_request(vault: &Vault, bytes: &[u8]) -> Result<Vec<u8>> {
    serve_owner_chunk_request_for(vault, bytes, PeerMachine::Unknown)
}

/// [`serve_owner_chunk_request`] for the machine `peer` proved on the owner's
/// socket: the manifest and every WANT are judged for that machine (mesh
/// PR2b).
pub fn serve_owner_chunk_request_for(
    vault: &Vault,
    bytes: &[u8],
    peer: PeerMachine,
) -> Result<Vec<u8>> {
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
    respond(vault, request, peer)
}

fn respond(vault: &Vault, request: ChunkSyncRequest, peer: PeerMachine) -> Result<Vec<u8>> {
    let oid = LfsOid::from_bytes(request.oid);
    if lfs_object_withheld_for(vault, oid, peer)? {
        return Err(invalid());
    }
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

/// Whether `id`'s stored row fits one frame, judged on the row in place,
/// without copying it.
fn row_fits_a_frame(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let fits =
        crate::ports::EntityStoreRead::port_entity_with_raw(&vault.store, &txn, id, |row| {
            Ok(row.len() <= MAX_CHUNK_SYNC_FRAME)
        })?;
    Ok(fits.unwrap_or(false))
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
