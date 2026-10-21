//! Authenticated manifest-scoped have/want exchange. Byte assets never use Loro.
//!
//! The same bounded binary envelope is carried by HTTP or a sync frame. The
//! server passes the authenticated principal, not a caller-claimed identity.
//!
//! An exchange of any size goes in pages (FIX 8860, 8183): a manifest by its
//! canonical bytes from an offset, a WANT by its hashes from an index, each
//! page within one frame. The server keeps nothing between pages: each
//! request repeats its whole exchange, and the cursor its last reply named.

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
use crate::origin::lfs::{LfsOid, LfsPutOutcome};
use crate::{EntityId, TimeRange, Vault};

/// Binary-envelope schema, independent from Git-LFS basic transfer.
pub const CHUNK_SYNC_VERSION: u8 = 2;
/// Hard bound on one control/data envelope, not an object-size cap.
pub const MAX_CHUNK_SYNC_FRAME: usize = 8 * 1024 * 1024;
/// The hashes one page reads and sends at most (4 MiB of chunk bytes): the
/// width a reply is built in, never a bound on an exchange.
pub const MAX_WANT_CHUNKS: usize = 32;
/// The encoded bytes one page's manifest bytes or chunk bodies take at most:
/// the frame, less room for the rest of its envelope and the socket's tag
/// (CALLS `lfs-chunks page constant`).
pub const CHUNK_PAGE_BYTES: usize = MAX_CHUNK_SYNC_FRAME - 64 * 1024;

/// A manifest request, or the hashes the receiver still wants after its have pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkSyncRequest {
    /// The receiver's id for the transfer this request belongs to, echoed on
    /// its reply, so a late reply never reaches another transfer.
    pub request: u64,
    /// SHA-256 pointer that scopes this exchange to one object.
    pub oid: [u8; 32],
    /// Existing grant-backed selector codec bytes.
    pub selector: Vec<u8>,
    /// Already-held ids in this bounded negotiation page.
    pub have: Vec<[u8; 32]>,
    /// None requests a manifest; Some requests only these missing hashes.
    pub want: Option<Vec<[u8; 32]>>,
    /// Where this request goes on from: the `next` its last reply named, or
    /// `None` for the first page.
    pub cursor: Option<ChunkPageCursor>,
    /// What the reader asks of a lift-marked object's read (FIX 2897).
    pub read: Option<ChunkRead>,
}

/// Where the next page of an exchange starts: the manifest every page reads,
/// and an offset into its canonical bytes or into the WANT. A position, never
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkPageCursor {
    /// BLAKE3 of the canonical manifest.
    pub manifest: [u8; 32],
    /// The canonical manifest byte, or the WANT's hash, the page starts at.
    pub offset: u64,
}

/// Bounded reply: one page of metadata or of requested missing bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ChunkSyncResponse {
    /// Canonical BLAKE3 manifest bytes, authenticated again whole on the
    /// receiving side.
    Manifest(ManifestPage),
    /// Exactly the requested chunks, with no unsolicited extras.
    Chunks(ChunkPage),
}

impl ChunkSyncResponse {
    /// The request id this reply answers.
    #[must_use]
    pub fn request(&self) -> u64 {
        match self {
            Self::Manifest(page) => page.request,
            Self::Chunks(page) => page.request,
        }
    }
}

/// One page of a manifest's canonical bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestPage {
    /// The request id it answers.
    pub request: u64,
    /// BLAKE3 of the whole canonical manifest.
    pub manifest: [u8; 32],
    /// Where these bytes start in it.
    pub offset: u64,
    /// Its whole length.
    pub total: u64,
    /// The page's bytes.
    pub bytes: Vec<u8>,
    /// Where the next page starts; `None` on the last.
    pub next: Option<ChunkPageCursor>,
    /// The granted read the host admitted (FIX 2897), which the read's later
    /// requests name.
    pub read: Option<EntityId>,
    /// The lift mark on the object, sent with its real bytes, so an owner's
    /// device that installs it keeps it marked (FIX 2897).
    pub mark: Option<ChunkMark>,
}

/// The requested chunks from one index of the WANT on, in its order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkPage {
    /// The request id it answers.
    pub request: u64,
    /// The WANT's index of the first chunk here.
    pub offset: u64,
    /// Each chunk's hash and body.
    pub chunks: Vec<([u8; 32], Vec<u8>)>,
    /// Where the rest of the WANT goes on; `None` once every hash was sent.
    pub next: Option<ChunkPageCursor>,
    /// The granted read the host admitted (FIX 2897).
    pub read: Option<EntityId>,
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

/// A reply decoded, for a receiver that checks its request id before it
/// takes it.
pub(crate) fn decode_chunk_response(bytes: &[u8]) -> Result<ChunkSyncResponse> {
    decode(bytes)
}

/// Encodes one bounded request for HTTP or WebSocket transport. Its HAVE and
/// WANT may hold any number of hashes its frame carries (FIX 8183).
pub fn encode_chunk_request(request: &ChunkSyncRequest) -> Result<Vec<u8>> {
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
    serve_chunk_request_reading(vault, principal, scope, bytes, peer, &mut |_, _| Ok(None))
}

/// [`serve_chunk_request_for`] with the host's judgment of a lift-marked
/// object's read (FIX 2897): `reader` builds the authority this request
/// reads a marked object's real bytes under. It is asked for a marked object
/// alone, and only once the selector admitted it; `None` keeps it withheld,
/// as before.
pub fn serve_chunk_request_reading(
    vault: &Vault,
    principal: EntityId,
    scope: FederationGrantScope,
    bytes: &[u8],
    peer: PeerMachine,
    reader: LfsMarkedReader<'_>,
) -> Result<Vec<u8>> {
    let request: ChunkSyncRequest = decode(bytes)?;
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
    respond(vault, request, peer, reader)
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
    lfs_object_withheld_as(vault, oid, peer, false)
}

/// [`lfs_object_withheld_for`] for a reader whose read of a lift-marked
/// object its host has just judged: `reads_marked`, as
/// [`lfs_object_hold_as`] takes it.
pub fn lfs_object_withheld_as(
    vault: &Vault,
    oid: LfsOid,
    peer: PeerMachine,
    reads_marked: bool,
) -> Result<bool> {
    Ok(lfs_object_hold_as(vault, oid, peer, reads_marked)?.is_some())
}

/// Why an LFS object's bytes stay on this device (FIX 4939), content-free:
/// never a world's, a row's or the object's name or id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsHold {
    /// The lift sweep marked a secret-scan hit in it (OF-067), and the
    /// reader holds no authority to read it (FIX 2897).
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
    lfs_object_hold_as(vault, oid, peer, false)
}

/// [`lfs_object_hold_for`] for a reader whose read of a lift-marked object
/// its host has just judged (FIX 2897): `reads_marked` is whether its
/// [`LfsReadAuthority`] stands now. A mark keeps the object here only from a
/// reader it is false for; where the object may go is judged for every
/// reader, as before.
pub fn lfs_object_hold_as(
    vault: &Vault,
    oid: LfsOid,
    peer: PeerMachine,
    reads_marked: bool,
) -> Result<Option<LfsHold>> {
    use crate::ports::{EdgeDirection, EdgeStoreRead};
    // An object the lift sweep marked holds a hit a new upload is refused
    // for (OF-067): it stays on this device, but for the owner and a reader
    // its read admits (ARCH-0069).
    if !reads_marked && vault.lfs_object_secret_withheld(oid)? {
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
    serve_owner_chunk_request_reading(vault, bytes, peer, &mut |_, _| Ok(None))
}

/// [`serve_owner_chunk_request_for`] with the host's judgment of a
/// lift-marked object's read, as [`serve_chunk_request_reading`] takes it
/// (FIX 2897).
pub fn serve_owner_chunk_request_reading(
    vault: &Vault,
    bytes: &[u8],
    peer: PeerMachine,
    reader: LfsMarkedReader<'_>,
) -> Result<Vec<u8>> {
    let request: ChunkSyncRequest = decode(bytes)?;
    if !request.selector.is_empty() {
        return Err(invalid());
    }
    respond(vault, request, peer, reader)
}

fn respond(
    vault: &Vault,
    request: ChunkSyncRequest,
    peer: PeerMachine,
    reader: LfsMarkedReader<'_>,
) -> Result<Vec<u8>> {
    let oid = LfsOid::from_bytes(request.oid);
    // Where the object may go is judged first, for every reader. A marked
    // object's read is the host's to build, for it alone: an unmarked one
    // reads exactly as before (FIX 2897).
    if lfs_object_withheld_as(vault, oid, peer, true)? {
        return Err(invalid());
    }
    let mark = vault
        .lfs_object_mark(oid)?
        .map(|(reason, marked_at)| ChunkMark { reason, marked_at });
    let read = match mark {
        Some(_) => Some(reader(oid, request.read.as_ref())?.ok_or_else(invalid)?),
        None => None,
    };
    let manifest = vault.lfs_manifest(oid)?.ok_or_else(invalid)?;
    let read = read.and_then(LfsReadAuthority::reference);
    encode(&page::reply(vault, oid, &manifest, request, read, mark)?)
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
    let mut request = ChunkSyncRequest {
        request: 0,
        oid: *oid.as_bytes(),
        selector,
        have: Vec::new(),
        want: None,
        cursor: None,
        read: None,
    };
    // The manifest comes in pages, each going on where the last ended.
    let mut pages = page::ManifestPages::default();
    loop {
        let response: ChunkSyncResponse = decode(&exchange(&encode_chunk_request(&request)?)?)?;
        let ChunkSyncResponse::Manifest(page) = response else {
            return Err(invalid());
        };
        match pages.take(request.request, page)? {
            Some(next) => request.cursor = Some(next),
            None => break,
        }
    }
    request.cursor = None;
    let manifest = pages.manifest()?;
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
        let ChunkSyncResponse::Chunks(mut page) = reply else {
            return Err(invalid());
        };
        if page.request != want.request
            || page.next.is_some()
            || page.chunks.len() != 1
            || page.chunks[0].0 != chunk.hash
        {
            return Err(invalid());
        }
        let (_, bytes) = page.chunks.pop().expect("one verified entry");
        if bytes.len() != chunk.size as usize || blake3::hash(&bytes).as_bytes() != &chunk.hash {
            return Err(invalid());
        }
        Ok(bytes)
    })
}

mod download;
mod page;
mod read;
pub use download::ChunkDownload;
pub use read::{ChunkMark, ChunkRead, LfsMarkedReader, LfsReadAuthority};

#[cfg(test)]
mod tests;
