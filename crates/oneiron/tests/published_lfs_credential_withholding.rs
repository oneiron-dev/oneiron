//! A published LFS object goes to a federation peer only whole and as stored
//! (EXPORTDOORS Q3 = A; FIX PUBLISHED-LFS-CHUNKS-SHIP-SCAN-OFF-CREDENTIALS).
//!
//! With the owner's scan off, an object that holds a credential is stored
//! unmarked. A peer whose grant admits the object's ASSET is refused its
//! manifest and every chunk alike, the chunks that do not hold the
//! credential included. A clean object still goes to the peer byte-exact,
//! and the owner's lane still reads the credential object's stored bytes.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The `LEAK:`
//! assertions come last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test published_lfs_credential_withholding`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(feature = "sync", feature = "test-hooks"))]

use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    SelectorRange,
};
use oneiron::origin::lfs::{LfsManifest, LfsOid};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::TypeByteFamily;
use oneiron::store::GateDecisionId;
use oneiron::sync::chunks::{
    CHUNK_SYNC_VERSION, ChunkPage, ChunkSyncRequest, ChunkSyncResponse, ManifestPage,
    encode_chunk_request, serve_chunk_request, serve_owner_chunk_request,
};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, encode_sync_selector, put_selector_test_federation_grant,
};
use oneiron::{EntityId, Error, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The shared vault the peer's grant names.
const SHARED: u64 = 7;
const LEARNED_AT: u64 = 1_700_000_000;
/// Filler lines: about 450 KiB, past three of the largest chunks (128 KiB).
const LINES: usize = 15_000;
const ASSIGNMENT_SECRET: &str = "residual-file-credential";
const SIGNATURE_SECRET: &str = "residual-signature";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// Numbered filler text, with no credential and no recovery-phrase word.
fn filler(lines: std::ops::Range<usize>) -> String {
    lines
        .map(|line| format!("lorem ipsum {line} dolor sit amet\n"))
        .collect()
}

/// A text file with one assignment credential at its middle line.
fn assignment_body() -> Vec<u8> {
    let half = LINES / 2;
    format!(
        "{}api_key = '{ASSIGNMENT_SECRET}'\n{}",
        filler(0..half),
        filler(half..LINES)
    )
    .into_bytes()
}

/// A JSON file whose last member is a signature.
fn signature_body() -> Vec<u8> {
    serde_json::json!({
        "notes": filler(0..LINES),
        "signature": SIGNATURE_SECRET,
    })
    .to_string()
    .into_bytes()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// A vault with the scan off, and a peer whose Viewer grant over the shared
/// vault admits the Content family, an LFS object's ASSET included.
struct Peer {
    _dir: tempfile::TempDir,
    vault: Vault,
    principal: EntityId,
    selector: Vec<u8>,
}

impl Peer {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let proof =
            vault.authenticate_owner(owner, "owen@example.com", true, GateDecisionId::now())?;
        // With the scan off, an object holding a credential is stored unmarked.
        vault.set_secret_scan_mode(&proof, SecretScanMode::Off, LEARNED_AT)?;
        let principal = EntityId::now();
        let grant_id = EntityId::now();
        let grant = FederationGrant::new(
            FederationGrantScope::vault(SHARED),
            principal,
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        );
        put_selector_test_federation_grant(&vault, &grant_id, &grant, LEARNED_AT)?;
        let selector = encode_sync_selector(&SyncSelector::new(
            grant_id,
            principal,
            SyncSelectorWorld::All,
            vec![],
            vec![SelectorRange::Family(TypeByteFamily::Content)],
        ))?;
        Ok(Self {
            _dir: dir,
            vault,
            principal,
            selector,
        })
    }

    /// Publishes `body` and returns its OID and stored manifest, checked to
    /// hold several chunks and to read back byte-exact.
    fn publish(&self, body: &[u8]) -> TestResult<(LfsOid, LfsManifest)> {
        let oid = LfsOid::digest(body);
        self.vault
            .put_lfs_object(oid, body, at(LEARNED_AT), LEARNED_AT)?;
        let manifest = self.vault.lfs_manifest(oid)?.ok_or("a stored manifest")?;
        assert!(
            manifest.chunks.len() >= 3,
            "FIXTURE: the object spans several chunks, got {}",
            manifest.chunks.len()
        );
        assert_eq!(
            self.vault.get_lfs_object(oid)?.as_deref(),
            Some(body),
            "FIXTURE: the scan-off store keeps the object byte-exact"
        );
        Ok((oid, manifest))
    }

    /// A request of the object `oid` under this peer's selector.
    fn request(&self, oid: LfsOid, want: Option<Vec<[u8; 32]>>) -> ChunkSyncRequest {
        ChunkSyncRequest {
            request: 1,
            oid: *oid.as_bytes(),
            selector: self.selector.clone(),
            have: vec![],
            want,
            cursor: None,
            read: None,
        }
    }

    /// The peer's reply to `request`, through its grant's shared vault.
    fn serve(&self, request: &ChunkSyncRequest, vault_id: u64) -> oneiron::Result<Vec<u8>> {
        serve_chunk_request(
            &self.vault,
            self.principal,
            FederationGrantScope::vault(vault_id),
            &encode_chunk_request(request)?,
        )
    }
}

fn decode_reply(bytes: &[u8]) -> TestResult<ChunkSyncResponse> {
    let (version, body) = bytes.split_first().ok_or("an empty reply")?;
    assert_eq!(*version, CHUNK_SYNC_VERSION);
    Ok(rmp_serde::from_slice(body)?)
}

/// The object's chunk bodies in its manifest's order.
fn chunk_bodies(body: &[u8], manifest: &LfsManifest) -> Vec<([u8; 32], Vec<u8>)> {
    let mut start = 0;
    manifest
        .chunks
        .iter()
        .map(|chunk| {
            let end = start + chunk.size as usize;
            let slice = (chunk.hash, body[start..end].to_vec());
            start = end;
            slice
        })
        .collect()
}

/// Asserts that `serve` answers the manifest request with the stored
/// manifest's canonical bytes, and each chunk's WANT with its exact bytes.
fn assert_served_exactly(
    serve: impl Fn(&ChunkSyncRequest) -> oneiron::Result<Vec<u8>>,
    request: impl Fn(Option<Vec<[u8; 32]>>) -> ChunkSyncRequest,
    body: &[u8],
    manifest: &LfsManifest,
) -> TestResult {
    let ChunkSyncResponse::Manifest(ManifestPage { bytes, next, .. }) =
        decode_reply(&serve(&request(None))?)?
    else {
        return Err("a manifest request answers a manifest page".into());
    };
    assert_eq!(next, None, "a small manifest goes in one page");
    assert_eq!(bytes, manifest.encode()?, "the manifest goes byte-exact");
    let mut joined = Vec::new();
    for (hash, chunk) in chunk_bodies(body, manifest) {
        let ChunkSyncResponse::Chunks(ChunkPage { chunks, next, .. }) =
            decode_reply(&serve(&request(Some(vec![hash])))?)?
        else {
            return Err("a WANT answers a chunk page".into());
        };
        assert_eq!(next, None);
        assert_eq!(
            chunks,
            vec![(hash, chunk.clone())],
            "each chunk goes byte-exact"
        );
        joined.extend_from_slice(&chunk);
    }
    assert_eq!(joined, body, "the chunks join into the whole object");
    Ok(())
}

/// Asserts that the peer is refused the manifest of `body` and every chunk
/// of it, each alone and all at once, though only some chunks hold `secret`.
fn assert_peer_refused_every_part(peer: &Peer, body: &[u8], secret: &str) -> TestResult {
    let (oid, manifest) = peer.publish(body)?;
    let chunks = chunk_bodies(body, &manifest);
    assert!(
        chunks.iter().any(|(_, chunk)| !contains(chunk, secret)),
        "FIXTURE: some chunk of the object does not hold the credential"
    );
    let mut distinct = Vec::new();
    for (hash, _) in &chunks {
        if !distinct.contains(hash) {
            distinct.push(*hash);
        }
    }
    let refused = |want: Option<Vec<[u8; 32]>>| {
        matches!(
            peer.serve(&peer.request(oid, want), SHARED),
            Err(Error::Artifact(_))
        )
    };
    assert!(
        refused(None),
        "LEAK: the peer must be refused the manifest of an object holding a credential"
    );
    for hash in &distinct {
        assert!(
            refused(Some(vec![*hash])),
            "LEAK: the peer must be refused every chunk of an object holding a credential"
        );
    }
    assert!(
        refused(Some(distinct)),
        "LEAK: the peer must be refused a WANT of the whole object"
    );
    assert!(
        refused(None),
        "LEAK: a later manifest request is refused as the first was"
    );
    Ok(())
}

#[test]
fn a_peer_reads_a_clean_published_object_exactly() -> TestResult {
    let peer = Peer::new()?;
    let body = filler(0..LINES).into_bytes();
    let (oid, manifest) = peer.publish(&body)?;
    assert_served_exactly(
        |request| peer.serve(request, SHARED),
        |want| peer.request(oid, want),
        &body,
        &manifest,
    )?;
    // The object's verdict is kept; who may read it is judged again.
    assert!(
        peer.serve(&peer.request(oid, None), SHARED + 1).is_err(),
        "a request under another vault's scope is refused after a served one"
    );
    Ok(())
}

#[test]
fn a_peer_is_refused_every_part_of_an_object_with_an_assignment_credential() -> TestResult {
    let peer = Peer::new()?;
    assert_peer_refused_every_part(&peer, &assignment_body(), ASSIGNMENT_SECRET)
}

#[test]
fn a_peer_is_refused_every_part_of_an_object_with_a_signature_member() -> TestResult {
    let peer = Peer::new()?;
    assert_peer_refused_every_part(&peer, &signature_body(), SIGNATURE_SECRET)
}

#[test]
fn the_owner_lane_reads_a_credential_object_exactly() -> TestResult {
    let peer = Peer::new()?;
    for body in [assignment_body(), signature_body()] {
        let (oid, manifest) = peer.publish(&body)?;
        assert_served_exactly(
            |request| serve_owner_chunk_request(&peer.vault, &encode_chunk_request(request)?),
            |want| ChunkSyncRequest {
                selector: vec![],
                ..peer.request(oid, want)
            },
            &body,
            &manifest,
        )?;
    }
    Ok(())
}
