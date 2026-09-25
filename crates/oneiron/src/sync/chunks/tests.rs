//! Real binary have/want exchanges between independent vaults.

use super::*;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use std::collections::BTreeSet;

fn bytes(size: usize) -> Vec<u8> {
    let mut n = 0xbadb007u64;
    (0..size)
        .map(|_| {
            n ^= n << 13;
            n ^= n >> 7;
            n ^= n << 17;
            n as u8
        })
        .collect()
}
fn time() -> TimeRange {
    TimeRange {
        start: 1_700_000_000,
        end: 1_700_000_000,
    }
}

fn transfer(source: &Vault, target: &Vault, oid: LfsOid) -> (usize, usize) {
    let mut download = ChunkDownload::new(oid).unwrap();
    let mut request = download.initial_request().unwrap();
    let mut transferred = 0;
    let mut have_entries = 0;
    let mut sent = BTreeSet::new();
    loop {
        let control: ChunkSyncRequest = decode(&request).unwrap();
        have_entries += control.have.len();
        if let Some(wanted) = &control.want {
            for hash in wanted {
                assert!(!control.have.contains(hash));
                assert!(sent.insert(*hash), "each missing hash moves once");
            }
        }
        let reply = serve_owner_chunk_request(source, &request).unwrap();
        if let ChunkSyncResponse::Chunks(chunks) = decode(&reply).unwrap() {
            transferred += chunks.iter().map(|(_, bytes)| bytes.len()).sum::<usize>();
        }
        match download.accept(target, &reply, time().start).unwrap() {
            Some(next) => request = next,
            None => break,
        }
    }
    assert_eq!(download.outcome().unwrap().object.oid, oid);
    (transferred, have_entries)
}

#[test]
fn wire_have_want_transfers_only_missing_chunks_after_four_kib_edit() {
    let (_a, a) = open_test_vault_with(embedding_test_config());
    let (_b, b) = open_test_vault_with(embedding_test_config());
    let mut body = bytes(4 * 1024 * 1024);
    let first = LfsOid::digest(&body);
    a.put_lfs_object(first, &body, time(), time().start)
        .unwrap();
    let (all, _) = transfer(&a, &b, first);
    assert_eq!(all, body.len());
    body[2 * 1024 * 1024..2 * 1024 * 1024 + 4096].fill(0x2a);
    let second = LfsOid::digest(&body);
    a.put_lfs_object(second, &body, time(), time().start)
        .unwrap();
    let (delta, have) = transfer(&a, &b, second);
    assert!(delta > 0 && delta <= 8 * 128 * 1024);
    assert!(have > 0);
    assert_eq!(b.get_lfs_object(second).unwrap(), Some(body));
    assert_ne!(
        a.lfs_chunk_parameters().unwrap(),
        b.lfs_chunk_parameters().unwrap()
    );
}

#[test]
fn chunks_outside_the_manifest_and_unbound_selectors_are_refused() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let body = b"object-scoped chunk bytes";
    let oid = LfsOid::digest(body);
    vault
        .put_lfs_object(oid, body, time(), time().start)
        .unwrap();
    let request = ChunkSyncRequest {
        oid: *oid.as_bytes(),
        selector: Vec::new(),
        have: vec![],
        want: Some(vec![[42; 32]]),
    };
    assert!(serve_owner_chunk_request(&vault, &encode_chunk_request(&request).unwrap()).is_err());
    let principal = EntityId::now();
    assert!(
        serve_chunk_request(
            &vault,
            principal,
            FederationGrantScope::vault(1),
            &encode_chunk_request(&request).unwrap()
        )
        .is_err()
    );
}

#[test]
fn reply_corruption_and_replay_after_delete_never_publish() {
    let (_a, a) = open_test_vault_with(embedding_test_config());
    let (_b, b) = open_test_vault_with(embedding_test_config());
    let body = b"one shared object";
    let oid = LfsOid::digest(body);
    a.put_lfs_object(oid, body, time(), time().start).unwrap();
    let mut download = ChunkDownload::new(oid).unwrap();
    let manifest = serve_owner_chunk_request(&a, &download.initial_request().unwrap()).unwrap();
    let want = download
        .accept(&b, &manifest, time().start)
        .unwrap()
        .unwrap();
    let mut reply: ChunkSyncResponse =
        decode(&serve_owner_chunk_request(&a, &want).unwrap()).unwrap();
    let ChunkSyncResponse::Chunks(chunks) = &mut reply else {
        panic!("chunks")
    };
    chunks[0].1[0] ^= 1;
    assert!(
        download
            .accept(&b, &encode(&reply).unwrap(), time().start)
            .is_err()
    );
    assert!(b.lfs_object(oid).unwrap().is_none());
    transfer(&a, &b, oid);
    assert!(b.delete_lfs_object(oid).unwrap());
    let mut replay = ChunkDownload::new(oid).unwrap();
    let mut request = replay.initial_request().unwrap();
    loop {
        let response = serve_owner_chunk_request(&a, &request).unwrap();
        match replay.accept(&b, &response, time().start) {
            Ok(Some(next)) => request = next,
            Ok(None) => panic!("deleted object was resurrected"),
            Err(_) => break,
        }
    }
    assert!(b.lfs_object(oid).unwrap().is_none());
}

#[test]
fn manifest_and_want_requests_enforce_grant_scope_and_asset_family() -> Result<()> {
    use crate::error::{SyncError, SyncProtocolValidation, SyncSelectorValidation};
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, SelectorRange,
        encode_federation_grant_body,
    };
    use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, TypeByteFamily};
    use crate::sync::selector::SyncSelectorWorld;

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let body = b"grant-scoped chunk bytes";
    let oid = LfsOid::digest(body);
    vault.put_lfs_object(oid, body, time(), time().start)?;
    let manifest = vault.lfs_manifest(oid)?.expect("manifest");
    let principal = EntityId::now();
    let grant_id = EntityId::now();
    let scope = FederationGrantScope::vault(7);
    let grant = FederationGrant::new(
        scope,
        principal,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            time(),
            time().start,
            &encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    let mut selector = SyncSelector::new(
        grant_id,
        principal,
        SyncSelectorWorld::All,
        vec![],
        vec![SelectorRange::Family(TypeByteFamily::Content)],
    );
    for want in [None, Some(vec![manifest.chunks[0].hash])] {
        selector.bands =
            crate::sync::RequestedAxis::Named(vec![SelectorRange::Family(TypeByteFamily::Content)]);
        let mut request = ChunkSyncRequest {
            oid: *oid.as_bytes(),
            selector: encode_sync_selector(&selector)?,
            have: vec![],
            want,
        };
        let allowed =
            serve_chunk_request(&vault, principal, scope, &encode_chunk_request(&request)?)?;
        match decode::<ChunkSyncResponse>(&allowed)? {
            ChunkSyncResponse::Manifest(bytes) => {
                assert!(request.want.is_none());
                assert_eq!(bytes, manifest.encode()?);
            }
            ChunkSyncResponse::Chunks(chunks) => {
                assert!(request.want.is_some());
                assert_eq!(chunks, vec![(manifest.chunks[0].hash, body.to_vec())]);
            }
        }
        assert!(matches!(
            serve_chunk_request(
                &vault,
                principal,
                FederationGrantScope::vault(8),
                &encode_chunk_request(&request)?,
            ),
            Err(Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::Selector {
                    reason: SyncSelectorValidation::GrantScopeMismatch
                }
            }))
        ));
        // This is a valid, principal-bound selector, but not for this asset.
        selector.bands =
            crate::sync::RequestedAxis::Named(vec![SelectorRange::Family(TypeByteFamily::People)]);
        request.selector = encode_sync_selector(&selector)?;
        assert!(matches!(
            serve_chunk_request(&vault, principal, scope, &encode_chunk_request(&request)?),
            Err(Error::Artifact(ArtifactError::InvalidLfsObject(_)))
        ));
    }
    Ok(())
}

/// One stored object and a Viewer grant for `principal`, whose authority
/// scope `narrow` may attenuate.
fn chunk_grant_fixture(
    narrow: impl FnOnce(&mut crate::federation::FederationGrant),
) -> Result<(
    tempfile::TempDir,
    Vault,
    LfsOid,
    LfsManifest,
    EntityId,
    EntityId,
)> {
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, encode_federation_grant_body,
    };
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let body = b"ceiling-scoped chunk bytes";
    let oid = LfsOid::digest(body);
    vault.put_lfs_object(oid, body, time(), time().start)?;
    let manifest = vault.lfs_manifest(oid)?.expect("manifest");
    let principal = EntityId::now();
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        FederationGrantScope::vault(7),
        principal,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    narrow(&mut grant);
    vault
        .batch()
        .put_replicated(
            &grant_id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            time(),
            time().start,
            &encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    Ok((dir, vault, oid, manifest, principal, grant_id))
}

fn manifest_request(oid: LfsOid, selector: &SyncSelector) -> Result<Vec<u8>> {
    encode_chunk_request(&ChunkSyncRequest {
        oid: *oid.as_bytes(),
        selector: encode_sync_selector(selector)?,
        have: vec![],
        want: None,
    })
}

#[test]
fn chunk_request_outside_the_grant_ceiling_is_refused() -> Result<()> {
    let (_dir, vault, oid, _, principal, grant_id) = chunk_grant_fixture(|grant| {
        grant.authority_scope.bands =
            crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
                crate::registry::ENTITY_TYPE_PERSON,
            ]));
    })?;
    let selector = SyncSelector::new(
        grant_id,
        principal,
        crate::sync::selector::SyncSelectorWorld::All,
        vec![],
        vec![],
    );

    assert!(matches!(
        serve_chunk_request(
            &vault,
            principal,
            FederationGrantScope::vault(7),
            &manifest_request(oid, &selector)?
        ),
        Err(Error::Artifact(ArtifactError::InvalidLfsObject(_)))
    ));
    Ok(())
}

#[test]
fn chunk_request_naming_the_asset_birth_facet_is_served() -> Result<()> {
    let (_dir, vault, oid, manifest, principal, grant_id) = chunk_grant_fixture(|_| {})?;
    let selector = SyncSelector::new(
        grant_id,
        principal,
        crate::sync::selector::SyncSelectorWorld::All,
        vec![vault.default_facet()?],
        vec![],
    );
    let reply = serve_chunk_request(
        &vault,
        principal,
        FederationGrantScope::vault(7),
        &manifest_request(oid, &selector)?,
    )?;

    assert!(matches!(
        decode::<ChunkSyncResponse>(&reply)?,
        ChunkSyncResponse::Manifest(bytes) if bytes == manifest.encode()?
    ));
    Ok(())
}
