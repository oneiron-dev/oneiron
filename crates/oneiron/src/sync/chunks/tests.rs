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
fn manifest_and_want_requests_enforce_grant_scope_and_silent_facet_bottom() -> Result<()> {
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
        selector.bands = vec![SelectorRange::Family(TypeByteFamily::Content)];
        let mut request = ChunkSyncRequest {
            oid: *oid.as_bytes(),
            selector: encode_sync_selector(&selector)?,
            have: vec![],
            want,
        };
        // Every grant, unpacted included, reads a silent facet axis as the
        // lattice bottom, and an ASSET row cannot carry a FacetOf stamp: even
        // the asset's own family band exports nothing through this lane.
        assert!(matches!(
            serve_chunk_request(&vault, principal, scope, &encode_chunk_request(&request)?),
            Err(Error::Artifact(ArtifactError::InvalidLfsObject(_)))
        ));
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
        selector.bands = vec![SelectorRange::Family(TypeByteFamily::People)];
        request.selector = encode_sync_selector(&selector)?;
        assert!(matches!(
            serve_chunk_request(&vault, principal, scope, &encode_chunk_request(&request)?),
            Err(Error::Artifact(ArtifactError::InvalidLfsObject(_)))
        ));
    }
    Ok(())
}
