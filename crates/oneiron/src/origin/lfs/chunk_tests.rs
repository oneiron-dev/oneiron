//! Chunked storage acceptance through public IO and stored ASSET rows.

use super::*;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use std::collections::BTreeSet;
use std::io::{Read, Write};

fn time() -> TimeRange {
    TimeRange {
        start: 1_700_000_000,
        end: 1_700_000_000,
    }
}
fn data(size: usize) -> Vec<u8> {
    let mut state = 0x9e3779b97f4a7c15u64;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn chunk_parameters_are_persisted_by_store_creation_before_vault_open() {
    let dir = tempfile::tempdir().unwrap();
    let config = embedding_test_config();
    let store = crate::store::Store::open(dir.path(), &config).unwrap();
    let txn = store.env.read_txn().unwrap();
    let raw = store
        .vault_meta
        .get(&txn, chunks::PARAM_KEY)
        .unwrap()
        .expect("creation must persist LFS parameters before a Vault opens");
    let seed = u64::from_le_bytes(raw.as_ref().try_into().unwrap());
    assert_ne!(seed, 0);
    drop(txn);
    drop(store);

    let vault = Vault::open(dir.path(), config).unwrap();
    assert_eq!(vault.lfs_chunk_parameters().unwrap().seed, seed);
}

#[test]
fn missing_chunk_parameters_fail_closed_without_upload_reminting() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut txn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .vault_meta
        .delete(&mut txn, chunks::PARAM_KEY)
        .unwrap();
    txn.commit().unwrap();

    assert_eq!(
        vault.lfs_chunk_parameters().unwrap_err().kind(),
        crate::ErrorKind::CorruptedIndex
    );
    let bytes = b"cannot mint params on upload";
    let oid = LfsOid::digest(bytes);
    assert_eq!(
        vault
            .put_lfs_object(oid, bytes, time(), time().start)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::CorruptedIndex
    );
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .vault_meta
            .get(&txn, chunks::PARAM_KEY)
            .unwrap()
            .is_none()
    );
}

#[test]
fn chunk_parameters_are_vault_private_and_small_files_use_one_chunk() {
    let (_a, a) = open_test_vault_with(embedding_test_config());
    let (_b, b) = open_test_vault_with(embedding_test_config());
    let params = a.lfs_chunk_parameters().unwrap();
    assert_ne!(params, b.lfs_chunk_parameters().unwrap());
    assert_eq!(params, a.lfs_chunk_parameters().unwrap());
    let bytes = b"small object";
    let oid = LfsOid::digest(bytes);
    a.put_lfs_object(oid, bytes, time(), time().start).unwrap();
    let manifest = a.lfs_manifest(oid).unwrap().unwrap();
    assert_eq!(manifest.chunks.len(), 1);
    assert_eq!(manifest.chunks[0].hash, *blake3::hash(bytes).as_bytes());
    assert_eq!(
        a.get(&manifest.asset_id().unwrap()).unwrap(),
        Some(manifest.encode().unwrap())
    );
}

#[test]
fn four_kib_edit_reuses_chunks_and_last_reference_gc_is_permanent() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut bytes = data(8 * 1024 * 1024);
    let first = LfsOid::digest(&bytes);
    vault
        .put_lfs_object(first, &bytes, time(), time().start)
        .unwrap();
    let before = vault.lfs_manifest(first).unwrap().unwrap();
    bytes[4 * 1024 * 1024..4 * 1024 * 1024 + 4096].fill(0x42);
    let second = LfsOid::digest(&bytes);
    vault
        .put_lfs_object(second, &bytes, time(), time().start)
        .unwrap();
    let after = vault.lfs_manifest(second).unwrap().unwrap();
    let old: BTreeSet<_> = before.chunks.iter().map(|c| c.hash).collect();
    let new: BTreeSet<_> = after.chunks.iter().map(|c| c.hash).collect();
    assert!(new.difference(&old).count() <= 8);
    assert!(new.intersection(&old).count() > 40);
    let unique = *old.difference(&new).next().expect("changed chunk");
    let shared = *old.intersection(&new).next().expect("shared chunk");
    assert!(vault.delete_lfs_object(first).unwrap());
    assert!(
        vault
            .get_raw(&chunks::chunk_id(&unique).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(vault.lfs_object_chunk(second, shared).unwrap().is_some());
    assert_eq!(vault.get_lfs_object(second).unwrap(), Some(bytes));
    assert!(vault.delete_lfs_object(second).unwrap());
    assert!(
        vault
            .get_raw(&chunks::chunk_id(&shared).unwrap())
            .unwrap()
            .is_none()
    );
    let original = data(8 * 1024 * 1024);
    assert_eq!(
        vault
            .put_lfs_object(first, &original, time(), time().start)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::InvalidLfsObject
    );
}

#[test]
fn collected_chunk_can_serve_a_new_oid_without_reviving_deleted_object() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let original = data(3 * LFS_CHUNK_MAX);
    let first = LfsOid::digest(&original);
    vault
        .put_lfs_object(first, &original, time(), time().start)
        .unwrap();
    let before = vault.lfs_manifest(first).unwrap().unwrap();
    let shared = &before.chunks[0];
    let chunk_id = chunks::chunk_id(&shared.hash).unwrap();
    let chunk_bytes = &original[..shared.size as usize];
    assert_eq!(
        vault
            .lfs_object_chunk(first, shared.hash)
            .unwrap()
            .as_deref(),
        Some(chunk_bytes)
    );
    #[cfg(feature = "sync")]
    let chunk_blob = vault.get_raw(&chunk_id).unwrap().unwrap();

    assert!(vault.delete_lfs_object(first).unwrap());
    assert!(vault.get_raw(&chunk_id).unwrap().is_none());
    for (kind, body) in [
        (ENTITY_TYPE_ASSET, b"tampered".as_slice()),
        (crate::registry::ENTITY_TYPE_PERSON, chunk_bytes),
    ] {
        assert_eq!(
            vault
                .put_entity(&chunk_id, kind, time(), time().start, body)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidLfsObject
        );
        assert!(vault.get_raw(&chunk_id).unwrap().is_none());
    }

    #[cfg(feature = "sync")]
    {
        // The retained reservation rejects both a stale ASSET blob and a
        // retyped blob that the content-address detector alone cannot identify.
        let key = crate::sync::WindowKey::new("2023-11");
        let materializer = crate::sync::bridge::Materializer::new();
        for kind in [ENTITY_TYPE_ASSET, crate::registry::ENTITY_TYPE_PERSON] {
            let doc = crate::sync::schema::create_window_doc("remote", &key);
            let entities = doc.get_map("entities");
            let mut stale = chunk_blob.clone();
            stale[0] = kind;
            crate::sync::loro_support::map_insert_bytes(&entities, &chunk_id.to_hex(), &stale)
                .unwrap();
            let control = EntityId::now();
            crate::sync::loro_support::map_insert_bytes(&entities, &control.to_hex(), &stale)
                .unwrap();
            doc.commit();
            crate::sync::window::forward_rematerialize(&vault, &doc, &materializer, &key).unwrap();
            assert!(vault.get_raw(&chunk_id).unwrap().is_none());
            assert_eq!(vault.get(&control).unwrap().as_deref(), Some(chunk_bytes));
        }
    }

    // The last byte is beyond the first maximum-size FastCDC chunk. This
    // changes the SHA-256 OID without changing that chunk under any vault seed.
    let mut edited = original.clone();
    *edited.last_mut().unwrap() ^= 1;
    let second = LfsOid::digest(&edited);
    assert_ne!(second, first);
    let published = vault
        .put_lfs_object(second, &edited, time(), time().start)
        .unwrap();
    assert!(!published.deduplicated);
    let after = vault.lfs_manifest(second).unwrap().unwrap();
    assert_eq!(after.chunks[0], *shared);
    assert_eq!(
        vault
            .lfs_object_chunk(second, shared.hash)
            .unwrap()
            .as_deref(),
        Some(chunk_bytes)
    );
    assert_eq!(vault.get_lfs_object(second).unwrap(), Some(edited));
    assert!(vault.lfs_object(first).unwrap().is_none());
    assert!(
        vault
            .lfs_object_chunk(first, shared.hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .put_lfs_object(first, &original, time(), time().start)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::InvalidLfsObject
    );
}

#[test]
fn cross_transport_boundary_credentials_never_publish_assets() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let assets_before = vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap();
    let mut bytes = vec![b' '; LFS_CHUNK_MAX - 10];
    bytes.extend_from_slice(b"ghp_0123456789abcdefghijklmnopqrstuvwxyz");
    let oid = LfsOid::digest(&bytes);
    assert!(
        vault
            .put_lfs_object_stream(oid, None, bytes.as_slice(), time(), time().start)
            .is_err()
    );
    assert!(vault.lfs_object(oid).unwrap().is_none());
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap(),
        assets_before
    );
    let mut scanner = scanner::CredentialStream::default();
    scanner.feed(b"-----BEGIN ").unwrap();
    scanner.feed(&vec![b' '; 2 * LFS_CHUNK_MAX]).unwrap();
    scanner.feed(b"PRIVATE ").unwrap();
    assert!(scanner.feed(b"KEY-----").is_err());
}

struct RepeatingReader {
    block: Vec<u8>,
    position: u64,
    size: u64,
    edited: bool,
}
impl RepeatingReader {
    fn new(size: u64) -> Self {
        Self {
            block: data(LFS_CHUNK_MAX),
            position: 0,
            size,
            edited: false,
        }
    }
    fn edited(size: u64) -> Self {
        Self {
            edited: true,
            ..Self::new(size)
        }
    }
}
impl Read for RepeatingReader {
    fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
        let offset = self.position as usize % self.block.len();
        let count = target
            .len()
            .min(self.block.len() - offset)
            .min((self.size - self.position) as usize);
        target[..count].copy_from_slice(&self.block[offset..offset + count]);
        if self.edited {
            let edit_start = self.size / 2;
            let start = self.position.max(edit_start);
            let end = (self.position + count as u64).min(edit_start + 4096);
            if start < end {
                target[(start - self.position) as usize..(end - self.position) as usize].fill(0x42);
            }
        }
        self.position += count as u64;
        Ok(count)
    }
}
struct HashWriter {
    sha: Sha256,
    size: u64,
}
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.sha.update(bytes);
        self.size += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn streamed_2_3_gb_generated_fixture_has_bounded_chunks() {
    // No giant source Vec or checked-in fixture. Repeated content also keeps
    // durable test storage small while exercising the full 64-bit IO length.
    let size = 2_300_000_000u64;
    let mut expected = HashWriter {
        sha: Sha256::new(),
        size: 0,
    };
    std::io::copy(&mut RepeatingReader::new(size), &mut expected).unwrap();
    let oid = LfsOid::from_bytes(expected.sha.finalize().into());
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    vault
        .put_lfs_object_stream(
            oid,
            Some(size),
            RepeatingReader::new(size),
            time(),
            time().start,
        )
        .unwrap();
    let manifest = vault.lfs_manifest(oid).unwrap().unwrap();
    assert_eq!(manifest.size_bytes, size);
    assert!(
        manifest
            .chunks
            .iter()
            .all(|c| c.size as usize <= LFS_CHUNK_MAX)
    );
    let mut actual = HashWriter {
        sha: Sha256::new(),
        size: 0,
    };
    assert!(vault.write_lfs_object_to(oid, &mut actual).unwrap());
    assert_eq!(actual.size, size);
    let hash: [u8; 32] = actual.sha.finalize().into();
    assert_eq!(&hash, oid.as_bytes());

    let before: BTreeSet<_> = manifest.chunks.iter().map(|c| c.hash).collect();
    let old_assets = vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap().len();
    let mut edited_hash = HashWriter {
        sha: Sha256::new(),
        size: 0,
    };
    std::io::copy(&mut RepeatingReader::edited(size), &mut edited_hash).unwrap();
    let edited_oid = LfsOid::from_bytes(edited_hash.sha.finalize().into());
    assert_ne!(oid, edited_oid);
    vault
        .put_lfs_object_stream(
            edited_oid,
            Some(size),
            RepeatingReader::edited(size),
            time(),
            time().start,
        )
        .unwrap();
    let edited_manifest = vault.lfs_manifest(edited_oid).unwrap().unwrap();
    let after: BTreeSet<_> = edited_manifest.chunks.iter().map(|c| c.hash).collect();
    let changed = after.difference(&before).count();
    assert!((1..=8).contains(&changed));
    assert!(after.intersection(&before).next().is_some());
    // Exactly the new manifest plus changed chunks; the repeated original
    // model chunks remain the same stored ASSETs, not rewritten copies.
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap().len(),
        old_assets + changed + 1
    );
}

#[test]
fn generic_writes_cannot_change_shared_chunks_or_manifests() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"immutable shared bytes";
    let oid = LfsOid::digest(bytes);
    let object = vault
        .put_lfs_object(oid, bytes, time(), time().start)
        .unwrap()
        .object;
    let manifest = vault.lfs_manifest(oid).unwrap().unwrap();
    for id in [
        object.asset_id,
        chunks::chunk_id(&manifest.chunks[0].hash).unwrap(),
    ] {
        assert_eq!(
            vault
                .put_entity(&id, ENTITY_TYPE_ASSET, time(), time().start, b"tampered")
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidLfsObject
        );
    }
    assert_eq!(vault.get_lfs_object(oid).unwrap().unwrap(), bytes);
}

#[cfg(feature = "sync")]
#[test]
fn window_export_scrubs_chunk_carriers_but_keeps_manifest() {
    use crate::sync::{WindowKey, schema::create_window_doc, window::export_window_updates_since};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"chunk bytes must stay outside Loro history";
    let oid = LfsOid::digest(bytes);
    let object = vault
        .put_lfs_object(oid, bytes, time(), time().start)
        .unwrap();
    let manifest = vault.lfs_manifest(oid).unwrap().unwrap();
    let chunk = chunks::chunk_id(&manifest.chunks[0].hash).unwrap();
    let key = WindowKey::new("2023-11");
    let doc = create_window_doc("source", &key);
    for id in [chunk, object.object.asset_id] {
        doc.get_map("entities")
            .insert(
                &id.to_hex(),
                loro::LoroValue::Binary(vault.get_raw(&id).unwrap().unwrap().into()),
            )
            .unwrap();
    }
    doc.commit();
    let exported =
        export_window_updates_since(&vault, &key, &doc, &loro::VersionVector::default().encode())
            .unwrap();
    let peer = create_window_doc("peer", &key);
    peer.import(&exported).unwrap();
    assert!(peer.get_map("entities").get(&chunk.to_hex()).is_none());
    assert!(
        peer.get_map("entities")
            .get(&object.object.asset_id.to_hex())
            .is_some()
    );
    // A second export must not reintroduce the scrubbed historical set-op.
    let later =
        export_window_updates_since(&vault, &key, &doc, &loro::VersionVector::default().encode())
            .unwrap();
    let later_peer = create_window_doc("later", &key);
    later_peer.import(&later).unwrap();
    assert!(
        later_peer
            .get_map("entities")
            .get(&chunk.to_hex())
            .is_none()
    );
}
