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
        .get(&txn, crate::side_table::ORIGIN_LFS_CDC_SEED.prefix)
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
        .delete(&mut txn, crate::side_table::ORIGIN_LFS_CDC_SEED.prefix)
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
            .get(&txn, crate::side_table::ORIGIN_LFS_CDC_SEED.prefix)
            .unwrap()
            .is_none()
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

/// Installs `parts` as one object whose peer-chosen chunks are exactly those
/// parts, as the sync chunk protocol lets a peer choose them.
fn install_parts(vault: &Vault, parts: &[&[u8]]) -> crate::error::Result<LfsPutOutcome> {
    install_parts_within(vault, parts, None)
}

/// [`install_parts`] with the bound up to which the object is read whole
/// lowered (`Some(0)`: every object is read by chunk and seam).
fn install_parts_within(
    vault: &Vault,
    parts: &[&[u8]],
    whole_scan_max: Option<u64>,
) -> crate::error::Result<LfsPutOutcome> {
    install_parts_with(vault, parts, whole_scan_max, |_| {})
}

/// [`install_parts_within`], calling `before_supply` with each part's index
/// before that part is handed over.
fn install_parts_with(
    vault: &Vault,
    parts: &[&[u8]],
    whole_scan_max: Option<u64>,
    mut before_supply: impl FnMut(usize),
) -> crate::error::Result<LfsPutOutcome> {
    let whole = parts.concat();
    let manifest = chunks::LfsManifest {
        size_bytes: whole.len() as u64,
        chunks: parts
            .iter()
            .map(|part| chunks::LfsChunkRef {
                hash: *blake3::hash(part).as_bytes(),
                size: part.len() as u32,
            })
            .collect(),
    };
    let mut parts = parts.iter().enumerate();
    let supply = move |_: &chunks::LfsChunkRef| {
        let (index, part) = parts.next().unwrap();
        before_supply(index);
        Ok(part.to_vec())
    };
    let oid = LfsOid::digest(&whole);
    match whole_scan_max {
        None => vault.install_lfs_manifest(oid, &manifest, time(), time().start, supply),
        Some(max) => vault.install_lfs_manifest_reading_whole(
            max,
            oid,
            &manifest,
            time(),
            time().start,
            supply,
        ),
    }
}

fn set_secret_scan(vault: &Vault, mode: crate::batch::secret_scan::SecretScanMode) {
    let mut txn = vault.store.env.write_txn().unwrap();
    crate::batch::secret_scan::put_secret_scan_mode_in_txn(&vault.store, &mut txn, mode).unwrap();
    txn.commit().unwrap();
}

fn refused_as_sensitive(result: crate::error::Result<LfsPutOutcome>) {
    let error = result.unwrap_err();
    assert!(
        matches!(&error, crate::error::Error::Gate(crate::error::GateError::GateWriteRejected { reason_codes, .. })
            if reason_codes.contains(&"gate.secret_scan.sensitive_env")),
        "{error:?}"
    );
}

#[test]
fn a_credential_assignment_split_across_peer_chunks_is_read_whole() {
    let parts: [&[u8]; 2] = [
        b"[service]\nhost = db.internal\npassword=",
        b"t7Rk2pLq9WzX\nport = 5432\n",
    ];
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let assets_before = vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap();
    // Read whole within the bound, and by the seam above it.
    for whole_scan_max in [None, Some(0)] {
        refused_as_sensitive(install_parts_within(&vault, &parts, whole_scan_max));
        assert!(
            vault
                .lfs_object(LfsOid::digest(&parts.concat()))
                .unwrap()
                .is_none()
        );
    }
    // With the owner's switch off the batch door stores it, and so does the seam.
    set_secret_scan(&vault, crate::batch::secret_scan::SecretScanMode::Off);
    install_parts(&vault, &parts).unwrap();
    assert!(vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap().len() > assets_before.len());
}

#[test]
fn an_object_within_the_bound_is_read_whole_however_a_peer_cuts_it() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    // Padding that outruns any seam, and a JSON key escaped and cut mid-member.
    let mut padded = b"password=".to_vec();
    padded.extend([b' '; 1016]);
    padded.extend_from_slice(b"t7Rk2pLq9WzX\n");
    let cases: [[&[u8]; 2]; 2] = [
        [&padded[..1025], &padded[1025..]],
        [br#"{"pass\u0077ord":"#, br#""private fixture"}"#],
    ];
    for parts in &cases {
        refused_as_sensitive(install_parts(&vault, parts));
        assert!(
            vault
                .lfs_object(LfsOid::digest(&parts.concat()))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn a_stored_chunk_is_read_again_when_another_object_reuses_it() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let stored: &[u8] = b"password=t7Rk2pLq9WzX\n";
    set_secret_scan(&vault, crate::batch::secret_scan::SecretScanMode::Off);
    install_parts(&vault, &[stored]).unwrap();
    set_secret_scan(&vault, crate::batch::secret_scan::SecretScanMode::On);
    let parts: [&[u8]; 2] = [stored, b"host = db.internal\n"];
    // Read by chunk, as above the bound, and read whole.
    for whole_scan_max in [Some(0), None] {
        refused_as_sensitive(install_parts_within(&vault, &parts, whole_scan_max));
        assert!(
            vault
                .lfs_object(LfsOid::digest(&parts.concat()))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn the_switch_is_read_where_each_write_of_an_object_lands() {
    use crate::batch::secret_scan::SecretScanMode::{Off, On};
    // The parts, the whole-read bound, the refusal.
    type Case = ([&'static [u8]; 2], Option<u64>, &'static str);
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let stored: &[u8] = b"password=t7Rk2pLq9WzX\n";
    set_secret_scan(&vault, Off);
    install_parts(&vault, &[stored]).unwrap();
    // The owner switches the scan on while the first chunk is on its way: a
    // stored chunk reused, an object read whole at publish, and one past the
    // bound whose edges went unread.
    let cases: [Case; 4] = [
        (
            [stored, b"host = db.internal\n"],
            None,
            "gate.secret_scan.sensitive_env",
        ),
        (
            [stored, b"host = db.internal\n"],
            Some(0),
            "gate.secret_scan.sensitive_env",
        ),
        (
            [b"host = db.internal\npassword=", b"t7Rk2pLq9WzX\n"],
            None,
            "gate.secret_scan.sensitive_env",
        ),
        (
            [b"host = a\n", b"port = 1\n"],
            Some(0),
            "gate.secret_scan.switched_on_mid_object",
        ),
    ];
    for (parts, whole_scan_max, reason) in cases {
        set_secret_scan(&vault, Off);
        let error = install_parts_with(&vault, &parts, whole_scan_max, |index| {
            if index == 0 {
                set_secret_scan(&vault, On);
            }
        })
        .unwrap_err();
        assert!(
            matches!(&error, crate::error::Error::Gate(crate::error::GateError::GateWriteRejected { reason_codes, .. })
                if reason_codes.contains(&reason)),
            "{reason}: {error:?}"
        );
        assert!(
            vault
                .lfs_object(LfsOid::digest(&parts.concat()))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn a_repeated_chunk_is_supplied_from_the_store_once_it_landed() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let part: &[u8] = b"host = db.internal\n";
    let whole = part.repeat(3);
    let chunk = chunks::LfsChunkRef {
        hash: *blake3::hash(part).as_bytes(),
        size: part.len() as u32,
    };
    let manifest = chunks::LfsManifest {
        size_bytes: whole.len() as u64,
        chunks: vec![chunk; 3],
    };
    // A sync pull asks its peer only for a chunk the store lacks, through the
    // store's own read: a generic reader finds no chunk before publication.
    let mut fetched = 0;
    vault
        .install_lfs_manifest(
            LfsOid::digest(&whole),
            &manifest,
            time(),
            time().start,
            |chunk| {
                if vault
                    .get_raw_unsealed(&chunks::chunk_id(&chunk.hash)?)?
                    .is_none()
                {
                    fetched += 1;
                }
                Ok(part.to_vec())
            },
        )
        .unwrap();
    assert_eq!(fetched, 1);
}

#[test]
fn no_generic_reader_returns_a_chunk_before_its_object_is_published() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    // Each chunk passes alone; the object they make is refused when read whole.
    let parts: [&[u8]; 3] = [br#"{"pass\u0077ord":"#, br#""private fixture"}"#, b"\n"];
    let id = |part: &[u8]| chunks::chunk_id(blake3::hash(part).as_bytes()).unwrap();
    let read = |vault: &Vault, wanted: &[&[u8]]| -> Vec<Vec<u8>> {
        let mut bodies: Vec<Vec<u8>> = vault
            .latest_entity_bodies_by_type(ENTITY_TYPE_ASSET, 64, 4096)
            .unwrap()
            .into_iter()
            .map(|(_, _, body)| body)
            .collect();
        for &part in wanted {
            bodies.extend(vault.get(&id(part)).unwrap());
            bodies.extend(
                vault
                    .get_raw(&id(part))
                    .unwrap()
                    .map(|raw| raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec()),
            );
        }
        bodies.retain(|body| wanted.contains(&body.as_slice()));
        bodies
    };
    let mut paused = Vec::new();
    refused_as_sensitive(install_parts_with(&vault, &parts, None, |index| {
        if index == 2 {
            // The first two chunks have landed; the third is on its way.
            assert!(vault.get_raw_unsealed(&id(parts[1])).unwrap().is_some());
            paused = read(&vault, &parts[..2]);
        }
    }));
    assert!(paused.is_empty(), "read before publication: {paused:?}");
    assert!(read(&vault, &parts[..]).is_empty());
    // A published object's chunks read as any ASSET does.
    let published: [&[u8]; 2] = [b"host = db.internal\n", b"port = 5432\n"];
    install_parts(&vault, &published).unwrap();
    assert_eq!(read(&vault, &published[..]).len(), 3 * published.len());
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
    // Past the default per-object cap, so the upload names its own.
    vault
        .put_lfs_object_stream_with_cap(
            oid,
            Some(size),
            size,
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
        .put_lfs_object_stream_with_cap(
            edited_oid,
            Some(size),
            size,
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
