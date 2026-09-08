//! Short-ID allocation/layout plus per-version storage-ABI rejection gates.

use super::*;

#[test]
fn batch_put_assigns_short_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id1 = EntityId::now();
    let id2 = EntityId::now();
    let data1 = b"entity-one";
    let data2 = b"entity-two";

    vault
        .batch()
        .put(&id1, 1, test_time_range(1, 1), 2, data1)
        .put(&id2, 1, test_time_range(3, 3), 4, data2)
        .commit()?;

    let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id1)?)?;
    let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id2)?)?;
    assert_eq!(short_id1, "tn1");
    assert_eq!(short_id2, "tn2");
    assert_eq!(hash1, content_hash(data1));
    assert_eq!(hash2, content_hash(data2));
    Ok(())
}

#[test]
fn batch_put_short_id_round_trips_both_directions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"reverse";

    // TURN (type 1), not CLAIM (type 0): the parallel ONE-1104 branch validates
    // all type-0 bodies (claim ABI), and merge rehearsal twice caught one of its
    // bulk 0->1 migration hunks silently anchoring into the wrong test. Seeding
    // type 1 keeps the round-trip purpose intact and removes the landmine.
    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, data)
        .commit()?;

    // Reverse direction (row n4): entity_id -> (short_id, content_hash).
    let short_id_value = read_short_id_value(&vault, &id)?;
    let (short_id, hash) = decode_short_id_value(&short_id_value)?;
    assert_eq!(short_id, "tn1");
    assert_eq!(hash, content_hash(data));

    // Forward direction (row n3): (short_id, content_hash) -> entity_id.
    let mut forward_key = short_id.as_bytes().to_vec();
    forward_key.push(hash);
    let rtxn = vault.store.env.read_txn()?;
    let forward = vault
        .store
        .short_ids
        .get(&rtxn, &forward_key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(forward.as_ref(), id.as_bytes());

    // A stale forward probe (wrong content hash) must NOT resolve: the hash
    // is part of the key, so it acts as a staleness check on resolution.
    let mut stale_key = short_id.as_bytes().to_vec();
    stale_key.push(hash.wrapping_add(1));
    assert!(vault.store.short_ids.get(&rtxn, &stale_key)?.is_none());
    Ok(())
}

/// ARCH-0019 dbManifest rows pinned byte-for-byte via a direct raw cursor
/// (NOT the short-id API):
///
/// * row n3 `short_ids`: key `(short_id, content_hash)` → value `entity_id`
/// * row n4 `short_ids_reverse`: key `entity_id` → value `(short_id, content_hash)`
///
/// A still-swapped implementation (short_ids keyed by the 16-byte entity id,
/// short_ids_reverse keyed by the bare short id) FAILS every assertion here.
#[test]
fn short_id_dbs_match_pinned_manifest_rows_raw_layout() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"short-id-layout-spec";

    // Type 1 (TURN) fixture: keeps this raw-layout spec off the CLAIM type
    // byte, whose body bytes are validated by the claim-body ABI.
    vault
        .batch()
        .put(&id, 1, test_time_range(7, 7), 8, data)
        .commit()?;

    // content_hash = xxh32(data, 0) % 256; first issued TURN short id = "tn1".
    let expected_hash = content_hash(data);
    let mut expected_pair = b"tn1".to_vec();
    expected_pair.push(expected_hash);

    let rtxn = vault.store.env.read_txn()?;

    // Row n3: exactly ONE forward row — key = short_id bytes ‖ content_hash
    // u8, value = the 16-byte entity id. No counter sentinel rows.
    // ONE-1890 seeds six AGENT_DEF rows into every vault, each with its own
    // `ag*` short id; this row is about the TURN entity written above.
    let forward_rows: Vec<(Vec<u8>, Vec<u8>)> = vault
        .store
        .short_ids
        .iter(&rtxn)?
        .map(|entry| entry.map(|(k, v)| (k.to_vec(), v.to_vec())))
        .filter(|row| {
            row.as_ref()
                .is_ok_and(|(_, value)| value.as_slice() == id.as_bytes())
        })
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(
        forward_rows.len(),
        1,
        "short_ids must hold only the manifest row (no sentinels): {forward_rows:?}"
    );
    assert_eq!(forward_rows[0].0, expected_pair, "forward KEY bytes");
    assert_eq!(
        forward_rows[0].1,
        id.as_bytes().to_vec(),
        "forward VALUE = 16-byte entity id"
    );

    // Row n4: exactly ONE reverse row — key = 16-byte entity id, value =
    // short_id bytes ‖ content_hash u8.
    let reverse_rows: Vec<(Vec<u8>, Vec<u8>)> = vault
        .store
        .short_ids_reverse
        .iter(&rtxn)?
        .map(|entry| entry.map(|(k, v)| (k.to_vec(), v.to_vec())))
        .filter(|row| {
            row.as_ref()
                .is_ok_and(|(key, _)| key.as_slice() == id.as_bytes())
        })
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(reverse_rows.len(), 1);
    assert_eq!(
        reverse_rows[0].0,
        id.as_bytes().to_vec(),
        "reverse KEY = 16-byte entity id"
    );
    assert_eq!(reverse_rows[0].1, expected_pair, "reverse VALUE bytes");
    Ok(())
}

/// Per-type short-id counters live in `vault_meta` under the documented
/// `b"sid_counter:" ‖ type_byte` scheme (u64 LE value) — NOT as
/// `[type_byte, 0xFF×15]` sentinel rows inside `short_ids` (pre-ABI-v3
/// layout). Scans the whole `short_ids` DB and asserts no sentinel remains.
#[test]
fn short_id_counters_live_in_vault_meta_not_short_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn_a = EntityId::now();
    let turn_b = EntityId::now();
    let session = EntityId::now();

    // Types 1 (TURN) and 2 (SESSION) exercise two distinct per-type counters
    // while keeping fixtures off the CLAIM type byte, whose body bytes are
    // validated by the claim-body ABI.
    vault
        .batch()
        .put(&turn_a, 1, test_time_range(1, 1), 2, b"turn-a")
        .put(&turn_b, 1, test_time_range(3, 3), 4, b"turn-b")
        .put(&session, 2, test_time_range(5, 5), 6, b"session-a")
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;

    for entry in vault.store.short_ids.iter(&rtxn)? {
        let (key, value) = entry?;
        assert!(
            !(key.len() == 16 && key[1..].iter().all(|&b| b == 0xFF)),
            "short_ids must not contain [type_byte, 0xFF x15] counter sentinels: {key:?}"
        );
        assert_eq!(
            value.len(),
            16,
            "every short_ids value must be a 16-byte entity id (counter rows were 8-byte): {value:?}"
        );
    }

    // Documented key scheme, pinned as literal bytes: 12-byte ASCII prefix
    // "sid_counter:" + raw type byte; value = last issued counter u64 LE.
    let turn_counter = vault
        .store
        .vault_meta
        .get(&rtxn, b"sid_counter:\x01")?
        .expect("TURN counter must live in vault_meta");
    assert_eq!(*turn_counter, 2_u64.to_le_bytes());
    let session_counter = vault
        .store
        .vault_meta
        .get(&rtxn, b"sid_counter:\x02")?
        .expect("SESSION counter must live in vault_meta");
    assert_eq!(*session_counter, 1_u64.to_le_bytes());
    Ok(())
}

/// Pins the short-id content hash formula `xxh32(data, 0) % 256` (u8) with a
/// precomputed literal so a formula/seed/width drift FAILS without relying on
/// the engine's own helper.
#[test]
fn short_id_content_hash_is_xxh32_of_data_mod_256() -> Result<()> {
    const EXPECTED_CONTENT_HASH: u8 = 105;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // xxh32(b"short-id-hash-pin", seed 0) = 0xc8d57569; 0xc8d57569 % 256 = 105.
    let data = b"short-id-hash-pin";

    // Type 1 (TURN) fixture: the hash formula is type-independent, and this
    // keeps the fixture off the CLAIM type byte, whose body bytes are
    // validated by the claim-body ABI. First issued TURN short id = "tn1".
    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 2, data)
        .commit()?;

    let (_, hash) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;
    assert_eq!(hash, EXPECTED_CONTENT_HASH);

    // The same byte is embedded in the forward KEY.
    let mut forward_key = b"tn1".to_vec();
    forward_key.push(EXPECTED_CONTENT_HASH);
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &forward_key)?.as_deref(),
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

/// M0-4 fail-closed gate over the M2-5 bump: vaults written under storage ABI
/// v2 (pre short-id direction swap) are REJECTED at open with the typed gate
/// error. Pins the literal stored version 2 against the current constant —
/// an implementation that skipped the bump would open the old vault and FAIL
/// this test.
#[test]
fn open_rejects_abi_v2_vault_after_short_id_swap() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(2))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-swap ABI v2 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(2),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(2), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1293 fail-closed gate over the maintenance-band type-byte realignment:
/// vaults written under storage ABI v4 have POLICY_MANIFEST at 122 and
/// FEDERATION_GRANT at 123, while v5 allocates 122 for AUTHORITY_LOG and moves
/// those kinds to 123/124. There is NO silent migration.
#[test]
fn open_rejects_abi_v4_vault_after_maintenance_band_reallocation() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "ONE-1754 pins the current storage ABI at 17 for the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(4))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1293 ABI v4 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(4),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(4), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1204 fail-closed gate over registering persistent maintenance type
/// PSYCH_PROFILE at byte 129: v5 code does not know this persistent entity
/// kind, so v5 vaults must not open under ABI v6 without rebuild.
#[test]
fn open_rejects_abi_v5_vault_after_psych_profile_type_registration() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "ONE-1754 pins the current storage ABI at 17 for the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(5))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1204 ABI v5 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(5),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(5), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1206 fail-closed gate over adding the generic attempt queue DBs: v6 code
/// does not know `job_records`, `job_ready`, or `job_dedupe`, so v6 vaults
/// must not open under ABI v7 without rebuild.
#[test]
fn open_rejects_abi_v6_vault_after_attempt_queue_manifest_addition() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "ONE-1754 pins the current storage ABI at 17 for the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(6))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1206 ABI v6 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(6),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(6), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1213 fail-closed gate over adding durable attempt queue terminal states:
/// v7 queue readers do not know `Completed`/`Failed` rows, so v7 vaults must
/// not open under ABI v8 without rebuild.
#[test]
fn open_rejects_abi_v7_vault_after_attempt_queue_terminal_states() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "ONE-1754 pins the current storage ABI at 17 for the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(7))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1213 ABI v7 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(7),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(7), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1530 fail-closed gate over registering persistent maintenance type
/// OUTBOUND_GRANT at byte 133: v8 code does not know this persistent entity
/// kind, so v8 vaults must not open under ABI v9 without rebuild.
#[test]
fn open_rejects_abi_v8_vault_after_outbound_grant_type_registration() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "ONE-1754 pins the current storage ABI at 17 for the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(8))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1530 ABI v8 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(8),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(8), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1443 fail-closed gate over registering persistent CORE type AGENT_DEF at
/// byte 17: v9 code does not know this persistent entity kind, so v9 vaults must
/// not open under the current ABI without rebuild.
#[test]
fn open_rejects_abi_v9_vault_after_agent_def_type_registration() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "ONE-1754 pins the current storage ABI at 17 for the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(9))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1443 ABI v9 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(9),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(9), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// Both public and internal open paths must traverse the same strict ABI gate.
/// The newer stored value exercises the anti-downgrade direction: an older
/// reader whose `current` version is lower rejects a newer vault by the same
/// equality rule tested exhaustively in `store::tests`.
#[test]
fn storage_abi_gate_runs_on_store_and_vault_open_paths() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 17,
        "current readers must advertise ABI 17 after the byte-space v3 type-byte re-key",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let _vault = Vault::open(path, test_config())?;
    }
    let newer_abi = STORAGE_ABI_VERSION + 1;
    set_raw_storage_abi_version(path, Some(newer_abi))?;

    let store_err = match Store::open(path, &test_config()) {
        Ok(_) => panic!("Store::open must run the ABI gate"),
        Err(err) => err,
    };
    assert!(matches!(
        store_err,
        Error::StorageAbiVersionChanged {
            stored: Some(stored),
            current: STORAGE_ABI_VERSION,
        } if stored == newer_abi
    ));

    let vault_err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("Vault::open must run the ABI gate through Store::open"),
        Err(err) => err,
    };
    assert!(matches!(
        vault_err,
        Error::StorageAbiVersionChanged {
            stored: Some(stored),
            current: STORAGE_ABI_VERSION,
        } if stored == newer_abi
    ));
    Ok(())
}
