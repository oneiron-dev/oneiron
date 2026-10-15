//! Short-ID allocation/layout plus per-version storage-ABI rejection gates.

use super::*;
use crate::error::StoreError;

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

/// Both public and internal open paths must traverse the same strict ABI gate.
/// The newer stored value exercises the anti-downgrade direction: an older
/// reader whose `current` version is lower rejects a newer vault by the same
/// equality rule tested exhaustively in `store::tests`.
#[test]
fn storage_abi_gate_runs_on_store_and_vault_open_paths() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 21,
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
        Error::Store(StoreError::StorageAbiVersionChanged {
            stored: Some(stored),
            current: STORAGE_ABI_VERSION,
        }) if stored == newer_abi
    ));

    let vault_err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("Vault::open must run the ABI gate through Store::open"),
        Err(err) => err,
    };
    assert!(matches!(
        vault_err,
        Error::Store(StoreError::StorageAbiVersionChanged {
            stored: Some(stored),
            current: STORAGE_ABI_VERSION,
        }) if stored == newer_abi
    ));
    Ok(())
}
