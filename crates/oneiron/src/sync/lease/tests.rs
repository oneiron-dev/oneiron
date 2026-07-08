use super::*;
use crate::types::VaultConfig;
use ed25519_dalek::SigningKey;

const TEST_RECEIPT_LEARNED_AT: u64 = 1_772_400_000;

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.embedding_model = None;
    let vault = Vault::open(dir.path(), cfg).unwrap();
    (dir, vault)
}

fn signed_receipt(seed: u8, client_id: u64) -> (EntityId, [u8; 32], Vec<u8>) {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let receipt_id = EntityId::now();
    let subject = EntityId::now();
    let input = crate::deletion::RedactionReceiptInput {
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: TEST_RECEIPT_LEARNED_AT,
        sweep_queued_at: Some(102),
    };
    let identity = crate::identity::DeviceIdentity {
        client_id,
        signing_key,
    };
    let body =
        crate::deletion::encode_redaction_audit_receipt(input, &receipt_id, &identity).unwrap();
    let mut blob = crate::deletion::receipt_envelope_header(TEST_RECEIPT_LEARNED_AT).to_vec();
    blob.extend_from_slice(&body);
    (receipt_id, pubkey, blob)
}

fn put_lease_row(
    vault: &Vault,
    vault_id: u64,
    client_id: u64,
    pubkey: [u8; 32],
    status: LeaseStatus,
) {
    let record = LeaseRecord {
        vault_id,
        status,
        pubkey,
        granted_at: 1,
        renewed_at: 2,
        expires_at: 3,
    };
    vault
        .sync_state_put(
            &lease_key(vault_id, client_id),
            &encode_lease_record(&record),
        )
        .unwrap();
}

fn verify_receipt_for_vault(
    vault: &Vault,
    vault_id: u64,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    let rtxn = vault.store.env.read_txn().unwrap();
    verify_new_receipt_origin_for_vault_in_txn(vault, &rtxn, vault_id, id, blob).map(|_| ())
}

/// OD-4 layout literals: 66 B, version 0x02, status byte at [1],
/// pubkey at [2..34], three u64 LE timestamps, vault_id u64 BE — a
/// transposed field or BE/LE flip fails here, not at a remote door.
#[test]
fn lease_record_layout_literals_round_trip() {
    let record = LeaseRecord {
        vault_id: 0x0102030405060708,
        status: LeaseStatus::Active,
        pubkey: [0xAB; 32],
        granted_at: 0x0102030405060708,
        renewed_at: 0x1112131415161718,
        expires_at: 0x2122232425262728,
    };
    let encoded = encode_lease_record(&record);
    assert_eq!(encoded.len(), LEASE_RECORD_LEN);
    assert_eq!(encoded.len(), 66);
    assert_eq!(encoded[0], 0x02, "version byte");
    assert_eq!(encoded[1], 0x01, "active status byte");
    assert_eq!(&encoded[2..34], &[0xAB; 32]);
    assert_eq!(
        &encoded[34..42],
        &0x0102030405060708u64.to_le_bytes(),
        "granted_at u64 LE"
    );
    assert_eq!(&encoded[42..50], &0x1112131415161718u64.to_le_bytes());
    assert_eq!(&encoded[50..58], &0x2122232425262728u64.to_le_bytes());
    assert_eq!(
        &encoded[58..66],
        &0x0102030405060708u64.to_be_bytes(),
        "vault_id u64 BE"
    );
    assert_eq!(decode_lease_record(&encoded).unwrap(), record);

    // Status wire bytes (OD-4): active=0x01, expired=0x02, revoked=0x03.
    for (status, byte) in [
        (LeaseStatus::Active, 0x01u8),
        (LeaseStatus::Expired, 0x02),
        (LeaseStatus::Revoked, 0x03),
    ] {
        assert_eq!(status as u8, byte);
        assert_eq!(LeaseStatus::from_wire_byte(byte), Some(status));
    }

    // Compat/fail-closed decode: the 58 B v1 layout and any wrong length
    // are refused; unknown status keeps its pinned error literal.
    let mut legacy_v1 = [0u8; 58];
    legacy_v1[0] = 0x01;
    legacy_v1[1] = 0x01;
    assert!(matches!(
        decode_lease_record(&legacy_v1),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        decode_lease_record(&encoded[..65]),
        Err(Error::CorruptedIndex(_))
    ));
    let mut overlong = encoded.to_vec();
    overlong.push(0);
    assert!(matches!(
        decode_lease_record(&overlong),
        Err(Error::CorruptedIndex(_))
    ));
    let mut bad_version = encoded;
    bad_version[0] = 0x01;
    assert!(matches!(
        decode_lease_record(&bad_version),
        Err(Error::CorruptedIndex(_))
    ));
    let mut bad_status = encoded;
    bad_status[1] = 0x00;
    assert!(matches!(
        decode_lease_record(&bad_status),
        Err(Error::CorruptedIndex("lease record status"))
    ));
}

/// OD-4 key grammar: `ls:` + `{vault_id:016x}` + `:` +
/// `{client_id:016x}` (BE nibble order ⇒ lexically sortable, 36 B total).
#[test]
fn lease_key_grammar_literal() {
    assert_eq!(client_id_hex(0x0123456789abcdef), "0123456789abcdef");
    assert_eq!(vault_id_hex(0x0102030405060708), "0102030405060708");
    let registry_key = lease_registry_key(0x0102030405060708, 0x0123456789abcdef);
    assert_eq!(registry_key, "0102030405060708:0123456789abcdef");
    assert_eq!(registry_key.len(), 33);
    assert_eq!(
        decode_lease_registry_key(&registry_key).unwrap(),
        LeaseRegistryKey {
            vault_id: Some(0x0102030405060708),
            client_id: 0x0123456789abcdef,
        }
    );
    assert_eq!(
        decode_lease_registry_key("0123456789abcdef").unwrap(),
        LeaseRegistryKey {
            vault_id: None,
            client_id: 0x0123456789abcdef,
        }
    );
    assert!(decode_lease_registry_key("0102030405060708:0123456789abcdeF").is_err());
    assert!(decode_lease_registry_key("0102030405060708:0123456789abcdef:00").is_err());
    assert_eq!(lease_key_prefix(0x0102030405060708), "ls:0102030405060708:");
    let key = lease_key(0x0102030405060708, 0x0123456789abcdef);
    assert_eq!(key, "ls:0102030405060708:0123456789abcdef");
    assert_eq!(key.len(), 36);
    assert_eq!(lease_key(7, 7), "ls:0000000000000007:0000000000000007");
}

#[test]
fn lease_prefix_scan_isolates_vault_dimension() {
    let (_dir, vault) = test_vault();
    let vault_a = 0x0a0b0c0d0e0f1011;
    let vault_b = 0x11100f0e0d0c0b0a;
    let client = 0x0123456789abcdef;
    let record_a = LeaseRecord {
        vault_id: vault_a,
        status: LeaseStatus::Active,
        pubkey: [0xA1; 32],
        granted_at: 1,
        renewed_at: 2,
        expires_at: 3,
    };
    let record_b = LeaseRecord {
        vault_id: vault_b,
        pubkey: [0xB2; 32],
        ..record_a
    };
    let row_a = encode_lease_record(&record_a);
    let row_b = encode_lease_record(&record_b);
    vault
        .sync_state_put(&lease_key(vault_a, client), &row_a)
        .unwrap();
    vault
        .sync_state_put(&lease_key(vault_b, client), &row_b)
        .unwrap();

    let rtxn = vault.store.env.read_txn().unwrap();
    let scoped_prefix = lease_key_prefix(vault_a);
    assert_eq!(scoped_prefix, "ls:0a0b0c0d0e0f1011:");
    let rows = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, &scoped_prefix)
        .unwrap()
        .map(|entry| {
            let (key, value) = entry.unwrap();
            (key.to_string(), value.to_vec())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![(
            "ls:0a0b0c0d0e0f1011:0123456789abcdef".to_owned(),
            row_a.to_vec()
        )]
    );
}

#[test]
fn receipt_door_uses_vault_scoped_claimed_lookup() {
    let (_dir, vault) = test_vault();
    let vault_a = 0x0a0b_0c0d_0e0f_1011;
    let vault_b = 0x1110_0f0e_0d0c_0b0a;
    let client = 0x0123_4567_89ab_cdef;
    let (receipt_id, pubkey, blob) = signed_receipt(0x21, client);

    put_lease_row(&vault, vault_a, client, pubkey, LeaseStatus::Active);

    let err = verify_receipt_for_vault(&vault, vault_b, &receipt_id, &blob).unwrap_err();
    assert!(
        matches!(err, Error::ReceiptLeaseUnknown { client_id } if client_id == client),
        "another vault's binding must not satisfy the claimed lookup: {err:?}"
    );
    assert!(
        verify_receipt_for_vault(&vault, vault_a, &receipt_id, &blob).is_ok(),
        "the same receipt must pass against the vault that owns the binding"
    );
}

#[test]
fn receipt_door_scopes_pubkey_revocation_floor_to_vault_prefix() {
    let (_dir, vault) = test_vault();
    let vault_a = 0x0a0b_0c0d_0e0f_1011;
    let vault_b = 0x1110_0f0e_0d0c_0b0a;
    let revoked_client_a = 0xaaaa_aaaa_aaaa_aaaa;
    let active_client_b = 0xbbbb_bbbb_bbbb_bbbb;
    let revoked_client_b = 0xcccc_cccc_cccc_cccc;
    let (receipt_id, pubkey, blob) = signed_receipt(0x31, active_client_b);

    put_lease_row(
        &vault,
        vault_a,
        revoked_client_a,
        pubkey,
        LeaseStatus::Revoked,
    );
    put_lease_row(
        &vault,
        vault_b,
        active_client_b,
        pubkey,
        LeaseStatus::Active,
    );

    assert!(
        verify_receipt_for_vault(&vault, vault_b, &receipt_id, &blob).is_ok(),
        "a revoked pubkey in vault A must not bleed into vault B"
    );

    put_lease_row(
        &vault,
        vault_b,
        revoked_client_b,
        pubkey,
        LeaseStatus::Revoked,
    );
    let err = verify_receipt_for_vault(&vault, vault_b, &receipt_id, &blob).unwrap_err();
    assert!(
        matches!(err, Error::ReceiptLeaseRevoked { client_id } if client_id == active_client_b),
        "same-vault revoked pubkey must still reject: {err:?}"
    );
}

#[test]
fn receipt_door_preserves_same_vault_expired_plus_revoked_floor() {
    let (_dir, vault) = test_vault();
    let vault_id = 0x0102_0304_0506_0708;
    let expired_client = 0x1111_1111_1111_1111;
    let revoked_client = 0x2222_2222_2222_2222;
    let (receipt_id, pubkey, blob) = signed_receipt(0x41, expired_client);

    put_lease_row(
        &vault,
        vault_id,
        expired_client,
        pubkey,
        LeaseStatus::Expired,
    );
    put_lease_row(
        &vault,
        vault_id,
        revoked_client,
        pubkey,
        LeaseStatus::Revoked,
    );

    let err = verify_receipt_for_vault(&vault, vault_id, &receipt_id, &blob).unwrap_err();
    assert!(
        matches!(err, Error::ReceiptLeaseRevoked { client_id } if client_id == expired_client),
        "expired claimed rows still accept OD-7, but same-vault revoked pubkey floor rejects"
    );
}

#[test]
fn revoked_claimed_row_returns_claimed_client_id_before_scoped_floor_scan() {
    let (_dir, vault) = test_vault();
    let vault_id = 0x0102_0304_0506_0708;
    let claimed_client = 0x4545_4545_4545_4545u64;
    let corrupt_sibling_client = 0x4545_4545_4545_0001u64;
    let (receipt_id, pubkey, blob) = signed_receipt(0x45, claimed_client);

    put_lease_row(
        &vault,
        vault_id,
        claimed_client,
        pubkey,
        LeaseStatus::Revoked,
    );
    vault
        .sync_state_put(&lease_key(vault_id, corrupt_sibling_client), b"too-short")
        .unwrap();

    let err = verify_receipt_for_vault(&vault, vault_id, &receipt_id, &blob)
        .expect_err("revoked claimed row must reject before scanning corrupt siblings");
    assert!(
        matches!(err, Error::ReceiptLeaseRevoked { client_id } if client_id == claimed_client),
        "claimed-row revoked path must return the claimed client_id, got: {err:?}"
    );
}

#[test]
fn mismatched_claimed_lease_key_vault_fails_closed_before_floor_scope() {
    let (_dir, vault) = test_vault();
    let trusted_vault_id = 0x0102_0304_0506_0708;
    let payload_vault_id = 0x0807_0605_0403_0201;
    let claimed_client = 0x4646_4646_4646_4646u64;
    let revoked_sibling_client = 0x4646_4646_4646_0001u64;
    let (receipt_id, pubkey, blob) = signed_receipt(0x46, claimed_client);
    let claimed_record = LeaseRecord {
        vault_id: payload_vault_id,
        status: LeaseStatus::Active,
        pubkey,
        granted_at: 10,
        renewed_at: 20,
        expires_at: 30,
    };
    vault
        .sync_state_put(
            &lease_key(trusted_vault_id, claimed_client),
            &encode_lease_record(&claimed_record),
        )
        .unwrap();
    put_lease_row(
        &vault,
        trusted_vault_id,
        revoked_sibling_client,
        pubkey,
        LeaseStatus::Revoked,
    );

    let err = verify_receipt_for_vault(&vault, trusted_vault_id, &receipt_id, &blob)
        .expect_err("key/payload vault mismatch must not scope the floor to payload vault");
    assert!(
        matches!(err, Error::CorruptedIndex("lease record vault_id")),
        "local lease key/value mismatch must fail closed, got: {err:?}"
    );
}

#[test]
fn receipt_door_corrupt_sibling_row_is_vault_scoped() {
    let (_dir, vault) = test_vault();
    let vault_a = 0x0a0b_0c0d_0e0f_1011;
    let vault_b = 0x1110_0f0e_0d0c_0b0a;
    let client = 0x0123_4567_89ab_cdef;
    let (receipt_id, pubkey, blob) = signed_receipt(0x51, client);

    put_lease_row(&vault, vault_a, client, pubkey, LeaseStatus::Active);
    vault
        .sync_state_put(
            &lease_key(vault_b, 0xdead_beef_dead_beef),
            b"corrupt-outside-scope",
        )
        .unwrap();

    assert!(
        verify_receipt_for_vault(&vault, vault_a, &receipt_id, &blob).is_ok(),
        "a corrupt row under another vault prefix must not affect this vault"
    );

    vault
        .sync_state_put(
            &lease_key(vault_a, 0xfeed_face_feed_face),
            b"corrupt-inside-scope",
        )
        .unwrap();
    let err = verify_receipt_for_vault(&vault, vault_a, &receipt_id, &blob).unwrap_err();
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "a corrupt same-vault sibling row must fail closed: {err:?}"
    );
}

#[test]
fn root_lease_mirror_keeps_foreign_vault_row_for_same_client() {
    let (_dir, vault) = test_vault();
    let doc = LoroDoc::new();
    let old_vault_id = 0x0101_0101_0101_0101;
    let new_vault_id = 0x0202_0202_0202_0202;
    let client_id = 0x0a0b_0c0d_0e0f_1011;

    let old_record = LeaseRecord {
        vault_id: old_vault_id,
        status: LeaseStatus::Active,
        pubkey: [0xA1; 32],
        granted_at: 10,
        renewed_at: 20,
        expires_at: 30,
    };
    let new_record = LeaseRecord {
        vault_id: new_vault_id,
        pubkey: [0xB2; 32],
        ..old_record
    };
    let old_key = lease_key(old_vault_id, client_id);
    let new_key = lease_key(new_vault_id, client_id);
    let old_bytes = encode_lease_record(&old_record);
    let new_bytes = encode_lease_record(&new_record);

    vault.sync_state_put(&old_key, &old_bytes).unwrap();
    doc.get_map(ROOT_LEASES_MAP)
        .insert(client_id_hex(client_id).as_str(), new_bytes.as_slice())
        .unwrap();
    doc.commit();

    mirror_leases_from_root(&vault, &doc).unwrap();
    assert_eq!(
        vault.sync_state_get(&old_key).unwrap().as_deref(),
        Some(old_bytes.as_slice()),
        "mirror cleanup must not delete a same-client row under another vault prefix"
    );
    assert_eq!(
        vault.sync_state_get(&new_key).unwrap().as_deref(),
        Some(new_bytes.as_slice())
    );
}

#[test]
fn root_lease_mirror_isolates_tenants_for_same_subscriber() {
    let (_dir, vault) = test_vault();
    let doc = LoroDoc::new();
    let tenant_a = 0x0a0b_0c0d_0e0f_1011;
    let tenant_b = 0x1110_0f0e_0d0c_0b0a;
    let subscriber = 0x0123_4567_89ab_cdef;
    let record_a = LeaseRecord {
        vault_id: tenant_a,
        status: LeaseStatus::Revoked,
        pubkey: [0xA1; 32],
        granted_at: 10,
        renewed_at: 20,
        expires_at: 30,
    };
    let record_b = LeaseRecord {
        vault_id: tenant_b,
        status: LeaseStatus::Active,
        pubkey: [0xA1; 32],
        ..record_a
    };
    let bytes_a = encode_lease_record(&record_a);
    let bytes_b = encode_lease_record(&record_b);
    let leases = doc.get_map(ROOT_LEASES_MAP);
    leases
        .insert(
            lease_registry_key(tenant_a, subscriber).as_str(),
            bytes_a.as_slice(),
        )
        .unwrap();
    leases
        .insert(
            lease_registry_key(tenant_b, subscriber).as_str(),
            bytes_b.as_slice(),
        )
        .unwrap();
    doc.commit();

    mirror_leases_from_root(&vault, &doc).unwrap();

    assert_eq!(
        vault
            .sync_state_get(&lease_key(tenant_a, subscriber))
            .unwrap()
            .as_deref(),
        Some(bytes_a.as_slice()),
        "tenant A revoked replay-door row must stay under tenant A"
    );
    assert_eq!(
        vault
            .sync_state_get(&lease_key(tenant_b, subscriber))
            .unwrap()
            .as_deref(),
        Some(bytes_b.as_slice()),
        "tenant B active replay-door row must stay under tenant B"
    );
}

#[test]
fn root_lease_map_value_matches_mirror_row_value() {
    let (_dir, vault) = test_vault();
    let doc = LoroDoc::new();
    let vault_id = 0x0102030405060708;
    let client_id = 0x0a0b0c0d0e0f1011;
    let record = LeaseRecord {
        vault_id,
        status: LeaseStatus::Expired,
        pubkey: [0x5A; 32],
        granted_at: 10,
        renewed_at: 20,
        expires_at: 30,
    };
    let bytes = encode_lease_record(&record);
    doc.get_map(ROOT_LEASES_MAP)
        .insert(
            lease_registry_key(vault_id, client_id).as_str(),
            bytes.as_slice(),
        )
        .unwrap();
    doc.commit();

    mirror_leases_from_root(&vault, &doc).unwrap();
    assert_eq!(
        vault
            .sync_state_get("ls:0102030405060708:0a0b0c0d0e0f1011")
            .unwrap()
            .as_deref(),
        Some(bytes.as_slice()),
        "root-doc leases value and ls: mirror value stay byte-identical"
    );
}

/// OD-6 PoP transcript literal: domain || client_id BE || pubkey. A
/// signature over a different client id must NOT verify (the transcript
/// binds both, which is what makes the frame replay-safe).
#[test]
fn lease_pop_transcript_binds_client_id_and_key() {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = key.verifying_key().to_bytes();

    let msg = lease_pop_transcript(0x0102030405060708, &pubkey);
    assert_eq!(&msg[..20], b"oneiron/lease-pop/v1");
    assert_eq!(&msg[20..28], &0x0102030405060708u64.to_be_bytes());
    assert_eq!(&msg[28..60], &pubkey);

    let sig = key.sign(&msg).to_bytes();
    assert!(verify_lease_pop(0x0102030405060708, &pubkey, &sig));
    assert!(
        !verify_lease_pop(0x0102030405060709, &pubkey, &sig),
        "a PoP signature must not transfer to a different client id"
    );
}
