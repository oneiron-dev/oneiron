//! A sealed AUTHORITY_LOG row in this vault (census L5-22): the door that
//! signs it stores the row in its scaffold form and the overlay record
//! beside it, sealed, and the vault's own reader opens the row whole, after
//! a reopen too.

use super::support::*;
use super::*;
use crate::side_table::{self, Raw, SideTable};
use crate::{OpenOptions, TimeRange, Vault, VaultConfig, VaultStorageId};
use oneiron_keystore::MemoryKeystore;
use std::sync::Arc;

const SECRET: &[u8] = b"overlay rows host root placeholder words";

fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn a_slip_minted_with_records_is_stored_sealed_and_reads_back_whole() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [91; 32];
    claims.records = BTreeSet::from(["record:a".to_owned()]);
    claims.channels = BTreeSet::from(["channel:a".to_owned()]);
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let entry_hash = vault.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let id = authority_log_entity_id_from_hash(&entry_hash).unwrap();

    // The stored row is the scaffold: it names neither the record nor the
    // channel, and without its overlay record it reads as unavailable.
    let raw = vault.get_raw(&id).unwrap().unwrap();
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    assert!(authority_body_is_sealed(body).unwrap());
    assert!(
        decode_authority_log_entry_body(body)
            .is_err_and(|error| is_authority_overlay_unavailable(&error))
    );
    assert!(!holds(body, b"record:a"));
    assert!(!holds(body, b"channel:a"));

    // The overlay record is kept under the hash of the stored body, sealed:
    // it does not name them either.
    let overlay: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
        SideTable::new(&side_table::AUTHORITY_OVERLAY);
    let rtxn = vault.store.env.read_txn().unwrap();
    let row = overlay
        .get(&vault.store, &rtxn, blake3::hash(body).as_bytes())
        .unwrap()
        .expect("the mint row's overlay record");
    drop(rtxn);
    assert!(!holds(&row, b"record:a"));
    assert!(!holds(&row, b"channel:a"));

    // The vault's own reader opens the row whole.
    let entry = vault.get_authority_log_entry(&id).unwrap().unwrap();
    let AuthorityOp::SlipMint(action) = &entry.op else {
        panic!("the mint row must open as a slip mint, not {:?}", entry.op);
    };
    assert_eq!(action.claims.slip_id, slip.claims.slip_id);
    assert_eq!(
        action.claims.records,
        BTreeSet::from(["record:a".to_owned()])
    );
    assert_eq!(
        action.claims.channels,
        BTreeSet::from(["channel:a".to_owned()])
    );
    assert_eq!(authority_entry_hash(&entry).unwrap(), entry_hash);

    // And again after the vault is closed and opened at the same path.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(vault.get_authority_log_entry(&id).unwrap(), Some(entry));
}

const PENDING_SECRET: &[u8] = b"pending overlay sealed grant host root";

/// A sealed granting row kept as FIX 2989 evidence lands whole once its
/// history arrives (census L5-22 round-2 P1-2): on a vault that adopted a
/// checkpoint image but holds none of its covered rows, a local append of a
/// sealed owner-role enrollment (grants-only, outside the adopted tail's
/// admits-past set, sealed by identifying attestation) is refused for
/// history and kept; once the covered history is imported, the import's
/// commit retries the evidence, the row lands, reads back open with its
/// attestation values, and leaves the evidence.
#[test]
fn a_sealed_grant_kept_as_evidence_lands_whole_once_its_history_arrives() {
    // The home vault: genesis plus the host root slip, which the image covers.
    let dir_a = tempfile::tempdir().unwrap();
    let vault_a = Vault::open(dir_a.path(), VaultConfig::default()).unwrap();
    vault_a.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = HostSlipIssuer::from_secret(PENDING_SECRET).unwrap();
    vault_a.ensure_host_root_slip(&issuer).unwrap();

    // The image, its pin and the bundle a new device adopts.
    let image_id = vault_a.write_authority_checkpoint_v2(&issuer).unwrap();
    let pin = vault_a.authority_checkpoint_pin([0; 32]).unwrap().unwrap();
    let bundle = vault_a
        .authority_checkpoint_bundle(&image_id)
        .unwrap()
        .unwrap();

    // A new device under the home's storage id: adopted, holding no history.
    let dir_b = tempfile::tempdir().unwrap();
    let vault_b = Vault::open_owned_with(
        dir_b.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(VaultStorageId::from_verified_pin(&pin)),
    )
    .unwrap();
    vault_b
        .adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations)
        .unwrap();

    // A sealed granting row whose fold past the image needs the whole
    // history: an owner-role enrollment is grants-only but no adopted tail
    // row, and identifying attestation seals it.
    let fold_b = vault_b.authority_fold().unwrap();
    assert!(fold_b.vault_id.is_some());
    let new_key = ed_key(77);
    let mut enrolled = device(
        authority_key_from_ed(&new_key),
        ROLE_ADMIN,
        AuthorityTier::Software,
    );
    enrolled.attestation = AuthorityAttestation {
        kind: "device-attestation".to_owned(),
        evidence: vec![9, 10, 11],
    };
    let now = vault_b.now_recorded_at();
    let entry = crate::authority::slip_vault::next_entry(
        &issuer,
        &fold_b,
        AuthorityOp::EnrollDevice {
            device: enrolled.clone(),
        },
        now,
    )
    .unwrap();
    assert!(
        entry.overlay_seed.is_some(),
        "an identifying attestation seals"
    );
    let body = encode_authority_log_entry_body(&entry).unwrap();
    assert!(authority_body_is_sealed(&body).unwrap());
    let hash = authority_entry_hash(&entry).unwrap();
    let id = authority_log_entity_id_from_hash(&hash).unwrap();

    // The local append is refused for history and the row is kept as evidence.
    let err = vault_b
        .put_authority_log_entries(&[(
            entry.clone(),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )])
        .unwrap_err();
    assert!(
        crate::authority::is_history_incomplete(&err),
        "a sealed grant past missing history waits for it: {err:?}"
    );
    assert!(vault_b.get_authority_log_entry(&id).unwrap().is_none());
    {
        let rtxn = vault_b.store.env.read_txn().unwrap();
        let pending = crate::authority::history_admission::pending_history_request_in_txn(
            &vault_b.store,
            vault_b.privacy_posture(),
            &rtxn,
        )
        .unwrap();
        assert!(pending.is_some(), "the refused row stays as evidence");
    }

    // The missing history arrives; the import stores it and retries the evidence.
    let history = vault_a.export_signed_authority_history().unwrap();
    vault_b.import_signed_authority_history(&history).unwrap();

    // The row lands whole and leaves the evidence.
    let stored = vault_b.get_authority_log_entry(&id).unwrap().unwrap();
    assert_eq!(authority_entry_hash(&stored).unwrap(), hash);
    let AuthorityOp::EnrollDevice { device: landed } = &stored.op else {
        panic!("the kept row must land as its enroll, not {:?}", stored.op);
    };
    assert_eq!(landed.key, enrolled.key);
    assert_eq!(landed.attestation.kind, "device-attestation".to_owned());
    assert_eq!(landed.attestation.evidence, vec![9, 10, 11]);
    {
        let rtxn = vault_b.store.env.read_txn().unwrap();
        let pending = crate::authority::history_admission::pending_history_request_in_txn(
            &vault_b.store,
            vault_b.privacy_posture(),
            &rtxn,
        )
        .unwrap();
        assert!(pending.is_none(), "a landed row leaves the evidence");
    }
}
