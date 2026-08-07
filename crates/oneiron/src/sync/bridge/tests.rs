use super::*;
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
    ENTITY_TYPE_COMPANION_REGISTER, encode_companion_record_body,
};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_since, import_doc,
    map_contains_binary, map_insert_bytes,
};
use crate::temporal::TimeRange;
use core::assert_matches;
use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;
use std::sync::Arc;

fn test_vault() -> Arc<Vault> {
    let dir = tempfile::tempdir().unwrap();
    Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap())
}

#[test]
fn decode_observer_u_seq_accepts_le_u32() {
    assert_eq!(decode_observer_u_seq(&42u32.to_le_bytes()).unwrap(), 42);
}

#[test]
fn decode_observer_u_seq_rejects_bad_lengths_without_panic() {
    for raw in [&[][..], &[1, 2, 3][..], &[1, 2, 3, 4, 5][..]] {
        let err = decode_observer_u_seq(raw).expect_err("malformed u_seq row must be rejected");
        assert_matches!(err, Error::CorruptedIndex(ERR_OBSERVER_A_U_SEQ_ROW));
    }
}

fn task_body() -> Vec<u8> {
    crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
}

/// Minimal WARN-level event capture: collects `message` fields so tests
/// can assert a specific warn fired without a subscriber dependency.
#[derive(Clone, Default)]
struct WarnCapture {
    messages: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct MessageVisitor(Option<String>);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }

        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut visitor = MessageVisitor(None);
        event.record(&mut visitor);
        if let Some(message) = visitor.0 {
            self.messages.lock().unwrap().push(message);
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn read_dt_marker(vault: &Vault, id: &EntityId) -> Option<Vec<u8>> {
    let rtxn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .sync_state
        .get(&rtxn, &crate::deletion::local_hard_delete_key(id))
        .unwrap()
        .map(|value| value.to_vec())
}

fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred.start.to_be_bytes());
    blob.extend_from_slice(&occurred.end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

fn companion_record(
    persona_ref: EntityId,
    export_classification: CompanionExportClassification,
) -> CompanionRecord {
    CompanionRecord::persona(
        CompanionScope::neutral(),
        persona_ref,
        Value::from("private companion tuning"),
        CompanionProvenance::new(
            EntityId::from_bytes_unchecked([0xB8; 16]),
            EdgeActorClass::Agent,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            Value::from("private provenance"),
        ),
        export_classification,
    )
}

#[cfg(feature = "sync")]
fn authority_test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[cfg(feature = "sync")]
fn authority_key_from_signing(signing: &SigningKey) -> crate::authority::AuthorityKey {
    crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

#[cfg(feature = "sync")]
fn authority_test_device(key: crate::authority::AuthorityKey) -> crate::authority::DeviceAuthority {
    crate::authority::DeviceAuthority {
        key,
        transport_key_binding: [0; 32],
        attestation: crate::authority::AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: crate::authority::AuthorityTier::Software,
        roles: crate::authority::ROLE_OWNER,
    }
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture(seed: u8) -> crate::authority::AuthorityLogEntry {
    let signing = authority_test_key(seed);
    let key = authority_key_from_signing(&signing);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: authority_test_device(key.clone()),
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_enroll_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let new_key = authority_key_from_signing(&authority_test_key(new_seed));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::EnrollDevice {
            device: authority_test_device(new_key),
        },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(new_seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_log_entity_blob(
    entry: &crate::authority::AuthorityLogEntry,
    learned_at: u64,
) -> Result<Vec<u8>> {
    let body = crate::authority::encode_authority_log_entry_body(entry)?;
    Ok(entity_blob(
        ENTITY_TYPE_AUTHORITY_LOG,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        &body,
    ))
}

#[cfg(feature = "sync")]
#[test]
fn over_quota_peer_rejected() -> Result<()> {
    let vault = test_vault();
    quota::set_maintenance_ingest_quota_config(
        &vault,
        quota::MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
        },
    )?;
    let owner = authority_test_key(31);
    let genesis = authority_genesis_fixture(31);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    vault.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;

    let first = authority_enroll_fixture(vault_id, &genesis, &owner, 32, 1);
    let second = authority_enroll_fixture(vault_id, &genesis, &owner, 33, 2);
    let first_blob = authority_log_entity_blob(&first, 2)?;
    let second_blob = authority_log_entity_blob(&second, 3)?;
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");

    vault.with_write_txn(|wtxn| {
        let wrote = materialize_entity_blob_in_txn(
            &vault,
            wtxn,
            &tombstones,
            "2026-03",
            &crate::authority::authority_log_entity_id(&first)?.to_hex(),
            &first_blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )?;
        assert!(
            wrote,
            "first authority replay-door write should materialize"
        );
        Ok(())
    })?;

    let second_id = crate::authority::authority_log_entity_id(&second)?;
    let err = vault
        .with_write_txn(|wtxn| {
            materialize_entity_blob_in_txn(
                &vault,
                wtxn,
                &tombstones,
                "2026-03",
                &second_id.to_hex(),
                &second_blob,
                crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            )
            .map(|_| ())
        })
        .expect_err("same authority signer must be capped by production replay-door quota");

    assert!(matches!(
        err,
        Error::MaintenanceIngestQuotaExceeded {
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
            ..
        }
    ));
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, second_id.as_bytes())?
            .is_none(),
        "over-quota authority replay-door blob must not be stored"
    );
    Ok(())
}

/// ONE-1604-D1 T6/T8: a peer row whose id does not match its content hash is
/// refused at the replicated door BEFORE the maintenance-ingest quota debit,
/// so a hostile peer cannot burn a victim's ingest quota with rows that were
/// never admissible. Local bytes and the fold are untouched.
#[cfg(feature = "sync")]
#[test]
fn store_key_mismatched_authority_row_from_peer_is_rejected_without_quota_debit() -> Result<()> {
    let vault = test_vault();
    let owner = authority_test_key(41);
    let genesis = authority_genesis_fixture(41);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    vault.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;
    let fold_before = vault.authority_fold()?.vault_id;

    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 42, 1);
    let blob = authority_log_entity_blob(&enroll, 2)?;
    let derived = crate::authority::authority_log_entity_id(&enroll)?;
    let wrong_id = EntityId::now();
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");

    let err = vault
        .with_write_txn(|wtxn| {
            materialize_entity_blob_in_txn(
                &vault,
                wtxn,
                &tombstones,
                "2026-03",
                &wrong_id.to_hex(),
                &blob,
                crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            )
            .map(|_| ())
        })
        .expect_err("a type-122 row under a non-derived id must be refused at the peer door");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::AuthorityLogStoreKeyMismatch
    );
    assert!(
        crate::sync::quarantine::remote_rejection_reason(&err).is_some(),
        "the rejection must classify as remote so the batch quarantines and continues"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, wrong_id.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, derived.as_bytes())?
            .is_none()
    );
    drop(rtxn);
    assert!(
        quota::maintenance_ingest_quota_snapshots(&vault)?.is_empty(),
        "a pre-quota rejection must not debit maintenance-ingest quota"
    );
    assert_eq!(vault.authority_fold()?.vault_id, fold_before);
    Ok(())
}

/// ONE-1604-D1/D5 T7 (mandated adversarial regression): a tombstone naming a
/// derived authority id that arrives and replays BEFORE the row itself must
/// not be able to poison the later materialization. AUTHORITY_LOG is
/// delete-protected, so the row still materializes and no `dt:` marker
/// survives to block it — a peer cannot pre-delete authority history it has
/// not seen yet.
#[cfg(feature = "sync")]
#[test]
fn tombstone_before_authority_row_cannot_poison_materialization() -> Result<()> {
    let vault = test_vault();
    let owner = authority_test_key(43);
    let genesis = authority_genesis_fixture(43);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    vault.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;

    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 44, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let id = crate::authority::authority_log_entity_id(&enroll)?;
    let blob = authority_log_entity_blob(&enroll, 2)?;

    // The tombstone lands first: no local row, no map carrier yet.
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    tombstones.insert(&id.to_hex(), b"1").unwrap();
    doc.commit();

    vault.with_write_txn(|wtxn| {
        let wrote = materialize_entity_blob_in_txn(
            &vault,
            wtxn,
            &tombstones,
            "2026-03",
            &id.to_hex(),
            &blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )?;
        assert!(
            wrote,
            "a delete-protected authority row must materialize despite an earlier tombstone"
        );
        Ok(())
    })?;

    assert_eq!(
        read_dt_marker(&vault, &id),
        None,
        "no dt: poison may survive over a delete-protected authority row"
    );
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(enroll));
    let fold = vault.authority_fold()?;
    assert!(
        fold.pending_widens.contains_key(&enroll_hash) || fold.valid_entries.contains(&enroll_hash),
        "the fold must see the admitted entry"
    );
    Ok(())
}

/// Hardware-tier genesis: a hardware owner grants INSTANT widen authority, so
/// the enroll below joins the roster immediately instead of sitting in
/// `pending_widens`. The revocation regression needs a real two-device roster
/// (revokes require peer quorum), not a pending one.
#[cfg(feature = "sync")]
fn authority_hardware_genesis_fixture(seed: u8) -> crate::authority::AuthorityLogEntry {
    let signing = authority_test_key(seed);
    let key = authority_key_from_signing(&signing);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: crate::authority::DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [0; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Hardware,
                roles: crate::authority::ROLE_OWNER | crate::authority::ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

/// Enrolls a second OWNER|ADMIN device so the roster can carry a quorum
/// revocation (the shared `authority_enroll_fixture` mints ROLE_OWNER only).
#[cfg(feature = "sync")]
fn authority_enroll_admin_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let new_key = authority_key_from_signing(&authority_test_key(new_seed));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::EnrollDevice {
            device: crate::authority::DeviceAuthority {
                key: new_key,
                transport_key_binding: [0; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Software,
                roles: crate::authority::ROLE_OWNER | crate::authority::ROLE_ADMIN,
            },
        },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(new_seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

/// Adds `cosigner`'s peer signature and re-signs both over the new
/// transcript (the transcript binds the cosigner key set).
#[cfg(feature = "sync")]
fn authority_cosign(
    mut entry: crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    cosigner: &SigningKey,
) -> crate::authority::AuthorityLogEntry {
    let cosigner_key = authority_key_from_signing(cosigner);
    entry.cosigns.push(crate::authority::AuthoritySignature {
        suite: cosigner_key.suite(),
        public_key: cosigner_key.clone(),
        signature: vec![0; 64],
    });
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for cosign in &mut entry.cosigns {
        if cosign.public_key == cosigner_key {
            cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
        }
    }
    entry
}

/// A cosigned RevokeDevice naming `revoked_key`, signed by `signer` and
/// cosigned by `cosigner` (revocations need peer quorum in the fold).
#[cfg(feature = "sync")]
fn authority_revoke_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    cosigner: &SigningKey,
    revoked_key: crate::authority::AuthorityKey,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let cosigner_key = authority_key_from_signing(cosigner);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::RevokeDevice { revoked_key },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: vec![crate::authority::AuthoritySignature {
            suite: cosigner_key.suite(),
            public_key: cosigner_key,
            signature: vec![0; 64],
        }],
        ts: 900 + seq,
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for cosign in &mut entry.cosigns {
        cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// ONE-1604-D1 (fix-leg 1, P2-a — adversarial revocation survival): the
/// content-derived store key lives in the caller-chosen GLOBAL entity
/// namespace, and RevokeDevice bodies are predictable under deterministic
/// signing. A hostile peer — the revoked device itself, in the worst case —
/// can therefore precompute a pending revocation's derived id and pre-squat
/// it with an ordinary EVENT row. Before the fix the authority row lost that
/// race as an `AuthorityLogAppendOnlyViolation`, the revocation never reached
/// the fold, and the revoked key STAYED ACTIVE — the append-only guard
/// suppressing the very evidence it exists to protect.
///
/// A fully validated type-122 row now dominates the squatter: it is admitted,
/// the squatter is evicted, and the revocation lands in the fold.
#[cfg(feature = "sync")]
#[test]
fn presquatted_revocation_id_still_admits_the_revocation() -> Result<()> {
    let owner = authority_test_key(51);
    let peer = authority_test_key(52);
    let third = authority_test_key(55);
    let genesis = authority_hardware_genesis_fixture(51);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    // A revoke must leave a surviving quorum, so the roster carries three
    // devices before the hostile one is revoked.
    let enroll_peer = authority_enroll_admin_fixture(vault_id, &genesis, &owner, 52, 1);
    // Once two devices are active every non-genesis entry needs peer quorum.
    let enroll_third = authority_cosign(
        authority_enroll_admin_fixture(vault_id, &enroll_peer, &owner, 55, 2),
        &owner,
        &peer,
    );
    let peer_key = authority_key_from_signing(&peer);

    // Both an ordinary (absent) and an LWW-winner (already-materialized)
    // squatter variant must lose to the validated authority row.
    for squatter_is_lww_winner in [false, true] {
        let vault = test_vault();
        vault.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;
        vault.put_authority_log_entry(&enroll_peer, TimeRange { start: 2, end: 2 }, 2)?;
        vault.put_authority_log_entry(&enroll_third, TimeRange { start: 3, end: 3 }, 3)?;

        let revoke =
            authority_revoke_fixture(vault_id, &enroll_third, &owner, &third, peer_key.clone(), 3);
        let revoke_hash = crate::authority::authority_entry_hash(&revoke)?;
        // The attacker derives the pending revocation's id from its
        // predictable body — exactly what the engine will derive.
        let squatted_id = crate::authority::authority_log_entity_id(&revoke)?;

        if squatter_is_lww_winner {
            // The squatter already won the key locally before the
            // revocation ever arrived.
            vault.put_entity(
                &squatted_id,
                crate::registry::ENTITY_TYPE_EVENT,
                TimeRange { start: 3, end: 3 },
                3,
                b"squatter",
            )?;
            assert!(vault.entity_exists(&squatted_id)?);
        }

        let blob = authority_log_entity_blob(&revoke, 4)?;
        let doc = LoroDoc::new();
        let tombstones = doc.get_map("tombstones");
        vault.with_write_txn(|wtxn| {
            let wrote = materialize_entity_blob_in_txn(
                &vault,
                wtxn,
                &tombstones,
                "2026-03",
                &squatted_id.to_hex(),
                &blob,
                crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            )?;
            assert!(
                wrote,
                "a fully validated revocation must dominate a cross-type squatter at its derived id"
            );
            Ok(())
        })?;

        assert_eq!(
            vault.get_authority_log_entry(&squatted_id)?,
            Some(revoke.clone()),
            "the revocation must occupy its own content-derived store key"
        );
        let fold = vault.authority_fold()?;
        assert!(
            fold.issues.is_empty(),
            "unexpected fold issues: {:?}",
            fold.issues
        );
        assert!(
            fold.valid_entries.contains(&revoke_hash),
            "the revocation must reach the fold despite the pre-squat"
        );
        assert!(
            fold.roster
                .get(&peer_key)
                .is_some_and(|device| device.revoked),
            "the pre-squatted revocation must still disable the prior authority"
        );
    }
    Ok(())
}

/// The dominance in the test above is conditioned on FULL validation, not on
/// the type byte: a FORGED type-122 row (tampered origin signature) fails
/// `decode_authority_log_entry_body` at the door, never reaches the store-key
/// check, and therefore cannot evict anything. Without this the "dominance"
/// would itself be a cross-type overwrite primitive for any hostile peer.
#[cfg(feature = "sync")]
#[test]
fn forged_authority_row_cannot_displace_a_key_occupant() -> Result<()> {
    let vault = test_vault();
    let genesis = authority_genesis_fixture(53);
    vault.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let owner = authority_test_key(53);
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 54, 1);
    let target_id = crate::authority::authority_log_entity_id(&enroll)?;

    // An ordinary row holds the key first.
    vault.put_entity(
        &target_id,
        crate::registry::ENTITY_TYPE_EVENT,
        TimeRange { start: 2, end: 2 },
        2,
        b"occupant",
    )?;
    let occupant = vault.get_raw(&target_id)?.expect("occupant stored");

    let mut forged = enroll;
    forged.signer.signature[0] ^= 0xff;
    let forged_body = crate::authority::encode_authority_log_entry_body(&forged)?;
    let forged_blob = entity_blob(
        ENTITY_TYPE_AUTHORITY_LOG,
        TimeRange { start: 3, end: 3 },
        3,
        &forged_body,
    );
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    // Production does NOT abort the transaction on a remote rejection:
    // Observer B quarantines the row and COMMITS (quarantine-and-continue,
    // sync/bridge.rs). Returning the error from `with_write_txn` would roll
    // the whole LMDB txn back, so the occupant assertion below would pass
    // even if dominance had evicted before validation. Catch the rejection
    // inside the txn — exactly as the observer does — and COMMIT, so the
    // assertion sees whatever side effects a rejected row actually leaves
    // behind.
    let kind = vault.with_write_txn(|wtxn| {
        let err = materialize_entity_blob_in_txn(
            &vault,
            wtxn,
            &tombstones,
            "2026-03",
            &target_id.to_hex(),
            &forged_blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )
        .map(|_| ())
        .expect_err("a forged authority row must fail validation before any dominance");
        assert!(
            crate::sync::quarantine::remote_rejection_reason(&err).is_some(),
            "the forged row must classify as a remote rejection (commit-on-rejection), got {err:?}"
        );
        Ok(err.kind())
    })?;

    assert_eq!(kind, crate::error::ErrorKind::InvalidAuthorityLogBody);
    assert_eq!(
        vault.get_raw(&target_id)?,
        Some(occupant),
        "a forged row must not evict the key's occupant"
    );
    Ok(())
}

/// ONE-1604-D1 fix-leg 2, P2 — a REJECTED authority row must be a pure no-op,
/// even though its rejection COMMITS. A fully valid entry carried in an
/// envelope with an inverted occurred range clears every body/signature check
/// (so it reaches the dominance verdict) and is then rejected by the envelope
/// time-range gate. `InvalidTimeRange` is a `remote_rejection_reason`, so
/// Observer B quarantines the row and commits the transaction — if the
/// squatter eviction ran before that gate, the commit would durably empty a
/// key the rejected row never earned. The occupant must survive intact.
#[cfg(feature = "sync")]
#[test]
fn rejected_authority_envelope_leaves_a_key_squatter_untouched() -> Result<()> {
    let vault = test_vault();
    let genesis = authority_genesis_fixture(56);
    vault.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let owner = authority_test_key(56);
    // A genuinely valid entry: body, origin signature, and vault-id fold all
    // pass, so nothing but the envelope can reject it.
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 57, 1);
    let target_id = crate::authority::authority_log_entity_id(&enroll)?;

    // The attacker pre-squats the derived id with an ordinary row.
    vault.put_entity(
        &target_id,
        crate::registry::ENTITY_TYPE_EVENT,
        TimeRange { start: 2, end: 2 },
        2,
        b"occupant",
    )?;
    let occupant = vault.get_raw(&target_id)?.expect("occupant stored");

    let body = crate::authority::encode_authority_log_entry_body(&enroll)?;
    // start > end: rejected by the envelope gate, AFTER the dominance verdict.
    let blob = entity_blob(
        ENTITY_TYPE_AUTHORITY_LOG,
        TimeRange { start: 9, end: 3 },
        9,
        &body,
    );

    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    map_insert_bytes(&doc.get_map("entities"), &target_id.to_hex(), &blob)
        .expect("insert authority blob");
    doc.commit();

    // The real Observer-B path ran and committed its transaction.
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?
            .iter()
            .any(|(_, record)| {
                record.reason_code == "InvalidTimeRange"
                    && record.container == crate::sync::quarantine::QuarantineContainer::Entities
            }),
        "the invalid-time authority envelope must quarantine-and-continue"
    );
    assert_eq!(
        vault.get_raw(&target_id)?,
        Some(occupant),
        "a rejected authority row must not evict the occupant of its derived key"
    );
    assert!(
        !vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)?
            .contains(&target_id),
        "the rejected row must not have materialized either"
    );
    Ok(())
}

/// Index-aligned metas for direct `apply_materialized_edge_ops` calls.
fn test_metas_for_ops(ops: &[BatchOp]) -> Vec<EdgeOpMeta> {
    ops.iter()
        .map(|op| {
            let (src, kind, tgt) = match op {
                BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::DeleteEdge { src, kind, tgt } => (src, *kind, tgt),
                _ => unreachable!("edge ops only"),
            };
            EdgeOpMeta::for_key(&format_edge_key(src, kind, tgt), &[])
        })
        .collect()
}

#[test]
fn parse_edge_key_valid() {
    let src = EntityId::from_bytes_unchecked([0x60; 16]);
    let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
    let key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let (s, k, t) = parse_edge_key(&key).unwrap();
    assert_eq!(s, src);
    assert_eq!(k, EdgeKind::Mentions);
    assert_eq!(t, tgt);
}

#[test]
fn parse_edge_key_invalid_length() {
    assert!(parse_edge_key("too-short").is_none());
}

#[test]
fn edge_value_round_trip() {
    let vad = Vad {
        valence: 0.5,
        arousal: 0.3,
        dominance: 0.7,
    };
    let buf = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 12345, Some(vad), None).unwrap();
    let decoded = parse_edge_value(&buf).unwrap();
    assert!((decoded.weight - 0.8).abs() < f32::EPSILON);
    assert_eq!(decoded.created_at, 12345);
    let v = decoded.vad.unwrap();
    assert!((v.valence - 0.5).abs() < f32::EPSILON);
    assert!((v.arousal - 0.3).abs() < f32::EPSILON);
    assert!((v.dominance - 0.7).abs() < f32::EPSILON);
}

#[test]
fn apply_materialized_edge_ops_keeps_other_edges_after_child_of_failure() {
    let vault = test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .put(
            &c,
            ENTITY_TYPE_TASK,
            TimeRange { start: 5, end: 5 },
            6,
            &task_body(),
        )
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .commit()
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let ops = vec![
                BatchOp::EdgeWithCreatedAt {
                    src: a,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                    weight: 1.0,
                    created_at: 10,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: c,
                    kind: EdgeKind::Mentions,
                    tgt: a,
                    weight: 0.8,
                    created_at: 11,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ];
            let metas = test_metas_for_ops(&ops);
            apply_materialized_edge_ops(&vault, wtxn, ops, &metas, "2026-03")?;
            Ok(())
        })
        .unwrap();

    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap());
    assert!(vault.edge_exists(&c, EdgeKind::Mentions, &a).unwrap());
}

#[test]
fn apply_materialized_edge_ops_keeps_valid_child_of_delete_when_add_fails() {
    let vault = test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .put(
            &c,
            ENTITY_TYPE_TASK,
            TimeRange { start: 5, end: 5 },
            6,
            &task_body(),
        )
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .commit()
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let ops = vec![
                BatchOp::DeleteEdge {
                    src: c,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: a,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                    weight: 1.0,
                    created_at: 10,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ];
            let metas = test_metas_for_ops(&ops);
            apply_materialized_edge_ops(&vault, wtxn, ops, &metas, "2026-03")?;
            Ok(())
        })
        .unwrap();

    assert!(!vault.edge_exists(&c, EdgeKind::ChildOf, &b).unwrap());
    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap());
}

#[test]
fn apply_materialized_edge_ops_child_of_subset_is_deterministic() {
    let vault = test_vault();
    let a = EntityId::from_bytes_unchecked([1; 16]);
    let x = EntityId::from_bytes_unchecked([2; 16]);
    let b = EntityId::from_bytes_unchecked([3; 16]);
    let y = EntityId::from_bytes_unchecked([4; 16]);

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &x,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 5, end: 5 },
            6,
            &task_body(),
        )
        .put(
            &y,
            ENTITY_TYPE_TASK,
            TimeRange { start: 7, end: 7 },
            8,
            &task_body(),
        )
        .edge(&a, EdgeKind::ChildOf, &x, 1.0)
        .edge(&b, EdgeKind::ChildOf, &y, 1.0)
        .commit()
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let ops = vec![
                BatchOp::EdgeWithCreatedAt {
                    src: y,
                    kind: EdgeKind::ChildOf,
                    tgt: a,
                    weight: 1.0,
                    created_at: 10,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: x,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                    weight: 1.0,
                    created_at: 11,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ];
            let metas = test_metas_for_ops(&ops);
            apply_materialized_edge_ops(&vault, wtxn, ops, &metas, "2026-03")?;
            Ok(())
        })
        .unwrap();

    assert!(vault.edge_exists(&x, EdgeKind::ChildOf, &b).unwrap());
    assert!(!vault.edge_exists(&y, EdgeKind::ChildOf, &a).unwrap());
}

#[test]
fn observer_b_hydrates_edge_endpoints_from_current_crdt_state() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let a = EntityId::now();
    let b = EntityId::now();

    map_insert_bytes(
        &entities,
        &a.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &b.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(vault.get(&a).unwrap().is_some());
    assert!(vault.get(&b).unwrap().is_some());
    assert!(vault.edge_exists(&a, EdgeKind::Mentions, &b).unwrap());
}

#[test]
fn observer_b_does_not_rehydrate_tombstoned_edge_endpoint() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let tombstones = doc.get_map("tombstones");
    let deleted = EntityId::now();
    let live = EntityId::now();

    map_insert_bytes(
        &entities,
        &deleted.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &live.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        ),
    )
    .unwrap();
    tombstones.insert(&deleted.to_hex(), b"1").unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(
        &edges,
        &format_edge_key(&deleted, EdgeKind::Mentions, &live),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(vault.get(&deleted).unwrap().is_none());
    assert!(
        !vault
            .edge_exists(&deleted, EdgeKind::Mentions, &live)
            .unwrap()
    );
}

/// The endpoint-ready check must run the tombstone gate BEFORE the
/// LMDB-row shortcut: a tombstoned endpoint whose stale local row
/// survives (crash window between the tombstone CRDT commit and the
/// purge txn, or a failed purge) must never count as "ready". Pre-fix
/// code returned true on ANY existing row and materialized the edge.
/// Covers binary AND non-binary tombstone values (fail closed).
#[test]
fn observer_b_does_not_materialize_edge_to_tombstoned_endpoint_with_stale_row() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let edges = doc.get_map("edges");
    let tombstones = doc.get_map("tombstones");
    let live = EntityId::now();
    let del_bin = EntityId::now(); // binary (legacy hard) tombstone
    let del_str = EntityId::now(); // non-binary tombstone — must gate too

    // All three rows exist locally — the deleted ones are the stale
    // survivors of an interrupted purge.
    for id in [&live, &del_bin, &del_str] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }
    tombstones.insert(&del_bin.to_hex(), b"1").unwrap();
    tombstones.insert(&del_str.to_hex(), "corrupt").unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    for (src, tgt) in [(&live, &del_bin), (&live, &del_str), (&del_bin, &live)] {
        map_insert_bytes(
            &edges,
            &format_edge_key(src, EdgeKind::Mentions, tgt),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
    }
    doc.commit();

    assert!(
        !vault
            .edge_exists(&live, EdgeKind::Mentions, &del_bin)
            .unwrap(),
        "edge to tombstoned target with stale row must not materialize"
    );
    assert!(
        !vault
            .edge_exists(&live, EdgeKind::Mentions, &del_str)
            .unwrap(),
        "non-binary tombstone must gate the target too (fail closed)"
    );
    assert!(
        !vault
            .edge_exists(&del_bin, EdgeKind::Mentions, &live)
            .unwrap(),
        "edge FROM a tombstoned source with stale row must not materialize"
    );
}

/// A replicated edge naming a LIVE session-overlay member is refused inside the
/// applying transaction by the K4 taint guard and quarantined as an ordinary
/// remote-op rejection, while the unrelated edge in the same Observer-B batch
/// still applies. ONE-1731 removed the separate endpoint pre-walk: one verdict,
/// one typed identity, raised where the write actually happens.
#[test]
fn observer_b_quarantines_overlay_member_edge_and_keeps_ordinary_control() {
    let vault = test_vault();
    let source = EntityId::now();
    let room_target = EntityId::now();
    let ordinary_target = EntityId::now();
    // All three rows exist in base BEFORE the room opens, so Observer-B's
    // both-endpoint filter admits the edge and the taint guard is what refuses
    // it. (Ordering matters: the K4 guard would refuse this put once the id is
    // a live overlay member.)
    for id in [&source, &room_target, &ordinary_target] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }
    let session = vault
        .off_record_session_vault()
        .enter(
            "sess-observer-edge-room",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .unwrap();
    {
        let overlay = session.overlay();
        let segment = overlay.install_txn_segment().unwrap();
        overlay
            .put(
                crate::session_overlay::OverlayKeyspace::Entities,
                room_target.as_bytes(),
                b"live session overlay entity",
            )
            .unwrap();
        segment.commit().unwrap();
    }

    let doc = LoroDoc::new();
    let edges = doc.get_map("edges");
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    for target in [&room_target, &ordinary_target] {
        map_insert_bytes(
            &edges,
            &format_edge_key(&source, EdgeKind::Mentions, target),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
    }
    doc.commit();

    assert!(
        !vault
            .edge_exists(&source, EdgeKind::Mentions, &room_target)
            .unwrap(),
        "an edge naming a live overlay member must never reach LMDB"
    );
    assert!(
        vault
            .edge_exists(&source, EdgeKind::Mentions, &ordinary_target)
            .unwrap(),
        "unrelated ordinary edge in the same Observer-B batch must survive"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .iter()
            .any(|(_, record)| {
                record.reason_code == "OffRecordTaintedBaseWrite"
                    && record.container == crate::sync::quarantine::QuarantineContainer::Edges
            }),
        "the rejected edge must retain hashed quarantine evidence"
    );
}

/// ONE-1122 AC2 — ARCH-0023b: "If tombstoned in CRDT → never resurrect";
/// contracts.ts `user_hard_delete`: "Tombstone-first prevents sync
/// resurrection". Hard delete writes the CRDT tombstone and (ONE-1132)
/// removes the live `entities[id]` map copy in the SAME CRDT commit, so
/// a later remote commit re-touching the entity key must NOT
/// rematerialize the purged body into LMDB.
#[test]
fn observer_b_never_resurrects_hard_deleted_entity_on_entity_key_retouch() {
    let vault = test_vault();
    let materializer = Arc::new(Materializer::new());

    let id = EntityId::now();
    let learned_at = 1_772_400_000u64; // 2026-03 window
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();

    // Mirror LMDB → CRDT, then persist, so `write_crdt_tombstone` (which
    // loads the persisted window doc) operates on a doc holding the blob.
    let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
    let window =
        crate::sync::window::LoadedWindow::new("local", window_key.clone(), &vault, &materializer);
    let mirrored =
        crate::sync::window::reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
    assert_eq!(mirrored, 1);
    window.persist_state(&vault).unwrap();
    drop(window);

    // Hard delete: CRDT tombstone FIRST, then active-store purge.
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(vault.get(&id).unwrap().is_none());

    let doc = crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
    let hex_id = id.to_hex();
    assert!(
        map_get_bytes(&doc.get_map("entities"), &hex_id).is_none(),
        "precondition: hard delete removes the live entities-map copy in the same CRDT commit (ONE-1132)"
    );
    assert!(
        map_contains_binary(&doc.get_map("tombstones"), &hex_id),
        "precondition: hard delete writes the CRDT tombstone"
    );

    // Remote commit re-touches the entity key after Observer B attaches.
    let window =
        crate::sync::window::LoadedWindow::from_doc(doc, window_key, &vault, &materializer);
    let entities = window.doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &hex_id,
        &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
    )
    .unwrap();
    window.doc.commit();

    assert!(
        vault.get(&id).unwrap().is_none(),
        "tombstoned entity must never resurrect into LMDB"
    );
}

/// ONE-1122 AC3 — SoftErased-shell variant: a 25 B envelope shell in
/// LMDB + the full blob arriving via an entities-map delta + the
/// tombstone present in the doc → the body is NOT restored. The gate
/// fires BEFORE the put; nothing heals after.
#[test]
fn observer_b_does_not_restore_soft_erased_body_when_tombstoned() {
    let vault = test_vault();
    let id = EntityId::now();
    let learned_at = 1_772_400_000u64;
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();

    // SoftErase (`user_delete`): scrubs the body, keeps the 25 B shell.
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
        .unwrap();
    assert!(outcome.existed);
    assert_eq!(
        vault.get_raw(&id).unwrap().expect("shell row").len(),
        ENTITY_METADATA_HEADER_LEN,
        "SoftErase must leave the bare 25 B envelope shell"
    );

    // Doc already tombstoned BEFORE observers attach; then the full blob
    // arrives via a delta re-touching the entity key.
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    tombstones.insert(&id.to_hex(), b"1").unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &id.to_hex(),
        &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
    )
    .unwrap();
    doc.commit();

    let raw = vault.get_raw(&id).unwrap().expect("shell must remain");
    assert_eq!(
        raw.len(),
        ENTITY_METADATA_HEADER_LEN,
        "tombstoned entity body must NOT be restored over the SoftErase shell"
    );
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(&[][..]),
        "entity body must stay empty after the gated delta"
    );
}

/// ONE-1115 AC7 — sync replay (observer-b edge materialization →
/// `apply_edge_with_created_at`) routes through the same contract \[0, 1\]
/// weight gate as local batch writes: an in-range replayed edge lands in
/// `edges_out` with its weight and `created_at` intact.
#[test]
fn observer_b_replays_in_range_edge_weight_through_write_gate() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let a = EntityId::now();
    let b = EntityId::now();

    map_insert_bytes(
        &entities,
        &a.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &b.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    let out = vault.edges_out(&a).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EdgeKind::Mentions);
    assert_eq!(out[0].target, b);
    assert_eq!(
        out[0].weight.to_bits(),
        0.6_f32.to_bits(),
        "replayed in-range weight must survive the write gate verbatim"
    );
    assert_eq!(out[0].created_at, 10);
}

/// ONE-1122 resurrection regression (handoff §8c.5): a crafted update
/// that REMOVES the CRDT tombstone and re-puts the entity key must NOT
/// rematerialize the hard-deleted body. The CRDT map is mutable remote
/// input; the `dt:` marker written in the origin purge txn is the local
/// truth the gate falls back to, and the removal is quarantined (x:
/// row, ONE-1124) as a protocol violation.
#[test]
fn observer_b_refuses_resurrection_after_crafted_tombstone_removal() {
    let vault = test_vault();
    let materializer = Arc::new(Materializer::new());

    let id = EntityId::now();
    let learned_at = 1_772_400_000u64; // 2026-03 window
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();

    // Mirror LMDB → CRDT and persist so the hard delete operates on a
    // window doc holding the blob.
    let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
    let window =
        crate::sync::window::LoadedWindow::new("local", window_key.clone(), &vault, &materializer);
    let mirrored =
        crate::sync::window::reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
    assert_eq!(mirrored, 1);
    window.persist_state(&vault).unwrap();
    drop(window);

    // Hard delete: CRDT tombstone + dt: marker + active-store purge.
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(vault.get(&id).unwrap().is_none());
    assert!(
        read_dt_marker(&vault, &id).is_some(),
        "precondition: hard delete writes the dt: marker"
    );

    let hex_id = id.to_hex();
    let local_doc =
        crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
    assert!(
        map_contains_binary(&local_doc.get_map("tombstones"), &hex_id),
        "precondition: hard delete writes the CRDT tombstone"
    );

    // Crafted attacker update: fork the local doc state, REMOVE the
    // tombstone, re-put the entity key, export the delta.
    let fork = doc_from_snapshot(&export_snapshot(&local_doc).unwrap()).unwrap();
    fork.get_map("tombstones").delete(&hex_id).unwrap();
    map_insert_bytes(
        &fork.get_map("entities"),
        &hex_id,
        &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
    )
    .unwrap();
    fork.commit();
    let crafted = export_updates_since(&fork, &doc_version_vector(&local_doc)).unwrap();

    // Apply the crafted update with observers attached, capturing warns.
    let window =
        crate::sync::window::LoadedWindow::from_doc(local_doc, window_key, &vault, &materializer);
    let warns = WarnCapture::default();
    tracing::subscriber::with_default(warns.clone(), || {
        import_doc(&window.doc, &crafted).unwrap();
    });

    // The removal landed in the CRDT map (no tombstone left to re-fire)…
    assert!(
        !map_contains_binary(&window.doc.get_map("tombstones"), &hex_id),
        "crafted removal must actually clear the CRDT tombstone"
    );
    // …but the dt: marker gate refused the re-put.
    assert!(
        vault.get(&id).unwrap().is_none(),
        "hard-deleted entity must not rematerialize after crafted tombstone removal"
    );
    let messages = warns.messages.lock().unwrap();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("rejected by write gate")),
        "protocol-violation quarantine warn must fire, got: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("dt: marker")),
        "dt: gate refusal warn must fire, got: {messages:?}"
    );
    // The removal is quarantined (x: row, ONE-1124) — never a bare log.
    let records = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert!(
        records
            .iter()
            .any(|(_, r)| r.container == QuarantineContainer::Tombstones),
        "crafted tombstone removal must persist a Tombstones x: row"
    );
}

/// ONE-1122 `dt:` marker shape: written in the purge txn on HARD
/// outcomes (pinned `[reason:1][deleted_at:8 LE][request_id:16]`
/// layout), absent on SoftErase, and pure LMDB truth — independent of
/// any CRDT map state.
#[test]
fn hard_delete_writes_dt_marker_soft_delete_does_not() {
    let vault = test_vault();
    let occurred = TimeRange { start: 1, end: 1 };
    let learned_at = 1_772_400_000u64;
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let hard = EntityId::now();
    vault
        .put_entity(&hard, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    vault
        .delete_entity_with_reason(&hard, crate::DeleteReason::UserHardDelete)
        .unwrap();

    let marker = read_dt_marker(&vault, &hard).expect("dt: row written on hard delete");
    assert_eq!(
        marker.len(),
        25,
        "pinned [reason:1][deleted_at:8 LE][request_id:16] layout"
    );
    assert_eq!(marker[0], 2, "user_hard_delete reason byte");
    let deleted_at = u64::from_le_bytes(marker[1..9].try_into().unwrap());
    assert!(
        deleted_at >= before && deleted_at <= before + 60,
        "deleted_at must be the request time"
    );
    assert_ne!(&marker[9..25], &[0u8; 16][..], "request id present");

    // GDPR delete is also HARD — marker with reason byte 3.
    let gdpr = EntityId::now();
    vault
        .put_entity(&gdpr, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    vault
        .delete_entity_with_reason(&gdpr, crate::DeleteReason::GdprDelete)
        .unwrap();
    let marker = read_dt_marker(&vault, &gdpr).expect("dt: row written on gdpr delete");
    assert_eq!(marker[0], 3, "gdpr_delete reason byte");

    // SoftErase writes NO marker.
    let soft = EntityId::now();
    vault
        .put_entity(&soft, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    vault
        .delete_entity_with_reason(&soft, crate::DeleteReason::UserDelete)
        .unwrap();
    assert!(
        read_dt_marker(&vault, &soft).is_none(),
        "soft delete must not write a dt: marker"
    );

    // The marker is LMDB truth: dropping the tombstone from the loaded
    // window doc leaves the dt: row untouched.
    let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
    let doc = crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
    doc.get_map("tombstones").delete(&hard.to_hex()).unwrap();
    doc.commit();
    assert!(
        read_dt_marker(&vault, &hard).is_some(),
        "dt: marker survives independently of the CRDT tombstone map"
    );
}

/// ONE-1122 `dt:` marker, headerless leg: a hard delete that routes
/// through `delete_entity_without_header` (active residue, entity row /
/// 25 B header missing) writes NO CRDT tombstone — the `dt:` marker
/// written in the purge txn is the only local delete truth for that id.
/// It must exist after the delete, and the Observer-B gate must refuse
/// a crafted re-put on its strength alone.
#[test]
fn headerless_hard_delete_writes_dt_marker_and_gate_refuses_reput() {
    let vault = test_vault();
    let occurred = TimeRange { start: 1, end: 1 };
    let learned_at = 1_772_400_000u64;

    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    // Strip ONLY the entity row, leaving index residue (short-id
    // reverse row) — the exact shape `delete_entity_without_header`
    // exists for: active data present, no parseable header.
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        assert!(
            vault
                .store
                .entities
                .delete(&mut wtxn, id.as_bytes())
                .unwrap()
        );
        wtxn.commit().unwrap();
    }

    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(
        outcome.receipt_id.is_some(),
        "headerless residue purge must write a receipt (not the missing no-op)"
    );
    let marker = read_dt_marker(&vault, &id)
        .expect("headerless hard delete must write the dt: marker in the purge txn");
    assert_eq!(
        marker.len(),
        25,
        "pinned [reason:1][deleted_at:8 LE][request_id:16] layout"
    );
    assert_eq!(marker[0], 2, "user_hard_delete reason byte");

    // Crafted re-put through Observer B: no CRDT tombstone exists for a
    // headerless delete, so ONLY the dt: leg of the OR-gate can refuse.
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let warns = WarnCapture::default();
    tracing::subscriber::with_default(warns.clone(), || {
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
        )
        .unwrap();
        doc.commit();
    });

    assert!(
        vault.get(&id).unwrap().is_none(),
        "dt: gate must refuse rematerialization of a headerless hard delete"
    );
    let messages = warns.messages.lock().unwrap();
    assert!(
        messages.iter().any(|m| m.contains("dt: marker")),
        "dt: gate refusal warn must fire, got: {messages:?}"
    );
}

/// Negative: an entity that was never deleted materializes through the
/// unchanged honest path — the dt: OR-gate adds no false refusals.
#[test]
fn observer_b_materializes_never_deleted_entity_normally() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let id = EntityId::now();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let expected = task_body();
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(expected.as_slice()),
        "never-deleted entity must materialize normally"
    );
}

#[test]
fn companion_register_api_observer_b_materializes_portable_on_fresh_vault() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let id = EntityId::from_bytes_unchecked([0x41; 16]);
    let learned_at = 1_772_400_000u64;
    let record = companion_record(id, CompanionExportClassification::Portable);
    let body = encode_companion_record_body(&record.created_at(learned_at).unwrap()).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(
        vault.get_companion_record(&id).unwrap().is_some(),
        "live sync replay should register the companion kind and materialize portable records"
    );
}

#[test]
fn companion_register_api_observer_b_suppresses_local_only_records() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let id = EntityId::from_bytes_unchecked([0x62; 16]);
    let learned_at = 1_772_400_000u64;
    let record = companion_record(id, CompanionExportClassification::LocalOnly);
    let body = encode_companion_record_body(&record.created_at(learned_at).unwrap()).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(
        vault.get_companion_record(&id).unwrap().is_none(),
        "live sync replay must not materialize local-only companion register records"
    );
}

#[test]
fn companion_register_api_observer_b_scrubs_local_only_rows_and_edges_from_crdt() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let local_id = EntityId::from_bytes_unchecked([0x43; 16]);
    let portable_id = EntityId::from_bytes_unchecked([0x44; 16]);
    let learned_at = 1_772_400_001u64;
    let local_record = companion_record(local_id, CompanionExportClassification::LocalOnly);
    let portable_record = companion_record(portable_id, CompanionExportClassification::Portable);
    let local_body =
        encode_companion_record_body(&local_record.created_at(learned_at).unwrap()).unwrap();
    let portable_body =
        encode_companion_record_body(&portable_record.created_at(learned_at).unwrap()).unwrap();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let edge_key = format_edge_key(&local_id, EdgeKind::Mentions, &portable_id);

    map_insert_bytes(
        &entities,
        &portable_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &portable_body,
        ),
    )
    .unwrap();
    map_insert_bytes(
        &edges,
        &edge_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, learned_at, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();

    map_insert_bytes(
        &entities,
        &local_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &local_body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(vault.get_companion_record(&local_id).unwrap().is_none());
    assert!(
        map_get_bytes(&entities, &local_id.to_hex()).is_none(),
        "live observer must scrub local-only companion rows from the CRDT window"
    );
    assert!(
        map_get_bytes(&edges, &edge_key).is_none(),
        "live observer must scrub edges touching local-only companion rows"
    );
    assert!(
        vault.get_companion_record(&portable_id).unwrap().is_some(),
        "syncable companion rows should still materialize"
    );
}

#[test]
fn companion_register_api_observer_b_rejects_edges_touching_existing_local_only_endpoint() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let local_id = EntityId::from_bytes_unchecked([0x45; 16]);
    let task_id = EntityId::from_bytes_unchecked([0x46; 16]);
    let learned_at = 1_772_400_002u64;
    let local_record = companion_record(local_id, CompanionExportClassification::LocalOnly);
    vault
        .create_companion_record(&local_id, &local_record, learned_at)
        .unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &task_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let edge_key = format_edge_key(&task_id, EdgeKind::Mentions, &local_id);
    map_insert_bytes(
        &doc.get_map("edges"),
        &edge_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, learned_at, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(
        !vault
            .edge_exists(&task_id, EdgeKind::Mentions, &local_id)
            .unwrap(),
        "edges touching existing local-only companion endpoints must not materialize"
    );
    assert!(
        map_get_bytes(&doc.get_map("edges"), &edge_key).is_none(),
        "live observer must scrub the rejected local-only edge carrier"
    );
}

/// ONE-1123: Observer B materializes a remote reserved-predicate
/// `edge.provenance` Claim — the truth behind the 26 B edge flag cache
/// (contracts.ts edgeProvenanceClaim: "the edge flags are a DERIVED
/// CACHE of that Claim, and the Claim is truth") — byte-identical,
/// instead of warn-skipping it at the public reserved-namespace gate.
///
/// FAILS against pre-fix code: `materialize_entity_blob_in_txn` routed
/// the type-0 Claim through the pre-rename replay door
/// (`allow_reserved_predicate: false`), `validate_claim_body_bytes`
/// rejected it with ReservedPredicate, and the observer warn-skipped it
/// — the Claim never reached the replica's LMDB.
///
/// Since ONE-1159 the door also validates provenance STRUCTURE, so the
/// forged Claim carries a real value record + actor-class evidence
/// (the original junk-string `val` pinned the pre-1159 hole) — this is
/// now also the door's positive control: a fully-valid edge.provenance
/// Claim replicates with zero quarantine rows.
#[test]
fn observer_b_materializes_remote_edge_provenance_claim() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");

    let src = EntityId::now();
    let tgt = EntityId::now();
    let actor = EntityId::now();
    let claim_id = EntityId::now();

    let record = crate::provenance::EdgeProvenanceClaimBody::new(
        actor,
        0.9,
        crate::provenance::SupersessionStatus::Confirmed,
    );
    let mut body = crate::claim::ClaimBody::new(
        "edge.provenance",
        crate::claim::ClaimSubject::Edge {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        },
        crate::provenance::encode_edge_provenance_value(&record),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(crate::provenance::encode_actor_class_evidence(
        crate::edge::EdgeActorClass::Human,
    ));
    let body_bytes = crate::claim::encode_claim_body(&body).unwrap();
    let claim_blob = entity_blob(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange { start: 5, end: 5 },
        6,
        &body_bytes,
    );

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(&entities, &claim_id.to_hex(), &claim_blob).unwrap();
    doc.commit();

    assert_eq!(
        vault.get_raw(&claim_id).unwrap().as_deref(),
        Some(claim_blob.as_slice()),
        "remote edge.provenance Claim must materialize byte-identical via Observer B"
    );
    let read = vault
        .get_claim(&claim_id)
        .unwrap()
        .expect("materialized Claim must read back through get_claim");
    assert_eq!(read.predicate, "edge.provenance");
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .is_empty(),
        "a fully-valid edge.provenance Claim must not trip the ONE-1159 door check"
    );
}

/// ONE-1124 fix wave 2 (fail-closed split) — when the src endpoint
/// fails with a REMOTE-rejectable error and the tgt endpoint fails with
/// a LOCAL error, the LOCAL error wins: the edge transaction aborts and
/// NO x: row is written. Pre-fix, `(Err(e), _) | (_, Err(e))` bound the
/// remote src error, quarantined the edge, and silently swallowed the
/// local failure.
#[test]
fn local_endpoint_error_aborts_batch_before_remote_quarantine() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let src = EntityId::now();
    let tgt = EntityId::now();

    // src endpoint blob: parses structurally but fails the entity write
    // gate with InvalidEntityType (unknown type byte) — a
    // remote-rejectable endpoint error. Inserted BEFORE the observer is
    // registered so only the edge delta fires.
    map_insert_bytes(
        &entities,
        &src.to_hex(),
        &entity_blob(200, TimeRange { start: 1, end: 1 }, 2, b"s"),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    // tgt endpoint: injected LOCAL read failure (the engine's own read
    // erroring — not classifiable as a remote rejection).
    INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.set(Some(tgt)));
    map_insert_bytes(
        &edges,
        &format_edge_key(&src, EdgeKind::Mentions, &tgt),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(
        INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.get().is_none()),
        "precondition: the local tgt failure was actually hit"
    );
    let records = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert!(
        records.is_empty(),
        "local endpoint error must abort the txn — no x: row may pretend the edge was handled"
    );
    assert!(
        !vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
        "aborted txn must not materialize the edge"
    );
    assert!(
        vault.get(&src).unwrap().is_none(),
        "aborted txn must not materialize the src endpoint"
    );
}

#[test]
fn observer_b_gates_reserved_edges_on_the_ledger_and_derives_shells_from_records() {
    use crate::identity_topology::{
        EntityLifecycleState, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let survivor = EntityId::now();
    let loser = EntityId::now();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    // Participants materialize through the ordinary entity pass first.
    for id in [&survivor, &loser] {
        map_insert_bytes(
            &entities,
            &id.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            ),
        )
        .unwrap();
    }
    doc.commit();
    assert!(vault.get(&survivor).unwrap().is_some());
    assert!(vault.get(&loser).unwrap().is_some());

    // A raw edges-map merged_into row with NO ledger event behind it is a
    // forged shell: quarantined-and-continue, never materialized — the
    // peer-controlled edges CRDT map has no redirect-shell write authority.
    let shell_key = format_edge_key(&loser, EdgeKind::MergedInto, &survivor);
    map_insert_bytes(
        &edges,
        &shell_key,
        &encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, 10, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();
    assert!(
        !vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap(),
        "an unledgered merged_into row must never land"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).unwrap(),
        EntityLifecycleState::Active
    );
    assert!(
        !crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .is_empty(),
        "the forged shell row must leave hashed quarantine evidence"
    );

    // The validated type-76 record arriving through the entities map IS
    // the door: its ingest reconciles the shell edge as a side-effect,
    // with no admissible edges-map row involved.
    let event_id = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            &body,
        ),
    )
    .unwrap();
    doc.commit();
    assert!(
        vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap(),
        "the ingested record's door side-effect materializes the shell edge"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).unwrap(),
        EntityLifecycleState::Merged
    );

    // A mandated PAIR with peer-chosen value bytes is still a forgery:
    // weight 0 would silently drop the shell's PPR mass. Only the door's
    // byte-exact echo (default weight, the event's `at`) is admitted.
    map_insert_bytes(
        &edges,
        &shell_key,
        &encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.0, 200, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();
    let shell_weight = vault
        .edges_out(&loser)
        .unwrap()
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::MergedInto)
        .map(|edge| edge.weight);
    assert_eq!(
        shell_weight,
        Some(0.3),
        "a zero-weight rewrite of a mandated shell edge must be quarantined"
    );

    // The door's byte-exact echo passes admission (idempotent rewrite).
    map_insert_bytes(
        &edges,
        &shell_key,
        &encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, 200, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();
    assert!(
        vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap()
    );

    // A raw edges-map REMOVAL of the still-mandated shell edge is an
    // unledgered teardown: quarantined, the edge survives.
    edges.delete(&shell_key).unwrap();
    doc.commit();
    assert!(
        vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap(),
        "an unledgered removal must not tear a mandated shell edge"
    );

    // The replicated undo counter-event is the legitimate teardown door.
    let undo_id = EntityId::now();
    let undo = StoredIdentityOpEvent {
        seq: 51,
        at: 300,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Undo { target: event_id },
    };
    let undo_body = crate::identity_topology::encode_identity_topology_event_body(&undo).unwrap();
    map_insert_bytes(
        &entities,
        &undo_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 300,
                end: 300,
            },
            300,
            &undo_body,
        ),
    )
    .unwrap();
    doc.commit();
    assert!(
        !vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap(),
        "the ingested undo counter-event tears the shell edge down"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).unwrap(),
        EntityLifecycleState::Active
    );
}

#[test]
fn observer_b_tombstone_first_then_type_76_blob_neutralizes_poison_with_evidence() {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let vault = test_vault();
    let event_id = EntityId::from_bytes([0x70; 16]).unwrap();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![EntityId::from_bytes([0x61; 16]).unwrap()],
            survivor: EntityId::from_bytes([0x62; 16]).unwrap(),
        },
    };
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let tombstone = 200_u64.to_be_bytes();

    map_insert_bytes(&doc.get_map("tombstones"), &event_id.to_hex(), &tombstone).unwrap();
    doc.commit();
    assert!(
        read_dt_marker(&vault, &event_id).is_some(),
        "precondition: headerless tombstone-first replay minted the dt: poison"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .is_empty(),
        "without the later protected envelope the tombstone has not yet been classifiable"
    );

    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &event_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    assert_eq!(
        vault.identity_topology_event(&event_id).unwrap(),
        Some(record)
    );
    assert!(
        read_dt_marker(&vault, &event_id).is_none(),
        "admitting a delete-protected row must neutralize headerless dt: poison atomically"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(
        quarantined[0].1.container,
        crate::sync::quarantine::QuarantineContainer::Tombstones
    );
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    assert_eq!(
        quarantined[0].1.payload_hash,
        crate::sync::quarantine::payload_hash(&tombstone)
    );
}

#[test]
fn observer_b_malformed_type_76_envelope_cannot_bypass_delete_wins() {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 200,
        request_id: [0x42; 16],
    }
    .encode();

    let malformed_id = EntityId::from_bytes([0x72; 16]).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &malformed_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            b"malformed type-76 body",
        ),
    )
    .unwrap();
    map_insert_bytes(
        &doc.get_map("tombstones"),
        &malformed_id.to_hex(),
        &tombstone,
    )
    .unwrap();
    doc.commit();

    assert!(vault.get(&malformed_id).unwrap().is_none());
    assert!(
        read_dt_marker(&vault, &malformed_id).is_some(),
        "a malformed protected envelope must run the normal tombstone path"
    );

    doc.get_map("tombstones")
        .delete(&malformed_id.to_hex())
        .unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &malformed_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 201,
                end: 201,
            },
            201,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();
    assert!(
        vault.get(&malformed_id).unwrap().is_none(),
        "the permanent dt: marker must block later ordinary resurrection"
    );

    let valid_id = EntityId::from_bytes([0x73; 16]).unwrap();
    let valid_record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![EntityId::from_bytes([0x61; 16]).unwrap()],
            survivor: EntityId::from_bytes([0x62; 16]).unwrap(),
        },
    };
    let valid_body =
        crate::identity_topology::encode_identity_topology_event_body(&valid_record).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &valid_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: valid_record.at,
                end: valid_record.at,
            },
            valid_record.at,
            &valid_body,
        ),
    )
    .unwrap();
    map_insert_bytes(&doc.get_map("tombstones"), &valid_id.to_hex(), &tombstone).unwrap();
    doc.commit();

    assert_eq!(
        vault.identity_topology_event(&valid_id).unwrap(),
        Some(valid_record),
        "a genuinely valid protected record must retain delete protection"
    );
    assert!(
        read_dt_marker(&vault, &valid_id).is_none(),
        "a valid protected record's tombstone must not write dt:"
    );
}

#[test]
fn observer_b_rejects_type_76_merge_with_nonstructural_participant() {
    use crate::identity_topology::{
        EntityLifecycleState, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let vault = test_vault();
    let survivor = EntityId::now();
    vault
        .put_entity(
            &survivor,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .unwrap();
    let claim_id = EntityId::now();
    let claim = crate::claim::ClaimBody::new(
        "user.note",
        crate::claim::ClaimSubject::Entity(survivor),
        Value::from("fixture"),
        1.0,
        ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let claim_body = crate::claim::encode_claim_body(&claim).unwrap();
    // This row is participant state for the sync-door test, not a local
    // claim-policy decision. Seed it through the replicated materialization
    // door: that still runs the full CLAIM body validator, while avoiding the
    // unrelated local criticality-floor gate that can legitimately park an
    // Auto `user.note` write.
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &claim_id,
                    crate::registry::ENTITY_TYPE_CLAIM,
                    TimeRange { start: 1, end: 1 },
                    2,
                    &claim_body,
                )
                .apply(wtxn)
        })
        .unwrap();

    let event_id = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![claim_id],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    map_insert_bytes(
        &doc.get_map("entities"),
        &event_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: record.at,
                end: record.at,
            },
            record.at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    let expected_state = EntityLifecycleState::Active;
    assert!(
        vault.identity_topology_event(&event_id).unwrap().is_none(),
        "the sync door must reject the event row itself"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&claim_id).unwrap(),
        expected_state
    );
    assert!(
        !vault
            .edge_exists(&claim_id, EdgeKind::MergedInto, &survivor)
            .unwrap(),
        "a rejected non-structural event must authorize no shell edge"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(
        quarantined[0].1.reason_code,
        "InvalidIdentityTopologyEventBody"
    );
}

#[test]
fn observer_b_revalidates_deferred_participant_before_reserved_edge_write() {
    use crate::identity_topology::{
        EntityLifecycleState, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let survivor = EntityId::now();
    let claim_id = EntityId::now();
    let claim = crate::claim::ClaimBody::new(
        "user.note",
        crate::claim::ClaimSubject::Entity(survivor),
        Value::from("fixture"),
        1.0,
        ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let claim_body = crate::claim::encode_claim_body(&claim).unwrap();

    // Endpoint blobs exist in the CRDT before Observer B starts, so the
    // event below sees both participants as locally absent and defers their
    // type validation. The later edge delta must hydrate then revalidate.
    map_insert_bytes(
        &entities,
        &survivor.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &claim_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            2,
            &claim_body,
        ),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let event_id = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![claim_id],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: record.at,
                end: record.at,
            },
            record.at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();
    assert!(
        vault.identity_topology_event(&event_id).unwrap().is_some(),
        "precondition: missing local participants defer event validation"
    );

    let shell_key = format_edge_key(&claim_id, EdgeKind::MergedInto, &survivor);
    map_insert_bytes(
        &edges,
        &shell_key,
        &encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, record.at, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();

    let expected_state = EntityLifecycleState::Active;
    assert!(vault.get(&claim_id).unwrap().is_some());
    assert!(vault.get(&survivor).unwrap().is_some());
    assert_eq!(
        vault.entity_lifecycle_state(&claim_id).unwrap(),
        expected_state
    );
    assert!(
        !vault
            .edge_exists(&claim_id, EdgeKind::MergedInto, &survivor)
            .unwrap(),
        "hydration revealed a non-structural source, so the mandate must be retracted before write"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Edges);
}

#[test]
fn observer_b_quarantined_undo_commits_no_event_or_seq_advance() {
    use crate::identity_topology::{
        IdentityOpOutcome, IdentityOpWrite, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let vault = test_vault();
    let ordinary_target = EntityId::now();
    let survivor = EntityId::now();
    let loser = EntityId::now();
    for id in [&ordinary_target, &survivor, &loser] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }

    let rejected_event = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: 77,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Undo {
            target: ordinary_target,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    map_insert_bytes(
        &doc.get_map("entities"),
        &rejected_event.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: record.at,
                end: record.at,
            },
            record.at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    let expected_next_seq = 1;
    assert!(
        vault
            .identity_topology_event(&rejected_event)
            .unwrap()
            .is_none(),
        "a quarantined undo must not survive in the outer observer txn"
    );
    let outcome = vault
        .apply_identity_topology_op(
            &crate::identity_topology::IdentityTopologyOp::Merge(
                crate::identity_topology::MergeOp {
                    sources: vec![loser],
                    survivor,
                    evidence: crate::identity_topology::IdentityOpEvidence::default(),
                    survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
                },
            ),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            300,
        )
        .unwrap();
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("control merge must apply");
    };
    assert_eq!(
        vault.identity_topology_event(&event).unwrap().unwrap().seq,
        expected_next_seq,
        "the rejected remote seq must not poison the local clock"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.reason_code, "InvalidEntityType");
}

#[test]
fn observer_b_rejects_seq_that_would_consume_local_headroom_before_clock_mutation() {
    use crate::identity_topology::{
        IdentityOpOutcome, IdentityOpWrite, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let vault = test_vault();
    let survivor = EntityId::now();
    let loser = EntityId::now();
    for id in [&survivor, &loser] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }
    let rejected_event = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: crate::identity_topology::IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING
            - crate::identity_topology::IDENTITY_TOPOLOGY_LOCAL_SEQ_HEADROOM,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    map_insert_bytes(
        &doc.get_map("entities"),
        &rejected_event.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: record.at,
                end: record.at,
            },
            record.at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    let expected_next_seq = 1;
    assert!(
        vault
            .identity_topology_event(&rejected_event)
            .unwrap()
            .is_none(),
        "a seq that consumes required local headroom must reject before storage"
    );
    let outcome = vault
        .apply_identity_topology_op(
            &crate::identity_topology::IdentityTopologyOp::Merge(
                crate::identity_topology::MergeOp {
                    sources: vec![loser],
                    survivor,
                    evidence: crate::identity_topology::IdentityOpEvidence::default(),
                    survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
                },
            ),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            300,
        )
        .unwrap();
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("control merge must apply");
    };
    assert_eq!(
        vault.identity_topology_event(&event).unwrap().unwrap().seq,
        expected_next_seq,
        "the rejected terminal seq must not advance the local allocator"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(
        quarantined[0].1.reason_code,
        "InvalidIdentityTopologyEventBody"
    );
}

#[test]
fn observer_b_endpoint_materialization_retriggers_deferred_topology_reconcile() {
    use crate::identity_topology::{
        EntityLifecycleState, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let vault = test_vault();
    let survivor = EntityId::now();
    let loser = EntityId::now();
    let event_id = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    // The event arrives first. Its missing endpoints are a deferral, so the
    // immutable record lands but no shell can be written yet.
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: record.at,
                end: record.at,
            },
            record.at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();
    assert!(vault.identity_topology_event(&event_id).unwrap().is_some());
    assert!(
        !vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap()
    );

    // No raw edge delta follows. The first endpoint still cannot complete
    // the pair; materializing the second endpoint must itself retrigger the
    // ledger reconciliation and derive the mandated edge.
    for (id, expect_edge) in [(&loser, false), (&survivor, true)] {
        map_insert_bytes(
            &entities,
            &id.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            ),
        )
        .unwrap();
        doc.commit();
        assert_eq!(
            vault
                .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
                .unwrap(),
            expect_edge
        );
    }
    let expected_state = EntityLifecycleState::Merged;
    assert_eq!(
        vault.entity_lifecycle_state(&loser).unwrap(),
        expected_state
    );
}

#[test]
fn identity_topology_ingest_door_replays_diverges_and_validates() {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let vault = test_vault();
    let survivor = EntityId::now();
    let loser = EntityId::now();
    for id in [&survivor, &loser] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }

    let event_id = EntityId::now();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    let blob = entity_blob(
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        TimeRange {
            start: 200,
            end: 200,
        },
        200,
        &body,
    );
    let ingest = |blob: &[u8]| {
        let header = EntityMetadataHeader::parse(blob).unwrap();
        vault.with_write_txn(|wtxn| {
            ingest_replicated_identity_topology_event_in_txn(
                &vault,
                wtxn,
                &event_id,
                &header,
                blob,
                &blob[ENTITY_METADATA_HEADER_LEN..],
                7,
            )
        })
    };

    // Fresh accept: record stored, shell edge reconciled.
    assert!(ingest(&blob).unwrap());
    assert!(
        vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap()
    );

    // Byte-identical replay: idempotent skip.
    assert!(!ingest(&blob).unwrap());

    // Divergent bytes for the SAME id: equivocation-shaped typed
    // rejection; the accepted local bytes win.
    let mut divergent = record.clone();
    divergent.at = 999;
    let divergent_body =
        crate::identity_topology::encode_identity_topology_event_body(&divergent).unwrap();
    let divergent_blob = entity_blob(
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        TimeRange {
            start: 200,
            end: 200,
        },
        200,
        &divergent_body,
    );
    let err = ingest(&divergent_blob).unwrap_err();
    assert_matches!(err, Error::IdentityTopologyEventDivergence { .. });
    assert_eq!(
        vault
            .identity_topology_event(&event_id)
            .unwrap()
            .unwrap()
            .at,
        200,
        "divergent remote bytes must never overwrite the accepted event"
    );

    // A malformed FRESH body is the typed ingress rejection.
    let bad_id = EntityId::now();
    let bad_blob = entity_blob(
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        TimeRange { start: 1, end: 1 },
        1,
        b"not a type-76 body",
    );
    let bad_header = EntityMetadataHeader::parse(&bad_blob).unwrap();
    let err = vault
        .with_write_txn(|wtxn| {
            ingest_replicated_identity_topology_event_in_txn(
                &vault,
                wtxn,
                &bad_id,
                &bad_header,
                &bad_blob,
                &bad_blob[ENTITY_METADATA_HEADER_LEN..],
                7,
            )
        })
        .unwrap_err();
    assert_matches!(err, Error::InvalidIdentityTopologyEventBody(_));

    // Both reject shapes classify as REMOTE rejections
    // (quarantine-and-continue), so one bad row cannot abort a batch.
    assert!(
        crate::sync::quarantine::remote_rejection_reason(&Error::IdentityTopologyEventDivergence {
            id: event_id
        })
        .is_some()
    );
    assert!(
        crate::sync::quarantine::remote_rejection_reason(&Error::InvalidIdentityTopologyEventBody(
            "identity topology event bytes are malformed"
        ))
        .is_some()
    );

    // The ingested seq joined the local clock: a LOCAL undo of the synced
    // merge allocates ABOVE it and the fold orders it after its target.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    let outcome = vault
        .undo_identity_topology_event(&event_id, &write, 300)
        .unwrap();
    let crate::identity_topology::IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("undo of the ingested merge must apply");
    };
    let undo_record = vault.identity_topology_event(&event).unwrap().unwrap();
    assert!(
        undo_record.seq > record.seq,
        "seq join: local undo must order after ingested history"
    );
    assert!(
        !vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .unwrap()
    );
}

#[test]
fn byte_identical_type_76_replay_short_circuits_before_full_reconciliation() {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let vault = test_vault();
    quota::set_maintenance_ingest_quota_config(
        &vault,
        quota::MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
        },
    )
    .unwrap();
    let survivor = EntityId::from_bytes([0x61; 16]).unwrap();
    let source = EntityId::from_bytes([0x62; 16]).unwrap();
    for id in [&survivor, &source] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                1,
                &task_body(),
            )
            .unwrap();
    }
    let event_id = EntityId::from_bytes([0x70; 16]).unwrap();
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Proposed,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![source],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record).unwrap();
    let blob = entity_blob(
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        TimeRange {
            start: 200,
            end: 200,
        },
        200,
        &body,
    );
    let header = EntityMetadataHeader::parse(&blob).unwrap();
    let ingest = || {
        vault.with_write_txn(|wtxn| {
            ingest_replicated_identity_topology_event_in_txn(
                &vault, &mut *wtxn, &event_id, &header, &blob, &body, 7,
            )
        })
    };

    crate::identity_topology::test_hooks::reset_full_reconciliations();
    assert!(ingest().unwrap(), "fresh record must materialize");
    let after_fresh = crate::identity_topology::test_hooks::full_reconciliations();
    assert_eq!(after_fresh, 1, "fresh admission reconciles once");

    // The one-op quota is now exhausted. Replay still succeeds because it is
    // recognized as byte-identical before quota and before the full fold.
    assert!(
        !ingest().unwrap(),
        "byte-identical replay is an idempotent skip"
    );
    assert_eq!(
        crate::identity_topology::test_hooks::full_reconciliations(),
        after_fresh,
        "unchanged replay must not enumerate and reconcile the whole family"
    );
}

#[test]
fn observer_b_rejects_every_local_impossible_type_76_shape_before_mutation() {
    use crate::identity_topology::{
        ReassignmentEntry, ReassignmentMap, ReassignmentTarget, StoredIdentityOpAction,
        StoredIdentityOpEvent,
    };

    let vault = test_vault();
    quota::set_maintenance_ingest_quota_config(
        &vault,
        quota::MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
        },
    )
    .unwrap();
    let survivor = EntityId::from_bytes([0x61; 16]).unwrap();
    let source = EntityId::from_bytes([0x62; 16]).unwrap();
    let head = EntityId::from_bytes([0x63; 16]).unwrap();
    for id in [&survivor, &source, &head] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                1,
                &task_body(),
            )
            .unwrap();
    }

    let base = |seq, approval, action| StoredIdentityOpEvent {
        seq,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval,
        confidence: 1.0,
        evidence: None,
        action,
    };
    let invalid = [
        base(
            1,
            ClaimApprovalStatus::Auto,
            StoredIdentityOpAction::Merge {
                sources: Vec::new(),
                survivor,
            },
        ),
        base(
            2,
            ClaimApprovalStatus::Auto,
            StoredIdentityOpAction::Merge {
                sources: vec![source],
                survivor: source,
            },
        ),
        base(
            3,
            ClaimApprovalStatus::Auto,
            StoredIdentityOpAction::Merge {
                sources: vec![source, source],
                survivor,
            },
        ),
        base(
            4,
            ClaimApprovalStatus::Auto,
            StoredIdentityOpAction::Split {
                entity: source,
                heads: vec![head],
                reassignment: ReassignmentMap {
                    entries: vec![ReassignmentEntry {
                        item: crate::claim::ClaimSubject::Entity(survivor),
                        target: ReassignmentTarget::Facet { index: 0 },
                    }],
                },
                applied_assigned: 0,
                applied_residue: 0,
            },
        ),
        base(
            0,
            ClaimApprovalStatus::Auto,
            StoredIdentityOpAction::Merge {
                sources: vec![source],
                survivor,
            },
        ),
        base(
            5,
            ClaimApprovalStatus::Rejected,
            StoredIdentityOpAction::Merge {
                sources: vec![source],
                survivor,
            },
        ),
    ];

    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let entities = doc.get_map("entities");
    let invalid_ids = invalid
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let event_id = EntityId::from_bytes([0x70 + index as u8; 16]).unwrap();
            let body = crate::identity_topology::encode_identity_topology_event_body(record)
                .expect("encode invalid-shape fixture");
            map_insert_bytes(
                &entities,
                &event_id.to_hex(),
                &entity_blob(
                    crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
                    TimeRange {
                        start: record.at,
                        end: record.at,
                    },
                    record.at,
                    &body,
                ),
            )
            .unwrap();
            event_id
        })
        .collect::<Vec<_>>();
    doc.commit();

    for event_id in &invalid_ids {
        assert!(
            vault.identity_topology_event(event_id).unwrap().is_none(),
            "a local-impossible shape must leave no stored row"
        );
    }
    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, crate::identity_topology::IDENTITY_TOPOLOGY_SEQ_KEY,)
            .unwrap()
            .is_none(),
        "rejected shapes must not advance the topology clock"
    );
    drop(rtxn);
    assert_eq!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .len(),
        invalid_ids.len(),
        "every rejected shape must leave quarantine evidence"
    );

    // With a one-op quota, this valid control can land only if none of the
    // invalid rows consumed quota before rejection.
    let valid_id = EntityId::from_bytes([0x7f; 16]).unwrap();
    let valid = base(
        50,
        ClaimApprovalStatus::Auto,
        StoredIdentityOpAction::Merge {
            sources: vec![source],
            survivor,
        },
    );
    let body = crate::identity_topology::encode_identity_topology_event_body(&valid).unwrap();
    map_insert_bytes(
        &entities,
        &valid_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            &body,
        ),
    )
    .unwrap();
    doc.commit();
    assert_eq!(
        vault.identity_topology_event(&valid_id).unwrap(),
        Some(valid)
    );
}

#[test]
fn observer_b_rejects_present_actor_class_mismatch_before_mutation() {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let vault = test_vault();
    quota::set_maintenance_ingest_quota_config(
        &vault,
        quota::MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
        },
    )
    .unwrap();
    let survivor = EntityId::from_bytes([0x61; 16]).unwrap();
    let source = EntityId::from_bytes([0x62; 16]).unwrap();
    let actor = EntityId::from_bytes([0x63; 16]).unwrap();
    for id in [&survivor, &source] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                1,
                &task_body(),
            )
            .unwrap();
    }
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )
        .unwrap();

    let record = |actor_class| StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: Some(crate::write_envelope::WriteActor::new(actor, actor_class)),
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![source],
            survivor,
        },
    };
    let rejected_id = EntityId::from_bytes([0x70; 16]).unwrap();
    let rejected = record(EdgeActorClass::System);
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let entities = doc.get_map("entities");
    let rejected_body =
        crate::identity_topology::encode_identity_topology_event_body(&rejected).unwrap();
    map_insert_bytes(
        &entities,
        &rejected_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            &rejected_body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(
        vault
            .identity_topology_event(&rejected_id)
            .unwrap()
            .is_none()
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, crate::identity_topology::IDENTITY_TOPOLOGY_SEQ_KEY,)
            .unwrap()
            .is_none(),
        "actor mismatch must not advance the topology clock"
    );
    drop(rtxn);
    let quarantined = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(
        quarantined[0].1.reason_code,
        "InvalidIdentityTopologyEventBody"
    );

    // The valid actor-class control lands under a one-op quota only if the
    // mismatch was rejected before quota debit.
    let valid_id = EntityId::from_bytes([0x71; 16]).unwrap();
    let valid = record(EdgeActorClass::Human);
    let valid_body = crate::identity_topology::encode_identity_topology_event_body(&valid).unwrap();
    map_insert_bytes(
        &entities,
        &valid_id.to_hex(),
        &entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            &valid_body,
        ),
    )
    .unwrap();
    doc.commit();
    assert_eq!(
        vault.identity_topology_event(&valid_id).unwrap(),
        Some(valid)
    );
}
