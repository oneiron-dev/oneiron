use super::*;
use crate::config::VaultConfig;
use crate::registry::{ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_PERSON};
use crate::self_heal::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticObservation, DiagnosticWorkingSet,
    encode_diagnostic_event_body,
};
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::quota::{
    MaintenanceIngestQuotaConfig, maintenance_ingest_quota_snapshots,
    set_maintenance_ingest_quota_config,
};
use crate::sync::types::WindowKey;
use crate::sync::window::forward_rematerialize;
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

fn diagnostic_blob() -> Result<Vec<u8>> {
    let observations = [DiagnosticObservation {
        source_ref: id(2),
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [2; 32],
        observed_at: 1_000,
    }];
    let event = ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &observations,
        })
        .remove(0);
    let mut blob = vec![ENTITY_TYPE_DIAGNOSTIC];
    blob.extend_from_slice(&1_000_u64.to_be_bytes());
    blob.extend_from_slice(&u64::MAX.to_be_bytes());
    blob.extend_from_slice(&1_000_u64.to_be_bytes());
    blob.extend_from_slice(&encode_diagnostic_event_body(&event)?);
    Ok(blob)
}

fn quota_vault() -> Result<(tempfile::TempDir, Vault)> {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    set_maintenance_ingest_quota_config(
        &vault,
        MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: 2,
            quota_window_secs: u64::MAX,
        },
    )?;
    Ok((dir, vault))
}

fn accepted(vault: &Vault) -> Result<u32> {
    Ok(maintenance_ingest_quota_snapshots(vault)?
        .iter()
        .map(|row| row.accepted_count)
        .sum())
}

#[test]
fn diagnostic_observer_b_quota_exhaustion_and_rejection_rollback() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let collision = id(3);
    vault.put_entity(
        &collision,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let original = vault.get_raw(&collision)?;
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    let blob = diagnostic_blob()?;
    let lease = crate::sync::lease::DEFAULT_LEASE_VAULT_ID;
    vault.with_write_txn(|wtxn| {
        let mut ingest = |entity: EntityId, bytes: &[u8]| {
            materialize_entity_blob_in_txn(
                &vault,
                wtxn,
                &tombstones,
                "2026-03",
                &entity.to_hex(),
                bytes,
                lease,
            )
        };
        let mut malformed = blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
        malformed.push(0x80);
        assert!(matches!(
            ingest(id(9), &malformed),
            Err(Error::InvalidDiagnosticBody(_))
        ));
        assert!(ingest(id(4), &blob)?);
        let err = ingest(collision, &blob).unwrap_err();
        assert!(matches!(err, Error::EntityTypeImmutable { .. }));
        assert!(remote_rejection_reason(&err).is_some());
        // Observer B continues after a remote rejection in the SAME txn.
        // The rejected debit must restore the previous count, not erase it.
        assert!(ingest(id(5), &blob)?);
        assert!(matches!(
            ingest(id(6), &blob),
            Err(Error::MaintenanceIngestQuotaExceeded {
                accepted_count: 2,
                ..
            })
        ));
        assert!(!ingest(id(4), &blob)?, "echo must not consume quota");
        Ok(())
    })?;
    assert_eq!(accepted(&vault)?, 2);
    assert_eq!(vault.get_raw(&collision)?, original);
    assert!(vault.get_raw(&id(4))?.is_some());
    assert!(vault.get_raw(&id(5))?.is_some());
    assert!(vault.get_raw(&id(6))?.is_none());
    assert!(vault.get_raw(&id(9))?.is_none());
    Ok(())
}

#[test]
fn diagnostic_observer_b_transaction_abort_restores_quota() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    let blob = diagnostic_blob()?;
    let entity = id(4);
    let err = vault
        .with_write_txn(|wtxn| {
            assert!(materialize_entity_blob_in_txn(
                &vault,
                wtxn,
                &tombstones,
                "2026-03",
                &entity.to_hex(),
                &blob,
                crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            )?);
            Err::<(), _>(Error::InvariantViolation("abort after diagnostic apply"))
        })
        .unwrap_err();
    assert!(matches!(err, Error::InvariantViolation(_)));
    assert!(vault.get_raw(&entity)?.is_none());
    assert!(maintenance_ingest_quota_snapshots(&vault)?.is_empty());
    vault.with_write_txn(|wtxn| {
        materialize_entity_blob_in_txn(
            &vault,
            wtxn,
            &tombstones,
            "2026-03",
            &entity.to_hex(),
            &blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )
        .map(|_| ())
    })?;
    assert_eq!(accepted(&vault)?, 1);
    Ok(())
}

#[test]
fn diagnostic_forward_rematerialize_quota_exhaustion_and_rollback() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let collision = id(3);
    vault.put_entity(
        &collision,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let original = vault.get_raw(&collision)?;
    let blob = diagnostic_blob()?;
    let materializer = Materializer::new();
    let window = WindowKey::new("2026-03");
    let replay = |entity: EntityId, bytes: &[u8]| -> Result<u32> {
        let doc = LoroDoc::new();
        map_insert_bytes(&doc.get_map("entities"), &entity.to_hex(), bytes)?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &window)
    };
    // Each rejected forward row aborts its quota+put transaction. Prove both
    // restoration of an absent bucket and preservation of an existing debit.
    assert_eq!(replay(collision, &blob)?, 0);
    assert!(maintenance_ingest_quota_snapshots(&vault)?.is_empty());
    assert_eq!(replay(id(4), &blob)?, 1);
    assert_eq!(replay(collision, &blob)?, 0);
    assert_eq!(accepted(&vault)?, 1);
    let mut malformed = blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
    malformed.push(0x80);
    assert_eq!(replay(id(9), &malformed)?, 0);
    assert_eq!(accepted(&vault)?, 1);
    assert_eq!(replay(id(5), &blob)?, 1);
    assert_eq!(replay(id(6), &blob)?, 0);
    assert_eq!(replay(id(4), &blob)?, 0, "echo is free even at quota");
    assert_eq!(accepted(&vault)?, 2);
    assert_eq!(vault.get_raw(&collision)?, original);
    assert!(vault.get_raw(&id(6))?.is_none());
    assert!(vault.get_raw(&id(9))?.is_none());
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    for reason in [
        "EntityTypeImmutable",
        "InvalidDiagnosticBody",
        "MaintenanceIngestQuotaExceeded",
    ] {
        assert!(quarantined.iter().any(|(_, row)| row.reason_code == reason));
    }
    // Both doors share the same aggregate stream bucket, not a per-window
    // or per-body bucket that a hostile peer can rotate to bypass the cap.
    let doc = LoroDoc::new();
    vault.with_write_txn(|wtxn| {
        let err = materialize_entity_blob_in_txn(
            &vault,
            wtxn,
            &doc.get_map("tombstones"),
            "2026-04",
            &id(7).to_hex(),
            &blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )
        .unwrap_err();
        assert!(matches!(err, Error::MaintenanceIngestQuotaExceeded { .. }));
        Ok(())
    })?;
    Ok(())
}
