use super::*;
use crate::config::VaultConfig;
use crate::error::{RecordError, SyncError};
use crate::registry::{ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_PERSON};
use crate::self_heal::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticObservation, DiagnosticWorkingSet,
    diagnostic_event_id, encode_diagnostic_event_body,
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

fn diagnostic_fixture(seed: u8, valid_to: Option<u64>) -> Result<(EntityId, Vec<u8>)> {
    let observations = [DiagnosticObservation {
        source_ref: id(seed),
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [seed; 32],
        observed_at: 1_000,
    }];
    let mut event = ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &observations,
        })
        .remove(0);
    event.valid_to = valid_to;
    let body = encode_diagnostic_event_body(&event)?;
    let entity = diagnostic_event_id(&event.detector_id, &body);
    let mut blob = vec![ENTITY_TYPE_DIAGNOSTIC];
    blob.extend_from_slice(&event.valid_from.to_be_bytes());
    blob.extend_from_slice(&valid_to.unwrap_or(u64::MAX).to_be_bytes());
    blob.extend_from_slice(&1_000_u64.to_be_bytes());
    blob.extend_from_slice(&body);
    Ok((entity, blob))
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
fn diagnostic_observer_b_quota_exhaustion_and_rejection_preserves_budget() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let (collision, collision_blob) = diagnostic_fixture(3, None)?;
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
    let (first, first_blob) = diagnostic_fixture(4, None)?;
    let (second, second_blob) = diagnostic_fixture(5, None)?;
    let (excess, excess_blob) = diagnostic_fixture(6, None)?;
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
        let mut malformed = first_blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
        malformed.push(0x80);
        assert!(matches!(
            ingest(id(9), &malformed),
            Err(Error::Record(RecordError::InvalidDiagnosticBody(_)))
        ));
        assert!(ingest(first, &first_blob)?);
        let err = ingest(collision, &collision_blob).unwrap_err();
        assert!(matches!(
            err,
            Error::Record(RecordError::InvalidDiagnosticBody(_))
        ));
        assert!(remote_rejection_reason(&err).is_some());
        // Observer B continues after a remote rejection in the SAME txn.
        // Rejection must preserve the first debit and leave room for a sibling.
        assert!(ingest(second, &second_blob)?);
        assert!(matches!(
            ingest(excess, &excess_blob),
            Err(Error::Sync(SyncError::MaintenanceIngestQuotaExceeded {
                accepted_count: 2,
                ..
            }))
        ));
        assert!(!ingest(first, &first_blob)?, "echo must not consume quota");
        Ok(())
    })?;
    assert_eq!(accepted(&vault)?, 2);
    assert_eq!(vault.get_raw(&collision)?, original);
    assert!(vault.get_raw(&first)?.is_some());
    assert!(vault.get_raw(&second)?.is_some());
    assert!(vault.get_raw(&excess)?.is_none());
    assert!(vault.get_raw(&id(9))?.is_none());
    Ok(())
}

#[test]
fn diagnostic_observer_b_transaction_abort_restores_quota() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    let (entity, blob) = diagnostic_fixture(4, None)?;
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
fn diagnostic_forward_remat_quota_exhaustion_and_rejection_preserves_budget() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let (collision, collision_blob) = diagnostic_fixture(3, None)?;
    vault.put_entity(
        &collision,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let original = vault.get_raw(&collision)?;
    let (first, first_blob) = diagnostic_fixture(4, None)?;
    let (second, second_blob) = diagnostic_fixture(5, None)?;
    let (excess, excess_blob) = diagnostic_fixture(6, None)?;
    let materializer = Materializer::new();
    let window = WindowKey::new("2026-03");
    let replay = |entity: EntityId, bytes: &[u8]| -> Result<u32> {
        let doc = LoroDoc::new();
        map_insert_bytes(&doc.get_map("entities"), &entity.to_hex(), bytes)?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &window)
    };
    // Rejection must neither create an absent bucket nor change an existing one.
    assert_eq!(replay(collision, &collision_blob)?, 0);
    assert!(maintenance_ingest_quota_snapshots(&vault)?.is_empty());
    assert_eq!(replay(first, &first_blob)?, 1);
    assert_eq!(replay(collision, &collision_blob)?, 0);
    assert_eq!(accepted(&vault)?, 1);
    let mut malformed = first_blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
    malformed.push(0x80);
    assert_eq!(replay(id(9), &malformed)?, 0);
    assert_eq!(accepted(&vault)?, 1);
    assert_eq!(replay(second, &second_blob)?, 1);
    assert_eq!(replay(excess, &excess_blob)?, 0);
    assert_eq!(replay(first, &first_blob)?, 0, "echo is free even at quota");
    assert_eq!(accepted(&vault)?, 2);
    assert_eq!(vault.get_raw(&collision)?, original);
    assert!(vault.get_raw(&excess)?.is_none());
    assert!(vault.get_raw(&id(9))?.is_none());
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    for reason in ["InvalidDiagnosticBody", "MaintenanceIngestQuotaExceeded"] {
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
            &excess.to_hex(),
            &excess_blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Sync(SyncError::MaintenanceIngestQuotaExceeded { .. })
        ));
        Ok(())
    })?;
    Ok(())
}

// Each body below is canonical. Only its externally supplied address or
// envelope is hostile, so schema-only validation cannot reject these rows.
fn hostile_diagnostics(local: EntityId, original: &[u8]) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let alias = diagnostic_event_id("another.detector", &original[ENTITY_METADATA_HEADER_LEN..]);
    let (_, divergent_body) = diagnostic_fixture(8, None)?;
    let (open_id, open) = diagnostic_fixture(6, None)?;
    let (closed_id, closed) = diagnostic_fixture(7, Some(1_060))?;
    let mut wrong_start = open.clone();
    wrong_start[1..9].copy_from_slice(&999_u64.to_be_bytes());
    let mut open_as_point = open;
    open_as_point[9..17].copy_from_slice(&1_000_u64.to_be_bytes());
    let mut closed_as_open = closed.clone();
    closed_as_open[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut wrong_end = closed;
    wrong_end[9..17].copy_from_slice(&1_059_u64.to_be_bytes());
    let mut divergent_envelope = original.to_vec();
    divergent_envelope[17..25].copy_from_slice(&1_001_u64.to_be_bytes());
    Ok(vec![
        (id(80), original.to_vec()),
        (id(81), original.to_vec()),
        (alias, original.to_vec()),
        (local, divergent_body),
        (open_id, wrong_start),
        (open_id, open_as_point),
        (closed_id, closed_as_open),
        (closed_id, wrong_end),
        (local, divergent_envelope),
    ])
}

fn assert_diagnostic_quarantined(vault: &Vault, entity: EntityId, bytes: &[u8]) -> Result<()> {
    let rows = crate::sync::quarantine::quarantined_records(vault)?;
    let key_hash = crate::sync::quarantine::crdt_key_metadata(&entity.to_hex()).0;
    let hash = crate::sync::quarantine::payload_hash(bytes);
    assert!(rows.iter().any(|(_, row)| {
        row.reason_code == "InvalidDiagnosticBody"
            && row.container == QuarantineContainer::Entities
            && row.crdt_key_hash == key_hash
            && row.payload_hash == hash
    }));
    Ok(())
}

#[test]
fn diagnostic_observer_b_quarantines_aliases_divergence_and_false_occurrence() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let vault = Arc::new(vault);
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let entities = doc.get_map("entities");
    let (local, original) = diagnostic_fixture(4, None)?;
    map_insert_bytes(&entities, &local.to_hex(), &original)?;
    doc.commit();
    assert_eq!(vault.get_raw(&local)?.as_deref(), Some(original.as_slice()));
    assert_eq!(accepted(&vault)?, 1);
    let before = maintenance_ingest_quota_snapshots(&vault)?;

    for (entity, hostile) in hostile_diagnostics(local, &original)? {
        let count = crate::sync::quarantine::quarantined_records(&vault)?.len();
        map_insert_bytes(&entities, &entity.to_hex(), &hostile)?;
        doc.commit();
        assert_eq!(maintenance_ingest_quota_snapshots(&vault)?, before);
        assert_eq!(vault.get_raw(&local)?.as_deref(), Some(original.as_slice()));
        if entity != local {
            assert!(vault.get_raw(&entity)?.is_none());
        }
        assert_eq!(
            crate::sync::quarantine::quarantined_records(&vault)?.len(),
            count + 1
        );
        assert_diagnostic_quarantined(&vault, entity, &hostile)?;
    }

    // A rejected alias and a legitimate closed finding share one Observer-B
    // transaction. The rejection must neither abort nor consume its sibling's
    // remaining budget. Restore the original local row as an exact echo too.
    let (second, second_blob) = diagnostic_fixture(5, Some(1_060))?;
    map_insert_bytes(&entities, &id(82).to_hex(), &original)?;
    map_insert_bytes(&entities, &second.to_hex(), &second_blob)?;
    map_insert_bytes(&entities, &local.to_hex(), &original)?;
    doc.commit();
    assert_diagnostic_quarantined(&vault, id(82), &original)?;
    assert!(vault.get_raw(&id(82))?.is_none());
    assert_eq!(
        vault.get_raw(&second)?.as_deref(),
        Some(second_blob.as_slice())
    );
    assert_eq!(vault.get_raw(&local)?.as_deref(), Some(original.as_slice()));
    assert_eq!(accepted(&vault)?, 2);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.len(), 2);
    Ok(())
}

#[test]
fn diagnostic_forward_remat_quarantines_aliases_divergence_and_false_occurrence() -> Result<()> {
    let (_dir, vault) = quota_vault()?;
    let materializer = Materializer::new();
    let window = WindowKey::new("2026-03");
    let replay = |entity: EntityId, bytes: &[u8]| -> Result<u32> {
        let doc = LoroDoc::new();
        map_insert_bytes(&doc.get_map("entities"), &entity.to_hex(), bytes)?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &window)
    };
    let (local, original) = diagnostic_fixture(4, None)?;
    assert_eq!(replay(local, &original)?, 1);
    let before = maintenance_ingest_quota_snapshots(&vault)?;
    for (entity, hostile) in hostile_diagnostics(local, &original)? {
        let count = crate::sync::quarantine::quarantined_records(&vault)?.len();
        assert_eq!(replay(entity, &hostile)?, 0);
        assert_eq!(maintenance_ingest_quota_snapshots(&vault)?, before);
        assert_eq!(vault.get_raw(&local)?.as_deref(), Some(original.as_slice()));
        if entity != local {
            assert!(vault.get_raw(&entity)?.is_none());
        }
        assert_eq!(
            crate::sync::quarantine::quarantined_records(&vault)?.len(),
            count + 1
        );
        assert_diagnostic_quarantined(&vault, entity, &hostile)?;
    }

    // One bad row must not stop the remainder of this forward pass.
    let (second, second_blob) = diagnostic_fixture(5, Some(1_060))?;
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &id(82).to_hex(), &original)?;
    map_insert_bytes(&entities, &second.to_hex(), &second_blob)?;
    doc.commit();
    assert_eq!(
        forward_rematerialize(&vault, &doc, &materializer, &window)?,
        1
    );
    assert_diagnostic_quarantined(&vault, id(82), &original)?;
    assert!(vault.get_raw(&id(82))?.is_none());
    let count = crate::sync::quarantine::quarantined_records(&vault)?.len();
    assert_eq!(replay(local, &original)?, 0, "open echo at quota");
    assert_eq!(replay(second, &second_blob)?, 0, "closed echo at quota");
    assert_eq!(
        crate::sync::quarantine::quarantined_records(&vault)?.len(),
        count
    );
    assert_eq!(vault.get_raw(&local)?.as_deref(), Some(original.as_slice()));
    assert_eq!(
        vault.get_raw(&second)?.as_deref(),
        Some(second_blob.as_slice())
    );
    assert_eq!(accepted(&vault)?, 2);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.len(), 2);
    Ok(())
}
