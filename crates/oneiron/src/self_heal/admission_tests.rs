//! Address and validity checks shared by diagnostic admission doors.

use super::*;
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::store::Store;
use crate::test_util::open_test_vault_with;

fn facts() -> [DiagnosticObservation; 1] {
    [DiagnosticObservation {
        source_ref: EntityId::from_bytes([2; 16]).unwrap(),
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [2; 32],
        observed_at: 1_000,
    }]
}

fn draft() -> DiagnosticEvent {
    ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &facts(),
        })
        .remove(0)
}

fn local_put(vault: &Vault, id: EntityId, occurred: TimeRange, data: Vec<u8>) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_DIAGNOSTIC,
                occurred,
                learned_at: 1_001,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            false,
            false,
            true,
        )
    })
}

#[test]
fn diagnostic_admission_binds_address_and_indexed_validity() -> Result<()> {
    let (_dir, vault) = open_vault();
    for end in [None, Some(1_060)] {
        let mut event = sample_event();
        event.valid_to = end;
        let body = encode_diagnostic_event_body(&event)?;
        let id = diagnostic_event_id(&event.detector_id, &body);
        let occurred = TimeRange {
            start: event.valid_from,
            end: end.unwrap_or(u64::MAX),
        };
        let alias = diagnostic_event_id("another.detector", &body);
        assert_ne!(id, alias);
        assert!(vault.emit_diagnostic_event(&alias, &event).is_err());
        for (id, wrong) in [
            (alias, occurred),
            (
                id,
                TimeRange {
                    start: 999,
                    ..occurred
                },
            ),
            (id, at(1_000)),
        ] {
            assert_eq!(
                local_put(&vault, id, wrong, body.clone())
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidDiagnosticBody
            );
            assert_eq!(
                vault
                    .batch()
                    .put_replicated(&id, ENTITY_TYPE_DIAGNOSTIC, wrong, 1_001, &body)
                    .commit()
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidDiagnosticBody
            );
            assert!(vault.get_raw(&id)?.is_none());
        }
        // Reordered bytes fail even under an address derived from those bytes.
        let mut entries = body_entries(&body);
        entries.swap(0, 1);
        let reordered = encode_entries(entries);
        let reordered_id = diagnostic_event_id(&event.detector_id, &reordered);
        assert!(local_put(&vault, reordered_id, occurred, reordered.clone()).is_err());
        assert!(
            vault
                .batch()
                .put_replicated(
                    &reordered_id,
                    ENTITY_TYPE_DIAGNOSTIC,
                    occurred,
                    1_001,
                    &reordered,
                )
                .commit()
                .is_err()
        );
        assert!(vault.get_raw(&reordered_id)?.is_none());

        vault.emit_diagnostic_event(&id, &event)?;
        let stored = vault.get_raw(&id)?.unwrap();
        let header = EntityMetadataHeader::parse(&stored).unwrap();
        assert_eq!(header.occurred_start, event.valid_from);
        assert_eq!(header.occurred_end, occurred.end);
        let txn = vault.store.env.read_txn()?;
        let key = Store::encode_temporal_key(occurred.end, &id);
        let indexed = vault
            .store
            .temporal_long_intervals
            .get(&txn, &key)?
            .is_some();
        assert_eq!(indexed, end.is_none());
        drop(txn);
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_DIAGNOSTIC, occurred, 1_001, &body)
            .commit()?;
        assert_eq!(stored_body(&vault, &id)?, body);
    }
    Ok(())
}

struct MisattributedDetector;

impl DeterministicDetector for MisattributedDetector {
    fn detector_id(&self) -> &'static str {
        "test.impostor"
    }

    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        StubDetector.detect(input)
    }
}

#[test]
fn diagnostic_identity_is_validated_before_any_write() -> Result<()> {
    let mut event = sample_event();
    let canonical = encode_diagnostic_event_body(&event)?;
    for invalid in [
        "".to_owned(),
        "UPPER".to_owned(),
        "a".repeat(MAX_TOKEN_LEN + 1),
    ] {
        event.detector_id = invalid.clone();
        assert!(encode_diagnostic_event_body(&event).is_err());
        let mut entries = body_entries(&canonical);
        set_key(&mut entries, "detector_id", Value::from(invalid));
        assert_rejected(&encode_entries(entries), "invalid detector identity");
    }
    let (_dir, vault) = open_vault();
    let observations = [observation(2, 1_000)];
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.fixture",
        observations: &observations,
    };
    assert!(
        run_deterministic_detectors(&vault, &input, &[&StubDetector, &MisattributedDetector])
            .is_err()
    );
    assert!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.is_empty());
    Ok(())
}

#[test]
fn diagnostic_local_and_replicated_admission_bind_identity_and_body() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let event = draft();
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    let occurred = TimeRange {
        start: event.valid_from,
        end: u64::MAX,
    };
    let mut other = event.clone();
    other.detector_id = "another.detector".to_owned();
    let other_body = encode_diagnostic_event_body(&other)?;
    let other_id = diagnostic_event_id(&other.detector_id, &other_body);
    assert_ne!(body, other_body, "identity is part of the canonical body");
    assert_ne!(id, other_id);
    assert_eq!(
        decode_diagnostic_event_body(&body)?.detector_id,
        event.detector_id
    );

    let mut changed = event.clone();
    changed.actual = Value::from(2_u64);
    let changed_body = encode_diagnostic_event_body(&changed)?;
    let changed_id = diagnostic_event_id(&changed.detector_id, &changed_body);
    for alias in [
        EntityId::from_bytes([3; 16])?,
        diagnostic_event_id(&other.detector_id, &body),
        other_id,
        changed_id,
    ] {
        assert_ne!(alias, id);
        assert_eq!(
            vault
                .emit_diagnostic_event(&alias, &event)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidDiagnosticBody
        );
        assert_eq!(
            local_put(&vault, alias, occurred, body.clone())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidDiagnosticBody
        );
        assert_eq!(
            vault
                .batch()
                .put_replicated(&alias, ENTITY_TYPE_DIAGNOSTIC, occurred, 1_000, &body)
                .commit()
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidDiagnosticBody
        );
        assert!(vault.get_raw(&alias)?.is_none());
    }
    assert!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.is_empty());

    // A valid identity is not an allowlist: another detector's correctly
    // addressed body is still admitted, including through the replay door.
    vault.emit_diagnostic_event(&id, &event)?;
    for _ in 0..2 {
        vault
            .batch()
            .put_replicated(
                &other_id,
                ENTITY_TYPE_DIAGNOSTIC,
                occurred,
                1_000,
                &other_body,
            )
            .commit()?;
    }
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.len(), 2);
    let before = vault.get_raw(&id)?;
    assert_eq!(
        local_put(&vault, id, occurred, changed_body)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidDiagnosticBody
    );
    assert_eq!(
        vault.get_raw(&id)?,
        before,
        "same-id divergence keeps local bytes"
    );
    Ok(())
}

#[test]
fn diagnostic_all_puts_bind_occurrence_to_open_and_closed_validity() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    for end in [None, Some(1_060)] {
        let mut event = draft();
        event.valid_to = end;
        let body = encode_diagnostic_event_body(&event)?;
        let id = diagnostic_event_id(&event.detector_id, &body);
        let occurred = TimeRange {
            start: event.valid_from,
            end: end.unwrap_or(u64::MAX),
        };
        for wrong in [
            TimeRange {
                start: 999,
                ..occurred
            },
            TimeRange {
                start: 1_000,
                end: 1_000,
            },
            TimeRange {
                start: 1_000,
                end: 1_061,
            },
        ] {
            assert_eq!(
                local_put(&vault, id, wrong, body.clone())
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidDiagnosticBody
            );
            assert_eq!(
                vault
                    .batch()
                    .put_replicated(&id, ENTITY_TYPE_DIAGNOSTIC, wrong, 1_000, &body)
                    .commit()
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidDiagnosticBody
            );
            assert!(vault.get_raw(&id)?.is_none());
        }
        local_put(&vault, id, occurred, body)?;
    }
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.len(), 2);
    Ok(())
}

#[test]
fn diagnostic_detector_identity_is_required_and_bounded() -> Result<()> {
    let body = encode_diagnostic_event_body(&draft())?;
    let Value::Map(entries) = rmpv::decode::read_value(&mut Cursor::new(&body)).unwrap() else {
        panic!("body map");
    };
    for invalid in [
        "".to_owned(),
        "UPPER".to_owned(),
        "space id".to_owned(),
        "é".to_owned(),
        "a".repeat(65),
    ] {
        let mut event = draft();
        event.detector_id = invalid.clone();
        assert_eq!(
            encode_diagnostic_event_body(&event).unwrap_err().kind(),
            ErrorKind::InvalidDiagnosticBody
        );
        let mut hostile = entries.clone();
        hostile
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("detector_id"))
            .unwrap()
            .1 = Value::from(invalid);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(hostile)).unwrap();
        assert_eq!(
            decode_diagnostic_event_body(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidDiagnosticBody
        );
    }
    let mut missing = entries;
    missing.retain(|(key, _)| key.as_str() != Some("detector_id"));
    let mut legacy = Vec::new();
    rmpv::encode::write_value(&mut legacy, &Value::Map(missing)).unwrap();
    assert_eq!(
        decode_diagnostic_event_body(&legacy).unwrap_err().kind(),
        ErrorKind::InvalidDiagnosticBody
    );
    Ok(())
}

struct ImpostorDetector;

impl DeterministicDetector for ImpostorDetector {
    fn detector_id(&self) -> &'static str {
        "impostor.detector"
    }

    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        ConsentDeniedDetector.detect(input)
    }
}

#[test]
fn diagnostic_runner_rejects_misattributed_drafts_before_any_write() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let facts = facts();
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.consent",
        observations: &facts,
    };
    let err =
        run_deterministic_detectors(&vault, &input, &[&ConsentDeniedDetector, &ImpostorDetector])
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidDiagnosticBody);
    assert!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.is_empty());
    Ok(())
}
