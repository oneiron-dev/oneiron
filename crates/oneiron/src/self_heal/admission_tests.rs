//! Address and validity checks shared by diagnostic admission doors.

use super::*;
use crate::store::Store;

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
                local_put(&vault, id, wrong, body.clone()).unwrap_err().kind(),
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
        let indexed = vault.store.temporal_long_intervals.get(&txn, &key)?.is_some();
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
    for invalid in ["".to_owned(), "UPPER".to_owned(), "a".repeat(MAX_TOKEN_LEN + 1)] {
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
