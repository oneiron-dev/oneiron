use super::*;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::consent::{ComposedEffect, EffectFacts};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::store::GateDecisionId;
use crate::test_util::open_test_vault_with;

fn consent_vault() -> Result<(tempfile::TempDir, Vault, EntityId, ReceiptQuery)> {
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let owner =
        vault.authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())?;
    let effect =
        ComposedEffect::new(EffectFacts::new("channel.send")?.with_external_observers(true));
    vault.approve_once(&owner, effect.digest())?;
    vault.deny_consent(&owner, effect.digest())?;
    vault.deny_consent(&owner, effect.digest())?;
    let query = ReceiptQuery::new(16)
        .with_kind(ReceiptKind::Gate)
        .with_actor(owner_id.to_hex());
    Ok((dir, vault, owner_id, query))
}

fn observations(receipts: &[ReceiptRecord]) -> Result<Vec<DiagnosticObservation>> {
    let mut observations = Vec::new();
    for receipt in receipts {
        if let Some(observation) = DiagnosticObservation::from_consent_receipt(receipt)? {
            observations.push(observation);
        }
    }
    observations.sort_by_key(DiagnosticObservation::order_key);
    Ok(observations)
}

fn body(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    Ok(vault.get_raw(id)?.expect("stored diagnostic")[ENTITY_METADATA_HEADER_LEN..].to_vec())
}

/// Owner ruling 2026-10-14 (fix 6): a diagnostic carries no world text. The
/// scope label is a caller's string, so no row the detector writes holds it,
/// a DIAGNOSTIC body with prose in a replay coordinate does not pass the write
/// door, and one stored before the ruling reads without it.
#[test]
fn a_prose_scope_label_reaches_no_stored_row() -> Result<()> {
    const PROSE: &str = "sentinel-world-text-4e19 my sister's diagnosis";
    let (_dir, vault, _, query) = consent_vault()?;
    let ids = vault.run_consent_denied_detector(PROSE, query)?;
    assert_eq!(ids.len(), 2, "both refusals are found");
    for (table, rows) in crate::test_util::row_dump::dump_rows(&vault) {
        for (key, value) in rows {
            assert!(
                !value
                    .windows(b"sentinel-world-text-4e19".len())
                    .any(|w| w == b"sentinel-world-text-4e19"),
                "{table} row {key:?} holds the scope label"
            );
        }
    }
    let canonical = body(&vault, &ids[0])?;
    for key in ["replay_run_ref", "replay_checkpoint_ref"] {
        let hostile = super::text_tests::replace_field(&canonical, key, Value::from(PROSE));
        assert_eq!(
            validate_diagnostic_event_body_bytes(&hostile)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidDiagnosticBody,
            "{key}"
        );
        let read = decode_diagnostic_event_body(&hostile)?;
        assert!(!format!("{read:?}").contains("sentinel"), "{key}");
    }
    Ok(())
}

/// CodeRabbit on #1421: an owner's vault keeps the DIAGNOSTIC rows it stored
/// before the owner ruling of 2026-10-14, with text wherever that grammar let
/// a writer put some, or an invariant map with no text in it at all. The
/// owner's scoped read and the reviewed-finding door read such a row at its
/// stored id with those values dropped, and the write door refuses its bytes.
#[test]
fn a_diagnostic_stored_before_the_ruling_reads_without_its_text() -> Result<()> {
    const TEXT: &str = "sentinel-world-text-0c5e: my sister's diagnosis";
    let (_dir, vault, owner, query) = consent_vault()?;
    let ids = vault.run_consent_denied_detector("scope.consent", query)?;
    let canonical = body(&vault, &ids[0])?;
    let stored = decode_diagnostic_event_body(&canonical)?;
    let with_text = vec![
        ("untrusted_detail", Value::from(TEXT)),
        ("expected", Value::from(TEXT)),
        (
            "delta",
            Value::Map(vec![(Value::from(TEXT), Value::from(1_u64))]),
        ),
        ("replay_run_ref", Value::from(TEXT)),
    ];
    let empty_map = vec![("expected", Value::Map(Vec::new()))];
    for fields in [with_text, empty_map] {
        let mut legacy = canonical.clone();
        for (key, value) in &fields {
            legacy = super::text_tests::replace_field(&legacy, key, value.clone());
        }
        let id = diagnostic_event_id(&stored.detector_id, &legacy);
        let occurred = TimeRange {
            start: stored.valid_from,
            end: u64::MAX,
        };
        let row = crate::test_support::entity_record(ENTITY_TYPE_DIAGNOSTIC, occurred, 1, &legacy);
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &row)?;
            let type_key = crate::store::Store::encode_type_key(ENTITY_TYPE_DIAGNOSTIC, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })?;

        let scoped = vault
            .scoped_read(crate::claim::ScopedReadActorKey::vault_owner(owner))
            .diagnostic_events()?
            .value
            .into_iter()
            .find_map(|(row, event)| (row == id).then_some(event))
            .expect("the stored row reads");
        let reviewed = vault.reviewed_diagnostic(&id)?;
        assert_eq!(scoped, reviewed);
        assert!(!format!("{reviewed:?}").contains("sentinel"));
        assert_eq!(reviewed.expected, Value::Nil);
        assert_eq!(reviewed.actual, stored.actual);
        assert_eq!(reviewed.evidence_refs, stored.evidence_refs);
        assert_eq!(reviewed.replay.content_hash, stored.replay.content_hash);
        assert_eq!(
            validate_diagnostic_event_admission(&id, occurred, &legacy)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidDiagnosticBody
        );
    }
    Ok(())
}

#[test]
fn detector_emits_typed_event() -> Result<()> {
    let (_dir, vault, _, query) = consent_vault()?;
    let receipts = vault.receipts(query.clone())?;
    assert_eq!(receipts.len(), 3);
    let facts = observations(&receipts)?;
    let ids = vault.run_consent_denied_detector("scope.consent", query.clone())?;
    assert_eq!(ids.len(), 2, "approvals are not refusals");
    for id in ids {
        let bytes = body(&vault, &id)?;
        validate_diagnostic_event_body_bytes(&bytes)?;
        let event = decode_diagnostic_event_body(&bytes)?;
        assert_eq!(event.detector_id, ConsentDeniedDetector.detector_id());
        assert_eq!(event.event_class, DiagnosticEventClass::ConsentDenied);
        assert_eq!(event.actor_class, "system");
        assert_eq!(event.actor_ref, None);
        assert_eq!(event.source, DiagnosticSourceKind::Receipt);
        assert_eq!(event.criticality, DiagnosticCriticality::Normal);
        assert_eq!(event.expected, Value::from(1_u64));
        assert_eq!(event.actual, Value::from(0_u64));
        assert_eq!(event.delta, Value::from(-1_i64));
        let fact = facts
            .iter()
            .find(|fact| event.evidence_refs == [fact.source_ref])
            .unwrap();
        assert_eq!(event.replay.content_hash, fact.payload_digest);
        assert_eq!(
            event.replay.run_ref.as_deref(),
            Some(fact.source_ref.to_hex().as_str())
        );
        assert_eq!(event.replay.checkpoint_ref, None);
        assert_eq!(event.valid_from, fact.observed_at);
        assert_eq!(event.valid_to, None);
    }
    assert!(
        vault
            .run_consent_denied_detector("scope.other_actor", query.clone().with_actor("absent"))?
            .is_empty()
    );
    assert!(
        vault
            .run_consent_denied_detector("scope.approved", query.with_outcome("approved"))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn no_repair_side_effect() -> Result<()> {
    let (_dir, vault, owner, query) = consent_vault()?;
    let receipts_before = vault.receipts(query.clone())?;
    let owner_before = vault.get_raw(&owner)?;
    let mut before = BTreeMap::new();
    for byte in 0..=u8::MAX {
        before.insert(byte, vault.entities_by_type(byte)?);
    }
    let ids = vault.run_consent_denied_detector("scope.consent", query.clone())?;
    assert_eq!(ids.len(), 2);
    assert_eq!(
        vault.receipts(query)?,
        receipts_before,
        "receipt ledger is read-only"
    );
    assert_eq!(vault.get_raw(&owner)?, owner_before);
    for (byte, entities) in before {
        let after = vault.entities_by_type(byte)?;
        if byte == ENTITY_TYPE_DIAGNOSTIC {
            assert_eq!(after.len(), entities.len() + ids.len());
        } else {
            assert_eq!(after, entities, "non-diagnostic entity set changed: {byte}");
        }
    }
    Ok(())
}
