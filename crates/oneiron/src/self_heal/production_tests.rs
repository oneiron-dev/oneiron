use super::*;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::consent::{ComposedEffect, EffectFacts};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;
use crate::test_util::open_test_vault_with;

fn consent_vault() -> Result<(tempfile::TempDir, Vault, EntityId, ReceiptQuery)> {
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    let owner_id = EntityId::from_bytes([0x51; 16])?;
    vault.put_entity(
        &owner_id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
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
        assert_eq!(event.replay.run_ref.as_deref(), Some("scope.consent"));
        assert_eq!(event.replay.checkpoint_ref, None);
        assert_eq!(event.valid_from, fact.observed_at);
        assert_eq!(event.valid_to, None);
        assert_eq!(event.untrusted_detail, None);
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
fn deterministic_detection() -> Result<()> {
    let (_dir, vault, _, query) = consent_vault()?;
    let facts = observations(&vault.receipts(query.clone())?)?;
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.consent",
        observations: &facts,
    };
    let (_other_dir, other) = open_test_vault_with(VaultConfig::default());
    let first = vault.run_consent_denied_detector(input.scope_ref, query)?;
    let detector = ConsentDeniedDetector;
    let second = run_deterministic_detectors(&other, &input, &[&detector, &detector])?;
    assert_eq!(
        first, second,
        "same real observations, ordering and deduplication"
    );
    assert_eq!(first.len(), 2);
    assert!(first.windows(2).all(|pair| pair[0] < pair[1]));
    for id in first {
        let bytes = body(&vault, &id)?;
        assert_eq!(bytes, body(&other, &id)?);
        assert_eq!(id, diagnostic_event_id(detector.detector_id(), &bytes));
        assert_ne!(id, diagnostic_event_id("another.detector", &bytes));
    }
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

#[test]
fn consent_detector_requires_explicit_scoped_receipt_fact() -> Result<()> {
    let (_dir, vault, _, query) = consent_vault()?;
    let receipt = vault
        .receipts(query.clone())?
        .into_iter()
        .find(|receipt| receipt.outcome == "denied")
        .expect("production denial receipt");
    let observation = DiagnosticObservation::from_consent_receipt(&receipt)?.unwrap();
    assert_eq!(
        observation.payload_digest,
        *blake3::hash(&rmp_serde::to_vec_named(&receipt).unwrap()).as_bytes()
    );
    for field in ["kind", "outcome", "content_kind", "reason"] {
        let mut unrelated = receipt.clone();
        match field {
            "kind" => unrelated.receipt_kind = ReceiptKind::ScopedRead,
            "outcome" => unrelated.outcome = "approved".to_owned(),
            "content_kind" => {
                unrelated
                    .fields
                    .insert("content_kind".to_owned(), "claim".to_owned());
            }
            "reason" => unrelated.policy_trace.clear(),
            _ => unreachable!(),
        }
        assert!(DiagnosticObservation::from_consent_receipt(&unrelated)?.is_none());
    }
    let mut malformed = receipt;
    malformed.receipt_id = "gate:not_an_id".to_owned();
    assert!(DiagnosticObservation::from_consent_receipt(&malformed).is_err());
    for limit in [0, MAX_EVENTS_PER_RUN + 1] {
        assert!(
            vault
                .run_consent_denied_detector("scope.consent", ReceiptQuery::new(limit))
                .is_err()
        );
    }
    let future = query.with_time_bounds(Some(u64::MAX), None);
    assert!(
        vault
            .run_consent_denied_detector("scope.future", future)?
            .is_empty()
    );
    assert!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.is_empty());
    Ok(())
}
