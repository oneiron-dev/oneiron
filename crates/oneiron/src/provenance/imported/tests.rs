use super::*;
use crate::claim::validate_claim_body_and_decode;
use crate::test_util::entity;

fn imported_claim() -> StoredProvenanceClaim {
    let actor_class = EdgeActorClass::Human;
    let subject = EdgeRef::new(entity(0x61), EdgeKind::EmployedBy, entity(0x62));
    let mut record = EdgeProvenanceClaimBody::new(entity(0x63), 1.0, SupersessionStatus::Proposed);
    record.actor_class = Some(actor_class);
    let mut wrapper = ClaimBody::new(
        PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::from(subject),
        encode_edge_provenance_value(&record),
        record.confidence,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    stamp_imported_source(
        &mut wrapper,
        Value::Map(vec![
            (Value::from("source_id"), Value::from("external-corpus")),
            (Value::from("source_record_id"), Value::from("record-1")),
        ]),
    );
    StoredProvenanceClaim {
        id: entity(0x64),
        occurred_start: 100,
        learned_at: 100,
        subject,
        wrapper,
        record,
        actor_class,
    }
}

#[test]
fn imported_canonical_serialization_keeps_one_actor_class_source() -> Result<()> {
    let claim = imported_claim();
    let data = encode_claim_body(&claim.wrapper)?;
    let decoded = validate_claim_body_and_decode(&data, true)?;
    let record = decode_edge_provenance_body(&decoded.value)?;
    assert_eq!(decoded.source, Some(ClaimSource::Imported));
    assert!(decoded.evidence.is_none());
    assert_eq!(decoded.scope, claim.wrapper.scope);
    assert_eq!(record.actor_entity_ref, claim.record.actor_entity_ref);
    assert_eq!(record.actor_class, Some(claim.actor_class));
    assert_eq!(
        resolve_persisted_actor_class(&record, decoded.evidence.as_ref())?,
        claim.actor_class
    );
    assert_eq!(encode_claim_body(&decoded)?, data);
    Ok(())
}

#[test]
fn imported_closing_serialization_preserves_source_scope_and_actor() -> Result<()> {
    let claim = imported_claim();
    for (record, lifecycle) in [
        (
            retract_record(&claim.record, 200)?,
            ClaimLifecycleStatus::Retracted,
        ),
        (
            close_record_for_supersession(&claim.record, 200)?,
            ClaimLifecycleStatus::Superseded,
        ),
    ] {
        let (occurred, learned_at, _, data) = closed_claim_put_payload(&claim, &record, lifecycle)?;
        let decoded = validate_claim_body_and_decode(&data, true)?;
        let closed_record = decode_edge_provenance_body(&decoded.value)?;
        assert_eq!(occurred.start, 100);
        assert_eq!(occurred.end, 200);
        assert_eq!(learned_at, 100);
        assert_eq!(decoded.lifecycle, lifecycle);
        assert_eq!(decoded.valid_to, Some(200));
        assert_eq!(decoded.source, claim.wrapper.source);
        assert_eq!(decoded.scope, claim.wrapper.scope);
        assert!(decoded.evidence.is_none());
        assert_eq!(
            closed_record.actor_entity_ref,
            claim.record.actor_entity_ref
        );
        assert_eq!(
            resolve_persisted_actor_class(&closed_record, decoded.evidence.as_ref())?,
            claim.actor_class
        );
    }
    Ok(())
}

#[test]
fn imported_serialization_does_not_relax_ambiguous_actor_rejection() -> Result<()> {
    let claim = imported_claim();
    for evidence in [
        encode_actor_class_evidence(claim.actor_class),
        encode_actor_class_evidence(EdgeActorClass::Agent),
        Value::Map(vec![(
            Value::from("source_id"),
            Value::from("external-corpus"),
        )]),
    ] {
        let mut ambiguous = claim.wrapper.clone();
        ambiguous.evidence = Some(evidence);
        assert!(matches!(
            validate_claim_body_and_decode(&encode_claim_body(&ambiguous)?, true),
            Err(Error::InvalidProvenanceBody(_))
        ));
    }
    let mut missing = claim.wrapper;
    let mut record = claim.record;
    record.actor_class = None;
    missing.value = encode_edge_provenance_value(&record);
    assert!(matches!(
        validate_claim_body_and_decode(&encode_claim_body(&missing)?, true),
        Err(Error::InvalidProvenanceBody(_))
    ));
    Ok(())
}

#[test]
fn imported_scope_cannot_supply_or_override_canonical_actor() -> Result<()> {
    let mut claim = imported_claim();
    stamp_imported_source(
        &mut claim.wrapper,
        Value::Map(vec![
            (
                Value::from("actor_entity_ref"),
                Value::Binary(entity(0x65).as_bytes().to_vec()),
            ),
            (
                Value::from("actor_class"),
                Value::from(EdgeActorClass::System as u8),
            ),
        ]),
    );
    let decoded = validate_claim_body_and_decode(&encode_claim_body(&claim.wrapper)?, true)?;
    let record = decode_edge_provenance_body(&decoded.value)?;
    assert_eq!(record.actor_entity_ref, claim.record.actor_entity_ref);
    assert_eq!(
        resolve_persisted_actor_class(&record, decoded.evidence.as_ref())?,
        EdgeActorClass::Human
    );
    claim.record.actor_class = None;
    claim.wrapper.value = encode_edge_provenance_value(&claim.record);
    assert!(matches!(
        validate_claim_body_and_decode(&encode_claim_body(&claim.wrapper)?, true),
        Err(Error::InvalidProvenanceBody(_))
    ));
    Ok(())
}

#[test]
fn imported_owner_payload_rejects_wrong_actor_source_or_envelope() -> Result<()> {
    let claim = imported_claim();
    for changed in 0..3 {
        let mut payload = ProvenanceMaterialization::new(
            claim.id,
            TimeRange {
                start: 100,
                end: u64::MAX,
            },
            100,
            encode_claim_body(&claim.wrapper)?,
            None,
        )?;
        payload.envelope = crate::WriteEnvelope::new(
            WriteActor::new(
                if changed == 0 {
                    entity(0x65)
                } else {
                    claim.record.actor_entity_ref
                },
                claim.actor_class,
            ),
            if changed == 1 {
                ClaimSource::Observed
            } else {
                ClaimSource::Imported
            },
            crate::WriteProvenance::new(if changed == 2 {
                Value::from("wrong provenance")
            } else {
                claim.wrapper.value.clone()
            })?,
            ClaimApprovalStatus::Auto,
        );
        assert!(crate::batch::ClaimMaterialization::provenance(payload).is_err());
    }
    Ok(())
}
