use super::*;
use crate::claim::{decode_claim_body, encode_claim_body};
use crate::provenance::{EdgeRef, SupersessionStatus, decode_edge_provenance_body};
use rmpv::Value;

// Test-only, actor-bound Imported permit. Production must bring its own policy.
pub(super) fn permit_imported(vault: &Vault, actor: EntityId) -> crate::Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest =
        rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)).expect("fixture manifest");
    let Value::Map(entries) = &mut manifest else {
        panic!("fixture")
    };
    let (_, Value::Map(trust)) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("source_trust"))
        .expect("fixture")
    else {
        panic!("fixture")
    };
    trust.push((
        Value::from("imported"),
        Value::Map(vec![
            (Value::from("actor_ref"), Value::from(actor.to_hex())),
            (
                Value::from("max_auto_sensitivity"),
                Value::from(u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND)),
            ),
            (Value::from("receipted"), Value::Boolean(true)),
            (Value::from("warned"), Value::Boolean(true)),
        ]),
    ));
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("fixture");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &data,
    )
}

pub(super) fn employment_claim_id() -> EntityId {
    derived_id(
        b"oneiron.linkedin.claim.v1",
        &[&key(true, 1).source_ref(), "linkedin.employed_by"],
    )
    .expect("fixture")
}

fn endpoints(vault: &Vault) -> crate::Result<(EntityId, EntityId)> {
    let person = resolve_linkedin_entity(vault, key(true, 1))
        .map_err(|e| match e {
            LinkedInResolutionError::Vault(e) => e,
            _ => Error::InvariantViolation("fixture"),
        })?
        .0;
    let company = resolve_linkedin_entity(vault, key(false, 1))
        .map_err(|e| match e {
            LinkedInResolutionError::Vault(e) => e,
            _ => Error::InvariantViolation("fixture"),
        })?
        .0;
    Ok((person, company))
}

#[test]
fn linkedin_employment_imported_actor_source_and_rerun_are_canonical() -> TestResult {
    let (_temp, vault, actor) = setup();
    let (person, company) = endpoints(&vault)?;
    assert_eq!(
        resolve_employment(&vault, person, company, &key(true, 1), actor)?,
        Disposition::Created
    );
    let claim_id = employment_claim_id();
    let claim = vault.get_claim(&claim_id)?.expect("fixture");
    assert_eq!(
        claim.predicate,
        crate::provenance::PREDICATE_EDGE_PROVENANCE
    );
    assert_eq!(
        claim.subject,
        ClaimSubject::from(EdgeRef::new(person, EdgeKind::EmployedBy, company))
    );
    assert_eq!(claim.source, Some(ClaimSource::Imported));
    let record = decode_edge_provenance_body(&claim.value)?;
    assert_eq!(record.actor_entity_ref, actor.entity_ref());
    assert_eq!(record.actor_class, Some(actor.actor_class()));
    assert_eq!(record.supersession_status, SupersessionStatus::Proposed);
    assert!(
        claim.evidence.is_none(),
        "canonical actor lives only in val"
    );
    let scope = claim.scope.expect("imported relationship scope");
    let evidence = field(&scope, "imported_evidence");
    assert_eq!(
        field(evidence, "source_id").as_str(),
        Some("linkedin-lead-corpus")
    );
    assert_eq!(
        field(evidence, "source_record_id").as_str(),
        Some(key(true, 1).source_ref().as_str())
    );
    assert!(vault.edge_exists(&claim_id, EdgeKind::ClaimOf, &person)?);
    let edge = vault
        .edges_out(&person)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::EmployedBy)
        .expect("fixture");
    let flags = edge.provenance.expect("canonical stamp");
    assert_eq!(flags.actor_class, actor.actor_class());
    assert_eq!(
        flags.confirmation_status,
        crate::edge::EdgeConfirmationStatus::Proposed
    );
    let before = snapshot(&vault);
    assert_eq!(
        resolve_employment(&vault, person, company, &key(true, 1), actor)?,
        Disposition::Reused
    );
    assert_eq!(snapshot(&vault), before);
    Ok(())
}

#[test]
fn linkedin_employment_missing_or_other_actor_permit_rolls_back_absent_edge() -> TestResult {
    for other_actor in [false, true] {
        let (_temp, vault, actor) = setup();
        let (person, company) = endpoints(&vault)?;
        if other_actor {
            permit_imported(&vault, EntityId::from_bytes([0x62; 16])?)?;
        } else {
            crate::test_util::put_policy_manifest_bytes(
                &vault,
                crate::gate::default_policy_manifest_id()?,
                &crate::gate::default_policy_manifest(),
            )?;
        }
        let before = snapshot(&vault);
        let error = resolve_employment(&vault, person, company, &key(true, 1), actor)
            .expect_err("Imported must not self-permit");
        assert!(
            matches!(
                error,
                LinkedInResolutionError::Vault(Error::GateWriteRejected { .. })
            ),
            "{error:?}"
        );
        assert_eq!(snapshot(&vault), before);
        assert!(!vault.edge_exists(&person, EdgeKind::EmployedBy, &company)?);
        assert!(!vault.edge_exists(&employment_claim_id(), EdgeKind::ClaimOf, &person)?);
        assert!(vault.get_raw(&employment_claim_id())?.is_none());
    }
    Ok(())
}

#[test]
fn linkedin_employment_wrong_actor_and_class_cannot_reuse_or_create() -> TestResult {
    for existing in [false, true] {
        let (_temp, vault, actor) = setup();
        let (person, company) = endpoints(&vault)?;
        let other = EntityId::from_bytes([0x63; 16])?;
        put_fixture_entity(&vault, &other, ENTITY_TYPE_PERSON, b"")?;
        if existing {
            resolve_employment(&vault, person, company, &key(true, 1), actor)?;
        }
        let before = snapshot(&vault);
        for wrong in [
            WriteActor::new(other, EdgeActorClass::Human),
            WriteActor::new(actor.entity_ref(), EdgeActorClass::System),
        ] {
            assert!(resolve_employment(&vault, person, company, &key(true, 1), wrong).is_err());
            assert_eq!(snapshot(&vault), before);
        }
    }
    Ok(())
}

#[test]
fn linkedin_employment_bare_edge_and_occupied_claim_fail_closed() -> TestResult {
    for bare in [false, true] {
        let (_temp, vault, actor) = setup();
        let (person, company) = endpoints(&vault)?;
        if bare {
            vault.put_edge(&person, EdgeKind::EmployedBy, &company, 0.4)?;
        } else {
            put_fixture_entity(
                &vault,
                &employment_claim_id(),
                ENTITY_TYPE_PERSON,
                b"synthetic-occupied",
            )?;
        }
        let before = snapshot(&vault);
        assert!(resolve_employment(&vault, person, company, &key(true, 1), actor).is_err());
        assert_eq!(snapshot(&vault), before);
        if !bare {
            assert!(!vault.edge_exists(&person, EdgeKind::EmployedBy, &company)?);
        }
    }
    Ok(())
}

#[test]
fn linkedin_employment_stored_source_identity_mismatch_is_not_laundered() -> TestResult {
    for change in [
        "source",
        "actor",
        "source_id",
        "source_record_id",
        "subject",
        "duplicate",
    ] {
        let (_temp, vault, actor) = setup();
        let (person, company) = endpoints(&vault)?;
        resolve_employment(&vault, person, company, &key(true, 1), actor)?;
        let claim_id = employment_claim_id();
        // Deliberate on-disk fixture corruption: the production reserved door
        // cannot mutate write-once provenance identity in place.
        vault.with_write_txn(|txn| {
            let raw = vault
                .store
                .entities
                .get(txn, claim_id.as_bytes())?
                .expect("fixture")
                .to_vec();
            let mut body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            match change {
                "source" => body.source = Some(ClaimSource::UserStated),
                "subject" => {
                    body.subject = ClaimSubject::from(EdgeRef::new(
                        person,
                        EdgeKind::EmployedBy,
                        actor.entity_ref(),
                    ))
                }
                "actor" => {
                    let Value::Map(fields) = &mut body.value else {
                        panic!("fixture")
                    };
                    fields
                        .iter_mut()
                        .find(|(k, _)| k.as_str() == Some("actor_entity_ref"))
                        .expect("fixture")
                        .1 = Value::Binary(person.as_bytes().to_vec());
                }
                _ => {
                    let Value::Map(scope) = body.scope.as_mut().expect("fixture") else {
                        panic!("fixture")
                    };
                    let (_, Value::Map(fields)) = scope
                        .iter_mut()
                        .find(|(key, _)| key.as_str() == Some("imported_evidence"))
                        .expect("fixture")
                    else {
                        panic!("fixture")
                    };
                    if change == "duplicate" {
                        fields.push(fields[0].clone());
                    } else {
                        fields
                            .iter_mut()
                            .find(|(k, _)| k.as_str() == Some(change))
                            .expect("fixture")
                            .1 = Value::from("synthetic-other");
                    }
                }
            }
            let mut changed = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            changed.extend(encode_claim_body(&body)?);
            vault
                .store
                .entities
                .put(txn, claim_id.as_bytes(), &changed)?;
            Ok(())
        })?;
        let before = snapshot(&vault);
        assert!(
            resolve_employment(&vault, person, company, &key(true, 1), actor).is_err(),
            "{change}"
        );
        assert_eq!(snapshot(&vault), before);
    }
    Ok(())
}

#[test]
fn linkedin_employment_revoked_import_permit_blocks_rerun_without_mutation() -> TestResult {
    let (_temp, vault, actor) = setup();
    let (person, company) = endpoints(&vault)?;
    resolve_employment(&vault, person, company, &key(true, 1), actor)?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest(),
    )?;
    let before = snapshot(&vault);
    assert!(matches!(
        resolve_employment(&vault, person, company, &key(true, 1), actor),
        Err(LinkedInResolutionError::Vault(
            Error::GateWriteRejected { .. }
        ))
    ));
    assert_eq!(snapshot(&vault), before);
    Ok(())
}
