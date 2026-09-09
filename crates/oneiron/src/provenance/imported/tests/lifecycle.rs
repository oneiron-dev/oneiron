//! Imported lifecycle regression through the private canonical writer.

use super::*;
use crate::provenance::writes::EdgeProvenanceWrite;
use crate::write_envelope::WriteActor;

#[test]
fn imported_owner_materialization_retracts_and_supersedes_without_actor_loss() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), crate::config::VaultConfig::default())?;
    let actor = WriteActor::new(entity(0x61), EdgeActorClass::Human);
    for id in [actor.entity_ref(), entity(0x62), entity(0x63)] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"",
        )?;
    }
    let permit = |actor: EntityId, sources: &[ClaimSource]| -> Result<()> {
        let mut manifest =
            rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice())
                .expect("manifest");
        let Value::Map(entries) = &mut manifest else {
            panic!("manifest map");
        };
        let (_, Value::Map(trust)) = entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("source_trust"))
            .expect("source trust")
        else {
            panic!("trust map");
        };
        for source in sources {
            trust.retain(|(key, _)| key.as_str() != Some(source.as_str()));
            trust.push((
                Value::from(source.as_str()),
                Value::Map(vec![
                    ("actor_ref".into(), actor.to_hex().into()),
                    (
                        "max_auto_sensitivity".into(),
                        u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND).into(),
                    ),
                    ("receipted".into(), true.into()),
                    ("warned".into(), true.into()),
                ]),
            ));
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encode");
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id()?,
            &bytes,
        )
    };
    permit(
        actor.entity_ref(),
        &[
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ],
    )?;
    let subject = EdgeRef::new(entity(0x62), EdgeKind::EmployedBy, entity(0x63));
    let first = entity(0x64);
    let second = entity(0x65);
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .edge(&subject.source, subject.kind, &subject.target, 0.8)
            .apply(wtxn)?;
        vault.write_edge_provenance_in_txn(
            wtxn,
            EdgeProvenanceWrite {
                claim_id: &first,
                subject: &subject,
                body: &EdgeProvenanceClaimBody::new(
                    actor.entity_ref(),
                    1.0,
                    SupersessionStatus::Proposed,
                ),
                actor_class: actor.actor_class(),
                learned_at: 10,
                explicit_prior: None,
                imported_evidence: Some(Value::from("external record")),
            },
        )
    })?;
    let admitted = vault.get_claim(&first)?.expect("admitted");
    assert_eq!(admitted.source, Some(ClaimSource::Imported));
    assert_eq!(admitted.lifecycle, ClaimLifecycleStatus::Active);
    let record = decode_edge_provenance_body(&admitted.value)?;
    assert_eq!(record.actor_entity_ref, actor.entity_ref());
    assert_eq!(record.actor_class, Some(actor.actor_class()));
    // The canonical replacement closes the Imported prior under its OWN actor.
    vault.supersede_edge_provenance(
        &first,
        &second,
        &subject,
        &EdgeProvenanceClaimBody::new(actor.entity_ref(), 1.0, SupersessionStatus::Confirmed),
        actor.actor_class(),
        20,
    )?;
    let closed = vault.get_claim(&first)?.expect("prior");
    assert_eq!(closed.source, Some(ClaimSource::Imported));
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    let record = decode_edge_provenance_body(&closed.value)?;
    assert_eq!(record.actor_entity_ref, actor.entity_ref());
    assert_eq!(record.actor_class, Some(actor.actor_class()));
    let third = entity(0x66);
    let other_subject = EdgeRef::new(entity(0x63), EdgeKind::EmployedBy, entity(0x62));
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .edge(
                &other_subject.source,
                other_subject.kind,
                &other_subject.target,
                0.8,
            )
            .apply(wtxn)?;
        vault.write_edge_provenance_in_txn(
            wtxn,
            EdgeProvenanceWrite {
                claim_id: &third,
                subject: &other_subject,
                body: &EdgeProvenanceClaimBody::new(
                    actor.entity_ref(),
                    1.0,
                    SupersessionStatus::Proposed,
                ),
                actor_class: actor.actor_class(),
                learned_at: 10,
                explicit_prior: None,
                imported_evidence: Some(Value::from("other record")),
            },
        )
    })?;
    permit(entity(0x63), &[ClaimSource::Imported])?;
    assert!(vault.retract_edge_provenance(&third, 30).is_err());
    assert_eq!(
        vault.get_claim(&third)?.expect("unchanged").lifecycle,
        ClaimLifecycleStatus::Active
    );
    permit(actor.entity_ref(), &[ClaimSource::Imported])?;
    vault.retract_edge_provenance(&third, 30)?;
    let closed = vault.get_claim(&third)?.expect("closed");
    assert_eq!(closed.source, Some(ClaimSource::Imported));
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(
        decode_edge_provenance_body(&closed.value)?.actor_entity_ref,
        actor.entity_ref()
    );
    Ok(())
}
