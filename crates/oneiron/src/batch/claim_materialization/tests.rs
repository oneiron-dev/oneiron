mod freshness;
mod lifecycle_actor_regressions;

use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::temporal::TimeRange;
use crate::test_util::entity;
use crate::write_envelope::ClaimCandidate;

fn fixture() -> Result<(tempfile::TempDir, Vault, WriteActor)> {
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
    permit(
        &vault,
        actor.entity_ref(),
        &[
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ],
    )?;
    Ok((dir, vault, actor))
}

fn permit(vault: &Vault, actor: EntityId, sources: &[ClaimSource]) -> Result<()> {
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
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn candidate(vault: &Vault, actor: WriteActor, id: EntityId) -> Result<()> {
    let envelope = WriteEnvelope::with_lineage(
        actor,
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("host operation"))?,
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::ToolOutput).with(ClaimSource::Generated),
    );
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "test.materialization",
                ClaimSubject::Entity(entity(0x62)),
                Value::from("fact"),
                1.0,
            ),
            &envelope,
            TimeRange {
                start: 10,
                end: u64::MAX,
            },
            10,
        )
        .commit()
}

#[test]
fn owner_materialization_preserves_auto_actor_and_complete_lineage_through_lifecycle() -> Result<()>
{
    let (_dir, vault, actor) = fixture()?;
    let old = entity(0x64);
    let new = entity(0x65);
    candidate(&vault, actor, old)?;
    candidate(&vault, actor, new)?;
    let before = vault.get_claim(&old)?.expect("claim");
    vault.supersede_claim(&new, &old, 20)?;
    let closed = vault.get_claim(&old)?.expect("closed");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(closed.evidence, before.evidence);
    assert_eq!(closed.source, Some(ClaimSource::ToolOutput));
    assert_eq!(closed.approval, ClaimApprovalStatus::Auto);
    // A permit for the declared source cannot cover a revoked lineage member.
    permit(&vault, actor.entity_ref(), &[ClaimSource::ToolOutput])?;
    let before = vault.get_claim(&new)?.expect("new");
    assert!(vault.retract_claim(&new, 30).is_err());
    assert_eq!(vault.get_claim(&new)?.expect("unchanged"), before);
    permit(
        &vault,
        actor.entity_ref(),
        &[ClaimSource::ToolOutput, ClaimSource::Generated],
    )?;
    vault.retract_claim(&new, 30)?;
    assert_eq!(
        vault.get_claim(&new)?.expect("closed").evidence,
        before.evidence
    );
    Ok(())
}

#[test]
fn owner_materialization_rejects_actor_source_and_operation_rebinding() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    candidate(&vault, actor, id)?;
    let mut body = vault.get_claim(&id)?.expect("claim");
    let txn = vault.store.env.read_txn()?;
    assert!(lifecycle_envelope(&vault.store, &txn, &entity(0x65), &body)?.is_none());
    let original = body.clone();
    body.source = Some(ClaimSource::Observed);
    assert!(lifecycle_envelope(&vault.store, &txn, &id, &body).is_err());
    body = original.clone();
    let Some(Value::Map(entries)) = &mut body.evidence else {
        panic!("stamp");
    };
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("actor_entity_ref"))
        .expect("actor")
        .1 = Value::Binary(entity(0x63).as_bytes().to_vec());
    assert!(lifecycle_envelope(&vault.store, &txn, &id, &body).is_err());
    body = original;
    body.lifecycle = ClaimLifecycleStatus::Retracted;
    body.valid_to = Some(20);
    let op = BatchOp::Put {
        id,
        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
        occurred: TimeRange { start: 10, end: 20 },
        learned_at: 10,
        data: encode_claim_body(&body)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    };
    let binding = ClaimMaterialization::lifecycle(&vault.store, &txn, &op)?.expect("bound");
    assert!(binding.matches_op(&op));
    for changed in 0..4 {
        let mut wrong = op.clone();
        let BatchOp::Put {
            id,
            occurred,
            learned_at,
            data,
            ..
        } = &mut wrong
        else {
            unreachable!()
        };
        match changed {
            0 => *id = entity(0x65),
            1 => occurred.end += 1,
            2 => *learned_at += 1,
            _ => data.push(0),
        }
        assert!(!binding.matches_op(&wrong));
        assert!(ClaimMaterialization::lifecycle(&vault.store, &txn, &wrong).is_err());
    }
    Ok(())
}

#[test]
fn imported_owner_materialization_retracts_and_supersedes_without_actor_loss() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let subject = crate::provenance::EdgeRef::new(entity(0x62), EdgeKind::EmployedBy, entity(0x63));
    let first = entity(0x64);
    let second = entity(0x65);
    assert!(
        vault.resolve_imported_edge_provenance(crate::provenance::ImportedEdgeProvenance {
            claim_id: first,
            subject,
            actor,
            evidence: Value::from("external record"),
            weight: 0.8,
            learned_at: 10,
        })?
    );
    // The canonical replacement closes the Imported prior under its OWN actor.
    vault.supersede_edge_provenance(
        &first,
        &second,
        &subject,
        &crate::provenance::EdgeProvenanceClaimBody::new(
            actor.entity_ref(),
            1.0,
            crate::provenance::SupersessionStatus::Confirmed,
        ),
        actor.actor_class(),
        20,
    )?;
    let closed = vault.get_claim(&first)?.expect("prior");
    assert_eq!(closed.source, Some(ClaimSource::Imported));
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    let record = crate::provenance::decode_edge_provenance_body(&closed.value)?;
    assert_eq!(record.actor_entity_ref, actor.entity_ref());
    assert_eq!(record.actor_class, Some(actor.actor_class()));
    let third = entity(0x66);
    let other_subject =
        crate::provenance::EdgeRef::new(entity(0x63), EdgeKind::EmployedBy, entity(0x62));
    vault.resolve_imported_edge_provenance(crate::provenance::ImportedEdgeProvenance {
        claim_id: third,
        subject: other_subject,
        actor,
        evidence: Value::from("other record"),
        weight: 0.8,
        learned_at: 10,
    })?;
    permit(&vault, entity(0x63), &[ClaimSource::Imported])?;
    assert!(vault.retract_edge_provenance(&third, 30).is_err());
    assert_eq!(
        vault.get_claim(&third)?.expect("unchanged").lifecycle,
        ClaimLifecycleStatus::Active
    );
    permit(&vault, actor.entity_ref(), &[ClaimSource::Imported])?;
    vault.retract_edge_provenance(&third, 30)?;
    let closed = vault.get_claim(&third)?.expect("closed");
    assert_eq!(closed.source, Some(ClaimSource::Imported));
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(
        crate::provenance::decode_edge_provenance_body(&closed.value)?.actor_entity_ref,
        actor.entity_ref()
    );
    Ok(())
}
