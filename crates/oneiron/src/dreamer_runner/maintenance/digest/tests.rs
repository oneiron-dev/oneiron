use super::*;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{ClaimBody, ClaimCandidate, ClaimSubject, TimeRange, WriteEnvelope, WriteProvenance};
use rmpv::Value;
fn propose(vault: &Vault, id: u8) -> Result<EntityId> {
    let actor = vault.dreamer_authority()?;
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("dreamer"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    let id = entity(id);
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "dreamer.proactivity.follow_up",
                ClaimSubject::Entity(actor.entity_ref()),
                Value::from("pending action"),
                0.7,
            ),
            &envelope,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .commit()?;
    Ok(id)
}
#[test]
fn three_proposals_one_digest_urgent_breakthrough_and_row_timing() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x12);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let row = ProactivityCadence {
        period_secs: 100,
        group_by_facet: true,
        urgent_breakthrough: true,
    };
    vault.set_proactivity_cadence(&owner, &row)?;
    for id in [0x21, 0x22, 0x23] {
        propose(&vault, id)?;
    }
    let digest = vault.proactivity_digest(&owner, 100, None)?.unwrap();
    assert_eq!(digest.groups.values().map(Vec::len).sum::<usize>(), 3);
    assert!(!digest.urgent);
    assert_eq!(vault.read_proactivity_digest(digest.id)?, Some(digest));
    propose(&vault, 0x24)?;
    assert!(vault.proactivity_digest(&owner, 101, None)?.is_none());
    let intent_id = entity(0x31);
    let mut intent = ClaimBody::new(
        "profile.intent",
        ClaimSubject::Entity(owner_id),
        Value::from("time-sensitive follow-up"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    intent.source = Some(ClaimSource::UserStated);
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let urgent = UrgentDigestWake {
        intent_ref: intent_id,
        needed_before: 150,
        waiting_harms_intent: true,
    };
    for change in 0..4 {
        let mut unrelated = intent.clone();
        match change {
            0 => unrelated.predicate = "profile.hobby".into(),
            1 => unrelated.subject = ClaimSubject::Entity(entity(0x32)),
            2 => unrelated.source = Some(ClaimSource::Generated),
            _ => unrelated.value = Value::Nil,
        }
        vault.put_claim(&intent_id, &unrelated, TimeRange { start: 1, end: 1 }, 1)?;
        assert!(
            vault
                .proactivity_digest(&owner, 102, Some(&urgent))?
                .is_none()
        );
    }
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let breakthrough = vault
        .proactivity_digest(&owner, 102, Some(&urgent))?
        .unwrap();
    assert!(breakthrough.urgent);
    assert_eq!(breakthrough.groups.values().map(Vec::len).sum::<usize>(), 1);
    propose(&vault, 0x25)?;
    assert!(vault.proactivity_digest(&owner, 107, None)?.is_none());
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 5,
            ..row
        },
    )?;
    let retimed = vault.proactivity_digest(&owner, 107, None)?.unwrap();
    assert!(!retimed.urgent);
    assert_eq!(retimed.groups.values().map(Vec::len).sum::<usize>(), 1);
    Ok(())
}
