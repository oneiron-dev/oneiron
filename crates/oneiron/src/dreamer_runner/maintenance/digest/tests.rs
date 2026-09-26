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
    let presentation = ProactivityPresentation {
        group_aliases: BTreeMap::from([("dreamer.proactivity".into(), "Forward".into())]),
        group_template: "{group}:\n".into(),
        item_template: "* {summary} ({ref})\n".into(),
        voice_style: "quiet".into(),
        urgent_groups: vec!["dreamer.proactivity".into()],
    };
    vault.set_proactivity_presentation(&owner, &presentation)?;
    assert_eq!(vault.next_proactivity_digest_at()?, None);
    for id in [0x21, 0x22, 0x23] {
        propose(&vault, id)?;
    }
    assert_eq!(vault.next_proactivity_digest_at()?, Some(0));
    let digest = vault.proactivity_digest(&owner, 100, None)?.unwrap();
    assert_eq!(digest.voice_style, "quiet");
    assert!(
        digest
            .rendered
            .starts_with("Forward:\n* dreamer.proactivity.follow_up:")
    );
    assert_eq!(digest.groups.len(), 1);
    assert_eq!(digest.groups.values().map(Vec::len).sum::<usize>(), 3);
    assert!(!digest.urgent);
    assert_eq!(
        vault.read_proactivity_digest(digest.id)?,
        Some(digest.clone())
    );
    assert_eq!(vault.latest_proactivity_digest()?, Some(digest));
    propose(&vault, 0x24)?;
    assert_eq!(vault.next_proactivity_digest_at()?, Some(200));
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
    vault.put_entity(
        &entity(0x32),
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"other owner",
    )?;
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
    assert_eq!(vault.next_proactivity_digest_at()?, Some(202));
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 5,
            ..row
        },
    )?;
    assert_eq!(vault.next_proactivity_digest_at()?, Some(107));
    let retimed = vault.proactivity_digest(&owner, 107, None)?.unwrap();
    assert!(!retimed.urgent);
    assert_eq!(retimed.groups.values().map(Vec::len).sum::<usize>(), 1);
    Ok(())
}

#[test]
fn policy_row_rejects_invalid_templates_and_disables_unpicked_breakthrough() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x51);
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
    let mut row = ProactivityPresentation {
        group_aliases: BTreeMap::new(),
        group_template: "{group}\n".into(),
        item_template: "{summary} [{ref}]\n".into(),
        voice_style: "neutral".into(),
        urgent_groups: vec![],
    };
    row.item_template = "no reference".into();
    assert!(vault.set_proactivity_presentation(&owner, &row).is_err());
    row.item_template = "{summary} [{ref}]\n".into();
    vault.set_proactivity_presentation(&owner, &row)?;
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 100,
            group_by_facet: true,
            urgent_breakthrough: true,
        },
    )?;
    propose(&vault, 0x52)?;
    vault.proactivity_digest(&owner, 100, None)?.unwrap();
    propose(&vault, 0x53)?;
    let intent_id = entity(0x54);
    let mut intent = ClaimBody::new(
        "profile.intent",
        ClaimSubject::Entity(owner_id),
        Value::from("urgent"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    intent.source = Some(ClaimSource::UserStated);
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let wake = UrgentDigestWake {
        intent_ref: intent_id,
        needed_before: 150,
        waiting_harms_intent: true,
    };
    assert!(
        vault
            .proactivity_digest(&owner, 101, Some(&wake))?
            .is_none()
    );
    assert_eq!(vault.next_proactivity_digest_at()?, Some(200));
    Ok(())
}
