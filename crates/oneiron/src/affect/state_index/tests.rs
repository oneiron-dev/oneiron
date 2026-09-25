use super::*;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::{VadAnnotation, VadAnnotationSource, VaultConfig};

#[test]
fn composite_is_provenanced_idempotent_and_neutral_when_unknown() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = VaultConfig {
        map_size: 64 * 1024 * 1024,
        ..VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config.clone()).expect("open source state-index fixture");
    let subject = EntityId::now();
    let time = TimeRange { start: 10, end: 10 };
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, time, 10, b"subject")?;
    let turn = EntityId::now();
    vault.put_entity(&turn, ENTITY_TYPE_TURN, time, 10, b"turn")?;
    vault.annotate_turn_vad(
        &turn,
        VadAnnotation::new(
            Vad {
                valence: 0.5,
                arousal: 0.6,
                dominance: 0.9,
            },
            VadAnnotationSource::UserSelfReport,
            10,
        )?,
    )?;
    let signal = |predicate, value| -> Result<EntityId> {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::F32(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        vault.put_claim(&id, &body, time, 10)?;
        Ok(id)
    };
    let evidence = StateIndexEvidence {
        vad_turns: vec![turn],
        goal_velocity: signal(GOAL_VELOCITY, 0.7)?,
        engagement: signal(ENGAGEMENT, 0.8)?,
    };
    // Raw/replay peers can assert ordinary claims, not producer-bound derived
    // heads. In particular a forged future row must not veto local derivation.
    let mut forged = ClaimBody::new(
        COMPOSITE_INDEX,
        ClaimSubject::Entity(subject),
        Value::Map(
            ["value", "affect", "goal_velocity", "engagement"]
                .into_iter()
                .map(|key| (Value::from(key), Value::F32(1.0)))
                .collect(),
        ),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    forged.source = Some(ClaimSource::Observed);
    forged.valid_from = Some(1000);
    vault.put_claim(
        &EntityId::now(),
        &forged,
        TimeRange {
            start: 1000,
            end: 1000,
        },
        10,
    )?;
    forged.valid_from = Some(5);
    let forged_bytes = crate::claim::encode_claim_body(&forged)?;
    vault
        .batch()
        .put_replicated(
            &EntityId::now(),
            crate::registry::ENTITY_TYPE_CLAIM,
            time,
            10,
            &forged_bytes,
        )
        .commit()?;
    assert_eq!(vault.state_index_at(&subject, 1000)?, StateIndex::default());
    let id = vault.derive_state_index(&subject, &evidence, 11)?;
    assert_eq!(vault.derive_state_index(&subject, &evidence, 12)?, id);
    let index = vault
        .memory(subject, crate::EdgeActorClass::Human)
        .state_index(&subject.to_hex())
        .expect("agent read");
    assert_eq!(index.claim, Some(id.to_hex()));
    assert!((index.value - 0.75).abs() < 0.0001);
    assert_eq!(index.inputs.unwrap().engagement, 0.8);
    let stored = vault.get_claim(&id)?.unwrap();
    assert_eq!(stored.predicate, COMPOSITE_INDEX);
    let Value::Map(fields) = stored.value else {
        panic!("numeric map")
    };
    assert_eq!(
        fields
            .iter()
            .map(|(key, _)| key.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["value", "affect", "goal_velocity", "engagement"]
    );
    assert_eq!(vault.state_index(&EntityId::now())?, StateIndex::default());
    // Reference strings survive credential nulling without a generic binary exemption.
    let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    let target_dir = tempfile::tempdir()?;
    let target =
        Vault::open(target_dir.path(), config.clone()).expect("open restore state-index fixture");
    target.import_whole_vault_json(export.bytes())?;
    let restored = target.get_claim(&id)?.unwrap();
    assert_eq!(
        restored.evidence,
        Some(Value::Array(
            vec![turn, evidence.goal_velocity, evidence.engagement]
                .into_iter()
                .map(|id| Value::from(id.to_hex()))
                .collect()
        ))
    );
    assert_eq!(restored.source, Some(ClaimSource::Imported));
    assert_eq!(restored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(target.state_index(&subject)?, StateIndex::default());

    let changed = StateIndexEvidence {
        vad_turns: evidence.vad_turns.clone(),
        goal_velocity: signal(GOAL_VELOCITY, 0.4)?,
        engagement: evidence.engagement,
    };
    let newer = vault.derive_state_index(&subject, &changed, 15)?;
    assert_ne!(newer, id);
    assert_eq!(
        vault.get_claim(&id)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(vault.state_index(&subject)?.claim, Some(newer.to_hex()));
    assert_eq!(vault.state_index_at(&subject, 14)?, StateIndex::default());
    assert!(vault.derive_state_index(&subject, &evidence, 14).is_err());
    let mut replaced = vault.get_claim(&newer)?.unwrap();
    replaced.value = forged.value;
    vault.put_claim(&newer, &replaced, TimeRange { start: 15, end: 15 }, 15)?;
    assert_eq!(vault.state_index_at(&subject, 16)?, StateIndex::default());
    let repaired = vault.derive_state_index(&subject, &changed, 16)?;
    assert_ne!(repaired, newer);
    assert_eq!(
        vault
            .state_index_at(&subject, 16)?
            .inputs
            .unwrap()
            .goal_velocity,
        0.4
    );
    let unknown = EntityId::now();
    assert_eq!(
        vault
            .memory(subject, crate::EdgeActorClass::Human)
            .state_index(&unknown.to_hex())
            .expect("unknown read"),
        StateIndex::default()
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), config).expect("reopen state-index fixture");
    assert_eq!(
        reopened.state_index_at(&subject, 16)?.claim,
        Some(repaired.to_hex())
    );
    Ok(())
}
