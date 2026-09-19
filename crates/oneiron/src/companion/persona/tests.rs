use super::*;
use crate::authority::HostSlipIssuer;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ScopedReadActorKey};
use serde_json::json;

// These tests replay already-reviewed changes, not their approval ceremony.
// The replay fixture door retains strict CLAIM/Scope validation; the gate suite
// separately proves that a direct unconfirmed write cannot mark itself approved.
fn replay_change(vault: &Vault, id: &EntityId, body: &ClaimBody, at: u64) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            id,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: at, end: at },
            at,
            &crate::claim::encode_claim_body(body)?,
        )
        .commit()
}

fn change(
    vault: &Vault,
    person: EntityId,
    patch: JsonValue,
    at: u64,
    lifecycle: ClaimLifecycleStatus,
) -> Result<EntityId> {
    let id = EntityId::now();
    let change = PersonaChange {
        patch,
        made_by: PersonaMadeBy {
            inputs: vec![person],
            process: "test.change".to_owned(),
            at,
        },
    };
    let body = ClaimBody::new(
        PERSONA_CHANGE_PREDICATE,
        ClaimSubject::Entity(person),
        change.to_claim_value()?,
        1.0,
        ClaimApprovalStatus::Approved,
        lifecycle,
    );
    replay_change(vault, &id, &body, at)?;
    Ok(id)
}

#[test]
fn persona_rebase_replays_changes_on_person_without_minting_masks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = crate::VaultConfig::default();
    let vault = Vault::open(dir.path(), config.clone())?;
    let issuer = HostSlipIssuer::from_secret(b"persona rebase fixture")?;
    let proof = vault.verified_host_root_slip(&issuer)?;
    let key = ScopedReadActorKey::from_verified_slip(&proof).unwrap();
    let person = EntityId::now();
    let raw = rmp_serde::to_vec_named(&json!({"label":"fixture"})).unwrap();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &raw,
    )?;
    let masks = vault.count_entities_by_type(ENTITY_TYPE_FACET)?;
    vault.put_persona_baseline(
        &person,
        &json!({"tone":"neutral","prefs":{"length":"long","old":true}}),
        10,
    )?;
    // Arrival order differs from recorded derivation order.
    let second = change(
        &vault,
        person,
        json!({"tone":"calm","prefs":{"old":null}}),
        30,
        ClaimLifecycleStatus::Active,
    )?;
    let first = change(
        &vault,
        person,
        json!({"tone":"brief","prefs":{"length":"short"}}),
        20,
        ClaimLifecycleStatus::Active,
    )?;
    let retired = change(
        &vault,
        person,
        json!({"tone":"retired"}),
        99,
        ClaimLifecycleStatus::Retracted,
    )?;
    let mut pending = vault.get_claim(&second)?.unwrap();
    pending.approval = ClaimApprovalStatus::Proposed;
    pending.value = PersonaChange {
        patch: json!({"tone":"not yet approved"}),
        made_by: PersonaMadeBy {
            inputs: vec![person],
            process: "test.pending".to_owned(),
            at: 40,
        },
    }
    .to_claim_value()?;
    replay_change(&vault, &EntityId::now(), &pending, 40)?;
    let read = vault.scoped_read(key.clone());
    let compiled = read.compile_persona(&person, None)?;
    assert_eq!(
        compiled.value,
        json!({"tone":"calm","prefs":{"length":"short"}})
    );
    assert_eq!(compiled.made_by.inputs, vec![person, first, second]);
    assert!(!compiled.made_by.inputs.contains(&retired));
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_FACET)?, masks);
    let change_bytes = vault.get(&first)?;
    vault.put_persona_baseline(
        &person,
        &json!({"tone":"new base","prefs":{"length":"medium","new":true,"old":false}}),
        100,
    )?;
    let rebased = read.compile_persona(&person, None)?;
    assert_eq!(
        rebased.value,
        json!({"tone":"calm","prefs":{"length":"short","new":true}})
    );
    assert_eq!(rebased.made_by.at, 100);
    assert_eq!(vault.get(&first)?, change_bytes);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_FACET)?, masks);
    let body = body_fields(&vault.get(&person)?.unwrap())?;
    assert_eq!(field(&body, "label")?.as_str(), Some("fixture"));
    drop(vault);
    let vault = Vault::open(dir.path(), config)?;
    let reopened_proof = vault.verified_host_root_slip(&issuer)?;
    let read = vault.scoped_read(ScopedReadActorKey::from_verified_slip(&reopened_proof).unwrap());
    assert_eq!(read.compile_persona(&person, None)?, rebased);
    Ok(())
}

#[test]
fn persona_scenario_is_a_scoped_owned_mask_and_malformed_changes_fail_closed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"persona scenario fixture")?;
    let proof = vault.verified_host_root_slip(&issuer)?;
    let read = vault.scoped_read(ScopedReadActorKey::from_verified_slip(&proof).unwrap());
    let person = EntityId::now();
    let other = EntityId::now();
    for id in [person, other] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"",
        )?;
        vault.put_persona_baseline(&id, &json!({"mode":"base"}), 2)?;
    }
    let facet = EntityId::now();
    vault.put_persona_scenario(
        &person,
        &facet,
        &json!({"mode":"scenario"}),
        Sensitivity::Private,
        3,
    )?;
    assert_eq!(
        read.compile_persona(&person, None)?.value,
        json!({"mode":"base"})
    );
    let scenario = read.compile_persona(&person, Some(facet))?;
    assert_eq!(scenario.value, json!({"mode":"scenario"}));
    assert_eq!(scenario.made_by.inputs, vec![person, facet]);
    assert!(read.compile_persona(&other, Some(facet)).is_err());
    assert!(
        vault
            .put_persona_scenario(&other, &facet, &json!({}), Sensitivity::Private, 4)
            .is_err()
    );
    let mut scoped_change = ClaimBody::new(
        PERSONA_CHANGE_PREDICATE,
        ClaimSubject::Entity(person),
        PersonaChange {
            patch: json!({"mode":"only inside a named mask"}),
            made_by: PersonaMadeBy {
                inputs: vec![person],
                process: "test.mask".to_owned(),
                at: 4,
            },
        }
        .to_claim_value()?,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    scoped_change.scope_facet = facet;
    replay_change(&vault, &EntityId::now(), &scoped_change, 4)?;
    assert_eq!(
        read.compile_persona(&person, None)?.value,
        json!({"mode":"base"})
    );
    let unproven = vault.scoped_read(ScopedReadActorKey::new("unproven").unwrap());
    assert!(matches!(
        unproven.compile_persona(&person, Some(facet)),
        Err(Error::EntityNotFound)
    ));
    let mut value = PersonaChange {
        patch: json!({"mode":"changed"}),
        made_by: PersonaMadeBy {
            inputs: vec![person],
            process: "test.change".to_owned(),
            at: 4,
        },
    }
    .to_claim_value()?;
    let Value::Map(entries) = &mut value else {
        panic!("change map");
    };
    put_field(entries, "patch", Value::Binary(vec![1, 2, 3]));
    let bad = ClaimBody::new(
        PERSONA_CHANGE_PREDICATE,
        ClaimSubject::Entity(person),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    replay_change(&vault, &EntityId::now(), &bad, 4)?;
    assert!(read.compile_persona(&person, None).is_err());
    Ok(())
}
