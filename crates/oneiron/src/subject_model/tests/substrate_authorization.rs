use super::authorization::root_owner;
use super::*;

#[test]
fn unauthorized_substrate_writes_preserve_absence_and_existing_history() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0x91), ENTITY_TYPE_PERSON);
    let stranger = seed(&vault, entity(0x92), ENTITY_TYPE_PERSON);
    let agent = seed(&vault, entity(0x93), ENTITY_TYPE_AGENT_DEF);
    let machine = seed(&vault, entity(0x94), crate::registry::ENTITY_TYPE_MACHINE);
    for existing in [false, true] {
        if existing {
            set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
        }
        let claims = vault.claims_for_subject(&person)?;
        let history = claims
            .iter()
            .map(|id| vault.get(id))
            .collect::<Result<Vec<_>>>()?;
        for untrusted in [
            WriteActor::new(stranger, EdgeActorClass::Human),
            WriteActor::new(agent, EdgeActorClass::Agent),
            WriteActor::new(machine, EdgeActorClass::System),
            WriteActor::new(writer().entity_ref(), EdgeActorClass::System),
            WriteActor::new(agent, EdgeActorClass::Human),
            WriteActor::new(entity(0x95), EdgeActorClass::Human),
        ] {
            let before = vault.claims_for_subject(&person)?;
            assert!(
                set_person_substrate(&vault, person, PersonSubstrate::Model, untrusted, 101)
                    .is_err()
            );
            assert_eq!(vault.claims_for_subject(&person)?, before);
            assert_eq!(vault.claims_for_subject(&person)?, claims);
            assert_eq!(
                claims
                    .iter()
                    .map(|id| vault.get(id))
                    .collect::<Result<Vec<_>>>()?,
                history
            );
            assert_eq!(
                person_substrate(&vault, &person)?,
                existing.then_some(PersonSubstrate::Meat)
            );
        }
    }
    set_person_substrate(&vault, person, PersonSubstrate::Model, writer(), 102)?;
    assert_eq!(
        person_substrate(&vault, &person)?,
        Some(PersonSubstrate::Model)
    );
    Ok(())
}

#[test]
fn substrate_write_observes_revocation_committed_after_preflight() -> Result<()> {
    let (_dir, vault) = unrooted_test_vault();
    seed(&vault, writer().entity_ref(), ENTITY_TYPE_PERSON);
    let revoke = root_owner(&vault, writer(), 0xE7)?;
    let person = seed(&vault, entity(0x96), ENTITY_TYPE_PERSON);
    let claim = set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
    let before = vault.get_claim(&claim)?;
    let mut revocation_txn = vault.store.env.write_txn()?;
    vault.put_authority_log_entries_in_txn(
        &mut revocation_txn,
        &[(
            revoke,
            TimeRange {
                start: 102,
                end: 102,
            },
            102,
        )],
    )?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let result = std::thread::scope(|scope| -> Result<EntityId> {
        let worker = scope.spawn(|| -> Result<EntityId> {
            let txn = vault.store.env.read_txn()?;
            vault.verify_owner_write_actor_in_txn(&txn, &writer())?;
            drop(txn);
            ready_tx.send(()).expect("notify preflight");
            set_person_substrate(&vault, person, PersonSubstrate::Model, writer(), 103)
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("preflight completed");
        revocation_txn.commit()?;
        worker.join().expect("substrate worker")
    });
    assert_eq!(
        result.expect_err("revoked owner").kind(),
        ErrorKind::ActorLacksClaimAuthority
    );
    assert_eq!(vault.get_claim(&claim)?, before);
    assert_eq!(
        person_substrate(&vault, &person)?,
        Some(PersonSubstrate::Meat)
    );
    assert_eq!(vault.claims_for_subject(&person)?.len(), 1);
    Ok(())
}

#[test]
fn unrooted_substrate_uses_canonical_human_owner_semantics() -> Result<()> {
    let (_dir, vault) = unrooted_test_vault();
    seed(&vault, writer().entity_ref(), ENTITY_TYPE_PERSON);
    let person = seed(&vault, entity(0x97), ENTITY_TYPE_PERSON);
    let machine = seed(&vault, entity(0x98), crate::registry::ENTITY_TYPE_MACHINE);
    assert_eq!(
        set_person_substrate(
            &vault,
            person,
            PersonSubstrate::Model,
            WriteActor::new(machine, EdgeActorClass::System),
            100,
        )
        .expect_err("System is not an owner capability")
        .kind(),
        ErrorKind::ActorLacksClaimAuthority
    );
    set_person_substrate(&vault, person, PersonSubstrate::Model, writer(), 101)?;
    assert_eq!(
        person_substrate(&vault, &person)?,
        Some(PersonSubstrate::Model)
    );
    Ok(())
}

#[test]
fn absent_substrate_subject_is_rejected_without_claims() -> Result<()> {
    let (_dir, vault) = test_vault();
    let absent = entity(0x99);
    assert_eq!(
        set_person_substrate(&vault, absent, PersonSubstrate::Model, writer(), 100)
            .expect_err("subject must exist in the write snapshot")
            .kind(),
        ErrorKind::InvalidClaimBody
    );
    assert!(vault.claims_for_subject(&absent)?.is_empty());
    Ok(())
}
