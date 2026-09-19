use super::*;

#[test]
fn archive_subject_facts_wait_for_a_current_owner_review() -> Result<()> {
    let (_source_dir, source) = unrooted_test_vault();
    seed(&source, writer().entity_ref(), ENTITY_TYPE_PERSON);
    let actor = seed(&source, EntityId::now(), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&source, EntityId::now(), ENTITY_TYPE_PERSON);
    let anchor = anchor_actor_subject(&source, actor, person, writer(), 100)?;
    let substrate = set_person_substrate(&source, person, PersonSubstrate::Model, writer(), 100)?;
    let export = source.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    let (_target_dir, target) = test_vault();
    let imported = target.import_whole_vault_json(export.bytes())?;
    assert!(imported.inserted_entities >= 4);
    for id in [anchor, substrate] {
        let body = target.get_claim(&id)?.unwrap();
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(body.source, Some(ClaimSource::Imported));
    }
    let now = crate::unix_seconds_now();
    assert_eq!(target.actor_subject_anchor(&actor, now)?, None);
    assert_eq!(target.person_substrate(&person, now)?, None);
    assert_eq!(
        target
            .import_whole_vault_json(export.bytes())?
            .inserted_entities,
        0
    );
    let stranger = seed(&target, EntityId::now(), ENTITY_TYPE_PERSON);
    let stranger = WriteActor::new(stranger, EdgeActorClass::Human);
    assert!(
        target
            .request_subject_restore_review(anchor, &stranger)
            .is_err()
    );
    for id in [anchor, substrate] {
        let request = target.request_subject_restore_review(id, &writer())?;
        assert_eq!(request.claim_id(), id);
        assert_eq!(request.proposal().approval, ClaimApprovalStatus::Proposed);
        assert_eq!(request.superseded_claim_ids().count(), 0);
        target.approve_subject_restore_review(&request)?;
        let body = target.get_claim(&id)?.unwrap();
        assert_eq!(body.source, Some(ClaimSource::Imported));
        assert_eq!(body.approval, ClaimApprovalStatus::Approved);
        assert!(target.approve_subject_restore_review(&request).is_err());
    }
    let now = crate::unix_seconds_now();
    assert_eq!(
        target
            .actor_subject_anchor(&actor, now)?
            .unwrap()
            .subject_ref,
        person
    );
    assert_eq!(
        target.person_substrate(&person, now)?,
        Some(PersonSubstrate::Model)
    );
    // The archive cannot undo a current owner's approval or revive its old author.
    assert!(target.import_whole_vault_json(export.bytes()).is_err());
    Ok(())
}

#[test]
fn a_stale_subject_review_never_supersedes_an_unreviewed_owner_change() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, EntityId::now(), ENTITY_TYPE_AGENT_DEF);
    let old = seed(&vault, EntityId::now(), ENTITY_TYPE_PERSON);
    let proposed = seed(&vault, EntityId::now(), ENTITY_TYPE_PERSON);
    let latest = seed(&vault, EntityId::now(), ENTITY_TYPE_PERSON);
    let head = anchor_actor_subject(&vault, actor, old, writer(), 100)?;
    let id = EntityId::now();
    let body = imported_subject_body(&subject_fact(
        PREDICATE_ACTOR_SUBJECT_REF,
        actor,
        Value::from(proposed.to_hex()),
        writer(),
        100,
    ))?;
    vault.with_write_txn(|txn| {
        vault.restore_subject_claim_in_txn(
            txn,
            &id,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
    })?;
    let request = vault.request_subject_restore_review(id, &writer())?;
    assert_eq!(
        request.superseded_claim_ids().collect::<Vec<_>>(),
        vec![head]
    );
    let now = crate::unix_seconds_now();
    anchor_actor_subject(&vault, actor, latest, writer(), now)?;
    assert!(vault.approve_subject_restore_review(&request).is_err());
    assert_eq!(
        vault
            .actor_subject_anchor(&actor, now)?
            .unwrap()
            .subject_ref,
        latest
    );
    assert_eq!(
        vault.get_claim(&id)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    // A fresh review can explicitly replace the now-visible current head.
    let fresh = vault.request_subject_restore_review(id, &writer())?;
    vault.approve_subject_restore_review(&fresh)?;
    assert_eq!(
        vault
            .actor_subject_anchor(&actor, crate::unix_seconds_now())?
            .unwrap()
            .subject_ref,
        proposed
    );
    Ok(())
}

#[test]
fn revoked_owner_cannot_complete_a_prepared_subject_restore() -> Result<()> {
    let (_dir, vault) = unrooted_test_vault();
    seed(&vault, writer().entity_ref(), ENTITY_TYPE_PERSON);
    let revoke = authorization::root_owner(&vault, writer(), 0xE3)?;
    let person = seed(&vault, EntityId::now(), ENTITY_TYPE_PERSON);
    let id = EntityId::now();
    let body = imported_subject_body(&subject_fact(
        PREDICATE_PERSON_SUBSTRATE,
        person,
        Value::from("model"),
        writer(),
        100,
    ))?;
    vault.with_write_txn(|txn| {
        vault.restore_subject_claim_in_txn(
            txn,
            &id,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
    })?;
    let review = vault.request_subject_restore_review(id, &writer())?;
    vault.with_write_txn(|txn| {
        vault.put_authority_log_entries_in_txn(
            txn,
            &[(
                revoke,
                TimeRange {
                    start: 102,
                    end: 102,
                },
                102,
            )],
        )
    })?;
    assert!(vault.approve_subject_restore_review(&review).is_err());
    assert_eq!(
        vault.person_substrate(&person, crate::unix_seconds_now())?,
        None
    );
    assert_eq!(
        vault.get_claim(&id)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}
