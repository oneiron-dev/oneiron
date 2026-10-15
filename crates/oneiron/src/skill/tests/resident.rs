use super::*;
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt,
    ManifestEntry, ManifestKind,
};

#[test]
fn supersession_never_crosses_resident_or_shared_ownership() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let a = EntityId::now();
    let b = EntityId::now();
    for actor in [a, b] {
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"resident",
        )?;
    }
    let base = EntityId::now();
    let parent = human_skill("1.0.0");
    vault.put_skill_record(&base, &parent, TimeRange { start: 2, end: 2 }, 2)?;
    activate(&vault, &base, &parent)?;
    let make = |resident: EntityId, version: &str| -> Result<EntityId> {
        let id = EntityId::now();
        let mut fork = vault.fork_skill_for_resident(
            &resident,
            &base,
            &id,
            "shared.child",
            TimeRange { start: 10, end: 10 },
            10,
        )?;
        if version != "1" {
            fork.version = version.to_owned();
            fork.desc = format!("revision {version}");
            vault.update_skill_record(&id, &fork, TimeRange { start: 11, end: 11 }, 11)?;
        }
        fork.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &fork, TimeRange { start: 12, end: 12 }, 12)?;
        Ok(id)
    };
    let a_old = make(a, "1")?;
    let b_new = make(b, "2")?;
    let unowned = EntityId::now();
    let mut shared = human_skill("3");
    shared.skill_id = "shared.child".into();
    vault.put_skill_record(&unowned, &shared, TimeRange { start: 13, end: 13 }, 13)?;
    shared.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&unowned, &shared, TimeRange { start: 14, end: 14 }, 14)?;
    for (old, new) in [(a_old, b_new), (a_old, unowned), (unowned, b_new)] {
        assert!(
            vault
                .supersede_skill_record(&old, &new, TimeRange { start: 20, end: 20 }, 20,)
                .is_err()
        );
        assert_eq!(
            vault.get_skill_record(&old)?.expect("old").lifecycle_status,
            SkillLifecycle::Active
        );
        assert_eq!(
            vault.get_skill_record(&new)?.expect("new").lifecycle_status,
            SkillLifecycle::Active
        );
        assert!(
            !vault.edges_out(&new)?.iter().any(|edge| {
                edge.kind == crate::edge::EdgeKind::Supersedes && edge.target == old
            })
        );
    }
    Ok(())
}

fn marked_skill(parent: EntityId, resident: EntityId) -> SkillRecord {
    let mut record = human_skill("1").with_forked_from(parent);
    let Value::Map(entries) = &mut record.provenance else {
        panic!("fixture provenance")
    };
    entries.push((
        Value::from(super::super::resident::RESIDENT_PROVENANCE_KEY),
        Value::from(resident.to_hex()),
    ));
    record
}

#[test]
fn owner_birth_is_validated_by_typed_raw_and_replay_doors() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let parent = EntityId::now();
    vault.put_skill_record(
        &parent,
        &human_skill("1"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let missing = EntityId::now();
    let invalid = marked_skill(parent, missing);
    let id = EntityId::now();
    assert_eq!(
        vault
            .put_skill_record(&id, &invalid, TimeRange { start: 2, end: 2 }, 2)
            .expect_err("local birth needs a real resident")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_SKILL,
                TimeRange { start: 2, end: 2 },
                2,
                &encode_skill_record(&invalid)?
            )
            .commit()
            .expect_err("raw birth uses the same door")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let mut active = invalid.clone();
    active.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_SKILL,
                TimeRange { start: 2, end: 2 },
                2,
                &encode_skill_record(&active)?
            )
            .commit()
            .expect_err("active replay must wait for its owner")
            .kind(),
        ErrorKind::ResidentOwnerDependencyPending
    );
    // An out-of-order Candidate is inert until its actor arrives; a wrong-kind
    // owner is refused immediately, and neither path grants a pack load.
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 3, end: 3 },
            3,
            &encode_skill_record(&invalid)?,
        )
        .commit()?;
    assert_eq!(
        vault
            .get_skill_record(&id)?
            .expect("inert")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    let wrong = EntityId::now();
    vault.put_entity(
        &wrong,
        ENTITY_TYPE_SKILL,
        TimeRange { start: 4, end: 4 },
        4,
        &encode_skill_record(&human_skill("1"))?,
    )?;
    let wrong_kind = marked_skill(parent, wrong);
    assert_eq!(
        vault
            .batch()
            .put_replicated(
                &EntityId::now(),
                ENTITY_TYPE_SKILL,
                TimeRange { start: 5, end: 5 },
                5,
                &encode_skill_record(&wrong_kind)?
            )
            .commit()
            .expect_err("wrong-kind owner on replay")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    vault.put_entity(
        &missing,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 6, end: 6 },
        6,
        b"resident",
    )?;
    // Candidate arrived before its owner. The later PERSON birth must not
    // leave a gap where an unbound receipt can become this actor's lesson.
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "resident.deferred".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 7,
    })?
    else {
        panic!("new attempt")
    };
    queue.append_manifest_entry(
        attempt.id,
        ManifestEntry::new(ManifestKind::SkillIndex, "index", "1", 8),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "resident.deferred",
        ClaimAttempt {
            lease_owner: "host".into(),
            now: 9,
        },
    )?
    else {
        panic!("claim")
    };
    queue.fail(FailAttempt {
        id: attempt.id,
        lease_owner: "host".into(),
        attempt_count: leased.attempt_count,
        reason: "failed".into(),
        now: 10,
    })?;
    let receipt = crate::receipt::attempt_pack_receipt_id(&attempt.id);
    assert!(crate::receipt::attempt_pack_receipt(&vault, &receipt)?.is_some());
    assert!(
        crate::skill_attribution::record_attribution_evidence(
            &vault,
            &crate::skill_attribution::OutcomeEvidence::new(
                &receipt,
                missing,
                crate::skill_attribution::AttemptOutcome::Failed,
                10,
            )
            .with_routing_facts(false, true)
        )
        .is_err()
    );
    assert!(
        crate::actor_claims::write_actor_claim(
            &vault,
            crate::actor_claims::ActorClaimRow::Lesson {
                actor: missing,
                text: "first-use".into()
            },
            &crate::actor_claims::ActorClaimEvidence::task(vec![receipt], 10)?,
        )
        .is_err()
    );
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 7, end: 7 },
            7,
            &encode_skill_record(&active)?,
        )
        .commit()?;
    assert_eq!(
        super::super::resident::resident_of(&vault.get_skill_record(&id)?.expect("active"))?,
        Some(missing)
    );
    let mut malformed = marked_skill(parent, missing);
    let Value::Map(entries) = &mut malformed.provenance else {
        panic!("fixture")
    };
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("residentActor"))
        .expect("owner")
        .1 = Value::from("not-a-hex-id");
    assert_eq!(
        encode_skill_record(&malformed)
            .expect_err("malformed body")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

#[test]
fn resident_owner_survives_same_batch_delete_separate_delete_and_rematerialization() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let a = EntityId::now();
    let b = EntityId::now();
    for actor in [a, b] {
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"resident",
        )?;
    }
    let parent = EntityId::now();
    vault.put_skill_record(
        &parent,
        &human_skill("1"),
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    let id = EntityId::now();
    let first = marked_skill(parent, a);
    vault.put_skill_record(&id, &first, TimeRange { start: 3, end: 3 }, 3)?;
    let different = marked_skill(parent, b);
    let raw = encode_skill_record(&different)?;
    let at = TimeRange { start: 4, end: 4 };
    assert_eq!(
        vault
            .batch()
            .delete(&id)
            .put(&id, ENTITY_TYPE_SKILL, at, 4, &raw)
            .commit()
            .expect_err("same-batch owner swap")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(vault.get_skill_record(&id)?, Some(first.clone()));
    assert!(vault.delete_entity(&id)?);
    assert_eq!(
        vault
            .put_skill_record(&id, &different, at, 4)
            .expect_err("separate-delete owner swap")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_SKILL, at, 4, &raw)
            .commit()
            .expect_err("replay cannot reassign deleted id")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    // Admission accepts the SAME owner, but the local deletion dominates this
    // older replay: it is refused, never permission to resurrect the body.
    assert_eq!(
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_SKILL, at, 4, &encode_skill_record(&first)?)
            .commit()
            .expect_err("a deletion here dominates the replay")
            .kind(),
        ErrorKind::InvariantViolation
    );
    assert!(vault.get_skill_record(&id)?.is_none());
    // The marker also freezes explicit absence: an unowned id cannot be
    // reborn with a resident mark after deletion.
    let unowned = EntityId::now();
    vault.put_skill_record(&unowned, &human_skill("1"), at, 4)?;
    assert!(vault.delete_entity(&unowned)?);
    assert_eq!(
        vault
            .put_skill_record(&unowned, &different, at, 4)
            .expect_err("absence is an immutable birth fact")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}
