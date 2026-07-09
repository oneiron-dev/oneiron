use super::*;
use crate::batch::export::companion_export_layer;
use crate::claim::ClaimSource;
use crate::registry::ENTITY_TYPE_TURN;
use crate::types::{TimeRange, WriteActor, WriteProvenance};
use crate::{EnqueueJob, EnqueueOutcome, JobQueue, JobState, Vault, VaultConfig};

fn entity(seed: u8) -> EntityId {
    let mut bytes = [seed; 16];
    bytes[0] = seed.max(1);
    EntityId::from_bytes(bytes).expect("test entity id")
}

fn provenance(seed: u8) -> CompanionProvenance {
    let envelope = WriteEnvelope::new(
        WriteActor::new(entity(seed), EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from(format!("fixture-{seed}"))).unwrap(),
        ClaimApprovalStatus::Approved,
    );
    CompanionProvenance::from_envelope(&envelope)
}

fn raw_companion_record_body(
    record: &CompanionRecord,
    lifecycle: ClaimLifecycleStatus,
    lifecycle_events: Vec<CompanionLifecycleEvent>,
) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMPANION_RECORD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_KIND), Value::from(record.kind().as_str())),
        (Value::from(KEY_SCOPE), encode_scope(&record.scope)),
        (Value::from(KEY_SUBJECT), encode_subject(&record.subject)),
        (Value::from(KEY_VALUE), record.value.clone()),
        (
            Value::from(KEY_PROVENANCE),
            encode_provenance(&record.provenance),
        ),
        (Value::from(KEY_LIFECYCLE), Value::from(lifecycle.as_str())),
        (
            Value::from(KEY_EXPORT),
            Value::from(record.export_classification.as_str()),
        ),
        (
            Value::from(KEY_LIFECYCLE_EVENTS),
            encode_lifecycle_events(&lifecycle_events),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("raw companion encode failed"))?;
    Ok(out)
}

fn companion_task(kind: CompanionTaskKind, key: CompanionRecordKey) -> Result<CompanionTask> {
    CompanionTask::new(kind, key)
}

#[test]
fn companion_task_payload_round_trips_all_task_kinds() -> Result<()> {
    let personal = CompanionScope::personal(entity(0x21));
    let fixtures = [
        companion_task(
            CompanionTaskKind::Context,
            CompanionRecordKey::relationship(personal.clone(), entity(0x22), entity(0x23)),
        )?,
        companion_task(
            CompanionTaskKind::Profile,
            CompanionRecordKey::persona(personal.clone(), entity(0x24)),
        )?,
        companion_task(
            CompanionTaskKind::Memory,
            CompanionRecordKey::persona(CompanionScope::neutral(), entity(0x25)),
        )?,
        companion_task(
            CompanionTaskKind::GoodbyeArtifact,
            CompanionRecordKey::relationship(personal, entity(0x26), entity(0x27)),
        )?,
    ];

    for task in fixtures {
        let encoded = encode_companion_task_payload(&task)?;
        let decoded = decode_companion_task_payload(&encoded)?;
        assert_eq!(decoded, task);
        assert!(
            task.dedupe_key().contains(task.kind.as_str()),
            "dedupe key should identify task kind"
        );
    }

    Ok(())
}

#[test]
fn companion_queue_fixture_enqueues_claims_completes_and_retries() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let companion_queue = CompanionQueue::new(&vault);
    let generic_queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(generic) = generic_queue.enqueue(EnqueueJob {
        kind: "claim_extraction".to_owned(),
        payload: b"generic".to_vec(),
        dedupe_key: Some("turn:generic".to_owned()),
        run_id: Some("run-generic".to_owned()),
        now: 5,
    })?
    else {
        panic!("expected generic enqueue");
    };

    let personal = CompanionScope::personal(entity(0x31));
    let context_task = companion_task(
        CompanionTaskKind::Context,
        CompanionRecordKey::relationship(personal.clone(), entity(0x32), entity(0x33)),
    )?;
    let context_dedupe_key = context_task.dedupe_key();
    let EnqueueCompanionTaskOutcome::Enqueued(context_status) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: context_task.clone(),
            run_id: Some("run-context".to_owned()),
            now: 10,
        })?
    else {
        panic!("expected context enqueue");
    };
    assert_eq!(context_status.job.kind, COMPANION_TASK_JOB_KIND);
    assert_eq!(context_status.job.state, JobState::Queued);
    assert_eq!(
        context_status.job.dedupe_key.as_deref(),
        Some(context_dedupe_key.as_str())
    );
    assert_eq!(context_status.task, context_task);

    let EnqueueCompanionTaskOutcome::Existing(duplicate_context) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: context_task,
            run_id: Some("run-context-duplicate".to_owned()),
            now: 11,
        })?
    else {
        panic!("expected context dedupe hit");
    };
    assert_eq!(duplicate_context.job.id, context_status.job.id);

    let ClaimCompanionTaskOutcome::Claimed(claimed_context) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 20,
        })?
    else {
        panic!("expected context claim");
    };
    assert_eq!(claimed_context.job.id, context_status.job.id);
    assert_eq!(claimed_context.job.state, JobState::Leased);
    assert_eq!(claimed_context.job.attempt_count, 1);
    assert_eq!(
        generic_queue.get(generic.id)?.expect("generic job").state,
        JobState::Queued,
        "companion claim must skip non-companion jobs"
    );

    let CompleteCompanionTaskOutcome::Completed(completed_context) =
        companion_queue.complete(CompleteCompanionTask {
            id: claimed_context.job.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: claimed_context.job.attempt_count,
            now: 21,
        })?
    else {
        panic!("expected context complete");
    };
    assert_eq!(completed_context.job.state, JobState::Completed);
    assert_eq!(
        companion_queue
            .status(completed_context.job.id)?
            .expect("context status")
            .job
            .state,
        JobState::Completed
    );

    let profile_task = companion_task(
        CompanionTaskKind::Profile,
        CompanionRecordKey::persona(personal, entity(0x34)),
    )?;
    let EnqueueCompanionTaskOutcome::Enqueued(profile_status) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: profile_task.clone(),
            run_id: Some("run-profile".to_owned()),
            now: 30,
        })?
    else {
        panic!("expected profile enqueue");
    };
    let ClaimCompanionTaskOutcome::Claimed(claimed_profile) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 31,
        })?
    else {
        panic!("expected profile claim");
    };
    assert_eq!(claimed_profile.job.id, profile_status.job.id);

    let RetryCompanionTaskOutcome::Retried(retried_profile) =
        companion_queue.retry(RetryCompanionTask {
            id: claimed_profile.job.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: claimed_profile.job.attempt_count,
            backoff_until: 40,
            last_error: Some("profile model unavailable".to_owned()),
            now: 32,
        })?;
    assert_eq!(retried_profile.job.state, JobState::Queued);
    assert_eq!(retried_profile.job.backoff_until, Some(40));
    assert_eq!(
        retried_profile.job.last_error.as_deref(),
        Some("profile model unavailable")
    );
    assert_eq!(
        companion_queue
            .status(retried_profile.job.id)?
            .expect("profile status")
            .job
            .last_error
            .as_deref(),
        Some("profile model unavailable")
    );
    assert_eq!(
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "too-early".to_owned(),
            now: 39,
        })?,
        ClaimCompanionTaskOutcome::Empty
    );

    let ClaimCompanionTaskOutcome::Claimed(reclaimed_profile) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 40,
        })?
    else {
        panic!("expected profile reclaim");
    };
    assert_eq!(reclaimed_profile.job.id, profile_status.job.id);
    assert_eq!(reclaimed_profile.job.attempt_count, 2);
    let CompleteCompanionTaskOutcome::Completed(completed_profile) =
        companion_queue.complete(CompleteCompanionTask {
            id: reclaimed_profile.job.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: reclaimed_profile.job.attempt_count,
            now: 41,
        })?
    else {
        panic!("expected profile complete");
    };
    assert_eq!(completed_profile.job.state, JobState::Completed);
    assert_eq!(completed_profile.task, profile_task);

    let memory_task = companion_task(
        CompanionTaskKind::Memory,
        CompanionRecordKey::persona(CompanionScope::neutral(), entity(0x35)),
    )?;
    let EnqueueCompanionTaskOutcome::Enqueued(memory_status) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: memory_task.clone(),
            run_id: Some("run-memory".to_owned()),
            now: 50,
        })?
    else {
        panic!("expected memory enqueue");
    };
    let ClaimCompanionTaskOutcome::Claimed(claimed_memory) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 51,
        })?
    else {
        panic!("expected memory claim");
    };
    assert_eq!(claimed_memory.job.id, memory_status.job.id);
    let FailCompanionTaskOutcome::Failed(failed_memory) =
        companion_queue.fail(FailCompanionTask {
            id: claimed_memory.job.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: claimed_memory.job.attempt_count,
            reason: "memory task exhausted retries".to_owned(),
            now: 52,
        })?
    else {
        panic!("expected memory fail");
    };
    assert_eq!(failed_memory.job.state, JobState::Failed);
    assert_eq!(
        companion_queue
            .status(failed_memory.job.id)?
            .expect("memory status")
            .job
            .last_error
            .as_deref(),
        Some("memory task exhausted retries")
    );
    assert_eq!(failed_memory.task, memory_task);

    let ClaimOutcome::Claimed(claimed_generic) = generic_queue.claim(ClaimJob {
        lease_owner: "generic-worker".to_owned(),
        now: 60,
    })?
    else {
        panic!("expected generic claim after companion work");
    };
    assert_eq!(claimed_generic.id, generic.id);
    assert!(
        companion_queue
            .complete(CompleteCompanionTask {
                id: claimed_generic.id,
                lease_owner: "generic-worker".to_owned(),
                attempt_count: claimed_generic.attempt_count,
                now: 61,
            })
            .is_err()
    );
    assert_eq!(
        generic_queue
            .get(claimed_generic.id)?
            .expect("generic job persisted")
            .state,
        JobState::Leased
    );

    Ok(())
}

#[test]
fn companion_queue_claim_fails_undecodable_task_payload() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let companion_queue = CompanionQueue::new(&vault);
    let generic_queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(invalid_task) = generic_queue.enqueue(EnqueueJob {
        kind: COMPANION_TASK_JOB_KIND.to_owned(),
        payload: b"not-msgpack".to_vec(),
        dedupe_key: Some("companion:invalid".to_owned()),
        run_id: Some("run-invalid".to_owned()),
        now: 70,
    })?
    else {
        panic!("expected invalid companion task enqueue");
    };

    assert_eq!(
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 80,
        })?,
        ClaimCompanionTaskOutcome::Empty
    );

    let failed = generic_queue
        .get(invalid_task.id)?
        .expect("invalid companion task persisted");
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(failed.lease_owner, None);
    assert_eq!(failed.attempt_count, 1);
    assert_eq!(
        failed.last_error.as_deref(),
        Some(ERR_INVALID_COMPANION_TASK_PAYLOAD)
    );

    assert_eq!(
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 81,
        })?,
        ClaimCompanionTaskOutcome::Empty
    );
    assert_eq!(
        generic_queue
            .get(invalid_task.id)?
            .expect("invalid companion task still persisted")
            .attempt_count,
        1
    );

    Ok(())
}

#[test]
fn companion_register_creates_and_looks_up_persona_and_relationship() -> Result<()> {
    let neutral = CompanionScope::neutral();
    let persona_ref = entity(0x11);
    let source_ref = entity(0x12);
    let target_ref = entity(0x13);

    let persona = CompanionRecord::persona(
        neutral.clone(),
        persona_ref,
        Value::from("neutral persona"),
        provenance(0xA1),
        CompanionExportClassification::Portable,
    );
    let relationship = CompanionRecord::relationship(
        neutral.clone(),
        source_ref,
        target_ref,
        Value::from("neutral relationship"),
        provenance(0xA2),
        CompanionExportClassification::LocalOnly,
    );

    let mut register = CompanionRegister::new();
    assert!(register.register(persona.clone())?.is_none());
    assert!(register.register(relationship.clone())?.is_none());

    assert_eq!(
        register.lookup_persona(&neutral, persona_ref),
        Some(&persona)
    );
    assert_eq!(
        register.lookup_relationship(&neutral, source_ref, target_ref),
        Some(&relationship)
    );
    assert_eq!(register.len(), 2);
    Ok(())
}

#[test]
fn companion_register_keeps_neutral_personal_and_shared_vault_scopes_separate() -> Result<()> {
    let persona_ref = entity(0x21);
    let person_owner = entity(0x22);
    let neutral = CompanionScope::neutral();
    let personal = CompanionScope::personal(person_owner);
    let shared = CompanionScope::shared_vault(7);

    let mut register = CompanionRegister::new();
    register.register(CompanionRecord::persona(
        neutral.clone(),
        persona_ref,
        Value::from("neutral"),
        provenance(0xB1),
        CompanionExportClassification::Portable,
    ))?;
    register.register(CompanionRecord::persona(
        personal.clone(),
        persona_ref,
        Value::from("personal"),
        provenance(0xB2),
        CompanionExportClassification::LocalOnly,
    ))?;
    register.register(CompanionRecord::persona(
        shared.clone(),
        persona_ref,
        Value::from("shared"),
        provenance(0xB3),
        CompanionExportClassification::SharedVault,
    ))?;

    assert_eq!(
        register
            .lookup_persona(&neutral, persona_ref)
            .map(|r| &r.value),
        Some(&Value::from("neutral"))
    );
    assert_eq!(
        register
            .lookup_persona(&personal, persona_ref)
            .map(|r| &r.value),
        Some(&Value::from("personal"))
    );
    assert_eq!(
        register
            .lookup_persona(&shared, persona_ref)
            .map(|r| &r.value),
        Some(&Value::from("shared"))
    );
    assert_eq!(register.records_in_scope(&neutral).count(), 1);
    assert_eq!(register.records_in_scope(&personal).count(), 1);
    assert_eq!(register.records_in_scope(&shared).count(), 1);
    Ok(())
}

#[test]
fn companion_scope_resolution_prefers_warm_personal_relationship_boundary() -> Result<()> {
    let persona_ref = entity(0x23);
    let person_ref = entity(0x24);
    let neutral = CompanionScope::neutral();
    let personal = CompanionScope::personal(person_ref);
    let mut register = CompanionRegister::new();
    let neutral_persona = CompanionRecord::persona(
        neutral,
        persona_ref,
        Value::from("neutral fallback persona"),
        provenance(0xC8),
        CompanionExportClassification::Portable,
    );
    let private_relationship_note = "private warm relationship note";
    let personal_relationship = CompanionRecord::relationship(
        personal.clone(),
        person_ref,
        persona_ref,
        Value::Map(vec![(
            Value::from("note"),
            Value::from(private_relationship_note),
        )]),
        provenance(0xC9),
        CompanionExportClassification::LocalOnly,
    );
    register.register(neutral_persona.clone())?;
    register.register(personal_relationship.clone())?;

    let mut expressions = CompanionExpressionRegister::new();
    expressions.update(neutral_persona.key(), CompanionExpression::Unrestricted)?;
    expressions.update(personal_relationship.key(), CompanionExpression::Warm)?;

    let resolution = register.resolve_companion_scope(
        &expressions,
        Some(person_ref),
        Some(persona_ref),
        Some((person_ref, persona_ref)),
    );

    assert_eq!(resolution.scope, personal);
    assert_eq!(
        resolution.source,
        CompanionScopeResolutionSource::RelationshipRecord
    );
    assert_eq!(resolution.persona_key, None);
    assert_eq!(
        resolution.relationship_key,
        Some(personal_relationship.key())
    );
    assert_eq!(resolution.expression, CompanionExpression::Warm);
    assert!(
        !format!("{resolution:?}").contains(private_relationship_note),
        "resolved scope must not carry opaque private companion values"
    );
    Ok(())
}

#[test]
fn companion_scope_resolution_falls_back_to_neutral_persona_and_blocks_orphan_expression()
-> Result<()> {
    let persona_ref = entity(0x25);
    let person_ref = entity(0x26);
    let neutral = CompanionScope::neutral();
    let mut register = CompanionRegister::new();
    let neutral_persona = CompanionRecord::persona(
        neutral.clone(),
        persona_ref,
        Value::from("neutral @Oneiron"),
        provenance(0xCA),
        CompanionExportClassification::Portable,
    );
    register.register(neutral_persona.clone())?;

    let mut expressions = CompanionExpressionRegister::new();
    expressions.update(
        CompanionRecordKey::persona(CompanionScope::personal(person_ref), persona_ref),
        CompanionExpression::Warm,
    )?;
    expressions.update(neutral_persona.key(), CompanionExpression::Professional)?;

    let resolution = register.resolve_companion_scope(
        &expressions,
        Some(person_ref),
        Some(persona_ref),
        Some((person_ref, persona_ref)),
    );
    assert_eq!(resolution.scope, neutral);
    assert_eq!(
        resolution.source,
        CompanionScopeResolutionSource::PersonaRecord
    );
    assert_eq!(resolution.persona_key, Some(neutral_persona.key()));
    assert_eq!(resolution.relationship_key, None);
    assert_eq!(resolution.expression, CompanionExpression::Professional);

    let orphan_only = CompanionRegister::new().resolve_companion_scope(
        &expressions,
        Some(person_ref),
        Some(persona_ref),
        Some((person_ref, persona_ref)),
    );
    assert_eq!(orphan_only.scope, CompanionScope::neutral());
    assert_eq!(
        orphan_only.source,
        CompanionScopeResolutionSource::NeutralDefault
    );
    assert_eq!(orphan_only.expression, CompanionExpression::Professional);
    Ok(())
}

#[test]
fn companion_register_body_round_trip_carries_provenance_lifecycle_and_export() -> Result<()> {
    let mut record = CompanionRecord::relationship(
        CompanionScope::shared_vault(42),
        entity(0x31),
        entity(0x32),
        Value::Map(vec![(Value::from("affinity"), Value::from("trusted"))]),
        CompanionProvenance::new(
            entity(0x33),
            EdgeActorClass::Human,
            ClaimSource::Observed,
            ClaimApprovalStatus::Proposed,
            Value::Map(vec![(Value::from("source"), Value::from("test"))]),
        ),
        CompanionExportClassification::SharedVault,
    );
    let unstamped_retired = record.retired()?;
    assert_eq!(unstamped_retired.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(unstamped_retired.lifecycle_events.is_empty());
    assert!(encode_companion_record_body(&unstamped_retired).is_err());
    record.lifecycle = ClaimLifecycleStatus::Superseded;
    record
        .lifecycle_events
        .push(CompanionLifecycleEvent::superseded(77));

    let encoded = encode_companion_record_body(&record)?;
    let decoded = decode_companion_record_body(&encoded)?;

    assert_eq!(decoded, record);
    assert_eq!(decoded.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(
        decoded.lifecycle_events,
        vec![CompanionLifecycleEvent::superseded(77)]
    );
    assert_eq!(
        decoded.export_classification,
        CompanionExportClassification::SharedVault
    );
    assert_eq!(decoded.provenance.actor_class, EdgeActorClass::Human);
    Ok(())
}

#[test]
fn companion_register_body_requires_current_schema_lifecycle_events() -> Result<()> {
    let record = CompanionRecord::persona(
        CompanionScope::neutral(),
        entity(0x36),
        Value::from("eventless v2 persona"),
        provenance(0xD6),
        CompanionExportClassification::Portable,
    );
    let err = encode_companion_record_body(&record)
        .expect_err("current schema writes require lifecycle events");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion lifecycle events required for current schema")
    ));

    let mut missing_encoded = Vec::new();
    rmpv::encode::write_value(
        &mut missing_encoded,
        &Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(COMPANION_RECORD_SCHEMA_VERSION),
            ),
            (Value::from(KEY_KIND), Value::from(record.kind().as_str())),
            (Value::from(KEY_SCOPE), encode_scope(&record.scope)),
            (Value::from(KEY_SUBJECT), encode_subject(&record.subject)),
            (Value::from(KEY_VALUE), record.value.clone()),
            (
                Value::from(KEY_PROVENANCE),
                encode_provenance(&record.provenance),
            ),
            (
                Value::from(KEY_LIFECYCLE),
                Value::from(ClaimLifecycleStatus::Retracted.as_str()),
            ),
            (
                Value::from(KEY_EXPORT),
                Value::from(record.export_classification.as_str()),
            ),
        ]),
    )
    .map_err(|_| Error::InvariantViolation("current companion encode failed"))?;
    let err = decode_companion_record_body(&missing_encoded)
        .expect_err("current schema decode requires lifecycle_events field");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("missing required field lifecycle_events")
    ));

    let mut encoded = Vec::new();
    rmpv::encode::write_value(
        &mut encoded,
        &Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(COMPANION_RECORD_SCHEMA_VERSION),
            ),
            (Value::from(KEY_KIND), Value::from(record.kind().as_str())),
            (Value::from(KEY_SCOPE), encode_scope(&record.scope)),
            (Value::from(KEY_SUBJECT), encode_subject(&record.subject)),
            (Value::from(KEY_VALUE), record.value.clone()),
            (
                Value::from(KEY_PROVENANCE),
                encode_provenance(&record.provenance),
            ),
            (
                Value::from(KEY_LIFECYCLE),
                Value::from(ClaimLifecycleStatus::Retracted.as_str()),
            ),
            (
                Value::from(KEY_EXPORT),
                Value::from(record.export_classification.as_str()),
            ),
            (Value::from(KEY_LIFECYCLE_EVENTS), Value::Array(Vec::new())),
        ]),
    )
    .map_err(|_| Error::InvariantViolation("current companion encode failed"))?;
    let err = decode_companion_record_body(&encoded)
        .expect_err("current schema decode requires terminal evidence");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion lifecycle events required for current schema")
    ));
    Ok(())
}

#[test]
fn companion_register_body_decodes_legacy_v1_without_lifecycle_events() -> Result<()> {
    let record = CompanionRecord::persona(
        CompanionScope::neutral(),
        entity(0x37),
        Value::from("legacy v1 persona"),
        provenance(0xD7),
        CompanionExportClassification::Portable,
    );
    let legacy = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMPANION_RECORD_SCHEMA_VERSION_V1),
        ),
        (Value::from(KEY_KIND), Value::from(record.kind().as_str())),
        (Value::from(KEY_SCOPE), encode_scope(&record.scope)),
        (Value::from(KEY_SUBJECT), encode_subject(&record.subject)),
        (Value::from(KEY_VALUE), record.value.clone()),
        (
            Value::from(KEY_PROVENANCE),
            encode_provenance(&record.provenance),
        ),
        (
            Value::from(KEY_LIFECYCLE),
            Value::from(record.lifecycle.as_str()),
        ),
        (
            Value::from(KEY_EXPORT),
            Value::from(record.export_classification.as_str()),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &legacy)
        .map_err(|_| Error::InvariantViolation("legacy companion encode failed"))?;

    let decoded = decode_companion_record_body(&encoded)?;
    assert_eq!(decoded, record);
    assert!(decoded.lifecycle_events.is_empty());
    Ok(())
}

#[test]
fn companion_register_create_canonicalizes_caller_lifecycle_history() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let id = entity(0xC1);
    let forged_id = entity(0xC5);
    let mut record = CompanionRecord::persona(
        CompanionScope::personal(entity(0xC2)),
        entity(0xC3),
        Value::from("canonical create"),
        provenance(0xC4),
        CompanionExportClassification::Portable,
    );
    record.lifecycle_events = vec![
        CompanionLifecycleEvent::created(1),
        CompanionLifecycleEvent::retired(2),
        CompanionLifecycleEvent::revived(3),
    ];

    let mut forged_create_history = record.clone();
    forged_create_history.lifecycle_events = vec![
        CompanionLifecycleEvent::created(1),
        CompanionLifecycleEvent::retired(2),
        CompanionLifecycleEvent::created(3),
    ];
    let err = vault
        .batch()
        .put(
            &forged_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 3, end: 3 },
            3,
            &encode_companion_record_body(&forged_create_history)?,
        )
        .commit()
        .expect_err("raw active create history must be canonical");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion create lifecycle history must be canonical")
    ));

    vault.create_companion_record(&id, &record, 40)?;

    let stored = vault
        .get_companion_record(&id)?
        .expect("created companion record");
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        stored.lifecycle_events,
        vec![CompanionLifecycleEvent::created(40)]
    );
    assert_eq!(
        record.created_at(41)?.lifecycle_events,
        vec![CompanionLifecycleEvent::created(41)]
    );
    Ok(())
}

#[test]
fn companion_register_raw_revived_put_requires_matching_retired_history() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let retired_id = entity(0xD1);
    let revived_id = entity(0xD2);
    let forged_id = entity(0xD3);
    let mismatched_id = entity(0xD4);
    let duplicate_id = entity(0xD8);
    let record = CompanionRecord::persona(
        CompanionScope::personal(entity(0xD5)),
        entity(0xD6),
        Value::from("revived row"),
        provenance(0xD7),
        CompanionExportClassification::Portable,
    );

    let mut revived_without_predecessor = record.clone();
    revived_without_predecessor.lifecycle_events = vec![
        CompanionLifecycleEvent::created(10),
        CompanionLifecycleEvent::retired(11),
        CompanionLifecycleEvent::revived(12),
    ];
    let err = vault
        .batch()
        .put(
            &forged_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 12, end: 12 },
            12,
            &encode_companion_record_body(&revived_without_predecessor)?,
        )
        .commit()
        .expect_err("raw revived put must require a retired predecessor");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion record revive requires retired history")
    ));

    vault.create_companion_record(&retired_id, &record, 20)?;
    let retired = vault.retire_companion_record(&retired_id, 21)?;

    let mut mismatched_revived = record.clone();
    mismatched_revived.lifecycle_events = vec![
        CompanionLifecycleEvent::created(20),
        CompanionLifecycleEvent::retired(99),
        CompanionLifecycleEvent::revived(22),
    ];
    let err = vault
        .batch()
        .put(
            &mismatched_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 22, end: 22 },
            22,
            &encode_companion_record_body(&mismatched_revived)?,
        )
        .commit()
        .expect_err("raw revived put must match retired lifecycle history");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion record revive requires retired history")
    ));

    let mut valid_revived = record;
    valid_revived.lifecycle_events = retired.lifecycle_events;
    valid_revived
        .lifecycle_events
        .push(CompanionLifecycleEvent::revived(22));
    vault
        .batch()
        .put(
            &revived_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 22, end: 22 },
            22,
            &encode_companion_record_body(&valid_revived)?,
        )
        .commit()?;

    assert_eq!(
        vault.get_companion_record(&revived_id)?,
        Some(valid_revived.clone())
    );

    let err = vault
        .batch()
        .put(
            &duplicate_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 23, end: 23 },
            23,
            &encode_companion_record_body(&valid_revived)?,
        )
        .commit()
        .expect_err("second raw active revived row for key must be rejected");
    assert!(matches!(err, Error::CompanionRecordAlreadyExists));
    Ok(())
}

#[test]
fn companion_register_raw_revived_put_accepts_same_batch_retired_history() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let retired_id = entity(0xE1);
    let revived_id = entity(0xE2);
    let record = CompanionRecord::persona(
        CompanionScope::personal(entity(0xE3)),
        entity(0xE4),
        Value::from("same batch revived row"),
        provenance(0xE5),
        CompanionExportClassification::Portable,
    );
    let retired = record.created_at(30)?.retired_at(31)?;
    let revived = retired.revived_at(32)?;

    vault
        .batch()
        .put(
            &revived_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 32, end: 32 },
            32,
            &encode_companion_record_body(&revived)?,
        )
        .put(
            &retired_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 31, end: 31 },
            31,
            &encode_companion_record_body(&retired)?,
        )
        .commit()?;

    assert_eq!(
        vault.get_companion_record(&revived_id)?,
        Some(revived.clone())
    );
    assert_eq!(vault.get_companion_record(&retired_id)?, Some(retired));
    assert_eq!(
        vault.companion_register()?.lookup(&revived.key()),
        Some(&revived)
    );
    Ok(())
}

#[test]
fn companion_export_expression_register_updates_and_fails_closed_on_future_values() -> Result<()> {
    assert_eq!(
        CompanionExpression::parse("professional"),
        Some(CompanionExpression::Professional)
    );
    assert_eq!(
        CompanionExpression::parse("warm"),
        Some(CompanionExpression::Warm)
    );
    assert_eq!(
        CompanionExpression::parse("unrestricted"),
        Some(CompanionExpression::Unrestricted)
    );
    for expression in [
        CompanionExpression::Professional,
        CompanionExpression::Warm,
        CompanionExpression::Unrestricted,
    ] {
        assert_eq!(
            CompanionExpression::parse(expression.as_str()),
            Some(expression)
        );
    }
    assert!(CompanionExpression::parse("future_closed").is_none());
    assert!(matches!(
        CompanionExpression::parse_closed("future_closed"),
        Err(Error::InvalidClaimBody(
            "expression must be professional|warm|unrestricted"
        ))
    ));

    let neutral = CompanionScope::neutral();
    let persona_ref = entity(0x41);
    let key = CompanionRecordKey::persona(neutral.clone(), persona_ref);
    let mut register = CompanionExpressionRegister::new();

    assert!(
        register
            .update(key.clone(), CompanionExpression::Professional)?
            .is_none()
    );
    assert_eq!(
        register.lookup_persona(&neutral, persona_ref),
        Some(CompanionExpression::Professional)
    );
    assert_eq!(
        register.update(key, CompanionExpression::Warm)?,
        Some(CompanionExpression::Professional)
    );
    assert_eq!(
        register.lookup_persona(&neutral, persona_ref),
        Some(CompanionExpression::Warm)
    );

    let err = register
        .update(
            CompanionRecordKey::persona(CompanionScope::shared_vault(0), persona_ref),
            CompanionExpression::Unrestricted,
        )
        .expect_err("invalid shared-vault expression scope must fail closed");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("shared-vault companion scope requires nonzero vault_id")
    ));
    Ok(())
}

#[test]
fn companion_register_api_persists_updates_exports_and_retires_privately() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert!(
        vault
            .structural_kind_registration(ENTITY_TYPE_COMPANION_REGISTER)
            .is_none(),
        "companion register is static and must not need a dynamic registry row"
    );
    let neutral_id = entity(0x51);
    let personal_id = entity(0x52);
    let shared_id = entity(0x53);
    let neutral_persona = entity(0x61);
    let personal_person = entity(0x62);
    let shared_source = entity(0x63);
    let shared_target = entity(0x64);
    let neutral_scope = CompanionScope::neutral();
    let personal_scope = CompanionScope::personal(personal_person);
    let shared_scope = CompanionScope::shared_vault(9);

    let neutral = CompanionRecord::persona(
        neutral_scope.clone(),
        neutral_persona,
        Value::from("neutral @Oneiron"),
        provenance(0xD1),
        CompanionExportClassification::Portable,
    );
    let personal = CompanionRecord::persona(
        personal_scope.clone(),
        neutral_persona,
        Value::Map(vec![(
            Value::from("note"),
            Value::from("private-person-note"),
        )]),
        provenance(0xD2),
        CompanionExportClassification::LocalOnly,
    );
    let shared = CompanionRecord::relationship(
        shared_scope.clone(),
        shared_source,
        shared_target,
        Value::Map(vec![(
            Value::from("note"),
            Value::from("shared-vault-note"),
        )]),
        provenance(0xD3),
        CompanionExportClassification::SharedVault,
    );

    vault.create_companion_record(&neutral_id, &neutral, 10)?;
    assert!(
        vault
            .structural_kind_registration(ENTITY_TYPE_COMPANION_REGISTER)
            .is_none(),
        "fresh companion create must not write a dynamic registry row"
    );
    vault.create_companion_record(&personal_id, &personal, 11)?;
    vault.create_companion_record(&shared_id, &shared, 12)?;
    let neutral_created = neutral.created_at(10)?;
    let personal_created = personal.created_at(11)?;
    let shared_created = shared.created_at(12)?;
    assert_eq!(
        vault.get_companion_record(&neutral_id)?,
        Some(neutral_created.clone())
    );
    assert_eq!(
        vault.get_companion_record(&shared_id)?,
        Some(shared_created)
    );
    assert_eq!(
        vault.companion_record_id_for_key(&personal.key())?,
        Some(personal_id)
    );

    let duplicate_personal_id = entity(0x54);
    let duplicate = vault
        .create_companion_record(&duplicate_personal_id, &personal, 13)
        .expect_err("duplicate register key must fail closed");
    assert!(matches!(duplicate, Error::CompanionRecordAlreadyExists));
    let raw_duplicate = vault
        .batch()
        .put(
            &entity(0x56),
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 13, end: 13 },
            13,
            &encode_companion_record_body(&personal_created)?,
        )
        .commit()
        .expect_err("raw batch put must preserve companion register key uniqueness");
    assert!(matches!(raw_duplicate, Error::CompanionRecordAlreadyExists));

    let mut retired_create = neutral.clone();
    retired_create.lifecycle = ClaimLifecycleStatus::Retracted;
    let inactive_create = vault
        .create_companion_record(&entity(0x57), &retired_create, 13)
        .expect_err("create helper must not accept retired payloads");
    assert!(matches!(
        inactive_create,
        Error::InvalidClaimBody("companion record create must be active")
    ));

    let mut retired_update = personal.clone();
    retired_update.lifecycle = ClaimLifecycleStatus::Retracted;
    let inactive_update = vault
        .update_companion_record(&personal_id, &retired_update, 14)
        .expect_err("update helper must not retire records");
    assert!(matches!(
        inactive_update,
        Error::InvalidClaimBody("companion record update must be active")
    ));
    let raw_inactive_without_event = vault
        .batch()
        .put(
            &personal_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 14, end: 14 },
            14,
            &raw_companion_record_body(
                &personal_created,
                ClaimLifecycleStatus::Retracted,
                Vec::new(),
            )?,
        )
        .commit()
        .expect_err("raw batch put must not retire without lifecycle evidence");
    assert!(matches!(
        raw_inactive_without_event,
        Error::InvalidClaimBody("companion lifecycle events required for current schema")
    ));
    let raw_inactive_without_history = vault
        .batch()
        .put(
            &personal_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 14, end: 14 },
            14,
            &raw_companion_record_body(
                &personal_created,
                ClaimLifecycleStatus::Retracted,
                vec![CompanionLifecycleEvent::retired(14)],
            )?,
        )
        .commit()
        .expect_err("raw batch put must preserve lifecycle history when retiring");
    assert!(matches!(
        raw_inactive_without_history,
        Error::InvalidClaimBody("companion lifecycle events must preserve history")
    ));
    let mut tampered_personal_history = personal_created;
    tampered_personal_history.lifecycle_events = vec![CompanionLifecycleEvent::created(99)];
    let raw_history_erase = vault
        .batch()
        .put(
            &personal_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 14, end: 14 },
            14,
            &encode_companion_record_body(&tampered_personal_history)?,
        )
        .commit()
        .expect_err("raw batch put must not rewrite lifecycle history");
    assert!(matches!(
        raw_history_erase,
        Error::InvalidClaimBody("companion lifecycle events cannot change through update")
    ));

    let mut updated_personal = personal;
    updated_personal.value = Value::Map(vec![(
        Value::from("note"),
        Value::from("updated-private-note"),
    )]);
    let updated_personal = vault.update_companion_record(&personal_id, &updated_personal, 14)?;
    let stored_personal = vault
        .get_companion_record(&personal_id)?
        .expect("updated personal record");
    assert_eq!(stored_personal.value, updated_personal.value);
    assert_eq!(
        stored_personal.lifecycle_events,
        vec![CompanionLifecycleEvent::created(11)]
    );

    let register = vault.companion_register()?;
    assert_eq!(register.records_in_scope(&neutral_scope).count(), 1);
    assert_eq!(register.records_in_scope(&personal_scope).count(), 1);
    assert_eq!(register.records_in_scope(&shared_scope).count(), 1);

    let mut expressions = CompanionExpressionRegister::new();
    expressions.update(neutral.key(), CompanionExpression::Warm)?;
    expressions.update(updated_personal.key(), CompanionExpression::Unrestricted)?;
    expressions.update(shared.key(), CompanionExpression::Professional)?;
    let export = companion_export_layer(&register, &expressions);
    assert_eq!(export.len(), 1);
    assert_eq!(export.personas()[0].record(), &neutral_created);
    assert_eq!(
        export.personas()[0].expression(),
        Some(CompanionExpression::Warm)
    );

    let mut local_only_downgrade = neutral_created;
    local_only_downgrade.export_classification = CompanionExportClassification::LocalOnly;
    let downgrade_err = vault
        .update_companion_record(&neutral_id, &local_only_downgrade, 15)
        .expect_err("exported companion records must not silently downgrade to local_only");
    assert!(matches!(
        downgrade_err,
        Error::InvalidClaimBody("companion record export cannot be downgraded to local_only")
    ));
    let raw_downgrade = vault
        .batch()
        .put(
            &neutral_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 15, end: 15 },
            15,
            &encode_companion_record_body(&local_only_downgrade)?,
        )
        .commit()
        .expect_err("raw batch put must reject export downgrades");
    assert!(matches!(
        raw_downgrade,
        Error::InvalidClaimBody("companion record export cannot be downgraded to local_only")
    ));

    let retired = vault.retire_companion_record(&neutral_id, 15)?;
    assert_eq!(retired.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(
        retired.lifecycle_events,
        vec![
            CompanionLifecycleEvent::created(10),
            CompanionLifecycleEvent::retired(15)
        ]
    );
    let repeated_retire = vault.retire_companion_record(&neutral_id, 16)?;
    assert_eq!(repeated_retire, retired);
    let register = vault.companion_register()?;
    assert!(
        companion_export_layer(&register, &expressions).is_empty(),
        "retired neutral record and private/shared records must not export"
    );
    assert_eq!(
        register.lookup_persona(&neutral_scope, neutral_persona),
        None,
        "active register queries must exclude retired persona records"
    );
    let duplicate_after_retire = vault
        .create_companion_record(&entity(0x59), &neutral, 16)
        .expect_err("retired keys must require explicit revive");
    assert!(matches!(
        duplicate_after_retire,
        Error::CompanionRecordAlreadyExists
    ));

    let err = vault
        .update_companion_record(&neutral_id, &neutral, 16)
        .expect_err("retired records must not reactivate through update");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion record is retired")
    ));
    let raw_reactivation = vault
        .batch()
        .put(
            &neutral_id,
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange { start: 16, end: 16 },
            16,
            &encode_companion_record_body(&neutral.created_at(16)?)?,
        )
        .commit()
        .expect_err("raw batch put must not reactivate retired companion records");
    assert!(matches!(
        raw_reactivation,
        Error::InvalidClaimBody("companion record is retired")
    ));
    assert_eq!(vault.companion_record_id_for_key(&neutral.key())?, None);

    let active_revival = vault
        .revive_companion_record(&personal_id, &entity(0x58), &updated_personal, 16)
        .expect_err("active records must not revive without retirement");
    assert!(matches!(
        active_revival,
        Error::InvalidClaimBody("companion record revive requires retired record")
    ));

    let replacement_id = entity(0x55);
    let mut revive_payload = neutral;
    revive_payload.value = Value::from("fresh neutral @Oneiron");
    revive_payload.provenance = provenance(0xD4);
    let revived =
        vault.revive_companion_record(&neutral_id, &replacement_id, &revive_payload, 17)?;
    assert_eq!(revived.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(revived.value, Value::from("fresh neutral @Oneiron"));
    assert_eq!(revived.provenance, provenance(0xD4));
    assert_eq!(
        revived.lifecycle_events,
        vec![
            CompanionLifecycleEvent::created(10),
            CompanionLifecycleEvent::retired(15),
            CompanionLifecycleEvent::revived(17)
        ]
    );
    assert_eq!(
        vault.companion_record_id_for_key(&revived.key())?,
        Some(replacement_id)
    );
    assert_eq!(
        {
            let stored = vault
                .get_companion_record(&neutral_id)?
                .expect("retired record remains readable");
            assert_eq!(
                stored.lifecycle_events,
                vec![
                    CompanionLifecycleEvent::created(10),
                    CompanionLifecycleEvent::retired(15)
                ]
            );
            stored
        }
        .lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert_eq!(
        vault.get_companion_record(&replacement_id)?,
        Some(revived.clone())
    );
    let register = vault.companion_register()?;
    assert_eq!(register.records_in_scope(&neutral_scope).count(), 1);
    assert_eq!(
        register.lookup_persona(&neutral_scope, neutral_persona),
        Some(&revived)
    );
    Ok(())
}

#[test]
fn companion_relationship_end_scrubs_private_memory_preserves_data_and_enqueues_goodbye()
-> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let relationship_id = entity(0xA1);
    let general_id = entity(0xA2);
    let person_ref = entity(0xA3);
    let persona_ref = entity(0xA4);
    let scope = CompanionScope::personal(person_ref);
    let private_note = "private-relationship-note-one1488";
    let record = CompanionRecord::relationship(
        scope.clone(),
        person_ref,
        persona_ref,
        Value::Map(vec![(Value::from("note"), Value::from(private_note))]),
        provenance(0xA6),
        CompanionExportClassification::LocalOnly,
    );
    vault.create_companion_record(&relationship_id, &record, 10)?;
    vault
        .batch()
        .put(
            &general_id,
            ENTITY_TYPE_TURN,
            TimeRange { start: 11, end: 11 },
            11,
            b"general-vault-data",
        )
        .commit()?;

    let outcome = vault.end_companion_relationship(
        &relationship_id,
        EndCompanionRelationship {
            ended_at: 20,
            ended_badly: false,
            run_id: Some("run-goodbye-one1488".to_owned()),
        },
    )?;

    assert_eq!(outcome.record.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(!outcome.already_ended);
    assert_eq!(
        outcome.record.lifecycle_events,
        vec![
            CompanionLifecycleEvent::created(10),
            CompanionLifecycleEvent::retired(20)
        ]
    );
    let stored = vault
        .get_companion_record(&relationship_id)?
        .expect("ended relationship record remains auditable");
    assert_eq!(stored, outcome.record);
    let stored_json = companion_value_to_json(&stored.value);
    assert_eq!(stored_json["kind"], "relationship_ended");
    assert_eq!(stored_json["private_memory"], "removed");
    assert_eq!(stored_json["ended_at"], 20);
    assert!(
        !stored_json.to_string().contains(private_note),
        "ended relationship record must not retain private memory"
    );
    assert_eq!(
        vault.get(&general_id)?.as_deref(),
        Some(b"general-vault-data".as_slice()),
        "relationship teardown must not delete general vault data"
    );
    assert_eq!(vault.companion_record_id_for_key(&record.key())?, None);
    assert_eq!(
        vault
            .companion_register()?
            .lookup_relationship(&scope, person_ref, persona_ref),
        None,
        "ended relationship must not remain an active binding"
    );

    let task_status = match outcome.goodbye_artifact {
        Some(EnqueueCompanionTaskOutcome::Enqueued(status))
        | Some(EnqueueCompanionTaskOutcome::Existing(status)) => status,
        None => panic!("amicable ending must enqueue goodbye artifact task"),
    };
    assert_eq!(task_status.task.kind, CompanionTaskKind::GoodbyeArtifact);
    assert_eq!(task_status.task.key, record.key());
    assert_eq!(
        task_status.job.run_id.as_deref(),
        Some("run-goodbye-one1488")
    );
    let claimed = CompanionQueue::new(&vault).claim(ClaimCompanionTask {
        lease_owner: "goodbye-worker".to_owned(),
        now: 21,
    })?;
    let ClaimCompanionTaskOutcome::Claimed(claimed_status) = claimed else {
        panic!("goodbye artifact task must be claimable");
    };
    assert_eq!(claimed_status.task.kind, CompanionTaskKind::GoodbyeArtifact);
    assert_eq!(claimed_status.task.key, record.key());
    Ok(())
}

#[test]
fn companion_relationship_end_skips_goodbye_artifact_for_bad_end() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let relationship_id = entity(0xB1);
    let person_ref = entity(0xB2);
    let persona_ref = entity(0xB3);
    let scope = CompanionScope::personal(person_ref);
    let record = CompanionRecord::relationship(
        scope.clone(),
        person_ref,
        persona_ref,
        Value::Map(vec![(
            Value::from("note"),
            Value::from("bad-end-private-note-one1488"),
        )]),
        provenance(0xB4),
        CompanionExportClassification::LocalOnly,
    );
    vault.create_companion_record(&relationship_id, &record, 30)?;

    let outcome = vault.end_companion_relationship(
        &relationship_id,
        EndCompanionRelationship {
            ended_at: 40,
            ended_badly: true,
            run_id: Some("run-skipped-one1488".to_owned()),
        },
    )?;

    assert_eq!(outcome.record.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(!outcome.already_ended);
    assert!(outcome.goodbye_artifact.is_none());
    assert_eq!(
        vault
            .companion_register()?
            .lookup_relationship(&scope, person_ref, persona_ref),
        None
    );
    assert_eq!(
        CompanionQueue::new(&vault).claim(ClaimCompanionTask {
            lease_owner: "goodbye-worker".to_owned(),
            now: 41,
        })?,
        ClaimCompanionTaskOutcome::Empty
    );
    Ok(())
}

#[test]
fn companion_relationship_end_scrubs_already_retracted_record() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let relationship_id = entity(0xC1);
    let person_ref = entity(0xC2);
    let persona_ref = entity(0xC3);
    let scope = CompanionScope::personal(person_ref);
    let private_note = "already-retracted-private-note-one1488";
    let record = CompanionRecord::relationship(
        scope,
        person_ref,
        persona_ref,
        Value::Map(vec![(Value::from("note"), Value::from(private_note))]),
        provenance(0xC4),
        CompanionExportClassification::LocalOnly,
    );
    vault.create_companion_record(&relationship_id, &record, 50)?;
    vault.retire_companion_record(&relationship_id, 60)?;

    let outcome = vault.end_companion_relationship(
        &relationship_id,
        EndCompanionRelationship {
            ended_at: 70,
            ended_badly: false,
            run_id: Some("run-already-ended-one1488".to_owned()),
        },
    )?;

    assert!(outcome.already_ended);
    assert!(outcome.goodbye_artifact.is_none());
    assert_eq!(
        outcome.record.lifecycle_events,
        vec![
            CompanionLifecycleEvent::created(50),
            CompanionLifecycleEvent::retired(60)
        ],
        "idempotent end must preserve the original retire audit event"
    );
    let stored = vault
        .get_companion_record(&relationship_id)?
        .expect("scrubbed retracted relationship remains auditable");
    let stored_json = companion_value_to_json(&stored.value);
    assert_eq!(stored_json["kind"], "relationship_ended");
    assert_eq!(stored_json["private_memory"], "removed");
    assert_eq!(stored_json["ended_at"], 70);
    assert!(
        !stored_json.to_string().contains(private_note),
        "already retracted relationship must not retain private memory"
    );
    assert_eq!(
        CompanionQueue::new(&vault).claim(ClaimCompanionTask {
            lease_owner: "goodbye-worker".to_owned(),
            now: 71,
        })?,
        ClaimCompanionTaskOutcome::Empty,
        "idempotent end must not enqueue another goodbye task"
    );
    Ok(())
}

#[test]
fn companion_register_api_redacts_invalid_msgpack_strings() {
    let encoded = [0xA1, 0xFF];
    let mut cursor = &encoded[..];
    let value = rmpv::decode::read_value(&mut cursor).expect("decode invalid utf8 string");

    assert_eq!(
        companion_value_to_json(&value),
        serde_json::json!({ "redacted": "invalid_utf8_string" })
    );
}
