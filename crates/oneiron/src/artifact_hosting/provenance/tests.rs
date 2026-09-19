use super::*;
use crate::blob_artifact::BlobArtifactBody;
use crate::code_artifact::{CodeArtifactBody, CodeArtifactClass};
use crate::edge::EdgeActorClass;

fn at(n: u64) -> TimeRange {
    TimeRange { start: n, end: n }
}
fn fixture(vault: &Vault) -> Result<(WriteActor, ArtifactBirthEnvelope)> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"maker",
    )?;
    let task = EntityId::now();
    vault.put_entity(
        &task,
        ENTITY_TYPE_TASK,
        at(1),
        1,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;
    let prompt_ref = EntityId::now();
    vault.put_entity(
        &prompt_ref,
        crate::registry::ENTITY_TYPE_ASSET_TEXT,
        at(1),
        1,
        b"Create a report",
    )?;
    Ok((
        WriteActor::new(actor, EdgeActorClass::Human),
        ArtifactBirthEnvelope {
            trigger: ArtifactTrigger::Task(task),
            prompt_ref,
            run_ref: Some("run:report".into()),
            content_hash: *blake3::hash(b"Create a report").as_bytes(),
            model_id: "fixture/model".into(),
            version: "fixture/v1".into(),
            params_hash: *blake3::hash(b"parameters").as_bytes(),
            purpose: ArtifactPurpose::Deliverable,
        },
    ))
}

#[test]
fn task_and_run_reverse_views_share_the_artifact_birth_ledger_for_both_kinds() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (actor, birth) = fixture(&vault)?;
    let blob = EntityId::now();
    let code = EntityId::now();
    let blob_body = BlobArtifactBody::new("report.pdf", "application/pdf");
    let code_body = CodeArtifactBody::new(
        "a report",
        [7; 32],
        "github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277",
    )
    .with_class(CodeArtifactClass::Artifact);
    for (artifact, body) in [
        (blob, ArtifactBirthBody::Blob(&blob_body)),
        (code, ArtifactBirthBody::Code(&code_body)),
    ] {
        let ledger = vault.create_artifact_with_birth(artifact, body, &birth, actor, at(2), 2)?;
        let projected = vault.artifact_birth(artifact)?.expect("birth");
        assert_eq!(projected.made_by, birth);
        assert_eq!(projected.ledger_ref, ledger);
        assert_eq!(projected.kind.family_id(), "artifact");
    }
    let task_artifacts = vault.artifacts_born_from(&birth.trigger, 20)?;
    let run_artifacts =
        vault.artifacts_born_from(&ArtifactTrigger::Run("run:report".into()), 20)?;
    assert_eq!(task_artifacts, run_artifacts);
    let ids: std::collections::BTreeSet<_> = task_artifacts.iter().map(|p| p.artifact_id).collect();
    assert_eq!(ids, [blob, code].into_iter().collect());
    assert_eq!(vault.artifacts_born_from(&birth.trigger, 1)?.len(), 1);
    assert!(vault.artifacts_born_from(&birth.trigger, 0).is_err());
    assert!(
        vault
            .artifacts_born_from(&ArtifactTrigger::Run("run:other".into()), 20)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn reports_and_skill_candidates_land_as_proposals_and_birth_is_immutable() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (actor, mut birth) = fixture(&vault)?;
    for purpose in [
        ArtifactPurpose::SkillReport,
        ArtifactPurpose::SkillCandidate,
    ] {
        birth.purpose = purpose;
        let artifact = EntityId::now();
        let body = BlobArtifactBody::new("proposal.txt", "text/plain");
        let id = vault.create_artifact_with_birth(
            artifact,
            ArtifactBirthBody::Blob(&body),
            &birth,
            actor,
            at(2),
            2,
        )?;
        assert_eq!(
            vault.artifact_birth(artifact)?.unwrap().approval_status,
            ClaimApprovalStatus::Proposed
        );
        assert_eq!(
            vault.create_artifact_with_birth(
                artifact,
                ArtifactBirthBody::Blob(&body),
                &birth,
                actor,
                at(3),
                3
            )?,
            id
        );
        let mut replacement = birth.clone();
        replacement.version = "other".into();
        assert!(matches!(
            vault.create_artifact_with_birth(
                artifact,
                ArtifactBirthBody::Blob(&body),
                &replacement,
                actor,
                at(3),
                3
            ),
            Err(Error::Artifact(ArtifactError::InvalidArtifactBirth(_)))
        ));
        assert_eq!(vault.artifact_birth(artifact)?.unwrap().made_by, birth);
    }
    Ok(())
}

#[test]
fn missing_or_substituted_birth_inputs_roll_back_artifact_creation() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (actor, birth) = fixture(&vault)?;
    for mutation in 0..3 {
        let mut invalid = birth.clone();
        match mutation {
            0 => invalid.prompt_ref = EntityId::now(),
            1 => invalid.content_hash = [0; 32],
            _ => invalid.trigger = ArtifactTrigger::Task(birth.prompt_ref),
        }
        let artifact = EntityId::now();
        let body = BlobArtifactBody::new("not-created", "text/plain");
        assert!(
            vault
                .create_artifact_with_birth(
                    artifact,
                    ArtifactBirthBody::Blob(&body),
                    &invalid,
                    actor,
                    at(2),
                    2
                )
                .is_err()
        );
        assert!(vault.get_blob_artifact(&artifact)?.is_none());
        assert!(vault.artifact_birth(artifact)?.is_none());
    }
    Ok(())
}

#[test]
fn typed_imports_have_upload_asks_but_raw_artifact_creation_is_refused() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let body = BlobArtifactBody::new("upload.txt", "text/plain");
    let artifact = EntityId::now();
    vault.put_blob_artifact(&artifact, &body, at(1), 1)?;
    let birth = vault
        .artifact_birth(artifact)?
        .expect("typed upload has a birth");
    let ArtifactTrigger::Ask(input) = birth.made_by.trigger else {
        panic!("upload is not an invented task");
    };
    assert_eq!(birth.made_by.prompt_ref, input);
    assert_eq!(
        vault.artifacts_born_from(&ArtifactTrigger::Ask(input), 10)?,
        vec![birth.clone()]
    );
    vault.put_blob_artifact(&artifact, &body, at(2), 2)?;
    assert_eq!(vault.artifact_birth(artifact)?, Some(birth));
    let raw = crate::blob_artifact::encode_blob_artifact_body(&body)?;
    for transactional in [false, true] {
        let id = EntityId::now();
        let result = if transactional {
            vault.with_write_txn(|txn| {
                vault
                    .batch_in()
                    .put(
                        &id,
                        crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                        at(1),
                        1,
                        &raw,
                    )
                    .apply(txn)
            })
        } else {
            vault.put_entity(
                &id,
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                at(1),
                1,
                &raw,
            )
        };
        assert!(matches!(
            result,
            Err(Error::Artifact(ArtifactError::InvalidArtifactBirth(_)))
        ));
        assert!(vault.get_blob_artifact(&id)?.is_none());
    }
    Ok(())
}

#[test]
fn attributed_birth_and_first_export_roll_back_together() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (actor, _) = fixture(&vault)?;
    let artifact = EntityId::now();
    let body = BlobArtifactBody::new("empty.txt", "text/plain");
    let result = vault.with_write_txn(|txn| {
        vault.persist_blob_with_birth_in_txn(
            txn,
            artifact,
            &body,
            &[],
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            at(2),
            2,
        )
    });
    assert!(result.is_err());
    assert!(vault.get_blob_artifact(&artifact)?.is_none());
    assert!(vault.artifact_birth(artifact)?.is_none());
    assert!(vault.blob_artifact_head(&artifact)?.is_none());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_birth_dependencies_retry_before_artifact_materializes() -> Result<()> {
    let (_source_dir, source) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (_target_dir, target) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (actor, birth) = fixture(&source)?;
    let artifact = EntityId::now();
    let body = BlobArtifactBody::new("replicated.txt", "text/plain");
    let ledger = source.create_artifact_with_birth(
        artifact,
        ArtifactBirthBody::Blob(&body),
        &birth,
        actor,
        at(2),
        2,
    )?;
    let data = source.get(&artifact)?.expect("artifact bytes");
    let ledger_data = source.get(&ledger)?.expect("birth bytes");
    let error = target
        .batch()
        .put_replicated(
            &artifact,
            crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
            at(2),
            2,
            &data,
        )
        .commit()
        .expect_err("birth must arrive first");
    assert!(artifact_birth_dependency_pending(&error));
    let error = target
        .batch()
        .put_replicated(&ledger, ENTITY_TYPE_CLAIM, at(2), 2, &ledger_data)
        .commit()
        .expect_err("input must arrive first");
    assert!(artifact_birth_dependency_pending(&error));
    let ArtifactTrigger::Task(task) = birth.trigger else {
        unreachable!()
    };
    for id in [actor.entity_ref(), task, birth.prompt_ref] {
        target.put_entity(
            &id,
            source.get_entity_type(&id)?.expect("input kind"),
            at(1),
            1,
            &source.get(&id)?.expect("input bytes"),
        )?;
    }
    target
        .batch()
        .put_replicated(&ledger, ENTITY_TYPE_CLAIM, at(2), 2, &ledger_data)
        .put_replicated(
            &artifact,
            crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
            at(2),
            2,
            &data,
        )
        .commit()?;
    assert_eq!(
        target.artifact_birth(artifact)?,
        source.artifact_birth(artifact)?
    );
    Ok(())
}
