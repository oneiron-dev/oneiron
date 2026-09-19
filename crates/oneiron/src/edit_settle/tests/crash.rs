use super::*;

#[test]
fn interrupted_settlement_reopens_without_partial_bytes_or_receipt_and_retries_once() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "edit_settle::tests::crash::crash_after_bytes_before_commit",
            "--ignored",
        ])
        .env("ONEIRON_SETTLE_CRASH_FIXTURE", dir.path())
        .status()?;
    assert_eq!(status.code(), Some(91));
    let ids = std::fs::read_to_string(dir.path().join("fixture-ids"))?;
    let mut lines = ids.lines();
    let artifact = EntityId::from_hex(lines.next().expect("artifact id"))?;
    let person = EntityId::from_hex(lines.next().expect("actor id"))?;
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let vault = Vault::open(dir.path().join("vault"), embedding_test_config())?;
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)?
            .map(|head| head.version),
        Some(1)
    );
    assert_eq!(vault.read_blob_artifact_version(&artifact, 2)?, None);
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "run:crash")?
            .is_none()
    );
    let prop = proposal("run:crash", b"durable edited bytes", Vec::new());
    let selected =
        vault.settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(12), 12)?;
    assert_eq!(selected.version.version, 2);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 2)?.as_deref(),
        Some(b"durable edited bytes".as_slice())
    );
    let err = vault
        .settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(13), 13)
        .expect_err("consume once");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::EditProposalAlreadySettled { .. })
    ));
    drop(vault);
    let reopened = Vault::open(dir.path().join("vault"), embedding_test_config())?;
    assert_eq!(reopened.blob_artifact_versions(&artifact)?.len(), 2);
    assert!(
        reopened
            .blob_artifact_settlement(&artifact, "run:crash")?
            .is_some()
    );
    Ok(())
}

#[test]
#[ignore = "isolated crash process, executed by the parent acceptance test"]
fn crash_after_bytes_before_commit() -> Result<()> {
    let path = std::path::PathBuf::from(
        std::env::var_os("ONEIRON_SETTLE_CRASH_FIXTURE").expect("crash parent"),
    );
    let vault = Vault::open(path.join("vault"), embedding_test_config())?;
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    std::fs::write(
        path.join("fixture-ids"),
        format!("{}\n{}\n", artifact.to_hex(), actor.entity_ref().to_hex()),
    )?;
    // Ensure the committed base is durable before killing the process with an
    // uncommitted output version. exit() deliberately runs no Rust destructors.
    vault.store.env.force_sync()?;
    vault
        .test_hooks()
        .install_edit_settle_after_bytes(|| std::process::exit(91));
    let prop = proposal("run:crash", b"durable edited bytes", Vec::new());
    vault.settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(11), 11)?;
    panic!("crash seam was not reached")
}
