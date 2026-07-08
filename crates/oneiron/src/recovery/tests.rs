use super::*;

const ARTIFACT_TYPE_FIXTURE: u16 = 42;

fn assert_invalid_suffix(path: &Path, original: &Path, suffix: u16) {
    let mut expected = original
        .file_name()
        .and_then(|name| name.to_str())
        .expect("test artifact path is valid UTF-8")
        .to_owned();
    expected.push_str(&format!(
        "{RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX}{suffix}"
    ));
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(expected.as_str())
    );
}

#[test]
fn valid_artifact_loads_after_header_and_checksum_validation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    fs::write(
        &artifact_path,
        encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?,
    )?;

    let RecoveryArtifactLoad::Ready(artifact) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("valid artifact should load");
    };

    assert_eq!(artifact.artifact_type(), ARTIFACT_TYPE_FIXTURE);
    assert_eq!(artifact.payload(), b"payload");
    assert!(artifact_path.exists(), "valid artifact stays in place");
    assert!(
        !invalid_artifact_path(&artifact_path, 1).exists(),
        "valid artifact must not create quarantine state"
    );
    Ok(())
}

#[test]
fn corrupt_magic_artifact_quarantines_without_losing_bytes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    corrupt[0] = b'X';
    fs::write(&artifact_path, &corrupt)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("bad magic artifact should quarantine");
    };

    let mut found = RECOVERY_ARTIFACT_MAGIC;
    found[0] = b'X';
    assert_eq!(
        quarantined.failure,
        RecoveryArtifactFailure::MagicMismatch { found }
    );
    assert!(!artifact_path.exists(), "invalid source is moved aside");
    assert_eq!(fs::read(&quarantined.quarantine_path)?, corrupt);
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn corrupt_checksum_artifact_quarantines_without_losing_bytes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    let last = corrupt.last_mut().expect("fixture has payload");
    *last ^= 0x01;
    fs::write(&artifact_path, &corrupt)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("corrupt artifact should quarantine");
    };

    assert_eq!(
        quarantined.failure,
        RecoveryArtifactFailure::ChecksumMismatch {
            expected: recovery_artifact_checksum(ARTIFACT_TYPE_FIXTURE, b"payload"),
            actual: recovery_artifact_checksum(ARTIFACT_TYPE_FIXTURE, &corrupt[HEADER_LEN..]),
        }
    );
    assert!(!artifact_path.exists(), "invalid source is moved aside");
    assert_eq!(fs::read(&quarantined.quarantine_path)?, corrupt);
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn artifact_type_tamper_quarantines_as_checksum_mismatch() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("type-tamper.oneiron-artifact");
    let mut tampered = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    let tampered_type = ARTIFACT_TYPE_FIXTURE + 1;
    tampered[KIND_OFFSET..LEN_OFFSET].copy_from_slice(&tampered_type.to_le_bytes());
    fs::write(&artifact_path, &tampered)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("type-tampered artifact should quarantine");
    };

    assert_eq!(
        quarantined.failure,
        RecoveryArtifactFailure::ChecksumMismatch {
            expected: recovery_artifact_checksum(ARTIFACT_TYPE_FIXTURE, b"payload"),
            actual: recovery_artifact_checksum(tampered_type, b"payload"),
        }
    );
    assert!(!artifact_path.exists(), "tampered source is moved aside");
    assert_eq!(fs::read(&quarantined.quarantine_path)?, tampered);
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn valid_artifact_with_unexpected_type_quarantines_without_use() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("wrong-type.oneiron-artifact");
    let encoded = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE + 1, b"payload")?;
    fs::write(&artifact_path, &encoded)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("wrong typed artifact should quarantine");
    };

    assert_eq!(
        quarantined.failure,
        RecoveryArtifactFailure::UnexpectedType {
            found: ARTIFACT_TYPE_FIXTURE + 1,
            expected: ARTIFACT_TYPE_FIXTURE,
        }
    );
    assert!(!artifact_path.exists(), "unexpected source is moved aside");
    assert_eq!(fs::read(&quarantined.quarantine_path)?, encoded);
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn repeated_invalid_artifact_quarantine_is_idempotent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    corrupt[HEADER_LEN] ^= 0x01;
    fs::write(&artifact_path, &corrupt)?;

    let RecoveryArtifactLoad::Quarantined(first) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("first corrupt artifact should quarantine");
    };

    fs::write(&artifact_path, &corrupt)?;
    let RecoveryArtifactLoad::Quarantined(second) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("second corrupt artifact should return typed quarantine");
    };

    assert_eq!(second.quarantine_path, first.quarantine_path);
    assert_eq!(fs::read(&second.quarantine_path)?, corrupt);
    assert!(!artifact_path.exists(), "second source is removed");
    assert_invalid_suffix(&second.quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn quarantine_uses_next_invalid_suffix_for_distinct_existing_bytes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    corrupt[HEADER_LEN] ^= 0x01;
    fs::write(
        invalid_artifact_path(&artifact_path, 1),
        b"previous invalid bytes",
    )?;
    fs::write(&artifact_path, &corrupt)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("corrupt artifact should quarantine");
    };

    assert_eq!(fs::read(&quarantined.quarantine_path)?, corrupt);
    assert!(!artifact_path.exists(), "fallback source is removed");
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 2);
    Ok(())
}

#[cfg(unix)]
#[test]
fn quarantine_skips_symlink_candidate_to_preserve_bytes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    corrupt[HEADER_LEN] ^= 0x01;
    fs::write(&artifact_path, &corrupt)?;
    std::os::unix::fs::symlink(&artifact_path, invalid_artifact_path(&artifact_path, 1))?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("corrupt artifact should quarantine");
    };

    assert_eq!(fs::read(&quarantined.quarantine_path)?, corrupt);
    assert!(!artifact_path.exists(), "source is removed after fallback");
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 2);
    Ok(())
}

#[test]
fn quarantine_preserves_validated_bytes_when_source_changes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("race.oneiron-artifact");
    let mut validated_bad = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    validated_bad[HEADER_LEN] ^= 0x01;
    let concurrently_written = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"new")?;
    fs::write(&artifact_path, &concurrently_written)?;

    let quarantine_path = quarantine_invalid_artifact(&artifact_path, &validated_bad)?;

    assert_eq!(
        fs::read(&quarantine_path)?,
        validated_bad,
        "quarantine keeps the bytes that drove validation"
    );
    assert_eq!(
        fs::read(&artifact_path)?,
        concurrently_written,
        "changed source bytes are not removed after quarantine"
    );
    assert_invalid_suffix(&quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn unsupported_artifact_version_quarantines_without_use() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("future.oneiron-artifact");
    let mut future = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    future[VERSION_OFFSET..KIND_OFFSET]
        .copy_from_slice(&(RECOVERY_ARTIFACT_VERSION + 1).to_le_bytes());
    fs::write(&artifact_path, &future)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("unsupported artifact should quarantine");
    };

    assert_eq!(
        quarantined.failure,
        RecoveryArtifactFailure::UnsupportedVersion {
            found: RECOVERY_ARTIFACT_VERSION + 1,
            supported: RECOVERY_ARTIFACT_VERSION,
        }
    );
    assert!(!artifact_path.exists(), "unsupported source is moved aside");
    assert_eq!(fs::read(&quarantined.quarantine_path)?, future);
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path, 1);
    Ok(())
}

#[test]
fn decode_error_exposes_recovery_reason() -> Result<()> {
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    corrupt[HEADER_LEN] ^= 0x01;

    let err = decode_recovery_artifact(&corrupt, ARTIFACT_TYPE_FIXTURE)
        .expect_err("bad checksum must fail closed");

    assert!(matches!(
        err,
        Error::InvalidRecoveryArtifact("artifact checksum mismatch")
    ));
    Ok(())
}
