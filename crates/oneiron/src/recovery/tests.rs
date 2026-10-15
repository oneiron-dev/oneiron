use super::*;

const ARTIFACT_TYPE_FIXTURE: u16 = 42;

/// `path` is a quarantine sibling of `original`: its name plus the invalid
/// prefix and 16 random hex digits (F33).
fn assert_invalid_suffix(path: &Path, original: &Path) {
    let mut prefix = original
        .file_name()
        .and_then(|name| name.to_str())
        .expect("test artifact path is valid UTF-8")
        .to_owned();
    prefix.push_str(RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("quarantine path is valid UTF-8");
    let suffix = name.strip_prefix(&prefix).expect("quarantine sibling name");
    assert_eq!(path.parent(), original.parent());
    assert!(
        suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{name}"
    );
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
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
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
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
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
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
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
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
    Ok(())
}

#[test]
fn repeated_invalid_artifact_quarantine_preserves_each_original() -> Result<()> {
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

    assert_ne!(second.quarantine_path, first.quarantine_path);
    assert_eq!(fs::read(&first.quarantine_path)?, corrupt);
    assert_eq!(fs::read(&second.quarantine_path)?, corrupt);
    assert!(!artifact_path.exists(), "second source is removed");
    assert_invalid_suffix(&second.quarantine_path, &artifact_path);
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
    let planted = invalid_artifact_path(&artifact_path, "1");
    std::os::unix::fs::symlink(&artifact_path, &planted)?;

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("corrupt artifact should quarantine");
    };

    assert_eq!(fs::read(&quarantined.quarantine_path)?, corrupt);
    assert!(!artifact_path.exists(), "source is removed after fallback");
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
    assert!(fs::symlink_metadata(&planted)?.file_type().is_symlink());
    Ok(())
}

/// F33 (H57): a writer in the artifact directory holding every name the old
/// quarantine probed (`.invalid-1` to `.invalid-65535`, a directory at the
/// first) cannot stop quarantine: the artifact moves to a fresh random name
/// and every foreign leaf stays as it was.
#[test]
fn quarantine_survives_a_reserved_predictable_name_range() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_path = dir.path().join("snapshot.oneiron-artifact");
    let mut corrupt = encode_recovery_artifact(ARTIFACT_TYPE_FIXTURE, b"payload")?;
    corrupt[HEADER_LEN] ^= 0x01;
    fs::write(&artifact_path, &corrupt)?;
    let reserved = |n: u16| {
        dir.path().join(format!(
            "snapshot.oneiron-artifact{RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX}{n}"
        ))
    };
    fs::create_dir(reserved(1))?;
    for n in 2..=u16::MAX {
        fs::File::create(reserved(n))?;
    }

    let RecoveryArtifactLoad::Quarantined(quarantined) =
        load_recovery_artifact(&artifact_path, ARTIFACT_TYPE_FIXTURE)?
    else {
        panic!("corrupt artifact should quarantine");
    };

    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
    assert_eq!(fs::read(&quarantined.quarantine_path)?, corrupt);
    assert!(!artifact_path.exists(), "source is removed");
    assert!(reserved(1).is_dir());
    assert_eq!(fs::read(reserved(u16::MAX))?, b"");
    assert_eq!(
        fs::read_dir(dir.path())?.count(),
        usize::from(u16::MAX) + 1,
        "every foreign leaf stays, beside the quarantined artifact"
    );
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

    assert!(matches!(
        quarantine_invalid_artifact(&artifact_path, &validated_bad),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(fs::read(&artifact_path)?, concurrently_written);
    assert!(invalid_artifact_siblings(&artifact_path).is_empty());
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
    assert_invalid_suffix(&quarantined.quarantine_path, &artifact_path);
    Ok(())
}
