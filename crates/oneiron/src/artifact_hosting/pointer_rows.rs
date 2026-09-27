use super::*;

pub(super) fn put_artifact_pointer_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &str,
    channel: ArtifactPointerChannel,
    export: ArtifactExportRef,
    stale_taint_override: bool,
) -> Result<()> {
    validate_artifact_id(artifact)?;
    ARTIFACT_POINTERS.put(
        store,
        wtxn,
        &ArtifactPointerRowKey {
            channel,
            artifact: artifact.to_owned(),
        },
        &ArtifactPointerRow {
            export,
            stale_taint_override,
        },
    )
}

/// A deleted blob must not leave a channel that can spring back to life.
pub(crate) fn remove_blob_pointers_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let artifact = id.to_hex();
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        let key = ArtifactPointerRowKey {
            channel,
            artifact: artifact.clone(),
        };
        if let Some(row) = ARTIFACT_POINTERS.get(store, wtxn, &key)?
            && matches!(row.export,
                ArtifactExportRef::BlobVersion { artifact_id, .. } if artifact_id == *id)
        {
            ARTIFACT_POINTERS.delete(store, wtxn, &key)?;
        }
    }
    Ok(())
}

pub(super) fn decode_artifact_pointer_row(raw: &[u8]) -> Result<(ArtifactExportRef, bool)> {
    let (export, stamp) = match raw.len() {
        32 | 33 => {
            let hash = raw[..CODEBASE_FORK_HASH_LEN]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact pointer fork hash"))?;
            (
                ArtifactExportRef::ForkHash(hash),
                raw.get(CODEBASE_FORK_HASH_LEN),
            )
        }
        25 | 26 => {
            if raw[0] != ARTIFACT_POINTER_BLOB_TAG {
                return Err(Error::CorruptedIndex("artifact pointer blob tag"));
            }
            let id = raw[1..17]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact pointer blob id"))?;
            let artifact_id = EntityId::from_bytes(id)
                .map_err(|_| Error::CorruptedIndex("artifact pointer blob id"))?;
            let version = u64::from_be_bytes(
                raw[17..25]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("artifact pointer blob version"))?,
            );
            if version == 0 {
                return Err(Error::CorruptedIndex("artifact pointer blob version"));
            }
            (
                ArtifactExportRef::BlobVersion {
                    artifact_id,
                    version,
                },
                raw.get(25),
            )
        }
        _ => return Err(Error::CorruptedIndex("artifact pointer frame")),
    };
    if stamp.is_some_and(|byte| *byte != ARTIFACT_POINTER_STALE_OVERRIDE_STAMP) {
        return Err(Error::CorruptedIndex("artifact pointer taint stamp"));
    }
    Ok((export, stamp.is_some()))
}

pub(super) fn snapshot_file_entry<'a>(
    snapshot: &'a CodebaseSnapshot,
    path: &str,
) -> Option<&'a CodebaseFileEntry> {
    let Ok(index) = snapshot
        .files
        .binary_search_by(|entry| entry.path.as_str().cmp(path))
    else {
        return None;
    };
    snapshot.files.get(index)
}

pub(crate) fn validate_artifact_id(artifact: &str) -> Result<()> {
    validate_bounded_text(
        artifact,
        CODEBASE_PROJECT_ID_MAX_BYTES,
        "artifact id must be non-empty and at most 256 bytes",
    )?;
    if artifact.trim() != artifact {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact id must not have leading or trailing whitespace",
        )));
    }
    Ok(())
}

pub(super) fn validate_artifact_path(path: &str) -> Result<()> {
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "artifact path must be non-empty and at most 4096 bytes",
    )?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact path must be bundle-relative",
        )));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact path must be normalized and cannot contain . or .. segments",
        )));
    }
    Ok(())
}

fn validate_bounded_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(context)));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact text fields must not contain control characters",
        )));
    }
    Ok(())
}

pub(super) fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
