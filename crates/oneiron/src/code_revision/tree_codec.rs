//! The strict canonical encoding of a tested queue revision's blob map and
//! queue record, and their fold input (FIX 6868, G2 PR3).
//!
//! Both are required keys of the current revision schema: an ordinary
//! revision writes an empty map and nil, and folds exactly as before. A
//! queue revision folds every blob's path, object, hash, size and mode and
//! the whole queue record, never a summary of them.
use std::collections::BTreeMap;

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::tree_inventory::CodeTreeBlob;
use super::{CodePathRetirement, CodeRevision};
use crate::error::{ArtifactError, Error, Result};
use crate::merge_queue::QueueTestedRevision;

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid tested queue revision encoding",
    ))
}

/// The blob map as an array of `[path, oid, hash, size, mode]` in path order.
pub(super) fn blobs_to_value(blobs: &BTreeMap<String, CodeTreeBlob>) -> Value {
    Value::Array(
        blobs
            .iter()
            .map(|(path, blob)| {
                Value::Array(vec![
                    Value::from(path.as_str()),
                    Value::from(blob.git_oid.as_str()),
                    Value::Binary(blob.content_hash.to_vec()),
                    Value::from(blob.size_bytes),
                    Value::from(blob.mode),
                ])
            })
            .collect(),
    )
}

/// The blob map, in strictly ascending path order with no repeat.
pub(super) fn blobs_from_value(value: &Value) -> Result<BTreeMap<String, CodeTreeBlob>> {
    let entries = value.as_array().ok_or_else(invalid)?;
    let mut out = BTreeMap::new();
    let mut last: Option<String> = None;
    for entry in entries {
        let fields = entry
            .as_array()
            .filter(|fields| fields.len() == 5)
            .ok_or_else(invalid)?;
        let path = fields[0].as_str().ok_or_else(invalid)?.to_owned();
        if last.as_ref().is_some_and(|last| *last >= path) {
            return Err(invalid());
        }
        let Value::Binary(hash) = &fields[2] else {
            return Err(invalid());
        };
        let blob = CodeTreeBlob {
            git_oid: fields[1].as_str().ok_or_else(invalid)?.to_owned(),
            content_hash: hash.as_slice().try_into().map_err(|_| invalid())?,
            size_bytes: fields[3].as_u64().ok_or_else(invalid)?,
            mode: u32::try_from(fields[4].as_u64().ok_or_else(invalid)?).map_err(|_| invalid())?,
        };
        last = Some(path.clone());
        out.insert(path, blob);
    }
    Ok(out)
}

/// The queue record as one canonical named MessagePack binary, or nil.
pub(super) fn tested_to_value(tested: Option<&QueueTestedRevision>) -> Result<Value> {
    tested.map_or(Ok(Value::Nil), |tested| {
        rmp_serde::to_vec_named(tested)
            .map(Value::Binary)
            .map_err(|_| invalid())
    })
}

/// The queue record: nil, or one binary decoded whole, unknown fields and
/// trailing bytes refused.
pub(super) fn tested_from_value(value: &Value) -> Result<Option<QueueTestedRevision>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => {
            let mut cursor = std::io::Cursor::new(bytes);
            let tested: QueueTestedRevision =
                serde::Deserialize::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor))
                    .map_err(|_| invalid())?;
            if cursor.position() != bytes.len() as u64 {
                return Err(invalid());
            }
            Ok(Some(tested))
        }
        _ => Err(invalid()),
    }
}

/// Folds `revision`'s queue fields after its documents. An ordinary
/// revision adds nothing, so its fold is unchanged.
pub(super) fn hash_queue_fields(hasher: &mut Sha256, revision: &CodeRevision) -> Result<()> {
    if revision.blob_frontiers.is_empty() && revision.tested_queue.is_none() {
        return Ok(());
    }
    hasher.update(b"tested-queue-tree:v1");
    let blobs = super::codec::encode_value(
        &blobs_to_value(&revision.blob_frontiers),
        "tested tree blob encode",
    )?;
    let tested = super::codec::encode_value(
        &tested_to_value(revision.tested_queue.as_ref())?,
        "tested queue record encode",
    )?;
    for part in [blobs, tested] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Ok(())
}

/// The retired paths as an array of `[path, retirement]` in path order,
/// each retirement one canonical named MessagePack binary (G4 PR1).
pub(super) fn retirements_to_value(
    retired: &BTreeMap<String, CodePathRetirement>,
) -> Result<Value> {
    retired
        .iter()
        .map(|(path, retirement)| {
            let encoded = rmp_serde::to_vec_named(retirement).map_err(|_| invalid())?;
            Ok(Value::Array(vec![
                Value::from(path.as_str()),
                Value::Binary(encoded),
            ]))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

/// The retired paths, in strictly ascending path order with no repeat,
/// each retirement decoded whole: unknown fields and trailing bytes
/// refused.
pub(super) fn retirements_from_value(
    value: &Value,
) -> Result<BTreeMap<String, CodePathRetirement>> {
    let entries = value.as_array().ok_or_else(invalid)?;
    let mut out = BTreeMap::new();
    let mut last: Option<String> = None;
    for entry in entries {
        let fields = entry
            .as_array()
            .filter(|fields| fields.len() == 2)
            .ok_or_else(invalid)?;
        let path = fields[0].as_str().ok_or_else(invalid)?.to_owned();
        if last.as_ref().is_some_and(|last| *last >= path) {
            return Err(invalid());
        }
        let Value::Binary(bytes) = &fields[1] else {
            return Err(invalid());
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let retirement: CodePathRetirement =
            serde::Deserialize::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor))
                .map_err(|_| invalid())?;
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid());
        }
        last = Some(path.clone());
        out.insert(path, retirement);
    }
    Ok(out)
}

/// Folds `revision`'s import binding and retired paths after its queue
/// fields. A revision with neither adds nothing, so every existing fold,
/// ordinary or queue, is unchanged (G4 PR1).
pub(super) fn hash_import_fields(hasher: &mut Sha256, revision: &CodeRevision) -> Result<()> {
    if revision.snapshot_anchor.is_none() && revision.retired_paths.is_empty() {
        return Ok(());
    }
    hasher.update(b"code-import-binding:v1");
    let anchor = super::codec::encode_value(
        &super::codec::optional_entity_value(revision.snapshot_anchor),
        "import anchor encode",
    )?;
    let retired = super::codec::encode_value(
        &retirements_to_value(&revision.retired_paths)?,
        "retired paths encode",
    )?;
    for part in [anchor, retired] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Ok(())
}
