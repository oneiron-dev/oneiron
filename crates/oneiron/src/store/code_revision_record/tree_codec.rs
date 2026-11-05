//! Core half of `store::code_revision_record::tree_codec`: its store-layer items live in `oneiron_store::code_revision_record::tree_codec` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::code_revision_record::tree_codec::*;

use super::{CodePathRetirement, CodeRevision};
use crate::error::{ArtifactError, Error, Result};
use crate::merge_queue::QueueTestedRevision;
use crate::store::code_tree_blob::CodeTreeBlob;
use rmpv::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The queue record as one canonical named MessagePack binary, or nil.
pub(crate) fn tested_to_value(tested: Option<&QueueTestedRevision>) -> Result<Value> {
    tested.map_or(Ok(Value::Nil), |tested| {
        rmp_serde::to_vec_named(tested)
            .map(Value::Binary)
            .map_err(|_| invalid())
    })
}

/// The queue record: nil, or one binary decoded whole, unknown fields and
/// trailing bytes refused.
pub(crate) fn tested_from_value(value: &Value) -> Result<Option<QueueTestedRevision>> {
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
pub(crate) fn hash_queue_fields(hasher: &mut Sha256, revision: &CodeRevision) -> Result<()> {
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

/// Folds `revision`'s import binding and retired paths after its queue
/// fields. A revision with neither adds nothing, so every existing fold,
/// ordinary or queue, is unchanged (G4 PR1).
pub(crate) fn hash_import_fields(hasher: &mut Sha256, revision: &CodeRevision) -> Result<()> {
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
