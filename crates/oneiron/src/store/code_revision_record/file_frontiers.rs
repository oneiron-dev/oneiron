//! Core half of `store::code_revision_record::file_frontiers`: its store-layer items live in `oneiron_store::code_revision_record::file_frontiers` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::code_revision_record::file_frontiers::*;

use super::CodeRevision;
use crate::error::{ArtifactError, Error, Result};
use crate::store::code_document_values::CodeDocumentFrontier;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn validate(revision: &CodeRevision) -> Result<()> {
    let mut paths = BTreeSet::new();
    for (id, frontier) in &revision.file_frontiers {
        if id != &frontier.document_id
            || !paths.insert((&frontier.repo, &frontier.path))
            || frontier.version.is_empty()
            || frontier.version.iter().any(|(_, c)| *c <= 0)
            || frontier.version.windows(2).any(|w| w[0].0 >= w[1].0)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn to_value(revision: &CodeRevision) -> Result<Value> {
    revision
        .file_frontiers
        .values()
        .map(|f| {
            Ok(Value::Binary(
                rmp_serde::to_vec_named(f).map_err(|_| invalid())?,
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}
