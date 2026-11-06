//! Move native model metadata through the core SDK result boundary.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::llm::catalog_doors::{ModelCatalogDiff, ModelCatalogRevision};
use crate::llm::registry::ModelRegistryRow;
use crate::memory::MemoryResult;

use super::encode;

type Metadata = BTreeMap<String, Value>;

pub(super) fn revision(mut output: ModelCatalogRevision) -> MemoryResult<Value> {
    let catalog_metadata: Vec<_> = output.catalog.rows.iter_mut().map(take_metadata).collect();
    let row_metadata: Vec<_> = output.rows.iter_mut().map(take_metadata).collect();
    let mut encoded = encode(output)?;
    for (index, metadata) in catalog_metadata.into_iter().enumerate() {
        restore_metadata(&mut encoded["catalog"]["rows"][index], metadata);
    }
    for (index, metadata) in row_metadata.into_iter().enumerate() {
        restore_metadata(&mut encoded["rows"][index], metadata);
    }
    Ok(encoded)
}

pub(super) fn diff(mut output: ModelCatalogDiff) -> MemoryResult<Value> {
    let metadata: Vec<_> = output
        .changes
        .iter_mut()
        .map(|change| {
            (
                change.previous.as_mut().map(take_metadata),
                change.current.as_mut().map(take_metadata),
            )
        })
        .collect();
    let mut encoded = encode(output)?;
    for (index, (previous, current)) in metadata.into_iter().enumerate() {
        if let Some(metadata) = previous {
            restore_metadata(&mut encoded["changes"][index]["previous"], metadata);
        }
        if let Some(metadata) = current {
            restore_metadata(&mut encoded["changes"][index]["current"], metadata);
        }
    }
    Ok(encoded)
}

fn take_metadata(row: &mut ModelRegistryRow) -> Metadata {
    std::mem::take(&mut row.catalog.metadata)
}

fn restore_metadata(encoded: &mut Value, metadata: Metadata) {
    if !metadata.is_empty() {
        encoded["catalog"]["metadata"] = Value::Object(metadata.into_iter().collect());
    }
}
