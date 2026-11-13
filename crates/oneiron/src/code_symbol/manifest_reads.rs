//! Symbol manifest reads in a caller's transaction (FIX 4300,
//! CODE-CUSTODY-01).
//!
//! A run's repository read joins the selected snapshot's own manifest in the
//! snapshot it serves from. The codebase scope index keeps one row for each
//! symbol a retained manifest names, so its writer reads the stable ids here.
//!
//! Spans and fingerprints come from the manifest, never from a symbol row.
//! A stable symbol id is shared by every revision that holds it, and its row
//! holds the revision written last.

use std::collections::BTreeSet;

use heed::RoTxn;

use super::keys::{MANIFEST, code_symbol_entity_id};
use super::storage::{code_symbol_definition, validate_code_artifact_target};
use super::types::{CODE_SYMBOL_NAME_MAX_BYTES, CodeSymbolDefinition, CodeSymbolManifest};
use super::validate::validate_text;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::store::Store;

/// The definitions named `name` that the manifest stored for
/// `code_artifact_id` records, in its order, read in `txn` (FIX 4300). Each
/// carries that manifest's span and fingerprint. The manifest comes back
/// beside them, so the caller can match its source revision. `None` when the
/// artifact has no manifest.
///
/// # Errors
/// A name that is not valid symbol text, a manifest that does not match its
/// CODE artifact, or a store failure.
pub(crate) fn code_symbol_definitions_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
    name: &str,
) -> Result<Option<(CodeSymbolManifest, Vec<CodeSymbolDefinition>)>> {
    validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
    let Some(manifest) = MANIFEST.get(store, txn, code_artifact_id)? else {
        return Ok(None);
    };
    validate_code_artifact_target(store, txn, code_artifact_id, &manifest.repo_ref)?;
    let definitions = manifest
        .symbols
        .iter()
        .filter(|symbol| symbol.name == name)
        .map(|symbol| code_symbol_definition(&manifest.repo_identity, symbol, &manifest.chunks))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some((manifest, definitions)))
}

/// The manifest stored for `code_artifact_id`, read in `txn` and checked
/// against its CODE artifact, as `Vault::get_code_symbol_manifest` reads it.
/// `None` when the artifact has no manifest.
///
/// # Errors
/// A manifest that does not match its CODE artifact, or a store failure.
pub(crate) fn code_symbol_manifest_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
) -> Result<Option<CodeSymbolManifest>> {
    let Some(manifest) = MANIFEST.get(store, txn, code_artifact_id)? else {
        return Ok(None);
    };
    validate_code_artifact_target(store, txn, code_artifact_id, &manifest.repo_ref)?;
    Ok(Some(manifest))
}

/// The stable ids of every symbol `manifest` names (FIX 4300).
///
/// # Errors
/// A symbol revision whose shape does not validate.
pub(crate) fn code_symbol_manifest_ids(
    manifest: &CodeSymbolManifest,
) -> Result<BTreeSet<EntityId>> {
    manifest
        .symbols
        .iter()
        .map(|symbol| code_symbol_entity_id(&manifest.repo_identity, symbol))
        .collect()
}

/// The stable ids of every symbol the manifest stored for
/// `code_artifact_id` names, read in `txn` (FIX 4300). Empty when the
/// artifact has no manifest. A manifest body that does not decode names no
/// symbol, as a snapshot body that does not decode names no file.
///
/// # Errors
/// A store failure.
pub(crate) fn code_symbol_manifest_ids_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    match MANIFEST.get(store, txn, code_artifact_id) {
        Ok(Some(manifest)) => code_symbol_manifest_ids(&manifest),
        Ok(None) | Err(Error::Code(CodeError::InvalidCodeSymbolManifestBody(_))) => {
            Ok(BTreeSet::new())
        }
        Err(other) => Err(other),
    }
}
