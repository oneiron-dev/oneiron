//! Model stack versioning.

use std::sync::LazyLock;

use super::keys::{
    DRAFTING_ROLE, ROW_VERSION, SERVING_MODEL_KEY, SERVING_MODEL_ROW_LABEL, StoredModelVersion,
    decode_row, encode_row,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::llm::ModelId;
use crate::settings::{ModelStack, ModelStackRegistry, default_model_stack_registry};

// ---------------------------------------------------------------------------
// Model version resolution
// ---------------------------------------------------------------------------

/// The compiled stack table, read-only prior art consulted on every version
/// resolution.
static MODEL_STACK_REGISTRY: LazyLock<ModelStackRegistry> =
    LazyLock::new(default_model_stack_registry);

/// The generation token for `model` — see [`RoutingScopeKey::for_model`].
///
/// A model claimed by the current default stack takes that stack's identity
/// even if an older generation also lists it, so the common case needs no
/// tie-break at all. Otherwise the newest generation claiming it wins.
pub(super) fn model_version_token(model: &ModelId) -> String {
    let registry = &*MODEL_STACK_REGISTRY;
    let current = registry.current_default();
    if stack_claims(current, model) {
        return format!("stack:{}", current.id);
    }
    registry
        .stacks
        .values()
        .filter(|stack| stack_claims(stack, model))
        .max_by_key(|stack| stack.generation)
        .map_or_else(
            || format!("model:{}", model.as_str()),
            |stack| format!("stack:{}", stack.id),
        )
}

fn stack_claims(stack: &ModelStack, model: &ModelId) -> bool {
    stack
        .models
        .iter()
        .any(|entry| entry.model.as_str() == model.as_str())
}

/// The generation [`record_judged_amendment`] stamps new folds with.
///
/// Unset resolves to the drafting role's compiled default, which is what the
/// consumer side would build a key from — so an unconfigured vault records and
/// reads under the same token instead of silently missing itself.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn serving_model_version(vault: &Vault) -> Result<String> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, SERVING_MODEL_KEY)? else {
        return Ok(model_version_token(&DRAFTING_ROLE.default_model_id()));
    };
    let row: StoredModelVersion = decode_row(&raw, SERVING_MODEL_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(SERVING_MODEL_ROW_LABEL));
    }
    Ok(row.model_version)
}

/// Declares which model is serving, and so which generation later folds belong
/// to.
///
/// Already-folded runs are untouched by design: they happened under the
/// generation that was serving when they happened, and a swap is not new
/// information about them.
///
/// # Errors
///
/// Storage errors.
pub fn set_serving_model(vault: &Vault, model: &ModelId) -> Result<()> {
    let encoded = encode_row(
        &StoredModelVersion {
            v: ROW_VERSION,
            model_version: model_version_token(model),
        },
        SERVING_MODEL_ROW_LABEL,
    )?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, SERVING_MODEL_KEY, &encoded)?;
        Ok(())
    })
}
