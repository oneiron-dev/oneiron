//! Create-door final phase: assemble the store and run open-time gates.

use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::store::{RawDatabases, Store};

use super::embedding_transform_gates::{
    persist_embedding_transform_if_missing, preflight_embedding_transform,
};
use super::hnsw_model_gates::{
    migrate_temporal_long_intervals_if_needed, persist_hnsw_config_if_missing,
    persist_model_id_if_missing, preflight_embedding_model, preflight_hnsw_config,
};
use super::manifest_storage_gates::{OwnedEnv, RegisteredPath, validate_fast_dims};
use super::open_version_keys::DefaultPolicySeedMode;

pub(super) fn create_preflight(
    env: OwnedEnv,
    raw: RawDatabases,
    registered_path: RegisteredPath,
    config: &VaultConfig,
    seed_mode: DefaultPolicySeedMode,
) -> Result<Store> {
    let store = Store::assemble(env, raw, registered_path, config)?;

    // EMB-2 preflight: an out-of-range fast_dims is a caller bug and
    // fails closed before the HNSW compat check below can compare it.
    validate_fast_dims(config)?;

    let should_persist_hnsw_config = preflight_hnsw_config(&store, config)?;
    let should_persist_model_id =
        preflight_embedding_model(&store, config.embedding_model.as_deref())?;
    // After the model: a transform is only compared under the model the
    // vault already holds, or is stamping now.
    let should_persist_transform =
        preflight_embedding_transform(&store, config.embedding_transform.as_deref())?;
    migrate_temporal_long_intervals_if_needed(&store)?;

    if should_persist_hnsw_config {
        persist_hnsw_config_if_missing(&store, config)?;
    }

    if should_persist_model_id {
        let requested = config
            .embedding_model
            .as_deref()
            .ok_or_else(|| Error::InvalidConfig("missing embedding model".to_owned()))?;
        persist_model_id_if_missing(&store, requested)?;
    }

    if should_persist_transform && let Some(requested) = config.embedding_transform.as_deref() {
        persist_embedding_transform_if_missing(&store, requested)?;
    }

    store.ensure_receipt_family_indexes_on_open()?;
    store.ensure_gate_claim_index_flag_on_open()?;
    if matches!(seed_mode, DefaultPolicySeedMode::Required) {
        store.ensure_default_policy_manifest_on_open()?;
    }
    store.reconcile_retrieval_telemetry_on_open()?;
    Ok(store)
}
