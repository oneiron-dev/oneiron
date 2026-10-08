//! Config model references to engine catalog rows.
//!
//! The engine names a model `provider/name@revision`; a provider names it
//! however it likes (`olety7/gpt-6.1-sol`, `qwen3:8b`). The catalog row keeps
//! the provider's spelling as `wire_model`, which both adapters send verbatim.
use std::collections::BTreeMap;

use oneiron::{LlmCatalogEntry, ModelId, ModelLocality};
use serde_json::Value as JsonValue;

use crate::config::models::{ModelRef, ProviderConfig};

/// The engine identity of a configured model. Characters outside the id
/// grammar become `.`; the provider's own spelling stays in the catalog.
pub(super) fn engine_model_id(
    model: &ModelRef,
    provider: &ProviderConfig,
) -> anyhow::Result<ModelId> {
    let name: String = model
        .model
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
                byte as char
            } else {
                '.'
            }
        })
        .collect();
    let name = name.trim_matches('.');
    ModelId::new(format!("{}/{name}@{}", model.provider, provider.revision))
        .map_err(|error| anyhow::anyhow!("model {model}: {error}"))
}

pub(super) fn catalog_entry(
    model: &ModelRef,
    provider: &ProviderConfig,
) -> anyhow::Result<LlmCatalogEntry> {
    Ok(LlmCatalogEntry {
        model: engine_model_id(model, provider)?,
        display_name: model.model.clone(),
        locality: provider.locality,
        context_window_tokens: provider.context_tokens,
        max_output_tokens: provider.max_output_tokens,
        cost: None,
        capabilities: provider.capabilities.clone(),
        metadata: BTreeMap::from([(
            "wire_model".to_owned(),
            JsonValue::String(model.model.clone()),
        )]),
    })
}

/// Rank of a route, narrowest first, for "the widest rung" of a ladder.
pub(super) const fn locality_rank(locality: ModelLocality) -> u8 {
    match locality {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}
