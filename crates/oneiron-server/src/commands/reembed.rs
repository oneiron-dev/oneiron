//! `reembed`: moves a stopped vault to the configured embedding space.
//!
//! One vault holds one embedding space: a model, and how the embedder turns
//! that model's output into stored vectors (the transform). A server
//! configured for a model or a transform the vault was not filled with refuses
//! to open it (`EmbeddingModelChanged`, `EmbeddingTransformChanged`). This is
//! the operator's door across that refusal. The engine's migration repins both
//! in one transaction, drops the vector graph and marks every embeddable record
//! pending; the next `serve` fills them in the background while lexical and
//! graph reads keep answering. It runs with the server stopped: the vault's
//! writer lease admits one process.
//!
//! `--force` runs the same swap under the pins the vault already holds.

use oneiron::error::StoreError;
use serde::Serialize;

use crate::cli::ReembedArgs;
use crate::config::{ServeConfig, resolve_serve_config};

/// What `reembed` did, printed as one JSON line.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReembedOutcome {
    /// The space the vault held before, when it held a different one.
    from: Option<String>,
    /// The configured space the vault holds now.
    to: String,
    /// The transform the vault holds now, when the configured embedder
    /// declares one before it loads.
    transform: Option<String>,
    /// Whether every embeddable record was queued to be embedded again.
    migrated: bool,
}

pub fn reembed(args: ReembedArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let outcome = reembed_with_config(&config, args.force)?;
    println!("{}", serde_json::to_string(&outcome)?);
    Ok(())
}

/// Repins the vault at `config.vault_path` to the configured embedder's space.
///
/// A vault already in that space, or holding no vectors and no space yet, is
/// left as it is unless `force` asks for the swap anyway: opening it under the
/// configured model is all `serve` needs.
fn reembed_with_config(config: &ServeConfig, force: bool) -> anyhow::Result<ReembedOutcome> {
    let Some(target) = config
        .embedder
        .as_ref()
        .filter(|embedder| embedder.is_active())
        .map(|embedder| embedder.model_id.clone())
    else {
        anyhow::bail!(
            "reembed needs an active [embedder] section; its model_id is the space the vault moves to"
        );
    };
    if !config.vault_path.join("data.mdb").is_file() {
        anyhow::bail!(
            "vault {} does not exist; refusing to create a new vault for reembed",
            config.vault_path.display()
        );
    }
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths =
        super::resolve_dict_search_paths(&config.dict_search_paths).paths;
    let transform = vault_config.embedding_transform.clone();
    let from = match oneiron::Vault::open_owned(&config.vault_path, vault_config.clone()) {
        Ok(mut already) => {
            if force {
                already.refill_embedding_space()?;
            }
            return Ok(ReembedOutcome {
                from: None,
                to: target,
                transform,
                migrated: force,
            });
        }
        Err(oneiron::Error::Store(StoreError::EmbeddingModelChanged { stored, .. })) => {
            Some(stored)
        }
        Err(oneiron::Error::Store(StoreError::EmbeddingTransformChanged { .. })) => None,
        Err(error) => return Err(open_refusal(config, error)),
    };
    // Reopened under what the vault holds, so the open admits it; the
    // migration then repins the model and the transform together.
    vault_config.embedding_model = Some(from.clone().unwrap_or_else(|| target.clone()));
    vault_config.embedding_transform = None;
    let mut vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(|error| open_refusal(config, error))?;
    match transform.as_deref() {
        Some(transform) => vault.migrate_embedding_space(&target, transform)?,
        None => vault.begin_embedding_migration(&target)?,
    }
    Ok(ReembedOutcome {
        from,
        to: target,
        transform,
        migrated: true,
    })
}

/// Why the vault did not open, with the typed refusal kept underneath.
///
/// The width a vault holds is fixed when it is created, so a configured model
/// of another width cannot move into it: that refusal says so, with both
/// numbers, rather than as a generic index mismatch.
fn open_refusal(config: &ServeConfig, error: oneiron::Error) -> anyhow::Error {
    let held = match &error {
        oneiron::Error::Store(StoreError::HnswConfigChanged { stored, .. }) => stored
            .split(',')
            .find_map(|field| field.strip_prefix("dimensions="))
            .filter(|held| *held != config.dimensions.to_string())
            .map(str::to_owned),
        _ => None,
    };
    let context = match held {
        Some(held) => format!(
            "vault {} holds {held}-dimension vectors and the configured model gives {}; a vault's dimensions are fixed when it is created, so a model of another width needs a new vault",
            config.vault_path.display(),
            config.dimensions
        ),
        None => format!("open vault {} failed", config.vault_path.display()),
    };
    anyhow::Error::from(error).context(context)
}

/// What `serve` says when the vault holds vectors from another model, or made
/// another way: both ways forward, with the typed refusal kept underneath.
pub(super) fn with_model_change_remedy(error: oneiron::Error) -> anyhow::Error {
    let remedy = match &error {
        oneiron::Error::Store(StoreError::EmbeddingModelChanged { stored, requested }) => format!(
            "the vault holds vectors from {stored}, but the configured embedder is {requested}. \
             To move the vault to the configured model, run `oneiron-server reembed` with this \
             configuration. To keep the vault's model, set embedder.model_id to {stored} and \
             that model's query settings (embedder.query_instruction or \
             embedder.query_prompt_name)"
        ),
        oneiron::Error::Store(StoreError::EmbeddingTransformChanged { stored, requested }) => {
            format!(
                "the vault's vectors were made as {stored}, but the configured embedder makes \
                 {requested}. To re-embed the vault the new way, run `oneiron-server reembed` \
                 with this configuration. To keep the vault's vectors, restore the settings \
                 that made them (embedder.attention, embedder.output_quantization)"
            )
        }
        _ => return error.into(),
    };
    anyhow::Error::from(error).context(remedy)
}

#[cfg(test)]
mod tests;
