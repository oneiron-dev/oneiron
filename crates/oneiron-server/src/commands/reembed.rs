//! `reembed`: moves a stopped vault to the configured embedding space.
//!
//! One vault holds one embedding space, so a server configured for a model the
//! vault was not filled with refuses to open it (`EmbeddingModelChanged`). This
//! is the operator's door across that refusal. The engine's migration repins the
//! vault to the configured model, drops the vector graph and marks every claim
//! pending; the next `serve` fills them in the background while lexical and
//! graph reads keep answering. It runs with the server stopped: the vault's
//! writer lease admits one process.

use serde::Serialize;

use crate::config::{ServeArgs, ServeConfig, resolve_serve_config};

/// What `reembed` did, printed as one JSON line.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReembedOutcome {
    /// The space the vault held before, when it held a different one.
    pub(crate) from: Option<String>,
    /// The configured space the vault holds now.
    pub(crate) to: String,
    /// Whether every claim was queued to be embedded again.
    pub(crate) migrated: bool,
}

pub fn reembed(args: ServeArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args)?;
    let outcome = reembed_with_config(&config)?;
    println!("{}", serde_json::to_string(&outcome)?);
    Ok(())
}

/// Repins the vault at `config.vault_path` to the configured embedder's space.
///
/// A vault already in that space, or holding no vectors and no space yet, is
/// left as it is: opening it under the configured model is all `serve` needs.
pub(crate) fn reembed_with_config(config: &ServeConfig) -> anyhow::Result<ReembedOutcome> {
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
    let stored = match oneiron::Vault::open_owned(&config.vault_path, vault_config.clone()) {
        Ok(_already) => {
            return Ok(ReembedOutcome {
                from: None,
                to: target,
                migrated: false,
            });
        }
        Err(oneiron::Error::Store(oneiron::error::StoreError::EmbeddingModelChanged {
            stored,
            ..
        })) => stored,
        Err(error) => {
            return Err(anyhow::anyhow!(
                "open vault {} failed: {error}",
                config.vault_path.display()
            ));
        }
    };
    vault_config.embedding_model = Some(stored.clone());
    let mut vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(|e| anyhow::anyhow!("open vault {} failed: {e}", config.vault_path.display()))?;
    vault.begin_embedding_migration(&target)?;
    Ok(ReembedOutcome {
        from: Some(stored),
        to: target,
        migrated: true,
    })
}

#[cfg(test)]
mod tests;
