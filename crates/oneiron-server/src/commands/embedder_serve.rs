//! `oneiron-server embedder serve`: resolves which model to serve, then hands
//! it to the endpoint ([`crate::embedder::serve`]).

use zeroize::Zeroizing;

use crate::cli::EmbedderServeArgs;
use crate::config::embedder::DEFAULT_DIMENSIONS;
use crate::config::{
    EmbedderConfig, EmbedderProvider, ServeArgs, default_config_path, resolve_serve_config,
};
use crate::embedder::serve::{Listen, run};

pub async fn embedder_serve(args: EmbedderServeArgs) -> anyhow::Result<()> {
    super::init_tracing(&args.log_level);
    let config = served_config(&args)?;
    let key = args
        .api_key_env
        .as_deref()
        .map(|name| match std::env::var(name) {
            Ok(key) if !key.trim().is_empty() => Ok(Zeroizing::new(key)),
            _ => Err(anyhow::anyhow!(
                "--api-key-env names {name}, which is not set to a key in this environment"
            )),
        })
        .transpose()?;
    run(
        config,
        Listen {
            addr: (args.host, args.port).into(),
            key,
            aliases: args.model_aliases,
        },
    )
    .await
}

/// The `[embedder]` section `serve` would resolve from the same file, flags
/// and environment. A local section is served as it stands; with none at all,
/// the default local model is.
fn served_config(args: &EmbedderServeArgs) -> anyhow::Result<EmbedderConfig> {
    // There is no vault here, so the vault-wide width only has to agree with
    // the model's. With no config file to name it, it is the model's: the
    // flags' width, or the default model's.
    let config_file = args.config.is_some()
        || std::env::var_os("ONEIRON_CONFIG").is_some()
        || default_config_path().is_some_and(|path| path.exists());
    let dimensions = match (args.dimensions, config_file) {
        (Some(dimensions), _) => Some(dimensions),
        (None, true) => None,
        (None, false) => Some(
            args.embedder
                .embedder_dimensions
                .unwrap_or(DEFAULT_DIMENSIONS),
        ),
    };
    let resolved = resolve_serve_config(&ServeArgs {
        config: args.config.clone(),
        embedder: args.embedder.clone(),
        dimensions,
        ..ServeArgs::default()
    })?;
    match resolved.embedder {
        Some(embedder) if embedder.provider == EmbedderProvider::Local => Ok(embedder),
        Some(embedder) if embedder.provider == EmbedderProvider::Endpoint => anyhow::bail!(
            "the resolved [embedder] section is an endpoint; embedder serve runs a local model \
             (pass --embedder-provider local, or a --config whose [embedder] provider is local)"
        ),
        _ => {
            tracing::info!(
                "no local [embedder] section configured; serving the default local model"
            );
            Ok(EmbedderConfig {
                provider: EmbedderProvider::Local,
                ..EmbedderConfig::default()
            })
        }
    }
}
