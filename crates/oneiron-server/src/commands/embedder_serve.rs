//! `oneiron-server embedder serve`: resolves which model to serve, then hands
//! it to the endpoint ([`crate::embedder::serve`]).

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::cli::EmbedderServeArgs;
use crate::config::{
    EmbedderArgs, EmbedderConfig, EmbedderProvider, EnvConfig, ServeArgs, default_config_path,
    resolve_serve_config_with_sources,
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
    served_config_from(args, &EnvConfig::from_process()?, default_config_path())
}

fn served_config_from(
    args: &EmbedderServeArgs,
    env: &EnvConfig,
    default_config_path: Option<PathBuf>,
) -> anyhow::Result<EmbedderConfig> {
    let resolve = |embedder: EmbedderArgs, dimensions: Option<usize>| {
        resolve_serve_config_with_sources(
            &ServeArgs {
                config: args.config.clone(),
                embedder,
                dimensions,
                ..ServeArgs::default()
            },
            env.clone(),
            default_config_path.clone(),
        )
    };
    // There is no vault here, so the vault-wide width only has to agree with
    // the model's, and unless --dimensions names it, it is the model's: the
    // section's width as every layer resolves it, read with the section held
    // inactive, which the vault check skips. Should that read fail, the full
    // resolution below says why.
    let dimensions = args.dimensions.or_else(|| {
        let inactive = EmbedderArgs {
            embedder_provider: Some(EmbedderProvider::None),
            ..args.embedder.clone()
        };
        resolve(inactive, None)
            .ok()
            .and_then(|resolved| resolved.embedder)
            .map(|embedder| embedder.dimensions)
    });
    let resolved = resolve(args.embedder.clone(), dimensions)?;
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

#[cfg(test)]
mod tests;
