//! Server configuration: resolved types, CLI flags, and the file/env/argv merge.

pub mod embedder;
mod lookup;
pub mod merge;
pub mod serve_args;
pub mod server_config;

pub use embedder::{
    EmbedderArgs, EmbedderConfig, EmbedderDevice, EmbedderLocality, EmbedderProvider,
    EmbedderQuant, EndpointEmbedderConfig, LocalEmbedderConfig,
};
pub use merge::{
    EnvConfig, default_config_path, resolve_serve_config, resolve_serve_config_with_sources,
};
pub use serve_args::ServeArgs;
pub use server_config::{ServeConfig, SyncServerConfig};

#[cfg(test)]
mod embedder_tests;
#[cfg(test)]
mod privacy_tests;
#[cfg(all(test, unix))]
mod process_env_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::runtime::{RuntimeMode, RuntimeProviderKind, RuntimeRole};
#[cfg(test)]
use crate::usage::UsageMode;
#[cfg(test)]
use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody, VaultPrivacyConfig};
#[cfg(test)]
use std::path::PathBuf;
