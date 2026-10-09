//! Server configuration: resolved types, CLI flags, and the file/env/argv merge.

pub mod backup;
pub mod embedder;
mod embedder_shape;
mod embedder_space;
mod lookup;
pub mod merge;
pub mod models;
pub mod oneironer;
pub mod remote_embedder;
pub mod serve_args;
pub mod server_config;

pub use backup::{BackupConfig, default_backup_dir};
pub use embedder::{
    EmbedderArgs, EmbedderConfig, EmbedderDevice, EmbedderLocality, EmbedderProvider,
    EmbedderQuant, EndpointEmbedderConfig, LocalEmbedderConfig,
};
pub use embedder_shape::{EmbedderAttention, EmbedderOutputQuantization};
pub use merge::{
    EnvConfig, default_config_path, resolve_backup_config, resolve_serve_config,
    resolve_serve_config_with_sources,
};
pub use models::ModelsConfig;
pub use oneironer::{
    OneironerArgs, OneironerConfig, OneironerConfigOverride, OneironerMode, OneironerProvider,
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
use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody};
