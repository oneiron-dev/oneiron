//! Server configuration: resolved types, CLI flags, and the file/env/argv merge.

pub mod backup;
pub mod browser;
pub mod desktop;
pub mod embedder;
mod embedder_shape;
mod embedder_space;
mod embedding;
mod failure_signals;
mod feedback;
pub mod import;
mod keystore;
mod limits;
mod line;
mod lookup;
pub mod merge;
pub mod models;
pub mod oneironer;
mod recall;
pub mod remote_embedder;
pub mod serve_args;
pub mod server_config;
mod skills;
mod trusted_proxy;

pub use backup::{BackupConfig, default_backup_dir};
pub use browser::BrowserConfig;
pub use desktop::DesktopConfig;
pub use embedder::{
    EmbedderArgs, EmbedderConfig, EmbedderDevice, EmbedderLocality, EmbedderProvider,
    EmbedderQuant, EndpointEmbedderConfig, LocalEmbedderConfig,
};
pub use embedder_shape::{EmbedderAttention, EmbedderOutputQuantization};
pub use embedding::{EmbeddingConfig, EmbeddingSlotsConfig};
pub use failure_signals::{CLOUD_FAILURE_SIGNALS_ENDPOINT, FailureSignalsConfig};
pub use feedback::{CLOUD_FEEDBACK_ENDPOINT, FeedbackConfig, FeedbackInboxConfig};
pub use import::ImportConfig;
pub use keystore::{DEFAULT_KEYCHAIN_SERVICE, KeystoreBackend, KeystoreConfig};
pub use limits::LimitsConfig;
pub use line::LineConfig;
pub(crate) use merge::layer_serve_config;
pub use merge::{
    EnvConfig, default_config_path, resolve_backup_config, resolve_serve_config,
    resolve_serve_config_with_sources,
};
pub use models::ModelsConfig;
pub use oneironer::{
    OneironerArgs, OneironerConfig, OneironerConfigOverride, OneironerMode, OneironerProvider,
};
pub use recall::RecallConfig;
pub use serve_args::ServeArgs;
pub use server_config::{ServeConfig, SyncServerConfig};
pub use skills::SkillsConfig;
pub use trusted_proxy::TrustedProxy;

#[cfg(test)]
mod embedder_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod privacy_tests;
#[cfg(all(test, unix))]
mod process_env_tests;
#[cfg(test)]
mod recall_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody};
