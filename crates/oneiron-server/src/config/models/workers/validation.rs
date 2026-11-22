//! The checks a `[models.workers.<id>]` row's fields pass when it resolves, and the one the
//! `listen = "unix"` rows hold together with the ladders and media seats (L9-15).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::ModelLocality;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{CacheDigest, CacheIdentity, WorkerKind, WorkerMode};

use super::super::levels::{Rung, role_key};
use super::super::media::MediaSettings;
use super::super::provider::{ProviderConfig, ProviderKind};
use super::{ArtifactSource, ExpectedFile, WorkerArtifact, WorkerConfig};
use crate::model_artifacts::catalog::house_artifact;

/// Refuses a `listen = "unix"` row whose provider serves anything but the
/// reranker over a Unix-socket row (L9-15): no other role's ladder and no
/// media seat names the provider, each reranker rung on it is a model such
/// a row serves, and no managed row on it listens over TCP. Nothing listens
/// on that provider's `base_url`.
pub(in crate::config::models) fn refuse_socket_provider_off_reranker(
    workers: &[WorkerConfig],
    roles: &BTreeMap<ModelRole, Vec<Rung>>,
    media: &MediaSettings,
) -> anyhow::Result<()> {
    let socket_rows: BTreeMap<&str, &WorkerConfig> = workers
        .iter()
        .filter(|row| row.listens_on_socket())
        .map(|row| (row.binding.provider.as_str(), row))
        .collect();
    // A managed row that listens over TCP binds its provider's host and port,
    // whether or not a ladder names its model.
    if let Some(row) = workers.iter().find(|row| {
        row.mode == WorkerMode::Managed
            && !row.listens_on_socket()
            && socket_rows.contains_key(row.binding.provider.as_str())
    }) {
        anyhow::bail!(
            "models.workers.{}.listen: provider {:?} is served on its workers' Unix sockets (models.workers.{}), so a managed row on it listens on one too",
            row.id,
            row.binding.provider,
            socket_rows[row.binding.provider.as_str()].id
        );
    }
    for (role, ladder) in roles {
        for rung in ladder {
            let Some(row) = socket_rows.get(rung.model.provider.as_str()) else {
                continue;
            };
            anyhow::ensure!(
                *role == ModelRole::Reranker,
                "models.workers.{}.listen: provider {:?} serves the reranker alone, but models.roles.{} names it",
                row.id,
                rung.model.provider,
                role_key(*role)
            );
            anyhow::ensure!(
                workers
                    .iter()
                    .any(|worker| worker.binding == rung.model && worker.listens_on_socket()),
                "models.workers.{}.listen: provider {:?} serves each reranker model from a listen = \"unix\" row, and none serves {}",
                row.id,
                rung.model.provider,
                rung.model
            );
        }
    }
    for (operation, seat) in &media.seats {
        if let Some(model) = seat
            .rungs
            .iter()
            .chain(seat.tiers.values())
            .find(|model| socket_rows.contains_key(model.provider.as_str()))
        {
            anyhow::bail!(
                "models.workers.{}.listen: provider {:?} serves the reranker alone, but the {} media seat names it",
                socket_rows[model.provider.as_str()].id,
                model.provider,
                operation.as_str()
            );
        }
    }
    Ok(())
}

/// Whether `kind` is a media worker's: VoxCPM2 speech or local ASR.
pub(super) fn media_kind(kind: WorkerKind) -> bool {
    matches!(kind, WorkerKind::VoxCpm2 | WorkerKind::Asr)
}

/// Whether a media worker of `kind` serves `provider`: VoxCPM2 a `voxcpm2`
/// provider; ASR a `local-openai-compat` one, or, external, an
/// `openai-compat` one that says it is an own server.
pub(super) fn media_provider(
    field: &str,
    kind: WorkerKind,
    mode: WorkerMode,
    provider: &ProviderConfig,
) -> anyhow::Result<()> {
    match kind {
        WorkerKind::VoxCpm2 => anyhow::ensure!(
            provider.kind == ProviderKind::Voxcpm2,
            "{field}: a vox_cpm2 worker serves a voxcpm2 provider"
        ),
        _ => anyhow::ensure!(
            provider.kind == ProviderKind::LocalOpenaiCompat
                || (mode == WorkerMode::External
                    && provider.kind == ProviderKind::OpenaiCompat
                    && provider.locality == ModelLocality::OwnServer),
            "{field}: an asr worker serves a local-openai-compat provider (an external one also an openai-compat provider with locality = \"own_server\")"
        ),
    }
    Ok(())
}

impl ExpectedFile {
    pub(super) fn resolve(&self, field: &str) -> anyhow::Result<CacheIdentity> {
        let digest = |name: &str, value: &Option<String>| {
            value
                .clone()
                .map(|hex| {
                    CacheDigest::new(hex)
                        .map_err(|error| anyhow::anyhow!("{field}.{name}: {error}"))
                })
                .transpose()
        };
        Ok(CacheIdentity {
            model: digest("model", &self.model)?,
            tokenizer: digest("tokenizer", &self.tokenizer)?,
            runtime: digest("runtime", &self.runtime)?,
            template: digest("template", &self.template)?,
            ..CacheIdentity::default()
        })
    }
}

/// One set of weights from its catalog id or manifest file, and its offline
/// directory; `None` when the row names neither.
pub(super) fn artifact(
    field: &str,
    catalog: Option<&str>,
    manifest: Option<&Path>,
    offline_dir: Option<&Path>,
    base: Option<&Path>,
) -> anyhow::Result<Option<WorkerArtifact>> {
    let source = match (catalog, manifest) {
        (Some(id), None) => {
            anyhow::ensure!(
                house_artifact(id).is_some(),
                "{field} = {id:?} is not a house catalog id"
            );
            ArtifactSource::Catalog(id.to_owned())
        }
        (None, Some(path)) => {
            ArtifactSource::Manifest(absolute(&format!("{field}_manifest"), path, base)?)
        }
        (None, None) => {
            anyhow::ensure!(
                offline_dir.is_none(),
                "{field}_dir needs {field} or {field}_manifest"
            );
            return Ok(None);
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("{field} and {field}_manifest name the same weights twice; keep one")
        }
    };
    let offline_dir = offline_dir
        .map(|dir| absolute(&format!("{field}_dir"), dir, base))
        .transpose()?;
    Ok(Some(WorkerArtifact {
        source,
        offline_dir,
    }))
}

/// `path` against the config file's directory, which must give an absolute
/// path.
pub(super) fn absolute(field: &str, path: &Path, base: Option<&Path>) -> anyhow::Result<PathBuf> {
    let path = match base {
        Some(base) if path.is_relative() => base.join(path),
        _ => path.to_path_buf(),
    };
    anyhow::ensure!(
        path.is_absolute(),
        "{field} must be an absolute path, or relative to the config file"
    );
    Ok(path)
}

/// The host and port a loopback `http://` base URL names, with its port
/// written out.
pub(super) fn loopback_listen(base_url: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(base_url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let port = url.port()?;
    let host = url.host_str()?;
    if host == "localhost" {
        return Some(("127.0.0.1".to_owned(), port));
    }
    let ip: std::net::IpAddr = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()?;
    ip.is_loopback().then(|| (ip.to_string(), port))
}

pub(super) fn plain(name: &str) -> bool {
    name.bytes().any(|byte| byte != b'.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}
