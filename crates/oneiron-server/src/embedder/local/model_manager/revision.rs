//! One hub ref, one commit (FIX 9489).
//!
//! A configured revision may be a branch or a tag, which can move to other
//! weights while the vault's space id stays the same. Before any file is
//! fetched, the ref is resolved once to the commit it names now, and every
//! file, the cache directory, the loaded model's revision and the transform
//! the vault admits are bound to that commit: a ref that moved meets the
//! vault's pinned transform as another one, and is refused until `reembed`
//! takes it, never filled into the old space. The requested ref stays the
//! configuration and the space id. A full commit is used as it stands, with
//! no request; an operator's `model_dir` is the files it holds, checked as
//! found, with no hub commit invented for it.

use std::time::Duration;

use super::{CONNECT_TIMEOUT, ModelManager, transport_class};
use crate::config::LocalEmbedderConfig;

/// How long the one ref lookup may take: a small JSON answer.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest answer the lookup reads: the hub's model card for one
/// revision, which lists its files.
const MAX_RESOLVE_BYTES: u64 = 4 * 1024 * 1024;

/// A configured local model with its revision resolved to one commit.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedLocalRevision {
    /// The revision the configuration names: a commit, a branch or a tag.
    requested: String,
    /// The configuration with its revision the resolved commit: what every
    /// fetch, cache path and loaded-model record uses.
    config: LocalEmbedderConfig,
}

impl ResolvedLocalRevision {
    /// The configuration bound to the resolved commit.
    pub(crate) fn config(&self) -> &LocalEmbedderConfig {
        &self.config
    }

    /// The commit the files come from; the requested revision for an
    /// operator's `model_dir`.
    pub(crate) fn commit(&self) -> &str {
        &self.config.revision
    }

    /// `transform` bound to the resolved commit when the configured revision
    /// is a ref that names it: the vault's pinned transform then holds the
    /// weights to that commit. A configured commit, and an operator's
    /// directory, leave it as it is.
    pub(crate) fn bind_transform(&self, transform: String) -> String {
        if self.requested == self.config.revision {
            transform
        } else {
            format!("{transform};revision={}", self.config.revision)
        }
    }
}

/// Whether `revision` is a full commit id: forty lowercase hex digits.
pub(crate) fn is_commit(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl ModelManager {
    /// `config` resolved to one commit, before any file is fetched: a full
    /// commit as it stands; an operator's `model_dir` as configured; any
    /// other ref asked of the hub once, its answer a full commit or an
    /// error. Never a guess: a lookup that fails fails the load, which the
    /// worker tries again.
    pub(in crate::embedder) fn resolve_local_revision(
        &self,
        config: &LocalEmbedderConfig,
    ) -> oneiron::Result<ResolvedLocalRevision> {
        let requested = config.revision.clone();
        if config.model_dir.is_some() || is_commit(&requested) {
            return Ok(ResolvedLocalRevision {
                requested,
                config: config.clone(),
            });
        }
        let commit = self.hub_commit(config)?;
        let mut resolved = config.clone();
        resolved.revision = commit;
        tracing::info!(
            repo = %config.repo,
            requested = %requested,
            commit = %resolved.revision,
            "embedder model ref resolved to its commit"
        );
        Ok(ResolvedLocalRevision {
            requested,
            config: resolved,
        })
    }

    /// The commit the hub says `config.revision` names now. The repository
    /// and ref are checked as plain names first, so neither reaches past the
    /// hub's model route.
    fn hub_commit(&self, config: &LocalEmbedderConfig) -> oneiron::Result<String> {
        super::check_cache_identity(config)?;
        let url = format!(
            "{}/api/models/{}/revision/{}",
            self.base_url, config.repo, config.revision
        );
        let failed = |reason: &str| oneiron::Error::UpstreamToolFailure {
            tool: "embedder-model-download",
            code: format!("revision {}: {reason}", config.revision),
        };
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(RESOLVE_TIMEOUT)
            .build()
            .map_err(|_| failed("client could not be built"))?;
        let response = client
            .get(&url)
            .send()
            .map_err(|error| failed(&transport_class(&error)))?;
        if !response.status().is_success() {
            return Err(failed(&format!("HTTP {}", response.status())));
        }
        let mut body = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(response, MAX_RESOLVE_BYTES + 1),
            &mut body,
        )
        .map_err(|_| failed("answer did not read"))?;
        if body.len() as u64 > MAX_RESOLVE_BYTES {
            return Err(failed("answer exceeds the lookup's body cap"));
        }
        #[derive(serde::Deserialize)]
        struct Revision {
            sha: String,
        }
        let answer: Revision =
            serde_json::from_slice(&body).map_err(|_| failed("answer names no commit"))?;
        if !is_commit(&answer.sha) {
            return Err(failed("answer names no full commit"));
        }
        Ok(answer.sha)
    }
}
