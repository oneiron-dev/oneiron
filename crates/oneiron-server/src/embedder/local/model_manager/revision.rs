//! One hub ref, one commit (FIX 9489).
//!
//! A configured revision may be a branch or a tag, which can move to other
//! weights while the vault's space id stays the same. Before any file is
//! fetched, the ref is resolved once to the commit it names now, and every
//! file, the cache directory, the loaded model's revision and the transform
//! the vault admits are bound to that commit. A vault whose pinned transform
//! names a commit loads that commit again, with no request, so a ref that
//! moved keeps serving the weights the stored vectors came from (and an
//! offline host its cached files): the hub is asked only afterwards, off the
//! load path, and a move is a warning that `reembed` takes the new weights,
//! never a refusal and never new weights filled into the old space. The
//! requested ref stays the configuration and the space id. A full commit is
//! used as it stands, with no request; an operator's `model_dir` is the files
//! it holds, checked as found, with no hub commit invented for it.

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
    /// The commit came from the vault's pin, not from asking the hub now.
    from_pin: bool,
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

/// The commit a vault's pinned transform names: the `;revision=<commit>` a
/// load bound into it, when that is a full commit.
pub(crate) fn pinned_commit(transform: &str) -> Option<&str> {
    let (_, commit) = transform.rsplit_once(";revision=")?;
    is_commit(commit).then_some(commit)
}

/// A look, off the load path, at whether a configured ref still names the
/// commit a vault pinned and this host serves.
pub(crate) struct RefCheck {
    base_url: String,
    /// The configuration as written: its revision the ref.
    asked: LocalEmbedderConfig,
    /// The commit served.
    serving: String,
}

impl RefCheck {
    /// The owner's warning when the ref names another commit now. `None`
    /// when it still names the one served, or when the hub could not be
    /// asked: that is logged, and the host serves its commit as before.
    /// Blocking: one small request.
    pub(crate) fn run(self) -> Option<String> {
        let ref_name = format!("{}@{}", self.asked.repo, self.asked.revision);
        match hub_commit_at(&self.base_url, &self.asked) {
            Ok(now) if now == self.serving => None,
            Ok(now) => {
                tracing::warn!(
                    model = %ref_name,
                    serving = %self.serving,
                    now = %now,
                    "embedder model ref moved; serving the vault's pinned commit until reembed"
                );
                Some(format!(
                    "{ref_name} now names commit {now}; this vault keeps serving its pinned commit {}, and `oneiron reembed` takes the new weights",
                    self.serving
                ))
            }
            Err(error) => {
                tracing::info!(
                    model = %ref_name,
                    serving = %self.serving,
                    %error,
                    "embedder model ref not checked; serving the vault's pinned commit"
                );
                None
            }
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
    /// commit as it stands; an operator's `model_dir` as configured; a ref
    /// the commit `pinned` (the vault's transform) names, with no request;
    /// any other ref asked of the hub once, its answer a full commit or an
    /// error. Never a guess: a lookup that fails fails the load, which the
    /// worker tries again. `reembed` and a vault with nothing pinned pass no
    /// pin, and take the commit the ref names now.
    pub(in crate::embedder) fn resolve_local_revision(
        &self,
        config: &LocalEmbedderConfig,
        pinned: Option<&str>,
    ) -> oneiron::Result<ResolvedLocalRevision> {
        let requested = config.revision.clone();
        if config.model_dir.is_some() || is_commit(&requested) {
            return Ok(ResolvedLocalRevision {
                requested,
                config: config.clone(),
                from_pin: false,
            });
        }
        if let Some(commit) = pinned.and_then(pinned_commit) {
            super::check_cache_identity(config)?;
            let mut resolved = config.clone();
            resolved.revision = commit.to_owned();
            return Ok(ResolvedLocalRevision {
                requested,
                config: resolved,
                from_pin: true,
            });
        }
        let commit = hub_commit_at(&self.base_url, config)?;
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
            from_pin: false,
        })
    }

    /// The check of a ref whose commit came from the vault's pin, to run
    /// once the model serves; `None` when nothing was taken from a pin.
    pub(in crate::embedder) fn ref_check(
        &self,
        resolved: &ResolvedLocalRevision,
    ) -> Option<RefCheck> {
        resolved.from_pin.then(|| {
            let mut asked = resolved.config.clone();
            asked.revision = resolved.requested.clone();
            RefCheck {
                base_url: self.base_url.clone(),
                asked,
                serving: resolved.config.revision.clone(),
            }
        })
    }
}

/// The commit the hub at `base_url` says `config.revision` names now. The
/// repository and ref are checked as plain names first, so neither reaches
/// past the hub's model route.
fn hub_commit_at(base_url: &str, config: &LocalEmbedderConfig) -> oneiron::Result<String> {
    super::check_cache_identity(config)?;
    let url = format!(
        "{}/api/models/{}/revision/{}",
        base_url, config.repo, config.revision
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
