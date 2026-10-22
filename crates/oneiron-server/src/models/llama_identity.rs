//! What a house llama.cpp answer names about the process that answered it
//! (FIX 7895, 6567 PR1b): its launch alias, read by the one parser
//! (`oneiron::llm::parse_llama_alias`), resolved to that launch's identity
//! manifest.
//!
//! The house launcher (`deploy/house-model/llama_identity.py`) mints one
//! epoch per launch, writes the manifest of what the launch loaded and runs
//! with, and starts llama-server under the alias that names both; the server
//! serves its manifests directory at its own root (`--path`), so a manifest
//! is `GET /<digest>.json` on the origin that answered. A manifest is fetched
//! once per origin, alias and configured target, and kept only when the
//! SHA-256 of its exact bytes is the alias's digest, its epoch is the
//! alias's and its configured wire id is the route's. Whatever the fetch
//! gave, verified or not, holds for the resolver's life: the bytes behind a
//! digest never change. A manifest that cannot be fetched or verified leaves
//! its digests unknown; it never refuses the answer, and never makes it
//! another model's. The epoch is the answer's own alias's either way.
//!
//! A manifest attests the launch, not each call: per-call settings (template
//! arguments, reasoning, samplers, a request's own cache options) are not in
//! it, so no record's `execution_mode` comes from it.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::llm::{
    CacheDigest, CacheEpoch, CacheIdentity, LlamaAlias, WorkerBuildEvidence, parse_llama_alias,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use super::http::{MAX_REPLY_BYTES, ProviderHttp};

/// The manifest schema this reader knows.
const SCHEMA_VERSION: u64 = 1;
/// The backend a llama.cpp manifest names.
const BACKEND: &str = "llama_cpp";

/// Every manifest this server has looked up, by where and for what. One per
/// llama.cpp launch a route has answered from.
type Manifests = HashMap<ManifestKey, Arc<OnceCell<Option<Arc<LlamaIdentityManifest>>>>>;

/// The launch manifests the house llama.cpp routes' answers name, fetched
/// once each and shared by the chat and the native transports.
#[derive(Default)]
pub(super) struct LlamaIdentityResolver {
    manifests: Mutex<Manifests>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ManifestKey {
    /// The server's root URL: the origin the answer came from.
    root: String,
    alias: LlamaAlias,
    target: String,
}

/// The digests one verified manifest lists: what the launcher took of what
/// that launch loaded and runs with. One it leaves out stays absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(super) struct LlamaIdentityManifest {
    /// The target GGUF's bytes.
    #[serde(default)]
    model: Option<CacheDigest>,
    /// The target's typed tokenizer metadata, chat templates aside.
    #[serde(default)]
    tokenizer: Option<CacheDigest>,
    /// The build: the pinned source and the binary's own SHA-256.
    #[serde(default)]
    runtime: Option<CacheDigest>,
    /// The chat templates the server selected, by their bytes.
    #[serde(default)]
    template: Option<CacheDigest>,
    /// The launch's explicit cache settings.
    #[serde(default)]
    cache_mode: Option<CacheDigest>,
}

/// The manifest's fields this reader checks, beside its digests. Its other
/// sections are the record the digests were taken of.
#[derive(Deserialize)]
struct ManifestWire {
    schema_version: u64,
    backend: String,
    backend_epoch: CacheEpoch,
    configured_wire_id: String,
    identity: LlamaIdentityManifest,
}

/// The identity one answer's own alias names: the launch's epoch, and its
/// manifest's digests when the manifest verified.
pub(super) struct AnsweringIdentity {
    epoch: CacheEpoch,
    manifest: Option<Arc<LlamaIdentityManifest>>,
}

impl AnsweringIdentity {
    /// The identity `returned`, a reply's own `model`, names when no manifest
    /// can be looked up for it (a brokered reply, which comes from no origin
    /// this server reaches): the launch's epoch alone. `None` when it is not
    /// a launch alias.
    pub(super) fn epoch_only(returned: &str) -> Option<Self> {
        parse_llama_alias(returned).map(|alias| Self {
            epoch: alias.epoch,
            manifest: None,
        })
    }

    /// How the answering launch's build is known (FIX 8314): verified
    /// artifacts only when its manifest resolved and verified (its bytes'
    /// digest, its epoch and the route's configured wire id) and lists the
    /// build it attests; unknown otherwise, an epoch-only first answer of a
    /// launch included.
    pub(super) fn build_evidence(&self) -> WorkerBuildEvidence {
        match self.manifest.as_deref() {
            Some(manifest) if manifest.runtime.is_some() => WorkerBuildEvidence::VerifiedArtifacts,
            _ => WorkerBuildEvidence::Unknown,
        }
    }

    /// A chat answer's identity: the server rendered its prompt with the
    /// chat template the manifest names.
    pub(super) fn for_chat(&self) -> CacheIdentity {
        let manifest = self.manifest.as_deref().cloned().unwrap_or_default();
        CacheIdentity {
            model: manifest.model,
            tokenizer: manifest.tokenizer,
            runtime: manifest.runtime,
            template: manifest.template,
            execution_mode: None,
            cache_mode: manifest.cache_mode,
            backend_epoch: Some(self.epoch.clone()),
        }
    }

    /// A native answer's identity, with no template: a native prompt is the
    /// host's recipe, rendered by the host, and the recipe's revision is its
    /// identity. The server's chat template never ran on it.
    pub(super) fn for_native(&self) -> CacheIdentity {
        CacheIdentity {
            template: None,
            ..self.for_chat()
        }
    }
}

impl LlamaIdentityResolver {
    /// The identity `returned`, a reply's own top-level `model`, names on
    /// `http`'s route, whose configured wire id is `target`. `None` when it
    /// is not a launch alias. Without a target there is nothing to bind a
    /// manifest to, so only the epoch is known.
    pub(super) async fn resolve(
        &self,
        http: &ProviderHttp,
        returned: Option<&str>,
        target: Option<&str>,
    ) -> Option<AnsweringIdentity> {
        let alias = parse_llama_alias(returned?)?;
        let manifest = match target {
            Some(target) => self.manifest(http, &alias, target),
            None => None,
        };
        Some(AnsweringIdentity {
            epoch: alias.epoch,
            manifest,
        })
    }

    /// The launch's verified manifest once its one GET has landed. An answer
    /// never waits on that GET: the first answers of a launch start it beside
    /// them and carry only the epoch, and later answers read what it found.
    fn manifest(
        &self,
        http: &ProviderHttp,
        alias: &LlamaAlias,
        target: &str,
    ) -> Option<Arc<LlamaIdentityManifest>> {
        let key = ManifestKey {
            root: http.native().url("/"),
            alias: alias.clone(),
            target: target.to_owned(),
        };
        let cell = Arc::clone(
            self.manifests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key)
                .or_default(),
        );
        if let Some(found) = cell.get() {
            return found.clone();
        }
        let (http, alias, target) = (http.clone(), alias.clone(), target.to_owned());
        tokio::spawn(async move {
            cell.get_or_init(|| fetch(&http, &alias, &target)).await;
        });
        None
    }
}

/// One GET of the alias's manifest, bounded as any reply is, then its
/// checks.
async fn fetch(
    http: &ProviderHttp,
    alias: &LlamaAlias,
    target: &str,
) -> Option<Arc<LlamaIdentityManifest>> {
    let path = format!("/{}.json", alias.manifest.as_str());
    let verified = match http.get_native_within(&path, MAX_REPLY_BYTES).await {
        Ok(reply) if (200..300).contains(&reply.status) => verify(&reply.body, alias, target),
        _ => None,
    };
    if verified.is_none() {
        tracing::warn!(
            epoch = alias.epoch.as_str(),
            "a house llama.cpp answer's identity manifest did not resolve; its digests stay unknown"
        );
    }
    verified.map(Arc::new)
}

/// The manifest's digests, when its exact bytes hash to the alias's digest
/// and it names the alias's epoch and the route's configured wire id.
fn verify(bytes: &[u8], alias: &LlamaAlias, target: &str) -> Option<LlamaIdentityManifest> {
    if format!("{:x}", Sha256::digest(bytes)) != alias.manifest.as_str() {
        return None;
    }
    let manifest: ManifestWire = serde_json::from_slice(bytes).ok()?;
    (manifest.schema_version == SCHEMA_VERSION
        && manifest.backend == BACKEND
        && manifest.backend_epoch == alias.epoch
        && manifest.configured_wire_id == target)
        .then_some(manifest.identity)
}
