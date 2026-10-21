//! The `[failure_signals]` section: the publisher this deployment's failure
//! signals go to (OF-380, DEC-0005 #world-privacy-p8-tier2). Whether it sends
//! at all is the "Help improve Oneiron" switch, `failure_signal_export`: on by
//! default in the hosted posture, where the owner can turn it off, and off on
//! self-host until the owner opts in. This names where the tier-1 counts and
//! the sealed code-fix records go. A hosted deployment sends to our own
//! collector unless told otherwise; elsewhere, with no endpoint, nothing
//! leaves and sealed records wait in the vault. The destination's credential
//! never sits in the file: `serve` reads it from
//! `ONEIRON_FAILURE_SIGNALS_TOKEN`.
//!
//! `[failure_signals.candidates.<id>]` names the publisher's candidate fixes
//! the Coach replays in the vault against each real failure: an instruction
//! file the publisher ships and the operator installs, pinned by its SHA-256,
//! or a candidate engine (FIX 1661, 2144), a build or a patch over its base
//! build, pinned by digest, which the Coach's shadow runner runs in a
//! sandboxed arm of its own once it can. Nothing fetches either and nothing
//! installs it; only the fixed or not-fixed result leaves, under a token
//! naming the whole pin, and only when the deployment participates. Every
//! candidate pinned is replayed, each whole: the vault measures them, and
//! nothing here caps their count or size.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::code_fix::{
    PublisherCandidate, PublisherCandidateKind, artifact_digest_text, parse_artifact_digest_text,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::lookup::lookup_parse;
use crate::feedback_delivery::check_endpoint;

/// Where a vault our cloud hosts sends its failure signals unless told
/// otherwise.
pub const CLOUD_FAILURE_SIGNALS_ENDPOINT: &str = "https://oneiron.dev/failure-signals";

const DEFAULT_EVERY_SECS: u64 = 3_600;
const DEFAULT_BATCH: usize = 64;
/// The `kind` of a candidate engine build.
const ENGINE_BUILD_KIND: &str = "engine_build";
/// The `kind` of a candidate patch over its base build.
const ENGINE_PATCH_KIND: &str = "engine_patch";

/// One publisher candidate: an instruction file and that file's pin, as it
/// has always been written, or a candidate engine by its `kind`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged, deny_unknown_fields)]
pub enum PublisherCandidateConfig {
    /// An instruction the publisher ships and the operator installs.
    Instruction {
        /// Absolute path of the instruction text, UTF-8.
        instructions_file: PathBuf,
        /// The file's SHA-256, lowercase hex. A file that differs is refused.
        sha256: String,
    },
    /// A candidate engine, by digest (FIX 1661, 2144). Nothing fetches or
    /// installs it.
    Engine {
        /// `engine_build`, or `engine_patch` for a patch over its base build.
        kind: String,
        /// The build, or a patch's base build: `blake3:` or `sha256:` and
        /// its 64 lowercase hex digits.
        build: String,
        /// An `engine_patch`'s patch, spelled as `build` is; none for an
        /// `engine_build`.
        #[serde(default)]
        patch: Option<String>,
    },
}

/// Resolved failure-signal destination.
#[derive(Clone, Eq, PartialEq)]
pub struct FailureSignalsConfig {
    /// The publisher's exact HTTPS endpoint. `None` takes the hosted default.
    pub endpoint: Option<String>,
    /// Seconds between delivery passes.
    pub every_secs: u64,
    /// Sealed code-fix records one delivery carries at most.
    pub batch: usize,
    /// The publisher's candidate fixes, by id. A later layer's table
    /// replaces an earlier one's whole.
    pub candidates: BTreeMap<String, PublisherCandidateConfig>,
}

impl Default for FailureSignalsConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            every_secs: DEFAULT_EVERY_SECS,
            batch: DEFAULT_BATCH,
            candidates: BTreeMap::new(),
        }
    }
}

impl FailureSignalsConfig {
    /// The endpoint sends go to: the configured one, else our collector
    /// when `hosted`. `None` sends nothing.
    #[must_use]
    pub fn destination(&self, hosted: bool) -> Option<String> {
        self.endpoint
            .clone()
            .or_else(|| hosted.then(|| CLOUD_FAILURE_SIGNALS_ENDPOINT.to_owned()))
    }

    pub(super) fn apply_override(&mut self, over: FailureSignalsConfigOverride) {
        if let Some(value) = over.endpoint {
            self.endpoint = Some(value);
        }
        if let Some(value) = over.every_secs {
            self.every_secs = value;
        }
        if let Some(value) = over.batch {
            self.batch = value;
        }
        if let Some(value) = over.candidates {
            self.candidates = value;
        }
    }

    /// Each publisher candidate read and checked against its pin, in id
    /// order. Its result exports as `publisher.<id>@<pin>`, the pin whole:
    /// an instruction file's SHA-256 in hex, or an engine's build digest and,
    /// for a patch, `+` and the patch's.
    pub fn publisher_candidates(&self) -> anyhow::Result<Arc<[PublisherCandidate]>> {
        self.candidates
            .iter()
            .map(|(id, candidate)| load_candidate(id, candidate))
            .collect()
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.every_secs > 0 && self.batch > 0,
            "failure_signals.every_secs and batch must be at least 1"
        );
        if let Some(endpoint) = &self.endpoint {
            check_endpoint(endpoint).map_err(|_| {
                anyhow::anyhow!(
                    "failure_signals.endpoint must be an HTTPS URL (HTTP only on loopback) with \
                     no credentials, query or fragment"
                )
            })?;
        }
        self.publisher_candidates()?;
        Ok(())
    }
}

fn load_candidate(
    id: &str,
    candidate: &PublisherCandidateConfig,
) -> anyhow::Result<PublisherCandidate> {
    anyhow::ensure!(
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')),
        "failure_signals.candidates: an id is one or more of a-z, 0-9, _ and -"
    );
    let field = format!("failure_signals.candidates.{id}");
    match candidate {
        PublisherCandidateConfig::Instruction {
            instructions_file,
            sha256,
        } => load_instruction(id, &field, instructions_file, sha256),
        PublisherCandidateConfig::Engine { kind, build, patch } => {
            engine_candidate(id, &field, kind, build, patch.as_deref())
        }
    }
}

/// An instruction candidate, its file read and checked against its pin.
fn load_instruction(
    id: &str,
    field: &str,
    instructions_file: &Path,
    sha256: &str,
) -> anyhow::Result<PublisherCandidate> {
    anyhow::ensure!(
        sha256.len() == 64
            && sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{field}.sha256 must be 64 lowercase hex digits"
    );
    anyhow::ensure!(
        instructions_file.is_absolute(),
        "{field}.instructions_file must be an absolute path"
    );
    let bytes = std::fs::read(instructions_file).map_err(|error| {
        anyhow::anyhow!("{field}: read {}: {error}", instructions_file.display())
    })?;
    anyhow::ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == sha256,
        "{field}: {} does not match its sha256",
        instructions_file.display()
    );
    let instruction = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{field}: the instructions are not UTF-8"))?;
    anyhow::ensure!(
        !instruction.trim().is_empty(),
        "{field}: the instructions are empty"
    );
    Ok(PublisherCandidate {
        id: format!("publisher.{id}@{sha256}"),
        kind: PublisherCandidateKind::Instruction { instruction },
    })
}

/// An engine candidate, by its `kind` and digests (FIX 1661, 2144).
fn engine_candidate(
    id: &str,
    field: &str,
    kind: &str,
    build: &str,
    patch: Option<&str>,
) -> anyhow::Result<PublisherCandidate> {
    let digest = |name: &str, text: &str| {
        parse_artifact_digest_text(text).ok_or_else(|| {
            anyhow::anyhow!("{field}.{name} must be blake3: or sha256: and 64 lowercase hex digits")
        })
    };
    let build = digest("build", build)?;
    let (kind, pin) = match (kind, patch) {
        (ENGINE_BUILD_KIND, None) => (
            PublisherCandidateKind::EngineBuild { build },
            artifact_digest_text(&build),
        ),
        (ENGINE_PATCH_KIND, Some(patch)) => {
            let patch = digest("patch", patch)?;
            (
                PublisherCandidateKind::EnginePatch { build, patch },
                format!(
                    "{}+{}",
                    artifact_digest_text(&build),
                    artifact_digest_text(&patch)
                ),
            )
        }
        _ => anyhow::bail!(
            "{field}: an engine candidate is kind = \"{ENGINE_BUILD_KIND}\" with its build, or \
             kind = \"{ENGINE_PATCH_KIND}\" with its base build and its patch"
        ),
    };
    Ok(PublisherCandidate {
        id: format!("publisher.{id}@{pin}"),
        kind,
    })
}

/// One layer's `[failure_signals]` keys.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FailureSignalsConfigOverride {
    pub(super) endpoint: Option<String>,
    pub(super) every_secs: Option<u64>,
    pub(super) batch: Option<usize>,
    /// File layers only.
    pub(super) candidates: Option<BTreeMap<String, PublisherCandidateConfig>>,
}

pub(super) fn lookup_failure_signals_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<FailureSignalsConfigOverride>> {
    let over = FailureSignalsConfigOverride {
        endpoint: lookup("ONEIRON_FAILURE_SIGNALS_ENDPOINT"),
        every_secs: lookup_parse(lookup, "ONEIRON_FAILURE_SIGNALS_EVERY_SECS")?,
        batch: lookup_parse(lookup, "ONEIRON_FAILURE_SIGNALS_BATCH")?,
        candidates: None,
    };
    Ok((over != FailureSignalsConfigOverride::default()).then_some(over))
}

// Debug names the endpoint's host only: a URL can carry credentials, and a
// rejected one is still printed when a layer is logged.
impl std::fmt::Debug for FailureSignalsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureSignalsConfig")
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .field("every_secs", &self.every_secs)
            .field("batch", &self.batch)
            .field("candidates", &self.candidates)
            .finish()
    }
}

impl std::fmt::Debug for FailureSignalsConfigOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureSignalsConfigOverride")
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .field("every_secs", &self.every_secs)
            .field("batch", &self.batch)
            .field("candidates", &self.candidates)
            .finish()
    }
}

fn endpoint_host(endpoint: Option<&str>) -> Option<String> {
    endpoint
        .and_then(|endpoint| reqwest::Url::parse(endpoint).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
}
