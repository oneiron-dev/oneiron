//! The `[failure_signals]` section: the publisher this deployment's failure
//! signals go to (OF-380, DEC-0005 #world-privacy-p8-tier2). Whether it sends
//! at all is the participation switch, `failure_signal_export`: automatic in
//! the hosted posture, off on self-host until the owner opts in. This names
//! where the tier-1 counts and the sealed code-fix records go. A hosted
//! deployment sends to our own collector unless told otherwise; elsewhere,
//! with no endpoint, nothing leaves and sealed records wait in the vault. The
//! destination's credential never sits in the file: `serve` reads it from
//! `ONEIRON_FAILURE_SIGNALS_TOKEN`.
//!
//! `[failure_signals.candidates.<id>]` names the publisher's candidate fixes
//! the Coach replays in the vault against each real failure: an instruction
//! file the publisher ships and the operator installs, pinned by its SHA-256.
//! Nothing fetches it and nothing installs it; only the fixed or not-fixed
//! result leaves, and only when the deployment participates.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::code_fix::PublisherCandidate;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::lookup::lookup_parse;
use crate::feedback_delivery::check_endpoint;

/// Where a vault our cloud hosts sends its failure signals unless told
/// otherwise.
pub const CLOUD_FAILURE_SIGNALS_ENDPOINT: &str = "https://oneiron.dev/failure-signals";

const DEFAULT_EVERY_SECS: u64 = 3_600;
const DEFAULT_BATCH: usize = 64;
/// Most publisher candidates one deployment replays: each costs every
/// failure case a replay and a judgment.
const MAX_PUBLISHER_CANDIDATES: usize = 8;
/// Most bytes of one candidate's instruction.
const MAX_PUBLISHER_INSTRUCTION_BYTES: usize = 16 * 1024;
/// Most bytes of a candidate's id.
const MAX_CANDIDATE_ID_BYTES: usize = 40;
/// Hex digits of the pin an exported result names.
const EXPORTED_PIN_HEX: usize = 16;

/// One publisher candidate: its instruction file and that file's pin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublisherCandidateConfig {
    /// Absolute path of the instruction text, UTF-8.
    pub instructions_file: PathBuf,
    /// The file's SHA-256, lowercase hex. A file that differs is refused.
    pub sha256: String,
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
    /// order. Its result exports as `publisher.<id>@<pin prefix>`.
    pub fn publisher_candidates(&self) -> anyhow::Result<Arc<[PublisherCandidate]>> {
        anyhow::ensure!(
            self.candidates.len() <= MAX_PUBLISHER_CANDIDATES,
            "failure_signals.candidates holds at most {MAX_PUBLISHER_CANDIDATES} candidates"
        );
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
            && id.len() <= MAX_CANDIDATE_ID_BYTES
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')),
        "failure_signals.candidates: an id is 1 to {MAX_CANDIDATE_ID_BYTES} of a-z, 0-9, _ and -"
    );
    let field = format!("failure_signals.candidates.{id}");
    anyhow::ensure!(
        candidate.sha256.len() == 64
            && candidate
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{field}.sha256 must be 64 lowercase hex digits"
    );
    anyhow::ensure!(
        candidate.instructions_file.is_absolute(),
        "{field}.instructions_file must be an absolute path"
    );
    let bytes = std::fs::read(&candidate.instructions_file).map_err(|error| {
        anyhow::anyhow!(
            "{field}: read {}: {error}",
            candidate.instructions_file.display()
        )
    })?;
    anyhow::ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == candidate.sha256,
        "{field}: {} does not match its sha256",
        candidate.instructions_file.display()
    );
    let instruction = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{field}: the instructions are not UTF-8"))?;
    anyhow::ensure!(
        !instruction.trim().is_empty() && instruction.len() <= MAX_PUBLISHER_INSTRUCTION_BYTES,
        "{field}: the instructions hold 1 to {MAX_PUBLISHER_INSTRUCTION_BYTES} bytes"
    );
    Ok(PublisherCandidate {
        id: format!("publisher.{id}@{}", &candidate.sha256[..EXPORTED_PIN_HEX]),
        instruction,
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
