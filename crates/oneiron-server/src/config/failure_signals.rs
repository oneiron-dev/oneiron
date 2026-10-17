//! The `[failure_signals]` section: the publisher this deployment's failure
//! signals go to (OF-380, DEC-0005 #world-privacy-p8-tier2). Whether it sends
//! at all is the participation switch, `failure_signal_export`: automatic in
//! the hosted posture, off on self-host until the owner opts in. This names
//! where the tier-1 counts and the sealed code-fix records go. A hosted
//! deployment sends to our own collector unless told otherwise; elsewhere,
//! with no endpoint, nothing leaves and sealed records wait in the vault. The
//! destination's credential never sits in the file: `serve` reads it from
//! `ONEIRON_FAILURE_SIGNALS_TOKEN`.

use serde::Deserialize;

use super::lookup::lookup_parse;
use crate::feedback_delivery::check_endpoint;

/// Where a vault our cloud hosts sends its failure signals unless told
/// otherwise.
pub const CLOUD_FAILURE_SIGNALS_ENDPOINT: &str = "https://oneiron.dev/failure-signals";

const DEFAULT_EVERY_SECS: u64 = 3_600;
const DEFAULT_BATCH: usize = 64;

/// Resolved failure-signal destination.
#[derive(Clone, Eq, PartialEq)]
pub struct FailureSignalsConfig {
    /// The publisher's exact HTTPS endpoint. `None` takes the hosted default.
    pub endpoint: Option<String>,
    /// Seconds between delivery passes.
    pub every_secs: u64,
    /// Sealed code-fix records one delivery carries at most.
    pub batch: usize,
}

impl Default for FailureSignalsConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            every_secs: DEFAULT_EVERY_SECS,
            batch: DEFAULT_BATCH,
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
        Ok(())
    }
}

/// One layer's `[failure_signals]` keys.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FailureSignalsConfigOverride {
    pub(super) endpoint: Option<String>,
    pub(super) every_secs: Option<u64>,
    pub(super) batch: Option<usize>,
}

pub(super) fn lookup_failure_signals_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<FailureSignalsConfigOverride>> {
    let over = FailureSignalsConfigOverride {
        endpoint: lookup("ONEIRON_FAILURE_SIGNALS_ENDPOINT"),
        every_secs: lookup_parse(lookup, "ONEIRON_FAILURE_SIGNALS_EVERY_SECS")?,
        batch: lookup_parse(lookup, "ONEIRON_FAILURE_SIGNALS_BATCH")?,
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
            .finish()
    }
}

impl std::fmt::Debug for FailureSignalsConfigOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureSignalsConfigOverride")
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .field("every_secs", &self.every_secs)
            .field("batch", &self.batch)
            .finish()
    }
}

fn endpoint_host(endpoint: Option<&str>) -> Option<String> {
    endpoint
        .and_then(|endpoint| reqwest::Url::parse(endpoint).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
}
