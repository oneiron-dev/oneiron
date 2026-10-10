//! The `[feedback]` section: where the owner's feedback goes (OF-420). Unset,
//! `/v1/owner/feedback` has nowhere to send and says so. The destination's
//! credential never sits in the file: `serve` reads it from
//! `ONEIRON_FEEDBACK_TOKEN`.

use serde::Deserialize;

use crate::feedback_delivery::{FeedbackDeliveryConfig, FeedbackDestination, check_endpoint};

/// Resolved feedback destination.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct FeedbackConfig {
    /// `cloud`, `collector` or `github_issue`.
    pub destination: Option<FeedbackDestination>,
    /// The exact HTTPS endpoint the owner's approval names.
    pub endpoint: Option<String>,
}

impl FeedbackConfig {
    /// The delivery both keys describe; `None` while either is unset.
    pub fn delivery(&self) -> Option<FeedbackDeliveryConfig> {
        Some(FeedbackDeliveryConfig {
            destination: self.destination?,
            endpoint: self.endpoint.clone()?,
        })
    }

    pub(super) fn apply_override(&mut self, over: FeedbackConfigOverride) {
        if let Some(value) = over.destination {
            self.destination = Some(value);
        }
        if let Some(value) = over.endpoint {
            self.endpoint = Some(value);
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        match (&self.destination, &self.endpoint) {
            (None, None) => Ok(()),
            (Some(_), Some(endpoint)) => check_endpoint(endpoint).map_err(|_| {
                anyhow::anyhow!(
                    "feedback.endpoint must be an HTTPS URL (HTTP only on loopback) with no \
                     credentials, query or fragment"
                )
            }),
            _ => anyhow::bail!("set feedback.destination and feedback.endpoint together"),
        }
    }
}

/// One layer's `[feedback]` keys.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FeedbackConfigOverride {
    pub(super) destination: Option<FeedbackDestination>,
    pub(super) endpoint: Option<String>,
}

pub(super) fn lookup_feedback_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<FeedbackConfigOverride>> {
    let destination = lookup("ONEIRON_FEEDBACK_DESTINATION")
        .map(|value| {
            serde_json::from_value(serde_json::Value::String(value.clone())).map_err(|_| {
                anyhow::anyhow!(
                    "ONEIRON_FEEDBACK_DESTINATION must be cloud, collector or github_issue, not {value:?}"
                )
            })
        })
        .transpose()?;
    let over = FeedbackConfigOverride {
        destination,
        endpoint: lookup("ONEIRON_FEEDBACK_ENDPOINT"),
    };
    Ok((over != FeedbackConfigOverride::default()).then_some(over))
}

// Debug names the endpoint's host only: a URL can carry credentials, and a
// rejected one is still printed when a layer is logged.
impl std::fmt::Debug for FeedbackConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedbackConfig")
            .field("destination", &self.destination)
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .finish()
    }
}

impl std::fmt::Debug for FeedbackConfigOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedbackConfigOverride")
            .field("destination", &self.destination)
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .finish()
    }
}

fn endpoint_host(endpoint: Option<&str>) -> Option<String> {
    endpoint
        .and_then(|endpoint| reqwest::Url::parse(endpoint).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
}
