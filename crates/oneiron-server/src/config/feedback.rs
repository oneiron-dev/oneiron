//! The `[feedback]` section: where the owner's feedback goes (OF-420). Unset,
//! `/v1/owner/feedback` has nowhere to send and says so. The destination's
//! credential never sits in the file: `serve` reads it from
//! `ONEIRON_FEEDBACK_TOKEN`. Its `[feedback.inbox]` table opens this vault's
//! own keyless inbox (ARCH-0056 #open-inbox), off unless enabled.

use serde::Deserialize;

use super::lookup::lookup_bool;
use crate::feedback_delivery::{FeedbackDeliveryConfig, FeedbackDestination, check_endpoint};

/// Resolved feedback destination.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct FeedbackConfig {
    /// `cloud`, `collector` or `github_issue`.
    pub destination: Option<FeedbackDestination>,
    /// The exact HTTPS endpoint the owner's approval names.
    pub endpoint: Option<String>,
    /// `[feedback.inbox]`: the open inbox this server keeps.
    pub inbox: FeedbackInboxConfig,
}

/// Where a vault our cloud hosts sends feedback unless told otherwise:
/// on by default in the cloud (ARCH-0056 r6), off on self-host. Every send
/// still asks the owner first.
pub const CLOUD_FEEDBACK_ENDPOINT: &str = "https://oneiron.dev/feedback";

/// The `[feedback.inbox]` table. On, anyone may leave this vault a note at
/// `/v1/feedback` with no key and no moderation; the counts below are its
/// only limit, past which a sender is shed until the hour turns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackInboxConfig {
    pub enabled: bool,
    /// Notes one sender may leave in an hour.
    pub notes_per_sender: u32,
    /// Notes the inbox takes in an hour, from every sender together.
    pub notes_per_hour: u32,
}

impl Default for FeedbackInboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            notes_per_sender: 20,
            notes_per_hour: 2_000,
        }
    }
}

impl FeedbackConfig {
    /// The default for a vault our cloud hosts: sends go to our own inbox.
    #[must_use]
    pub fn cloud_default() -> Self {
        Self {
            destination: Some(FeedbackDestination::Collector),
            endpoint: Some(CLOUD_FEEDBACK_ENDPOINT.to_owned()),
            inbox: FeedbackInboxConfig::default(),
        }
    }

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
        if let Some(inbox) = over.inbox {
            if let Some(value) = inbox.enabled {
                self.inbox.enabled = value;
            }
            if let Some(value) = inbox.notes_per_sender {
                self.inbox.notes_per_sender = value;
            }
            if let Some(value) = inbox.notes_per_hour {
                self.inbox.notes_per_hour = value;
            }
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        // A zero count would shed every note: an inbox that is on but closed.
        if self.inbox.notes_per_sender == 0 || self.inbox.notes_per_hour == 0 {
            anyhow::bail!("feedback.inbox.notes_per_sender and notes_per_hour must be at least 1");
        }
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
    pub(super) inbox: Option<FeedbackInboxOverride>,
}

/// One layer's `[feedback.inbox]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FeedbackInboxOverride {
    pub(super) enabled: Option<bool>,
    pub(super) notes_per_sender: Option<u32>,
    pub(super) notes_per_hour: Option<u32>,
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
        inbox: lookup_bool(lookup, "ONEIRON_FEEDBACK_INBOX")?.map(|enabled| {
            FeedbackInboxOverride {
                enabled: Some(enabled),
                ..FeedbackInboxOverride::default()
            }
        }),
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
            .field("inbox", &self.inbox)
            .finish()
    }
}

impl std::fmt::Debug for FeedbackConfigOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedbackConfigOverride")
            .field("destination", &self.destination)
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .field("inbox", &self.inbox)
            .finish()
    }
}

fn endpoint_host(endpoint: Option<&str>) -> Option<String> {
    endpoint
        .and_then(|endpoint| reqwest::Url::parse(endpoint).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
}
