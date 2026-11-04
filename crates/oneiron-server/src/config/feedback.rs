//! The `[feedback]` section: where the owner's feedback goes (OF-420). Unset,
//! `/v1/owner/feedback` has nowhere to send and says so. The destination's
//! credential never sits in the file: `key_secret` names the vault secret
//! holding the bearer, read at the custody door when serve starts, else a
//! plain serve reads `ONEIRON_FEEDBACK_TOKEN`. Its `[feedback.inbox]` table
//! opens this vault's own keyless inbox (ARCH-0056 #open-inbox), off unless
//! enabled. Its `[feedback.triage]` table binds the GitHub repositories the
//! Coach's feedback sweep reads; none by default.

use std::collections::BTreeSet;

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
    /// The vault secret holding the private endpoint's bearer, read at the
    /// custody door when serve starts; wins over `ONEIRON_FEEDBACK_TOKEN`.
    pub key_secret: Option<String>,
    /// `[feedback.inbox]`: the open inbox this server keeps.
    pub inbox: FeedbackInboxConfig,
    /// `[feedback.triage]`: the repositories the feedback sweep reads.
    pub triage: FeedbackTriageConfig,
}

/// Where a vault our cloud hosts sends feedback unless told otherwise:
/// on by default in the cloud (ARCH-0056 r6), off on self-host. Every send
/// still asks the owner first.
pub const CLOUD_FEEDBACK_ENDPOINT: &str = "https://oneiron.dev/feedback";

/// The custody effector the feedback bearer secret is bound to: the door
/// hands the key to a feedback send and to nothing else. The owner binds it
/// with `POST /v1/owner/secrets/bind`, effector `feedback:send`.
const FEEDBACK_BEARER_EFFECTOR: &str = "feedback:send";

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

/// The `[feedback.triage]` table (ARCH-0056: "GitHub issues still work. We
/// sweep both on a schedule with the triage skill"). Each GitHub repository
/// the Coach's feedback sweep reads is bound by its exact issues endpoint.
/// Empty, the default, sends no request anywhere: only a repository named
/// here is read. One on the `github_issue` destination's own origin is read
/// with that destination's credential; every other goes without.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct FeedbackTriageConfig {
    /// `https://<host>/repos/<owner>/<repo>/issues`, or the same under
    /// GitHub Enterprise's `/api/v3`: one per repository.
    pub github_sources: Vec<String>,
}

impl FeedbackConfig {
    /// The default for a vault our cloud hosts: sends go to our own inbox.
    #[must_use]
    pub fn cloud_default() -> Self {
        Self {
            destination: Some(FeedbackDestination::Collector),
            endpoint: Some(CLOUD_FEEDBACK_ENDPOINT.to_owned()),
            key_secret: None,
            inbox: FeedbackInboxConfig::default(),
            triage: FeedbackTriageConfig::default(),
        }
    }

    /// The delivery both keys describe; `None` while either is unset.
    pub fn delivery(&self) -> Option<FeedbackDeliveryConfig> {
        Some(FeedbackDeliveryConfig {
            destination: self.destination?,
            endpoint: self.endpoint.clone()?,
        })
    }

    /// The bearer serve sends with: the vault secret `key_secret` names,
    /// read at the custody door bound to `feedback:send`; `None` when none
    /// is named, or when the secret does not resolve (said once).
    pub(crate) fn bearer_from_secret(
        &self,
        vault: &oneiron::Vault,
    ) -> Option<zeroize::Zeroizing<String>> {
        let name = self.key_secret.as_deref()?;
        read_bearer_secret(vault, name, FEEDBACK_BEARER_EFFECTOR, "feedback.key_secret")
    }

    pub(super) fn apply_override(&mut self, over: FeedbackConfigOverride) {
        if let Some(value) = over.destination {
            self.destination = Some(value);
        }
        if let Some(value) = over.endpoint {
            self.endpoint = Some(value);
        }
        if let Some(value) = over.key_secret {
            self.key_secret = Some(value);
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
        // A layer that names the list names all of it: it is replaced whole.
        if let Some(triage) = over.triage
            && let Some(sources) = triage.github_sources
        {
            self.triage.github_sources = sources;
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        // A zero count would shed every note: an inbox that is on but closed.
        if self.inbox.notes_per_sender == 0 || self.inbox.notes_per_hour == 0 {
            anyhow::bail!("feedback.inbox.notes_per_sender and notes_per_hour must be at least 1");
        }
        if let Some(secret) = &self.key_secret
            && (secret.is_empty()
                || secret.len() > 256
                || !secret.bytes().all(|b| b.is_ascii_graphic()))
        {
            anyhow::bail!(
                "feedback.key_secret must name a vault secret (printable ASCII, no spaces); put the key itself in the vault, never in the config file"
            );
        }
        let mut bound = BTreeSet::new();
        for endpoint in &self.triage.github_sources {
            let Some(source) = github_issue_source(endpoint) else {
                anyhow::bail!(
                    "each feedback.triage.github_sources entry must be a repository's exact \
                     issues endpoint, https://<host>[/api/v3]/repos/<owner>/<repo>/issues (HTTP \
                     only on loopback), with no credentials, query or fragment"
                );
            };
            if !bound.insert(source) {
                anyhow::bail!("feedback.triage.github_sources binds one repository twice");
            }
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

/// Reads the vault secret `name` at the custody door bound to `effector`,
/// for a private endpoint's bearer (FIX 5013). The key is copied out and
/// wiped on drop, so the send never runs inside the door's transaction. A
/// secret that does not resolve is said once and reads as none, as a
/// missing bearer does today; its value is never logged.
pub(super) fn read_bearer_secret(
    vault: &oneiron::Vault,
    name: &str,
    effector: &'static str,
    field: &'static str,
) -> Option<zeroize::Zeroizing<String>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    if let Err(error) = vault.inject_secret_at_door(name, effector, &mut |value: &[u8]| {
        // Sized once, so no reallocation leaves an unwiped copy.
        bytes.reserve_exact(value.len());
        bytes.extend_from_slice(value);
        Ok(())
    }) {
        tracing::warn!(
            %error,
            secret = name,
            "{field} names a vault secret the custody door did not release; the endpoint sends with no bearer"
        );
        return None;
    }
    let bearer = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .unwrap_or_default();
    if bearer.is_empty() {
        tracing::warn!(
            secret = name,
            "{field} names a vault secret holding no bearer text; the endpoint sends with none"
        );
        return None;
    }
    Some(zeroize::Zeroizing::new(bearer.to_owned()))
}

/// The name the feedback sweep gives the repository a bound issues endpoint
/// names: `github:<owner>/<repo>`, in lower case. `None` for anything but
/// `https://<host>/repos/<owner>/<repo>/issues`, or the same under GitHub
/// Enterprise's `/api/v3`, HTTPS (HTTP only on loopback) with no
/// credentials, query or fragment.
pub(crate) fn github_issue_source(endpoint: &str) -> Option<String> {
    check_endpoint(endpoint).ok()?;
    let url = reqwest::Url::parse(endpoint).ok()?;
    let segments: Vec<&str> = url.path_segments()?.collect();
    let rest = match segments.as_slice() {
        ["api", "v3", rest @ ..] => rest,
        rest => rest,
    };
    let &["repos", owner, repo, "issues"] = rest else {
        return None;
    };
    (github_name(owner) && github_name(repo)).then(|| {
        format!(
            "{}{}/{}",
            oneiron::feedback::FEEDBACK_TRIAGE_GITHUB_PREFIX,
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        )
    })
}

/// An owner or repository name as GitHub spells one.
fn github_name(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// One layer's `[feedback]` keys.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FeedbackConfigOverride {
    pub(super) destination: Option<FeedbackDestination>,
    pub(super) endpoint: Option<String>,
    pub(super) key_secret: Option<String>,
    pub(super) inbox: Option<FeedbackInboxOverride>,
    pub(super) triage: Option<FeedbackTriageOverride>,
}

/// One layer's `[feedback.inbox]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FeedbackInboxOverride {
    pub(super) enabled: Option<bool>,
    pub(super) notes_per_sender: Option<u32>,
    pub(super) notes_per_hour: Option<u32>,
}

/// One layer's `[feedback.triage]` keys.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FeedbackTriageOverride {
    pub(super) github_sources: Option<Vec<String>>,
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
        // File-only, like `[linear]`'s secrets: no environment names one.
        key_secret: None,
        inbox: lookup_bool(lookup, "ONEIRON_FEEDBACK_INBOX")?.map(|enabled| {
            FeedbackInboxOverride {
                enabled: Some(enabled),
                ..FeedbackInboxOverride::default()
            }
        }),
        triage: None,
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
            .field("key_secret", &self.key_secret)
            .field("inbox", &self.inbox)
            .field("triage", &self.triage)
            .finish()
    }
}

impl std::fmt::Debug for FeedbackTriageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedbackTriageConfig")
            .field("github_source_hosts", &endpoint_hosts(&self.github_sources))
            .finish()
    }
}

impl std::fmt::Debug for FeedbackConfigOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedbackConfigOverride")
            .field("destination", &self.destination)
            .field("endpoint_host", &endpoint_host(self.endpoint.as_deref()))
            .field("key_secret", &self.key_secret)
            .field("inbox", &self.inbox)
            .field(
                "triage_github_source_hosts",
                &self
                    .triage
                    .as_ref()
                    .and_then(|triage| triage.github_sources.as_deref())
                    .map(endpoint_hosts),
            )
            .finish()
    }
}

fn endpoint_host(endpoint: Option<&str>) -> Option<String> {
    endpoint
        .and_then(|endpoint| reqwest::Url::parse(endpoint).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
}

fn endpoint_hosts(endpoints: &[String]) -> Vec<Option<String>> {
    endpoints
        .iter()
        .map(|endpoint| endpoint_host(Some(endpoint)))
        .collect()
}
