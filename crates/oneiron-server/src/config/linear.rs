//! `[linear]`: the Linear mirror this server runs and the tracker mapping its
//! signed webhook applies under (OF-427, WILL-PLAN L14 row 15). File-only,
//! like `[native_mail]`. Not `[line]`, the LINE Official Account's plan.
//!
//! ```toml
//! [linear]
//! mode = "direct"                     # direct | bridge; absent, the webhook's mapping alone
//! scheduler_actor = "<MACHINE id>"    # the stored Machine actor a scheduled send acts as
//! team_id = "<Linear team id>"        # the tracker mapping: the webhook's, and the direct mirror's
//! page_size = 50                      # direct: issues per pulled page, 1 to 250
//! api_key_secret = "linear.api_key"   # direct: the vault secret holding the Linear API key
//! graphql_endpoint = "https://api.linear.app/graphql"   # direct; Linear's own when absent
//! response_dir = "/srv/oneiron/linear-responses"         # direct: host-private response custody
//! bridge_url = "https://bridge.example/linear/"          # bridge
//! bridge_token_secret = "linear.bridge_token"            # bridge: the vault secret holding its bearer
//!
//! [linear.status_ids]
//! queued = "<Linear workflow state id>"
//!
//! [linear.assignee_ids]
//! owner = "<Linear user id>"
//! ```
//!
//! The section names each credential by the vault secret holding it, and
//! every pass reads it through the custody door bound to `connector:linear`:
//! no key sits in a file, and none is held between passes. A managed vault's
//! `response_dir` is its host's (`<data_dir>.linear-responses`).
//!
//! A plain serve with no section reads its `ONEIRON_LINEAR_*` environment
//! into the same settings ([`LinearConfig::or_environment`]): the direct
//! mirror's `ONEIRON_LINEAR_API_KEY` and the JSON file `ONEIRON_LINEAR_CONFIG`
//! names, or the bridge's `ONEIRON_LINEAR_BRIDGE_URL` and
//! `ONEIRON_LINEAR_BRIDGE_TOKEN`, each with `ONEIRON_LINEAR_SCHEDULER_ACTOR`,
//! and the bridge's webhook mapping in the JSON file
//! `ONEIRON_LINEAR_WEBHOOK_CONFIG` names. Those keys stay in the environment
//! and are read when the mirror starts. A section and that environment
//! together stop serve: one host runs one mirror.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::EntityId;
use oneiron_linear::{LINEAR_GRAPHQL_ENDPOINT, LinearTrackerConfig};
use serde::Deserialize;

const LINEAR_API_KEY_ENV: &str = "ONEIRON_LINEAR_API_KEY";
const LINEAR_CONFIG_ENV: &str = "ONEIRON_LINEAR_CONFIG";
const LINEAR_SCHEDULER_ACTOR_ENV: &str = "ONEIRON_LINEAR_SCHEDULER_ACTOR";
const LINEAR_BRIDGE_URL_ENV: &str = "ONEIRON_LINEAR_BRIDGE_URL";
const LINEAR_BRIDGE_TOKEN_ENV: &str = "ONEIRON_LINEAR_BRIDGE_TOKEN";
/// Names the JSON file of the webhook's tracker mapping in bridge mode.
const LINEAR_WEBHOOK_CONFIG_ENV: &str = "ONEIRON_LINEAR_WEBHOOK_CONFIG";

/// A webhook reads no tracker page; this only meets the shared mapping's
/// own check when no direct mirror names a page size.
const WEBHOOK_PAGE_SIZE: u32 = 1;

/// How the scheduled mirror reaches Linear.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinearMode {
    /// Linear's GraphQL API, with the host's response custody.
    Direct,
    /// A host-owned bridge that keeps Linear's credential and event IDs.
    Bridge,
}

/// The `[linear]` settings, nonsecret: a credential is named, never held.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LinearConfig {
    /// The scheduled mirror's transport. Absent: no mirror runs, and the
    /// section maps the webhook alone.
    pub mode: Option<LinearMode>,
    /// The stored Machine actor a scheduled send acts as, 32 hex characters.
    /// The vault's ExternalEffect Gate must admit each send for it and for
    /// the verified writer of the TASK revision.
    pub scheduler_actor: Option<String>,
    /// The Linear team the tracker mapping names.
    pub team_id: Option<String>,
    /// TASK status tokens to Linear workflow state IDs.
    pub status_ids: BTreeMap<String, String>,
    /// TASK assignee tokens to Linear user IDs.
    pub assignee_ids: BTreeMap<String, String>,
    /// Direct: issues per pulled page.
    pub page_size: Option<u32>,
    /// Direct: the vault secret holding the Linear API key.
    pub api_key_secret: Option<String>,
    /// Direct: the GraphQL endpoint; Linear's own when absent (OF-427 C10).
    pub graphql_endpoint: Option<String>,
    /// Direct: the existing absolute directory of host-private response
    /// custody, outside the replicated vault graph.
    pub response_dir: Option<PathBuf>,
    /// Bridge: the bridge's base URL.
    pub bridge_url: Option<String>,
    /// Bridge: the vault secret holding the bridge's bearer token.
    pub bridge_token_secret: Option<String>,
    /// The environment variable a plain serve holds the mode's credential
    /// in, set only when [`LinearConfig::or_environment`] read these
    /// settings from it. No file names one.
    #[serde(skip)]
    pub(crate) environment_credential: Option<&'static str>,
}

/// Where the mirror's provider credential is.
pub(crate) enum LinearCredential<'a> {
    /// The vault custody secret of this name.
    Secret(&'a str),
    /// The plain serve's environment variable of this name.
    Environment(&'static str),
}

/// The direct mirror's JSON file at `ONEIRON_LINEAR_CONFIG`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectFile {
    team_id: String,
    status_ids: BTreeMap<String, String>,
    assignee_ids: BTreeMap<String, String>,
    page_size: u32,
    response_dir: PathBuf,
    #[serde(default)]
    graphql_endpoint: Option<String>,
}

/// The webhook's tracker mapping in bridge mode, at
/// `ONEIRON_LINEAR_WEBHOOK_CONFIG`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookFile {
    team_id: String,
    status_ids: BTreeMap<String, String>,
    assignee_ids: BTreeMap<String, String>,
}

impl LinearConfig {
    /// The settings a plain serve runs its Linear host with: `section`, or
    /// with none its `ONEIRON_LINEAR_*` environment read into the same
    /// settings, off the async runtime. Both together are refused.
    pub(crate) async fn or_environment(section: Option<Self>) -> anyhow::Result<Option<Self>> {
        let environment =
            crate::logging::off_runtime("Linear settings", Self::from_environment).await??;
        match (section, environment) {
            (Some(_), Some(_)) => anyhow::bail!(
                "configure Linear in [linear] or in the ONEIRON_LINEAR_* environment, not both"
            ),
            (section, environment) => Ok(section.or(environment)),
        }
    }

    /// The `ONEIRON_LINEAR_*` environment as these settings, checked as a
    /// section is; `None` when it names nothing.
    fn from_environment() -> anyhow::Result<Option<Self>> {
        let present = |key: &str| std::env::var_os(key).is_some();
        let webhook = std::env::var_os(LINEAR_WEBHOOK_CONFIG_ENV);
        let mut settings = Self::default();
        if let Some(path) = std::env::var_os(LINEAR_CONFIG_ENV) {
            anyhow::ensure!(
                webhook.is_none(),
                "a direct Linear mirror maps its webhook in {LINEAR_CONFIG_ENV}, not {LINEAR_WEBHOOK_CONFIG_ENV}"
            );
            let file: DirectFile = serde_json::from_slice(&std::fs::read(path)?)?;
            settings.team_id = Some(file.team_id);
            settings.status_ids = file.status_ids;
            settings.assignee_ids = file.assignee_ids;
            settings.page_size = Some(file.page_size);
            settings.response_dir = Some(file.response_dir);
            settings.graphql_endpoint = file.graphql_endpoint;
        } else if let Some(path) = webhook {
            let file: WebhookFile = serde_json::from_slice(&std::fs::read(path)?)?;
            settings.team_id = Some(file.team_id);
            settings.status_ids = file.status_ids;
            settings.assignee_ids = file.assignee_ids;
        }
        let api_key = std::env::var(LINEAR_API_KEY_ENV).is_ok();
        if api_key || present(LINEAR_CONFIG_ENV) {
            anyhow::ensure!(
                !(present(LINEAR_BRIDGE_URL_ENV) || present(LINEAR_BRIDGE_TOKEN_ENV)),
                "configure either direct Linear GraphQL or a Linear bridge, not both"
            );
            anyhow::ensure!(
                api_key,
                "Linear direct mirror requires {LINEAR_API_KEY_ENV}"
            );
            anyhow::ensure!(
                present(LINEAR_CONFIG_ENV),
                "Linear direct mirror requires {LINEAR_CONFIG_ENV}"
            );
            settings.mode = Some(LinearMode::Direct);
            settings.environment_credential = Some(LINEAR_API_KEY_ENV);
        } else {
            let base = std::env::var(LINEAR_BRIDGE_URL_ENV).ok();
            let token = std::env::var(LINEAR_BRIDGE_TOKEN_ENV).is_ok();
            if base.is_some() || token {
                anyhow::ensure!(
                    base.is_some() && token,
                    "Linear bridge requires both URL and token"
                );
                settings.mode = Some(LinearMode::Bridge);
                settings.bridge_url = base;
                settings.environment_credential = Some(LINEAR_BRIDGE_TOKEN_ENV);
            }
        }
        if settings.mode.is_some() {
            settings.scheduler_actor = std::env::var(LINEAR_SCHEDULER_ACTOR_ENV).ok();
        }
        if settings == Self::default() {
            return Ok(None);
        }
        settings.validate()?;
        Ok(Some(settings))
    }

    /// Refuses settings that cannot run: a mapping the shared tracker check
    /// refuses, a mode missing its actor, URL or credential, keys of the
    /// other mode, or mirror keys with no mode.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        let mapped = self.tracker()?.is_some();
        anyhow::ensure!(
            mapped
                || (self.status_ids.is_empty()
                    && self.assignee_ids.is_empty()
                    && self.page_size.is_none()),
            "[linear] maps status_ids, assignee_ids and page_size under its team_id"
        );
        let Some(mode) = self.mode else {
            anyhow::ensure!(
                mapped
                    && self.scheduler_actor.is_none()
                    && self.api_key_secret.is_none()
                    && self.graphql_endpoint.is_none()
                    && self.response_dir.is_none()
                    && self.bridge_url.is_none()
                    && self.bridge_token_secret.is_none(),
                "[linear] with no mode maps the webhook's team_id and status_ids alone; \
                 a mirror names mode = \"direct\" or \"bridge\""
            );
            return Ok(());
        };
        self.scheduler_actor()?;
        match mode {
            LinearMode::Direct => {
                anyhow::ensure!(
                    self.bridge_url.is_none() && self.bridge_token_secret.is_none(),
                    "configure either direct Linear GraphQL or a Linear bridge, not both"
                );
                anyhow::ensure!(
                    mapped && self.page_size.is_some(),
                    "a direct Linear mirror maps linear.team_id, status_ids and page_size"
                );
                anyhow::ensure!(
                    self.response_dir.as_deref().is_some_and(Path::is_absolute),
                    "Linear response_dir must name an absolute host-private directory"
                );
                self.graphql_endpoint()?;
            }
            LinearMode::Bridge => {
                anyhow::ensure!(
                    self.api_key_secret.is_none()
                        && self.graphql_endpoint.is_none()
                        && self.response_dir.is_none()
                        && self.page_size.is_none(),
                    "configure either direct Linear GraphQL or a Linear bridge, not both"
                );
                self.bridge_base()?;
            }
        }
        self.credential()?;
        Ok(())
    }

    /// The checked tracker mapping, `None` when the settings name no team:
    /// the webhook's (OF-427 C11), and the direct mirror's reads and writes.
    pub(crate) fn tracker(&self) -> anyhow::Result<Option<LinearTrackerConfig>> {
        let Some(team_id) = &self.team_id else {
            return Ok(None);
        };
        let tracker = LinearTrackerConfig {
            team_id: team_id.clone(),
            status_ids: self.status_ids.clone(),
            assignee_ids: self.assignee_ids.clone(),
            page_size: self.page_size.unwrap_or(WEBHOOK_PAGE_SIZE),
        };
        tracker.validate()?;
        Ok(Some(tracker))
    }

    /// The scheduler actor's entity id.
    pub(crate) fn scheduler_actor(&self) -> anyhow::Result<EntityId> {
        let raw = self.scheduler_actor.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "Linear mirror requires linear.scheduler_actor ({LINEAR_SCHEDULER_ACTOR_ENV})"
            )
        })?;
        EntityId::from_hex(raw.trim())
            .map_err(|_| anyhow::anyhow!("Linear scheduler actor must be an entity id"))
    }

    /// The endpoint the direct mirror sends to, checked as the bridge URL is.
    pub(crate) fn graphql_endpoint(&self) -> anyhow::Result<reqwest::Url> {
        let endpoint = reqwest::Url::parse(
            self.graphql_endpoint
                .as_deref()
                .unwrap_or(LINEAR_GRAPHQL_ENDPOINT),
        )?;
        check_host_url(&endpoint, "Linear GraphQL endpoint")?;
        Ok(endpoint)
    }

    /// The bridge's base URL, its path ending in `/`.
    pub(crate) fn bridge_base(&self) -> anyhow::Result<reqwest::Url> {
        let base = self.bridge_url.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Linear bridge requires linear.bridge_url ({LINEAR_BRIDGE_URL_ENV})")
        })?;
        let mut base = reqwest::Url::parse(base)?;
        let normalized_path = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&normalized_path);
        check_host_url(&base, "Linear bridge")?;
        Ok(base)
    }

    /// Where the mode's provider credential is: the vault secret its
    /// `*_secret` key names, or a plain serve's environment variable.
    pub(crate) fn credential(&self) -> anyhow::Result<LinearCredential<'_>> {
        if let Some(variable) = self.environment_credential {
            return Ok(LinearCredential::Environment(variable));
        }
        let (secret, key) = match self.mode {
            Some(LinearMode::Direct) => (&self.api_key_secret, "linear.api_key_secret"),
            Some(LinearMode::Bridge) => (&self.bridge_token_secret, "linear.bridge_token_secret"),
            None => anyhow::bail!("[linear] names no mirror mode"),
        };
        secret
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(LinearCredential::Secret)
            .ok_or_else(|| anyhow::anyhow!("the Linear mirror names its vault secret in {key}"))
    }
}

/// A host-configured Linear URL, the bridge base or the direct GraphQL
/// endpoint: HTTPS, or HTTP on a loopback host only, with no embedded
/// credentials, query or fragment.
fn check_host_url(url: &reqwest::Url, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http"
                && url.host_str().is_some_and(|host| host == "localhost"
                    || host == "127.0.0.1"
                    || host == "[::1]")),
        "{what} must use HTTPS or local loopback"
    );
    anyhow::ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{what} URL must not embed credentials or parameters"
    );
    Ok(())
}
