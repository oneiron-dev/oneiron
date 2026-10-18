//! Opt-in scheduled Linear mirror over an authenticated host-owned bridge.
//!
//! This host boundary carries normalized tracker events with stable event IDs.
//! The bridge, not the vault, owns the Linear provider credential. Every
//! mutation it is asked to send first passes the vault's ExternalEffect Gate
//! for both the verified TASK writer and the configured scheduler actor. A raw
//! issue-list poll cannot supply exact event IDs.
//!
//! Beside the scheduled pass, the host serves the signed Linear webhook
//! (`webhook`, OF-427): its tracker mapping is the direct config's tracker
//! part in direct mode, else the file `ONEIRON_LINEAR_WEBHOOK_CONFIG` names,
//! read and checked once, at startup.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use oneiron::linear_sync::ServedLinearEgress;
use oneiron::{
    EntityId, LinearChangePage, LinearChangeSource, LinearEgress, LinearIssueChange,
    LinearIssueRef, LinearSyncAdapter, LinearSyncError, LinearSyncResult, MirroredTaskFields,
};
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::server::SyncServer;
use oneiron::linear_sync::VaultLinearTaskStore;
use oneiron_linear::LinearTrackerConfig;

mod direct;
mod webhook;

pub(crate) use webhook::routes as webhook_routes;

/// Names the JSON file of the webhook's tracker mapping in bridge mode.
const LINEAR_WEBHOOK_CONFIG_ENV: &str = "ONEIRON_LINEAR_WEBHOOK_CONFIG";

/// A webhook reads no tracker page; this only meets the shared mapping's
/// own check.
const WEBHOOK_PAGE_SIZE: u32 = 1;

/// The webhook's tracker mapping in bridge mode.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookConfig {
    team_id: String,
    status_ids: BTreeMap<String, String>,
    assignee_ids: BTreeMap<String, String>,
}

/// The tracker mapping the Linear webhook applies under (OF-427 C11): the
/// direct config's tracker part in direct mode, else the file
/// `ONEIRON_LINEAR_WEBHOOK_CONFIG` names, each checked as the poller checks
/// its own; `None` when the host configures neither, and the webhook answers
/// `linear_webhook_not_configured`. The first good read, at startup, is
/// kept: a later edit of the file waits for a restart rather than turning
/// the route to 404.
pub(crate) fn webhook_tracker() -> anyhow::Result<Option<LinearTrackerConfig>> {
    static TRACKER: std::sync::OnceLock<Option<LinearTrackerConfig>> = std::sync::OnceLock::new();
    if let Some(tracker) = TRACKER.get() {
        return Ok(tracker.clone());
    }
    let tracker = read_webhook_tracker()?;
    Ok(TRACKER.get_or_init(|| tracker).clone())
}

fn read_webhook_tracker() -> anyhow::Result<Option<LinearTrackerConfig>> {
    let webhook = std::env::var_os(LINEAR_WEBHOOK_CONFIG_ENV);
    if let Some(direct) = std::env::var_os("ONEIRON_LINEAR_CONFIG") {
        anyhow::ensure!(
            webhook.is_none(),
            "a direct Linear mirror maps its webhook in ONEIRON_LINEAR_CONFIG, not {LINEAR_WEBHOOK_CONFIG_ENV}"
        );
        return direct::tracker_at(std::path::Path::new(&direct)).map(Some);
    }
    let Some(path) = webhook else {
        return Ok(None);
    };
    let config: WebhookConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    let tracker = LinearTrackerConfig {
        team_id: config.team_id,
        status_ids: config.status_ids,
        assignee_ids: config.assignee_ids,
        page_size: WEBHOOK_PAGE_SIZE,
    };
    tracker.validate()?;
    Ok(Some(tracker))
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

#[derive(Clone)]
struct LinearBridge {
    client: Client,
    base: reqwest::Url,
    credential: reqwest::header::HeaderValue,
    request_timeout: Duration,
}

impl LinearBridge {
    fn configured(
        base: Option<String>,
        token: Option<String>,
        timeout_secs: u64,
    ) -> anyhow::Result<Option<Self>> {
        anyhow::ensure!(
            base.is_some() == token.is_some(),
            "Linear bridge requires both URL and token"
        );
        let (Some(base), Some(token)) = (base, token) else {
            return Ok(None);
        };
        anyhow::ensure!(!token.trim().is_empty(), "Linear bridge token is empty");
        let mut base = reqwest::Url::parse(&base)?;
        let normalized_path = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&normalized_path);
        check_host_url(&base, "Linear bridge")?;
        let credential = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Some(Self {
            client,
            base,
            credential,
            request_timeout: Duration::from_secs(timeout_secs),
        }))
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> LinearSyncResult<Value> {
        let endpoint = self
            .base
            .join(path)
            .map_err(|error| LinearSyncError::Transport(error.to_string()))?;
        let mut request = self
            .client
            .request(method, endpoint)
            .header(reqwest::header::AUTHORIZATION, self.credential.clone())
            .timeout(self.request_timeout);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .map_err(|error| LinearSyncError::Transport(error.to_string()))?;
        if response.status() == reqwest::StatusCode::CONFLICT
            || response.status() == reqwest::StatusCode::PRECONDITION_FAILED
        {
            return Err(LinearSyncError::RemoteChanged);
        }
        if !response.status().is_success() {
            // Provider bodies can contain secrets; report the status only.
            return Err(LinearSyncError::Transport(format!(
                "Linear bridge returned {}",
                response.status()
            )));
        }
        bounded_json(response)
    }
}

const MAX_BRIDGE_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

fn bounded_json<T: DeserializeOwned>(response: reqwest::blocking::Response) -> LinearSyncResult<T> {
    let mut bytes = Vec::new();
    response
        .take(MAX_BRIDGE_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LinearSyncError::Transport(format!("Linear bridge read failed: {error}"))
        })?;
    if bytes.len() as u64 > MAX_BRIDGE_RESPONSE_BYTES {
        return Err(LinearSyncError::Transport(
            "Linear bridge response exceeds limit".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| LinearSyncError::Transport(format!("invalid Linear bridge JSON: {error}")))
}

impl LinearChangeSource for LinearBridge {
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        let mut endpoint = self
            .base
            .join("changes")
            .map_err(|error| LinearSyncError::Transport(error.to_string()))?;
        if let Some(cursor) = cursor {
            endpoint.query_pairs_mut().append_pair("cursor", cursor);
        }
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, self.credential.clone())
            .timeout(self.request_timeout)
            .send()
            .map_err(|error| LinearSyncError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(LinearSyncError::Transport(format!(
                "Linear bridge returned {}",
                response.status()
            )));
        }
        bounded_json(response)
    }
}

impl LinearEgress for LinearBridge {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        serde_json::from_value(self.request(reqwest::Method::POST, "issues", Some(json!({
            "operation_id": hex_operation_id(operation_id), "task_ref": task_ref.to_hex(), "fields": fields,
        })))?).map_err(|error| LinearSyncError::Transport(format!("invalid Linear create receipt: {error}")))
    }

    fn update_issue_conditional(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        expected_base: &BTreeMap<String, [u8; 32]>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        // The bridge MUST enforce this base atomically with the provider write.
        // A read-then-write implementation is unsafe: an edit can race the read.
        let expected_base: BTreeMap<&str, String> = expected_base
            .iter()
            .map(|(field, hash)| (field.as_str(), hex_operation_id(*hash)))
            .collect();
        // Fixed path: opaque issue IDs never become URL path components.
        serde_json::from_value(self.request(
            reqwest::Method::POST,
            "issues/update",
            Some(json!({
                "operation_id": hex_operation_id(operation_id), "issue": issue,
                "expected_base_field_hashes": expected_base, "fields": fields,
            })),
        )?)
        .map_err(|error| {
            LinearSyncError::Transport(format!("invalid Linear update receipt: {error}"))
        })
    }
}

fn hex_operation_id(id: [u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A bearer-gated server is a prerequisite, independent of provider auth.
/// Otherwise an anonymous core batch writer can inject TASKs for the mirror.
pub(crate) fn validate_server_auth(
    configured: bool,
    auth_secret: Option<&str>,
    allow_unauthenticated: bool,
) -> anyhow::Result<()> {
    if configured && (allow_unauthenticated || auth_secret.is_none_or(str::is_empty)) {
        anyhow::bail!("Linear mirror refuses a server without authenticated core writes");
    }
    Ok(())
}

fn scheduler_actor(raw: Option<String>) -> anyhow::Result<EntityId> {
    let raw = raw
        .ok_or_else(|| anyhow::anyhow!("Linear mirror requires ONEIRON_LINEAR_SCHEDULER_ACTOR"))?;
    EntityId::from_hex(raw.trim())
        .map_err(|_| anyhow::anyhow!("Linear scheduler actor must be an entity id"))
}

fn synchronize_once<I: LinearChangeSource, O: LinearEgress>(
    vault: &oneiron::Vault,
    inbound: I,
    outbound: O,
    now: u64,
    max_pull_pages_per_pass: usize,
) -> LinearSyncResult<(
    Vec<oneiron::LinearMirrorReceipt>,
    oneiron::LinearPullReceipt,
)> {
    LinearSyncAdapter::new(VaultLinearTaskStore::new(vault), inbound, outbound)
        .synchronize(now, max_pull_pages_per_pass)
}

/// Construct the blocking HTTP client off the Tokio runtime thread. Inputs
/// are explicit so a parallel test needs no process-global env mutation.
async fn build_bridge(
    base: Option<String>,
    token: Option<String>,
    timeout_secs: u64,
) -> anyhow::Result<Option<LinearBridge>> {
    crate::logging::off_runtime("Linear bridge setup", move || {
        LinearBridge::configured(base, token, timeout_secs)
    })
    .await?
}

/// Start a scheduled mirror when the host configured its authenticated bridge.
/// Every pass uses the vault's durable dirty outbox and pull cursor; errors
/// leave both for the next pass. This timer lives in the server, never core.
pub(crate) async fn spawn(
    server: Arc<SyncServer>,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    // An unreadable or invalid webhook mapping fails startup (OF-427 C11).
    crate::logging::off_runtime("Linear webhook mapping", webhook_tracker).await??;
    let api_key = std::env::var("ONEIRON_LINEAR_API_KEY").ok();
    let direct_config = std::env::var_os("ONEIRON_LINEAR_CONFIG");
    if api_key.is_some() || direct_config.is_some() {
        anyhow::ensure!(
            std::env::var_os("ONEIRON_LINEAR_BRIDGE_URL").is_none()
                && std::env::var_os("ONEIRON_LINEAR_BRIDGE_TOKEN").is_none(),
            "configure either direct Linear GraphQL or a Linear bridge, not both"
        );
        let api_key = api_key.ok_or_else(|| {
            anyhow::anyhow!("Linear direct mirror requires ONEIRON_LINEAR_API_KEY")
        })?;
        let config = direct_config.ok_or_else(|| {
            anyhow::anyhow!("Linear direct mirror requires ONEIRON_LINEAR_CONFIG")
        })?;
        return direct::spawn(server, api_key, config.into()).await;
    }
    let base = std::env::var("ONEIRON_LINEAR_BRIDGE_URL").ok();
    let token = std::env::var("ONEIRON_LINEAR_BRIDGE_TOKEN").ok();
    if base.is_none() && token.is_none() {
        return Ok(None);
    }
    validate_server_auth(
        true,
        server.config.auth_secret.as_deref(),
        server.config.allow_unauthenticated,
    )?;
    let scheduler_actor = scheduler_actor(std::env::var("ONEIRON_LINEAR_SCHEDULER_ACTOR").ok())?;
    // Fail at configuration time if a provided credential is incomplete or
    // the resolved manifest is unreadable. The client itself is built off
    // Tokio's runtime thread.
    let policy = server.vault().linear_mirror_policy()?;
    let Some(bridge) = build_bridge(base, token, policy.request_timeout_secs).await? else {
        return Ok(None);
    };
    let handle = tokio::spawn(async move {
        let mut wait = Duration::ZERO;
        let mut last_valid_interval = policy.poll_interval_secs;
        loop {
            tokio::time::sleep(wait).await;
            let vault = server.vault().clone();
            let client = bridge.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let policy = vault
                    .linear_mirror_policy()
                    .map_err(LinearSyncError::Store)?;
                let budget = vault.linear_sync_budget().map_err(LinearSyncError::Store)?;
                let mut inbound = client;
                inbound.request_timeout = Duration::from_secs(policy.request_timeout_secs);
                let outbound = ServedLinearEgress::new(&vault, scheduler_actor, inbound.clone());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |time| time.as_secs());
                let result = synchronize_once(
                    &vault,
                    inbound,
                    outbound,
                    now,
                    budget.max_pull_pages_per_pass,
                )?;
                Ok::<_, LinearSyncError>((result, policy.poll_interval_secs))
            })
            .await;
            match outcome {
                Ok(Ok(((pushed, pulled), interval))) => {
                    last_valid_interval = interval;
                    wait = Duration::from_secs(interval);
                    tracing::debug!(
                        pushed = pushed.len(),
                        pulled = pulled.applied,
                        "Linear mirror pass"
                    );
                }
                Ok(Err(_)) => {
                    tracing::warn!(
                        reason = "linear_sync_failed",
                        "Linear mirror pass failed; will retry"
                    );
                    // A policy read failure cannot authorize a provider call.
                    // Re-read after the last VALID interval, never a hardcoded
                    // timer or a stale operational policy for the effect.
                    wait = Duration::from_secs(last_valid_interval);
                }
                Err(error) => {
                    tracing::warn!(
                        panicked = error.is_panic(),
                        "Linear mirror worker failed; will retry"
                    );
                    wait = Duration::from_secs(last_valid_interval);
                }
            }
        }
    });
    Ok(Some(handle))
}

#[cfg(test)]
#[path = "linear_host/tests.rs"]
mod tests;
