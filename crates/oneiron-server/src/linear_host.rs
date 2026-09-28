//! Opt-in scheduled Linear mirror over an authenticated host-owned bridge.
//!
//! This host boundary carries normalized tracker events with stable event IDs.
//! The bridge, not the vault, owns the Linear provider credential. Every
//! mutation it is asked to send first passes the vault's ExternalEffect Gate
//! for both the verified TASK writer and the configured scheduler actor. A raw
//! issue-list poll cannot supply exact event IDs.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use oneiron::linear_sync::{LinearEffectKind, LinearEffectRequest};
use oneiron::{
    EntityId, LinearChangePage, LinearChangeSource, LinearEgress, LinearIssueChange,
    LinearIssueRef, LinearSyncAdapter, LinearSyncError, LinearSyncResult, LinearTaskStore,
    MirroredTaskFields,
};
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::server::SyncServer;
use oneiron::linear_sync::VaultLinearTaskStore;

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
        anyhow::ensure!(
            base.scheme() == "https"
                || (base.scheme() == "http"
                    && base.host_str().is_some_and(|host| host == "localhost"
                        || host == "127.0.0.1"
                        || host == "[::1]")),
            "Linear bridge must use HTTPS or local loopback"
        );
        anyhow::ensure!(
            base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "Linear bridge URL must not embed credentials or parameters"
        );
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

/// Outbound door for the scheduled mirror: no bridge mutation is sent until
/// the vault admits it for the TASK's verified writer AND the scheduler.
struct GatedEgress {
    bridge: LinearBridge,
    vault: Arc<oneiron::Vault>,
    scheduler_actor: EntityId,
}

impl GatedEgress {
    fn admit(
        &self,
        kind: LinearEffectKind,
        operation_id: [u8; 32],
        task_ref: EntityId,
        issue: Option<&LinearIssueRef>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<()> {
        let gate_ref = self.vault.authorize_linear_effect(&LinearEffectRequest {
            operation_id,
            task_ref,
            scheduler_actor: self.scheduler_actor,
            issue: issue.cloned(),
            kind,
            fields: fields.clone(),
        })?;
        tracing::debug!(gate_ref, "Linear effect admitted");
        Ok(())
    }
}

impl LinearEgress for GatedEgress {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        self.admit(
            LinearEffectKind::Create,
            operation_id,
            task_ref,
            None,
            fields,
        )?;
        self.bridge.create_issue(operation_id, task_ref, fields)
    }

    fn update_issue_conditional(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        expected_remote: &BTreeMap<String, [u8; 32]>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        let task_ref = oneiron::linear_sync::VaultLinearTaskStore::new(&self.vault)
            .link_for_issue(issue)?
            .ok_or(LinearSyncError::AuthorizationDenied)?
            .task_ref;
        self.admit(
            LinearEffectKind::Update,
            operation_id,
            task_ref,
            Some(issue),
            fields,
        )?;
        self.bridge
            .update_issue_conditional(operation_id, issue, expected_remote, fields)
    }
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

fn synchronize_once<O: LinearEgress>(
    vault: &oneiron::Vault,
    inbound: LinearBridge,
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
    tokio::task::spawn_blocking(move || LinearBridge::configured(base, token, timeout_secs))
        .await
        .map_err(|error| anyhow::anyhow!("Linear bridge setup failed: {error}"))?
}

/// Start a scheduled mirror when the host configured its authenticated bridge.
/// Every pass uses the vault's durable dirty outbox and pull cursor; errors
/// leave both for the next pass. This timer lives in the server, never core.
pub(crate) async fn spawn(
    server: Arc<SyncServer>,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
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
                let outbound = GatedEgress {
                    bridge: inbound.clone(),
                    vault: vault.clone(),
                    scheduler_actor,
                };
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
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "Linear mirror pass failed; will retry");
                    // A policy read failure cannot authorize a provider call.
                    // Re-read after the last VALID interval, never a hardcoded
                    // timer or a stale operational policy for the effect.
                    wait = Duration::from_secs(last_valid_interval);
                }
                Err(error) => {
                    tracing::warn!(error = %error, "Linear mirror worker failed; will retry");
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
