//! Opt-in scheduled Linear mirror over an authenticated host-owned bridge.
//!
//! This host boundary carries normalized tracker events with stable event IDs.
//! The bridge, not the vault, owns the Linear provider credential. Every
//! mutation it is asked to send first passes the vault's ExternalEffect Gate
//! for both the verified TASK writer and the configured scheduler actor. A raw
//! issue-list poll cannot supply exact event IDs.
//!
//! Every host starts the mirror through [`spawn_configured`] from the server's
//! own `[linear]` settings (`crate::config::LinearConfig`): a managed vault's
//! settings file, a plain serve's config file, or its `ONEIRON_LINEAR_*`
//! environment read into the same settings before the server starts. Beside
//! the scheduled pass, the host serves the signed Linear webhook (`webhook`,
//! OF-427) under the same settings' tracker mapping, checked at startup.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use oneiron::linear_sync::{LinearEffectRequest, ServedLinearEgress};
use oneiron::{
    EntityId, LinearChangePage, LinearChangeSource, LinearEgress, LinearIssueChange,
    LinearIssueRef, LinearSyncAdapter, LinearSyncError, LinearSyncResult, MirroredTaskFields,
};
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::config::{IngressAuth, LinearConfig, LinearCredential, LinearMode, SyncServerConfig};
use crate::server::{HousekeepingAdmission, SyncServer};
use oneiron::linear_sync::VaultLinearTaskStore;
use oneiron_linear::LinearTrackerConfig;

mod body_line;
mod direct;
mod push;
mod webhook;

pub(crate) use push::{LinearPushError, push_body_line, push_task_now};
pub(crate) use webhook::routes as webhook_routes;

/// The tracker mapping the Linear webhook applies under (OF-427 C11): the
/// server's `[linear]` mapping, a plain serve's direct config or webhook
/// file read into it at startup; `None` when it maps none, and the webhook
/// answers `linear_webhook_not_configured`. The mapping was checked when
/// the server started, so a later edit of a file waits for a restart.
pub(crate) fn webhook_tracker(server: &SyncServer) -> anyhow::Result<Option<LinearTrackerConfig>> {
    server
        .config
        .linear
        .as_ref()
        .map_or(Ok(None), LinearConfig::tracker)
}

#[derive(Clone)]
struct LinearBridge {
    client: Client,
    base: reqwest::Url,
    credential: reqwest::header::HeaderValue,
    request_timeout: Duration,
    /// How long an admission waits for a full Rate window (FIX 8788): none
    /// for a background pass, the caller's own for its push (FIX 9382).
    rate_wait: Duration,
}

impl LinearBridge {
    /// The bridge at `base` over `client`, presenting `token` as its bearer.
    fn with_token(
        client: Client,
        base: reqwest::Url,
        token: &str,
        request_timeout: Duration,
    ) -> LinearSyncResult<Self> {
        let invalid =
            |what: &str| LinearSyncError::Store(oneiron::Error::InvalidConfig(what.into()));
        if token.trim().is_empty() {
            return Err(invalid("Linear bridge token is empty"));
        }
        let mut credential = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| invalid("Linear bridge token is not a valid header"))?;
        credential.set_sensitive(true);
        Ok(Self {
            client,
            base,
            credential,
            request_timeout,
            rate_wait: Duration::ZERO,
        })
    }

    /// This bridge, its admissions waiting up to `wait` for a full Rate
    /// window at their fair turn (FIX 8788).
    fn with_rate_wait(mut self, wait: Duration) -> Self {
        self.rate_wait = wait;
        self
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
    /// The default admission, waiting up to the bridge's Rate wait (none
    /// unless a caller's push asked for one); then the bridge's create.
    fn create_issue_admitted(
        &mut self,
        vault: &oneiron::Vault,
        effect: &LinearEffectRequest,
    ) -> LinearSyncResult<LinearIssueChange> {
        vault.authorize_linear_effect_within(effect, self.rate_wait)?;
        self.create_issue(effect.operation_id, effect.task_ref, &effect.fields)
    }

    /// As [`Self::create_issue_admitted`], for the conditional update.
    fn update_issue_conditional_admitted(
        &mut self,
        vault: &oneiron::Vault,
        effect: &LinearEffectRequest,
        expected_remote: &BTreeMap<String, [u8; 32]>,
    ) -> LinearSyncResult<LinearIssueChange> {
        let issue = effect
            .issue
            .as_ref()
            .ok_or(LinearSyncError::AuthorizationDenied)?;
        vault.authorize_linear_effect_within(effect, self.rate_wait)?;
        self.update_issue_conditional(effect.operation_id, issue, expected_remote, &effect.fields)
    }

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

/// The ingress a mirror needs, as the server's serve entry declares it: a
/// plain serve's own auth config ([`validate_server_auth`]), or a managed
/// vault's supervisor, which authenticates the private socket it owns. Either
/// way a dev mode's anonymous ingress is refused.
fn validate_ingress(config: &SyncServerConfig) -> anyhow::Result<()> {
    match config.ingress {
        IngressAuth::Configured => validate_server_auth(
            true,
            config.auth_secret.as_deref(),
            config.allow_unauthenticated,
        ),
        IngressAuth::Supervisor if config.allow_unauthenticated => {
            anyhow::bail!("Linear mirror refuses a server without authenticated core writes")
        }
        IngressAuth::Supervisor => Ok(()),
    }
}

/// Where each pass reads the mirror's provider credential.
#[derive(Clone)]
enum PassCredential {
    /// The vault custody secret of this name, read through the door bound to
    /// `connector:linear` for one pass at a time. A secret the vault does not
    /// hold or bind there refuses that pass, and the next pass asks again.
    Secret(String),
    /// A plain serve's environment value, read once at startup.
    Held(Arc<zeroize::Zeroizing<String>>),
}

impl PassCredential {
    /// The settings' credential: a vault secret by name, or the plain
    /// serve's environment variable, read now.
    fn of(settings: &LinearConfig) -> anyhow::Result<Self> {
        match settings.credential()? {
            LinearCredential::Secret(name) => Ok(Self::Secret(name.to_owned())),
            LinearCredential::Environment(variable) => std::env::var(variable)
                .map(|value| Self::Held(Arc::new(zeroize::Zeroizing::new(value))))
                .map_err(|_| anyhow::anyhow!("Linear mirror requires {variable}")),
        }
    }

    /// Runs `pass` with the credential's text. A vault secret is read
    /// through its door for this pass alone and scrubbed when it ends.
    fn with<T>(
        &self,
        vault: &oneiron::Vault,
        pass: impl FnOnce(&str) -> LinearSyncResult<T>,
    ) -> LinearSyncResult<T> {
        let name = match self {
            Self::Held(value) => return pass(value.as_str()),
            Self::Secret(name) => name,
        };
        let mut pass = Some(pass);
        let mut outcome = None;
        vault
            .inject_secret_at_door(
                name,
                webhook::LINEAR_SECRET_EFFECTOR,
                &mut |value: &[u8]| {
                    let text = std::str::from_utf8(value).map_err(|_| {
                        oneiron::Error::InvalidConfig(
                            "the stored Linear credential is not text".into(),
                        )
                    })?;
                    outcome = pass.take().map(|pass| pass(text.trim()));
                    Ok(())
                },
            )
            .inspect_err(|error| {
                tracing::warn!(
                    reason = "linear_credential_unavailable",
                    %error,
                    "the Linear credential is not available at its door"
                );
            })?;
        outcome.unwrap_or_else(|| {
            Err(LinearSyncError::Transport(
                "the Linear credential door did not run".into(),
            ))
        })
    }
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

/// Starts the Linear host the server's `[linear]` settings name: checks the
/// webhook's tracker mapping, and runs the scheduled mirror when they name
/// a mode. The one entry for every host. Each pass is admitted through
/// `admit` and holds that admission on its blocking thread through the
/// policy and budget reads, every provider request, the response journal
/// and the cursor and receipt settlement; a refused pass sends nothing and
/// waits its interval. Settings, a mapping, an actor, a URL or an ingress
/// the mirror cannot use fail the start.
pub(crate) async fn spawn_configured(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(settings) = server.config.linear.clone() else {
        return Ok(None);
    };
    // An invalid tracker mapping fails startup (OF-427 C11).
    settings.validate()?;
    let tracker = settings.tracker()?;
    let Some(mode) = settings.mode else {
        return Ok(None);
    };
    validate_ingress(&server.config)?;
    let scheduler_actor = settings.scheduler_actor()?;
    let credential = PassCredential::of(&settings)?;
    match mode {
        LinearMode::Direct => {
            direct::spawn(
                server,
                &settings,
                tracker,
                scheduler_actor,
                credential,
                admit,
            )
            .await
        }
        LinearMode::Bridge => spawn_bridge(server, &settings, scheduler_actor, credential, admit)
            .await
            .map(Some),
    }
}

/// The bridge mirror. Every pass uses the vault's durable dirty outbox and
/// pull cursor; errors leave both for the next pass. This timer lives in the
/// server, never core.
async fn spawn_bridge(
    server: Arc<SyncServer>,
    settings: &LinearConfig,
    scheduler_actor: EntityId,
    credential: PassCredential,
    admit: HousekeepingAdmission,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let base = settings.bridge_base()?;
    // Fail at configuration time if the resolved manifest is unreadable or a
    // token the environment holds is blank. The client itself is built off
    // Tokio's runtime thread.
    let policy = server.vault().linear_mirror_policy()?;
    let client = crate::logging::off_runtime("Linear bridge setup", || {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
    })
    .await??;
    if let PassCredential::Held(token) = &credential {
        LinearBridge::with_token(
            client.clone(),
            base.clone(),
            token.as_str(),
            Duration::from_secs(policy.request_timeout_secs),
        )?;
    }
    Ok(tokio::spawn(async move {
        let mut wait = Duration::ZERO;
        let mut last_valid_interval = policy.poll_interval_secs;
        loop {
            tokio::time::sleep(wait).await;
            wait = Duration::from_secs(last_valid_interval);
            // A refused tick (a vault frozen for reap) asks again after it.
            let Some(admission) = admit() else {
                continue;
            };
            let vault = server.vault().clone();
            let (client, base, credential) = (client.clone(), base.clone(), credential.clone());
            let outcome = tokio::task::spawn_blocking(move || {
                // Held through every read, request and settlement of the
                // pass, even when its waiter is aborted.
                let _admission = admission;
                let policy = vault
                    .linear_mirror_policy()
                    .map_err(LinearSyncError::Store)?;
                let budget = vault.linear_sync_budget().map_err(LinearSyncError::Store)?;
                let result = credential.with(&vault, |token| {
                    let inbound = LinearBridge::with_token(
                        client,
                        base,
                        token,
                        Duration::from_secs(policy.request_timeout_secs),
                    )?;
                    let outbound =
                        ServedLinearEgress::new(&vault, scheduler_actor, inbound.clone());
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |time| time.as_secs());
                    synchronize_once(
                        &vault,
                        inbound,
                        outbound,
                        now,
                        budget.max_pull_pages_per_pass,
                    )
                })?;
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
                Ok(Err(LinearSyncError::Waiting(_))) => {
                    // FIX 8788: a full Rate window refused nothing; the TASK
                    // stays dirty and a later pass sends it.
                    tracing::debug!(
                        reason = oneiron::linear_sync::LINEAR_RATE_WINDOW_REASON,
                        "Linear mutation waits; it stays pending"
                    );
                    wait = Duration::from_secs(last_valid_interval);
                }
                Ok(Err(error)) => {
                    // The typed failure (a held push names its approve-once
                    // digest, FIX 11871); provider bodies never enter one.
                    tracing::warn!(
                        reason = "linear_sync_failed",
                        %error,
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
    }))
}

#[cfg(test)]
#[path = "linear_host/tests.rs"]
mod tests;
