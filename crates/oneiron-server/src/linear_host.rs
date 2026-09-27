//! Opt-in authenticated Linear host for the vault TASK mirror. No token enters the engine.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use chrono::DateTime;
use oneiron::linear_sync::{
    LinearChangePage, LinearChangeSource, LinearEffectKind, LinearEffectRequest, LinearEgress,
    LinearHostPolicy, LinearIssueChange, LinearIssueRef, LinearMissedTick, LinearPermission,
    LinearSyncAdapter, LinearSyncError, LinearSyncResult, LinearTaskStore, MirroredTaskFields,
    VaultLinearTaskStore,
};
use oneiron::{EntityId, Vault};
use serde_json::{Value, json};

const GRAPHQL: &str = "https://api.linear.app/graphql";
const ISSUE_FIELDS: &str =
    "id identifier updatedAt title description priority team { id } assignee { id } state { name }";

#[cfg(test)]
#[path = "linear_host/tests.rs"]
mod tests;

fn valid_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
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

/// Explicit opt-in: a credential alone cannot turn on periodic external writes.
/// The host admits only Linear's fixed HTTPS endpoint (no caller-selected URL).
pub(crate) struct LinearHostConfig {
    token: String,
    team_id: String,
    status_names: BTreeMap<String, String>,
    assignee_ids: BTreeMap<String, String>,
    scheduler_actor: EntityId,
    policy_override: Option<LinearHostPolicy>,
    #[cfg(test)]
    endpoint: Option<String>,
}
impl LinearHostConfig {
    pub(crate) fn from_env() -> anyhow::Result<Option<Self>> {
        let enabled = std::env::var("ONEIRON_LINEAR_SYNC_ENABLED").ok();
        let token = std::env::var("ONEIRON_LINEAR_API_KEY").ok();
        let team_id = std::env::var("ONEIRON_LINEAR_TEAM_ID").ok();
        let status_map = std::env::var("ONEIRON_LINEAR_STATUS_NAMES").ok();
        let assignee_map = std::env::var("ONEIRON_LINEAR_ASSIGNEE_IDS").ok();
        let scheduler_actor = std::env::var("ONEIRON_LINEAR_SCHEDULER_ACTOR").ok();
        let policy_manifest = std::env::var("ONEIRON_LINEAR_POLICY_MANIFEST").ok();
        if enabled.is_none()
            && token.is_none()
            && team_id.is_none()
            && status_map.is_none()
            && assignee_map.is_none()
            && scheduler_actor.is_none()
            && policy_manifest.is_none()
        {
            return Ok(None);
        }
        let (Some(token), Some(team_id), Some(status_map)) = (token, team_id, status_map) else {
            anyhow::bail!("Linear sync requires enabled=true, API key, team id, and status map");
        };
        if enabled.as_deref() != Some("true")
            || token.is_empty()
            || team_id.is_empty()
            || status_map.is_empty()
        {
            anyhow::bail!("Linear sync requires enabled=true, API key, team id, and status map");
        }
        let scheduler_actor = scheduler_actor
            .ok_or_else(|| anyhow::anyhow!("Linear sync requires a scheduler actor"))?;
        let scheduler_actor = EntityId::from_hex(&scheduler_actor)
            .map_err(|_| anyhow::anyhow!("Linear scheduler actor must be a valid entity ID"))?;
        let status_names: BTreeMap<String, String> = serde_json::from_str(&status_map)?;
        if status_names.is_empty()
            || status_names
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
            || status_names
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != status_names.len()
        {
            anyhow::bail!("Linear status mapping must be nonempty and bijective");
        }
        let assignee_ids: BTreeMap<String, String> = assignee_map
            .map(|raw| serde_json::from_str(&raw))
            .transpose()?
            .unwrap_or_default();
        if assignee_ids
            .iter()
            .any(|(actor, user)| EntityId::from_hex(actor).is_err() || !valid_uuid(user))
            || assignee_ids
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != assignee_ids.len()
        {
            anyhow::bail!("Linear assignee mapping must be canonical and bijective");
        }
        let policy_override = policy_manifest
            .map(|manifest| toml::from_str::<LinearHostPolicy>(&manifest))
            .transpose()?;
        Ok(Some(Self {
            policy_override,
            token,
            team_id,
            status_names,
            assignee_ids,
            scheduler_actor,
            #[cfg(test)]
            endpoint: None,
        }))
    }
}

#[derive(Clone)]
struct LinearHttp {
    client: reqwest::blocking::Client,
    token: Arc<str>,
    team_id: Arc<str>,
    status_names: Arc<BTreeMap<String, String>>,
    assignee_ids: Arc<BTreeMap<String, String>>,
    scheduler_actor: EntityId,
    policy: LinearHostPolicy,
    endpoint: Arc<str>,
}
impl LinearHttp {
    fn new(config: LinearHostConfig, policy: LinearHostPolicy) -> anyhow::Result<Self> {
        policy.validate()?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(policy.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        #[cfg(test)]
        let endpoint = config.endpoint.unwrap_or_else(|| GRAPHQL.to_owned());
        #[cfg(not(test))]
        let endpoint = GRAPHQL.to_owned();
        Ok(Self {
            client,
            token: Arc::from(config.token),
            team_id: Arc::from(config.team_id),
            status_names: Arc::new(config.status_names),
            assignee_ids: Arc::new(config.assignee_ids),
            scheduler_actor: config.scheduler_actor,
            policy,
            endpoint: Arc::from(endpoint),
        })
    }
    fn query(&self, query: &str, variables: Value) -> LinearSyncResult<Value> {
        self.query_optional(query, variables, false)?
            .ok_or_else(transport)
    }
    fn query_optional(
        &self,
        query: &str,
        variables: Value,
        allow_missing_issue: bool,
    ) -> LinearSyncResult<Option<Value>> {
        let response = self
            .client
            .post(&*self.endpoint)
            .header("Authorization", &*self.token)
            .json(&json!({"query":query,"variables":variables}))
            .send()
            .map_err(|_| transport())?;
        if !response.status().is_success() {
            return Err(transport());
        }
        let mut bytes = Vec::new();
        response
            .take(self.policy.max_response_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| transport())?;
        if bytes.len() as u64 > self.policy.max_response_bytes {
            return Err(transport());
        }
        let response: Value = serde_json::from_slice(&bytes).map_err(|_| transport())?;
        if let Some(errors) = response.get("errors") {
            let missing = allow_missing_issue
                && response.get("data").is_some_and(Value::is_null)
                && errors.as_array().is_some_and(|errors| {
                    errors.len() == 1
                        && errors[0].get("message").and_then(Value::as_str)
                            == Some("Entity not found: Issue")
                        && errors[0]
                            .pointer("/extensions/code")
                            .and_then(Value::as_str)
                            == Some("INPUT_ERROR")
                        && errors[0].get("path") == Some(&json!(["issue"]))
                });
            return if missing { Ok(None) } else { Err(transport()) };
        }
        response
            .get("data")
            .cloned()
            .filter(Value::is_object)
            .map(Some)
            .ok_or_else(transport)
    }
    fn issue(&self, id: &str) -> LinearSyncResult<Option<LinearIssueChange>> {
        let Some(data) = self.query_optional(
            &format!("query($id:String!){{ issue(id:$id){{ {ISSUE_FIELDS} }} }}"),
            json!({"id":id}),
            true,
        )?
        else {
            return Ok(None);
        };
        let issue = self.parse_issue(
            data.get("issue")
                .filter(|issue| issue.is_object())
                .ok_or_else(transport)?,
        )?;
        if issue.unmapped_assignee {
            return Err(LinearSyncError::AssigneeUnmapped);
        }
        Ok(Some(issue))
    }
    fn state_id(&self, status: &str) -> LinearSyncResult<String> {
        // Unknown status is a refusal, not permission to silently lose a TASK field.
        let mapped = self.status_names.get(status).ok_or_else(transport)?;
        let data = self.query(
            "query($id:String!){team(id:$id){states{nodes{id name}}}}",
            json!({"id":&*self.team_id}),
        )?;
        data.pointer("/team/states/nodes")
            .and_then(Value::as_array)
            .and_then(|states| {
                states
                    .iter()
                    .find(|s| s.get("name").and_then(Value::as_str) == Some(mapped.as_str()))
            })
            .and_then(|state| state.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(transport)
    }
    fn parse_issue(&self, value: &Value) -> LinearSyncResult<LinearIssueChange> {
        let mut issue = parse_issue(value)?;
        issue.fields.status = self
            .status_names
            .iter()
            .find(|(_, name)| *name == &issue.fields.status)
            .map(|(token, _)| token.clone())
            .ok_or_else(transport)?;
        if issue.issue.team_id != *self.team_id {
            return Err(transport());
        }
        match self.engine_assignee(issue.fields.assignee_ref.as_deref()) {
            Ok(mapped) => issue.fields.assignee_ref = mapped,
            Err(LinearSyncError::AssigneeUnmapped) => {
                // Preserve the provider ID as opaque DATA. The engine can skip
                // an unlinked issue or refuse a linked one before applying it;
                // it may never turn an unknown user into `None`.
                issue.unmapped_assignee = true;
            }
            Err(error) => return Err(error),
        }
        Ok(issue)
    }
    fn engine_assignee(&self, provider: Option<&str>) -> LinearSyncResult<Option<String>> {
        provider
            .map(|id| {
                self.assignee_ids
                    .iter()
                    .find(|(_, value)| value.as_str() == id)
                    .map(|(actor, _)| actor.clone())
                    .ok_or(LinearSyncError::AssigneeUnmapped)
            })
            .transpose()
    }
    fn provider_assignee(&self, actor: Option<&str>) -> LinearSyncResult<Option<String>> {
        actor
            .map(|id| {
                self.assignee_ids
                    .get(id)
                    .cloned()
                    .ok_or(LinearSyncError::AssigneeUnmapped)
            })
            .transpose()
    }
    fn fields_input(&self, fields: &MirroredTaskFields) -> LinearSyncResult<Value> {
        let assignee_id = self.provider_assignee(fields.assignee_ref.as_deref())?;
        Ok(
            json!({"title":fields.title,"description":fields.description,
            "priority":fields.priority,"assigneeId":assignee_id,
            "stateId":self.state_id(&fields.status)?}),
        )
    }
}

fn transport() -> LinearSyncError {
    // Never format provider responses: they can echo a bearer or user content.
    LinearSyncError::Transport("Linear request or response refused".to_owned())
}
fn string_at<'a>(value: &'a Value, path: &str) -> LinearSyncResult<&'a str> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .ok_or_else(transport)
}
fn parse_issue(value: &Value) -> LinearSyncResult<LinearIssueChange> {
    let issue_id = string_at(value, "/id")?.to_owned();
    let updated = string_at(value, "/updatedAt")?;
    let at = DateTime::parse_from_rfc3339(updated).map_err(|_| transport())?;
    let updated_at_ms: u64 = at.timestamp_millis().try_into().map_err(|_| transport())?;
    let fields = MirroredTaskFields {
        title: string_at(value, "/title")?.to_owned(),
        description: value
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned),
        priority: value
            .get("priority")
            .and_then(Value::as_u64)
            .filter(|priority| *priority != 0) // Linear's unprioritized default.
            .map(|n| n.try_into().map_err(|_| transport()))
            .transpose()?,
        assignee_ref: value
            .pointer("/assignee/id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        status: string_at(value, "/state/name")?.to_owned(),
    };
    // A snapshot API has no webhook event id; hash the issue's state and time
    // so two distinct snapshots with an equal updatedAt never alias.
    let mut event = blake3::Hasher::new();
    event.update(b"oneiron:linear-snapshot-event:v1");
    event.update(issue_id.as_bytes());
    event.update(&updated_at_ms.to_be_bytes());
    event.update(
        serde_json::to_vec(value)
            .map_err(|_| transport())?
            .as_slice(),
    );
    Ok(LinearIssueChange {
        unmapped_assignee: false,
        event_id: event.finalize().to_hex().to_string(),
        issue: LinearIssueRef {
            issue_id,
            team_id: string_at(value, "/team/id")?.to_owned(),
            identifier: string_at(value, "/identifier")?.to_owned(),
        },
        updated_at_ms,
        fields,
    })
}

fn stable_issue_uuid(task: EntityId, team: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:linear-task-issue:v1");
    hasher.update(task.as_bytes());
    hasher.update(team.as_bytes());
    let mut id = hasher.finalize().as_bytes()[..16].to_vec();
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    let hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[derive(Clone)]
struct LinearPort {
    http: LinearHttp,
    vault: Option<Arc<Vault>>,
    #[cfg(test)]
    bypass_gate: bool,
}
impl LinearPort {
    fn new(http: LinearHttp, vault: Option<Arc<Vault>>) -> Self {
        Self {
            http,
            vault,
            #[cfg(test)]
            bypass_gate: false,
        }
    }
    #[cfg(test)]
    fn unchecked_for_test(http: LinearHttp, vault: Option<Arc<Vault>>) -> Self {
        let mut port = Self::new(http, vault);
        port.bypass_gate = true;
        port
    }
    fn admit(
        &self,
        kind: LinearEffectKind,
        operation_id: [u8; 32],
        task_ref: EntityId,
        issue_id: Option<&str>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<()> {
        #[cfg(test)]
        if self.bypass_gate {
            return Ok(());
        }
        let vault = self
            .vault
            .as_ref()
            .ok_or(LinearSyncError::AuthorizationDenied)?;
        if self.http.policy.permission == LinearPermission::Denied {
            return Err(LinearSyncError::AuthorizationDenied);
        }
        let gate_ref = vault.authorize_linear_effect(&LinearEffectRequest {
            operation_id,
            task_ref,
            scheduler_actor: self.http.scheduler_actor,
            team_id: self.http.team_id.to_string(),
            issue_id: issue_id.map(str::to_owned),
            kind,
            fields: fields.clone(),
            risk: self.http.policy.risk,
        })?;
        tracing::debug!(gate_ref = %gate_ref, "Linear external effect admitted");
        Ok(())
    }
}
impl LinearChangeSource for LinearPort {
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        // Persist the GraphQL cursor after a successful page. A stopped worker
        // resumes from that position; echo suppression lives in the TASK link.
        let data = self.http.query(
            &format!("query($team:ID!,$after:String,$first:Int!){{ issues(filter:{{team:{{id:{{eq:$team}}}}}},sort:[{{updatedAt:{{order:Ascending}}}}],after:$after,first:$first){{nodes{{{ISSUE_FIELDS}}} pageInfo{{endCursor hasNextPage}}}}}}"),
            json!({"team":&*self.http.team_id,"after":cursor,"first":self.http.policy.page_size}),
        )?;
        let nodes = data
            .pointer("/issues/nodes")
            .and_then(Value::as_array)
            .ok_or_else(transport)?;
        let changes = nodes
            .iter()
            .map(|node| self.http.parse_issue(node))
            .collect::<LinearSyncResult<Vec<_>>>()?;
        let next_cursor = data
            .pointer("/issues/pageInfo/endCursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let has_more = data
            .pointer("/issues/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            .ok_or_else(transport)?;
        if (!changes.is_empty() && next_cursor.is_none())
            || (has_more && (changes.is_empty() || next_cursor.is_none()))
        {
            return Err(transport());
        }
        Ok(LinearChangePage {
            changes,
            next_cursor,
            has_more,
        })
    }
}
impl LinearEgress for LinearPort {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        task: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        // The UUID depends on the stable TASK, not its current revision.
        // A lost create response followed by a TASK edit must revisit the
        // SAME remote issue, never create a second one.
        let uuid = stable_issue_uuid(task, &self.http.team_id);
        self.http
            .provider_assignee(fields.assignee_ref.as_deref())?;
        self.admit(LinearEffectKind::Create, operation_id, task, None, fields)?;
        if let Some(existing) = self.http.issue(&uuid)? {
            return if existing.fields == *fields {
                Ok(existing)
            } else {
                Err(LinearSyncError::CreateConflict)
            };
        }
        let mut input = self.http.fields_input(fields)?;
        input["id"] = json!(uuid);
        input["teamId"] = json!(&*self.http.team_id);
        let data = self.http.query(
            &format!("mutation($input:IssueCreateInput!){{issueCreate(input:$input){{success issue{{{ISSUE_FIELDS}}}}}}}"),
            json!({"input":input}),
        )?;
        if data
            .pointer("/issueCreate/success")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(transport());
        }
        let created = self
            .http
            .parse_issue(data.pointer("/issueCreate/issue").ok_or_else(transport)?)?;
        if created.issue.issue_id != uuid {
            return Err(transport());
        }
        Ok(created)
    }
    fn update_issue(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        if issue.team_id != *self.http.team_id {
            return Err(transport());
        }
        self.http
            .provider_assignee(fields.assignee_ref.as_deref())?;
        let vault = self.vault.as_ref().ok_or_else(transport)?;
        let link = VaultLinearTaskStore::new(vault)
            .link_for_issue(issue)?
            .ok_or_else(transport)?;
        self.admit(
            LinearEffectKind::Update,
            operation_id,
            link.task_ref,
            Some(&issue.issue_id),
            fields,
        )?;
        let current = self.http.issue(&issue.issue_id)?.ok_or_else(transport)?;
        if current.issue.issue_id != issue.issue_id {
            return Err(transport());
        }
        // A lost response after a successful write is idempotent. Any OTHER
        // tracker change not in the durable base is a conflict, not permission
        // to overwrite it with a full local snapshot.
        if current.fields == *fields {
            return Ok(current);
        }
        if current.updated_at_ms != link.issue_updated_at_ms
            || current.fields.field_hashes() != link.base_field_hashes
        {
            return Err(transport());
        }
        let input = self.http.fields_input(fields)?;
        let data = self.http.query(
            &format!("mutation($id:String!,$input:IssueUpdateInput!){{issueUpdate(id:$id,input:$input){{success issue{{{ISSUE_FIELDS}}}}}}}"),
            json!({"id":issue.issue_id,"input":input}),
        )?;
        if data
            .pointer("/issueUpdate/success")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(transport());
        }
        let updated = self
            .http
            .parse_issue(data.pointer("/issueUpdate/issue").ok_or_else(transport)?)?;
        if updated.issue.issue_id != issue.issue_id {
            return Err(transport());
        }
        Ok(updated)
    }
}

/// Runs one serialized pass in a blocking worker; the live server owns cadence.
fn sync_once(vault: &Vault, port: &LinearPort) -> LinearSyncResult<()> {
    let store = VaultLinearTaskStore::new(vault);
    let mut adapter = LinearSyncAdapter::new(store, port.clone(), port.clone());
    let (pushed, pulled) = adapter.synchronize(vault.now_recorded_at())?;
    tracing::info!(
        pushed = pushed.len(),
        applied = pulled.applied,
        conflicts = pulled.conflicts.len(),
        refused = pulled.refused_outbound.len(),
        "Linear mirror tick completed"
    );
    Ok(())
}

pub(crate) async fn spawn_linear_sync(
    vault: Arc<Vault>,
    config: LinearHostConfig,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    // reqwest::blocking::ClientBuilder::build starts its own runtime and
    // panics if called from inside Tokio. Finish initialization on a blocking
    // thread before the server reports ready; a failed init refuses startup.
    let init_vault = Arc::clone(&vault);
    let port = tokio::task::spawn_blocking(move || {
        let floor = init_vault.linear_host_policy()?;
        let policy = config
            .policy_override
            .as_ref()
            .map_or(Ok(floor.clone()), |override_row| floor.narrow(override_row))?;
        Ok::<_, anyhow::Error>(LinearPort::new(
            LinearHttp::new(config, policy)?,
            Some(init_vault),
        ))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Linear host client initialization failed"))??;
    Ok(tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(port.http.policy.interval_secs));
        interval.set_missed_tick_behavior(match port.http.policy.missed_tick {
            LinearMissedTick::Skip => tokio::time::MissedTickBehavior::Skip,
            LinearMissedTick::Delay => tokio::time::MissedTickBehavior::Delay,
        });
        loop {
            interval.tick().await;
            let vault = Arc::clone(&vault);
            let port = port.clone();
            match tokio::task::spawn_blocking(move || sync_once(&vault, &port)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(error = %error, "Linear mirror tick failed"),
                Err(error) => tracing::warn!(error = %error, "Linear mirror worker failed"),
            }
        }
    }))
}
