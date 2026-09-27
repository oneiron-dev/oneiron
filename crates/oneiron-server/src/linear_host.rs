//! Opt-in authenticated Linear host for the vault TASK mirror. No token enters the engine.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use chrono::DateTime;
use oneiron::linear_sync::{
    LinearChangePage, LinearChangeSource, LinearEgress, LinearIssueChange, LinearIssueRef,
    LinearSyncAdapter, LinearSyncError, LinearSyncResult, LinearTaskStore, MirroredTaskFields,
    VaultLinearTaskStore,
};
use oneiron::{EntityId, Vault};
use serde_json::{Value, json};

const GRAPHQL: &str = "https://api.linear.app/graphql";
const ISSUE_FIELDS: &str =
    "id identifier updatedAt title description priority team { id } assignee { id } state { name }";
const PAGE_SIZE: u64 = 50;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const TICK: Duration = Duration::from_secs(60);

#[cfg(test)]
#[path = "linear_host/tests.rs"]
mod tests;

/// Explicit opt-in: a credential alone cannot turn on periodic external writes.
/// The host admits only Linear's fixed HTTPS endpoint (no caller-selected URL).
pub(crate) struct LinearHostConfig {
    token: String,
    team_id: String,
    status_names: BTreeMap<String, String>,
}
impl LinearHostConfig {
    pub(crate) fn from_env() -> anyhow::Result<Option<Self>> {
        let enabled = std::env::var("ONEIRON_LINEAR_SYNC_ENABLED").ok();
        let token = std::env::var("ONEIRON_LINEAR_API_KEY").ok();
        let team_id = std::env::var("ONEIRON_LINEAR_TEAM_ID").ok();
        let status_map = std::env::var("ONEIRON_LINEAR_STATUS_NAMES").ok();
        if enabled.is_none() && token.is_none() && team_id.is_none() && status_map.is_none() {
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
        Ok(Some(Self {
            token,
            team_id,
            status_names,
        }))
    }
}

#[derive(Clone)]
struct LinearHttp {
    client: reqwest::blocking::Client,
    token: Arc<str>,
    team_id: Arc<str>,
    status_names: Arc<BTreeMap<String, String>>,
    endpoint: Arc<str>,
}
impl LinearHttp {
    fn new(config: LinearHostConfig) -> anyhow::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            client,
            token: Arc::from(config.token),
            team_id: Arc::from(config.team_id),
            status_names: Arc::new(config.status_names),
            endpoint: Arc::from(GRAPHQL),
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
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| transport())?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
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
        Ok(Some(
            self.parse_issue(
                data.get("issue")
                    .filter(|issue| issue.is_object())
                    .ok_or_else(transport)?,
            )?,
        ))
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
        Ok(issue)
    }
    fn fields_input(&self, fields: &MirroredTaskFields) -> LinearSyncResult<Value> {
        Ok(
            json!({"title":fields.title,"description":fields.description,
            "priority":fields.priority,"assigneeId":fields.assignee_ref,
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

#[derive(Clone)]
struct LinearPort(LinearHttp, Option<Arc<Vault>>);
impl LinearChangeSource for LinearPort {
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        // Persist the GraphQL cursor after a successful page. A stopped worker
        // resumes from that position; echo suppression lives in the TASK link.
        let data = self.0.query(
            &format!("query($team:ID!,$after:String,$first:Int!){{ issues(filter:{{team:{{id:{{eq:$team}}}}}},sort:[{{updatedAt:{{order:Ascending}}}}],after:$after,first:$first){{nodes{{{ISSUE_FIELDS}}} pageInfo{{endCursor}}}}}}"),
            json!({"team":&*self.0.team_id,"after":cursor,"first":PAGE_SIZE}),
        )?;
        let nodes = data
            .pointer("/issues/nodes")
            .and_then(Value::as_array)
            .ok_or_else(transport)?;
        let changes = nodes
            .iter()
            .map(|node| self.0.parse_issue(node))
            .collect::<LinearSyncResult<Vec<_>>>()?;
        let next_cursor = data
            .pointer("/issues/pageInfo/endCursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if !changes.is_empty() && next_cursor.is_none() {
            return Err(transport());
        }
        Ok(LinearChangePage {
            changes,
            next_cursor,
        })
    }
}
impl LinearEgress for LinearPort {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        _task: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        // Linear accepts a caller-provided issue UUID. A retry after a lost
        // response reads the same id, instead of creating a second issue.
        let mut id = operation_id[..16].to_vec();
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        if let Some(existing) = self.0.issue(&uuid)? {
            return Ok(existing);
        }
        let mut input = self.0.fields_input(fields)?;
        input["id"] = json!(uuid);
        input["teamId"] = json!(&*self.0.team_id);
        let data = self.0.query(
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
            .0
            .parse_issue(data.pointer("/issueCreate/issue").ok_or_else(transport)?)?;
        if created.issue.issue_id != uuid {
            return Err(transport());
        }
        Ok(created)
    }
    fn update_issue(
        &mut self,
        _operation_id: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        if issue.team_id != *self.0.team_id {
            return Err(transport());
        }
        let vault = self.1.as_ref().ok_or_else(transport)?;
        let link = VaultLinearTaskStore::new(vault)
            .link_for_issue(issue)?
            .ok_or_else(transport)?;
        let current = self.0.issue(&issue.issue_id)?.ok_or_else(transport)?;
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
        let input = self.0.fields_input(fields)?;
        let data = self.0.query(
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
            .0
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
        "Linear mirror tick completed"
    );
    Ok(())
}

pub(crate) fn spawn_linear_sync(
    vault: Arc<Vault>,
    config: LinearHostConfig,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let port = LinearPort(LinearHttp::new(config)?, Some(Arc::clone(&vault)));
    Ok(tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
