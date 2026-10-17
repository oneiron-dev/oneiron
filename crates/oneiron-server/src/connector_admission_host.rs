//! The host half of a generic MCP catalog connector's first admission
//! (OF-189): discovery at the endpoint `[connectors.<name>]` installed, and
//! the HTTP transport the ARCH-0028 qualification suite probes through.
//!
//! Discovery is `initialize`, `notifications/initialized`, then every
//! `tools/list` page. Qualification opens a fresh MCP session for each
//! connection at the key's pinned revision and sends each probe as one
//! `tools/call`. The suite gets the request body and headers this host
//! built and sent; the rest of a probe reply is the connector's own
//! evidence, read from the result's `_meta`, which the suite grades against
//! the kit's sources and an effect state read on a session of its own.
//! Every request carries `Mcp-Method` and `Mcp-Name` read from its own
//! body. The credential is presented only inside the credential door, as
//! the call host presents it. No proxy, no redirects, bounded replies, and
//! any server request on a reply stream is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use oneiron::Vault;
use oneiron::connector_key::qualification::{
    GroundingOracle, ProbeDisposition, ProbeReply, ProbeRequest, ProbeTool, ProbeTraceEvent,
    ProbeWrite, QualificationConnection, QualificationConnector, QualificationFailure,
    QualificationPlan,
};
use oneiron::connector_key::{
    ConnectorToolSchema, ResolvedConnectorManifest, SlateDataClass, SlateToolManifest,
};
use oneiron::outbound_consent::CONNECTOR_REPLY_MAX_BYTES;
use oneiron::skill_hub::pack_catalog::PackObservedTool;
use reqwest::blocking::{Client, Request, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};

/// The MCP revision discovery asks for.
const REQUESTED_REVISION: &str = "2026-07-28";
/// The streamable HTTP revisions this client speaks. A connector that
/// answers `initialize` with another is not admitted.
const SPOKEN_REVISIONS: [&str; 4] = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];
/// The most `tools/list` pages one discovery reads.
const MAX_LIST_PAGES: usize = 64;
/// Connecting to a connector's endpoint.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `initialize`, a notification, one list page, a refusal, the session's end.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// One probe's `tools/call` or one effect-state read, until its reply is read.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The `_meta` key a connector's probe declarations and its probe evidence
/// ride under.
const PROBE_META: &str = "oneiron/probe";
/// A tool's data class when the owner names none at registration.
const DEFAULT_DATA_CLASS: SlateDataClass = SlateDataClass::Personal;

const SESSION_HEADER: &str = "mcp-session-id";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";
const ACCEPT_BOTH: &str = "application/json, text/event-stream";

fn refused(reason: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(reason.to_owned())
}

/// The admission HTTP client. Build it on a blocking worker.
pub(crate) fn client() -> oneiron::Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CALL_TIMEOUT)
        .build()
        .map_err(|_| refused("the connector HTTP client could not be built"))
}

/// Runs `work` with the connector's credential as an `Authorization`
/// header, inside the credential door, or with none when the key names no
/// custody record. The header never leaves `work`.
pub(crate) fn with_credential<T>(
    vault: &Vault,
    secret_ref: Option<&str>,
    connector: &str,
    work: impl FnOnce(Option<&HeaderValue>) -> T,
) -> oneiron::Result<T> {
    let Some(secret_ref) = secret_ref else {
        return Ok(work(None));
    };
    let effector = format!("connector:{connector}");
    let mut work = Some(work);
    let mut done = None;
    let _receipt = vault.inject_secret_at_door(secret_ref, &effector, &mut |value: &[u8]| {
        let header = authorization_header(value)?;
        if let Some(work) = work.take() {
            done = Some(work(Some(&header)));
        }
        Ok(())
    })?;
    done.ok_or_else(|| refused("the connector credential door did not open"))
}

/// The stored value is a whole `Authorization` header (`Basic ...` or
/// `Bearer ...`) or a bare bearer token, as the call host reads it.
fn authorization_header(value: &[u8]) -> oneiron::Result<HeaderValue> {
    let value = std::str::from_utf8(value)
        .map_err(|_| refused("the stored credential is not text"))?
        .trim();
    let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
        value.to_owned()
    } else {
        format!("Bearer {value}")
    };
    let mut header = HeaderValue::from_str(&header)
        .map_err(|_| refused("the stored credential is not a header value"))?;
    header.set_sensitive(true);
    Ok(header)
}

/// One tool as the connector listed it. The hints read with MCP's
/// defaults: a tool not marked read-only writes, a writer not marked
/// otherwise destroys, and a tool not marked closed reaches the open world.
#[derive(Debug)]
pub(crate) struct ListedTool {
    pub(crate) name: String,
    description: String,
    /// The literal declaration; resolution happens on the engine side.
    input_schema: Value,
    read_only: bool,
    destructive: bool,
    open_world: bool,
    /// The result types the connector declares for the probe suite.
    result_types: BTreeSet<String>,
}

impl ListedTool {
    fn parse(tool: &Value) -> Result<Self, &'static str> {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or("a listed tool has no name")?;
        let input_schema = tool
            .get("inputSchema")
            .filter(|schema| schema.is_object())
            .ok_or("a listed tool has no input schema")?;
        let hint = |name: &str| {
            tool.get("annotations")
                .and_then(|annotations| annotations.get(name))
                .and_then(Value::as_bool)
        };
        let read_only = hint("readOnlyHint") == Some(true);
        let result_types = tool
            .get("_meta")
            .and_then(|meta| meta.get(PROBE_META))
            .and_then(|probe| probe.get("result_types"))
            .and_then(Value::as_array)
            .map(|types| {
                types
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            name: name.to_owned(),
            description: tool
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            input_schema: input_schema.clone(),
            read_only,
            destructive: !read_only && hint("destructiveHint") != Some(false),
            open_world: hint("openWorldHint") != Some(false),
            result_types,
        })
    }

    /// What the suite lists: the literal schema, the declared result types,
    /// and a write unless the tool is marked read-only. MCP names no trigger.
    fn probe_tool(&self) -> ProbeTool {
        ProbeTool {
            name: self.name.clone(),
            input_schema: self.input_schema.clone(),
            trigger: None,
            result_types: self.result_types.clone(),
            writes: !self.read_only,
        }
    }

    /// The retained manifest's row. The hints become permissions, so a tool
    /// that starts writing, destroying or reaching out drifts as an
    /// expansion, and one that stops is a proved narrow.
    fn schema_row(&self) -> ConnectorToolSchema {
        let mut permissions = BTreeSet::from(["read".to_owned()]);
        if !self.read_only {
            permissions.insert("write".to_owned());
        }
        if self.destructive {
            permissions.insert("destroy".to_owned());
        }
        if self.open_world {
            permissions.insert("open_world".to_owned());
        }
        ConnectorToolSchema {
            name: self.name.clone(),
            permissions,
            triggers: BTreeSet::new(),
            input_schema: self.input_schema.clone(),
        }
    }

    /// The screening input: name, description and literal schema.
    pub(crate) fn screened(&self) -> PackObservedTool {
        PackObservedTool {
            name: self.name.clone(),
            description: self.description.clone(),
            input_schema: self.input_schema.clone(),
        }
    }
}

/// What one discovery found.
pub(crate) struct Discovery {
    /// The revision `initialize` negotiated.
    pub(crate) revision: String,
    pub(crate) tools: Vec<ListedTool>,
}

/// Lists the connector's tools at `endpoint`: at `pinned` once the key has
/// pinned a revision, else at the newest one both sides speak.
pub(crate) fn discover(
    client: &Client,
    endpoint: &str,
    auth: Option<&HeaderValue>,
    pinned: Option<&str>,
) -> oneiron::Result<Discovery> {
    let mut session = Session::open(client, endpoint, auth, pinned).map_err(refused)?;
    let tools = session.list_tools().map_err(refused)?;
    Ok(Discovery {
        revision: std::mem::take(&mut session.revision),
        tools,
    })
}

/// The listed tools resolved as the retained manifest resolves them.
pub(crate) fn resolve(tools: &[ListedTool]) -> oneiron::Result<ResolvedConnectorManifest> {
    ResolvedConnectorManifest::resolve(tools.iter().map(ListedTool::schema_row).collect())
}

/// What the owner names for one tool at registration. MCP declares neither.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolClass {
    #[serde(default = "default_data_class")]
    pub(crate) data_class: SlateDataClass,
    /// Whether a call spends.
    #[serde(default)]
    pub(crate) spends: bool,
}

impl Default for ToolClass {
    fn default() -> Self {
        Self {
            data_class: DEFAULT_DATA_CLASS,
            spends: false,
        }
    }
}

fn default_data_class() -> SlateDataClass {
    DEFAULT_DATA_CLASS
}

/// The slate manifest for the resolved tools: each resolved schema and its
/// header parameters, the hints as effects, and the owner's classes.
pub(crate) fn slate_manifest(
    resolved: &ResolvedConnectorManifest,
    tools: &[ListedTool],
    classes: &BTreeMap<String, ToolClass>,
) -> Vec<SlateToolManifest> {
    resolved
        .tools()
        .iter()
        .filter_map(|row| {
            let listed = tools.iter().find(|tool| tool.name == row.name)?;
            let class = classes.get(&row.name).copied().unwrap_or_default();
            Some(SlateToolManifest {
                name: row.name.clone(),
                data_class: class.data_class,
                header_parameters: header_parameters(&row.input_schema),
                resolved_input_schema: Some(row.input_schema.clone()),
                trigger: None,
                destroys: listed.destructive,
                spends: class.spends,
                sends_outward: !listed.read_only && listed.open_world,
                legacy_ask: false,
            })
        })
        .collect()
}

/// The parameters an `x-mcp-header` annotation sends as headers.
fn header_parameters(schema: &Value) -> Vec<String> {
    let mut names: Vec<String> = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| {
            properties
                .iter()
                .filter(|(_, property)| {
                    matches!(
                        property.get("x-mcp-header"),
                        Some(Value::Bool(true) | Value::String(_))
                    )
                })
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The owner's qualification kit: the probe plan, the isolated probe
/// store's sources and claims the oracle reads, and the MCP resource whose
/// contents are the sandbox's effect state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationKit {
    plan: QualificationPlan,
    /// Each source record's text, by reference.
    #[serde(default)]
    sources: BTreeMap<String, String>,
    /// Each claim's source references, by claim reference.
    #[serde(default)]
    claims: BTreeMap<String, Vec<String>>,
    pub(crate) effect_state_uri: String,
}

impl QualificationKit {
    /// The plan for one suite run, every idempotency key made fresh.
    /// Staging and activation each run the whole suite; a key the first run
    /// spent would replay with no new effect in the second.
    pub(crate) fn plan_for_run(&self) -> QualificationPlan {
        let run = oneiron::EntityId::now().to_hex();
        let mut plan = self.plan.clone();
        let injected = plan
            .injections
            .iter_mut()
            .flat_map(|injection| [&mut injection.baseline, &mut injection.injected]);
        for case in plan
            .reads
            .iter_mut()
            .chain([&mut plan.unanswerable])
            .chain(injected)
            .chain(plan.scope_escape.iter_mut())
            .chain(plan.write.as_mut())
            .chain(plan.timeout_retry.as_mut())
        {
            if let Some(Value::String(key)) = case.call.arguments.get_mut("idempotency_key") {
                key.push('.');
                key.push_str(&run);
            }
        }
        plan
    }
}

/// The kit's probe store, never the connector's word.
impl GroundingOracle for QualificationKit {
    fn source_bytes(&self, reference: &str) -> Option<Vec<u8>> {
        self.sources
            .get(reference)
            .map(|text| text.as_bytes().to_vec())
    }

    fn claim_sources(&self, reference: &str) -> Option<Vec<String>> {
        self.claims.get(reference).cloned()
    }
}

/// The suite's transport. Each connection is a fresh MCP session at the
/// key's pinned revision; the effect state is one `resources/read` of the
/// kit's resource on a session of its own, never read from a call reply.
pub(crate) struct HttpQualificationConnector<'a> {
    client: &'a Client,
    endpoint: &'a str,
    auth: Option<&'a HeaderValue>,
    revision: &'a str,
    effect_state_uri: &'a str,
}

impl<'a> HttpQualificationConnector<'a> {
    pub(crate) fn new(
        client: &'a Client,
        endpoint: &'a str,
        auth: Option<&'a HeaderValue>,
        revision: &'a str,
        effect_state_uri: &'a str,
    ) -> Self {
        Self {
            client,
            endpoint,
            auth,
            revision,
            effect_state_uri,
        }
    }

    fn session(&self) -> Result<Session<'a>, QualificationFailure> {
        Session::open(self.client, self.endpoint, self.auth, Some(self.revision))
            .map_err(|_| QualificationFailure::Transport)
    }
}

impl QualificationConnector for HttpQualificationConnector<'_> {
    fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
        Ok(Box::new(HttpQualificationConnection {
            session: self.session()?,
        }))
    }

    fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
        let result = self
            .session()?
            .rpc(
                "effect_state",
                "resources/read",
                json!({ "uri": self.effect_state_uri }),
                CALL_TIMEOUT,
            )
            .map_err(|_| QualificationFailure::Transport)?;
        let contents = result
            .get("contents")
            .ok_or(QualificationFailure::Transport)?;
        serde_json::to_vec(contents).map_err(|_| QualificationFailure::Transport)
    }
}

struct HttpQualificationConnection<'a> {
    session: Session<'a>,
}

impl QualificationConnection for HttpQualificationConnection<'_> {
    fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure> {
        Ok(self
            .session
            .list_tools()
            .map_err(|_| QualificationFailure::Transport)?
            .iter()
            .map(ListedTool::probe_tool)
            .collect())
    }

    fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": request.id,
            "method": "tools/call",
            "params": { "name": request.name, "arguments": request.arguments },
        });
        let built = self
            .session
            .build(&body, CALL_TIMEOUT)
            .map_err(|_| QualificationFailure::Transport)?;
        let (request_body, request_headers) = captured(&built)?;
        let response = self
            .session
            .client
            .execute(built)
            .map_err(|_| QualificationFailure::Transport)?;
        let message = self
            .session
            .answer(response, &body["id"])
            .map_err(|_| QualificationFailure::Transport)?;
        let result = message
            .get("result")
            .ok_or(QualificationFailure::Transport)?;
        let evidence = result
            .get("_meta")
            .and_then(|meta| meta.get(PROBE_META))
            .ok_or(QualificationFailure::Trace)?;
        let evidence =
            ProbeEvidence::deserialize(evidence).map_err(|_| QualificationFailure::Trace)?;
        Ok(ProbeReply {
            request_body,
            request_headers,
            disposition: evidence.disposition,
            result_type: evidence.result_type,
            result: result
                .get("structuredContent")
                .cloned()
                .unwrap_or(Value::Null),
            writes: evidence.writes,
            answer_claim_refs: evidence.answer_claim_refs,
            retrieval_refs: evidence.retrieval_refs,
            trace: evidence.trace,
            tokens: evidence.tokens,
            budget_units: evidence.budget_units,
        })
    }
}

/// What a connector reports about one probe, under `_meta["oneiron/probe"]`
/// of its `tools/call` result. The suite grades it; nothing here is trusted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeEvidence {
    disposition: ProbeDisposition,
    result_type: String,
    #[serde(default)]
    writes: Vec<ProbeWrite>,
    #[serde(default)]
    answer_claim_refs: Vec<String>,
    #[serde(default)]
    retrieval_refs: Vec<String>,
    trace: Vec<ProbeTraceEvent>,
    tokens: u64,
    budget_units: u64,
}

/// The body and headers of the request as built, the credential left out.
fn captured(request: &Request) -> Result<(Value, BTreeMap<String, String>), QualificationFailure> {
    let body = request
        .body()
        .and_then(reqwest::blocking::Body::as_bytes)
        .ok_or(QualificationFailure::Transport)?;
    let body: Value = serde_json::from_slice(body).map_err(|_| QualificationFailure::Transport)?;
    let mut headers = BTreeMap::new();
    for (name, value) in request.headers() {
        if *name == AUTHORIZATION {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|_| QualificationFailure::Transport)?;
        headers.insert(name.as_str().to_owned(), value.to_owned());
    }
    Ok((body, headers))
}

/// One MCP session on one endpoint. Dropping it ends the session.
struct Session<'a> {
    client: &'a Client,
    endpoint: &'a str,
    auth: Option<&'a HeaderValue>,
    revision: String,
    protocol: Option<HeaderValue>,
    session: Option<HeaderValue>,
}

impl<'a> Session<'a> {
    /// `initialize` and `notifications/initialized`. A pinned revision must
    /// come back as itself; otherwise the answer must be one this client
    /// speaks.
    fn open(
        client: &'a Client,
        endpoint: &'a str,
        auth: Option<&'a HeaderValue>,
        pinned: Option<&str>,
    ) -> Result<Self, &'static str> {
        let mut opened = Self {
            client,
            endpoint,
            auth,
            revision: String::new(),
            protocol: None,
            session: None,
        };
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": pinned.unwrap_or(REQUESTED_REVISION),
                "capabilities": {},
                "clientInfo": { "name": "oneiron", "version": env!("CARGO_PKG_VERSION") },
            },
        });
        let response = client
            .execute(opened.build(&initialize, HANDSHAKE_TIMEOUT)?)
            .map_err(|_| "the connector did not answer initialize")?;
        opened.session = response.headers().get(SESSION_HEADER).cloned();
        let answer = opened.answer(response, &initialize["id"])?;
        let revision = answer
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .ok_or("the connector's initialize answer names no revision")?;
        if !pinned.map_or(SPOKEN_REVISIONS.contains(&revision), |pinned| {
            pinned == revision
        }) {
            return Err("the connector answered a protocol revision this host does not speak");
        }
        opened.protocol = Some(
            HeaderValue::from_str(revision)
                .map_err(|_| "the connector's revision is not a token")?,
        );
        opened.revision = revision.to_owned();
        opened.notify("notifications/initialized")?;
        Ok(opened)
    }

    /// One POST with the session's headers. `Mcp-Method` and `Mcp-Name` are
    /// read from the body itself, so they always match it.
    fn build(&self, body: &Value, timeout: Duration) -> Result<Request, &'static str> {
        let mut request = self
            .client
            .post(self.endpoint)
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, ACCEPT_BOTH)
            .body(body.to_string());
        if let Some(method) = body.get("method").and_then(Value::as_str) {
            request = request.header(METHOD_HEADER, method);
        }
        if let Some(name) = body
            .pointer("/params/name")
            .or_else(|| body.pointer("/params/uri"))
            .and_then(Value::as_str)
        {
            request = request.header(NAME_HEADER, name);
        }
        if let Some(auth) = self.auth {
            request = request.header(AUTHORIZATION, auth.clone());
        }
        if let Some(session) = &self.session {
            request = request.header(SESSION_HEADER, session.clone());
        }
        if let Some(protocol) = &self.protocol {
            request = request.header(PROTOCOL_HEADER, protocol.clone());
        }
        request
            .build()
            .map_err(|_| "a request to the connector could not be built")
    }

    fn notify(&self, method: &str) -> Result<(), &'static str> {
        let body = json!({ "jsonrpc": "2.0", "method": method });
        let response = self
            .client
            .execute(self.build(&body, HANDSHAKE_TIMEOUT)?)
            .map_err(|_| "the connector did not take a notification")?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err("the connector refused a notification")
        }
    }

    /// One request and its result; an error answer fails it.
    fn rpc(
        &self,
        id: &str,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, &'static str> {
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self
            .client
            .execute(self.build(&body, timeout)?)
            .map_err(|_| "the connector did not answer")?;
        let message = self.answer(response, &body["id"])?;
        message
            .get("result")
            .cloned()
            .ok_or("the connector answered with an error")
    }

    /// The message answering `id` on a successful reply.
    fn answer(&self, response: Response, id: &Value) -> Result<Value, &'static str> {
        if !response.status().is_success() {
            return Err("the connector refused a request");
        }
        read_reply(response, id, &mut |request: &Value| self.refuse(request))
    }

    /// Every `tools/list` page, in the connector's order.
    fn list_tools(&self) -> Result<Vec<ListedTool>, &'static str> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_LIST_PAGES {
            let params = cursor
                .take()
                .map_or_else(|| json!({}), |cursor| json!({ "cursor": cursor }));
            let result = self.rpc(
                &format!("tools/list:{page}"),
                "tools/list",
                params,
                HANDSHAKE_TIMEOUT,
            )?;
            let listed = result
                .get("tools")
                .and_then(Value::as_array)
                .ok_or("a tools/list page has no tools")?;
            for tool in listed {
                tools.push(ListedTool::parse(tool)?);
            }
            match result.get("nextCursor").and_then(Value::as_str) {
                Some(next) => cursor = Some(next.to_owned()),
                None => return Ok(tools),
            }
        }
        Err("the connector lists more tool pages than this host reads")
    }

    /// Answers one server request on a reply stream with a refusal: this
    /// client serves no elicitation, sampling or roots.
    fn refuse(&self, request: &Value) {
        let Some(id) = request.get("id") else {
            return;
        };
        let refusal = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "this client serves no server requests" },
        });
        if let Ok(refusal) = self.build(&refusal, HANDSHAKE_TIMEOUT) {
            drop(self.client.execute(refusal));
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        // The session's end is a courtesy; its outcome changes nothing.
        let mut end = self
            .client
            .delete(self.endpoint)
            .timeout(HANDSHAKE_TIMEOUT)
            .header(SESSION_HEADER, session.clone());
        if let Some(protocol) = &self.protocol {
            end = end.header(PROTOCOL_HEADER, protocol.clone());
        }
        if let Some(auth) = self.auth {
            end = end.header(AUTHORIZATION, auth.clone());
        }
        drop(end.send());
    }
}

const UNREADABLE: &str = "the connector's reply is unreadable";

/// Reads one reply body, JSON or an event stream, until the response that
/// answers `id`. Server requests on a stream go to `refuse`; notifications
/// are dropped. More than [`CONNECTOR_REPLY_MAX_BYTES`] is unreadable.
fn read_reply(
    response: Response,
    id: &Value,
    refuse: &mut dyn FnMut(&Value),
) -> Result<Value, &'static str> {
    let stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("text/event-stream"));
    let limit = u64::try_from(CONNECTOR_REPLY_MAX_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut body = response.take(limit);
    if !stream {
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).map_err(|_| UNREADABLE)?;
        if bytes.len() > CONNECTOR_REPLY_MAX_BYTES {
            return Err(UNREADABLE);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| UNREADABLE)?;
        let found = match value {
            Value::Array(batch) => batch.into_iter().find(|message| answers(message, id)),
            message => answers(&message, id).then_some(message),
        };
        return found.ok_or(UNREADABLE);
    }
    let mut reader = BufReader::new(body);
    let mut read = 0usize;
    let mut data = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|_| UNREADABLE)?;
        read = read.saturating_add(n);
        if read > CONNECTOR_REPLY_MAX_BYTES {
            return Err(UNREADABLE);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if n == 0 || trimmed.is_empty() {
            if let Some(message) = finished_event(&mut data, id, refuse) {
                return Ok(message);
            }
            if n == 0 {
                return Err(UNREADABLE);
            }
            continue;
        }
        if let Some(field) = trimmed.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(field.strip_prefix(' ').unwrap_or(field));
        }
    }
}

/// One finished event: the answer to `id`, else nothing. A server request
/// in it is refused.
fn finished_event(data: &mut String, id: &Value, refuse: &mut dyn FnMut(&Value)) -> Option<Value> {
    if data.is_empty() {
        return None;
    }
    let message = serde_json::from_str::<Value>(&std::mem::take(data)).ok()?;
    if answers(&message, id) {
        return Some(message);
    }
    if message.get("method").is_some() && message.get("id").is_some() {
        refuse(&message);
    }
    None
}

/// A response (not a request) carrying exactly this id.
fn answers(message: &Value, id: &Value) -> bool {
    message.get("method").is_none()
        && message.get("id") == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}
