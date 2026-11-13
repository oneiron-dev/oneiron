//! The built-in workspace connectors (FIX 4862; MAIL-GOOGLE = A, rows 1 and
//! 3; L3-17): typed code-mode modules over the user's own files in Google,
//! each a catalog name `connector.call` routes, such as `google.sheets`.
//! Code mode spells a call
//! `connector["google.sheets"]["values.batchGet"](args)`; the guest's proxy
//! sends it as the same `connector.call`.
//!
//! Each API is one [`WorkspaceApi`] descriptor: its catalog name, its tools
//! with the pack grant each needs and its input schema, and how a call's
//! checked input becomes the exact requests it sends ([`WorkspacePlan`]).
//! Everything else is this core's, the same for every API:
//!
//! * **Reads and writes.** A read sends one request. A write runs only on
//!   an explicit mutation; a preview (the default) shows the request and
//!   sends nothing. A write sends its effect and, when the provider answered
//!   it with a success, reads the file back. Each write leaves two Gate
//!   records: its intent before the send and its outcome after, under the
//!   reason `connector.<catalog name>.effect`. A write whose caller carries
//!   an invocation (a pumped run's step, say) claims it in its intent's
//!   transaction and settles the claim in its outcome's, so a replay of the
//!   invocation never sends an attempted write again: it answers the earlier
//!   send by its two records' ids, an uncertain or unsettled one as pending
//!   delivery, and sends again only when nothing reached the provider.
//!   Another request on the same invocation is refused.
//! * **Any bound caller.** A code-mode run, a pumped agent run, an agent's
//!   own MCP or HTTP credential, or the owner. A write from an anonymous
//!   off-record session is refused, as a secret grant is: the token's use
//!   keeps Gate records.
//! * **Ships as a pack.** An API runs only while its connection's engine
//!   pack (`oneiron.google`, [`GOOGLE_CONNECTION`]) is installed Active and
//!   the connection's check is Verified, and each tool only while the owner
//!   allows the permission its grant names. One sign-in serves every API of
//!   the connection; each API is its own optional permission.
//! * **The token stays in custody.** The grant is read at the custody door
//!   for the connection's effector and refreshed inside it; its access token
//!   goes to the host's credential broker with each request, and the broker
//!   adds it to the request and strips it from the reply. No token is
//!   returned, logged or written.
//!
//! A refusal that concerns the connection names it first, such as
//! `google_connection_not_checked`.

mod invocation;
mod receipt;
mod run;
pub mod sheets;
mod token;
mod wire;

pub use self::receipt::workspace_effect_reason;
pub use self::wire::{
    WorkspaceBrokerCall, WorkspaceBrokerHost, WorkspaceEndpoint, WorkspaceWireOutcome,
    WorkspaceWireRequest,
};

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use self::invocation::{WorkspaceWriteClaim, WorkspaceWriteIdentity};
use self::run::{WorkspaceAnswer, WorkspaceRun};
use crate::code_run::ConnectorCallReply;
use crate::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorToolSchema, ResolvedConnectorManifest,
    normalize_connector_key,
};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult, verify_actor_binding};
use crate::outbound_consent::tool_call::MutationIntent;
use crate::outbound_consent::{
    ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest, UntrustedToolResult,
};
use crate::vault::Vault;

/// No such tool.
const TOOL_UNKNOWN: &str = "connector_tool_unknown";
/// The reason code of arguments that are not the tool's input.
pub(crate) const ARGUMENTS_INVALID: &str = "connector_arguments_invalid";
/// The pack is not installed Active, or its connection is not checked.
const CONNECTION_NOT_CHECKED: &str = "connection_not_checked";
/// The owner did not allow the permission the tool's grant names.
const PERMISSION_NOT_ALLOWED: &str = "permission_not_allowed";
/// An off-record session keeps no Gate record, and a write writes two.
const WRITE_NEEDS_RECORD: &str = "write_needs_record";
/// The host installed no credential broker leg for the workspace modules.
const BROKER_NOT_INSTALLED: &str = "broker_not_installed";

/// One sign-in a module's calls present: a built-in pack's setup
/// connection, and the effector its stored grant is bound to.
#[derive(Debug)]
pub struct WorkspaceConnection {
    /// The engine pack that ships the connection.
    pub pack: &'static str,
    /// The pack's built-in adapter name: the pack is `oneiron.<builtin>`.
    pub builtin: &'static str,
    /// The pack's setup connection.
    pub connection: &'static str,
    /// The effector the stored grant's custody binding must cover with read.
    pub effector: &'static str,
    /// The first word of the connection's own reason codes: `google` in
    /// `google_connection_not_checked`.
    pub family: &'static str,
}

impl WorkspaceConnection {
    /// The connection's reason code `reason`: `<family>_<reason>`.
    pub(crate) fn code(&self, reason: &str) -> String {
        format!("{}_{reason}", self.family)
    }
}

/// The Google connection (L3-17-PACK = A): one pack, one sign-in, and each
/// API (Sheets, Docs, Slides, Drive) an optional permission with its own
/// scope.
pub static GOOGLE_CONNECTION: WorkspaceConnection = WorkspaceConnection {
    pack: "oneiron.google",
    builtin: "google",
    connection: "google",
    effector: "connector:google",
    family: "google",
};

/// One tool of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceTool {
    /// The tool's name, as `connector.call` names it.
    pub name: &'static str,
    /// The pack grant the owner must have allowed for a call of it.
    pub grant: &'static str,
    /// Whether a call changes the user's file.
    pub writes: bool,
}

/// The file a module's calls act on, as its replies and receipts name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceTarget {
    /// The reply field holding the file's id, such as `spreadsheetId`.
    pub field: &'static str,
    /// The file's kind in a Gate record's details, such as `spreadsheet`.
    pub kind: &'static str,
}

/// One call's checked input as the exact requests it sends.
#[derive(Debug)]
pub struct WorkspacePlan {
    target: String,
    effect: WorkspaceWireRequest,
    readback: Option<WorkspaceWireRequest>,
    preview: Map<String, Value>,
}

impl WorkspacePlan {
    /// A plan acting on the file `target`: its `effect`, the `readback`
    /// that reads a write back, and what a write's preview shows beside the
    /// request's digest.
    pub(crate) fn new(
        target: String,
        effect: WorkspaceWireRequest,
        readback: Option<WorkspaceWireRequest>,
        preview: Map<String, Value>,
    ) -> Self {
        Self {
            target,
            effect,
            readback,
            preview,
        }
    }

    /// The id of the file the call acts on.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The request the call sends first: the read, or the write's effect.
    #[must_use]
    pub const fn effect(&self) -> &WorkspaceWireRequest {
        &self.effect
    }

    /// The read a write sends after its effect succeeded; `None` for a read.
    #[must_use]
    pub const fn readback(&self) -> Option<&WorkspaceWireRequest> {
        self.readback.as_ref()
    }
}

/// One API's descriptor: what the core needs to list, check and send its
/// calls.
pub trait WorkspaceApi: Sync {
    /// The catalog name `connector.call` routes, such as `google.sheets`.
    fn catalog_name(&self) -> &'static str;

    /// The one-line catalog summary.
    fn summary(&self) -> &'static str;

    /// The sign-in its calls present.
    fn connection(&self) -> &'static WorkspaceConnection;

    /// The file its calls act on.
    fn target(&self) -> WorkspaceTarget;

    /// Every tool, in catalog order.
    fn tools(&self) -> &'static [WorkspaceTool];

    /// `tool`'s input schema, typed at its top level.
    fn input_schema(&self, tool: &WorkspaceTool) -> Value;

    /// `arguments` checked as `tool`'s input, and the exact requests a call
    /// of it sends.
    ///
    /// # Errors
    ///
    /// The reason code the arguments do not fit, such as
    /// `connector_arguments_invalid`.
    fn plan(
        &self,
        tool: &WorkspaceTool,
        arguments: &Value,
    ) -> std::result::Result<WorkspacePlan, &'static str>;
}

/// Every built-in workspace module, in catalog order.
static MODULES: [&dyn WorkspaceApi; 1] = [&sheets::SheetsApi];

/// The built-in module whose catalog name is exactly `name`.
#[must_use]
pub fn module(name: &str) -> Option<&'static dyn WorkspaceApi> {
    MODULES
        .iter()
        .copied()
        .find(|module| module.catalog_name() == name)
}

/// The tool of `module` named `name`.
fn tool_named(module: &dyn WorkspaceApi, name: &str) -> Option<&'static WorkspaceTool> {
    module.tools().iter().find(|tool| tool.name == name)
}

/// One `connector.call` of `module` for the caller `memory` is bound to,
/// under `invocation`, the caller's logical call as a connector call's
/// ledger keys it, when it carries one. Blocking: it sends, so call it on a
/// blocking worker.
///
/// # Errors
///
/// Storage faults, and a caller whose actor binding does not hold. Every
/// other stop is the reply's: a refusal names its reason code, and the
/// provider's refusal answers as a tool error.
pub fn call_workspace_connector(
    memory: &Memory<'_>,
    module: &'static dyn WorkspaceApi,
    input: &ConnectorCallRequest,
    invocation: Option<ConnectorCallInvocation>,
) -> MemoryResult<ConnectorCallReply> {
    let Some(tool) = tool_named(module, &input.tool) else {
        return Ok(refused(TOOL_UNKNOWN));
    };
    let vault = memory.vault();
    verify_actor_binding(vault, memory.actor(), memory.actor_class())?;
    let plan = match module.plan(tool, &input.arguments) {
        Ok(plan) => plan,
        Err(reason) => return Ok(refused(reason)),
    };
    let connection = module.connection();
    let Some(credential) = checked_credential(vault, connection)? else {
        return Ok(refused(&connection.code(CONNECTION_NOT_CHECKED)));
    };
    if !grant_allowed(vault, connection, tool) {
        return Ok(refused(&connection.code(PERMISSION_NOT_ALLOWED)));
    }
    if tool.writes && input.mutation == MutationIntent::Preview {
        return Ok(delivered(module, tool, preview(module, &plan), false));
    }
    if tool.writes && memory.keeps_no_record() {
        return Ok(refused(&connection.code(WRITE_NEEDS_RECORD)));
    }
    let claim = match invocation {
        Some(invocation) if tool.writes && input.mutation == MutationIntent::ExplicitMutation => {
            let identity = WorkspaceWriteIdentity {
                connector: module.catalog_name().to_owned(),
                tool: tool.name.to_owned(),
                target: plan.target().to_owned(),
                request: plan.effect().digest(),
                mutation: input.mutation,
            };
            Some(WorkspaceWriteClaim::new(
                memory.actor(),
                invocation,
                identity,
                module,
            )?)
        }
        _ => None,
    };
    if let Some(claim) = &claim
        && let Some(answer) = claim.answer(vault)?
    {
        return Ok(reply(module, tool, answer));
    }
    let Some(host) = vault.served_transports().workspace_broker().cloned() else {
        return Ok(refused(&connection.code(BROKER_NOT_INSTALLED)));
    };
    let run = WorkspaceRun {
        vault,
        host,
        module,
        credential,
        actor: memory.actor(),
        actor_class: memory.actor_class(),
        claim,
    };
    Ok(reply(module, tool, run.send(tool, plan)?))
}

/// The reply `answer` makes for a call of `tool`: a write's uncertain send
/// waits as pending delivery, a read's answers as a tool error.
fn reply(
    module: &dyn WorkspaceApi,
    tool: &WorkspaceTool,
    answer: WorkspaceAnswer,
) -> ConnectorCallReply {
    match answer {
        WorkspaceAnswer::Answered { output, is_error } => delivered(module, tool, output, is_error),
        WorkspaceAnswer::NotSent(reason) => refused(&reason),
        WorkspaceAnswer::Uncertain(reason) if tool.writes => ConnectorCallReply::PendingDelivery {
            call_ref: None,
            reasons: vec![reason],
        },
        WorkspaceAnswer::Uncertain(reason) => {
            delivered(module, tool, json!({ "error": reason }), true)
        }
    }
}

/// `module`'s tools as one resolved connector manifest, the typed
/// declaration a catalogued connector's slate shows: each tool's input
/// schema, and as its permission the pack grant it needs.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when a declared schema does not resolve.
pub fn workspace_manifest(module: &dyn WorkspaceApi) -> Result<ResolvedConnectorManifest> {
    ResolvedConnectorManifest::resolve(
        module
            .tools()
            .iter()
            .map(|tool| ConnectorToolSchema {
                name: tool.name.to_owned(),
                permissions: BTreeSet::from([tool.grant.to_owned()]),
                triggers: BTreeSet::new(),
                input_schema: module.input_schema(tool),
            })
            .collect(),
    )
}

/// `connector.schema` for one tool of `module`: its declared input schema
/// while a call of it would run, else the refusal a call would meet first.
pub(crate) fn workspace_tool_schema(
    vault: &Vault,
    module: &dyn WorkspaceApi,
    tool: &str,
) -> Result<crate::outbound_consent::ConnectorToolSchema> {
    let unavailable = |reason: String| crate::outbound_consent::ConnectorToolSchema::Unavailable {
        reasons: vec![reason],
    };
    let Some(tool) = tool_named(module, tool) else {
        return Ok(unavailable(TOOL_UNKNOWN.to_owned()));
    };
    let connection = module.connection();
    if checked_credential(vault, connection)?.is_none() {
        return Ok(unavailable(connection.code(CONNECTION_NOT_CHECKED)));
    }
    if !grant_allowed(vault, connection, tool) {
        return Ok(unavailable(connection.code(PERMISSION_NOT_ALLOWED)));
    }
    let manifest = workspace_manifest(module)?;
    let declared = manifest
        .tools()
        .iter()
        .find(|declared| declared.name == tool.name)
        .ok_or_else(|| {
            Error::InvalidConfig("workspace manifest declares no such tool".to_owned())
        })?;
    Ok(crate::outbound_consent::ConnectorToolSchema::Approved {
        input_schema: declared.input_schema.clone(),
        destructive_hint: tool.writes,
    })
}

/// Every built-in module as `connector.list` lists it, in catalog order:
/// each while its connection is checked, the owner allows at least one of
/// its tools, and `query` finds it as the catalog search finds a name or a
/// summary. Its verbs are the tools the owner's allowed permissions reach.
pub(crate) fn workspace_catalog_entries(
    vault: &Vault,
    query: &str,
) -> Result<Vec<ConnectorCatalogEntry>> {
    let mut entries = Vec::new();
    for module in MODULES {
        let connection = module.connection();
        let Some(checked) =
            vault.checked_builtin_channel(connection.builtin, connection.connection)?
        else {
            continue;
        };
        let found = module
            .catalog_name()
            .contains(&normalize_connector_key(query))
            || module
                .summary()
                .to_lowercase()
                .contains(&query.trim().to_lowercase());
        if !found {
            continue;
        }
        let verbs: Vec<String> = module
            .tools()
            .iter()
            .filter(|tool| grant_allowed(vault, connection, tool))
            .map(|tool| tool.name.to_owned())
            .collect();
        if verbs.is_empty() {
            continue;
        }
        entries.push(ConnectorCatalogEntry {
            name: module.catalog_name().to_owned(),
            connector: module.catalog_name().to_owned(),
            summary: module.summary().to_owned(),
            verbs,
            call_class: ConnectorCallClass::ScopedMcp,
            registered_at: checked.check.checked_at,
        });
    }
    Ok(entries)
}

/// The custody name of the grant a checked connection presents: the
/// credential its setup declares for the connection's effector. `None`
/// while the pack is not installed Active for this engine, or its
/// connection's check is not Verified.
fn checked_credential(vault: &Vault, connection: &WorkspaceConnection) -> Result<Option<String>> {
    let Some(checked) = vault.checked_builtin_channel(connection.builtin, connection.connection)?
    else {
        return Ok(None);
    };
    Ok(checked
        .connection
        .secrets
        .into_iter()
        .find(|secret| secret.effector == connection.effector)
        .map(|secret| secret.name))
}

/// Whether a checked session holds the owner's live grant for the
/// permission `tool` needs.
fn grant_allowed(vault: &Vault, connection: &WorkspaceConnection, tool: &WorkspaceTool) -> bool {
    vault
        .require_pack_grants_verified(connection.pack, &[tool.grant])
        .is_ok()
}

/// What a write would send, and that nothing was sent: the file, the
/// request's digest, and what the module's plan shows of it.
fn preview(module: &dyn WorkspaceApi, plan: &WorkspacePlan) -> Value {
    let mut output = plan.preview.clone();
    output.insert("preview".to_owned(), Value::Bool(true));
    output.insert(module.target().field.to_owned(), Value::from(plan.target()));
    output.insert("request".to_owned(), Value::from(plan.effect().digest()));
    output.insert(
        "note".to_owned(),
        Value::from("Nothing was written. Call again with mutation explicit_mutation to write."),
    );
    Value::Object(output)
}

/// A delivered reply carrying `output` as foreign data: the MCP text block,
/// and the same JSON as its structured content.
fn delivered(
    module: &dyn WorkspaceApi,
    tool: &WorkspaceTool,
    output: Value,
    is_error: bool,
) -> ConnectorCallReply {
    let text = output.to_string();
    ConnectorCallReply::project(
        module.catalog_name(),
        tool.name,
        ConnectorCallOutcome::Delivered {
            intent: None,
            result: Some(UntrustedToolResult {
                content: json!([{ "type": "text", "text": text }]),
                structured_content: Some(output),
                is_error,
                rpc_error: None,
            }),
            result_absence: None,
            budget_steering: Vec::new(),
        },
    )
}

fn refused(reason: &str) -> ConnectorCallReply {
    ConnectorCallReply::Refused {
        decision_ref: None,
        reasons: vec![reason.to_owned()],
    }
}
