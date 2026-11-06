//! The built-in Google Sheets connector (FIX 4862; MAIL-GOOGLE = A, row 1):
//! `connector.call` on the catalog name `google.sheets`, with four tools
//! over the Sheets v4 REST API. Code mode spells a call
//! `connector["google.sheets"]["values.batchGet"](args)`; the guest's proxy
//! sends it as the same `connector.call`.
//!
//! * **Reads.** `spreadsheets.get` reads a spreadsheet's title and each
//!   sheet's id, title, index and grid size; `values.batchGet` reads the
//!   values of one or more A1 ranges.
//! * **Writes.** `values.batchUpdate` writes values into A1 ranges and reads
//!   them back; `spreadsheets.batchUpdate` passes structural requests through
//!   and reads the sheets back. A write runs only on an explicit mutation; a
//!   preview (the default) shows the request and sends nothing. Each write
//!   leaves two Gate records: its intent before the send and its outcome
//!   after ([`SHEETS_EFFECT_REASON`]). A write whose caller carries an
//!   invocation (a pumped run's step, say) claims it in its intent's
//!   transaction and settles the claim in its outcome's, so a replay of the
//!   invocation never sends an attempted write again: it answers the earlier
//!   send by its two records' ids, an uncertain or unsettled one as pending
//!   delivery, and sends again only when nothing reached Google. Another
//!   request on the same invocation is refused.
//! * **Any bound caller.** A code-mode run, a pumped agent run, an agent's
//!   own MCP or HTTP credential, or the owner. A write from an anonymous
//!   off-record session is refused, as a secret grant is: the token's use
//!   keeps Gate records.
//! * **Ships as a pack.** It runs only while the engine pack `oneiron.sheets`
//!   is installed Active and its `sheets` connection's check is Verified,
//!   and each tool only while the owner allows the permission its grant
//!   names.
//! * **The token stays in custody.** The grant is read at the custody door
//!   for [`SHEETS_CONNECTOR_EFFECTOR`] and refreshed inside it; its access
//!   token goes to the host's credential broker with each request, and the
//!   broker adds it to the request and strips it from the reply. No token is
//!   returned, logged or written.

mod invocation;
mod receipt;
mod run;
mod token;
mod tools;
mod wire;

pub use self::receipt::SHEETS_EFFECT_REASON;
pub use self::wire::{
    SHEETS_API_ORIGIN, SHEETS_WIRE_MODEL, SheetsBrokerCall, SheetsBrokerHost, SheetsEndpoint,
    SheetsWireOutcome, SheetsWireRequest,
};

use std::collections::BTreeSet;

use serde_json::{Value, json};

use self::invocation::{SheetsWriteClaim, SheetsWriteIdentity};
use self::run::{SheetsAnswer, SheetsRequests, SheetsRun};
use self::tools::{SheetsCall, SheetsTool};
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

/// The engine pack that ships the connector.
pub const SHEETS_PACK: &str = "oneiron.sheets";

/// The pack's built-in adapter name.
pub const SHEETS_BUILTIN: &str = "sheets";

/// The pack's one setup connection.
pub const SHEETS_CONNECTION: &str = "sheets";

/// The connector's catalog name, as `connector.call` names it.
pub const SHEETS_CATALOG_NAME: &str = "google.sheets";

/// The effector the stored grant's custody binding must cover with read.
pub const SHEETS_CONNECTOR_EFFECTOR: &str = "connector:google.sheets";

/// The pack grant each read needs the owner to have allowed.
pub const SHEETS_READ_GRANT: &str = "sheets.read";

/// The pack grant each write needs the owner to have allowed.
pub const SHEETS_WRITE_GRANT: &str = "sheets.write";

/// The connector's one-line catalog summary.
const SHEETS_SUMMARY: &str = "Google Sheets: read sheets and cell values, and write values and sheet structure with a readback, through the credential broker.";

/// No such tool.
const TOOL_UNKNOWN: &str = "connector_tool_unknown";
/// The pack is not installed Active, or its connection is not checked.
const CONNECTION_NOT_CHECKED: &str = "sheets_connection_not_checked";
/// The owner did not allow the permission the tool's grant names.
const PERMISSION_NOT_ALLOWED: &str = "sheets_permission_not_allowed";
/// An off-record session keeps no Gate record, and a write writes two.
const WRITE_NEEDS_RECORD: &str = "sheets_write_needs_record";
/// The host installed no credential broker leg for Sheets.
const BROKER_NOT_INSTALLED: &str = "sheets_broker_not_installed";

/// One `connector.call` of `google.sheets` for the caller `memory` is bound
/// to, under `invocation`, the caller's logical call as a connector call's
/// ledger keys it, when it carries one. Blocking: it sends, so call it on a
/// blocking worker.
///
/// # Errors
///
/// Storage faults, and a caller whose actor binding does not hold. Every
/// other stop is the reply's: a refusal names its reason code, and Google's
/// refusal answers as a tool error.
pub fn call_google_sheets(
    memory: &Memory<'_>,
    input: &ConnectorCallRequest,
    invocation: Option<ConnectorCallInvocation>,
) -> MemoryResult<ConnectorCallReply> {
    let Some(tool) = SheetsTool::parse(&input.tool) else {
        return Ok(refused(TOOL_UNKNOWN));
    };
    let vault = memory.vault();
    verify_actor_binding(vault, memory.actor(), memory.actor_class())?;
    let call = match SheetsCall::parse(tool, &input.arguments) {
        Ok(call) => call,
        Err(reason) => return Ok(refused(reason)),
    };
    let Some(credential) = checked_credential(vault)? else {
        return Ok(refused(CONNECTION_NOT_CHECKED));
    };
    if !grant_allowed(vault, tool) {
        return Ok(refused(PERMISSION_NOT_ALLOWED));
    }
    let requests = match SheetsRequests::of(&call) {
        Ok(requests) => requests,
        Err(reason) => return Ok(refused(reason)),
    };
    if tool.writes() && input.mutation == MutationIntent::Preview {
        return Ok(delivered(tool, preview(&call, &requests), false));
    }
    if tool.writes() && memory.keeps_no_record() {
        return Ok(refused(WRITE_NEEDS_RECORD));
    }
    let claim = match invocation {
        Some(invocation) if tool.writes() && input.mutation == MutationIntent::ExplicitMutation => {
            let identity = SheetsWriteIdentity {
                tool: tool.as_str().to_owned(),
                spreadsheet_id: call.spreadsheet_id().to_owned(),
                request: requests.effect.digest(),
                mutation: input.mutation,
            };
            Some(SheetsWriteClaim::new(memory.actor(), invocation, identity)?)
        }
        _ => None,
    };
    if let Some(claim) = &claim
        && let Some(answer) = claim.answer(vault)?
    {
        return Ok(reply(tool, answer));
    }
    let Some(host) = vault.served_transports().sheets_broker().cloned() else {
        return Ok(refused(BROKER_NOT_INSTALLED));
    };
    let run = SheetsRun {
        vault,
        host,
        credential,
        actor: memory.actor(),
        actor_class: memory.actor_class(),
        claim,
    };
    Ok(reply(tool, run.send(&call, requests)?))
}

/// The reply `answer` makes for a call of `tool`: a write's uncertain send
/// waits as pending delivery, a read's answers as a tool error.
fn reply(tool: SheetsTool, answer: SheetsAnswer) -> ConnectorCallReply {
    match answer {
        SheetsAnswer::Answered { output, is_error } => delivered(tool, output, is_error),
        SheetsAnswer::NotSent(reason) => refused(&reason),
        SheetsAnswer::Uncertain(reason) if tool.writes() => ConnectorCallReply::PendingDelivery {
            call_ref: None,
            reasons: vec![reason],
        },
        SheetsAnswer::Uncertain(reason) => delivered(tool, json!({ "error": reason }), true),
    }
}

/// The connector's tools as one resolved connector manifest, the typed
/// declaration a catalogued connector's slate shows: each tool's input
/// schema, and as its permission the pack grant it needs.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when a declared schema does not resolve.
pub fn sheets_manifest() -> Result<ResolvedConnectorManifest> {
    ResolvedConnectorManifest::resolve(
        SheetsTool::ALL
            .into_iter()
            .map(|tool| ConnectorToolSchema {
                name: tool.as_str().to_owned(),
                permissions: BTreeSet::from([tool.grant().to_owned()]),
                triggers: BTreeSet::new(),
                input_schema: tool.input_schema(),
            })
            .collect(),
    )
}

/// `connector.schema` for one tool of `google.sheets`: its declared input
/// schema while a call of it would run, else the refusal a call would meet
/// first.
pub(crate) fn sheets_tool_schema(
    vault: &Vault,
    tool: &str,
) -> Result<crate::outbound_consent::ConnectorToolSchema> {
    let unavailable = |reason: &str| crate::outbound_consent::ConnectorToolSchema::Unavailable {
        reasons: vec![reason.to_owned()],
    };
    let Some(tool) = SheetsTool::parse(tool) else {
        return Ok(unavailable(TOOL_UNKNOWN));
    };
    if checked_credential(vault)?.is_none() {
        return Ok(unavailable(CONNECTION_NOT_CHECKED));
    }
    if !grant_allowed(vault, tool) {
        return Ok(unavailable(PERMISSION_NOT_ALLOWED));
    }
    let manifest = sheets_manifest()?;
    let declared = manifest
        .tools()
        .iter()
        .find(|declared| declared.name == tool.as_str())
        .ok_or_else(|| Error::InvalidConfig("sheets manifest declares no such tool".to_owned()))?;
    Ok(crate::outbound_consent::ConnectorToolSchema::Approved {
        input_schema: declared.input_schema.clone(),
        destructive_hint: tool.writes(),
    })
}

/// `google.sheets` as `connector.list` lists it: while the pack's connection
/// is checked, and `query` finds it as the catalog search finds a name or a
/// summary. Its verbs are the tools the owner's allowed permissions reach.
pub(crate) fn sheets_catalog_entry(
    vault: &Vault,
    query: &str,
) -> Result<Option<ConnectorCatalogEntry>> {
    let Some(checked) = vault.checked_builtin_channel(SHEETS_BUILTIN, SHEETS_CONNECTION)? else {
        return Ok(None);
    };
    let found = SHEETS_CATALOG_NAME.contains(&normalize_connector_key(query))
        || SHEETS_SUMMARY
            .to_lowercase()
            .contains(&query.trim().to_lowercase());
    if !found {
        return Ok(None);
    }
    Ok(Some(ConnectorCatalogEntry {
        name: SHEETS_CATALOG_NAME.to_owned(),
        connector: SHEETS_CATALOG_NAME.to_owned(),
        summary: SHEETS_SUMMARY.to_owned(),
        verbs: SheetsTool::ALL
            .into_iter()
            .filter(|tool| grant_allowed(vault, *tool))
            .map(|tool| tool.as_str().to_owned())
            .collect(),
        call_class: ConnectorCallClass::ScopedMcp,
        registered_at: checked.check.checked_at,
    }))
}

/// The custody name of the grant a checked Sheets connection presents: the
/// credential its setup declares for [`SHEETS_CONNECTOR_EFFECTOR`]. `None`
/// while the pack is not installed Active for this engine, or its
/// connection's check is not Verified.
fn checked_credential(vault: &Vault) -> Result<Option<String>> {
    let Some(checked) = vault.checked_builtin_channel(SHEETS_BUILTIN, SHEETS_CONNECTION)? else {
        return Ok(None);
    };
    Ok(checked
        .connection
        .secrets
        .into_iter()
        .find(|secret| secret.effector == SHEETS_CONNECTOR_EFFECTOR)
        .map(|secret| secret.name))
}

/// Whether a checked session holds the owner's live grant for the
/// permission `tool` needs.
fn grant_allowed(vault: &Vault, tool: SheetsTool) -> bool {
    vault
        .require_pack_grants_verified(SHEETS_PACK, &[tool.grant()])
        .is_ok()
}

/// What a write would send, and that nothing was sent: the request's
/// digest, and the ranges it writes or the request kinds it carries.
fn preview(call: &SheetsCall, requests: &SheetsRequests) -> Value {
    let mut output = json!({
        "preview": true,
        "spreadsheetId": call.spreadsheet_id(),
        "request": requests.effect.digest(),
        "note": "Nothing was written. Call again with mutation explicit_mutation to write."
    });
    match call {
        SheetsCall::ValuesBatchUpdate(input) => {
            let ranges: Vec<&str> = input
                .data
                .iter()
                .map(|range| range.range.as_str())
                .collect();
            output["ranges"] = json!(ranges);
        }
        SheetsCall::StructuralBatchUpdate(input) => {
            let kinds: Vec<&str> = input
                .requests
                .iter()
                .filter_map(|request| request.keys().next().map(String::as_str))
                .collect();
            output["requests"] = json!(kinds);
        }
        SheetsCall::SpreadsheetGet { .. } | SheetsCall::ValuesBatchGet(_) => {}
    }
    output
}

/// A delivered reply carrying `output` as foreign data: the MCP text block,
/// and the same JSON as its structured content.
fn delivered(tool: SheetsTool, output: Value, is_error: bool) -> ConnectorCallReply {
    let text = output.to_string();
    ConnectorCallReply::project(
        SHEETS_CATALOG_NAME,
        tool.as_str(),
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
