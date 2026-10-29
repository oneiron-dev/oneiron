//! The served half of the built-in `web` connector (FIX 11598, CONN-1 A):
//! every `connector.call` that names `web` lands here from
//! [`crate::api::connector_call_listing_as`], before the MCP driver.
//!
//! One call reads the vault's switch ([`WebConnectorSetting`]) and takes the
//! provider's key: the deploy's backend key from [`BACKEND_KEY_ENV`], the
//! owner's own secret copied out at the custody door, or a hub connector's own
//! call under its own grant and gate. It sends one HTTPS request outside any
//! transaction, shapes the answer as Afterglow's `search_web` does, and writes
//! one usage row: provider, tool, key source, latency, cost and the provider's
//! request id, never the query, the URL or the results. A provider failure
//! answers as a tool error, as an MCP tool's would; a call that cannot start
//! (no key, bad arguments, an unknown tool) is refused with its reason code.
mod charge;
mod keys;
mod providers;

use std::time::Instant;

use oneiron::EntityId;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{Memory, MemoryResult};
use oneiron::outbound_consent::{ConnectorCallOutcome, ConnectorCallRequest, UntrustedToolResult};
use oneiron::task_verb::sdk::ConnectorCallReply;
use oneiron::web_connector::{
    FETCH_CONTENT_MAX_CHARS, FetchRoute, WEB_CONNECTOR_NAME, WebCallOutcome, WebConnectorUsage,
    WebCostBasis, WebFetchInput, WebFetchOutput, WebKeySource, WebProvider, WebProviderKey,
    WebSearchInput, WebSearchOutput, WebTool, cut_chars, micro_usd_to_usd,
};
use serde_json::{Value, json};

use crate::server::SyncServer;
use providers::{ProviderAnswer, ProviderBody, ProviderError};

/// One `connector.call` of the `web` connector, beside the rows its passes
/// picked: the hub connector's, when the switch forwards to one, else none.
/// A call on the deploy's backend key is charged on `line`, the calling run's
/// own, else on a meter of its own (FIX 11604). Blocking: it sends, so call it
/// on a blocking worker.
pub(crate) fn call_listing(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: ConnectorCallRequest,
    line: Option<&RunAdmission>,
) -> MemoryResult<(ConnectorCallReply, Option<Vec<EntityId>>)> {
    let Some(tool) = WebTool::parse(&input.tool) else {
        return Ok((refused("connector_tool_unknown"), None));
    };
    let setting = server.vault().web_connector_setting()?;
    if let WebProviderKey::Hub { connector } = &setting.key {
        let connector = connector.clone();
        return forward_to_hub(server, memory, setting.provider, &connector, tool, input);
    }
    let call = match tool {
        WebTool::Search => WebSearchInput::from_arguments(&input.arguments).map(WebCall::Search),
        WebTool::Fetch => WebFetchInput::from_arguments(&input.arguments).map(WebCall::Fetch),
    };
    let Some(call) = call else {
        return Ok((refused("connector_arguments_invalid"), None));
    };
    let provider = setting.provider;
    let profile = provider.profile();
    let direct = matches!(call, WebCall::Fetch(_)) && profile.fetch == FetchRoute::Direct;
    let key_source = keys::key_source(&setting);
    let key = if direct {
        None
    } else {
        match keys::provider_key(server, &setting) {
            Ok(key) => Some(key),
            Err(reason) => return Ok((refused(reason), None)),
        }
    };
    // Our backend key's calls are our cash: each is admitted and settled as a
    // paid connector call (FIX 11604).
    let charge = if key_source == WebKeySource::Backend && key.is_some() {
        match charge::admit(server, line, provider, tool) {
            Ok(permit) => Some(permit),
            Err(reason) => return Ok((refused(reason), None)),
        }
    } else {
        None
    };
    let at_ms = now_ms();
    let started = Instant::now();
    let answer = match (&call, &key) {
        (WebCall::Fetch(input), None) => read_direct(server, input),
        (call, Some(key)) => providers::client().and_then(|client| match call {
            WebCall::Search(input) => providers::search(provider, &client, key.expose(), input),
            WebCall::Fetch(input) => providers::fetch(provider, &client, key.expose(), input),
        }),
        (WebCall::Search(_), None) => Err(ProviderError::message("no provider key")),
    };
    drop(key);
    if let Some(permit) = charge {
        charge::settle(permit, answer.is_ok());
    }
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (reply, usage) = match answer {
        Ok(answer) => {
            let (cost_micro_usd, cost_basis) = priced(
                answer.cost_micro_usd,
                profile.declared_price_micro_usd(tool),
            );
            let usage = WebConnectorUsage {
                at_ms,
                tool,
                provider,
                key: key_source,
                hub_connector: None,
                latency_ms,
                cost_micro_usd,
                cost_basis,
                provider_request_id: answer.request_id.clone(),
                outcome: WebCallOutcome::Ok {
                    results: answer.body.result_count(),
                },
            };
            let output = shaped(provider, answer, latency_ms, cost_micro_usd);
            (delivered(tool, output, false), usage)
        }
        Err(error) => {
            let usage = WebConnectorUsage {
                at_ms,
                tool,
                provider,
                key: key_source,
                hub_connector: None,
                latency_ms,
                cost_micro_usd: None,
                cost_basis: WebCostBasis::Unpriced,
                provider_request_id: None,
                outcome: WebCallOutcome::Failed {
                    reason: error.reason_code(),
                },
            };
            let output = json!({
                "provider": provider.as_str(),
                "error": { "status": error.status, "message": error.message },
                "latency_ms": latency_ms,
            });
            (delivered(tool, output, true), usage)
        }
    };
    record(server, &usage);
    Ok((reply, None))
}

/// One call's parsed arguments.
enum WebCall {
    Search(WebSearchInput),
    Fetch(WebFetchInput),
}

/// The switch names a hub connector: the same tool and arguments go to that
/// connector's own `connector.call`, under its own grant and gate, and its
/// reply answers as it stands. Its usage row takes the reply's `cost_usd` as
/// actual when the reply carries one.
fn forward_to_hub(
    server: &SyncServer,
    memory: &Memory<'_>,
    provider: WebProvider,
    connector: &str,
    tool: WebTool,
    input: ConnectorCallRequest,
) -> MemoryResult<(ConnectorCallReply, Option<Vec<EntityId>>)> {
    let request = ConnectorCallRequest {
        name: connector.to_owned(),
        ..input
    };
    let at_ms = now_ms();
    let started = Instant::now();
    let (reply, rows) = crate::api::connector_call_listing_as(server, memory, request)?;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut cost_micro_usd = None;
    let outcome = match &reply {
        ConnectorCallReply::Delivered {
            result: Some(result),
            ..
        } if !result.is_error => {
            let structured = result.structured_content.as_ref();
            cost_micro_usd = providers::usd_micro(
                structured
                    .and_then(|value| value.get("cost_usd"))
                    .and_then(Value::as_f64),
            );
            let results = structured
                .and_then(|value| value.get("results"))
                .and_then(Value::as_array)
                .map_or(1, Vec::len);
            WebCallOutcome::Ok {
                results: u32::try_from(results).unwrap_or(u32::MAX),
            }
        }
        ConnectorCallReply::Delivered { .. } => WebCallOutcome::Failed {
            reason: "hub_tool_error".to_owned(),
        },
        ConnectorCallReply::Refused { reasons, .. } => WebCallOutcome::Failed {
            reason: reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "hub_call_refused".to_owned()),
        },
        ConnectorCallReply::Held { .. }
        | ConnectorCallReply::PendingDelivery { .. }
        | ConnectorCallReply::AwaitingInput { .. } => WebCallOutcome::Waiting {
            reason: "hub_call_waiting".to_owned(),
        },
    };
    let cost_basis = if cost_micro_usd.is_some() {
        WebCostBasis::Actual
    } else {
        WebCostBasis::Unpriced
    };
    record(
        server,
        &WebConnectorUsage {
            at_ms,
            tool,
            provider,
            key: WebKeySource::Hub,
            hub_connector: Some(connector.to_owned()),
            latency_ms,
            cost_micro_usd,
            cost_basis,
            provider_request_id: None,
            outcome,
        },
    );
    Ok((reply, rows))
}

/// A page read through our own guarded reader (`web_fetch`), for a provider
/// with no page-reading endpoint: no key and no fee.
fn read_direct(
    server: &SyncServer,
    input: &WebFetchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let fetcher = server
        .web_fetcher()
        .map_err(|error| ProviderError::message(&error.to_string()))?;
    let page = fetcher
        .fetch(&input.url, now_ms() / 1_000)
        .map_err(|error| ProviderError::message(&error.to_string()))?;
    let url = match page.canonical_url() {
        "" => input.url.clone(),
        canonical => canonical.to_owned(),
    };
    let title = Some(page.title().to_owned()).filter(|title| !title.trim().is_empty());
    Ok(ProviderAnswer {
        body: ProviderBody::Page {
            url,
            title,
            content: page.markdown().to_owned(),
        },
        cost_micro_usd: Some(0),
        request_id: None,
    })
}

/// The cost a row records and its basis: the provider-reported cost, else the
/// declared price as an estimate, else unpriced (Engine call on FIX 8689).
fn priced(reported: Option<u64>, declared: Option<u64>) -> (Option<u64>, WebCostBasis) {
    match (reported, declared) {
        (Some(cost), _) => (Some(cost), WebCostBasis::Actual),
        (None, Some(cost)) => (Some(cost), WebCostBasis::Estimated),
        (None, None) => (None, WebCostBasis::Unpriced),
    }
}

/// The answer in Afterglow's `search_web` shape, or a fetched page's.
fn shaped(
    provider: WebProvider,
    answer: ProviderAnswer,
    latency_ms: u64,
    cost_micro_usd: Option<u64>,
) -> Value {
    let provider = provider.as_str().to_owned();
    let cost_usd = cost_micro_usd.map(micro_usd_to_usd);
    let output = match answer.body {
        ProviderBody::Hits(results) => serde_json::to_value(WebSearchOutput {
            provider,
            results,
            latency_ms,
            cost_usd,
        }),
        ProviderBody::Page {
            url,
            title,
            content,
        } => serde_json::to_value(WebFetchOutput {
            provider,
            url,
            title,
            content: cut_chars(&content, FETCH_CONTENT_MAX_CHARS),
            latency_ms,
            cost_usd,
        }),
    };
    output.unwrap_or(Value::Null)
}

/// A delivered reply carrying `output` as foreign data: the MCP text block and
/// the same JSON as its structured content.
fn delivered(tool: WebTool, output: Value, is_error: bool) -> ConnectorCallReply {
    let text = output.to_string();
    ConnectorCallReply::project(
        WEB_CONNECTOR_NAME,
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
        },
    )
}

fn refused(reason: &str) -> ConnectorCallReply {
    ConnectorCallReply::Refused {
        decision_ref: None,
        reasons: vec![reason.to_owned()],
    }
}

/// Writes one usage row. A failed write is logged, never the caller's: the
/// call already ran.
fn record(server: &SyncServer, usage: &WebConnectorUsage) {
    if let Err(error) = server.vault().record_web_connector_usage(usage) {
        tracing::warn!(%error, provider = usage.provider.as_str(), "web connector usage row not written");
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
