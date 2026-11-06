//! The MCP `read_result` door: one read of a result of a durable run under
//! the caller's credential. A read of a step's stored diagnostics body shows
//! a view of that step's type feedback (FIX 10614). After the call's last
//! wait, that view is judged with the step's feedback, as one feedback item
//! is judged. A hold withholds only the feedback's text: the read's `output`
//! becomes the step's withheld feedback, built from its durable row. The
//! whole answer is then released as every answer is, so every other hold
//! still withholds it whole.

use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, mcp_actor_result, mcp_endpoint_result,
};
use crate::api::type_feedback_release::stored_feedback_hold;
use crate::mcp::{McpPageBudget, McpRetrievalHealth};
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::code_run::{ProgramStepFeedback, ProgramStepFeedbackRelease};
use serde_json::{Value, json};
use std::sync::Arc;

/// One read of a result of the durable run `run_ref` names under this
/// credential: its card, or a slice, search, query or chunks page of it. No
/// model is called and no run is entered. The run id is the credential's own
/// derivation, never an id or digest a caller sends, and only that run's
/// results resolve. The read is checked against the rows the run's answers
/// were served from and the result's taint, as inside the run, and the
/// answer is released as `execute_code`'s is, under its live credential. A
/// view of a step's stored diagnostics leaves as that step's feedback does
/// (FIX 10614, `release_stored_feedback`).
pub(crate) async fn execute_mcp_read_result(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpReadResultToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    let run_id = crate::mcp::mcp_code_run_id(&args.run_ref, actor);
    let facet = args.facet.and_then(crate::mcp::McpResultFacet::facet);
    let destination = actor.destination();
    let vault = Arc::clone(&server.vault);
    let reference = args.reference.clone();
    let input = Value::Object(args.input.clone().unwrap_or_default());
    // A search or a table query scans up to its bound from disk, so it runs
    // off the gateway's reactor.
    let (reply, feedback, served) = tokio::task::spawn_blocking(move || {
        let mut served = None;
        let read =
            vault.read_code_run_result_with_feedback(run_id, &reference, facet, input, |rows| {
                served = Some(rows.map(<[EntityId]>::to_vec));
                if !destination.is_off_device() {
                    return Ok(false);
                }
                rows.map_or(Ok(true), |rows| {
                    crate::device_local::withholds_retained(&vault, &destination, rows, &[])
                })
            });
        read.map(|(reply, feedback)| (reply, feedback, served))
    })
    .await
    .map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "read_result worker ended without a result",
        )
    })?
    .map_err(|error| super::mcp_engine_error("read_result failed", error))?;
    let health = if reply.get("denied").is_some() {
        McpRetrievalHealth::Degraded
    } else if reply["output"]["done"] == json!(false) {
        McpRetrievalHealth::Partial
    } else {
        McpRetrievalHealth::Healthy
    };
    let help = vec![
        "pass a reply's next back as input.cursor (search, query, chunks) or as the selection (slice) to read on".to_owned(),
        "a chunk's ref is a range ref read_result takes as ref".to_owned(),
    ];
    let structured = json!({
        "tool": crate::mcp::MCP_READ_RESULT_TOOL,
        "schema_version": crate::mcp::MCP_CODE_RUN_SCHEMA_VERSION,
        "run_ref": args.run_ref,
        "run_id": run_id.to_hex(),
        "ref": args.reference,
        "facet": facet.map_or("describe", oneiron::code_run::ResultFacet::as_str),
        "result": reply,
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            health,
            McpPageBudget::resolve(None, crate::mcp::McpPageSource::complete(1)),
            help,
            None,
        ),
    });
    let result = mcp_endpoint_result(
        server,
        actor,
        "read_result answered",
        structured,
        McpCarrierPolicy::Drain,
    )
    .await;
    super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
    // An unknown ref resolved nothing, so no rows were read.
    let rows = served.unwrap_or_else(|| Some(Vec::new()));
    // Nothing waits between the feedback's judgment and the answer's
    // release, and the release keeps the projected answer for a claim's
    // waiters.
    let result = release_stored_feedback(server, actor, rows.as_deref(), feedback, result);
    super::device_release::mcp_release_run_result(server, actor, rows.as_deref(), result)
}

/// A `read_result` answer as it goes to its whole release when the read
/// showed a view of a step's stored diagnostics body (FIX 10614): as it
/// stands while that view, judged with the step's `feedback` for `actor`'s
/// destination by `rows`, may leave. Else the view's `output` is the step's
/// withheld feedback, and the answer's text copy states it again. Nothing
/// else in the answer changes.
fn release_stored_feedback(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[EntityId]>,
    feedback: Option<ProgramStepFeedback>,
    mut result: Value,
) -> Value {
    let Some(feedback) = feedback else {
        return result;
    };
    let Some(view) = result.pointer("/structuredContent/result") else {
        return result;
    };
    let destination = actor.destination();
    let Some(reason) = stored_feedback_hold(&server.vault, &destination, rows, &feedback, view)
    else {
        return result;
    };
    let withheld = ProgramStepFeedbackRelease::withheld(&feedback, reason);
    if let Some(slot) = result.pointer_mut("/structuredContent/result/output") {
        *slot = serde_json::to_value(&withheld).unwrap_or(Value::Null);
    }
    super::type_feedback_release::sync_content(&mut result);
    result
}
