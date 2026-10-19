//! What a gateway result may carry off this device once its call has
//! nothing left to wait on (DEC-0005): a retained page, a fresh result and a
//! queued carrier frame, each judged by the rows it was derived from, for
//! the machine the call's connection proved (mesh PR2b). A refusal names
//! its content-free reason: the owner's recipient choice, or an integrity
//! hold, never a hidden world.

use super::{McpCallContext, McpGatewayError, mcp_engine_error, mcp_page_cursor_error};
use crate::server::SyncServer;
use oneiron::settings::ReleaseHold;
use serde_json::Value;
use std::sync::Arc;

/// Whether a page its producer retained may leave again: none of the rows
/// it was derived from, nor any row its output or keyframe names, is one a
/// device-local world keeps from the caller now.
pub(super) fn mcp_snapshot_releases(
    server: &SyncServer,
    actor: &McpCallContext,
    snapshot: &crate::mcp::McpPageSnapshot,
) -> Result<bool, McpGatewayError> {
    let retained = serde_json::to_vec(&(&snapshot.output, &snapshot.keyframe))
        .map_err(|_| mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch))?;
    crate::device_local::withholds_retained(
        &server.vault,
        actor.destination(),
        &snapshot.rows,
        &retained,
    )
    .map(|withheld| !withheld)
    .map_err(|error| mcp_engine_error("mcp page snapshot release check failed", error))
}

/// Whether a carrier frame may leave for `actor`: none of the rows it was
/// derived from, the TASKs its delta rows are keyed by and `rider_rows`, nor
/// any row it names, is one a device-local world keeps from the caller now.
pub(super) fn mcp_carrier_releases(
    server: &SyncServer,
    actor: &McpCallContext,
    frame: &oneiron::context_board::BoardStreamFrame,
    rider_rows: &[oneiron::EntityId],
) -> bool {
    let mut rows = rider_rows.to_vec();
    if let oneiron::context_board::FrameKind::Delta(delta) = &frame.kind {
        rows.extend(
            delta
                .iter()
                .filter_map(|row| row.key.strip_prefix("tasks:"))
                .filter_map(|task| oneiron::EntityId::from_hex(task).ok()),
        );
    }
    let destination = actor.destination();
    serde_json::to_vec(frame).is_ok_and(|bytes| {
        let withheld =
            crate::device_local::withholds_retained(&server.vault, destination, &rows, &bytes);
        matches!(withheld, Ok(false))
    })
}

/// Every result, fresh or a continuation of one its producer retained, is
/// judged again once its call has nothing left to wait on (DEC-0005), by
/// `rows`, those its producer listed, and every row it names: a whole id, or
/// a short ref standing as a whole string, whichever door produced it. One
/// derived from a row a device-local world keeps now, or naming one, or
/// naming a short ref that resolves to no row, is refused: a continuation's
/// caller starts over from page one, and a fresh call is told its result
/// changed and to call again.
pub(super) fn mcp_release_result(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    rows: &[oneiron::EntityId],
    continued: bool,
    result: Value,
) -> Result<Value, McpGatewayError> {
    let refused = |hold: ReleaseHold| {
        if continued {
            mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
        } else {
            mcp_result_withheld(hold)
        }
    };
    let destination = actor.destination();
    if !destination.is_off_device() {
        return Ok(result);
    }
    let Some(mut named) = crate::device_local::short_refs_named(&server.vault, &result) else {
        return Err(refused(ReleaseHold::Placement));
    };
    named.extend_from_slice(rows);
    let bytes = serde_json::to_vec(&result).map_err(|_| refused(ReleaseHold::Placement))?;
    if let Some(hold) =
        crate::device_local::retained_hold(&server.vault, &destination, &named, &bytes)
            .map_err(|error| mcp_engine_error("mcp page release check failed", error))?
    {
        return Err(refused(hold));
    }
    Ok(result)
}

/// A refusal is released as a result is (DEC-0005): by `rows`, those its
/// call served before it failed, and every row its words and its effective
/// scope name, a whole id or a short ref among them. Off this device one
/// naming a row a device-local world keeps now, or a short ref that resolves
/// to no row, or whose call's rows are unknown (`None`), leaves as its code
/// alone, with no scope.
pub(super) fn mcp_release_error(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[oneiron::EntityId]>,
    error: McpGatewayError,
) -> McpGatewayError {
    let destination = actor.destination();
    if !destination.is_off_device() {
        return error;
    }
    let words = serde_json::to_string(&(
        &error.message,
        &error.field,
        &error.successor_short_id,
        &error.vault_read,
        &error.effective_scope,
    ))
    .ok();
    let hold = match (rows, words) {
        (None, _) => Some(ReleaseHold::ProducersUnknown),
        (Some(_), None) => Some(ReleaseHold::Placement),
        (Some(rows), Some(words)) => {
            match crate::device_local::short_refs_in_text(&server.vault, &words) {
                None => Some(ReleaseHold::Placement),
                Some(mut named) => {
                    named.extend_from_slice(rows);
                    let bytes = words.as_bytes();
                    crate::device_local::retained_hold(&server.vault, &destination, &named, bytes)
                        .unwrap_or(Some(ReleaseHold::Placement))
                }
            }
        }
    };
    let Some(hold) = hold else {
        return error;
    };
    McpGatewayError::new(
        error.code,
        error.kind,
        format!(
            "the call failed; its detail stays on this device: {}",
            hold.reason()
        ),
    )
}

/// The rows a code run's verb answers name by short ref inside the JSON
/// each was recorded as, fresh or replayed; `None` when one names no row.
/// The rest of its result is read at [`mcp_release_result`].
pub(super) fn mcp_run_named_rows(
    vault: &oneiron::Vault,
    structured: &Value,
) -> Option<Vec<oneiron::EntityId>> {
    let mut rows = Vec::new();
    let outputs = structured["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|step| step["outcome"]["output"].as_str());
    for output in outputs {
        if let Ok(output) = serde_json::from_str::<Value>(output) {
            rows.extend(crate::device_local::short_refs_named(vault, &output)?);
        }
    }
    Some(rows)
}

/// [`mcp_release_result`] for a code run's result: judged by `rows`, those
/// its verb answers listed and its step log names. Off this device a run
/// with an answer recorded with no row set, or whose steps name a short ref
/// that resolves to no row (`None`), is refused.
pub(super) fn mcp_release_run_result(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    rows: Option<&[oneiron::EntityId]>,
    result: Value,
) -> Result<Value, McpGatewayError> {
    match rows {
        Some(rows) => mcp_release_result(server, actor, rows, false, result),
        None if !actor.destination().is_off_device() => Ok(result),
        None => Err(mcp_result_withheld(ReleaseHold::ProducersUnknown)),
    }
}

/// A fresh result refused at release: the caller calls again. The message
/// names the hold, content-free: the owner's world recipient limit for this
/// destination, or the integrity hold, never the owner's choice for one
/// (mesh PR2-reasons).
fn mcp_result_withheld(hold: ReleaseHold) -> McpGatewayError {
    let message = if hold.is_owner_choice() {
        format!(
            "the owner's world recipient limit withholds this result from this destination \
             ({}); call again after the destination or the policy is verified",
            hold.reason()
        )
    } else {
        format!(
            "the result changed before it was released ({}); call again",
            hold.reason()
        )
    };
    McpGatewayError::new(-32603, "mcp_result_changed", message)
}

/// A device-only flag committed while a call waits, after its checks ran
/// and before its result is released: past a continuation's cursor check,
/// or on a carrier's rider.
#[cfg(test)]
pub(crate) mod release_hook {
    use std::cell::Cell;

    thread_local! {
        // Per thread: the call resumes on the test's own current-thread
        // runtime.
        static FLAG: Cell<Option<oneiron::EntityId>> = const { Cell::new(None) };
    }

    pub(crate) fn arm(world: oneiron::EntityId) {
        FLAG.set(Some(world));
    }

    pub(in crate::api::mcp_gateway) fn run(server: &crate::server::SyncServer) {
        if let Some(world) = FLAG.take() {
            server
                .vault
                .keep_world_on_this_machine_under_for_test(
                    &crate::test_credentials::host_issuer(server),
                    world,
                    true,
                )
                .expect("device-only flag");
        }
    }
}
