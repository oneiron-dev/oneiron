//! What a claimed MCP `tools/call` keeps of its answer for the calls waiting on it, and how each
//! waiter's reply is released again from it (FIX 7914, with FIX 8212's facade claim).
//! `capturing`, `record`, `kept` and `replayed` are its call surface.
//! `oneiron::runtime_hooks::verb::InvocationRelease` is the record the shared claim keeps.

use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::runtime_hooks::verb::{InvocationOutcome, InvocationRelease};
use serde_json::{Value, json};

use super::{McpCallContext, mcp_text_content};
use crate::server::SyncServer;

/// A result as a release was about to judge it, beside the rows it judged by.
type Judged = (Value, Option<Vec<EntityId>>);

tokio::task_local! {
    /// The last result a release judged while a claimed call ran.
    static JUDGED: RefCell<Option<Judged>>;
}

/// Runs `call`, a claimed `tools/call`, beside the last result a release
/// judged in it ([`record`]): the answer before its destination release, and
/// its rows. Nothing is kept for a call no claim holds.
pub(super) async fn capturing<T>(call: impl Future<Output = T>) -> (T, Option<Judged>) {
    JUDGED
        .scope(RefCell::new(None), async move {
            let output = call.await;
            let judged = JUDGED.with(|judged| judged.borrow_mut().take());
            (output, judged)
        })
        .await
}

/// Keeps `result`, which a release is about to judge by `rows`, as the last
/// result judged in the claimed call this runs in; outside one it does
/// nothing.
pub(super) fn record(result: &Value, rows: Option<&[EntityId]>) {
    let _ = JUDGED.try_with(|judged| {
        *judged.borrow_mut() = Some((result.clone(), rows.map(<[EntityId]>::to_vec)));
    });
}

/// What the claim keeps beside `saved`, the reply that went out without its
/// id: the last result judged, with its rows and the first caller's machine
/// `peer`, when it is the result that went out, or when the reply withheld it
/// (`mcp_result_changed`, FIX 10498) so an admitted waiter gets its own
/// projection. Any other reply, a refusal among them, keeps nothing beside it
/// and is sent again as it was.
pub(super) fn kept(
    peer: PeerMachine,
    saved: &Value,
    judged: Option<Judged>,
) -> Option<InvocationRelease> {
    let (value, rows) = judged?;
    if saved.get("result") == Some(&value) {
        return Some(InvocationRelease { peer, value, rows });
    }
    // FIX 10498: a first caller whose result was withheld leaves its refusal
    // for no waiter; the final release's pre-release value is kept too, so a
    // waiter toward another machine is judged for its own destination. Only a
    // result with known rows is kept, so the waiter's copy is released again.
    let withheld = saved
        .get("error")
        .and_then(|error| error.get("data"))
        .and_then(|data| data.get("kind"))
        .and_then(Value::as_str)
        == Some("mcp_result_changed");
    (withheld && rows.is_some()).then_some(InvocationRelease { peer, value, rows })
}

/// The reply a waiter `actor` gets from the first call's `outcome` (FIX
/// 7914), without its id: the kept result released again for this waiter's
/// credential and destination, as a fresh result of the call would be
/// released, and never run again. A listed row its credential no longer
/// reads or that was erased since, or a result the release would hold, gives
/// the content-free word that the call ran; a waiter toward another machine
/// is answered for its own, never refused for the difference. A refusal kept
/// with nothing beside it has its words released again for this waiter
/// (FIX 10497); a result whose rows are unknown, and any other such reply,
/// go as they were.
pub(super) fn replayed(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    outcome: InvocationOutcome,
) -> Value {
    let mut reply = outcome.body;
    let Some(release) = outcome.release else {
        return super::device_release::mcp_rerelease_refusal(server, actor, reply);
    };
    let peer = actor.auth.as_ref().map(crate::auth::CoreAuth::peer);
    if peer != Some(release.peer) {
        tracing::debug!("mcp invocation answer reprojected for the waiter's machine");
    }
    let result = match release.rows.as_deref() {
        None => release.value,
        Some(rows)
            if actor.auth.as_ref().is_some_and(|auth| {
                !crate::api::facade::rows_still_admitted(server.vault(), auth, rows)
            }) =>
        {
            details_on_device_result()
        }
        Some(rows) => {
            super::device_release::mcp_release_result(server, actor, rows, false, release.value)
                .unwrap_or_else(|_| details_on_device_result())
        }
    };
    if let Some(reply) = reply.as_object_mut() {
        // FIX 10498: a waiter whose projection is kept from a withheld reply
        // gets its own result, never the first caller's refusal.
        reply.remove("error");
        reply.insert("result".to_owned(), result);
    }
    reply
}

/// The tool result that says only that the call ran and its details stay
/// on this device: `{"details_on_device": true}` as its structured content
/// and its text.
fn details_on_device_result() -> Value {
    let ran = crate::api::facade::details_on_device();
    json!({
        "content": [mcp_text_content(ran.to_string())],
        "structuredContent": ran,
    })
}
