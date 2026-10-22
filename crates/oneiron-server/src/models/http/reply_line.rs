//! The media-reply line (FIX 8615, FIX 9321): the bytes the media replies
//! providers send this server (an image, a clip, speech) hold in memory at
//! once, `limits.media_reply_bytes`. A reply is read whole, however large:
//! no size refuses it. Its first room is taken in arrival order, waiting its
//! turn while the line is full, and the row asks past it; what the reply
//! grows past that room is charged as it arrives, never waited for, so no
//! call waits for bytes while it holds some. The buffer grows by fallible
//! allocation, and only a real allocation failure ends the read, as
//! [`HttpFailure::OutOfMemory`].
//!
//! The line is the vault's own ([`ModelHostBudgets`]): a media call reads on
//! the line of the runtime that runs it, and holds its replies' bytes until
//! its answer leaves the adapter ([`holding_replies`]): across the encoded
//! reply and its decode. A read no media call scopes (a health probe) keeps
//! its bytes on the reply it returns, on a line of the row's default of its
//! own: no process-wide line paces it. These lines book the encoded bytes a
//! reply holds: a decode's copies and a parsed JSON tree are the call's, and
//! not booked here.

use std::cell::RefCell;
use std::future::Future;
use std::time::Duration;

use crate::byte_line::HeldBytes;

use super::super::host_budgets::{MediaReplyLine, ModelHostBudgets};
use super::HttpFailure;

/// The room a reply that declares no length takes before its first byte;
/// past it, it is charged as it grows.
const FIRST_ROOM: usize = 64 * 1024;

/// The media call a task runs: the budgets of the runtime it runs on, and
/// the bytes of every reply read for it.
struct MediaCall {
    budgets: ModelHostBudgets,
    held: RefCell<Vec<HeldBytes>>,
}

tokio::task_local! {
    static CALL: MediaCall;
}

/// The budgets of the media call this task runs; for a read no call
/// scopes, budgets of its own at the rows' defaults, their crossings logged
/// and not kept.
fn call_budgets() -> ModelHostBudgets {
    CALL.try_with(|call| call.budgets.clone())
        .unwrap_or_else(|_| ModelHostBudgets::unhosted())
}

/// Runs `call`, one media rung's call on the runtime whose budgets are
/// `budgets`, holding the bytes of every reply read for it on that runtime's
/// line until it ends: until its decoded answer leaves the adapter.
pub(in crate::models) async fn holding_replies<F: Future>(
    budgets: &ModelHostBudgets,
    call: F,
) -> F::Output {
    let scope = MediaCall {
        budgets: budgets.clone(),
        held: RefCell::new(Vec::new()),
    };
    CALL.scope(scope, call).await
}

/// The bytes one reply's body holds on its line, while the reply that
/// carries them lives: none once the media call it was read for holds them.
#[derive(Default)]
pub(in crate::models) struct ReplyBytes {
    _held: Option<HeldBytes>,
}

/// Reads `response`'s body whole on the media-reply line of the call that
/// reads it.
pub(in crate::models) async fn read_booked(
    mut response: reqwest::Response,
) -> Result<(Vec<u8>, ReplyBytes), HttpFailure> {
    let budgets = call_budgets();
    let MediaReplyLine { line, questions } = budgets.media_line();
    let first = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(FIRST_ROOM);
    // Only a call that holds nothing yet waits its turn: one that holds a
    // reply already is charged, so no wait closes a cycle.
    let waits = CALL
        .try_with(|call| call.held.borrow().is_empty())
        .unwrap_or(true);
    let mut held = if waits {
        line.reserve_alone(first, Duration::MAX, questions).await
    } else {
        None
    }
    .unwrap_or_else(|| {
        let mut held = line.empty();
        line.charge(&mut held, first, questions);
        held
    });
    let mut body = Vec::new();
    body.try_reserve_exact(first)
        .map_err(|_| out_of_memory(first))?;
    line.charge(&mut held, body.capacity(), questions);
    while let Some(chunk) = response.chunk().await? {
        if body.capacity() - body.len() < chunk.len() {
            body.try_reserve(chunk.len())
                .map_err(|_| out_of_memory(body.len()))?;
            line.charge(&mut held, body.capacity(), questions);
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, keep(held)))
}

/// Reads `response`'s body whole, however large (FIX 9321): on the media
/// call's line when one reads it, else grown by fallible allocation as its
/// bytes arrive, on no line. No size refuses it; only a real allocation
/// failure ends the read, as [`HttpFailure::OutOfMemory`].
pub(in crate::models) async fn read_whole(
    mut response: reqwest::Response,
) -> Result<(Vec<u8>, ReplyBytes), HttpFailure> {
    if CALL.try_with(|_| ()).is_ok() {
        return read_booked(response).await;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.try_reserve(chunk.len())
            .map_err(|_| out_of_memory(body.len()))?;
        body.extend_from_slice(&chunk);
    }
    Ok((body, ReplyBytes::default()))
}

/// Charges `bytes` a reply already holds, read whole by another transport
/// (the credential broker's), on the line of the call that reads it: kept
/// as a read reply's are.
pub(in crate::models) fn charge_read(bytes: usize) -> ReplyBytes {
    let budgets = call_budgets();
    let MediaReplyLine { line, questions } = budgets.media_line();
    let mut held = line.empty();
    line.charge(&mut held, bytes, questions);
    keep(held)
}

/// A reply this machine could not allocate room for past `held` bytes: the
/// call's public error is coarse (a retryable server error), so its local
/// cause is kept in the host's record here, never read as the provider's
/// status (FIX 9321).
fn out_of_memory(held: usize) -> HttpFailure {
    tracing::warn!(
        held,
        "this machine could not allocate a provider reply's next bytes; the call fails locally"
    );
    HttpFailure::OutOfMemory
}

/// Hands `held` to the media call this task runs, if one does; else the
/// reply keeps it.
fn keep(held: HeldBytes) -> ReplyBytes {
    let mut held = Some(held);
    let _ = CALL.try_with(|call| {
        if let Some(held) = held.take() {
            call.held.borrow_mut().push(held);
        }
    });
    ReplyBytes { _held: held }
}
