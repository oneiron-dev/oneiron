//! The media-reply line (FIX 8615): the bytes the media replies providers
//! send this server (an image, a clip, speech) hold in memory at once,
//! `limits.media_reply_bytes`. A reply is read whole, however large: no
//! size refuses it. Its first room is taken in arrival order, waiting its
//! turn while the line is full, and the row asks past it; what the reply
//! grows past that room is charged as it arrives, never waited for, so no
//! call waits for bytes while it holds some. The buffer grows by fallible
//! allocation, and only a real allocation failure ends the read, as
//! [`HttpFailure::OutOfMemory`].
//!
//! A media rung's call holds its replies' bytes until its answer leaves the
//! adapter ([`holding_replies`]): across the encoded reply and its decode.
//! A read outside such a call keeps its bytes on the reply it returns.

use std::cell::RefCell;
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::byte_line::{ByteLine, HeldBytes};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

use super::HttpFailure;

/// The room a reply that declares no length takes before its first byte;
/// past it, it is charged as it grows.
const FIRST_ROOM: usize = 64 * 1024;

/// This process's line and where its row asks.
struct ReplyLine {
    line: ByteLine,
    questions: Arc<LimitQuestions>,
}

static LINE: OnceLock<ReplyLine> = OnceLock::new();

tokio::task_local! {
    /// The bytes of every reply read for the media call this task runs.
    static HELD: RefCell<Vec<HeldBytes>>;
}

/// Installs this process's media-reply line of `bytes`, its row asking on
/// `questions`. The first install holds. A host that installs none reads on
/// a line of the row's default, whose crossings are logged and not kept.
pub(crate) fn install_media_reply_line(bytes: u64, questions: Arc<LimitQuestions>) {
    let _ = LINE.set(ReplyLine {
        line: ByteLine::new(
            LimitRow::MediaReplyBytes,
            usize::try_from(bytes).unwrap_or(usize::MAX),
        ),
        questions,
    });
}

fn line() -> &'static ReplyLine {
    LINE.get_or_init(|| ReplyLine {
        line: ByteLine::new(
            LimitRow::MediaReplyBytes,
            usize::try_from(crate::config::LimitsConfig::default().media_reply_bytes)
                .unwrap_or(usize::MAX),
        ),
        questions: Arc::default(),
    })
}

/// Runs `call`, one media rung's call, holding the bytes of every reply read
/// for it until it ends: until its decoded answer leaves the adapter.
pub(in crate::models) async fn holding_replies<F: Future>(call: F) -> F::Output {
    HELD.scope(RefCell::new(Vec::new()), call).await
}

/// The bytes one reply's body holds on the line, while the reply that
/// carries them lives: none once the media call it was read for holds them.
#[derive(Default)]
pub(in crate::models) struct ReplyBytes {
    _held: Option<HeldBytes>,
}

/// Reads `response`'s body whole on the media-reply line.
pub(in crate::models) async fn read_booked(
    mut response: reqwest::Response,
) -> Result<(Vec<u8>, ReplyBytes), HttpFailure> {
    let ReplyLine { line, questions } = line();
    let first = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(FIRST_ROOM);
    // Only a call that holds nothing yet waits its turn: one that holds a
    // reply already is charged, so no wait closes a cycle.
    let waits = HELD
        .try_with(|held| held.borrow().is_empty())
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
        .map_err(|_| HttpFailure::OutOfMemory)?;
    line.charge(&mut held, body.capacity(), questions);
    while let Some(chunk) = response.chunk().await? {
        if body.capacity() - body.len() < chunk.len() {
            body.try_reserve(chunk.len())
                .map_err(|_| HttpFailure::OutOfMemory)?;
            line.charge(&mut held, body.capacity(), questions);
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, keep(held)))
}

/// Charges `bytes` a reply already holds, read whole by another transport
/// (the credential broker's): kept as a read reply's are.
pub(in crate::models) fn charge_read(bytes: usize) -> ReplyBytes {
    let ReplyLine { line, questions } = line();
    let mut held = line.empty();
    line.charge(&mut held, bytes, questions);
    keep(held)
}

/// Hands `held` to the media call this task runs, if one does; else the
/// reply keeps it.
fn keep(held: HeldBytes) -> ReplyBytes {
    let mut held = Some(held);
    let _ = HELD.try_with(|kept| {
        if let Some(held) = held.take() {
            kept.borrow_mut().push(held);
        }
    });
    ReplyBytes { _held: held }
}
