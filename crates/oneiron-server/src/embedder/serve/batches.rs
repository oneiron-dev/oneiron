//! A request's work, batch by batch (FIX 9487).
//!
//! An authenticated request may carry any number of inputs. The model
//! embeds them [`MAX_INPUTS`] at a time, in order, each batch under its own
//! turn and its own room in the `embedder_answer_bytes` row, taken before the
//! batch runs and given back once its rows are handed to the transport; the
//! request keeps its cursor between batches, so a request larger than the
//! answer row never waits for room it would have to hold all at once, and
//! the turn passes to other requests between its batches. Every row keeps
//! its index in the whole request, the token usage is summed, and the
//! answer names the model, transform, profile and device once.
//!
//! A request of one batch is answered as before: whole, with its length.
//! A larger one streams its rows as each batch is made, after the first
//! batch has succeeded. A batch that fails after that ends the stream
//! broken, never closed as a shorter list: no partial answer reads as a
//! complete one. A request that asks for it (`error_member`, which the
//! vault's endpoint client sends) gets a readable end instead: the list
//! closes and an `error` member, where the answer's tail would be, names
//! why it is not complete (FIX 10702). Nothing here adds a size limit or a
//! deadline: the admission wait applies to the first batch alone, before
//! anything is started, and a later batch waits for its room and its turn
//! for as long as it takes, unless the client goes away, which ends those
//! waits at once (FIX 10756), or stops reading for the idle limit.

use std::future::Future;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use serde::Serialize;

use super::budget::{Fixed, answer_bytes, encoding_bytes};
use super::{ANSWER_PIECE, EmbeddingRow, Encoded, MAX_INPUTS, Served, Usage, refuse, waited_out};
use crate::admission::Permit;
use crate::byte_line::HeldBytes;
use crate::embedder::local::{Priority, Side};

/// One authenticated request's whole work: its texts, which the cursor walks,
/// and how they are embedded and encoded.
pub(super) struct EmbeddingRequestWork {
    pub(super) texts: Vec<String>,
    pub(super) side: Side,
    pub(super) instruction: Option<String>,
    pub(super) priority: Priority,
    pub(super) base64: bool,
    /// The name the request gave its model.
    pub(super) model: String,
    /// The client reads an `error` member that ends an answer a later batch
    /// could not complete ([`error_terminal`]).
    pub(super) error_member: bool,
}

/// What the transport takes of an answer: its pieces, or the error that
/// breaks it off.
type Piece = Result<axum::body::Bytes, std::io::Error>;

/// The fields an answer carries after its rows.
#[derive(Serialize)]
struct Tail<'a> {
    model: &'a str,
    usage: Usage,
    model_id: &'a str,
    transform: &'a str,
    profile: &'a super::RunProfile,
    provenance: oneiron::embed::EmbeddingProvenance,
}

/// One batch's rows, encoded as the comma-joined row objects of the answer's
/// `data` list, the tokens it used, and the room it holds until its bytes
/// are handed on.
struct EncodedBatch {
    rows: Vec<u8>,
    tokens: usize,
    _room: HeldBytes,
}

/// Why a batch did not come back.
enum BatchFailure {
    /// The first batch's wait for its turn or its room reached the queue
    /// deadline: nothing was started.
    WaitedOut,
    /// The client went away while a later batch waited for its room or its
    /// turn: nobody reads the rest.
    ClientGone,
    /// The model could not embed it.
    Embedding,
    /// Its rows could not be encoded.
    Encoding,
}

/// The texts of the batch starting at `start`.
fn batch_range(work: &EmbeddingRequestWork, start: usize) -> Range<usize> {
    start..work.texts.len().min(start.saturating_add(MAX_INPUTS))
}

/// `wait`'s outcome, or `None` once `transport` closes first: a client that
/// went away frees what its later batch waits for (FIX 10756). The first
/// batch, which runs before any byte goes out, passes no transport, and its
/// wait runs as it is.
async fn unless_gone<T>(
    transport: Option<&tokio::sync::mpsc::Sender<Piece>>,
    wait: impl Future<Output = T>,
) -> Option<T> {
    let Some(transport) = transport else {
        return Some(wait.await);
    };
    tokio::select! {
        done = wait => Some(done),
        () = transport.closed() => None,
    }
}

/// Embeds the batch starting at `start` under a turn and room of its own.
/// The first batch waits for each up to the queue deadline; a later one, of
/// a request already admitted and answering, waits its turn until it comes
/// or `transport` closes.
async fn embed_request_batches(
    served: &Arc<Served>,
    work: &Arc<EmbeddingRequestWork>,
    start: usize,
    transport: Option<&tokio::sync::mpsc::Sender<Piece>>,
) -> Result<EncodedBatch, BatchFailure> {
    let range = batch_range(work, start);
    let dimensions = served.embedder.dimensions();
    let first = start == 0;
    let bytes = answer_bytes(range.len(), dimensions);
    let room = loop {
        let reserved = served
            .answers
            .reserve_alone(bytes, served.wait, &served.questions);
        match unless_gone(transport, reserved).await {
            None => return Err(BatchFailure::ClientGone),
            Some(Some(room)) => break room,
            Some(None) if first => return Err(BatchFailure::WaitedOut),
            Some(None) => {}
        }
    };
    let turns = match work.priority {
        Priority::Query => &served.queries,
        Priority::Bulk => &served.bulk,
    };
    let turn = if first {
        match tokio::time::timeout(served.wait, Arc::clone(turns).acquire_owned()).await {
            Ok(Ok(turn)) => turn,
            _ => return Err(BatchFailure::WaitedOut),
        }
    } else {
        match unless_gone(transport, Arc::clone(turns).acquire_owned()).await {
            None => return Err(BatchFailure::ClientGone),
            Some(turn) => turn.map_err(|_| BatchFailure::Embedding)?,
        }
    };
    let embedder = Arc::clone(&served.embedder);
    let task = Arc::clone(work);
    let embedded = tokio::task::spawn_blocking(move || {
        let _turn = turn;
        embedder.embed_raw(
            &task.texts[batch_range(&task, start)],
            task.side,
            task.instruction.as_deref(),
            task.priority,
        )
    })
    .await;
    let embedded = match embedded {
        Ok(Ok(embedded)) => embedded,
        Ok(Err(error)) => {
            tracing::warn!(kind = ?error.kind(), "endpoint embedding failed");
            return Err(BatchFailure::Embedding);
        }
        Err(error) => {
            tracing::warn!(
                panicked = error.is_panic(),
                "endpoint embedding task failed"
            );
            return Err(BatchFailure::Embedding);
        }
    };
    if embedded.rows.len() != range.len() {
        return Err(BatchFailure::Embedding);
    }
    let mut rows = Fixed(Vec::with_capacity(encoding_bytes(range.len(), dimensions)));
    for (offset, row) in embedded.rows.into_iter().enumerate() {
        if start + offset > 0 && std::io::Write::write_all(&mut rows, b",").is_err() {
            return Err(BatchFailure::Encoding);
        }
        let row = EmbeddingRow {
            object: "embedding",
            index: start + offset,
            embedding: if work.base64 {
                let bytes: Vec<u8> = row.iter().flat_map(|value| value.to_le_bytes()).collect();
                Encoded::Base64(base64::engine::general_purpose::STANDARD.encode(bytes))
            } else {
                Encoded::Float(row)
            },
        };
        if serde_json::to_writer(&mut rows, &row).is_err() {
            return Err(BatchFailure::Encoding);
        }
    }
    Ok(EncodedBatch {
        rows: rows.0,
        tokens: embedded.tokens,
        _room: room,
    })
}

/// The answer's opening and closing bytes around its rows.
fn head_and_tail(
    served: &Served,
    work: &EmbeddingRequestWork,
    tokens: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let tail = serde_json::to_vec(&Tail {
        model: &work.model,
        usage: Usage {
            prompt_tokens: tokens,
            total_tokens: tokens,
        },
        model_id: served.embedder.model_id(),
        transform: served.embedder.transform(),
        profile: served.embedder.profile(),
        provenance: served.embedder.provenance(),
    })
    .ok()?;
    // `{"model":…}` follows the rows as `],"model":…}`.
    let mut closing = b"],".to_vec();
    closing.extend_from_slice(tail.get(1..)?);
    Some((br#"{"object":"list","data":["#.to_vec(), closing))
}

/// What a client that asked for it (`error_member`) reads at the end of an
/// answer whose rows had started when it could not complete: the list
/// closed and an OpenAI-shaped `error` member in place of the tail, naming
/// why by `code` and the inputs it covered, never their text (FIX 10702).
/// `None` for any other client, whose stream ends broken, so no reader takes
/// a shorter list for a whole one.
fn error_terminal(
    work: &EmbeddingRequestWork,
    code: &'static str,
    message: &str,
) -> Option<Vec<u8>> {
    if !work.error_member {
        return None;
    }
    let error = serde_json::to_vec(&serde_json::json!({
        "message": message,
        "type": "server_error",
        "param": null,
        "code": code,
    }))
    .ok()?;
    let mut terminal = br#"],"error":"#.to_vec();
    terminal.extend_from_slice(&error);
    terminal.push(b'}');
    Some(terminal)
}

/// The code and message a later batch's failure ends an answer with.
fn unfinished(failure: &BatchFailure, inputs: &Range<usize>) -> (&'static str, String) {
    let (code, what) = match failure {
        BatchFailure::Encoding => ("encoding_failed", "could not be encoded"),
        _ => ("embedding_failed", "could not be embedded"),
    };
    (
        code,
        format!(
            "inputs {} to {} {what}; the rows before them were sent, and this answer is not complete",
            inputs.start,
            inputs.end.saturating_sub(1)
        ),
    )
}

/// Answers `work`: its first batch before any byte goes out, so a request
/// that fails there is refused whole, as one that fits a batch always is;
/// then every later batch streamed in order. `held` is the request's place
/// in `embedder_requests` and its body's bytes, kept until the answer is
/// delivered or abandoned.
pub(super) async fn stream_embedding_rows(
    served: Arc<Served>,
    work: EmbeddingRequestWork,
    held: (Permit, HeldBytes),
) -> Response {
    let work = Arc::new(work);
    let first = match embed_request_batches(&served, &work, 0, None).await {
        Ok(first) => first,
        Err(BatchFailure::WaitedOut) => return waited_out(),
        Err(BatchFailure::ClientGone | BatchFailure::Embedding | BatchFailure::Encoding) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the model could not embed this request",
            );
        }
    };
    let next = batch_range(&work, 0).end;
    if next >= work.texts.len() {
        let Some((head, tail)) = head_and_tail(&served, &work, first.tokens) else {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the answer could not be encoded",
            );
        };
        let mut answer = head;
        answer.extend_from_slice(&first.rows);
        answer.extend_from_slice(&tail);
        let length = answer.len();
        let idle = served.idle;
        let mut response =
            Response::new(pieces_body(served, work, held, first, Some(answer), idle));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        // A declared length makes an answer cut short at the idle limit a
        // broken one to the client, never a shorter one.
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, header::HeaderValue::from(length));
        return response;
    }
    let idle = served.idle;
    let mut response = Response::new(pieces_body(served, work, held, first, None, idle));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response
}

/// The answer's body. `whole` is a one-batch answer, sent as it is; with
/// none, the rows stream batch by batch after `first`, and the answer
/// closes only once every batch has come back. A batch that fails ends the
/// stream broken, or with its `error` member for a client that asked
/// ([`error_terminal`]); a client that goes away, or one that reads nothing
/// for `idle`, ends it broken. The request's place, its body's bytes and
/// each batch's room are given back then.
fn pieces_body(
    served: Arc<Served>,
    work: Arc<EmbeddingRequestWork>,
    held: (Permit, HeldBytes),
    first: EncodedBatch,
    whole: Option<Vec<u8>>,
    idle: Duration,
) -> axum::body::Body {
    let (pieces, receiver) = tokio::sync::mpsc::channel::<Piece>(2);
    tokio::spawn(async move {
        let _held = held;
        let send = |bytes: &[u8]| {
            let pieces = pieces.clone();
            let owned: Vec<axum::body::Bytes> = bytes
                .chunks(ANSWER_PIECE)
                .map(axum::body::Bytes::copy_from_slice)
                .collect();
            async move {
                for piece in owned {
                    if pieces.send_timeout(Ok(piece), idle).await.is_err() {
                        return false;
                    }
                }
                true
            }
        };
        if let Some(answer) = whole {
            let _first = first;
            send(&answer).await;
            return;
        }
        let Some((head, _)) = head_and_tail(&served, &work, 0) else {
            let _ = pieces.send(Err(broken())).await;
            return;
        };
        if !send(&head).await || !send(&first.rows).await {
            return;
        }
        let mut tokens = first.tokens;
        drop(first);
        let mut start = batch_range(&work, 0).end;
        while start < work.texts.len() {
            let batch = match embed_request_batches(&served, &work, start, Some(&pieces)).await {
                Ok(batch) => batch,
                Err(BatchFailure::ClientGone) => return,
                Err(failure) => {
                    tracing::warn!(
                        error_member = work.error_member,
                        "a later batch of an embeddings answer failed; the answer ends unfinished"
                    );
                    let (code, message) = unfinished(&failure, &batch_range(&work, start));
                    end_unfinished(&pieces, error_terminal(&work, code, &message), idle).await;
                    return;
                }
            };
            if !send(&batch.rows).await {
                return;
            }
            tokens = tokens.saturating_add(batch.tokens);
            start = batch_range(&work, start).end;
        }
        let Some((_, tail)) = head_and_tail(&served, &work, tokens) else {
            let message = "the answer's closing fields could not be encoded; every row was sent, and this answer is not complete";
            end_unfinished(&pieces, error_terminal(&work, "encoding_failed", message), idle).await;
            return;
        };
        send(&tail).await;
    });
    axum::body::Body::from_stream(futures_util::stream::unfold(
        receiver,
        |mut receiver| async move {
            let piece = receiver.recv().await?;
            Some((piece, receiver))
        },
    ))
}

/// Ends an answer that could not complete: with `terminal`, one piece, for a
/// client that reads it, else broken.
async fn end_unfinished(
    pieces: &tokio::sync::mpsc::Sender<Piece>,
    terminal: Option<Vec<u8>>,
    idle: Duration,
) {
    match terminal {
        Some(terminal) => {
            let piece = Ok(axum::body::Bytes::from(terminal));
            let _ = pieces.send_timeout(piece, idle).await;
        }
        None => {
            let _ = pieces.send(Err(broken())).await;
        }
    }
}

/// What a stream that cannot complete ends with when its client reads no
/// `error` member: never a closed list.
fn broken() -> std::io::Error {
    std::io::Error::other("the embeddings answer could not be completed")
}
