//! A request's body, read under room its budget holds for it (FIX 149).
//!
//! A body that declares its length reserves all of it before any of it is
//! read: one of at most [`SMALL_BODY_BYTES`] on the small budget, so a query
//! never waits behind an upload, and a larger one on the large budget. A body
//! that declares none is read a piece at a time on the large budget: before
//! each piece is taken, room for [`BODY_PIECE_BYTES`] past what has arrived
//! is reserved, and the endpoint's listener caps each connection's HTTP/1
//! read buffer at that bound, so one read hands over no more than that room.
//! A piece that still arrives past it (the buffer's spare capacity) is
//! charged to the budget at once, owed past its free bytes, never held
//! uncharged across a wait. Room a body being read grows into is
//! taken at once when it is free, ahead of bodies not yet read, which wait
//! for it to end anyway; otherwise it waits in order up to the queue
//! deadline, as a declared body's room does, and a wait that runs out
//! answers 503 with nothing kept, so the caller retries. No size refuses a
//! body: one larger than the whole large budget takes all of it and waits
//! until it can run alone, the only large body held, and the row asks
//! (OF-520). A wait for room does not count against [`BODY_READ_TIMEOUT`],
//! which is the time the body is read with its room reserved.
//!
//! The pieces are kept as they arrived, never copied into one buffer beside
//! them, so a body's bytes are held once; decoding reads them in order and
//! lets each go once it is read.

use std::collections::VecDeque;

use axum::body::{Bytes, HttpBody as _};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use futures_util::StreamExt as _;
use serde::de::DeserializeOwned;

use super::{BODY_READ_TIMEOUT, SMALL_BODY_BYTES, Served, refuse};
use crate::byte_line::HeldBytes;

/// The room a body that declares no length keeps reserved on the large
/// budget past what it has received before it takes its next piece: as much
/// as the largest small body. Short of it, the reservation grows to two such
/// pieces past what has arrived. It is also the endpoint listener's HTTP/1
/// read buffer cap, so one read hands over no more than this room.
pub(super) const BODY_PIECE_BYTES: usize = SMALL_BODY_BYTES;

/// A request body as it arrived, in its pieces.
pub(super) struct BodyPieces(Vec<Bytes>);

impl BodyPieces {
    /// Decodes the body as JSON: a body of one piece straight from it, one
    /// of several from its pieces in order.
    pub(super) fn decode<T: DeserializeOwned>(self) -> serde_json::Result<T> {
        let mut pieces = VecDeque::from(self.0);
        if pieces.len() <= 1 {
            let whole = pieces.pop_front().unwrap_or_default();
            return serde_json::from_slice(&whole);
        }
        serde_json::from_reader(PieceReader { pieces, at: 0 })
    }
}

/// A body's pieces read in order as one stream, each let go once it is
/// read.
struct PieceReader {
    pieces: VecDeque<Bytes>,
    /// How far into the front piece the reader is.
    at: usize,
}

impl std::io::Read for PieceReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(front) = self.pieces.front() {
            let rest = &front[self.at..];
            if rest.is_empty() {
                self.pieces.pop_front();
                self.at = 0;
                continue;
            }
            let read = rest.len().min(buf.len());
            buf[..read].copy_from_slice(&rest[..read]);
            self.at += read;
            return Ok(read);
        }
        Ok(0)
    }
}

/// Reads `request`'s body under its budget's room, which the returned bytes
/// hold until the request's work ends. The key was checked before this
/// ([`super::require_key`]).
pub(super) async fn read_body(
    served: &Served,
    request: Request,
) -> Result<(HeldBytes, BodyPieces), Response> {
    let declared = request
        .body()
        .size_hint()
        .exact()
        .map(|bytes| usize::try_from(bytes).unwrap_or(usize::MAX));
    let mut held = match declared {
        Some(bytes) => {
            let budget = if bytes <= SMALL_BODY_BYTES {
                &served.small_bodies
            } else {
                &served.large_bodies
            };
            budget
                .reserve_alone(bytes, served.wait, &served.questions)
                .await
                .ok_or_else(|| {
                    no_room("the request waited past its deadline for room for its body; nothing was read; retry")
                })?
        }
        None => served.large_bodies.empty(),
    };
    // The bytes `held` covers, past the whole budget too.
    let mut reserved = declared.unwrap_or(0);
    let mut received = 0usize;
    let mut pieces = Vec::new();
    let mut frames = request.into_body().into_data_stream();
    let mut reading = BODY_READ_TIMEOUT;
    loop {
        // Room for the next piece, and one more past it when it grows, so
        // it grows once a piece rather than once a frame.
        if declared.is_none() && reserved < received.saturating_add(BODY_PIECE_BYTES) {
            let ahead = received
                .saturating_add(BODY_PIECE_BYTES)
                .saturating_add(BODY_PIECE_BYTES);
            grow_reservation(served, &mut held, &mut reserved, ahead).await?;
        }
        let started = tokio::time::Instant::now();
        let next = tokio::time::timeout(reading, frames.next()).await;
        reading = reading.saturating_sub(started.elapsed());
        let piece = match next {
            Ok(Some(Ok(piece))) => piece,
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(broke_off(declared)),
            Err(_) => {
                return Err(refuse(
                    StatusCode::REQUEST_TIMEOUT,
                    "invalid_request_error",
                    &format!(
                        "the body did not arrive within {} s of reading",
                        BODY_READ_TIMEOUT.as_secs()
                    ),
                ));
            }
        };
        received = received.saturating_add(piece.len());
        match declared {
            Some(bytes) if received > bytes => {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    "the body ran past its declared length",
                ));
            }
            Some(_) => {}
            // Past the room reserved ahead it is charged now, before any
            // wait, so it is never held uncharged.
            None if received > reserved => {
                served
                    .large_bodies
                    .charge(&mut held, received, &served.questions);
                reserved = received;
            }
            None => {}
        }
        pieces.push(piece);
    }
    match declared {
        Some(bytes) if received < bytes => return Err(broke_off(declared)),
        Some(_) => {}
        // The room reserved ahead of the end goes back to the budget.
        None => {
            served
                .large_bodies
                .try_resize(&mut held, received, &served.questions);
        }
    }
    Ok((held, BodyPieces(pieces)))
}

/// Grows `held` on the large budget to cover `bytes`, if it does not yet
/// ([`crate::byte_line::ByteLine::grow_alone`]). The refusal when its wait
/// for room ran out, with nothing kept.
async fn grow_reservation(
    served: &Served,
    held: &mut HeldBytes,
    reserved: &mut usize,
    bytes: usize,
) -> Result<(), Response> {
    if *reserved >= bytes {
        return Ok(());
    }
    if !served
        .large_bodies
        .grow_alone(held, bytes, served.wait, &served.questions)
        .await
    {
        return Err(no_room(
            "the request waited past its deadline for room for the rest of its body; nothing was kept; retry",
        ));
    }
    *reserved = bytes;
    Ok(())
}

/// A body whose room could not be reserved in time.
fn no_room(message: &str) -> Response {
    refuse(StatusCode::SERVICE_UNAVAILABLE, "server_error", message)
}

/// A body that ended or broke off before all of it arrived.
fn broke_off(declared: Option<usize>) -> Response {
    let message = if declared.is_some() {
        "the body ended before its declared length"
    } else {
        "the body broke off before its end"
    };
    refuse(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}
