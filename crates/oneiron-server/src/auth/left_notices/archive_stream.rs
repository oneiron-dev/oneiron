//! The removal archive doors' answers, written as they are sent (FIX
//! 21529): each copy's JSON comes from
//! [`RemovalExportFile::write_json`], its archive base64-encoded from the
//! copy's spool file, so no answer is held whole. The bytes are the ones
//! `axum::Json` gave for the same answer: the same envelope, compact, its
//! members in declaration order. The engine's door has answered before the
//! first byte goes out, so a refusal keeps its status; an answer that fails
//! once it has begun ends broken, never as a shorter document.

use std::io::{self, Write};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, header};
use axum::response::Response;
use oneiron::federation::RemovalExportFile;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// The largest piece of an answer handed to its body at once.
const ANSWER_PIECE: usize = 64 * 1024;

/// An answer's bytes on their way to its body, gathered into pieces of at
/// most [`ANSWER_PIECE`]; a client that reads nothing for `idle` ends it.
struct AnswerWriter {
    pieces: mpsc::Sender<io::Result<Bytes>>,
    runtime: Handle,
    idle: Duration,
    piece: Vec<u8>,
}

impl AnswerWriter {
    fn send_piece(&mut self) -> io::Result<()> {
        if self.piece.is_empty() {
            return Ok(());
        }
        let piece = std::mem::replace(&mut self.piece, Vec::with_capacity(ANSWER_PIECE));
        crate::api::send_within(
            &self.runtime,
            &self.pieces,
            Ok(Bytes::from(piece)),
            self.idle,
        )
    }
}

impl Write for AnswerWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let room = ANSWER_PIECE.saturating_sub(self.piece.len());
        let taken = bytes.get(..room).unwrap_or(bytes);
        self.piece.extend_from_slice(taken);
        if self.piece.len() >= ANSWER_PIECE {
            self.send_piece()?;
        }
        Ok(taken.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_piece()
    }
}

/// `{"exports":[…]}`: the removal-export list's answer.
pub(super) fn exports_answer(exports: Vec<RemovalExportFile>, idle: Duration) -> Response {
    json_answer(idle, move |out| {
        out.write_all(br#"{"exports":["#)?;
        for (at, mut export) in exports.into_iter().enumerate() {
            if at > 0 {
                out.write_all(b",")?;
            }
            export.write_json(out)?;
        }
        out.write_all(b"]}")
    })
}

/// `{"export":…}`: one removal receipt's archive.
pub(super) fn export_answer(mut export: RemovalExportFile, idle: Duration) -> Response {
    json_answer(idle, move |out| {
        out.write_all(br#"{"export":"#)?;
        export.write_json(out)?;
        out.write_all(b"}")
    })
}

/// `{"deliveries":[{"version":…,"copy":…},…],"woken":false}`: a delivery
/// session's archives, each with the delivery version its ack names.
pub(super) fn deliveries_answer(owed: Vec<(u64, RemovalExportFile)>, idle: Duration) -> Response {
    json_answer(idle, move |out| {
        out.write_all(br#"{"deliveries":["#)?;
        for (at, (version, mut copy)) in owed.into_iter().enumerate() {
            if at > 0 {
                out.write_all(b",")?;
            }
            write!(out, r#"{{"version":{version},"copy":"#)?;
            copy.write_json(out)?;
            out.write_all(b"}")?;
        }
        out.write_all(br#"],"woken":false}"#)
    })
}

/// An `application/json` answer whose body `write` writes on a worker
/// thread of its own, piece by piece as the client reads. A `write` that
/// fails ends the body with an error, so the client reads a broken answer.
fn json_answer(
    idle: Duration,
    write: impl FnOnce(&mut AnswerWriter) -> io::Result<()> + Send + 'static,
) -> Response {
    let (pieces, receiver) = mpsc::channel(2);
    let runtime = Handle::current();
    // Detached: the worker answers nobody; it ends with the body.
    drop(crate::api::spawn_worker(move || {
        let mut out = AnswerWriter {
            pieces,
            runtime,
            idle,
            piece: Vec::with_capacity(ANSWER_PIECE),
        };
        if let Err(error) = write(&mut out).and_then(|()| out.flush()) {
            tracing::warn!(
                kind = ?error.kind(),
                "a removal archive answer ended unfinished (FIX 21529)"
            );
            let ending = io::Error::other("the removal archive answer ended unfinished");
            let _ = crate::api::send_within(&out.runtime, &out.pieces, Err(ending), idle);
        }
    }));
    let mut response = Response::new(Body::from_stream(futures_util::stream::unfold(
        receiver,
        |mut receiver| async move {
            let piece = receiver.recv().await?;
            Some((piece, receiver))
        },
    )));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}
