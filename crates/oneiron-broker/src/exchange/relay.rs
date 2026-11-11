//! A spooled exchange's reply, from its header on: relayed byte for byte in
//! chunks, under the echo watch, then its end, clean or cut. An LFS batch
//! reply is read whole first, within its reply limit, and its whole bytes
//! are watched before any goes.

use std::io;
use std::time::Duration;

use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::idle_bound;
use super::send::failure;
use crate::frame::{STREAM_CHUNK, write_chunk, write_stream_end, write_stream_header};
use crate::send::push_wiped;
use crate::{Failure, Outcome, PROTOCOL_VERSION, ReplyHeader};

/// Relays the reply's body as it comes, byte for byte, in chunks of at most
/// [`STREAM_CHUNK`]. [`EchoWatch`] reads it for `forms`, the literal forms
/// of the credential, and holds back only the bytes a form could still end
/// in; a reply that holds a form is cut before any byte of it goes. With no
/// forms (no credential was installed), every byte goes as it came.
/// Returns how the body ended: clean, or cut.
pub(crate) async fn relay(
    response: &mut reqwest::Response,
    stream: &mut UnixStream,
    forms: Vec<Zeroizing<Vec<u8>>>,
    idle: Duration,
) -> io::Result<Option<Failure>> {
    let mut watch = EchoWatch::new(forms);
    loop {
        let (released, last) = match tokio::time::timeout(idle, response.chunk()).await {
            Err(_) => return Ok(Some(Failure::Timeout)),
            Ok(Err(error)) => return Ok(Some(failure(&error))),
            Ok(Ok(Some(chunk))) => (watch.push(&chunk)?, false),
            Ok(Ok(None)) => (Some(watch.finish()), true),
        };
        let Some(released) = released else {
            return Ok(Some(Failure::ReplyHoldsKey));
        };
        for piece in released.chunks(STREAM_CHUNK) {
            idle_bound(idle, write_chunk(stream, piece)).await?;
        }
        if last {
            return Ok(None);
        }
    }
}

/// Reads the reply's body whole, each chunk within `idle`, into a buffer
/// wiped as it drops: at most `limit` bytes. Returns the body, or the
/// failure that ends it: one past `limit` ([`Failure::ReplyTooLarge`]), a
/// stall, or a broken read.
pub(crate) async fn read_whole(
    response: &mut reqwest::Response,
    limit: u64,
    idle: Duration,
) -> io::Result<Result<Zeroizing<Vec<u8>>, Failure>> {
    let mut body = Zeroizing::new(Vec::new());
    loop {
        match tokio::time::timeout(idle, response.chunk()).await {
            Err(_) => return Ok(Err(Failure::Timeout)),
            Ok(Err(error)) => return Ok(Err(failure(&error))),
            Ok(Ok(None)) => return Ok(Ok(body)),
            Ok(Ok(Some(chunk))) => {
                if (body.len() as u64).saturating_add(chunk.len() as u64) > limit {
                    return Ok(Err(Failure::ReplyTooLarge));
                }
                push_wiped(&mut body, &chunk)?;
            }
        }
    }
}

/// Relays a body read whole, in chunks of at most [`STREAM_CHUNK`], when it
/// holds none of `forms`, the literal forms of the credential; one that
/// holds a form is cut before any byte of it goes. Returns how the body
/// ended: clean, or cut.
pub(crate) async fn relay_whole(
    stream: &mut UnixStream,
    body: &[u8],
    forms: &[Zeroizing<Vec<u8>>],
    idle: Duration,
) -> io::Result<Option<Failure>> {
    if forms
        .iter()
        .any(|form| memchr::memmem::find(body, form).is_some())
    {
        return Ok(Some(Failure::ReplyHoldsKey));
    }
    for piece in body.chunks(STREAM_CHUNK) {
        idle_bound(idle, write_chunk(stream, piece)).await?;
    }
    Ok(None)
}

/// A reply's credential watch: the credential's literal forms (raw,
/// JSON-escaped, `Bearer`, percent-encoded, and its base64, whole and at
/// each byte offset; `crate::send::git_echo_forms`), searched across chunk
/// edges. Unlike the model strip, it never marks a run it cannot settle: a
/// pack, an advertisement or an object full of escapes is passed byte for
/// byte unless a form is in it. It holds back only the bytes a form could
/// still end in.
struct EchoWatch {
    forms: Vec<Zeroizing<Vec<u8>>>,
    /// The longest form's length less one: what a form split across chunks
    /// can have shown so far.
    keep: usize,
    /// The bytes that came and are not released yet.
    held: Zeroizing<Vec<u8>>,
}

impl EchoWatch {
    fn new(forms: Vec<Zeroizing<Vec<u8>>>) -> Self {
        let keep = forms
            .iter()
            .map(|form| form.len())
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Self {
            forms,
            keep,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// Takes the next `chunk` and answers the bytes released with it, or
    /// `None` when a form of the credential is in what came.
    fn push(&mut self, chunk: &[u8]) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        push_wiped(&mut self.held, chunk)?;
        if self
            .forms
            .iter()
            .any(|form| memchr::memmem::find(&self.held, form).is_some())
        {
            return Ok(None);
        }
        let release = self.held.len().saturating_sub(self.keep);
        let mut released = Zeroizing::new(Vec::new());
        push_wiped(&mut released, &self.held[..release])?;
        let rest = self.held.len() - release;
        self.held.copy_within(release.., 0);
        self.held.truncate(rest);
        Ok(Some(released))
    }

    /// The bytes still held once the reply ended: no form ends in them,
    /// since every form was searched as they came.
    fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.held, Zeroizing::new(Vec::new()))
    }
}

/// The reply header that answers the exchange `call`, whose digest is
/// `digest`, with `outcome`.
pub(crate) fn reply_header(call: &str, digest: &str, outcome: Outcome) -> ReplyHeader {
    ReplyHeader {
        version: PROTOCOL_VERSION,
        call: call.to_owned(),
        digest: digest.to_owned(),
        outcome,
    }
}

/// Answers the exchange `call` with `outcome` and no body: a streamed reply
/// that ends clean at once.
pub(crate) async fn answer(
    stream: &mut UnixStream,
    call: &str,
    digest: &str,
    outcome: Outcome,
    idle: Duration,
) -> io::Result<()> {
    idle_bound(
        idle,
        write_stream_header(stream, &reply_header(call, digest, outcome)),
    )
    .await?;
    idle_bound(idle, write_stream_end(stream, None)).await
}
