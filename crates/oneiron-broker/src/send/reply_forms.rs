//! The two forms a reached reply goes back in: one segment, read whole and
//! stripped, or a stream, relayed as it comes.

use std::io;

use reqwest::Url;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use super::{
    Sender, answer, failed, failure, push_wiped, reply, reply_headers, while_daemon_waits,
};
use crate::deadline::{CallDeadline, within};
use crate::frame::{STREAM_CHUNK, write_chunk, write_stream_end, write_stream_header};
use crate::strip::{KeyWatch, strip};
use crate::{CallHeader, Failure, MAX_BODY, Outcome, Refusal};

impl Sender {
    /// Sends `body` to `url` once with the key in the shape's auth header,
    /// then strips the key from what came back. `call` has passed
    /// [`CallHeader::check`] on `body`. The send ends by `deadline`'s send
    /// limit.
    pub(crate) async fn send<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        url: Url,
        body: Zeroizing<Vec<u8>>,
        secret: &[u8],
        writer: &mut W,
        released: bool,
        deadline: CallDeadline,
    ) -> (Outcome, Zeroizing<Vec<u8>>) {
        let empty = Zeroizing::new(Vec::new());
        let mut response = match self
            .reach(
                call,
                url,
                body,
                secret,
                released.then_some(&mut *writer),
                released,
                deadline,
            )
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => {
                return (
                    Outcome::Failed {
                        reason: Failure::Send,
                    },
                    empty,
                );
            }
            Err(outcome) => return (outcome, empty),
        };
        let mut raw = Zeroizing::new(Vec::new());
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if raw.len() + chunk.len() > MAX_BODY {
                        return (
                            Outcome::Failed {
                                reason: Failure::ReplyTooLarge,
                            },
                            empty,
                        );
                    }
                    if push_wiped(&mut raw, &chunk).is_err() {
                        return (
                            Outcome::Failed {
                                reason: Failure::Send,
                            },
                            empty,
                        );
                    }
                }
                Ok(None) => break,
                Err(error) => return (failed(&error), empty),
            }
        }
        let headers = reply_headers(response.headers(), secret);
        let body = strip(secret, &raw);
        if call.shape.answers_file_content() && body.as_slice() != raw.as_slice() {
            // A file's content goes whole or not at all: a marker in place
            // of its bytes would pass as the file.
            return (
                Outcome::Failed {
                    reason: Failure::ReplyHoldsKey,
                },
                empty,
            );
        }
        let status = response.status().as_u16();
        (Outcome::Answered { status, headers }, body)
    }

    /// Sends a call whose shape streams ([`crate::Shape::streams`]) and
    /// writes its reply to `writer` as it comes: the header, then the body in
    /// chunks [`KeyWatch`] has released, then the end. Each form of the key
    /// in the body is replaced at its bytes as the buffered strip replaces
    /// it, and the stream goes on (FIX 6103): nothing is cut for holding the
    /// key. So the key stays until the last chunk is read. `checked` is the call's
    /// [`CallHeader::check`]. The send ends by `deadline`'s send limit, and
    /// each write within its frame allowance and the deadline; a daemon that
    /// takes longer is gone, and the reply is dropped.
    pub(crate) async fn stream<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        checked: Result<Url, Refusal>,
        body: Zeroizing<Vec<u8>>,
        whole: Option<Zeroizing<Vec<u8>>>,
        released: bool,
        secret: &[u8],
        writer: &mut W,
        deadline: CallDeadline,
    ) {
        let _ = self
            .stream_to(
                call, checked, body, whole, released, secret, writer, deadline,
            )
            .await;
    }

    async fn stream_to<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        checked: Result<Url, Refusal>,
        body: Zeroizing<Vec<u8>>,
        whole: Option<Zeroizing<Vec<u8>>>,
        released: bool,
        secret: &[u8],
        writer: &mut W,
        deadline: CallDeadline,
    ) -> io::Result<()> {
        if call.shape == crate::Shape::OpenAiResponses {
            return crate::responses::responses_to(
                &self.ws_tls,
                call,
                checked,
                body,
                whole,
                released,
                secret,
                writer,
                deadline,
            )
            .await;
        }
        let reached = match checked {
            Ok(url) => {
                self.reach(
                    call,
                    url,
                    body,
                    secret,
                    Some(&mut *writer),
                    released,
                    deadline,
                )
                .await
            }
            Err(reason) => Err(Outcome::Refused { reason }),
        };
        let response = match reached {
            Ok(Some(response)) => response,
            Ok(None) => return Ok(()),
            Err(outcome) => return answer(writer, call, outcome, deadline).await,
        };
        if call.shape.relays_events() {
            // HTTP release checks finish before this header/body phase.
            let (mut reading, mut writing) = tokio::io::split(writer);
            while_daemon_waits(
                Some(&mut reading),
                stream_reply_to(&mut writing, call, response, secret, deadline),
            )
            .await
            .unwrap_or(Ok(()))
        } else {
            stream_reply_to(writer, call, response, secret, deadline).await
        }
    }
}

async fn stream_reply_to<W: AsyncWrite + Unpin>(
    writer: &mut W,
    call: &CallHeader,
    mut response: reqwest::Response,
    secret: &[u8],
    deadline: CallDeadline,
) -> io::Result<()> {
    let answered = Outcome::Answered {
        status: response.status().as_u16(),
        headers: reply_headers(response.headers(), secret),
    };
    let header = reply(call, answered);
    within(deadline, write_stream_header(writer, &header)).await?;
    let mut watch = KeyWatch::new(secret);
    let mut cleared = Zeroizing::new(Vec::new());
    // Relayed events go on as soon as the watch clears them, a frame at
    // most at a time; other streamed bodies go in whole frames (FIX
    // 15702). The watch still holds back any bytes that could begin a
    // form of the key.
    let eager = call.shape.relays_events();
    let cut = loop {
        let (passed, last) = match response.chunk().await {
            Ok(Some(chunk)) => (watch.push(&chunk), false),
            Ok(None) => (watch.finish(), true),
            Err(error) => break Some(failure(&error)),
        };
        if push_wiped(&mut cleared, &passed).is_err() {
            break Some(Failure::Send);
        }
        // Whole chunks as they fill; at the end, the rest too.
        let mut sent = 0;
        while cleared.len() - sent >= STREAM_CHUNK || ((last || eager) && sent < cleared.len()) {
            let end = cleared.len().min(sent + STREAM_CHUNK);
            within(deadline, write_chunk(writer, &cleared[sent..end])).await?;
            sent = end;
        }
        if last {
            break None;
        }
        if sent > 0 {
            let mut remainder = Zeroizing::new(Vec::new());
            if push_wiped(&mut remainder, &cleared[sent..]).is_err() {
                break Some(Failure::Send);
            }
            cleared = remainder;
        }
    };
    within(deadline, write_stream_end(writer, cut)).await
}
