//! The daemon's side of a spooled exchange: the opening word, the header
//! and the body, the wait for the broker's acknowledgement, then the
//! credential segment and the reply as it streams.

use std::future::Future;
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::Prepared;
use crate::frame::{
    MAX_HEADER, STREAM_CHUNK, read_chunk, read_reply_header, read_segment, read_stream_end,
    write_segment,
};
use crate::{
    BrokerConnection, BrokerError, Failure, MAX_SECRET, Outcome, PROTOCOL_VERSION, Refusal,
    StreamPart,
};

/// One step on the broker's socket, within `idle`.
async fn step<T>(
    idle: Duration,
    io: impl Future<Output = std::io::Result<T>>,
) -> Result<T, BrokerError> {
    tokio::time::timeout(idle, io)
        .await
        .map_err(|_| BrokerError::Lost)?
        .map_err(|_| BrokerError::Lost)
}

/// Writes the exchange `call`'s opening `word`, its JSON header `head`,
/// and its body, read from `body`, which must hold exactly `body_len`
/// bytes; then waits for the broker's acknowledgement that it holds the
/// body and its digest is `digest`. Returns the socket and its idle bound,
/// the connection's reply timeout, which each write and read waits at most.
///
/// # Errors
///
/// [`BrokerError::Refused`] for a header too long to frame, a body of
/// another length than `body_len`, or the broker's refusal;
/// [`BrokerError::Lost`] when the connection breaks, or answers another
/// exchange. Nothing was sent, either way.
pub(crate) async fn prepare<R: AsyncRead + Unpin>(
    connection: BrokerConnection,
    word: u32,
    head: &[u8],
    call: &str,
    digest: &str,
    body_len: u64,
    body: &mut R,
) -> Result<(UnixStream, Duration), BrokerError> {
    if head.len() > MAX_HEADER {
        return Err(BrokerError::Refused(Refusal::Frame));
    }
    let (mut stream, idle) = connection.into_parts();
    step(idle, async {
        stream.write_all(&word.to_be_bytes()).await?;
        write_segment(&mut stream, head).await
    })
    .await?;
    let short = || BrokerError::Refused(Refusal::Body);
    let mut left = body_len;
    let mut buffer = vec![0; STREAM_CHUNK];
    while left > 0 {
        let want = usize::try_from(left).map_or(STREAM_CHUNK, |left| left.min(STREAM_CHUNK));
        let read = body.read(&mut buffer[..want]).await.map_err(|_| short())?;
        if read == 0 {
            return Err(short());
        }
        step(idle, write_segment(&mut stream, &buffer[..read])).await?;
        left -= read as u64;
    }
    // A body past its length is refused before any credential.
    let mut past = [0; 1];
    if body.read(&mut past).await.map_err(|_| short())? != 0 {
        return Err(short());
    }
    step(idle, async {
        write_segment(&mut stream, &[]).await?;
        stream.flush().await
    })
    .await?;
    let prepared = step(idle, read_segment(&mut stream, MAX_HEADER)).await?;
    let prepared: Prepared = serde_json::from_slice(&prepared).map_err(|_| BrokerError::Lost)?;
    if prepared.version != PROTOCOL_VERSION || prepared.call != call || prepared.digest != digest {
        return Err(BrokerError::Lost);
    }
    if let Some(reason) = prepared.refused {
        return Err(BrokerError::Refused(reason));
    }
    Ok((stream, idle))
}

/// Writes `secret`, the exchange's credential segment (empty for none), on
/// `stream`, and waits for the reply's outcome, however long the send
/// takes: the broker ends a send that makes no progress. The daemon's copy
/// of the secret is wiped once written.
///
/// # Errors
///
/// [`BrokerError::Refused`] for a secret too long to frame, before it is
/// written; [`BrokerError::Lost`] when the connection breaks or answers
/// another exchange: the request may have left.
pub(crate) async fn open(
    mut stream: UnixStream,
    idle: Duration,
    call: &str,
    digest: &str,
    secret: Zeroizing<Vec<u8>>,
) -> Result<(Outcome, ReplyBody), BrokerError> {
    if secret.len() > MAX_SECRET {
        return Err(BrokerError::Refused(Refusal::Secret));
    }
    let written = step(idle, async {
        write_segment(&mut stream, &secret).await?;
        stream.flush().await
    })
    .await;
    drop(secret);
    written?;
    let reply = read_reply_header(&mut stream)
        .await
        .map_err(|_| BrokerError::Lost)?;
    if reply.version != PROTOCOL_VERSION || reply.call != call || reply.digest != digest {
        return Err(BrokerError::Lost);
    }
    Ok((
        reply.outcome,
        ReplyBody {
            stream,
            idle,
            ended: None,
        },
    ))
}

/// An exchange's reply body as it arrives, exactly as the far end sent it.
/// A body the broker cut ([`StreamPart::Cut`]) is no answer: every chunk
/// taken must be dropped. Dropping it cancels the rest.
#[derive(Debug)]
pub(crate) struct ReplyBody {
    stream: UnixStream,
    idle: Duration,
    /// How the body ended, once it has: clean (`None`) or cut.
    ended: Option<Option<Failure>>,
}

impl ReplyBody {
    /// Reads the one JSON frame an adapter writes between its reply's
    /// header and its body (an LFS batch reply's rewrite count), within the
    /// idle bound: the broker writes it with the header.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Lost`] when the connection breaks or the frame is not
    /// `T`.
    pub(crate) async fn read_frame<T: DeserializeOwned>(&mut self) -> Result<T, BrokerError> {
        let frame = step(self.idle, read_segment(&mut self.stream, MAX_HEADER)).await?;
        serde_json::from_slice(&frame).map_err(|_| BrokerError::Lost)
    }

    /// The body's next step, waited for as long as the broker relays: the
    /// broker times the far end by the exchange's idle bound and may hold
    /// bytes back while it watches them for the credential, so a slow
    /// trickle never reads as a stall here. Once it has ended, every later
    /// call gives the same end.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Lost`]: the reply is broken, and counts as cut.
    pub(crate) async fn next(&mut self) -> Result<StreamPart, BrokerError> {
        if let Some(end) = self.ended {
            return Ok(end.map_or(StreamPart::End, StreamPart::Cut));
        }
        let chunk = read_chunk(&mut self.stream)
            .await
            .map_err(|_| BrokerError::Lost)?;
        if let Some(chunk) = chunk {
            return Ok(StreamPart::Chunk(chunk));
        }
        let end = step(self.idle, read_stream_end(&mut self.stream)).await?;
        self.ended = Some(end);
        Ok(end.map_or(StreamPart::End, StreamPart::Cut))
    }
}
