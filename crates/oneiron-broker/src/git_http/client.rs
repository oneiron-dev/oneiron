//! The daemon's side of a git exchange (see the parent module's steps): the
//! header and the spooled body first, the credential only once the broker
//! has the body and its digest checks, then the reply as it streams.

use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::{GitCallHeader, GitPrepared};
use crate::frame::{
    GIT_CALL, MAX_HEADER, STREAM_CHUNK, read_chunk, read_reply_header, read_segment,
    read_stream_end, write_segment,
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

impl BrokerConnection {
    /// Opens the git exchange `call`: checks it, writes its header and its
    /// body, read from `body`, which must hold exactly `call.body_len`
    /// bytes, and waits for the broker's acknowledgement that it holds the
    /// body and its digest is the header's. No credential is read or sent
    /// yet, and nothing reaches the repository before
    /// [`PreparedGitCall::open`]. Each write and read waits at most the
    /// connection's reply timeout.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Refused`] for the daemon's own check, a body of
    /// another length than the header's, or the broker's refusal;
    /// [`BrokerError::Lost`] when the connection breaks, or answers another
    /// exchange. Nothing was sent, either way.
    pub async fn prepare_git<R: AsyncRead + Unpin>(
        self,
        call: &GitCallHeader,
        body: &mut R,
    ) -> Result<PreparedGitCall, BrokerError> {
        call.check().map_err(BrokerError::Refused)?;
        let head = serde_json::to_vec(call).map_err(|_| BrokerError::Refused(Refusal::Frame))?;
        if head.len() > MAX_HEADER {
            return Err(BrokerError::Refused(Refusal::Frame));
        }
        let (mut stream, idle) = self.into_parts();
        step(idle, async {
            stream.write_all(&GIT_CALL.to_be_bytes()).await?;
            write_segment(&mut stream, &head).await
        })
        .await?;
        let short = || BrokerError::Refused(Refusal::Body);
        let mut left = call.body_len;
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
        let prepared: GitPrepared =
            serde_json::from_slice(&prepared).map_err(|_| BrokerError::Lost)?;
        if prepared.version != PROTOCOL_VERSION
            || prepared.call != call.call
            || prepared.digest != call.digest
        {
            return Err(BrokerError::Lost);
        }
        if let Some(reason) = prepared.refused {
            return Err(BrokerError::Refused(reason));
        }
        Ok(PreparedGitCall {
            stream,
            idle,
            call: call.call.clone(),
            digest: call.digest.clone(),
        })
    }
}

/// A git exchange the broker holds the body of, waiting for its
/// credential. Dropping it sends nothing.
#[derive(Debug)]
pub struct PreparedGitCall {
    stream: UnixStream,
    idle: Duration,
    call: String,
    digest: String,
}

impl PreparedGitCall {
    /// Hands over `secret`, the exchange's complete `Authorization` value,
    /// and waits for the reply's outcome, however long the send takes: the
    /// broker ends a send that makes no progress. Its body follows through
    /// [`GitReply::next`]. The daemon's copy of the secret is wiped once
    /// written.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Refused`] for a secret too long to frame, before it
    /// is written; [`BrokerError::Lost`] when the connection breaks or
    /// answers another exchange: the request may have left.
    pub async fn open(mut self, secret: Zeroizing<Vec<u8>>) -> Result<GitReply, BrokerError> {
        if secret.len() > MAX_SECRET {
            return Err(BrokerError::Refused(Refusal::Secret));
        }
        let written = step(self.idle, async {
            write_segment(&mut self.stream, &secret).await?;
            self.stream.flush().await
        })
        .await;
        drop(secret);
        written?;
        let reply = read_reply_header(&mut self.stream)
            .await
            .map_err(|_| BrokerError::Lost)?;
        if reply.version != PROTOCOL_VERSION
            || reply.call != self.call
            || reply.digest != self.digest
        {
            return Err(BrokerError::Lost);
        }
        Ok(GitReply {
            outcome: reply.outcome,
            stream: self.stream,
            idle: self.idle,
            ended: None,
        })
    }
}

/// A git exchange's reply as it arrives: its outcome first, then its body,
/// exactly as the repository sent it, through [`Self::next`]. A body the
/// broker cut ([`StreamPart::Cut`]) is no answer: every chunk taken must be
/// dropped. Dropping the reply cancels the rest of it.
#[derive(Debug)]
pub struct GitReply {
    outcome: Outcome,
    stream: UnixStream,
    idle: Duration,
    /// How the body ended, once it has: clean (`None`) or cut.
    ended: Option<Option<Failure>>,
}

impl GitReply {
    /// What happened. An answer here can still be cut.
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The body's next step, each waited for at most the connection's reply
    /// timeout. Once it has ended, every later call gives the same end.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Lost`]: the reply is broken, and counts as cut.
    pub async fn next(&mut self) -> Result<StreamPart, BrokerError> {
        if let Some(end) = self.ended {
            return Ok(end.map_or(StreamPart::End, StreamPart::Cut));
        }
        if let Some(chunk) = step(self.idle, read_chunk(&mut self.stream)).await? {
            return Ok(StreamPart::Chunk(chunk));
        }
        let end = step(self.idle, read_stream_end(&mut self.stream)).await?;
        self.ended = Some(end);
        Ok(end.map_or(StreamPart::End, StreamPart::Cut))
    }
}
