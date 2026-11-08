//! The daemon's side of a git exchange (see the parent module's steps): the
//! header and the spooled body first, the credential only once the broker
//! has the body and its digest checks, then the reply as it streams.

use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::GitCallHeader;
use crate::exchange::client::{ReplyBody, open, prepare};
use crate::frame::GIT_CALL;
use crate::{BrokerConnection, BrokerError, Outcome, Refusal, StreamPart};

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
        let (stream, idle) = prepare(
            self,
            GIT_CALL,
            &head,
            &call.call,
            &call.digest,
            call.body_len,
            body,
        )
        .await?;
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
    pub async fn open(self, secret: Zeroizing<Vec<u8>>) -> Result<GitReply, BrokerError> {
        let (outcome, body) =
            open(self.stream, self.idle, &self.call, &self.digest, secret).await?;
        Ok(GitReply { outcome, body })
    }
}

/// A git exchange's reply as it arrives: its outcome first, then its body,
/// exactly as the repository sent it, through [`Self::next`]. A body the
/// broker cut ([`StreamPart::Cut`]) is no answer: every chunk taken must be
/// dropped. Dropping the reply cancels the rest of it.
#[derive(Debug)]
pub struct GitReply {
    outcome: Outcome,
    body: ReplyBody,
}

impl GitReply {
    /// What happened. An answer here can still be cut.
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The body's next step, waited for as long as the broker relays: the
    /// broker times the repository by the exchange's idle bound and may
    /// hold bytes back while it watches them for the credential, so a slow
    /// trickle never reads as a stall here. The caller cancels by dropping
    /// the reply. Once it has ended, every later call gives the same end.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Lost`]: the reply is broken, and counts as cut.
    pub async fn next(&mut self) -> Result<StreamPart, BrokerError> {
        self.body.next().await
    }
}
