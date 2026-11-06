//! The daemon's side of an LFS exchange (see the parent module's steps):
//! the header and the spooled body first; then, once the broker has the
//! body and its digest checks, a batch's credential or no credential at
//! all; then the reply as it streams.

use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::LfsCallHeader;
use crate::exchange::client::{ReplyBody, open, prepare};
use crate::frame::LFS_CALL;
use crate::{BrokerConnection, BrokerError, Outcome, Refusal, StreamPart};

impl BrokerConnection {
    /// Opens the LFS exchange `call`: checks it, writes its header and its
    /// body, read from `body`, which must hold exactly `call.body_len`
    /// bytes, and waits for the broker's acknowledgement that it holds the
    /// body, its digest is the header's and, for an action, its host was
    /// admitted. No credential is read or sent yet, and nothing reaches
    /// the far end before [`PreparedLfsCall::open`] or
    /// [`PreparedLfsCall::open_without_credential`]. Each write and read
    /// waits at most the connection's reply timeout.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Refused`] for the daemon's own check, a body of
    /// another length than the header's, or the broker's refusal;
    /// [`BrokerError::Lost`] when the connection breaks, or answers another
    /// exchange. Nothing was sent, either way.
    pub async fn prepare_lfs<R: AsyncRead + Unpin>(
        self,
        call: &LfsCallHeader,
        body: &mut R,
    ) -> Result<PreparedLfsCall, BrokerError> {
        call.check().map_err(BrokerError::Refused)?;
        let head = serde_json::to_vec(call).map_err(|_| BrokerError::Refused(Refusal::Frame))?;
        let (stream, idle) = prepare(
            self,
            LFS_CALL,
            &head,
            &call.call,
            &call.digest,
            call.body_len,
            body,
        )
        .await?;
        Ok(PreparedLfsCall {
            stream,
            idle,
            call: call.call.clone(),
            digest: call.digest.clone(),
            batch: call.target.is_batch(),
        })
    }
}

/// An LFS exchange the broker holds the body of, waiting for its credential
/// segment. Dropping it sends nothing.
#[derive(Debug)]
pub struct PreparedLfsCall {
    stream: UnixStream,
    idle: Duration,
    call: String,
    digest: String,
    /// Whether the exchange is a batch, the one that may carry the
    /// repository credential.
    batch: bool,
}

impl PreparedLfsCall {
    /// Hands over `secret`, a batch's complete `Authorization` value, and
    /// waits for the reply's outcome, however long the send takes: the
    /// broker ends a send that makes no progress. Its body follows through
    /// [`LfsReply::next`]. The daemon's copy of the secret is wiped once
    /// written, or at once when refused.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Refused`] with [`Refusal::Secret`] for an action,
    /// which never carries the repository credential, an empty secret, or
    /// one too long to frame, before anything is written;
    /// [`BrokerError::Lost`] when the connection breaks or answers another
    /// exchange: the request may have left.
    pub async fn open(self, secret: Zeroizing<Vec<u8>>) -> Result<LfsReply, BrokerError> {
        if !self.batch || secret.is_empty() {
            return Err(BrokerError::Refused(Refusal::Secret));
        }
        self.open_with(secret).await
    }

    /// Sends the exchange with no credential: an action, with its own
    /// headers alone, or an anonymous batch. Waits for the reply's outcome
    /// as [`Self::open`] does.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Lost`] when the connection breaks or answers another
    /// exchange: the request may have left.
    pub async fn open_without_credential(self) -> Result<LfsReply, BrokerError> {
        self.open_with(Zeroizing::new(Vec::new())).await
    }

    /// Writes the credential segment `secret` (empty for none) and reads the
    /// reply's header.
    async fn open_with(self, secret: Zeroizing<Vec<u8>>) -> Result<LfsReply, BrokerError> {
        let (outcome, body) =
            open(self.stream, self.idle, &self.call, &self.digest, secret).await?;
        Ok(LfsReply { outcome, body })
    }
}

/// An LFS exchange's reply as it arrives: its outcome first, then its body,
/// exactly as the far end sent it, through [`Self::next`]. A body the
/// broker cut ([`StreamPart::Cut`]) is no answer: every chunk taken must be
/// dropped, and a batch's JSON or an object's bytes count only once the
/// body ended clean ([`StreamPart::End`]). Dropping the reply cancels the
/// rest of it.
#[derive(Debug)]
pub struct LfsReply {
    outcome: Outcome,
    body: ReplyBody,
}

impl LfsReply {
    /// What happened. An answer here can still be cut.
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The body's next step, waited for as long as the broker relays: the
    /// broker times the far end by the exchange's idle bound and may hold a
    /// batch reply's bytes back while it watches them for the credential,
    /// so a slow trickle never reads as a stall here. The caller cancels by
    /// dropping the reply. Once it has ended, every later call gives the
    /// same end.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Lost`]: the reply is broken, and counts as cut.
    pub async fn next(&mut self) -> Result<StreamPart, BrokerError> {
        self.body.next().await
    }
}
