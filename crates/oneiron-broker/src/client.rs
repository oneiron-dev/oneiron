//! The daemon's side of the socket.
//!
//! The daemon checks the call, connects and checks the peer (or, for its
//! same-user child, hands the child its end of a fresh socket pair), and only
//! then reads the key at the custody door and writes the frame. So a refused
//! call, or a broker that is not there, never costs a key read.
//!
//! A reply whose shape streams arrives in chunks ([`BrokerStream`]); the
//! daemon keeps them only once the broker says the body ended clean.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::frame::{read_chunk, read_reply, read_reply_header, read_stream_end, write_call};
use crate::peer::own_uid;
use crate::send::push_wiped;
use crate::{
    BrokerError, CallHeader, ChildBroker, Failure, Isolation, MAX_STREAM, Outcome,
    PROTOCOL_VERSION, ReplyHeader,
};

/// How the daemon reaches its broker, and who the broker must be.
#[derive(Debug, Clone)]
pub struct BrokerClient {
    peer: Peer,
    isolation: Isolation,
    reply_timeout: Duration,
}

#[derive(Debug, Clone)]
enum Peer {
    /// A broker the host runs, at a socket, as `uid`.
    User { socket: PathBuf, uid: u32 },
    /// The daemon's own child, reached over the channel it inherited.
    Child(Arc<ChildBroker>),
}

impl BrokerClient {
    /// A broker at `socket` that runs as `broker_uid`. A separate-user broker
    /// must not share the daemon's uid, and a same-user one must.
    /// `reply_timeout` bounds the wait for a reply, past the broker's own
    /// send limit.
    pub fn new(
        socket: PathBuf,
        broker_uid: u32,
        isolation: Isolation,
        reply_timeout: Duration,
    ) -> Result<Self, BrokerError> {
        let same = broker_uid == own_uid();
        if same != (isolation == Isolation::SameUser) {
            return Err(BrokerError::Peer);
        }
        Ok(Self {
            peer: Peer::User {
                socket,
                uid: broker_uid,
            },
            isolation,
            reply_timeout,
        })
    }

    /// The same-user `child` (`#broker-same-user-open`), which takes each
    /// call's socket over the channel it inherited, so nothing but that child
    /// can be the peer.
    #[must_use]
    pub fn child(child: Arc<ChildBroker>, reply_timeout: Duration) -> Self {
        Self {
            peer: Peer::Child(child),
            isolation: Isolation::SameUser,
            reply_timeout,
        }
    }

    /// Whether a call could reach the broker now, checked before the call's
    /// permit starts: a host's broker has a socket at its path, and the
    /// child is running, or starts now.
    pub fn ready(&self) -> std::io::Result<()> {
        match &self.peer {
            Peer::User { socket, .. } => {
                let meta = std::fs::metadata(socket)?;
                if std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()) {
                    Ok(())
                } else {
                    Err(std::io::Error::other(format!(
                        "{} is not a socket",
                        socket.display()
                    )))
                }
            }
            Peer::Child(child) => child.ensure(),
        }
    }

    /// How this broker is isolated, for the call's receipt.
    #[must_use]
    pub const fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Connects: to a host's broker at its socket, whose peer must run as
    /// the broker's uid, or to the child, through a socket pair whose other
    /// end the child alone receives. Nothing is written yet.
    pub async fn connect(&self) -> Result<BrokerConnection, BrokerError> {
        let stream = match &self.peer {
            Peer::User { socket, uid } => {
                let stream = UnixStream::connect(socket)
                    .await
                    .map_err(|_| BrokerError::Unreachable)?;
                let cred = stream.peer_cred().map_err(|_| BrokerError::Peer)?;
                if cred.uid() != *uid {
                    return Err(BrokerError::Peer);
                }
                stream
            }
            Peer::Child(child) => {
                let stream = child.connect().map_err(|_| BrokerError::Unreachable)?;
                stream
                    .set_nonblocking(true)
                    .and_then(|()| UnixStream::from_std(stream))
                    .map_err(|_| BrokerError::Unreachable)?
            }
        };
        Ok(BrokerConnection {
            stream,
            reply_timeout: self.reply_timeout,
        })
    }
}

/// A connection to the broker, good for one call: peer-checked, or the
/// child's over its channel.
#[derive(Debug)]
pub struct BrokerConnection {
    stream: UnixStream,
    reply_timeout: Duration,
}

/// The broker's answer to one call.
#[derive(Debug)]
pub struct BrokerReply {
    /// What happened.
    pub outcome: Outcome,
    /// The reply body, stripped (or, for a shape that streams, checked and
    /// whole); empty unless answered.
    pub body: Zeroizing<Vec<u8>>,
}

/// A reply as it arrives: its outcome first, then its body through
/// [`Self::next`]. A buffered shape's body comes as one chunk; a streamed
/// shape's ([`crate::Shape::streams`]) as many, up to [`MAX_STREAM`] bytes.
/// The whole reply must arrive within the client's reply timeout.
#[derive(Debug)]
pub struct BrokerStream {
    outcome: Outcome,
    stream: UnixStream,
    deadline: Instant,
    /// A buffered shape's body, not yet handed out; `None` for a streamed
    /// shape.
    whole: Option<Zeroizing<Vec<u8>>>,
    received: usize,
    /// How the body ended, once it has: clean (`None`) or cut.
    ended: Option<Option<Failure>>,
}

/// One step of a reply's body.
#[derive(Debug)]
pub enum StreamPart {
    /// The next bytes of the body.
    Chunk(Zeroizing<Vec<u8>>),
    /// The body ended clean: the chunks are the whole of it.
    End,
    /// The broker cut the body: every chunk taken so far must be dropped.
    Cut(Failure),
}

impl BrokerConnection {
    /// Sends one call with its key, and waits for the whole answer. The
    /// daemon's copy of the key is wiped once the frame is written. A reply
    /// for another call or digest counts as lost. A streamed body the broker
    /// cut comes back as [`Outcome::Failed`] with no body.
    pub async fn call(
        self,
        call: &CallHeader,
        body: &[u8],
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<BrokerReply, BrokerError> {
        let mut reply = self.open(call, body, secret).await?;
        let mut whole = Zeroizing::new(Vec::new());
        loop {
            match reply.next().await? {
                StreamPart::Chunk(chunk) if whole.is_empty() => whole = chunk,
                StreamPart::Chunk(chunk) => push_wiped(&mut whole, &chunk),
                StreamPart::End => break,
                StreamPart::Cut(reason) => {
                    return Ok(BrokerReply {
                        outcome: Outcome::Failed { reason },
                        body: Zeroizing::new(Vec::new()),
                    });
                }
            }
        }
        Ok(BrokerReply {
            outcome: reply.outcome,
            body: whole,
        })
    }

    /// Sends one call with its key, and waits for the reply's outcome; its
    /// body follows through [`BrokerStream::next`]. The daemon's copy of the
    /// key is wiped once the frame is written. A reply for another call or
    /// digest counts as lost.
    pub async fn open(
        mut self,
        call: &CallHeader,
        body: &[u8],
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<BrokerStream, BrokerError> {
        call.check(body).map_err(BrokerError::Refused)?;
        let written = write_call(&mut self.stream, call, body, &secret).await;
        drop(secret);
        written.map_err(|_| BrokerError::Lost)?;
        let deadline = Instant::now() + self.reply_timeout;
        let (reply, whole): (ReplyHeader, _) = if call.shape.streams() {
            let reply = tokio::time::timeout_at(deadline, read_reply_header(&mut self.stream))
                .await
                .map_err(|_| BrokerError::Lost)?
                .map_err(|_| BrokerError::Lost)?;
            (reply, None)
        } else {
            let (reply, body) = tokio::time::timeout_at(deadline, read_reply(&mut self.stream))
                .await
                .map_err(|_| BrokerError::Lost)?
                .map_err(|_| BrokerError::Lost)?;
            (reply, Some(body))
        };
        if reply.version != PROTOCOL_VERSION
            || reply.call != call.call
            || reply.digest != call.digest
        {
            return Err(BrokerError::Lost);
        }
        Ok(BrokerStream {
            outcome: reply.outcome,
            stream: self.stream,
            deadline,
            whole,
            received: 0,
            ended: None,
        })
    }
}

impl BrokerStream {
    /// What happened. For a streamed body, an answer here can still be cut.
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The body's next step. Once it has ended, every later call gives the
    /// same end. An error ends the reply: the call counts as lost.
    pub async fn next(&mut self) -> Result<StreamPart, BrokerError> {
        if let Some(end) = self.ended {
            return Ok(end.map_or(StreamPart::End, StreamPart::Cut));
        }
        if let Some(whole) = self.whole.take() {
            self.ended = Some(None);
            return Ok(if whole.is_empty() {
                StreamPart::End
            } else {
                StreamPart::Chunk(whole)
            });
        }
        let chunk = tokio::time::timeout_at(self.deadline, read_chunk(&mut self.stream))
            .await
            .map_err(|_| BrokerError::Lost)?
            .map_err(|_| BrokerError::Lost)?;
        if let Some(chunk) = chunk {
            self.received += chunk.len();
            if self.received > MAX_STREAM {
                return Err(BrokerError::Lost);
            }
            return Ok(StreamPart::Chunk(chunk));
        }
        let end = tokio::time::timeout_at(self.deadline, read_stream_end(&mut self.stream))
            .await
            .map_err(|_| BrokerError::Lost)?
            .map_err(|_| BrokerError::Lost)?;
        self.ended = Some(end);
        Ok(end.map_or(StreamPart::End, StreamPart::Cut))
    }
}
