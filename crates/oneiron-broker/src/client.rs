//! The daemon's side of the socket.
//!
//! The daemon checks the call, connects and checks the peer, and only then
//! reads the key at the custody door and writes the frame. So a refused call,
//! or a broker that is not there, never costs a key read.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixStream;
use zeroize::Zeroizing;

use crate::frame::{read_reply, write_call};
use crate::peer::own_uid;
use crate::{BrokerError, CallHeader, ChildBroker, Isolation, Outcome, PROTOCOL_VERSION};

/// Where the daemon's broker listens, and who it must be.
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
    /// The daemon's own child.
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

    /// The same-user `child` (`#broker-same-user-open`): a peer on its
    /// socket must be that child.
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
            Peer::Child(child) => child.ensure().map(drop),
        }
    }

    /// How this broker is isolated, for the call's receipt.
    #[must_use]
    pub const fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Connects and checks the peer: the broker's uid, and for the child,
    /// its pid too. Nothing is written yet.
    pub async fn connect(&self) -> Result<BrokerConnection, BrokerError> {
        let (socket, uid, pid) = match &self.peer {
            Peer::User { socket, uid } => (socket.as_path(), *uid, None),
            Peer::Child(child) => {
                let pid = child.ensure().map_err(|_| BrokerError::Unreachable)?;
                (child.socket(), own_uid(), Some(pid))
            }
        };
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|_| BrokerError::Unreachable)?;
        let cred = stream.peer_cred().map_err(|_| BrokerError::Peer)?;
        let peer_pid = cred.pid().and_then(|peer| u32::try_from(peer).ok());
        if cred.uid() != uid || pid.is_some_and(|pid| peer_pid != Some(pid)) {
            return Err(BrokerError::Peer);
        }
        Ok(BrokerConnection {
            stream,
            reply_timeout: self.reply_timeout,
        })
    }
}

/// A peer-checked connection, good for one call.
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
    /// The stripped reply body; empty unless answered.
    pub body: Zeroizing<Vec<u8>>,
}

impl BrokerConnection {
    /// Sends one call with its key, and waits for the answer. The daemon's
    /// copy of the key is wiped once the frame is written. A reply for another
    /// call or digest counts as lost.
    pub async fn call(
        mut self,
        call: &CallHeader,
        body: &[u8],
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<BrokerReply, BrokerError> {
        call.check(body).map_err(BrokerError::Refused)?;
        let written = write_call(&mut self.stream, call, body, &secret).await;
        drop(secret);
        written.map_err(|_| BrokerError::Lost)?;
        let (reply, body) = tokio::time::timeout(self.reply_timeout, read_reply(&mut self.stream))
            .await
            .map_err(|_| BrokerError::Lost)?
            .map_err(|_| BrokerError::Lost)?;
        if reply.version != PROTOCOL_VERSION
            || reply.call != call.call
            || reply.digest != call.digest
        {
            return Err(BrokerError::Lost);
        }
        Ok(BrokerReply {
            outcome: reply.outcome,
            body,
        })
    }
}
