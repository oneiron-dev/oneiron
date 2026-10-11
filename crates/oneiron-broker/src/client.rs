//! The daemon's side of the socket.
//!
//! The daemon checks the call, connects and checks the peer, and only then
//! reads the key at the custody door and writes the frame. So a refused call,
//! or a broker that is not there, never costs a key read.

use std::path::PathBuf;
use std::time::Duration;

use tokio::net::UnixStream;
use zeroize::Zeroizing;

use crate::frame::{read_reply, write_call};
use crate::peer::own_uid;
use crate::{BrokerError, CallHeader, Isolation, Outcome, PROTOCOL_VERSION};

/// Where the daemon's broker listens, and who it must be.
#[derive(Debug, Clone)]
pub struct BrokerClient {
    socket: PathBuf,
    broker_uid: u32,
    isolation: Isolation,
    reply_timeout: Duration,
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
            socket,
            broker_uid,
            isolation,
            reply_timeout,
        })
    }

    /// How this broker is isolated, for the call's receipt.
    #[must_use]
    pub const fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Connects and checks the peer's uid. Nothing is written yet.
    pub async fn connect(&self) -> Result<BrokerConnection, BrokerError> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| BrokerError::Unreachable)?;
        let uid = stream.peer_cred().map_err(|_| BrokerError::Peer)?.uid();
        if uid != self.broker_uid {
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
