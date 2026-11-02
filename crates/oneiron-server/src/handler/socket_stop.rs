//! An upgraded socket's transport under its server's stop (OF-237).
//!
//! [`crate::embedded::UpgradeHold::run`] hands each socket the server's stop,
//! and the socket answers it itself: its loop stops reading at its next wait,
//! a send held up by a peer that stopped reading gives way, the transport
//! closes, and the socket ends only once every call it admitted has finished.
//! An embedded channel or mesh carries the lifetime, as plain and managed
//! serve do through [`crate::embedded::upgrade_lifetime`]; a request
//! without one runs its socket as before, its stop never turning.

use std::ops::{Deref, DerefMut};

use axum::extract::ws::{Message as WsMessage, WebSocket};

use super::hello::{HelloOutcome, await_protocol_hello};
use super::transport::GuardedTransport;
use crate::embedded::UpgradeStop;

/// A socket's guarded transport under its engine's stop. The hello and every
/// send wait on the peer; here each gives way to the stop, the hello as a
/// peer that went away and a send as one that failed, so the loop waiting on
/// it ends. Everything else is the transport's own.
pub(super) struct StoppingTransport {
    transport: GuardedTransport<WebSocket>,
    stop: UpgradeStop,
}

impl StoppingTransport {
    pub(super) fn new(transport: GuardedTransport<WebSocket>, stop: UpgradeStop) -> Self {
        Self { transport, stop }
    }

    /// The client's protocol hello, or [`HelloOutcome::Disconnected`] once
    /// the engine stops first.
    pub(super) async fn hello(&mut self) -> HelloOutcome {
        self.stop
            .until(await_protocol_hello(&mut self.transport))
            .await
            .unwrap_or(HelloOutcome::Disconnected)
    }

    /// [`GuardedTransport::send_binary`], or `false` once the engine stops.
    #[must_use]
    pub(super) async fn send_binary(&mut self, data: Vec<u8>) -> bool {
        self.stop
            .until(self.transport.send_binary(data))
            .await
            .unwrap_or(false)
    }

    /// [`GuardedTransport::send_unguarded_close_frame`], given up once the
    /// engine stops.
    pub(super) async fn send_unguarded_close_frame(&mut self, close: WsMessage) {
        let _ = self
            .stop
            .until(self.transport.send_unguarded_close_frame(close))
            .await;
    }
}

impl Deref for StoppingTransport {
    type Target = GuardedTransport<WebSocket>;

    fn deref(&self) -> &Self::Target {
        &self.transport
    }
}

impl DerefMut for StoppingTransport {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transport
    }
}
