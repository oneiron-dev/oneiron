//! A native node batch stays in the existing split slot until socket release.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use super::node_batch::PreparedNodeBatch;
use crate::Vault;
use crate::authority::PeerMachine;
use crate::sync::carrier::SyncSocket;
use crate::sync::client::SyncClient;

pub(super) struct ConnectionSocket {
    socket: SyncSocket,
    vault: Arc<Vault>,
    peer: PeerMachine,
}

pub(super) enum OutgoingMessage {
    Frame(Message),
    NodeBatch(PreparedNodeBatch),
}

impl Stream for ConnectionSocket {
    type Item = Result<Message, WsError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().socket).poll_next(cx)
    }
}

impl Sink<OutgoingMessage> for ConnectionSocket {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().socket).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: OutgoingMessage) -> Result<(), WsError> {
        let this = self.get_mut();
        let message = match item {
            OutgoingMessage::Frame(message) => message,
            OutgoingMessage::NodeBatch(batch) => {
                Message::Binary(batch.into_frame(&this.vault, this.peer).into())
            }
        };
        Pin::new(&mut this.socket).start_send(message)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().socket).poll_close(cx)
    }
}

pub(super) struct WsSink {
    inner: SplitSink<ConnectionSocket, OutgoingMessage>,
}

pub(super) type WsSource = SplitStream<ConnectionSocket>;

/// The peer comes from this upgrade's original home proof, not from a frame.
pub(super) fn split(socket: SyncSocket, client: &SyncClient) -> (WsSink, WsSource) {
    let (inner, read) = ConnectionSocket {
        socket,
        vault: client.vault.clone(),
        peer: client.home_peer,
    }
    .split();
    (WsSink { inner }, read)
}

pub(super) fn reunite(read: WsSource, write: WsSink) -> Result<SyncSocket, String> {
    read.reunite(write.inner)
        .map(|socket| socket.socket)
        .map_err(|error| error.to_string())
}

impl WsSink {
    pub(super) async fn send_node_batch(
        &mut self,
        batch: PreparedNodeBatch,
    ) -> Result<(), WsError> {
        self.inner.send(OutgoingMessage::NodeBatch(batch)).await
    }
}

impl Sink<Message> for WsSink {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, message: Message) -> Result<(), WsError> {
        Pin::new(&mut self.get_mut().inner).start_send(OutgoingMessage::Frame(message))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}
