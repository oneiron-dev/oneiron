//! An admitted connection and its streams. Every stream open and accept,
//! and every send and receive on a stream, checks the live pairing policy
//! again, so a withdrawn grant or a changed endpoint key refuses the next one.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use iroh::endpoint::Connection;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    AcceptPolicy, MachineId, MeshConnection, MeshDuplex, MeshError, MeshFuture, MeshStream,
};

const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Debug)]
pub(super) struct IrohConnection {
    pub(super) machine: MachineId,
    pub(super) alpn: Vec<u8>,
    pub(super) inner: Connection,
    pub(super) policy: AcceptPolicy,
    pub(super) incoming: bool,
}
impl IrohConnection {
    /// Refuses once the live policy no longer admits this machine under this
    /// protocol at this endpoint key.
    pub(super) fn check(&self) -> Result<(), MeshError> {
        let key = *self.inner.remote_id().as_bytes();
        if self.incoming {
            if self.policy.inbound(key, &self.alpn)? != self.machine {
                return Err(MeshError::Refused);
            }
        } else if self.policy.outbound(self.machine, &self.alpn)?.endpoint_key != key {
            return Err(MeshError::Refused);
        }
        Ok(())
    }
}
impl MeshConnection for IrohConnection {
    fn machine(&self) -> MachineId {
        self.machine
    }
    fn alpn(&self) -> &[u8] {
        &self.alpn
    }
    fn open_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohStream {
                send,
                recv,
                grant: StreamGrant {
                    policy: self.policy.clone(),
                    machine: self.machine,
                    alpn: self.alpn.clone(),
                    endpoint_key: *self.inner.remote_id().as_bytes(),
                    incoming: self.incoming,
                },
            }) as Box<dyn MeshStream>)
        })
    }
    fn accept_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .accept_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohStream {
                send,
                recv,
                grant: StreamGrant {
                    policy: self.policy.clone(),
                    machine: self.machine,
                    alpn: self.alpn.clone(),
                    endpoint_key: *self.inner.remote_id().as_bytes(),
                    incoming: self.incoming,
                },
            }) as Box<dyn MeshStream>)
        })
    }
    fn endpoint_key(&self) -> [u8; 32] {
        *self.inner.remote_id().as_bytes()
    }
    fn open_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohDuplex {
                send,
                recv,
                _connection: self.inner.clone(),
            }) as Box<dyn MeshDuplex>)
        })
    }
    fn accept_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .accept_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohDuplex {
                send,
                recv,
                _connection: self.inner.clone(),
            }) as Box<dyn MeshDuplex>)
        })
    }
    fn close(&self) {
        self.inner.close(0u32.into(), b"closed");
    }
}

/// One bidirectional QUIC stream as a byte pipe. It keeps a handle to its
/// connection: the last handle dropped closes the connection.
struct IrohDuplex {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    _connection: Connection,
}
impl AsyncRead for IrohDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}
impl AsyncWrite for IrohDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
#[derive(Debug)]
struct StreamGrant {
    policy: AcceptPolicy,
    machine: MachineId,
    alpn: Vec<u8>,
    endpoint_key: [u8; 32],
    incoming: bool,
}
impl StreamGrant {
    fn check(&self) -> Result<(), MeshError> {
        if self.incoming {
            if self.policy.inbound(self.endpoint_key, &self.alpn)? != self.machine {
                return Err(MeshError::Refused);
            }
        } else if self.policy.outbound(self.machine, &self.alpn)?.endpoint_key != self.endpoint_key
        {
            return Err(MeshError::Refused);
        }
        Ok(())
    }
}
/// The application error code of a stream this side abandoned
/// ([`MeshStream::reset`]).
const STREAM_ABANDONED: iroh::endpoint::VarInt = iroh::endpoint::VarInt::from_u32(0);
struct IrohStream {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    grant: StreamGrant,
}
impl MeshStream for IrohStream {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()> {
        Box::pin(async move {
            self.grant.check()?;
            if bytes.len() > MAX_MESSAGE {
                return Err(MeshError::Unavailable);
            }
            self.send
                .write_all(bytes)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.send
                .finish()
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.grant.check()
        })
    }
    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.grant.check()?;
            let bytes = self
                .recv
                .read_to_end(MAX_MESSAGE)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.grant.check()?;
            Ok(bytes)
        })
    }
    fn delivered(&mut self) -> MeshFuture<'_, ()> {
        // The finished write half's end: the peer acknowledged all of it,
        // or stopped the stream.
        Box::pin(async move {
            self.send
                .stopped()
                .await
                .map(drop)
                .map_err(|e| MeshError::Io(e.to_string()))
        })
    }
    fn reset(&mut self) {
        // A half that has already ended answers ClosedStream: nothing is
        // left to abandon on it.
        drop(self.send.reset(STREAM_ABANDONED));
        drop(self.recv.stop(STREAM_ABANDONED));
    }
}
