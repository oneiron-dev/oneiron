//! Managed API and artifact connections on the process's descriptor line
//! (FIX 6299): the same ledger the vault's guests' network work charges,
//! which the vault server's construction sized and set to ask its
//! Connections question.
//!
//! Each accepted socket waits for one permit before it is served, and the
//! permit goes with the socket, through keep-alive and upgrades, until the
//! socket closes. Past the floor the socket in hand waits its turn and the
//! next ones wait in the backlog: queued, never refused. The listener keeps
//! its own peer type, so a UNIX peer's kernel credentials still name it, and
//! a shutdown that lands while a socket waits drops that socket unserved
//! and its place in line with it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::serve::Listener;
use oneiron::host_descriptors::descriptor_line;
use oneiron::work_line::LinePermit;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `listener`, each accepted socket admitted on the descriptor line.
pub(crate) struct AdmittedListener<L> {
    listener: L,
}

impl<L> AdmittedListener<L> {
    pub(super) fn new(listener: L) -> Self {
        Self { listener }
    }
}

impl<L: Listener> Listener for AdmittedListener<L> {
    type Io = AdmittedIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (io, addr) = self.listener.accept().await;
        let permit = descriptor_line().admit_in_line_untimed((), None).await;
        (
            AdmittedIo {
                io,
                _permit: permit,
            },
            addr,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// An accepted socket and the descriptor permit it holds until it closes.
pub(crate) struct AdmittedIo<Io> {
    io: Io,
    _permit: LinePermit,
}

impl<Io> AdmittedIo<Io> {
    /// The socket itself, as its peer's identity is read off it.
    pub(crate) fn get_ref(&self) -> &Io {
        &self.io
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for AdmittedIo<Io> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for AdmittedIo<Io> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
