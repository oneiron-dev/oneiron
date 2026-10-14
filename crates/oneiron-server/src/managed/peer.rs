//! Kernel-verified local transport peer, not a public caller IP.
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::{UnixListener, unix::UCred};

#[derive(Clone, Debug)]
pub(crate) struct UnixPeer(Option<UCred>);

impl UnixPeer {
    pub(crate) fn verified(&self) -> bool {
        self.0.is_some()
    }

    /// A peer the kernel verified as this test process, read off a real
    /// socket pair. Needs a Tokio runtime.
    #[cfg(test)]
    pub(crate) fn verified_for_test() -> Self {
        let (socket, _other) = tokio::net::UnixStream::pair().expect("socket pair");
        Self(Some(socket.peer_cred().expect("peer credentials")))
    }
}

impl Connected<IncomingStream<'_, UnixListener>> for UnixPeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        // The socket owns this identity: no HTTP header can provide it. If
        // credential lookup fails, the signing transport fails closed.
        Self(stream.io().peer_cred().ok())
    }
}
