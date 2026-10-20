//! The native microVM supervisor's network reaches only the engine's vsock.
use oneiron_container::{
    EgressRelay, HttpRequest, HttpResponse, RelayReply, RelayRequest, read_relay, write_relay,
};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    os::fd::OwnedFd,
};
pub(crate) struct VsockRelay;
impl VsockRelay {
    fn request(&self, request: &RelayRequest) -> io::Result<(std::fs::File, RelayReply)> {
        let mut stream = super::boot::connect_vsock_port(54).map_err(io::Error::other)?;
        write_relay(&mut stream, request)?;
        let reply: RelayReply = read_relay(&mut stream)?;
        if reply.errno != 0 {
            // The host floor's back-pressure keeps its name (FIX 5979).
            return Err(reply
                .floor
                .as_deref()
                .and_then(oneiron_container::known_floor)
                .map_or_else(
                    || io::Error::from_raw_os_error(reply.errno),
                    oneiron_container::floor_saturated,
                ));
        }
        Ok((stream, reply))
    }
}
impl EgressRelay for VsockRelay {
    fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        let (stream, _) = self.request(&RelayRequest::Connect { target })?;
        let fd: OwnedFd = stream.into();
        // A connected vsock stream supports the same read/write, shutdown,
        // duplication and timeout operations the notifier transport uses.
        Ok(TcpStream::from(fd))
    }
    fn authorize_datagram(&self, target: SocketAddr) -> io::Result<()> {
        self.request(&RelayRequest::AuthorizeDatagram { target })
            .map(|_| ())
    }
    fn datagram(&self, target: SocketAddr, bytes: &[u8]) -> io::Result<Vec<u8>> {
        self.request(&RelayRequest::Datagram {
            target,
            bytes: bytes.to_vec(),
        })
        .map(|(_, r)| r.bytes)
    }
    fn fetch(&self, _: HttpRequest) -> io::Result<HttpResponse> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "browser HTTP uses the host CDP proxy",
        ))
    }
    fn record_session(&self, _: &oneiron_container::SessionManifest) -> io::Result<()> {
        Ok(())
    }
    fn record_abandoned(&self, _: &oneiron_container::SessionManifest) -> io::Result<()> {
        Ok(())
    }
    fn transferred(&self, _: SocketAddr, _: [u8; 32], _: u64) {}
    /// The host keeps the receipt: the refusal goes on the existing egress
    /// channel (port 54), and opens nothing there.
    fn record_refusal(&self, refusal: &oneiron_container::LoopbackRefusal) -> io::Result<()> {
        self.request(&RelayRequest::Refusal(refusal.clone()))
            .map(|_| ())
    }
    /// The VM's own threads and descriptors are the VM's. The host charges
    /// each vsock request to its own floor before it starts it and answers
    /// a full floor with `EAGAIN` naming it (FIX 5979).
    fn host_net_floor(&self) -> &dyn oneiron_container::HostNetFloor {
        &oneiron_container::UnmeteredFloor
    }
}
