//! The native microVM supervisor's network reaches only the engine's vsock.
//!
//! A datagram is admitted on the host before the guest's send is
//! acknowledged (FIX 6298): the notifier prepares it here, this relay reads
//! the host's `Admitted`, and only the worker that answers it reads the
//! host's `Answer`. Rebuild the code guest image from the same commit as the
//! host: this agent and the host speak one wire.
use oneiron_container::{
    EgressRelay, HttpRequest, HttpResponse, PreparedDatagram, RelayAnswer, RelayReply,
    RelayRequest, read_relay, write_relay,
};
use std::{
    fs::File,
    io,
    net::{SocketAddr, TcpStream},
    os::fd::OwnedFd,
    sync::Arc,
};
pub(crate) struct VsockRelay;
impl VsockRelay {
    /// Sends `request` on a fresh channel and reads the host's first reply.
    fn exchange(&self, request: &RelayRequest) -> io::Result<(File, RelayReply)> {
        let mut stream = super::boot::connect_vsock_port(54).map_err(io::Error::other)?;
        write_relay(&mut stream, request)?;
        let reply: RelayReply = read_relay(&mut stream)?;
        Ok((stream, reply))
    }
    /// A request the host answers once: a connect, an authorization or a
    /// refusal. The channel is returned for a connect's raw stream.
    fn request(&self, request: &RelayRequest) -> io::Result<(File, Vec<u8>)> {
        match self.exchange(request)? {
            (stream, RelayReply::Answer(answer)) => {
                answer_bytes(answer).map(|bytes| (stream, bytes))
            }
            (_, RelayReply::Admitted) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay admitted a request it answers once",
            )),
        }
    }
    /// Sends a datagram and returns its channel once the host has admitted
    /// it (FIX 6298). A host floor with no room answers `EAGAIN` naming the
    /// floor, before admission.
    fn admit(&self, target: SocketAddr, bytes: Vec<u8>) -> io::Result<File> {
        match self.exchange(&RelayRequest::Datagram { target, bytes })? {
            (stream, RelayReply::Admitted) => Ok(stream),
            (_, RelayReply::Answer(answer)) => match answer_bytes(answer) {
                Err(error) => Err(error),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "relay answered a datagram it had not admitted",
                )),
            },
        }
    }
}
/// Reads an admitted datagram's answer on its channel.
fn read_answer(mut stream: File) -> io::Result<Vec<u8>> {
    let reply: RelayReply = read_relay(&mut stream)?;
    match reply {
        RelayReply::Answer(answer) => answer_bytes(answer),
        RelayReply::Admitted => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "relay admitted a datagram twice",
        )),
    }
}
/// The bytes of a request's last reply, or its failure. The host floor's
/// back-pressure keeps its name (FIX 5979).
fn answer_bytes(answer: RelayAnswer) -> io::Result<Vec<u8>> {
    if answer.errno == 0 {
        return Ok(answer.bytes);
    }
    Err(answer
        .floor
        .as_deref()
        .and_then(oneiron_container::known_floor)
        .map_or_else(
            || io::Error::from_raw_os_error(answer.errno),
            oneiron_container::floor_saturated,
        ))
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
        read_answer(self.admit(target, bytes.to_vec())?)
    }
    /// Returns once the host has admitted the datagram; the worker that owns
    /// the prepared datagram reads its answer (FIX 6298).
    fn prepare_datagram(
        self: Arc<Self>,
        target: SocketAddr,
        bytes: Vec<u8>,
    ) -> io::Result<PreparedDatagram> {
        let stream = self.admit(target, bytes)?;
        Ok(PreparedDatagram::new(move || read_answer(stream)))
    }
    fn fetch(&self, request: HttpRequest) -> io::Result<HttpResponse> {
        let (_, bytes) = self.request(&RelayRequest::Fetch { request })?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
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
    /// The VM's own threads and descriptors are the VM's, so this floor
    /// charges nothing. The host charges each vsock request to its own floor
    /// before it starts it and answers a full floor with `EAGAIN` naming it
    /// (FIX 5979). A datagram is admitted there before its send is
    /// acknowledged here (FIX 6298).
    fn host_net_floor(&self) -> &dyn oneiron_container::HostNetFloor {
        &oneiron_container::UnmeteredFloor
    }
}
