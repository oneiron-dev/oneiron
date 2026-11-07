//! Bounded host/guest network transport over the no-NIC VM's private vsock.
//!
//! Each reply names its phase (FIX 6298). A datagram gets two replies:
//! [`RelayReply::Admitted`] once the host holds its room, then its
//! [`RelayReply::Answer`]. Every other request gets one `Answer`; a connect
//! that succeeds then carries the raw stream. A request the host has no room
//! for, or that fails before admission, gets one `Answer` with its errno and
//! floor. A reply without its phase does not decode. The code guest image
//! carries the guest side of this wire: rebuild it from the same commit as
//! the host.
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
};

/// One request on the VM's egress channel. `Refusal` carries a loopback call
/// the VM's fence refused to the host's receipt: it opens nothing.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayRequest {
    Connect { target: SocketAddr },
    Datagram { target: SocketAddr, bytes: Vec<u8> },
    AuthorizeDatagram { target: SocketAddr },
    Fetch { request: crate::HttpRequest },
    Refusal(crate::LoopbackRefusal),
}
/// One reply on the VM's egress channel, tagged with its phase (FIX 6298).
#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayReply {
    /// The host admitted a datagram and holds its room until the datagram's
    /// `Answer`. The VM acknowledges the guest's send only on this reply.
    Admitted,
    /// The request's last reply.
    Answer(RelayAnswer),
}
/// A request's last reply: its bytes, or the errno it failed with.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAnswer {
    pub errno: i32,
    pub bytes: Vec<u8>,
    /// The host floor that back-pressured the request, when one did: its
    /// `errno` is then `EAGAIN` (FIX 5979).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<String>,
}
impl RelayReply {
    /// The last reply of a request that succeeded with `bytes`.
    #[must_use]
    pub fn answered(bytes: Vec<u8>) -> Self {
        Self::Answer(RelayAnswer {
            errno: 0,
            bytes,
            floor: None,
        })
    }
}
const MAX_RELAY_FRAME: usize = 2 * 1024 * 1024;
pub fn write_relay<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_RELAY_FRAME {
        return Err(io::Error::other("relay frame bound"));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)
}
pub fn read_relay<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> io::Result<T> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_RELAY_FRAME {
        return Err(io::Error::other("relay frame bound"));
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
