//! Bounded host/guest network transport over the no-NIC VM's private vsock.
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
    Refusal(crate::LoopbackRefusal),
}
#[derive(Serialize, Deserialize)]
pub struct RelayReply {
    pub errno: i32,
    pub bytes: Vec<u8>,
    /// The host floor that back-pressured the request, when one did: its
    /// `errno` is then `EAGAIN` (FIX 5979).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<String>,
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
