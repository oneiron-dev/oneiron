//! Private host-to-fence streams over a native VM's separate vsock door.
//!
//! Data and directional EOF are framed: Firecracker treats a host Unix-socket
//! EOF as a shutdown of both vsock directions, not just the host's write side.

mod bridge;
mod guest;
mod host;
mod io;

pub use guest::{bind as bind_guest, serve as serve_guest};
pub use host::HostEndpoint;

/// Trusted PID 1's ingress listener; 52, 53 and 54 keep their existing roles.
pub const PORT: u32 = 55;

// The existing loopback blocked-call cadence, not an admission deadline.
const POLL_MS: i32 = 250;
// A data frame's geometry, not a connection's total byte allowance.
const CHUNK: usize = 32 * 1024;
const CLOSED: u32 = u32::MAX;

fn request(token: &str, target: std::net::SocketAddr) -> std::io::Result<[u8; 51]> {
    if token.len() != 32 {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut bytes = [0; 51];
    bytes[..32].copy_from_slice(token.as_bytes());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes[32] = 4;
            bytes[33..37].copy_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes[32] = 6;
            bytes[33..49].copy_from_slice(&ip.octets());
        }
    }
    bytes[49..].copy_from_slice(&target.port().to_be_bytes());
    Ok(bytes)
}

fn target(bytes: &[u8; 51], token: &str) -> std::io::Result<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    if token.len() != 32 || &bytes[..32] != token.as_bytes() {
        return Err(std::io::Error::from_raw_os_error(libc::EACCES));
    }
    let ip = match bytes[32] {
        4 => IpAddr::V4(Ipv4Addr::new(bytes[33], bytes[34], bytes[35], bytes[36])),
        6 => {
            let mut address = [0; 16];
            address.copy_from_slice(&bytes[33..49]);
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
    };
    Ok(SocketAddr::new(
        ip,
        u16::from_be_bytes([bytes[49], bytes[50]]),
    ))
}
