//! Moved from `crates/oneiron/src/code_sandbox/egress/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_sandbox::egress::receipt::EgressReceipt;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use std::time::Instant;

/// Host-owned limits, shared by all transports in a session.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressConfig {
    pub allowed_domains: Option<Vec<String>>,
    /// The owner's raw endpoint grants (FIX 7652). Each admits raw sockets
    /// to its endpoint unread, where a domain of `allowed_domains` alone
    /// admits a stream only once the name its opening bytes carry is bound
    /// to the address.
    pub raw_endpoints: Vec<RawEndpointGrant>,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_redirects: u8,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            allowed_domains: None,
            raw_endpoints: Vec::new(),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: 32 * 1024 * 1024,
            max_redirects: 3,
        }
    }
}

impl EgressConfig {
    pub fn from_env() -> io::Result<Self> {
        match std::env::var_os("ONEIRON_EGRESS_CONFIG") {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?).map_err(io::Error::other),
            None => Ok(Self::default()),
        }
    }
}

/// An owner grant of raw socket authority to one endpoint (FIX 7652, CALLS):
/// its streams and datagrams go on unread, past the name gate a domain of
/// the allowlist alone keeps. A grant is the owner's own act, written in the
/// host's egress config.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEndpointGrant {
    /// An IP address, or a name matched as `allowed_domains` matches its
    /// entries, which grants an address it is bound to now.
    pub host: String,
    pub port: u16,
    pub protocol: RawProtocol,
}

/// The transport a [`RawEndpointGrant`] admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawProtocol {
    Tcp,
    Udp,
}

impl RawEndpointGrant {
    /// The address this grant names, when its host is an IP literal.
    fn address(&self) -> Option<IpAddr> {
        self.host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()
    }
}
pub mod receipt;
