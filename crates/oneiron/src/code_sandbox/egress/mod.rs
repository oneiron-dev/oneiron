//! The engine's open egress proxy. No guest network or credential proxy is
//! used as a transport. The owner allowlist is an optional narrowing dial.

mod dns;
mod fixture;
mod http;
mod name_gate;
mod receipt;

use crate::policy_model::{PolicyClassifyDecision, PolicyClassifyRequest, PolicyVerdictCategory};
use crate::{EntityId, Vault};
pub use dns::{UnusableResolver, exchange_dns_query};
pub use fixture::{FixtureForward, FixtureForwardError};
pub use name_gate::EgressNameRefusal;
use oneiron_container::{
    EgressRelay, HostNetFloor, HostNetPermit, HttpRequest, HttpResponse, UnmeteredFloor,
};
use oneiron_sandbox_contract::network::global_address;
pub use receipt::EgressReceipt;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// What admits a raw socket to an address (FIX 7652).
#[derive(Clone, Copy, PartialEq, Eq)]
enum RawAuthority {
    /// No allowlist, an allowlisted address or an owner raw endpoint grant:
    /// the guest's bytes go on unread.
    Open,
    /// A name of the allowlist bound to the address now: a stream's opening
    /// bytes must carry a name bound to it.
    Named,
}

/// Whether `host` is `domain` or a name under it, as the owner allowlist
/// matches: case and trailing dots aside, at a label boundary.
fn within(domain: &str, host: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == domain
        || host
            .strip_suffix(&domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

impl Vault {
    /// Lends guest network work this host's floor (FIX 5978, FIX 5979):
    /// every relay a run on this vault opens charges its guest's sockets and
    /// relayed datagrams to it. The first lend holds.
    pub fn lend_host_net_floor(&self, floor: Arc<dyn HostNetFloor>) {
        let _ = self.host_net_floor.set(floor);
    }

    /// Takes `fds` descriptors and `workers` threads of the floor this
    /// vault's host lent ([`Vault::lend_host_net_floor`]), looked up now, as
    /// a run's relay charges it; a vault no host lent one charges nothing.
    /// For a host relay that serves no run (FIX 7333).
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    pub fn acquire_host_net_floor(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        match self.host_net_floor.get() {
            Some(floor) => floor.acquire(fds, workers),
            None => UnmeteredFloor.acquire(fds, workers),
        }
    }
}

pub struct OpenEgressProxy {
    vault: Arc<Vault>,
    run_id: EntityId,
    config: EgressConfig,
    /// Each address a name of the owner allowlist was answered with, by
    /// that name, until the least TTL on its answer's chain ends (FIX 7652).
    /// An ended binding admits nothing: it names the name to look up again
    /// when its address is used.
    bindings: Mutex<HashMap<IpAddr, HashMap<String, Instant>>>,
    fixture: Option<std::path::PathBuf>,
    /// The fixture origin's one upstream (FIX 8061), none unless the host
    /// set one through [`OpenEgressProxy::with_fixture_forward`].
    fixture_forward: Option<FixtureForward>,
}
impl OpenEgressProxy {
    #[must_use]
    pub fn new(vault: Arc<Vault>, run_id: EntityId, config: EgressConfig) -> Self {
        Self {
            vault,
            run_id,
            config,
            bindings: Mutex::new(HashMap::new()),
            fixture: None,
            fixture_forward: None,
        }
    }
    #[must_use]
    pub fn with_fixture(mut self, directory: Option<std::path::PathBuf>) -> Self {
        self.fixture = directory;
        self
    }
    /// Has the fixture origin forward to `target` alone (FIX 8061), as
    /// [`FixtureForward::new`] checks it; `None` sets no forward. An origin
    /// that serves a directory takes none: the two modes never meet.
    ///
    /// # Errors
    /// The target rule `target` breaks, or
    /// [`FixtureForwardError::WithDirectory`].
    pub fn with_fixture_forward(
        mut self,
        target: Option<SocketAddrV4>,
    ) -> Result<Self, FixtureForwardError> {
        let forward = target.map(FixtureForward::new).transpose()?;
        if forward.is_some() && self.fixture.is_some() {
            return Err(FixtureForwardError::WithDirectory);
        }
        self.fixture_forward = forward;
        Ok(self)
    }
    fn domain_allowed(&self, host: &str) -> bool {
        self.config
            .allowed_domains
            .as_ref()
            .is_none_or(|domains| domains.iter().any(|domain| within(domain, host)))
    }
    /// What admits a raw socket to `target` over `protocol`, if anything: a
    /// public address, and then no allowlist, the address itself on it, an
    /// owner grant of the endpoint, or a name of it bound to the address now
    /// (FIX 7652). An ended binding is looked up again on this use.
    fn raw_authority(&self, target: SocketAddr, protocol: RawProtocol) -> Option<RawAuthority> {
        let ip = target.ip();
        if !global_address(ip) {
            return None;
        }
        let grants: Vec<&RawEndpointGrant> = self
            .config
            .raw_endpoints
            .iter()
            .filter(|grant| grant.port == target.port() && grant.protocol == protocol)
            .collect();
        if self.config.allowed_domains.is_none()
            || self.domain_allowed(&ip.to_string())
            || grants.iter().any(|grant| grant.address() == Some(ip))
        {
            return Some(RawAuthority::Open);
        }
        let granted = |name: &str| {
            grants
                .iter()
                .any(|grant| grant.address().is_none() && within(&grant.host, name))
        };
        if !grants.is_empty() && dns::bound_name(self, ip, granted).is_some() {
            return Some(RawAuthority::Open);
        }
        dns::bound_name(self, ip, |_| true).map(|_| RawAuthority::Named)
    }
    /// A stream to `target`, and whether a name gates its upload. A caller
    /// that reads no opening bytes (`reads_opening` false) is refused a
    /// stream a name would gate, before any connect.
    fn open_stream(
        &self,
        target: SocketAddr,
        reads_opening: bool,
    ) -> io::Result<(TcpStream, bool)> {
        let url = format!("tcp://{target}");
        let authority = self.raw_authority(target, RawProtocol::Tcp);
        if authority.is_none() || (authority == Some(RawAuthority::Named) && !reads_opening) {
            self.record(
                "connect",
                &url,
                &[],
                PolicyClassifyDecision::Block,
                PolicyVerdictCategory::None,
                None,
            )?;
            return Err(match authority {
                None => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "non-public or ungranted destination",
                ),
                Some(_) => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    EgressNameRefusal::Unverifiable {
                        target,
                        why: "this relay path reads no opening bytes",
                    },
                ),
            });
        }
        let (decision, category, policy_receipt) = self.policy(&url, &[])?;
        self.record("connect", &url, &[], decision, category, policy_receipt)?;
        if !Self::permits(decision) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "egress policy",
            ));
        }
        let stream = TcpStream::connect_timeout(&target, self.config.request_timeout)?;
        Ok((stream, authority == Some(RawAuthority::Named)))
    }
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let answer = (|| {
            if !self.domain_allowed(host) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "owner egress allowlist",
                ));
            }
            let name = host.to_owned();
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let answer = (name.as_str(), port)
                    .to_socket_addrs()
                    .map(|a| a.collect::<Vec<_>>());
                let _ = send.send(answer);
            });
            let addresses: Vec<_> = receive
                .recv_timeout(self.config.request_timeout)
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "engine DNS deadline"))??
                .into_iter()
                .filter(|a| global_address(a.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no public address",
                ));
            }
            // These addresses serve this request alone: a host lookup has no
            // TTL, so it binds no raw socket authority (FIX 7652).
            Ok(addresses)
        })();
        let bytes = answer
            .as_ref()
            .ok()
            .and_then(|a| serde_json::to_vec(a).ok())
            .unwrap_or_default();
        let decision = if answer.is_ok() {
            PolicyClassifyDecision::Allow
        } else {
            PolicyClassifyDecision::Block
        };
        self.record(
            "dns",
            &format!("dns://{host}"),
            &bytes,
            decision,
            PolicyVerdictCategory::None,
            None,
        )?;
        answer
    }
    fn policy(
        &self,
        url: &str,
        bytes: &[u8],
    ) -> io::Result<(
        PolicyClassifyDecision,
        PolicyVerdictCategory,
        Option<String>,
    )> {
        // A read is still an outbound operation. The owner plane is opt-in;
        // its usual fail-open/Skipped semantics are unchanged.
        let request =
            PolicyClassifyRequest::action(format!("{url}\n{}", String::from_utf8_lossy(bytes)))
                .with_caller_ref(self.run_id.to_hex());
        let enforcement = self
            .vault
            .enforce_policy_model(request)
            .map_err(io::Error::other)?;
        Ok((
            enforcement.verdict.decision,
            enforcement.verdict.category,
            enforcement.receipt_ref,
        ))
    }
    fn record(
        &self,
        operation: &str,
        url: &str,
        bytes: &[u8],
        decision: PolicyClassifyDecision,
        category: PolicyVerdictCategory,
        policy_receipt: Option<String>,
    ) -> io::Result<()> {
        self.vault
            .append_egress_receipt(&EgressReceipt {
                run_id: self.run_id,
                operation: operation.to_owned(),
                url: url.to_owned(),
                content_hash: *blake3::hash(bytes).as_bytes(),
                content_bytes: bytes.len() as u64,
                decision,
                category,
                policy_receipt,
            })
            .map(|_| ())
            .map_err(io::Error::other)
    }
    fn permits(decision: PolicyClassifyDecision) -> bool {
        matches!(
            decision,
            PolicyClassifyDecision::Allow
                | PolicyClassifyDecision::Warn
                | PolicyClassifyDecision::Skipped(_)
        )
    }
}
/// The floor the vault's host lent ([`Vault::lend_host_net_floor`]), looked
/// up at each charge, so a run opened before the lend is charged once it
/// lands. A vault no host lent one charges nothing.
impl HostNetFloor for OpenEgressProxy {
    fn acquire(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        match self.vault.host_net_floor.get() {
            Some(floor) => floor.acquire(fds, workers),
            None => UnmeteredFloor.acquire(fds, workers),
        }
    }

    fn acquire_bytes(&self, bytes: u64) -> io::Result<HostNetPermit> {
        match self.vault.host_net_floor.get() {
            Some(floor) => floor.acquire_bytes(bytes),
            None => UnmeteredFloor.acquire_bytes(bytes),
        }
    }
}
impl EgressRelay for OpenEgressProxy {
    fn host_net_floor(&self) -> &dyn HostNetFloor {
        self
    }
    fn record_abandoned(&self, manifest: &oneiron_container::SessionManifest) -> io::Result<()> {
        self.vault
            .append_sandbox_abandon_receipt(self.run_id, manifest)
            .map(|_| ())
            .map_err(io::Error::other)
    }

    fn record_session(&self, manifest: &oneiron_container::SessionManifest) -> io::Result<()> {
        self.vault
            .append_sandbox_manifest_receipt(self.run_id, manifest)
            .map(|_| ())
            .map_err(io::Error::other)
    }
    /// A loopback call the guest fence refused is a blocked receipt naming
    /// its address, as a refused connect is; no network work happens.
    fn record_refusal(&self, refusal: &oneiron_container::LoopbackRefusal) -> io::Result<()> {
        self.record(
            &format!("loopback_{}", refusal.operation.as_str()),
            &refusal.address.to_string(),
            refusal.reason.as_str().as_bytes(),
            PolicyClassifyDecision::Block,
            PolicyVerdictCategory::None,
            None,
        )
    }
    fn authorize_datagram(&self, target: SocketAddr) -> io::Result<()> {
        let allowed = target.port() == 53 || self.raw_authority(target, RawProtocol::Udp).is_some();
        self.record(
            "connect_udp",
            &format!("udp://{target}"),
            &[],
            if allowed {
                PolicyClassifyDecision::Allow
            } else {
                PolicyClassifyDecision::Block
            },
            PolicyVerdictCategory::None,
            None,
        )?;
        if allowed {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-public datagram destination",
            ))
        }
    }

    fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        self.open_stream(target, false).map(|(stream, _)| stream)
    }
    /// The name gate's stream (FIX 7652): one a name of the allowlist
    /// admits is gated on the name its opening bytes carry.
    fn connect_stream(&self, target: SocketAddr) -> io::Result<(TcpStream, bool)> {
        self.open_stream(target, true)
    }
    fn open_upload(
        &self,
        target: SocketAddr,
        guest: &mut dyn io::Read,
        alive: &AtomicBool,
    ) -> io::Result<Vec<u8>> {
        name_gate::open_upload(self, target, guest, alive)
    }
    fn datagram(&self, target: SocketAddr, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if target.port() == 53 {
            return dns::answer(self, bytes);
        }
        let url = format!("udp://{target}");
        if self.raw_authority(target, RawProtocol::Udp).is_none() {
            self.record(
                "datagram",
                &url,
                bytes,
                PolicyClassifyDecision::Block,
                PolicyVerdictCategory::None,
                None,
            )?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-public or ungranted destination",
            ));
        }
        let (decision, category, policy_receipt) = self.policy(&url, bytes)?;
        self.record(
            "datagram_request",
            &url,
            bytes,
            decision,
            category.clone(),
            policy_receipt.clone(),
        )?;
        if !Self::permits(decision) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "egress policy",
            ));
        }
        let socket = UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_read_timeout(Some(self.config.request_timeout))?;
        socket.connect(target)?;
        socket.send(bytes)?;
        let mut response = vec![0; 65536];
        let result = socket.recv(&mut response);
        if let Ok(n) = result {
            response.truncate(n);
        } else {
            response.clear();
        }
        self.record(
            "datagram_response",
            &url,
            &response,
            decision,
            category,
            policy_receipt,
        )?;
        result.map(|_| response)
    }
    fn fetch(&self, request: HttpRequest) -> io::Result<HttpResponse> {
        if let Some(answer) = fixture::fetch(self, &request) {
            return answer;
        }
        http::fetch(self, request)
    }
    fn transferred(&self, target: SocketAddr, content_hash: [u8; 32], bytes: u64) {
        let receipt = EgressReceipt {
            run_id: self.run_id,
            operation: "stream_bytes".into(),
            url: format!("tcp://{target}"),
            content_hash,
            content_bytes: bytes,
            decision: PolicyClassifyDecision::Allow,
            category: PolicyVerdictCategory::None,
            policy_receipt: None,
        };
        if let Err(error) = self.vault.append_egress_receipt(&receipt) {
            tracing::error!(%error, "egress transfer receipt failed");
        }
    }
}
