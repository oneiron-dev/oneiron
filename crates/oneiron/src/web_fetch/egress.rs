//! The managed (hosted) node's web-fetch egress guard (SCAN C447). A hosted
//! node's fetcher never reaches the infrastructure it runs on: loopback,
//! link-local (169.254.0.0/16, fe80::/10), the node's own addresses and the
//! cloud metadata endpoints. Nor does it reach a private network (FIX 7657):
//! RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), CGNAT
//! (100.64.0.0/10) and IPv6 ULA (fc00::/7), except at an origin the hosting
//! operator names ([`HostedPrivateOrigin`]). Infrastructure is never
//! excepted, and it wins over a private address anywhere in one name's
//! answers. A self-hosted node carries no guard: the owner's own private
//! services stay his to fetch.
//!
//! The guard judges RESOLVED addresses, never the URL's spelling, and reads
//! the node's own addresses afresh at every check, so an address assigned
//! after boot is refused too (FIX 6101). The fetcher checks every page it is
//! asked for, each crawl page included, before any rung runs; it hands each
//! rung the guard ([`Renderer::render_guarded`]) for the hops and addresses
//! the rung reaches, and checks the navigation-final URL every rung hands
//! back. The host's transport (the client
//! [`build_web_fetch_client`](super::build_web_fetch_client) builds) checks
//! every name it connects to, a redirect's included, through
//! [`HostedEgressGuard::refuses_resolved`], and fails that connection with
//! the [`HostedEgressRefusal`]; a host browser checks each request it sends
//! with [`HostedEgressGuard::check_request`]. Every one of these refusals
//! ends the ladder typed ([`WebFetchError::HostedInfrastructure`] or
//! [`WebFetchError::HostedPrivateNetwork`]).
//!
//! An operator's origin admits a private address only where the guard knows
//! the name: a name's own answers, resolved at the check, and a URL whose
//! scheme and port that origin lists. A check that sees only an address (an
//! address-literal URL, a raw connection) refuses every private address.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

use reqwest::Url;

use super::render::{redact_url_credentials, validated_web_url};
use super::{
    RenderedPage, Renderer, RendererError, RendererErrorKind, RendererResult, WebFetchError,
    WebFetchResult, WebFetcher,
};

/// The named reason every hosted-infrastructure refusal carries.
pub const HOSTED_INFRASTRUCTURE_REASON: &str = "hosted_infrastructure";

/// The named reason every hosted private-network refusal carries (FIX 7657).
pub const HOSTED_PRIVATE_NETWORK_REASON: &str = "hosted_private_network";

/// Cloud metadata endpoints outside link-local: Alibaba Cloud's, Oracle
/// Cloud's legacy one and Azure's platform (WireServer) address. The
/// link-local ones (169.254.169.254, 169.254.170.2, ...) are refused as
/// link-local.
const CLOUD_METADATA_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(192, 0, 0, 192),
    Ipv4Addr::new(168, 63, 129, 16),
];

/// Cloud metadata endpoints on IPv6: AWS's (fd00:ec2::254) and Google
/// Cloud's (fd20:ce::254).
const CLOUD_METADATA_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254),
];

/// What a hosted node's fetcher may not reach, judged by resolved address.
#[derive(Clone)]
pub struct HostedEgressGuard {
    /// Reads the node's own addresses as its host finds them now: called at
    /// every check, never cached, so the guard follows address changes.
    node: Arc<dyn Fn() -> BTreeSet<IpAddr> + Send + Sync>,
    /// The private origins the hosting operator lets the fetcher reach.
    private_origins: Arc<BTreeSet<HostedPrivateOrigin>>,
}

impl std::fmt::Debug for HostedEgressGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedEgressGuard")
            .field("private_origins", &self.private_origins)
            .finish_non_exhaustive()
    }
}

impl HostedEgressGuard {
    /// A guard that also refuses the node's own addresses, as `node_addresses`
    /// reads them at each check, and admits a private address only at one of
    /// `private_origins` (FIX 7657); with none, every private address is
    /// refused.
    #[must_use]
    pub fn new(
        node_addresses: impl Fn() -> BTreeSet<IpAddr> + Send + Sync + 'static,
        private_origins: BTreeSet<HostedPrivateOrigin>,
    ) -> Self {
        Self {
            node: Arc::new(node_addresses),
            private_origins: Arc::new(private_origins),
        }
    }

    /// Why `ip` is refused, by address alone: hosted infrastructure
    /// (loopback or "this host" (0.0.0.0/8, ::), link-local, a cloud metadata
    /// endpoint or one of the node's own addresses), or a private network
    /// (RFC1918, CGNAT, ULA), an IPv4 address spelled inside IPv6
    /// (IPv4-mapped, IPv4-compatible, NAT64) judged as itself. No operator
    /// origin admits anything here.
    #[must_use]
    pub fn refuses(&self, ip: IpAddr) -> Option<HostedEgressRefusal> {
        self.refuses_any([ip])
    }

    /// Why `ips` are refused ([`Self::refuses`]), as one set: infrastructure
    /// anywhere in it wins over a private address, and the node's own
    /// addresses are read at most once for the whole set.
    #[must_use]
    pub fn refuses_any(
        &self,
        ips: impl IntoIterator<Item = IpAddr>,
    ) -> Option<HostedEgressRefusal> {
        let mut node: Option<BTreeSet<IpAddr>> = None;
        let mut private = false;
        for ip in ips.into_iter().map(unwrapped) {
            if is_infrastructure(ip)
                || node
                    .get_or_insert_with(|| (self.node)().into_iter().map(unwrapped).collect())
                    .contains(&ip)
            {
                return Some(HostedEgressRefusal::Infrastructure);
            }
            private |= is_private_network(ip);
        }
        private.then_some(HostedEgressRefusal::PrivateNetwork)
    }

    /// Why `ips`, what `name` resolved to at this check, are refused
    /// ([`Self::refuses_any`]); private answers pass when `name` is the host
    /// of an operator origin (FIX 7657). Infrastructure never passes.
    #[must_use]
    pub fn refuses_resolved(
        &self,
        name: &str,
        ips: impl IntoIterator<Item = IpAddr>,
    ) -> Option<HostedEgressRefusal> {
        match self.refuses_any(ips) {
            Some(HostedEgressRefusal::PrivateNetwork)
                if self.private_origins.iter().any(|origin| origin.names(name)) =>
            {
                None
            }
            refused => refused,
        }
    }

    /// Refuses `url` as a private network when its host is an operator
    /// origin's name but no origin for that name lists its scheme and port
    /// (FIX 7657), so a listed name's private address is reached only at a
    /// listed origin. Any other URL passes here.
    #[must_use]
    pub fn refuses_origin(&self, url: &Url) -> Option<HostedEgressRefusal> {
        (self.origin_listed(url) == Some(false)).then_some(HostedEgressRefusal::PrivateNetwork)
    }

    /// Refuses one request a host is about to send to `resolved_ip`, the
    /// address it connects to for `request_url`, when that address is
    /// refused ([`Self::refuses`]). A managed
    /// [`HeadlessRenderer`](super::HeadlessRenderer) adapter calls it before
    /// its browser connects or sends each request, every redirect hop and
    /// subresource included (FIX 7122). `request_url` only names the request
    /// in the refusal, its credentials redacted, and admits nothing.
    ///
    /// # Errors
    /// Returns the refusal's [`RendererErrorKind`] error when `resolved_ip`
    /// is refused; returned from the rung, it ends the ladder.
    pub fn check_request(&self, request_url: &str, resolved_ip: IpAddr) -> RendererResult<()> {
        match self.refuses(resolved_ip) {
            Some(refused) => Err(refused.request_error(request_url)),
            None => Ok(()),
        }
    }

    /// Whether `url`'s host is an operator origin's name (`Some`), and then
    /// whether an origin for it lists `url`'s scheme and port.
    fn origin_listed(&self, url: &Url) -> Option<bool> {
        let host = url.host_str()?;
        let mut named = self
            .private_origins
            .iter()
            .filter(|origin| origin.names(host))
            .peekable();
        named.peek()?;
        Some(named.any(|origin| origin.serves(url)))
    }

    /// Why `url` is refused: an address literal by its address; a name by
    /// every address it resolves to now, then by its origin. A host that
    /// does not resolve is left to the transport, which fails it as before.
    fn refuses_url(&self, url: &Url) -> Option<HostedEgressRefusal> {
        let host = url.host_str()?;
        let literal = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = literal.parse::<IpAddr>() {
            return self.refuses(ip);
        }
        let answered = (literal, url.port_or_known_default().unwrap_or(0))
            .to_socket_addrs()
            .ok()
            .and_then(|addresses| {
                self.refuses_resolved(literal, addresses.map(|address| address.ip()))
            });
        match answered {
            Some(HostedEgressRefusal::Infrastructure) => answered,
            Some(HostedEgressRefusal::PrivateNetwork) | None => {
                self.refuses_origin(url).or(answered)
            }
        }
    }

    /// Refuses `url`, a page the fetcher is asked for, when it resolves to
    /// hosted infrastructure or to a private network no operator origin
    /// admits.
    pub(super) fn admit(&self, url: &Url) -> WebFetchResult<()> {
        match self.refuses_url(url) {
            Some(refused) => Err(refused.fetch_error(url.as_str())),
            None => Ok(()),
        }
    }

    /// Refuses the response a rung's client handed back when the address it
    /// actually came from (`peer`, when the client reports one) is refused:
    /// a final hop whose name was re-resolved (rebound) after any earlier
    /// check, whatever client the host supplied. A private peer passes when
    /// `url`, the final URL, is at an operator origin: the client's resolver
    /// bound that name to the address before it connected (FIX 7657).
    pub(super) fn admit_peer(&self, peer: Option<SocketAddr>, url: &Url) -> RendererResult<()> {
        let refused = peer.and_then(|peer| match self.refuses(peer.ip()) {
            Some(HostedEgressRefusal::PrivateNetwork) if self.origin_listed(url) == Some(true) => {
                None
            }
            refused => refused,
        });
        match refused {
            Some(refused) => Err(RendererError::hosted(
                refused,
                format!(
                    "the response for {} came from {}: {refused}",
                    redact_url_credentials(url.as_str()),
                    refused.destination()
                ),
            )),
            None => Ok(()),
        }
    }

    /// Refuses a page whose navigation-final URL, as its rung reported it,
    /// is refused as a page the fetcher is asked for is.
    fn admit_landing(&self, page: &RenderedPage) -> RendererResult<()> {
        let Some(landing) = page.final_url.as_deref().and_then(validated_web_url) else {
            return Ok(());
        };
        match self.refuses_url(&landing) {
            Some(refused) => Err(RendererError::hosted(
                refused,
                format!(
                    "the rung landed on {}: {refused}",
                    redact_url_credentials(landing.as_str())
                ),
            )),
            None => Ok(()),
        }
    }
}

/// Whether `ip`, already unwrapped, is infrastructure on every node: loopback,
/// "this host", link-local or a cloud metadata endpoint.
fn is_infrastructure(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.octets()[0] == 0
                || v4.is_link_local()
                || CLOUD_METADATA_V4.contains(&v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unicast_link_local()
                || CLOUD_METADATA_V6.contains(&v6)
        }
    }
}

/// Whether `ip`, already unwrapped, is in a private network a hosted node
/// refuses (FIX 7657): RFC1918, CGNAT 100.64.0.0/10 or IPv6 ULA fc00::/7.
fn is_private_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || (a == 100 && (64..=127).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// `ip`, with an IPv4 address embedded in IPv6 taken out, so one rule
/// judges every spelling of it.
fn unwrapped(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let segments = v6.segments();
    let nat64 = segments[..6] == [0x64_u16, 0xff9b, 0, 0, 0, 0];
    let compatible = segments[..6] == [0_u16; 6] && !v6.is_loopback() && !v6.is_unspecified();
    if nat64 || compatible {
        let [.., a, b, c, d] = v6.octets();
        return IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    }
    ip
}

/// One private origin the hosting operator lets a hosted node's fetcher
/// reach (FIX 7657, `--hosted-private-origin`): `http` or `https`, a DNS
/// name and a port, the scheme's own by default. The name is lowercase
/// ASCII (IDNA), at least two labels of letters, digits and hyphens, with
/// no wildcard; it is never an address, in any spelling. The origin carries
/// no path, query, fragment or credentials. It admits the private addresses
/// its name resolves to, at its scheme and port, and never infrastructure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostedPrivateOrigin {
    host: String,
    scheme: &'static str,
    port: u16,
}

impl HostedPrivateOrigin {
    /// Whether `host`, a URL's or a resolver's name, is this origin's name;
    /// one final DNS dot is no difference.
    fn names(&self, host: &str) -> bool {
        self.host
            .eq_ignore_ascii_case(host.strip_suffix('.').unwrap_or(host))
    }

    /// Whether `url` is at this origin: its name, scheme and port.
    fn serves(&self, url: &Url) -> bool {
        url.host_str().is_some_and(|host| self.names(host))
            && url.scheme() == self.scheme
            && url.port_or_known_default() == Some(self.port)
    }
}

impl std::fmt::Display for HostedPrivateOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Parses `http|https://<dns-name>[:port]`, with an empty or `/` path.
impl FromStr for HostedPrivateOrigin {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        const FORM: &str = "a hosted private origin is http(s)://<dns-name>[:port]: a name of two or more labels of letters, digits and hyphens, never an address or a wildcard, with no path, query, fragment or credentials";
        let url = Url::parse(raw).map_err(|_| FORM.to_owned())?;
        let scheme = match url.scheme() {
            "http" => "http",
            "https" => "https",
            _ => return Err(FORM.to_owned()),
        };
        let bare = url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        // The URL parser writes every IPv4 spelling as dotted decimal and
        // every IPv6 one in brackets, so neither passes as a name.
        let host = url.host_str().unwrap_or_default();
        let host = host.strip_suffix('.').unwrap_or(host);
        let name = host.parse::<Ipv4Addr>().is_err()
            && host.split('.').count() >= 2
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            });
        match url.port_or_known_default() {
            Some(port) if bare && name => Ok(Self {
                host: host.to_owned(),
                scheme,
                port,
            }),
            _ => Err(FORM.to_owned()),
        }
    }
}

/// Why a hosted node's guard refused a destination; also the error a host's
/// transport fails a refused connection with (its resolver's, its redirect
/// policy's or its relay's), which the rung turns into the matching
/// [`RendererErrorKind`] error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedEgressRefusal {
    /// Hosted infrastructure: loopback, "this host", link-local, a cloud
    /// metadata endpoint or one of the node's own addresses.
    Infrastructure,
    /// A private network (RFC1918, CGNAT, ULA) no operator origin admits
    /// (FIX 7657).
    PrivateNetwork,
}

impl HostedEgressRefusal {
    /// The named reason this refusal carries.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Infrastructure => HOSTED_INFRASTRUCTURE_REASON,
            Self::PrivateNetwork => HOSTED_PRIVATE_NETWORK_REASON,
        }
    }

    /// The refusal `reason` names exactly, as [`Self::reason`] gives it;
    /// any other reason is none of them.
    #[must_use]
    pub fn from_reason(reason: &str) -> Option<Self> {
        [Self::Infrastructure, Self::PrivateNetwork]
            .into_iter()
            .find(|refused| refused.reason() == reason)
    }

    /// The refusal a guard failed `error` with, found by type in its source
    /// chain, an `io::Error`'s payload included; never read from words.
    #[must_use]
    pub fn of_error(error: &(dyn std::error::Error + 'static)) -> Option<Self> {
        std::iter::successors(Some(error), |&error| error.source()).find_map(|error| {
            error
                .downcast_ref::<Self>()
                .or_else(|| {
                    error
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::get_ref)
                        .and_then(|inner| inner.downcast_ref::<Self>())
                })
                .copied()
        })
    }

    /// The rung error refusing the request for `request_url`, its
    /// credentials redacted.
    #[must_use]
    pub fn request_error(self, request_url: &str) -> RendererError {
        RendererError::hosted(
            self,
            format!(
                "the request for {} goes to {}: {self}",
                redact_url_credentials(request_url),
                self.destination()
            ),
        )
    }

    /// Where a refused destination goes, in words.
    const fn destination(self) -> &'static str {
        match self {
            Self::Infrastructure => "the hosting infrastructure",
            Self::PrivateNetwork => "a private network",
        }
    }

    /// The fetch error refusing `url`, the requested page, credential-redacted.
    pub(super) fn fetch_error(self, url: &str) -> WebFetchError {
        let url = redact_url_credentials(url);
        match self {
            Self::Infrastructure => WebFetchError::HostedInfrastructure { url },
            Self::PrivateNetwork => WebFetchError::HostedPrivateNetwork { url },
        }
    }
}

impl std::fmt::Display for HostedEgressRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Infrastructure => write!(
                f,
                "web fetch refused ({HOSTED_INFRASTRUCTURE_REASON}): on a hosted node, the destination resolves to the hosting infrastructure (loopback, link-local, this node's own address or a cloud metadata endpoint); a self-hosted node fetches it"
            ),
            Self::PrivateNetwork => write!(
                f,
                "web fetch refused ({HOSTED_PRIVATE_NETWORK_REASON}): on a hosted node, the destination is a private-network address outside the hosting operator's allowed origins, and hosted nodes refuse private-network addresses (RFC1918, CGNAT 100.64.0.0/10, IPv6 ULA fc00::/7); a self-hosted node fetches it, or the hosting operator can allow its named private origin"
            ),
        }
    }
}

impl std::error::Error for HostedEgressRefusal {}

impl RendererErrorKind {
    /// The guard refusal this kind stands for, if it is one.
    #[must_use]
    pub const fn hosted_refusal(self) -> Option<HostedEgressRefusal> {
        match self {
            Self::HostedInfrastructure => Some(HostedEgressRefusal::Infrastructure),
            Self::HostedPrivateNetwork => Some(HostedEgressRefusal::PrivateNetwork),
            Self::Transport | Self::Extraction | Self::InvalidResponse => None,
        }
    }
}

impl RendererError {
    /// A managed node's egress guard refused a hop, an address or a landing
    /// this rung reached (SCAN C447, FIX 7657), for `refused`'s reason. The
    /// ladder stops on it and reports [`WebFetchError::HostedInfrastructure`]
    /// or [`WebFetchError::HostedPrivateNetwork`]; no lower rung runs.
    #[must_use]
    pub fn hosted(refused: HostedEgressRefusal, message: impl Into<String>) -> Self {
        let kind = match refused {
            HostedEgressRefusal::Infrastructure => RendererErrorKind::HostedInfrastructure,
            HostedEgressRefusal::PrivateNetwork => RendererErrorKind::HostedPrivateNetwork,
        };
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl WebFetcher {
    /// Makes this a managed (hosted) node's fetcher (SCAN C447): every page
    /// it is asked for, each crawl page included, is refused before any rung
    /// runs when the guard refuses it; each rung renders with the guard
    /// ([`Renderer::render_guarded`]); and the navigation-final URL each
    /// rung hands back is checked too. Takes a shared reference, so a host
    /// installs it on a ladder it was handed, at first use; a fetcher that
    /// already carries a guard keeps it. A self-hosted node's fetcher
    /// carries none.
    pub fn install_hosted_egress_guard(&self, guard: Arc<HostedEgressGuard>) {
        // `Err` only hands back `guard` when one is already installed.
        let _ = self.egress.set(guard);
    }

    /// The guard's check of `url`, when this fetcher carries one.
    pub(super) fn admit_destination(&self, url: &Url) -> WebFetchResult<()> {
        match self.egress.get() {
            Some(guard) => guard.admit(url),
            None => Ok(()),
        }
    }

    /// Runs one rung: unguarded on a self-hosted node; on a managed one
    /// through [`Renderer::render_guarded`], with the navigation-final URL it
    /// hands back checked as well (FIX 6101).
    pub(super) fn render_rung(
        &self,
        renderer: &dyn Renderer,
        url: &str,
    ) -> RendererResult<RenderedPage> {
        let Some(guard) = self.egress.get() else {
            return renderer.render(url);
        };
        let page = renderer.render_guarded(url, guard)?;
        guard.admit_landing(&page)?;
        Ok(page)
    }
}
