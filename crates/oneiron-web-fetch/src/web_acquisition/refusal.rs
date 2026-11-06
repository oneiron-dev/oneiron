use super::{RendererError, RendererErrorKind, WebFetchError, redact_url_credentials};

/// The named reason every hosted-infrastructure refusal carries.
pub const HOSTED_INFRASTRUCTURE_REASON: &str = "hosted_infrastructure";

/// The named reason every hosted private-network refusal carries (FIX 7657).
pub const HOSTED_PRIVATE_NETWORK_REASON: &str = "hosted_private_network";

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
    pub(crate) const fn destination(self) -> &'static str {
        match self {
            Self::Infrastructure => "the hosting infrastructure",
            Self::PrivateNetwork => "a private network",
        }
    }

    /// The fetch error refusing `url`, the requested page, credential-redacted.
    pub(crate) fn fetch_error(self, url: &str) -> WebFetchError {
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
