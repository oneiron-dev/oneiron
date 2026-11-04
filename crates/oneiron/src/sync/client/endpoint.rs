//! FIX 8862: where this machine's sync credentials may go. A transport slip,
//! a bearer token or a NOTE bind leaves only for a TLS (`wss`) endpoint, a
//! `ws` endpoint on a numeric loopback address, or over the private carrier
//! actually chosen for that endpoint (a paired machine's mesh dial). The
//! configured server is held to this rule, and the residence lane holds the
//! endpoint it dials, the elected home's included, to the same rule.

use super::types::SyncClientConfig;
use crate::sync::SyncDialer;

/// Whether `url` may carry this machine's credentials. `private_carrier`
/// says whether a private dialer was chosen to reach it; the clear upgrade
/// then never crosses an open network. A URL that does not parse may not.
pub(super) fn admits_credentials(url: &str, private_carrier: bool) -> bool {
    let Ok(uri) = url.parse::<tokio_tungstenite::tungstenite::http::Uri>() else {
        return false;
    };
    let loopback = uri.host().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    private_carrier
        || uri.scheme_str() == Some("wss")
        || (uri.scheme_str() == Some("ws") && loopback)
}

impl SyncClientConfig {
    /// FIX 11111: whether the configured server may carry this machine's
    /// credentials on the main sync socket, which dials it over the mesh
    /// dialer when one is set.
    pub(crate) fn server_admits_credentials(&self) -> bool {
        admits_credentials(&self.server_url, self.mesh_dialer.is_some())
    }
}

/// One residence dial's endpoint, read once, and the carrier chosen for it.
pub(super) struct ResidenceEndpoint<'a> {
    pub(super) url: String,
    /// The mesh dialer, only when it reaches this endpoint: it carries
    /// sockets to the configured server alone.
    pub(super) dialer: Option<&'a dyn SyncDialer>,
}

impl<'a> ResidenceEndpoint<'a> {
    /// The endpoint `config` routes residence calls to now, with its
    /// carrier; `None` when that endpoint may not carry credentials.
    pub(super) fn select(config: &'a SyncClientConfig) -> Option<Self> {
        let url = config.residence_url();
        let dialer = config
            .mesh_dialer
            .as_deref()
            .filter(|_| url == config.server_url);
        admits_credentials(&url, dialer.is_some()).then_some(Self { url, dialer })
    }
}
