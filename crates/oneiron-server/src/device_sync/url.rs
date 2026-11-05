//! A verified TLS carrier for the ordinary URL sync connection.

use std::sync::Arc;

use oneiron::sync::{SyncDial, SyncDialer, SyncStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

struct UrlDialer {
    host: String,
    port: u16,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for UrlDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlDialer").finish_non_exhaustive()
    }
}

/// A private, certificate-verified stream for `wss`. The core still owns
/// the HTTP upgrade and every WebSocket frame. Loopback `ws` uses its
/// existing plain TCP path; a paired mesh carrier takes precedence.
pub(super) fn dialer(url: &str) -> anyhow::Result<Option<Arc<dyn SyncDialer>>> {
    let uri: axum::http::Uri = url.parse()?;
    if uri.scheme_str() != Some("wss") {
        return Ok(None);
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("home_url has no host"))?
        .trim_matches(['[', ']'])
        .to_owned();
    let name = ServerName::try_from(host.clone())
        .map_err(|_| anyhow::anyhow!("home_url has no valid TLS server name"))?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Do not depend on a process-global default crypto provider.
    let tls = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Some(Arc::new(UrlDialer {
        host,
        port: uri.port_u16().unwrap_or(443),
        name,
        tls: Arc::new(tls),
    })))
}

impl SyncDialer for UrlDialer {
    fn dial(&self) -> SyncDial<'_> {
        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?;
            let stream = TlsConnector::from(Arc::clone(&self.tls))
                .connect(self.name.clone(), tcp)
                .await?;
            Ok(Box::new(stream) as Box<dyn SyncStream>)
        })
    }
}
