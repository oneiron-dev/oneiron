//! Vault subdomain hosts on the artifact listener: `<vault>.<domain>/<artifact>/…`.
//!
//! DNS, certificates and the edge are static config; the edge sends each
//! configured domain's subdomains here. The Host header picks the vault, and
//! that vault's own artifact app answers with its own credentials and binding
//! admission, so a credential reads only in the vault that issued it. A host
//! under a configured domain that names no vault here answers exactly as a
//! forbidden artifact does, and so does every refusal from a known vault: the
//! one artifact 404. A host under no configured domain keeps local `/a/`.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::extract::{OriginalUri, Request};
use axum::http::header::HOST;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use tower::ServiceExt;

use crate::error::{ApiError, EnvelopedApiError};

/// Marks a request this router rewrote from `/<artifact>/…` to
/// `/a/<artifact>/…`, so its redirects keep the vault host's form. Set by
/// this router alone, never read from a request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VaultHostRoute;

/// The vaults one artifact listener serves by subdomain, and under which domains.
#[derive(Clone, Default)]
pub(crate) struct ArtifactHosts {
    domains: Vec<String>,
    vaults: BTreeMap<String, Router>,
}

enum HostRoute {
    /// Not under a configured domain: local serving.
    Local,
    Vault(Router),
    /// Under a configured domain, naming no vault served here.
    Unknown,
}

impl ArtifactHosts {
    pub(crate) fn new(domains: &[String]) -> Self {
        Self {
            domains: domains
                .iter()
                .map(|domain| domain.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|domain| !domain.is_empty())
                .collect(),
            vaults: BTreeMap::new(),
        }
    }

    /// Serves one vault's artifact app at `<name>.<domain>` under every domain.
    /// A name that is not a DNS label is never served.
    pub(crate) fn with_vault_app(mut self, name: &str, app: Router) -> Self {
        let name = name.to_ascii_lowercase();
        if oneiron_vault_contract::valid_vault_name(&name) {
            self.vaults.insert(name, app);
        }
        self
    }

    /// The listener's router: `local` for every host outside the configured
    /// domains, and each vault at its subdomain inside them.
    pub(crate) fn into_app(self, local: Router) -> Router {
        if self.domains.is_empty() {
            return local;
        }
        let hosts = Arc::new(self);
        Router::new().fallback_service(tower::service_fn(move |request: Request| {
            let hosts = Arc::clone(&hosts);
            let local = local.clone();
            async move { Ok::<_, Infallible>(hosts.dispatch(local, request).await) }
        }))
    }

    fn route(&self, host: Option<&str>) -> HostRoute {
        let Some(host) = host.map(normalize_host) else {
            return HostRoute::Local;
        };
        for domain in &self.domains {
            if host == *domain {
                return HostRoute::Unknown;
            }
            let Some(label) = host
                .strip_suffix(domain.as_str())
                .and_then(|rest| rest.strip_suffix('.'))
            else {
                continue;
            };
            return match self.vaults.get(label) {
                Some(app) if !label.contains('.') => HostRoute::Vault(app.clone()),
                _ => HostRoute::Unknown,
            };
        }
        HostRoute::Local
    }

    async fn dispatch(&self, local: Router, mut request: Request) -> Response {
        let app = match self.route(request_host(&request)) {
            HostRoute::Local => return answer(local, request).await,
            HostRoute::Unknown => return unknown_artifact(),
            HostRoute::Vault(app) => app,
        };
        // `<vault>.<domain>/<artifact>/…` is that vault's `/a/<artifact>/…`.
        let Some(uri) = vault_route_uri(request.uri()) else {
            return unknown_artifact();
        };
        // The handlers parse the original URI, which the outer router recorded.
        request.extensions_mut().insert(OriginalUri(uri.clone()));
        *request.uri_mut() = uri;
        request.extensions_mut().insert(VaultHostRoute);
        let response = answer(app, request).await;
        // A refusal for any reason (credential, tier, selector, binding)
        // must not tell a known vault from an unknown one. Shedding is the
        // listener's, not the vault's, so it stays as it is.
        let status = response.status();
        if status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS {
            return unknown_artifact();
        }
        response
    }
}

async fn answer(app: Router, request: Request) -> Response {
    match app.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// The authority a request names: the URI's (HTTP/2, absolute form), else
/// the Host header. A forwarded host is never trusted here.
fn request_host(request: &Request) -> Option<&str> {
    request
        .uri()
        .authority()
        .map(|authority| authority.host())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
        })
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            name
        }
        _ => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn vault_route_uri(uri: &Uri) -> Option<Uri> {
    let path_and_query = uri.path_and_query()?.as_str();
    if !path_and_query.starts_with('/') || uri.path() == "/" {
        return None;
    }
    format!("/a{path_and_query}").parse().ok()
}

fn unknown_artifact() -> Response {
    EnvelopedApiError::from(ApiError::not_found("artifact", None)).into_response()
}
