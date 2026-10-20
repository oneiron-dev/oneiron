//! Vault subdomain hosts on the artifact listener: `<vault>.<domain>/<artifact>/…`,
//! and one app on an origin of its own, `<app>--<vault>.<domain>/…`, read by
//! the contract a cloud front forwards by (`oneiron_vault_contract::artifact_origin`).
//! A managed vault reads its internal authority instead,
//! `<vault_id>.artifact.invalid/<artifact>/…` and
//! `<app>.<vault_id>.artifact.invalid/…`, which the edge forwards once it has
//! checked the public name (FIX 6716); its configured domains are never read.
//!
//! DNS, certificates and the edge are static config; the edge sends each
//! configured domain's subdomains here. The Host header picks the vault, and
//! that vault's own artifact app answers with its own credentials and binding
//! admission, so a credential reads only in the vault that issued it. A host
//! under a configured domain (or the internal authority) that names no vault
//! here answers exactly as a forbidden artifact does, and so does every
//! refusal from a known vault: the one artifact 404. Any other host keeps
//! local `/a/`.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::extract::{OriginalUri, Request};
use axum::http::header::HOST;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use oneiron_vault_contract::artifact_origin::{
    ArtifactHost, ArtifactHostRead, ArtifactInternalHost, ArtifactInternalRead,
    normalize_artifact_domain, valid_app_label,
};
use oneiron_vault_contract::valid_vault_name;
use tower::ServiceExt;

use crate::error::{ApiError, EnvelopedApiError};

/// Marks a request this router rewrote from `/<artifact>/…` (or an app
/// host's `/…`) to `/a/<artifact>/…`, so its redirects keep the host's form.
/// Set by this router alone, never read from a request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VaultHostRoute {
    /// Reached at `<app>--<vault>.<domain>` (or
    /// `<app>.<vault_id>.artifact.invalid`): the path names no artifact.
    pub(crate) app: bool,
}

/// The vaults one artifact listener serves by subdomain, and under which names.
#[derive(Clone, Default)]
pub(crate) struct ArtifactHosts {
    names: HostNames,
    vaults: BTreeMap<String, Router>,
}

/// Which hosts name a vault on the listener.
#[derive(Clone)]
enum HostNames {
    /// Subdomains of the configured artifact domains, keyed by vault label.
    Domains(Vec<String>),
    /// A managed vault's internal authority alone, keyed by vault id.
    Internal,
}

impl Default for HostNames {
    fn default() -> Self {
        Self::Domains(Vec::new())
    }
}

enum HostRoute {
    /// Not under a configured domain (or the internal authority): local
    /// serving.
    Local,
    /// A vault served here, and maybe one of its apps.
    Vault(Router, Option<String>),
    /// Under a configured domain (or the internal authority), naming no
    /// vault served here.
    Unknown,
}

impl ArtifactHosts {
    pub(crate) fn new(domains: &[String]) -> Self {
        Self {
            names: HostNames::Domains(
                domains
                    .iter()
                    .map(|domain| normalize_artifact_domain(domain))
                    .filter(|domain| !domain.is_empty())
                    .collect(),
            ),
            vaults: BTreeMap::new(),
        }
    }

    /// A managed vault's listener: vaults by their id on the internal
    /// authority, `<vault_id>.artifact.invalid`, and on no artifact domain.
    pub(crate) fn internal() -> Self {
        Self {
            names: HostNames::Internal,
            vaults: BTreeMap::new(),
        }
    }

    /// Serves one vault's artifact app at `<name>.<domain>`, and its apps at
    /// `<app>--<name>.<domain>`, under every domain; on the internal
    /// authority, at `<name>.artifact.invalid` and
    /// `<app>.<name>.artifact.invalid`, where `name` is the vault id. A name
    /// that is not a DNS label (free of `--` under a domain) is never served.
    pub(crate) fn with_vault_app(mut self, name: &str, app: Router) -> Self {
        let name = name.to_ascii_lowercase();
        let served = match self.names {
            HostNames::Domains(_) => valid_app_label(&name),
            HostNames::Internal => valid_vault_name(&name),
        };
        if served {
            self.vaults.insert(name, app);
        }
        self
    }

    /// The listener's router: `local` for every host outside the configured
    /// domains (or the internal authority), and each vault at its host
    /// inside them. With no domain and no internal authority, `local` alone.
    pub(crate) fn into_app(self, local: Router) -> Router {
        if matches!(&self.names, HostNames::Domains(domains) if domains.is_empty()) {
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
        let Some(host) = host else {
            return HostRoute::Local;
        };
        let (vault, artifact) = match &self.names {
            HostNames::Domains(domains) => match ArtifactHost::read(host, domains) {
                ArtifactHostRead::Outside => return HostRoute::Local,
                ArtifactHostRead::Unnamed => return HostRoute::Unknown,
                ArtifactHostRead::Named(named) => (named.vault, named.app),
            },
            // The vault id must be this vault's: another id names nothing.
            HostNames::Internal => match ArtifactInternalHost::read(host) {
                ArtifactInternalRead::Outside => return HostRoute::Local,
                ArtifactInternalRead::Unnamed => return HostRoute::Unknown,
                ArtifactInternalRead::Named(named) => (named.vault_id, named.app),
            },
        };
        match self.vaults.get(&vault) {
            Some(app) => HostRoute::Vault(app.clone(), artifact),
            None => HostRoute::Unknown,
        }
    }

    async fn dispatch(&self, local: Router, mut request: Request) -> Response {
        let (app, artifact) = match self.route(request_host(&request)) {
            HostRoute::Local => return answer(local, request).await,
            HostRoute::Unknown => return unknown_artifact(),
            HostRoute::Vault(app, artifact) => (app, artifact),
        };
        // `<vault>.<domain>/<artifact>/…` is that vault's `/a/<artifact>/…`,
        // and `<app>--<vault>.<domain>/…` is its `/a/<app>/…`; so are
        // `<vault_id>.artifact.invalid/<artifact>/…` and
        // `<app>.<vault_id>.artifact.invalid/…`.
        let Some(uri) = vault_route_uri(request.uri(), artifact.as_deref()) else {
            return unknown_artifact();
        };
        // The handlers parse the original URI, which the outer router recorded.
        request.extensions_mut().insert(OriginalUri(uri.clone()));
        *request.uri_mut() = uri;
        request.extensions_mut().insert(VaultHostRoute {
            app: artifact.is_some(),
        });
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

fn vault_route_uri(uri: &Uri, artifact: Option<&str>) -> Option<Uri> {
    let path_and_query = uri.path_and_query()?.as_str();
    if !path_and_query.starts_with('/') {
        return None;
    }
    match artifact {
        Some(artifact) => format!("/a/{artifact}{path_and_query}").parse().ok(),
        None if uri.path() == "/" => None,
        None => format!("/a{path_and_query}").parse().ok(),
    }
}

fn unknown_artifact() -> Response {
    EnvelopedApiError::from(ApiError::not_found("artifact", None)).into_response()
}
