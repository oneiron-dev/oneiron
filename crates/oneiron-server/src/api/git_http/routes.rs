//! Git smart-HTTP routes and per-service RPC handlers.

use super::gate::{advertised_service, authenticate, header_value, remote_user, repo_name};
use super::serve::run_serve;
use crate::auth::CoreScope;
use crate::server::SyncServer;
use axum::Router;
use axum::body::Body;
use axum::extract::Path;
use axum::extract::RawQuery;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_ENCODING;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use oneiron::origin::smart_http;
use std::sync::Arc;

/// The two smart-HTTP services, and the only two this origin serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GitService {
    UploadPack,
    ReceivePack,
}

impl GitService {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    pub(super) const fn scope(self) -> CoreScope {
        match self {
            Self::UploadPack => CoreScope::Read,
            Self::ReceivePack => CoreScope::Write,
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }
}

/// Builds the git smart-HTTP routes.
pub(crate) fn git_http_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/git/{repo}/info/refs", get(git_info_refs))
        .route("/git/{repo}/git-upload-pack", post(git_upload_pack))
        .route("/git/{repo}/git-receive-pack", post(git_receive_pack))
        .merge(crate::api::git_lfs::lfs_routes())
}

/// `GET /git/{repo}/info/refs` — the ref advertisement, streamed.
pub(crate) async fn git_info_refs(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let service = match advertised_service(&query.unwrap_or_default()) {
        Ok(service) => service,
        Err(refusal) => return refusal.response(),
    };
    let auth = match authenticate(&headers, &server.config, server.vault().as_ref(), service) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let name = repo_name(&repo).to_owned();
    let request = advertisement_request(&name, service, remote_user(&auth));
    run_serve(server, name, request, Body::empty()).await
}

/// The advertisement invocation this route hands to the serving plane.
///
/// Built as a value so the one property that matters can be asserted without a
/// transport around it: this is the request shape
/// [`smart_http::ServeRequest::is_ref_advertisement`] recognizes, and therefore
/// the one the publication projection gates. An advertisement the gate does not
/// recognize would be a ref list nobody projected.
pub(super) fn advertisement_request(
    name: &str,
    service: GitService,
    remote_user: Option<String>,
) -> smart_http::ServeRequest {
    smart_http::ServeRequest {
        method: "GET".to_owned(),
        path_info: format!("/{name}.git/info/refs"),
        // The CANONICAL spelling of the service the gate just authorized, never
        // the client's query. What the backend advertises and what the gate
        // decided are one value by construction.
        query_string: format!("service={}", service.as_str()),
        content_type: None,
        content_length: None,
        content_encoding: None,
        // The client's `Git-Protocol` is read and not forwarded. Protocol v2
        // moves the ref list out of this response and into an `ls-refs` command
        // inside the RPC body, where the publication projection cannot reach
        // it; declining the version is what keeps "every advertised ref is a
        // published ref" true. A stock client falls back on its own.
        git_protocol: None,
        remote_user,
        remote_addr: None,
    }
}

/// `POST /git/{repo}/git-upload-pack` — fetch/clone negotiation, streamed.
pub(crate) async fn git_upload_pack(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    serve_rpc(server, repo, headers, body, GitService::UploadPack).await
}

/// `POST /git/{repo}/git-receive-pack` — the push, streamed.
///
/// The gate is the whole of RC4: `Write` scope plus a registered
/// `principal_ref` proved by a real bearer, on loopback and everywhere else
/// alike. The door window and the single-writer landing happen inside
/// [`smart_http::serve`]; this handler adds no ref logic of its own.
pub(crate) async fn git_receive_pack(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    serve_rpc(server, repo, headers, body, GitService::ReceivePack).await
}

async fn serve_rpc(
    server: Arc<SyncServer>,
    repo: String,
    headers: HeaderMap,
    body: Body,
    service: GitService,
) -> Response {
    let auth = match authenticate(&headers, &server.config, server.vault().as_ref(), service) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let name = repo_name(&repo).to_owned();
    let request = smart_http::ServeRequest {
        method: "POST".to_owned(),
        path_info: format!("/{name}.git/{}", service.as_str()),
        query_string: String::new(),
        content_type: header_value(&headers, CONTENT_TYPE.as_str()),
        content_length: header_value(&headers, CONTENT_LENGTH.as_str())
            .and_then(|value| value.parse::<u64>().ok()),
        content_encoding: header_value(&headers, CONTENT_ENCODING.as_str()),
        // Pinned for the same reason the advertisement pins it: an exchange
        // whose advertisement spoke v0 and whose RPC speaks v2 is not one
        // conversation.
        git_protocol: None,
        remote_user: remote_user(&auth),
        remote_addr: None,
    };
    run_serve(server, name, request, body).await
}
