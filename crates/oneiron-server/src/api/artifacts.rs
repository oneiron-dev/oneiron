use super::core_engine_error;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::Extension;
use axum::body::Body;
use axum::extract::OriginalUri;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::http::header::CONTENT_DISPOSITION;
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::ETAG;
use axum::http::header::IF_NONE_MATCH;
use axum::http::header::LOCATION;
use axum::http::header::REFERRER_POLICY;
use axum::http::header::X_CONTENT_TYPE_OPTIONS;
use axum::response::Response;
use serde::Deserialize;
use std::sync::Arc;

pub(crate) const ARTIFACT_POINTER_CACHE_CONTROL: &str = "no-cache, max-age=0, must-revalidate";

pub(crate) const ARTIFACT_IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

pub(crate) const BLOB_POINTER_CACHE_CONTROL: &str = "private, no-cache, max-age=0, must-revalidate";
pub(crate) const BLOB_IMMUTABLE_CACHE_CONTROL: &str = "private, max-age=31536000, immutable";

pub(crate) const ARTIFACT_CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self'; ",
    "style-src 'self'; ",
    "img-src 'self' data: blob:; ",
    "font-src 'self' data:; ",
    "connect-src 'none'; ",
    "object-src 'none'; ",
    "base-uri 'none'; ",
    "form-action 'none'; ",
    "frame-ancestors 'none'"
);

/// A code bundle served on the API's origin, beside an artifact listener,
/// would run its own scripts on the daemon's origin, so its document is
/// sandboxed into an opaque origin: it cannot read the API, another artifact
/// or their storage through a frame or a window it opens, and it may neither
/// frame, open popups nor submit forms. Its own relative classic scripts,
/// styles and images still load ('self' matches the response URL); module
/// scripts and fonts, fetched in CORS mode, load only on the artifact origin.
pub(crate) const CODE_ARTIFACT_CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self'; ",
    "style-src 'self'; ",
    "img-src 'self' data: blob:; ",
    "font-src 'self' data:; ",
    "connect-src 'none'; ",
    "object-src 'none'; ",
    "base-uri 'none'; ",
    "form-action 'none'; ",
    "frame-ancestors 'none'; ",
    "frame-src 'none'; ",
    "sandbox allow-scripts"
);

/// A code bundle on the artifact listener keeps that origin, which holds no
/// API and no credential, so its module scripts and fonts load. It still may
/// neither frame, open popups nor submit forms, and it may start no worker: a
/// service worker would outlive the page and answer for every bundle that
/// shares the origin.
pub(crate) const OWN_ORIGIN_CODE_ARTIFACT_CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self'; ",
    "style-src 'self'; ",
    "img-src 'self' data: blob:; ",
    "font-src 'self' data:; ",
    "connect-src 'none'; ",
    "object-src 'none'; ",
    "base-uri 'none'; ",
    "form-action 'none'; ",
    "frame-ancestors 'none'; ",
    "frame-src 'none'; ",
    "worker-src 'none'; ",
    "sandbox allow-scripts allow-same-origin"
);

/// Marks the router of the artifact-only listener, whose origin is the
/// bundles' own. Set by that router alone, never read from a request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ArtifactOnlyListener;

/// The policy a code bundle's documents get where this request arrived. Where
/// no artifact listener serves (a managed vault given no artifact socket, an
/// embedder's bare app), `/a/` keeps the policy every artifact had before the
/// listener existed, so that bundles there keep their modules until such a
/// listener does.
fn code_artifact_policy(
    server: &SyncServer,
    listener: Option<Extension<ArtifactOnlyListener>>,
) -> &'static str {
    match (listener, server.has_artifact_origin()) {
        (Some(_), _) => OWN_ORIGIN_CODE_ARTIFACT_CONTENT_SECURITY_POLICY,
        (None, true) => CODE_ARTIFACT_CONTENT_SECURITY_POLICY,
        (None, false) => ARTIFACT_CONTENT_SECURITY_POLICY,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactServeQuery {
    channel: Option<String>,
    fork_hash: Option<String>,
    blob_version: Option<u64>,
}

#[path = "artifacts/route.rs"]
mod route;
use self::route::ArtifactRoute;

#[path = "artifacts/host.rs"]
mod host;
pub(crate) use self::host::{ArtifactHosts, VaultHostRoute};

pub(crate) async fn serve_artifact_root(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
    Query(query): Query<ArtifactServeQuery>,
    listener: Option<Extension<ArtifactOnlyListener>>,
    vault_host: Option<Extension<VaultHostRoute>>,
) -> Result<Response, EnvelopedApiError> {
    let mut route = ArtifactRoute::parse(&uri, &artifact, &query)?;
    if let Some(Extension(host)) = vault_host {
        route.on_vault_host(host.app);
    }
    let code_policy = code_artifact_policy(&server, listener);
    let response = serve_artifact_file(server, &route, &headers, code_policy)?;
    if let Some(target) = route.redirect() {
        return artifact_redirect_response(&target);
    }
    Ok(response)
}

pub(crate) async fn serve_artifact_path(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, _path)): Path<(String, String)>,
    Query(query): Query<ArtifactServeQuery>,
    listener: Option<Extension<ArtifactOnlyListener>>,
    vault_host: Option<Extension<VaultHostRoute>>,
) -> Result<Response, EnvelopedApiError> {
    let mut route = ArtifactRoute::parse(&uri, &artifact, &query)?;
    if let Some(Extension(host)) = vault_host {
        route.on_vault_host(host.app);
    }
    let code_policy = code_artifact_policy(&server, listener);
    let response = serve_artifact_file(server, &route, &headers, code_policy)?;
    if let Some(target) = route.redirect() {
        return artifact_redirect_response(&target);
    }
    Ok(response)
}

fn serve_artifact_file(
    server: Arc<SyncServer>,
    route: &ArtifactRoute,
    request_headers: &HeaderMap,
    code_policy: &'static str,
) -> Result<Response, EnvelopedApiError> {
    // An adapter without content-scope enforcement must reject narrowed
    // credentials. Neither a write-only slip nor an identity alone grants a read.
    let principal =
        CoreAuth::from_headers(request_headers, &server.config, server.vault().as_ref())
            .ok()
            .filter(|auth| {
                auth.has_scope(CoreScope::Read) && auth.require_unrestricted_record_scope().is_ok()
            })
            .and_then(|auth| {
                auth.principal_ref()
                    .and_then(|id| oneiron::EntityId::from_hex(id).ok())
            });
    let Some(file) = server
        .vault
        .resolve_authorized_artifact_file(
            &route.artifact,
            route.selector,
            route.path(),
            route.token.as_deref(),
            principal,
        )
        .map_err(|error| core_engine_error("artifact serving failed", error))?
    else {
        return Err(ApiError::not_found("artifact", None).into());
    };
    artifact_file_response(file, request_headers, code_policy)
}

fn artifact_redirect_response(target: &str) -> Result<Response, EnvelopedApiError> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(target).map_err(|_| ApiError::not_found("artifact", None))?,
    );
    Ok(response)
}

pub(crate) fn artifact_file_response(
    file: oneiron::ArtifactServedFile,
    request_headers: &HeaderMap,
    code_policy: &'static str,
) -> Result<Response, EnvelopedApiError> {
    let cache_control = if file.serve_tier == oneiron::artifact_hosting::ArtifactServeTier::Public {
        artifact_cache_control(file.selector, file.export)
    } else {
        "private, no-store"
    };
    let content_security_policy = if file.media_type.is_some() {
        ARTIFACT_CONTENT_SECURITY_POLICY
    } else {
        code_policy
    };
    let (content_type, attachment) = match file.media_type.as_deref() {
        Some(media_type) => match passive_blob_media_type(media_type) {
            Some(safe_type) => (HeaderValue::from_static(safe_type), false),
            None => (HeaderValue::from_static("application/octet-stream"), true),
        },
        None => (
            HeaderValue::from_static(artifact_content_type(&file.path)),
            false,
        ),
    };
    // A blob version pins its export presentation as well as its bytes.
    // Same-byte forks can change MIME/attachment policy, so the blob ETag
    // must name the immutable version, not only the shared content hash.
    let etag = match file.export {
        oneiron::artifact_hosting::ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        } => {
            format!(
                "\"blob-{}-{version}-{}\"",
                artifact_id.to_hex(),
                oneiron::artifact_hex(&file.content_hash)
            )
        }
        _ => format!("\"{}\"", oneiron::artifact_hex(&file.content_hash)),
    };
    if request_etag_matches(request_headers, &etag) {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        let headers = response.headers_mut();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        if attachment {
            headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
        }
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(content_security_policy),
        );
        headers.insert(
            ETAG,
            HeaderValue::from_str(&etag)
                .map_err(|_| ApiError::internal_server_error("artifact ETag was invalid"))?,
        );
        return Ok(response);
    }

    let mut response = Response::new(Body::from(file.bytes));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if attachment {
        headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    }
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(content_security_policy),
    );
    headers.insert(
        ETAG,
        HeaderValue::from_str(&etag)
            .map_err(|_| ApiError::internal_server_error("artifact ETag was invalid"))?,
    );
    Ok(response)
}

/// Only inert types may render inline on the shared local origin. An active
/// or unknown blob media type is served as an attachment with nosniff.
fn passive_blob_media_type(media_type: &str) -> Option<&'static str> {
    match media_type {
        "application/pdf" => Some("application/pdf"),
        "text/plain" => Some("text/plain; charset=utf-8"),
        "image/png" => Some("image/png"),
        "image/jpeg" => Some("image/jpeg"),
        "image/webp" => Some("image/webp"),
        "image/gif" => Some("image/gif"),
        _ => None,
    }
}

pub(crate) fn artifact_cache_control(
    selector: oneiron::ArtifactSnapshotSelector,
    export: oneiron::artifact_hosting::ArtifactExportRef,
) -> &'static str {
    match (selector, export) {
        (
            oneiron::ArtifactSnapshotSelector::Channel(_),
            oneiron::artifact_hosting::ArtifactExportRef::BlobVersion { .. },
        ) => BLOB_POINTER_CACHE_CONTROL,
        (oneiron::ArtifactSnapshotSelector::BlobVersion(_), _) => BLOB_IMMUTABLE_CACHE_CONTROL,
        (oneiron::ArtifactSnapshotSelector::Channel(_), _) => ARTIFACT_POINTER_CACHE_CONTROL,
        (oneiron::ArtifactSnapshotSelector::ForkHash(_), _) => ARTIFACT_IMMUTABLE_CACHE_CONTROL,
        _ => ARTIFACT_POINTER_CACHE_CONTROL,
    }
}

pub(crate) fn request_etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate == etag || candidate.strip_prefix("W/") == Some(etag)
            })
        })
}

pub(crate) fn artifact_content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
