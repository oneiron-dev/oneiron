use super::core_engine_error;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::body::Body;
use axum::extract::OriginalUri;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::Uri;
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

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactServeQuery {
    channel: Option<String>,
    fork_hash: Option<String>,
    blob_version: Option<u64>,
}

pub(crate) async fn serve_artifact_root(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
    Query(query): Query<ArtifactServeQuery>,
) -> Result<Response, EnvelopedApiError> {
    let response = serve_artifact_file(server, artifact, "", query, &headers, None, None)?;
    if !uri.path().ends_with('/') {
        return artifact_root_redirect_response(&uri);
    }
    Ok(response)
}

pub(crate) async fn serve_artifact_path(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, path)): Path<(String, String)>,
    Query(query): Query<ArtifactServeQuery>,
) -> Result<Response, EnvelopedApiError> {
    let (token, selected, file_path) = artifact_token_route_path(&path)?;
    let explicit_query =
        query.channel.is_some() || query.fork_hash.is_some() || query.blob_version.is_some();
    if token.is_some() && selected.is_some() && explicit_query {
        return Err(ApiError::not_found("artifact", None).into());
    }
    let query_selector = if token.is_some() && selected.is_none() && explicit_query {
        Some(artifact_snapshot_selector(&query)?)
    } else {
        None
    };
    let response = serve_artifact_file(
        server, artifact, file_path, query, &headers, token, selected,
    )?;
    if let (Some(token), Some(selector)) = (token, query_selector) {
        // Canonicalize a query-selected bundle BEFORE navigation. A browser
        // drops a document's query when it requests relative JS/CSS/links.
        return artifact_selection_redirect_response(&uri, token, selector);
    }
    if let Some(token) = token
        && selected.is_none()
        && file_path.is_empty()
    {
        // Even Published needs a selector namespace, or `c/`, `f/`, and
        // `b/` inside the stored bundle would collide with selector tags.
        return artifact_selection_redirect_response(
            &uri,
            token,
            oneiron::ArtifactSnapshotSelector::default(),
        );
    }
    if token.is_some() && file_path.is_empty() && !uri.path().ends_with('/') {
        return artifact_root_redirect_response(&uri);
    }
    Ok(response)
}

pub(crate) fn serve_artifact_file(
    server: Arc<SyncServer>,
    artifact: String,
    route_path: &str,
    query: ArtifactServeQuery,
    request_headers: &HeaderMap,
    token: Option<&str>,
    selected: Option<oneiron::ArtifactSnapshotSelector>,
) -> Result<Response, EnvelopedApiError> {
    let selector = selected.map_or_else(|| artifact_snapshot_selector(&query), Ok)?;
    // Only a verified, bound principal can claim membership. An invalid bearer
    // cannot turn an anonymous hit into a different error shape.
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
    let path = normalize_artifact_route_path(route_path);
    let Some(file) = server
        .vault
        .resolve_authorized_artifact_file(&artifact, selector, &path, token, principal)
        .map_err(|error| core_engine_error("artifact serving failed", error))?
    else {
        return Err(ApiError::not_found("artifact", None).into());
    };
    artifact_file_response(file, request_headers)
}

pub(crate) fn artifact_snapshot_selector(
    query: &ArtifactServeQuery,
) -> Result<oneiron::ArtifactSnapshotSelector, EnvelopedApiError> {
    if let Some(version) = query.blob_version {
        if version == 0 {
            return Err(ApiError::bad_request(
                "blobVersion must be greater than zero",
                Some("blobVersion"),
            )
            .into());
        }
        if query.channel.is_some() || query.fork_hash.is_some() {
            return Err(ApiError::bad_request(
                "blobVersion cannot be combined with channel or forkHash",
                Some("blobVersion"),
            )
            .into());
        }
        return Ok(oneiron::ArtifactSnapshotSelector::BlobVersion(version));
    }
    if query.channel.is_some() && query.fork_hash.is_some() {
        return Err(ApiError::bad_request(
            "channel and forkHash cannot be combined",
            Some("forkHash"),
        )
        .into());
    }
    if let Some(fork_hash) = &query.fork_hash {
        return Ok(oneiron::ArtifactSnapshotSelector::ForkHash(
            oneiron::parse_codebase_fork_hash_hex(fork_hash)
                .map_err(|error| ApiError::bad_request(error.to_string(), Some("forkHash")))?,
        ));
    }
    let channel = match query.channel.as_deref() {
        Some(channel) => oneiron::ArtifactPointerChannel::parse(channel)
            .map_err(|error| ApiError::bad_request(error.to_string(), Some("channel")))?,
        None => oneiron::ArtifactPointerChannel::Published,
    };
    Ok(oneiron::ArtifactSnapshotSelector::Channel(channel))
}

/// The selected export is part of the capability URL namespace. Browsers
/// resolve relative bundle resources beneath this prefix without a query.
pub(crate) fn artifact_token_route_path(
    path: &str,
) -> Result<
    (
        Option<&str>,
        Option<oneiron::ArtifactSnapshotSelector>,
        &str,
    ),
    EnvelopedApiError,
> {
    let Some(rest) = path.strip_prefix("_t/") else {
        return Ok((None, None, path));
    };
    let (token, path) = rest.split_once('/').unwrap_or((rest, ""));
    let Some(tagged) = path.strip_prefix("_s/") else {
        return Ok((Some(token), None, path));
    };
    let (kind, tail) = tagged.split_once('/').unwrap_or((tagged, ""));
    let parsed = match kind {
        "c" => {
            let (channel, file) = tail.split_once('/').unwrap_or((tail, ""));
            let channel = oneiron::ArtifactPointerChannel::parse(channel)
                .map_err(|_| ApiError::not_found("artifact", None))?;
            Some((oneiron::ArtifactSnapshotSelector::Channel(channel), file))
        }
        "f" => {
            let (hash, file) = tail.split_once('/').unwrap_or((tail, ""));
            let hash = oneiron::parse_codebase_fork_hash_hex(hash)
                .map_err(|_| ApiError::not_found("artifact", None))?;
            Some((oneiron::ArtifactSnapshotSelector::ForkHash(hash), file))
        }
        "b" => {
            let (version, file) = tail.split_once('/').unwrap_or((tail, ""));
            let version = version
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| ApiError::not_found("artifact", None))?;
            Some((
                oneiron::ArtifactSnapshotSelector::BlobVersion(version),
                file,
            ))
        }
        _ => None,
    };
    if let Some((selector, file)) = parsed {
        Ok((Some(token), Some(selector), file))
    } else {
        Ok((Some(token), None, path))
    }
}

fn artifact_selection_redirect_response(
    uri: &Uri,
    token: &str,
    selector: oneiron::ArtifactSnapshotSelector,
) -> Result<Response, EnvelopedApiError> {
    let segment = match selector {
        oneiron::ArtifactSnapshotSelector::Channel(channel) => format!("c/{}", channel.as_str()),
        oneiron::ArtifactSnapshotSelector::ForkHash(hash) => {
            format!("f/{}", oneiron::artifact_hex(&hash))
        }
        oneiron::ArtifactSnapshotSelector::BlobVersion(version) => format!("b/{version}"),
        _ => return Err(ApiError::not_found("artifact", None).into()),
    };
    let (prefix, raw_token_path) = uri
        .path()
        .split_once("/_t/")
        .ok_or_else(|| ApiError::not_found("artifact", None))?;
    // Axum's Path extractor percent-decodes the wildcard. Use OriginalUri's
    // RAW suffix so a literal `#`, `?`, or `%20` in a stored file name cannot
    // turn into a fragment, query, or a second decode on the redirect hop.
    let encoded_file_path = raw_token_path
        .split_once('/')
        .map_or("", |(_, suffix)| suffix);
    let target = format!("{prefix}/_t/{token}/_s/{segment}/{encoded_file_path}");
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&target).map_err(|_| ApiError::not_found("artifact", None))?,
    );
    Ok(response)
}

pub(crate) fn normalize_artifact_route_path(route_path: &str) -> String {
    let path = route_path.trim_start_matches('/');
    if path.is_empty() {
        "index.html".to_owned()
    } else if path.ends_with('/') {
        format!("{path}index.html")
    } else {
        path.to_owned()
    }
}

pub(crate) fn artifact_root_redirect_response(uri: &Uri) -> Result<Response, EnvelopedApiError> {
    let query_len = uri.query().map_or(0, str::len);
    let mut target =
        String::with_capacity(uri.path().len() + 1 + query_len + usize::from(query_len > 0));
    target.push_str(uri.path());
    target.push('/');
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&target)
            .map_err(|_| ApiError::internal_server_error("artifact redirect target was invalid"))?,
    );
    Ok(response)
}

pub(crate) fn artifact_file_response(
    file: oneiron::ArtifactServedFile,
    request_headers: &HeaderMap,
) -> Result<Response, EnvelopedApiError> {
    let cache_control = if file.serve_tier == oneiron::artifact_hosting::ArtifactServeTier::Public {
        artifact_cache_control(file.selector, file.export)
    } else {
        "private, no-store"
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
            HeaderValue::from_static(ARTIFACT_CONTENT_SECURITY_POLICY),
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
        HeaderValue::from_static(ARTIFACT_CONTENT_SECURITY_POLICY),
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
        _ => "application/octet-stream",
    }
}
