//! Published zero-engine-action backends on the artifact-only listener.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::Arc;

use axum::Router;
use axum::extract::{OriginalUri, Path, Query, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, HOST, LOCATION, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::Response;
use axum::routing::any;
use serde::Deserialize;

use super::route::ArtifactRoute;
use super::{ArtifactServeQuery, CoreAuth, CoreScope, SyncServer};
use crate::error::{ApiError, EnvelopedApiError};

#[path = "backend_runtime.rs"]
mod runtime;

const BACKEND_ROUTE_PREFIX: &str = "/_apps/";
const BACKEND_MANIFEST_PATH: &str = "oneiron.backend.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendManifest {
    transport: BackendTransport,
    command: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackendTransport {
    Http1Stdio,
}

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(&format!("{BACKEND_ROUTE_PREFIX}{{artifact}}"), any(serve))
        .route(&format!("{BACKEND_ROUTE_PREFIX}{{artifact}}/"), any(serve))
        .route(
            &format!("{BACKEND_ROUTE_PREFIX}{{artifact}}/{{*path}}"),
            any(serve),
        )
}

async fn serve(
    State(server): State<Arc<SyncServer>>,
    Path(params): Path<HashMap<String, String>>,
    Query(query): Query<ArtifactServeQuery>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Result<Response, EnvelopedApiError> {
    let host = server.artifact_backend.clone().ok_or_else(missing)?;
    let profile = host.profile.clone();
    let artifact = params.get("artifact").ok_or_else(missing)?;
    let internal: Uri = format!(
        "/a/{}",
        uri.path_and_query()
            .ok_or_else(missing)?
            .as_str()
            .strip_prefix(BACKEND_ROUTE_PREFIX)
            .ok_or_else(missing)?
    )
    .parse()
    .map_err(|_| missing())?;
    let route = ArtifactRoute::parse(&internal, artifact, &query)?;
    let (mut parts, body) = request.into_parts();
    let caller = CoreAuth::for_managed_request(
        &parts.headers,
        &parts.extensions,
        crate::auth::request_path(&parts),
        &server,
    )
    .unwrap_or_else(|| {
        CoreAuth::from_headers(&parts.headers, &server.config, server.vault().as_ref())
    });
    let principal = caller
        .ok()
        .filter(|auth| {
            auth.has_scope(CoreScope::Read) && auth.require_unrestricted_record_scope().is_ok()
        })
        .and_then(|auth| {
            auth.principal_ref()
                .and_then(|id| oneiron::EntityId::from_hex(id).ok())
        });
    let permit = host
        .sessions
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal_server_error("artifact backend host stopped"))?;
    let vault = server.vault().clone();
    let artifact = route.artifact.clone();
    let token = route.token.clone();
    let selector = route.selector;
    let staged = tokio::task::spawn_blocking(move || {
        stage(
            &vault,
            &artifact,
            selector,
            token.as_deref(),
            principal,
            permit,
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("artifact backend staging failed"))?
    .map_err(|error| super::core_engine_error("artifact backend staging failed", error))?
    .ok_or_else(missing)?;
    let app_query = application_query(uri.query());
    if let Some(target) = route.redirect() {
        let target = target.replacen("/a/", BACKEND_ROUTE_PREFIX, 1);
        let target = if app_query.is_empty() {
            target
        } else {
            format!("{target}?{app_query}")
        };
        return super::artifact_redirect_response(&target);
    }
    let encoded_path = route.encoded_path();
    let prefix = uri.path().strip_suffix(encoded_path).ok_or_else(missing)?;
    let policy = backend_policy(&uri, &parts.headers, prefix)?;
    let target = if app_query.is_empty() {
        format!("/{encoded_path}")
    } else {
        format!("/{encoded_path}?{app_query}")
    };
    parts.uri = target.parse().map_err(|_| missing())?;
    // No owner/read credential, link capability, forwarding attestation or
    // host cookie crosses the guest boundary. The original Body is moved.
    strip_hop_headers(&mut parts.headers);
    let private_headers: Vec<_> = parts
        .headers
        .keys()
        .filter(|name| {
            matches!(
                name.as_str(),
                "authorization" | "cookie" | "origin" | "referer" | "forwarded"
            ) || name.as_str().starts_with("x-forwarded-")
                || name.as_str().starts_with("x-oneiron-")
        })
        .cloned()
        .collect();
    for name in private_headers {
        parts.headers.remove(name);
    }
    parts
        .headers
        .insert(HOST, HeaderValue::from_static("artifact.invalid"));
    parts
        .headers
        .insert("connection", HeaderValue::from_static("close"));
    parts.version = axum::http::Version::HTTP_11;
    parts.extensions.clear();
    let mut response = runtime::forward(profile, staged, Request::from_parts(parts, body)).await?;
    strip_hop_headers(response.headers_mut());
    response.headers_mut().remove("set-cookie");
    // CSP ignores source paths after a redirect. App redirects therefore
    // resolve inside this admitted app, never into another artifact's path.
    if let Some(location) = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
    {
        let value = backend_location(prefix, &target, location)?;
        response.headers_mut().insert(LOCATION, value);
    }
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, policy);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(response)
}

fn stage(
    vault: &oneiron::Vault,
    artifact: &str,
    selector: oneiron::ArtifactSnapshotSelector,
    token: Option<&str>,
    principal: Option<oneiron::EntityId>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> oneiron::Result<Option<runtime::StagedBackend>> {
    let directory = tempfile::tempdir()?;
    // The private parent stays 0700 on the host. Only its read-only child is
    // mounted, so the configured non-root guest can traverse that child.
    let source = directory.path().join("source");
    fs::create_dir(&source)?;
    let admitted = vault.visit_authorized_artifact_codebase(
        artifact,
        selector,
        token,
        principal,
        |file, mode| {
            let target = source.join(&file.path);
            let parent = target
                .parent()
                .ok_or_else(|| std::io::Error::other("artifact file parent missing"))?;
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for parent in parent
                    .ancestors()
                    .take_while(|parent| parent.starts_with(&source))
                {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
                }
            }
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            output.write_all(&file.bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o444 | (mode & 0o111)))?;
            }
            Ok(())
        },
    )?;
    if admitted.is_none() {
        return Ok(None);
    }
    let bytes = match fs::read(source.join(BACKEND_MANIFEST_PATH)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let manifest: BackendManifest = serde_json::from_slice(&bytes).map_err(|error| {
        oneiron::Error::InvalidConfig(format!("artifact backend manifest: {error}"))
    })?;
    let BackendTransport::Http1Stdio = manifest.transport;
    if manifest.command.is_empty() || manifest.command[0].is_empty() {
        return Err(oneiron::Error::InvalidConfig(
            "artifact backend command is empty".into(),
        ));
    }
    let source = fs::canonicalize(source)?;
    Ok(Some(runtime::StagedBackend {
        directory,
        source,
        permit,
        command: manifest
            .command
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect(),
    }))
}

fn backend_location(
    prefix: &str,
    current: &str,
    location: &str,
) -> Result<HeaderValue, EnvelopedApiError> {
    let (target, fragment) = location.split_once('#').unwrap_or((location, ""));
    let (current_path, current_query) = current.split_once('?').unwrap_or((current, ""));
    let target = target.replace('\\', "/");
    let scheme = target.split_once(':').is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme.bytes().enumerate().all(|(i, byte)| {
                byte.is_ascii_alphabetic()
                    || (i > 0 && (byte.is_ascii_digit() || b"+.-".contains(&byte)))
            })
    });
    let (path, query) = if scheme || target.starts_with("//") {
        let uri: Uri = target
            .parse()
            .map_err(|_| ApiError::internal_server_error("artifact backend redirect invalid"))?;
        (
            uri.path().to_owned(),
            uri.query().unwrap_or_default().to_owned(),
        )
    } else if target.is_empty() {
        (current_path.to_owned(), current_query.to_owned())
    } else {
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let path = if path.is_empty() {
            current_path.to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            let directory = current_path
                .rsplit_once('/')
                .map_or("", |(directory, _)| directory);
            format!("{directory}/{path}")
        };
        (path, query.to_owned())
    };
    let path = super::route::backend_redirect_path(&path)?;
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let fragment = if fragment.is_empty() {
        String::new()
    } else {
        format!("#{fragment}")
    };
    HeaderValue::from_str(&format!("{prefix}{path}{query}{fragment}"))
        .map_err(|_| ApiError::internal_server_error("artifact backend redirect invalid").into())
}

fn application_query(query: Option<&str>) -> String {
    // The control query belongs to the artifact router, never to the app.
    query
        .unwrap_or_default()
        .split('&')
        .filter(|part| !super::route::selector_query_pair(part) && !part.is_empty())
        .collect::<Vec<_>>()
        .join("&")
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| axum::http::HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn backend_policy(
    uri: &Uri,
    headers: &HeaderMap,
    prefix: &str,
) -> Result<HeaderValue, EnvelopedApiError> {
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| headers.get(HOST).and_then(|value| value.to_str().ok()))
        .ok_or_else(missing)?;
    let parsed: axum::http::uri::Authority = authority.parse().map_err(|_| missing())?;
    if !parsed
        .as_str()
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-_:[]".contains(&byte))
    {
        return Err(missing());
    }
    // A path-scoped source lets this document call its own backend without
    // opening fetch access to every other artifact on the local listener.
    let csp_path: String = prefix
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~/%".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    let endpoint = format!("http://{parsed}{csp_path}");
    HeaderValue::from_str(&format!(
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; connect-src {endpoint}; object-src 'none'; base-uri 'none'; form-action {endpoint}; frame-ancestors 'none'; frame-src 'none'; worker-src 'none'; sandbox allow-scripts allow-same-origin"
    )).map_err(|_| missing())
}

fn missing() -> EnvelopedApiError {
    ApiError::not_found("artifact", None).into()
}
