//! HTTP and WebSocket forwarding on a preview-only origin.

use std::convert::Infallible;
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{
    CACHE_CONTROL, CONNECTION, CONTENT_SECURITY_POLICY, COOKIE, HOST, LOCATION, REFERRER_POLICY,
    SET_COOKIE, UPGRADE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::{Access, SharedPreview};

const ACCESS_PATH: &str = "/__oneiron_preview_access";
const ACCESS_COOKIE: &str = "oneiron_preview_access";

pub(super) async fn serve_connection(socket: TcpStream, shared: Arc<SharedPreview>) {
    let closed = shared.closed.triggered();
    let service = hyper::service::service_fn(move |request| {
        let shared = Arc::clone(&shared);
        async move {
            let mut response = handle(request, shared).await;
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
            response
                .headers_mut()
                .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
            response
                .headers_mut()
                .insert("x-oneiron-preview-stage", HeaderValue::from_static("draft"));
            response.headers_mut().insert(
                "x-robots-tag",
                HeaderValue::from_static("noindex, nofollow, noarchive"),
            );
            response.headers_mut().append(
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("worker-src 'none'; frame-ancestors 'none'"),
            );
            Ok::<_, Infallible>(response)
        }
    });
    let builder = hyper::server::conn::http1::Builder::new();
    let connection = builder
        .serve_connection(TokioIo::new(socket), service)
        .with_upgrades();
    tokio::select! {
        biased;
        () = closed => {},
        _ = connection => {},
    }
}

async fn handle(request: Request<Incoming>, shared: Arc<SharedPreview>) -> Response<Body> {
    // The listener has one random .localhost authority, not a catch-all for
    // arbitrary DNS names or absolute-form proxy requests.
    let valid_host = request
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(&shared.authority));
    if !valid_host
        || !shared.is_live()
        || request.uri().authority().is_some()
        || request.uri().scheme().is_some()
        || request.method() == Method::CONNECT
    {
        return refusal();
    }
    if request.uri().path() == ACCESS_PATH {
        return bootstrap(&request, &shared);
    }
    if request
        .headers()
        .get("origin")
        .is_some_and(|origin| origin.as_bytes() != shared.endpoint.local_url.as_bytes())
    {
        return refusal();
    }
    let Some(token) = cookie_token(request.headers()) else {
        return refusal();
    };
    let Some(access) = Access::authorize(&shared, &token) else {
        return refusal();
    };
    tokio::select! {
        biased;
        () = access.clone().revoked() => refusal(),
        response = forward(request, &access) => response.unwrap_or_else(|_| {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            response
        }),
    }
}

fn bootstrap(request: &Request<Incoming>, shared: &Arc<SharedPreview>) -> Response<Body> {
    if request.method() != Method::GET {
        return refusal();
    }
    let Some(token) = request
        .uri()
        .query()
        .and_then(|query| query.strip_prefix("token="))
    else {
        return refusal();
    };
    if Access::authorize(shared, token).is_none() {
        return refusal();
    }
    let Ok(cookie) = HeaderValue::from_str(&format!(
        "{ACCESS_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"
    )) else {
        return refusal();
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(SET_COOKIE, cookie);
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    response
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    for cookie in headers.get_all(COOKIE) {
        for part in cookie.to_str().ok()?.split(';') {
            if let Some((name, value)) = part.trim().split_once('=')
                && name == ACCESS_COOKIE
            {
                return Some(value.to_owned());
            }
        }
    }
    None
}

async fn forward(
    mut request: Request<Incoming>,
    access: &Access,
) -> anyhow::Result<Response<Body>> {
    let websocket = request.method() == Method::GET
        && request
            .headers()
            .get(UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    anyhow::ensure!(
        websocket || !request.headers().contains_key(UPGRADE),
        "unsupported preview upgrade"
    );
    let downstream_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let declared_port = access
        .shared
        .preview
        .lock()
        .expect("preview lock")
        .manifest()
        .preview
        .port;
    let stream = access.shared.process.connect(declared_port).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let driver_access = access.clone();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            () = driver_access.revoked() => {},
            _ = connection.with_upgrades() => {},
        }
    });

    let (mut parts, body) = request.into_parts();
    strip_hop_headers(&mut parts.headers);
    strip_host_credentials(&mut parts.headers);
    parts.headers.insert(
        CONNECTION,
        HeaderValue::from_static(if websocket { "upgrade" } else { "close" }),
    );
    if websocket {
        parts
            .headers
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    // Keep the preview authority and root-relative paths so a backend's
    // cookies, redirects and same-origin checks see the app's browser origin.
    parts.uri = Uri::builder()
        .path_and_query(parts.uri.path_and_query().map_or("/", |path| path.as_str()))
        .build()?;
    let mut response = sender
        .send_request(Request::from_parts(parts, Body::new(body)))
        .await?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        anyhow::ensure!(websocket, "unexpected preview upgrade");
        let downstream =
            downstream_upgrade.ok_or_else(|| anyhow::anyhow!("preview upgrade missing"))?;
        let upstream = hyper::upgrade::on(&mut response);
        let tunnel_access = access.clone();
        tokio::spawn(async move {
            let tunnel = async move {
                let (downstream, upstream) = tokio::try_join!(downstream, upstream)?;
                let mut downstream = TokioIo::new(downstream);
                let mut upstream = TokioIo::new(upstream);
                tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! {
                biased;
                () = tunnel_access.revoked() => {},
                _ = tunnel => {},
            }
        });
        strip_hop_headers(response.headers_mut());
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        response
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
    } else {
        strip_hop_headers(response.headers_mut());
    }
    isolate_cookies(response.headers_mut());
    rewrite_location(
        response.headers_mut(),
        declared_port,
        &access.shared.endpoint.local_url,
    );
    Ok(response.map(Body::new))
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
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

fn strip_host_credentials(headers: &mut HeaderMap) {
    let private: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            name == "authorization"
                || name == "forwarded"
                || name.starts_with("x-forwarded-")
                || name.starts_with("x-oneiron-")
        })
        .cloned()
        .collect();
    for name in private {
        headers.remove(name);
    }
    let app_cookies = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|cookie| {
            cookie
                .split_once('=')
                .is_some_and(|(name, _)| name != ACCESS_COOKIE)
        })
        .collect::<Vec<_>>()
        .join("; ");
    headers.remove(COOKIE);
    if !app_cookies.is_empty()
        && let Ok(value) = HeaderValue::from_str(&app_cookies)
    {
        headers.insert(COOKIE, value);
    }
}

fn isolate_cookies(headers: &mut HeaderMap) {
    let cookies: Vec<HeaderValue> = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| {
            let text = value.to_str().ok()?;
            let mut parts = text.split(';');
            let first = parts.next()?;
            if first.split_once('=')?.0.trim() == ACCESS_COOKIE {
                return None;
            }
            let mut cookie = first.to_owned();
            for part in parts {
                if part
                    .trim()
                    .split_once('=')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("domain"))
                {
                    continue;
                }
                cookie.push(';');
                cookie.push_str(part);
            }
            HeaderValue::from_str(&cookie).ok()
        })
        .collect();
    headers.remove(SET_COOKIE);
    for cookie in cookies {
        headers.append(SET_COOKIE, cookie);
    }
}

fn rewrite_location(headers: &mut HeaderMap, port: u16, origin: &str) {
    let Some(uri) = headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Uri>().ok())
    else {
        return;
    };
    if let Some(authority) = uri.authority()
        && matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]")
        && authority.port_u16() == Some(port)
        && let Ok(value) = HeaderValue::from_str(&format!(
            "{origin}{}",
            uri.path_and_query().map_or("/", |path| path.as_str())
        ))
    {
        headers.insert(LOCATION, value);
    }
}

fn refusal() -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}
