//! Guarded, pinned HTTP with manual redirects and final-domain decisions.

use super::*;
use crate::limit_ask::EngineLimit;
use oneiron_container::HostNetPermit;
use reqwest::{Url, header};
use std::io::Read;

/// Bytes of a response body read and leased at a time (FIX 7946).
const BODY_CHUNK_BYTES: usize = 64 * 1024;
/// The first wait for a full host byte floor, doubled at each wait up to
/// [`FLOOR_WAIT_MAX`] (FIX 7946).
const FLOOR_WAIT_FIRST: Duration = Duration::from_millis(5);
/// The longest single wait for a full host byte floor.
const FLOOR_WAIT_MAX: Duration = Duration::from_millis(250);

pub(super) fn fetch(proxy: &OpenEgressProxy, request: HttpRequest) -> io::Result<HttpResponse> {
    let mut url = Url::parse(&request.url).map_err(io::Error::other)?;
    let mut method =
        reqwest::Method::from_bytes(request.method.as_bytes()).map_err(io::Error::other)?;
    let mut body = request.body;
    let mut headers = request.headers;
    let start = std::time::Instant::now();
    for hop in 0..=proxy.config.max_redirects {
        let attempt = (|| {
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "HTTP scheme or URL credentials",
                ));
            }
            let host = url
                .host_str()
                .ok_or_else(|| io::Error::other("HTTP host"))?
                .trim_start_matches('[')
                .trim_end_matches(']');
            let port = url
                .port_or_known_default()
                .ok_or_else(|| io::Error::other("HTTP port"))?;
            let addresses = proxy.resolve(host, port)?;
            let remaining = proxy
                .config
                .request_timeout
                .checked_sub(start.elapsed())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "egress deadline"))?;
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(remaining)
                .resolve_to_addrs(host, &addresses)
                .build()
                .map_err(io::Error::other)?;
            let mut builder = client
                .request(method.clone(), url.clone())
                .body(body.clone());
            for (name, value) in &headers {
                if carried(name) {
                    builder = builder.header(name, value);
                }
            }
            let (decision, category, policy_receipt) = proxy.policy(url.as_str(), &body)?;
            proxy.record(
                "http_request",
                url.as_str(),
                &body,
                decision,
                category,
                policy_receipt,
            )?;
            if !OpenEgressProxy::permits(decision) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "egress policy",
                ));
            }
            let response = builder.send().map_err(io::Error::other)?;
            Ok(response)
        })();
        let response = match attempt {
            Ok(response) => response,
            Err(error) => {
                proxy.record(
                    "http_failure",
                    url.as_str(),
                    &[],
                    PolicyClassifyDecision::Block,
                    PolicyVerdictCategory::None,
                    None,
                )?;
                return Err(error);
            }
        };
        let status = response.status().as_u16();
        if request.follow_redirects && matches!(status, 301 | 302 | 303 | 307 | 308) {
            let next = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| url.join(v).ok());
            let redirect = next
                .filter(|_| hop < proxy.config.max_redirects)
                .ok_or_else(|| io::Error::other("egress redirect bound or location"));
            proxy.record(
                "http_redirect",
                url.as_str(),
                &[],
                PolicyClassifyDecision::Allow,
                PolicyVerdictCategory::None,
                None,
            )?;
            let next = redirect?;
            if url.origin() != next.origin() {
                headers.retain(|(name, _)| {
                    !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "authorization" | "cookie"
                    )
                });
            }
            if status == 303
                || ((status == 301 || status == 302) && method == reqwest::Method::POST)
            {
                method = reqwest::Method::GET;
                body.clear();
            }
            url = next;
            continue;
        }
        return deliver(proxy, &url, response, start + proxy.config.request_timeout);
    }
    Err(io::Error::other("egress redirects exhausted"))
}

/// The fixture origin's forward (FIX 8061): `request`, made to the fixture
/// URL `logical`, sent to `target` alone at the same path and query, once,
/// on a fresh HTTP/1 connection with no proxy. A redirect goes back to the
/// browser, whose next request comes through the fixture origin again.
/// CONNECT and Upgrade are refused: the forward is no tunnel. The policy
/// and receipts name the upstream URL at `target`; the guest is answered at
/// `logical`, with the upstream's status, headers and body.
pub(super) fn forward(
    proxy: &OpenEgressProxy,
    target: SocketAddrV4,
    logical: &Url,
    request: &HttpRequest,
) -> io::Result<HttpResponse> {
    // The authority alone is replaced, never joined: the path cannot name
    // another destination.
    let mut upstream = logical.clone();
    let deadline = Instant::now() + proxy.config.request_timeout;
    let attempt = (|| {
        upstream
            .set_ip_host(IpAddr::V4(*target.ip()))
            .and_then(|()| upstream.set_port(Some(target.port())))
            .map_err(|()| io::Error::other("fixture forward authority"))?;
        let method =
            reqwest::Method::from_bytes(request.method.as_bytes()).map_err(io::Error::other)?;
        if method == reqwest::Method::CONNECT
            || request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture forward tunnel",
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(proxy.config.request_timeout)
            .build()
            .map_err(io::Error::other)?;
        let mut builder = client
            .request(method, upstream.clone())
            .body(request.body.clone());
        for (name, value) in &request.headers {
            if carried(name) {
                builder = builder.header(name, value);
            }
        }
        let (decision, category, policy_receipt) =
            proxy.policy(upstream.as_str(), &request.body)?;
        proxy.record(
            "http_request",
            upstream.as_str(),
            &request.body,
            decision,
            category,
            policy_receipt,
        )?;
        if !OpenEgressProxy::permits(decision) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "egress policy",
            ));
        }
        builder.send().map_err(io::Error::other)
    })();
    let response = match attempt {
        Ok(response) => response,
        Err(error) => {
            proxy.record(
                "http_failure",
                upstream.as_str(),
                &[],
                PolicyClassifyDecision::Block,
                PolicyVerdictCategory::None,
                None,
            )?;
            return Err(error);
        }
    };
    let mut answer = deliver(proxy, &upstream, response, deadline)?;
    answer.url = logical.to_string();
    Ok(answer)
}

/// A guest header the host's request carries: the guest's Host, framing,
/// encoding and proxy credentials are the host client's own.
fn carried(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "proxy-authorization"
            | "transfer-encoding"
            | "content-length"
            | "accept-encoding"
    )
}

/// The answer `response` delivered from `url`: its headers less framing,
/// its whole body read under the vault's host byte floor before
/// `deadline` (FIX 7946), policy-checked and receipted as delivered.
fn deliver(
    proxy: &OpenEgressProxy,
    url: &Url,
    mut response: reqwest::blocking::Response,
    deadline: Instant,
) -> io::Result<HttpResponse> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "content-encoding" | "content-length" | "transfer-encoding" | "connection"
            )
        })
        .collect();
    let (bytes, _held) = match read_body_under_floor(proxy, &mut response, deadline) {
        Ok(read) => read,
        Err(error) => {
            proxy.record(
                "http_response",
                url.as_str(),
                &[],
                PolicyClassifyDecision::Block,
                PolicyVerdictCategory::None,
                None,
            )?;
            return Err(error);
        }
    };
    // The final URL and exact delivered content, not the first URL or a
    // rewritten summary, are what the policy and receipt name.
    let (decision, category, policy_receipt) = proxy.policy(url.as_str(), &bytes)?;
    proxy.record(
        "http_response",
        url.as_str(),
        &bytes,
        decision,
        category,
        policy_receipt,
    )?;
    if !OpenEgressProxy::permits(decision) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "egress policy",
        ));
    }
    Ok(HttpResponse {
        url: url.to_string(),
        status,
        headers,
        body: bytes.into(),
    })
}

/// Reads `source` whole under the vault's host byte floor (FIX 7946):
/// each chunk takes its bytes of the floor before it is kept, and the
/// permits, growing with the body, are returned with it, so the floor
/// holds the body until its caller drops them. A full floor is waited
/// for, backing off, until it frees or `deadline` passes; then the read
/// refuses with the floor's own typed saturation (`WouldBlock` naming
/// the byte floor). No byte count refuses a body: its size is measured
/// on `limits.sandbox_egress_response_bytes`, which asks past its row.
pub(super) fn read_body_under_floor(
    proxy: &OpenEgressProxy,
    source: &mut impl Read,
    deadline: Instant,
) -> io::Result<(Vec<u8>, Vec<HostNetPermit>)> {
    let floor = proxy.host_net_floor();
    let mut bytes = Vec::new();
    let mut held = Vec::new();
    let mut chunk = vec![0_u8; BODY_CHUNK_BYTES];
    loop {
        let read = match source.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        held.push(lease_body_bytes(floor, read as u64, deadline)?);
        bytes
            .try_reserve(read)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    proxy
        .vault
        .measure_limit(EngineLimit::SandboxEgressResponseBytes, bytes.len() as u64);
    Ok((bytes, held))
}

/// `bytes` of `floor`, waited for while the floor is full until `deadline`.
fn lease_body_bytes(
    floor: &dyn HostNetFloor,
    bytes: u64,
    deadline: Instant,
) -> io::Result<HostNetPermit> {
    let mut wait = FLOOR_WAIT_FIRST;
    loop {
        match floor.acquire_bytes(bytes) {
            Ok(permit) => return Ok(permit),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(wait.min(left));
                wait = wait.saturating_mul(2).min(FLOOR_WAIT_MAX);
            }
            Err(error) => return Err(error),
        }
    }
}
