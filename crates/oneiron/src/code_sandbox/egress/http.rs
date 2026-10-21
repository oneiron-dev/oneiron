//! Guarded, pinned HTTP with manual redirects and final-domain decisions.

use super::*;
use reqwest::{Url, header};
use std::io::Read;

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
        return deliver(proxy, &url, response);
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
    let mut answer = deliver(proxy, &upstream, response)?;
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
/// its body under the byte bound, policy-checked and receipted as
/// delivered.
fn deliver(
    proxy: &OpenEgressProxy,
    url: &Url,
    mut response: reqwest::blocking::Response,
) -> io::Result<HttpResponse> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_owned())))
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "content-encoding" | "content-length" | "transfer-encoding" | "connection"
            )
        })
        .collect();
    let mut bytes = Vec::new();
    (&mut response)
        .take(proxy.config.max_response_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io::Error::other)?;
    if bytes.len() > proxy.config.max_response_bytes {
        proxy.record(
            "http_response",
            url.as_str(),
            &bytes,
            PolicyClassifyDecision::Block,
            PolicyVerdictCategory::None,
            None,
        )?;
        return Err(io::Error::other("egress response byte bound"));
    }
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
        body: bytes,
    })
}
