//! Guarded, pinned HTTP with manual redirects and final-domain decisions.

use super::*;
use reqwest::{Url, header};
use std::io::Read;

pub(super) fn fetch(proxy: &OpenEgressProxy, request: HttpRequest) -> io::Result<HttpResponse> {
    let mut url = Url::parse(&request.url).map_err(io::Error::other)?;
    let mut method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(io::Error::other)?;
    let mut body = request.body;
    let mut headers = request.headers;
    let start = std::time::Instant::now();
    for hop in 0..=proxy.config.max_redirects {
        let attempt = (|| {
            if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "HTTP scheme or URL credentials"));
            }
            let host = url.host_str().ok_or_else(|| io::Error::other("HTTP host"))?.trim_start_matches('[').trim_end_matches(']');
            let port = url.port_or_known_default().ok_or_else(|| io::Error::other("HTTP port"))?;
            let addresses = proxy.resolve(host, port)?;
            let remaining = proxy.config.request_timeout.checked_sub(start.elapsed())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "egress deadline"))?;
            let client = reqwest::blocking::Client::builder().no_proxy()
                .redirect(reqwest::redirect::Policy::none()).timeout(remaining)
                .resolve_to_addrs(host, &addresses).build().map_err(io::Error::other)?;
            let mut builder = client.request(method.clone(), url.clone()).body(body.clone());
            for (name, value) in &headers {
                if !matches!(name.to_ascii_lowercase().as_str(), "host" | "connection" | "proxy-authorization" | "transfer-encoding" | "content-length" | "accept-encoding") {
                    builder = builder.header(name, value);
                }
            }
            let (decision, category, policy_receipt) = proxy.policy(url.as_str(), &body)?;
            proxy.record("http_request", url.as_str(), &body, decision, category, policy_receipt)?;
            if !OpenEgressProxy::permits(decision) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "egress policy"));
            }
            let response = builder.send().map_err(io::Error::other)?;
            Ok(response)
        })();
        let mut response = match attempt {
            Ok(response) => response,
            Err(error) => {
                proxy.record("http_failure", url.as_str(), &[], PolicyClassifyDecision::Block, PolicyVerdictCategory::None, None)?;
                return Err(error);
            }
        };
        let status = response.status().as_u16();
        if request.follow_redirects && matches!(status, 301 | 302 | 303 | 307 | 308) {
            let next = response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok())
                .and_then(|v| url.join(v).ok());
            let redirect = next.filter(|_| hop < proxy.config.max_redirects)
                .ok_or_else(|| io::Error::other("egress redirect bound or location"));
            proxy.record("http_redirect", url.as_str(), &[], PolicyClassifyDecision::Allow, PolicyVerdictCategory::None, None)?;
            let next = redirect?;
            if url.origin() != next.origin() {
                headers.retain(|(name, _)| !matches!(name.to_ascii_lowercase().as_str(), "authorization" | "cookie"));
            }
            if status == 303 || ((status == 301 || status == 302) && method == reqwest::Method::POST) {
                method = reqwest::Method::GET; body.clear();
            }
            url = next;
            continue;
        }
        let headers = response.headers().iter().filter_map(|(k,v)| v.to_str().ok().map(|v| (k.to_string(),v.to_owned())))
            .filter(|(k,_)| !matches!(k.as_str(), "content-encoding" | "content-length" | "transfer-encoding" | "connection")).collect();
        let mut bytes = Vec::new();
        (&mut response).take(proxy.config.max_response_bytes as u64 + 1).read_to_end(&mut bytes).map_err(io::Error::other)?;
        if bytes.len() > proxy.config.max_response_bytes {
            proxy.record("http_response", url.as_str(), &bytes, PolicyClassifyDecision::Block, PolicyVerdictCategory::None, None)?;
            return Err(io::Error::other("egress response byte bound"));
        }
        // The final URL and exact delivered content, not the first URL or a
        // rewritten summary, are what the policy and receipt name.
        let (decision, category, policy_receipt) = proxy.policy(url.as_str(), &bytes)?;
        proxy.record("http_response", url.as_str(), &bytes, decision, category, policy_receipt)?;
        if !OpenEgressProxy::permits(decision) { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "egress policy")); }
        return Ok(HttpResponse { url: url.to_string(), status, headers, body: bytes });
    }
    Err(io::Error::other("egress redirects exhausted"))
}
