//! SSRF-guarded fetcher (§5). The one fetch door (GATE-1 amendment A4):
//! every AIA, OCSP, CRL, and TSA fetch passes through [`crate::SealFetcher`].
//!
//! Policy evaluation is compiled with `native` so it is unit-testable
//! without the HTTP stack; the reqwest-backed [`SsrfGuardedHttpFetcher`]
//! rides `network-fetch`.

use std::net::IpAddr;

use crate::api::{FetchPolicy, FetchPurpose};

/// Rule 1: only configured exact origins, scheme included. Origins are
/// compared as `scheme://host[:port]`; query strings never participate.
#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
pub(crate) fn origin_allowed(policy: &FetchPolicy, url: &url::Url) -> bool {
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    policy.allowed_origins.iter().any(|o| {
        o.scheme() == url.scheme()
            && o.host_str() == url.host_str()
            && effective_port(o) == effective_port(url)
    })
}

#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
fn effective_port(u: &url::Url) -> u16 {
    u.port_or_known_default().unwrap_or(0)
}

/// Rule 2: address classes. Deny loopback, link-local, private, multicast,
/// unspecified, and other non-global ranges unless an explicit configured
/// CIDR row admits the address.
#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
pub(crate) fn addr_allowed(ip: IpAddr, allowed_cidrs: &[ipnet::IpNet]) -> bool {
    if allowed_cidrs.iter().any(|c| c.contains(&ip)) {
        return true;
    }
    is_globally_routable(ip)
}

#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19)))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xFE00) == 0xFC00 // unique local
                || (v6.segments()[0] & 0xFFC0) == 0xFE80) // link local
        }
    }
}

/// Rule 5: per-purpose streaming cap.
#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
pub(crate) fn purpose_cap(policy: &FetchPolicy, purpose: FetchPurpose) -> usize {
    match purpose {
        FetchPurpose::AuthorityInformationAccess => policy.max_aia_bytes,
        FetchPurpose::Ocsp => policy.max_ocsp_bytes,
        FetchPurpose::Crl => policy.max_crl_bytes,
        FetchPurpose::Timestamp => policy.max_tsa_bytes,
    }
}

// ---------------------------------------------------------------------------
// Production guarded HTTP fetcher (network-fetch)
// ---------------------------------------------------------------------------

#[cfg(feature = "network-fetch")]
mod http {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use futures_util::StreamExt;

    use crate::api::{FetchError, FetchMethod, FetchPolicy, FetchRequest, FetchResponse, SealFetcher};

    use super::{addr_allowed, origin_allowed, purpose_cap};

    const CACHE_MAX_ENTRIES: usize = 64;
    /// Conservative validity bound: well inside typical OCSP/CRL windows.
    const CACHE_TTL: Duration = Duration::from_secs(300);

    struct CacheEntry {
        response_digest: [u8; 32],
        body: Vec<u8>,
        content_type: Option<String>,
        inserted: Instant,
    }

    /// SSRF-guarded HTTP fetcher. Redirects are followed manually (at most
    /// `max_redirects`, default three) with the complete policy re-run on
    /// every hop. Environment/system proxies are disabled. Error values
    /// never carry URL query strings or response bodies.
    pub struct SsrfGuardedHttpFetcher {
        policy: FetchPolicy,
        cache: Mutex<HashMap<String, CacheEntry>>,
    }

    impl SsrfGuardedHttpFetcher {
        pub fn new(policy: FetchPolicy) -> Self {
            Self {
                policy,
                cache: Mutex::new(HashMap::new()),
            }
        }

        fn cache_key(request: &FetchRequest) -> String {
            let body_digest = super::super::cms::sha256(&request.request_body);
            let mut key = request.url.as_str().to_string();
            for b in body_digest {
                key.push_str(&format!("{b:02x}"));
            }
            key
        }

        fn cache_get(&self, key: &str) -> Option<FetchResponse> {
            let mut cache = self.cache.lock().ok()?;
            let entry = cache.get(key)?;
            if entry.inserted.elapsed() > CACHE_TTL {
                cache.remove(key);
                return None;
            }
            // Integrity self-check: the cached body must still match the
            // digest recorded under the canonical-URL key.
            if super::super::cms::sha256(&entry.body) != entry.response_digest {
                cache.remove(key);
                return None;
            }
            Some(FetchResponse {
                body: entry.body.clone(),
                content_type: entry.content_type.clone(),
            })
        }

        fn cache_put(&self, key: String, resp: &FetchResponse) {
            let Ok(mut cache) = self.cache.lock() else { return };
            if cache.len() >= CACHE_MAX_ENTRIES {
                cache.retain(|_, e| e.inserted.elapsed() <= CACHE_TTL);
                if cache.len() >= CACHE_MAX_ENTRIES {
                    cache.clear();
                }
            }
            cache.insert(
                key,
                CacheEntry {
                    response_digest: super::super::cms::sha256(&resp.body),
                    body: resp.body.clone(),
                    content_type: resp.content_type.clone(),
                    inserted: Instant::now(),
                },
            );
        }

        /// Resolve DNS once, apply the address policy, and return the pinned
        /// address set for this request. DNS rebinding between validation
        /// and connection cannot escape this set: the client override pins
        /// exactly these addresses for the connection.
        async fn pinned_addrs(&self, url: &url::Url) -> Result<Vec<std::net::SocketAddr>, FetchError> {
            let host = url.host_str().ok_or(FetchError::Denied)?.to_string();
            let port = url.port_or_known_default().ok_or(FetchError::Denied)?;
            let looked_up = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| FetchError::Unavailable)?;
            let pinned: Vec<_> = looked_up
                .filter(|a| addr_allowed(a.ip(), &self.policy.allowed_cidrs))
                .collect();
            if pinned.is_empty() {
                return Err(FetchError::Denied);
            }
            Ok(pinned)
        }

        fn client_for(&self, host: &str, addrs: &[std::net::SocketAddr]) -> Result<reqwest::Client, FetchError> {
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(host, addrs)
                .build()
                .map_err(|_| FetchError::Unavailable)
        }

        async fn one_hop(
            &self,
            url: &url::Url,
            request: &FetchRequest,
        ) -> Result<reqwest::Response, FetchError> {
            if !origin_allowed(&self.policy, url) {
                return Err(FetchError::Denied);
            }
            let addrs = self.pinned_addrs(url).await?;
            let host = url.host_str().ok_or(FetchError::Denied)?;
            let client = self.client_for(host, &addrs)?;
            let builder = match request.method {
                FetchMethod::Get => client.get(url.as_str()),
                FetchMethod::Post => {
                    let b = client.post(url.as_str());
                    match &request.content_type {
                        Some(ct) => b.header(reqwest::header::CONTENT_TYPE, ct.as_str()),
                        None => b,
                    }
                    .body(request.request_body.clone())
                }
            };
            let send = builder.send();
            let resp = tokio::time::timeout(
                Duration::from_millis(self.policy.timeout_ms),
                send,
            )
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(|_| FetchError::Unavailable)?;
            Ok(resp)
        }

        async fn stream_body(
            &self,
            resp: reqwest::Response,
            cap: usize,
        ) -> Result<FetchResponse, FetchError> {
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| FetchError::Unavailable)?;
                if body.len() + chunk.len() > cap {
                    return Err(FetchError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(FetchResponse { body, content_type })
        }
    }

    #[async_trait]
    impl SealFetcher for SsrfGuardedHttpFetcher {
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
            let key = Self::cache_key(&request);
            if let Some(hit) = self.cache_get(&key) {
                return Ok(hit);
            }
            let mut url = request.url.clone();
            let mut hops = 0u8;
            let cap = purpose_cap(&self.policy, request.purpose);
            let response = loop {
                let resp = self.one_hop(&url, &request).await?;
                if resp.status().is_redirection() {
                    if hops >= self.policy.max_redirects {
                        return Err(FetchError::Denied);
                    }
                    let location = resp
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|l| url.join(l).ok())
                        .ok_or(FetchError::InvalidResponse)?;
                    url = location; // next loop iteration re-runs the full policy
                    hops += 1;
                    continue;
                }
                if !resp.status().is_success() {
                    return Err(FetchError::InvalidResponse);
                }
                break resp;
            };
            let out = self.stream_body(response, cap).await?;
            self.cache_put(key, &out);
            Ok(out)
        }
    }
}

#[cfg(feature = "network-fetch")]
pub use http::SsrfGuardedHttpFetcher;
