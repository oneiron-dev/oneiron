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
/// CIDR row admits the address. IPv4-mapped IPv6 addresses are unmapped
/// first so a mapped form cannot smuggle a denied v4 class past the v6
/// arm; NAT64 well-known-prefix (64:ff9b::/96, RFC 6052) addresses are
/// decoded the same way — the embedded v4 address is what the packet
/// actually reaches, so the v4 deny/admit rules decide it. CIDR admission
/// matches the unmapped/decoded form too.
#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
pub(crate) fn addr_allowed(ip: IpAddr, allowed_cidrs: &[ipnet::IpNet]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match embedded_ipv4(&v6) {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    };
    if allowed_cidrs.iter().any(|c| c.contains(&ip)) {
        return true;
    }
    is_globally_routable(ip)
}

/// Decode the embedded IPv4 form of a v4-mapped (::ffff:0:0/96) or NAT64
/// well-known-prefix (64:ff9b::/96, RFC 6052 — the v4 sits in the low 32
/// bits) address. The policy carries no other configured NAT64 prefixes, so
/// the well-known /96 is the only translation decoded here; anything else
/// stays on the v6 class rules.
#[cfg_attr(not(feature = "network-fetch"), allow(dead_code))]
fn embedded_ipv4(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = v6.segments();
    if seg[0] == 0x0064 && seg[1] == 0xFF9B && seg[2..6] == [0, 0, 0, 0] {
        let o = v6.octets();
        return Some(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
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
                || v4.octets()[0] >= 240 // 240.0.0.0/4 reserved (incl. broadcast)
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19)))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xFE00) == 0xFC00 // unique local fc00::/7
                || (seg[0] & 0xFFC0) == 0xFE80 // link local fe80::/10
                || (seg[0] & 0xFFC0) == 0xFEC0 // site local fec0::/10 (deprecated)
                || seg[..6] == [0, 0, 0, 0, 0, 0] // IPv4-compatible ::/96 (deprecated)
                || (seg[0] == 0x0064 && seg[1] == 0xFF9B && seg[2] == 1) // NAT64 local 64:ff9b:1::/48
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0) // discard 100::/64
                || (seg[0] == 0x2001 && seg[1] == 0x0000) // Teredo 2001::/32
                || (seg[0] == 0x2001 && seg[1] == 0x0002) // benchmarking 2001:2::/48
                || (seg[0] == 0x2001 && (seg[1] & 0xFFF0) == 0x0020) // ORCHIDv2 2001:20::/28
                || (seg[0] == 0x2001 && seg[1] == 0x0DB8) // documentation 2001:db8::/32
                || seg[0] == 0x2002) // 6to4 2002::/16
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

    use crate::api::{
        FetchError, FetchMethod, FetchPolicy, FetchRequest, FetchResponse, SealFetcher,
    };

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

        /// Cache identity: URL, method, purpose, and request-body digest. A
        /// body cached under a larger purpose cap can never be replayed for a
        /// smaller-cap purpose, and a GET hit never serves a POST.
        fn cache_key(request: &FetchRequest) -> String {
            let body_digest = super::super::cms::sha256(&request.request_body);
            let method = match request.method {
                FetchMethod::Get => "GET",
                FetchMethod::Post => "POST",
            };
            let purpose = match request.purpose {
                crate::api::FetchPurpose::AuthorityInformationAccess => "aia",
                crate::api::FetchPurpose::Ocsp => "ocsp",
                crate::api::FetchPurpose::Crl => "crl",
                crate::api::FetchPurpose::Timestamp => "tsa",
            };
            let mut key = format!("{purpose}\n{method}\n{}\n", request.url.as_str());
            for b in body_digest {
                key.push_str(&format!("{b:02x}"));
            }
            key
        }

        fn cache_get(&self, key: &str, cap: usize) -> Option<FetchResponse> {
            let mut cache = self.cache.lock().ok()?;
            let entry = cache.get(key)?;
            if entry.inserted.elapsed() > CACHE_TTL {
                cache.remove(key);
                return None;
            }
            // Cap is enforced before any cached byte is served: a stored body
            // larger than this request's purpose cap is a miss, never a hit.
            if entry.body.len() > cap {
                return None;
            }
            // Integrity self-check: the cached body must still match the
            // digest recorded under the canonical key.
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
            let Ok(mut cache) = self.cache.lock() else {
                return;
            };
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
        /// address set for this request — all inside the request deadline:
        /// a stalled resolver must not bypass `timeout_ms`. DNS rebinding
        /// between validation and connection cannot escape this set: the
        /// client override pins exactly these addresses for the connection.
        async fn pinned_addrs(
            &self,
            url: &url::Url,
            deadline: tokio::time::Instant,
        ) -> Result<Vec<std::net::SocketAddr>, FetchError> {
            let host = url.host_str().ok_or(FetchError::Denied)?.to_string();
            let port = url.port_or_known_default().ok_or(FetchError::Denied)?;
            resolve_pinned(
                async move {
                    tokio::net::lookup_host((host.as_str(), port))
                        .await
                        .map(std::iter::Iterator::collect::<Vec<_>>)
                },
                &self.policy.allowed_cidrs,
                deadline,
            )
            .await
        }

        fn client_for(
            host: &str,
            addrs: &[std::net::SocketAddr],
        ) -> Result<reqwest::Client, FetchError> {
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
            deadline: tokio::time::Instant,
        ) -> Result<reqwest::Response, FetchError> {
            if !origin_allowed(&self.policy, url) {
                return Err(FetchError::Denied);
            }
            let addrs = self.pinned_addrs(url, deadline).await?;
            let host = url.host_str().ok_or(FetchError::Denied)?;
            let client = Self::client_for(host, &addrs)?;
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
            let resp = tokio::time::timeout_at(deadline, builder.send())
                .await
                .map_err(|_| FetchError::Timeout)?
                .map_err(|_| FetchError::Unavailable)?;
            Ok(resp)
        }

        /// Stream the body under the per-purpose cap AND the request's total
        /// deadline: the header-phase timeout does not cover the body phase,
        /// so every chunk read races the same deadline (a stalled body is a
        /// Timeout, not an unbounded wait).
        async fn stream_body<S>(
            stream: &mut S,
            content_type: Option<String>,
            cap: usize,
            deadline: tokio::time::Instant,
        ) -> Result<FetchResponse, FetchError>
        where
            S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
        {
            let mut body = Vec::new();
            loop {
                let chunk = tokio::time::timeout_at(deadline, stream.next())
                    .await
                    .map_err(|_| FetchError::Timeout)?;
                let Some(chunk) = chunk else { break };
                let chunk = chunk.map_err(|_| FetchError::Unavailable)?;
                if body.len() + chunk.len() > cap {
                    return Err(FetchError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(FetchResponse { body, content_type })
        }
    }

    /// Resolve through `lookup`, filter by the address policy, bound by the
    /// request deadline. A resolution that outlives the deadline is a
    /// Timeout, never an unbounded wait.
    async fn resolve_pinned(
        lookup: impl std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>,
        allowed_cidrs: &[ipnet::IpNet],
        deadline: tokio::time::Instant,
    ) -> Result<Vec<std::net::SocketAddr>, FetchError> {
        let looked_up = tokio::time::timeout_at(deadline, lookup)
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(|_| FetchError::Unavailable)?;
        let pinned: Vec<_> = looked_up
            .into_iter()
            .filter(|a| addr_allowed(a.ip(), allowed_cidrs))
            .collect();
        if pinned.is_empty() {
            return Err(FetchError::Denied);
        }
        Ok(pinned)
    }

    #[async_trait]
    impl SealFetcher for SsrfGuardedHttpFetcher {
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
            // Purpose cap first: it gates both the cache hit and the network
            // path, so no byte is served before the cap is known.
            let cap = purpose_cap(&self.policy, request.purpose);
            let key = Self::cache_key(&request);
            if let Some(hit) = self.cache_get(&key, cap) {
                return Ok(hit);
            }
            let deadline =
                tokio::time::Instant::now() + Duration::from_millis(self.policy.timeout_ms);
            let mut url = request.url.clone();
            let mut hops = 0u8;
            let response = loop {
                let resp = self.one_hop(&url, &request, deadline).await?;
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
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut stream = response.bytes_stream();
            let out = Self::stream_body(&mut stream, content_type, cap, deadline).await?;
            self.cache_put(key, &out);
            Ok(out)
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used)]
        use super::*;

        fn request(method: FetchMethod, purpose: crate::api::FetchPurpose) -> FetchRequest {
            FetchRequest {
                purpose,
                url: url::Url::parse("https://ca.example.test/x").unwrap(),
                method,
                request_body: vec![1, 2, 3],
                content_type: None,
            }
        }

        #[test]
        fn cache_key_binds_method_and_purpose() {
            let get_crl = SsrfGuardedHttpFetcher::cache_key(&request(
                FetchMethod::Get,
                crate::api::FetchPurpose::Crl,
            ));
            let post_crl = SsrfGuardedHttpFetcher::cache_key(&request(
                FetchMethod::Post,
                crate::api::FetchPurpose::Crl,
            ));
            let get_ocsp = SsrfGuardedHttpFetcher::cache_key(&request(
                FetchMethod::Get,
                crate::api::FetchPurpose::Ocsp,
            ));
            assert_ne!(get_crl, post_crl, "method participates in the key");
            assert_ne!(get_crl, get_ocsp, "purpose participates in the key");
        }

        #[test]
        fn cache_hit_beyond_purpose_cap_is_a_miss() {
            let fetcher = SsrfGuardedHttpFetcher::new(FetchPolicy::default());
            let req = request(FetchMethod::Get, crate::api::FetchPurpose::Crl);
            let key = SsrfGuardedHttpFetcher::cache_key(&req);
            let big = FetchResponse {
                body: vec![7u8; 1024],
                content_type: None,
            };
            fetcher.cache_put(key.clone(), &big);
            assert!(fetcher.cache_get(&key, 2048).is_some(), "within cap hits");
            assert!(
                fetcher.cache_get(&key, 512).is_none(),
                "cached body larger than this request's purpose cap must not be served"
            );
        }

        #[tokio::test]
        async fn dns_resolution_races_the_total_deadline() {
            // A resolver that never answers must abort at the deadline, not
            // hang past timeout_ms (test-double resolver).
            let past = tokio::time::Instant::now() - Duration::from_secs(1);
            let lookup = std::future::pending::<std::io::Result<Vec<std::net::SocketAddr>>>();
            let err = super::resolve_pinned(lookup, &[], past).await.unwrap_err();
            assert!(matches!(err, FetchError::Timeout));
            // An immediate answer inside the deadline resolves and filters.
            let later = tokio::time::Instant::now() + Duration::from_secs(60);
            let ok_lookup = async {
                Ok(vec![std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                    443,
                )])
            };
            let pinned = super::resolve_pinned(ok_lookup, &[], later).await.unwrap();
            assert_eq!(pinned.len(), 1);
        }

        #[tokio::test]
        async fn body_stream_races_the_total_deadline() {
            // One immediate chunk, then a stream that never yields: the
            // header-phase timeout does not cover this, the deadline must.
            let mut stream =
                futures_util::stream::iter(vec![Ok(bytes::Bytes::from_static(b"chunk"))])
                    .chain(futures_util::stream::pending());
            let past = tokio::time::Instant::now() - Duration::from_secs(1);
            let err = SsrfGuardedHttpFetcher::stream_body(&mut stream, None, 1024, past)
                .await
                .unwrap_err();
            assert!(matches!(err, FetchError::Timeout));
            // A finite stream inside the deadline streams fine.
            let mut ok_stream =
                futures_util::stream::iter(vec![Ok(bytes::Bytes::from_static(b"ab"))]);
            let later = tokio::time::Instant::now() + Duration::from_secs(60);
            let out = SsrfGuardedHttpFetcher::stream_body(&mut ok_stream, None, 1024, later)
                .await
                .unwrap();
            assert_eq!(out.body, b"ab");
        }
    }
}

#[cfg(feature = "network-fetch")]
pub use http::SsrfGuardedHttpFetcher;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn policy() -> FetchPolicy {
        FetchPolicy {
            allowed_origins: vec![url::Url::parse("https://ca.example.test").unwrap()],
            allowed_cidrs: Vec::new(),
            ..FetchPolicy::default()
        }
    }

    #[test]
    fn origin_matching_is_exact_scheme_host_port() {
        let p = policy();
        assert!(origin_allowed(
            &p,
            &url::Url::parse("https://ca.example.test/ocsp?x=1").unwrap()
        ));
        assert!(origin_allowed(
            &p,
            &url::Url::parse("https://ca.example.test:443/").unwrap()
        ));
        assert!(!origin_allowed(
            &p,
            &url::Url::parse("http://ca.example.test/").unwrap()
        ));
        assert!(!origin_allowed(
            &p,
            &url::Url::parse("https://ca.example.test:444/").unwrap()
        ));
        assert!(!origin_allowed(
            &p,
            &url::Url::parse("https://sub.ca.example.test/").unwrap()
        ));
        assert!(!origin_allowed(
            &p,
            &url::Url::parse("ftp://ca.example.test/").unwrap()
        ));
    }

    #[test]
    fn address_classes_denied_unless_cidr_admits() {
        let cidrs: Vec<ipnet::IpNet> = Vec::new();
        let denied_v4 = [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 8),
            Ipv4Addr::new(172, 16, 3, 4),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(100, 64, 0, 1),
        ];
        for ip in denied_v4 {
            assert!(!addr_allowed(IpAddr::V4(ip), &cidrs), "{ip} must be denied");
        }
        assert!(addr_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &cidrs));
        let denied_v6 = [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            "fc00::1".parse::<Ipv6Addr>().unwrap(),
            "ff02::1".parse::<Ipv6Addr>().unwrap(),
            "fec0::1".parse::<Ipv6Addr>().unwrap(), // site local
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(), // documentation
            "2002::1".parse::<Ipv6Addr>().unwrap(), // 6to4
            "2001::1".parse::<Ipv6Addr>().unwrap(), // Teredo
            "2001:2::1".parse::<Ipv6Addr>().unwrap(), // benchmarking
            "2001:20::1".parse::<Ipv6Addr>().unwrap(), // ORCHIDv2
            "64:ff9b:1::1".parse::<Ipv6Addr>().unwrap(), // NAT64 local-use
            "100::1".parse::<Ipv6Addr>().unwrap(),  // discard-only
            "::8.8.8.8".parse::<Ipv6Addr>().unwrap(), // v4-compatible ::/96
        ];
        for ip in denied_v6 {
            assert!(!addr_allowed(IpAddr::V6(ip), &cidrs), "{ip} must be denied");
        }
        assert!(addr_allowed(
            IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
            &cidrs
        ));
        // Global 2001: space stays allowed.
        assert!(addr_allowed(
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            &cidrs
        ));
        // Explicit CIDR admission overrides the class denial.
        let admit: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(addr_allowed(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), &admit));
    }

    #[test]
    fn nat64_well_known_prefix_decodes_the_embedded_v4() {
        let cidrs: Vec<ipnet::IpNet> = Vec::new();
        // 64:ff9b::/96 (RFC 6052): the embedded v4 decides the class rules.
        // 64:ff9b::808:808 embeds 8.8.8.8 — global, allowed.
        assert!(addr_allowed(
            IpAddr::V6("64:ff9b::808:808".parse().unwrap()),
            &cidrs
        ));
        // 64:ff9b::a9fe:a9fe embeds 169.254.169.254 — link-local, denied.
        assert!(!addr_allowed(
            IpAddr::V6("64:ff9b::a9fe:a9fe".parse().unwrap()),
            &cidrs
        ));
        // 64:ff9b::7f00:1 embeds 127.0.0.1 — loopback, denied.
        assert!(!addr_allowed(
            IpAddr::V6("64:ff9b::7f00:1".parse().unwrap()),
            &cidrs
        ));
        // A v4 CIDR admit row matches the decoded embedded address.
        let admit: Vec<ipnet::IpNet> = vec!["169.254.0.0/16".parse().unwrap()];
        assert!(addr_allowed(
            IpAddr::V6("64:ff9b::a9fe:a9fe".parse().unwrap()),
            &admit
        ));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_unmapped_before_the_class_check() {
        let cidrs: Vec<ipnet::IpNet> = Vec::new();
        // ::ffff:7f00:1 is mapped 127.0.0.1 — denied via the v4 loopback arm.
        let mapped_loopback: Ipv6Addr = "::ffff:7f00:1".parse().unwrap();
        assert!(!addr_allowed(IpAddr::V6(mapped_loopback), &cidrs));
        // ::ffff:808:808 is mapped 8.8.8.8 — global, allowed.
        let mapped_global: Ipv6Addr = "::ffff:808:808".parse().unwrap();
        assert!(addr_allowed(IpAddr::V6(mapped_global), &cidrs));
        // A v4 CIDR admit row matches the unmapped form.
        let admit: Vec<ipnet::IpNet> = vec!["127.0.0.0/8".parse().unwrap()];
        assert!(addr_allowed(IpAddr::V6(mapped_loopback), &admit));
    }

    #[test]
    fn reserved_240_4_is_denied() {
        let cidrs: Vec<ipnet::IpNet> = Vec::new();
        assert!(!addr_allowed(
            IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
            &cidrs
        ));
        assert!(!addr_allowed(
            IpAddr::V4(Ipv4Addr::new(250, 1, 2, 3)),
            &cidrs
        ));
        // 239.x stays covered by the multicast arm; 238.x is multicast too,
        // so pin the boundary on the v6-mapped form instead: ::ffff:f000:1.
        let mapped_reserved: Ipv6Addr = "::ffff:f000:1".parse().unwrap();
        assert!(!addr_allowed(IpAddr::V6(mapped_reserved), &cidrs));
    }

    #[test]
    fn purpose_caps_come_from_policy() {
        let p = FetchPolicy::default();
        assert_eq!(purpose_cap(&p, FetchPurpose::Crl), 8_388_608);
        assert_eq!(purpose_cap(&p, FetchPurpose::Timestamp), 1_048_576);
        assert_eq!(purpose_cap(&p, FetchPurpose::Ocsp), 1_048_576);
        assert_eq!(
            purpose_cap(&p, FetchPurpose::AuthorityInformationAccess),
            1_048_576
        );
    }
}
