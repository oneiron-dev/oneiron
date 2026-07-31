//! Fetch-policy tests (§5, §10): offline fetcher posture, policy defaults,
//! and — with `network-fetch` — the guarded client's pre-network denials.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use oneiron_seal::{
    FetchError, FetchMethod, FetchPolicy, FetchPurpose, FetchRequest, OfflineFetcher, SealFetcher,
};

#[test]
fn fetch_policy_defaults_match_blueprint() {
    let p = FetchPolicy::default();
    assert!(p.allowed_origins.is_empty());
    assert!(p.allowed_cidrs.is_empty());
    assert_eq!(p.max_redirects, 3);
    assert_eq!(p.timeout_ms, 5_000);
    assert_eq!(p.max_aia_bytes, 1_048_576);
    assert_eq!(p.max_ocsp_bytes, 1_048_576);
    assert_eq!(p.max_crl_bytes, 8_388_608);
    assert_eq!(p.max_tsa_bytes, 1_048_576);
}

#[tokio::test]
async fn offline_fetcher_denies_everything_as_unavailable() {
    let f = OfflineFetcher;
    let req = FetchRequest {
        purpose: FetchPurpose::Timestamp,
        url: url::Url::parse("https://tsa.example.test/").unwrap(),
        method: FetchMethod::Post,
        request_body: vec![1, 2, 3],
        content_type: None,
    };
    let err = f.fetch(req).await.unwrap_err();
    assert!(matches!(err, FetchError::Unavailable));
}

#[tokio::test]
async fn fixture_fetcher_redacts_nothing_but_serves_configured_urls() {
    let mut fetcher = support::FixtureFetcher::offline();
    fetcher.responses.insert(
        "https://crl.example.test/ca.crl".to_string(),
        oneiron_seal::FetchResponse {
            body: b"crl-bytes".to_vec(),
            content_type: Some("application/pkcs7-crl".to_string()),
        },
    );
    let hit = fetcher
        .fetch(FetchRequest {
            purpose: FetchPurpose::Crl,
            url: url::Url::parse("https://crl.example.test/ca.crl").unwrap(),
            method: FetchMethod::Get,
            request_body: Vec::new(),
            content_type: None,
        })
        .await
        .unwrap();
    assert_eq!(hit.body, b"crl-bytes");
    let miss = fetcher
        .fetch(FetchRequest {
            purpose: FetchPurpose::Crl,
            url: url::Url::parse("https://other.example.test/ca.crl").unwrap(),
            method: FetchMethod::Get,
            request_body: Vec::new(),
            content_type: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(miss, FetchError::Unavailable));
}

#[cfg(feature = "network-fetch")]
mod guarded {
    use oneiron_seal::{FetchPolicy, SsrfGuardedHttpFetcher};

    use super::*;

    fn policy_with(origin: &str) -> FetchPolicy {
        FetchPolicy {
            allowed_origins: vec![url::Url::parse(origin).unwrap()],
            ..FetchPolicy::default()
        }
    }

    #[tokio::test]
    async fn unlisted_origin_denied_before_any_network() {
        // Default policy: no origins configured — everything denied without
        // touching DNS or sockets.
        let f = SsrfGuardedHttpFetcher::new(FetchPolicy::default());
        let err = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url: url::Url::parse("https://ocsp.example.test/").unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Denied));
    }

    #[tokio::test]
    async fn listed_origin_with_loopback_resolution_is_denied() {
        // Origin allowed, but the name resolves to loopback: the address
        // policy rejects it unless an explicit CIDR admits it.
        let f = SsrfGuardedHttpFetcher::new(policy_with("https://localhost"));
        let err = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url: url::Url::parse("https://localhost:9/ocsp").unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Denied));
    }

    #[tokio::test]
    async fn wrong_scheme_denied_even_for_listed_host() {
        let f = SsrfGuardedHttpFetcher::new(policy_with("https://crl.example.test"));
        let err = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::Crl,
                url: url::Url::parse("ftp://crl.example.test/ca.crl").unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Denied));
    }

    #[tokio::test]
    async fn query_strings_never_appear_in_errors() {
        let f = SsrfGuardedHttpFetcher::new(FetchPolicy::default());
        let err = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::AuthorityInformationAccess,
                url: url::Url::parse("https://aia.example.test/ca.cer?secret=hunter2").unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap_err();
        let shown = format!("{err}");
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("secret"));
    }
}

#[cfg(feature = "network-fetch")]
mod guarded_live {
    //! Loopback-socket legs: redirect hops re-run the policy, per-purpose
    //! caps abort streaming, and an explicit CIDR row admits loopback.
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use oneiron_seal::{FetchPolicy, SsrfGuardedHttpFetcher};

    use super::*;

    /// Serve `302 -> /next` then a 200 body of `body_len` bytes on a loopback
    /// listener; returns (port, Arc<hop counter>).
    fn serve(body_len: usize) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hops2 = hops.clone();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut sock, _)) = listener.accept() else { break };
                hops2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let is_next = String::from_utf8_lossy(&buf).contains("GET /next");
                let (status, body) = if is_next {
                    ("200 OK", vec![b'x'; body_len])
                } else {
                    ("302 Found", Vec::new())
                };
                let location = if is_next {
                    String::new()
                } else {
                    format!("Location: http://127.0.0.1:{port}/next\r\n")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.write_all(&body);
            }
        });
        (port, hops)
    }

    fn loopback_policy(port: u16, cap: usize) -> FetchPolicy {
        FetchPolicy {
            allowed_origins: vec![url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap()],
            allowed_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
            max_ocsp_bytes: cap,
            ..FetchPolicy::default()
        }
    }

    #[tokio::test]
    async fn redirect_hop_reruns_policy_and_succeeds_when_admitted() {
        let (port, hops) = serve(64);
        let f = SsrfGuardedHttpFetcher::new(loopback_policy(port, 1024));
        let out = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url: url::Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap();
        assert_eq!(out.body, vec![b'x'; 64]);
        assert_eq!(hops.load(std::sync::atomic::Ordering::SeqCst), 2);
        // Second fetch hits the cache: no third hop.
        let _ = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url: url::Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap();
        assert_eq!(hops.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn purpose_cap_aborts_oversized_response() {
        let (port, _hops) = serve(4096);
        let f = SsrfGuardedHttpFetcher::new(loopback_policy(port, 1024));
        let err = f
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url: url::Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap(),
                method: FetchMethod::Get,
                request_body: Vec::new(),
                content_type: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::ResponseTooLarge));
    }
}
