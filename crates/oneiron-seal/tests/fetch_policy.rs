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
