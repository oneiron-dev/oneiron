//! Fetch-policy tests (§5, §10), all behind `network-fetch`: the guarded
//! client's pre-network denials.
#![cfg(feature = "network-fetch")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::support;

use oneiron_seal::{FetchError, FetchMethod, FetchPurpose, FetchRequest, SealFetcher};

/// Accepts one loopback connection, or panics after ten seconds: a client
/// that never connects then fails the peer thread's join instead of hanging it.
fn accept_within(listener: &std::net::TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no client connected within 10 s"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

mod guarded {
    use oneiron_seal::{FetchPolicy, SsrfGuardedHttpFetcher};

    use super::*;

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
                let Ok((mut sock, _)) = listener.accept() else {
                    break;
                };
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
    async fn redirect_policy_blocks_forbidden_origin_before_connection() {
        let forbidden = TcpListener::bind("127.0.0.1:0").unwrap();
        forbidden.set_nonblocking(true).unwrap();
        let target = format!("http://{}/forbidden", forbidden.local_addr().unwrap());
        let source = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = source.local_addr().unwrap().port();
        let sender = std::thread::spawn(move || {
            let mut socket = accept_within(&source);
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut chunk = [0u8; 1024];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
            }
            socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        });
        let fetcher = SsrfGuardedHttpFetcher::new(loopback_policy(port, 1024));
        let result = fetcher
            .fetch(FetchRequest {
                purpose: FetchPurpose::Ocsp,
                url: url::Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap(),
                method: FetchMethod::Get,
                request_body: vec![],
                content_type: None,
            })
            .await;
        sender.join().unwrap();
        assert!(matches!(result, Err(FetchError::Denied)));
        assert!(matches!(forbidden.accept(), Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock));

        // An admitted redirect and a cache hit remain live positive controls.
        let (port, hops) = serve(64);
        let fetcher = SsrfGuardedHttpFetcher::new(loopback_policy(port, 1024));
        for _ in 0..2 {
            let response = fetcher
                .fetch(FetchRequest {
                    purpose: FetchPurpose::Ocsp,
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}/start")).unwrap(),
                    method: FetchMethod::Get,
                    request_body: vec![],
                    content_type: None,
                })
                .await
                .unwrap();
            assert_eq!(response.body, vec![b'x'; 64]);
            assert_eq!(hops.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }
}

mod engine_entry {
    //! `SealConfig.fetch_policy` is wired: the engine built by
    //! `with_guarded_fetcher` enforces the CONFIGURED policy — a deny bites
    //! through the engine entry and an admit reaches a live TSA.
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    use oneiron_seal::{
        FetchPolicy, NativeSealEngine, PadesProfile, PdfSealEngine, ProfileDegradeReason,
        SealConfig, SealRequest, SealResourceLimits, SealWarning, TsaEndpoint,
    };

    use super::support::{
        FixedClock, FixtureBackend, TEST_TIME_MS, TestIdentity, p256_identity, tsa_response,
    };

    /// Serve one functional-TSA response on a loopback listener: reads one
    /// POST, mints a real TimeStampResp for its request body.
    fn serve_tsa(tsa: TestIdentity) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let (body_start, content_len) = loop {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                    let cl = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos + 4, cl);
                }
            };
            while buf.len() < body_start + content_len {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let reply = tsa_response(&tsa, &buf[body_start..body_start + content_len]).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
            sock.write_all(&reply).unwrap();
        });
        port
    }

    fn engine_for(
        port: u16,
        allowed_cidrs: Vec<ipnet::IpNet>,
        anchors: Vec<Vec<u8>>,
        signer: TestIdentity,
    ) -> NativeSealEngine {
        let config = SealConfig {
            trust_anchors_der: anchors,
            timestamp_authorities: vec![TsaEndpoint {
                url: url::Url::parse(&format!("http://127.0.0.1:{port}/tsa")).unwrap(),
                expected_policy_oid: None,
            }],
            fetch_policy: FetchPolicy {
                allowed_origins: vec![
                    url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                ],
                allowed_cidrs,
                ..FetchPolicy::default()
            },
            resource_limits: SealResourceLimits::default(),
        };
        NativeSealEngine::with_guarded_fetcher(
            config,
            Arc::new(FixtureBackend::new(signer)),
            Arc::new(FixedClock(TEST_TIME_MS)),
        )
        .unwrap()
    }

    fn input_pdf() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn denied_tsa_egress_sends_nothing_but_admitted_policy_reaches_same_tsa() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let tsa = p256_identity(true);
        let tsa_cert = tsa.cert_der.clone();
        let signer = p256_identity(false);
        let denied = engine_for(
            port,
            vec![],
            vec![signer.cert_der.clone(), tsa_cert.clone()],
            signer,
        );
        let result = denied
            .seal_pdf(
                &input_pdf(),
                &SealRequest {
                    operation_id: "live-policy-deny".into(),
                    target_profile: PadesProfile::BaselineT,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.achieved_profile, PadesProfile::BaselineB);
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            SealWarning::ProfileDegraded {
                reason: ProfileDegradeReason::TimestampUnavailable,
                ..
            }
        )));
        assert!(matches!(listener.accept(), Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock));
        let sender = std::thread::spawn(move || {
            let mut sock = super::accept_within(&listener);
            sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let (body_start, content_len) = loop {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                    let cl = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos + 4, cl);
                }
            };
            while buf.len() < body_start + content_len {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let reply = tsa_response(&tsa, &buf[body_start..body_start + content_len]).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
            sock.write_all(&reply).unwrap();
        });
        let signer = p256_identity(false);
        let admitted = engine_for(
            port,
            vec!["127.0.0.0/8".parse().unwrap()],
            vec![signer.cert_der.clone(), tsa_cert],
            signer,
        );
        let result = admitted
            .seal_pdf(
                &input_pdf(),
                &SealRequest {
                    operation_id: "same-live-policy-admit".into(),
                    target_profile: PadesProfile::BaselineT,
                },
            )
            .await
            .unwrap();
        sender.join().unwrap();
        assert_eq!(result.achieved_profile, PadesProfile::BaselineT);
    }

    #[tokio::test]
    async fn configured_admit_cidr_reaches_the_tsa_through_the_engine() {
        // Same shape with the loopback CIDR admitted: the wired policy lets
        // the fetch through and the seal reaches B-T. This is the mutation
        // probe for the wiring — a policy the engine ignored could never
        // produce both outcomes.
        let signer = p256_identity(false);
        let tsa = p256_identity(true);
        let tsa_cert = tsa.cert_der.clone();
        let port = serve_tsa(tsa);
        let anchors = vec![signer.cert_der.clone(), tsa_cert];
        let engine = engine_for(port, vec!["127.0.0.0/8".parse().unwrap()], anchors, signer);
        let out = engine
            .seal_pdf(
                &input_pdf(),
                &SealRequest {
                    operation_id: "policy-admit".to_string(),
                    target_profile: PadesProfile::BaselineT,
                },
            )
            .await
            .unwrap();
        assert_eq!(out.achieved_profile, PadesProfile::BaselineT);
    }
}
