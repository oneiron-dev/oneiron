//! Push round-trip and status-codec tests for Git smart-HTTP.

use super::serve::{GIT_HTTP_MAX_HELD_BYTES, ResponseHead, landed_response, serve_failure};
use super::status_codec::{append_status_packet, rewrite_receive_pack_status, status_packet};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use oneiron::origin::smart_http;

#[cfg(test)]
mod tests {
    use super::*;

    // -- the publication-gated push and advertisement ----------------------

    fn receive_pack_head() -> ResponseHead {
        (
            200,
            vec![(
                CONTENT_TYPE.as_str().to_owned(),
                "application/x-git-receive-pack-result".to_owned(),
            )],
        )
    }

    /// The status report `git receive-pack` produces for a push it accepted.
    fn receive_pack_report() -> Vec<Bytes> {
        vec![Bytes::from_static(
            b"000eunpack ok\n0019ok refs/heads/main\n0000",
        )]
    }

    fn landed_report() -> smart_http::ServeReport {
        smart_http::ServeReport {
            status: 200,
            admission: None,
            door: smart_http::DoorWindowReport {
                verdict: smart_http::DoorWindowVerdict::Clean,
                ref_updates: Vec::new(),
                lfs_pointers: Vec::new(),
                quarantine_path: None,
            },
            outcome: None,
            landing: None,
            ref_results: Vec::new(),
        }
    }

    fn status_body(lines: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        append_status_packet(&mut body, b"unpack ok\n").expect("unpack");
        for line in lines {
            append_status_packet(&mut body, line.as_bytes()).expect("status");
        }
        append_status_packet(&mut body, &[]).expect("flush");
        body
    }

    fn partial_ref_results() -> Vec<smart_http::ReceivePackRefResult> {
        use smart_http::{ReceivePackRefResult, ReceivePackRefStatus};
        vec![
            ReceivePackRefResult {
                name: "refs/heads/first".to_owned(),
                status: ReceivePackRefStatus::Published,
            },
            ReceivePackRefResult {
                name: "refs/heads/second".to_owned(),
                status: ReceivePackRefStatus::Pending,
            },
            ReceivePackRefResult {
                name: "refs/heads/third".to_owned(),
                status: ReceivePackRefStatus::NotApplied,
            },
        ]
    }

    #[tokio::test]
    async fn git_http_partial_push_keeps_each_ref_status_and_removes_stale_length() {
        let mut report = landed_report();
        report.ref_results = partial_ref_results();
        let body = status_body(&[
            "ok refs/heads/first\n",
            "ok refs/heads/second\n",
            "option new-oid 1111111111111111111111111111111111111111\n",
            "ng refs/heads/third internal /private/vault/data.mdb\n",
        ]);
        let (status, mut headers) = receive_pack_head();
        headers.push(("Content-Length".to_owned(), body.len().to_string()));
        let response = landed_response(
            Some((status, headers)),
            vec![Bytes::from(body)],
            Ok(Ok(report)),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(CONTENT_LENGTH).is_none());
        let actual = axum::body::to_bytes(response.into_body(), GIT_HTTP_MAX_HELD_BYTES)
            .await
            .expect("body");
        assert_eq!(
            actual.as_ref(),
            status_body(&[
                "ok refs/heads/first\n",
                "ng refs/heads/second publication pending; ref effects may exist\n",
                "ng refs/heads/third ref was not applied\n",
            ])
        );
    }

    #[test]
    fn git_http_partial_status_handles_split_sideband_and_rejects_missing_or_duplicate_refs() {
        let results = partial_ref_results();
        let raw = status_body(&[
            "ok refs/heads/first\n",
            "ok refs/heads/second\n",
            "ng refs/heads/third refused\n",
        ]);
        let mut framed = Vec::new();
        append_status_packet(&mut framed, b"\x02progress\n").expect("progress");
        for byte in &raw {
            append_status_packet(&mut framed, &[1, *byte]).expect("split status");
        }
        append_status_packet(&mut framed, &[]).expect("flush");
        let rewritten = rewrite_receive_pack_status(&framed, &results).expect("sideband status");
        let mut input = rewritten.as_slice();
        let packet = status_packet(&mut input).expect("channel one");
        assert_eq!(packet.first(), Some(&1));
        assert_eq!(
            &packet[1..],
            rewrite_receive_pack_status(&raw, &results).expect("plain status")
        );
        assert_eq!(status_packet(&mut input), Some(&b""[..]));
        assert!(input.is_empty());
        for invalid in [
            status_body(&["ok refs/heads/first\n"]),
            status_body(&[
                "ok refs/heads/first\n",
                "ok refs/heads/first\n",
                "ok refs/heads/third\n",
            ]),
            status_body(&[
                "ok refs/heads/first\n",
                "ok refs/heads/second\n",
                "ok refs/heads/other\n",
            ]),
            raw[..raw.len() - 4].to_vec(),
        ] {
            assert!(rewrite_receive_pack_status(&invalid, &results).is_none());
        }
    }

    #[tokio::test]
    async fn git_http_fatal_sideband_rejects_complete_published_status() {
        let mut report = landed_report();
        report.ref_results = vec![smart_http::ReceivePackRefResult {
            name: "refs/heads/main".to_owned(),
            status: smart_http::ReceivePackRefStatus::Published,
        }];
        let mut payload = vec![1];
        payload.extend_from_slice(&status_body(&["ok refs/heads/main\n"]));
        let mut framed = Vec::new();
        append_status_packet(&mut framed, b"\x02progress\n").expect("progress");
        append_status_packet(&mut framed, &payload).expect("complete channel one status");

        let mut progress_only = framed.clone();
        append_status_packet(&mut progress_only, &[]).expect("flush");
        let mut expected = Vec::new();
        append_status_packet(&mut expected, &payload).expect("status");
        append_status_packet(&mut expected, &[]).expect("flush");
        assert_eq!(
            rewrite_receive_pack_status(&progress_only, &report.ref_results),
            Some(expected),
            "channel two progress is omitted without changing the published status"
        );

        append_status_packet(&mut framed, b"\x03fatal: /private/vault/data.mdb secret\n")
            .expect("fatal");
        append_status_packet(&mut framed, &[]).expect("flush");
        assert!(rewrite_receive_pack_status(&framed, &report.ref_results).is_none());
        let response = landed_response(
            Some(receive_pack_head()),
            vec![Bytes::from(framed)],
            Ok(Ok(report)),
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), GIT_HTTP_MAX_HELD_BYTES)
            .await
            .expect("body");
        assert_eq!(
            body.as_ref(),
            b"git per-ref status is unavailable; ref effects may be partial; retry to recover"
        );
    }

    #[tokio::test]
    async fn git_http_internal_failure_text_never_reaches_the_client() {
        for error in [
            oneiron::Error::Code(oneiron::error::CodeError::ReceivePackLandingRefused {
                reason: "/private/vault/data.mdb secret".to_owned(),
            }),
            oneiron::Error::ConcurrentWrite("/private/vault/data.mdb secret"),
            oneiron::Error::Code(oneiron::error::CodeError::RepoMutationFailed(
                "/private/vault/data.mdb secret".to_owned(),
            )),
            oneiron::Error::InvariantViolation("/private/vault/data.mdb secret"),
        ] {
            let response = serve_failure(Ok(Err(error)));
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .expect("public body");
            let text = std::str::from_utf8(&body).expect("text");
            assert!(!text.contains("/private"));
            assert!(!text.contains("data.mdb"));
            assert!(!text.contains("secret"));
            assert!(text.contains("ref effects may be partial"));
        }
    }

    /// A push whose publication was refused is a refused push, never an `ok`.
    ///
    /// `git receive-pack` reports on what it did; the publication protocol runs
    /// after it and can still refuse. Handing the backend's `ok` to the client
    /// in that case is the one failure mode this route must not have: the
    /// client would record a push the origin will never advertise.
    #[test]
    fn git_http_rejects_publication_failure() {
        let refused = landed_response(
            Some(receive_pack_head()),
            receive_pack_report(),
            Ok(Err(oneiron::Error::Code(
                oneiron::error::CodeError::ReceivePackLandingRefused {
                    reason: "publication conflicted".to_owned(),
                },
            ))),
        );
        assert_eq!(
            refused.status(),
            StatusCode::CONFLICT,
            "a refused publication is not a successful push"
        );
        assert_ne!(
            refused
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-git-receive-pack-result"),
            "the backend's own success report never reaches the client"
        );

        let uncertain = landed_response(
            Some(receive_pack_head()),
            receive_pack_report(),
            Ok(Err(oneiron::Error::ConcurrentWrite(
                "origin CAS effect is uncertain",
            ))),
        );
        assert_eq!(uncertain.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            uncertain.headers().get("retry-after").expect("retry hint"),
            "1"
        );

        let landed = landed_response(
            Some(receive_pack_head()),
            receive_pack_report(),
            Ok(Ok(landed_report())),
        );
        assert_eq!(
            landed.status(),
            StatusCode::OK,
            "a push whose publication landed answers exactly as the backend did"
        );
        assert_eq!(
            landed
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-git-receive-pack-result")
        );
    }
}
