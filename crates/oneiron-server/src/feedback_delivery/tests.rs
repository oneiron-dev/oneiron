use super::*;
use oneiron::outbound::{
    OutboundExecutionRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
    outbound_verb_contract,
};
use std::io::{Read, Write};
fn call(
    transport: &mut HttpFeedbackTransport,
    bytes: &[u8],
    target: &str,
) -> OutboundExecutionOutcome {
    let route = transport.config.route();
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("actor", &route.verb, &route.channel, target),
        OutboundIntentTrigger::agent_immediate("approval"),
    );
    let execution = OutboundExecutionRequest {
        intent_ref: "intent",
        intent: &intent,
        idempotency_key: Some("intent"),
        verb_contract: outbound_verb_contract(&route.channel, &route.verb).unwrap(),
        channel_identity_ref: None,
        counterparty_ref: None,
        hygiene_headers: Default::default(),
        apns_interruption_level: None,
        calendar_invite: None,
        space_posting: None,
    };
    transport.send_feedback_bundle(&FeedbackTransportRequest {
        execution: &execution,
        bundle_bytes: bytes,
        bundle_digest: "digest",
        bundle_encoding: oneiron::feedback::FEEDBACK_BUNDLE_ENCODING,
        approval_receipt_ref: "approval",
    })
}
fn endpoint(status: u16) -> (String, std::thread::JoinHandle<Vec<u8>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/ingest", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        let (header_end, length) = loop {
            let n = socket.read(&mut buf).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|s| s.parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (end + 4, length);
            }
        };
        while bytes.len() < header_end + length {
            let n = socket.read(&mut buf).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buf[..n]);
        }
        write!(
            socket,
            "HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        bytes[header_end..header_end + length].to_vec()
    });
    (url, worker)
}
#[test]
fn transports_deliver_exact_bytes_and_fail_typed_without_redirecting() {
    for destination in [
        FeedbackDestination::Cloud,
        FeedbackDestination::Collector,
        FeedbackDestination::GithubIssue,
    ] {
        let (url, worker) = endpoint(201);
        let mut transport = HttpFeedbackTransport::new(
            FeedbackDeliveryConfig {
                destination,
                endpoint: url.clone(),
            },
            None,
        )
        .unwrap();
        let bytes = b"\x81\xa1x\x01";
        assert_eq!(
            call(&mut transport, bytes, &url).kind,
            oneiron::outbound::OutboundExecutionOutcomeKind::DeliveredToChannel
        );
        let received = worker.join().unwrap();
        if destination == FeedbackDestination::GithubIssue {
            use base64::Engine;
            let json: serde_json::Value = serde_json::from_slice(&received).unwrap();
            let encoded = json["body"]
                .as_str()
                .unwrap()
                .split("```base64\n")
                .nth(1)
                .unwrap()
                .split('\n')
                .next()
                .unwrap();
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap(),
                bytes
            );
        } else {
            assert_eq!(received, bytes);
        }
        assert_eq!(
            call(&mut transport, bytes, "https://other.test").kind,
            oneiron::outbound::OutboundExecutionOutcomeKind::Failed
        );
        assert_eq!(
            transport.last_error(),
            Some(&FeedbackDeliveryError::RouteMismatch)
        );
    }
    let (url, worker) = endpoint(503);
    let mut transport = HttpFeedbackTransport::new(
        FeedbackDeliveryConfig {
            destination: FeedbackDestination::Collector,
            endpoint: url.clone(),
        },
        None,
    )
    .unwrap();
    assert_eq!(
        call(&mut transport, b"x", &url).kind,
        oneiron::outbound::OutboundExecutionOutcomeKind::Failed
    );
    assert_eq!(
        transport.last_error(),
        Some(&FeedbackDeliveryError::Http(503))
    );
    worker.join().unwrap();
}

#[test]
fn rejected_requests_are_definite_failures_but_indeterminate_responses_are_not() {
    for (status, possible_delivery) in [
        (400, false),
        (401, false),
        (403, false),
        (404, false),
        (422, false),
        (429, false),
        (408, true),
        (409, true),
        (503, true),
    ] {
        let (url, worker) = endpoint(status);
        let mut transport = HttpFeedbackTransport::new(
            FeedbackDeliveryConfig {
                destination: FeedbackDestination::Collector,
                endpoint: url.clone(),
            },
            None,
        )
        .unwrap();
        let outcome = call(&mut transport, b"approved", &url);
        assert_eq!(
            outcome.kind,
            oneiron::outbound::OutboundExecutionOutcomeKind::Failed
        );
        assert_eq!(
            outcome.delivery_may_have_occurred, possible_delivery,
            "HTTP {status}"
        );
        assert_eq!(
            transport.last_error(),
            Some(&FeedbackDeliveryError::Http(status))
        );
        assert_eq!(worker.join().unwrap(), b"approved");
    }
}
