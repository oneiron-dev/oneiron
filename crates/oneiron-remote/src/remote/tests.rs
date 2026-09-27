use super::{MAX_REMOTE_RESPONSE_BYTES, RemoteClient, normalize_origin, parse_error_envelope};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

/// A loopback peer that answers `count` requests with an empty 200 and
/// hands back each request's header lines.
fn peer(count: usize) -> (String, std::thread::JoinHandle<Vec<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let captured = std::thread::spawn(move || {
        (0..count)
            .map(|_| {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut headers = Vec::new();
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse::<usize>().unwrap();
                    }
                    headers.push(line.trim_end().to_owned());
                }
                reader.read_exact(&mut vec![0; content_length]).unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .unwrap();
                headers
            })
            .collect()
    });
    (origin, captured)
}

fn binding(headers: &[String]) -> Option<serde_json::Value> {
    headers.iter().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("x-oneiron-binding")
            .then(|| serde_json::from_str(value.trim()).unwrap())
    })
}

/// A slip minted on a temp vault, bound to its own connection key.
fn paired() -> (
    tempfile::TempDir,
    oneiron::Vault,
    HostSlipIssuer,
    CapabilitySlip,
    SigningKey,
) {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"remote-holder-host").unwrap();
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut claims = vault.ensure_host_root_slip(&issuer).unwrap().claims;
    claims.slip_id = [4; 32];
    claims.parent_id = None;
    claims.holder_ref = "remote-holder".to_owned();
    claims.binding_key = key.verifying_key().to_bytes();
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    (dir, vault, issuer, slip, key)
}

fn call(client: &RemoteClient) {
    client
        .call::<_, serde_json::Value>("receipts", &serde_json::json!({}))
        .unwrap();
}

#[test]
fn a_slip_holder_signs_each_request_with_a_proof_the_vault_accepts() {
    let (_dir, vault, issuer, slip, key) = paired();
    let (origin, captured) = peer(1);
    let client = RemoteClient::connect(&origin, &slip.to_token().unwrap(), Some(key)).unwrap();
    call(&client);
    let proof = binding(&captured.join().unwrap()[0]).unwrap();
    let signature: Vec<u8> = (0..128)
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&proof["signature"].as_str().unwrap()[at..at + 2], 16).unwrap()
        })
        .collect();
    assert!(
        vault
            .authenticate_capability_slip(
                &issuer,
                &slip,
                proof["timestamp"].as_u64().unwrap(),
                &signature,
                proof["nonce"].as_str().unwrap().as_bytes(),
            )
            .is_ok()
    );
}

#[test]
fn back_to_back_requests_carry_distinct_nonces() {
    let (_dir, _vault, _issuer, slip, key) = paired();
    let (origin, captured) = peer(2);
    let client = RemoteClient::connect(&origin, &slip.to_token().unwrap(), Some(key)).unwrap();
    call(&client);
    call(&client);
    let nonces: Vec<_> = captured
        .join()
        .unwrap()
        .iter()
        .map(|headers| binding(headers).unwrap()["nonce"].clone())
        .collect();
    assert_ne!(nonces[0], nonces[1]);
}

#[test]
fn a_host_secret_crosses_as_a_bare_bearer() {
    let (origin, captured) = peer(1);
    let client = RemoteClient::connect(&origin, "host-secret", None).unwrap();
    call(&client);
    assert!(binding(&captured.join().unwrap()[0]).is_none());
}

#[test]
fn the_streaming_request_carries_a_holder_proof() {
    use oneiron::{
        BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, LlmRequest,
        ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
    };
    let (_dir, _vault, _issuer, slip, key) = paired();
    let (origin, captured) = peer(1);
    let client = RemoteClient::connect(&origin, &slip.to_token().unwrap(), Some(key)).unwrap();
    let request = LlmRequest {
        model: ModelId::new("own/model@1").unwrap(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    let guard = BudgetGuard::with_reserve_units("client", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request).unwrap().lease;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(client.llm_stream(&request, &lease))
        .unwrap();
    assert!(binding(&captured.join().unwrap()[0]).is_some());
}

/// §Test/Shared #5 — an engine code the SDK has never heard of survives.
#[test]
fn remote_maps_api_error_envelope_losslessly() {
    let body = br#"{"error":{"code":"LEASE_REQUIRED","message":"deep recall needs a lease",
            "requestId":"facade-req-0000000000000001","suggestions":["Use effort standard."]}}"#;
    let error = parse_error_envelope(body).expect("a well-formed envelope parses");
    assert_eq!(error.code, "LEASE_REQUIRED");
    assert_eq!(error.message, "deep recall needs a lease");
    assert_eq!(error.suggestions, vec!["Use effort standard.".to_owned()]);
}

/// An unknown FUTURE code is carried as a string, never collapsed.
#[test]
fn unknown_future_codes_pass_through() {
    let body = br#"{"error":{"code":"SOME_FUTURE_CODE","message":"m","suggestions":["s"]}}"#;
    let error = parse_error_envelope(body).expect("parses");
    assert_eq!(error.code, "SOME_FUTURE_CODE");
}

/// The contract's non-empty `suggestions` guarantee is restored, not
/// forwarded as an empty array.
#[test]
fn empty_suggestions_are_backfilled() {
    let body = br#"{"error":{"code":"BAD_REQUEST","message":"m","suggestions":[]}}"#;
    let error = parse_error_envelope(body).expect("parses");
    assert!(!error.suggestions.is_empty());
}

/// §Test/Shared #6 — foreign bodies are not envelopes and never become
/// one.
#[test]
fn remote_rejects_non_oneiron_error_bodies() {
    for body in [
        &b"<html><body>502 Bad Gateway</body></html>"[..],
        &b"{\"error\":{\"code\":\"\",\"message\":\"\"}}"[..],
        &b"{\"message\":\"nope\"}"[..],
        &b"{\"error\":{\"code\":\"TRUNC\""[..],
        &b""[..],
    ] {
        assert!(
            parse_error_envelope(body).is_none(),
            "a non-envelope body must not become a typed refusal"
        );
    }
}

/// The origin is normalized once, into a joinable base.
#[test]
fn origin_normalization_produces_a_joinable_base() {
    let base = normalize_origin("http://127.0.0.1:8080").expect("normalizes");
    assert!(base.as_str().ends_with('/'));
    let joined = base.join("v1/core/facade/witness").expect("joins");
    assert_eq!(
        joined.as_str(),
        "http://127.0.0.1:8080/v1/core/facade/witness"
    );
}

/// A base carrying a path prefix keeps it, and the verb hangs off it.
#[test]
fn origin_normalization_preserves_a_path_prefix() {
    let base = normalize_origin("https://example.invalid/oneiron").expect("normalizes");
    let joined = base.join("v1/core/facade/recall").expect("joins");
    assert_eq!(
        joined.as_str(),
        "https://example.invalid/oneiron/v1/core/facade/recall"
    );
}

/// Both SDK projections use the remote route. Export, unlike ordinary
/// verbs, must consume a complete archive larger than the 64 MiB ceiling.
#[test]
fn connected_export_dispatches_generic_and_streams_large_typed_document() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for large in [false, true] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            assert!(first.starts_with("POST /v1/core/facade/export HTTP/1.1"));
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut request = vec![0; length];
            reader.read_exact(&mut request).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request).unwrap()["format"],
                "json"
            );
            drop(reader);
            let prefix = br#"{"format":"json","rendered":""#;
            let suffix = b"\"}";
            let count = if large {
                MAX_REMOTE_RESPONSE_BYTES + 1
            } else {
                4
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", prefix.len() + count + suffix.len()).unwrap();
            stream.write_all(prefix).unwrap();
            let block = [b'x'; 64 * 1024];
            let mut remaining = count;
            while remaining > 0 {
                let n = remaining.min(block.len());
                stream.write_all(&block[..n]).unwrap();
                remaining -= n;
            }
            stream.write_all(suffix).unwrap();
        }
    });
    let client = crate::OneironClient::connect(&origin, "local-secret").unwrap();
    let generic = client
        .agent_verb("export", serde_json::json!({"format":"json"}))
        .unwrap();
    assert_eq!(generic["rendered"], "xxxx");
    let large = client.export(Some("json")).unwrap();
    assert_eq!(large.format, "json");
    assert_eq!(large.rendered.len(), MAX_REMOTE_RESPONSE_BYTES + 1);
    assert!(large.rendered.bytes().all(|byte| byte == b'x'));
    server.join().unwrap();
}
