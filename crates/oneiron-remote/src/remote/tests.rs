use super::{MAX_REMOTE_RESPONSE_BYTES, RemoteClient};
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
