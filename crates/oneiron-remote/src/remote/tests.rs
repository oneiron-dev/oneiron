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
            assert!(first.starts_with("POST /v1/core/facade/vault.export HTTP/1.1"));
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
            // OF-222 (fe8d9318937): an export is an archive, standard base64 on
            // the wire; `AAAA` is three zero bytes.
            let prefix = br#"{"format":"json","digest":"","archive":""#;
            let suffix = b"\"}";
            let count = if large {
                (MAX_REMOTE_RESPONSE_BYTES / 4 + 1) * 4
            } else {
                4
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", prefix.len() + count + suffix.len()).unwrap();
            stream.write_all(prefix).unwrap();
            let block = [b'A'; 64 * 1024];
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
        .agent_verb("vault.export", serde_json::json!({"format":"json"}))
        .unwrap();
    assert_eq!(generic["archive"], "AAAA");
    let oneiron::memory::ExportAnswer::Inline(large) = client.vault_export(Some("json")).unwrap()
    else {
        panic!("an inline export");
    };
    assert_eq!(large.format, "json");
    assert_eq!(large.archive.len(), (MAX_REMOTE_RESPONSE_BYTES / 4 + 1) * 3);
    assert!(large.archive.iter().all(|byte| *byte == 0));
    server.join().unwrap();
}

/// A loopback peer that answers one export with a valid document whose
/// archive is `count` zero bytes (a multiple of three: `AAAA` each three),
/// framed by `Content-Length` or by closing the connection, and hands back
/// how many bytes it wrote of how many.
fn export_peer(
    count: usize,
    content_length: bool,
) -> (String, std::thread::JoinHandle<(usize, usize)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(&mut stream);
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
        reader.read_exact(&mut vec![0; length]).unwrap();
        drop(reader);
        let mut body = br#"{"format":"json","digest":"","archive":""#.to_vec();
        body.resize(body.len() + count / 3 * 4, b'A');
        body.extend_from_slice(b"\"}");
        let framing = if content_length {
            format!("Content-Length: {}\r\n", body.len())
        } else {
            String::new()
        };
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{framing}Connection: close\r\n\r\n").unwrap();
        let mut written = 0;
        for block in body.chunks(64 * 1024) {
            if stream.write_all(block).is_err() {
                break;
            }
            written += block.len();
        }
        (written, body.len())
    });
    (origin, served)
}

/// C13 capped what export read at a ceiling. Rule 5 (OF-222, FIX 2766,
/// 79f9066ed5c) removed that ceiling: an export streams whole into its typed
/// result, so the same bodies, at the old ceiling, past it and an origin that
/// keeps sending, now decode in full, with or without `Content-Length`.
#[test]
fn export_reads_at_most_its_ceiling_with_or_without_content_length() {
    const LIMIT: usize = 64 * 1024;
    let framing = br#"{"format":"json","digest":"","archive":""}"#.len();
    // The largest archive whose body fits the old ceiling, and the next one.
    let at_limit = (LIMIT - framing) / 4 * 3;
    let export = |count: usize, content_length: bool| {
        let (origin, served) = export_peer(count, content_length);
        // The client, and with it any connection, is gone before the join.
        let result = {
            let client = RemoteClient::connect(&origin, "local-secret", None).unwrap();
            client.call::<_, oneiron::memory::MemoryExport>(
                "vault.export",
                &serde_json::json!({"format":"json"}),
            )
        };
        (result, served.join().unwrap())
    };
    for content_length in [true, false] {
        let (at, _) = export(at_limit, content_length);
        assert_eq!(at.unwrap().archive.len(), at_limit);
        let (over, _) = export(at_limit + 3, content_length);
        assert_eq!(
            over.expect("past the old ceiling").archive.len(),
            at_limit + 3
        );
    }
    // An origin that keeps sending is read to its end.
    let (endless, (written, total)) = export(1024 * LIMIT / 4 * 3, false);
    assert_eq!(
        endless.expect("read whole").archive.len(),
        1024 * LIMIT / 4 * 3
    );
    assert_eq!(written, total);
}
