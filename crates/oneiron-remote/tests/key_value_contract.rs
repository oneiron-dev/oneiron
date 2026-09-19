//! The dispatcher exposes exact keyed memory, not recall reconstruction.
use oneiron::memory::{KeyValueAddress, KeyValueNamespaces, KeyValuePut, KeyValueSearch};
use oneiron_remote::{OneironClient, OpenOptions};
use serde_json::json;

#[test]
fn embedded_keyed_catalog_round_trip_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let client =
        OneironClient::open(Some(&dir.path().join("vault")), &OpenOptions::default()).unwrap();
    let address = KeyValueAddress {
        namespace: vec!["facts".into()],
        key: "preference".into(),
    };
    let request = KeyValuePut {
        namespace: address.namespace.clone(),
        key: address.key.clone(),
        value: json!({"theme":"dark"}),
        request_id: "request-one".into(),
        source: "user_stated".into(),
    };
    assert!(client.key_value_get(&address).unwrap().is_none());
    let receipt = client.key_value_put(&request).unwrap();
    assert!(!receipt.replayed);
    assert_eq!(
        client.key_value_get(&address).unwrap(),
        Some(receipt.item.clone())
    );
    assert!(client.key_value_put(&request).unwrap().replayed);
    assert_eq!(
        client.key_value_search(&KeyValueSearch::default()).unwrap(),
        vec![receipt.item]
    );
    assert_eq!(
        client
            .key_value_namespaces(&KeyValueNamespaces::default())
            .unwrap(),
        vec![address.namespace.clone()]
    );
    assert!(client.key_value_delete(&address).unwrap().existed);
    assert!(client.key_value_get(&address).unwrap().is_none());
    assert!(client.key_value_put(&request).is_err());
}

#[test]
fn keyed_filter_cap_is_the_same_at_embedded_and_remote_boundaries() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let embedded = OneironClient::open(Some(&path), &OpenOptions::default()).unwrap();
    // The filter is exactly at its engine cap; framing and a maximal namespace
    // make the complete request larger. The transport must not impose a second
    // entity-size cap over that complete envelope.
    let empty_filter_len = serde_json::to_vec(&json!({"blob": ""})).unwrap().len();
    for excess in [0, 1] {
        let request = KeyValueSearch {
            namespace_prefix: vec!["n".repeat(4096)],
            filter: Some(json!({"blob": "x".repeat(oneiron_remote::MAX_ENTITY_PAYLOAD_BYTES - empty_filter_len + excess)})
                .as_object().unwrap().clone()),
            ..Default::default()
        };
        assert!(
            serde_json::to_vec(&request).unwrap().len() > oneiron_remote::MAX_ENTITY_PAYLOAD_BYTES
        );
        let expected = embedded.key_value_search(&request);
        if excess == 0 {
            assert!(expected.as_ref().unwrap().is_empty());
        } else {
            assert_eq!(expected.as_ref().unwrap_err().code, "BAD_REQUEST");
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let path = path.clone();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    return false;
                }
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let request: KeyValueSearch = serde_json::from_slice(&body).unwrap();
            let server_engine = OneironClient::open(Some(&path), &OpenOptions::default()).unwrap();
            let (status, body) = match server_engine.key_value_search(&request) {
                Ok(rows) => ("200 OK", serde_json::to_vec(&rows).unwrap()),
                Err(error) => (
                    "400 Bad Request",
                    serde_json::to_vec(&json!({"error": error})).unwrap(),
                ),
            };
            write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
            true
        });
        let remote = OneironClient::connect(&format!("http://{address}"), "fixture").unwrap();
        let actual = remote.key_value_search(&request);
        // Wake a still-accepting fixture if a regressed local precheck refused
        // before sending. This makes the negative regression fail, not hang.
        drop(TcpStream::connect(address));
        assert!(peer.join().unwrap(), "request must reach the engine");
        assert_eq!(actual, expected);
    }
}
