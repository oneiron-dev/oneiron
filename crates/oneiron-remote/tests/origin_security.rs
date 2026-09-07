//! Credentials may travel over HTTP only to loopback development endpoints.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use oneiron_remote::OneironClient;

#[test]
fn connect_requires_https_except_for_loopback_development() {
    for url in [
        "http://example.invalid/",
        "http://192.0.2.1/",
        "http://10.0.0.1/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http://[2001:db8::1]/",
        "http://localhost.example.invalid/",
        "http://127.0.0.1.example.invalid/",
    ] {
        let error = OneironClient::connect(url, "origin-probe")
            .expect_err("a bearer must not cross a non-loopback HTTP connection");
        assert_eq!(error.code, "BAD_REQUEST");
        assert!(error.message.contains("HTTPS"));
        assert!(!error.suggestions.is_empty());
    }
    for url in [
        "https://example.invalid/",
        "https://192.0.2.1/",
        "http://127.0.0.1/",
        "http://127.0.0.2/",
        "http://[::1]/",
        "http://localhost/",
        "http://LOCALHOST:8080/base",
    ] {
        // connect validates configuration without making a network request.
        assert!(OneironClient::connect(url, "origin-probe").is_ok(), "{url}");
    }
}

#[test]
fn invalid_origins_never_echo_caller_secrets() {
    for url in [
        "http://user:origin-secret@/",
        "http://user:origin-secret@example.invalid:bad/",
        "https://user:origin-secret@example.invalid/",
        "https://example.invalid/?origin-secret",
        "https://example.invalid/#origin-secret",
        "http://example.invalid/origin-secret",
        "file:///origin-secret",
        "origin-secret://example.invalid/",
    ] {
        let error = OneironClient::connect(url, "bearer-secret").expect_err("invalid origin");
        assert_eq!(error.code, "BAD_REQUEST");
        let payload = serde_json::to_string(&error).expect("error envelope");
        assert!(!payload.contains("origin-secret"));
        assert!(!payload.contains("bearer-secret"));
        assert!(!payload.contains(url));
    }
}

#[test]
fn bearer_requests_do_not_follow_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut reader = BufReader::new(&mut stream);
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).expect("request header") > 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse::<usize>().expect("body length");
            }
        }
        reader
            .read_exact(&mut vec![0; content_length])
            .expect("request body");
        stream
            .write_all(
                concat!(
                    "HTTP/1.1 302 Found\r\n",
                    "Location: http://127.0.0.1:9/origin-secret\r\n",
                    "Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .as_bytes(),
            )
            .expect("redirect response");
    });
    let client = OneironClient::connect(&format!("http://{address}"), "bearer-secret")
        .expect("loopback client");
    let error = client
        .receipts(1)
        .expect_err("redirects are not facade responses");
    peer.join().expect("fixture thread");
    assert_eq!(error.code, "INTERNAL_SERVER_ERROR");
    // A followed redirect would instead report a transport failure at port 9.
    assert!(error.message.contains("302"), "{error:?}");
    assert!(!error.message.contains("origin-secret"));
    assert!(!error.message.contains("bearer-secret"));
}
