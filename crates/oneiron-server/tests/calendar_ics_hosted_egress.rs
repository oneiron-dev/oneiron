#![cfg(oneiron_test_support)]
//! CAL-02: an ICS feed goes out through the one shared network boundary
//! (ARCH-0060 :130, "The adapter keeps no network rules of its own"; ARCH-0046
//! :327, a hosted node refuses private addresses). On a managed node the
//! hosted egress guard refuses a feed URL whose address literal is private or
//! the node's own, and a feed name that answers with one, before any byte is
//! sent. A self-hosted node fetches a loopback feed as before.
//!
//! Main kept the feed's own URL rules and no guard, so a managed node fetched
//! loopback and private addresses; it has no door to the feed transport, so
//! main cannot build this file.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test calendar_ics_hosted_egress`.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use oneiron::web_fetch::HostedEgressGuard;
use oneiron_server::test_doors::calendar_ics_egress::get_ics_feed;

const FEED_BODY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";

/// A managed node's guard with no operator-listed private origin.
fn hosted_guard() -> Arc<HostedEgressGuard> {
    Arc::new(HostedEgressGuard::new(BTreeSet::new, BTreeSet::new()))
}

/// A loopback listener that must never see a connection.
fn untouched_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

fn assert_no_connection(listener: &TcpListener) {
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok(_) => panic!("the refused feed reached the loopback listener"),
        Err(error) => panic!("listener failed: {error}"),
    }
}

#[test]
fn hosted_node_refuses_a_feed_on_a_private_or_node_address_before_connecting() {
    let (listener, port) = untouched_listener();
    for url in [
        format!("http://127.0.0.1:{port}/feed.ics"),
        format!("https://127.0.0.1:{port}/feed.ics"),
        format!("https://[::1]:{port}/feed.ics"),
        "https://10.1.2.3/feed.ics".to_owned(),
        "https://192.168.0.7/feed.ics".to_owned(),
        "https://169.254.169.254/latest/meta-data".to_owned(),
    ] {
        let refused = get_ics_feed(Some(hosted_guard()), &url)
            .expect_err("a hosted node does not fetch a private or node address");
        assert!(
            refused.contains("private or node address"),
            "{url}: refused at admission, not by the transport: {refused}"
        );
    }
    assert_no_connection(&listener);
}

#[test]
fn hosted_node_refuses_a_feed_name_that_resolves_to_loopback() {
    let (listener, port) = untouched_listener();
    // A name passes admission; its answers are checked as the client
    // connects, so a name that rebinds to loopback is refused as well.
    let refused = get_ics_feed(
        Some(hosted_guard()),
        &format!("http://localhost:{port}/feed.ics"),
    )
    .expect_err("a feed name answering with loopback is refused");
    assert_eq!(refused, "ICS feed request failed");
    assert_no_connection(&listener);
}

#[test]
fn self_hosted_node_fetches_a_loopback_feed_as_before() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the feed is fetched");
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).expect("read request");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/calendar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{FEED_BODY}",
            FEED_BODY.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    let status = get_ics_feed(None, &format!("http://127.0.0.1:{port}/feed.ics"))
        .expect("a self-hosted node fetches its own loopback feed");
    assert_eq!(status, 200);
    server.join().expect("feed server");
}
