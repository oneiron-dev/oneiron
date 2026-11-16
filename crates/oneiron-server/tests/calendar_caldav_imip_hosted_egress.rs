#![cfg(oneiron_test_support)]
//! FIX [CALDAV-SEAL-SKIP-HOSTED-EGRESS]: CalDAV and the iMIP submission go out
//! through the one shared network boundary (ARCH-0046 :327, RC84: "Web
//! fetching, the calendar and sealing all go out through it"; a hosted node
//! refuses private addresses). On a managed node the calendar setup doors
//! refuse a CalDAV or submission endpoint whose address literal is private or
//! the node's own; the CalDAV wire and the iMIP send refuse it before any byte
//! is sent; a name that answers with one fails at connect. A self-hosted node
//! reaches a loopback endpoint as before.
//!
//! Red: the head with the guard dropped (`calendar_host::client` unguarded,
//! `hosted_guard_refuses` always false), as main sends: the managed-node tests
//! fail, the self-hosted one passes.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test calendar_caldav_imip_hosted_egress`.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use oneiron::web_fetch::HostedEgressGuard;
use oneiron_server::test_doors::calendar_egress::{
    admit_calendar_endpoint, caldav_propfind, imip_post,
};

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
        Ok(_) => panic!("the refused endpoint reached the loopback listener"),
        Err(error) => panic!("listener failed: {error}"),
    }
}

/// A loopback server that answers one request with `status` and returns the
/// request line it read.
fn answer_once(status: &'static str) -> (std::thread::JoinHandle<String>, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the endpoint is reached");
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).expect("read request");
        let text = String::from_utf8_lossy(&request[..read]).into_owned();
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        text.lines().next().unwrap_or_default().to_owned()
    });
    (server, port)
}

#[test]
fn hosted_node_refuses_a_caldav_or_submission_endpoint_on_a_private_or_node_address() {
    let (listener, port) = untouched_listener();
    for endpoint in [
        format!("http://127.0.0.1:{port}/dav/"),
        format!("https://127.0.0.1:{port}/dav/"),
        format!("https://[::1]:{port}/dav/"),
        "https://10.1.2.3/dav/".to_owned(),
        "https://192.168.0.7/submit".to_owned(),
        "https://169.254.169.254/latest/meta-data".to_owned(),
    ] {
        let configure = admit_calendar_endpoint(Some(hosted_guard()), &endpoint)
            .expect_err("a hosted node's setup door refuses a private or node endpoint");
        assert!(
            configure.contains("private or node address"),
            "{endpoint}: configure: {configure}"
        );
        let caldav = caldav_propfind(Some(hosted_guard()), &endpoint)
            .expect_err("a hosted node's CalDAV wire refuses a private or node endpoint");
        assert!(
            caldav.contains("private or node address"),
            "{endpoint}: refused before the request, not by the transport: {caldav}"
        );
        let imip = imip_post(Some(hosted_guard()), &endpoint)
            .expect_err("a hosted node's iMIP send refuses a private or node endpoint");
        assert!(
            imip.contains("private or node address"),
            "{endpoint}: refused before the request, not by the transport: {imip}"
        );
    }
    assert_no_connection(&listener);
}

#[test]
fn hosted_node_refuses_an_endpoint_name_that_resolves_to_loopback() {
    let (listener, port) = untouched_listener();
    // A name passes admission; its answers are checked as the client
    // connects, so a name that answers with loopback is refused as well.
    let endpoint = format!("http://localhost:{port}/dav/");
    admit_calendar_endpoint(Some(hosted_guard()), &endpoint)
        .expect("a name is left to the resolver");
    assert_eq!(
        caldav_propfind(Some(hosted_guard()), &endpoint),
        Err("CalDAV request failed".to_owned())
    );
    assert_eq!(
        imip_post(Some(hosted_guard()), &endpoint),
        Err("iMIP submission failed".to_owned())
    );
    assert_no_connection(&listener);
}

#[test]
fn self_hosted_node_reaches_a_loopback_endpoint_as_before() {
    let endpoint = |port: u16| format!("http://127.0.0.1:{port}/dav/");
    admit_calendar_endpoint(None, &endpoint(1)).expect("a self-hosted setup door admits loopback");

    let (server, port) = answer_once("207 Multi-Status");
    assert_eq!(caldav_propfind(None, &endpoint(port)), Ok(207));
    assert!(
        server
            .join()
            .expect("CalDAV server")
            .starts_with("PROPFIND /dav/ "),
        "the PROPFIND reached the self-hosted endpoint"
    );

    let (server, port) = answer_once("202 Accepted");
    assert_eq!(imip_post(None, &endpoint(port)), Ok(202));
    assert!(
        server
            .join()
            .expect("submission server")
            .starts_with("POST /dav/ "),
        "the submission reached the self-hosted endpoint"
    );
}
