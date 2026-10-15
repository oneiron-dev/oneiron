//! ONE-1441 shared-backend contract tests (blueprint §Test/Shared #1–#4).
//!
//! These prove the properties the two language bindings are allowed to ASSUME:
//! that the catalog is a declared list rather than whatever the code happens
//! to expose, and that divergent reopen options are refused instead of quietly
//! honored.

use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_remote::OneironClient;

/// I10 — `as_actor` exists on both backends and refuses on the remote one.
///
/// `connect` makes no request, so this needs no server: the refusal is a
/// property of the handle, decided before any transport is involved.
#[test]
fn remote_as_actor_is_forbidden() {
    let client = OneironClient::connect("http://127.0.0.1:9/", "v2.scope=core:read.deadbeef")
        .expect("connect validates configuration only");
    assert!(client.is_remote());

    let error = client
        .as_actor("human:00000000000000000000000000000001")
        .expect_err("a connected handle cannot rebind its actor");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    assert!(!error.suggestions.is_empty());
}
