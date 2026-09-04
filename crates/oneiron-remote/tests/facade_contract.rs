//! ONE-1441 shared-backend contract tests (blueprint §Test/Shared #1–#4).
//!
//! These prove the properties the two language bindings are allowed to ASSUME:
//! that the catalog is a declared list rather than whatever the code happens
//! to expose, that a same-PID reopen shares one native vault, and that
//! divergent reopen options are refused instead of quietly honored.

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN};
use oneiron_remote::{
    FACADE_VERB_CATALOG, OneironClient, OpenOptions, store_open_count, unix_seconds_now,
};

/// The declared catalog, spelled once here so a silent reorder or addition in
/// the crate fails a test rather than a downstream census.
const EXPECTED_CATALOG: [&str; 4] = ["witness", "claim_upsert", "recall", "receipts"];

/// §Test/Shared #1 — `facade_contract_catalog_is_exact`.
#[test]
fn facade_contract_catalog_is_exact() {
    assert_eq!(
        FACADE_VERB_CATALOG, EXPECTED_CATALOG,
        "the shipped catalog must equal the declared catalog, in order"
    );
}

/// §Test/Shared #4 — every catalog entry is a legal facade path segment.
///
/// The server nests these under `/v1/core/facade/`, so a verb carrying an
/// upper-case letter, a dash, or a slash would produce a route no client could
/// address and no census could match.
#[test]
fn remote_route_catalog_is_total() {
    let mut seen = std::collections::BTreeSet::new();
    for verb in FACADE_VERB_CATALOG {
        assert!(
            !verb.is_empty()
                && verb
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "{verb:?} must match ^[a-z0-9_]+$ to be a facade path segment"
        );
        assert!(seen.insert(verb), "{verb:?} appears twice in the catalog");
    }
    assert_eq!(seen.len(), FACADE_VERB_CATALOG.len());
}

/// §Test/Shared #3 — `same_pid_reopen_shares_native_vault`.
///
/// Both halves matter. Sharing without counting would pass on an
/// implementation that opened the store twice and discarded one; counting
/// without comparing pointers would pass on one that handed back an unrelated
/// vault it had opened earlier.
#[test]
fn same_pid_reopen_shares_native_vault() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault");
    let options = OpenOptions::default();

    let before = store_open_count();
    let first = OneironClient::open(Some(&path), &options).expect("first open");
    let after_first = store_open_count();
    let second = OneironClient::open(Some(&path), &options).expect("second open");
    let after_second = store_open_count();

    assert_eq!(
        after_first,
        before + 1,
        "the first open opens the store once"
    );
    assert_eq!(
        after_second, after_first,
        "a same-path, same-options reopen must not open the store again"
    );
    assert_eq!(
        first.shared_vault_addr(),
        second.shared_vault_addr(),
        "both handles must point at the same native vault"
    );
    assert_eq!(first.lease_pid(), Some(std::process::id()));
}

/// §Test/Shared #3 — divergent reopen options are a typed refusal.
#[test]
fn divergent_reopen_options_are_bad_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault");

    let _first = OneironClient::open(Some(&path), &OpenOptions::default()).expect("first open");
    let error = OneironClient::open(
        Some(&path),
        &OpenOptions {
            dimensions: Some(512),
        },
    )
    .expect_err("a divergent reopen must fail");

    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        !error.suggestions.is_empty(),
        "suggestions is never empty on this surface"
    );
}

/// §Test/Shared #2 — the embedded backend reaches the engine through the
/// memory facade, and a bound handle is usable with no actor ceremony.
#[test]
fn embedded_backend_calls_memory_facade() {
    let dir = tempfile::tempdir().expect("temp dir");
    let client = OneironClient::open(Some(&dir.path().join("vault")), &OpenOptions::default())
        .expect("open");

    // `receipts` is the read half of the quickstart and needs no fixture.
    // Reaching a typed answer at all proves the constructor bound an actor and
    // the dispatcher found the facade.
    let receipts = client.receipts(10).expect("receipts");
    assert!(receipts.len() <= 10);
    assert!(!client.is_remote());
    assert_eq!(client.base_url(), None);
}

/// The caps are enforced before dispatch, not after (I11).
#[test]
fn boundary_caps_refuse_before_dispatch() {
    let dir = tempfile::tempdir().expect("temp dir");
    let client = OneironClient::open(Some(&dir.path().join("vault")), &OpenOptions::default())
        .expect("open");

    let oversized = "x".repeat(oneiron_remote::MAX_QUERY_BYTES + 1);
    let error = client
        .recall(
            &oversized,
            oneiron::memory::Effort::Standard,
            &oneiron::memory::RecallScope::default(),
            10,
            None,
        )
        .expect_err("an over-cap query is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);

    let zero_limit = client.receipts(0).expect_err("a zero limit is refused");
    assert_eq!(zero_limit.code, MEMORY_CODE_BAD_REQUEST);
}

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

/// I14 — an omitted timestamp is stamped at the call boundary, in seconds.
#[test]
fn omitted_timestamp_is_stamped_in_unix_seconds() {
    let stamped = oneiron_remote::stamp_occurred_at(None).expect("stamp");
    let now = unix_seconds_now();
    assert!(
        stamped.abs_diff(now) <= 300,
        "an omitted timestamp is stamped with the current wall clock"
    );

    // Supplied values cross unconverted, and impossible ones are refused
    // before any narrowing could make them look plausible.
    assert_eq!(oneiron_remote::stamp_occurred_at(Some(1.0)), Ok(1));
    for rejected in [-1.0, f64::NAN, f64::INFINITY, 1.5] {
        assert!(
            oneiron_remote::stamp_occurred_at(Some(rejected)).is_err(),
            "{rejected} must be refused before core entry"
        );
    }
}
