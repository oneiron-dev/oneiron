//! Curated RFC 6125 hostname-binding corpus for `verify_tls_server`.
//!
//! Companion to `tests/hostname_corpus_baseline.md`, which documents the
//! per-case expected outcome and the wildcard-policy decisions the
//! shipped matcher makes.
//!
//! Fixtures: see `tests/fixtures/gen.py`. Oracle: pyca/cryptography. The
//! Rust verifier under test never participates in fixture creation.
//!
//! Tracks PKIX-fmtv.22.

use pkix_chain::{
    verify_tls_server, DefaultVerifier, Error, IdentityError, NoAiaFetcher, NoRevocation,
    ServerName, TrustAnchor,
};
use pkix_profiles::{BasicTlsProfile, Rfc5280Profile};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// A timestamp inside every fixture's validity window (2026-06-01 UTC).
const NOW: u64 = 1_780_272_000;

fn load_fixture(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn anchors() -> [TrustAnchor; 1] {
    [TrustAnchor::from_cert(load_fixture("root.der"))]
}

/// Expected outcome of running `verify_tls_server` on a corpus case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Wrapper must return `Ok(_)`.
    Ok,
    /// Wrapper must return `Err(Error::Identity(IdentityError::NoMatchingSan))`.
    NoMatchingSan,
    /// Wrapper must return `Err(Error::Identity(IdentityError::MissingSan))`.
    MissingSan,
}

enum Target<'a> {
    Dns(&'a str),
    Ip(&'a str),
}

fn run(fixture: &str, target: Target<'_>, expected: Outcome) {
    let leaf = load_fixture(fixture);
    let chain = [leaf];
    let name = match target {
        Target::Dns(s) => {
            ServerName::dns_name(s).unwrap_or_else(|e| panic!("parse target DNS {s:?}: {e:?}"))
        }
        Target::Ip(s) => {
            ServerName::ip_address(s).unwrap_or_else(|e| panic!("parse target IP {s:?}: {e:?}"))
        }
    };
    let anchors = anchors();

    let result = verify_tls_server(
        &chain,
        &anchors,
        &name,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    assert_outcome(fixture, &target_label(&target), &result, expected);
}

fn target_label(t: &Target<'_>) -> String {
    match t {
        Target::Dns(s) => format!("dns:{s}"),
        Target::Ip(s) => format!("ip:{s}"),
    }
}

fn assert_outcome<T: std::fmt::Debug>(
    fixture: &str,
    target: &str,
    result: &Result<T, Error>,
    expected: Outcome,
) {
    match (expected, result) {
        (Outcome::Ok, Ok(_)) => {}
        (Outcome::NoMatchingSan, Err(Error::Identity(IdentityError::NoMatchingSan))) => {}
        (Outcome::MissingSan, Err(Error::Identity(IdentityError::MissingSan))) => {}
        _ => panic!("fixture={fixture} target={target}: expected {expected:?} but got {result:?}"),
    }
}

// ---------------------------------------------------------------------------
// RFC 6125 §6.4.1 — exact-match dNSName
// ---------------------------------------------------------------------------

#[test]
fn exact_match() {
    run(
        "host-exact-foo.der",
        Target::Dns("foo.example.com"),
        Outcome::Ok,
    );
}

#[test]
fn exact_mismatch() {
    run(
        "host-exact-foo.der",
        Target::Dns("bar.example.com"),
        Outcome::NoMatchingSan,
    );
}

/// Target's parent does not match a non-wildcard SAN.
#[test]
fn exact_parent_does_not_match() {
    run(
        "host-exact-foo.der",
        Target::Dns("example.com"),
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// RFC 6125 §6.4.2 — leftmost-wildcard matching
// ---------------------------------------------------------------------------

#[test]
fn wildcard_matches_single_label() {
    run(
        "host-wildcard.der",
        Target::Dns("foo.example.com"),
        Outcome::Ok,
    );
}

/// A wildcard label replaces exactly one label; the parent domain
/// (`example.com` against `*.example.com`) does NOT match.
#[test]
fn wildcard_does_not_match_parent() {
    run(
        "host-wildcard.der",
        Target::Dns("example.com"),
        Outcome::NoMatchingSan,
    );
}

/// A wildcard label replaces exactly one label; deeper subdomains
/// (`foo.bar.example.com` against `*.example.com`) do NOT match.
#[test]
fn wildcard_does_not_match_deeper_subdomain() {
    run(
        "host-wildcard.der",
        Target::Dns("foo.bar.example.com"),
        Outcome::NoMatchingSan,
    );
}

/// Partial-label wildcards (`f*o.example.com`) are not honored.
/// RFC 6125 §7.2 deprecates them; shipped matcher refuses any SAN
/// whose `*` is not a whole leftmost label.
#[test]
fn wildcard_partial_label_rejected() {
    run(
        "host-wildcard-partial-label.der",
        Target::Dns("foo.example.com"),
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// RFC 6125 §6.4.3 — leftmost-label-only wildcard pinning
// ---------------------------------------------------------------------------

/// Internal wildcards (`foo.*.example.com`) are not honored — only the
/// leftmost label may be wildcarded.
#[test]
fn wildcard_internal_label_rejected() {
    run(
        "host-wildcard-internal.der",
        Target::Dns("foo.bar.example.com"),
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// Public-suffix-shape wildcard rejection
// ---------------------------------------------------------------------------

/// A SAN of `*.com` is structurally a single-label wildcard remainder
/// (the part after `*.` has no `.` separator). The shipped matcher
/// refuses to honor such wildcards conservatively — matches webpki and
/// browser behavior on public-suffix-shaped SANs. Documented as
/// out-of-scope for full Public Suffix List enforcement in the crate
/// rustdoc; this is the structural check that's universally safe.
#[test]
fn wildcard_public_suffix_shape_rejected() {
    run(
        "host-wildcard-tld.der",
        Target::Dns("foo.com"),
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// RFC 4343 — case-insensitive DNS comparison
// ---------------------------------------------------------------------------

/// SAN uses uppercase, target uses lowercase. RFC 4343 requires
/// case-insensitive ASCII comparison.
#[test]
fn case_folding_san_upper_target_lower() {
    run(
        "host-mixed-case-san.der",
        Target::Dns("foo.example.com"),
        Outcome::Ok,
    );
}

/// SAN uses lowercase, target uses uppercase. `ServerName::dns_name`
/// lowercases its input client-side; the matcher then compares
/// case-insensitively. Both directions of normalization must hold.
#[test]
fn case_folding_san_lower_target_upper() {
    run(
        "host-exact-foo.der",
        Target::Dns("FOO.example.com"),
        Outcome::Ok,
    );
}

// ---------------------------------------------------------------------------
// RFC 5891 IDN — A-label / U-label normalization
// ---------------------------------------------------------------------------

/// A-label SAN matches A-label target — the round-trip real-world CAs
/// always use.
#[test]
fn idn_alabel_san_alabel_target() {
    run(
        "host-idn-alabel.der",
        Target::Dns("xn--bcher-kva.example"),
        Outcome::Ok,
    );
}

/// `ServerName::dns_name` accepts a U-label target and normalizes it
/// to A-label form via idna 2008 before the matcher sees it. The
/// fixture's SAN is in A-label form (real-world CAs do not emit
/// U-labels in SANs). End-to-end: caller passes a U-label, match
/// succeeds.
#[test]
fn idn_ulabel_target_normalizes_to_alabel() {
    run(
        "host-idn-alabel.der",
        Target::Dns("bücher.example"),
        Outcome::Ok,
    );
}

// ---------------------------------------------------------------------------
// IP literal SANs (RFC 5280 §4.2.1.6)
// ---------------------------------------------------------------------------

#[test]
fn ipv4_san_matches_ipv4_target() {
    run("host-ipv4.der", Target::Ip("192.0.2.5"), Outcome::Ok);
}

#[test]
fn ipv4_san_mismatch() {
    run(
        "host-ipv4.der",
        Target::Ip("192.0.2.6"),
        Outcome::NoMatchingSan,
    );
}

#[test]
fn ipv6_san_matches_ipv6_target() {
    run("host-ipv6.der", Target::Ip("2001:db8::1"), Outcome::Ok);
}

#[test]
fn ipv6_san_mismatch() {
    run(
        "host-ipv6.der",
        Target::Ip("2001:db8::2"),
        Outcome::NoMatchingSan,
    );
}

/// An IPv4 SAN cannot satisfy an IPv6 target — the two are byte-equal
/// compared, and they have different lengths (4 vs 16 octets). Note:
/// `ServerName::ip_address` rejects IPv4-in-IPv6 mapped forms
/// (`::ffff:192.0.2.5`) at parse time per RFC 5952 strictness, so this
/// test uses a plain IPv6 target to exercise the length-mismatch path.
#[test]
fn ipv4_san_does_not_match_ipv6_target() {
    run(
        "host-ipv4.der",
        Target::Ip("2001:db8::42"),
        Outcome::NoMatchingSan,
    );
}

/// A DNS-name SAN does not satisfy an IP-literal target even when the
/// SAN entry is structurally a valid IP-string. The matcher dispatches
/// on the SAN entry's `GeneralName` variant, not on the textual form.
#[test]
fn dns_san_does_not_satisfy_ip_target() {
    run(
        "host-exact-foo.der",
        Target::Ip("192.0.2.5"),
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// Multi-SAN iteration
// ---------------------------------------------------------------------------

/// Multi-SAN fixture: three DNS entries (one exact, one exact, one
/// wildcard). Iteration must visit all entries, not just the first.
#[test]
fn multi_san_first_entry_matches() {
    run(
        "host-multi-san.der",
        Target::Dns("api.example.com"),
        Outcome::Ok,
    );
}

#[test]
fn multi_san_middle_entry_matches() {
    run(
        "host-multi-san.der",
        Target::Dns("www.example.com"),
        Outcome::Ok,
    );
}

#[test]
fn multi_san_wildcard_entry_matches() {
    run(
        "host-multi-san.der",
        Target::Dns("static.cdn.example.com"),
        Outcome::Ok,
    );
}

#[test]
fn multi_san_no_entry_matches() {
    run(
        "host-multi-san.der",
        Target::Dns("other.example.com"),
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// SAN-absent rejection (RFC 6125 §6.4.4)
// ---------------------------------------------------------------------------

/// RFC 6125 §6.4.4 deprecated CN-fallback. Reuses `leaf-no-san.der`
/// (which has CN="pkix-chain test leaf" but no SAN extension). Even if
/// the CN textually were a hostname, the wrapper would reject with
/// `MissingSan` rather than honor the CN.
#[test]
fn missing_san_extension_rejected() {
    run(
        "leaf-no-san.der",
        Target::Dns("foo.example.com"),
        Outcome::MissingSan,
    );
}

// ---------------------------------------------------------------------------
// BasicTlsProfile wiring smoke
// ---------------------------------------------------------------------------

/// One profile smoke under `BasicTlsProfile` (which sets
/// `required_leaf_eku=[id-kp-serverAuth]` and
/// `require_subject_alt_name`) against the exact-match fixture. The
/// fixture's EKU and SAN both satisfy the profile; this pins that the
/// corpus harness is correctly composable with the production profile,
/// not just `Rfc5280Profile`.
#[test]
fn basictls_profile_exact_match() {
    let leaf = load_fixture("host-exact-foo.der");
    let chain = [leaf];
    let name = ServerName::dns_name("foo.example.com").unwrap();
    let anchors = anchors();
    let result = verify_tls_server(
        &chain,
        &anchors,
        &name,
        &BasicTlsProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    assert!(
        result.is_ok(),
        "BasicTlsProfile + serverAuth EKU + matching SAN must succeed; got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// ServerName::dns_name parser — bead-listed edge cases that the
// constructor rejects before the wrapper is ever invoked.
// ---------------------------------------------------------------------------

#[test]
fn empty_target_rejected_at_parse() {
    assert!(
        ServerName::dns_name("").is_err(),
        "empty target must fail ServerName::dns_name"
    );
}

#[test]
fn wildcard_target_rejected_at_parse() {
    // Wildcards are only meaningful as SAN content, never as a target.
    assert!(
        ServerName::dns_name("*.example.com").is_err(),
        "wildcard target must fail ServerName::dns_name"
    );
}
