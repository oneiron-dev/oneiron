//! Curated RFC 8398 / RFC 5280 §4.2.1.6 mailbox-binding corpus for
//! `verify_smime_signer` and `verify_smime_recipient`.
//!
//! Companion to `tests/mailbox_corpus_baseline.md`, which documents the
//! per-case expected outcome and the strict-RFC-5321 local-part
//! case-sensitivity decision.
//!
//! Each test below runs both `verify_smime_signer` and
//! `verify_smime_recipient` against the same fixture/target and asserts
//! the identical outcome — the two wrappers have byte-identical bodies
//! and the corpus must keep them aligned.
//!
//! Fixtures: see `tests/fixtures/gen.py`. Oracle: pyca/cryptography. The
//! Rust verifier under test never participates in fixture creation.
//!
//! Tracks PKIX-fmtv.23.

use pkix_chain::{
    verify_smime_recipient, verify_smime_signer, DefaultVerifier, Error, IdentityError,
    MailboxName, NoAiaFetcher, NoRevocation, TrustAnchor,
};
use pkix_path::Error as PathError;
use pkix_profiles::{BasicSmimeProfile, Rfc5280Profile};
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

/// Expected outcome of running either wrapper on a corpus case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Both wrappers must return `Ok(_)`.
    Ok,
    /// Both wrappers must return `Err(Error::Identity(IdentityError::NoMatchingSan))`.
    NoMatchingSan,
    /// Both wrappers must return `Err(Error::Identity(IdentityError::MissingSan))`.
    MissingSan,
    /// Both wrappers must return `Err(Error::Path(PathError::MissingRfc822San))`.
    PathMissingRfc822San,
}

/// Run both wrappers under `Rfc5280Profile` (no SAN-shape requirement at
/// the path layer) against the supplied fixture and target, asserting
/// they both produce `expected`.
fn run_rfc5280(fixture: &str, target_mailbox: &str, expected: Outcome) {
    let leaf = load_fixture(fixture);
    let chain = [leaf];
    let mailbox = MailboxName::parse(target_mailbox)
        .unwrap_or_else(|e| panic!("parse target {target_mailbox:?}: {e:?}"));
    let anchors = anchors();

    let signer_result = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    let recipient_result = verify_smime_recipient(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );

    assert_outcome(fixture, target_mailbox, "signer", &signer_result, expected);
    assert_outcome(
        fixture,
        target_mailbox,
        "recipient",
        &recipient_result,
        expected,
    );
}

/// Variant of `run_rfc5280` that runs under `BasicSmimeProfile`, which
/// adds `require_subject_alt_name + require_rfc822_san` at the path
/// layer. Used to exercise the path-vs-identity ordering for cases that
/// pass path validation under Rfc5280Profile but fail under
/// BasicSmimeProfile (e.g. SmtpUTF8-only leaf).
fn run_basic_smime(fixture: &str, target_mailbox: &str, expected: Outcome) {
    let leaf = load_fixture(fixture);
    let chain = [leaf];
    let mailbox = MailboxName::parse(target_mailbox)
        .unwrap_or_else(|e| panic!("parse target {target_mailbox:?}: {e:?}"));
    let anchors = anchors();

    let signer_result = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &BasicSmimeProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    let recipient_result = verify_smime_recipient(
        &chain,
        &anchors,
        &mailbox,
        &BasicSmimeProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );

    assert_outcome(fixture, target_mailbox, "signer", &signer_result, expected);
    assert_outcome(
        fixture,
        target_mailbox,
        "recipient",
        &recipient_result,
        expected,
    );
}

fn assert_outcome<T: std::fmt::Debug>(
    fixture: &str,
    target: &str,
    role: &str,
    result: &Result<T, Error>,
    expected: Outcome,
) {
    match (expected, result) {
        (Outcome::Ok, Ok(_)) => {}
        (Outcome::NoMatchingSan, Err(Error::Identity(IdentityError::NoMatchingSan))) => {}
        (Outcome::MissingSan, Err(Error::Identity(IdentityError::MissingSan))) => {}
        (Outcome::PathMissingRfc822San, Err(Error::Path(PathError::MissingRfc822San))) => {}
        _ => panic!(
            "[{role}] fixture={fixture} target={target}: expected {expected:?} but got {result:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// RFC 5280 §4.2.1.6 rfc822Name — ASCII baseline
// ---------------------------------------------------------------------------

/// Positive: rfc822Name SAN value exactly matches the target mailbox.
#[test]
fn rfc822_exact_match() {
    run_rfc5280(
        "mailbox-rfc822-user-example.der",
        "user@example.com",
        Outcome::Ok,
    );
}

/// Negative: SAN local-part differs from target local-part.
#[test]
fn rfc822_local_part_mismatch() {
    run_rfc5280(
        "mailbox-rfc822-user-example.der",
        "other@example.com",
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// RFC 5321 §2.4 case sensitivity
// ---------------------------------------------------------------------------

/// Positive: SAN carries `user@EXAMPLE.com`; target is lowercase. The
/// domain part is matched ASCII case-insensitively per RFC 5321 §2.4.
#[test]
fn rfc5321_domain_case_insensitive_san_to_target() {
    run_rfc5280(
        "mailbox-rfc822-user-EXAMPLE.der",
        "user@example.com",
        Outcome::Ok,
    );
}

/// Positive: the target's domain may also carry mixed case; both sides
/// normalize to a single A-label form before comparison.
#[test]
fn rfc5321_domain_case_insensitive_target_to_san() {
    run_rfc5280(
        "mailbox-rfc822-user-example.der",
        "user@EXAMPLE.com",
        Outcome::Ok,
    );
}

/// Negative under the shipped strict-RFC-5321 policy: the SAN's
/// local-part `User` differs from the target's local-part `user` by
/// case alone. See mailbox_corpus_baseline.md for the rationale.
#[test]
fn rfc5321_local_part_case_sensitive_strict() {
    run_rfc5280(
        "mailbox-rfc822-User-example.der",
        "user@example.com",
        Outcome::NoMatchingSan,
    );
}

/// Symmetric strict-case check: a target with mixed-case local-part
/// does not bind to a fixture with lowercase local-part either.
#[test]
fn rfc5321_local_part_case_sensitive_strict_inverted() {
    run_rfc5280(
        "mailbox-rfc822-user-example.der",
        "User@example.com",
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// RFC 8398 SmtpUTF8Mailbox
// ---------------------------------------------------------------------------

/// Positive: leaf carries only an SmtpUTF8Mailbox otherName SAN with an
/// internationalized local-part; target matches.
#[test]
fn smtputf8_only_internationalized_match() {
    run_rfc5280("mailbox-smtputf8-only.der", "用户@example.com", Outcome::Ok);
}

/// Negative: an ASCII MailboxName cannot match an SmtpUTF8Mailbox SAN
/// entry (RFC 8398 §4 — the two SAN forms encode disjoint identity
/// spaces). The fixture has no rfc822Name SAN, so an ASCII target
/// reports `NoMatchingSan`.
#[test]
fn smtputf8_only_does_not_match_ascii_target() {
    run_rfc5280(
        "mailbox-smtputf8-only.der",
        "user@example.com",
        Outcome::NoMatchingSan,
    );
}

/// Mixed fixture: both rfc822Name (ASCII) and SmtpUTF8Mailbox (i18n) SAN
/// entries on the same leaf. The ASCII target binds via the rfc822Name
/// entry.
#[test]
fn mixed_san_ascii_target_binds_rfc822() {
    run_rfc5280("mailbox-mixed.der", "user@example.com", Outcome::Ok);
}

/// Mixed fixture, internationalized target binds via the SmtpUTF8 entry.
#[test]
fn mixed_san_i18n_target_binds_smtputf8() {
    run_rfc5280("mailbox-mixed.der", "用户@example.com", Outcome::Ok);
}

/// Mixed fixture, neither ASCII nor i18n target matches.
#[test]
fn mixed_san_unrelated_target_rejected() {
    run_rfc5280(
        "mailbox-mixed.der",
        "stranger@example.com",
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// Multi-mailbox rfc822Name SAN
// ---------------------------------------------------------------------------

/// Positive: any one of three rfc822Name SAN entries can satisfy a
/// target. Exercises the matcher's must-iterate-all-entries shape.
#[test]
fn multi_rfc822_first_match() {
    run_rfc5280("mailbox-multi-rfc822.der", "alpha@example.com", Outcome::Ok);
}

#[test]
fn multi_rfc822_middle_match() {
    run_rfc5280("mailbox-multi-rfc822.der", "beta@example.com", Outcome::Ok);
}

#[test]
fn multi_rfc822_last_match() {
    run_rfc5280("mailbox-multi-rfc822.der", "gamma@example.com", Outcome::Ok);
}

#[test]
fn multi_rfc822_no_match() {
    run_rfc5280(
        "mailbox-multi-rfc822.der",
        "delta@example.com",
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// Negative shapes
// ---------------------------------------------------------------------------

/// Leaf has a SAN extension but it carries no rfc822Name and no
/// SmtpUTF8Mailbox entries. Under Rfc5280Profile the path-layer SAN
/// check passes (SAN is non-empty); identity binding then fails with
/// `NoMatchingSan` (not `MissingSan` — the SAN extension is present).
#[test]
fn dns_only_san_rejects_mailbox_under_rfc5280() {
    run_rfc5280(
        "mailbox-dns-only.der",
        "user@example.com",
        Outcome::NoMatchingSan,
    );
}

/// Same fixture under `BasicSmimeProfile`: the path layer enforces
/// `require_rfc822_san` and rejects the leaf with `MissingRfc822San`
/// before identity binding runs.
#[test]
fn dns_only_san_rejects_at_path_under_basicsmime() {
    run_basic_smime(
        "mailbox-dns-only.der",
        "user@example.com",
        Outcome::PathMissingRfc822San,
    );
}

/// Leaf has no SAN extension at all. The shipped `find_san` returns
/// `MissingSan` before any matching iteration runs. The reused fixture
/// is the same `leaf-no-san.der` exercised by `verify_smime.rs`.
#[test]
fn missing_san_extension() {
    run_rfc5280("leaf-no-san.der", "user@example.com", Outcome::MissingSan);
}

/// The rfc822Name SAN value `no-at-sign` is a valid IA5String but does
/// not split into local@domain. The matcher's `rsplit_once('@')` step
/// returns `None`; that SAN entry contributes no match. The leaf has
/// only this single entry, so the wrapper reports `NoMatchingSan`.
#[test]
fn rfc822_san_without_at_sign_is_not_a_match() {
    run_rfc5280(
        "mailbox-rfc822-malformed-no-at.der",
        "user@example.com",
        Outcome::NoMatchingSan,
    );
}

/// SmtpUTF8Mailbox otherName whose inner UTF8String tag is well-formed
/// but whose value bytes are not valid UTF-8. RFC 8398 §3 violation.
/// The shipped matcher catches the decode error in
/// `san_entry_matches_mailbox` and treats the entry as a non-match, so
/// the wrapper reports `NoMatchingSan` rather than `MalformedSan`. The
/// baseline doc records this as the shipped behavior.
#[test]
fn smtputf8_malformed_utf8_is_not_a_match() {
    run_rfc5280(
        "mailbox-smtputf8-bad-utf8.der",
        "用户@example.com",
        Outcome::NoMatchingSan,
    );
}

// ---------------------------------------------------------------------------
// MailboxName::parse — bead-listed edge cases that fail at parse, not at
// the wrapper. These tests pin that the wrapper is never reached for
// inputs that the identity-side parser already rejects.
// ---------------------------------------------------------------------------

/// Empty input is rejected at parse time. `MailboxName::parse("")` does
/// not produce a value the wrapper could even be invoked with.
#[test]
fn empty_input_rejected_at_parse() {
    assert!(
        MailboxName::parse("").is_err(),
        "empty input must fail MailboxName::parse"
    );
}

/// Quoted local-parts (RFC 5321 §4.1.2 syntax) are explicitly out of
/// scope for `MailboxName::parse` — the parser rejects the `"` byte.
/// The wrapper is therefore never invoked with such an input.
#[test]
fn quoted_local_part_rejected_at_parse() {
    assert!(
        MailboxName::parse("\"a b\"@example.com").is_err(),
        "quoted local-part must fail MailboxName::parse"
    );
}
