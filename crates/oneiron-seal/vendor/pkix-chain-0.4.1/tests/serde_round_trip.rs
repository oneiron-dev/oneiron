//! Round-trip tests for `pkix-chain`'s serde feature.
//!
//! `pkix-chain::Error` wraps `pkix_path::Error`, `pkix_revocation::Error`,
//! and `pkix_identity::IdentityError`; each of those is independently
//! tested under its own crate's `tests/serde_round_trip.rs`. This file
//! exercises only:
//!
//! * The `Path` / `Revocation` / `Identity` wrapper variants forward
//!   correctly through serde.
//! * The `ProfileViolation` / `OcspDelegation` variants preserve their
//!   `Cow<'static, str>` reason field across serialize → deserialize.
//!
//! Run with: `cargo test -p pkix-chain --features serde --test serde_round_trip`

#![cfg(feature = "serde")]

use pkix_chain::Error;
use pkix_identity::IdentityError;
use std::borrow::Cow;

/// `Error::Identity` round-trips, preserving the inner `IdentityError`
/// variant identity.
#[test]
fn error_identity_round_trips() {
    let cases = [
        IdentityError::MissingSan,
        IdentityError::MalformedSan,
        IdentityError::MalformedInput,
        IdentityError::NoMatchingSan,
    ];
    for inner in cases {
        let err = Error::Identity(inner.clone());
        let json = serde_json::to_string(&err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }
}

/// `Error::Path` forwards a `pkix_path::Error` through serde. Only one
/// variant exercised here; full coverage lives in pkix-path's own
/// round-trip suite.
#[test]
fn error_path_forwards_inner_serde() {
    let inner = pkix_path::Error::NoTrustedPath;
    let err = Error::Path(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(back, Error::Path(pkix_path::Error::NoTrustedPath)));
}

/// `Error::Revocation` forwards a `pkix_revocation::Error` through
/// serde. Coverage parity with the previous test for the path wrapper.
#[test]
fn error_revocation_forwards_inner_serde() {
    let inner = pkix_revocation::Error::CrlSignatureInvalid;
    let err = Error::Revocation(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(
        back,
        Error::Revocation(pkix_revocation::Error::CrlSignatureInvalid)
    ));
}

/// `Error::ProfileViolation` and `Error::OcspDelegation` preserve their
/// `Cow<'static, str>` reason field through serde. The recovered value
/// is `Cow::Owned(String)`; `PartialEq` between `Borrowed` and `Owned`
/// of the same content is `true` (Cow Eq is content-based, not
/// variant-based), so the round-trip preserves PartialEq.
#[test]
fn profile_violation_and_ocsp_delegation_preserve_reason() {
    for err in [
        Error::ProfileViolation {
            reason: Cow::Borrowed("test reason"),
        },
        Error::OcspDelegation {
            reason: Cow::Borrowed("delegation reason"),
        },
    ] {
        let json = serde_json::to_string(&err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
        // Display should also be preserved.
        assert_eq!(format!("{err}"), format!("{back}"));
    }
}

/// Hand-written expected JSON for `Error::ProfileViolation`. Acts as an
/// independent oracle that the wire form is the simple
/// `{"ProfileViolation":{"reason":"..."}}` shape (serde-default for
/// externally-tagged enums with a struct payload).
#[test]
fn profile_violation_wire_form_is_externally_tagged() {
    let err = Error::ProfileViolation {
        reason: Cow::Borrowed("invariant"),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    assert_eq!(json, r#"{"ProfileViolation":{"reason":"invariant"}}"#);
}

/// `Error::Aia` forwards a `pkix_aia::AiaError` through serde. Variant
/// coverage parity with the `Path` / `Revocation` / `Identity` wrapper
/// tests above. The companion `pkix_aia` crate exercises full per-variant
/// coverage in its own round-trip suite.
#[test]
fn error_aia_forwards_inner_serde() {
    let inner = pkix_aia::AiaError::FetchingDisabled;
    let err = Error::Aia(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(
        back,
        Error::Aia(pkix_aia::AiaError::FetchingDisabled)
    ));
}

/// `Error::PathBuild` forwards a `pkix_path_builder::Error` through
/// serde. Coverage parity with the wrapper tests.
#[test]
fn error_path_build_forwards_inner_serde() {
    let inner = pkix_path_builder::Error::NoPathFound;
    let err = Error::PathBuild(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(
        back,
        Error::PathBuild(pkix_path_builder::Error::NoPathFound)
    ));
}

/// `Error::AiaDepthExceeded` is a unit variant; round-trip is a sanity
/// check that no payload requirements were missed.
#[test]
fn error_aia_depth_exceeded_round_trips() {
    let err = Error::AiaDepthExceeded;
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert_eq!(json, r#""AiaDepthExceeded""#);
}
