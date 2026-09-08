//! Native verifier and profile classifier (§7.7).
//!
//! A parseable but cryptographically invalid sealed PDF yields
//! `Ok(VerifyReport { valid: false, .. })`; [`SealError::InputInvalid`] is
//! reserved for bytes that cannot be safely parsed within limits. A malformed
//! optional timestamp or DSS object is a failed verification, never an
//! absent optional profile.

mod verify_chain_gates;
mod verify_dss_core;
mod verify_revocation;
mod verify_sig_pipeline;
#[cfg(test)]
mod verify_tests_dss_b;
#[cfg(test)]
mod verify_tests_fixtures_dss_a;
#[cfg(test)]
mod verify_tests_lta_probes;
#[cfg(test)]
mod verify_tests_sig_shapes;
#[cfg(test)]
mod verify_tests_time_lta_a;

pub(crate) use self::verify_chain_gates::{
    VerifyCtx, issuer_permits_crl_sign, validate_chain, verify_document,
};
pub(crate) use self::verify_dss_core::EmbeddedCert;
pub(crate) use self::verify_revocation::{
    crl_complete_scope, evidence_fresh, gen_time_beyond_skew, issued_by,
};
