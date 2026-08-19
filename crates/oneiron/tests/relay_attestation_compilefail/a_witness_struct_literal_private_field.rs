//! (a.1) Out-of-boundary construction of `AttestedRelayDomain` must fail:
//! BOTH fields are private — the trust domain and the attested service
//! identity it was established for — so no struct-literal path exists outside
//! the crate and neither half of the evidence can be supplied by hand. (Kept
//! in its own case file: an `E0599` elsewhere in the same file masks this
//! private-field diagnostic in compiler output.)

fn main() {
    let _ = oneiron::AttestedRelayDomain {
        domain: oneiron::RelayTrustDomain::CloudVault,
    };
}
