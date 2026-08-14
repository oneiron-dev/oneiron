//! (a.1) Out-of-boundary construction of `AttestedRelayDomain` must fail:
//! the wrapped field is private, so no struct-literal path exists outside
//! the crate. (Kept in its own case file: an `E0599` elsewhere in the same
//! file masks this `E0451` in compiler output.)

fn main() {
    let _ = oneiron::AttestedRelayDomain {
        domain: oneiron::RelayTrustDomain::CloudVault,
    };
}
