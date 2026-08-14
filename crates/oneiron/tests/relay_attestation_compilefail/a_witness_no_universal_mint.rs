//! (a.2) Out-of-boundary construction of `AttestedRelayDomain` must fail:
//! there is no absent-constructor backdoor either — the honest test mint is
//! `#[cfg(test)] pub(crate)`, so it does not exist for any external crate
//! (including this integration-test position). No universal mint.

fn main() {
    let _ = oneiron::AttestedRelayDomain::for_testing(oneiron::RelayTrustDomain::CloudVault);
}
