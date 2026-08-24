//! (c) External-privacy proof ONLY: the hosted-edge domain type is private
//! to the crate, so it cannot even be NAMED from an external crate position
//! — this case fails no matter which variants the enum carries, so it does
//! NOT pin the variant set. The variant-set tripwire (exactly two hosted
//! arms, never a BYO arm) is the in-crate exhaustive no-wildcard match in
//! `policy_model::tests`
//! (`hosted_domain_variant_set_is_exactly_two_hosted_arms`), backed by the
//! exhaustive private `from_hosted_domain` match: adding a variant breaks
//! the crate's own build before this fixture's expectation could change.

fn main() {
    // Hypothetical BYO arm on the hosted-edge domain. Neither the module that
    // holds it nor the type itself is nameable outside the crate — that
    // privacy fact is all this case proves.
    let _ = oneiron::policy_model::relay::HostedDomain::LocalViaByoConnector;
}
