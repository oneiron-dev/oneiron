//! DEC-0006 invariant 5 (`the guard offers, never grants`): compile-fail proof
//! that the guard→owner boundary is a type fact. These cases compile against
//! the NORMAL (non-test) `oneiron` library from an external-crate position, so
//! the private fields of `AuthenticatedOwner` and the absent
//! `From<ConsentProposal>` impls are observed exactly as a downstream guard
//! implementor would meet them.

#[test]
fn consent_guard_compilefail() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail(
        "tests/consent_guard_compilefail/a_owner_stamp_struct_literal_private_fields.rs",
    );
    cases.compile_fail("tests/consent_guard_compilefail/b_no_proposal_to_owner_conversion.rs");
    cases.compile_fail("tests/consent_guard_compilefail/c_no_proposal_to_grant_conversion.rs");
}
