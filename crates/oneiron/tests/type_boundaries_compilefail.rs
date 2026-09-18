//! Compile-fail proofs of three type boundaries from external-crate positions.
//!
//! All cases use the NORMAL (non-test) `oneiron` library, so test-only mints and
//! `pub(crate)` fields cannot make a boundary appear stronger than it is.
//! One test and one `TestCases` session share the generated Cargo workspace.

#[test]
fn type_boundaries_compilefail() {
    let cases = trybuild::TestCases::new();

    // DEC-0006 invariant 5: the guard offers, never grants. Authenticated owner
    // fields stay private and a proposal cannot become an owner or a grant.
    cases.compile_fail(
        "tests/consent_guard_compilefail/a_owner_stamp_struct_literal_private_fields.rs",
    );
    cases.compile_fail("tests/consent_guard_compilefail/b_no_proposal_to_owner_conversion.rs");
    cases.compile_fail("tests/consent_guard_compilefail/c_no_proposal_to_grant_conversion.rs");

    // B11-2b / ONE-1572: relay attestation witnesses and verified identities can
    // only be constructed through their sealed production boundary.
    cases.compile_fail(
        "tests/relay_attestation_compilefail/a_witness_struct_literal_private_field.rs",
    );
    cases.compile_fail("tests/relay_attestation_compilefail/a_witness_no_universal_mint.rs");
    cases.compile_fail(
        "tests/relay_attestation_compilefail/b_identity_construction_outside_edge_auth.rs",
    );
    cases.compile_fail(
        "tests/relay_attestation_compilefail/b_identity_from_edge_auth_not_public.rs",
    );
    cases.compile_fail("tests/relay_attestation_compilefail/c_byo_variant_does_not_exist.rs");

    // SECRET-01 S1: public metadata has no value, and the record's value bytes
    // cannot be supplied directly by an external crate.
    cases.compile_fail("tests/secret_custody_compilefail/a_metadata_has_no_value_field.rs");
    cases.compile_fail(
        "tests/secret_custody_compilefail/b_record_struct_literal_private_value_bytes.rs",
    );
}
