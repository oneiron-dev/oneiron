//! B11-2b / ONE-1572: compile-fail proof that the sealed relay attestation
//! boundary is real at the type level. These cases compile against the NORMAL
//! (non-test) `oneiron` library from an external-crate position, so
//! `#[cfg(test)] pub(crate)` mints and private fields do not exist there.

#[test]
fn relay_attestation_compilefail() {
    let cases = trybuild::TestCases::new();
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
}
