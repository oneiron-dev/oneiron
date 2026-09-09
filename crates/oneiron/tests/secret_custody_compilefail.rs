//! SECRET-01 S1 read-plane discipline: compile-fail proof from an
//! external-crate position. In-crate, `value_bytes` and `manifest_ref` are
//! `pub(crate)` and therefore visible, so the module doc's claim — that the
//! value never crosses the crate boundary unbound, and that the metadata
//! projection has no value member by construction — can only be stated from
//! out here, against the NORMAL (non-test) `oneiron` library.

#[test]
fn secret_custody_compilefail() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/secret_custody_compilefail/a_metadata_has_no_value_field.rs");
    cases.compile_fail(
        "tests/secret_custody_compilefail/b_record_struct_literal_private_value_bytes.rs",
    );
}
