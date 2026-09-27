use oneiron_docedit::retained_opc::XmlLimits;
use oneiron_docedit::retained_opc::{Error, Limits, Package};

fn fixture_limits() -> Limits {
    Limits {
        archive_bytes: 32 * 1024 * 1024,
        entries: 10_000,
        part_bytes: 16 * 1024 * 1024,
        expanded_bytes: 64 * 1024 * 1024,
        xml: XmlLimits {
            max_depth: 256,
            max_nodes: 1_000_000,
        },
    }
}

const PART: &str = "word/document.xml";
const PATH: &[&str] = &["root", "item"];

fn edit_must_refuse(bytes: &[u8], prior: &str) {
    let mut package = Package::open(bytes, fixture_limits()).expect("well-formed ZIP");
    assert_eq!(package.export().expect("no-op"), bytes);
    let before = package.part(PART).expect("part read");
    let result = package.replace_text(PART, PATH, prior, "changed");
    assert!(
        matches!(result, Err(Error::Edit(_))),
        "XML={:?}, result={result:?}",
        String::from_utf8_lossy(before.as_deref().unwrap_or_default())
    );
    assert_eq!(package.part(PART).expect("part read after refusal"), before);
    assert_eq!(package.export().expect("unchanged archive"), bytes);
}

#[test]
fn empty_children_before_between_and_after_text_cannot_be_deleted() {
    for bytes in [
        include_bytes!("fixtures/adversarial/empty-before.zip").as_slice(),
        include_bytes!("fixtures/adversarial/empty-child.zip").as_slice(),
        include_bytes!("fixtures/adversarial/empty-after.zip").as_slice(),
    ] {
        edit_must_refuse(bytes, "beforeafter");
    }
}

#[test]
fn malformed_touched_xml_refuses_without_touching_archive() {
    for bytes in [
        include_bytes!("fixtures/adversarial/multiple-roots.zip").as_slice(),
        include_bytes!("fixtures/adversarial/outer-text.zip").as_slice(),
        include_bytes!("fixtures/adversarial/unknown-entity.zip").as_slice(),
        include_bytes!("fixtures/adversarial/invalid-char.zip").as_slice(),
        include_bytes!("fixtures/adversarial/duplicate-attr.zip").as_slice(),
        include_bytes!("fixtures/adversarial/unbound-prefix.zip").as_slice(),
        include_bytes!("fixtures/adversarial/xml-version.zip").as_slice(),
        include_bytes!("fixtures/adversarial/xml-prolog.zip").as_slice(),
        include_bytes!("fixtures/adversarial/xml-pi.zip").as_slice(),
    ] {
        edit_must_refuse(bytes, "old");
    }
}

#[test]
fn nonstandard_signature_location_and_case_refuse_edits_but_keep_noop() {
    edit_must_refuse(
        include_bytes!("fixtures/adversarial/custom-signature.zip"),
        "old",
    );
    edit_must_refuse(
        include_bytes!("fixtures/adversarial/mixed-case-signature.zip"),
        "old",
    );
}

#[test]
fn unsigned_descriptor_crc_equal_to_signature_is_still_valid() {
    let bytes = include_bytes!("fixtures/adversarial/crc-signature.zip");
    let package = Package::open(bytes, fixture_limits()).expect("unsigned descriptor");
    assert_eq!(package.export().expect("no-op"), bytes);
}

#[test]
fn raw_crlf_and_cr_are_normalized_but_character_reference_is_not() {
    for bytes in [
        include_bytes!("fixtures/adversarial/cr-input.zip").as_slice(),
        include_bytes!("fixtures/adversarial/cr-lone.zip").as_slice(),
    ] {
        let mut package = Package::open(bytes, fixture_limits()).expect("input ZIP");
        package
            .replace_text(PART, PATH, "a\nb", "changed")
            .expect("normalized raw EOL");
        assert!(
            package
                .part(PART)
                .expect("part")
                .expect("XML")
                .windows(b"changed".len())
                .any(|w| w == b"changed")
        );
    }
    let bytes = include_bytes!("fixtures/adversarial/cr-ref.zip");
    let mut package = Package::open(bytes, fixture_limits()).expect("reference ZIP");
    assert!(matches!(
        package.replace_text(PART, PATH, "a\nb", "changed"),
        Err(Error::Edit(_))
    ));
    assert_eq!(package.export().expect("no-op"), bytes);
    package
        .replace_text(PART, PATH, "a\rb", "changed")
        .expect("reference is literal CR");
}

#[test]
fn emitted_carriage_return_is_a_character_reference() {
    let mut package = Package::open(
        include_bytes!("fixtures/adversarial/plain.zip"),
        fixture_limits(),
    )
    .expect("input ZIP");
    package
        .replace_text(PART, PATH, "old", "a\rb")
        .expect("patch");
    assert_eq!(
        package.part(PART).expect("part").expect("XML"),
        b"<root><item>a&#13;b</item></root>"
    );
}

#[test]
fn malformed_signature_metadata_makes_package_read_only() {
    for bytes in [
        include_bytes!("fixtures/adversarial/bad-types.zip").as_slice(),
        include_bytes!("fixtures/adversarial/bad-rels.zip").as_slice(),
        include_bytes!("fixtures/adversarial/case-rels.zip").as_slice(),
    ] {
        edit_must_refuse(bytes, "old");
    }
}

#[test]
fn complete_xml_grammar_refuses_malformed_siblings_without_mutation() {
    for bytes in [
        include_bytes!("fixtures/xml-grammar/forbidden_cdata_terminator.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/empty_qname_prefix.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/empty_attribute_prefix.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/invalid_pi_target.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/duplicate_decl_version.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/invalid_decl_standalone.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/unexpected_decl_attribute.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/missing_attribute_separator.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/stray_ampersand.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/empty-dtd.zip").as_slice(),
    ] {
        edit_must_refuse(bytes, "old");
    }
}

#[test]
fn valid_declarations_namespaces_and_cdata_siblings_stay_in_place() {
    for bytes in [
        include_bytes!("fixtures/xml-grammar/valid_decl_and_pi.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/valid_namespaced_sibling.zip").as_slice(),
        include_bytes!("fixtures/xml-grammar/valid_cdata_sibling.zip").as_slice(),
    ] {
        let mut package = Package::open(bytes, fixture_limits()).expect("valid ZIP");
        let original = package
            .part(PART)
            .expect("part read")
            .expect("document part");
        package
            .replace_text(PART, PATH, "old", "changed")
            .expect("valid XML edit");
        let edited = package.part(PART).expect("part read").expect("edited part");
        let at = original
            .windows(3)
            .position(|window| window == b"old")
            .expect("unique old text");
        let mut expected = original[..at].to_vec();
        expected.extend_from_slice(b"changed");
        expected.extend_from_slice(&original[at + 3..]);
        assert_eq!(edited, expected, "only intended leaf changed");
        assert!(Package::open(&package.export().expect("write"), fixture_limits()).is_ok());
    }
}
