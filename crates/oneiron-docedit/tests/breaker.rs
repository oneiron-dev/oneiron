use oneiron_docedit::retained_opc::{Editability, Error, Limits, Package, XmlLimits};
const PART: &str = "word/document.xml";
const PATH: &[&str] = &["root", "item"];
fn limits() -> Limits {
    Limits {
        archive_bytes: 16 * 1024 * 1024,
        entries: 1000,
        part_bytes: 4 * 1024 * 1024,
        expanded_bytes: 8 * 1024 * 1024,
        xml: XmlLimits {
            max_depth: 128,
            max_nodes: 10_000,
        },
    }
}

#[test]
fn invalid_references_and_namespace_bindings_refuse_exactly() {
    for input in [
        include_bytes!("fixtures/breaker/surrogate_text.zip").as_slice(),
        include_bytes!("fixtures/breaker/out_of_range_text.zip").as_slice(),
        include_bytes!("fixtures/breaker/surrogate_attribute.zip").as_slice(),
        include_bytes!("fixtures/breaker/empty_namespace_prefix_binding.zip").as_slice(),
        include_bytes!("fixtures/breaker/reserved_xmlns_binding.zip").as_slice(),
        include_bytes!("fixtures/breaker/prefixed_xmlns_attribute.zip").as_slice(),
    ] {
        let mut package = Package::open(input, limits()).expect("ZIP opens");
        let prior = package.part(PART).expect("part");
        assert!(
            matches!(
                package.replace_text(PART, PATH, "old", "changed"),
                Err(Error::Edit(_))
            ),
            "malformed XML must refuse: {:?}",
            prior.as_deref().map(String::from_utf8_lossy)
        );
        assert_eq!(package.part(PART).expect("part after refusal"), prior);
        assert_eq!(package.export().expect("no-op"), input);
    }
}

#[test]
fn bom_and_valid_namespace_edits_keep_every_other_byte() {
    for input in [
        include_bytes!("fixtures/breaker/valid_bom_decl.zip").as_slice(),
        include_bytes!("fixtures/breaker/valid_bom_without_declaration.zip").as_slice(),
        include_bytes!("fixtures/breaker/valid_tab_decl.zip").as_slice(),
        include_bytes!("fixtures/breaker/valid_namespace_undeclaration.zip").as_slice(),
        include_bytes!("fixtures/breaker/valid_high_codepoint_reference.zip").as_slice(),
    ] {
        let mut package = Package::open(input, limits()).expect("ZIP opens");
        let original = package.part(PART).expect("part").expect("document");
        let untouched: Vec<_> = package
            .names()
            .filter(|name| *name != PART)
            .map(|name| (name.to_owned(), package.part(name).expect("part")))
            .collect();
        assert_eq!(package.export().expect("no-op"), input);
        package
            .replace_text(PART, PATH, "old", "changed")
            .expect("valid leaf edit");
        let exported = package.export().expect("write");
        let reopened = Package::open(&exported, limits()).expect("reopen");
        let xml = reopened.part(PART).expect("part").expect("document");
        let at = original
            .windows(3)
            .position(|slice| slice == b"old")
            .expect("old leaf");
        let mut expected = original[..at].to_vec();
        expected.extend_from_slice(b"changed");
        expected.extend_from_slice(&original[at + 3..]);
        assert_eq!(
            xml, expected,
            "source bytes including BOM and unknown XML stay in place"
        );
        roxmltree::Document::parse(std::str::from_utf8(&xml).expect("UTF-8"))
            .expect("independent candidate XML parse");
        for (name, old) in untouched {
            assert_eq!(reopened.part(&name).expect("unchanged part"), old);
        }
    }
}

fn deep_subprocess(name: &str, input: &[u8], edit: bool) {
    if std::env::var("ONEIRON_DOCEDIT_DEPTH_CHILD").as_deref() == Ok(name) {
        let mut policy = limits();
        policy.xml = XmlLimits {
            max_depth: 8,
            max_nodes: 10_000,
        };
        let mut package = Package::open(input, policy).expect("bounded ZIP open");
        assert_eq!(package.export().expect("no-op"), input);
        if edit {
            assert_eq!(package.editability(), Editability::Unsigned);
            assert!(matches!(
                package.replace_text(PART, PATH, "old", "changed"),
                Err(Error::Edit("XML depth limit"))
            ));
        } else {
            assert_eq!(package.editability(), Editability::MetadataUnsupported);
            assert!(package.replace_text(PART, PATH, "old", "changed").is_err());
        }
        assert_eq!(package.export().expect("no-op"), input);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--nocapture", "--test-threads", "1"])
        .env("ONEIRON_DOCEDIT_DEPTH_CHILD", name)
        .output()
        .expect("child output");
    assert!(
        output.status.success(),
        "{name}: {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn deep_metadata_is_read_only_not_abort() {
    deep_subprocess(
        "deep_metadata_is_read_only_not_abort",
        include_bytes!("fixtures/breaker/deep_metadata.zip"),
        false,
    );
}
#[test]
fn deep_touched_part_refuses_not_abort() {
    deep_subprocess(
        "deep_touched_part_refuses_not_abort",
        include_bytes!("fixtures/breaker/deep_touched.zip"),
        true,
    );
}

#[test]
fn configured_node_and_depth_limits_apply_at_both_xml_doors() {
    let metadata = include_bytes!("fixtures/breaker/metadata_nodes.zip");
    let touched = include_bytes!("fixtures/breaker/part_nodes.zip");
    let mut small = limits();
    small.xml = XmlLimits {
        max_depth: 2,
        max_nodes: 2,
    };
    let mut meta = Package::open(metadata, small).expect("ZIP opens");
    assert_eq!(meta.editability(), Editability::MetadataUnsupported);
    assert!(meta.replace_text(PART, PATH, "old", "new").is_err());
    assert_eq!(meta.export().expect("no-op"), metadata);
    let mut doc = Package::open(touched, small).expect("ZIP opens");
    assert_eq!(doc.editability(), Editability::Unsigned);
    assert!(matches!(
        doc.replace_text(PART, PATH, "old", "new"),
        Err(Error::Edit("XML node limit"))
    ));
    assert_eq!(doc.export().expect("no-op"), touched);
    small.xml.max_nodes = 4;
    let mut doc = Package::open(touched, small).expect("ZIP opens");
    doc.replace_text(PART, PATH, "old", "new")
        .expect("boundary admitted");
    let mut meta = Package::open(metadata, small).expect("ZIP opens");
    assert_eq!(
        meta.editability(),
        Editability::MetadataUnsupported,
        "depth still bounds metadata"
    );
    small.xml.max_depth = 3;
    meta = Package::open(metadata, small).expect("ZIP opens");
    assert_eq!(
        meta.editability(),
        Editability::Unsigned,
        "boundary admitted"
    );
}

#[test]
fn refusal_after_prior_checked_edit_keeps_the_candidate_exact() {
    let input = include_bytes!("fixtures/adversarial/plain.zip");
    let mut package = Package::open(input, limits()).expect("ZIP opens");
    package
        .replace_text(PART, PATH, "old", "changed")
        .expect("first checked patch");
    let prior = package.export().expect("first candidate");
    assert!(
        package
            .replace_text(PART, PATH, "wrong", "malicious")
            .is_err()
    );
    assert_eq!(package.export().expect("no partial change"), prior);
    let mut tight = limits();
    tight.part_bytes = 1024;
    let mut tiny = Package::open(input, tight).expect("ZIP still opens");
    assert!(
        tiny.replace_text(PART, PATH, "old", &"x".repeat(1024))
            .is_err()
    );
    assert_eq!(tiny.export().expect("no partial change"), input);
}

#[test]
fn checked_patch_rejects_archive_budget_before_state_changes() {
    let input = include_bytes!("fixtures/adversarial/plain.zip");
    let mut policy = limits();
    policy.archive_bytes = input.len();
    let mut package = Package::open(input, policy).expect("archive at exact input ceiling");
    assert!(matches!(
        package.replace_text(PART, PATH, "old", &"&".repeat(100)),
        Err(Error::Edit("edited archive size limit"))
    ));
    assert_eq!(package.export().expect("no change"), input);
}
