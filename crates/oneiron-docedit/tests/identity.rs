use oneiron_docedit::retained_opc::{Error, Limits, Package};

const PATH: &[&str] = &["root", "item"];
const SAMPLES: [(&str, &[u8]); 3] = [
    ("docx", include_bytes!("fixtures/retained.docx")),
    ("xlsx", include_bytes!("fixtures/retained.xlsx")),
    ("pptx", include_bytes!("fixtures/retained.pptx")),
];

#[test]
fn corpus_noop_is_archive_exact_and_edits_keep_opaque_parts_and_nodes() {
    for (format, source) in SAMPLES {
        let part = match format {
            "docx" => "word/document.xml",
            "xlsx" => "xl/worksheets/sheet1.xml",
            _ => "ppt/slides/slide1.xml",
        };
        let mut package = Package::open(source, Limits::default()).expect("open fixture");
        assert_eq!(package.export().expect("no-op export"), source, "{format}");
        let old_names: Vec<_> = package.names().map(str::to_owned).collect();
        let unknown = package
            .part("customXml/unreachable.bin")
            .expect("fixture operation")
            .expect("fixture operation");
        let old_xml = package
            .part(part)
            .expect("fixture operation")
            .expect("fixture operation");
        package
            .replace_text(part, PATH, "old", "new & <text>")
            .expect("narrow patch");
        let edited = package.export().expect("edit export");
        let reopened = Package::open(&edited, Limits::default()).expect("reopen candidate");
        assert_eq!(
            reopened.names().collect::<Vec<_>>(),
            old_names.iter().map(String::as_str).collect::<Vec<_>>()
        );
        for name in &old_names {
            if name != part {
                assert_eq!(
                    package_part(source, name),
                    reopened
                        .part(name)
                        .expect("fixture operation")
                        .expect("fixture operation"),
                    "{format}: {name}"
                );
            }
        }
        assert_eq!(
            reopened
                .part("customXml/unreachable.bin")
                .expect("fixture operation")
                .expect("fixture operation"),
            unknown
        );
        let new_xml = reopened
            .part(part)
            .expect("fixture operation")
            .expect("fixture operation");
        let before = b"<item note=\"keep\">old</item>";
        let after = b"<item note=\"keep\">new &amp; &lt;text&gt;</item>";
        let location = old_xml
            .windows(before.len())
            .position(|w| w == before)
            .expect("old node");
        let mut expected = Vec::new();
        expected.extend_from_slice(&old_xml[..location]);
        expected.extend_from_slice(after);
        expected.extend_from_slice(&old_xml[location + before.len()..]);
        assert_eq!(new_xml, expected, "{format}: unknown XML retained in place");
        assert_ne!(edited, source);
        package
            .replace_text(part, PATH, "new & <text>", "old")
            .expect("revert semantic edit");
        assert_eq!(
            package.export().expect("fixture operation"),
            source,
            "{format}: semantic revert is archive exact"
        );
    }
}

fn package_part(source: &[u8], part: &str) -> Vec<u8> {
    Package::open(source, Limits::default())
        .expect("fixture operation")
        .part(part)
        .expect("fixture operation")
        .expect("fixture operation")
}

#[test]
fn pinned_office_deck_is_archive_exact_and_edit_confined() {
    let source = include_bytes!("../../../scripts/office/fixtures/clean.pptx");
    let mut package = Package::open(source, Limits::default()).expect("pinned clean deck");
    assert_eq!(package.export().expect("fixture operation"), source);
    let names: Vec<String> = package.names().map(str::to_owned).collect();
    package
        .replace_text(
            "ppt/slides/slide1.xml",
            &[
                "p:sld", "p:cSld", "p:spTree", "p:sp", "p:txBody", "a:p", "a:r", "a:t",
            ],
            "ONE-2531 clean oracle fixture",
            "Retained & safe",
        )
        .expect("fixture operation");
    let candidate = Package::open(
        &package.export().expect("fixture operation"),
        Limits::default(),
    )
    .expect("fixture operation");
    for name in names {
        if name != "ppt/slides/slide1.xml" {
            assert_eq!(
                candidate.part(&name).expect("fixture operation"),
                Some(package_part(source, &name)),
                "{name}"
            );
        }
    }
    let text = candidate
        .part("ppt/slides/slide1.xml")
        .expect("fixture operation")
        .expect("fixture operation");
    assert!(
        text.windows(b"Retained &amp; safe".len())
            .any(|w| w == b"Retained &amp; safe")
    );
}

#[test]
fn limits_missing_target_and_stale_expected_fail_closed() {
    let source = SAMPLES[0].1;
    assert!(matches!(
        Package::open(
            source,
            Limits {
                entries: 2,
                ..Limits::default()
            }
        ),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Package::open(
            source,
            Limits {
                part_bytes: 4,
                ..Limits::default()
            }
        ),
        Err(Error::Invalid(_))
    ));
    let mut package = Package::open(source, Limits::default()).expect("fixture operation");
    assert!(matches!(
        package.replace_text("word/document.xml", PATH, "stale", "other"),
        Err(Error::Edit(_))
    ));
    assert!(matches!(
        package.replace_text(
            "word/document.xml",
            &["root", "opaque"],
            "unread",
            "overwrite"
        ),
        Ok(())
    ));
    assert!(matches!(
        package.replace_text("word/document.xml", &["root", "x:extLst"], "", "other"),
        Err(Error::Edit(_))
    ));
}

#[test]
fn signed_duplicate_and_unsafe_paths_refuse_mutation_or_open() {
    let signed = include_bytes!("fixtures/signed.zip");
    let mut package = Package::open(signed, Limits::default()).expect("fixture operation");
    assert_eq!(package.export().expect("signed no-op"), signed);
    assert!(matches!(
        package.replace_text("word/document.xml", PATH, "old", "new"),
        Err(Error::Edit(_))
    ));
    for bad in [
        include_bytes!("fixtures/duplicate.zip").as_slice(),
        include_bytes!("fixtures/traversal.zip").as_slice(),
    ] {
        assert!(matches!(
            Package::open(bad, Limits::default()),
            Err(Error::Invalid(_))
        ));
    }
}

#[test]
#[ignore = "requires locally acquired pinned PPTArena-001 pair"]
fn optional_pinned_pptarena_pair_proves_identity_without_redistributing_decks() {
    let folder =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pptarena-001");
    assert!(
        folder.exists(),
        "acquire pinned PPTArena-001 before running the ignored test"
    );
    for (file, digest) in [
        (
            "original.pptx",
            "166e95dcf7883aa0ed60768e184c225851161a908f82223a7f8443f45cdd32dd",
        ),
        (
            "ground_truth.pptx",
            "32a2adb5d145439a959d53b7dc2f24dabb54d01e37cc0cbd2c0a9b3c34dde7c2",
        ),
    ] {
        use sha2::Digest;
        let bytes = std::fs::read(folder.join(file)).expect("fixture operation");
        assert_eq!(format!("{:x}", sha2::Sha256::digest(&bytes)), digest);
        let mut package = Package::open(&bytes, Limits::default()).expect("fixture operation");
        assert_eq!(
            package.export().expect("fixture operation"),
            bytes,
            "{file}: archive exact"
        );
        let slide = "ppt/slides/slide1.xml";
        let before = package
            .part(slide)
            .expect("fixture operation")
            .expect("fixture operation");
        let names: Vec<_> = package.names().map(str::to_owned).collect();
        let text = if file == "original.pptx" {
            "Iklassova"
        } else {
            // Choose an existing uniquely addressed leaf in the ground truth.
            "Iklassova"
        };
        package
            .replace_text(
                slide,
                &[
                    "p:sld", "p:cSld", "p:spTree", "p:sp", "p:txBody", "a:p", "a:r", "a:t",
                ],
                text,
                "Changed & safe",
            )
            .expect("fixture operation");
        let changed = package.export().expect("fixture operation");
        let reopened = Package::open(&changed, Limits::default()).expect("fixture operation");
        let new = reopened
            .part(slide)
            .expect("fixture operation")
            .expect("fixture operation");
        let old = text.as_bytes();
        let at = before
            .windows(old.len())
            .position(|w| w == old)
            .expect("text offset");
        let mut expected_xml = Vec::new();
        expected_xml.extend_from_slice(&before[..at]);
        expected_xml.extend_from_slice(b"Changed &amp; safe");
        expected_xml.extend_from_slice(&before[at + old.len()..]);
        assert_eq!(
            new, expected_xml,
            "{file}: all unknown XML remains in place"
        );
        for name in names {
            if name != slide {
                assert_eq!(
                    reopened.part(&name).expect("fixture operation"),
                    Some(package_part(&bytes, &name)),
                    "{file}: {name}"
                );
            }
        }
    }
}

#[test]
fn ambiguous_target_and_invalid_xml_character_refuse() {
    let mut package = Package::open(include_bytes!("fixtures/ambiguous.zip"), Limits::default())
        .expect("fixture operation");
    assert!(matches!(
        package.replace_text("word/document.xml", PATH, "old", "new"),
        Err(Error::Edit(_))
    ));
    assert!(matches!(
        package.replace_text("word/document.xml", PATH, "old", "invalid\u{0001}"),
        Err(Error::Edit(_))
    ));
    assert_eq!(
        package.export().expect("fixture operation"),
        include_bytes!("fixtures/ambiguous.zip")
    );
}

#[test]
fn data_descriptors_survive_noop_and_changed_entry_drops_only_its_descriptor() {
    let source = include_bytes!("fixtures/descriptor.docx");
    let mut package = Package::open(source, Limits::default()).expect("fixture operation");
    assert_eq!(package.export().expect("fixture operation"), source);
    let unknown = package
        .part("customXml/unreachable.bin")
        .expect("fixture operation");
    package
        .replace_text("word/document.xml", PATH, "old", "edited")
        .expect("fixture operation");
    let output = package.export().expect("fixture operation");
    let reopened = Package::open(&output, Limits::default()).expect("fixture operation");
    assert_eq!(
        reopened
            .part("customXml/unreachable.bin")
            .expect("fixture operation"),
        unknown
    );
    let xml = reopened
        .part("word/document.xml")
        .expect("fixture operation")
        .expect("fixture operation");
    assert_eq!(
        xml,
        b"<root><item>edited</item><x:extLst xmlns:x=\"urn:x\"/></root>"
    );
}
