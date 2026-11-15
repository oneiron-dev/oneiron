//! The stemma fork reads untrusted DOCX parts with quick-xml. Before 0.41,
//! quick-xml checked a start tag's attributes for duplicates pairwise, so one
//! tag with n attributes cost O(n^2) (RUSTSEC-2026-0194). The fork's own
//! expanded-name duplicate check (word_xml.rs) scanned the same way until
//! FIX TEST-RED-DOCEDIT-STEMMA-BUDGET, and its namespace scope scanned each
//! tag's declarations per prefix until FIX STEMMA-NS-PREFIX-SCAN.

use std::io::{Cursor, Read, Write};
use std::time::{Duration, Instant};

use oneiron_docedit::Document;

const INPUT: &[u8] = include_bytes!("../vendor/stemma-engine/testdata/simple-text/before.docx");

/// Copy `INPUT` with its first `<w:p ...>` start tag given `attributes`.
fn with_paragraph_attributes(attributes: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(INPUT)).expect("fixture opens");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("entry");
        let name = entry.name().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("entry inflates");
        if name == "word/document.xml" {
            let xml = String::from_utf8(bytes).expect("UTF-8 part");
            assert!(xml.contains("<w:p "), "fixture paragraph has attributes");
            bytes = xml
                .replacen("<w:p ", &format!("<w:p {attributes} "), 1)
                .into_bytes();
        }
        writer
            .start_file(name, zip::write::FileOptions::default())
            .expect("entry starts");
        writer.write_all(&bytes).expect("entry writes");
    }
    writer.finish().expect("archive finishes").into_inner()
}

fn accepted_text(bytes: &[u8]) -> String {
    Document::parse(bytes)
        .expect("DOCX parses")
        .read_accepted()
        .expect("accepted view")
        .to_text()
}

#[test]
fn start_tag_with_many_attributes_parses_in_bounded_time() {
    // Equal-length keys, so the pre-0.41 pairwise check compares every pair
    // byte by byte: ~5e9 comparisons per pass. Hashing keeps it linear.
    const ATTRIBUTES: usize = 100_000;
    let attributes: Vec<String> = (0..ATTRIBUTES)
        .map(|index| format!("x{index:06}=\"{index}\""))
        .collect();
    let bytes = with_paragraph_attributes(&attributes.join(" "));

    let started = Instant::now();
    let text = accepted_text(&bytes);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "{ATTRIBUTES} attributes on one start tag took {elapsed:?}"
    );
    assert_eq!(text, accepted_text(INPUT));
}

#[test]
fn start_tag_with_many_namespace_declarations_parses_in_bounded_time() {
    // Each prefixed attribute resolves its prefix against the declarations on
    // its own tag. Equal-length prefixes, so a scan of the declarations
    // compares ~5e9 pairs byte by byte. Keying them by prefix keeps it linear.
    const PREFIXES: usize = 100_000;
    let attributes: Vec<String> = (0..PREFIXES)
        .map(|index| {
            format!("xmlns:p{index:06}=\"urn:oneiron:ns:{index}\" p{index:06}:x=\"{index}\"")
        })
        .collect();
    let bytes = with_paragraph_attributes(&attributes.join(" "));

    let started = Instant::now();
    let text = accepted_text(&bytes);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "{PREFIXES} namespace declarations and prefixed attributes on one start tag took {elapsed:?}"
    );
    assert_eq!(text, accepted_text(INPUT));
}

#[test]
fn start_tag_refuses_a_duplicate_expanded_name_below_and_past_the_scan_limit() {
    // Two prefixes bound to one URI name one expanded attribute. quick-xml
    // sees two different names, so the fork's own check must refuse it, on a
    // tag it scans and on a tag it hashes (more than 32 attributes).
    for filler in [0_usize, 64] {
        let mut attributes: Vec<String> = (0..filler)
            .map(|index| format!("x{index:06}=\"{index}\""))
            .collect();
        attributes.push(
            "xmlns:twina=\"urn:oneiron:twin\" xmlns:twinb=\"urn:oneiron:twin\" \
             twina:name=\"1\" twinb:name=\"2\""
                .to_owned(),
        );
        let bytes = with_paragraph_attributes(&attributes.join(" "));
        let refusal = Document::parse(&bytes)
            .err()
            .unwrap_or_else(|| panic!("a duplicate expanded name beside {filler} attributes read"));
        assert!(
            refusal.to_string().contains("duplicate attribute"),
            "{refusal}"
        );
    }
}
