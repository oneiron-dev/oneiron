//! The stemma fork reads untrusted DOCX parts with quick-xml. Before 0.41,
//! quick-xml checked a start tag's attributes for duplicates pairwise, so one
//! tag with n attributes cost O(n^2) (RUSTSEC-2026-0194).

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
