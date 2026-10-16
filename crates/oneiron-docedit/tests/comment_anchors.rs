//! Native Word comment ranges for the comment-anchor scenarios (owner ask
//! 2026-10-16; the cases come from tdoc's anchor tests): a comment authored on
//! a one-character, a CJK or a cross-run selection encloses exactly that text
//! in the saved `word/document.xml`, read back with an XML parser rather than
//! through the engine, and a quote that does not pin one place is refused
//! rather than anchored somewhere.

use std::io::{Read, Write};

use oneiron_docedit::{DoceditError, Document, revise};

const W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

/// A minimal DOCX whose body holds `paragraphs`, each a list of
/// `(text, bold)` runs.
fn docx(paragraphs: &[&[(&str, bool)]]) -> Vec<u8> {
    let mut body = String::new();
    for runs in paragraphs {
        body.push_str("<w:p>");
        for (text, bold) in *runs {
            let props = if *bold { "<w:rPr><w:b/></w:rPr>" } else { "" };
            body.push_str(&format!(
                r#"<w:r>{props}<w:t xml:space="preserve">{text}</w:t></w:r>"#
            ));
        }
        body.push_str("</w:p>");
    }
    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W}"><w:body>{body}<w:sectPr/></w:body></w:document>"#
    );
    let parts = [
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#.to_owned(),
        ),
        (
            "_rels/.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#.to_owned(),
        ),
        (
            "word/_rels/document.xml.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>"#.to_owned(),
        ),
        ("word/document.xml", document),
    ];
    let mut out = Vec::new();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
    for (name, data) in parts {
        zip.start_file(name, zip::write::FileOptions::default())
            .expect("part starts");
        zip.write_all(data.as_bytes()).expect("part writes");
    }
    zip.finish().expect("archive finishes");
    drop(zip);
    out
}

/// Authors one comment per `(paragraph index, quote)` through the native
/// revision door.
fn comment(input: &[u8], quotes: &[(usize, &str)]) -> Result<Vec<u8>, DoceditError> {
    let blocks = Document::parse(input).expect("input parses").read().blocks;
    let ops: Vec<_> = quotes
        .iter()
        .map(|(block, quote)| {
            serde_json::json!({ "op": "comment_create", "target": blocks[*block].id,
                "expect": quote, "body": "Check this." })
        })
        .collect();
    let transaction = serde_json::json!({ "ops": ops, "revision": { "author": "Reviewer" } });
    revise(input, &transaction.to_string())
}

fn document_xml(docx: &[u8]) -> String {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(docx)).expect("output opens");
    let mut xml = String::new();
    archive
        .by_name("word/document.xml")
        .expect("document part")
        .read_to_string(&mut xml)
        .expect("document part reads");
    xml
}

/// The text each comment range encloses, in the order the ranges open.
fn commented_text(docx: &[u8]) -> Vec<String> {
    let xml = document_xml(docx);
    let doc = roxmltree::Document::parse(&xml).expect("document XML parses");
    let mut ranges: Vec<(String, String)> = Vec::new();
    let mut open: Vec<String> = Vec::new();
    for node in doc.descendants() {
        if node.tag_name().namespace() != Some(W) {
            continue;
        }
        match node.tag_name().name() {
            "commentRangeStart" => {
                let id = node.attribute((W, "id")).expect("range id").to_owned();
                ranges.push((id.clone(), String::new()));
                open.push(id);
            }
            "commentRangeEnd" => {
                let id = node.attribute((W, "id")).expect("range id").to_owned();
                assert!(open.contains(&id), "range {id} ends unopened");
                open.retain(|o| *o != id);
            }
            "t" => {
                for (id, text) in &mut ranges {
                    if open.contains(id) {
                        text.push_str(node.text().unwrap_or_default());
                    }
                }
            }
            _ => {}
        }
    }
    assert!(open.is_empty(), "ranges left open: {open:?}");
    ranges.into_iter().map(|(_, text)| text).collect()
}

/// All text that sits in a bold run.
fn bold_text(docx: &[u8]) -> String {
    let xml = document_xml(docx);
    let doc = roxmltree::Document::parse(&xml).expect("document XML parses");
    let is_bold = |run: roxmltree::Node<'_, '_>| {
        run.children()
            .filter(|n| n.has_tag_name((W, "rPr")))
            .flat_map(|props| props.children())
            .any(|n| {
                n.has_tag_name((W, "b")) && !matches!(n.attribute((W, "val")), Some("0" | "false"))
            })
    };
    doc.descendants()
        .filter(|n| n.has_tag_name((W, "r")) && is_bold(*n))
        .flat_map(|run| run.children().filter(|n| n.has_tag_name((W, "t"))))
        .filter_map(|t| t.text())
        .collect()
}

fn paragraph_text(docx: &[u8]) -> Vec<String> {
    Document::parse(docx)
        .expect("output parses")
        .read()
        .blocks
        .into_iter()
        .map(|block| block.text)
        .collect()
}

#[test]
fn one_char_and_cjk_comments_enclose_exactly_their_selection() {
    let input = docx(&[&[("Hello world", false)], &[("東京は晴れ", false)]]);
    let output = comment(&input, &[(0, "w"), (1, "東京")]).unwrap();
    assert_eq!(commented_text(&output), ["w", "東京"]);
    // Splitting the runs at the range edges loses and repeats nothing.
    assert_eq!(paragraph_text(&output), ["Hello world", "東京は晴れ"]);
}

#[test]
fn comment_across_a_bold_run_encloses_the_selection_and_keeps_the_bold() {
    let input = docx(&[&[("Plain ", false), ("bold", true), (" tail", false)]]);
    let output = comment(&input, &[(0, "n bold t")]).unwrap();
    assert_eq!(commented_text(&output), ["n bold t"]);
    assert_eq!(bold_text(&output), "bold");
    assert_eq!(paragraph_text(&output), ["Plain bold tail"]);
}

#[test]
fn comment_on_a_sentence_the_paragraph_no_longer_holds_is_refused() {
    // The reviewer read "Rewrite this one." in an older version.
    let input = docx(&[&[("Keep this. Something else now.", false)]]);
    assert!(comment(&input, &[(0, "Rewrite this one.")]).is_err());
}

#[test]
#[ignore = "bug: comment_create anchors the first of repeated quotes (reported to Engine 10-16)"]
fn repeated_quote_comment_is_refused_rather_than_put_on_the_first_copy() {
    let input = docx(&[&[("the cat and the dog", false)]]);
    // `set_format` refuses a quote that occurs twice (AmbiguousFormatTarget);
    // a comment has no more right to pick one of the copies.
    assert!(comment(&input, &[(0, "the")]).is_err());
    // A quote long enough to be unique still lands.
    let output = comment(&input, &[(0, "the dog")]).unwrap();
    assert_eq!(commented_text(&output), ["the dog"]);
}
