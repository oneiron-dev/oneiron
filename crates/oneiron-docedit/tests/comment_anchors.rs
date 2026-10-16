//! Native Word comment ranges for the comment-anchor scenarios (owner ask
//! 2026-10-16; the cases come from tdoc's anchor tests): a comment authored on
//! a one-character, a CJK or a cross-run selection encloses exactly that text
//! in the saved `word/document.xml`, read back with an XML parser rather than
//! through the engine; a quote the paragraph no longer holds is refused; and a
//! repeated quote anchors its first copy unless `occurrence` names another,
//! with the step reporting how many copies matched and which one it took.

use std::io::{Read, Write};

use oneiron_docedit::{ArchiveLimits, DoceditError, Document, revise, revise_with_diagnostics};

const W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

/// A minimal DOCX whose body holds `paragraphs`, each a list of
/// `(text, bold)` runs.
fn docx(paragraphs: &[&[(&str, bool)]]) -> Vec<u8> {
    let paragraphs: Vec<String> = paragraphs
        .iter()
        .map(|runs| {
            runs.iter()
                .map(|(text, bold)| {
                    let props = if *bold { "<w:rPr><w:b/></w:rPr>" } else { "" };
                    format!(r#"<w:r>{props}<w:t xml:space="preserve">{text}</w:t></w:r>"#)
                })
                .collect()
        })
        .collect();
    let paragraphs: Vec<&str> = paragraphs.iter().map(String::as_str).collect();
    docx_xml(&paragraphs)
}

/// A minimal DOCX whose body holds one `<w:p>` per entry of raw paragraph XML.
fn docx_xml(paragraphs: &[&str]) -> Vec<u8> {
    let body: String = paragraphs
        .iter()
        .map(|p| format!("<w:p>{p}</w:p>"))
        .collect();
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

/// Authors one comment on `quote` in the first paragraph, naming its 1-based
/// `occurrence` when given; returns the output and the notes the step reported.
fn comment_copy(
    input: &[u8],
    quote: &str,
    occurrence: Option<usize>,
) -> Result<(Vec<u8>, Vec<String>), DoceditError> {
    let blocks = Document::parse(input).expect("input parses").read().blocks;
    let mut op = serde_json::json!({ "op": "comment_create", "target": blocks[0].id,
        "expect": quote, "body": "Check this." });
    if let Some(occurrence) = occurrence {
        op["occurrence"] = occurrence.into();
    }
    let transaction = serde_json::json!({ "ops": [op], "revision": { "author": "Reviewer" } });
    let (output, notes) =
        revise_with_diagnostics(input, &transaction.to_string(), ArchiveLimits::DEFAULT)?;
    Ok((output, notes.into_iter().map(|note| note.message).collect()))
}

/// The step reported `copies` copies of its quote and named the anchored one.
fn assert_copy_note(notes: &[String], copies: usize, anchored: usize) {
    let [note] = notes else {
        panic!("one repeated-quote note expected: {notes:?}");
    };
    assert!(note.contains(&format!("occurs {copies} times")), "{note}");
    assert!(
        note.contains(&format!("anchored copy {anchored}")),
        "{note}"
    );
    assert!(note.contains("occurrence"), "{note}");
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

/// Each paragraph's visible text with `[` and `]` where comment ranges open
/// and close, and a run's line break as `\n`; deleted text is left out.
fn bracketed(docx: &[u8]) -> Vec<String> {
    let xml = document_xml(docx);
    let doc = roxmltree::Document::parse(&xml).expect("document XML parses");
    doc.descendants()
        .filter(|n| n.has_tag_name((W, "p")))
        .map(|p| {
            p.descendants()
                .filter(|n| n.tag_name().namespace() == Some(W))
                .filter_map(|n| match n.tag_name().name() {
                    "commentRangeStart" => Some("["),
                    "commentRangeEnd" => Some("]"),
                    "t" => n.text(),
                    "br" => Some("\n"),
                    _ => None,
                })
                .collect()
        })
        .collect()
}

/// The text inside tracked insertions.
fn inserted_text(docx: &[u8]) -> String {
    let xml = document_xml(docx);
    let doc = roxmltree::Document::parse(&xml).expect("document XML parses");
    doc.descendants()
        .filter(|n| n.has_tag_name((W, "t")) && n.ancestors().any(|a| a.has_tag_name((W, "ins"))))
        .filter_map(|t| t.text())
        .collect()
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
                n.has_tag_name((W, "b"))
                    && !matches!(n.attribute((W, "val")), Some("0" | "false" | "off"))
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
fn repeated_quote_comment_lands_on_the_first_copy_and_occurrence_picks_another() {
    let input = docx(&[&[("the cat and the dog", false)]]);
    // Without `occurrence` the first copy is anchored, as before, and the step
    // says how many copies matched.
    let (output, notes) = comment_copy(&input, "the", None).unwrap();
    assert_eq!(bracketed(&output), ["[the] cat and the dog"]);
    assert_copy_note(&notes, 2, 1);
    let (output, notes) = comment_copy(&input, "the", Some(2)).unwrap();
    assert_eq!(bracketed(&output), ["the cat and [the] dog"]);
    assert_copy_note(&notes, 2, 2);
    // A quote long enough to be unique still lands, with nothing to report.
    let (output, notes) = comment_copy(&input, "the dog", None).unwrap();
    assert_eq!(commented_text(&output), ["the dog"]);
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn occurrence_addresses_each_of_two_identical_sentences() {
    // No longer quote is unique here, so only `occurrence` reaches the second.
    let input = docx(&[&[("Same line. Same line.", false)]]);
    for (occurrence, anchored, expected) in [
        (None, 1, "[Same line.] Same line."),
        (Some(1), 1, "[Same line.] Same line."),
        (Some(2), 2, "Same line. [Same line.]"),
    ] {
        let (output, notes) = comment_copy(&input, "Same line.", occurrence).unwrap();
        assert_eq!(bracketed(&output), [expected], "occurrence {occurrence:?}");
        assert_eq!(paragraph_text(&output), ["Same line. Same line."]);
        assert_copy_note(&notes, 2, anchored);
    }
    for occurrence in [0, 3] {
        let error = comment_copy(&input, "Same line.", Some(occurrence)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("occurrence {occurrence} is not one of them")),
            "{error}"
        );
    }
}

#[test]
fn occurrence_reaches_a_copy_inside_a_tracked_insertion() {
    let input = docx_xml(&[concat!(
        r#"<w:r><w:t>Pay the fee</w:t></w:r>"#,
        r#"<w:ins w:id="1" w:author="Drafter" w:date="2026-10-01T00:00:00Z">"#,
        r#"<w:r><w:t xml:space="preserve"> and the fee</w:t></w:r></w:ins>"#,
    )]);
    let (output, notes) = comment_copy(&input, "the fee", None).unwrap();
    assert_eq!(bracketed(&output), ["Pay [the fee] and the fee"]);
    assert_copy_note(&notes, 2, 1);
    // The second copy is pending inserted text: the range encloses the whole
    // insertion rather than splitting it, and the insertion stays tracked.
    let (output, notes) = comment_copy(&input, "the fee", Some(2)).unwrap();
    assert_eq!(bracketed(&output), ["Pay the fee[ and the fee]"]);
    assert_eq!(inserted_text(&output), " and the fee");
    assert_copy_note(&notes, 2, 2);
}

#[test]
fn a_quote_that_also_matches_across_a_line_break_counts_that_copy() {
    // A break adds no visible text, so the paragraph reads "xy xy" and the
    // first copy runs across the break.
    let input = docx_xml(&[concat!(
        r#"<w:r><w:t>x</w:t></w:r><w:r><w:br/></w:r>"#,
        r#"<w:r><w:t xml:space="preserve">y xy</w:t></w:r>"#,
    )]);
    // The default still anchors the copy inside one run, and names it as the
    // second, so `occurrence: 2` reproduces it.
    let (output, notes) = comment_copy(&input, "xy", None).unwrap();
    assert_eq!(bracketed(&output), ["x\ny [xy]"]);
    assert_copy_note(&notes, 2, 2);
    let (output, notes) = comment_copy(&input, "xy", Some(1)).unwrap();
    assert_eq!(bracketed(&output), ["[x\ny] xy"]);
    assert_copy_note(&notes, 2, 1);
    let (output, notes) = comment_copy(&input, "xy", Some(2)).unwrap();
    assert_eq!(bracketed(&output), ["x\ny [xy]"]);
    assert_copy_note(&notes, 2, 2);
}
