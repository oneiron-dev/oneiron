// The contract a hosted caller outside this repository uses, which no other
// test here calls: one run of each op through `execute_json`, the envelope's
// refusals, and the shape of the discovery document and of the generated call
// and reply schemas, pinned to the schema number. The pin does not hold the
// grammar behind a field the schema types as any JSON (the DOCX and deck
// transactions, the deck report and marks), nor the bytes of an input.
// FIX [DOCEDIT-CONTRACT-RUN-BY-NO-TEST]
// From a checkout of the whole repository (the Office fixtures are under scripts/office):
// cargo test --locked -p oneiron-docedit --all-features --test contract

use std::cell::RefCell;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use oneiron_docedit::contract::{
    self, CONTRACT_SCHEMA, Call, ContractError, Done, ErrorCode, MAX_DETAIL_BYTES, Ports,
    RecalcClockArgs, RecalcPort, Recalculated, Reply,
};
use oneiron_docedit::docx_body::{DocxBlock, DocxBlockKind};
use oneiron_docedit::retained_opc::Limits;
use oneiron_docedit::xlsx_body::{XlsxBook, XlsxValue};
use serde_json::{Value, json};

const OP_NAMES: [&str; 14] = [
    "contract.describe",
    "docx.read",
    "docx.revise",
    "docx.validate",
    "docx.project",
    "xlsx.read",
    "xlsx.project",
    "xlsx.mark_full_calc",
    "xlsx.recalc",
    "deck.read",
    "deck.transaction",
    "deck.create",
    "pptx.comments",
    "pptx.comments.inspect",
];
const REVISION_DATE: &str = "2026-10-01T00:00:00Z";
const WORDPROCESSING_ML: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const SPREADSHEET_ML: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const PRESENTATION_ML: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
const DRAWING_ML: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
/// The one paragraph of [`document`].
const PARAGRAPH: &str = "This is a test now foo bar baz";

/// The schema number the rows of [`PINNED`] were measured under.
const PINNED_SCHEMA: u32 = 5;
/// The contract's shape as pinned for one schema number: `(name, length of the shape text in bytes, BLAKE3 hex)`.
const PINNED: [(&str, usize, &str); 3] = [
    (
        "describe",
        46060,
        "8fbc7ea3130bc8fae903dad79c5fb8fbe0c336491a1694cc2bda211b5b663927",
    ),
    (
        "call_schema",
        24343,
        "f46f2ce972dbfe318a2363cc1a3d47019827c677d58060ff0b295eadc06550ef",
    ),
    (
        "reply_schema",
        16039,
        "16ebb7c7204a8fd9c8f205e4ba605b7c48751b1a7252eafcc3960858c2ddac9c",
    ),
];

/// A committed file, by its path from this crate's directory.
fn file(path: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn fixture(name: &str) -> Vec<u8> {
    file(&format!("tests/fixtures/{name}"))
}

fn zip_part(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("open fixture archive");
    let mut part = archive
        .by_name(name)
        .unwrap_or_else(|error| panic!("part {name}: {error}"));
    let mut bytes = Vec::new();
    part.read_to_end(&mut bytes).expect("read archive part");
    bytes
}

fn workbook() -> Vec<u8> {
    zip_part(
        &fixture("spreadsheet-compat/excel/cached-workbooks.zip"),
        "case-0000.xlsx",
    )
}

/// A document Word wrote, of one paragraph: [`PARAGRAPH`].
fn document() -> Vec<u8> {
    file("vendor/stemma-engine/testdata/simple-text/before.docx")
}

/// The relationships part of the main part `word/document.xml`.
const MAIN_PART_RELATIONSHIPS: &str = "word/_rels/document.xml.rels";
const PACKAGE_RELATIONSHIPS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const RELATIONSHIPS_TYPE: &str = "application/vnd.openxmlformats-package.relationships+xml";
// testkit-lint: allow(network) a relationship type name the fork writes, compared as text; no test opens it
const REVISION_IDS_REL: &str = "http://stemma.sh/2026/relationships/revisionIds";
const CONTENT_TYPES: &str = "http://schemas.openxmlformats.org/package/2006/content-types";

fn has_part(bytes: &[u8], name: &str) -> bool {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("open archive");
    archive.file_names().any(|part| part == name)
}

/// A document of three paragraphs whose package holds no relationships part
/// for its main part. OPC asks for that part only when the main part has a
/// relationship, and this one has none.
fn document_with_no_relationships_part() -> Vec<u8> {
    let bytes = fixture("docx/word-semantics/join-base.docx");
    assert!(
        !has_part(&bytes, MAIN_PART_RELATIONSHIPS),
        "the fixture gained the part these tests need absent"
    );
    bytes
}

/// `bytes` with the part `name` holding `data`, and every other part as it was.
fn with_part(bytes: &[u8], name: &str, data: &[u8]) -> Vec<u8> {
    rewrite_part(bytes, Some(name), name, data)
}

/// Write `data` under `name`, replacing `original_name` in place or adding a new part.
fn rewrite_part(bytes: &[u8], original_name: Option<&str>, name: &str, data: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("open archive");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut replaced = false;
    for index in 0..archive.len() {
        let mut part = archive.by_index(index).expect("archive part");
        let mut held = Vec::new();
        let (part_name, part_bytes) = if original_name == Some(part.name()) {
            replaced = true;
            (name, data)
        } else {
            part.read_to_end(&mut held).expect("read archive part");
            (part.name(), held.as_slice())
        };
        writer
            .start_file(part_name, zip::write::FileOptions::default())
            .expect("start archive part");
        writer.write_all(part_bytes).expect("write archive part");
    }
    if let Some(original_name) = original_name {
        assert!(replaced, "the archive holds no part {original_name}");
    } else {
        writer
            .start_file(name, zip::write::FileOptions::default())
            .expect("start new archive part");
        writer.write_all(data).expect("write new archive part");
    }
    writer.finish().expect("finish archive").into_inner()
}

/// The content type the package declares for `part`: its Override, or else
/// the Default of its extension.
fn content_type_of(bytes: &[u8], part: &str) -> Option<String> {
    let xml = xml_part(bytes, "[Content_Types].xml");
    let tree = roxmltree::Document::parse(&xml).expect("content types XML");
    let declared = |tag: &str, attribute: &str, value: &str| {
        tree.descendants()
            .find(|node| {
                node.has_tag_name((CONTENT_TYPES, tag))
                    && node
                        .attribute(attribute)
                        .is_some_and(|held| held.eq_ignore_ascii_case(value))
            })
            .and_then(|node| node.attribute("ContentType"))
            .map(str::to_owned)
    };
    let extension = part.rsplit_once('.').map_or("", |(_, extension)| extension);
    declared("Override", "PartName", &format!("/{part}"))
        .or_else(|| declared("Default", "Extension", extension))
}

/// `docx.revise` of `bytes` that replaces its paragraph "second." by
/// SECOND-AS-REVISED.
fn revise_second_paragraph(bytes: &[u8]) -> Done {
    revise_paragraph(bytes, "second.", "SECOND-AS-REVISED", "Editor")
}

fn revise_paragraph(bytes: &[u8], original: &str, revised: &str, author: &str) -> Done {
    let parsed = oneiron_docedit::Document::parse(bytes).expect("parse base document");
    let view = parsed.read();
    let block = view
        .blocks
        .iter()
        .find(|block| block.text == original)
        .expect("the paragraph to revise");
    run(
        "docx.revise",
        json!({
            "document": 0, "limits": docx_limits(),
            "transaction": {"ops": [{"op": "replace", "target": block.id, "guard": block.guard,
                "content": {"type": "paragraph", "content": [{"type": "text", "text": revised}]}}],
                "revision": {"author": author, "date": REVISION_DATE}}
        }),
        &[bytes],
    )
}

/// The part that a relationship names by `target`: a leading slash counts
/// from the package root, anything else from the main part's directory.
fn main_part_target(main_dir: &str, target: &str) -> String {
    let path = match target.strip_prefix('/') {
        Some(from_root) => from_root.to_owned(),
        None if main_dir.is_empty() => target.to_owned(),
        None => format!("{main_dir}/{target}"),
    };
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    segments.join("/")
}

fn docx_limits() -> Value {
    json!({"max_entries": 1024, "max_part_bytes": 16_777_216, "max_total_bytes": 67_108_864})
}

fn package_limits() -> Value {
    json!({"archive_bytes": 33_554_432, "part_bytes": 16_777_216, "expanded_bytes": 67_108_864})
}

fn call_text(name: &str, args: Value) -> String {
    assert!(OP_NAMES.contains(&name), "{name} is not in OP_NAMES");
    let text = json!({"schema": CONTRACT_SCHEMA, "op": name, "args": args}).to_string();
    let call: Call =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {name} call: {error}"));
    assert_eq!(call.op.name(), name, "serde tag and Op::name disagree");
    text
}

fn run(name: &str, args: Value, inputs: &[&[u8]]) -> Done {
    let text = call_text(name, args);
    contract::execute_json(text.as_bytes(), inputs, Ports::default())
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn output<'a>(done: &'a Done, name: &str, media_type: &str) -> &'a [u8] {
    let [output] = done.outputs.as_slice() else {
        panic!("expected one output: {:?}", done.outputs);
    };
    assert_eq!(output.name, name);
    assert_eq!(output.media_type, media_type);
    &output.bytes
}

fn read_document(bytes: &[u8]) -> Vec<DocxBlock> {
    let done = run(
        "docx.read",
        json!({"document": 0, "limits": docx_limits()}),
        &[bytes],
    );
    match done.reply {
        Reply::DocxBlocks { blocks, .. } => blocks,
        reply => panic!("expected DocxBlocks: {reply:?}"),
    }
}

fn read_workbook(bytes: &[u8]) -> XlsxBook {
    let done = run(
        "xlsx.read",
        json!({"workbook": 0, "limits": package_limits()}),
        &[bytes],
    );
    match done.reply {
        Reply::XlsxBook { book } => book,
        reply => panic!("expected XlsxBook: {reply:?}"),
    }
}

fn assert_workbook_cell(book: &XlsxBook, col: u32, value: XlsxValue, formula: Option<&str>) {
    let sheet = book
        .sheets
        .iter()
        .find(|sheet| sheet.name == "Sheet1")
        .expect("Sheet1");
    let cell = sheet
        .cells
        .iter()
        .find(|cell| cell.col == col && cell.row == 1)
        .expect("row 1 cell");
    assert_eq!(cell.value, value);
    assert_eq!(cell.formula.as_deref(), formula);
}

fn assert_error(result: Result<Done, ContractError>, code: ErrorCode) {
    let error = result.expect_err("call must refuse");
    assert_eq!(error.code, code, "{error}");
    assert!(
        (1..=MAX_DETAIL_BYTES).contains(&error.detail.len()),
        "the detail is empty or too long: {error:?}"
    );
}

fn xml_part(bytes: &[u8], name: &str) -> String {
    String::from_utf8(zip_part(bytes, name)).unwrap_or_else(|error| panic!("part {name}: {error}"))
}

/// The DOCX holds `text` as one tracked insertion under the test's author and
/// revision date.
fn assert_tracked_insertion(bytes: &[u8], text: &str) {
    let xml = xml_part(bytes, "word/document.xml");
    let tree = roxmltree::Document::parse(&xml).expect("document XML");
    let inserted = tree.descendants().any(|node| {
        node.has_tag_name((WORDPROCESSING_ML, "ins"))
            && node.attribute((WORDPROCESSING_ML, "author")) == Some("Editor")
            && node.attribute((WORDPROCESSING_ML, "date")) == Some(REVISION_DATE)
            && node
                .descendants()
                .filter(|child| child.has_tag_name((WORDPROCESSING_ML, "t")))
                .map(|child| child.text().unwrap_or_default())
                .collect::<String>()
                == text
    });
    assert!(inserted, "no tracked insertion of {text:?}: {xml}");
}

#[test]
fn described_ops_are_the_names_run_here() {
    let description = contract::describe();
    for name in OP_NAMES {
        assert!(
            description.ops.iter().any(|op| op.name == name),
            "describe is missing {name}"
        );
    }
    for op in &description.ops {
        assert!(
            OP_NAMES.contains(&op.name.as_str()),
            "describe names an op with no run here: {}",
            op.name
        );
    }
    assert_eq!(description.ops.len(), OP_NAMES.len());
}

#[test]
fn contract_describe() {
    let done = run("contract.describe", Value::Null, &[]);
    match &done.reply {
        Reply::Described(description) => {
            assert_eq!(description, &contract::describe());
            assert_eq!(description.schema, CONTRACT_SCHEMA);
            assert_eq!(description.ops.len(), 14);
            let recalc = description
                .ops
                .iter()
                .find(|op| op.name == "xlsx.recalc")
                .expect("recalc row");
            assert_eq!(recalc.port.as_deref(), Some("recalc"));
        }
        reply => panic!("expected Described: {reply:?}"),
    }
    assert!(done.outputs.is_empty());
    // The op takes no args: a call with no `args` member is the same call.
    let text = json!({"schema": CONTRACT_SCHEMA, "op": "contract.describe"}).to_string();
    let without_args = contract::execute_json(text.as_bytes(), &[], Ports::default())
        .unwrap_or_else(|error| panic!("contract.describe with no args member: {error}"));
    assert_eq!(without_args, done);
}

#[test]
fn docx_read() {
    let bytes = document();
    let blocks = read_document(&bytes);
    let read: Vec<_> = blocks
        .iter()
        .map(|block| (block.kind, block.text.as_str()))
        .collect();
    assert_eq!(read, [(DocxBlockKind::Paragraph, PARAGRAPH)]);
}

#[test]
fn docx_revise() {
    let bytes = document();
    let parsed = oneiron_docedit::Document::parse(&bytes).expect("parse base document");
    let view = parsed.read();
    let block = view
        .blocks
        .iter()
        .find(|block| block.text == PARAGRAPH)
        .expect("the document's paragraph");
    let done = run(
        "docx.revise",
        json!({
            "document": 0, "limits": docx_limits(),
            "transaction": {"ops": [{"op": "replace", "target": block.id, "guard": block.guard,
                "content": {"type": "paragraph", "content": [{"type": "text", "text": "PARAGRAPH-AS-REVISED"}]}}],
                "revision": {"author": "Editor", "date": REVISION_DATE}}
        }),
        &[&bytes],
    );
    match &done.reply {
        Reply::DocxRevised { transaction, .. } => {
            assert_eq!(transaction["revision"]["date"], REVISION_DATE);
        }
        reply => panic!("expected DocxRevised: {reply:?}"),
    }
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    assert!(
        read_document(changed)
            .iter()
            .any(|block| block.text.contains("PARAGRAPH-AS-REVISED"))
    );
    assert_tracked_insertion(changed, "PARAGRAPH-AS-REVISED");
}

#[test]
fn docx_validate() {
    let bytes = document();
    let done = run(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits()}),
        &[&bytes],
    );
    match &done.reply {
        Reply::Checked => {}
        reply => panic!("expected Checked: {reply:?}"),
    }
    assert!(done.outputs.is_empty());
    let text = call_text(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits()}),
    );
    assert_error(
        contract::execute_json(text.as_bytes(), &[b"not a package"], Ports::default()),
        ErrorCode::InvalidDocument,
    );
    // A transaction, when given, is checked against the writer's grammar.
    let text = call_text(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits(), "transaction": {"ops": "none"}}),
    );
    assert_error(
        contract::execute_json(text.as_bytes(), &[&bytes], Ports::default()),
        ErrorCode::BadRequest,
    );
}

#[test]
fn docx_project() {
    let bytes = document();
    let blocks = read_document(&bytes);
    let block = blocks
        .iter()
        .find(|block| block.text == PARAGRAPH)
        .expect("the document's paragraph");
    let done = run(
        "docx.project",
        json!({"source": 0, "limits": docx_limits(),
            "changes": [{"set_text": {"block": block.id, "text": "PARAGRAPH-AS-CHANGED"}}],
            "revision": {"author": "Editor", "date": REVISION_DATE, "group": "contract-projection"}
        }),
        &[&bytes],
    );
    match &done.reply {
        Reply::Written => {}
        reply => panic!("expected Written: {reply:?}"),
    }
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    assert!(
        read_document(changed)
            .iter()
            .any(|block| block.text.contains("PARAGRAPH-AS-CHANGED"))
    );
    assert_tracked_insertion(changed, "PARAGRAPH-AS-CHANGED");
}

// FIX [DOCX-READER-REFUSES-A-DOCUMENT-WITH-NO-RELATIONSHIPS-PART]: the reader
// and the writer take a main part with no relationships part, as the linker
// already did.
#[test]
fn docx_read_takes_a_main_part_with_no_relationships_part() {
    let bytes = document_with_no_relationships_part();
    let blocks = read_document(&bytes);
    let read: Vec<_> = blocks
        .iter()
        .map(|block| (block.kind, block.text.as_str()))
        .collect();
    assert_eq!(
        read,
        [
            (DocxBlockKind::Paragraph, "First "),
            (DocxBlockKind::Paragraph, "second."),
            (DocxBlockKind::Paragraph, "Untouched third."),
        ]
    );
    let done = run(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits()}),
        &[&bytes],
    );
    match &done.reply {
        Reply::Checked => {}
        reply => panic!("expected Checked: {reply:?}"),
    }
}

#[test]
fn docx_revise_writes_the_relationships_part_its_input_lacked() {
    let bytes = document_with_no_relationships_part();
    let done = revise_second_paragraph(&bytes);
    match &done.reply {
        Reply::DocxRevised { transaction, .. } => {
            assert_eq!(transaction["revision"]["date"], REVISION_DATE);
        }
        reply => panic!("expected DocxRevised: {reply:?}"),
    }
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    let reread = read_document(changed);
    assert!(
        reread
            .iter()
            .any(|block| block.text.contains("SECOND-AS-REVISED"))
    );
    assert!(reread.iter().any(|block| block.text == "Untouched third."));
    assert_tracked_insertion(changed, "SECOND-AS-REVISED");
    // The revision relates the main part to parts the writer made. Each
    // relationship it wrote names a part the package holds.
    let relationships = xml_part(changed, MAIN_PART_RELATIONSHIPS);
    let tree = roxmltree::Document::parse(&relationships).expect("relationships XML");
    let targets: Vec<String> = tree
        .descendants()
        .filter(|node| {
            node.has_tag_name((PACKAGE_RELATIONSHIPS, "Relationship"))
                && node.attribute("TargetMode") != Some("External")
        })
        .map(|node| {
            main_part_target(
                "word",
                node.attribute("Target").expect("a relationship's Target"),
            )
        })
        .collect();
    assert!(
        !targets.is_empty(),
        "the revision wrote no relationship: {relationships}"
    );
    for target in &targets {
        assert!(
            has_part(changed, target),
            "no part {target}: {relationships}"
        );
    }
}

/// A package may type its relationships parts one by one, with no `rels`
/// Default. The relationships part the revision creates is then typed too.
#[test]
fn docx_revise_types_the_relationships_part_it_creates() {
    let base = document_with_no_relationships_part();
    let content_types = xml_part(&base, "[Content_Types].xml");
    let default = format!(r#"<Default Extension="rels" ContentType="{RELATIONSHIPS_TYPE}"/>"#);
    assert!(
        content_types.contains(&default),
        "FIXTURE: the base types its relationships parts by the Default: {content_types}"
    );
    let one_by_one = content_types.replace(
        &default,
        &format!(r#"<Override PartName="/_rels/.rels" ContentType="{RELATIONSHIPS_TYPE}"/>"#),
    );
    let bytes = with_part(&base, "[Content_Types].xml", one_by_one.as_bytes());
    assert_eq!(
        content_type_of(&bytes, MAIN_PART_RELATIONSHIPS),
        None,
        "FIXTURE: the input types no relationships part of the main part"
    );
    let done = revise_second_paragraph(&bytes);
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    assert!(has_part(changed, MAIN_PART_RELATIONSHIPS));
    assert_eq!(
        content_type_of(changed, MAIN_PART_RELATIONSHIPS).as_deref(),
        Some(RELATIONSHIPS_TYPE)
    );
    assert_eq!(
        content_type_of(changed, "_rels/.rels").as_deref(),
        Some(RELATIONSHIPS_TYPE)
    );
}

/// A main part that references a relationship needs its relationships part.
/// Without the part the reference dangles, and a relationship the writer adds
/// later could take its id. The package is refused at the parse that
/// `docx.read`, `docx.revise` and `docx.project` share.
#[test]
fn docx_read_refuses_a_reference_with_no_relationships_part() {
    let base = document_with_no_relationships_part();
    let document = xml_part(&base, "word/document.xml");
    let referencing = document
        .replace(
            r#"xmlns:u="urn:unfamiliar""#,
            r#"xmlns:u="urn:unfamiliar" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships""#,
        )
        .replace("<w:sectPr/>", r#"<w:altChunk r:id="rId1"/><w:sectPr/>"#);
    assert!(
        referencing.contains("xmlns:r=") && referencing.contains(r#"<w:altChunk r:id="rId1"/>"#),
        "FIXTURE: the main part references rId1: {referencing}"
    );
    let bytes = with_part(&base, "word/document.xml", referencing.as_bytes());
    let text = call_text("docx.read", json!({"document": 0, "limits": docx_limits()}));
    assert_error(
        contract::execute_json(text.as_bytes(), &[&bytes], Ports::default()),
        ErrorCode::InvalidDocument,
    );
    let refusal = match oneiron_docedit::Document::parse(&bytes) {
        Ok(_) => panic!("a main part with a dangling reference parsed"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        refusal.contains(MAIN_PART_RELATIONSHIPS) && refusal.contains("rId1"),
        "the refusal names neither the absent part nor the reference: {refusal}"
    );
}

/// The relationships namespace a `r:id` reference lives in.
const OFFICE_RELATIONSHIPS: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const HYPERLINK_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink";
const PEOPLE_REL: &str = "http://schemas.microsoft.com/office/2011/relationships/people";

/// A document whose main part holds `<w:altChunk {reference_attribute_text}/>` before
/// `sectPr`, beside a present but empty relationships part.
fn document_with_a_dangling_main_reference(reference_attribute_text: &str) -> Vec<u8> {
    let base = document_with_no_relationships_part();
    let document = xml_part(&base, "word/document.xml");
    let reference = format!("<w:altChunk {reference_attribute_text}/>");
    let referencing = document
        .replace(
            r#"xmlns:u="urn:unfamiliar""#,
            r#"xmlns:u="urn:unfamiliar" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships""#,
        )
        .replace("<w:sectPr/>", &format!("{reference}<w:sectPr/>"));
    let bytes = with_part(&base, "word/document.xml", referencing.as_bytes());
    let empty = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{PACKAGE_RELATIONSHIPS}"/>"#
    );
    let bytes = rewrite_part(&bytes, None, MAIN_PART_RELATIONSHIPS, empty.as_bytes());
    assert!(has_part(&bytes, MAIN_PART_RELATIONSHIPS));
    bytes
}

/// A document whose main part links its third paragraph through `rId1` to an external
/// hyperlink, and, when given, also holds an `altChunk` with the dangling id before
/// `sectPr`.
fn document_with_hyperlink(dangling_alt_chunk_id: Option<&str>) -> Vec<u8> {
    let base = document_with_no_relationships_part();
    let document = xml_part(&base, "word/document.xml");
    let with_namespace = document.replace(
        r#"xmlns:u="urn:unfamiliar""#,
        r#"xmlns:u="urn:unfamiliar" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships""#,
    );
    let linked = with_namespace.replace(
        "<w:p><w:r><w:t>Untouched third.</w:t></w:r></w:p>",
        r#"<w:p><w:hyperlink r:id="rId1"><w:r><w:t>Untouched third.</w:t></w:r></w:hyperlink></w:p>"#,
    );
    let referencing = match dangling_alt_chunk_id {
        Some(id) => linked.replace(
            "<w:sectPr/>",
            &format!(r#"<w:altChunk r:id="{id}"/><w:sectPr/>"#),
        ),
        None => linked,
    };
    let bytes = with_part(&base, "word/document.xml", referencing.as_bytes());
    let relationships = format!(
        r#"<Relationships xmlns="{PACKAGE_RELATIONSHIPS}"><Relationship Id="rId1" Type="{HYPERLINK_REL}" Target="https://example.invalid/" TargetMode="External"/></Relationships>"#
    );
    let bytes = rewrite_part(
        &bytes,
        None,
        MAIN_PART_RELATIONSHIPS,
        relationships.as_bytes(),
    );
    assert!(has_part(&bytes, MAIN_PART_RELATIONSHIPS));
    bytes
}

/// The relationships-namespace `id` of each `tag` in the main part, in document order.
fn main_part_relationship_ids(bytes: &[u8], tag: &str) -> Vec<String> {
    let xml = xml_part(bytes, "word/document.xml");
    let tree = roxmltree::Document::parse(&xml).expect("document XML");
    tree.descendants()
        .filter(|node| node.has_tag_name((WORDPROCESSING_ML, tag)))
        .map(|node| {
            node.attribute((OFFICE_RELATIONSHIPS, "id"))
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// The `(Id, Type, Target, TargetMode)` of each `Relationship` in the main part's set.
fn main_relationships(bytes: &[u8]) -> Vec<(String, String, String, Option<String>)> {
    let xml = xml_part(bytes, MAIN_PART_RELATIONSHIPS);
    let tree = roxmltree::Document::parse(&xml).expect("relationships XML");
    tree.descendants()
        .filter(|node| node.has_tag_name((PACKAGE_RELATIONSHIPS, "Relationship")))
        .map(|node| {
            (
                node.attribute("Id").unwrap_or_default().to_owned(),
                node.attribute("Type").unwrap_or_default().to_owned(),
                node.attribute("Target").unwrap_or_default().to_owned(),
                node.attribute("TargetMode").map(str::to_owned),
            )
        })
        .collect()
}

/// `docx.revise` of "second." to "SECOND-AS-REVISED" as a `Result`, for an expected refusal.
fn try_revise_second_paragraph(bytes: &[u8]) -> Result<Done, ContractError> {
    let parsed = oneiron_docedit::Document::parse(bytes).expect("parse base document");
    let view = parsed.read();
    let block = view
        .blocks
        .iter()
        .find(|block| block.text == "second.")
        .expect("the paragraph to revise");
    let text = call_text(
        "docx.revise",
        json!({
            "document": 0, "limits": docx_limits(),
            "transaction": {"ops": [{"op": "replace", "target": block.id, "guard": block.guard,
                "content": {"type": "paragraph", "content": [{"type": "text", "text": "SECOND-AS-REVISED"}]}}],
                "revision": {"author": "Editor", "date": REVISION_DATE}}
        }),
    );
    contract::execute_json(text.as_bytes(), &[bytes], Ports::default())
}

/// The detail of an expected refusal, after `assert_error` holds the code and length.
fn refusal_detail(result: Result<Done, ContractError>, code: ErrorCode) -> String {
    let detail = match &result {
        Ok(done) => panic!("the call succeeded: {done:?}"),
        Err(error) => error.detail.clone(),
    };
    assert_error(result, code);
    detail
}

/// A relationship the writer adds never takes an id the source main part references
/// without a binding: the revision is refused exactly as for an id the writer would
/// never mint.
#[test]
fn docx_revise_does_not_bind_a_dangling_main_reference() {
    let mut revise_details = Vec::new();
    for id in ["rId9", "rId1", "rId2"] {
        let bytes = document_with_a_dangling_main_reference(&format!(r#"r:id="{id}""#));
        assert_eq!(
            main_part_relationship_ids(&bytes, "altChunk"),
            [id],
            "FIXTURE: the main part holds one altChunk referencing {id}"
        );
        assert!(
            main_relationships(&bytes).is_empty(),
            "FIXTURE: the relationships part holds no Relationship"
        );

        let blocks = read_document(&bytes);
        assert_eq!(
            blocks
                .iter()
                .map(|block| (block.id.as_str(), block.kind, block.text.as_str()))
                .collect::<Vec<_>>(),
            [
                ("p_1", DocxBlockKind::Paragraph, "First "),
                ("p_2", DocxBlockKind::Paragraph, "second."),
                ("p_3", DocxBlockKind::Paragraph, "Untouched third."),
                ("opaque_1", DocxBlockKind::Opaque, ""),
            ],
            "docx.read of the {id} input"
        );
        assert!(
            blocks[0].locked.is_none() && blocks[1].locked.is_none() && blocks[2].locked.is_none(),
            "docx.read of the {id} input locks no paragraph"
        );
        assert_eq!(
            blocks[3].locked,
            Some(oneiron_docedit::docx_body::DocxLock::Opaque),
            "docx.read of the {id} input locks the altChunk opaque"
        );

        let text = call_text(
            "docx.validate",
            json!({"document": 0, "limits": docx_limits()}),
        );
        let detail = refusal_detail(
            contract::execute_json(text.as_bytes(), &[&bytes], Ports::default()),
            ErrorCode::Refused,
        );
        assert!(
            detail.contains("I-REL-001")
                && detail.contains(id)
                && detail.contains(MAIN_PART_RELATIONSHIPS),
            "docx.validate of the {id} input names I-REL-001, the id and the part: {detail}"
        );

        let detail = refusal_detail(
            try_revise_second_paragraph(&bytes),
            ErrorCode::InvalidDocument,
        );
        let expected = format!(
            "output main document references relationship \"{id}\", but neither source package supplies that binding"
        );
        assert!(
            detail.contains(&expected),
            "docx.revise of the {id} input refuses the dangling reference: {detail}"
        );
        revise_details.push(detail);
    }
    let normalized: Vec<_> = ["rId9", "rId1", "rId2"]
        .into_iter()
        .zip(revise_details.iter())
        .map(|(id, detail)| detail.replace(id, "rIdN"))
        .collect();
    assert_eq!(
        normalized[0], normalized[1],
        "the rId9 and rId1 revise refusals match once the id is replaced"
    );
    assert_eq!(
        normalized[1], normalized[2],
        "the rId1 and rId2 revise refusals match once the id is replaced"
    );
}

/// The reservation reads the decoded attribute value, not the lexical spelling:
/// an entity-encoded `rId1` still refuses the projection.
#[test]
fn docx_project_does_not_bind_a_dangling_entity_encoded_reference() {
    let bytes = document_with_a_dangling_main_reference(r#"r:id="rId&#49;""#);
    assert_eq!(
        main_part_relationship_ids(&bytes, "altChunk"),
        ["rId1"],
        "FIXTURE: the entity-encoded value reads rId1"
    );
    assert!(
        main_relationships(&bytes).is_empty(),
        "FIXTURE: the relationships part holds no Relationship"
    );

    let blocks = read_document(&bytes);
    let block = blocks
        .iter()
        .find(|block| block.text == "second.")
        .expect("p_2");
    let text = call_text(
        "docx.project",
        json!({"source": 0, "limits": docx_limits(),
            "changes": [{"set_text": {"block": block.id, "text": "SECOND-AS-PROJECTED"}}],
            "revision": {"author": "Editor", "date": REVISION_DATE, "group": "contract-projection"}
        }),
    );
    let detail = refusal_detail(
        contract::execute_json(text.as_bytes(), &[&bytes], Ports::default()),
        ErrorCode::InvalidDocument,
    );
    assert!(
        detail.contains(
            "output main document references relationship \"rId1\", but neither source package supplies that binding"
        ),
        "docx.project of the entity-encoded input refuses the dangling reference: {detail}"
    );
}

/// A dangling reference beside a held one still refuses: the writer must not hand
/// the dangling id to a new part.
#[test]
fn docx_revise_does_not_bind_a_dangling_reference_beside_a_held_one() {
    let bytes = document_with_hyperlink(Some("rId2"));
    assert_eq!(
        main_part_relationship_ids(&bytes, "hyperlink"),
        ["rId1"],
        "FIXTURE: the hyperlink references rId1"
    );
    assert_eq!(
        main_part_relationship_ids(&bytes, "altChunk"),
        ["rId2"],
        "FIXTURE: the altChunk references rId2"
    );
    assert_eq!(
        main_relationships(&bytes),
        [(
            "rId1".to_owned(),
            HYPERLINK_REL.to_owned(),
            "https://example.invalid/".to_owned(),
            Some("External".to_owned()),
        )],
        "FIXTURE: the relationships part holds the hyperlink"
    );

    let detail = refusal_detail(
        try_revise_second_paragraph(&bytes),
        ErrorCode::InvalidDocument,
    );
    assert!(
        detail.contains(
            "output main document references relationship \"rId2\", but neither source package supplies that binding"
        ),
        "docx.revise beside a held hyperlink refuses rId2: {detail}"
    );
}

/// The control: when every reference resolves, the writer keeps today's ids.
#[test]
fn docx_revise_keeps_todays_ids_when_every_reference_resolves() {
    let bytes = document_with_hyperlink(None);
    assert_eq!(
        main_part_relationship_ids(&bytes, "hyperlink"),
        ["rId1"],
        "FIXTURE: the hyperlink references rId1"
    );
    assert!(
        main_part_relationship_ids(&bytes, "altChunk").is_empty(),
        "FIXTURE: the main part holds no altChunk"
    );
    let done = run(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits()}),
        &[&bytes],
    );
    match &done.reply {
        Reply::Checked => {}
        reply => panic!("expected Checked: {reply:?}"),
    }

    let done = revise_second_paragraph(&bytes);
    match &done.reply {
        Reply::DocxRevised { transaction, .. } => {
            assert_eq!(transaction["revision"]["date"], REVISION_DATE);
        }
        reply => panic!("expected DocxRevised: {reply:?}"),
    }
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    let rels = main_relationships(changed);
    assert_eq!(
        rels.len(),
        3,
        "the revision keeps the hyperlink and adds people and revision identities"
    );
    assert_eq!(
        rels[0],
        (
            "rId1".to_owned(),
            HYPERLINK_REL.to_owned(),
            "https://example.invalid/".to_owned(),
            Some("External".to_owned()),
        )
    );
    assert_eq!(rels[1].0, "rId2");
    assert_eq!(rels[1].1, PEOPLE_REL);
    assert_ne!(rels[1].3.as_deref(), Some("External"));
    let people = main_part_target("word", &rels[1].2);
    assert_eq!(people, "word/people.xml");
    assert!(has_part(changed, &people));
    assert_eq!(rels[2].0, "rId3");
    assert_eq!(rels[2].1, REVISION_IDS_REL);
    assert_ne!(rels[2].3.as_deref(), Some("External"));
    let revision = main_part_target("word", &rels[2].2);
    assert_eq!(revision, "word/stemmaRevisionIds.xml");
    assert!(has_part(changed, &revision));

    assert_eq!(
        main_part_relationship_ids(changed, "hyperlink"),
        ["rId1"],
        "the output hyperlink still references rId1"
    );
    assert!(
        main_part_relationship_ids(changed, "altChunk").is_empty(),
        "the output holds no altChunk"
    );
    let done = run(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits()}),
        &[changed],
    );
    match &done.reply {
        Reply::Checked => {}
        reply => panic!("expected Checked: {reply:?}"),
    }
}

/// A revision owns its identity part through its relationship, not its file name.
/// Two writes keep a foreign part at the conventional name, and reopening reads the related part.
#[test]
fn docx_revise_keeps_another_producers_part_at_the_revision_ids_name() {
    let base = document_with_no_relationships_part();
    let foreign_part = "word/stemmaRevisionIds.xml";
    let foreign_type = "urn:example:metadata-part";
    let payload = b"<payload/>";
    let root_rels = xml_part(&base, "_rels/.rels").replace(
        "</Relationships>",
        &format!(
            r#"<Relationship Id="rId2" Type="{foreign_type}" Target="{foreign_part}"/></Relationships>"#
        ),
    );
    let bytes = with_part(&base, "_rels/.rels", root_rels.as_bytes());
    let bytes = rewrite_part(&bytes, None, foreign_part, payload);
    assert_eq!(
        content_type_of(&bytes, foreign_part).as_deref(),
        Some("application/xml")
    );
    let done = revise_second_paragraph(&bytes);
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    assert_eq!(zip_part(changed, foreign_part).as_slice(), payload);
    let rel_xml = xml_part(changed, "_rels/.rels");
    let root = roxmltree::Document::parse(&rel_xml).expect("root relationships XML");
    let foreign_link = root
        .descendants()
        .find(|node| {
            node.has_tag_name((PACKAGE_RELATIONSHIPS, "Relationship"))
                && node.attribute("Type") == Some(foreign_type)
        })
        .expect("the foreign root relationship is kept");
    assert_eq!(foreign_link.attribute("Target"), Some(foreign_part));

    let rel_xml = xml_part(changed, MAIN_PART_RELATIONSHIPS);
    let main = roxmltree::Document::parse(&rel_xml).expect("main part relationships XML");
    let revision_link = main
        .descendants()
        .find(|node| {
            node.has_tag_name((PACKAGE_RELATIONSHIPS, "Relationship"))
                && node.attribute("Type") == Some(REVISION_IDS_REL)
                && node.attribute("TargetMode") != Some("External")
        })
        .expect("the writer relates its own revision identities");
    let sidecar = main_part_target(
        "word",
        revision_link
            .attribute("Target")
            .expect("revision identities target"),
    );
    assert_eq!(sidecar, "word/stemmaRevisionIds2.xml");
    assert_eq!(
        content_type_of(changed, &sidecar).as_deref(),
        Some("application/vnd.stemma.revisionids+xml")
    );
    assert!(
        read_document(changed)
            .iter()
            .any(|block| block.text.contains("SECOND-AS-REVISED"))
    );

    // Record a distinguishable identity without changing the carrier walk; merely
    // reopening the text could succeed with derived identities and miss a bad binding.
    let revisions = oneiron_docedit::Document::parse(changed)
        .expect("reopen revised document")
        .revisions();
    let probe_id = (1..)
        .find(|id| revisions.iter().all(|rev| rev.revision_id != *id))
        .expect("an unused revision identity");
    let sidecar_xml = xml_part(changed, &sidecar);
    let persisted = roxmltree::Document::parse(&sidecar_xml).expect("revision identities XML");
    let recorded_id = persisted
        .root_element()
        .children()
        .filter_map(|node| node.attribute("identity"))
        .find(|id| *id != "0")
        .expect("a recorded nonzero body revision identity");
    let probe_xml = sidecar_xml.replace(
        &format!(r#"identity="{recorded_id}""#),
        &format!(r#"identity="{probe_id}""#),
    );
    let probe = with_part(changed, &sidecar, probe_xml.as_bytes());
    let reopened = oneiron_docedit::Document::parse(&probe).expect("reopen with recorded identity");
    assert!(
        reopened
            .revisions()
            .iter()
            .any(|rev| rev.revision_id == probe_id)
    );

    let second = revise_paragraph(
        changed,
        "Untouched third.",
        "THIRD-AS-REVISED",
        "Second Editor",
    );
    let changed_again = output(&second, "document", contract::DOCX_MEDIA_TYPE);
    assert_eq!(zip_part(changed_again, foreign_part).as_slice(), payload);
    assert!(!has_part(changed_again, "word/stemmaRevisionIds3.xml"));
    assert!(
        read_document(changed_again)
            .iter()
            .any(|block| block.text.contains("THIRD-AS-REVISED"))
    );
}

/// A main part outside `word/` can gain valid relationships to generated sidecars.
#[test]
fn docx_revise_takes_a_main_part_outside_word_with_no_relationships_part() {
    let base = document_with_no_relationships_part();
    let old_main = "word/document.xml";
    let main = "body/document.xml";
    let root_rels = xml_part(&base, "_rels/.rels").replace(old_main, main);
    let types = xml_part(&base, "[Content_Types].xml").replace(old_main, main);
    let document = zip_part(&base, old_main);
    let bytes = rewrite_part(&base, Some(old_main), main, &document);
    let bytes = with_part(&bytes, "_rels/.rels", root_rels.as_bytes());
    let bytes = with_part(&bytes, "[Content_Types].xml", types.as_bytes());
    assert!(!has_part(&bytes, "body/_rels/document.xml.rels"));
    let done = revise_second_paragraph(&bytes);
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    let relationships = xml_part(changed, "body/_rels/document.xml.rels");
    let tree = roxmltree::Document::parse(&relationships).expect("main part relationships XML");
    let targets: Vec<_> = tree
        .descendants()
        .filter(|node| {
            node.has_tag_name((PACKAGE_RELATIONSHIPS, "Relationship"))
                && node.attribute("TargetMode") != Some("External")
        })
        .map(|node| {
            (
                node.attribute("Type").expect("relationship type"),
                node.attribute("Target").expect("relationship target"),
            )
        })
        .collect();
    for &(_, target) in &targets {
        let part = main_part_target("body", target);
        assert!(has_part(changed, &part), "missing related part {part}");
    }
    for (rel_type, target) in [
        (
            "http://schemas.microsoft.com/office/2011/relationships/people",
            "/word/people.xml",
        ),
        (REVISION_IDS_REL, "/word/stemmaRevisionIds.xml"),
    ] {
        assert_eq!(
            targets
                .iter()
                .find(|(held, _)| *held == rel_type)
                .map(|(_, held)| *held),
            Some(target)
        );
    }
}

/// A generated relationships part needs an Override if the `rels` Default has the wrong type.
#[test]
fn docx_revise_types_the_relationships_part_it_creates_under_another_default() {
    let base = document_with_no_relationships_part();
    let types = xml_part(&base, "[Content_Types].xml").replace(
        &format!(r#"<Default Extension="rels" ContentType="{RELATIONSHIPS_TYPE}"/>"#),
        &format!(r#"<Default Extension="rels" ContentType="application/xml"/><Override PartName="/_rels/.rels" ContentType="{RELATIONSHIPS_TYPE}"/>"#),
    );
    let bytes = with_part(&base, "[Content_Types].xml", types.as_bytes());
    assert_eq!(
        content_type_of(&bytes, "_rels/.rels").as_deref(),
        Some(RELATIONSHIPS_TYPE)
    );
    assert_eq!(
        content_type_of(&bytes, MAIN_PART_RELATIONSHIPS).as_deref(),
        Some("application/xml")
    );
    let done = revise_second_paragraph(&bytes);
    let changed = output(&done, "document", contract::DOCX_MEDIA_TYPE);
    assert_eq!(
        content_type_of(changed, MAIN_PART_RELATIONSHIPS).as_deref(),
        Some(RELATIONSHIPS_TYPE)
    );
}

/// SmartArt's `r:dm`, `r:lo`, `r:qs`, and `r:cs` also need a main relationships part.
#[test]
fn docx_read_refuses_a_diagram_reference_with_no_relationships_part() {
    let base = document_with_no_relationships_part();
    let document = xml_part(&base, "word/document.xml");
    let referencing = document.replace("<w:sectPr/>", concat!(
        r#"<w:sdt><w:sdtPr/><w:sdtContent><w:p><w:r><w:drawing>"#,
        r#"<wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">"#,
        r#"<wp:extent cx="914400" cy="914400"/><wp:docPr id="1" name="Diagram"/>"#,
        r#"<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">"#,
        r#"<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram">"#,
        r#"<dgm:relIds xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" "#,
        r#"xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" "#,
        r#"r:dm="rId1" r:lo="rId2" r:qs="rId3" r:cs="rId4"/>"#,
        r#"</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></w:sdtContent></w:sdt><w:sectPr/>"#,
    ));
    assert!(referencing.contains(r#"r:dm="rId1""#));
    let bytes = with_part(&base, "word/document.xml", referencing.as_bytes());
    let text = call_text("docx.read", json!({"document": 0, "limits": docx_limits()}));
    let result = contract::execute_json(text.as_bytes(), &[&bytes], Ports::default());
    let detail = &result
        .as_ref()
        .expect_err("the diagram reference dangles")
        .detail;
    assert!(
        ["rId1", "rId2", "rId3", "rId4"]
            .iter()
            .any(|id| detail.contains(&format!(
                "missing {MAIN_PART_RELATIONSHIPS}: the main part references relationship {id:?}"
            ))),
        "unexpected refusal: {detail}"
    );
    assert_error(result, ErrorCode::InvalidDocument);
}

/// A foreign namespace bound to `r` does not make its ignorable `r:id` a relationship reference.
#[test]
fn docx_read_takes_an_attribute_of_another_namespace_under_the_r_prefix() {
    let base = document_with_no_relationships_part();
    let document = xml_part(&base, "word/document.xml");
    let labeled = document
        .replace(
            r#"mc:Ignorable="u""#,
            r#"xmlns:r="urn:example:metadata" mc:Ignorable="u r""#,
        )
        .replacen("<w:p>", r#"<w:p r:id="label">"#, 1);
    assert!(labeled.contains(r#"xmlns:r="urn:example:metadata" mc:Ignorable="u r""#));
    assert!(labeled.contains(r#"<w:p r:id="label">"#));
    let bytes = with_part(&base, "word/document.xml", labeled.as_bytes());
    let blocks = read_document(&bytes);
    let read: Vec<_> = blocks
        .iter()
        .map(|block| (block.kind, block.text.as_str()))
        .collect();
    assert_eq!(
        read,
        [
            (DocxBlockKind::Paragraph, "First "),
            (DocxBlockKind::Paragraph, "second."),
            (DocxBlockKind::Paragraph, "Untouched third."),
        ]
    );
}

/// With a main relationships part present, an attribute of another namespace
/// under the `r` prefix is no relationship reference to the linker either.
#[test]
fn docx_validate_takes_an_attribute_of_another_namespace_under_the_r_prefix() {
    let base = document_with_no_relationships_part();
    let document = xml_part(&base, "word/document.xml");
    let labeled = document
        .replace(
            r#"mc:Ignorable="u""#,
            r#"xmlns:r="urn:example:metadata" mc:Ignorable="u r""#,
        )
        .replacen("<w:p>", r#"<w:p r:id="label">"#, 1);
    assert!(labeled.contains(r#"<w:p r:id="label">"#));
    let bytes = with_part(&base, "word/document.xml", labeled.as_bytes());
    let relationships = format!(r#"<Relationships xmlns="{PACKAGE_RELATIONSHIPS}"/>"#);
    let bytes = rewrite_part(
        &bytes,
        None,
        MAIN_PART_RELATIONSHIPS,
        relationships.as_bytes(),
    );
    assert!(has_part(&bytes, MAIN_PART_RELATIONSHIPS));
    let done = run(
        "docx.validate",
        json!({"document": 0, "limits": docx_limits()}),
        &[&bytes],
    );
    match &done.reply {
        Reply::Checked => {}
        reply => panic!("expected Checked: {reply:?}"),
    }
}

#[test]
fn xlsx_read() {
    let book = read_workbook(&workbook());
    assert_workbook_cell(&book, 6, XlsxValue::Number(5.0), Some("ABS(5)"));
    assert_workbook_cell(&book, 26, XlsxValue::Number(3333.0), Some("1111+2222"));
}

#[test]
fn xlsx_project() {
    let bytes = workbook();
    let done = run(
        "xlsx.project",
        json!({"source": 0, "limits": package_limits(),
            "changes": [{"cell": {"sheet": "Sheet1", "col": 1, "row": 1,
                "value": {"text": "Projected cell"}, "formula": null, "style": null}}]
        }),
        &[&bytes],
    );
    match &done.reply {
        Reply::XlsxProjected { .. } => {}
        reply => panic!("expected XlsxProjected: {reply:?}"),
    }
    let changed = output(&done, "workbook", contract::XLSX_MEDIA_TYPE);
    let book = read_workbook(changed);
    assert_workbook_cell(&book, 1, XlsxValue::Text("Projected cell".to_owned()), None);
    assert_workbook_cell(&book, 6, XlsxValue::Number(5.0), Some("ABS(5)"));
}

#[test]
fn xlsx_mark_full_calc() {
    let bytes = workbook();
    let done = run(
        "xlsx.mark_full_calc",
        json!({"workbook": 0, "limits": package_limits()}),
        &[&bytes],
    );
    match &done.reply {
        Reply::Written => {}
        reply => panic!("expected Written: {reply:?}"),
    }
    let changed = output(&done, "workbook", contract::XLSX_MEDIA_TYPE);
    assert_workbook_cell(
        &read_workbook(changed),
        6,
        XlsxValue::Number(5.0),
        Some("ABS(5)"),
    );
    let xml = xml_part(changed, "xl/workbook.xml");
    let tree = roxmltree::Document::parse(&xml).expect("workbook XML");
    let settings: Vec<_> = tree
        .descendants()
        .filter(|node| node.has_tag_name((SPREADSHEET_ML, "calcPr")))
        .collect();
    let [calc] = settings.as_slice() else {
        panic!("expected one calcPr: {settings:?}");
    };
    assert_eq!(calc.attribute("fullCalcOnLoad"), Some("1"));
}

#[derive(Debug, PartialEq, Eq)]
struct RecalcRequest {
    workbook: Vec<u8>,
    /// Archive, part and expanded bytes.
    limits: (usize, usize, usize),
    clock: RecalcClockArgs,
    location: Option<contract::DocumentLocationArgs>,
}

struct FixedRecalc {
    requests: RefCell<Vec<RecalcRequest>>,
    answer: Result<Vec<u8>, ContractError>,
}

impl RecalcPort for FixedRecalc {
    fn recalculate(
        &self,
        workbook: &[u8],
        limits: Limits,
        clock: &RecalcClockArgs,
        location: Option<&contract::DocumentLocationArgs>,
    ) -> Result<Recalculated, ContractError> {
        self.requests.borrow_mut().push(RecalcRequest {
            workbook: workbook.to_vec(),
            limits: (
                limits.archive_bytes,
                limits.part_bytes,
                limits.expanded_bytes,
            ),
            clock: *clock,
            location: location.cloned(),
        });
        Ok(Recalculated {
            bytes: self.answer.clone()?,
            engine: "fixed-recalc".to_owned(),
            version: "1.2.3".to_owned(),
            formula_count: 7,
        })
    }
}

fn recalc_args() -> Value {
    json!({"workbook": 0, "limits": package_limits(),
        "clock": {"now_ms": 1_700_000_000_000_i64, "utc_offset_minutes": 60, "seed": 23},
        "location": {"directory": "/Reports/", "file_name": "Fixture.xlsx"}})
}

#[test]
fn xlsx_recalc() {
    let bytes = workbook();
    let returned = zip_part(
        &fixture("spreadsheet-compat/excel/cached-workbooks.zip"),
        "case-0001.xlsx",
    );
    let port = FixedRecalc {
        requests: RefCell::new(Vec::new()),
        answer: Ok(returned.clone()),
    };
    let text = call_text("xlsx.recalc", recalc_args());
    let done = contract::execute_json(
        text.as_bytes(),
        &[&bytes],
        Ports {
            recalc: Some(&port),
            ..Ports::default()
        },
    )
    .unwrap_or_else(|error| panic!("xlsx.recalc: {error}"));
    match &done.reply {
        Reply::Recalculated {
            engine,
            version,
            formula_count,
        } => {
            assert_eq!(engine, "fixed-recalc");
            assert_eq!(version, "1.2.3");
            assert_eq!(*formula_count, 7);
        }
        reply => panic!("expected Recalculated: {reply:?}"),
    }
    let changed = output(&done, "workbook", contract::XLSX_MEDIA_TYPE);
    assert_eq!(changed, returned);
    assert_workbook_cell(
        &read_workbook(changed),
        6,
        XlsxValue::Number(5.0),
        Some("ABS(-5)"),
    );
    assert_eq!(
        *port.requests.borrow(),
        vec![RecalcRequest {
            workbook: bytes,
            limits: (33_554_432, 16_777_216, 67_108_864),
            clock: RecalcClockArgs {
                now_ms: 1_700_000_000_000,
                utc_offset_minutes: 60,
                seed: 23
            },
            location: Some(contract::DocumentLocationArgs {
                directory: "/Reports/".to_owned(),
                file_name: "Fixture.xlsx".to_owned(),
            }),
        }]
    );
}

#[test]
fn xlsx_recalc_answers_the_ports_refusal() {
    let bytes = workbook();
    let refusal = ContractError::new(
        ErrorCode::NeedsFallback,
        "the fixed port refuses this workbook",
    );
    let port = FixedRecalc {
        requests: RefCell::new(Vec::new()),
        answer: Err(refusal.clone()),
    };
    let text = call_text("xlsx.recalc", recalc_args());
    let error = contract::execute_json(
        text.as_bytes(),
        &[&bytes],
        Ports {
            recalc: Some(&port),
            ..Ports::default()
        },
    )
    .expect_err("the port refused");
    assert_eq!(error, refusal);
}

#[test]
fn xlsx_recalc_without_port_is_unavailable() {
    let bytes = workbook();
    let text = call_text("xlsx.recalc", recalc_args());
    assert_error(
        contract::execute_json(text.as_bytes(), &[&bytes], Ports::default()),
        ErrorCode::Unavailable,
    );
}

fn office_file(name: &str) -> Vec<u8> {
    file(&format!("../../scripts/office/{name}"))
}

fn read_deck(bytes: &[u8]) -> contract::DeckRead {
    let done = run(
        "deck.read",
        json!({"deck": 0, "limits": package_limits()}),
        &[bytes],
    );
    match done.reply {
        Reply::Deck(deck) => deck,
        reply => panic!("expected Deck: {reply:?}"),
    }
}

fn comment_limits() -> Value {
    json!({"max_archive_bytes": 33_554_432, "max_part_bytes": 16_777_216,
        "max_expanded_bytes": 67_108_864, "max_xml_bytes": 16_777_216})
}

#[test]
fn deck_read() {
    let bytes = office_file("fixtures/clean.pptx");
    let deck = read_deck(&bytes);
    assert_eq!(deck.slides.len(), 1);
    assert_eq!(deck.slides[0].sld_id, 256);
    assert_eq!(deck.slides[0].part, "ppt/slides/slide1.xml");
    assert!(deck.slides[0].shapes.iter().any(|shape| {
        shape.id == Some(2) && shape.paragraphs == ["ONE-2531 clean oracle fixture"]
    }));
    // A transaction's `marks` seed: the largest slide id and shape id there.
    assert_eq!(
        deck.marks,
        json!({"slide": 256, "shapes": {"ppt/slides/slide1.xml": 2}})
    );
}

#[test]
fn deck_transaction() {
    let bytes = office_file("fixtures/clean.pptx");
    let done = run(
        "deck.transaction",
        json!({"deck": 0, "limits": package_limits(),
            "transaction": {"schema": 2, "base": blake3::hash(&bytes).to_hex().to_string(), "seed": "contract-shape",
                "steps": [{"add_shape": {"slide": "ppt/slides/slide1.xml", "preset": "rect", "name": "Contract marker",
                    "offset": [500_000, 600_000], "extent": [300_000, 200_000]}}]}
        }),
        &[&bytes],
    );
    let changed = output(&done, "deck", contract::PPTX_MEDIA_TYPE);
    match &done.reply {
        Reply::DeckTransaction { report } => {
            assert_eq!(report["steps"][0]["verb"], "add_shape");
            assert_eq!(
                report["candidate"],
                blake3::hash(changed).to_hex().to_string()
            );
        }
        reply => panic!("expected DeckTransaction: {reply:?}"),
    }
    let deck = read_deck(changed);
    let marker = deck.slides[0]
        .shapes
        .iter()
        .find(|shape| shape.name.as_deref() == Some("Contract marker"))
        .expect("added shape");
    assert_eq!(marker.top_left, Some((500_000, 600_000)));
    assert_eq!(marker.extent, Some((300_000, 200_000)));
    let xml = xml_part(changed, "ppt/slides/slide1.xml");
    let tree = roxmltree::Document::parse(&xml).expect("slide XML");
    let shape = tree
        .descendants()
        .filter(|node| node.has_tag_name((PRESENTATION_ML, "sp")))
        .find(|shape| {
            shape.descendants().any(|node| {
                node.has_tag_name((PRESENTATION_ML, "cNvPr"))
                    && node.attribute("name") == Some("Contract marker")
            })
        })
        .expect("the added shape's XML");
    assert!(shape.descendants().any(|node| {
        node.has_tag_name((DRAWING_ML, "prstGeom")) && node.attribute("prst") == Some("rect")
    }));
}

#[test]
fn pptx_comments_inspect() {
    let bytes = office_file("fixtures/clean.pptx");
    let done = run(
        "pptx.comments.inspect",
        json!({"deck": 0, "limits": comment_limits()}),
        &[&bytes],
    );
    match &done.reply {
        Reply::PptxCommentsInspected {
            slides,
            signature_parts,
            unknown_anchor_threads,
        } => {
            assert_eq!(slides.len(), 1);
            assert_eq!(slides[0].sld_id, 256);
            assert_eq!(slides[0].part, "ppt/slides/slide1.xml");
            assert_eq!(slides[0].creation_id, None, "an inspection mints no id");
            assert!(slides[0].shapes.iter().any(|shape| shape.shape_id == 2));
            assert!(signature_parts.is_empty());
            assert!(unknown_anchor_threads.is_empty());
        }
        reply => panic!("expected PptxCommentsInspected: {reply:?}"),
    }
    assert!(done.outputs.is_empty());
}

#[test]
fn deck_create() {
    let brief = office_file("deck-create-v1/long-title.json");
    let template = office_file("fixtures/deck-create-template.pptx");
    let done = run(
        "deck.create",
        json!({
            "brief": {"input": 0, "version": "deck-create-v1"}, "template": 1, "fonts": [], "assets": {},
            "names": {"text": "TextBox", "table": "Table", "chart": "Chart", "picture": "Picture", "figure": "Group", "sheet": "Sheet1"},
            "limits": package_limits()
        }),
        &[&brief, &template],
    );
    let created = match &done.reply {
        Reply::DeckCreated(created) => created,
        reply => panic!("expected DeckCreated: {reply:?}"),
    };
    let changed = output(&done, "deck", contract::PPTX_MEDIA_TYPE);
    assert_eq!(created.hash, blake3::hash(changed).to_hex().to_string());
    assert_eq!(created.slides.len(), 1);
    assert_eq!(created.slides[0].page, "main");
    let deck = read_deck(changed);
    assert_eq!(
        deck.slides.len(),
        1,
        "the output deck holds the brief's one page as one slide"
    );
    let paragraphs: Vec<_> = deck.slides[0]
        .shapes
        .iter()
        .flat_map(|shape| &shape.paragraphs)
        .collect();
    // Each block of the brief is one whole paragraph of that slide: a title cut short fails here.
    for block in [
        "Fourth-quarter spending stayed inside every limit",
        "Spending stayed within the approved limit.",
    ] {
        let whole = paragraphs.iter().filter(|text| text.as_str() == block);
        assert_eq!(
            whole.count(),
            1,
            "the deck does not hold the brief's block {block:?} as one whole paragraph: {paragraphs:?}"
        );
    }
}

#[test]
fn pptx_comments() {
    let bytes = office_file("fixtures/clean.pptx");
    let thread_id = "5a0e1c3b-7d2f-4e8a-9b61-0c4d3e2f1a10";
    let args = |seed: u64, slide_creation_ids: Value| {
        json!({"deck": 0, "seed": seed, "limits": comment_limits(),
            "slide_creation_ids": slide_creation_ids,
            "edits": [{"author": {"guid": "5a0e1c3b-7d2f-4e8a-9b61-0c4d3e2f1a11", "name": "Editor"},
                "thread_id": thread_id, "comment_id": thread_id, "at": 1_700_000_000_000_u64,
                "action": {"add": {"target": {"slide": 1}, "text": "Contract comment"}}}]
        })
    };
    let done = run("pptx.comments", args(7, Value::Null), &[&bytes]);
    let (minted, comment_part) = match &done.reply {
        Reply::PptxComments {
            slide_creation_ids,
            touched_parts,
            ..
        } => {
            assert_eq!(slide_creation_ids.len(), 1);
            assert_eq!(slide_creation_ids[0].slide, 1);
            let part = touched_parts
                .iter()
                .find(|name| name.starts_with("ppt/comments/") && name.ends_with(".xml"))
                .expect("written comment part");
            (slide_creation_ids[0].creation_id, part)
        }
        reply => panic!("expected PptxComments: {reply:?}"),
    };
    let changed = output(&done, "deck", contract::PPTX_MEDIA_TYPE);
    let read = run(
        "pptx.comments.inspect",
        json!({"deck": 0, "limits": comment_limits()}),
        &[changed],
    );
    match &read.reply {
        Reply::PptxCommentsInspected {
            slides,
            unknown_anchor_threads,
            ..
        } => {
            assert_eq!(slides[0].creation_id, Some(minted));
            assert!(unknown_anchor_threads.is_empty());
        }
        reply => panic!("expected PptxCommentsInspected: {reply:?}"),
    }
    let xml = xml_part(changed, comment_part);
    let tree = roxmltree::Document::parse(&xml).expect("comment XML");
    assert!(
        tree.descendants()
            .any(|node| node.is_text() && node.text() == Some("Contract comment"))
    );
    // The minted id, replayed under another seed, writes the same bytes again.
    let replayed = run(
        "pptx.comments",
        args(8, json!([{"slide": 1, "creation_id": minted}])),
        &[&bytes],
    );
    assert!(
        replayed.outputs == done.outputs,
        "a replay of the minted slide creation id wrote other bytes"
    );
}

#[test]
fn invalid_json_is_bad_request() {
    assert_error(
        contract::execute_json(b"not JSON", &[], Ports::default()),
        ErrorCode::BadRequest,
    );
}

#[test]
fn missing_numeric_schema_is_bad_request() {
    for value in [
        json!([]),
        json!({}),
        json!({"schema": "5"}),
        json!({"schema": null}),
        json!({"schema": -1}),
        json!({"schema": 5.5}),
    ] {
        assert_error(
            contract::execute_json(value.to_string().as_bytes(), &[], Ports::default()),
            ErrorCode::BadRequest,
        );
    }
}

#[test]
fn other_json_schemas_refuse_before_reading_op() {
    let served = u64::from(CONTRACT_SCHEMA);
    for schema in [served - 1, served + 1, u64::from(u32::MAX) + 1] {
        let text = json!({"schema": schema, "op": "unknown.op", "args": {}}).to_string();
        assert_error(
            contract::execute_json(text.as_bytes(), &[], Ports::default()),
            ErrorCode::UnsupportedSchema,
        );
    }
}

#[test]
fn unknown_op_is_bad_request() {
    let text =
        json!({"schema": CONTRACT_SCHEMA, "op": "unknown.op".repeat(128), "args": {}}).to_string();
    assert_error(
        contract::execute_json(text.as_bytes(), &[], Ports::default()),
        ErrorCode::BadRequest,
    );
}

#[test]
fn a_call_the_op_table_cannot_read_is_bad_request() {
    let bytes = workbook();
    let limits = package_limits();
    for call in [
        json!({"schema": CONTRACT_SCHEMA}),
        json!({"schema": CONTRACT_SCHEMA, "op": null}),
        json!({"schema": CONTRACT_SCHEMA, "op": "contract.describe", "args": "unexpected"}),
        json!({"schema": CONTRACT_SCHEMA, "op": "xlsx.read"}),
        json!({"schema": CONTRACT_SCHEMA, "op": "xlsx.read", "args": null}),
        json!({"schema": CONTRACT_SCHEMA, "op": "xlsx.read", "args": {"limits": limits}}),
        json!({"schema": CONTRACT_SCHEMA, "op": "xlsx.read",
            "args": {"workbook": -1, "limits": limits}}),
        json!({"schema": CONTRACT_SCHEMA, "op": "xlsx.read",
            "args": {"workbook": u64::from(u32::MAX) + 1, "limits": limits}}),
        json!({"schema": CONTRACT_SCHEMA, "op": "xlsx.read",
            "args": {"workbook": 0, "limits": limits, "extra": true}}),
    ] {
        let result =
            contract::execute_json(call.to_string().as_bytes(), &[&bytes], Ports::default());
        assert_error(result, ErrorCode::BadRequest);
    }
}

#[test]
fn missing_input_is_bad_request() {
    let text = call_text(
        "xlsx.read",
        json!({"workbook": 1, "limits": package_limits()}),
    );
    let bytes = workbook();
    assert_error(
        contract::execute_json(text.as_bytes(), &[&bytes], Ports::default()),
        ErrorCode::BadRequest,
    );
}

#[test]
fn non_package_input_is_invalid_document() {
    let text = call_text(
        "xlsx.read",
        json!({"workbook": 0, "limits": package_limits()}),
    );
    assert_error(
        contract::execute_json(text.as_bytes(), &[b"not a package"], Ports::default()),
        ErrorCode::InvalidDocument,
    );
}

#[test]
fn other_typed_schema_is_unsupported() {
    let call = Call {
        schema: CONTRACT_SCHEMA + 1,
        op: contract::Op::Describe,
    };
    assert_error(
        contract::execute(&call, &[], Ports::default()),
        ErrorCode::UnsupportedSchema,
    );
}

/// Compact JSON with object keys sorted by ascending bytes at every depth.
/// String-valued `description` and `summary` members are omitted as prose;
/// properties with those names stay because their values under `properties`
/// are objects, not strings. The rule reads no schema keyword, so it would
/// also omit such a member inside a `default`, `const` or `enum` value; the
/// three pinned values hold none. Arrays keep their order. Scalars use
/// serde_json's own representation.
fn shape_text(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object
                .keys()
                .filter(|key| {
                    !matches!(key.as_str(), "description" | "summary") || !object[*key].is_string()
                })
                .collect();
            keys.sort_unstable();
            let members: Vec<_> = keys
                .into_iter()
                .map(|key| {
                    let quoted = serde_json::to_string(key).expect("serialize object key");
                    format!("{quoted}:{}", shape_text(&object[key]))
                })
                .collect();
            format!("{{{}}}", members.join(","))
        }
        Value::Array(values) => {
            let members: Vec<_> = values.iter().map(shape_text).collect();
            format!("[{}]", members.join(","))
        }
        _ => serde_json::to_string(value).expect("serialize JSON scalar"),
    }
}

#[test]
fn shape_text_orders_nested_keys_and_ignores_only_prose() {
    let first: Value =
        serde_json::from_str(r#"{"z":[{"b":2,"a":1}],"a":true}"#).expect("first JSON");
    let second: Value =
        serde_json::from_str(r#"{"a":true,"z":[{"a":1,"b":2}]}"#).expect("second JSON");
    assert_eq!(shape_text(&first), shape_text(&second));
    assert_eq!(shape_text(&first), r#"{"a":true,"z":[{"a":1,"b":2}]}"#);
    let prose = json!({"description": "ignored", "summary": "ignored", "properties": {
        "summary": {"type": "string"}, "description": {"description": "nested prose", "type": "string"}
    }});
    assert_eq!(
        shape_text(&prose),
        r#"{"properties":{"description":{"type":"string"},"summary":{"type":"string"}}}"#
    );
}

#[test]
fn contract_shape_is_pinned_to_schema() {
    let values = [
        (
            "describe",
            serde_json::to_value(contract::describe()).expect("serialize description"),
        ),
        ("call_schema", contract::call_schema()),
        ("reply_schema", contract::reply_schema()),
    ];
    let measured = values.map(|(name, value)| {
        let text = shape_text(&value);
        (
            name,
            text.len(),
            blake3::hash(text.as_bytes()).to_hex().to_string(),
        )
    });
    let matches = measured
        .iter()
        .zip(PINNED)
        .all(|((name, length, hash), pin)| (*name, *length, hash.as_str()) == pin);
    if matches && CONTRACT_SCHEMA == PINNED_SCHEMA {
        return;
    }
    let reason = if CONTRACT_SCHEMA == PINNED_SCHEMA {
        format!(
            "The contract's shape text differs under schema {CONTRACT_SCHEMA}. If an op's args, its reply or a row of the op table changed, give the contract a new schema number (docs/ops/documents-api-handoff.md) and pin its rows here. If only the schema's spelling changed (a schemars upgrade, a renamed Rust type), pin the new rows under the same number."
        )
    } else {
        format!("CONTRACT_SCHEMA is now {CONTRACT_SCHEMA}; pin its rows and PINNED_SCHEMA here.")
    };
    // The rows as rustfmt lays them out, to paste over `PINNED`.
    let rows = measured.map(|(name, length, hash)| {
        format!("    (\n        {name:?},\n        {length},\n        {hash:?},\n    ),")
    });
    panic!("{reason}\n{}", rows.join("\n"));
}
