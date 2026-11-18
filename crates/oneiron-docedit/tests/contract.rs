// Contract handler runs, envelope refusals and schema-shape pins cover the public
// boundary used by a hosted caller outside this repository. No existing test
// exercises that boundary. FIX [DOCEDIT-CONTRACT-RUN-BY-NO-TEST]
// cargo test --locked -p oneiron-docedit --all-features --test contract

use std::cell::RefCell;
use std::io::{Cursor, Read};
use std::path::Path;

use oneiron_docedit::contract::{
    self, CONTRACT_SCHEMA, Call, ContractError, Done, ErrorCode, MAX_DETAIL_BYTES, Ports,
    RecalcClockArgs, RecalcPort, Recalculated, Reply,
};
use oneiron_docedit::docx_body::DocxBlock;
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

fn docx_limits() -> Value {
    json!({"max_entries": 1024, "max_part_bytes": 16_777_216, "max_total_bytes": 67_108_864})
}

fn package_limits() -> Value {
    json!({"archive_bytes": 33_554_432, "part_bytes": 16_777_216, "expanded_bytes": 67_108_864})
}

fn call_text(name: &str, args: Value) -> String {
    assert!(
        OP_NAMES.contains(&name),
        "add a run for op {name} to OP_NAMES"
    );
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
        error.detail.len() <= MAX_DETAIL_BYTES,
        "detail is too long: {error}"
    );
}

#[test]
fn described_ops_have_runs() {
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
            "add a run for op {} to OP_NAMES",
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
    assert!(blocks.iter().any(|block| block.text == PARAGRAPH));
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
}

#[test]
fn xlsx_read() {
    let bytes = workbook();
    assert_workbook_cell(
        &read_workbook(&bytes),
        6,
        XlsxValue::Number(5.0),
        Some("ABS(5)"),
    );
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
    assert_workbook_cell(
        &read_workbook(changed),
        1,
        XlsxValue::Text("Projected cell".to_owned()),
        None,
    );
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
    let xml = String::from_utf8(zip_part(changed, "xl/workbook.xml")).expect("workbook XML text");
    let tree = roxmltree::Document::parse(&xml).expect("workbook XML");
    let calc = tree
        .descendants()
        .find(|node| {
            node.has_tag_name((
                "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
                "calcPr",
            ))
        })
        .expect("calculation settings");
    assert_eq!(calc.attribute("fullCalcOnLoad"), Some("1"));
}

#[derive(Debug, PartialEq, Eq)]
struct RecalcRequest {
    workbook: Vec<u8>,
    clock: RecalcClockArgs,
}

struct FixedRecalc {
    requests: RefCell<Vec<RecalcRequest>>,
    bytes: Vec<u8>,
}

impl RecalcPort for FixedRecalc {
    fn recalculate(
        &self,
        workbook: &[u8],
        _limits: Limits,
        clock: &RecalcClockArgs,
        _location: Option<&contract::DocumentLocationArgs>,
    ) -> Result<Recalculated, ContractError> {
        self.requests.borrow_mut().push(RecalcRequest {
            workbook: workbook.to_vec(),
            clock: *clock,
        });
        Ok(Recalculated {
            bytes: self.bytes.clone(),
            engine: "fixed-recalc".to_owned(),
            version: "1.2.3".to_owned(),
            formula_count: 7,
        })
    }
}

fn recalc_args() -> Value {
    json!({"workbook": 0, "limits": package_limits(),
        "clock": {"now_ms": 1_700_000_000_000_i64, "utc_offset_minutes": 60, "seed": 23}})
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
        bytes: returned.clone(),
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
            clock: RecalcClockArgs {
                now_ms: 1_700_000_000_000,
                utc_offset_minutes: 60,
                seed: 23
            }
        }]
    );
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
    assert!(
        deck.slides[0]
            .shapes
            .iter()
            .any(|shape| shape.paragraphs == ["ONE-2531 clean oracle fixture"])
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
    match &done.reply {
        Reply::DeckTransaction { report } => assert_eq!(report["steps"][0]["verb"], "add_shape"),
        reply => panic!("expected DeckTransaction: {reply:?}"),
    }
    let changed = output(&done, "deck", contract::PPTX_MEDIA_TYPE);
    let deck = read_deck(changed);
    let marker = deck.slides[0]
        .shapes
        .iter()
        .find(|shape| shape.name.as_deref() == Some("Contract marker"))
        .expect("added shape");
    assert_eq!(marker.top_left, Some((500_000, 600_000)));
    assert_eq!(marker.extent, Some((300_000, 200_000)));
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
            assert!(slides[0].shapes.iter().any(|shape| shape.shape_id == 2));
            assert!(signature_parts.is_empty());
            assert!(unknown_anchor_threads.is_empty());
        }
        reply => panic!("expected PptxCommentsInspected: {reply:?}"),
    }
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
    assert!(
        deck.slides
            .iter()
            .flat_map(|slide| &slide.shapes)
            .flat_map(|shape| &shape.paragraphs)
            .any(|text| text.contains("Fourth-quarter"))
    );
}

#[test]
fn pptx_comments() {
    let bytes = office_file("fixtures/clean.pptx");
    let thread_id = "5a0e1c3b-7d2f-4e8a-9b61-0c4d3e2f1a10";
    let done = run(
        "pptx.comments",
        json!({"deck": 0, "seed": 7, "limits": comment_limits(),
            "edits": [{"author": {"guid": "5a0e1c3b-7d2f-4e8a-9b61-0c4d3e2f1a11", "name": "Editor"},
                "thread_id": thread_id, "comment_id": thread_id, "at": 1_700_000_000_000_u64,
                "action": {"add": {"target": {"slide": 1}, "text": "Contract comment"}}}]
        }),
        &[&bytes],
    );
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
    let xml = String::from_utf8(zip_part(changed, comment_part)).expect("comment XML text");
    let tree = roxmltree::Document::parse(&xml).expect("comment XML");
    assert!(
        tree.descendants()
            .any(|node| node.is_text() && node.text() == Some("Contract comment"))
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
    for value in [json!({}), json!({"schema": "5"}), json!({"schema": null})] {
        assert_error(
            contract::execute_json(value.to_string().as_bytes(), &[], Ports::default()),
            ErrorCode::BadRequest,
        );
    }
}

#[test]
fn other_json_schemas_refuse_before_reading_op() {
    for schema in [CONTRACT_SCHEMA - 1, CONTRACT_SCHEMA + 1] {
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
/// are objects, not strings. Scalars use serde_json's own representation.
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
            "The contract's shape changed under schema {CONTRACT_SCHEMA}; an op's args, reply or table row changed. Give the contract a new schema number (docs/ops/documents-api-handoff.md), then pin the new rows here."
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
