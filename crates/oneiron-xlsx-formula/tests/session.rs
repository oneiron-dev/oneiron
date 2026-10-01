//! Actual XLSX in/out tests through the core's edit round-trip pipeline.
use std::io::{Cursor, Read, Write};

use oneiron::blob_artifact::CalcEngineStamp;
use oneiron::edit_roundtrip::{
    AppliedEdit, CellRef, CellValue, EditOp, EditOutcome, EditPlan, EditProposal, EditSession,
    OfficeDoc, OfficeFormat, RecalcStatus, run_edit_roundtrip,
};
use oneiron::error::{ArtifactError, Error, Result};
use oneiron_docedit::retained_opc::{Limits, Package, XmlLimits};
use oneiron_xlsx_formula::engine::FormualizerEngine;
use oneiron_xlsx_formula::{FormulaError, InProcessSession};
use proptest::prelude::*;

const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const DOC_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const INPUT: &str = "xl/worksheets/input.xml";
const OUTPUT: &str = "xl/worksheets/result.xml";
const UNKNOWN: &[u8] = b"opaque vendor bytes\0\xff";
const NATIVE_STAMP: &str = "oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.2";

fn limits() -> Limits {
    Limits {
        archive_bytes: 64 * 1024 * 1024,
        entries: 1_000,
        part_bytes: 16 * 1024 * 1024,
        expanded_bytes: 64 * 1024 * 1024,
        xml: XmlLimits {
            max_depth: 256,
            max_nodes: 1_000_000,
        },
    }
}

/// Test-only archive writer; the crate under test never writes whole packages.
fn build(parts: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in parts {
        zip.start_file(name.as_str(), zip::write::FileOptions::default())
            .expect("part header");
        zip.write_all(data).expect("part bytes");
    }
    zip.finish().expect("archive").into_inner()
}
fn parts(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("fixture archive");
    (0..archive.len())
        .map(|index| {
            let mut file = archive.by_index(index).expect("entry");
            let mut data = Vec::new();
            file.read_to_end(&mut data).expect("entry bytes");
            (file.name().to_owned(), data)
        })
        .collect()
}
/// Rebuild `bytes` with `name` replaced, or added when absent.
fn with_part(bytes: &[u8], name: &str, data: impl Into<Vec<u8>>) -> Vec<u8> {
    let data = data.into();
    let mut parts = parts(bytes);
    match parts.iter_mut().find(|(existing, _)| existing == name) {
        Some(part) => part.1 = data,
        None => parts.push((name.to_owned(), data)),
    }
    build(&parts)
}
fn part(name: &str, data: impl Into<Vec<u8>>) -> (String, Vec<u8>) {
    (name.into(), data.into())
}
fn sheet(cells: &str) -> String {
    format!(
        r#"<worksheet xmlns="{MAIN}" xmlns:u="urn:unknown"><sheetData><row r="1">{cells}</row></sheetData><extLst><u:keep value="unaltered">unmodelled content</u:keep></extLst></worksheet>"#
    )
}
fn fixture(inputs: &str, formulas: &str, date1904: bool) -> Vec<u8> {
    build(&[
        part("[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>"#.to_vec()),
        // Formula sheet comes first and references the later-created input sheet.
        part("xl/workbook.xml", format!(r#"<workbook xmlns="{MAIN}" xmlns:link="{DOC_REL}"><workbookPr date1904="{}"/><sheets><sheet name="Result" sheetId="7" link:id="out"/><sheet name="Input" sheetId="3" link:id="in"/></sheets></workbook>"#, u8::from(date1904))),
        part("xl/_rels/workbook.xml.rels", format!(r#"<Relationships xmlns="{REL}"><Relationship Id="out" Type="{DOC_REL}/worksheet" Target="worksheets/result.xml"/><Relationship Id="in" Type="{DOC_REL}/worksheet" Target="worksheets/input.xml"/></Relationships>"#)),
        part(INPUT, sheet(inputs)), part(OUTPUT, sheet(formulas)), part("vendor/opaque.bin", UNKNOWN.to_vec()),
    ])
}
fn part_bytes(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    Package::open(bytes, limits())
        .expect("retained XLSX")
        .part(name)
        .expect("readable part")
}
fn part_text(bytes: &[u8], name: &str) -> String {
    String::from_utf8(part_bytes(bytes, name).expect("part")).expect("UTF-8 XML")
}
fn recalc(bytes: &[u8]) -> oneiron_xlsx_formula::Result<oneiron_xlsx_formula::WorkbookRecalc> {
    FormualizerEngine::new().recalculate_xlsx(bytes, limits())
}
fn stamp(proposal: &EditProposal) -> Option<String> {
    proposal
        .calc_engine
        .as_deref()
        .map(|stamp| format!("{}/{}", stamp.engine(), stamp.version()))
}
fn fallback_stamp() -> CalcEngineStamp {
    CalcEngineStamp::new("libreoffice", "fixture-precision").expect("fixture stamp")
}
fn refusal(result: Result<EditOutcome>) -> &'static str {
    match result {
        Err(Error::Artifact(ArtifactError::EditRoundtripFailed(reason))) => reason,
        other => panic!("expected an edit refusal, got {other:?}"),
    }
}

struct FixtureSession {
    edit: Option<(String, String)>,
    fallback: Option<Vec<u8>>,
    expected_fallback_input: Option<Vec<u8>>,
}
impl FixtureSession {
    fn editor() -> Self {
        Self {
            edit: None,
            fallback: None,
            expected_fallback_input: None,
        }
    }
}
impl EditSession for FixtureSession {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        let mut bytes = doc.bytes.clone();
        if let Some((before, after)) = &self.edit {
            let input = part_text(&bytes, INPUT);
            assert!(input.contains(before));
            bytes = with_part(&bytes, INPUT, input.replace(before, after));
        }
        Ok(AppliedEdit {
            bytes,
            applied_ops: plan.ops.clone(),
            warnings: Vec::new(),
        })
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        if let Some(expected) = &self.expected_fallback_input {
            assert_eq!(&doc.bytes, expected);
        }
        self.fallback
            .clone()
            .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "unexpected precision fallback",
            )))
    }
    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        Some(fallback_stamp())
    }
}

fn recalc_plan() -> EditPlan {
    EditPlan {
        ops: Vec::new(),
        request_recalc: Some(true),
    }
}

#[test]
fn edit_session_recalculates_cross_sheet_graph_and_stamps_proposal() {
    let input = fixture(
        r#"<c r="A1"><v>2</v></c>"#,
        r#"<c r="A1"><f>B1+3</f><v>0</v></c><c r="B1"><f>Input!A1*2</f><v>0</v></c>"#,
        false,
    );
    let session = InProcessSession::opt_in(
        FixtureSession {
            edit: Some(("<v>2</v>".into(), "<v>7</v>".into())),
            ..FixtureSession::editor()
        },
        limits(),
    );
    let plan = EditPlan::new(vec![EditOp::SetCell {
        sheet: "Input".into(),
        cell: CellRef { row: 1, col: 1 },
        before: Some(CellValue::Number(2.0)),
        after: CellValue::Number(7.0),
    }]);
    let outcome = run_edit_roundtrip(&session, &input, OfficeFormat::Xlsx, &plan, "native-graph")
        .expect("pipeline");
    let EditOutcome::Proposed(proposal) = outcome else {
        panic!("rejected XLSX");
    };
    assert!(proposal.validation.ok);
    assert_eq!(proposal.recalc, RecalcStatus::Performed);
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    let xml = part_text(&proposal.new_bytes, OUTPUT);
    assert!(xml.contains("<f>B1+3</f><v>17</v>"));
    assert!(xml.contains("<f>Input!A1*2</f><v>14</v>"));
    assert_eq!(
        part_bytes(&proposal.new_bytes, "vendor/opaque.bin").as_deref(),
        Some(UNKNOWN)
    );
    assert_eq!(
        part_text(&input, "xl/workbook.xml"),
        part_text(&proposal.new_bytes, "xl/workbook.xml")
    );
    assert!(part_text(&input, INPUT).contains("<v>2</v>"));
}

#[test]
fn a_reused_session_does_not_stamp_an_old_engine_on_a_no_recalc_proposal() {
    let input = fixture("", r#"<c r="A1"><f>1+1</f><v>0</v></c>"#, false);
    let session = InProcessSession::opt_in(FixtureSession::editor(), limits());
    let first = run_edit_roundtrip(
        &session,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "first",
    )
    .expect("first recalc");
    let EditOutcome::Proposed(first) = first else {
        panic!("rejected first");
    };
    assert_eq!(stamp(&first).as_deref(), Some(NATIVE_STAMP));
    let second = run_edit_roundtrip(
        &session,
        &first.new_bytes,
        OfficeFormat::Xlsx,
        &EditPlan::new(Vec::new()),
        "second",
    )
    .expect("second proposal");
    let EditOutcome::Proposed(second) = second else {
        panic!("rejected second");
    };
    assert_eq!(second.calc_engine, None);
    assert_eq!(second.recalc, RecalcStatus::NotNeeded);
    assert_eq!(second.new_bytes, first.new_bytes);
}

#[test]
fn scalar_cache_types_and_unknown_xml_survive_the_retained_writer() {
    let cells = r#"<c r="A1" t="str" s="4" u:cell="keep"><f u:f="keep">40+2</f><v u:v="keep">old</v><u:cellExt a="b"/></c><c r="B1"><f>&quot;東京 &amp; &lt;report&gt;&quot;</f><v/></c><c r="C1" t="str"><f>1/0</f><v>old</v></c><c r="D1"><f>TRUE()</f></c>"#;
    let input = fixture("", cells, false);
    let report = recalc(&input).expect("real XLSX recalc");
    assert_eq!(report.formula_count, 4);
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(xml.contains(r#"<c r="A1"  s="4" u:cell="keep"><f u:f="keep">40+2</f><v u:v="keep">42</v><u:cellExt a="b"/></c>"#));
    assert!(xml.contains(r#"<c r="B1" t="str"><f>&quot;東京 &amp; &lt;report&gt;&quot;</f><v>東京 &amp; &lt;report&gt;</v></c>"#));
    assert!(xml.contains(r#"<c r="C1" t="e"><f>1/0</f><v>#DIV/0!</v></c>"#));
    assert!(xml.contains(r#"<c r="D1" t="b"><f>TRUE()</f><v>1</v></c>"#));
    assert!(xml.ends_with(
        r#"<extLst><u:keep value="unaltered">unmodelled content</u:keep></extLst></worksheet>"#
    ));
    let again = recalc(&report.bytes).expect("idempotent recalc");
    assert_eq!(again.bytes, report.bytes);
}

#[test]
fn prefixed_sheet_elements_and_unknown_same_name_elements_are_preserved() {
    let input = fixture("", "", false);
    let source = format!(
        r#"<s:worksheet xmlns:s="{MAIN}" xmlns:u="urn:unknown"><s:sheetData><s:row r="1"><s:c r="A1" u:t="not-a-cache-type"><s:f>20+22</s:f><s:v/></s:c><u:c r="B1"><u:f>unmodelled</u:f></u:c></s:row></s:sheetData></s:worksheet>"#
    );
    let report = recalc(&with_part(&input, OUTPUT, source)).expect("prefixed XML");
    assert_eq!(report.formula_count, 1);
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(
        xml.contains(r#"<s:c r="A1" u:t="not-a-cache-type"><s:f>20+22</s:f><s:v>42</s:v></s:c>"#)
    );
    assert!(xml.contains(r#"<u:c r="B1"><u:f>unmodelled</u:f></u:c>"#));
}

#[test]
fn xlookup_is_evaluated_and_written_with_storage_prefix() {
    let input = fixture(
        r#"<c r="A1"><v>7</v></c><c r="B1" t="inlineStr"><is><t>found</t></is></c>"#,
        r#"<c r="A1"><f u:keep="f">XLOOKUP(7,Input!A1:A1,Input!B1:B1)</f><v/></c>"#,
        false,
    );
    let report = recalc(&input).expect("XLOOKUP");
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(
        xml.contains(r#"<f u:keep="f">_xlfn.XLOOKUP(7,Input!A1:A1,Input!B1:B1)</f><v>found</v>"#)
    );
    assert!(xml.contains(r#"<c r="A1" t="str">"#));
}

#[test]
fn package_shared_strings_and_typed_input_errors_reach_the_graph() {
    let bytes = fixture(
        r#"<c r="A1" t="s"><v>0</v></c><c r="B1" t="e"><v>#N/A</v></c>"#,
        r#"<c r="A1"><f>Input!A1&amp;&quot;!&quot;</f><v/></c><c r="B1"><f>IFERROR(Input!B1,7)</f><v/></c>"#,
        false,
    );
    let rels = part_text(&bytes, "xl/_rels/workbook.xml.rels")
        .replace("</Relationships>", &format!(r#"<Relationship Id="strings" Type="{DOC_REL}/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#));
    let bytes = with_part(&bytes, "xl/_rels/workbook.xml.rels", rels);
    let input = with_part(
        &bytes,
        "xl/sharedStrings.xml",
        format!(
            r#"<sst xmlns="{MAIN}"><si><r><t>東</t></r><r><t>京</t></r><rPh><t>ignored phonetics</t></rPh></si></sst>"#
        ),
    );
    let report = recalc(&input).expect("typed inputs");
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(xml.contains("<v>東京!</v>"));
    assert!(xml.contains("<f>IFERROR(Input!B1,7)</f><v>7</v>"));
    assert_eq!(
        part_text(&report.bytes, "xl/sharedStrings.xml"),
        part_text(&input, "xl/sharedStrings.xml")
    );
}

#[test]
fn workbook_date_system_changes_dates_but_not_time_or_numeric_inputs() {
    let formula = r#"<c r="A1"><f>DATE(2024,3,15)</f><v/></c><c r="B1"><f>TIME(13,30,0)</f><v/></c><c r="C1"><f>Input!A1+1</f><v/></c>"#;
    for (is_1904, expected) in [(false, "45366"), (true, "43904")] {
        let input = fixture(r#"<c r="A1"><v>60</v></c>"#, formula, is_1904);
        let report = recalc(&input).expect("date-aware XLSX");
        let xml = part_text(&report.bytes, OUTPUT);
        assert!(xml.contains(&format!("<f>DATE(2024,3,15)</f><v>{expected}</v>")));
        assert!(xml.contains("<f>TIME(13,30,0)</f><v>0.5625</v>"));
        assert!(xml.contains("<f>Input!A1+1</f><v>61</v>"));
    }
}

fn external_workbook() -> Vec<u8> {
    let bytes = fixture("", r#"<c r="A1"><f>'[1]Sheet1'!A1</f><v>42</v></c>"#, false);
    let bytes = with_part(
        &bytes,
        "xl/externalLinks/externalLink1.xml",
        b"<externalLink keep='all'/>".to_vec(),
    );
    with_part(
        &bytes,
        "xl/externalLinks/_rels/externalLink1.xml.rels",
        format!(
            r#"<Relationships xmlns="{REL}"><Relationship Id="link" Type="{DOC_REL}/externalLinkPath" TargetMode="External" Target="file:///private/other.xlsx"/></Relationships>"#
        ),
    )
}

#[test]
fn external_link_workbook_crosses_fallback_unchanged_and_never_gets_native_stamp() {
    let input = external_workbook();
    let session = InProcessSession::opt_in(
        FixtureSession {
            fallback: Some(input.clone()),
            expected_fallback_input: Some(input.clone()),
            ..FixtureSession::editor()
        },
        limits(),
    );
    let outcome = run_edit_roundtrip(
        &session,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "external-safe",
    )
    .expect("fallback");
    let EditOutcome::Proposed(proposal) = outcome else {
        panic!("rejected");
    };
    assert_eq!(proposal.new_bytes, input);
    assert_eq!(proposal.calc_engine.as_deref(), Some(&fallback_stamp()));
    assert!(matches!(
        recalc(&input),
        Err(FormulaError::UnsupportedWorkbook("external-links-part"))
    ));
}

#[test]
fn destructive_external_link_fallback_is_refused() {
    let input = external_workbook();
    let damaged = with_part(
        &input,
        "xl/externalLinks/externalLink1.xml",
        b"<externalLink/>".to_vec(),
    );
    let session = InProcessSession::opt_in(
        FixtureSession {
            fallback: Some(damaged),
            ..FixtureSession::editor()
        },
        limits(),
    );
    assert_eq!(
        refusal(run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "external-loss"
        )),
        "fallback altered or dropped an external-link part"
    );
}

#[test]
fn formula_only_external_references_cannot_be_destroyed_by_fallback() {
    let input = fixture(
        "",
        r#"<c r="A1"><f>'[linked.xlsx]S'!A1</f><v>42</v></c>"#,
        false,
    );
    let damaged = with_part(&input, OUTPUT, sheet(r#"<c r="A1"><v>42</v></c>"#));
    let session = InProcessSession::opt_in(
        FixtureSession {
            fallback: Some(damaged),
            ..FixtureSession::editor()
        },
        limits(),
    );
    assert_eq!(
        refusal(run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "external-formula-loss"
        )),
        "fallback altered or dropped an external formula link"
    );
}

#[test]
fn unsupported_spills_and_shared_formulas_use_precision_fallback_not_partial_output() {
    for formula in [
        r#"<f t="shared" si="0" ref="A1:A2">1+2</f>"#,
        "<f>SEQUENCE(2,2)</f>",
    ] {
        let input = fixture("", &format!(r#"<c r="A1">{formula}<v>999</v></c>"#), false);
        let session = InProcessSession::opt_in(
            FixtureSession {
                fallback: Some(input.clone()),
                expected_fallback_input: Some(input.clone()),
                ..FixtureSession::editor()
            },
            limits(),
        );
        let outcome = run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "unsupported",
        )
        .expect("fallback");
        let EditOutcome::Proposed(proposal) = outcome else {
            panic!("rejected");
        };
        assert_eq!(proposal.new_bytes, input);
        assert_eq!(proposal.calc_engine.as_deref(), Some(&fallback_stamp()));
    }
}

#[test]
fn malformed_xml_and_duplicate_cells_are_not_recalculated() {
    let input = fixture(
        "",
        r#"<c r="A1"><f>1+1</f></c><c r="A1"><f>9+9</f></c>"#,
        false,
    );
    assert!(matches!(
        recalc(&input),
        Err(FormulaError::InvalidWorkbook(_))
    ));
    let input = fixture("", "<c r='A1'><f>1</f></wrong>", false);
    assert!(matches!(
        recalc(&input),
        Err(FormulaError::InvalidWorkbook(_))
    ));
}

#[test]
fn stored_excel_scalar_goldens_survive_actual_xlsx_recalculation() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron-docedit/tests/fixtures/spreadsheet-compat/excel");
    let goldens: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("goldens.json")).expect("stored goldens"))
            .expect("golden metadata");
    let archive =
        parts(&std::fs::read(base.join("cached-workbooks.zip")).expect("stored Excel saves"));
    // These are stored Excel saves, not generated fixtures or upstream beliefs.
    // Stale-cache tests above independently prove this is not a no-op adapter.
    for case in [
        "ABS_cell_reference_negative",
        "ABS_error_propagates",
        "DATE_basic",
        "TIME_basic",
    ] {
        let file = goldens["cases"][case]["file"]
            .as_str()
            .expect("oracle file");
        let (_, input) = archive
            .iter()
            .find(|(name, _)| name == file)
            .expect("native saved XLSX");
        let output = recalc(input).expect("native scalar golden");
        assert!(output.formula_count > 0);
        assert_eq!(
            &output.bytes, input,
            "stored Excel cache and untouched bytes: {case}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn retained_recalc_agrees_with_integer_algebra_and_is_idempotent(a in -10000i32..10000, b in -10000i32..10000) {
        let input = fixture(&format!(r#"<c r="A1"><v>{a}</v></c><c r="B1"><v>{b}</v></c>"#),
            r#"<c r="A1"><f>Input!A1+Input!B1</f><v>0</v></c><c r="B1"><f>A1-Input!B1</f><v>0</v></c>"#, false);
        let report = recalc(&input).expect("recalc");
        let xml = part_text(&report.bytes, OUTPUT);
        let sum = a + b;
        let expected_sum = format!("<f>Input!A1+Input!B1</f><v>{sum}</v>");
        let expected_difference = format!("<f>A1-Input!B1</f><v>{a}</v>");
        prop_assert!(xml.contains(&expected_sum));
        prop_assert!(xml.contains(&expected_difference));
        let again = recalc(&report.bytes).expect("recalc twice");
        prop_assert_eq!(&again.bytes, &report.bytes);
        let opaque = part_bytes(&again.bytes, "vendor/opaque.bin");
        prop_assert_eq!(opaque.as_deref(), Some(UNKNOWN));
        prop_assert_eq!(part_text(&input, INPUT), part_text(&again.bytes, INPUT));
    }
}

#[test]
fn contextual_formulas_use_precision_fallback_not_the_corpus_clock() {
    for formula in [
        "NOW()",
        "_xlfn.TODAY()",
        "SUM(RAND(),1)",
        "LAMBDA(x,NOW()+x)(2)",
    ] {
        let input = fixture(
            "",
            &format!(r#"<c r="A1"><f>{formula}</f><v>42</v></c>"#),
            false,
        );
        let session = InProcessSession::opt_in(
            FixtureSession {
                fallback: Some(input.clone()),
                expected_fallback_input: Some(input.clone()),
                ..FixtureSession::editor()
            },
            limits(),
        );
        let EditOutcome::Proposed(proposal) = run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "context-fallback",
        )
        .expect("precision route") else {
            panic!("rejected precision route");
        };
        assert_eq!(proposal.new_bytes, input);
        assert_eq!(proposal.calc_engine.as_deref(), Some(&fallback_stamp()));
    }
    let input = fixture(
        "",
        r#"<c r="A1"><f>&quot;NOW()&quot;</f><v>0</v></c>"#,
        false,
    );
    let output = recalc(&input).expect("literal is not a volatile call");
    assert!(part_text(&output.bytes, OUTPUT).contains("<v>NOW()</v>"));
    assert_eq!(output.engine.engine, "oneiron-xlsx-formula");
}

#[test]
fn windows_only_functions_return_name_errors_in_the_native_mac_session() {
    for formula in [
        r#"ENCODEURL("a b")"#,
        r#"FILTERXML("<root/>","/root")"#,
        r#"WEBSERVICE("https://example.invalid/")"#,
    ] {
        let xml_formula = formula.replace('&', "&amp;").replace('<', "&lt;");
        let input = fixture(
            "",
            &format!(r#"<c r="A1"><f>{xml_formula}</f><v>42</v></c>"#),
            false,
        );
        let session = InProcessSession::opt_in(FixtureSession::editor(), limits());
        let EditOutcome::Proposed(proposal) = run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "mac-function-parity",
        )
        .expect("native session") else {
            panic!("rejected native session")
        };
        let xml = part_text(&proposal.new_bytes, OUTPUT);
        assert!(
            xml.contains(r#"t="e""#) && xml.contains("<v>#NAME?</v>"),
            "{xml}"
        );
        assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    }
}

#[test]
fn native_xlsx_session_settles_once_with_bound_engine_stamp() -> oneiron::Result<()> {
    use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use oneiron::edit_settle::SettleConsent;
    use oneiron::write_envelope::WriteActor;
    use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let at = TimeRange { start: 10, end: 10 };
    let person = EntityId::now();
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        10,
        b"owner",
    )?;
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new(
            "native.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        at,
        10,
    )?;
    let input = fixture("", r#"<c r="A1"><f>40+2</f><v>0</v></c>"#, false);
    vault.append_blob_artifact_version(
        &artifact,
        &input,
        &BlobVersionProvenance::UserUpload,
        actor,
        at,
        10,
    )?;
    // The host reads packages under the vault's resolved document ceilings.
    let session =
        InProcessSession::opt_in(FixtureSession::editor(), vault.docedit_package_limits()?);
    let EditOutcome::Proposed(proposal) =
        vault.propose_blob_artifact_edit(&artifact, &session, &recalc_plan(), "run:native-xlsx")?
    else {
        panic!("rejected native XLSX")
    };
    assert!(part_text(&proposal.new_bytes, OUTPUT).contains("<v>42</v>"));
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    vault.settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at, 12)?;
    assert_eq!(
        vault
            .blob_artifact_version_metadata(&artifact, 2)?
            .expect("version")
            .calc_engine
            .as_ref(),
        proposal.calc_engine.as_deref()
    );
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 2)?,
        Some(proposal.new_bytes.clone())
    );
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at, 13),
        Err(Error::Artifact(
            ArtifactError::EditProposalAlreadySettled { .. }
        ))
    ));
    Ok(())
}

#[test]
fn native_measurement_cli_writes_recalc_and_refuses_overwrite_or_fallback() {
    use std::process::Command;

    let directory = tempfile::tempdir().expect("measurement directory");
    let input = directory.path().join("input.xlsx");
    let output = directory.path().join("output.xlsx");
    let bytes = fixture(
        r#"<c r="A1"><v>2</v></c>"#,
        r#"<c r="A1"><f>Input!A1*2</f><v>0</v></c>"#,
        false,
    );
    std::fs::write(&input, &bytes).expect("input");
    let command = Command::new(env!("CARGO_BIN_EXE_recalc_native"))
        .args([&input, &output])
        .output()
        .expect("native measurement CLI");
    assert!(command.status.success());
    let report: serde_json::Value = serde_json::from_slice(&command.stdout).expect("engine report");
    assert_eq!(report["engine"]["engine"], "oneiron-xlsx-formula");
    assert_eq!(
        report["engine"]["version"],
        "0.1.0+formualizer.0.9.3-oneiron.2"
    );
    assert_eq!(report["formulas"], 1);
    assert_eq!(report["precision_fallback"], false);
    let result = std::fs::read(&output).expect("native output");
    assert!(part_text(&result, OUTPUT).contains("<v>4</v>"));
    assert_eq!(std::fs::read(&input).expect("unchanged input"), bytes);

    assert!(
        !Command::new(env!("CARGO_BIN_EXE_recalc_native"))
            .args([&input, &output])
            .output()
            .expect("existing output refusal")
            .status
            .success()
    );
    assert_eq!(std::fs::read(&output).expect("unchanged output"), result);
    std::fs::remove_file(&output).expect("owned output cleanup");
    std::fs::write(&input, fixture("", r#"<c r="A1"><f>NOW()</f></c>"#, false))
        .expect("context-dependent input");
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_recalc_native"))
            .args([&input, &output])
            .output()
            .expect("precision fallback refusal")
            .status
            .success()
    );
    assert!(!output.exists());
}

#[test]
fn absent_inline_string_is_blank_but_explicit_empty_text_is_not() {
    for (cell, expected) in [
        (r#"<c r="A1" t="inlineStr"/>"#, "<v>1</v>"),
        (
            r#"<c r="A1" t="inlineStr"><is><t></t></is></c>"#,
            "<v>0</v>",
        ),
    ] {
        let input = fixture(
            cell,
            r#"<c r="A1"><f>IF(ISBLANK(Input!A1),1,0)</f></c>"#,
            false,
        );
        let output = recalc(&input).expect("blank or explicit empty string");
        assert!(part_text(&output.bytes, OUTPUT).contains(expected));
        assert_eq!(part_text(&input, INPUT), part_text(&output.bytes, INPUT));
    }
    let malformed = fixture(
        r#"<c r="A1" t="inlineStr"><v>not an inline string</v></c>"#,
        "",
        false,
    );
    assert!(matches!(
        recalc(&malformed),
        Err(FormulaError::InvalidWorkbook(_))
    ));
}

#[test]
fn unsafe_formula_depth_refuses_before_recursive_evaluation_on_both_doors() {
    use oneiron_xlsx_formula::engine::{RecalcEngine, StagedValue};
    use std::collections::BTreeMap;
    let fixture_formula = include_str!("fixtures/fuse-chain-formula.txt").trim();
    let long_chain = std::iter::repeat_n("1", 10_000)
        .collect::<Vec<_>>()
        .join("+");
    let deep_chain = std::iter::repeat_n("1", 40).collect::<Vec<_>>().join("+");
    let nested = format!("{}1{}", "ABS(".repeat(40), ")".repeat(40));
    for formula in [
        fixture_formula,
        long_chain.as_str(),
        deep_chain.as_str(),
        nested.as_str(),
    ] {
        let input = fixture(
            "",
            &format!(r#"<c r="A1"><f>{formula}</f><v>999</v></c>"#),
            false,
        );
        assert!(matches!(
            recalc(&input),
            Err(FormulaError::UnsupportedWorkbook(_))
        ));
        assert!(matches!(
            FormualizerEngine::new().evaluate(&BTreeMap::new(), formula, "A1", None),
            Err(FormulaError::UnsupportedWorkbook(_))
        ));
        let setup = BTreeMap::from([("B1".into(), StagedValue::Formula(formula.into()))]);
        assert!(matches!(
            FormualizerEngine::new().evaluate(&setup, "B1", "A1", None),
            Err(FormulaError::UnsupportedWorkbook(_))
        ));
    }
}

#[test]
fn bounded_formula_values_stay_native_and_over_limit_preserves_fallback_identity() {
    use oneiron_xlsx_formula::engine::{CellValue as CalcValue, RecalcEngine};
    use std::collections::BTreeMap;
    let normal = std::iter::repeat_n("1", 24).collect::<Vec<_>>().join("+");
    let result = FormualizerEngine::new()
        .evaluate(&BTreeMap::new(), &normal, "A1", None)
        .unwrap();
    assert_eq!(result.value, CalcValue::Number(24.0));
    // Operators inside a quoted string do not become expression-depth budget.
    let text = "+".repeat(1000);
    let result = FormualizerEngine::new()
        .evaluate(&BTreeMap::new(), &format!("LEN(\"{text}\")"), "A1", None)
        .unwrap();
    assert_eq!(result.value, CalcValue::Number(1000.0));
    let input = fixture(
        "",
        &format!(
            r#"<c r="A1"><f>{}</f><v>999</v></c>"#,
            include_str!("fixtures/fuse-chain-formula.txt").trim()
        ),
        false,
    );
    let session = InProcessSession::opt_in(
        FixtureSession {
            fallback: Some(input.clone()),
            expected_fallback_input: Some(input.clone()),
            ..FixtureSession::editor()
        },
        limits(),
    );
    let result = run_edit_roundtrip(
        &session,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "bounded-formula",
    )
    .unwrap();
    let EditOutcome::Proposed(proposal) = result else {
        panic!("expected fallback proposal");
    };
    assert_eq!(proposal.new_bytes, input);
    assert_eq!(proposal.calc_engine.as_deref(), Some(&fallback_stamp()));
}

#[test]
fn concatenation_preserves_error_values_for_iferror_in_retained_xlsx() {
    let input = fixture(
        r#"<c r="A1" t="e"><v>#N/A</v></c>"#,
        r#"<c r="A1"><f>IFERROR(Input!A1&amp;&quot;&quot;,&quot;missing&quot;)</f><v>0</v></c><c r="B1"><f>IFERROR(&quot;&quot;&amp;Input!A1,&quot;missing&quot;)</f><v>0</v></c><c r="C1"><f>&quot;#N/A&quot;&amp;&quot;&quot;</f><v>0</v></c>"#,
        false,
    );
    let result = recalc(&input).expect("recalc");
    let xml = part_text(&result.bytes, OUTPUT);
    assert_eq!(xml.matches("<v>missing</v>").count(), 2);
    assert!(xml.contains("<v>#N/A</v>"));
    assert_eq!(result.formula_count, 3);
}
