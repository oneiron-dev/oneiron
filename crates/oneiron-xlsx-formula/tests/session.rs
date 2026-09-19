//! Actual XLSX in/out tests through the production EditSession pipeline.
use oneiron_docedit::calc::EngineId;
use oneiron_docedit::opc::{self, Limits, OpcPackage, OpcPart, Package};
use oneiron_docedit::roundtrip::{
    AppliedEdit, CellRef, CellValue, EditOp, EditOutcome, EditPlan, EditSession, OfficeDoc,
    OfficeFormat, RecalcStatus, run_edit_roundtrip,
};
use oneiron_docedit::{Error, Result};
use oneiron_xlsx_formula::engine::FormualizerEngine;
use oneiron_xlsx_formula::{FormulaError, InProcessSession};
use proptest::prelude::*;

const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const DOC_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const INPUT: &str = "xl/worksheets/input.xml";
const OUTPUT: &str = "xl/worksheets/result.xml";
const UNKNOWN: &[u8] = b"opaque vendor bytes\0\xff";

fn part(name: &str, data: impl Into<Vec<u8>>) -> OpcPart {
    OpcPart {
        name: name.into(),
        data: data.into(),
    }
}
fn sheet(cells: &str) -> String {
    format!(
        r#"<worksheet xmlns="{MAIN}" xmlns:u="urn:unknown"><sheetData><row r="1">{cells}</row></sheetData><extLst><u:keep value="unaltered">unmodelled content</u:keep></extLst></worksheet>"#
    )
}
fn fixture(inputs: &str, formulas: &str, date1904: bool) -> Vec<u8> {
    opc::write(&OpcPackage::from_parts(vec![
        part("[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>"#.to_vec()),
        // Formula sheet comes first and references the later-created input sheet.
        part("xl/workbook.xml", format!(r#"<workbook xmlns="{MAIN}" xmlns:link="{DOC_REL}"><workbookPr date1904="{}"/><sheets><sheet name="Result" sheetId="7" link:id="out"/><sheet name="Input" sheetId="3" link:id="in"/></sheets></workbook>"#, u8::from(date1904))),
        part("xl/_rels/workbook.xml.rels", format!(r#"<Relationships xmlns="{REL}"><Relationship Id="out" Type="{DOC_REL}/worksheet" Target="worksheets/result.xml"/><Relationship Id="in" Type="{DOC_REL}/worksheet" Target="worksheets/input.xml"/></Relationships>"#)),
        part(INPUT, sheet(inputs)), part(OUTPUT, sheet(formulas)), part("vendor/opaque.bin", UNKNOWN.to_vec()),
    ]))
}
fn part_text(bytes: &[u8], name: &str) -> String {
    let package = Package::open(bytes, Limits::default()).expect("retained XLSX");
    String::from_utf8(package.part(name).expect("part").to_vec()).expect("UTF-8 XML")
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
    fn engine_id(&self) -> EngineId {
        EngineId::libreoffice("fixture-precision")
    }
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        let mut bytes = doc.bytes.clone();
        if let Some((before, after)) = &self.edit {
            let mut package = Package::open(&bytes, Limits::default())?;
            let input = std::str::from_utf8(package.part(INPUT).expect("input")).expect("XML");
            assert!(input.contains(before));
            package.replace(INPUT, input.replace(before, after).into_bytes())?;
            bytes = package.write()?;
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
            .ok_or(Error::EditFailed("unexpected precision fallback"))
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
    let session = InProcessSession::opt_in(FixtureSession {
        edit: Some(("<v>2</v>".into(), "<v>7</v>".into())),
        ..FixtureSession::editor()
    });
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
    assert_eq!(
        proposal.engine.stamp(),
        "oneiron-xlsx-formula/0.1.0+formualizer.0.9.3"
    );
    let xml = part_text(&proposal.new_bytes, OUTPUT);
    assert!(xml.contains("<f>B1+3</f><v>17</v>"));
    assert!(xml.contains("<f>Input!A1*2</f><v>14</v>"));
    let package = Package::open(&proposal.new_bytes, Limits::default()).expect("output");
    assert_eq!(package.part("vendor/opaque.bin"), Some(UNKNOWN));
    assert_eq!(
        part_text(&input, "xl/workbook.xml"),
        part_text(&proposal.new_bytes, "xl/workbook.xml")
    );
    assert!(part_text(&input, INPUT).contains("<v>2</v>"));
}

#[test]
fn a_reused_session_does_not_stamp_an_old_engine_on_a_no_recalc_proposal() {
    let input = fixture("", r#"<c r="A1"><f>1+1</f><v>0</v></c>"#, false);
    let session = InProcessSession::opt_in(FixtureSession::editor());
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
    assert_eq!(
        first.engine.stamp(),
        "oneiron-xlsx-formula/0.1.0+formualizer.0.9.3"
    );
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
    assert_eq!(second.engine, EngineId::none());
    assert_eq!(second.recalc, RecalcStatus::NotNeeded);
    assert_eq!(second.new_bytes, first.new_bytes);
}

#[test]
fn scalar_cache_types_and_unknown_xml_survive_the_retained_writer() {
    let cells = r#"<c r="A1" t="str" s="4" u:cell="keep"><f u:f="keep">40+2</f><v u:v="keep">old</v><u:cellExt a="b"/></c><c r="B1"><f>&quot;東京 &amp; &lt;report&gt;&quot;</f><v/></c><c r="C1" t="str"><f>1/0</f><v>old</v></c><c r="D1"><f>TRUE()</f></c>"#;
    let input = fixture("", cells, false);
    let report = FormualizerEngine::new()
        .recalculate_xlsx(&input)
        .expect("real XLSX recalc");
    assert_eq!(report.formula_count, 4);
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(xml.contains(r#"<c r="A1"  s="4" u:cell="keep"><f u:f="keep">40+2</f><v u:v="keep">42</v><u:cellExt a="b"/></c>"#));
    assert!(xml.contains(r#"<c r="B1" t="str"><f>&quot;東京 &amp; &lt;report&gt;&quot;</f><v>東京 &amp; &lt;report&gt;</v></c>"#));
    assert!(xml.contains(r#"<c r="C1" t="e"><f>1/0</f><v>#DIV/0!</v></c>"#));
    assert!(xml.contains(r#"<c r="D1" t="b"><f>TRUE()</f><v>1</v></c>"#));
    assert!(xml.ends_with(
        r#"<extLst><u:keep value="unaltered">unmodelled content</u:keep></extLst></worksheet>"#
    ));
    let again = FormualizerEngine::new()
        .recalculate_xlsx(&report.bytes)
        .expect("idempotent recalc");
    assert_eq!(again.bytes, report.bytes);
}

#[test]
fn prefixed_sheet_elements_and_unknown_same_name_elements_are_preserved() {
    let input = fixture("", "", false);
    let mut package = Package::open(&input, Limits::default()).expect("package");
    let source = format!(
        r#"<s:worksheet xmlns:s="{MAIN}" xmlns:u="urn:unknown"><s:sheetData><s:row r="1"><s:c r="A1" u:t="not-a-cache-type"><s:f>20+22</s:f><s:v/></s:c><u:c r="B1"><u:f>unmodelled</u:f></u:c></s:row></s:sheetData></s:worksheet>"#
    );
    package
        .replace(OUTPUT, source.into_bytes())
        .expect("prefixes");
    let report = FormualizerEngine::new()
        .recalculate_xlsx(&package.write().expect("input"))
        .expect("prefixed XML");
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
    let report = FormualizerEngine::new()
        .recalculate_xlsx(&input)
        .expect("XLOOKUP");
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
    let mut package = Package::open(&bytes, Limits::default()).expect("package");
    let rels = std::str::from_utf8(package.part("xl/_rels/workbook.xml.rels").expect("rels")).expect("XML")
        .replace("</Relationships>", &format!(r#"<Relationship Id="strings" Type="{DOC_REL}/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#));
    package
        .replace("xl/_rels/workbook.xml.rels", rels.into_bytes())
        .expect("link strings");
    package.insert("xl/sharedStrings.xml", format!(r#"<sst xmlns="{MAIN}"><si><r><t>東</t></r><r><t>京</t></r><rPh><t>ignored phonetics</t></rPh></si></sst>"#).into_bytes()).expect("strings");
    let input = package.write().expect("input");
    let report = FormualizerEngine::new()
        .recalculate_xlsx(&input)
        .expect("typed inputs");
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
        let report = FormualizerEngine::new()
            .recalculate_xlsx(&input)
            .expect("date-aware XLSX");
        let xml = part_text(&report.bytes, OUTPUT);
        assert!(xml.contains(&format!("<f>DATE(2024,3,15)</f><v>{expected}</v>")));
        assert!(xml.contains("<f>TIME(13,30,0)</f><v>0.5625</v>"));
        assert!(xml.contains("<f>Input!A1+1</f><v>61</v>"));
    }
}

fn external_workbook() -> Vec<u8> {
    let bytes = fixture("", r#"<c r="A1"><f>'[1]Sheet1'!A1</f><v>42</v></c>"#, false);
    let mut package = Package::open(&bytes, Limits::default()).expect("package");
    package
        .insert(
            "xl/externalLinks/externalLink1.xml",
            b"<externalLink keep='all'/>".to_vec(),
        )
        .expect("external link");
    package.insert("xl/externalLinks/_rels/externalLink1.xml.rels", format!(r#"<Relationships xmlns="{REL}"><Relationship Id="link" Type="{DOC_REL}/externalLinkPath" TargetMode="External" Target="file:///private/other.xlsx"/></Relationships>"#).into_bytes()).expect("external rels");
    package.write().expect("external XLSX")
}

#[test]
fn external_link_workbook_crosses_fallback_unchanged_and_never_gets_native_stamp() {
    let input = external_workbook();
    let session = InProcessSession::opt_in(FixtureSession {
        fallback: Some(input.clone()),
        expected_fallback_input: Some(input.clone()),
        ..FixtureSession::editor()
    });
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
    assert_eq!(proposal.engine, EngineId::libreoffice("fixture-precision"));
    assert!(matches!(
        FormualizerEngine::new().recalculate_xlsx(&input),
        Err(FormulaError::UnsupportedWorkbook("external-links-part"))
    ));
}

#[test]
fn destructive_external_link_fallback_is_refused() {
    let input = external_workbook();
    let mut damaged = Package::open(&input, Limits::default()).expect("input");
    damaged
        .replace(
            "xl/externalLinks/externalLink1.xml",
            b"<externalLink/>".to_vec(),
        )
        .expect("damage");
    let session = InProcessSession::opt_in(FixtureSession {
        fallback: Some(damaged.write().expect("damaged workbook")),
        ..FixtureSession::editor()
    });
    assert_eq!(
        run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "external-loss"
        )
        .unwrap_err(),
        Error::EditFailed("fallback altered or dropped an external-link part")
    );
}

#[test]
fn formula_only_external_references_cannot_be_destroyed_by_fallback() {
    let input = fixture(
        "",
        r#"<c r="A1"><f>'[linked.xlsx]S'!A1</f><v>42</v></c>"#,
        false,
    );
    let mut damaged = Package::open(&input, Limits::default()).expect("package");
    damaged
        .replace(OUTPUT, sheet(r#"<c r="A1"><v>42</v></c>"#).into_bytes())
        .expect("remove linked formula");
    let session = InProcessSession::opt_in(FixtureSession {
        fallback: Some(damaged.write().expect("output")),
        ..FixtureSession::editor()
    });
    assert_eq!(
        run_edit_roundtrip(
            &session,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "external-formula-loss"
        )
        .unwrap_err(),
        Error::EditFailed("fallback altered or dropped an external formula link")
    );
}

#[test]
fn unsupported_spills_and_shared_formulas_use_precision_fallback_not_partial_output() {
    for formula in [
        r#"<f t="shared" si="0" ref="A1:A2">1+2</f>"#,
        "<f>SEQUENCE(2,2)</f>",
    ] {
        let input = fixture("", &format!(r#"<c r="A1">{formula}<v>999</v></c>"#), false);
        let session = InProcessSession::opt_in(FixtureSession {
            fallback: Some(input.clone()),
            expected_fallback_input: Some(input.clone()),
            ..FixtureSession::editor()
        });
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
        assert_eq!(proposal.engine, EngineId::libreoffice("fixture-precision"));
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
        FormualizerEngine::new().recalculate_xlsx(&input),
        Err(FormulaError::InvalidWorkbook(_))
    ));
    let input = fixture("", "<c r='A1'><f>1</f></wrong>", false);
    assert!(matches!(
        FormualizerEngine::new().recalculate_xlsx(&input),
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
        opc::read(&std::fs::read(base.join("cached-workbooks.zip")).expect("stored Excel saves"))
            .expect("fixture archive");
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
        let input = archive.part(file).expect("native saved XLSX");
        let output = FormualizerEngine::new()
            .recalculate_xlsx(input)
            .expect("native scalar golden");
        assert!(output.formula_count > 0);
        assert_eq!(
            output.bytes, input,
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
        let engine = FormualizerEngine::new();
        let report = engine.recalculate_xlsx(&input).expect("recalc");
        let xml = part_text(&report.bytes, OUTPUT);
        let sum = a + b;
        let expected_sum = format!("<f>Input!A1+Input!B1</f><v>{sum}</v>");
        let expected_difference = format!("<f>A1-Input!B1</f><v>{a}</v>");
        prop_assert!(xml.contains(&expected_sum));
        prop_assert!(xml.contains(&expected_difference));
        let again = engine.recalculate_xlsx(&report.bytes).expect("recalc twice");
        prop_assert_eq!(&again.bytes, &report.bytes);
        let output = Package::open(&again.bytes, Limits::default()).expect("output");
        prop_assert_eq!(output.part("vendor/opaque.bin"), Some(UNKNOWN));
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
        let session = InProcessSession::opt_in(FixtureSession {
            fallback: Some(input.clone()),
            expected_fallback_input: Some(input.clone()),
            ..FixtureSession::editor()
        });
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
        assert_eq!(proposal.engine, EngineId::libreoffice("fixture-precision"));
    }
    let input = fixture(
        "",
        r#"<c r="A1"><f>&quot;NOW()&quot;</f><v>0</v></c>"#,
        false,
    );
    let output = FormualizerEngine::new()
        .recalculate_xlsx(&input)
        .expect("literal is not a volatile call");
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
        let session = InProcessSession::opt_in(FixtureSession::editor());
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
        assert_eq!(proposal.engine.engine, "oneiron-xlsx-formula");
    }
}

#[test]
fn native_xlsx_session_settles_once_with_bound_engine_stamp() -> oneiron::Result<()> {
    use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use oneiron::edit_roundtrip::{DocumentSession, EditOutcome as StoredOutcome};
    use oneiron::edit_settle::SettleConsent;
    use oneiron::error::ArtifactError;
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
    let session = DocumentSession::new(InProcessSession::opt_in(FixtureSession::editor()));
    let StoredOutcome::Proposed(proposal) =
        vault.propose_blob_artifact_edit(&artifact, &session, &recalc_plan(), "run:native-xlsx")?
    else {
        panic!("rejected native XLSX")
    };
    assert!(part_text(&proposal.new_bytes, OUTPUT).contains("<v>42</v>"));
    assert_eq!(proposal.engine.engine, "oneiron-xlsx-formula");
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let mut forged = proposal.clone();
    forged.engine.version = "substituted".into();
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &forged, &consent, actor, at, 11),
        Err(oneiron::Error::Artifact(
            ArtifactError::EditProposalCommitMismatch
        ))
    ));
    assert_eq!(
        vault.blob_artifact_head(&artifact)?.expect("head").version,
        1
    );
    vault.settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at, 12)?;
    assert_eq!(
        vault
            .blob_artifact_version_metadata(&artifact, 2)?
            .expect("version")
            .engine,
        proposal.engine
    );
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 2)?,
        Some(proposal.new_bytes.clone())
    );
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at, 13),
        Err(oneiron::Error::Artifact(
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
    assert_eq!(report["engine"]["version"], "0.1.0+formualizer.0.9.3");
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
