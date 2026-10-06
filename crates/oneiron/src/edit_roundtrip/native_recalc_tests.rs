//! The default stage-3 route ([`RecalcPolicy::NativeFirst`]) on real XLSX.
//! [`Host`] stands in for openpyxl + LibreOffice and implements only the
//! seam's required methods and its calculator stamp, as a host that knows
//! nothing of the formula engine would. Its recalc is the precision fallback.

use std::cell::RefCell;

use super::opc::{self, OpcPackage, OpcPart};
use super::*;
use crate::blob_artifact::CalcEngineStamp;
use crate::error::{ArtifactError, Error, Result};

const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const DOC_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const TYPES: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const SPREADSHEET: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml";
const INPUT: &str = "xl/worksheets/input.xml";
const OUTPUT: &str = "xl/worksheets/result.xml";
const OPAQUE: &str = "vendor/opaque.bin";
const UNKNOWN: &[u8] = b"opaque vendor bytes\0\xff";
const NATIVE_STAMP: &str = "oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.10";

fn build(parts: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    opc::write(&OpcPackage::from_parts(
        parts
            .into_iter()
            .map(|(name, data)| OpcPart {
                name: name.to_owned(),
                data,
            })
            .collect(),
    ))
}
fn with_part(bytes: &[u8], name: &str, data: impl Into<Vec<u8>>) -> Vec<u8> {
    let mut package = opc::read(bytes).expect("fixture package");
    package.upsert(name, data.into());
    opc::write(&package)
}
fn part_text(bytes: &[u8], name: &str) -> String {
    let package = opc::read(bytes).expect("package");
    String::from_utf8(package.part(name).expect("part").to_vec()).expect("UTF-8 XML")
}
fn sheet(cells: &str) -> String {
    format!(
        r#"<worksheet xmlns="{MAIN}"><sheetData><row r="1">{cells}</row></sheetData></worksheet>"#
    )
}
/// A two-sheet workbook whose `Result` formulas read the later `Input` sheet,
/// plus one opaque vendor part the passthrough law must keep.
fn workbook(inputs: &str, formulas: &str) -> Vec<u8> {
    build(vec![
        ("[Content_Types].xml", format!(r#"<Types xmlns="{TYPES}"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="bin" ContentType="application/octet-stream"/><Override PartName="/xl/workbook.xml" ContentType="{SPREADSHEET}.sheet.main+xml"/><Override PartName="/{OUTPUT}" ContentType="{SPREADSHEET}.worksheet+xml"/><Override PartName="/{INPUT}" ContentType="{SPREADSHEET}.worksheet+xml"/></Types>"#).into_bytes()),
        ("_rels/.rels", format!(r#"<Relationships xmlns="{REL}"><Relationship Id="rId1" Type="{DOC_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>"#).into_bytes()),
        ("xl/workbook.xml", format!(r#"<workbook xmlns="{MAIN}" xmlns:r="{DOC_REL}"><sheets><sheet name="Result" sheetId="1" r:id="out"/><sheet name="Input" sheetId="2" r:id="in"/></sheets></workbook>"#).into_bytes()),
        ("xl/_rels/workbook.xml.rels", format!(r#"<Relationships xmlns="{REL}"><Relationship Id="out" Type="{DOC_REL}/worksheet" Target="worksheets/result.xml"/><Relationship Id="in" Type="{DOC_REL}/worksheet" Target="worksheets/input.xml"/></Relationships>"#).into_bytes()),
        (INPUT, sheet(inputs).into_bytes()),
        (OUTPUT, sheet(formulas).into_bytes()),
        (OPAQUE, UNKNOWN.to_vec()),
    ])
}
fn external_workbook() -> Vec<u8> {
    let bytes = workbook("", r#"<c r="A1"><f>'[1]Sheet1'!A1</f><v>42</v></c>"#);
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

/// `workbook` plus the defined name `rate` (`Input!$A$1`) and the `Prices`
/// table on `Input!A3:B5`; `Result!A1:A2` repeat one shared formula over both.
fn names_tables_and_shared_formulas() -> Vec<u8> {
    let inputs = r#"<c r="A1"><v>2</v></c></row><row r="3"><c r="A3" t="inlineStr"><is><t>Item</t></is></c><c r="B3" t="inlineStr"><is><t>Price</t></is></c></row><row r="4"><c r="A4" t="inlineStr"><is><t>tea</t></is></c><c r="B4"><v>3</v></c></row><row r="5"><c r="A5" t="inlineStr"><is><t>cake</t></is></c><c r="B5"><v>5</v></c>"#;
    let formulas = r#"<c r="A1"><f t="shared" ref="A1:A2" si="0">Input!B4*rate</f><v>0</v></c><c r="B1"><f>SUM(Prices[Price])*rate</f><v>0</v></c></row><row r="2"><c r="A2"><f t="shared" si="0"/><v>0</v></c>"#;
    let bytes = workbook(inputs, formulas);
    let bytes = with_part(
        &bytes,
        "xl/workbook.xml",
        part_text(&bytes, "xl/workbook.xml").replace(
            "</sheets>",
            r#"</sheets><definedNames><definedName name="rate">Input!$A$1</definedName></definedNames>"#,
        ),
    );
    let bytes = with_part(
        &bytes,
        "[Content_Types].xml",
        part_text(&bytes, "[Content_Types].xml").replace(
            "</Types>",
            &format!(r#"<Override PartName="/xl/tables/table1.xml" ContentType="{SPREADSHEET}.table+xml"/></Types>"#),
        ),
    );
    let bytes = with_part(
        &bytes,
        "xl/worksheets/_rels/input.xml.rels",
        format!(
            r#"<Relationships xmlns="{REL}"><Relationship Id="t1" Type="{DOC_REL}/table" Target="../tables/table1.xml"/></Relationships>"#
        ),
    );
    with_part(
        &bytes,
        "xl/tables/table1.xml",
        format!(
            r#"<table xmlns="{MAIN}" id="1" name="Prices" displayName="Prices" ref="A3:B5"><autoFilter ref="A3:B5"/><tableColumns count="2"><tableColumn id="1" name="Item"/><tableColumn id="2" name="Price"/></tableColumns></table>"#
        ),
    )
}

fn host_stamp() -> CalcEngineStamp {
    CalcEngineStamp::new("libreoffice", "fixture-precision").expect("fixture stamp")
}
fn stamp(proposal: &EditProposal) -> Option<String> {
    proposal
        .calc_engine
        .as_deref()
        .map(|stamp| format!("{}/{}", stamp.engine(), stamp.version()))
}
fn proposed(result: Result<EditOutcome>) -> EditProposal {
    match result.expect("pipeline runs") {
        EditOutcome::Proposed(proposal) => *proposal,
        EditOutcome::Rejected { report, .. } => panic!("expected a proposal: {report:?}"),
    }
}
fn refusal(result: Result<EditOutcome>) -> &'static str {
    match result {
        Err(Error::Artifact(ArtifactError::EditRoundtripFailed(reason))) => reason,
        other => panic!("expected an edit refusal, got {other:?}"),
    }
}
fn recalc_plan() -> EditPlan {
    EditPlan {
        ops: Vec::new(),
        request_recalc: Some(true),
    }
}
/// The plan [`Host::edit`] carries out: `Input!A1` from 2 to 7.
fn set_input() -> EditPlan {
    EditPlan::new(vec![EditOp::SetCell {
        sheet: "Input".into(),
        cell: CellRef::new(1, 1),
        before: Some(CellValue::Number(2.0)),
        after: CellValue::Number(7.0),
    }])
}
fn edited(input: &[u8]) -> Vec<u8> {
    with_part(
        input,
        INPUT,
        part_text(input, INPUT).replace("<v>2</v>", "<v>7</v>"),
    )
}

/// Host editor and calculator; no `recalc_policy` override, so the default.
#[derive(Default)]
struct Host {
    /// Apply [`set_input`] to the `Input` sheet.
    edit: bool,
    /// What the host calculator returns; `None` fails the round trip.
    output: Option<Vec<u8>>,
    /// Every package the host calculator was handed.
    seen: RefCell<Vec<Vec<u8>>>,
}
impl EditSession for Host {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        Ok(AppliedEdit {
            bytes: if self.edit {
                edited(&doc.bytes)
            } else {
                doc.bytes.clone()
            },
            applied_ops: plan.ops.clone(),
            warnings: Vec::new(),
        })
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.seen.borrow_mut().push(doc.bytes.clone());
        self.output
            .clone()
            .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "unexpected precision fallback",
            )))
    }
    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        Some(host_stamp())
    }
}

/// The same host in an image without a calculator.
struct NoCalculator(Host);
impl EditSession for NoCalculator {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        self.0.apply_edits(doc, plan)
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.0.recalc(doc)
    }
    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.0.recalc_engine()
    }
    fn supports_recalc(&self) -> bool {
        false
    }
}

/// The same host, explicitly opted out of in-process recalc.
struct OptedOut(Host);
impl EditSession for OptedOut {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        self.0.apply_edits(doc, plan)
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.0.recalc(doc)
    }
    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.0.recalc_engine()
    }
    fn recalc_policy(&self) -> RecalcPolicy {
        RecalcPolicy::SessionOnly
    }
}

#[test]
fn supported_workbook_recalculates_natively_by_default_and_stamps_the_crate() {
    let input = workbook(
        r#"<c r="A1"><v>2</v></c>"#,
        r#"<c r="A1"><f>B1+3</f><v>0</v></c><c r="B1"><f>Input!A1*2</f><v>0</v></c>"#,
    );
    let host = Host {
        edit: true,
        ..Host::default()
    };
    assert_eq!(host.recalc_policy(), RecalcPolicy::NativeFirst);
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &set_input(),
        "run:native",
    ));
    assert!(proposal.validation.ok);
    assert_eq!(proposal.recalc, RecalcStatus::Performed);
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    let xml = part_text(&proposal.new_bytes, OUTPUT);
    assert!(xml.contains("<f>B1+3</f><v>17</v>"), "{xml}");
    assert!(xml.contains("<f>Input!A1*2</f><v>14</v>"), "{xml}");
    assert!(part_text(&proposal.new_bytes, INPUT).contains("<v>7</v>"));
    assert_eq!(
        opc::read(&proposal.new_bytes).expect("output").part(OPAQUE),
        Some(UNKNOWN)
    );
    assert!(
        host.seen.borrow().is_empty(),
        "the host calculator never ran"
    );
}

#[test]
fn shared_formulas_defined_names_and_tables_recalculate_natively_through_the_gate() {
    let input = names_tables_and_shared_formulas();
    let host = Host {
        edit: true,
        ..Host::default()
    };
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &set_input(),
        "run:names-tables",
    ));
    assert!(proposal.validation.ok, "{:?}", proposal.validation);
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    let xml = part_text(&proposal.new_bytes, OUTPUT);
    assert!(
        xml.contains(r#"<f t="shared" ref="A1:A2" si="0">Input!B4*rate</f><v>21</v>"#),
        "{xml}"
    );
    assert!(xml.contains(r#"<f t="shared" si="0"/><v>35</v>"#), "{xml}");
    assert!(
        xml.contains("<f>SUM(Prices[Price])*rate</f><v>56</v>"),
        "{xml}"
    );
    assert!(
        host.seen.borrow().is_empty(),
        "the host calculator never ran"
    );
}

#[test]
fn a_reused_host_does_not_stamp_an_old_engine_on_a_no_recalc_proposal() {
    let input = workbook("", r#"<c r="A1"><f>1+1</f><v>0</v></c>"#);
    let host = Host::default();
    let first = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "run:first",
    ));
    assert_eq!(stamp(&first).as_deref(), Some(NATIVE_STAMP));
    let second = proposed(run_edit_roundtrip(
        &host,
        &first.new_bytes,
        OfficeFormat::Xlsx,
        &EditPlan::new(Vec::new()),
        "run:second",
    ));
    assert_eq!(second.recalc, RecalcStatus::NotNeeded);
    assert_eq!(second.calc_engine, None);
    assert_eq!(second.new_bytes, first.new_bytes);
}

#[test]
fn refused_workbooks_reach_the_host_recalc_untouched() {
    let deep_chain = format!("<f>{}</f>", ["1"; 40].join("+"));
    let cases = [
        // What only the host knows: the environment, the file's path, the
        // active cell.
        "<f>INFO(&quot;osversion&quot;)</f>",
        "<f>CELL(&quot;filename&quot;,A1)</f>",
        "<f>LAMBDA(x,CELL(&quot;row&quot;)+x)(2)</f>",
        deep_chain.as_str(),
        // The engine would cache #NAME? where Excel computes a value.
        "<f>NOSUCHFUNCTION(1)</f>",
        // The edit gate requires the OOXML prefix in a recalculated sheet.
        "<f>XLOOKUP(2,Input!A1:A1,Input!A1:A1)</f>",
    ];
    let mut inputs: Vec<Vec<u8>> = cases
        .iter()
        .map(|formula| {
            workbook(
                r#"<c r="A1"><v>2</v></c>"#,
                &format!(r#"<c r="A1">{formula}<v>999</v></c>"#),
            )
        })
        .collect();
    // A workbook feature the engine refuses, not a formula.
    let local = workbook(r#"<c r="A1"><v>2</v></c>"#, r#"<c r="A1"><f>1+1</f></c>"#);
    inputs.push(with_part(
        &local,
        "xl/workbook.xml",
        part_text(&local, "xl/workbook.xml")
            .replace("</sheets>", r#"</sheets><calcPr fullPrecision="0"/>"#),
    ));
    // A workbook LAMBDA name, which the engine would resolve to #NAME?.
    let named = workbook(
        r#"<c r="A1"><v>2</v></c>"#,
        r#"<c r="A1"><f>SUM(_xlfn.MAP(Input!A1:A1,AddDouble))</f></c>"#,
    );
    inputs.push(with_part(
        &named,
        "xl/workbook.xml",
        part_text(&named, "xl/workbook.xml").replace(
            "</sheets>",
            r#"</sheets><definedNames><definedName name="AddDouble">_xlfn.LAMBDA(_xlpm.x,_xlpm.x*2)</definedName></definedNames>"#,
        ),
    ));
    // An escape the engine's reader keeps as seven characters (`_x20AC_` is €),
    // in a string and in a defined name.
    inputs.push(workbook(
        r#"<c r="A1"><v>2</v></c><c r="B1" t="inlineStr"><is><t>_x20AC_</t></is></c>"#,
        r#"<c r="A1"><f>LEN(Input!B1)</f></c>"#,
    ));
    let escaped = workbook(
        r#"<c r="A1"><v>2</v></c>"#,
        r#"<c r="A1"><f>LEN(rate)</f></c>"#,
    );
    inputs.push(with_part(
        &escaped,
        "xl/workbook.xml",
        part_text(&escaped, "xl/workbook.xml").replace(
            "</sheets>",
            r#"</sheets><definedNames><definedName name="rate">&quot;_x20AC_&quot;</definedName></definedNames>"#,
        ),
    ));
    for input in inputs {
        let expected = edited(&input);
        let host = Host {
            edit: true,
            output: Some(expected.clone()),
            ..Host::default()
        };
        let proposal = proposed(run_edit_roundtrip(
            &host,
            &input,
            OfficeFormat::Xlsx,
            &set_input(),
            "run:refused",
        ));
        let sheet = part_text(&input, OUTPUT);
        assert_eq!(*host.seen.borrow(), vec![expected.clone()], "{sheet}");
        assert_eq!(proposal.new_bytes, expected, "{sheet}");
        assert_eq!(proposal.calc_engine.as_deref(), Some(&host_stamp()));
    }
}

/// [`Host`] with its own clock: 2026-10-06T20:00:00Z in Tokyo (UTC+9).
struct Clocked(Host);
impl EditSession for Clocked {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        self.0.apply_edits(doc, plan)
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.0.recalc(doc)
    }
    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.0.recalc_engine()
    }
    fn recalc_clock(&self) -> Option<RecalcClock> {
        let now = "2026-10-06T20:00:00Z".parse().expect("instant");
        RecalcClock::new(now, 540, 7)
    }
}

/// The cached value of `cell` in worksheet XML.
fn cached(xml: &str, cell: &str) -> String {
    let at = xml.find(&format!(r#"<c r="{cell}""#)).expect("cell");
    let start = at + xml[at..].find("<v>").expect("cache") + 3;
    xml[start..start + xml[start..].find("</v>").expect("cache end")].to_owned()
}

#[test]
fn clock_functions_recalculate_natively_on_the_session_clock_or_the_hosts() {
    let input = workbook(
        "",
        r#"<c r="A1"><f>TODAY()</f><v>0</v></c><c r="B1"><f>NOW()</f><v>0</v></c><c r="C1"><f>A1+1</f><v>0</v></c><c r="D1"><f>RANDBETWEEN(1,6)</f><v>0</v></c><c r="E1"><f>OFFSET(A1,0,2)</f><v>0</v></c>"#,
    );
    // The session's clock: Wednesday 7 October 2026, 05:00 in Tokyo.
    let host = Clocked(Host::default());
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "run:session-clock",
    ));
    assert!(proposal.validation.ok, "{:?}", proposal.validation);
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    let xml = part_text(&proposal.new_bytes, OUTPUT);
    assert_eq!(cached(&xml, "A1"), "46302", "{xml}");
    let now: f64 = cached(&xml, "B1").parse().expect("serial");
    assert!((now - (46302.0 + 5.0 / 24.0)).abs() < 1e-9, "{xml}");
    assert_eq!(cached(&xml, "C1"), "46303", "{xml}");
    assert_eq!(cached(&xml, "E1"), "46303", "{xml}");
    let die: f64 = cached(&xml, "D1").parse().expect("draw");
    assert!(die.fract() == 0.0 && (1.0..=6.0).contains(&die), "{xml}");
    assert!(
        host.0.seen.borrow().is_empty(),
        "the host calculator never ran"
    );
    // Without a session clock, the host's clock at recalc time.
    let host = Host::default();
    let before = RecalcClock::system();
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "run:host-clock",
    ));
    let today: f64 = cached(&part_text(&proposal.new_bytes, OUTPUT), "A1")
        .parse()
        .expect("serial");
    let local = before.now().timestamp() + i64::from(before.utc_offset_minutes()) * 60;
    // Days from 1899-12-30, Excel's serial epoch, to the local date.
    let expected = (local.div_euclid(86_400) + 25_569) as f64;
    assert!((today - expected).abs() <= 1.0, "{today} vs {expected}");
    assert!(
        host.seen.borrow().is_empty(),
        "the host calculator never ran"
    );
}

#[test]
fn malformed_workbooks_fail_outright_without_the_host_recalc() {
    // Two sheets with one sheet ID (the fixture's are 1 and 2).
    let local = workbook("", r#"<c r="A1"><f>1+1</f></c>"#);
    let shared_id = with_part(
        &local,
        "xl/workbook.xml",
        part_text(&local, "xl/workbook.xml").replace(r#"sheetId="2""#, r#"sheetId="1""#),
    );
    for (input, reason) in [
        (
            workbook("", r#"<c r="A1"><f>1+1</f></c><c r="A1"><f>9+9</f></c>"#),
            "duplicate or out-of-grid cell",
        ),
        (
            workbook(
                r#"<c r="A1" t="b"><v>2</v></c>"#,
                r#"<c r="A1"><f>Input!A1</f></c>"#,
            ),
            "invalid boolean",
        ),
        (shared_id, "duplicate sheet ID"),
    ] {
        let host = Host {
            output: Some(Vec::new()),
            ..Host::default()
        };
        assert_eq!(
            refusal(run_edit_roundtrip(
                &host,
                &input,
                OfficeFormat::Xlsx,
                &recalc_plan(),
                "run:malformed",
            )),
            reason
        );
        assert!(host.seen.borrow().is_empty());
    }
}

#[test]
fn a_host_without_a_calculator_still_recalculates_admitted_workbooks() {
    let host = NoCalculator(Host::default());
    let input = workbook("", r#"<c r="A1"><f>40+2</f><v>0</v></c>"#);
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "run:no-calculator",
    ));
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    assert!(part_text(&proposal.new_bytes, OUTPUT).contains("<v>42</v>"));
    let refused = workbook(
        "",
        r#"<c r="A1"><f>INFO(&quot;osversion&quot;)</f><v>0</v></c>"#,
    );
    assert_eq!(
        refusal(run_edit_roundtrip(
            &host,
            &refused,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "run:no-calculator-refused",
        )),
        "workbook needs a recalc-capable precision fallback"
    );
    assert!(host.0.seen.borrow().is_empty());
}

#[test]
fn external_link_workbooks_keep_the_link_preserving_host_route() {
    let input = external_workbook();
    let host = Host {
        output: Some(input.clone()),
        ..Host::default()
    };
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "run:linked",
    ));
    assert_eq!(*host.seen.borrow(), vec![input.clone()]);
    assert_eq!(proposal.new_bytes, input);
    assert_eq!(proposal.calc_engine.as_deref(), Some(&host_stamp()));

    // A host calculator that alters a link part is refused, never proposed.
    let host = Host {
        output: Some(with_part(
            &input,
            "xl/externalLinks/externalLink1.xml",
            b"<externalLink/>".to_vec(),
        )),
        ..Host::default()
    };
    assert_eq!(
        refusal(run_edit_roundtrip(
            &host,
            &input,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "run:link-loss",
        )),
        "fallback altered or dropped an external-link part"
    );

    // A formula-only reference has no link part; its text is the link.
    let linked = workbook("", r#"<c r="A1"><f>'[linked.xlsx]S'!A1</f><v>42</v></c>"#);
    let host = Host {
        output: Some(with_part(
            &linked,
            OUTPUT,
            sheet(r#"<c r="A1"><v>42</v></c>"#),
        )),
        ..Host::default()
    };
    assert_eq!(
        refusal(run_edit_roundtrip(
            &host,
            &linked,
            OfficeFormat::Xlsx,
            &recalc_plan(),
            "run:formula-link-loss",
        )),
        "fallback altered or dropped an external formula link"
    );
    assert_eq!(*host.seen.borrow(), vec![linked]);
}

#[test]
fn non_xlsx_formats_are_refused_before_the_default_wrap_applies() {
    let input = workbook("", r#"<c r="A1"><f>40+2</f><v>0</v></c>"#);
    let host = Host::default();
    for format in [OfficeFormat::Docx, OfficeFormat::Pptx] {
        let err = run_edit_roundtrip(&host, &input, format, &recalc_plan(), "run:doc")
            .expect_err("non-spreadsheet formats are unsupported");
        assert!(
            matches!(err, Error::Artifact(ArtifactError::InvalidEditManifest(_))),
            "expected InvalidEditManifest, got {err:?}"
        );
    }
    // The wrap never ran: the host saw no document.
    assert!(host.seen.borrow().is_empty());
}

#[test]
fn explicit_opt_out_sends_every_recalc_to_the_host() {
    let input = workbook("", r#"<c r="A1"><f>40+2</f><v>0</v></c>"#);
    // The engine would cache 42; the host's own calculator answer proves the route.
    let host_output = with_part(
        &input,
        OUTPUT,
        sheet(r#"<c r="A1"><f>40+2</f><v>41</v></c>"#),
    );
    let host = OptedOut(Host {
        output: Some(host_output.clone()),
        ..Host::default()
    });
    let proposal = proposed(run_edit_roundtrip(
        &host,
        &input,
        OfficeFormat::Xlsx,
        &recalc_plan(),
        "run:opt-out",
    ));
    assert_eq!(*host.0.seen.borrow(), vec![input]);
    assert_eq!(proposal.new_bytes, host_output);
    assert_eq!(proposal.calc_engine.as_deref(), Some(&host_stamp()));
}

#[test]
fn vault_proposals_recalculate_natively_by_default_and_settle_the_crate_stamp() -> Result<()> {
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::edge::EdgeActorClass;
    use crate::edit_settle::SettleConsent;
    use crate::entity_id::EntityId;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::write_envelope::WriteActor;

    // A production open seeds the policy manifest that carries the vault's
    // document ceilings; the default wrap reads packages under them.
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device())?;
    let at = TimeRange { start: 10, end: 10 };
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at, 10, b"owner")?;
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
    let input = workbook("", r#"<c r="A1"><f>40+2</f><v>0</v></c>"#);
    vault.append_blob_artifact_version(
        &artifact,
        &input,
        &BlobVersionProvenance::UserUpload,
        actor,
        at,
        10,
    )?;

    // An explicitly opted-out host keeps its own calculator on this door too.
    let opted_out = OptedOut(Host {
        output: Some(input.clone()),
        ..Host::default()
    });
    let EditOutcome::Proposed(host_proposal) =
        vault.propose_blob_artifact_edit(&artifact, &opted_out, &recalc_plan(), "run:host")?
    else {
        panic!("rejected opted-out XLSX")
    };
    assert_eq!(host_proposal.calc_engine.as_deref(), Some(&host_stamp()));
    assert_eq!(*opted_out.0.seen.borrow(), vec![input]);

    let host = Host::default();
    let EditOutcome::Proposed(proposal) =
        vault.propose_blob_artifact_edit(&artifact, &host, &recalc_plan(), "run:native-xlsx")?
    else {
        panic!("rejected native XLSX")
    };
    assert!(part_text(&proposal.new_bytes, OUTPUT).contains("<v>42</v>"));
    assert_eq!(stamp(&proposal).as_deref(), Some(NATIVE_STAMP));
    assert!(host.seen.borrow().is_empty());
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
