//! ARTL-3 pipeline tests. The [`FixtureSession`] stands in for the microVM
//! openpyxl/LibreOffice binaries so the full gate runs in CI without them.

use super::opc::{self, OpcPackage, OpcPart};
use super::*;
use crate::error::ArtifactError;

const SHEET_PART: &str = "xl/worksheets/sheet1.xml";
const UNKNOWN_PART: &str = "customXml/item1.xml";

fn xlsx_bytes(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let pkg = OpcPackage::from_parts(
        parts
            .iter()
            .map(|(name, data)| OpcPart {
                name: (*name).to_owned(),
                data: (*data).to_vec(),
            })
            .collect(),
    );
    opc::write(&pkg)
}

/// A minimal, well-formed xlsx-shaped package carrying one unknown custom-XML
/// part the passthrough law must preserve.
fn base_parts() -> Vec<(&'static str, &'static [u8])> {
    vec![
        (opc::CONTENT_TYPES_PART, b"<Types/>" as &[u8]),
        (
            "xl/workbook.xml",
            b"<workbook><sheets><sheet name=\"Sheet1\" sheetId=\"1\"/></sheets></workbook>",
        ),
        (
            SHEET_PART,
            b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><v>5</v></c></row></sheetData></worksheet>",
        ),
        (UNKNOWN_PART, b"<custom>unknown part, preserve me byte-for-byte</custom>"),
    ]
}

fn pivot_parts() -> Vec<(&'static str, &'static [u8])> {
    let mut parts = base_parts();
    parts.push(("xl/pivotTables/pivotTable1.xml", b"<pivotTableDefinition/>"));
    parts
}

fn set_a1(value: f64) -> EditOp {
    EditOp::SetCell {
        sheet: "Sheet1".to_owned(),
        cell: CellRef::new(1, 1),
        before: Some(CellValue::Number(5.0)),
        after: CellValue::Number(value),
    }
}

#[derive(Debug, Clone, Copy)]
enum MockMode {
    /// Apply the plan to the target sheet, preserve everything else.
    Faithful,
    /// Emit output missing `[Content_Types].xml`.
    DropContentTypes,
    /// Rewrite an unknown part (passthrough violation).
    MutateUnknown,
}

struct FixtureSession {
    mode: MockMode,
    supports_recalc: bool,
}

impl FixtureSession {
    fn faithful() -> Self {
        Self {
            mode: MockMode::Faithful,
            supports_recalc: true,
        }
    }
}

impl EditSession for FixtureSession {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        let mut pkg = opc::read(&doc.bytes).expect("fixture input parses");
        let mut sheet = pkg.part(SHEET_PART).unwrap_or(b"<worksheet/>").to_vec();
        sheet.extend_from_slice(format!("<!--edited:{}-->", plan.ops.len()).as_bytes());
        pkg.upsert(SHEET_PART, sheet);
        match self.mode {
            MockMode::Faithful => {}
            MockMode::MutateUnknown => pkg.upsert(UNKNOWN_PART, b"TAMPERED".to_vec()),
            MockMode::DropContentTypes => {
                pkg = OpcPackage::from_parts(
                    pkg.parts()
                        .iter()
                        .filter(|p| p.name != opc::CONTENT_TYPES_PART)
                        .cloned()
                        .collect(),
                );
            }
        }
        Ok(AppliedEdit {
            bytes: opc::write(&pkg),
            applied_ops: plan.ops.clone(),
            warnings: Vec::new(),
        })
    }

    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        let mut pkg = opc::read(&doc.bytes).expect("edited output parses");
        let mut sheet = pkg.part(SHEET_PART).unwrap_or(b"<worksheet/>").to_vec();
        sheet.extend_from_slice(b"<!--recalc:cached=42-->");
        pkg.upsert(SHEET_PART, sheet);
        Ok(opc::write(&pkg))
    }

    fn recalc_engine(&self) -> Option<crate::blob_artifact::CalcEngineStamp> {
        Some(crate::blob_artifact::CalcEngineStamp::new("fixture-calc", "1.0").unwrap())
    }

    fn supports_recalc(&self) -> bool {
        self.supports_recalc
    }
}

fn propose(session: &FixtureSession, input: &[u8], plan: &EditPlan, run_ref: &str) -> EditProposal {
    match run_edit_roundtrip(session, input, OfficeFormat::Xlsx, plan, run_ref)
        .expect("pipeline runs")
    {
        EditOutcome::Proposed(proposal) => proposal,
        EditOutcome::Rejected { report, .. } => {
            panic!("expected a proposal, got rejection: {report:?}")
        }
    }
}

// -- Acceptance test 1 ------------------------------------------------------

#[test]
fn round_trip_preserves_untouched_xml_byte_for_byte() {
    let input = xlsx_bytes(&base_parts());
    let original_unknown = opc::read(&input)
        .unwrap()
        .part(UNKNOWN_PART)
        .unwrap()
        .to_vec();

    let plan = EditPlan::new(vec![set_a1(10.0)]);
    let proposal = propose(
        &FixtureSession::faithful(),
        &input,
        &plan,
        "run:passthrough",
    );

    let after = opc::read(&proposal.new_bytes).unwrap();
    assert_eq!(
        after.part(UNKNOWN_PART),
        Some(original_unknown.as_slice()),
        "the unknown custom-XML part must survive byte-for-byte"
    );
    assert!(proposal.manifest.touched_parts.contains(SHEET_PART));
    assert!(!proposal.manifest.touched_parts.contains(UNKNOWN_PART));
    assert!(proposal.validation.ok);
}

// -- Acceptance test 2 ------------------------------------------------------

#[test]
fn manifest_exactly_describes_applied_ops() {
    let input = xlsx_bytes(&base_parts());
    let ops = vec![
        set_a1(10.0),
        EditOp::InsertRows {
            sheet: "Sheet1".to_owned(),
            at: 2,
            count: 1,
        },
    ];
    let plan = EditPlan::new(ops.clone());
    let proposal = propose(&FixtureSession::faithful(), &input, &plan, "run:manifest");

    // No phantom ops, no missing ops.
    assert_eq!(proposal.manifest.ops, ops);
    // The structural op yields exactly one anchor effect for ARTL-2 replay.
    assert_eq!(
        proposal.manifest.anchor_effects(),
        vec![AnchorEffect::Shift(StructuralShift {
            sheet: "Sheet1".to_owned(),
            axis: Axis::Row,
            at: 2,
            delta: 1,
        })]
    );
    // The value write contributes no anchor shift.
    assert_eq!(proposal.manifest.anchor_effects().len(), 1);
    assert_eq!(proposal.manifest.render_diff().len(), 2);
}

// -- Acceptance test 3 ------------------------------------------------------

#[test]
fn heavy_pivot_fixture_triggers_minimal_mutation_warn() {
    let input = xlsx_bytes(&pivot_parts());
    let plan = EditPlan::new(vec![set_a1(10.0)]);
    let proposal = propose(&FixtureSession::faithful(), &input, &plan, "run:pivot");

    assert!(proposal.inspection.has_pivots);
    assert_eq!(proposal.manifest.mutation_mode, MutationMode::Minimal);
    assert!(
        proposal
            .manifest
            .warnings
            .iter()
            .any(|w| w.code == WarningCode::HeavyPivotMinimalMutation),
        "a heavy-pivot workbook must warn: {:?}",
        proposal.manifest.warnings
    );
    // The pivot part is unknown and must have passed through untouched.
    assert!(
        !proposal
            .manifest
            .touched_parts
            .contains("xl/pivotTables/pivotTable1.xml")
    );
}

// -- Acceptance test 4 ------------------------------------------------------

#[test]
fn recalc_stage_updates_cached_values_via_seam() {
    struct FormulaSession;

    impl EditSession for FormulaSession {
        fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
            FixtureSession::faithful().apply_edits(doc, plan)
        }

        fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
            let mut pkg = opc::read(&doc.bytes)?;
            let sheet = String::from_utf8_lossy(pkg.part(SHEET_PART).unwrap()).replace(
                "<c r=\"B1\"><f>A1*2</f><v>10</v></c>",
                "<c r=\"B1\"><f>A1*2</f><v>20</v></c>",
            );
            pkg.upsert(SHEET_PART, sheet.into_bytes());
            Ok(opc::write(&pkg))
        }
        fn recalc_engine(&self) -> Option<crate::blob_artifact::CalcEngineStamp> {
            Some(crate::blob_artifact::CalcEngineStamp::new("formula-fixture", "1.0").unwrap())
        }
    }

    let mut parts = base_parts();
    for (name, data) in &mut parts {
        if *name == SHEET_PART {
            *data = b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><v>5</v></c><c r=\"B1\"><f>A1*2</f><v>10</v></c></row></sheetData></worksheet>";
        }
    }
    let input = xlsx_bytes(&parts);
    let plan = EditPlan::new(vec![set_a1(10.0)]);

    let proposal = match run_edit_roundtrip(
        &FormulaSession,
        &input,
        OfficeFormat::Xlsx,
        &plan,
        "run:recalc",
    )
    .expect("pipeline runs")
    {
        EditOutcome::Proposed(proposal) => proposal,
        EditOutcome::Rejected { report, .. } => {
            panic!("expected a proposal, got rejection: {report:?}")
        }
    };
    assert_eq!(proposal.recalc, RecalcStatus::Performed);
    let package = opc::read(&proposal.new_bytes).unwrap();
    let sheet = String::from_utf8_lossy(package.part(SHEET_PART).unwrap());
    let cell = sheet
        .split("<c r=\"B1\">")
        .nth(1)
        .expect("formula cell is present")
        .split("</c>")
        .next()
        .unwrap();
    let cached = cell
        .split("<v>")
        .nth(1)
        .expect("formula has a cached value")
        .split("</v>")
        .next()
        .unwrap()
        .parse::<f64>()
        .expect("cached value is numeric");
    assert_eq!(cached, 20.0);

    // A session image without a recalc backend must refuse a value-affecting
    // edit: proposing with stale cached formula values would be silent
    // corruption, so the round-trip fails closed instead.
    let no_recalc = FixtureSession {
        mode: MockMode::Faithful,
        supports_recalc: false,
    };
    let err = run_edit_roundtrip(
        &no_recalc,
        &input,
        OfficeFormat::Xlsx,
        &plan,
        "run:no-recalc",
    )
    .expect_err("recalc-incapable session must refuse a value-affecting edit");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::EditRoundtripFailed(_))
    ));

    // But when nothing needs recalc, the same session proposes normally.
    let add_sheet = EditPlan::new(vec![EditOp::AddSheet {
        name: "Extra".to_owned(),
    }]);
    let proposal = propose(&no_recalc, &input, &add_sheet, "run:no-recalc-notneeded");
    assert_eq!(proposal.recalc, RecalcStatus::NotNeeded);
}

// -- Acceptance test 5 ------------------------------------------------------

#[test]
fn corruption_gate_blocks_broken_output_from_proposal() {
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![set_a1(10.0)]);

    // A gutted package (missing [Content_Types].xml) is rejected pre-proposal.
    let dropped = FixtureSession {
        mode: MockMode::DropContentTypes,
        supports_recalc: true,
    };
    let outcome =
        run_edit_roundtrip(&dropped, &input, OfficeFormat::Xlsx, &plan, "run:gut").unwrap();
    let EditOutcome::Rejected { report, .. } = outcome else {
        panic!("gutted output must be rejected, never proposed");
    };
    assert!(!report.ok);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "content_types_present" && !c.passed)
    );

    // A tampered unknown part is a passthrough violation.
    let tampered = FixtureSession {
        mode: MockMode::MutateUnknown,
        supports_recalc: true,
    };
    let outcome =
        run_edit_roundtrip(&tampered, &input, OfficeFormat::Xlsx, &plan, "run:tamper").unwrap();
    let EditOutcome::Rejected { report, .. } = outcome else {
        panic!("passthrough violation must be rejected");
    };
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "passthrough_unknown_parts" && !c.passed)
    );
}

#[test]
fn xlookup_write_is_prefixed_before_the_session_serializes_it() {
    struct FormulaWriteSession;
    impl EditSession for FormulaWriteSession {
        fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
            let EditOp::SetCell {
                after: CellValue::Formula { expr, .. },
                ..
            } = &plan.ops[0]
            else {
                panic!("expected formula write");
            };
            let mut pkg = opc::read(&doc.bytes)?;
            pkg.upsert(SHEET_PART, format!("<worksheet><sheetData><row r=\"1\"><c r=\"B1\"><f>{expr}</f><v>42</v></c></row></sheetData></worksheet>").into_bytes());
            Ok(AppliedEdit {
                bytes: opc::write(&pkg),
                applied_ops: plan.ops.clone(),
                warnings: vec![],
            })
        }
        fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
            Ok(doc.bytes.clone())
        }
        fn recalc_engine(&self) -> Option<crate::blob_artifact::CalcEngineStamp> {
            Some(crate::blob_artifact::CalcEngineStamp::new("test-calc", "1.2").unwrap())
        }
    }
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![EditOp::SetCell {
        sheet: "Sheet1".into(),
        cell: CellRef::new(2, 1),
        before: None,
        after: CellValue::Formula {
            expr: "XLOOKUP(A1,A2:A3,B2:B3)+SUM(1,2)".into(),
            cached: None,
        },
    }]);
    let outcome = run_edit_roundtrip(
        &FormulaWriteSession,
        &input,
        OfficeFormat::Xlsx,
        &plan,
        "run:xlookup",
    )
    .unwrap();
    let EditOutcome::Proposed(proposal) = outcome else {
        panic!("formula should propose")
    };
    let after = opc::read(&proposal.new_bytes).unwrap();
    assert!(
        String::from_utf8_lossy(after.part(SHEET_PART).unwrap())
            .contains("<f>_xlfn.XLOOKUP(A1,A2:A3,B2:B3)+SUM(1,2)</f>")
    );
    assert_eq!(proposal.calc_engine.as_ref().unwrap().engine(), "test-calc");
    assert_eq!(proposal.calc_engine.as_ref().unwrap().version(), "1.2");
}

#[test]
fn recalculation_without_engine_identity_cannot_be_proposed() {
    struct UnstampedSession;
    impl EditSession for UnstampedSession {
        fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
            FixtureSession::faithful().apply_edits(doc, plan)
        }
        fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
            FixtureSession::faithful().recalc(doc)
        }
    }
    let err = run_edit_roundtrip(
        &UnstampedSession,
        &xlsx_bytes(&base_parts()),
        OfficeFormat::Xlsx,
        &EditPlan::new(vec![set_a1(10.0)]),
        "run:unstamped",
    )
    .expect_err("a recalc that cannot identify its engine must not propose");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::EditRoundtripFailed(_))
    ));
}

#[test]
fn session_cannot_strip_modern_function_prefix_after_serialization() {
    let before = opc::read(&xlsx_bytes(&base_parts())).unwrap();
    let mut after = before.clone();
    after.upsert(SHEET_PART, b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><f>XLOOKUP(A1,A2:A3,B2:B3)</f><v>42</v></c></row></sheetData></worksheet>".to_vec());
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "modern_functions_prefixed" && !c.passed)
    );
}

#[test]
fn external_workbook_link_must_survive_session_edit() {
    let mut parts = base_parts();
    parts.push(("xl/_rels/workbook.xml.rels", b"<Relationships><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink\" Target=\"externalLinks/externalLink1.xml\"/></Relationships>"));
    parts.push(("xl/externalLinks/externalLink1.xml", b"<externalLink/>"));
    parts.push(("xl/externalLinks/_rels/externalLink1.xml.rels", b"<Relationships><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath\" Target=\"file:///source.xlsx\" TargetMode=\"External\"/></Relationships>"));
    parts[0].1 = b"<Types><Override PartName=\"/xl/externalLinks/externalLink1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml\"/></Types>";
    parts[1].1 = b"<workbook xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><externalReferences><externalReference r:id=\"rId2\"/></externalReferences></workbook>";
    let input = xlsx_bytes(&parts);
    let before = opc::read(&input).unwrap();
    let proposal = propose(
        &FixtureSession::faithful(),
        &input,
        &EditPlan::new(vec![set_a1(10.0)]),
        "run:linked",
    );
    let edited = opc::read(&proposal.new_bytes).unwrap();
    for name in [
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/externalLinks/externalLink1.xml",
        "xl/externalLinks/_rels/externalLink1.xml.rels",
    ] {
        assert_eq!(
            edited.part(name),
            before.part(name),
            "link part {name} changed"
        );
    }
    assert!(proposal.validation.ok);
    let mut dropped_rel = before.clone();
    dropped_rel.upsert("xl/_rels/workbook.xml.rels", b"<Relationships/>".to_vec());
    let report = validate(&before, &dropped_rel, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed)
    );
    let mut dropped_ref = before.clone();
    dropped_ref.upsert("xl/workbook.xml", b"<workbook/>".to_vec());
    let report = validate(&before, &dropped_ref, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed)
    );
    let mut changed_target = before.clone();
    changed_target.upsert("xl/externalLinks/_rels/externalLink1.xml.rels", b"<Relationships><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath\" Target=\"file:///wrong.xlsx\" TargetMode=\"External\"/></Relationships>".to_vec());
    let report = validate(&before, &changed_target, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed)
    );
    let report = validate(&before, &before, OfficeFormat::Xlsx);
    assert!(report.ok);
}

// -- Unit tests -------------------------------------------------------------

#[test]
fn cell_ref_round_trips_a1_notation() {
    for (text, col, row) in [
        ("A1", 1, 1),
        ("Z9", 26, 9),
        ("AA10", 27, 10),
        ("AB100", 28, 100),
    ] {
        let parsed = CellRef::parse(text).unwrap();
        assert_eq!(parsed, CellRef::new(col, row));
        assert_eq!(parsed.to_a1(), text);
    }
    assert!(CellRef::parse("1A").is_err());
    assert!(CellRef::parse("A0").is_err());
    assert!(CellRef::parse("AB").is_err());
    assert_eq!(RangeRef::parse("A1:B2").unwrap().to_a1(), "A1:B2");
    assert!(RangeRef::parse("A1B2").is_err());
}

#[test]
fn manifest_round_trips_through_msgpack() {
    let manifest = EditManifest {
        schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
        format: OfficeFormat::Xlsx,
        ops: vec![
            set_a1(3.5),
            EditOp::AddFormulaColumn {
                sheet: "Sheet1".to_owned(),
                column: 4,
                header: Some("Total".to_owned()),
                formula: "A{row}*B{row}".to_owned(),
            },
            EditOp::MoveRange {
                sheet: "Sheet1".to_owned(),
                from: RangeRef::parse("A1:B2").unwrap(),
                to: CellRef::new(4, 1),
            },
        ],
        touched_parts: ["xl/worksheets/sheet1.xml".to_owned()]
            .into_iter()
            .collect(),
        mutation_mode: MutationMode::Full,
        warnings: vec![EditWarning::new(WarningCode::SessionReported, "note")],
    };
    let bytes = manifest.to_msgpack().unwrap();
    let decoded = EditManifest::from_msgpack(&bytes).unwrap();
    assert_eq!(decoded, manifest);
}

#[test]
fn office_format_maps_known_media_types() {
    assert_eq!(
        OfficeFormat::from_media_type(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        .unwrap(),
        OfficeFormat::Xlsx
    );
    assert_eq!(
        OfficeFormat::from_media_type("application/vnd.ms-excel.sheet.macroEnabled.12").unwrap(),
        OfficeFormat::Xlsx
    );
    assert!(OfficeFormat::from_media_type("text/plain").is_err());
}

#[test]
fn inspect_detects_cross_sheet_dependency() {
    let parts: Vec<(&str, &[u8])> = vec![
        (opc::CONTENT_TYPES_PART, b"<Types/>"),
        (
            "xl/workbook.xml",
            b"<workbook><sheets><sheet name=\"Sheet1\" sheetId=\"1\"/><sheet name=\"Sheet2\" sheetId=\"2\"/></sheets></workbook>",
        ),
        (
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><f>Sheet2!A1+1</f><v>2</v></c></row></sheetData></worksheet>",
        ),
        (
            "xl/worksheets/sheet2.xml",
            b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><v>1</v></c></row></sheetData></worksheet>",
        ),
    ];
    let pkg = opc::read(&xlsx_bytes(&parts)).unwrap();
    let summary = inspect(&pkg, OfficeFormat::Xlsx);
    assert_eq!(
        summary.sheets,
        vec![
            SheetSummary {
                name: "Sheet1".to_owned(),
                index: 1
            },
            SheetSummary {
                name: "Sheet2".to_owned(),
                index: 2
            },
        ]
    );
    assert_eq!(
        summary.cross_sheet_dependencies,
        vec![CrossSheetDep {
            from_sheet: "Sheet1".to_owned(),
            to_sheet: "Sheet2".to_owned(),
        }]
    );
    assert!(!summary.has_pivots && !summary.has_macros);
}

#[test]
fn empty_run_ref_is_rejected() {
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![set_a1(10.0)]);
    let err = run_edit_roundtrip(
        &FixtureSession::faithful(),
        &input,
        OfficeFormat::Xlsx,
        &plan,
        "   ",
    )
    .expect_err("blank run_ref must fail");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::EditRoundtripFailed(_))
    ));
}

#[test]
fn agent_run_provenance_carries_run_ref() {
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![set_a1(10.0)]);
    let proposal = propose(&FixtureSession::faithful(), &input, &plan, "run:prov#7");
    assert_eq!(
        proposal.agent_run_provenance(),
        BlobVersionProvenance::AgentRun {
            run_ref: "run:prov#7".to_owned(),
        }
    );
}

// -- Format gating (docx/pptx) ----------------------------------------------

#[test]
fn docx_and_pptx_are_refused_at_the_pipeline() {
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![set_a1(10.0)]);
    for format in [OfficeFormat::Docx, OfficeFormat::Pptx] {
        let err = run_edit_roundtrip(
            &FixtureSession::faithful(),
            &input,
            format,
            &plan,
            "run:doc",
        )
        .expect_err("non-spreadsheet formats are unsupported");
        assert!(
            matches!(err, Error::Artifact(ArtifactError::InvalidEditManifest(_))),
            "expected InvalidEditManifest, got {err:?}"
        );
    }
}

// -- 1-based address validation ---------------------------------------------

#[test]
fn zero_index_cell_is_rejected() {
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![EditOp::SetCell {
        sheet: "Sheet1".to_owned(),
        cell: CellRef::new(0, 1),
        before: None,
        after: CellValue::Number(1.0),
    }]);
    let err = run_edit_roundtrip(
        &FixtureSession::faithful(),
        &input,
        OfficeFormat::Xlsx,
        &plan,
        "run:badcell",
    )
    .expect_err("a 0 column must be rejected");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidEditManifest(_))
    ));
}

#[test]
fn inverted_range_is_rejected() {
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![EditOp::SetRange {
        sheet: "Sheet1".to_owned(),
        range: RangeRef::new(CellRef::new(3, 3), CellRef::new(1, 1)),
        writes: Vec::new(),
    }]);
    let err = run_edit_roundtrip(
        &FixtureSession::faithful(),
        &input,
        OfficeFormat::Xlsx,
        &plan,
        "run:inverted",
    )
    .expect_err("an inverted range must be rejected");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidEditManifest(_))
    ));
}

// -- Cross-sheet scan: rels-resolved names + shared formulas ----------------

#[test]
fn cross_sheet_scan_resolves_names_via_workbook_rels() {
    // The workbook lists Summary (rId1) then Data (rId2), but rId1 targets
    // sheet2.xml and rId2 targets sheet1.xml — so the positional heuristic
    // would mislabel them. Only the rels join yields the right names. The
    // dependency also lives inside a shared-formula element (`<f t="shared">`).
    let parts: Vec<(&str, &[u8])> = vec![
        (opc::CONTENT_TYPES_PART, b"<Types/>" as &[u8]),
        (
            "xl/workbook.xml",
            b"<workbook><sheets><sheet name=\"Summary\" sheetId=\"1\" r:id=\"rId1\"/><sheet name=\"Data\" sheetId=\"2\" r:id=\"rId2\"/></sheets></workbook>",
        ),
        (
            "xl/_rels/workbook.xml.rels",
            b"<Relationships><Relationship Id=\"rId1\" Target=\"worksheets/sheet2.xml\"/><Relationship Id=\"rId2\" Target=\"worksheets/sheet1.xml\"/></Relationships>",
        ),
        (
            "xl/worksheets/sheet2.xml",
            b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><f t=\"shared\" ref=\"A1:A2\" si=\"0\">Data!A1+1</f><v>2</v></c></row></sheetData></worksheet>",
        ),
        (
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\"><v>1</v></c></row></sheetData></worksheet>",
        ),
    ];
    let pkg = opc::read(&xlsx_bytes(&parts)).unwrap();
    let summary = inspect(&pkg, OfficeFormat::Xlsx);
    assert_eq!(
        summary.cross_sheet_dependencies,
        vec![CrossSheetDep {
            from_sheet: "Summary".to_owned(),
            to_sheet: "Data".to_owned(),
        }]
    );
}

// -- Referential-integrity gate ---------------------------------------------

#[test]
fn resolve_part_path_collapses_relative_segments() {
    for (rels_part, target, expected_ok) in [
        ("xl/_rels/workbook.xml.rels", "worksheets/sheet1.xml", true),
        (
            "xl/worksheets/_rels/sheet1.xml.rels",
            "../drawings/drawing1.xml",
            true,
        ),
        ("xl/_rels/workbook.xml.rels", "/docProps/core.xml", true),
        ("xl/_rels/workbook.xml.rels", "../../..", false),
    ] {
        let mut package = opc::read(&xlsx_bytes(&base_parts())).unwrap();
        package.upsert("xl/drawings/drawing1.xml", b"<drawing/>".to_vec());
        package.upsert("docProps/core.xml", b"<coreProperties/>".to_vec());
        package.upsert(
            rels_part,
            format!(
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing\" Target=\"{target}\"/></Relationships>",
            )
            .into_bytes(),
        );

        // Identical packages preserve every part; only the relationship's
        // ability to resolve to an existing package part varies here.
        let report = validate(&package, &package, OfficeFormat::Xlsx);
        assert_eq!(report.ok, expected_ok, "relationship target: {target}");
    }
}

#[test]
fn referential_integrity_gate_flags_dropped_referenced_part() {
    let rels = b"<Relationships><Relationship Id=\"rId1\" Target=\"worksheets/sheet1.xml\"/></Relationships>" as &[u8];
    let full: Vec<(&str, &[u8])> = vec![
        (opc::CONTENT_TYPES_PART, b"<Types/>" as &[u8]),
        ("xl/workbook.xml", b"<workbook/>"),
        ("xl/_rels/workbook.xml.rels", rels),
        ("xl/worksheets/sheet1.xml", b"<worksheet/>"),
    ];
    let before = opc::read(&xlsx_bytes(&full)).unwrap();
    // Output keeps the rels but drops the worksheet it points at.
    let dropped: Vec<(&str, &[u8])> = vec![
        (opc::CONTENT_TYPES_PART, b"<Types/>" as &[u8]),
        ("xl/workbook.xml", b"<workbook/>"),
        ("xl/_rels/workbook.xml.rels", rels),
    ];
    let after = opc::read(&xlsx_bytes(&dropped)).unwrap();

    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(!report.ok);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "referential_integrity" && !c.passed),
        "a dangling .rels target must fail the referential-integrity check: {report:?}"
    );

    // The intact package passes the same gate.
    let intact = validate(&before, &before, OfficeFormat::Xlsx);
    assert!(
        intact
            .checks
            .iter()
            .any(|c| c.name == "referential_integrity" && c.passed)
    );
}

#[test]
fn referential_integrity_gate_flags_missing_content_type_override() {
    let content_types =
        b"<Types><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"x\"/></Types>"
            as &[u8];
    let after = opc::read(&xlsx_bytes(&[
        (opc::CONTENT_TYPES_PART, content_types),
        ("xl/workbook.xml", b"<workbook/>" as &[u8]),
    ]))
    .unwrap();
    let report = validate(&after, &after, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "referential_integrity" && !c.passed),
        "an override naming a missing part must fail: {report:?}"
    );
}

// -- Minimal-mutation structural-op refusal ---------------------------------

#[test]
fn minimal_mutation_mode_refuses_structural_ops() {
    // A pivot workbook forces minimal-mutation mode; an InsertRows there would
    // leave the preserved pivot part stale against a shifted grid.
    let input = xlsx_bytes(&pivot_parts());
    let structural = EditPlan::new(vec![EditOp::InsertRows {
        sheet: "Sheet1".to_owned(),
        at: 2,
        count: 1,
    }]);
    let err = run_edit_roundtrip(
        &FixtureSession::faithful(),
        &input,
        OfficeFormat::Xlsx,
        &structural,
        "run:struct",
    )
    .expect_err("structural op in minimal mode must be refused");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidEditManifest(_))
    ));

    // A cell-level op on the same pivot workbook is still allowed.
    let cell = EditPlan::new(vec![set_a1(10.0)]);
    let proposal = propose(&FixtureSession::faithful(), &input, &cell, "run:cell-ok");
    assert_eq!(proposal.manifest.mutation_mode, MutationMode::Minimal);
}

// A real openpyxl 3.1.5 load_workbook(keep_links=True, data_only=False)
// B1 edit/save pair. The target spelling changes to /xl/..., but resolves to
// the same link part; no external link bytes or workbook references are lost.
#[test]
fn real_openpyxl_link_roundtrip_accepts_equivalent_target() {
    let before = opc::read(include_bytes!("fixtures/linked-before.xlsx")).unwrap();
    let after = opc::read(include_bytes!("fixtures/linked-after.xlsx")).unwrap();
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(report.ok, "{report:?}");
    assert_eq!(
        before.part("xl/externalLinks/externalLink1.xml"),
        after.part("xl/externalLinks/externalLink1.xml")
    );
}

#[test]
fn link_gate_rejects_removed_single_quoted_or_prefixed_reference() {
    let before = opc::read(include_bytes!("fixtures/linked-before.xlsx")).unwrap();
    let original = String::from_utf8(before.part("xl/workbook.xml").unwrap().to_vec()).unwrap();
    let mut single = before.clone();
    single.upsert("xl/workbook.xml", original.replace('"', "'").into_bytes());
    let mut dropped = single.clone();
    let workbook = String::from_utf8(single.part("xl/workbook.xml").unwrap().to_vec()).unwrap();
    let start = workbook.find("<externalReferences>").unwrap();
    let end = workbook.find("</externalReferences>").unwrap() + "</externalReferences>".len();
    dropped.upsert(
        "xl/workbook.xml",
        format!("{}{}", &workbook[..start], &workbook[end..]).into_bytes(),
    );
    assert!(validate(&single, &single, OfficeFormat::Xlsx).ok);
    let report = validate(&single, &dropped, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed),
        "{report:?}"
    );

    let mut prefixed = before;
    prefixed.upsert("xl/workbook.xml", b"<x:workbook xmlns:x=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><x:externalReferences><x:externalReference r:id=\"rId2\"/></x:externalReferences></x:workbook>".to_vec());
    let mut dropped = prefixed.clone();
    dropped.upsert(
        "xl/workbook.xml",
        b"<x:workbook xmlns:x=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"/>"
            .to_vec(),
    );
    assert!(validate(&prefixed, &prefixed, OfficeFormat::Xlsx).ok);
    let report = validate(&prefixed, &dropped, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed),
        "{report:?}"
    );
}

#[test]
fn link_gate_rejects_lost_or_changed_content_type() {
    let before = opc::read(include_bytes!("fixtures/linked-before.xlsx")).unwrap();
    let types = String::from_utf8(before.part(opc::CONTENT_TYPES_PART).unwrap().to_vec()).unwrap();
    let mut after = before.clone();
    let override_start = types
        .find("<Override PartName=\"/xl/externalLinks/externalLink1.xml\"")
        .or_else(|| {
            types
                .find("PartName=\"/xl/externalLinks/externalLink1.xml\"")
                .and_then(|i| types[..i].rfind("<Override"))
        })
        .unwrap();
    let override_end = override_start + types[override_start..].find("/>").unwrap() + 2;
    after.upsert(
        opc::CONTENT_TYPES_PART,
        format!("{}{}", &types[..override_start], &types[override_end..]).into_bytes(),
    );
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed),
        "{report:?}"
    );
    let mut changed = before.clone();
    changed.upsert(
        opc::CONTENT_TYPES_PART,
        types
            .replace(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml",
                "application/xml",
            )
            .into_bytes(),
    );
    let report = validate(&before, &changed, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed),
        "{report:?}"
    );
}

#[test]
fn formula_gate_reads_xml_decoded_literals_and_prefixed_elements() {
    let before = opc::read(&xlsx_bytes(&base_parts())).unwrap();
    let mut after = before.clone();
    after.upsert(SHEET_PART, b"<x:worksheet xmlns:x=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><x:sheetData><x:row><x:c><x:f>&quot;XLOOKUP(&quot;</x:f></x:c></x:row></x:sheetData></x:worksheet>".to_vec());
    assert_eq!(
        super::xml::formulas(std::str::from_utf8(after.part(SHEET_PART).unwrap()).unwrap())
            .unwrap(),
        vec!["\"XLOOKUP(\""]
    );
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(report.ok, "{report:?}");
    after.upsert(SHEET_PART, b"<x:worksheet xmlns:x=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><x:f>XLOOKUP(A1,A2:A3,B2:B3)</x:f></x:worksheet>".to_vec());
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "modern_functions_prefixed" && !c.passed),
        "{report:?}"
    );
}

#[test]
fn structured_header_stays_unmodified_across_each_formula_write_verb() {
    let expr = "SUM(Table1[XLOOKUP(foo)])";
    let set_cell = EditOp::SetCell {
        sheet: "Sheet1".into(),
        cell: CellRef::new(2, 1),
        before: None,
        after: CellValue::Formula {
            expr: expr.into(),
            cached: None,
        },
    };
    let set_range = EditOp::SetRange {
        sheet: "Sheet1".into(),
        range: RangeRef::new(CellRef::new(2, 1), CellRef::new(2, 1)),
        writes: vec![CellWrite {
            cell: CellRef::new(2, 1),
            before: None,
            after: CellValue::Formula {
                expr: expr.into(),
                cached: None,
            },
        }],
    };
    let column = EditOp::AddFormulaColumn {
        sheet: "Sheet1".into(),
        column: 3,
        header: None,
        formula: expr.into(),
    };
    let serialized = super::formula::serialize_plan(&EditPlan::new(vec![
        set_cell.clone(),
        set_range.clone(),
        column.clone(),
    ]));
    assert_eq!(serialized.ops, vec![set_cell, set_range, column]);
}

#[test]
fn formula_gate_rejects_partial_filter_qualifier_and_missing_randarray() {
    let before = opc::read(&xlsx_bytes(&base_parts())).unwrap();
    for expr in ["_xlfn.FILTER(A1:A2,A1:A2&gt;0)", "RANDARRAY(2,2)"] {
        let mut after = before.clone();
        after.upsert(
            SHEET_PART,
            format!("<worksheet><f>{expr}</f></worksheet>").into_bytes(),
        );
        let report = validate(&before, &after, OfficeFormat::Xlsx);
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == "modern_functions_prefixed" && !c.passed),
            "{expr}: {report:?}"
        );
    }
}

#[test]
fn public_vault_and_raw_proposal_paths_preserve_calculator_at_settle() -> Result<()> {
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::edge::EdgeActorClass;
    use crate::edit_settle::SettleConsent;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::write_envelope::WriteActor;

    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let time = |start| TimeRange { start, end: start };
    let actor_id = crate::entity_id::EntityId::now();
    vault.put_entity(&actor_id, ENTITY_TYPE_PERSON, time(10), 10, b"editor")?;
    let actor = WriteActor::new(actor_id, EdgeActorClass::Human);
    let artifact = crate::entity_id::EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new(
            "sheet.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        time(10),
        10,
    )?;
    vault.append_blob_artifact_version(
        &artifact,
        &xlsx_bytes(&base_parts()),
        &BlobVersionProvenance::UserUpload,
        actor,
        time(10),
        10,
    )?;
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let session = FixtureSession::faithful();

    // The Vault wrapper binds the head and reports the performed recalc.
    let EditOutcome::Proposed(calculated) = vault.propose_blob_artifact_edit(
        &artifact,
        &session,
        &EditPlan::new(vec![set_a1(10.0)]),
        "run:calculated",
    )?
    else {
        panic!("expected calculated proposal")
    };
    let computed = vault
        .settle_select_edit_proposal(&artifact, &calculated, &consent, actor, time(11), 11)?
        .version;
    assert_eq!(
        computed.calc_engine.as_ref().unwrap().engine(),
        "fixture-calc"
    );

    // The public raw path has no artifact context. AddSheet does not recalc;
    // settlement binds it to the head and keeps the head calculator stamp.
    let head_bytes = vault
        .read_blob_artifact_version(&artifact, computed.version)?
        .unwrap();
    let EditOutcome::Proposed(raw) = run_edit_roundtrip(
        &session,
        &head_bytes,
        OfficeFormat::Xlsx,
        &EditPlan::new(vec![EditOp::AddSheet {
            name: "Extra".into(),
        }]),
        "run:raw",
    )?
    else {
        panic!("expected raw proposal")
    };
    assert_eq!(raw.recalc, RecalcStatus::NotNeeded);
    assert!(raw.calc_engine.is_none());
    let settled = vault
        .settle_select_edit_proposal(&artifact, &raw, &consent, actor, time(12), 12)?
        .version;
    assert_eq!(settled.calc_engine, computed.calc_engine);
    assert_eq!(
        vault.blob_artifact_version_metadata(&artifact, settled.version)?,
        Some(settled)
    );
    Ok(())
}

// openpyxl 3.1.5 load_workbook(keep_links=True, data_only=False),
// create_sheet("Extra"), save: workbook r:id and matching relationship Id
// both change rId2 -> rId3 while the external link still resolves unchanged.
#[test]
fn real_openpyxl_add_sheet_keeps_the_ordered_link_join() {
    let before = opc::read(include_bytes!("fixtures/linked-before.xlsx")).unwrap();
    let after = opc::read(include_bytes!("fixtures/linked-add-sheet.xlsx")).unwrap();
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(
        report.ok,
        "valid AddSheet save must retain its external link: {report:?}"
    );
    for part in [
        "xl/externalLinks/externalLink1.xml",
        "xl/externalLinks/_rels/externalLink1.xml.rels",
    ] {
        assert_eq!(before.part(part), after.part(part));
    }
}

#[test]
fn renumbered_link_ids_are_equivalent_only_when_both_sides_join() {
    let before = opc::read(include_bytes!("fixtures/linked-before.xlsx")).unwrap();
    let mut after = before.clone();
    let wb = String::from_utf8(before.part("xl/workbook.xml").unwrap().to_vec()).unwrap();
    let rels =
        String::from_utf8(before.part("xl/_rels/workbook.xml.rels").unwrap().to_vec()).unwrap();
    after.upsert("xl/workbook.xml", wb.replace("rId2", "rId3").into_bytes());
    after.upsert(
        "xl/_rels/workbook.xml.rels",
        rels.replace("rId2", "rId3").into_bytes(),
    );
    assert!(validate(&before, &after, OfficeFormat::Xlsx).ok);
    after.upsert("xl/_rels/workbook.xml.rels", rels.into_bytes());
    let report = validate(&before, &after, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed),
        "broken join must still fail: {report:?}"
    );
}

#[test]
fn omitted_and_explicit_internal_modes_are_equivalent_but_external_refuses() {
    let before = opc::read(include_bytes!("fixtures/linked-before.xlsx")).unwrap();
    let rels =
        String::from_utf8(before.part("xl/_rels/workbook.xml.rels").unwrap().to_vec()).unwrap();
    let mut explicit = before.clone();
    explicit.upsert(
        "xl/_rels/workbook.xml.rels",
        rels.replace(
            "Target=\"externalLinks/externalLink1.xml\"",
            "TargetMode=\"Internal\" Target=\"externalLinks/externalLink1.xml\"",
        )
        .into_bytes(),
    );
    assert_ne!(
        explicit.part("xl/_rels/workbook.xml.rels"),
        before.part("xl/_rels/workbook.xml.rels")
    );
    assert!(validate(&explicit, &explicit, OfficeFormat::Xlsx).ok);
    assert!(validate(&before, &explicit, OfficeFormat::Xlsx).ok);
    assert!(validate(&explicit, &before, OfficeFormat::Xlsx).ok);
    let mut invalid = before.clone();
    invalid.upsert(
        "xl/_rels/workbook.xml.rels",
        rels.replace(
            "Target=\"externalLinks/externalLink1.xml\"",
            "TargetMode=\"External\" Target=\"externalLinks/externalLink1.xml\"",
        )
        .into_bytes(),
    );
    let report = validate(&before, &invalid, OfficeFormat::Xlsx);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "external_links_preserved" && !c.passed),
        "external mode must still fail: {report:?}"
    );
}
