//! ARTL-3 pipeline tests. The [`FixtureSession`] stands in for the microVM
//! openpyxl/LibreOffice binaries so the full gate runs in CI without them.

use super::opc::{self, OpcPackage, OpcPart};
use super::*;

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
    let input = xlsx_bytes(&base_parts());
    let plan = EditPlan::new(vec![set_a1(10.0)]);

    let proposal = propose(&FixtureSession::faithful(), &input, &plan, "run:recalc");
    assert_eq!(proposal.recalc, RecalcStatus::Performed);
    let sheet = opc::read(&proposal.new_bytes)
        .unwrap()
        .part(SHEET_PART)
        .unwrap()
        .to_vec();
    assert!(
        String::from_utf8_lossy(&sheet).contains("recalc:cached=42"),
        "recalc must refresh the cached value through the seam"
    );

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
    assert!(matches!(err, Error::EditRoundtripFailed(_)));

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
    assert!(matches!(err, Error::EditRoundtripFailed(_)));
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
            matches!(err, Error::InvalidEditManifest(_)),
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
    assert!(matches!(err, Error::InvalidEditManifest(_)));
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
    assert!(matches!(err, Error::InvalidEditManifest(_)));
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
    assert_eq!(
        resolve_part_path("xl/", "worksheets/sheet1.xml").as_deref(),
        Some("xl/worksheets/sheet1.xml")
    );
    assert_eq!(
        resolve_part_path("xl/worksheets/", "../drawings/drawing1.xml").as_deref(),
        Some("xl/drawings/drawing1.xml")
    );
    assert_eq!(
        resolve_part_path("xl/", "/docProps/core.xml").as_deref(),
        Some("docProps/core.xml")
    );
    assert_eq!(resolve_part_path("xl/", "../../..").as_deref(), None);
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
    assert!(matches!(err, Error::InvalidEditManifest(_)));

    // A cell-level op on the same pivot workbook is still allowed.
    let cell = EditPlan::new(vec![set_a1(10.0)]);
    let proposal = propose(&FixtureSession::faithful(), &input, &cell, "run:cell-ok");
    assert_eq!(proposal.manifest.mutation_mode, MutationMode::Minimal);
}
