//! Actual XLSX in/out tests of the retained engine. The core's edit round
//! trip, which wraps host sessions in this engine by default, tests the
//! session routing (`crates/oneiron/src/edit_roundtrip/native_recalc_tests.rs`).
use std::io::{Cursor, Read, Write};

use oneiron_docedit::retained_opc::{Limits, Package, XmlLimits};
use oneiron_xlsx_formula::engine::FormualizerEngine;
use oneiron_xlsx_formula::{FormulaError, preserve_external_links};
use proptest::prelude::*;

const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const DOC_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const TYPES: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const SPREADSHEET: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml";
const INPUT: &str = "xl/worksheets/input.xml";
const OUTPUT: &str = "xl/worksheets/result.xml";
const UNKNOWN: &[u8] = b"opaque vendor bytes\0\xff";

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
/// Rebuild `bytes` with `edit` applied to the text of part `name`.
fn edit_part(bytes: &[u8], name: &str, edit: impl FnOnce(String) -> String) -> Vec<u8> {
    with_part(bytes, name, edit(part_text(bytes, name)))
}
fn part(name: &str, data: impl Into<Vec<u8>>) -> (String, Vec<u8>) {
    (name.into(), data.into())
}
fn sheet(cells: &str) -> String {
    format!(
        r#"<worksheet xmlns="{MAIN}" xmlns:u="urn:unknown"><sheetData><row r="1">{cells}</row></sheetData><extLst><u:keep value="unaltered">unmodelled content</u:keep></extLst></worksheet>"#
    )
}
/// An Excel-shaped package: root relationships, content types, `r:id` sheets.
fn fixture(inputs: &str, formulas: &str, date1904: bool) -> Vec<u8> {
    build(&[
        part(
            "[Content_Types].xml",
            format!(
                r#"<Types xmlns="{TYPES}"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="bin" ContentType="application/octet-stream"/><Override PartName="/xl/workbook.xml" ContentType="{SPREADSHEET}.sheet.main+xml"/><Override PartName="/{OUTPUT}" ContentType="{SPREADSHEET}.worksheet+xml"/><Override PartName="/{INPUT}" ContentType="{SPREADSHEET}.worksheet+xml"/></Types>"#
            ),
        ),
        part(
            "_rels/.rels",
            format!(
                r#"<Relationships xmlns="{REL}"><Relationship Id="rId1" Type="{DOC_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>"#
            ),
        ),
        // Formula sheet comes first and references the later-created input sheet.
        part(
            "xl/workbook.xml",
            format!(
                r#"<workbook xmlns="{MAIN}" xmlns:r="{DOC_REL}"><workbookPr date1904="{}"/><sheets><sheet name="Result" sheetId="7" r:id="out"/><sheet name="Input" sheetId="3" r:id="in"/></sheets></workbook>"#,
                u8::from(date1904)
            ),
        ),
        part(
            "xl/_rels/workbook.xml.rels",
            format!(
                r#"<Relationships xmlns="{REL}"><Relationship Id="out" Type="{DOC_REL}/worksheet" Target="worksheets/result.xml"/><Relationship Id="in" Type="{DOC_REL}/worksheet" Target="worksheets/input.xml"/></Relationships>"#
            ),
        ),
        part(INPUT, sheet(inputs)),
        part(OUTPUT, sheet(formulas)),
        part("vendor/opaque.bin", UNKNOWN.to_vec()),
    ])
}
/// `fixture` with `definedNames` added to the workbook part.
fn with_names(bytes: &[u8], names: &str) -> Vec<u8> {
    edit_part(bytes, "xl/workbook.xml", |xml| {
        xml.replace(
            "</sheets>",
            &format!("</sheets><definedNames>{names}</definedNames>"),
        )
    })
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
/// The fallback reason, or a panic when the workbook was not refused to it.
fn fallback(bytes: &[u8]) -> String {
    match recalc(bytes) {
        Err(FormulaError::UnsupportedWorkbook(reason)) => reason.into_owned(),
        other => panic!("expected the precision fallback, got {other:?}"),
    }
}
#[test]
fn scalar_cache_types_and_unknown_xml_survive_the_retained_writer() {
    let cells = r#"<c r="A1" t="str" s="4" u:cell="keep"><f u:f="keep">40+2</f><v u:v="keep">old</v></c><c r="B1"><f>&quot;東京 &amp; &lt;report&gt;&quot;</f><v/></c><c r="C1" t="str"><f>1/0</f><v>old</v></c><c r="D1"><f>TRUE()</f></c>"#;
    let input = fixture("", cells, false);
    let report = recalc(&input).expect("real XLSX recalc");
    assert_eq!(report.formula_count, 4);
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(
        xml.contains(
            r#"<c r="A1"  s="4" u:cell="keep"><f u:f="keep">40+2</f><v u:v="keep">42</v></c>"#
        ),
        "{xml}"
    );
    assert!(xml.contains(r#"<c r="B1" t="str"><f>&quot;東京 &amp; &lt;report&gt;&quot;</f><v>東京 &amp; &lt;report&gt;</v></c>"#), "{xml}");
    assert!(
        xml.contains(r#"<c r="C1" t="e"><f>1/0</f><v>#DIV/0!</v></c>"#),
        "{xml}"
    );
    assert!(
        xml.contains(r#"<c r="D1" t="b"><f>TRUE()</f><v>1</v></c>"#),
        "{xml}"
    );
    assert!(xml.ends_with(
        r#"<extLst><u:keep value="unaltered">unmodelled content</u:keep></extLst></worksheet>"#
    ));
    assert_eq!(
        part_bytes(&report.bytes, "vendor/opaque.bin").as_deref(),
        Some(UNKNOWN)
    );
    let again = recalc(&report.bytes).expect("idempotent recalc");
    assert_eq!(again.bytes, report.bytes);
}

#[test]
fn prefixed_sheet_elements_recalculate_and_unknown_same_name_elements_fall_back() {
    let input = fixture("", "", false);
    let source = |extra: &str| {
        format!(
            r#"<s:worksheet xmlns:s="{MAIN}" xmlns:u="urn:unknown"><s:sheetData><s:row r="1"><s:c r="A1" u:t="not-a-cache-type"><s:f>20+22</s:f><s:v/></s:c>{extra}</s:row></s:sheetData></s:worksheet>"#
        )
    };
    let report = recalc(&with_part(&input, OUTPUT, source(""))).expect("prefixed XML");
    assert_eq!(report.formula_count, 1);
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(
        xml.contains(r#"<s:c r="A1" u:t="not-a-cache-type"><s:f>20+22</s:f><s:v>42</s:v></s:c>"#),
        "{xml}"
    );
    // The writer refuses a lookalike rather than guess which cell it is.
    let lookalike = source(r#"<u:c r="B1"><u:f>unmodelled</u:f></u:c>"#);
    assert!(fallback(&with_part(&input, OUTPUT, lookalike)).contains("lookalike"));
    let foreign_child = sheet(r#"<c r="A1"><f>40+2</f><v>0</v><u:cellExt a="b"/></c>"#);
    assert!(matches!(
        recalc(&with_part(&input, OUTPUT, foreign_child)),
        Err(FormulaError::Engine(_))
    ));
}

#[test]
fn xlookup_is_evaluated_from_its_storage_spelling() {
    let input = fixture(
        r#"<c r="A1"><v>7</v></c><c r="B1" t="inlineStr"><is><t>found</t></is></c>"#,
        r#"<c r="A1"><f u:keep="f">_xlfn.XLOOKUP(7,Input!A1:A1,Input!B1:B1)</f><v/></c>"#,
        false,
    );
    let report = recalc(&input).expect("XLOOKUP");
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(
        xml.contains(r#"<f u:keep="f">_xlfn.XLOOKUP(7,Input!A1:A1,Input!B1:B1)</f><v>found</v>"#),
        "{xml}"
    );
    assert!(xml.contains(r#"<c r="A1" t="str">"#));
}

#[test]
fn an_unprefixed_modern_function_falls_back_rather_than_fail_the_edit_gate() {
    // The writer patches caches, never formula text, and the edit gate
    // requires the OOXML prefix in every worksheet whose bytes change.
    let input = fixture(
        r#"<c r="A1"><v>7</v></c>"#,
        r#"<c r="A1"><f>XLOOKUP(7,Input!A1:A1,Input!A1:A1)</f><v>0</v></c>"#,
        false,
    );
    assert!(fallback(&input).contains("OOXML function prefix"));
}

#[test]
fn package_shared_strings_and_typed_input_errors_reach_the_graph() {
    let bytes = fixture(
        r#"<c r="A1" t="s"><v>0</v></c><c r="B1" t="e"><v>#N/A</v></c>"#,
        r#"<c r="A1"><f>Input!A1&amp;&quot;!&quot;</f><v/></c><c r="B1"><f>IFERROR(Input!B1,7)</f><v/></c>"#,
        false,
    );
    let bytes = edit_part(&bytes, "xl/_rels/workbook.xml.rels", |rels| {
        rels.replace("</Relationships>", &format!(r#"<Relationship Id="strings" Type="{DOC_REL}/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#))
    });
    let bytes = edit_part(&bytes, "[Content_Types].xml", |types| {
        types.replace("</Types>", &format!(r#"<Override PartName="/xl/sharedStrings.xml" ContentType="{SPREADSHEET}.sharedStrings+xml"/></Types>"#))
    });
    let input = with_part(
        &bytes,
        "xl/sharedStrings.xml",
        format!(
            r#"<sst xmlns="{MAIN}"><si><r><t>東</t></r><r><t>京</t></r><rPh><t>ignored phonetics</t></rPh></si></sst>"#
        ),
    );
    let report = recalc(&input).expect("typed inputs");
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(xml.contains("<v>東京!</v>"), "{xml}");
    assert!(xml.contains("<f>IFERROR(Input!B1,7)</f><v>7</v>"), "{xml}");
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
        assert!(
            xml.contains(&format!("<f>DATE(2024,3,15)</f><v>{expected}</v>")),
            "{xml}"
        );
        assert!(xml.contains("<f>TIME(13,30,0)</f><v>0.5625</v>"), "{xml}");
        assert!(xml.contains("<f>Input!A1+1</f><v>61</v>"), "{xml}");
    }
}

/// `Result!A1:A3` repeat one shared formula over the defined name `rate` and
/// the `Prices` table on `Input`; `B1` totals a table column.
fn names_tables_and_shared_formulas() -> Vec<u8> {
    let input = r#"<c r="A1" t="inlineStr"><is><t>Item</t></is></c><c r="B1" t="inlineStr"><is><t>Price</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>tea</t></is></c><c r="B2"><v>3</v></c></row><row r="3"><c r="A3" t="inlineStr"><is><t>cake</t></is></c><c r="B3"><v>5</v></c></row><row r="4"><c r="A4"><v>10</v></c>"#;
    let result = r#"<c r="A1"><f t="shared" ref="A1:A3" si="0">Input!B2*rate</f><v>0</v></c><c r="B1"><f>SUM(Prices[Price])</f><v>0</v></c></row><row r="2"><c r="A2"><f t="shared" si="0"/><v>0</v></c></row><row r="3"><c r="A3"><f t="shared" si="0"/><v>0</v></c>"#;
    let bytes = with_names(
        &fixture(input, result, false),
        r#"<definedName name="rate">Input!$A$4</definedName>"#,
    );
    let bytes = edit_part(&bytes, INPUT, |xml| {
        xml.replace(
            "<extLst>",
            &format!(r#"<tableParts count="1"><tablePart xmlns:r="{DOC_REL}" r:id="t1"/></tableParts><extLst>"#),
        )
    });
    let bytes = with_part(
        &bytes,
        "xl/worksheets/_rels/input.xml.rels",
        format!(
            r#"<Relationships xmlns="{REL}"><Relationship Id="t1" Type="{DOC_REL}/table" Target="../tables/table1.xml"/></Relationships>"#
        ),
    );
    let bytes = edit_part(&bytes, "[Content_Types].xml", |types| {
        types.replace("</Types>", &format!(r#"<Override PartName="/xl/tables/table1.xml" ContentType="{SPREADSHEET}.table+xml"/></Types>"#))
    });
    with_part(
        &bytes,
        "xl/tables/table1.xml",
        format!(
            r#"<table xmlns="{MAIN}" id="1" name="Prices" displayName="Prices" ref="A1:B3"><autoFilter ref="A1:B3"/><tableColumns count="2"><tableColumn id="1" name="Item"/><tableColumn id="2" name="Price"/></tableColumns></table>"#
        ),
    )
}

#[test]
fn shared_formulas_defined_names_and_tables_recalculate_natively() {
    let input = names_tables_and_shared_formulas();
    let report = recalc(&input).expect("native recalc");
    assert_eq!(report.formula_count, 4);
    let xml = part_text(&report.bytes, OUTPUT);
    for expected in [
        r#"<c r="A1"><f t="shared" ref="A1:A3" si="0">Input!B2*rate</f><v>30</v></c>"#,
        r#"<c r="A2"><f t="shared" si="0"/><v>50</v></c>"#,
        r#"<c r="A3"><f t="shared" si="0"/><v>0</v></c>"#,
        r#"<c r="B1"><f>SUM(Prices[Price])</f><v>8</v></c>"#,
    ] {
        assert!(xml.contains(expected), "{expected} in {xml}");
    }
    for unchanged in [
        INPUT,
        "xl/workbook.xml",
        "xl/tables/table1.xml",
        "vendor/opaque.bin",
    ] {
        assert_eq!(
            part_bytes(&report.bytes, unchanged),
            part_bytes(&input, unchanged)
        );
    }
    assert_eq!(
        recalc(&report.bytes).expect("idempotent").bytes,
        report.bytes
    );
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
fn external_link_workbook_is_refused_before_evaluation() {
    let input = external_workbook();
    assert_eq!(fallback(&input), "external-links-part");
    assert_eq!(preserve_external_links(&input, &input, limits()), Ok(()));
}

#[test]
fn destructive_external_link_fallback_is_refused() {
    let input = external_workbook();
    let damaged = with_part(
        &input,
        "xl/externalLinks/externalLink1.xml",
        b"<externalLink/>".to_vec(),
    );
    assert_eq!(
        preserve_external_links(&input, &damaged, limits()),
        Err("fallback altered or dropped an external-link part")
    );
    let unlinked = with_part(
        &input,
        "xl/externalLinks/_rels/externalLink1.xml.rels",
        format!(r#"<Relationships xmlns="{REL}"/>"#),
    );
    assert_eq!(
        preserve_external_links(&input, &unlinked, limits()),
        Err("fallback altered or dropped an external-link part")
    );
}

#[test]
fn formula_only_external_references_cannot_be_destroyed_by_fallback() {
    let input = fixture(
        "",
        r#"<c r="A1"><f>'[linked.xlsx]S'!A1</f><v>42</v></c>"#,
        false,
    );
    assert_eq!(fallback(&input), "external-formula-reference");
    let named = with_names(
        &fixture("", r#"<c r="A1"><f>1+1</f><v>0</v></c>"#, false),
        r#"<definedName name="linked">'[linked.xlsx]S'!$A$1</definedName>"#,
    );
    assert_eq!(fallback(&named), "external-formula-reference");
    let damaged = with_part(&input, OUTPUT, sheet(r#"<c r="A1"><v>42</v></c>"#));
    assert_eq!(
        preserve_external_links(&input, &damaged, limits()),
        Err("fallback altered or dropped an external formula link")
    );
    let recached = with_part(
        &input,
        OUTPUT,
        sheet(r#"<c r="A1"><f>'[linked.xlsx]S'!A1</f><v>43</v></c>"#),
    );
    assert_eq!(preserve_external_links(&input, &recached, limits()), Ok(()));
}

/// `fixture` whose `Result!A1` is a dynamic-array formula saved over `extent`.
fn dynamic_array(extent: &str, members: &str) -> Vec<u8> {
    let cells = format!(
        r#"<c r="A1" cm="1"><f t="array" ref="{extent}">_xlfn.SEQUENCE(2,2)</f><v>999</v></c>{members}"#
    );
    let bytes = fixture("", &cells, false);
    let bytes = edit_part(&bytes, "xl/_rels/workbook.xml.rels", |rels| {
        rels.replace("</Relationships>", &format!(r#"<Relationship Id="md" Type="{DOC_REL}/sheetMetadata" Target="metadata.xml"/></Relationships>"#))
    });
    let bytes = edit_part(&bytes, "[Content_Types].xml", |types| {
        types.replace("</Types>", &format!(r#"<Override PartName="/xl/metadata.xml" ContentType="{SPREADSHEET}.sheetMetadata+xml"/></Types>"#))
    });
    with_part(
        &bytes,
        "xl/metadata.xml",
        format!(
            r#"<metadata xmlns="{MAIN}" xmlns:xda="http://schemas.microsoft.com/office/spreadsheetml/2017/dynamicarray"><metadataTypes count="1"><metadataType name="XLDAPR" minSupportedVersion="120000" copy="1" pasteAll="1" pasteValues="1" merge="1" splitFirst="1" rowColShift="1" clearFormats="1" clearComments="1" assign="1" coerce="1" cellMeta="1"/></metadataTypes><futureMetadata name="XLDAPR" count="1"><bk><extLst><ext uri="{{bdbb8cdc-fa1e-496e-a857-3c3f30c029c3}}"><xda:dynamicArrayProperties fDynamic="1" fCollapsed="0"/></ext></extLst></bk></futureMetadata><cellMetadata count="1"><bk><rc t="1" v="0"/></bk></cellMetadata></metadata>"#
        ),
    )
}

#[test]
fn dynamic_arrays_fill_their_saved_extent_and_larger_spills_fall_back() {
    let members =
        r#"<c r="B1"><v>9</v></c></row><row r="2"><c r="A2"><v>9</v></c><c r="B2"><v>9</v></c>"#;
    let report = recalc(&dynamic_array("A1:B2", members)).expect("native spill");
    let xml = part_text(&report.bytes, OUTPUT);
    assert!(xml.contains(r#"<f t="array" ref="A1:B2">_xlfn.SEQUENCE(2,2)</f><v>1</v></c><c r="B1"><v>2</v></c></row><row r="2"><c r="A2"><v>3</v></c><c r="B2"><v>4</v></c>"#), "{xml}");
    // A result larger than the saved extent needs cells the package lacks.
    assert!(fallback(&dynamic_array("A1", "")).contains("multi-cell dynamic spill"));
}

#[test]
fn new_rich_error_tags_fall_back_to_keep_passthrough_parts() {
    // Excel saves #CALC! as #VALUE! tagged by a rich value in xl/richData/,
    // a part the edit gate passes through byte for byte.
    let input = fixture(
        r#"<c r="A1"><v>2</v></c>"#,
        r#"<c r="A1"><f>_xlfn._xlws.FILTER(Input!A1:A1,Input!A1:A1&gt;5)</f><v>0</v></c>"#,
        false,
    );
    let reason = fallback(&input);
    assert!(reason.contains("xl/richData/"), "{reason}");
}

#[test]
fn malformed_xml_and_duplicate_cells_are_not_recalculated() {
    let input = fixture(
        "",
        r#"<c r="A1"><f>1+1</f></c><c r="A1"><f>9+9</f></c>"#,
        false,
    );
    assert!(recalc(&input).is_err());
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
fn contextual_formulas_are_refused_not_evaluated_on_the_corpus_clock() {
    for formula in [
        "NOW()",
        "_xlfn.TODAY()",
        "SUM(RAND(),1)",
        "_xlfn.LAMBDA(_xlpm.x,NOW()+_xlpm.x)(2)",
    ] {
        let input = fixture(
            "",
            &format!(r#"<c r="A1"><f>{formula}</f><v>42</v></c>"#),
            false,
        );
        assert!(fallback(&input).contains("caller context"), "{formula}");
    }
    // A defined name is evaluated too.
    let named = with_names(
        &fixture("", r#"<c r="A1"><f>stamp+1</f><v>0</v></c>"#, false),
        r#"<definedName name="stamp">NOW()</definedName>"#,
    );
    assert!(fallback(&named).contains("caller context"));
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
fn filterxml_evaluates_like_excel_for_windows() {
    // Windows is the reference where Excel for Windows and Mac differ (ruling 2026-10-01);
    // the truth for FILTERXML cells was recorded on Excel for Windows 16.0.20430.
    let formula = r#"_xlfn.FILTERXML("<r><a>7</a></r>","/r/a")"#;
    let xml_formula = formula.replace('&', "&amp;").replace('<', "&lt;");
    let input = fixture(
        "",
        &format!(r#"<c r="A1"><f>{xml_formula}</f><v>0</v></c>"#),
        false,
    );
    let output = recalc(&input).expect("native recalc");
    let xml = part_text(&output.bytes, OUTPUT);
    assert!(xml.contains("<v>7</v>") && !xml.contains("#NAME?"), "{xml}");
}

#[test]
fn functions_the_engine_lacks_fall_back_instead_of_caching_name_errors() {
    for (formula, function) in [
        (r#"_xlfn.ENCODEURL("a b")"#, "_xlfn.ENCODEURL"),
        (
            r#"_xlfn.WEBSERVICE("https://example.invalid/")"#,
            "_xlfn.WEBSERVICE",
        ),
        ("1+NOSUCHFUNCTION(2)", "NOSUCHFUNCTION"),
        ("_xludf.MACRO(1)", "_xludf.MACRO"),
        ("_xlfn.ANCHORARRAY(Input!A1)", "_xlfn.ANCHORARRAY"),
    ] {
        let input = fixture(
            "",
            &format!(
                r#"<c r="A1"><f>{}</f><v>42</v></c>"#,
                formula.replace('&', "&amp;")
            ),
            false,
        );
        assert_eq!(
            fallback(&input),
            format!("function the engine does not implement: {function}")
        );
    }
    let named = with_names(
        &fixture("", r#"<c r="A1"><f>scaled</f><v>0</v></c>"#, false),
        r#"<definedName name="scaled">NOSUCHFUNCTION(2)</definedName>"#,
    );
    assert_eq!(
        fallback(&named),
        "function the engine does not implement: NOSUCHFUNCTION"
    );
    // LET names and LAMBDA parameters are callable; storage prefixes resolve,
    // and so do Excel's unprefixed compatibility names.
    let input = fixture(
        "",
        r#"<c r="A1"><f>_xlfn.LET(_xlpm.f,_xlfn.LAMBDA(_xlpm.x,_xlpm.x+1),_xlpm.f(2))</f><v>0</v></c><c r="B1"><f>_xlfn.CONCAT(&quot;a&quot;,&quot;b&quot;)</f><v>0</v></c><c r="C1"><f>NORMSDIST(0)</f><v>0</v></c>"#,
        false,
    );
    let xml = part_text(&recalc(&input).expect("native recalc").bytes, OUTPUT);
    assert!(
        xml.contains("<v>3</v>") && xml.contains("<v>ab</v>"),
        "{xml}"
    );
    assert!(xml.contains("<f>NORMSDIST(0)</f><v>0.5</v>"), "{xml}");
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
        "0.1.0+formualizer.0.9.3-oneiron.8"
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
    let refused = Command::new(env!("CARGO_BIN_EXE_recalc_native"))
        .args([&input, &output])
        .output()
        .expect("precision fallback refusal");
    assert_eq!(refused.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&refused.stdout).expect("refusal");
    assert_eq!(report["code"], "unsupported-workbook");
    assert_eq!(report["precision_fallback"], true);
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
fn bounded_formula_values_stay_native_and_over_limit_is_refused() {
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
    assert!(matches!(
        recalc(&input),
        Err(FormulaError::UnsupportedWorkbook(_))
    ));
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
