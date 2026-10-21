//! Typed sheet-answer verification and reader seam.
//! Entry: `verify_sheet_answer_bytes`.
//! read owns OOXML cell reads; this module owns verification.
//!
//! Independent OOXML reads for typed sheet answers. No session assertion is
//! trusted for either the source cells or the retained output cells.

mod read;

use super::judgment::SheetAnswerBundle;
use super::opc::{self, OpcPackage};
use super::session_validate::resolve_part_path;
use super::xml;
use super::{CellRef, CellValue};
use crate::error::{ArtifactError, Error, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use read::named_sheet_cells;

const SHEET_NS: &[u8] = b"http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL_NS: &[u8] = b"http://schemas.openxmlformats.org/package/2006/relationships";

/// Transient decoded cell while walking a worksheet's grid path.
type CellRead = (CellRef, Option<String>, String, Option<String>, bool);

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(
        "typed sheet answers do not match the artifact bytes",
    ))
}

/// Validate before values if supplied, and every non-abstaining after value.
/// Called both before returning a proposal and at Keep on public proposal bytes.
pub(crate) fn verify_sheet_answer_bytes(
    bundle: &SheetAnswerBundle,
    source: Option<&[u8]>,
    output: Option<&[u8]>,
) -> Result<()> {
    bundle.ops()?;
    if let Some(source) = source {
        let actual = sheet_cells(source, bundle, true)?;
        for answer in &bundle.answers {
            if let Some(before) = &answer.before
                && actual
                    .get(&answer.cell)
                    .cloned()
                    .unwrap_or(CellValue::Blank)
                    != *before
            {
                return Err(invalid());
            }
        }
    }
    if let Some(output) = output {
        let actual = sheet_cells(output, bundle, false)?;
        for answer in &bundle.answers {
            if let Some(after) = &answer.value
                && actual
                    .get(&answer.cell)
                    .cloned()
                    .unwrap_or(CellValue::Blank)
                    != *after
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn sheet_cells(
    bytes: &[u8],
    bundle: &SheetAnswerBundle,
    source: bool,
) -> Result<BTreeMap<CellRef, CellValue>> {
    // Only cells whose value is needed are parsed. In particular, a formula
    // on an abstaining cell or an unchecked source is not an error.
    let targets: BTreeSet<CellRef> = bundle
        .answers
        .iter()
        .filter(|a| {
            if source {
                a.before.is_some()
            } else {
                a.value.is_some()
            }
        })
        .map(|a| a.cell)
        .collect();
    named_sheet_cells(bytes, &bundle.sheet, &|cell| targets.contains(cell))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit_roundtrip::{RangeRef, SheetCellAnswer};

    fn bundle(sheet: &str, before: Option<CellValue>, value: CellValue) -> SheetAnswerBundle {
        SheetAnswerBundle {
            question: "fit".into(),
            question_version: "q1".into(),
            principal: "owner".into(),
            sheet: sheet.into(),
            range: RangeRef::parse("B2:B2").unwrap(),
            max_count_override: None,
            answers: vec![SheetCellAnswer {
                cell: CellRef::parse("B2").unwrap(),
                before,
                value: Some(value),
                probability: 0.8,
                confidence: 0.9,
                rung: "rule".into(),
                model: "local".into(),
                revision: "r1".into(),
                cost_per_thousand: 0.0,
                evidence_versions: vec![],
            }],
        }
    }

    fn package(target: &str, shared: bool) -> Vec<u8> {
        let mut parts = vec![
            opc::OpcPart { name: "[Content_Types].xml".into(), data: b"<Types/>".to_vec() },
            opc::OpcPart { name: "xl/workbook.xml".into(), data: br#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Other" sheetId="1" r:id="rId1"/><sheet name="Data &amp; Co" sheetId="2" r:id="rId2"/></sheets></workbook>"#.to_vec() },
            opc::OpcPart { name: "xl/_rels/workbook.xml.rels".into(), data: br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#.to_vec() },
            opc::OpcPart { name: "xl/worksheets/sheet2.xml".into(), data: br#"<worksheet><sheetData><row r="2"><c r="B2"><v>999</v></c></row></sheetData></worksheet>"#.to_vec() },
            opc::OpcPart { name: "xl/worksheets/sheet1.xml".into(), data: target.as_bytes().to_vec() },
        ];
        if shared {
            parts.push(opc::OpcPart {
                name: "xl/sharedStrings.xml".into(),
                data: b"<sst><si><t>Other</t></si><si><t>Yes &amp; No</t></si></sst>".to_vec(),
            });
        }
        opc::write(&OpcPackage::from_parts(parts))
    }

    #[test]
    fn source_formula_and_abstention_are_not_literal_answer_refusals() -> Result<()> {
        let source = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2"><f>1+1</f><v>2</v></c></row><row r="3"><c r="B3"><f>3+3</f><v>6</v></c></row></sheetData></worksheet>"#,
            false,
        );
        let output = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2"><v>7</v></c></row><row r="3"><c r="B3"><f>3+3</f><v>6</v></c></row></sheetData></worksheet>"#,
            false,
        );
        let mut ask = bundle("Data & Co", None, CellValue::Number(7.0));
        ask.answers.push(SheetCellAnswer {
            cell: CellRef::parse("B3")?,
            before: None,
            value: None,
            ..ask.answers[0].clone()
        });
        ask.range = RangeRef::parse("B2:B3")?;
        verify_sheet_answer_bytes(&ask, Some(&source), Some(&output))?;
        ask.answers[0].before = Some(CellValue::Formula {
            expr: "1+1".into(),
            cached: Some(Box::new(CellValue::Number(2.0))),
        });
        verify_sheet_answer_bytes(&ask, Some(&source), Some(&output))?;
        let no_cache = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2"><f>1+1</f></c></row></sheetData></worksheet>"#,
            false,
        );
        ask.answers[0].before = Some(CellValue::Formula {
            expr: "1+1".into(),
            cached: None,
        });
        verify_sheet_answer_bytes(&ask, Some(&no_cache), Some(&output))?;
        ask.answers[0].before = Some(CellValue::Formula {
            expr: "9+9".into(),
            cached: Some(Box::new(CellValue::Number(2.0))),
        });
        assert!(verify_sheet_answer_bytes(&ask, Some(&source), Some(&output)).is_err());
        Ok(())
    }

    #[test]
    fn extension_and_phonetic_descendants_are_not_cell_values() -> Result<()> {
        let mut ask = bundle("Data & Co", None, CellValue::Number(6.0));
        let blank = package("<worksheet><sheetData/></worksheet>", false);
        for fake in [
            r#"<worksheet><sheetData><row r="2"><c r="B2"><extLst><ext uri="urn:example"><x:v xmlns:x="urn:example">6</x:v></ext></extLst></c></row></sheetData></worksheet>"#,
            r#"<worksheet><sheetData><row r="2"><c r="B2"><extLst><ext><v>6</v></ext></extLst></c></row></sheetData></worksheet>"#,
        ] {
            let output = package(fake, false);
            assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&output)).is_err());
        }
        ask.answers[0].value = Some(CellValue::Text("False".into()));
        let fake_inline = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="inlineStr"><is><ext><t>False</t></ext></is></c></row></sheetData></worksheet>"#,
            false,
        );
        assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&fake_inline)).is_err());
        let shared_cell = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="s"><v>0</v></c></row></sheetData></worksheet>"#,
            true,
        );
        let mut pkg = opc::read(&shared_cell)?;
        pkg.upsert(
            "xl/sharedStrings.xml",
            br#"<sst><si><rPh><t>False</t></rPh></si></sst>"#.to_vec(),
        );
        assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&opc::write(&pkg))).is_err());
        pkg.upsert(
            "xl/sharedStrings.xml",
            br#"<sst><si><r><t>True</t></r><rPh><t>False</t></rPh></si></sst>"#.to_vec(),
        );
        assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&opc::write(&pkg))).is_err());
        Ok(())
    }

    #[test]
    fn joins_named_sheet_relationship_and_shared_string_not_sheet_position() -> Result<()> {
        let source = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="s"><v>1</v></c></row></sheetData></worksheet>"#,
            true,
        );
        let output = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></row></sheetData></worksheet>"#,
            true,
        );
        let bundle = bundle(
            "Data & Co",
            Some(CellValue::Text("Yes & No".into())),
            CellValue::Text("Ready & Yes".into()),
        );
        verify_sheet_answer_bytes(&bundle, Some(&source), Some(&output))?;
        assert!(
            verify_sheet_answer_bytes(
                &bundle,
                Some(&package("<worksheet><sheetData/></worksheet>", true)),
                Some(&output)
            )
            .is_err()
        );
        assert!(
            verify_sheet_answer_bytes(
                &bundle,
                Some(&source),
                Some(&package("<worksheet><sheetData/></worksheet>", true))
            )
            .is_err()
        );
        // A matching XML tag outside sheetData/row, or in another namespace,
        // does not create an Excel grid cell and must not ground a receipt.
        for fake in [
            r#"<worksheet><sheetData/><extLst><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></extLst></worksheet>"#,
            r#"<worksheet><sheetData><row r="2"><x:c xmlns:x="urn:other" r="B2" t="inlineStr"><x:is><x:t>Ready &amp; Yes</x:t></x:is></x:c></row></sheetData></worksheet>"#,
            r#"<worksheet><sheetData><row r="3"><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></row></sheetData></worksheet>"#,
            r#"<worksheet><sheetData/><extLst><sheetData><row r="2"><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></row></sheetData></extLst></worksheet>"#,
        ] {
            assert!(
                verify_sheet_answer_bytes(&bundle, Some(&source), Some(&package(fake, true)))
                    .is_err()
            );
        }
        Ok(())
    }
}
