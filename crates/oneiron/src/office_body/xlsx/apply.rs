//! Application of one live XLSX operation.
//! Entry: `apply`.
//! Definitions live here; office_body::xlsx keeps the old bindings.

use super::*;

/// Apply one operation.
/// Apply one operation; what it adapts so the workbook stays one Excel
/// opens (a sheet shown or added) is named in `effects`.
pub(in crate::office_body) fn apply(
    doc: &LoroDoc,
    op: &XlsxBodyOp,
    effects: &mut Vec<String>,
) -> Result<()> {
    match op {
        XlsxBodyOp::SetValue { sheet, cell, value } => {
            check_cell(value, None).map_err(|_| invalid("the value is not one a cell holds"))?;
            write_cell(doc, sheet, cell, |held| BodyCell {
                value: value.clone(),
                formula: None,
                ..held
            })
        }
        XlsxBodyOp::SetFormula {
            sheet,
            cell,
            formula,
        } => {
            let formula = formula.strip_prefix('=').unwrap_or(formula);
            check_cell(&XlsxValue::Blank, Some(formula))
                .map_err(|_| invalid("a formula is 1 to 8,192 characters"))?;
            write_cell(doc, sheet, cell, |held| BodyCell {
                value: XlsxValue::Blank,
                formula: Some(formula.to_owned()),
                ..held
            })
        }
        XlsxBodyOp::SetStyle { sheet, cell, style } => {
            if let Some(style) = style {
                let count = read_styles_len(doc)?;
                if *style as usize >= count {
                    return Err(invalid("a cell format the workbook does not have"));
                }
            }
            write_cell(doc, sheet, cell, |held| BodyCell {
                style: *style,
                format: None,
                ..held
            })
        }
        XlsxBodyOp::DefineFormat { id, format } => {
            if id.is_empty()
                || id.len() > MAX_FORMAT_ID
                || !id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            {
                return Err(invalid(
                    "a format id is 1 to 64 letters, digits, '_', '-' or '.'",
                ));
            }
            let count = read_styles_len(doc)?;
            if count == 0 {
                return Err(invalid(
                    "the workbook has no cell format to compose one from",
                ));
            }
            check_format(format, count).map_err(|error| invalid(&error.to_string()))?;
            let formats = doc.get_map(FORMATS);
            match formats.get(id) {
                None => {
                    let json =
                        serde_json::to_string(format).map_err(|_| invalid("XLSX body format"))?;
                    formats.insert(id, json).map_err(loro)
                }
                Some(ValueOrContainer::Value(LoroValue::String(json))) => {
                    let held = serde_json::from_str::<XlsxFormat>(&json.to_string())
                        .map_err(|_| invalid("XLSX body format"))?;
                    if held == *format {
                        Ok(())
                    } else {
                        Err(invalid(
                            "a format id is immutable; compose the new look under a new id",
                        ))
                    }
                }
                Some(_) => Err(invalid("XLSX body format")),
            }
        }
        XlsxBodyOp::SetFormat {
            sheet,
            cell,
            format,
        } => {
            if doc.get_map(FORMATS).get(format).is_none() {
                return Err(invalid("no such cell format in the body"));
            }
            write_cell(doc, sheet, cell, |held| BodyCell {
                style: None,
                format: Some(format.clone()),
                ..held
            })
        }
        XlsxBodyOp::Clear { sheet, cell } => write_cell(doc, sheet, cell, |held| BodyCell {
            value: XlsxValue::Blank,
            formula: None,
            ..held
        }),
        XlsxBodyOp::SetName {
            name,
            sheet,
            formula,
            hidden,
        } => {
            check_name(name).map_err(|_| invalid("not a valid defined name"))?;
            let formula = formula.strip_prefix('=').unwrap_or(formula);
            check_cell(&XlsxValue::Blank, Some(formula))
                .map_err(|_| invalid("a name's formula is 1 to 8,192 characters"))?;
            let scope = sheet
                .as_deref()
                .map(|sheet| sheet_key(doc, sheet))
                .transpose()?;
            let names = doc.get_map(NAMES);
            let key = name_key(name, scope.as_deref());
            writable_name(&names, &key)?;
            let body = BodyName {
                name: name.clone(),
                sheet: scope,
                formula: formula.to_owned(),
                hidden: *hidden,
                locked: None,
            };
            names.insert(&key, encode_name(&body)).map_err(loro)
        }
        XlsxBodyOp::DeleteName { name, sheet } => {
            let scope = sheet
                .as_deref()
                .map(|sheet| sheet_key(doc, sheet))
                .transpose()?;
            let names = doc.get_map(NAMES);
            let key = name_key(name, scope.as_deref());
            if !writable_name(&names, &key)? {
                return Err(invalid("no such defined name in the body"));
            }
            names.delete(&key).map_err(loro)
        }
        XlsxBodyOp::AddSheet { sheet, at } => {
            check_sheet_name(sheet).map_err(|_| invalid("not a valid worksheet name"))?;
            let mut list = sheet_list(doc)?;
            free_name(&list, sheet, None)?;
            let at = at.map_or(list.len(), |at| at as usize);
            if at > list.len() {
                return Err(invalid("a sheet position past the last sheet"));
            }
            let key = new_sheet(doc, sheet)?;
            list.insert(at, (key, sheet.clone()));
            set_sheet_list(doc, &list)
        }
        XlsxBodyOp::RenameSheet { sheet, name } => {
            check_sheet_name(name).map_err(|_| invalid("not a valid worksheet name"))?;
            let mut list = sheet_list(doc)?;
            let at = sheet_at(&list, sheet)?;
            free_name(&list, name, Some(at))?;
            let order = sheet_names(&list);
            list[at].1.clone_from(name);
            set_sheet_list(doc, &list)?;
            let old = sheet.to_lowercase();
            retarget_body(
                doc,
                &order,
                &|held: &str| {
                    if held.to_lowercase() == old {
                        SheetFate::Rename(name.clone())
                    } else {
                        SheetFate::Keep
                    }
                },
                &HashSet::new(),
            )
        }
        XlsxBodyOp::MoveSheet { sheet, at } => {
            let mut list = sheet_list(doc)?;
            let from = sheet_at(&list, sheet)?;
            let at = *at as usize;
            if at >= list.len() {
                return Err(invalid("a sheet position past the last sheet"));
            }
            let held = list.remove(from);
            list.insert(at, held);
            set_sheet_list(doc, &list)
        }
        XlsxBodyOp::DeleteSheet { sheet } => {
            let mut list = sheet_list(doc)?;
            let at = sheet_at(&list, sheet)?;
            if list.len() == 1 {
                return Err(invalid("a workbook keeps at least one worksheet"));
            }
            let order = sheet_names(&list);
            let (key, _) = list.remove(at);
            // Its tables go with it, and the formulas naming them read #REF!.
            let gone = gone_tables(&read(doc)?, |held| held.key == key);
            set_sheet_list(doc, &list)?;
            let names = doc.get_map(NAMES);
            let LoroValue::Map(entries) = names.get_value() else {
                return Err(invalid("XLSX body names"));
            };
            for held in entries.keys() {
                if held.rsplit_once('!').is_some_and(|(scope, _)| scope == key) {
                    names.delete(held).map_err(loro)?;
                }
            }
            let mut states = sheet_states(doc)?;
            states.remove(&key);
            keep_one_visible(doc, &mut list, &mut states, None, effects)?;
            set_sheet_states(doc, &states)?;
            let old = sheet.to_lowercase();
            retarget_body(
                doc,
                &order,
                &|held: &str| {
                    if held.to_lowercase() == old {
                        SheetFate::Delete
                    } else {
                        SheetFate::Keep
                    }
                },
                &gone,
            )
        }
        XlsxBodyOp::SetSheetVisibility { sheet, visibility } => {
            let mut list = sheet_list(doc)?;
            let key = list[sheet_at(&list, sheet)?].0.clone();
            let mut states = sheet_states(doc)?;
            states.insert(key.clone(), *visibility);
            let sheets = list.len();
            keep_one_visible(doc, &mut list, &mut states, Some(&key), effects)?;
            if list.len() != sheets {
                set_sheet_list(doc, &list)?;
            }
            set_sheet_states(doc, &states)
        }
        XlsxBodyOp::InsertRows { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Row,
                at: *at,
                count: *count,
                delete: false,
            },
        ),
        XlsxBodyOp::DeleteRows { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Row,
                at: *at,
                count: *count,
                delete: true,
            },
        ),
        XlsxBodyOp::InsertColumns { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Column,
                at: *at,
                count: *count,
                delete: false,
            },
        ),
        XlsxBodyOp::DeleteColumns { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Column,
                at: *at,
                count: *count,
                delete: true,
            },
        ),
    }
}
