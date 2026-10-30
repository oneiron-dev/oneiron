//! Live XLSX conditional formats (FIX 3468).
//! Entry: `set_conditional`.
//! Root `conditional` maps `key!id` (a sheet's key, the format's id) to one
//! conditional format as JSON, its range and formulas addressed as the row and
//! column log leaves the sheet. A deleted sheet's formats stay under its key,
//! as its cells do.

use super::*;

/// The body key of conditional format `id` on the sheet keyed `key`.
fn conditional_key(key: &str, id: &str) -> String {
    format!("{key}!{id}")
}

/// Add or replace conditional format `id` on worksheet `sheet`.
pub(super) fn set_conditional(
    doc: &LoroDoc,
    sheet: &str,
    id: &str,
    format: &XlsxConditionalFormat,
) -> Result<()> {
    check_id(id)?;
    let mut format = format.clone();
    for formula in format.rule.formulas_mut() {
        if let Some(bare) = formula.strip_prefix('=') {
            *formula = bare.to_owned();
        }
    }
    check_conditional(&format).map_err(|error| invalid(&error.to_string()))?;
    let key = sheet_key(doc, sheet)?;
    let json =
        serde_json::to_string(&format).map_err(|_| invalid("XLSX body conditional format"))?;
    doc.get_map(CONDITIONAL)
        .insert(&conditional_key(&key, id), json)
        .map_err(loro)
}

/// Delete conditional format `id` from worksheet `sheet`.
pub(super) fn delete_conditional(doc: &LoroDoc, sheet: &str, id: &str) -> Result<()> {
    let key = conditional_key(&sheet_key(doc, sheet)?, id);
    let formats = doc.get_map(CONDITIONAL);
    if formats.get(&key).is_none() {
        return Err(invalid("no such conditional format in the body"));
    }
    formats.delete(&key).map_err(loro)
}

/// Refuse an id that is not 1 to 64 letters, digits, `_`, `-` or `.`.
fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_FORMAT_ID
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(invalid(
            "a conditional format id is 1 to 64 letters, digits, '_', '-' or '.'",
        ));
    }
    Ok(())
}

/// Each sheet's conditional formats, by id, read into `sheets`; a format
/// whose sheet a concurrent edit deleted is gone with it.
pub(super) fn read_conditional(doc: &LoroDoc, sheets: &mut [BodySheet]) -> Result<()> {
    let LoroValue::Map(entries) = doc.get_map(CONDITIONAL).get_value() else {
        return Err(invalid("XLSX body conditional formats"));
    };
    for (key, value) in entries.iter() {
        let (Some((scope, id)), LoroValue::String(json)) = (key.rsplit_once('!'), value) else {
            return Err(invalid("XLSX body conditional format"));
        };
        let format = serde_json::from_str::<XlsxConditionalFormat>(&json.to_string())
            .map_err(|_| invalid("XLSX body conditional format"))?;
        if let Some(sheet) = sheets.iter_mut().find(|sheet| sheet.key == scope) {
            sheet.conditional.insert(id.to_owned(), format);
        }
    }
    Ok(())
}

/// Move one sheet's conditional formats through a row or column edit to the
/// sheet `name` names: on that sheet (`own`) their ranges move, losing what
/// the edit deletes, and a format left with no cell goes; on every sheet
/// their formulas follow, as a cell's do.
pub(super) fn shift_conditional(
    formats: &mut BTreeMap<String, XlsxConditionalFormat>,
    home: &str,
    name: &str,
    edit: &XlsxAxisEdit,
    dropped: &[(XlsxTable, Vec<String>)],
    own: bool,
) {
    formats.retain(|_, format| {
        if own {
            match shift_conditional_range(&format.range, edit) {
                Some(range) => format.range = range,
                None => return false,
            }
        }
        for formula in format.rule.formulas_mut() {
            if let Some(moved) = shift_axis_formula(formula, Some(home), name, edit, dropped, None)
            {
                *formula = moved;
            }
        }
        true
    });
}

/// Rewrite every conditional format's formulas by `rewrite`.
pub(super) fn retarget_conditional(body: &mut XlsxBody, rewrite: &dyn Fn(&str) -> Option<String>) {
    for formula in body
        .sheets
        .iter_mut()
        .flat_map(|sheet| sheet.conditional.values_mut())
        .flat_map(|format| format.rule.formulas_mut())
    {
        if let Some(moved) = rewrite(formula) {
            *formula = moved;
        }
    }
}

/// Write the conditional formats that differ between two typed reads.
pub(super) fn write_conditional(doc: &LoroDoc, before: &XlsxBody, after: &XlsxBody) -> Result<()> {
    let formats = doc.get_map(CONDITIONAL);
    let empty = BTreeMap::new();
    for sheet in &after.sheets {
        let old = before
            .sheets
            .iter()
            .find(|held| held.key == sheet.key)
            .map_or(&empty, |held| &held.conditional);
        for id in old.keys() {
            if !sheet.conditional.contains_key(id) {
                formats
                    .delete(&conditional_key(&sheet.key, id))
                    .map_err(loro)?;
            }
        }
        for (id, format) in &sheet.conditional {
            if old.get(id) != Some(format) {
                let json = serde_json::to_string(format)
                    .map_err(|_| invalid("XLSX body conditional format"))?;
                formats
                    .insert(&conditional_key(&sheet.key, id), json)
                    .map_err(loro)?;
            }
        }
    }
    Ok(())
}

/// The change that writes each sheet's conditional formats onto the
/// imported package, which holds none of the body's.
pub(super) fn conditional_changes(current: &XlsxBody) -> Vec<XlsxChange> {
    current
        .sheets
        .iter()
        .filter(|sheet| !sheet.conditional.is_empty())
        .map(|sheet| XlsxChange::ConditionalFormats {
            sheet: sheet.name.clone(),
            formats: sheet.conditional.values().cloned().collect(),
        })
        .collect()
}
