//! Loro cell, name, table and axis codecs.
//! Entry: `encode_cell`.
//! Definitions live here; office_body::xlsx keeps the old bindings.

use super::*;

/// Write one cell from its current state (a blank one when absent). A cell
/// inside a read-only range, or locked at import, refuses.
pub(super) fn write_cell(
    doc: &LoroDoc,
    sheet: &str,
    cell: &str,
    edit: impl FnOnce(BodyCell) -> BodyCell,
) -> Result<()> {
    let (col, row) = parse_a1(cell).ok_or_else(|| invalid("not a cell address"))?;
    let address = a1(col, row);
    let key = sheet_key(doc, sheet)?;
    let grid = child_map(&doc.get_map(CELLS), &key).ok_or_else(|| invalid("XLSX body sheet"))?;
    let office = doc.get_map(OFFICE);
    let locked = match office.get("locked") {
        Some(ValueOrContainer::Value(LoroValue::Map(locked))) => locked,
        _ => return Err(invalid("XLSX body locks")),
    };
    if let Some(LoroValue::List(areas)) = locked.get(&key) {
        for area in areas.iter() {
            if let LoroValue::List(pair) = area
                && let [LoroValue::String(reference), _] = pair.as_slice()
                && XlsxArea::parse(reference, XlsxLock::Unsupported)
                    .is_some_and(|area| area.contains(col, row))
            {
                return Err(invalid("the cell is read-only in the body"));
            }
        }
    }
    let held = match grid.get(&address) {
        Some(ValueOrContainer::Value(value)) => decode_cell(&address, &value)?,
        None => BodyCell {
            address: address.clone(),
            value: XlsxValue::Blank,
            formula: None,
            style: None,
            format: None,
            locked: None,
        },
        Some(_) => return Err(invalid("XLSX body cell")),
    };
    if held.locked.is_some() {
        return Err(invalid("the cell is read-only in the body"));
    }
    grid.insert(&address, encode_cell(&edit(held)))
        .map_err(loro)
}

/// Whether the name exists; a read-only one refuses.
pub(super) fn writable_name(names: &LoroMap, key: &str) -> Result<bool> {
    match names.get(key) {
        None => Ok(false),
        Some(ValueOrContainer::Value(value)) => {
            if decode_name(&value)?.locked.is_some() {
                return Err(invalid("the name is read-only in the body"));
            }
            Ok(true)
        }
        Some(_) => Err(invalid("XLSX body name")),
    }
}

pub(super) fn read_styles_len(doc: &LoroDoc) -> Result<usize> {
    match doc.get_map(OFFICE).get("styles") {
        Some(ValueOrContainer::Value(LoroValue::List(styles))) => Ok(styles.len()),
        _ => Err(invalid("XLSX body styles")),
    }
}

pub(super) fn name_key(name: &str, sheet: Option<&str>) -> String {
    format!("{}!{}", sheet.unwrap_or_default(), name.to_lowercase())
}

pub(super) fn encode_cell(cell: &BodyCell) -> LoroValue {
    let mut map: HashMap<String, LoroValue> = HashMap::new();
    let (kind, value) = match &cell.value {
        XlsxValue::Blank => ("blank", None),
        XlsxValue::Number(number) => ("n", Some(LoroValue::from(*number))),
        XlsxValue::Text(text) => ("s", Some(LoroValue::from(text.as_str()))),
        XlsxValue::Bool(flag) => ("b", Some(LoroValue::from(*flag))),
        XlsxValue::Error(error) => ("e", Some(LoroValue::from(error.as_str()))),
    };
    map.insert("t".into(), kind.into());
    if let Some(value) = value {
        map.insert("v".into(), value);
    }
    if let Some(formula) = &cell.formula {
        map.insert("f".into(), formula.as_str().into());
    }
    if let Some(style) = cell.style {
        map.insert("s".into(), i64::from(style).into());
    }
    if let Some(format) = &cell.format {
        map.insert("fmt".into(), format.as_str().into());
    }
    if let Some(lock) = cell.locked {
        map.insert("lock".into(), lock_token(lock).into());
    }
    map.into()
}

pub(super) fn decode_cell(address: &str, value: &LoroValue) -> Result<BodyCell> {
    let LoroValue::Map(map) = value else {
        return Err(invalid("XLSX body cell"));
    };
    let bad = || invalid("XLSX body cell");
    let value = match (string(map, "t").as_deref(), map.get("v")) {
        (Some("blank"), None) => XlsxValue::Blank,
        (Some("n"), Some(LoroValue::Double(number))) => XlsxValue::Number(*number),
        (Some("s"), Some(LoroValue::String(text))) => XlsxValue::Text(text.to_string()),
        (Some("b"), Some(LoroValue::Bool(flag))) => XlsxValue::Bool(*flag),
        (Some("e"), Some(LoroValue::String(error))) => XlsxValue::Error(error.to_string()),
        _ => return Err(bad()),
    };
    let style = match map.get("s") {
        None => None,
        Some(LoroValue::I64(style)) => Some(u32::try_from(*style).map_err(|_| bad())?),
        Some(_) => return Err(bad()),
    };
    Ok(BodyCell {
        address: address.to_owned(),
        value,
        formula: string(map, "f"),
        style,
        format: string(map, "fmt"),
        locked: string(map, "lock").as_deref().map(parse_lock).transpose()?,
    })
}

pub(super) fn encode_areas(areas: &[XlsxArea]) -> LoroValue {
    areas
        .iter()
        .map(|area| {
            LoroValue::from(vec![
                LoroValue::from(area.reference()),
                LoroValue::from(lock_token(area.lock)),
            ])
        })
        .collect::<Vec<_>>()
        .into()
}

pub(super) fn encode_tables(tables: &[XlsxTable]) -> Result<LoroValue> {
    serde_json::to_string(tables)
        .map(LoroValue::from)
        .map_err(|_| invalid("XLSX body tables"))
}

/// A sheet's rows and columns with their own size or format, as JSON.
pub(super) fn encode_lines(rows: &[XlsxLines], columns: &[XlsxLines]) -> Result<LoroValue> {
    serde_json::to_string(&(rows, columns))
        .map(LoroValue::from)
        .map_err(|_| invalid("XLSX body rows and columns"))
}

pub(super) fn decode_lines(value: &LoroValue) -> Result<(Vec<XlsxLines>, Vec<XlsxLines>)> {
    let LoroValue::String(json) = value else {
        return Err(invalid("XLSX body rows and columns"));
    };
    serde_json::from_str(&json.to_string()).map_err(|_| invalid("XLSX body rows and columns"))
}

pub(super) fn encode_axes(axes: &[(String, XlsxAxisEdit)]) -> Vec<LoroValue> {
    axes.iter()
        .map(|(key, edit)| {
            LoroValue::from(vec![
                LoroValue::from(key.as_str()),
                LoroValue::from(match edit.axis {
                    XlsxAxis::Row => "row",
                    XlsxAxis::Column => "col",
                }),
                LoroValue::from(i64::from(edit.at)),
                LoroValue::from(i64::from(edit.count)),
                LoroValue::from(edit.delete),
            ])
        })
        .collect()
}

pub(super) fn decode_axis(value: &LoroValue) -> Result<(String, XlsxAxisEdit)> {
    let bad = || invalid("XLSX body row or column edit");
    let LoroValue::List(entry) = value else {
        return Err(bad());
    };
    let [
        LoroValue::String(key),
        LoroValue::String(axis),
        LoroValue::I64(at),
        LoroValue::I64(count),
        LoroValue::Bool(delete),
    ] = entry.as_slice()
    else {
        return Err(bad());
    };
    let edit = XlsxAxisEdit {
        axis: match axis.to_string().as_str() {
            "row" => XlsxAxis::Row,
            "col" => XlsxAxis::Column,
            _ => return Err(bad()),
        },
        at: u32::try_from(*at).map_err(|_| bad())?,
        count: u32::try_from(*count).map_err(|_| bad())?,
        delete: *delete,
    };
    if !edit.fits() {
        return Err(bad());
    }
    Ok((key.to_string(), edit))
}

pub(super) fn encode_name(name: &BodyName) -> LoroValue {
    let mut map: HashMap<String, LoroValue> = HashMap::new();
    map.insert("name".into(), name.name.as_str().into());
    if let Some(sheet) = &name.sheet {
        map.insert("sheet".into(), sheet.as_str().into());
    }
    map.insert("formula".into(), name.formula.as_str().into());
    map.insert("hidden".into(), name.hidden.into());
    if let Some(lock) = name.locked {
        map.insert("lock".into(), lock_token(lock).into());
    }
    map.into()
}

pub(super) fn decode_name(value: &LoroValue) -> Result<BodyName> {
    let LoroValue::Map(map) = value else {
        return Err(invalid("XLSX body name"));
    };
    Ok(BodyName {
        name: string(map, "name").ok_or_else(|| invalid("XLSX body name"))?,
        sheet: string(map, "sheet"),
        formula: string(map, "formula").ok_or_else(|| invalid("XLSX body name"))?,
        hidden: matches!(map.get("hidden"), Some(LoroValue::Bool(true))),
        locked: string(map, "lock").as_deref().map(parse_lock).transpose()?,
    })
}

pub(super) fn lock_token(lock: XlsxLock) -> &'static str {
    match lock {
        XlsxLock::SharedFormula => "shared_formula",
        XlsxLock::ArrayFormula => "array_formula",
        XlsxLock::DataTable => "data_table",
        XlsxLock::RichValue => "rich_value",
        XlsxLock::TableRow => "table_row",
        XlsxLock::Unsupported => "unsupported",
        XlsxLock::BuiltinName => "builtin_name",
    }
}

pub(super) fn parse_lock(token: &str) -> Result<XlsxLock> {
    Ok(match token {
        "shared_formula" => XlsxLock::SharedFormula,
        "array_formula" => XlsxLock::ArrayFormula,
        "data_table" => XlsxLock::DataTable,
        "rich_value" => XlsxLock::RichValue,
        "table_row" => XlsxLock::TableRow,
        "unsupported" => XlsxLock::Unsupported,
        "builtin_name" => XlsxLock::BuiltinName,
        _ => return Err(invalid("XLSX body lock")),
    })
}

pub(super) fn string(map: &LoroMapValue, key: &str) -> Option<String> {
    match map.get(key) {
        Some(LoroValue::String(value)) => Some(value.to_string()),
        _ => None,
    }
}

pub(super) fn child_map(map: &LoroMap, key: &str) -> Option<LoroMap> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::Map(child)) => Some(child),
        _ => None,
    }
}
