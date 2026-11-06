//! XLSX body import and typed Loro reads.
//! Entry: `read`.
//! Definitions live here; office_body::xlsx keeps the old bindings.

use super::*;

/// Write the imported workbook into a fresh document, every cell of it.
pub(in crate::office_body) fn import(doc: &LoroDoc, book: &XlsxBook) -> Result<()> {
    let office = doc.get_map(OFFICE);
    office.insert("kind", "xlsx").map_err(loro)?;
    office.insert("schema", i64::from(SCHEMA)).map_err(loro)?;
    office.insert("date1904", book.date1904).map_err(loro)?;
    let sheets: Vec<(String, String)> = book
        .sheets
        .iter()
        .map(|sheet| (sheet.name.clone(), sheet.name.clone()))
        .collect();
    set_sheet_list(doc, &sheets)?;
    let states: BTreeMap<String, XlsxSheetVisibility> = book
        .sheets
        .iter()
        .map(|sheet| (sheet.name.clone(), sheet.visibility))
        .collect();
    set_sheet_states(doc, &states)?;
    let locked: HashMap<String, LoroValue> = book
        .sheets
        .iter()
        .map(|sheet| (sheet.name.clone(), encode_areas(&sheet.locked)))
        .collect();
    office.insert("locked", locked).map_err(loro)?;
    let tables = book
        .sheets
        .iter()
        .filter(|sheet| !sheet.tables.is_empty())
        .map(|sheet| -> Result<(String, LoroValue)> {
            Ok((sheet.name.clone(), encode_tables(&sheet.tables)?))
        })
        .collect::<Result<HashMap<String, LoroValue>>>()?;
    office.insert("tables", tables).map_err(loro)?;
    let lines = book
        .sheets
        .iter()
        .filter(|sheet| !sheet.rows.is_empty() || !sheet.columns.is_empty())
        .map(|sheet| -> Result<(String, LoroValue)> {
            Ok((
                sheet.name.clone(),
                encode_lines(&sheet.rows, &sheet.columns)?,
            ))
        })
        .collect::<Result<HashMap<String, LoroValue>>>()?;
    office.insert("lines", lines).map_err(loro)?;
    office
        .insert("axes", Vec::<LoroValue>::new())
        .map_err(loro)?;
    let styles: Vec<LoroValue> = book
        .styles
        .iter()
        .map(|style| {
            LoroValue::from(vec![
                LoroValue::from(i64::from(style.num_fmt)),
                style
                    .format
                    .as_deref()
                    .map_or(LoroValue::Null, LoroValue::from),
            ])
        })
        .collect();
    office.insert("styles", styles).map_err(loro)?;
    let cells = doc.get_map(CELLS);
    for sheet in &book.sheets {
        if cells.get(&sheet.name).is_some() {
            return Err(invalid("duplicate imported sheet name"));
        }
        let grid = cells
            .insert_container(&sheet.name, LoroMap::new())
            .map_err(loro)?;
        for cell in &sheet.cells {
            let body = BodyCell {
                address: a1(cell.col, cell.row),
                value: cell.value.clone(),
                formula: cell.formula.clone(),
                style: cell.style,
                format: None,
                locked: cell.locked,
            };
            grid.insert(&body.address, encode_cell(&body))
                .map_err(loro)?;
        }
    }
    let names = doc.get_map(NAMES);
    for name in &book.names {
        let key = name_key(&name.name, name.sheet.as_deref());
        if names.get(&key).is_some() {
            return Err(invalid("duplicate imported defined name"));
        }
        let body = BodyName {
            name: name.name.clone(),
            sheet: name.sheet.clone(),
            formula: name.formula.clone(),
            hidden: name.hidden,
            locked: name.locked,
        };
        names.insert(&key, encode_name(&body)).map_err(loro)?;
    }
    Ok(())
}

/// The body's typed state; a malformed document fails closed.
pub(in crate::office_body) fn read(doc: &LoroDoc) -> Result<XlsxBody> {
    let office = doc.get_map(OFFICE);
    let LoroValue::Map(meta) = office.get_value() else {
        return Err(invalid(&format!("not a schema-{SCHEMA} XLSX body")));
    };
    if string(&meta, "kind").as_deref() != Some("xlsx")
        || meta.get("schema") != Some(&LoroValue::I64(i64::from(SCHEMA)))
    {
        return Err(invalid(&format!("not a schema-{SCHEMA} XLSX body")));
    }
    let list = |key: &str| match meta.get(key) {
        Some(LoroValue::List(list)) => Ok(list.clone()),
        _ => Err(invalid("XLSX body metadata")),
    };
    let sheet_list = list("sheets")?
        .iter()
        .map(decode_sheet)
        .collect::<Result<Vec<_>>>()?;
    let Some(LoroValue::Map(locked)) = meta.get("locked") else {
        return Err(invalid("XLSX body locks"));
    };
    let held_tables = match meta.get("tables") {
        None => None,
        Some(LoroValue::Map(tables)) => Some(tables),
        Some(_) => return Err(invalid("XLSX body tables")),
    };
    let held_lines = match meta.get("lines") {
        None => None,
        Some(LoroValue::Map(lines)) => Some(lines),
        Some(_) => return Err(invalid("XLSX body rows and columns")),
    };
    let states = sheet_states(doc)?;
    let styles = list("styles")?
        .iter()
        .map(|style| match style {
            LoroValue::List(pair) => match pair.as_slice() {
                [LoroValue::I64(num_fmt), format] => Ok(XlsxStyle {
                    num_fmt: u32::try_from(*num_fmt).map_err(|_| invalid("XLSX body style"))?,
                    format: match format {
                        LoroValue::String(code) => Some(code.to_string()),
                        _ => None,
                    },
                }),
                _ => Err(invalid("XLSX body style")),
            },
            _ => Err(invalid("XLSX body style")),
        })
        .collect::<Result<Vec<_>>>()?;
    let grids = doc.get_map(CELLS);
    let mut sheets = Vec::with_capacity(sheet_list.len());
    for (key, name) in sheet_list {
        let grid = child_map(&grids, &key).ok_or_else(|| invalid("XLSX body sheet"))?;
        let LoroValue::Map(entries) = grid.get_value() else {
            return Err(invalid("XLSX body sheet"));
        };
        let mut cells = BTreeMap::new();
        for (address, value) in entries.iter() {
            let (col, row) = parse_a1(address).ok_or_else(|| invalid("XLSX body cell address"))?;
            cells.insert((row, col), decode_cell(address, value)?);
        }
        let areas = match locked.get(&key) {
            None => Vec::new(),
            Some(LoroValue::List(areas)) => areas
                .iter()
                .map(|area| match area {
                    LoroValue::List(pair) => match pair.as_slice() {
                        [LoroValue::String(reference), LoroValue::String(lock)] => {
                            XlsxArea::parse(reference, parse_lock(lock)?)
                                .ok_or_else(|| invalid("XLSX body locked range"))
                        }
                        _ => Err(invalid("XLSX body locked range")),
                    },
                    _ => Err(invalid("XLSX body locked range")),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(invalid("XLSX body locks")),
        };
        let tables = match held_tables.and_then(|tables| tables.get(&key)) {
            None => Vec::new(),
            Some(LoroValue::String(json)) => {
                serde_json::from_str(&json.to_string()).map_err(|_| invalid("XLSX body tables"))?
            }
            Some(_) => return Err(invalid("XLSX body tables")),
        };
        let (rows, columns) = match held_lines.and_then(|lines| lines.get(&key)) {
            None => (Vec::new(), Vec::new()),
            Some(value) => decode_lines(value)?,
        };
        sheets.push(BodySheet {
            visibility: states.get(&key).copied().unwrap_or_default(),
            key,
            name,
            cells,
            locked: areas,
            tables,
            conditional: BTreeMap::new(),
            rows,
            columns,
        });
    }
    read_conditional(doc, &mut sheets)?;
    let axes = match meta.get("axes") {
        None => Vec::new(),
        Some(LoroValue::List(list)) => list.iter().map(decode_axis).collect::<Result<Vec<_>>>()?,
        Some(_) => return Err(invalid("XLSX body row and column edits")),
    };
    let LoroValue::Map(composed) = doc.get_map(FORMATS).get_value() else {
        return Err(invalid("XLSX body formats"));
    };
    let mut formats = BTreeMap::new();
    for (id, value) in composed.iter() {
        let LoroValue::String(json) = value else {
            return Err(invalid("XLSX body format"));
        };
        let format = serde_json::from_str::<XlsxFormat>(&json.to_string())
            .map_err(|_| invalid("XLSX body format"))?;
        formats.insert(id.clone(), format);
    }
    let LoroValue::Map(entries) = doc.get_map(NAMES).get_value() else {
        return Err(invalid("XLSX body names"));
    };
    let mut names = BTreeMap::new();
    for (key, value) in entries.iter() {
        let mut name = decode_name(value)?;
        if *key != name_key(&name.name, name.sheet.as_deref()) {
            return Err(invalid("XLSX body name key"));
        }
        // A local name reads its sheet's name; one whose sheet a concurrent
        // edit deleted is gone with it.
        if let Some(scope) = &name.sheet {
            let Some(sheet) = sheets.iter().find(|sheet| sheet.key == *scope) else {
                continue;
            };
            name.sheet = Some(sheet.name.clone());
        }
        names.insert(key.clone(), name);
    }
    Ok(XlsxBody {
        date1904: matches!(meta.get("date1904"), Some(LoroValue::Bool(true))),
        sheets,
        names,
        styles,
        axes,
        formats,
    })
}
