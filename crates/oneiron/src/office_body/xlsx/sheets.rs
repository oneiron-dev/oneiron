//! XLSX sheet identity, order and visibility storage.
//! Entry: `sheet_list`.
//! Definitions live here; office_body::xlsx keeps the old bindings.

use super::*;

/// The body's worksheets in workbook order, as `(key, name)`.
/// The names in a sheet list, in order.
pub(super) fn sheet_names(list: &[(String, String)]) -> Vec<String> {
    list.iter().map(|(_, name)| name.clone()).collect()
}

pub(super) fn sheet_list(doc: &LoroDoc) -> Result<Vec<(String, String)>> {
    match doc.get_map(OFFICE).get("sheets") {
        Some(ValueOrContainer::Value(LoroValue::List(list))) => {
            list.iter().map(decode_sheet).collect()
        }
        _ => Err(invalid("XLSX body metadata")),
    }
}

pub(super) fn set_sheet_list(doc: &LoroDoc, sheets: &[(String, String)]) -> Result<()> {
    let list: Vec<LoroValue> = sheets
        .iter()
        .map(|(key, name)| {
            LoroValue::from(vec![
                LoroValue::from(key.as_str()),
                LoroValue::from(name.as_str()),
            ])
        })
        .collect();
    doc.get_map(OFFICE).insert("sheets", list).map_err(loro)
}

pub(super) fn decode_sheet(value: &LoroValue) -> Result<(String, String)> {
    match value {
        LoroValue::List(pair) => match pair.as_slice() {
            [LoroValue::String(key), LoroValue::String(name)] => {
                Ok((key.to_string(), name.to_string()))
            }
            _ => Err(invalid("XLSX body sheet")),
        },
        _ => Err(invalid("XLSX body sheet")),
    }
}

pub(super) fn sheet_at(sheets: &[(String, String)], name: &str) -> Result<usize> {
    sheets
        .iter()
        .position(|(_, held)| held == name)
        .ok_or_else(|| invalid("no such worksheet in the body"))
}

pub(super) fn sheet_key(doc: &LoroDoc, name: &str) -> Result<String> {
    let sheets = sheet_list(doc)?;
    Ok(sheets[sheet_at(&sheets, name)?].0.clone())
}

/// Refuse a sheet name another sheet holds, in any case.
/// Each sheet key's visibility; a visible sheet's is not stored.
pub(super) fn sheet_states(doc: &LoroDoc) -> Result<BTreeMap<String, XlsxSheetVisibility>> {
    match doc.get_map(OFFICE).get("visibility") {
        None => Ok(BTreeMap::new()),
        Some(ValueOrContainer::Value(LoroValue::Map(states))) => states
            .iter()
            .map(|(key, state)| match state {
                LoroValue::String(state) => Ok((
                    key.clone(),
                    XlsxSheetVisibility::from_state(Some(state.to_string().as_str())),
                )),
                _ => Err(invalid("XLSX body sheet visibility")),
            })
            .collect(),
        Some(_) => Err(invalid("XLSX body sheet visibility")),
    }
}

pub(super) fn set_sheet_states(
    doc: &LoroDoc,
    states: &BTreeMap<String, XlsxSheetVisibility>,
) -> Result<()> {
    let held: HashMap<String, LoroValue> = states
        .iter()
        .filter_map(|(key, state)| Some((key.clone(), LoroValue::from(state.state()?))))
        .collect();
    doc.get_map(OFFICE).insert("visibility", held).map_err(loro)
}

/// Excel keeps one sheet visible. Where `list` would show none, the first
/// hidden sheet other than `except` is shown, else the first very hidden
/// one, else an empty worksheet is added; `effects` names it.
pub(super) fn keep_one_visible(
    doc: &LoroDoc,
    list: &mut Vec<(String, String)>,
    states: &mut BTreeMap<String, XlsxSheetVisibility>,
    except: Option<&str>,
    effects: &mut Vec<String>,
) -> Result<()> {
    let state = |states: &BTreeMap<String, XlsxSheetVisibility>, key: &str| {
        states.get(key).copied().unwrap_or_default()
    };
    if list
        .iter()
        .any(|(key, _)| state(states, key) == XlsxSheetVisibility::Visible)
    {
        return Ok(());
    }
    for wanted in [XlsxSheetVisibility::Hidden, XlsxSheetVisibility::VeryHidden] {
        let shown = list
            .iter()
            .find(|(key, _)| Some(key.as_str()) != except && state(states, key) == wanted)
            .cloned();
        if let Some((key, name)) = shown {
            states.remove(&key);
            effects.push(format!(
                "sheet {name:?} shown: a workbook keeps one visible sheet"
            ));
            return Ok(());
        }
    }
    let name = (1..)
        .map(|n| format!("Sheet{n}"))
        .find(|name| free_name(list.as_slice(), name, None).is_ok())
        .ok_or_else(|| invalid("no free worksheet name"))?;
    let key = new_sheet(doc, &name)?;
    list.push((key, name.clone()));
    effects.push(format!(
        "sheet {name:?} added: a workbook keeps one visible sheet"
    ));
    Ok(())
}

/// A new worksheet's key, minted from its name, with its empty grid.
pub(super) fn new_sheet(doc: &LoroDoc, sheet: &str) -> Result<String> {
    let cells = doc.get_map(CELLS);
    let mut key = format!("+{sheet}");
    let mut n = 1;
    while cells.get(&key).is_some() {
        n += 1;
        key = format!("+{sheet}#{n}");
    }
    cells.insert_container(&key, LoroMap::new()).map_err(loro)?;
    Ok(key)
}

pub(super) fn free_name(
    sheets: &[(String, String)],
    name: &str,
    except: Option<usize>,
) -> Result<()> {
    let lower = name.to_lowercase();
    if sheets
        .iter()
        .enumerate()
        .any(|(at, (_, held))| Some(at) != except && held.to_lowercase() == lower)
    {
        return Err(invalid("another sheet has that name"));
    }
    Ok(())
}
