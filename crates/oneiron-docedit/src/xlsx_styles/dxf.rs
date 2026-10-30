//! The differential formats (`dxf`) a conditional format draws a matching
//! cell in (FIX 3468): font, fill, border and number format changes over the
//! cell's own format. The projection appends each to the stylesheet's
//! `dxfs`, reusing an equal record, so the records the workbook had keep
//! their bytes and indices.

use super::{
    Element, FIRST_CUSTOM_FORMAT, FONT_ORDER, List, Result, XlsxBorder, XlsxFill, XlsxFont,
    XlsxFormat, XlsxNumberFormat, check_format, color, patch_border, patch_font, refused,
};
use crate::edit::xml::splice;
use crate::ooxml::{SPREADSHEET_MAIN as SML, XmlTree};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The look a conditional format gives a cell its rule matches: each part set
/// here is drawn over the cell's own format. Excel draws a font's bold,
/// italic, underline, strikethrough and color from it, not its name or size.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxDifferentialFormat {
    pub font: Option<XlsxFont>,
    /// A solid fill's color (`fg`, else `bg`) is drawn behind the cell's text.
    pub fill: Option<XlsxFill>,
    pub border: Option<XlsxBorder>,
    /// A built-in format is one with a code every Excel spells alike (0 to
    /// 4, 9 to 22, 37 to 40, 45 to 49); any other is given by its code.
    pub number_format: Option<XlsxNumberFormat>,
}

/// Refuse a differential format the stylesheet could not hold: a font, fill,
/// border or number format [`check_format`] refuses, or a built-in number
/// format with no code a `dxf` can spell.
pub fn check_differential_format(format: &XlsxDifferentialFormat) -> Result<()> {
    if let Some(XlsxNumberFormat::Builtin { id }) = &format.number_format
        && builtin_code(*id).is_none()
    {
        return Err(refused(
            "a conditional format's built-in number format is 0 to 4, 9 to 22, 37 to 40 or 45 to 49; give any other by its code",
        ));
    }
    check_format(
        &XlsxFormat {
            base: 0,
            cell_style: None,
            font: format.font.clone(),
            fill: format.fill.clone(),
            border: format.border.clone(),
            number_format: format.number_format.clone(),
            alignment: None,
            protection: None,
        },
        1,
    )
}

/// Write `formats` into the stylesheet `bytes`'s `dxfs`: each format's index
/// there, in order, and the stylesheet's new bytes when a record was added.
pub(crate) fn write_dxfs(
    bytes: &[u8],
    resources: &crate::resource::Resources,
    formats: &[XlsxDifferentialFormat],
) -> Result<(Vec<u32>, Option<Vec<u8>>)> {
    let tree = XmlTree::parse(bytes, resources)?;
    tree.root(SML, "styleSheet")
        .map_err(|_| refused("the stylesheet is not SpreadsheetML"))?;
    let num_fmts = List::read(&tree, "numFmts", "numFmt")?;
    let mut dxfs = List::read(&tree, "dxfs", "dxf")?;
    let mut indices = Vec::with_capacity(formats.len());
    for format in formats {
        check_differential_format(format)?;
        let dxf = dxf_element(format, &num_fmts, &dxfs);
        indices.push(dxfs.find_or_push(dxf)?);
    }
    let prefix = tree.nodes[0]
        .qualified
        .rsplit_once(':')
        .map_or_else(String::new, |(prefix, _)| format!("{prefix}:"));
    let mut edits = Vec::new();
    dxfs.write(&tree, bytes, &prefix, &mut edits);
    if edits.is_empty() {
        return Ok((indices, None));
    }
    let value =
        splice(bytes, edits).map_err(|_| refused("the stylesheet could not be rewritten"))?;
    Ok((indices, Some(value)))
}

/// `format` as a `dxf` record: its font, number format, fill and border in
/// schema order. A number format code takes the id the workbook or one of
/// its `dxf` records gives it, else one past every id either uses.
fn dxf_element(format: &XlsxDifferentialFormat, num_fmts: &List, dxfs: &List) -> Element {
    let mut dxf = Element::new("dxf");
    if let Some(patch) = &format.font {
        let mut font = Element::new("font");
        patch_font(&mut font, patch);
        // A differential font turns a part off by saying so.
        for (name, on) in [
            ("b", patch.bold),
            ("i", patch.italic),
            ("strike", patch.strike),
        ] {
            if on == Some(false) {
                let mut off = Element::new(name);
                off.set("val", 0);
                font.put(off, FONT_ORDER);
            }
        }
        dxf.children.push(font);
    }
    if let Some(number) = &format.number_format {
        let (id, code) = match number {
            XlsxNumberFormat::Builtin { id } => {
                (*id, builtin_code(*id).unwrap_or("General").to_owned())
            }
            XlsxNumberFormat::Code { code } => (code_id(num_fmts, dxfs, code), code.clone()),
        };
        let mut element = Element::new("numFmt");
        element.set("numFmtId", id);
        element.set("formatCode", code);
        dxf.children.push(element);
    }
    if let Some(fill) = &format.fill {
        let mut pattern = Element::new("patternFill");
        if fill.pattern == "solid" {
            // A differential solid fill paints its background color.
            pattern.children.extend(
                fill.fg
                    .as_ref()
                    .or(fill.bg.as_ref())
                    .map(|paint| color("bgColor", paint)),
            );
        } else {
            pattern.set("patternType", &fill.pattern);
            pattern
                .children
                .extend(fill.fg.as_ref().map(|fg| color("fgColor", fg)));
            pattern
                .children
                .extend(fill.bg.as_ref().map(|bg| color("bgColor", bg)));
        }
        let mut element = Element::new("fill");
        element.children.push(pattern);
        dxf.children.push(element);
    }
    if let Some(patch) = &format.border {
        let mut border = Element::new("border");
        patch_border(&mut border, patch);
        dxf.children.push(border);
    }
    dxf
}

/// The id of number format `code` in a `dxf`: the workbook's or an existing
/// `dxf`'s for the same code, else one past every id either uses.
fn code_id(num_fmts: &List, dxfs: &List, code: &str) -> u32 {
    let held: Vec<&Element> = num_fmts
        .entries
        .iter()
        .chain(dxfs.entries.iter().filter_map(|dxf| dxf.child("numFmt")))
        .collect();
    let id = |entry: &Element| {
        entry
            .attrs
            .get("numFmtId")
            .and_then(|id| id.trim().parse::<u32>().ok())
    };
    if let Some(same) = held
        .iter()
        .find(|entry| entry.attrs.get("formatCode").map(String::as_str) == Some(code))
        .and_then(|entry| id(entry))
    {
        return same;
    }
    held.iter()
        .filter_map(|entry| id(entry))
        .map(|held| held.saturating_add(1))
        .max()
        .unwrap_or(0)
        .max(FIRST_CUSTOM_FORMAT)
}

/// The code of a built-in number format every Excel spells alike
/// (ECMA-376 §18.8.30); the locale's currency and date formats have none.
fn builtin_code(id: u32) -> Option<&'static str> {
    Some(match id {
        0 => "General",
        1 => "0",
        2 => "0.00",
        3 => "#,##0",
        4 => "#,##0.00",
        9 => "0%",
        10 => "0.00%",
        11 => "0.00E+00",
        12 => "# ?/?",
        13 => "# ??/??",
        14 => "mm-dd-yy",
        15 => "d-mmm-yy",
        16 => "d-mmm",
        17 => "mmm-yy",
        18 => "h:mm AM/PM",
        19 => "h:mm:ss AM/PM",
        20 => "h:mm",
        21 => "h:mm:ss",
        22 => "m/d/yy h:mm",
        37 => "#,##0 ;(#,##0)",
        38 => "#,##0 ;[Red](#,##0)",
        39 => "#,##0.00;(#,##0.00)",
        40 => "#,##0.00;[Red](#,##0.00)",
        45 => "mm:ss",
        46 => "[h]:mm:ss",
        47 => "mmss.0",
        48 => "##0.0E+0",
        49 => "@",
        _ => return None,
    })
}
