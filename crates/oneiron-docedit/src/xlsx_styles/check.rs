//! Refusing a cell format the workbook could not hold, before the projection
//! writes anything: the limits and value lists Excel sets, and the checks.

use super::{FIRST_CUSTOM_FORMAT, Result, XlsxColor, XlsxFormat, XlsxNumberFormat, refused};
use crate::edit::xml::writable;

const MAX_FORMAT_CODE: usize = 255;
/// Excel's ceiling on a font name.
const MAX_FONT_NAME: usize = 31;
/// Excel's font sizes, in points.
const FONT_SIZES: std::ops::RangeInclusive<f64> = 1.0..=409.0;
const UNDERLINES: &[&str] = &[
    "single",
    "double",
    "singleAccounting",
    "doubleAccounting",
    "none",
];
/// ST_PatternType.
const PATTERNS: &[&str] = &[
    "none",
    "solid",
    "mediumGray",
    "darkGray",
    "lightGray",
    "darkHorizontal",
    "darkVertical",
    "darkDown",
    "darkUp",
    "darkGrid",
    "darkTrellis",
    "lightHorizontal",
    "lightVertical",
    "lightDown",
    "lightUp",
    "lightGrid",
    "lightTrellis",
    "gray125",
    "gray0625",
];
/// ST_BorderStyle.
const LINES: &[&str] = &[
    "none",
    "thin",
    "medium",
    "dashed",
    "dotted",
    "thick",
    "double",
    "hair",
    "mediumDashed",
    "dashDot",
    "mediumDashDot",
    "dashDotDot",
    "mediumDashDotDot",
    "slantDashDot",
];
/// ST_HorizontalAlignment.
const HORIZONTAL: &[&str] = &[
    "general",
    "left",
    "center",
    "right",
    "fill",
    "justify",
    "centerContinuous",
    "distributed",
];
/// ST_VerticalAlignment.
const VERTICAL: &[&str] = &["top", "center", "bottom", "justify", "distributed"];
/// Excel's ceiling on a cell's indent, in steps.
const MAX_INDENT: u32 = 250;
/// The text rotation that stacks letters top to bottom.
const STACKED: u32 = 255;
/// Excel's ceiling on a cell style's name.
const MAX_STYLE_NAME: usize = 255;

/// Refuse a format the workbook could not hold: a base past its `styles`
/// cell formats, a style name, font size or name, a pattern, line style,
/// color, number format or alignment out of range.
pub fn check_format(format: &XlsxFormat, styles: usize) -> Result<()> {
    if format.base as usize >= styles {
        return Err(refused("a cell format the workbook does not have"));
    }
    if format.cell_style.as_deref().is_some_and(|name| {
        name.trim().is_empty() || name.chars().count() > MAX_STYLE_NAME || !writable(name)
    }) {
        return Err(refused("a cell style name is 1 to 255 characters"));
    }
    if let Some(alignment) = &format.alignment {
        if alignment
            .horizontal
            .as_deref()
            .is_some_and(|value| !HORIZONTAL.contains(&value))
        {
            return Err(refused("not a horizontal alignment"));
        }
        if alignment
            .vertical
            .as_deref()
            .is_some_and(|value| !VERTICAL.contains(&value))
        {
            return Err(refused("not a vertical alignment"));
        }
        if alignment.indent.is_some_and(|indent| indent > MAX_INDENT) {
            return Err(refused("an indent is 0 to 250 steps"));
        }
        if alignment
            .rotation
            .is_some_and(|angle| angle > 180 && angle != STACKED)
        {
            return Err(refused("a text rotation is 0 to 180 degrees, or 255"));
        }
        if alignment.reading_order.is_some_and(|order| order > 2) {
            return Err(refused("a reading order is 0, 1 or 2"));
        }
    }
    if let Some(font) = &format.font {
        if font.name.as_deref().is_some_and(|name| {
            name.trim().is_empty() || name.chars().count() > MAX_FONT_NAME || !writable(name)
        }) {
            return Err(refused("a font name is 1 to 31 characters"));
        }
        if font.size.is_some_and(|size| !FONT_SIZES.contains(&size)) {
            return Err(refused("a font size is 1 to 409 points"));
        }
        if font
            .underline
            .as_deref()
            .is_some_and(|line| !UNDERLINES.contains(&line))
        {
            return Err(refused("not an underline style"));
        }
        font.color.as_ref().map(check_color).transpose()?;
    }
    if let Some(fill) = &format.fill {
        if !PATTERNS.contains(&fill.pattern.as_str()) {
            return Err(refused("not a fill pattern"));
        }
        fill.fg.as_ref().map(check_color).transpose()?;
        fill.bg.as_ref().map(check_color).transpose()?;
    }
    if let Some(border) = &format.border {
        for edge in [
            &border.left,
            &border.right,
            &border.top,
            &border.bottom,
            &border.diagonal,
        ]
        .into_iter()
        .flatten()
        {
            if !LINES.contains(&edge.style.as_str()) {
                return Err(refused("not a border line style"));
            }
            edge.color.as_ref().map(check_color).transpose()?;
        }
    }
    match &format.number_format {
        Some(XlsxNumberFormat::Builtin { id }) if *id >= FIRST_CUSTOM_FORMAT => {
            Err(refused("a built-in number format is 0 to 163"))
        }
        Some(XlsxNumberFormat::Code { code })
            if code.is_empty() || code.chars().count() > MAX_FORMAT_CODE || !writable(code) =>
        {
            Err(refused("a number format code is 1 to 255 characters"))
        }
        _ => Ok(()),
    }
}

fn check_color(color: &XlsxColor) -> Result<()> {
    match color {
        XlsxColor::Rgb { argb }
            if !matches!(argb.len(), 6 | 8) || !argb.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Err(refused("an RGB color is 6 or 8 hex digits"))
        }
        XlsxColor::Theme {
            tint: Some(tint), ..
        } if !(-1.0..=1.0).contains(tint) => Err(refused("a color tint is -1 to 1")),
        _ => Ok(()),
    }
}
