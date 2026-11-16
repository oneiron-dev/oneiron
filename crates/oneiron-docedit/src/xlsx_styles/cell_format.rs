//! The cell format a body composes and its parts: font, fill, border, number
//! format, alignment and protection.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A cell format composed from one of the workbook's: `base`, an index into
/// [`XlsxBook::styles`](crate::xlsx_body::XlsxBook::styles), with the parts
/// set here changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxFormat {
    pub base: u32,
    /// A named cell style (`Normal`, `Good`, `Heading 1` or one the workbook
    /// defines; case does not matter), applied as Excel applies one first:
    /// each part the style includes replaces the base's, and the changes
    /// below go on top. A name the workbook lacks is added as a style of the
    /// base's look, where Excel would refuse it.
    pub cell_style: Option<String>,
    /// Changes to the base's font.
    pub font: Option<XlsxFont>,
    /// Replaces the base's fill.
    pub fill: Option<XlsxFill>,
    /// Changes to the base's borders.
    pub border: Option<XlsxBorder>,
    /// Replaces the base's number format.
    pub number_format: Option<XlsxNumberFormat>,
    /// Changes to the base's alignment.
    pub alignment: Option<XlsxAlignment>,
    /// Changes to the base's protection.
    pub protection: Option<XlsxProtection>,
}

/// A change to a cell's alignment: what is left out stays the base's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxAlignment {
    /// `general`, `left`, `center`, `right`, `fill`, `justify`,
    /// `centerContinuous` or `distributed`.
    pub horizontal: Option<String>,
    /// `top`, `center`, `bottom`, `justify` or `distributed`.
    pub vertical: Option<String>,
    pub wrap_text: Option<bool>,
    pub shrink_to_fit: Option<bool>,
    /// Indent steps, 0 to 250.
    pub indent: Option<u32>,
    /// The text's angle in degrees: 0 to 90 turns it up, 91 to 180 turns it
    /// down by the amount past 90, and 255 stacks its letters.
    pub rotation: Option<u32>,
    /// 0 follows the text, 1 reads left to right, 2 right to left.
    pub reading_order: Option<u32>,
}

/// A change to a cell's protection, which holds once its sheet is protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxProtection {
    /// The cell refuses edits.
    pub locked: Option<bool>,
    /// The formula bar hides the cell's formula.
    pub hidden: Option<bool>,
}

/// A change to a font: what is left out stays the base font's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxFont {
    /// A font family name, up to 31 characters; the font then no longer
    /// follows the theme's fonts.
    pub name: Option<String>,
    /// Points, 1 to 409.
    pub size: Option<f64>,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    /// `single`, `double`, `singleAccounting`, `doubleAccounting` or `none`.
    pub underline: Option<String>,
    pub strike: Option<bool>,
    pub color: Option<XlsxColor>,
}

/// A pattern fill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxFill {
    /// `none`, `solid`, `gray125`, `darkGray`, `lightGrid` and the other
    /// SpreadsheetML patterns.
    pub pattern: String,
    /// The pattern's color; a solid fill's only one.
    pub fg: Option<XlsxColor>,
    /// The color behind the pattern.
    pub bg: Option<XlsxColor>,
}

/// A change to the borders: an edge left out stays the base's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxBorder {
    pub left: Option<XlsxEdge>,
    pub right: Option<XlsxEdge>,
    pub top: Option<XlsxEdge>,
    pub bottom: Option<XlsxEdge>,
    /// The diagonal line; `diagonal_up` and `diagonal_down` say which.
    pub diagonal: Option<XlsxEdge>,
    pub diagonal_up: Option<bool>,
    pub diagonal_down: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxEdge {
    /// `none`, `thin`, `medium`, `thick`, `double`, `dashed`, `dotted`,
    /// `hair` and the other SpreadsheetML line styles.
    pub style: String,
    pub color: Option<XlsxColor>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum XlsxColor {
    /// `RRGGBB`, or `AARRGGBB` with alpha.
    Rgb { argb: String },
    /// A theme color, lightened (a positive `tint`) or darkened (a negative
    /// one), -1 to 1.
    Theme { theme: u32, tint: Option<f64> },
    /// A legacy palette color.
    Indexed { index: u32 },
    /// The application's automatic color.
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum XlsxNumberFormat {
    /// A built-in format, 0 to 163 (0 is General, 14 a short date).
    Builtin { id: u32 },
    /// A format code such as `0.00%` or `yyyy-mm-dd`, 1 to 255 characters.
    Code { code: String },
}
