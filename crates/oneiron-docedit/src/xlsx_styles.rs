//! Cell formats a body composes from the workbook's own: an imported cell
//! format with its named cell style, font, fill, border, number format,
//! alignment or protection changed. The
//! projection writes each into the stylesheet, reusing an equal font, fill,
//! border, number format or cell format already there, so the stylesheet
//! grows only by what is new; imported records keep their bytes and indices.

use crate::edit::xml::{escape_attribute, set_attribute, splice, writable};
use crate::ooxml::{SPREADSHEET_MAIN as SML, XmlTree, escape_text};
use crate::retained_opc::XmlLimits;
use crate::xlsx_body::XlsxBodyError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Write as _};

/// The first number format id a workbook defines; lower ids are built in.
const FIRST_CUSTOM_FORMAT: u32 = 164;
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
/// A cell format's children in schema order.
const XF_ORDER: &[&str] = &["alignment", "protection", "extLst"];
/// What a named cell style may carry, each with the flag that says a style
/// includes it: an id attribute, or the child element of that name.
const STYLE_PARTS: &[(&str, &str)] = &[
    ("numFmtId", "applyNumberFormat"),
    ("fontId", "applyFont"),
    ("fillId", "applyFill"),
    ("borderId", "applyBorder"),
    ("alignment", "applyAlignment"),
    ("protection", "applyProtection"),
];
/// A font's children in the order Excel writes them.
const FONT_ORDER: &[&str] = &[
    "b",
    "i",
    "strike",
    "condense",
    "extend",
    "outline",
    "shadow",
    "u",
    "vertAlign",
    "sz",
    "color",
    "name",
    "family",
    "charset",
    "scheme",
];
/// A border's edges in schema order.
const BORDER_ORDER: &[&str] = &[
    "start",
    "left",
    "end",
    "right",
    "top",
    "bottom",
    "diagonal",
    "vertical",
    "horizontal",
];
/// The stylesheet's children in schema order, which places a missing list.
const SHEET_ORDER: &[&str] = &[
    "numFmts",
    "fonts",
    "fills",
    "borders",
    "cellStyleXfs",
    "cellXfs",
    "cellStyles",
    "dxfs",
    "tableStyles",
    "colors",
    "extLst",
];

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

type Result<T> = std::result::Result<T, XlsxBodyError>;

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

/// Write `formats` into the stylesheet `bytes`, whose `cellXfs` holds the
/// `styles` cell formats the body read: each format's index in `cellXfs`, in
/// order, and the stylesheet's new bytes when any record was added.
pub(crate) fn write_formats(
    bytes: &[u8],
    limits: XmlLimits,
    formats: &[XlsxFormat],
    styles: usize,
) -> Result<(Vec<u32>, Option<Vec<u8>>)> {
    let tree = XmlTree::parse(bytes, limits)?;
    tree.root(SML, "styleSheet")
        .map_err(|_| refused("the stylesheet is not SpreadsheetML"))?;
    let mut num_fmts = List::read(&tree, "numFmts", "numFmt")?;
    let mut fonts = List::read(&tree, "fonts", "font")?;
    let mut fills = List::read(&tree, "fills", "fill")?;
    let mut borders = List::read(&tree, "borders", "border")?;
    let mut xfs = List::read(&tree, "cellXfs", "xf")?;
    let mut style_xfs = List::read(&tree, "cellStyleXfs", "xf")?;
    let mut cell_styles = List::read(&tree, "cellStyles", "cellStyle")?;
    if xfs.imported != styles {
        return Err(refused("the stylesheet changed under the body"));
    }
    let mut indices = Vec::with_capacity(formats.len());
    for format in formats {
        check_format(format, styles)?;
        let mut xf = xfs.entries[format.base as usize].clone();
        if let Some(name) = &format.cell_style {
            apply_cell_style(&mut xf, name, &mut style_xfs, &mut cell_styles)?;
        }
        let part = |name: &str| {
            xf.attrs
                .get(name)
                .and_then(|id| id.trim().parse::<usize>().ok())
                .unwrap_or(0)
        };
        let (font_id, border_id) = (part("fontId"), part("borderId"));
        if let Some(patch) = &format.font {
            let mut font = fonts
                .entries
                .get(font_id)
                .cloned()
                .unwrap_or_else(|| Element::new("font"));
            patch_font(&mut font, patch);
            xf.set("fontId", fonts.find_or_push(font)?);
            xf.set("applyFont", 1);
        }
        if let Some(fill) = &format.fill {
            let mut pattern = Element::new("patternFill");
            pattern.set("patternType", &fill.pattern);
            pattern
                .children
                .extend(fill.fg.as_ref().map(|fg| color("fgColor", fg)));
            pattern
                .children
                .extend(fill.bg.as_ref().map(|bg| color("bgColor", bg)));
            let mut element = Element::new("fill");
            element.children.push(pattern);
            xf.set("fillId", fills.find_or_push(element)?);
            xf.set("applyFill", 1);
        }
        if let Some(patch) = &format.border {
            let mut border = borders
                .entries
                .get(border_id)
                .cloned()
                .unwrap_or_else(|| Element::new("border"));
            patch_border(&mut border, patch);
            xf.set("borderId", borders.find_or_push(border)?);
            xf.set("applyBorder", 1);
        }
        if let Some(number) = &format.number_format {
            let id = match number {
                XlsxNumberFormat::Builtin { id } => *id,
                XlsxNumberFormat::Code { code } => code_id(&mut num_fmts, code),
            };
            xf.set("numFmtId", id);
            xf.set("applyNumberFormat", 1);
        }
        if let Some(patch) = &format.alignment {
            let mut alignment = xf
                .child("alignment")
                .cloned()
                .unwrap_or_else(|| Element::new("alignment"));
            patch_alignment(&mut alignment, patch);
            xf.put(alignment, XF_ORDER);
            xf.set("applyAlignment", 1);
        }
        if let Some(patch) = &format.protection {
            let mut protection = xf
                .child("protection")
                .cloned()
                .unwrap_or_else(|| Element::new("protection"));
            // Unwritten, a cell is locked and its formula shown.
            for (name, on) in [("locked", patch.locked), ("hidden", patch.hidden)] {
                if let Some(on) = on {
                    protection.set(name, u8::from(on));
                }
            }
            xf.put(protection, XF_ORDER);
            xf.set("applyProtection", 1);
        }
        indices.push(xfs.find_or_push(xf)?);
    }
    let prefix = tree.nodes[0]
        .qualified
        .rsplit_once(':')
        .map_or_else(String::new, |(prefix, _)| format!("{prefix}:"));
    let mut edits = Vec::new();
    for list in [
        &num_fmts,
        &fonts,
        &fills,
        &borders,
        &style_xfs,
        &xfs,
        &cell_styles,
    ] {
        list.write(&tree, bytes, &prefix, &mut edits);
    }
    if edits.is_empty() {
        return Ok((indices, None));
    }
    let value =
        splice(bytes, edits).map_err(|_| refused("the stylesheet could not be rewritten"))?;
    Ok((indices, Some(value)))
}

/// One stylesheet list: its records, imported ones first, then those added.
struct List {
    name: &'static str,
    /// The list element, when the stylesheet has one.
    node: Option<usize>,
    entries: Vec<Element>,
    imported: usize,
}

impl List {
    fn read(tree: &XmlTree, name: &'static str, entry: &str) -> Result<Self> {
        let node = tree.child(0, SML, name)?.map(|(index, _)| index);
        let entries: Vec<Element> = node
            .map(|list| {
                tree.children(list)
                    .filter(|(_, node)| node.is(SML, entry))
                    .map(|(index, _)| Element::read(tree, index))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            name,
            node,
            imported: entries.len(),
            entries,
        })
    }

    /// The index of an equal record, appending this one when there is none.
    fn find_or_push(&mut self, entry: Element) -> Result<u32> {
        let at = match self.entries.iter().position(|held| *held == entry) {
            Some(at) => at,
            None => {
                self.entries.push(entry);
                self.entries.len() - 1
            }
        };
        u32::try_from(at).map_err(|_| refused("a stylesheet list is too long"))
    }

    /// The edits that write the records added: before the list's close tag,
    /// its `count` fixed, or a new list where the schema places it.
    fn write(
        &self,
        tree: &XmlTree,
        bytes: &[u8],
        prefix: &str,
        edits: &mut Vec<(std::ops::Range<usize>, Vec<u8>)>,
    ) {
        if self.entries.len() == self.imported {
            return;
        }
        let mut added = String::new();
        for entry in &self.entries[self.imported..] {
            entry.write(prefix, &mut added);
        }
        let count = self.entries.len().to_string();
        match self.node.map(|index| &tree.nodes[index]) {
            Some(node) => {
                edits.push(set_attribute(bytes, node, "count", &count));
                if node.empty {
                    // `<fonts count="0"/>` opens around what it now holds.
                    let end = node.open_end;
                    edits.push((
                        end - 2..end,
                        format!(">{added}</{}>", node.qualified).into_bytes(),
                    ));
                } else {
                    let at = node.content.end;
                    edits.push((at..at, added.into_bytes()));
                }
            }
            None => {
                let rank = |name: &str| SHEET_ORDER.iter().position(|held| *held == name);
                let own = rank(self.name);
                let at = tree
                    .children(0)
                    .filter(|(_, node)| node.namespace == SML)
                    .filter(|(_, node)| rank(&node.name) < own)
                    .map(|(_, node)| node.span.end)
                    .max()
                    .unwrap_or(tree.nodes[0].open_end);
                let name = format!("{prefix}{}", self.name);
                edits.push((
                    at..at,
                    format!("<{name} count=\"{count}\">{added}</{name}>").into_bytes(),
                ));
            }
        }
    }
}

/// One stylesheet element as records compare: a SpreadsheetML element by its
/// local name (written with the stylesheet's prefix), another by its written
/// name, with its attributes, text and children as read.
#[derive(Debug, Clone, PartialEq)]
struct Element {
    sml: bool,
    name: String,
    attrs: BTreeMap<String, String>,
    text: String,
    children: Vec<Element>,
}

impl Element {
    fn new(name: &str) -> Self {
        Self {
            sml: true,
            name: name.to_owned(),
            attrs: BTreeMap::new(),
            text: String::new(),
            children: Vec::new(),
        }
    }

    fn read(tree: &XmlTree, index: usize) -> Self {
        let node = &tree.nodes[index];
        let sml = node.namespace == SML;
        Self {
            sml,
            name: if sml {
                node.name.clone()
            } else {
                node.qualified.clone()
            },
            attrs: node.attrs.clone(),
            text: if node.children.is_empty() {
                node.text.trim().to_owned()
            } else {
                String::new()
            },
            children: node
                .children
                .iter()
                .map(|&child| Self::read(tree, child))
                .collect(),
        }
    }

    fn set(&mut self, name: &str, value: impl Display) {
        self.attrs.insert(name.to_owned(), value.to_string());
    }

    fn flag(&mut self, name: &str, on: Option<bool>) {
        match on {
            Some(true) => self.set(name, 1),
            Some(false) => {
                self.attrs.remove(name);
            }
            None => {}
        }
    }

    /// Put `child` in place of the SpreadsheetML child of its name, or where
    /// `order` places it.
    fn put(&mut self, child: Self, order: &[&str]) {
        if let Some(held) = self
            .children
            .iter_mut()
            .find(|held| held.sml && held.name == child.name)
        {
            *held = child;
            return;
        }
        let rank = |name: &str| order.iter().position(|held| *held == name);
        let own = rank(&child.name);
        let at = self
            .children
            .iter()
            .position(|held| held.sml && rank(&held.name) > own)
            .unwrap_or(self.children.len());
        self.children.insert(at, child);
    }

    /// The SpreadsheetML child of this name.
    fn child(&self, name: &str) -> Option<&Self> {
        self.children
            .iter()
            .find(|held| held.sml && held.name == name)
    }

    fn remove(&mut self, name: &str) {
        self.children
            .retain(|held| !(held.sml && held.name == name));
    }

    fn write(&self, prefix: &str, out: &mut String) {
        let name = if self.sml {
            format!("{prefix}{}", self.name)
        } else {
            self.name.clone()
        };
        let _ = write!(out, "<{name}");
        for (key, value) in &self.attrs {
            let _ = write!(out, " {key}=\"{}\"", escape_attribute(value));
        }
        if self.children.is_empty() && self.text.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        out.push_str(&escape_text(&self.text));
        for child in &self.children {
            child.write(prefix, out);
        }
        let _ = write!(out, "</{name}>");
    }
}

fn patch_font(font: &mut Element, patch: &XlsxFont) {
    let toggle = |font: &mut Element, name: &str, on: Option<bool>| match on {
        Some(true) => font.put(Element::new(name), FONT_ORDER),
        Some(false) => font.remove(name),
        None => {}
    };
    toggle(font, "b", patch.bold);
    toggle(font, "i", patch.italic);
    toggle(font, "strike", patch.strike);
    match patch.underline.as_deref() {
        Some("none") => font.remove("u"),
        Some(line) => {
            let mut underline = Element::new("u");
            underline.set("val", line);
            font.put(underline, FONT_ORDER);
        }
        None => {}
    }
    if let Some(size) = patch.size {
        let mut sz = Element::new("sz");
        sz.set("val", size);
        font.put(sz, FONT_ORDER);
    }
    if let Some(fill) = &patch.color {
        font.put(color("color", fill), FONT_ORDER);
    }
    if let Some(name) = &patch.name {
        let mut element = Element::new("name");
        element.set("val", name);
        font.put(element, FONT_ORDER);
        // A named font no longer follows the theme's major or minor font.
        font.remove("scheme");
    }
}

/// Apply the named cell style `name` to the cell format `xf` as Excel
/// does: each part the style's record includes (all but those flagged off)
/// replaces the format's, and the format then follows the style. A name the
/// workbook lacks is added as a style whose record is the format's own look.
fn apply_cell_style(
    xf: &mut Element,
    name: &str,
    style_xfs: &mut List,
    cell_styles: &mut List,
) -> Result<()> {
    let lower = name.to_lowercase();
    let held = cell_styles.entries.iter().find_map(|style| {
        (style.attrs.get("name")?.to_lowercase() == lower)
            .then(|| style.attrs.get("xfId")?.trim().parse::<usize>().ok())
            .flatten()
    });
    let at = match held.filter(|at| *at < style_xfs.entries.len()) {
        Some(at) => {
            let style = style_xfs.entries[at].clone();
            for (part, flag) in STYLE_PARTS {
                if style.attrs.get(*flag).map(String::as_str) == Some("0") {
                    continue;
                }
                if part.ends_with("Id") {
                    match style.attrs.get(*part) {
                        Some(id) => xf.set(part, id),
                        None => {
                            xf.attrs.remove(*part);
                        }
                    }
                } else {
                    match style.child(part) {
                        Some(child) => xf.put(child.clone(), XF_ORDER),
                        None => xf.remove(part),
                    }
                }
                xf.attrs.remove(*flag);
            }
            at
        }
        None => {
            let mut record = Element::new("xf");
            for (part, _) in STYLE_PARTS {
                if part.ends_with("Id") {
                    if let Some(id) = xf.attrs.get(*part) {
                        record.set(part, id);
                    }
                } else if let Some(child) = xf.child(part) {
                    record.put(child.clone(), XF_ORDER);
                }
            }
            let at = style_xfs.find_or_push(record)?;
            let mut style = Element::new("cellStyle");
            style.set("name", name);
            style.set("xfId", at);
            cell_styles.entries.push(style);
            at as usize
        }
    };
    xf.set("xfId", at);
    Ok(())
}

fn patch_alignment(alignment: &mut Element, patch: &XlsxAlignment) {
    for (name, value) in [
        ("horizontal", &patch.horizontal),
        ("vertical", &patch.vertical),
    ] {
        if let Some(value) = value {
            alignment.set(name, value);
        }
    }
    for (name, value) in [
        ("indent", patch.indent),
        ("textRotation", patch.rotation),
        ("readingOrder", patch.reading_order),
    ] {
        if let Some(value) = value {
            alignment.set(name, value);
        }
    }
    alignment.flag("wrapText", patch.wrap_text);
    alignment.flag("shrinkToFit", patch.shrink_to_fit);
}

fn patch_border(border: &mut Element, patch: &XlsxBorder) {
    // `start` and `end` are the newer names of `left` and `right`.
    for (name, alias, edge) in [
        ("left", Some("start"), &patch.left),
        ("right", Some("end"), &patch.right),
        ("top", None, &patch.top),
        ("bottom", None, &patch.bottom),
        ("diagonal", None, &patch.diagonal),
    ] {
        let Some(edge) = edge else {
            continue;
        };
        if let Some(alias) = alias {
            border.remove(alias);
        }
        let mut element = Element::new(name);
        if edge.style != "none" {
            element.set("style", &edge.style);
        }
        element
            .children
            .extend(edge.color.as_ref().map(|fill| color("color", fill)));
        border.put(element, BORDER_ORDER);
    }
    border.flag("diagonalUp", patch.diagonal_up);
    border.flag("diagonalDown", patch.diagonal_down);
}

fn color(name: &str, color: &XlsxColor) -> Element {
    let mut element = Element::new(name);
    match color {
        XlsxColor::Rgb { argb } => {
            let argb = argb.to_ascii_uppercase();
            let argb = if argb.len() == 6 {
                format!("FF{argb}")
            } else {
                argb
            };
            element.set("rgb", argb);
        }
        XlsxColor::Theme { theme, tint } => {
            element.set("theme", theme);
            if let Some(tint) = tint {
                element.set("tint", tint);
            }
        }
        XlsxColor::Indexed { index } => element.set("indexed", index),
        XlsxColor::Auto => element.set("auto", 1),
    }
    element
}

/// The id of a number format code: the workbook's own when it defines the
/// code, else a new one past every id it defines.
fn code_id(list: &mut List, code: &str) -> u32 {
    let id = |entry: &Element| {
        entry
            .attrs
            .get("numFmtId")
            .and_then(|id| id.trim().parse::<u32>().ok())
    };
    if let Some(held) = list
        .entries
        .iter()
        .find(|entry| entry.attrs.get("formatCode").map(String::as_str) == Some(code))
        .and_then(id)
    {
        return held;
    }
    let next = list
        .entries
        .iter()
        .filter_map(id)
        .map(|held| held.saturating_add(1))
        .max()
        .unwrap_or(0)
        .max(FIRST_CUSTOM_FORMAT);
    let mut entry = Element::new("numFmt");
    entry.set("numFmtId", next);
    entry.set("formatCode", code);
    list.entries.push(entry);
    next
}

fn refused(reason: &'static str) -> XlsxBodyError {
    XlsxBodyError::Refused(reason)
}
