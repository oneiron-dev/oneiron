//! Conditional formats a body adds to a worksheet (FIX 3468): a rule over a
//! range, and the differential format a cell the rule matches is drawn in.
//! The projection writes each as its own `conditionalFormatting` after the
//! sheet's own rules, which keep their bytes and come first, and appends its
//! look to the stylesheet's `dxfs`.

use super::{
    Book, MAX_COLUMN, MAX_ROW, Result, XlsxArea, XlsxAxisEdit, XlsxLock, XlsxValue, check_cell,
    escape_attribute, escape_text, insertion, moved_list, refused, splice, storage_form,
};
use crate::ooxml::XmlTree;
use crate::xlsx_styles::{XlsxDifferentialFormat, check_differential_format, write_dxfs};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The worksheet elements a `conditionalFormatting` follows, itself last.
const BEFORE: &[&str] = &[
    "sheetData",
    "sheetCalcPr",
    "sheetProtection",
    "protectedRanges",
    "scenarios",
    "autoFilter",
    "sortState",
    "dataConsolidate",
    "customSheetViews",
    "mergeCells",
    "phoneticPr",
    "conditionalFormatting",
];

/// One conditional format on a worksheet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxConditionalFormat {
    /// The cells it covers: one or more ranges, space-separated (`B2:B20 D2`).
    pub range: String,
    pub rule: XlsxConditionalRule,
    /// The look a cell the rule matches takes.
    pub format: XlsxDifferentialFormat,
    /// No later rule applies to a cell this one matches.
    #[serde(default)]
    pub stop_if_true: bool,
}

/// When a cell takes a conditional format's look. A formula is written
/// without its `=`, as for the range's top-left cell; Excel moves its
/// relative references for each other cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum XlsxConditionalRule {
    /// The cell's value compared with one formula's, or with two for
    /// `between` and `not_between`.
    CellIs {
        operator: XlsxConditionalOperator,
        formulas: Vec<String>,
    },
    /// A formula that is true for a matching cell.
    Expression { formula: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XlsxConditionalOperator {
    Between,
    NotBetween,
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

impl XlsxConditionalOperator {
    /// Its `ST_ConditionalFormattingOperator` spelling.
    fn spelling(self) -> &'static str {
        match self {
            Self::Between => "between",
            Self::NotBetween => "notBetween",
            Self::Equal => "equal",
            Self::NotEqual => "notEqual",
            Self::GreaterThan => "greaterThan",
            Self::LessThan => "lessThan",
            Self::GreaterThanOrEqual => "greaterThanOrEqual",
            Self::LessThanOrEqual => "lessThanOrEqual",
        }
    }

    /// How many formulas it compares with.
    fn operands(self) -> usize {
        match self {
            Self::Between | Self::NotBetween => 2,
            _ => 1,
        }
    }
}

impl XlsxConditionalRule {
    /// Its formulas, in order.
    #[must_use]
    pub fn formulas(&self) -> &[String] {
        match self {
            Self::CellIs { formulas, .. } => formulas,
            Self::Expression { formula } => std::slice::from_ref(formula),
        }
    }

    /// Its formulas, to rewrite in place.
    pub fn formulas_mut(&mut self) -> &mut [String] {
        match self {
            Self::CellIs { formulas, .. } => formulas,
            Self::Expression { formula } => std::slice::from_mut(formula),
        }
    }
}

/// Refuse a conditional format the worksheet could not hold: a range that
/// does not read as cells on the sheet, a formula [`check_cell`] refuses, the
/// wrong count of formulas for its operator, or a look the stylesheet could
/// not hold.
pub fn check_conditional(format: &XlsxConditionalFormat) -> Result<()> {
    let mut ranges = format.range.split_whitespace().peekable();
    if ranges.peek().is_none()
        || !ranges.all(|range| {
            XlsxArea::parse(range, XlsxLock::Unsupported)
                .is_some_and(|area| area.last.0 <= MAX_COLUMN && area.last.1 <= MAX_ROW)
        })
    {
        return Err(refused(
            "a conditional format's range is one or more cell ranges, space-separated",
        ));
    }
    if let XlsxConditionalRule::CellIs { operator, formulas } = &format.rule
        && formulas.len() != operator.operands()
    {
        return Err(refused(
            "a cell-value rule compares with two formulas for between and not_between, else one",
        ));
    }
    for formula in format.rule.formulas() {
        check_cell(&XlsxValue::Blank, Some(formula.as_str()))?;
    }
    check_differential_format(&format.format)
}

/// `range` after a row or column edit, without what it deletes; `None` when
/// the edit deletes all of it.
#[must_use]
pub fn shift_conditional_range(range: &str, edit: &XlsxAxisEdit) -> Option<String> {
    let moved = moved_list(range, edit);
    (!moved.is_empty()).then_some(moved)
}

impl Book {
    /// Write `formats` onto worksheet `sheet` after its own conditional
    /// formats, each its own rule ranked after every rule the sheet has, its
    /// look added to the stylesheet's `dxfs`.
    pub(super) fn add_conditional_formats(
        &mut self,
        sheet: &str,
        formats: &[XlsxConditionalFormat],
    ) -> Result<()> {
        if formats.is_empty() {
            return Ok(());
        }
        for format in formats {
            check_conditional(format)?;
        }
        let looks: Vec<XlsxDifferentialFormat> =
            formats.iter().map(|format| format.format.clone()).collect();
        let dxfs = self.resolve_dxfs(&looks)?;
        let part = self
            .worksheets
            .get(sheet)
            .ok_or(refused("no such worksheet"))?
            .clone();
        let bytes = self
            .package
            .part(&part)?
            .ok_or(refused("a workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.resources())?;
        // Every rule the sheet has, its extensions' included, ranks first.
        let mut priority = tree
            .nodes
            .iter()
            .filter(|node| node.name == "cfRule")
            .filter_map(|node| node.attr("priority")?.trim().parse::<u32>().ok())
            .max()
            .unwrap_or(0);
        let root = &tree.nodes[0];
        let (block, rule, formula) = (
            root.child_name("conditionalFormatting"),
            root.child_name("cfRule"),
            root.child_name("formula"),
        );
        let mut added = String::new();
        for (format, dxf) in formats.iter().zip(dxfs) {
            priority = priority.saturating_add(1);
            let (kind, operator) = match &format.rule {
                XlsxConditionalRule::CellIs { operator, .. } => {
                    ("cellIs", format!(" operator=\"{}\"", operator.spelling()))
                }
                XlsxConditionalRule::Expression { .. } => ("expression", String::new()),
            };
            let stop = if format.stop_if_true {
                " stopIfTrue=\"1\""
            } else {
                ""
            };
            added.push_str(&format!(
                "<{block} sqref=\"{}\"><{rule} type=\"{kind}\" dxfId=\"{dxf}\" priority=\"{priority}\"{stop}{operator}>",
                escape_attribute(&format.range)
            ));
            for text in format.rule.formulas() {
                added.push_str(&format!(
                    "<{formula}>{}</{formula}>",
                    escape_text(&storage_form(text))
                ));
            }
            added.push_str(&format!("</{rule}></{block}>"));
        }
        let at = insertion(&tree, BEFORE).ok_or(refused("a worksheet has no cell data"))?;
        let value = splice(&bytes, vec![(at..at, added.into_bytes())])
            .map_err(|_| refused("a worksheet could not be rewritten"))?;
        self.package.replace_xml_part(&part, value)?;
        Ok(())
    }

    /// Write `looks` into the stylesheet's `dxfs`: each one's index there, in
    /// order. A workbook with no stylesheet gets a minimal one first.
    fn resolve_dxfs(&mut self, looks: &[XlsxDifferentialFormat]) -> Result<Vec<u32>> {
        let part = match self.styles_part.clone() {
            Some(part) => part,
            None => self.seed_styles()?,
        };
        let bytes = self
            .package
            .part(&part)?
            .ok_or(refused("a workbook part is missing"))?;
        let (indices, value) = write_dxfs(&bytes, self.package.resources(), looks)?;
        if let Some(value) = value {
            self.package.replace_xml_part(&part, value)?;
        }
        Ok(indices)
    }
}
