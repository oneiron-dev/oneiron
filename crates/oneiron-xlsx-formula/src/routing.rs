//! External links on the precision fallback's route.
//!
//! The in-process engine recalculates a linked workbook itself when it reads
//! the link's saved values exactly as Excel does with the linked workbook
//! closed (`crate::links`). Every other workbook with an external link goes to
//! the host's fallback session, never an unchecked openpyxl-to-LibreOffice
//! round trip: [`preserve_external_links`] refuses fallback output that alters
//! or drops a link. [`route_workbook`] finds what is external:
//!
//! - any `xl/externalLinks/*.xml` part, or any `.rels` relationship whose
//!   `TargetMode` is `External`;
//! - any formula whose parsed AST contains `ReferenceType::External` (a
//!   `[book]Sheet!A1` reference, quoted or bracket-pathed);
//! - anything else is local.
//!
//! The router only reads; it never rewrites parts and never discards unknown
//! XML. Detection failures fail closed toward the fallback.

use formualizer_parse::parser::{ASTNode, ASTNodeType, ReferenceType};

use oneiron_docedit::retained_opc::{Limits, Package, XmlLimits};

pub use crate::calc::RouteDecision;

/// Check that a fallback round trip kept every external link of `before`:
/// `xl/externalLinks/` parts and `.rels` parts naming an external target stay
/// byte-identical, and every external formula keeps its cell and text.
///
/// `Err` carries the reason the output is refused, including when either
/// package cannot be inspected under `limits`. Pure: it only reads.
pub fn preserve_external_links(
    before: &[u8],
    after: &[u8],
    limits: Limits,
) -> std::result::Result<(), &'static str> {
    let before = Package::open(before, limits).map_err(|_| "unreadable input package")?;
    let after = Package::open(after, limits).map_err(|_| "unreadable output package")?;
    for name in before.names() {
        let link_part = name.starts_with("xl/externalLinks/");
        if !link_part && !name.ends_with(".rels") {
            continue;
        }
        let part = before
            .part(name)
            .map_err(|_| "unreadable input part")?
            .ok_or("missing external-link input part")?;
        let protected =
            link_part || !route_workbook([], [part.as_slice()], [], limits.xml).is_in_process();
        if protected
            && after
                .part(name)
                .map_err(|_| "unreadable output part")?
                .as_ref()
                != Some(&part)
        {
            return Err("fallback altered or dropped an external-link part");
        }
    }
    let before_formulas = crate::workbook::external_formulas(&before)
        .map_err(|_| "cannot inspect external formula links")?;
    if !before_formulas.is_empty() {
        let after_formulas = crate::workbook::external_formulas(&after)
            .map_err(|_| "cannot inspect output external formula links")?;
        if before_formulas
            .iter()
            .any(|(cell, formula)| after_formulas.get(cell) != Some(formula))
        {
            return Err("fallback altered or dropped an external formula link");
        }
    }
    Ok(())
}

/// Decide the recalc route for a workbook from its part names, relationship
/// XML, and parsed formulas.
///
/// `part_names` are OPC part paths; `rels_xml` are the bytes of every `.rels`
/// part, read under `limits`; `formulas` are UI formula strings, parsed here
/// so a parse failure also fails closed. Pure and deterministic: same inputs,
/// same decision.
pub fn route_workbook<'a>(
    part_names: impl IntoIterator<Item = &'a str>,
    rels_xml: impl IntoIterator<Item = &'a [u8]>,
    formulas: impl IntoIterator<Item = &'a str>,
    limits: XmlLimits,
) -> RouteDecision {
    for name in part_names {
        if name.starts_with("xl/externalLinks/") {
            return RouteDecision::Openpyxl {
                reason: "external-links-part",
            };
        }
    }
    for xml in rels_xml {
        if rels_has_external_target(xml, limits) {
            return RouteDecision::Openpyxl {
                reason: "external-rels-target",
            };
        }
    }
    for formula in formulas {
        // `Err(())` (unparseable) fails closed: only a clean parse proving
        // locality keeps the in-process route.
        let external = has_external_reference(formula).unwrap_or(true);
        if external {
            return RouteDecision::Openpyxl {
                reason: "external-formula-reference",
            };
        }
    }
    RouteDecision::InProcess
}

/// True when a `.rels` document names an external target. The scan is a
/// namespace-aware parse of `TargetMode="External"`, including entities; unknown XML
/// elsewhere in the part is ignored, never stripped or rewritten.
fn rels_has_external_target(xml: &[u8], limits: XmlLimits) -> bool {
    crate::xml::Xml::parse(xml, limits).map_or(true, |xml| {
        xml.nodes
            .iter()
            .any(|node| node.attr("TargetMode") == Some("External"))
    })
}

/// Parse a formula with the parser's mandatory leading `=`. Unlike the
/// workbook setter, `parse` treats unprefixed input as literal text.
fn has_external_reference(formula: &str) -> std::result::Result<bool, ()> {
    let expression = if formula.starts_with('=') {
        std::borrow::Cow::Borrowed(formula)
    } else {
        std::borrow::Cow::Owned(format!("={formula}"))
    };
    let ast = formualizer_parse::parse(expression.as_ref()).map_err(|_| ())?;
    Ok(ast_contains_external(&ast))
}

fn ast_contains_external(node: &ASTNode) -> bool {
    match &node.node_type {
        ASTNodeType::Literal(_) | ASTNodeType::Omitted => false,
        ASTNodeType::Reference { reference, .. } => {
            matches!(reference, ReferenceType::External(_))
        }
        ASTNodeType::UnaryOp { expr, .. } => ast_contains_external(expr),
        ASTNodeType::BinaryOp { left, right, .. } => {
            ast_contains_external(left) || ast_contains_external(right)
        }
        ASTNodeType::Function { args, .. } => args.iter().any(ast_contains_external),
        ASTNodeType::Call { callee, args } => {
            ast_contains_external(callee) || args.iter().any(ast_contains_external)
        }
        ASTNodeType::Array(rows) => rows.iter().flatten().any(ast_contains_external),
    }
}
