//! External-link routing (step 25): linked workbooks stay off this engine.
//!
//! External-link workbooks require a link-preserving fallback session, never
//! an unchecked openpyxl-to-LibreOffice round trip; the in-process engine has no linked-workbook resolver (the
//! upstream `CalamineAdapter::external_link_target` needs the `calamine`
//! feature this crate deliberately leaves off). Routing a workbook with
//! external references into this engine would silently drop the links, so the
//! decision is made before any evaluation:
//!
//! - any `xl/externalLinks/*.xml` part, or any `.rels` relationship whose
//!   `TargetMode` is `External`, routes to the openpyxl path unchanged;
//! - any formula whose parsed AST contains `ReferenceType::External` (a
//!   `[book]Sheet!A1` reference, quoted or bracket-pathed) routes the same way;
//! - anything else may use the in-process engine.
//!
//! The router only reads; it never rewrites parts and never discards unknown
//! XML. Detection failures fail closed toward openpyxl.
//! [`preserve_external_links`] checks the fallback's output the same way.

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

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: XmlLimits = XmlLimits {
        max_depth: 64,
        max_nodes: 10_000,
    };

    #[test]
    fn local_workbook_routes_in_process() {
        let decision = route_workbook(
            ["xl/workbook.xml", "xl/worksheets/sheet1.xml"],
            [
                br#"<Relationships><Relationship Target="worksheets/sheet1.xml"/></Relationships>"#
                    .as_slice(),
            ],
            ["=SUM(A1:A3)", "=XLOOKUP(1,A:A,B:B)"],
            LIMITS,
        );
        assert_eq!(decision, RouteDecision::InProcess);
    }

    #[test]
    fn external_links_part_routes_to_openpyxl() {
        let decision = route_workbook(
            ["xl/workbook.xml", "xl/externalLinks/externalLink1.xml"],
            [],
            ["=SUM(A1:A3)"],
            LIMITS,
        );
        assert_eq!(
            decision,
            RouteDecision::Openpyxl {
                reason: "external-links-part"
            }
        );
    }

    #[test]
    fn external_rels_target_routes_to_openpyxl() {
        let rels = br#"<Relationships><Relationship Id="rId1" TargetMode="External" Target="https://example.invalid/x.xlsx"/></Relationships>"#;
        let decision = route_workbook(["xl/workbook.xml"], [rels.as_slice()], ["=SUM(A1)"], LIMITS);
        assert_eq!(
            decision,
            RouteDecision::Openpyxl {
                reason: "external-rels-target"
            }
        );
    }

    #[test]
    fn encoded_external_mode_and_external_callee_fail_closed() {
        let rels = br#"<Relationships><Relationship TargetMode='Ext&#101;rnal' Target='book.xlsx'/></Relationships>"#;
        assert!(!route_workbook([], [rels.as_slice()], [], LIMITS).is_in_process());
        assert!(!route_workbook([], [], ["=LAMBDA(x,'[1]S'!A1+x)(2)"], LIMITS).is_in_process());
    }

    #[test]
    fn external_formula_reference_routes_to_openpyxl() {
        let decision = route_workbook(
            ["xl/workbook.xml"],
            [],
            ["='[1]Sheet1'!A1+2", "=SUM(A1:A3)"],
            LIMITS,
        );
        assert_eq!(
            decision,
            RouteDecision::Openpyxl {
                reason: "external-formula-reference"
            }
        );
    }

    #[test]
    fn unparseable_formula_fails_closed_to_openpyxl() {
        let decision = route_workbook(["xl/workbook.xml"], [], ["=SUM(("], LIMITS);
        assert_eq!(
            decision,
            RouteDecision::Openpyxl {
                reason: "external-formula-reference"
            }
        );
    }
}
