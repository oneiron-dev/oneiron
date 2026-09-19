//! Keep ambient context out of the deterministic production recalc path.
use formualizer_parse::parser::{ASTNode, ASTNodeType};

/// The corpus clock is not a production caller's time, file or random seed.
/// Until the session supplies that context, use its precision fallback instead.
pub(super) fn requires_caller_context(formula: &str) -> bool {
    let expression = if formula.starts_with('=') {
        std::borrow::Cow::Borrowed(formula)
    } else {
        std::borrow::Cow::Owned(format!("={formula}"))
    };
    formualizer_parse::parse(expression.as_ref()).map_or(true, |node| contextual(&node))
}

fn contextual(node: &ASTNode) -> bool {
    match &node.node_type {
        ASTNodeType::Literal(_) | ASTNodeType::Omitted | ASTNodeType::Reference { .. } => false,
        ASTNodeType::UnaryOp { expr, .. } => contextual(expr),
        ASTNodeType::BinaryOp { left, right, .. } => contextual(left) || contextual(right),
        ASTNodeType::Function { name, args } => {
            let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
            matches!(
                name.as_str(),
                "NOW"
                    | "TODAY"
                    | "RAND"
                    | "RANDBETWEEN"
                    | "RANDARRAY"
                    | "CELL"
                    | "INFO"
                    | "OFFSET"
                    | "INDIRECT"
            ) || args.iter().any(contextual)
        }
        ASTNodeType::Call { callee, args } => contextual(callee) || args.iter().any(contextual),
        ASTNodeType::Array(rows) => rows.iter().flatten().any(contextual),
    }
}
