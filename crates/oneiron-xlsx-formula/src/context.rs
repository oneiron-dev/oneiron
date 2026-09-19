//! Bound formula AST evaluation and keep ambient context out of native recalc.
use formualizer_parse::TokenStream;
use formualizer_parse::parser::{ASTNode, ASTNodeType};

use crate::Result;
use crate::xml::unsupported;

// The upstream evaluator recursively walks expressions on worker threads. Real
// FUSE inputs with about 200 chained additions overflow that stack in debug
// builds. Bound tokens before constructing a recursive AST (including its Drop)
// and bound evaluation depth independently of the parser's own nesting guard.
const MAX_FORMULA_BYTES: usize = 32 * 1024;
const MAX_FORMULA_TOKENS: usize = 256;
const MAX_EVALUATION_DEPTH: usize = 32;

/// Prove bounded evaluation and return whether caller-owned context is needed.
/// The compatibility harness may supply deterministic context; production falls
/// back rather than substitute its corpus clock for the caller's time or seed.
pub(super) fn inspect_formula(formula: &str) -> Result<bool> {
    if formula.len() > MAX_FORMULA_BYTES {
        return Err(unsupported("formula byte limit"));
    }
    let expression = if formula.starts_with('=') {
        std::borrow::Cow::Borrowed(formula)
    } else {
        std::borrow::Cow::Owned(format!("={formula}"))
    };
    let tokens = TokenStream::new(&expression).map_err(|_| unsupported("formula tokenization"))?;
    if tokens.len() > MAX_FORMULA_TOKENS {
        return Err(unsupported("formula token limit"));
    }
    let node = formualizer_parse::parse(expression.as_ref())
        .map_err(|_| unsupported("formula parsing"))?;
    let mut pending: Vec<(&ASTNode, usize)> = vec![(&node, 1)];
    let mut contextual = false;
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_EVALUATION_DEPTH {
            return Err(unsupported("formula evaluation depth limit"));
        }
        match &node.node_type {
            ASTNodeType::Literal(_) | ASTNodeType::Omitted | ASTNodeType::Reference { .. } => {}
            ASTNodeType::UnaryOp { expr, .. } => pending.push((expr, depth + 1)),
            ASTNodeType::BinaryOp { left, right, .. } => {
                pending.push((left, depth + 1));
                pending.push((right, depth + 1));
            }
            ASTNodeType::Function { name, args } => {
                let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
                contextual |= matches!(
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
                );
                pending.extend(args.iter().map(|arg| (arg, depth + 1)));
            }
            ASTNodeType::Call { callee, args } => {
                pending.push((callee, depth + 1));
                pending.extend(args.iter().map(|arg| (arg, depth + 1)));
            }
            ASTNodeType::Array(rows) => {
                pending.extend(rows.iter().flatten().map(|arg| (arg, depth + 1)));
            }
        }
    }
    Ok(contextual)
}
