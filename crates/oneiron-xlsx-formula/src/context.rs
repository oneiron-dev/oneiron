//! Bound formula AST evaluation, keep ambient context out of native recalc and
//! find the functions the engine does not implement.
use std::collections::BTreeSet;

use formualizer_parse::TokenStream;
use formualizer_parse::parser::{ASTNode, ASTNodeType, ReferenceType};

use crate::Result;
use crate::xml::unsupported;

// The upstream evaluator recursively walks expressions on worker threads. Real
// FUSE inputs with about 200 chained additions overflow that stack in debug
// builds. Bound tokens before constructing a recursive AST (including its Drop)
// and bound evaluation depth independently of the parser's own nesting guard.
const MAX_FORMULA_BYTES: usize = 32 * 1024;
const MAX_FORMULA_TOKENS: usize = 256;
const MAX_EVALUATION_DEPTH: usize = 32;

/// What one bounded formula needs from its caller and from the engine.
pub(super) struct Inspection {
    /// The formula needs caller-owned context or volatile reference semantics.
    pub contextual: bool,
    /// A function the engine's registry does not resolve. The engine would
    /// cache `#NAME?` for it where Excel computes a value.
    pub unknown_function: Option<String>,
}

/// Prove bounded evaluation and report what the formula needs.
/// The compatibility harness may supply deterministic context; production falls
/// back rather than substitute its corpus clock for the caller's time or seed.
pub(super) fn inspect_formula(formula: &str) -> Result<Inspection> {
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
    // Called names, and the LET names and LAMBDA parameters a call may name.
    let mut called = Vec::new();
    let mut local = BTreeSet::new();
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_EVALUATION_DEPTH {
            return Err(unsupported("formula evaluation depth limit"));
        }
        match &node.node_type {
            ASTNodeType::Literal(_) | ASTNodeType::Omitted => {}
            ASTNodeType::Reference { reference, .. } => {
                // A function passed by name (`_xleta.SUM`) is a call too.
                if let ReferenceType::NamedRange(name) = reference
                    && let Some(function) = strip_prefix(name, "_xleta.")
                {
                    called.push(function);
                }
            }
            ASTNodeType::UnaryOp { expr, .. } => pending.push((expr, depth + 1)),
            ASTNodeType::BinaryOp { left, right, .. } => {
                pending.push((left, depth + 1));
                pending.push((right, depth + 1));
            }
            ASTNodeType::Function { name, args } => {
                let bare = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
                contextual |= matches!(
                    bare.as_str(),
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
                // LET binds every other argument before its body; LAMBDA
                // binds each argument before its body.
                let step = match bare.as_str() {
                    "LET" => 2,
                    "LAMBDA" => 1,
                    _ => 0,
                };
                if step > 0 {
                    let bound = args.len().saturating_sub(1);
                    for arg in args[..bound].iter().step_by(step) {
                        if let ASTNodeType::Reference {
                            reference: ReferenceType::NamedRange(name),
                            ..
                        } = &arg.node_type
                        {
                            local.insert(name.to_ascii_uppercase());
                        }
                    }
                }
                called.push(name.as_str());
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
    let unknown_function = called
        .into_iter()
        .find(|name| !local.contains(&name.to_ascii_uppercase()) && !registered(name))
        .map(str::to_owned);
    Ok(Inspection {
        contextual,
        unknown_function,
    })
}

/// Whether the engine resolves `name` as it resolves a call: its registry,
/// after the `_xlfn.`, `_xlws.` and `_xll.` storage prefixes.
fn registered(name: &str) -> bool {
    formualizer_workbook::ensure_builtins_loaded();
    formualizer_eval::function_registry::get("", name).is_some()
}

fn strip_prefix<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &name[prefix.len()..])
}
