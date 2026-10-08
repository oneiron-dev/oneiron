//! Bound formula AST evaluation, keep what only the host knows out of native
//! recalc and find the called names the engine does not resolve.
use std::collections::BTreeSet;

use formualizer_common::LiteralValue;
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
    /// What the formula reads that only the host knows: the active cell, the
    /// application's environment or cell formatting the engine does not
    /// model. The clock and the random seed come from the caller
    /// ([`crate::RecalcClock`]); OFFSET and INDIRECT read the workbook alone.
    /// INDIRECT text that names a workbook, which may be computed, is the
    /// writer's to refuse as evaluation meets it.
    pub host_context: Option<&'static str>,
    /// Why the formula reads where the workbook was opened from
    /// (CELL("filename"), or CELL("address") of a cell that may be on another
    /// sheet), which the caller's [`crate::DocumentLocation`] gives, else the
    /// workbook's own CELL("filename") caches.
    pub location: Option<&'static str>,
    /// Every name called as a function, or passed by name (`_xleta.`), that
    /// the engine's registry does not resolve and that is not a LET name or
    /// LAMBDA parameter, each once, as the formula spells it with its
    /// prefixes. The engine evaluates such a call to `#NAME?`; the workbook
    /// check decides whether Excel does too.
    pub unknown_functions: Vec<String>,
    /// A name passed where a helper (MAP, REDUCE, BYROW, ...) takes its
    /// LAMBDA, or invoked, that is not a LET name or LAMBDA parameter. The
    /// engine does not resolve a workbook name to a LAMBDA yet.
    pub callable_name: Option<String>,
    /// The formula builds a LAMBDA.
    pub lambda: bool,
}

/// Prove bounded evaluation and report what the formula needs.
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
    let node = parse_bounded(&expression)?;
    let mut pending: Vec<(&ASTNode, usize)> = vec![(&node, 1)];
    let mut host_context = None;
    let mut location = None;
    let mut need = |call: Option<Need>| match call {
        Some(Need::Host(reason)) => host_context = host_context.or(Some(reason)),
        Some(Need::Location(reason)) => location = location.or(Some(reason)),
        None => {}
    };
    let mut lambda = false;
    // Called names (as spelled, and as the registry looks them up), names in
    // a callable position, and the LET names and LAMBDA parameters either
    // may name.
    let mut called = Vec::new();
    let mut callable = Vec::new();
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
                    need(needs(function, None));
                    called.push((name.as_str(), function));
                }
            }
            ASTNodeType::UnaryOp { expr, .. } => pending.push((expr, depth + 1)),
            ASTNodeType::BinaryOp { left, right, .. } => {
                pending.push((left, depth + 1));
                pending.push((right, depth + 1));
            }
            ASTNodeType::Function { name, args } => {
                let bare = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
                need(needs(&bare, Some(args)));
                lambda |= bare == "LAMBDA";
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
                        if let Some(name) = plain_name(arg) {
                            local.insert(name.to_ascii_uppercase());
                        }
                    }
                }
                if let Some(arg) = lambda_slot(&bare, args.len()).and_then(|slot| args.get(slot))
                    && let Some(name) = plain_name(arg)
                {
                    callable.push(name);
                }
                called.push((name.as_str(), name.as_str()));
                pending.extend(args.iter().map(|arg| (arg, depth + 1)));
            }
            ASTNodeType::Call { callee, args } => {
                if let Some(name) = plain_name(callee) {
                    callable.push(name);
                }
                pending.push((callee, depth + 1));
                pending.extend(args.iter().map(|arg| (arg, depth + 1)));
            }
            ASTNodeType::Array(rows) => {
                pending.extend(rows.iter().flatten().map(|arg| (arg, depth + 1)));
            }
        }
    }
    let mut seen = BTreeSet::new();
    let unknown_functions = called
        .into_iter()
        .filter(|(spelled, name)| {
            !local.contains(&name.to_ascii_uppercase())
                && !registered(name)
                && seen.insert(spelled.to_ascii_uppercase())
        })
        .map(|(spelled, _)| spelled.to_owned())
        .collect();
    let callable_name = callable
        .into_iter()
        .find(|name| !local.contains(&name.to_ascii_uppercase()))
        .map(str::to_owned);
    Ok(Inspection {
        host_context,
        location,
        unknown_functions,
        callable_name,
        lambda,
    })
}

/// What a call needs beyond the workbook.
enum Need {
    /// Only the host knows it.
    Host(&'static str),
    /// Where the workbook was opened from.
    Location(&'static str),
}

/// What a call of `name` (after any storage prefix) with `args` (`None` when
/// the function is passed by name) needs beyond the workbook, if anything, as
/// Excel for Windows 16.0.20430 reads it (ops/excel-context-probe-20261006.md,
/// ops/excel-hostinfo-probe-20261008.md). CELL reads the workbook alone for
/// "col", "contents", "row" and "type", for "address" of a reference written
/// without a sheet, and for text outside Excel's info types (#VALUE!), each
/// named by a text literal with a reference. "filename" prints the file's
/// folder and name, and "address" names the file for a cell on another sheet
/// (`[Book.xlsx]Other!$B$2`): both read the location. Without a reference it
/// reports on the active cell, and the formatting types read formatting the
/// engine does not model. INFO reads the application's environment, except
/// for the types whose answer does not depend on it: the retired memory types
/// (#N/A), text outside Excel's types and a literal that is not text
/// (#VALUE!).
fn needs(name: &str, args: Option<&[ASTNode]>) -> Option<Need> {
    let bare = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
    match bare.as_str() {
        "INFO" => info_need(args).map(Need::Host),
        "CELL" => match args {
            Some([info, reference]) => match &info.node_type {
                ASTNodeType::Literal(LiteralValue::Text(info)) => {
                    cell_need(&info.to_ascii_lowercase(), reference)
                }
                _ => Some(Need::Host(
                    "CELL of a computed info type may read what the engine does not model",
                )),
            },
            Some([_]) => Some(Need::Host("CELL without a reference reads the active cell")),
            _ => Some(Need::Host("CELL info type the engine does not compute")),
        },
        _ => None,
    }
}

/// What CELL(`info`, `reference`) needs, `info` a literal in lowercase.
fn cell_need(info: &str, reference: &ASTNode) -> Option<Need> {
    let host = |reason| Some(Need::Host(reason));
    match info {
        "address" if unqualified(reference) => None,
        "address" => Some(Need::Location(
            "CELL(\"address\") of another sheet reads the file's name",
        )),
        "filename" => Some(Need::Location("CELL(\"filename\") reads the file's path")),
        "format" => {
            host("CELL(\"format\") reads the cell's number format, which the engine does not model")
        }
        "color" => {
            host("CELL(\"color\") reads the cell's number format, which the engine does not model")
        }
        "parentheses" => host(
            "CELL(\"parentheses\") reads the cell's number format, which the engine does not model",
        ),
        "prefix" => {
            host("CELL(\"prefix\") reads the cell's alignment, which the engine does not model")
        }
        "protect" => {
            host("CELL(\"protect\") reads the cell's protection, which the engine does not model")
        }
        "width" => {
            host("CELL(\"width\") reads the column's width, which the engine does not model")
        }
        // "col", "contents", "row", "type", and text that is no info type.
        _ => None,
    }
}

/// What INFO with `args` reads from the application that calculates, if
/// anything.
fn info_need(args: Option<&[ASTNode]>) -> Option<&'static str> {
    let computed = "INFO of a computed type may read the environment";
    let Some([kind]) = args else {
        return Some(computed);
    };
    match &kind.node_type {
        ASTNodeType::Literal(LiteralValue::Text(kind)) => {
            match kind.to_ascii_lowercase().as_str() {
                "directory" => Some("INFO(\"directory\") reads the host's current folder"),
                "numfile" => Some("INFO(\"numfile\") counts the host's open worksheets"),
                "origin" => Some("INFO(\"origin\") reads the host window's scroll position"),
                "osversion" => Some("INFO(\"osversion\") reads the host's operating system"),
                "recalc" => Some("INFO(\"recalc\") reads the host's calculation mode"),
                "release" => Some("INFO(\"release\") reads the host's Excel version"),
                "system" => Some("INFO(\"system\") reads the host's platform"),
                // "memavail", "memused", "totmem", and text that is no type.
                _ => None,
            }
        }
        ASTNodeType::Literal(_) => None,
        _ => Some(computed),
    }
}

/// Whether `node` is one CELL("filename") call, whose value is the path of
/// the file the workbook was calculated in.
pub(super) fn cell_filename(node: &ASTNode) -> bool {
    matches!(
        &node.node_type,
        ASTNodeType::Function { name, args }
            if name.eq_ignore_ascii_case("CELL")
                && matches!(
                    args.first().map(|arg| &arg.node_type),
                    Some(ASTNodeType::Literal(LiteralValue::Text(info)))
                        if info.eq_ignore_ascii_case("filename")
                )
    )
}

/// Parse a formula within the bounds `inspect_formula` proves, with the
/// parser's mandatory leading `=`.
pub(super) fn parse_bounded(formula: &str) -> Result<ASTNode> {
    let expression = if formula.starts_with('=') {
        std::borrow::Cow::Borrowed(formula)
    } else {
        std::borrow::Cow::Owned(format!("={formula}"))
    };
    formualizer_parse::parse(expression.as_ref()).map_err(|_| unsupported("formula parsing"))
}

/// A cell or range reference written without a sheet: on the formula's own
/// sheet.
fn unqualified(node: &ASTNode) -> bool {
    matches!(
        &node.node_type,
        ASTNodeType::Reference {
            reference: ReferenceType::Cell { sheet: None, .. }
                | ReferenceType::Range { sheet: None, .. },
            ..
        }
    )
}

/// The argument a LAMBDA helper calls, by position among `count` arguments.
fn lambda_slot(bare: &str, count: usize) -> Option<usize> {
    match bare {
        "MAP" => count.checked_sub(1),
        "BYROW" | "BYCOL" => Some(1),
        "REDUCE" | "SCAN" | "MAKEARRAY" | "GROUPBY" => Some(2),
        "PIVOTBY" => Some(3),
        _ => None,
    }
}

/// A bare name: a workbook name, LET name or LAMBDA parameter, not a
/// function passed by name (`_xleta.SUM`).
fn plain_name(node: &ASTNode) -> Option<&str> {
    match &node.node_type {
        ASTNodeType::Reference {
            reference: ReferenceType::NamedRange(name),
            ..
        } if strip_prefix(name, "_xleta.").is_none() => Some(name),
        _ => None,
    }
}

/// Whether the engine resolves `name` as it resolves a call: its registry,
/// after the `_xlfn.`, `_xlws.` and `_xll.` storage prefixes.
fn registered(name: &str) -> bool {
    formualizer_workbook::ensure_builtins_loaded();
    formualizer_eval::function_registry::get("", name).is_some()
}

pub(super) fn strip_prefix<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &name[prefix.len()..])
}
