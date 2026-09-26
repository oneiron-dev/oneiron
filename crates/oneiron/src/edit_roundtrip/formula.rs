//! Serialize post-2007 spreadsheet functions with Excel's OOXML prefix.

use super::{CellValue, EditOp, EditPlan};

/// Return a plan with modern function calls prefixed before the session sees
/// them. The returned ops (rather than the caller's input) become the manifest.
pub(super) fn serialize_plan(plan: &EditPlan) -> EditPlan {
    let mut plan = plan.clone();
    for op in &mut plan.ops {
        match op {
            EditOp::SetCell { after, .. } => serialize_value(after),
            EditOp::SetRange { writes, .. } => {
                for write in writes {
                    serialize_value(&mut write.after);
                }
            }
            EditOp::AddFormulaColumn { formula, .. } => *formula = prefix_functions(formula),
            _ => {}
        }
    }
    plan
}

fn serialize_value(value: &mut CellValue) {
    if let CellValue::Formula { expr, .. } = value {
        *expr = prefix_functions(expr);
    }
}

/// Tokenize function names, not occurrences in strings, quoted sheet names,
/// longer identifiers, or already qualified `_xlfn.` names. This is idempotent.
/// `FILTER` and `SORT` are worksheet-only functions in MS-XLSX's future
/// function list and need the additional `_xlws.` qualifier.
pub(super) fn prefix_functions(formula: &str) -> String {
    const MODERN: &[&str] = &[
        "XLOOKUP",
        "XMATCH",
        "LET",
        "LAMBDA",
        "FILTER",
        "SORT",
        "SORTBY",
        "UNIQUE",
        "SEQUENCE",
        "TEXTSPLIT",
        "TEXTBEFORE",
        "TEXTAFTER",
        "ARRAYTOTEXT",
        "VSTACK",
        "HSTACK",
        "TAKE",
        "DROP",
        "CHOOSECOLS",
        "CHOOSEROWS",
        "TOCOL",
        "TOROW",
        "WRAPCOLS",
        "WRAPROWS",
        "EXPAND",
        "BYROW",
        "BYCOL",
        "MAP",
        "REDUCE",
        "SCAN",
        "MAKEARRAY",
        "ISOMITTED",
    ];
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len());
    let mut i = 0;
    let mut copy_from = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == quote {
                    i += 1;
                    if i < bytes.len() && bytes[i] == quote {
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.'))
            {
                i += 1;
            }
            let name = &formula[start..i];
            let mut next = i;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len()
                && bytes[next] == b'('
                && MODERN.iter().any(|known| name.eq_ignore_ascii_case(known))
            {
                out.push_str(&formula[copy_from..start]);
                out.push_str(
                    if name.eq_ignore_ascii_case("FILTER") || name.eq_ignore_ascii_case("SORT") {
                        "_xlfn._xlws."
                    } else {
                        "_xlfn."
                    },
                );
                copy_from = start;
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&formula[copy_from..]);
    out
}

#[cfg(test)]
mod tests {
    use super::prefix_functions;

    #[test]
    fn worksheet_only_functions_get_their_extra_qualifier() {
        let source = "FILTER(A1:A2,A1:A2>0)+SORT(B1:B2)+SORTBY(C1:C2,D1:D2)";
        let expected =
            "_xlfn._xlws.FILTER(A1:A2,A1:A2>0)+_xlfn._xlws.SORT(B1:B2)+_xlfn.SORTBY(C1:C2,D1:D2)";
        assert_eq!(prefix_functions(source), expected);
        assert_eq!(prefix_functions(expected), expected);
    }

    #[test]
    fn prefix_is_idempotent_and_skips_literals_and_qualified_names() {
        let formula = r#"XLOOKUP(A1, A2:A3, B2:B3)+_xlfn.LET(x,1,x)+SUM(1)+"XLOOKUP(ignored)"+'XLOOKUP(sheet)'!A1+MYXLOOKUP(1)"#;
        let expected = r#"_xlfn.XLOOKUP(A1, A2:A3, B2:B3)+_xlfn.LET(x,1,x)+SUM(1)+"XLOOKUP(ignored)"+'XLOOKUP(sheet)'!A1+MYXLOOKUP(1)"#;
        assert_eq!(prefix_functions(formula), expected);
        assert_eq!(prefix_functions(expected), expected);
    }
}
