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
    // MS-XLSX "Functions" future-function table (2026-09-26):
    // https://learn.microsoft.com/en-us/openspecs/office_standards/ms-xlsx/5d1b6d44-6fc1-4ecd-8fef-0b27406cc2bf
    // XMATCH and ARRAYTOTEXT are also supported by current Excel's future
    // function syntax; the published table omits them.
    const FUTURE: &[&str] = &[
        "ACOT",
        "ACOTH",
        "AGGREGATE",
        "ARABIC",
        "ARRAYTOTEXT",
        "BASE",
        "BETA.DIST",
        "BETA.INV",
        "BINOM.DIST",
        "BINOM.DIST.RANGE",
        "BINOM.INV",
        "BITAND",
        "BITLSHIFT",
        "BITOR",
        "BITRSHIFT",
        "BITXOR",
        "BYCOL",
        "BYROW",
        "CEILING.MATH",
        "CEILING.PRECISE",
        "CHISQ.DIST",
        "CHISQ.DIST.RT",
        "CHISQ.INV",
        "CHISQ.INV.RT",
        "CHISQ.TEST",
        "CHOOSECOLS",
        "CHOOSEROWS",
        "COMBINA",
        "CONCAT",
        "CONFIDENCE.NORM",
        "CONFIDENCE.T",
        "COT",
        "COTH",
        "COVARIANCE.P",
        "COVARIANCE.S",
        "CSC",
        "CSCH",
        "DAYS",
        "DECIMAL",
        "DROP",
        "ERF.PRECISE",
        "ERFC.PRECISE",
        "EXPAND",
        "EXPON.DIST",
        "F.DIST",
        "F.DIST.RT",
        "F.INV",
        "F.INV.RT",
        "F.TEST",
        "FIELDVALUE",
        "FILTERXML",
        "FLOOR.MATH",
        "FLOOR.PRECISE",
        "FORECAST.ETS",
        "FORECAST.ETS.CONFINT",
        "FORECAST.ETS.SEASONALITY",
        "FORECAST.ETS.STAT",
        "FORECAST.LINEAR",
        "FORMULATEXT",
        "GAMMA",
        "GAMMA.DIST",
        "GAMMA.INV",
        "GAMMALN.PRECISE",
        "GAUSS",
        "HSTACK",
        "HYPGEOM.DIST",
        "IFNA",
        "IFS",
        "IMCOSH",
        "IMCOT",
        "IMCSC",
        "IMCSCH",
        "IMSEC",
        "IMSECH",
        "IMSINH",
        "IMTAN",
        "ISFORMULA",
        "ISOMITTED",
        "ISOWEEKNUM",
        "LAMBDA",
        "LET",
        "LOGNORM.DIST",
        "LOGNORM.INV",
        "MAKEARRAY",
        "MAP",
        "MAXIFS",
        "MINIFS",
        "MODE.MULT",
        "MODE.SNGL",
        "MUNIT",
        "NEGBINOM.DIST",
        "NORM.DIST",
        "NORM.INV",
        "NORM.S.DIST",
        "NORM.S.INV",
        "NUMBERVALUE",
        "PDURATION",
        "PERCENTILE.EXC",
        "PERCENTILE.INC",
        "PERCENTRANK.EXC",
        "PERCENTRANK.INC",
        "PERMUTATIONA",
        "PHI",
        "POISSON.DIST",
        "PQSOURCE",
        "QUARTILE.EXC",
        "QUARTILE.INC",
        "QUERYSTRING",
        "RANDARRAY",
        "RANK.AVG",
        "RANK.EQ",
        "REDUCE",
        "RRI",
        "SCAN",
        "SEC",
        "SECH",
        "SEQUENCE",
        "SHEET",
        "SHEETS",
        "SKEW.P",
        "SORTBY",
        "STDEV.P",
        "STDEV.S",
        "SWITCH",
        "T.DIST",
        "T.DIST.2T",
        "T.DIST.RT",
        "T.INV",
        "T.INV.2T",
        "T.TEST",
        "TAKE",
        "TEXTAFTER",
        "TEXTBEFORE",
        "TEXTJOIN",
        "TEXTSPLIT",
        "TOCOL",
        "TOROW",
        "UNICHAR",
        "UNICODE",
        "UNIQUE",
        "VAR.P",
        "VAR.S",
        "VSTACK",
        "WEBSERVICE",
        "WEIBULL.DIST",
        "WRAPCOLS",
        "WRAPROWS",
        "XLOOKUP",
        "XMATCH",
        "XOR",
        "Z.TEST",
    ];
    const WORKSHEET_ONLY: &[&str] = &["FILTER", "PY", "SORT"];
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
        // Structured references are data, not formula tokens. Preserve header
        // text through nested brackets and Excel's single-quote escape for
        // reserved characters (including literal '[' and ']').
        if bytes[i] == b'[' {
            let mut depth = 1;
            i += 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\''
                    && i + 1 < bytes.len()
                    && matches!(bytes[i + 1], b'[' | b']' | b'#' | b'\'')
                {
                    i += 2;
                } else {
                    if bytes[i] == b'[' {
                        depth += 1;
                    }
                    if bytes[i] == b']' {
                        depth -= 1;
                    }
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
            if next < bytes.len() && bytes[next] == b'(' {
                let core = name.strip_prefix("_xlfn.").unwrap_or(name);
                let core = core.strip_prefix("_xlws.").unwrap_or(core);
                let qualifier = if WORKSHEET_ONLY
                    .iter()
                    .any(|known| core.eq_ignore_ascii_case(known))
                {
                    Some("_xlfn._xlws.")
                } else if FUTURE.iter().any(|known| core.eq_ignore_ascii_case(known)) {
                    Some("_xlfn.")
                } else {
                    None
                };
                if let Some(qualifier) = qualifier {
                    let canonical = format!("{qualifier}{core}");
                    if name != canonical {
                        out.push_str(&formula[copy_from..start]);
                        out.push_str(&canonical);
                        copy_from = i;
                    }
                }
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
    fn structured_headers_are_not_functions_even_when_nested_or_escaped() {
        for expr in [
            "SUM(Table1[XLOOKUP(foo)])",
            "SUM(Table1[[#All],[XLOOKUP(foo)]])",
            "SUM(Table1['[XLOOKUP(foo)']])+IFNA(A1,0)",
        ] {
            let expected = expr.replace("IFNA(A1,0)", "_xlfn.IFNA(A1,0)");
            assert_eq!(prefix_functions(expr), expected);
        }
    }

    #[test]
    fn future_functions_and_partial_qualifiers_follow_specification() {
        for (source, expected) in [
            ("RANDARRAY(2,2)", "_xlfn.RANDARRAY(2,2)"),
            ("IFNA(A1,0)", "_xlfn.IFNA(A1,0)"),
            ("IFS(A1>0,1,TRUE,0)", "_xlfn.IFS(A1>0,1,TRUE,0)"),
            ("CONCAT(A1:A2)", "_xlfn.CONCAT(A1:A2)"),
            (
                r#"TEXTJOIN(",",TRUE,A1:A2)"#,
                r#"_xlfn.TEXTJOIN(",",TRUE,A1:A2)"#,
            ),
            ("_xlfn.FILTER(A1:A2,TRUE)", "_xlfn._xlws.FILTER(A1:A2,TRUE)"),
            ("_xlfn.SORT(A1:A2)", "_xlfn._xlws.SORT(A1:A2)"),
        ] {
            assert_eq!(prefix_functions(source), expected);
            assert_eq!(prefix_functions(expected), expected);
        }
    }

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
