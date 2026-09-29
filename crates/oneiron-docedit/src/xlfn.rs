//! Excel's storage qualifiers for post-2007 worksheet functions.
//!
//! The worksheet XML stores a post-2007 function call with an `_xlfn.` prefix
//! (`_xlfn._xlws.` for worksheet-only functions); the formula a user types has
//! none. A stored call without its prefix opens as `#NAME?` in Excel, so every
//! writer of stored formula text goes through [`storage_form`]. [`ui_form`] is
//! the inverse. One tokenizer serves both directions: string literals, quoted
//! sheet names, structured references and longer identifiers are never calls.

// MS-XLSX "Functions" future-function table (2026-09-26):
// https://learn.microsoft.com/en-us/openspecs/office_standards/ms-xlsx/5d1b6d44-6fc1-4ecd-8fef-0b27406cc2bf
// XMATCH and ARRAYTOTEXT are also supported by current Excel's future
// function syntax; the published table omits them. The table also predates
// GROUPBY, PIVOTBY, TRIMRANGE and VALUETOTEXT, which current Excel saves with
// the prefix, and ANCHORARRAY and SINGLE, the stored forms of the `#` spill
// and `@` intersection operators.
const FUTURE: &[&str] = &[
    "ACOT",
    "ACOTH",
    "AGGREGATE",
    "ANCHORARRAY",
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
    "ECMA.CEILING",
    "ENCODEURL",
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
    "GROUPBY",
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
    "ISO.CEILING",
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
    "PIVOTBY",
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
    "SINGLE",
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
    "TRIMRANGE",
    "UNICHAR",
    "UNICODE",
    "UNIQUE",
    "VALUETOTEXT",
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

/// Qualify modern function calls for storage. Idempotent; unknown names and
/// already-qualified names pass through.
#[must_use]
pub fn storage_form(formula: &str) -> String {
    rewrite_calls(formula, |core| {
        if WORKSHEET_ONLY
            .iter()
            .any(|known| core.eq_ignore_ascii_case(known))
        {
            Some(format!("_xlfn._xlws.{core}"))
        } else if FUTURE.iter().any(|known| core.eq_ignore_ascii_case(known)) {
            Some(format!("_xlfn.{core}"))
        } else {
            None
        }
    })
}

/// Strip storage qualifiers from every call site, giving the typed form.
#[must_use]
pub fn ui_form(formula: &str) -> String {
    rewrite_calls(formula, |core| Some(core.to_owned()))
}

/// Tokenize function names, not occurrences in strings, quoted sheet names,
/// longer identifiers, or structured references. `canonical` maps a call's
/// unqualified name to its replacement spelling, or `None` to keep it.
fn rewrite_calls(formula: &str, canonical: impl Fn(&str) -> Option<String>) -> String {
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
        // Excel names can begin with a Unicode letter, underscore or
        // backslash; subsequent letters and digits are not ASCII-only. Read
        // the *whole* identifier so a built-in suffix of a defined LAMBDA
        // name (e.g. \XLOOKUP or 名前XLOOKUP) is never treated as a call.
        let ch = formula[i..]
            .chars()
            .next()
            .expect("nonempty formula suffix");
        if ch.is_alphabetic() || matches!(ch, '_' | '\\') {
            let start = i;
            i += ch.len_utf8();
            while i < bytes.len() {
                let next = formula[i..]
                    .chars()
                    .next()
                    .expect("nonempty identifier suffix");
                if next.is_alphanumeric() || matches!(next, '_' | '.') {
                    i += next.len_utf8();
                } else {
                    break;
                }
            }
            let name = &formula[start..i];
            let mut next = i;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len() && bytes[next] == b'(' {
                let core = name.strip_prefix("_xlfn.").unwrap_or(name);
                let core = core.strip_prefix("_xlws.").unwrap_or(core);
                if let Some(canonical) = canonical(core)
                    && name != canonical
                {
                    out.push_str(&formula[copy_from..start]);
                    out.push_str(&canonical);
                    copy_from = i;
                }
            }
        } else {
            i += ch.len_utf8();
        }
    }
    out.push_str(&formula[copy_from..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{storage_form, ui_form};

    #[test]
    fn defined_names_are_consumed_as_whole_identifiers() {
        for name in [
            r"\XLOOKUP(1)",
            "名前XLOOKUP(1)",
            "éXLOOKUP(1)",
            "MYXLOOKUP(1)",
        ] {
            assert_eq!(storage_form(name), name);
        }
        let source = "LET(éXLOOKUP,LAMBDA(x,x),éXLOOKUP(1))";
        let expected = "_xlfn.LET(éXLOOKUP,_xlfn.LAMBDA(x,x),éXLOOKUP(1))";
        assert_eq!(storage_form(source), expected);
        assert_eq!(storage_form(expected), expected);
        assert_eq!(storage_form("XLOOKUP(1)"), "_xlfn.XLOOKUP(1)");
    }

    #[test]
    fn structured_headers_are_not_functions_even_when_nested_or_escaped() {
        for expr in [
            "SUM(Table1[XLOOKUP(foo)])",
            "SUM(Table1[[#All],[XLOOKUP(foo)]])",
            "SUM(Table1['[XLOOKUP(foo)']])+IFNA(A1,0)",
        ] {
            let expected = expr.replace("IFNA(A1,0)", "_xlfn.IFNA(A1,0)");
            assert_eq!(storage_form(expr), expected);
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
            assert_eq!(storage_form(source), expected);
            assert_eq!(storage_form(expected), expected);
        }
    }

    #[test]
    fn worksheet_only_functions_get_their_extra_qualifier() {
        let source = "FILTER(A1:A2,A1:A2>0)+SORT(B1:B2)+SORTBY(C1:C2,D1:D2)";
        let expected =
            "_xlfn._xlws.FILTER(A1:A2,A1:A2>0)+_xlfn._xlws.SORT(B1:B2)+_xlfn.SORTBY(C1:C2,D1:D2)";
        assert_eq!(storage_form(source), expected);
        assert_eq!(storage_form(expected), expected);
    }

    #[test]
    fn prefix_is_idempotent_and_skips_literals_and_qualified_names() {
        let formula = r#"XLOOKUP(A1, A2:A3, B2:B3)+_xlfn.LET(x,1,x)+SUM(1)+"XLOOKUP(ignored)"+'XLOOKUP(sheet)'!A1+MYXLOOKUP(1)"#;
        let expected = r#"_xlfn.XLOOKUP(A1, A2:A3, B2:B3)+_xlfn.LET(x,1,x)+SUM(1)+"XLOOKUP(ignored)"+'XLOOKUP(sheet)'!A1+MYXLOOKUP(1)"#;
        assert_eq!(storage_form(formula), expected);
        assert_eq!(storage_form(expected), expected);
    }

    #[test]
    fn ui_form_strips_both_qualifier_shapes_at_call_sites_only() {
        assert_eq!(ui_form("=_xlfn.XLOOKUP(1,A:A,B:B)"), "=XLOOKUP(1,A:A,B:B)");
        assert_eq!(ui_form("=_xlfn._xlws.FILTER(A,B)"), "=FILTER(A,B)");
        assert_eq!(ui_form("=SUM(A1:A3)"), "=SUM(A1:A3)");
        assert_eq!(
            ui_form(r#"="_xlfn.XLOOKUP("&A1"#),
            r#"="_xlfn.XLOOKUP("&A1"#
        );
    }

    #[test]
    fn storage_form_keeps_unicode_literals_sheet_names_and_legacy_functions() {
        assert_eq!(
            storage_form("=XLOOKUP(1,A:A,B:B)&\"東京🌕\""),
            "=_xlfn.XLOOKUP(1,A:A,B:B)&\"東京🌕\""
        );
        assert_eq!(storage_form("='XLOOKUP(東京)'!A1"), "='XLOOKUP(東京)'!A1");
        assert_eq!(
            storage_form("=HLOOKUP(1,A1:B2,2)+XIRR(A1:A3,B1:B3)"),
            "=HLOOKUP(1,A1:B2,2)+XIRR(A1:A3,B1:B3)"
        );
        assert_eq!(
            storage_form("=SEQUENCE(2)+UNIQUE(A1:A2)+GROUPBY(A1:A2,B1:B2,SUM)"),
            "=_xlfn.SEQUENCE(2)+_xlfn.UNIQUE(A1:A2)+_xlfn.GROUPBY(A1:A2,B1:B2,SUM)"
        );
    }

    proptest::proptest! {
        #[test]
        fn storage_roundtrip_keeps_arbitrary_literal_text(text in ".{0,80}") {
            let escaped = text.replace('"', "\"\"");
            let formula = format!("=XLOOKUP(1,A:A,B:B)&\"{escaped}\"");
            let stored = storage_form(&formula);
            proptest::prop_assert_eq!(ui_form(&stored), formula);
            proptest::prop_assert_eq!(storage_form(&stored), stored);
        }
    }
}
