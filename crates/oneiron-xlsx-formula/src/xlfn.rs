//! `_xlfn.` storage-prefix mapping for post-2007 functions (step 25).
//!
//! Excel stores post-2007 functions with a `_xlfn.` (or `_xlfn._xlws.`) prefix
//! in the worksheet XML; the UI formula users type has no prefix. The
//! openpyxl writer path drops the prefix, so a stored `=XLOOKUP(...)` shows
//! `#NAME?` in every engine including Excel. The in-process engine needs no
//! prefix on input (formualizer strips `EXCEL_PREFIXES` internally), but any
//! Rust writer emitting stored XML must add it back.
//!
//! This module owns the prefix table and both directions. It never touches the
//! engine: callers pass UI text to the engine and storage text to the writer.

/// Post-2007 functions Excel stores with a plain `_xlfn.` prefix.
const XLFN_FUNCTIONS: &[&str] = &[
    "ANCHORARRAY",
    "SINGLE",
    "UNIQUE",
    "SEQUENCE",
    "SORTBY",
    "RANDARRAY",
    "CHOOSECOLS",
    "CHOOSEROWS",
    "CONCAT",
    "GROUPBY",
    "PIVOTBY",
    "PDURATION",
    "RRI",
    "PERCENTRANK.INC",
    "PERCENTRANK.EXC",
    "ISO.CEILING",
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
    "COMBINA",
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
    "EXPAND",
    "F.DIST",
    "F.DIST.RT",
    "F.INV",
    "F.INV.RT",
    "F.TEST",
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
    "PERCENTILE.EXC",
    "PERCENTILE.INC",
    "PERMUTATIONA",
    "PHI",
    "POISSON.DIST",
    "QUARTILE.EXC",
    "QUARTILE.INC",
    "RANDARRAY",
    "RANK.AVG",
    "RANK.EQ",
    "REDUCE",
    "SCAN",
    "SEC",
    "SECH",
    "SHEET",
    "SHEETS",
    "SINGLE",
    "SKEW.P",
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
];

/// Post-2007 functions Excel stores with the doubled `_xlfn._xlws.` prefix.
const XLFN_XLWS_FUNCTIONS: &[&str] = &["FILTER", "SORT"];

/// Windows-only functions absent on Mac Excel and the web. The crate returns
/// `#NAME?` for them, which is parity with the Mac oracle (ARCH-0075 section
/// 6 edge table), not a missing-function defect.
pub(super) const MAC_ABSENT_FUNCTIONS: &[&str] = &["ENCODEURL", "FILTERXML", "WEBSERVICE"];

/// True when `name` (case-insensitive, prefix optional) is absent on Mac Excel.
#[must_use]
pub fn is_mac_absent(name: &str) -> bool {
    MAC_ABSENT_FUNCTIONS
        .iter()
        .any(|mac| mac.eq_ignore_ascii_case(strip_storage_prefix(name)))
}

/// Rewrite a UI formula to its stored XML form, prefixing post-2007 function
/// names. Prefix matching is ASCII case-insensitive and skips string literals
/// (`"XLOOKUP"` inside quotes is text, not a call). Unknown names pass through
/// unchanged: prefixing a name Excel does not know would invent a function.
#[must_use]
pub fn storage_form(ui_formula: &str) -> String {
    rewrite_prefixes(ui_formula, true)
}

/// Strip storage prefixes back to the UI form the engine and users read.
#[must_use]
pub fn ui_form(stored_formula: &str) -> String {
    rewrite_prefixes(stored_formula, false)
}

/// Strip one storage prefix layer (`_xlfn.` with an optional `_xlws.`).
fn strip_storage_prefix(name: &str) -> &str {
    let bare = if name
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("_xlfn."))
    {
        &name[6..]
    } else {
        name
    };
    if bare
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("_xlws."))
    {
        &bare[6..]
    } else {
        bare
    }
}

fn storage_prefix(name: &str) -> Option<&'static str> {
    if XLFN_XLWS_FUNCTIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
    {
        return Some("_xlfn._xlws.");
    }
    if XLFN_FUNCTIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
    {
        return Some("_xlfn.");
    }
    None
}

/// Single-pass rewriter shared by both directions. `to_storage = true` adds
/// prefixes at call sites; `false` strips them. String literals (`"..."` with
/// `""` escapes) are copied verbatim in both directions.
fn rewrite_prefixes(formula: &str, to_storage: bool) -> String {
    let bytes = formula.as_bytes();
    let mut out = String::with_capacity(formula.len() + 16);
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        // Both string literals and quoted sheet names can contain function-
        // looking text. Copy the original UTF-8 slice, including doubled quotes.
        if matches!(byte, b'"' | b'\'') {
            let start = index;
            index = quoted_end(bytes, index, byte);
            out.push_str(&formula[start..index]);
            continue;
        }
        // Structured references are not function call sites.
        if byte == b'[' {
            let start = index;
            index = bracket_end(bytes, index);
            out.push_str(&formula[start..index]);
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.'))
            {
                index += 1;
            }
            let word = &formula[start..index];
            let is_call = matches!(bytes.get(index), Some(b'('));
            rewrite_word(&mut out, word, is_call, to_storage);
            continue;
        }
        // Advance a Unicode scalar, not a byte promoted to a different scalar.
        if let Some(character) = formula[index..].chars().next() {
            out.push(character);
            index += character.len_utf8();
        }
    }
    out
}

fn quoted_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut end = start + 1;
    while end < bytes.len() {
        if bytes[end] == quote {
            end += 1;
            if bytes.get(end) == Some(&quote) {
                end += 1;
                continue;
            }
            break;
        }
        end += 1;
    }
    end
}
fn bracket_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0;
    let mut end = start;
    while end < bytes.len() {
        match bytes[end] {
            b'[' => depth += 1,
            b']' => depth -= 1,
            _ => {}
        }
        end += 1;
        if depth == 0 {
            break;
        }
    }
    end
}
fn rewrite_word(out: &mut String, word: &str, is_call: bool, to_storage: bool) {
    if !is_call {
        out.push_str(word);
        return;
    }
    let bare = strip_storage_prefix(word);
    if to_storage {
        if let Some(prefix) = storage_prefix(bare) {
            out.push_str(prefix);
        } else if bare != word {
            out.push_str(&word[..word.len() - bare.len()]);
        }
    }
    out.push_str(bare);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_form_prefixes_post_2007_calls_only() {
        assert_eq!(
            storage_form("=XLOOKUP(1,A:A,B:B)"),
            "=_xlfn.XLOOKUP(1,A:A,B:B)"
        );
        assert_eq!(
            storage_form("=FILTER(A1:A5,B1:B5>2)"),
            "=_xlfn._xlws.FILTER(A1:A5,B1:B5>2)"
        );
        assert_eq!(storage_form("=SUM(A1:A3)"), "=SUM(A1:A3)");
        assert_eq!(
            storage_form(r#"="XLOOKUP"&A1"#),
            r#"="XLOOKUP"&A1"#,
            "string literals are text, not calls"
        );
    }

    #[test]
    fn ui_form_strips_both_prefix_shapes() {
        assert_eq!(ui_form("=_xlfn.XLOOKUP(1,A:A,B:B)"), "=XLOOKUP(1,A:A,B:B)");
        assert_eq!(ui_form("=_xlfn._xlws.FILTER(A,B)"), "=FILTER(A,B)");
        assert_eq!(ui_form("=SUM(A1:A3)"), "=SUM(A1:A3)");
    }

    #[test]
    fn storage_mapping_preserves_unicode_literals_sheet_names_and_legacy_functions() {
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
            storage_form("=SEQUENCE(2)+UNIQUE(A1:A2)"),
            "=_xlfn.SEQUENCE(2)+_xlfn.UNIQUE(A1:A2)"
        );
        let stored = "=_XLFN.XLOOKUP(1,A:A,B:B)";
        assert_eq!(storage_form(stored), "=_xlfn.XLOOKUP(1,A:A,B:B)");
        assert_eq!(ui_form(stored), "=XLOOKUP(1,A:A,B:B)");
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

    #[test]
    fn mac_absent_set_is_exactly_the_oracle_edges() {
        assert!(is_mac_absent("ENCODEURL"));
        assert!(is_mac_absent("_xlfn.WEBSERVICE"));
        assert!(!is_mac_absent("XLOOKUP"));
        assert!(!is_mac_absent("SUM"));
    }
}
