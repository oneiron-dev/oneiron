//! Error operands remain typed errors across both owned evaluator paths.
use std::collections::BTreeMap;
use oneiron_docedit::calc::{CalcSetup, CalcValue, RecalcEngine};
use oneiron_xlsx_formula::engine::FormualizerEngine;

#[test]
fn error_concatenation_propagates_without_stringifying_or_suppressing_literal_text() {
    let mut engine = FormualizerEngine::new();
    let setup = BTreeMap::from([("A1".into(), CalcSetup::Formula("=NA()".into()))]);
    for (formula, expected) in [
        ("=A1&\"\"", CalcValue::Error("#N/A".into())),
        ("=\"\"&A1", CalcValue::Error("#N/A".into())),
        ("=IFERROR(A1&\"\",\"missing\")", CalcValue::Text("missing".into())),
        ("=IFERROR(\"\"&A1,\"missing\")", CalcValue::Text("missing".into())),
        ("=IFERROR(INDEX(A1:A1,MATCH(2,{1},0))&\"\",\"\")", CalcValue::Text(String::new())),
        ("=IFERROR(\"#N/A\"&\"\",\"missing\")", CalcValue::Text("#N/A".into())),
    ] {
        assert_eq!(engine.evaluate(&setup, formula, "B1", None).expect("evaluate").value, expected, "{formula}");
    }
}
