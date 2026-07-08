use super::*;

fn run_slices<'a>(text: &'a str, runs: &[ScriptRun]) -> Vec<(&'a str, ScriptClass)> {
    runs.iter().map(|r| (r.as_slice(text), r.script)).collect()
}

#[test]
fn empty_input_yields_no_runs() {
    let runs = ScriptRunSplitter::new().runs("");
    assert!(runs.is_empty());
}

/// Pure-script inputs yield a single run classified as the expected
/// script. Variants cover the three originally-separate cases.
///
/// Variants:
/// - `pure_latin`: `"hello world"` → Latin, slice equals input.
/// - `pure_han`: `"東京大学"` → Han, slice equals input.
/// - `pure_punct_is_common`: `"!!!,,,"` → Common (slice not asserted, the
///   original test only checked classification).
#[test]
fn pure_script_produces_single_run() {
    // (case_name, text, expected_script, assert_slice_equals_text)
    let cases: Vec<(&str, &str, ScriptClass, bool)> = vec![
        ("pure_latin", "hello world", ScriptClass::Latin, true),
        ("pure_han", "東京大学", ScriptClass::Han, true),
        ("pure_punct_is_common", "!!!,,,", ScriptClass::Common, false),
    ];

    for (case_name, text, expected_script, assert_slice) in cases {
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(
            runs.len(),
            1,
            "case {case_name}: expected exactly one run, got {}",
            runs.len()
        );
        assert_eq!(
            runs[0].script, expected_script,
            "case {case_name}: unexpected script class"
        );
        if assert_slice {
            assert_eq!(
                runs[0].as_slice(text),
                text,
                "case {case_name}: run slice did not cover full input"
            );
        }
    }
}

#[test]
fn hiragana_han_boundary_splits() {
    let text = "とう東京";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("とう", ScriptClass::Hiragana), ("東京", ScriptClass::Han)]
    );
}

#[test]
fn hangul_han_boundary_splits() {
    let text = "한국人";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("한국", ScriptClass::Hangul), ("人", ScriptClass::Han)]
    );
}

#[test]
fn latin_han_boundary_splits() {
    let text = "hello東京";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("hello", ScriptClass::Latin), ("東京", ScriptClass::Han)]
    );
}

#[test]
fn common_attaches_to_preceding_run() {
    let text = "hello! world";
    let runs = ScriptRunSplitter::new().runs(text);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].script, ScriptClass::Latin);
    assert_eq!(runs[0].as_slice(text), text);
}

#[test]
fn leading_common_attaches_to_next_run() {
    let text = "   hello";
    let runs = ScriptRunSplitter::new().runs(text);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].byte_start, 0);
    assert_eq!(runs[0].as_slice(text), text);
    assert_eq!(runs[0].script, ScriptClass::Latin);
}

#[test]
fn common_between_distinct_scripts_attaches_to_preceding() {
    let text = "hello 東京";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("hello ", ScriptClass::Latin), ("東京", ScriptClass::Han)]
    );
}

#[test]
fn runs_cover_input_with_no_gaps() {
    let text = "abc한국とう東京!";
    let runs = ScriptRunSplitter::new().runs(text);
    assert_eq!(runs.first().unwrap().byte_start, 0);
    assert_eq!(runs.last().unwrap().byte_end, text.len() as u32);
    for [left, right] in runs.array_windows::<2>() {
        assert_eq!(left.byte_end, right.byte_start);
    }
}

#[test]
fn runs_always_produce_valid_utf8_slices() {
    let text = "とう東京abcабв";
    let runs = ScriptRunSplitter::new().runs(text);
    for r in &runs {
        let _ = r.as_slice(text); // would panic on invalid boundary
    }
}

#[test]
fn han_digit_mix_splits_into_separate_runs() {
    let text = "東京123";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("東京", ScriptClass::Han), ("123", ScriptClass::Common)]
    );
}

#[test]
fn han_punct_mix_splits() {
    let text = "北京、大学";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![
            ("北京", ScriptClass::Han),
            ("、", ScriptClass::Common),
            ("大学", ScriptClass::Han),
        ]
    );
}

#[test]
fn leading_digits_split_off_han_run() {
    let text = "2024東京";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("2024", ScriptClass::Common), ("東京", ScriptClass::Han)]
    );
}

#[test]
fn leading_punct_splits_off_cjk_run() {
    let text = "【東京";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("【", ScriptClass::Common), ("東京", ScriptClass::Han)]
    );
}

#[test]
fn leading_common_before_hangul_splits() {
    let text = "...안녕";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("...", ScriptClass::Common), ("안녕", ScriptClass::Hangul)]
    );
}

#[test]
fn hiragana_digit_mix_splits() {
    let text = "とう123";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![
            ("とう", ScriptClass::Hiragana),
            ("123", ScriptClass::Common)
        ]
    );
}

/// The Japanese prolonged sound mark `ー` must not split a kana run.
/// Variants cover both hiragana and katakana host runs.
///
/// Variants:
/// - `katakana`: `"スーパー"` → single Katakana run.
/// - `hiragana`: `"らーめん"` → single Hiragana run.
#[test]
fn prolonged_mark_stays_in_preceding_script() {
    let cases: Vec<(&str, &str, ScriptClass)> = vec![
        ("katakana", "スーパー", ScriptClass::Katakana),
        ("hiragana", "らーめん", ScriptClass::Hiragana),
    ];

    for (case_name, text, expected_script) in cases {
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(
            runs.len(),
            1,
            "case {case_name}: expected single run, got {}",
            runs.len()
        );
        assert_eq!(
            runs[0].script, expected_script,
            "case {case_name}: unexpected script class"
        );
        assert_eq!(
            runs[0].as_slice(text),
            text,
            "case {case_name}: run slice did not cover full input"
        );
    }
}

#[test]
fn trailing_prolonged_mark_after_hiragana_stays_hiragana() {
    let text = "あー";
    let runs = ScriptRunSplitter::new().runs(text);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].script, ScriptClass::Hiragana);
    assert_eq!(runs[0].as_slice(text), text);
}

#[test]
fn katakana_double_hyphen_stays_in_run() {
    let text = "カ゠ナ";
    let runs = ScriptRunSplitter::new().runs(text);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].script, ScriptClass::Katakana);
    assert_eq!(runs[0].as_slice(text), text);
}

#[test]
fn hiragana_double_hyphen_stays_in_run() {
    let text = "ひ゠ら";
    let runs = ScriptRunSplitter::new().runs(text);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].script, ScriptClass::Hiragana);
    assert_eq!(runs[0].as_slice(text), text);
}

#[test]
fn is_cjk_classifies_correctly() {
    assert!(ScriptClass::Han.is_cjk());
    assert!(ScriptClass::Hiragana.is_cjk());
    assert!(ScriptClass::Katakana.is_cjk());
    assert!(ScriptClass::Hangul.is_cjk());
    assert!(!ScriptClass::Latin.is_cjk());
    assert!(!ScriptClass::Arabic.is_cjk());
    assert!(!ScriptClass::Thai.is_cjk());
}
