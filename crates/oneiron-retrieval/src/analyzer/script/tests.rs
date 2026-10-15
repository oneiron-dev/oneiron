use super::*;

fn run_slices<'a>(text: &'a str, runs: &[ScriptRun]) -> Vec<(&'a str, ScriptClass)> {
    runs.iter().map(|r| (r.as_slice(text), r.script)).collect()
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
fn leading_digits_split_off_han_run() {
    let text = "2024東京";
    let runs = ScriptRunSplitter::new().runs(text);
    let sliced = run_slices(text, &runs);
    assert_eq!(
        sliced,
        vec![("2024", ScriptClass::Common), ("東京", ScriptClass::Han)]
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
