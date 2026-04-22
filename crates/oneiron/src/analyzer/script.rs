//! Script-run splitter.
//!
//! Groups consecutive characters of the same script into byte-range runs.
//! `Common` / `Inherited` characters attach to the adjacent non-Common run
//! so that boundaries only appear between real script transitions. The
//! script-boundary invariant from plan §1.1 — "no generated bigram crosses
//! a script-class boundary" — is enforced by downstream analyzers that
//! consume these runs, not by the splitter itself.

use unicode_script::{Script, UnicodeScript};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScriptClass {
    Latin,
    Cyrillic,
    Greek,
    Hebrew,
    Arabic,
    Han,
    Hiragana,
    Katakana,
    Hangul,
    Thai,
    Lao,
    Khmer,
    Myanmar,
    Devanagari,
    Tamil,
    /// Common / Inherited / Unknown — never emitted as its own run after
    /// [`ScriptRunSplitter::runs`] has attached it to a neighbor.
    Common,
    /// Scripts outside the explicit list above.
    Other,
}

impl ScriptClass {
    pub fn from_char(c: char) -> ScriptClass {
        match c.script() {
            Script::Latin => ScriptClass::Latin,
            Script::Cyrillic => ScriptClass::Cyrillic,
            Script::Greek => ScriptClass::Greek,
            Script::Hebrew => ScriptClass::Hebrew,
            Script::Arabic => ScriptClass::Arabic,
            Script::Han => ScriptClass::Han,
            Script::Hiragana => ScriptClass::Hiragana,
            Script::Katakana => ScriptClass::Katakana,
            Script::Hangul => ScriptClass::Hangul,
            Script::Thai => ScriptClass::Thai,
            Script::Lao => ScriptClass::Lao,
            Script::Khmer => ScriptClass::Khmer,
            Script::Myanmar => ScriptClass::Myanmar,
            Script::Devanagari => ScriptClass::Devanagari,
            Script::Tamil => ScriptClass::Tamil,
            Script::Common | Script::Inherited | Script::Unknown => ScriptClass::Common,
            _ => ScriptClass::Other,
        }
    }

    pub fn is_cjk(self) -> bool {
        matches!(
            self,
            ScriptClass::Han
                | ScriptClass::Hiragana
                | ScriptClass::Katakana
                | ScriptClass::Hangul
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScriptClass::Latin => "latin",
            ScriptClass::Cyrillic => "cyrillic",
            ScriptClass::Greek => "greek",
            ScriptClass::Hebrew => "hebrew",
            ScriptClass::Arabic => "arabic",
            ScriptClass::Han => "han",
            ScriptClass::Hiragana => "hiragana",
            ScriptClass::Katakana => "katakana",
            ScriptClass::Hangul => "hangul",
            ScriptClass::Thai => "thai",
            ScriptClass::Lao => "lao",
            ScriptClass::Khmer => "khmer",
            ScriptClass::Myanmar => "myanmar",
            ScriptClass::Devanagari => "devanagari",
            ScriptClass::Tamil => "tamil",
            ScriptClass::Common => "common",
            ScriptClass::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptRun {
    pub byte_start: u32,
    pub byte_end: u32,
    pub script: ScriptClass,
}

impl ScriptRun {
    pub fn as_slice<'a>(&self, text: &'a str) -> &'a str {
        &text[self.byte_start as usize..self.byte_end as usize]
    }
}

/// Splits UTF-8 input into script-uniform runs.
///
/// Returns an empty `Vec` for empty input. Every returned run has
/// `byte_start < byte_end`, and the concatenated ranges cover the input
/// exactly (no gaps, no overlaps). Runs with a non-`Common` script absorb
/// trailing `Common` characters; a leading `Common` prefix before any real
/// script attaches to the following run. If the entire input is `Common`
/// (e.g., pure punctuation / digits), a single `Common` run is emitted.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScriptRunSplitter;

impl ScriptRunSplitter {
    pub fn new() -> Self {
        Self
    }

    pub fn runs(&self, text: &str) -> Vec<ScriptRun> {
        if text.is_empty() {
            return Vec::new();
        }

        let mut runs: Vec<ScriptRun> = Vec::new();
        let mut pending_start: Option<u32> = None;
        let mut active: Option<ScriptClass> = None;

        for (idx, ch) in text.char_indices() {
            let start = idx as u32;
            let class = ScriptClass::from_char(ch);

            match (active, class) {
                (None, ScriptClass::Common) => {
                    if pending_start.is_none() {
                        pending_start = Some(start);
                    }
                }
                (None, other) => {
                    let run_start = pending_start.take().unwrap_or(start);
                    active = Some(other);
                    runs.push(ScriptRun {
                        byte_start: run_start,
                        byte_end: start + ch.len_utf8() as u32,
                        script: other,
                    });
                }
                (Some(prev), ScriptClass::Common) => {
                    let last = runs.last_mut().expect("active implies last run exists");
                    debug_assert_eq!(last.script, prev);
                    last.byte_end = start + ch.len_utf8() as u32;
                }
                (Some(prev), other) if prev == other => {
                    let last = runs.last_mut().expect("active implies last run exists");
                    last.byte_end = start + ch.len_utf8() as u32;
                }
                (Some(_), other) => {
                    active = Some(other);
                    runs.push(ScriptRun {
                        byte_start: start,
                        byte_end: start + ch.len_utf8() as u32,
                        script: other,
                    });
                }
            }
        }

        if runs.is_empty() {
            if let Some(start) = pending_start {
                runs.push(ScriptRun {
                    byte_start: start,
                    byte_end: text.len() as u32,
                    script: ScriptClass::Common,
                });
            }
        }

        runs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_slices<'a>(text: &'a str, runs: &[ScriptRun]) -> Vec<(&'a str, ScriptClass)> {
        runs.iter().map(|r| (r.as_slice(text), r.script)).collect()
    }

    #[test]
    fn empty_input_yields_no_runs() {
        let runs = ScriptRunSplitter::new().runs("");
        assert!(runs.is_empty());
    }

    #[test]
    fn pure_latin_single_run() {
        let text = "hello world";
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].script, ScriptClass::Latin);
        assert_eq!(runs[0].as_slice(text), text);
    }

    #[test]
    fn pure_han_single_run() {
        let text = "東京大学";
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].script, ScriptClass::Han);
        assert_eq!(runs[0].as_slice(text), text);
    }

    #[test]
    fn pure_punct_single_common_run() {
        let text = "!!!,,,";
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].script, ScriptClass::Common);
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
        for pair in runs.windows(2) {
            assert_eq!(pair[0].byte_end, pair[1].byte_start);
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
    fn is_cjk_classifies_correctly() {
        assert!(ScriptClass::Han.is_cjk());
        assert!(ScriptClass::Hiragana.is_cjk());
        assert!(ScriptClass::Katakana.is_cjk());
        assert!(ScriptClass::Hangul.is_cjk());
        assert!(!ScriptClass::Latin.is_cjk());
        assert!(!ScriptClass::Arabic.is_cjk());
        assert!(!ScriptClass::Thai.is_cjk());
    }
}
