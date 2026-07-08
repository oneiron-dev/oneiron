//! Script-run splitter.
//!
//! Groups consecutive characters of the same script into byte-range runs.
//! `Common` / `Inherited` characters attach to the adjacent non-CJK run so
//! that Latin boundaries only appear between real script transitions; when
//! CJK runs would absorb `Common` on either side the Common chars are split
//! into their own run, so cjk_ngram never absorbs digits or punctuation
//! into CJK bigrams (plan §1.1 no-cross-script-bigram invariant). Both
//! trailing `Common` after CJK and leading `Common` before CJK are split.

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
    /// Common / Inherited / Unknown.
    ///
    /// `ScriptRunSplitter::runs` attaches Common runs to an adjacent
    /// non-CJK neighbor when one exists, but Common can still surface as
    /// its own run when:
    /// * the input is purely Common (e.g. `"!?@"`),
    /// * Common bytes lead or trail the input with no non-CJK neighbor to
    ///   absorb them,
    /// * Common bytes sit between two CJK runs — they never merge into a
    ///   CJK run because that would let punctuation cross the n-gram
    ///   boundary, so they stand alone.
    ///
    /// Consumers must handle Common runs (the dispatcher routes them to
    /// `icu::analyze`).
    Common,
    /// Scripts outside the explicit list above.
    Other,
}

impl ScriptClass {
    pub fn from_char(c: char) -> ScriptClass {
        // U+30FC (prolonged sound mark) and U+30A0 (double hyphen) have
        // Script=Common but kana script-extension behavior. Treating them
        // as Common splits kana words into separate runs, so default them
        // to Katakana and let the splitter override active Hiragana runs.
        if matches!(c, '\u{30FC}' | '\u{30A0}') {
            return ScriptClass::Katakana;
        }
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
            ScriptClass::Han | ScriptClass::Hiragana | ScriptClass::Katakana | ScriptClass::Hangul
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
/// exactly (no gaps, no overlaps). Non-CJK runs absorb trailing `Common`
/// characters; CJK runs do not (trailing `Common` starts a fresh `Common`
/// run so cjk_ngram never produces cross-script bigrams). A leading
/// `Common` prefix before a non-CJK run attaches to that run; before a
/// CJK run the leading `Common` is split off into its own run for the
/// same invariant. If the entire input is `Common` (e.g., pure punctuation
/// / digits), a single `Common` run is emitted.
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
            // Kana marks default to Katakana in `from_char`; override to
            // Hiragana when the active run is Hiragana so `らーめん` and
            // `ひ゠ら` stay one run instead of splitting Hira/Kata/Hira.
            let class =
                if matches!(ch, '\u{30FC}' | '\u{30A0}') && active == Some(ScriptClass::Hiragana) {
                    ScriptClass::Hiragana
                } else {
                    ScriptClass::from_char(ch)
                };

            match (active, class) {
                (None, ScriptClass::Common) => {
                    if pending_start.is_none() {
                        pending_start = Some(start);
                    }
                }
                (None, other) => {
                    let run_start = match pending_start.take() {
                        // Leading Common before CJK splits into its own
                        // run — otherwise the CJK analyzer would bigram
                        // across the Common/CJK boundary (e.g. `4東`
                        // from `2024東京`), breaking plan §1.1.
                        Some(p_start) if other.is_cjk() => {
                            runs.push(ScriptRun {
                                byte_start: p_start,
                                byte_end: start,
                                script: ScriptClass::Common,
                            });
                            start
                        }
                        Some(p_start) => p_start,
                        None => start,
                    };
                    active = Some(other);
                    runs.push(ScriptRun {
                        byte_start: run_start,
                        byte_end: start + ch.len_utf8() as u32,
                        script: other,
                    });
                }
                (Some(prev), ScriptClass::Common) if prev.is_cjk() => {
                    // Starting a fresh Common run — otherwise cjk_ngram would
                    // absorb trailing digits/punctuation into a CJK run and
                    // emit unigrams like `1`/`、` plus bigrams like `京1`/`京、`,
                    // breaking the plan §1.1 no-cross-script-bigram invariant.
                    active = Some(ScriptClass::Common);
                    runs.push(ScriptRun {
                        byte_start: start,
                        byte_end: start + ch.len_utf8() as u32,
                        script: ScriptClass::Common,
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

        if runs.is_empty()
            && let Some(start) = pending_start
        {
            runs.push(ScriptRun {
                byte_start: start,
                byte_end: text.len() as u32,
                script: ScriptClass::Common,
            });
        }

        runs
    }
}

#[cfg(test)]
mod tests;
