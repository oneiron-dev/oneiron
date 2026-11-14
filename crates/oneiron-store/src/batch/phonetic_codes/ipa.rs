//! Grapheme-to-phoneme readings of a name (CROSS-ARCH-0013 `#ladder` rung 1,
//! G2P → IPA → NPD): each reading is a string of IPA segments, the key the
//! Normalized Phonetic Distance compares across scripts.

mod english;
mod japanese;
mod korean;
mod mandarin;

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

use super::features::Segment;

/// At most this many readings of one name.
const MAX_READINGS: usize = 4;

/// The language tag of a reading joined from runs read in different
/// languages.
const MIXED_LANGUAGES: &str = "mul";

/// Company-form words carrying no sound of the name (CROSS-ARCH-0013
/// `#intl-cautions`), stripped when they lead or end a name with no
/// separator between.
const CJK_ORG_SUFFIXES: [&str; 3] = ["株式会社", "有限公司", "주식회사"];

/// The same as whole Latin words, dots and commas aside (Ltd., Inc., K.K.).
const LATIN_ORG_SUFFIXES: [&str; 4] = ["ltd", "inc", "gmbh", "kk"];

/// One reading of a name: the language it is read in (ISO 639-3: `jpn`,
/// `kor`, `cmn`, `eng`, or `mul` for runs read in different languages) and
/// its segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaReading {
    /// The language the name is read in.
    pub lang: &'static str,
    /// The reading's phoneme segments.
    pub segments: Vec<Segment>,
}

impl IpaReading {
    /// The reading as one IPA string: its segments' symbols in order, the
    /// form a stored `ipa:` key holds.
    pub fn ipa(&self) -> String {
        self.segments.iter().copied().map(Segment::symbol).collect()
    }

    fn new(lang: &'static str, segments: Vec<Segment>) -> Self {
        Self { lang, segments }
    }

    /// This reading followed by `tail`.
    fn join(&self, tail: &Self) -> Self {
        let lang = if self.lang == tail.lang {
            self.lang
        } else {
            MIXED_LANGUAGES
        };
        let mut segments = self.segments.clone();
        segments.extend(&tail.segments);
        Self::new(lang, segments)
    }
}

/// The readings of a name, at most four: after NFKC and lower-casing and
/// with a company-form word stripped ([`strip_org_suffix`]), each run of one
/// script is read on its own and the run readings join in order.
///
/// - Kana: Japanese, through Hepburn romaji.
/// - Hangul: Korean, jamo by jamo.
/// - Han: Mandarin (pinyin, toneless; up to four readings over the
///   characters' other readings). No Japanese kanji reading is guessed:
///   kanji readings are entity-specific and come from a reading field.
/// - Latin (marks stripped): Japanese when every word parses as Hepburn,
///   Mandarin when every word parses as pinyin, and always English (the NRL
///   letter-to-sound rules).
///
/// Anything else (digits, symbols, other scripts) is not read.
pub fn phonetic_readings(name: &str) -> Vec<IpaReading> {
    let normalized = super::normalize(name);
    let mut readings: Vec<IpaReading> = Vec::new();
    for run in script_runs(strip_org_suffix(&normalized)) {
        let run_readings = run.readings();
        if run_readings.is_empty() {
            continue;
        }
        readings = if readings.is_empty() {
            run_readings
        } else {
            readings
                .iter()
                .flat_map(|head| run_readings.iter().map(move |tail| head.join(tail)))
                .collect()
        };
        readings.truncate(MAX_READINGS);
    }
    let mut distinct: Vec<IpaReading> = Vec::new();
    for reading in readings {
        if !distinct.contains(&reading) {
            distinct.push(reading);
        }
    }
    distinct
}

/// `name` without a leading or trailing company-form word: 株式会社,
/// 有限公司 or 주식회사 at either end, or Ltd, Inc, GmbH or KK (any case,
/// dots and commas aside) as the first or last word. A name that is only
/// such words keeps them.
pub fn strip_org_suffix(name: &str) -> &str {
    let mut rest = trim_name(name);
    loop {
        let stripped = trim_name(strip_one_org_suffix(rest));
        if stripped.len() == rest.len() || stripped.is_empty() {
            return rest;
        }
        rest = stripped;
    }
}

fn trim_name(name: &str) -> &str {
    name.trim_matches(|c: char| c.is_whitespace() || c == ',')
}

fn strip_one_org_suffix(name: &str) -> &str {
    for suffix in CJK_ORG_SUFFIXES {
        if let Some(rest) = name
            .strip_prefix(suffix)
            .or_else(|| name.strip_suffix(suffix))
        {
            return rest;
        }
    }
    if let Some((first, rest)) = name.split_once(char::is_whitespace)
        && is_latin_org_suffix(first)
    {
        return rest;
    }
    if let Some((rest, last)) = name.rsplit_once(char::is_whitespace)
        && is_latin_org_suffix(last)
    {
        return rest;
    }
    name
}

fn is_latin_org_suffix(word: &str) -> bool {
    let letters: String = word.chars().filter(|c| !matches!(c, '.' | ',')).collect();
    LATIN_ORG_SUFFIXES
        .iter()
        .any(|suffix| suffix.eq_ignore_ascii_case(&letters))
}

/// The scripts a reader reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    /// Hiragana and katakana, folded to hiragana, and the long-vowel mark.
    Kana,
    Hangul,
    Han,
    /// ASCII letters once marks are stripped.
    Latin,
}

/// A maximal run of one script. A Latin run keeps a space between its
/// words; other runs drop separators.
struct ScriptRun {
    script: Script,
    text: String,
}

impl ScriptRun {
    fn readings(&self) -> Vec<IpaReading> {
        match self.script {
            Script::Kana => japanese::kana_reading(&self.text)
                .map(|segments| IpaReading::new("jpn", segments))
                .into_iter()
                .collect(),
            Script::Hangul => korean::hangul_reading(&self.text)
                .map(|segments| IpaReading::new("kor", segments))
                .into_iter()
                .collect(),
            Script::Han => mandarin::han_readings(&self.text)
                .into_iter()
                .map(|segments| IpaReading::new("cmn", segments))
                .collect(),
            Script::Latin => {
                let words: Vec<&str> = self.text.split(' ').filter(|w| !w.is_empty()).collect();
                [
                    ("jpn", japanese::latin_reading(&words)),
                    ("cmn", mandarin::latin_reading(&words)),
                    ("eng", english::latin_reading(&words)),
                ]
                .into_iter()
                .filter_map(|(lang, segments)| Some(IpaReading::new(lang, segments?)))
                .collect()
            }
        }
    }
}

/// The script runs of a normalized name. A character no reader reads ends a
/// Latin word and is dropped.
fn script_runs(name: &str) -> Vec<ScriptRun> {
    let mut runs: Vec<ScriptRun> = Vec::new();
    for c in name.chars() {
        let Some((script, text)) = script_of(c) else {
            if let Some(run) = runs.last_mut()
                && run.script == Script::Latin
                && !run.text.ends_with(' ')
            {
                run.text.push(' ');
            }
            continue;
        };
        match runs.last_mut() {
            Some(run) if run.script == script => run.text.push_str(&text),
            _ => runs.push(ScriptRun { script, text }),
        }
    }
    runs
}

/// The script of `c` and the text its reader takes for it.
fn script_of(c: char) -> Option<(Script, String)> {
    let kana = match c {
        'ァ'..='ヶ' => char::from_u32(u32::from(c) - 0x60),
        'ぁ'..='ゖ' | 'ー' => Some(c),
        _ => None,
    };
    if let Some(kana) = kana {
        return Some((Script::Kana, kana.to_string()));
    }
    if korean::is_hangul_syllable(c) {
        return Some((Script::Hangul, c.to_string()));
    }
    if mandarin::has_mandarin_reading(c) {
        return Some((Script::Han, c.to_string()));
    }
    let latin: String = c.nfkd().filter(|c| !is_combining_mark(*c)).collect();
    (!latin.is_empty() && latin.chars().all(|c| c.is_ascii_alphabetic()))
        .then_some((Script::Latin, latin))
}
