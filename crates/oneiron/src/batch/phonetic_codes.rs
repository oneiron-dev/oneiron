//! Deterministic name codes for the first phonetic rung (OF-101).
//!
//! Kana and Latin romaji share a romanized key. English additionally gets a
//! Soundex key; it is a Latin-only shortcut, not G2P/NPD or a learned model.

use std::collections::BTreeSet;
use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

/// Generate the same codes used on writes for a name or a query mention.
///
/// Hiragana, katakana and half-width kana are folded to hiragana and Hepburn
/// romaji. Latin names receive a romaji key and an English Soundex key. Han
/// readings are entity-specific: pass a known kana/romaji reading separately
/// rather than guessing a pronunciation from the written name.
pub fn generate_phonetic_codes(name: &str) -> Vec<String> {
    let normalized: String = name.nfkc().flat_map(char::to_lowercase).collect();
    let mut codes = BTreeSet::new();
    let kana: String = normalized
        .chars()
        .map(|c| match c {
            'ァ'..='ヶ' => char::from_u32(c as u32 - 0x60).unwrap_or(c),
            _ => c,
        })
        .collect();
    if kana.chars().any(|c| matches!(c, 'ぁ'..='ゖ')) {
        if let Some(romaji) = romanize(&kana) {
            let folded: String = kana.chars().filter(|c| !is_separator(*c)).collect();
            codes.insert(format!("kana:{folded}"));
            add_romaji(&mut codes, &romaji);
        }
    } else {
        let latin: String = normalized.nfkd().filter(|c| !is_combining_mark(*c)).collect();
        if latin
            .chars()
            .all(|c| c.is_ascii_alphabetic() || is_separator(c))
        {
            add_romaji(&mut codes, &latin);
            if let Some(code) = soundex(&latin) {
                codes.insert(format!("en:soundex:{code}"));
            }
            // Each part also finds a multi-part name from a single mention.
            for part in latin.split(is_separator).filter(|part| !part.is_empty()) {
                add_romaji(&mut codes, part);
                if let Some(code) = soundex(part) {
                    codes.insert(format!("en:soundex:{code}"));
                }
            }
        }
    }
    codes.into_iter().collect()
}

/// Only explicit name/alias/reading fields feed this index, never prose or
/// secret custody. A reading can accompany a Han name without changing it.
pub(crate) fn codes_for_body(entity_type: u8, data: &[u8]) -> Vec<String> {
    if entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return Vec::new();
    }
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
    else {
        return Vec::new();
    };
    let mut codes = BTreeSet::new();
    for (key, value) in fields {
        match key.as_str() {
            Some(
                "name" | "reading" | "kana" | "romaji" | "nameKana" | "name_kana"
                | "nameReading" | "name_reading",
            ) => {
                if let Some(name) = value.as_str() {
                    codes.extend(generate_phonetic_codes(name));
                }
            }
            Some("aliases") => {
                if let Some(aliases) = value.as_array() {
                    for alias in aliases.iter().filter_map(rmpv::Value::as_str) {
                        codes.extend(generate_phonetic_codes(alias));
                    }
                }
            }
            _ => {}
        }
    }
    codes.into_iter().collect()
}

fn is_separator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '-' | '\'' | '’' | '.' | '・' | '･')
}

fn add_romaji(codes: &mut BTreeSet<String>, text: &str) {
    let compact: String = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if compact.is_empty() {
        return;
    }
    // Long vowels have several common Latin spellings (o/ou/oo/ō).
    let mut key = String::new();
    for c in compact.chars() {
        if (key.ends_with(c) && matches!(c, 'a' | 'i' | 'u' | 'e' | 'o'))
            || (c == 'u' && key.ends_with('o'))
        {
            continue;
        }
        key.push(c);
    }
    codes.insert(format!("romaji:{key}"));
}

fn soundex(name: &str) -> Option<String> {
    let mut letters = name.chars().filter(char::is_ascii_alphabetic);
    let first = letters.next()?.to_ascii_uppercase();
    let mut key = String::from(first);
    let mut previous = soundex_digit(first);
    for c in letters {
        let c = c.to_ascii_uppercase();
        // H and W do not separate adjacent consonant classes in Soundex.
        if matches!(c, 'H' | 'W') {
            continue;
        }
        let digit = soundex_digit(c);
        if digit != '0' && digit != previous {
            key.push(digit);
            if key.len() == 4 {
                break;
            }
        }
        previous = digit;
    }
    while key.len() < 4 {
        key.push('0');
    }
    Some(key)
}

fn soundex_digit(c: char) -> char {
    match c {
        'B' | 'F' | 'P' | 'V' => '1',
        'C' | 'G' | 'J' | 'K' | 'Q' | 'S' | 'X' | 'Z' => '2',
        'D' | 'T' => '3',
        'L' => '4',
        'M' | 'N' => '5',
        'R' => '6',
        _ => '0',
    }
}

fn romanize(kana: &str) -> Option<String> {
    let chars: Vec<char> = kana.chars().filter(|c| !is_separator(*c)).collect();
    let mut out = String::new();
    let mut geminate = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == 'っ' {
            if geminate {
                return None;
            }
            geminate = true;
            i += 1;
            continue;
        }
        if c == 'ー' {
            let vowel = out
                .chars()
                .rev()
                .find(|c| matches!(c, 'a' | 'i' | 'u' | 'e' | 'o'))?;
            out.push(vowel);
            i += 1;
            continue;
        }
        let mut syllable = kana_syllable(c)?.to_owned();
        if let Some(next) = chars.get(i + 1).copied() {
            if let Some(pair) = kana_pair(c, next) {
                syllable = pair.to_owned();
                i += 1;
            } else if matches!(next, 'ゃ' | 'ゅ' | 'ょ') && syllable.ends_with('i') {
                syllable.pop();
                syllable.push('y');
                syllable.push(match next {
                    'ゃ' => 'a',
                    'ゅ' => 'u',
                    _ => 'o',
                });
                i += 1;
            }
        }
        if geminate {
            let first = syllable.chars().next()?;
            if matches!(first, 'a' | 'i' | 'u' | 'e' | 'o' | 'n') {
                return None;
            }
            out.push(if syllable.starts_with("ch") { 't' } else { first });
            geminate = false;
        }
        out.push_str(&syllable);
        i += 1;
    }
    (!geminate && !out.is_empty()).then_some(out)
}

fn kana_pair(first: char, second: char) -> Option<&'static str> {
    Some(match (first, second) {
        ('し', 'ゃ') => "sha",
        ('し', 'ゅ') => "shu",
        ('し', 'ょ') => "sho",
        ('ち', 'ゃ') => "cha",
        ('ち', 'ゅ') => "chu",
        ('ち', 'ょ') => "cho",
        ('じ' | 'ぢ', 'ゃ') => "ja",
        ('じ' | 'ぢ', 'ゅ') => "ju",
        ('じ' | 'ぢ', 'ょ') => "jo",
        ('い', 'ぇ') => "ye",
        ('う', 'ぃ') => "wi",
        ('う', 'ぇ') => "we",
        ('う', 'ぉ') => "wo",
        ('し', 'ぇ') => "she",
        ('じ', 'ぇ') => "je",
        ('ち', 'ぇ') => "che",
        ('て', 'ぃ') => "ti",
        ('て', 'ゅ') => "tyu",
        ('で', 'ぃ') => "di",
        ('で', 'ゅ') => "dyu",
        ('と', 'ぅ') => "tu",
        ('ど', 'ぅ') => "du",
        ('つ', 'ぁ') => "tsa",
        ('つ', 'ぃ') => "tsi",
        ('つ', 'ぇ') => "tse",
        ('つ', 'ぉ') => "tso",
        ('ふ', 'ぁ') => "fa",
        ('ふ', 'ぃ') => "fi",
        ('ふ', 'ぇ') => "fe",
        ('ふ', 'ぉ') => "fo",
        ('ふ', 'ゅ') => "fyu",
        ('ゔ', 'ぁ') => "va",
        ('ゔ', 'ぃ') => "vi",
        ('ゔ', 'ぇ') => "ve",
        ('ゔ', 'ぉ') => "vo",
        ('ゔ', 'ゅ') => "vyu",
        ('く', 'ぁ') => "kwa",
        ('く', 'ぃ') => "kwi",
        ('く', 'ぇ') => "kwe",
        ('く', 'ぉ') => "kwo",
        ('ぐ', 'ぁ') => "gwa",
        ('ぐ', 'ぃ') => "gwi",
        ('ぐ', 'ぇ') => "gwe",
        ('ぐ', 'ぉ') => "gwo",
        _ => return None,
    })
}

fn kana_syllable(c: char) -> Option<&'static str> {
    Some(match c {
        'あ' | 'ぁ' => "a",
        'い' | 'ぃ' => "i",
        'う' | 'ぅ' => "u",
        'え' | 'ぇ' => "e",
        'お' | 'ぉ' => "o",
        'か' | 'ゕ' => "ka",
        'き' => "ki",
        'く' => "ku",
        'け' | 'ゖ' => "ke",
        'こ' => "ko",
        'が' => "ga",
        'ぎ' => "gi",
        'ぐ' => "gu",
        'げ' => "ge",
        'ご' => "go",
        'さ' => "sa",
        'し' => "shi",
        'す' => "su",
        'せ' => "se",
        'そ' => "so",
        'ざ' => "za",
        'じ' | 'ぢ' => "ji",
        'ず' | 'づ' => "zu",
        'ぜ' => "ze",
        'ぞ' => "zo",
        'た' => "ta",
        'ち' => "chi",
        'つ' => "tsu",
        'て' => "te",
        'と' => "to",
        'だ' => "da",
        'で' => "de",
        'ど' => "do",
        'な' => "na",
        'に' => "ni",
        'ぬ' => "nu",
        'ね' => "ne",
        'の' => "no",
        'は' => "ha",
        'ひ' => "hi",
        'ふ' => "fu",
        'へ' => "he",
        'ほ' => "ho",
        'ば' => "ba",
        'び' => "bi",
        'ぶ' => "bu",
        'べ' => "be",
        'ぼ' => "bo",
        'ぱ' => "pa",
        'ぴ' => "pi",
        'ぷ' => "pu",
        'ぺ' => "pe",
        'ぽ' => "po",
        'ま' => "ma",
        'み' => "mi",
        'む' => "mu",
        'め' => "me",
        'も' => "mo",
        'や' | 'ゃ' => "ya",
        'ゆ' | 'ゅ' => "yu",
        'よ' | 'ょ' => "yo",
        'ら' => "ra",
        'り' => "ri",
        'る' => "ru",
        'れ' => "re",
        'ろ' => "ro",
        'わ' | 'ゎ' => "wa",
        'ゐ' => "wi",
        'ゑ' => "we",
        'を' => "o",
        'ん' => "n",
        'ゔ' => "vu",
        _ => return None,
    })
}
