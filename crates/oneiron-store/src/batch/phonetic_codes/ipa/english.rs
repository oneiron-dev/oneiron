//! The English reading (`eng`): the letter-to-sound rules of NRL Report 7948
//! (H. S. Elovitz, R. W. Johnson, A. McHugh and J. E. Shore, "Automatic
//! Translation of English Text to Phonetics by Means of Letter-to-Sound
//! Rules", Naval Research Laboratory, 1976; public domain), in the order of
//! John A. Wasser's public-domain C listing of them (comp.sources.unix,
//! April 1985), with their phoneme codes written in IPA.

use super::super::features::{Segment, ipa_segments};

/// The reading of Latin words: each word's phoneme codes, in IPA.
pub(super) fn latin_reading(words: &[&str]) -> Option<Vec<Segment>> {
    let mut ipa = String::new();
    for word in words {
        push_codes_ipa(&mut ipa, &word_codes(word));
    }
    ipa_segments(&ipa)
}

/// The phoneme codes the rules write for one word of ASCII letters. At each
/// letter the first rule of that letter's list whose letters and contexts
/// match is applied, and reading goes on after its letters.
fn word_codes(word: &str) -> String {
    let text = format!(" {} ", word.to_ascii_uppercase()).into_bytes();
    let mut codes = String::new();
    let mut index = 1;
    while index + 1 < text.len() {
        let rules = match text[index] {
            letter @ b'A'..=b'Z' => RULES[usize::from(letter - b'A')],
            _ => &[],
        };
        match rules.iter().find(|rule| rule.applies(&text, index)) {
            Some(rule) => {
                codes.push_str(rule.3);
                index += rule.1.len().max(1);
            }
            None => index += 1,
        }
    }
    codes
}

/// Appends the IPA of phoneme codes: two capitals or one lower-case letter
/// each, as the rules write them.
fn push_codes_ipa(ipa: &mut String, codes: &str) {
    let mut rest = codes;
    while let Some(first) = rest.chars().next() {
        let width = if first.is_ascii_uppercase() { 2 } else { 1 };
        let code = rest.get(..width).unwrap_or(rest);
        if let Some((_, symbol)) = CODE_IPA.iter().find(|(name, _)| *name == code) {
            ipa.push_str(symbol);
        }
        rest = rest.get(code.len()..).unwrap_or_default();
    }
}

/// The report's phoneme codes and their IPA. Diphthongs are two segments.
const CODE_IPA: [(&str, &str); 42] = [
    ("IY", "i"),
    ("IH", "ɪ"),
    ("EY", "eɪ"),
    ("EH", "ɛ"),
    ("AE", "æ"),
    ("AA", "ɑ"),
    ("AO", "ɔ"),
    ("OW", "oʊ"),
    ("UH", "ʊ"),
    ("UW", "u"),
    ("ER", "ɜ"),
    ("AX", "ə"),
    ("AH", "ʌ"),
    ("AY", "aɪ"),
    ("AW", "aʊ"),
    ("OY", "ɔɪ"),
    ("p", "p"),
    ("b", "b"),
    ("t", "t"),
    ("d", "d"),
    ("k", "k"),
    ("g", "ɡ"),
    ("f", "f"),
    ("v", "v"),
    ("TH", "θ"),
    ("DH", "ð"),
    ("s", "s"),
    ("z", "z"),
    ("SH", "ʃ"),
    ("ZH", "ʒ"),
    ("HH", "h"),
    ("h", "h"),
    ("m", "m"),
    ("n", "n"),
    ("NG", "ŋ"),
    ("l", "l"),
    ("w", "w"),
    ("y", "j"),
    ("r", "ɹ"),
    ("CH", "t͡ʃ"),
    ("j", "d͡ʒ"),
    ("WH", "w"),
];

/// One rule: its left context, the letters it reads, its right context, and
/// the phoneme codes it writes. In a context, `#` is one or more vowels, `:`
/// zero or more consonants, `^` one consonant, `.` one voiced consonant (B,
/// D, V, G, J, L, M, N, R, W or Z), `+` a front vowel (E, I or Y), `%` a
/// suffix (ER, E, ES, ED, ING or ELY; right contexts only), and a space the
/// edge of the word. Any other character stands for itself.
struct Rule(&'static str, &'static str, &'static str, &'static str);

impl Rule {
    /// Whether the rule reads `text` at `index`.
    fn applies(&self, text: &[u8], index: usize) -> bool {
        let Self(left, letters, right, _) = self;
        text[index..].starts_with(letters.as_bytes())
            && context_matches(
                left.bytes().rev(),
                Cursor {
                    text,
                    at: index.checked_sub(1),
                    leftward: true,
                },
            )
            && context_matches(
                right.bytes(),
                Cursor {
                    text,
                    at: Some(index + letters.len()),
                    leftward: false,
                },
            )
    }
}

/// A place in a word, moving left or right.
struct Cursor<'a> {
    text: &'a [u8],
    /// `None` once it has moved past the word's start.
    at: Option<usize>,
    leftward: bool,
}

impl Cursor<'_> {
    /// The byte `offset` steps ahead, 0 outside the word.
    fn peek_ahead(&self, offset: usize) -> u8 {
        let at = if self.leftward {
            self.at.and_then(|at| at.checked_sub(offset))
        } else {
            self.at.map(|at| at + offset)
        };
        at.and_then(|at| self.text.get(at)).copied().unwrap_or(0)
    }

    fn peek(&self) -> u8 {
        self.peek_ahead(0)
    }

    fn advance(&mut self) {
        self.at = if self.leftward {
            self.at.and_then(|at| at.checked_sub(1))
        } else {
            self.at.map(|at| at + 1)
        };
    }

    /// Steps over a suffix (ER, E, ES, ED, ING or ELY), when one starts here.
    fn skip_suffix(&mut self) -> bool {
        match self.peek() {
            b'E' => {
                let length = match (self.peek_ahead(1), self.peek_ahead(2)) {
                    (b'L', b'Y') => 3,
                    (b'R' | b'S' | b'D', _) => 2,
                    _ => 1,
                };
                (0..length).for_each(|_| self.advance());
                true
            }
            b'I' if self.peek_ahead(1) == b'N' && self.peek_ahead(2) == b'G' => {
                (0..3).for_each(|_| self.advance());
                true
            }
            _ => false,
        }
    }
}

fn is_vowel(letter: u8) -> bool {
    matches!(letter, b'A' | b'E' | b'I' | b'O' | b'U')
}

fn is_consonant(letter: u8) -> bool {
    letter.is_ascii_uppercase() && !is_vowel(letter)
}

/// Whether a context's symbols, in reading order, match from `cursor`.
fn context_matches(symbols: impl Iterator<Item = u8>, mut cursor: Cursor<'_>) -> bool {
    for symbol in symbols {
        let letter = cursor.peek();
        let matched = match symbol {
            b'#' => {
                let vowel = is_vowel(letter);
                while is_vowel(cursor.peek()) {
                    cursor.advance();
                }
                vowel
            }
            b':' => {
                while is_consonant(cursor.peek()) {
                    cursor.advance();
                }
                true
            }
            b'%' => !cursor.leftward && cursor.skip_suffix(),
            _ => {
                cursor.advance();
                match symbol {
                    b'^' => is_consonant(letter),
                    b'.' => b"BDVGJLMNRWZ".contains(&letter),
                    b'+' => b"EIY".contains(&letter),
                    _ => symbol == letter,
                }
            }
        };
        if !matched {
            return false;
        }
    }
    true
}

/// Each letter's rules, A to Z, tried in order.
static RULES: [&[Rule]; 26] = [
    A_RULES, B_RULES, C_RULES, D_RULES, E_RULES, F_RULES, G_RULES, H_RULES, I_RULES, J_RULES,
    K_RULES, L_RULES, M_RULES, N_RULES, O_RULES, P_RULES, Q_RULES, R_RULES, S_RULES, T_RULES,
    U_RULES, V_RULES, W_RULES, X_RULES, Y_RULES, Z_RULES,
];

const A_RULES: &[Rule] = &[
    Rule("", "A", " ", "AX"),
    Rule(" ", "ARE", " ", "AAr"),
    Rule(" ", "AR", "O", "AXr"),
    Rule("", "AR", "#", "EHr"),
    Rule("^", "AS", "#", "EYs"),
    Rule("", "A", "WA", "AX"),
    Rule("", "AW", "", "AO"),
    Rule(" :", "ANY", "", "EHnIY"),
    Rule("", "A", "^+#", "EY"),
    Rule("#:", "ALLY", "", "AXlIY"),
    Rule(" ", "AL", "#", "AXl"),
    Rule("", "AGAIN", "", "AXgEHn"),
    Rule("#:", "AG", "E", "IHj"),
    Rule("", "A", "^+:#", "AE"),
    Rule(" :", "A", "^+ ", "EY"),
    Rule("", "A", "^%", "EY"),
    Rule(" ", "ARR", "", "AXr"),
    Rule("", "ARR", "", "AEr"),
    Rule(" :", "AR", " ", "AAr"),
    Rule("", "AR", " ", "ER"),
    Rule("", "AR", "", "AAr"),
    Rule("", "AIR", "", "EHr"),
    Rule("", "AI", "", "EY"),
    Rule("", "AY", "", "EY"),
    Rule("", "AU", "", "AO"),
    Rule("#:", "AL", " ", "AXl"),
    Rule("#:", "ALS", " ", "AXlz"),
    Rule("", "ALK", "", "AOk"),
    Rule("", "AL", "^", "AOl"),
    Rule(" :", "ABLE", "", "EYbAXl"),
    Rule("", "ABLE", "", "AXbAXl"),
    Rule("", "ANG", "+", "EYnj"),
    Rule("", "A", "", "AE"),
];
const B_RULES: &[Rule] = &[
    Rule(" ", "BE", "^#", "bIH"),
    Rule("", "BEING", "", "bIYIHNG"),
    Rule(" ", "BOTH", " ", "bOWTH"),
    Rule(" ", "BUS", "#", "bIHz"),
    Rule("", "BUIL", "", "bIHl"),
    Rule("", "B", "", "b"),
];
const C_RULES: &[Rule] = &[
    Rule(" ", "CH", "^", "k"),
    Rule("^E", "CH", "", "k"),
    Rule("", "CH", "", "CH"),
    Rule(" S", "CI", "#", "sAY"),
    Rule("", "CI", "A", "SH"),
    Rule("", "CI", "O", "SH"),
    Rule("", "CI", "EN", "SH"),
    Rule("", "C", "+", "s"),
    Rule("", "CK", "", "k"),
    Rule("", "COM", "%", "kAHm"),
    Rule("", "C", "", "k"),
];
const D_RULES: &[Rule] = &[
    Rule("#:", "DED", " ", "dIHd"),
    Rule(".E", "D", " ", "d"),
    Rule("#:^E", "D", " ", "t"),
    Rule(" ", "DE", "^#", "dIH"),
    Rule(" ", "DO", " ", "dUW"),
    Rule(" ", "DOES", "", "dAHz"),
    Rule(" ", "DOING", "", "dUWIHNG"),
    Rule(" ", "DOW", "", "dAW"),
    Rule("", "DU", "A", "jUW"),
    Rule("", "D", "", "d"),
];
const E_RULES: &[Rule] = &[
    Rule("#:", "E", " ", ""),
    Rule("':^", "E", " ", ""),
    Rule(" :", "E", " ", "IY"),
    Rule("#", "ED", " ", "d"),
    Rule("#:", "E", "D ", ""),
    Rule("", "EV", "ER", "EHv"),
    Rule("", "E", "^%", "IY"),
    Rule("", "ERI", "#", "IYrIY"),
    Rule("", "ERI", "", "EHrIH"),
    Rule("#:", "ER", "#", "ER"),
    Rule("", "ER", "#", "EHr"),
    Rule("", "ER", "", "ER"),
    Rule(" ", "EVEN", "", "IYvEHn"),
    Rule("#:", "E", "W", ""),
    Rule("T", "EW", "", "UW"),
    Rule("S", "EW", "", "UW"),
    Rule("R", "EW", "", "UW"),
    Rule("D", "EW", "", "UW"),
    Rule("L", "EW", "", "UW"),
    Rule("Z", "EW", "", "UW"),
    Rule("N", "EW", "", "UW"),
    Rule("J", "EW", "", "UW"),
    Rule("TH", "EW", "", "UW"),
    Rule("CH", "EW", "", "UW"),
    Rule("SH", "EW", "", "UW"),
    Rule("", "EW", "", "yUW"),
    Rule("", "E", "O", "IY"),
    Rule("#:S", "ES", " ", "IHz"),
    Rule("#:C", "ES", " ", "IHz"),
    Rule("#:G", "ES", " ", "IHz"),
    Rule("#:Z", "ES", " ", "IHz"),
    Rule("#:X", "ES", " ", "IHz"),
    Rule("#:J", "ES", " ", "IHz"),
    Rule("#:CH", "ES", " ", "IHz"),
    Rule("#:SH", "ES", " ", "IHz"),
    Rule("#:", "E", "S ", ""),
    Rule("#:", "ELY", " ", "lIY"),
    Rule("#:", "EMENT", "", "mEHnt"),
    Rule("", "EFUL", "", "fUHl"),
    Rule("", "EE", "", "IY"),
    Rule("", "EARN", "", "ERn"),
    Rule(" ", "EAR", "^", "ER"),
    Rule("", "EAD", "", "EHd"),
    Rule("#:", "EA", " ", "IYAX"),
    Rule("", "EA", "SU", "EH"),
    Rule("", "EA", "", "IY"),
    Rule("", "EIGH", "", "EY"),
    Rule("", "EI", "", "IY"),
    Rule(" ", "EYE", "", "AY"),
    Rule("", "EY", "", "IY"),
    Rule("", "EU", "", "yUW"),
    Rule("", "E", "", "EH"),
];
const F_RULES: &[Rule] = &[Rule("", "FUL", "", "fUHl"), Rule("", "F", "", "f")];
const G_RULES: &[Rule] = &[
    Rule("", "GIV", "", "gIHv"),
    Rule(" ", "G", "I^", "g"),
    Rule("", "GE", "T", "gEH"),
    Rule("SU", "GGES", "", "gjEHs"),
    Rule("", "GG", "", "g"),
    Rule(" B#", "G", "", "g"),
    Rule("", "G", "+", "j"),
    Rule("", "GREAT", "", "grEYt"),
    Rule("#", "GH", "", ""),
    Rule("", "G", "", "g"),
];
const H_RULES: &[Rule] = &[
    Rule(" ", "HAV", "", "hAEv"),
    Rule(" ", "HERE", "", "hIYr"),
    Rule(" ", "HOUR", "", "AWER"),
    Rule("", "HOW", "", "hAW"),
    Rule("", "H", "#", "h"),
    Rule("", "H", "", ""),
];
const I_RULES: &[Rule] = &[
    Rule(" ", "IN", "", "IHn"),
    Rule(" ", "I", " ", "AY"),
    Rule("", "IN", "D", "AYn"),
    Rule("", "IER", "", "IYER"),
    Rule("#:R", "IED", "", "IYd"),
    Rule("", "IED", " ", "AYd"),
    Rule("", "IEN", "", "IYEHn"),
    Rule("", "IE", "T", "AYEH"),
    Rule(" :", "I", "%", "AY"),
    Rule("", "I", "%", "IY"),
    Rule("", "IE", "", "IY"),
    Rule("", "I", "^+:#", "IH"),
    Rule("", "IR", "#", "AYr"),
    Rule("", "IZ", "%", "AYz"),
    Rule("", "IS", "%", "AYz"),
    Rule("", "I", "D%", "AY"),
    Rule("+^", "I", "^+", "IH"),
    Rule("", "I", "T%", "AY"),
    Rule("#:^", "I", "^+", "IH"),
    Rule("", "I", "^+", "AY"),
    Rule("", "IR", "", "ER"),
    Rule("", "IGH", "", "AY"),
    Rule("", "ILD", "", "AYld"),
    Rule("", "IGN", " ", "AYn"),
    Rule("", "IGN", "^", "AYn"),
    Rule("", "IGN", "%", "AYn"),
    Rule("", "IQUE", "", "IYk"),
    Rule("", "I", "", "IH"),
];
const J_RULES: &[Rule] = &[Rule("", "J", "", "j")];
const K_RULES: &[Rule] = &[Rule(" ", "K", "N", ""), Rule("", "K", "", "k")];
const L_RULES: &[Rule] = &[
    Rule("", "LO", "C#", "lOW"),
    Rule("L", "L", "", ""),
    Rule("#:^", "L", "%", "AXl"),
    Rule("", "LEAD", "", "lIYd"),
    Rule("", "L", "", "l"),
];
const M_RULES: &[Rule] = &[Rule("", "MOV", "", "mUWv"), Rule("", "M", "", "m")];
const N_RULES: &[Rule] = &[
    Rule("E", "NG", "+", "nj"),
    Rule("", "NG", "R", "NGg"),
    Rule("", "NG", "#", "NGg"),
    Rule("", "NGL", "%", "NGgAXl"),
    Rule("", "NG", "", "NG"),
    Rule("", "NK", "", "NGk"),
    Rule(" ", "NOW", " ", "nAW"),
    Rule("", "N", "", "n"),
];
const O_RULES: &[Rule] = &[
    Rule("", "OF", " ", "AXv"),
    Rule("", "OROUGH", "", "EROW"),
    Rule("#:", "OR", " ", "ER"),
    Rule("#:", "ORS", " ", "ERz"),
    Rule("", "OR", "", "AOr"),
    Rule(" ", "ONE", "", "wAHn"),
    Rule("", "OW", "", "OW"),
    Rule(" ", "OVER", "", "OWvER"),
    Rule("", "OV", "", "AHv"),
    Rule("", "O", "^%", "OW"),
    Rule("", "O", "^EN", "OW"),
    Rule("", "O", "^I#", "OW"),
    Rule("", "OL", "D", "OWl"),
    Rule("", "OUGHT", "", "AOt"),
    Rule("", "OUGH", "", "AHf"),
    Rule(" ", "OU", "", "AW"),
    Rule("H", "OU", "S#", "AW"),
    Rule("", "OUS", "", "AXs"),
    Rule("", "OUR", "", "AOr"),
    Rule("", "OULD", "", "UHd"),
    Rule("^", "OU", "^L", "AH"),
    Rule("", "OUP", "", "UWp"),
    Rule("", "OU", "", "AW"),
    Rule("", "OY", "", "OY"),
    Rule("", "OING", "", "OWIHNG"),
    Rule("", "OI", "", "OY"),
    Rule("", "OOR", "", "AOr"),
    Rule("", "OOK", "", "UHk"),
    Rule("", "OOD", "", "UHd"),
    Rule("", "OO", "", "UW"),
    Rule("", "O", "E", "OW"),
    Rule("", "O", " ", "OW"),
    Rule("", "OA", "", "OW"),
    Rule(" ", "ONLY", "", "OWnlIY"),
    Rule(" ", "ONCE", "", "wAHns"),
    Rule("", "ON'T", "", "OWnt"),
    Rule("C", "O", "N", "AA"),
    Rule("", "O", "NG", "AO"),
    Rule(" :^", "O", "N", "AH"),
    Rule("I", "ON", "", "AXn"),
    Rule("#:", "ON", " ", "AXn"),
    Rule("#^", "ON", "", "AXn"),
    Rule("", "O", "ST ", "OW"),
    Rule("", "OF", "^", "AOf"),
    Rule("", "OTHER", "", "AHDHER"),
    Rule("", "OSS", " ", "AOs"),
    Rule("#:^", "OM", "", "AHm"),
    Rule("", "O", "", "AA"),
];
const P_RULES: &[Rule] = &[
    Rule("", "PH", "", "f"),
    Rule("", "PEOP", "", "pIYp"),
    Rule("", "POW", "", "pAW"),
    Rule("", "PUT", " ", "pUHt"),
    Rule("", "P", "", "p"),
];
const Q_RULES: &[Rule] = &[
    Rule("", "QUAR", "", "kwAOr"),
    Rule("", "QU", "", "kw"),
    Rule("", "Q", "", "k"),
];
const R_RULES: &[Rule] = &[Rule(" ", "RE", "^#", "rIY"), Rule("", "R", "", "r")];
const S_RULES: &[Rule] = &[
    Rule("", "SH", "", "SH"),
    Rule("#", "SION", "", "ZHAXn"),
    Rule("", "SOME", "", "sAHm"),
    Rule("#", "SUR", "#", "ZHER"),
    Rule("", "SUR", "#", "SHER"),
    Rule("#", "SU", "#", "ZHUW"),
    Rule("#", "SSU", "#", "SHUW"),
    Rule("#", "SED", " ", "zd"),
    Rule("#", "S", "#", "z"),
    Rule("", "SAID", "", "sEHd"),
    Rule("^", "SION", "", "SHAXn"),
    Rule("", "S", "S", ""),
    Rule(".", "S", " ", "z"),
    Rule("#:.E", "S", " ", "z"),
    Rule("#:^##", "S", " ", "z"),
    Rule("#:^#", "S", " ", "s"),
    Rule("U", "S", " ", "s"),
    Rule(" :#", "S", " ", "z"),
    Rule(" ", "SCH", "", "sk"),
    Rule("", "S", "C+", ""),
    Rule("#", "SM", "", "zm"),
    Rule("#", "SN", "'", "zAXn"),
    Rule("", "S", "", "s"),
];
const T_RULES: &[Rule] = &[
    Rule(" ", "THE", " ", "DHAX"),
    Rule("", "TO", " ", "tUW"),
    Rule("", "THAT", " ", "DHAEt"),
    Rule(" ", "THIS", " ", "DHIHs"),
    Rule(" ", "THEY", "", "DHEY"),
    Rule(" ", "THERE", "", "DHEHr"),
    Rule("", "THER", "", "DHER"),
    Rule("", "THEIR", "", "DHEHr"),
    Rule(" ", "THAN", " ", "DHAEn"),
    Rule(" ", "THEM", " ", "DHEHm"),
    Rule("", "THESE", " ", "DHIYz"),
    Rule(" ", "THEN", "", "DHEHn"),
    Rule("", "THROUGH", "", "THrUW"),
    Rule("", "THOSE", "", "DHOWz"),
    Rule("", "THOUGH", " ", "DHOW"),
    Rule(" ", "THUS", "", "DHAHs"),
    Rule("", "TH", "", "TH"),
    Rule("#:", "TED", " ", "tIHd"),
    Rule("S", "TI", "#N", "CH"),
    Rule("", "TI", "O", "SH"),
    Rule("", "TI", "A", "SH"),
    Rule("", "TIEN", "", "SHAXn"),
    Rule("", "TUR", "#", "CHER"),
    Rule("", "TU", "A", "CHUW"),
    Rule(" ", "TWO", "", "tUW"),
    Rule("", "T", "", "t"),
];
const U_RULES: &[Rule] = &[
    Rule(" ", "UN", "I", "yUWn"),
    Rule(" ", "UN", "", "AHn"),
    Rule(" ", "UPON", "", "AXpAOn"),
    Rule("T", "UR", "#", "UHr"),
    Rule("S", "UR", "#", "UHr"),
    Rule("R", "UR", "#", "UHr"),
    Rule("D", "UR", "#", "UHr"),
    Rule("L", "UR", "#", "UHr"),
    Rule("Z", "UR", "#", "UHr"),
    Rule("N", "UR", "#", "UHr"),
    Rule("J", "UR", "#", "UHr"),
    Rule("TH", "UR", "#", "UHr"),
    Rule("CH", "UR", "#", "UHr"),
    Rule("SH", "UR", "#", "UHr"),
    Rule("", "UR", "#", "yUHr"),
    Rule("", "UR", "", "ER"),
    Rule("", "U", "^ ", "AH"),
    Rule("", "U", "^^", "AH"),
    Rule("", "UY", "", "AY"),
    Rule(" G", "U", "#", ""),
    Rule("G", "U", "%", ""),
    Rule("G", "U", "#", "w"),
    Rule("#N", "U", "", "yUW"),
    Rule("T", "U", "", "UW"),
    Rule("S", "U", "", "UW"),
    Rule("R", "U", "", "UW"),
    Rule("D", "U", "", "UW"),
    Rule("L", "U", "", "UW"),
    Rule("Z", "U", "", "UW"),
    Rule("N", "U", "", "UW"),
    Rule("J", "U", "", "UW"),
    Rule("TH", "U", "", "UW"),
    Rule("CH", "U", "", "UW"),
    Rule("SH", "U", "", "UW"),
    Rule("", "U", "", "yUW"),
];
const V_RULES: &[Rule] = &[Rule("", "VIEW", "", "vyUW"), Rule("", "V", "", "v")];
const W_RULES: &[Rule] = &[
    Rule(" ", "WERE", "", "wER"),
    Rule("", "WA", "S", "wAA"),
    Rule("", "WA", "T", "wAA"),
    Rule("", "WHERE", "", "WHEHr"),
    Rule("", "WHAT", "", "WHAAt"),
    Rule("", "WHOL", "", "hOWl"),
    Rule("", "WHO", "", "hUW"),
    Rule("", "WH", "", "WH"),
    Rule("", "WAR", "", "wAOr"),
    Rule("", "WOR", "^", "wER"),
    Rule("", "WR", "", "r"),
    Rule("", "W", "", "w"),
];
const X_RULES: &[Rule] = &[Rule("", "X", "", "ks")];
const Y_RULES: &[Rule] = &[
    Rule("", "YOUNG", "", "yAHNG"),
    Rule(" ", "YOU", "", "yUW"),
    Rule(" ", "YES", "", "yEHs"),
    Rule(" ", "Y", "", "y"),
    Rule("#:^", "Y", " ", "IY"),
    Rule("#:^", "Y", "I", "IY"),
    Rule(" :", "Y", " ", "AY"),
    Rule(" :", "Y", "#", "AY"),
    Rule(" :", "Y", "^+:#", "IH"),
    Rule(" :", "Y", "^#", "AY"),
    Rule("", "Y", "", "IH"),
];
const Z_RULES: &[Rule] = &[Rule("", "Z", "", "z")];
